import { $, $$, api, esc, sev, ago, stamp, num, label, emptyState, toast, busy, emit, can, modal, closeLayer } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { openAlert } from '../panels.js';

// Threat hunting: test a hypothesis against stored logs, alerts and
// investigations, optionally with every SigmaHQ rule and live reputation
// checks. Saved hunts remember their last result so a re-run shows what is new.

const TABS = [['hunt', 'Hunt'], ['saved', 'Saved hunts'], ['runs', 'Run history'], ['attack', 'ATT&CK rollup']];
const LOG_TYPES = [['http_access', 'Web access'], ['auth_log', 'Auth'], ['edr_process', 'Process'], ['system', 'System']];
const WINDOWS = [['1', '1 hour'], ['24', '24 hours'], ['168', '7 days'], ['720', '30 days'], ['2160', '90 days']];
const KIND_IC = { log: 'terminal', alert: 'bell', investigation: 'scan', sigma: 'filter', intel: 'globe' };
const KIND_TEXT = { log: 'Log', alert: 'Alert', investigation: 'Investigation', sigma: 'Sigma', intel: 'Intel' };
const STARTERS = [
  { name: 'Log4Shell probes', hypothesis: 'Someone is sending JNDI lookups to our Java services.', criteria: { text: '/\\$\\{jndi:(ldap|rmi|dns)/i', window_hours: 720 } },
  { name: 'Password spraying on SSH', hypothesis: 'An external address is trying many accounts with few attempts each.', criteria: { technique: 'T1110', log_types: ['auth_log'], window_hours: 168 } },
  { name: 'Known-bad infrastructure in logs', hypothesis: 'Hosts are talking to addresses that reputation feeds list as malicious.', criteria: { intel: true, window_hours: 24 } },
  { name: 'Sigma sweep', hypothesis: 'Something in the last week matches a community detection rule we have not alerted on.', criteria: { sigma: true, window_hours: 168 } }
];

let ctx = null;

export async function render({ el, query, navigate }) {
  ctx = { el, navigate, tab: TABS.some(([k]) => k === query.tab) ? query.tab : 'hunt', result: null, hunts: [], days: 30 };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Threat hunting</h1>
        <p class="page-sub">Go looking before an alert fires. A hunt searches stored logs, alerts and investigations, and can sweep them with SigmaHQ rules and live reputation feeds.</p>
      </div>
    </div>
    <section class="panel reveal">
      <div class="tabs" role="tablist" id="hn-tabs">${TABS.map(([k, t]) => `<button class="tab" data-tab="${k}" role="tab">${esc(t)}</button>`).join('')}</div>
      <div id="hn-pane"></div>
    </section>`;
  $$('#hn-tabs [data-tab]', el).forEach((b) => { b.onclick = () => setTab(b.dataset.tab); });
  await setTab(ctx.tab, query);
}

export function onDataChanged() {
  if (!ctx || !document.body.contains(ctx.el)) return;
  if (ctx.tab === 'saved' || ctx.tab === 'runs' || ctx.tab === 'attack') setTab(ctx.tab);
}

async function setTab(tab, query = {}) {
  const { el } = ctx;
  ctx.tab = tab;
  $$('#hn-tabs [data-tab]', el).forEach((b) => { const on = b.dataset.tab === tab; b.classList.toggle('is-on', on); b.setAttribute('aria-selected', String(on)); });
  history.replaceState(null, '', tab === 'hunt' ? '#/hunts' : `#/hunts?tab=${tab}`);
  const pane = $('#hn-pane', el);
  if (tab === 'hunt') paintBuilder(pane, ctx.prefill || (query.technique ? { criteria: { technique: query.technique, window_hours: 720 } } : query.indicators ? { criteria: { indicators: String(query.indicators).split(',').filter(Boolean).slice(0, 50), window_hours: 720 } } : null));
  else if (tab === 'saved') await paintSaved(pane);
  else if (tab === 'runs') await paintRuns(pane);
  else await paintAttack(pane);
  hydrateIcons(pane);
}

// ---- Builder ---------------------------------------------------------------
function paintBuilder(pane, pre) {
  const c = (pre && pre.criteria) || {};
  const respond = can('respond');
  pane.innerHTML = `
    <div class="hunt">
      <form class="hunt__form" id="hb-form" novalidate>
        ${pre && pre.hunt_id ? `<div class="notice">${icon('info')}<div class="small">Editing saved hunt <b>${esc(pre.name)}</b>. Run it from Saved hunts to compare with its previous result.</div></div>` : ''}
        <div class="form-grid">
          <label class="field span-2"><span>Search text <small>plain text, or /regex/flags</small></span><input class="input input--mono" name="text" maxlength="300" value="${esc(c.text || '')}" placeholder="/union\\s+select/i  or  powershell -enc"></label>
          <label class="field"><span>Address or CIDR</span><input class="input input--mono" name="ip" value="${esc(c.ip || '')}" placeholder="185.220.101.0/24"></label>
          <label class="field"><span>ATT&amp;CK technique</span><input class="input input--mono" name="technique" value="${esc(c.technique || '')}" placeholder="T1110 or T1110.003"></label>
          <label class="field span-2"><span>Indicators <small>IPs, domains, URLs, hashes; defanged is fine</small></span><textarea class="textarea input--mono" name="indicators" rows="2" placeholder="evil[.]top, 45.95.147.12">${esc((c.indicators || []).join('\n'))}</textarea></label>
          <div class="field span-2"><span>Log sources</span><div class="row wrap">${LOG_TYPES.map(([v, t]) => `<label class="check"><input type="checkbox" name="log_types" value="${v}" ${(c.log_types || []).includes(v) ? 'checked' : ''}> ${t}</label>`).join('')}<span class="small muted">none ticked = all</span></div></div>
          <label class="field"><span>Window</span><select class="select" name="window_hours">${WINDOWS.map(([v, t]) => `<option value="${v}" ${String(c.window_hours || 168) === v ? 'selected' : ''}>Last ${t}</option>`).join('')}</select></label>
          <label class="field"><span>Minimum alert severity</span><select class="select" name="min_severity"><option value="">Any</option>${['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => `<option ${c.min_severity === s ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
          <div class="field span-2"><span>Sweeps</span>
            <label class="check"><input type="checkbox" name="sigma" ${c.sigma ? 'checked' : ''}> Run every loaded SigmaHQ rule over the logs in the window</label>
            <label class="check"><input type="checkbox" name="intel" ${c.intel ? 'checked' : ''}> Check external addresses seen in the window against reputation feeds</label>
          </div>
        </div>
        <div class="row mt-16 wrap">
          <button class="btn btn--primary" id="hb-run" ${respond ? '' : 'disabled'}>${icon('play')}Run hunt</button>
          <button class="btn" type="button" id="hb-save" ${respond ? '' : 'disabled'}>${icon('download')}${pre && pre.hunt_id ? 'Save changes' : 'Save as hunt'}</button>
          <span class="form-error grow" id="hb-err"></span>
        </div>
      </form>
      <aside class="hunt__side">
        <h3 class="section-title" style="margin-top:0">Starting points</h3>
        <div class="list">${STARTERS.map((s, i) => `<button class="list__item is-clickable hunt__starter" data-starter="${i}"><div class="grow"><div class="list__title">${esc(s.name)}</div><div class="list__sub">${esc(s.hypothesis)}</div></div>${icon('arrow')}</button>`).join('')}</div>
        <p class="small muted mt-12">Every hit links to the record it came from. Nothing is sampled: if a run is cut at 500 findings, it says so.</p>
      </aside>
    </div>
    <div id="hb-out"></div>`;
  const form = $('#hb-form', pane);
  const read = () => {
    const f = new FormData(form);
    const crit = { window_hours: Number(f.get('window_hours')) };
    for (const k of ['text', 'ip', 'technique', 'indicators', 'min_severity']) { const v = String(f.get(k) || '').trim(); if (v) crit[k] = v; }
    const lt = f.getAll('log_types');
    if (lt.length) crit.log_types = lt;
    if (f.get('sigma')) crit.sigma = true;
    if (f.get('intel')) crit.intel = true;
    return crit;
  };
  form.onsubmit = (e) => {
    e.preventDefault();
    $('#hb-err', pane).textContent = '';
    busy($('#hb-run', pane), async () => {
      const out = $('#hb-out', pane);
      out.innerHTML = '<div class="panel__body"><div class="skeleton" style="height:120px"></div></div>';
      try {
        const r = await api('/hunts/adhoc', { method: 'POST', body: { criteria: read() } });
        ctx.result = r;
        paintResult(out, r);
      } catch (err) { out.innerHTML = ''; $('#hb-err', pane).textContent = err.message; }
    });
  };
  $('#hb-run', pane).onclick = form.onsubmit;
  $('#hb-save', pane).onclick = () => (pre && pre.hunt_id ? updateHunt(pre, read()) : saveHunt(read()));
  $$('[data-starter]', pane).forEach((b) => { b.onclick = () => { ctx.prefill = STARTERS[Number(b.dataset.starter)]; paintBuilder(pane, ctx.prefill); hydrateIcons(pane); }; });
  if (ctx.result) paintResult($('#hb-out', pane), ctx.result);
}
function critText(c) {
  const p = [];
  if (c.text) p.push(`text <code>${esc(c.text)}</code>`);
  if (c.ip) p.push(`address <code>${esc(c.ip)}</code>`);
  if (c.technique) p.push(`technique <code>${esc(c.technique)}</code>`);
  if (c.indicators) p.push(`${c.indicators.length} indicator${c.indicators.length === 1 ? '' : 's'}`);
  if (c.log_types) p.push(`logs: ${c.log_types.map((x) => esc(label(x))).join(', ')}`);
  if (c.min_severity) p.push(`alerts ${esc(c.min_severity)}+`);
  if (c.sigma) p.push('Sigma sweep');
  if (c.intel) p.push('reputation sweep');
  p.push(`last ${c.window_hours >= 48 ? `${Math.round(c.window_hours / 24)} days` : `${c.window_hours} hours`}`);
  return p.join(' &middot; ');
}

function findingHref(f) {
  if (f.kind === 'alert') return { alert: f.ref };
  if (f.kind === 'investigation' && f.alert_id) return { href: `#/investigate/${encodeURIComponent(f.alert_id)}` };
  if (f.kind === 'intel') return { href: `#/intel?q=${encodeURIComponent(f.ref)}` };
  if (f.kind === 'sigma') return { href: '#/intel?tab=detect' };
  if (f.remote) return { href: `#/ip/${encodeURIComponent(f.remote)}` };
  return {};
}

function paintResult(out, r) {
  const s = r.summary || {};
  const kinds = Object.entries(s.kinds || {});
  const techs = Object.entries(s.techniques || {}).sort((a, b) => b[1] - a[1]);
  const shown = r.findings.slice(0, 200);
  out.innerHTML = `
    <div class="hunt-res reveal">
      <div class="hunt-res__head">
        <div class="grow">
          <div class="hunt-res__n"><b>${num(r.hits)}</b> finding${r.hits === 1 ? '' : 's'}${r.new_hits != null ? ` <span class="tag ${r.new_hits ? 'tag--warn' : ''}">${r.new_hits} new since last run</span>` : ''}</div>
          <div class="small muted">${critText(r.criteria || s.criteria || {})}</div>
        </div>
        <div class="small muted mono hunt-res__meta">run #${esc(r.run_id)} &middot; ${num(r.duration_ms)} ms<br>scanned ${num(s.scanned?.logs)} logs, ${num(s.scanned?.alerts)} alerts, ${num(s.scanned?.investigations)} investigations</div>
      </div>
      ${(s.notes || []).length || s.truncated ? `<div class="notice notice--warn">${icon('alert')}<div class="small">${s.truncated ? 'Stopped at 500 findings; narrow the hunt to see the rest. ' : ''}${(s.notes || []).map(esc).join(' ')}</div></div>` : ''}
      ${r.hits ? `
      <div class="hunt-res__facets">
        <div><span class="small muted">By source</span><div class="row wrap mt-8">${kinds.map(([k, n]) => `<span class="tag">${icon(KIND_IC[k] || 'dot')}${esc(KIND_TEXT[k] || k)} <b>${n}</b></span>`).join('')}</div></div>
        ${(s.hosts || []).length ? `<div><span class="small muted">Hosts</span><div class="row wrap mt-8">${s.hosts.slice(0, 8).map((h) => `<a class="tag" href="#/ip/${encodeURIComponent(h)}">${esc(h)}</a>`).join('')}${s.hosts.length > 8 ? `<span class="small muted">+${s.hosts.length - 8}</span>` : ''}</div></div>` : ''}
        ${(s.remotes || []).length ? `<div><span class="small muted">Remote addresses</span><div class="row wrap mt-8">${s.remotes.slice(0, 8).map((h) => `<a class="tag" href="#/ip/${encodeURIComponent(h)}">${esc(h)}</a>`).join('')}${s.remotes.length > 8 ? `<span class="small muted">+${s.remotes.length - 8}</span>` : ''}</div></div>` : ''}
        ${techs.length ? `<div><span class="small muted">Techniques</span><div class="row wrap mt-8">${techs.slice(0, 8).map(([t, n]) => `<span class="tag">${esc(t)} <b>${n}</b></span>`).join('')}</div></div>` : ''}
        ${s.sigma ? `<div><span class="small muted">Sigma</span><div class="small mt-8">${num(s.sigma.rules)} rules over ${num(s.sigma.lines)} lines, ${num(s.sigma.rules_hit)} rules matched</div></div>` : ''}
        ${s.intel ? `<div><span class="small muted">Reputation</span><div class="small mt-8">${num(s.intel.checked)} of ${num(s.intel.addresses)} addresses checked</div></div>` : ''}
      </div>
      <ol class="hunt-hits">${shown.map((f, i) => {
        const link = findingHref(f);
        return `<li class="hunt-hit ${f.new ? 'is-new' : ''}" style="--i:${Math.min(i, 30)}">
          <span class="hunt-hit__ic" title="${esc(KIND_TEXT[f.kind] || f.kind)}">${icon(KIND_IC[f.kind] || 'dot')}</span>
          <div class="grow" style="min-width:0">
            <div class="row wrap" style="gap:6px">${f.severity ? sev(f.severity) : ''}${link.alert ? `<a href="#" class="hunt-hit__title" data-alert="${esc(link.alert)}">${esc(f.title)}</a>` : link.href ? `<a class="hunt-hit__title" href="${link.href}">${esc(f.title)}</a>` : `<span class="hunt-hit__title">${esc(f.title)}</span>`}${f.new ? '<span class="tag tag--warn">new</span>' : ''}${f.technique ? `<span class="tag">${esc(f.technique)}</span>` : ''}</div>
            <div class="small muted mono">${stamp(f.at)}${f.host ? ` &middot; ${esc(f.host)}` : ''}${f.remote ? ` &middot; ${esc(f.remote)}` : ''} &middot; ${esc(f.ref)}</div>
            ${f.detail ? `<pre class="hunt-hit__detail">${esc(f.detail)}</pre>` : ''}
          </div></li>`;
      }).join('')}</ol>
      ${r.findings.length > shown.length ? `<div class="table-foot">Showing the newest ${shown.length} of ${num(r.findings.length)}. The full set is stored with run #${esc(r.run_id)} and available over the API.</div>` : ''}`
      : emptyState('No hits', 'The hypothesis did not match anything in the window. That is a result too: the run is recorded in history.', 'shieldCheck')}
    </div>`;
  $$('[data-alert]', out).forEach((a) => { a.onclick = (e) => { e.preventDefault(); openAlert(a.dataset.alert, ctx.navigate); }; });
  hydrateIcons(out);
}

function huntForm(title, pre, onSave) {
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">${esc(title)}</h2></div>
    <form class="modal__body form-grid" id="hs-form" novalidate>
      <label class="field span-2"><span>Name</span><input class="input" name="name" maxlength="160" value="${esc(pre.name || '')}" placeholder="e.g. Tor exit nodes reaching the VPN"></label>
      <label class="field span-2"><span>Hypothesis</span><textarea class="textarea" name="hypothesis" rows="3" maxlength="2000" placeholder="What you expect to find if the threat is real">${esc(pre.hypothesis || '')}</textarea></label>
    </form>
    <div class="modal__foot"><span class="form-error" id="hs-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="hs-go">Save</button></div>`);
  const go = (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData($('#hs-form', panel)));
    busy($('#hs-go', panel), async () => { try { await onSave(f); closeLayer(); } catch (err) { $('#hs-err', panel).textContent = err.message; } });
  };
  $('#hs-go', panel).onclick = go;
  $('#hs-form', panel).onsubmit = go;
}

function saveHunt(criteria) {
  const pre = ctx.prefill && !ctx.prefill.hunt_id ? ctx.prefill : {};
  huntForm('Save hunt', pre, async (f) => {
    const h = await api('/hunts', { method: 'POST', body: { ...f, criteria } });
    toast(`Saved ${h.hunt_id}`, h.name, 'ok');
    ctx.prefill = null;
    emit('data:changed');
    setTab('saved');
  });
}

function updateHunt(h, criteria) {
  huntForm(`Edit ${h.hunt_id}`, h, async (f) => {
    await api(`/hunts/${encodeURIComponent(h.hunt_id)}`, { method: 'PATCH', body: { ...f, criteria } });
    toast('Hunt updated', h.name, 'ok');
    ctx.prefill = null;
    setTab('saved');
  });
}
// ---- Saved hunts -------------------------------------------------------------
async function paintSaved(pane) {
  pane.innerHTML = '<div class="panel__body"><div class="skeleton" style="height:120px"></div></div>';
  let hunts;
  try { hunts = await api('/hunts'); } catch (e) { pane.innerHTML = emptyState('Could not load hunts', e.message, 'alert'); return; }
  ctx.hunts = hunts;
  const respond = can('respond');
  pane.innerHTML = hunts.length ? `<div class="table-wrap"><table class="table">
    <thead><tr><th>Hunt</th><th class="hide-sm">Looks for</th><th class="num">Runs</th><th class="num">Last hits</th><th class="hide-sm">Last run</th><th style="width:1%"></th></tr></thead>
    <tbody class="rows-in">${hunts.map((h, i) => `<tr style="--i:${i}">
      <td><span class="cell-main">${esc(h.name)}</span><span class="cell-sub">${esc(h.hypothesis)}</span></td>
      <td class="hide-sm small">${critText(h.criteria || {})}</td>
      <td class="num">${num(h.runs || 0)}</td>
      <td class="num">${h.last_hits == null ? '-' : num(h.last_hits)}</td>
      <td class="hide-sm small muted">${h.last_run_at ? `<span title="${stamp(h.last_run_at)}">${ago(h.last_run_at)}</span>` : 'never'}</td>
      <td><div class="row" style="gap:4px;justify-content:flex-end">
        ${respond ? `<button class="btn btn--sm btn--primary" data-run="${esc(h.hunt_id)}">${icon('play')}Run</button>
        <button class="icon-btn icon-btn--bare" data-edit="${esc(h.hunt_id)}" title="Edit" aria-label="Edit ${esc(h.name)}">${icon('edit')}</button>
        <button class="icon-btn icon-btn--bare" data-del="${esc(h.hunt_id)}" title="Delete" aria-label="Delete ${esc(h.name)}">${icon('trash')}</button>` : ''}
      </div></td></tr>`).join('')}</tbody></table></div>
    <div id="hs-out"></div>`
    : emptyState('No saved hunts', 'Build a hunt, then Save as hunt. Saved hunts flag what is new each time they run.', 'search');
  $$('[data-run]', pane).forEach((b) => {
    b.onclick = () => busy(b, async () => {
      const out = $('#hs-out', pane);
      try {
        const r = await api(`/hunts/${encodeURIComponent(b.dataset.run)}/run`, { method: 'POST' });
        toast(`${r.name}: ${r.hits} finding${r.hits === 1 ? '' : 's'}`, r.new_hits != null ? `${r.new_hits} new since the last run` : 'First run; the next one will flag what is new', r.new_hits ? 'error' : 'ok');
        paintResult(out, r);
        out.scrollIntoView({ behavior: 'smooth', block: 'start' });
        const row = b.closest('tr');
        row.children[2].textContent = num((ctx.hunts.find((h) => h.hunt_id === b.dataset.run)?.runs || 0) + 1);
        row.children[3].textContent = num(r.hits);
        row.children[4].textContent = 'just now';
      } catch (e) { toast('Hunt failed', e.message, 'error'); }
    });
  });
  $$('[data-edit]', pane).forEach((b) => { b.onclick = () => { ctx.prefill = hunts.find((h) => h.hunt_id === b.dataset.edit); setTab('hunt'); }; });
  $$('[data-del]', pane).forEach((b) => {
    b.onclick = async () => {
      if (b.dataset.armed !== '1') {
        b.dataset.armed = '1'; b.classList.add('is-armed'); b.title = 'Click again to delete';
        toast('Click delete again to confirm', 'Its run history goes with it.', 'info', 3000);
        setTimeout(() => { if (b.isConnected) { b.dataset.armed = ''; b.classList.remove('is-armed'); b.title = 'Delete'; } }, 3000);
        return;
      }
      busy(b, async () => { try { await api(`/hunts/${encodeURIComponent(b.dataset.del)}`, { method: 'DELETE' }); toast('Hunt deleted'); setTab('saved'); } catch (e) { toast('Not deleted', e.message, 'error'); } });
    };
  });
}

// ---- Run history ---------------------------------------------------------------
async function paintRuns(pane) {
  pane.innerHTML = '<div class="panel__body"><div class="skeleton" style="height:120px"></div></div>';
  let runs;
  try { runs = await api('/hunts/runs?limit=100'); } catch (e) { pane.innerHTML = emptyState('Could not load runs', e.message, 'alert'); return; }
  const respond = can('respond');
  pane.innerHTML = runs.length ? `<div class="table-wrap"><table class="table">
    <thead><tr><th>Run</th><th class="num">Hits</th><th class="num hide-sm">New</th><th class="num hide-sm">Time</th><th>When</th><th style="width:1%"></th></tr></thead>
    <tbody class="rows-in">${runs.map((r, i) => `<tr style="--i:${Math.min(i, 30)}">
      <td><span class="cell-main">${esc(r.name)}</span><span class="cell-sub"><span class="mono">#${esc(r.id)}</span>${r.hunt_id ? ` &middot; ${esc(r.hunt_id)}` : ' &middot; ad-hoc'} &middot; ${esc(r.run_by)}</span></td>
      <td class="num">${num(r.hits)}</td>
      <td class="num hide-sm">${r.new_hits == null ? '-' : num(r.new_hits)}</td>
      <td class="num hide-sm mono small">${num(r.duration_ms)} ms</td>
      <td class="small muted"><span title="${stamp(r.created_at)}">${ago(r.created_at)}</span></td>
      <td><div class="row" style="gap:4px;justify-content:flex-end"><button class="btn btn--sm btn--ghost" data-open="${esc(r.id)}">Open</button>${respond ? `<button class="btn btn--sm" data-replay="${esc(r.id)}" title="Run the same criteria again now">${icon('rotate')}Replay</button>` : ''}</div></td>
    </tr>`).join('')}</tbody></table></div><div id="hr-out"></div>`
    : emptyState('No runs yet', 'Every hunt run, saved or ad-hoc, is stored here with its findings.', 'inbox');
  const out = $('#hr-out', pane);
  $$('[data-open]', pane).forEach((b) => {
    b.onclick = () => busy(b, async () => {
      try {
        const r = await api(`/hunts/runs/${encodeURIComponent(b.dataset.open)}`);
        paintResult(out, { run_id: r.id, hunt_id: r.hunt_id, name: r.name, hits: r.hits, new_hits: r.new_hits, duration_ms: r.duration_ms, criteria: (r.summary || {}).criteria, summary: r.summary, findings: r.findings || [] });
        out.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } catch (e) { toast('Could not open run', e.message, 'error'); }
    });
  });
  $$('[data-replay]', pane).forEach((b) => {
    b.onclick = () => busy(b, async () => {
      try {
        const r = await api(`/hunts/runs/${encodeURIComponent(b.dataset.replay)}/replay`, { method: 'POST' });
        toast(`Replayed: ${r.hits} finding${r.hits === 1 ? '' : 's'}`, r.new_hits != null ? `${r.new_hits} new` : '', 'ok');
        await paintRuns(pane);
        hydrateIcons(pane);
        paintResult($('#hr-out', pane), r);
      } catch (e) { toast('Replay failed', e.message, 'error'); }
    });
  });
}

// ---- ATT&CK rollup -----------------------------------------------------------------
async function paintAttack(pane) {
  pane.innerHTML = '<div class="panel__body"><div class="skeleton" style="height:200px"></div></div>';
  let d;
  try { d = await api(`/hunts/techniques?days=${ctx.days}`); } catch (e) { pane.innerHTML = emptyState('Could not load the rollup', e.message, 'alert'); return; }
  const max = Math.max(1, ...d.tactics.map((t) => t.hits));
  pane.innerHTML = `
    <div class="toolbar">
      <div class="seg" id="ha-days">${[7, 30, 90, 365].map((n) => `<button data-d="${n}" class="${n === d.days ? 'is-on' : ''}">${n === 365 ? '1 year' : `${n} days`}</button>`).join('')}</div>
      <div class="toolbar__end small muted">${num(d.alerts)} alerts in window &middot; ${num(d.untagged)} carry no technique id</div>
    </div>
    ${d.techniques.length ? `
    <div class="attack" style="--cols:${d.tactics.length}">${d.tactics.map((t, i) => {
      const own = d.techniques.filter((x) => x.group === t.tactic);
      return `<div class="attack__col ${t.hits ? 'is-hit' : ''}" style="--i:${i};--heat:${t.hits / max}">
        <div class="attack__head"><span class="attack__name">${esc(t.tactic)}</span><span class="attack__n mono">${t.hits || ''}</span></div>
        <div class="attack__body">${own.length ? own.slice(0, 5).map((x) => `<button class="attack__tech" data-hunt-t="${esc(x.technique)}" title="Hunt for ${esc(x.technique)}"><span class="truncate">${esc(x.name || x.technique)}</span><b class="mono">${x.alerts + x.investigations}</b></button>`).join('') : '<span class="attack__none">-</span>'}
        ${t.confirmed ? `<div class="attack__hit">${t.confirmed} confirmed</div>` : ''}</div></div>`;
    }).join('')}</div>
    <div class="table-wrap"><table class="table">
      <thead><tr><th>Technique</th><th class="hide-sm">Tactic</th><th class="num">Alerts</th><th class="num">Open</th><th class="num hide-sm">Investigated</th><th class="num">Confirmed</th><th class="num hide-sm">Hosts</th><th class="hide-sm">Last seen</th><th style="width:1%"></th></tr></thead>
      <tbody class="rows-in">${d.techniques.map((x, i) => `<tr style="--i:${Math.min(i, 30)}">
        <td><a class="mono" href="https://attack.mitre.org/techniques/${esc(x.technique.replace('.', '/'))}/" target="_blank" rel="noopener">${esc(x.technique)}</a>${x.name ? ` <span class="small">${esc(x.name)}</span>` : ''}</td>
        <td class="hide-sm small">${esc(x.tactic || '-')}</td>
        <td class="num">${num(x.alerts)}</td><td class="num">${num(x.open)}</td><td class="num hide-sm">${num(x.investigations)}</td>
        <td class="num ${x.confirmed ? 'bad' : ''}">${num(x.confirmed)}</td><td class="num hide-sm">${num(x.hosts)}</td>
        <td class="hide-sm small muted">${x.last_seen ? `<span title="${stamp(x.last_seen)}">${ago(x.last_seen)}</span>` : '-'}</td>
        <td>${can('respond') ? `<button class="btn btn--sm btn--ghost" data-hunt-t="${esc(x.technique)}">Hunt</button>` : ''}</td>
      </tr>`).join('')}</tbody></table></div>`
    : emptyState('No techniques in this window', 'Alerts whose sensor reference or payload carries an ATT&CK id, and investigations with a mapped technique, are counted here.', 'chart')}`;
  $$('#ha-days button', pane).forEach((b) => { b.onclick = () => { ctx.days = Number(b.dataset.d); paintAttack(pane).then(() => hydrateIcons(pane)); }; });
  $$('[data-hunt-t]', pane).forEach((b) => {
    b.onclick = () => { ctx.prefill = { name: `${b.dataset.huntT} activity`, hypothesis: `Find every trace of ${b.dataset.huntT} in the last ${d.days} days.`, criteria: { technique: b.dataset.huntT, window_hours: Math.min(2160, d.days * 24) } }; setTab('hunt'); };
  });
}