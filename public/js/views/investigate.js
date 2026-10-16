import { $, $$, api, stream, esc, sev, pill, flow, ago, stamp, label, markPayload, emptyState, toast, busy, emit, state, can } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

const PHASES = [['triage', 'Triage'], ['enrich', 'Enrich'], ['correlate', 'Correlate'], ['decide', 'Decide'], ['contain', 'Contain'], ['verify', 'Verify']];
const OUTCOME_TEXT = { ATTACK_SUCCEEDED: 'Compromise confirmed', ATTACK_FAILED: 'Attempt failed', FALSE_POSITIVE: 'False positive', RECON_ONLY: 'Reconnaissance only' };
const OPEN = ['NEW', 'INVESTIGATING', 'CONFIRMED'];

let ctx = null;

export async function render({ el, params, query, navigate, refresh }) {
  if (ctx && ctx.abort && !refresh) ctx.abort.abort();
  const prevSel = ctx && ctx.el === el ? ctx.selected : null;
  ctx = { el, navigate, selected: params[0] || prevSel || null, running: false, abort: null, filter: 'open' };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Investigations</h1>
        <p class="page-sub">Payload, asset, CVE and host checks per alert. Every step is logged.</p>
      </div>
    </div>
    <div class="workspace">
      <aside class="panel queue reveal">
        <div class="panel__head"><h2 class="panel__title">Queue</h2>
          <div class="seg panel__meta" id="q-filter"><button data-f="open" class="is-on">Open</button><button data-f="all">All</button></div></div>
        <div class="queue__list" id="q-list"><div class="stack" style="padding:14px">${'<div class="skeleton" style="height:52px"></div>'.repeat(4)}</div></div>
      </aside>
      <section class="panel case reveal" id="case">${emptyState('No alert selected', 'Choose one from the queue.', 'scan')}</section>
    </div>`;
  $$('#q-filter button', el).forEach((b) => {
    b.onclick = () => { ctx.filter = b.dataset.f; $$('#q-filter button', el).forEach((x) => x.classList.toggle('is-on', x === b)); paintQueue(); };
  });
  await loadQueue();
  if (!ctx.selected) {
    const first = ctx.alerts.find((a) => OPEN.includes(a.status));
    if (first) ctx.selected = first.alert_id;
  }
  paintQueue();
  if (ctx.selected) await openCase(ctx.selected, query.run === '1');
  return () => { if (ctx && ctx.abort) ctx.abort.abort(); };
}

export function onDataChanged() {
  if (!ctx || !document.body.contains(ctx.el) || ctx.running) return;
  loadQueue().then(() => { paintQueue(); if (ctx.selected) openCase(ctx.selected, false, true); });
}

async function loadQueue() {
  const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  ctx.alerts = (await api('/alerts')).sort((a, b) => (OPEN.includes(b.status) - OPEN.includes(a.status)) || RANK[b.severity] - RANK[a.severity] || b.detected_at.localeCompare(a.detected_at));
}

function paintQueue() {
  const list = $('#q-list', ctx.el);
  if (!list) return;
  const rows = ctx.alerts.filter((a) => ctx.filter === 'all' || OPEN.includes(a.status) || a.alert_id === ctx.selected);
  list.innerHTML = rows.length ? `<div class="rows-in">${rows.map((a, i) => `
    <div class="queue__item ${a.alert_id === ctx.selected ? 'is-active' : ''}" style="--i:${Math.min(i, 15)}" data-id="${esc(a.alert_id)}" tabindex="0">
      <div class="queue__row">${sev(a.severity)}<span class="small muted">${ago(a.detected_at)}</span></div>
      <div class="queue__sig">${esc(a.signature)}</div>
      <div class="queue__row"><span class="mono small muted">${esc(a.alert_id)}</span>${pill(a.status)}</div>
    </div>`).join('')}</div>` : emptyState('Nothing open', 'Switch to All for closed cases.', 'shieldCheck');
  $$('.queue__item', list).forEach((it) => {
    const go = () => {
      if (ctx.running) { toast('Investigation in progress', 'Wait for the current run to finish.'); return; }
      ctx.selected = it.dataset.id;
      history.replaceState(null, '', `#/investigate/${it.dataset.id}`);
      $$('.queue__item', list).forEach((x) => x.classList.toggle('is-active', x === it));
      openCase(it.dataset.id);
    };
    it.onclick = go;
    it.onkeydown = (e) => { if (e.key === 'Enter') go(); };
  });
}

async function openCase(id, autoRun = false, quiet = false) {
  const box = $('#case', ctx.el);
  if (!quiet) box.innerHTML = `<div style="padding:22px" class="stack"><div class="skeleton" style="height:16px;width:30%"></div><div class="skeleton" style="height:30px;width:80%"></div><div class="skeleton" style="height:220px"></div></div>`;
  let data;
  try { data = await api(`/alerts/${encodeURIComponent(id)}`); } catch (e) { box.innerHTML = emptyState('Alert not found', e.message, 'alert'); return; }
  if (ctx.selected !== id) return;
  ctx.data = data;
  const { alert: a, asset, investigations } = data;
  const inv = investigations[0];
  const llm = state.health && state.health.engine.llm;
  const engine = (state.config && state.config.engine) || 'playbook';

  box.innerHTML = `
    <div class="case-head">
      <div class="case-head__main">
        <div class="small muted"><span class="mono">${esc(a.alert_id)}</span> &middot; ${esc(a.category)} &middot; ${ago(a.detected_at)}</div>
        <h2 class="case-head__title">${esc(a.signature)}</h2>
        <div class="row wrap">${sev(a.severity)}<span id="case-status">${pill(a.status)}</span>${flow(a.source_ip, a.dest_ip, a.dest_port)}${asset ? `<span class="tag">${esc(asset.hostname)}</span>` : '<span class="tag tag--warn">not in CMDB</span>'}</div>
      </div>
      <div class="case-head__actions">
        ${llm ? `<div class="seg" id="engine-seg" title="Investigation engine"><button data-e="playbook" class="${engine !== 'llm' ? 'is-on' : ''}">Playbook</button><button data-e="llm" class="${engine === 'llm' ? 'is-on' : ''}">LLM</button></div>` : ''}
        ${can('respond') ? `<button class="btn btn--primary btn--lg" id="run-btn" ${a.status === 'INVESTIGATING' ? 'disabled' : ''}>${inv ? 'Re-run' : 'Run investigation'}</button>` : '<span class="tag">read only</span>'}
      </div>
    </div>
    <div class="phases" id="phases">${PHASES.map(([k, t], i) => `<div class="phase" data-phase="${k}"><span class="phase__n">${String(i + 1).padStart(2, '0')}</span>${t}</div>`).join('')}</div>
    <div class="case-body">
      <div style="min-width:0">
        <div id="run-area">${inv ? '' : `<div class="empty"><b>Not run yet</b><span class="small">No evidence collected for this alert.</span></div>`}</div>
      </div>
      <aside class="case-side">
        <div><h3 class="section-title">Payload</h3><pre class="code" style="max-height:200px">${markPayload(a.raw_payload)}</pre></div>
        ${asset ? `<div><h3 class="section-title">Target host</h3><dl class="dl" style="grid-template-columns:90px 1fr">
          <dt>Host</dt><dd>${esc(asset.hostname)}</dd><dt>OS</dt><dd>${esc(asset.os_version)}</dd>
          <dt>Owner</dt><dd>${esc(asset.owner || '-')}</dd><dt>Criticality</dt><dd>${sev(asset.criticality)}</dd>
          <dt>WAF</dt><dd>${asset.waf_enabled ? 'In front' : '<span style="color:var(--crit)">None</span>'}</dd></dl></div>` : ''}
        <div><h3 class="section-title">Previous runs</h3><div id="history">${investigations.length ? investigations.map((i) => `
          <div class="history-item" data-inv="${esc(i.investigation_id)}"><div class="row">${pill(i.outcome)}<span class="small muted" style="margin-left:auto">${ago(i.created_at)}</span></div>
          <div class="list__title mono small">${esc(i.investigation_id)}</div><div class="small muted">${esc(i.engine)} &middot; ${i.confidence}%${i.human_override ? ' &middot; overridden' : ''}</div></div>`).join('') : '<p class="small muted" style="margin:0">None.</p>'}</div></div>
      </aside>
    </div>`;

  $$('#engine-seg button', box).forEach((b) => {
    b.onclick = () => { $$('#engine-seg button', box).forEach((x) => x.classList.toggle('is-on', x === b)); };
  });
  if ($('#run-btn', box)) $('#run-btn', box).onclick = () => run(a.alert_id);
  $$('[data-inv]', box).forEach((h) => {
    h.onclick = () => { const i = investigations.find((x) => x.investigation_id === h.dataset.inv); if (i) showInvestigation(i, false); };
  });
  if (inv) showInvestigation(inv, false);
  hydrateIcons(box);
  if (autoRun && a.status !== 'INVESTIGATING' && can('respond')) {
    history.replaceState(null, '', `#/investigate/${a.alert_id}`);
    run(a.alert_id);
  }
}

function setPhases(done, active) {
  $$('.phase', ctx.el).forEach((p) => {
    p.classList.toggle('is-done', done.has(p.dataset.phase));
    p.classList.toggle('is-active', p.dataset.phase === active);
  });
}

function stepIcon(s) {
  if (s.state === 'running') return icon('dot');
  if (s.state === 'error') return icon('x');
  if (s.kind === 'adaptation') return icon('rotate');
  if (s.kind === 'verdict') return icon('check');
  if (s.kind === 'policy') return icon('info');
  return icon('check');
}

function stepHtml(s, i) {
  const cls = s.state === 'running' ? 'running' : s.state === 'error' || s.ok === false ? 'error' : s.kind && s.kind !== 'note' ? s.kind : 'done';
  const hasResult = s.result || s.args;
  return `<li class="tl tl--${cls}" data-step="${i}">
    <span class="tl__icon">${stepIcon(s)}</span>
    <div style="min-width:0">
      <div class="tl__head"><span class="tl__title">${esc(s.title)}</span>${s.tool ? `<span class="tl__tool">${esc(s.tool)}()</span>` : ''}${s.state !== 'running' && s.tool ? `<span class="tl__ms">${s.ms} ms</span>` : ''}</div>
      ${s.detail ? `<div class="tl__detail">${esc(s.detail)}</div>` : ''}
      ${s.error ? `<div class="tl__detail" style="color:var(--crit)">${esc(s.error)}</div>` : ''}
      ${hasResult && s.state !== 'running' ? `<button class="tl__toggle" data-toggle>Show ${s.result ? 'output' : 'arguments'}</button>` : ''}
    </div></li>`;
}

function bindToggles(list, steps) {
  $$('[data-toggle]', list).forEach((b) => {
    b.onclick = () => {
      const li = b.closest('.tl');
      const s = steps[Number(li.dataset.step)];
      const open = li.querySelector('.tl__result');
      if (open) { open.remove(); b.textContent = b.textContent.replace('Hide', 'Show'); return; }
      const payload = s.result ? { args: s.args, result: s.result } : s.args;
      b.insertAdjacentHTML('afterend', `<div class="tl__result"><pre class="code">${esc(JSON.stringify(payload, null, 2))}</pre></div>`);
      b.textContent = b.textContent.replace('Show', 'Hide');
    };
  });
}

async function run(alertId) {
  if (ctx.running || !can('respond')) return;
  const box = $('#case', ctx.el);
  const btn = $('#run-btn', box);
  const seg = $('#engine-seg .is-on', box);
  const engine = seg ? seg.dataset.e : 'playbook';
  ctx.running = true;
  ctx.abort = new AbortController();
  btn.disabled = true;
  btn.classList.add('is-busy');
  $('#case-status', box).innerHTML = pill('INVESTIGATING');
  const area = $('#run-area', box);
  area.innerHTML = '<ol class="timeline" id="tl"></ol>';
  const list = $('#tl', area);
  const steps = [];
  const done = new Set();
  let runningEl = null;
  setPhases(done, 'triage');

  const onEvent = (ev) => {
    if (ev.type === 'start') {
      list.insertAdjacentHTML('beforeend', `<li class="tl tl--policy"><span class="tl__icon">${icon('cpu')}</span><div><div class="tl__head"><span class="tl__title">Run started</span><span class="tl__tool">${esc(ev.engine)} engine</span><span class="tl__ms">${new Date().toISOString().slice(11, 19)}Z</span></div></div></li>`);
    } else if (ev.type === 'step') {
      const phaseIdx = PHASES.findIndex(([k]) => k === ev.phase);
      if (phaseIdx > 0) PHASES.slice(0, phaseIdx).forEach(([k]) => done.add(k));
      if (ev.phase !== 'adapt') setPhases(done, ev.phase);
      if (ev.state === 'running') {
        list.insertAdjacentHTML('beforeend', stepHtml(ev, -1));
        runningEl = list.lastElementChild;
      } else {
        steps.push(ev);
        const html = stepHtml(ev, steps.length - 1);
        if (runningEl && ev.tool) { runningEl.outerHTML = html; runningEl = null; } else list.insertAdjacentHTML('beforeend', html);
        bindToggles(list, steps);
      }
    } else if (ev.type === 'verdict') {
      PHASES.forEach(([k]) => done.add(k));
      setPhases(done, null);
      $('#case-status', box).innerHTML = pill(ev.alert_status);
      ctx.lastInv = ev.investigation;
    } else if (ev.type === 'error') {
      toast('Investigation stopped', ev.message, 'error');
      list.insertAdjacentHTML('beforeend', `<li class="tl tl--error"><span class="tl__icon">${icon('x')}</span><div><div class="tl__title">Run failed</div><div class="tl__detail">${esc(ev.message)}</div></div></li>`);
    }
  };

  ctx.lastInv = null;
  try {
    await stream('/investigations/stream', { alert_id: alertId, engine }, onEvent, ctx.abort.signal);
  } catch (e) {
    if (e.name !== 'AbortError') toast('Investigation failed', e.message, 'error');
  }
  ctx.running = false;
  btn.classList.remove('is-busy');
  btn.disabled = false;
  if (ctx.lastInv) {
    const inv = ctx.lastInv;
    toast(OUTCOME_TEXT[inv.outcome] || inv.outcome, `${inv.investigation_id} - ${inv.confidence}% confidence`, inv.outcome === 'ATTACK_SUCCEEDED' ? 'error' : 'ok');
    appendVerdict(area, inv);
    emit('data:changed');
  }
}

function showInvestigation(inv, animate = true) {
  const area = $('#run-area', ctx.el);
  setPhases(new Set(PHASES.map(([k]) => k)), null);
  const steps = (inv.steps || []).map((s) => ({ ...s, state: s.ok === false ? 'error' : 'done' }));
  area.innerHTML = `<ol class="timeline" id="tl">${steps.map(stepHtml).join('')}</ol>`;
  if (!animate) $$('.tl', area).forEach((li) => { li.style.animation = 'none'; });
  bindToggles($('#tl', area), steps);
  appendVerdict(area, inv);
}

function renderReport(md) {
  return md.split('\n').map((line) => {
    const t = esc(line).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    if (line.startsWith('## ')) return `<h2>${t.slice(3)}</h2>`;
    if (line.startsWith('### ')) return `<h3>${t.slice(4)}</h3>`;
    if (line.startsWith('- ')) return `<li>${t.slice(2)}</li>`;
    return line.trim() ? `<p>${t}</p>` : '';
  }).join('').replace(/(<li>.*?<\/li>)+/g, (m) => `<ul>${m}</ul>`);
}

function appendVerdict(area, inv) {
  $$('.verdict, .report-wrap, .override', area).forEach((n) => n.remove());
  const ov = inv.human_override;
  area.insertAdjacentHTML('beforeend', `
    <div class="verdict verdict--${esc(inv.outcome)}">
      <div class="verdict__top">
        <span class="verdict__label">${OUTCOME_TEXT[inv.outcome] || label(inv.outcome)}</span>
        <span class="verdict__conf">confidence ${inv.confidence}%</span>
        <span class="verdict__id">${esc(inv.investigation_id)}</span>
      </div>
      <p class="verdict__summary">${esc(inv.summary)}</p>
      <div class="facts">
        <div><span>Tactic</span>${esc(inv.mitre_tactic || '-')}</div>
        <div><span>Technique</span>${esc(inv.mitre_technique || '-')}</div>
        <div><span>Response</span><div class="acts">${(inv.actions_taken || []).length ? inv.actions_taken.map((x) => `<span>${esc(label(x.type))} <span class="mono">${esc(x.target)}</span>${x.enforcement ? ` ${pill(x.enforcement)}` : ''}</span>`).join('') : 'None'}</div></div>
        <div><span>Duration</span><span class="mono">${inv.duration_ms ? `${(inv.duration_ms / 1000).toFixed(1)}s` : '-'}</span></div>
      </div>
      ${ov ? `<div class="notice mt-12"><div><b>${esc(ov.analyst)}</b> changed this from ${esc(label(ov.previous_outcome))} to ${esc(label(ov.outcome))} ${ago(ov.at)}. <span class="muted">"${esc(ov.notes)}"</span><div class="small muted mt-8">${ov.changes.map(esc).join(' &middot; ')}</div></div></div>` : ''}
    </div>
    <div class="report-wrap">
      <div class="row"><h3 class="section-title grow" style="margin:0">Report</h3><button class="btn btn--ghost btn--sm" id="copy-report">Copy as markdown</button></div>
      <div class="report mt-12">${renderReport(inv.report || '')}</div>
    </div>
    ${can('respond') ? `<div class="override">
      <h3 class="section-title">Override verdict</h3>
      <div class="override__grid">
        <label class="field"><span>Correct outcome</span><select class="select" id="ov-outcome">${Object.entries(OUTCOME_TEXT).map(([k, t]) => `<option value="${k}" ${k === inv.outcome ? 'disabled' : ''}>${t}</option>`).join('')}</select></label>
        <label class="field"><span>Justification</span><input class="input" id="ov-notes" placeholder="Reason for the change"></label>
        <button class="btn" id="ov-apply">Apply</button>
      </div>
      <p class="small muted" style="margin:8px 0 0">False positive / recon rolls back rules from this case. Compromise confirmed blocks the source IP.</p>
    </div>` : ''}`);
  const sel = $('#ov-outcome', area);
  const firstOpen = sel && [...sel.options].find((o) => !o.disabled);
  if (firstOpen) sel.value = firstOpen.value;
  $('#copy-report', area).onclick = async () => {
    try { await navigator.clipboard.writeText(inv.report || ''); toast('Report copied'); } catch { toast('Clipboard unavailable', '', 'error'); }
  };
  if ($('#ov-apply', area)) $('#ov-apply', area).onclick = (e) => busy(e.currentTarget, async () => {
    const notes = $('#ov-notes', area).value.trim();
    if (notes.length < 4) { $('#ov-notes', area).classList.add('is-invalid'); toast('Reason required', 'Add a short note for the audit log.', 'error'); return; }
    try {
      const r = await api(`/investigations/${inv.investigation_id}/override`, { method: 'POST', body: { outcome: sel.value, notes } });
      toast('Verdict overridden', r.changes.join('. '), 'ok', 6000);
      emit('data:changed');
      ctx.running = false;
      await loadQueue();
      paintQueue();
      await openCase(inv.alert_id, false, true);
    } catch (err) { toast('Override failed', err.message, 'error'); }
  });
  hydrateIcons(area);
}