import { $, $$, api, esc, ago, stamp, num, label, emptyState, toast, busy, emit, can, modal, closeLayer, sev } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

// Custom detections: Sigma rules written for this environment. They run on
// every ingested log alongside the SigmaHQ bundle, and a draft can be tested
// against pasted lines or replayed over stored telemetry before it goes live.

const STARTER = `title: SSH login for a disabled service account
id: 00000000-0000-0000-0000-000000000000
status: experimental
description: A service account that should never log in interactively accepted a password.
logsource:
  product: linux
  service: sshd
detection:
  selection:
    message|contains: 'Accepted password for'
  accounts:
    message|contains:
      - ' for svc_'
      - ' for backup '
  condition: selection and accounts
level: high
tags:
  - attack.initial_access
  - attack.t1078.003
falsepositives:
  - Break-glass access during an outage
`;

let ctx = null;

export async function render({ el, query }) {
  ctx = { el, rules: [], editing: null, lintSeq: 0, open: query.r || null };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Detections</h1>
        <p class="page-sub">Your own Sigma rules. They run on every log that arrives, next to the SigmaHQ community rules, and raise alerts like any other detection.</p>
      </div>
      <div class="page-actions">
        <a class="btn btn--ghost" href="#/intel?tab=detect">${icon('shield')}Built-in rules</a>
        ${can('respond') ? `<button class="btn btn--primary" id="dt-new">${icon('plus')}New rule</button>` : ''}
      </div>
    </div>
    <div id="dt-body" class="reveal"><div class="panel" style="padding:18px"><div class="skeleton" style="height:160px"></div></div></div>`;
  hydrateIcons(el);
  const nb = $('#dt-new', el);
  if (nb) nb.onclick = () => openEditor(null);
  await load();
  if (ctx.open) { const r = ctx.rules.find((x) => x.rule_id === ctx.open); if (r) openEditor(r); }
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) load(); }

async function load() {
  try { ctx.rules = await api('/detections/custom'); } catch (e) { $('#dt-body', ctx.el).innerHTML = `<section class="panel">${emptyState('Could not load rules', e.message, 'alert')}</section>`; return; }
  if (!document.body.contains(ctx.el)) return;
  const respond = can('respond');
  const rows = ctx.rules;
  const on = rows.filter((r) => r.enabled !== false).length;
  const hits = rows.reduce((a, r) => a + (r.hits || 0), 0);
  $('#dt-body', ctx.el).innerHTML = `
    <div class="kpis grid grid-kpi">
      <div class="kpi"><div class="kpi__label">Rules</div><div class="kpi__value">${num(rows.length)}</div><div class="kpi__foot">${num(on)} enabled</div></div>
      <div class="kpi"><div class="kpi__label">Matches</div><div class="kpi__value">${num(hits)}</div><div class="kpi__foot">since each rule was created</div></div>
      <div class="kpi"><div class="kpi__label">Firing</div><div class="kpi__value">${num(rows.filter((r) => r.hits).length)}</div><div class="kpi__foot">rules with at least one match</div></div>
      <div class="kpi"><div class="kpi__label">Silent</div><div class="kpi__value">${num(rows.filter((r) => !r.hits && r.enabled !== false).length)}</div><div class="kpi__foot">enabled, never matched</div></div>
    </div>
    <section class="panel mt-12">
      ${rows.length ? `<div class="table-wrap"><table class="table">
        <thead><tr><th>Rule</th><th>Level</th><th class="hide-sm">Technique</th><th class="num">Matches</th><th class="hide-sm">Last match</th><th>Enabled</th></tr></thead>
        <tbody class="rows-in">${rows.map((r, i) => `<tr class="is-clickable" data-rule="${esc(r.rule_id)}" style="--i:${Math.min(i, 30)}">
          <td><span class="cell-main">${esc(r.title)}</span><span class="cell-sub mono">${esc(r.rule_id)} &middot; ${esc(r.target || 'any log')} &middot; ${esc(r.updated_by || r.created_by)}</span></td>
          <td>${sev(levelSev(r.level))}</td>
          <td class="hide-sm mono small">${esc(r.technique || '-')}</td>
          <td class="num mono">${num(r.hits || 0)}</td>
          <td class="hide-sm small" title="${stamp(r.last_hit_at)}">${r.last_hit_at ? ago(r.last_hit_at) : '<span class="muted">never</span>'}</td>
          <td>${respond ? `<button class="switch" role="switch" aria-checked="${r.enabled !== false}" data-toggle="${esc(r.rule_id)}" aria-label="Enabled"></button>` : r.enabled !== false ? 'Yes' : 'No'}</td>
        </tr>`).join('')}</tbody></table></div>`
      : `${emptyState('No custom rules yet', 'Write a Sigma rule for something specific to your environment: a service account, an internal URL, an admin tool you never use.', 'shield')}${respond ? '<div class="row" style="justify-content:center;padding-bottom:24px"><button class="btn btn--primary" id="dt-first">Write the first rule</button></div>' : ''}`}
    </section>`;
  hydrateIcons(ctx.el);
  const first = $('#dt-first', ctx.el);
  if (first) first.onclick = () => openEditor(null);
  $$('[data-rule]', ctx.el).forEach((tr) => { tr.onclick = (e) => { if (e.target.closest('[data-toggle]')) return; openEditor(rows.find((r) => r.rule_id === tr.dataset.rule)); }; });
  $$('[data-toggle]', ctx.el).forEach((b) => {
    b.onclick = async (e) => {
      e.stopPropagation();
      const next = b.getAttribute('aria-checked') !== 'true';
      b.setAttribute('aria-checked', String(next));
      try { await api(`/detections/custom/${encodeURIComponent(b.dataset.toggle)}`, { method: 'PUT', body: { enabled: next } }); toast(next ? 'Rule enabled' : 'Rule disabled', b.dataset.toggle, 'ok'); load(); }
      catch (err) { b.setAttribute('aria-checked', String(!next)); toast('Not changed', err.message, 'error'); }
    };
  });
}

const levelSev = (l) => ({ critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', informational: 'LOW' }[String(l).toLowerCase()] || 'MEDIUM');

function openEditor(rule) {
  const respond = can('respond');
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">${rule ? esc(rule.title) : 'New detection rule'}</h2>${rule ? `<span class="mono small muted">${esc(rule.rule_id)}</span>` : ''}</div>
    <div class="modal__body dt-ed">
      <div class="dt-ed__code">
        <div class="dt-ed__bar"><span class="small muted">Sigma YAML</span><span class="dt-lint" id="dt-lint"></span></div>
        <textarea class="textarea mono dt-yaml" id="dt-yaml" spellcheck="false" ${respond ? '' : 'readonly'}>${esc(rule ? rule.yaml : STARTER)}</textarea>
        <ul class="dt-msgs" id="dt-msgs"></ul>
      </div>
      <div class="dt-ed__test">
        <div class="seg dt-src"><button class="is-on" data-src="paste">Paste lines</button><button data-src="stored">Stored logs</button></div>
        <div id="dt-src-paste" class="mt-8">
          <textarea class="textarea mono" id="dt-lines" rows="7" spellcheck="false" placeholder="Oct 18 09:12:44 bastion sshd[2211]: Accepted password for svc_backup from 203.0.113.9 port 51022 ssh2"></textarea>
          <label class="field mt-8"><span>Host IP the lines came from</span><input class="input mono" id="dt-host" value="10.0.0.10"></label>
        </div>
        <div id="dt-src-stored" class="mt-8" hidden>
          <label class="field"><span>Replay over the last</span><select class="select" id="dt-hours"><option value="24">24 hours</option><option value="168" selected>7 days</option><option value="720">30 days</option><option value="2160">90 days</option></select></label>
          <p class="small muted">Runs the draft over stored telemetry without raising alerts.</p>
        </div>
        <button class="btn btn--sm mt-8" id="dt-test">${icon('play')}Test rule</button>
        <div id="dt-result" class="dt-result"></div>
      </div>
    </div>
    <div class="modal__foot">
      ${rule && respond ? `<button class="btn btn--ghost btn--danger-text" id="dt-del">${icon('trash')}Delete</button><span class="grow"></span>` : ''}
      <span class="form-error" id="dt-err"></span><button class="btn btn--ghost" data-close>Close</button>
      ${respond ? `<button class="btn btn--primary" id="dt-save">${icon('check')}${rule ? 'Save changes' : 'Create rule'}</button>` : ''}
    </div>`);
  panel.classList.add('modal--xl');
  hydrateIcons(panel);
  const yaml = $('#dt-yaml', panel);
  let src = 'paste';
  let timer = null;
  const lint = async () => {
    const seq = ++ctx.lintSeq;
    let r;
    try { r = await api('/detections/custom/lint', { method: 'POST', body: { yaml: yaml.value } }); } catch (e) { r = { ok: false, errors: [e.message], warnings: [] }; }
    if (seq !== ctx.lintSeq || !document.body.contains(panel)) return;
    paintLint(panel, r);
  };
  yaml.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(lint, 350); });
  yaml.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') { e.preventDefault(); const s = yaml.selectionStart; yaml.setRangeText('  ', s, yaml.selectionEnd, 'end'); }
  });
  lint();
  $$('[data-src]', panel).forEach((b) => { b.onclick = () => { src = b.dataset.src; $$('[data-src]', panel).forEach((x) => x.classList.toggle('is-on', x === b)); $('#dt-src-paste', panel).hidden = src !== 'paste'; $('#dt-src-stored', panel).hidden = src !== 'stored'; }; });
  $('#dt-test', panel).onclick = (e) => busy(e.currentTarget, async () => {
    const body = { yaml: yaml.value };
    if (src === 'paste') {
      body.lines = $('#dt-lines', panel).value;
      body.host_ip = $('#dt-host', panel).value.trim();
      if (!body.lines.trim()) { $('#dt-lines', panel).focus(); return; }
    } else body.hours = Number($('#dt-hours', panel).value);
    try { paintResult(panel, await api('/detections/custom/test', { method: 'POST', body })); } catch (err) { $('#dt-result', panel).innerHTML = `<div class="notice notice--warn">${icon('alert')}<span>${esc(err.message)}</span></div>`; hydrateIcons(panel); }
  });
  const save = $('#dt-save', panel);
  if (save) save.onclick = () => busy(save, async () => {
    try {
      const r = rule ? await api(`/detections/custom/${encodeURIComponent(rule.rule_id)}`, { method: 'PUT', body: { yaml: yaml.value } }) : await api('/detections/custom', { method: 'POST', body: { yaml: yaml.value } });
      closeLayer();
      toast(rule ? 'Rule saved' : 'Rule created', `${r.title} is ${r.enabled === false ? 'disabled' : 'live on new logs'}`, 'ok');
      emit('data:changed');
      load();
    } catch (err) { $('#dt-err', panel).textContent = err.message; }
  });
  const del = $('#dt-del', panel);
  if (del) del.onclick = () => busy(del, async () => {
    if (del.dataset.armed !== '1') { del.dataset.armed = '1'; del.innerHTML = `${icon('trash')}Click again to delete`; return; }
    try { await api(`/detections/custom/${encodeURIComponent(rule.rule_id)}`, { method: 'DELETE' }); closeLayer(); toast('Rule deleted', rule.title, 'ok'); load(); } catch (err) { $('#dt-err', panel).textContent = err.message; }
  });
}

function paintLint(panel, r) {
  const badge = $('#dt-lint', panel);
  badge.className = `dt-lint ${r.ok ? (r.warnings.length ? 'is-warn' : 'is-ok') : 'is-bad'}`;
  badge.innerHTML = r.ok ? `${icon('check')}${r.warnings.length ? `${r.warnings.length} warning${r.warnings.length === 1 ? '' : 's'}` : 'Valid'}` : `${icon('x')}${r.errors.length} error${r.errors.length === 1 ? '' : 's'}`;
  const meta = r.rule ? `<li class="dt-msg dt-msg--info">${esc(r.rule.title)} &middot; ${esc(r.rule.level)}${r.rule.target ? ` &middot; ${esc(r.rule.target)}` : ''}${r.rule.technique ? ` &middot; ${esc(r.rule.technique)}` : ''}</li>` : '';
  $('#dt-msgs', panel).innerHTML = meta + r.errors.map((m) => `<li class="dt-msg dt-msg--err">${esc(m)}</li>`).join('') + r.warnings.map((m) => `<li class="dt-msg dt-msg--warn">${esc(m)}</li>`).join('');
}

function paintResult(panel, r) {
  const box = $('#dt-result', panel);
  if (!r.lint.ok) { box.innerHTML = `<div class="notice notice--warn">${icon('alert')}<span>Fix the lint errors first.</span></div>`; hydrateIcons(box); return; }
  box.innerHTML = `
    <div class="dt-res__head ${r.hits ? 'is-hit' : ''}"><b class="mono">${num(r.hits)}</b> match${r.hits === 1 ? '' : 'es'} in ${num(r.parsed)} lines <span class="small muted">(${esc(r.source)}${r.rejected ? `, ${r.rejected} unparsed` : ''}, ${r.ms} ms)</span></div>
    ${r.matches.length ? `<ul class="dt-hits">${r.matches.map((m, i) => `<li style="--i:${Math.min(i, 20)}"><div class="small muted mono">${esc(stamp(m.logged_at))} &middot; ${esc(m.host_ip)}${m.client_ip ? ` &larr; ${esc(m.client_ip)}` : ''} &middot; ${esc(label(m.log_type))}</div><code>${esc(m.line)}</code></li>`).join('')}</ul>`
    : `<p class="small muted">No line matched. ${r.parsed ? 'Check the field names (message, client_ip, url, status...) and the modifiers.' : 'There were no lines to test.'}</p>`}`;
}