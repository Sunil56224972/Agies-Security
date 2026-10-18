import { $, $$, api, stream, esc, ago, stamp, num, label, emptyState, toast, busy, emit, can, modal, closeLayer, pill } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

// Workflows chain the same services the console uses (investigate, intel, hunt,
// cases, containment, notifications) into repeatable playbooks. Runs stream
// step by step and are kept for review.

let ctx = null;
const STATUS_PILL = { SUCCEEDED: 'ENFORCED', PARTIAL: 'PENDING', FAILED: 'FAILED', RUNNING: 'INVESTIGATING' };
const runPill = (s) => pill(STATUS_PILL[s] || s, label(s));

export async function render({ el, query, navigate }) {
  ctx = { el, navigate, tab: ['runs', 'templates'].includes(query.tab) ? query.tab : 'saved', catalog: null, list: [] };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Workflows</h1>
        <p class="page-sub">Chain investigation, intel, hunting, cases and containment into a playbook you can rerun. Containment still goes through the approval policy.</p>
      </div>
      <div class="page-actions">${can('respond') ? `<button class="btn btn--primary" id="wf-new">${icon('plus')}New workflow</button>` : ''}</div>
    </div>
    <div class="tabs tabs--page" role="tablist" id="wf-tabs">
      <button class="tab" role="tab" data-tab="saved">Workflows <span class="tab__n mono" id="wf-n"></span></button>
      <button class="tab" role="tab" data-tab="templates">Templates</button>
      <button class="tab" role="tab" data-tab="runs">Run history</button>
    </div>
    <div id="wf-body" class="reveal"><div class="panel" style="padding:18px"><div class="stack">${'<div class="skeleton" style="height:72px"></div>'.repeat(3)}</div></div></div>`;
  $$('[data-tab]', el).forEach((b) => { b.onclick = () => { ctx.tab = b.dataset.tab; history.replaceState(null, '', ctx.tab === 'saved' ? '#/workflows' : `#/workflows?tab=${ctx.tab}`); load(); }; });
  const nb = $('#wf-new', el);
  if (nb) nb.onclick = () => openEditor(null);
  try { ctx.catalog = await api('/workflows/catalog'); } catch (e) { $('#wf-body', el).innerHTML = `<section class="panel">${emptyState('Workflows are unavailable', e.message, 'alert')}</section>`; return; }
  await load();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el) && ctx.tab !== 'templates') load(); }

async function load() {
  const { el } = ctx;
  $$('[data-tab]', el).forEach((b) => { const on = b.dataset.tab === ctx.tab; b.classList.toggle('is-on', on); b.setAttribute('aria-selected', String(on)); });
  try {
    if (ctx.tab === 'templates') paintTemplates();
    else if (ctx.tab === 'runs') paintRuns(await api('/workflows/runs?limit=100'));
    else { ctx.list = await api('/workflows'); paintSaved(); }
  } catch (e) { $('#wf-body', el).innerHTML = `<section class="panel">${emptyState('Could not load workflows', e.message, 'alert')}</section>`; }
  if (ctx.tab === 'saved') $('#wf-n', el).textContent = ctx.list.length || '';
  hydrateIcons(el);
}

const stepLabel = (t) => (ctx.catalog.steps[t] ? ctx.catalog.steps[t].label : t);

function chain(steps) {
  return `<ol class="wf-chain">${steps.map((s) => `<li class="${ctx.catalog.steps[s.type] && ctx.catalog.steps[s.type].write ? 'is-write' : ''}" title="${esc(s.when ? `Only when ${s.when.path} ${s.when.op} ${s.when.value ?? ''}` : '')}">${esc(s.name || stepLabel(s.type))}${s.when ? '<i>if</i>' : ''}</li>`).join('')}</ol>`;
}

function paintTemplates() {
  const respond = can('respond');
  $('#wf-body', ctx.el).innerHTML = `<div class="wf-grid">${ctx.catalog.templates.map((t, i) => `
    <article class="wf-card wf-card--tpl" style="--i:${i}">
      <div class="wf-card__top"><span class="wf-card__ic">${icon('zap')}</span><h3>${esc(t.name)}</h3></div>
      <p class="wf-card__desc">${esc(t.description)}</p>
      ${chain(t.steps)}
      <div class="wf-card__foot">
        <span class="small muted">${t.steps.length} steps &middot; input: ${t.inputs.map((x) => esc(x.label)).join(', ')}</span>
        ${respond ? `<button class="btn btn--sm btn--primary" data-use="${esc(t.key)}">${icon('plus')}Use template</button>` : ''}
      </div>
    </article>`).join('')}</div>`;
  $$('[data-use]', ctx.el).forEach((b) => {
    b.onclick = () => busy(b, async () => {
      try {
        const wf = await api('/workflows', { method: 'POST', body: { template: b.dataset.use } });
        toast('Workflow added', `${wf.name} is ready to run`, 'ok');
        ctx.tab = 'saved'; history.replaceState(null, '', '#/workflows');
        await load();
      } catch (e) { toast('Not added', e.message, 'error'); }
    });
  });
}

function paintSaved() {
  const respond = can('respond');
  const rows = ctx.list;
  if (!rows.length) {
    $('#wf-body', ctx.el).innerHTML = `<section class="panel wf-empty">
      ${emptyState('No workflows yet', 'Start from a template: alert to incident, IOC triage or attacker sweep. You can edit every step afterwards.', 'zap')}
      ${respond ? '<div class="row" style="justify-content:center;padding-bottom:24px"><button class="btn btn--primary" id="wf-go-tpl">Browse templates</button></div>' : ''}
    </section>`;
    const g = $('#wf-go-tpl', ctx.el);
    if (g) g.onclick = () => { ctx.tab = 'templates'; load(); };
    return;
  }
  $('#wf-body', ctx.el).innerHTML = `<div class="wf-grid">${rows.map((w, i) => `
    <article class="wf-card ${w.enabled === false ? 'is-off' : ''}" style="--i:${i}" data-wf="${esc(w.workflow_id)}">
      <div class="wf-card__top">
        <h3>${esc(w.name)}</h3>
        ${respond ? `<button class="switch" role="switch" aria-checked="${w.enabled !== false}" data-toggle="${esc(w.workflow_id)}" title="${w.enabled !== false ? 'Enabled' : 'Disabled'}"></button>` : ''}
      </div>
      ${w.description ? `<p class="wf-card__desc">${esc(w.description)}</p>` : ''}
      ${chain(w.steps || [])}
      <div class="wf-card__stats small">
        <span><b class="mono">${num(w.runs || 0)}</b> runs</span>
        ${w.last_run_at ? `<span>last ${runPill(w.last_status)} <span class="muted" title="${stamp(w.last_run_at)}">${ago(w.last_run_at)}</span></span>` : '<span class="muted">never run</span>'}
        <span class="muted mono">${esc(w.workflow_id)}</span>
      </div>
      <div class="wf-card__foot">
        ${respond ? `<button class="btn btn--sm btn--primary" data-run="${esc(w.workflow_id)}" ${w.enabled === false ? 'disabled' : ''}>${icon('play')}Run</button>
        <button class="btn btn--sm btn--ghost" data-edit="${esc(w.workflow_id)}">${icon('edit')}Edit</button>` : ''}
        <button class="btn btn--sm btn--ghost" data-hist="${esc(w.workflow_id)}">${icon('activity')}Runs</button>
        ${respond ? `<button class="icon-btn" data-del="${esc(w.workflow_id)}" title="Delete">${icon('trash')}</button>` : ''}
      </div>
    </article>`).join('')}</div>`;
  const find = (id) => rows.find((w) => w.workflow_id === id);
  $$('[data-run]', ctx.el).forEach((b) => { b.onclick = () => openRun(find(b.dataset.run)); });
  $$('[data-edit]', ctx.el).forEach((b) => { b.onclick = () => openEditor(find(b.dataset.edit)); });
  $$('[data-hist]', ctx.el).forEach((b) => { b.onclick = async () => { ctx.tab = 'runs'; $$('[data-tab]', ctx.el).forEach((x) => x.classList.toggle('is-on', x.dataset.tab === 'runs')); paintRuns(await api(`/workflows/runs?workflow_id=${encodeURIComponent(b.dataset.hist)}&limit=100`), find(b.dataset.hist)); hydrateIcons(ctx.el); }; });
  $$('[data-toggle]', ctx.el).forEach((b) => {
    b.onclick = async () => {
      const on = b.getAttribute('aria-checked') !== 'true';
      b.setAttribute('aria-checked', String(on));
      try { await api(`/workflows/${encodeURIComponent(b.dataset.toggle)}/enabled`, { method: 'POST', body: { enabled: on } }); load(); } catch (e) { b.setAttribute('aria-checked', String(!on)); toast('Not changed', e.message, 'error'); }
    };
  });
  $$('[data-del]', ctx.el).forEach((b) => { b.onclick = () => confirmDelete(find(b.dataset.del)); });
}

function confirmDelete(w) {
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Delete ${esc(w.name)}?</h2></div>
    <div class="modal__body"><p class="small muted" style="margin:0">Past runs stay in the history. Cases, hunts and rules it created are not touched.</p></div>
    <div class="modal__foot"><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--danger" id="wf-del-go">Delete</button></div>`);
  $('#wf-del-go', panel).onclick = () => busy($('#wf-del-go', panel), async () => {
    try { await api(`/workflows/${encodeURIComponent(w.workflow_id)}`, { method: 'DELETE' }); closeLayer(); toast('Workflow deleted', w.name, 'ok'); load(); } catch (e) { toast('Not deleted', e.message, 'error'); }
  });
}

// ---- Running ---------------------------------------------------------------------
function openRun(w) {
  const inputs = w.inputs || [];
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Run ${esc(w.name)}</h2></div>
    <form class="modal__body" id="wf-run-form" novalidate>
      ${inputs.length ? inputs.map((i) => `<label class="field"><span>${esc(i.label)}${i.required ? '' : ' <small>(optional)</small>'}</span>${i.multiline || i.key === 'text'
        ? `<textarea class="textarea mono" name="${esc(i.key)}" rows="6" ${i.required ? 'required' : ''}></textarea>`
        : `<input class="input mono" name="${esc(i.key)}" ${i.required ? 'required' : ''} autocomplete="off">`}</label>`).join('') : '<p class="small muted">This workflow takes no input.</p>'}
      <div class="wf-steps" id="wf-live" hidden></div>
    </form>
    <div class="modal__foot"><span class="form-error" id="wf-run-err"></span><button class="btn btn--ghost" data-close>Close</button><button class="btn btn--primary" id="wf-run-go">${icon('play')}Run now</button></div>`);
  panel.classList.add('modal--wide');
  const go = (e) => {
    e.preventDefault();
    const form = $('#wf-run-form', panel);
    const input = Object.fromEntries(new FormData(form));
    const missing = inputs.find((i) => i.required && !String(input[i.key] || '').trim());
    if (missing) { $('#wf-run-err', panel).textContent = `${missing.label} is required`; return; }
    $('#wf-run-err', panel).textContent = '';
    busy($('#wf-run-go', panel), () => execute(w, input, panel));
  };
  $('#wf-run-form', panel).onsubmit = go;
  $('#wf-run-go', panel).onclick = go;
}

async function execute(w, input, panel) {
  const live = $('#wf-live', panel);
  $$('.field', panel).forEach((f) => f.classList.add('is-locked'));
  live.hidden = false;
  live.innerHTML = '';
  let steps = [];
  let final = null; let failed = null;
  try {
    await stream(`/workflows/${encodeURIComponent(w.workflow_id)}/run/stream`, { input }, (e) => {
      if (e.type === 'start') { steps = e.steps; live.innerHTML = `<div class="wf-run__head"><span class="mono small">${esc(e.run_id)}</span><span class="wf-run__status" id="wf-st">${runPill('RUNNING')}</span></div>${steps.map((s, i) => stepRow(s, i)).join('')}`; }
      else if (e.type === 'step') { const row = $(`[data-step="${e.index}"]`, live); if (row) { const tmp = document.createElement('div'); tmp.innerHTML = stepRow(e, e.index); row.replaceWith(tmp.firstElementChild); } }
      else if (e.type === 'finish') { const st = $('#wf-st', live); if (st) st.innerHTML = `${runPill(e.status)} <span class="mono small muted">${(e.duration_ms / 1000).toFixed(1)} s</span>`; }
      else if (e.type === 'done') final = e.result;
      else if (e.type === 'error') failed = e.message;
      hydrateIcons(live);
    });
  } catch (err) { failed = err.message; }
  if (failed) { $('#wf-run-err', panel).textContent = failed; $$('.field', panel).forEach((f) => f.classList.remove('is-locked')); return; }
  if (final) {
    toast(`Run ${label(final.status).toLowerCase()}`, `${w.name} in ${(final.duration_ms / 1000).toFixed(1)} s`, final.status === 'FAILED' ? 'error' : 'ok');
    emit('data:changed');
    const btn = $('#wf-run-go', panel);
    btn.innerHTML = `${icon('rotate')}Run again`;
    $$('.field', panel).forEach((f) => f.classList.remove('is-locked'));
  }
}

const STEP_IC = { pending: 'dot', running: 'refresh', ok: 'check', failed: 'x', skipped: 'arrow', cancelled: 'x' };
function stepRow(s, i) {
  const out = s.output && !s.output.truncated ? links(s.output) : '';
  return `<div class="wf-step wf-step--${esc(s.status)}" data-step="${i}">
    <span class="wf-step__ic">${icon(STEP_IC[s.status] || 'dot')}</span>
    <div class="wf-step__main">
      <div class="wf-step__name">${esc(s.name || stepLabel(s.type))}<span class="mono muted small">${esc(s.id)}</span>${s.ms != null ? `<span class="mono muted small wf-step__ms">${s.ms < 1000 ? `${s.ms} ms` : `${(s.ms / 1000).toFixed(1)} s`}</span>` : ''}</div>
      ${s.summary ? `<div class="small">${esc(s.summary)}</div>` : ''}
      ${s.error ? `<div class="small wf-step__err">${esc(s.error)}</div>` : ''}
      ${out}
    </div>
  </div>`;
}

// Click-through links for things a step created.
function links(o) {
  const a = [];
  if (o.case_id) a.push(`<a href="#/cases/${encodeURIComponent(o.case_id)}">${icon('file')}${esc(o.case_id)}</a>`);
  if (o.investigation_id && o.attacker_ip) a.push(`<a href="#/ip/${encodeURIComponent(o.attacker_ip)}">${icon('globe')}${esc(o.attacker_ip)}</a>`);
  if (o.run_id && o.hits != null) a.push(`<a href="#/hunts">${icon('search')}Hunt ${esc(o.run_id)}</a>`);
  for (const q of o.queued || []) a.push(`<a href="#/approvals">${icon('shieldCheck')}${esc(q.approval_id)}</a>`);
  for (const r of o.executed || []) a.push(`<a href="#/containment">${icon('shield')}${esc(r.rule_id)}</a>`);
  return a.length ? `<div class="row wrap small wf-step__links">${a.join('')}</div>` : '';
}

function paintRuns(rows, only) {
  const body = $('#wf-body', ctx.el);
  body.innerHTML = `<section class="panel">
    ${only ? `<div class="toolbar"><span class="small">Runs of <b>${esc(only.name)}</b></span><button class="btn btn--sm btn--ghost toolbar__end" id="wf-all">Show all</button></div>` : ''}
    ${rows.length ? `<div class="table-wrap"><table class="table">
      <thead><tr><th>Workflow</th><th>Status</th><th class="hide-sm">Steps</th><th>Started</th><th class="hide-sm">Duration</th></tr></thead>
      <tbody class="rows-in">${rows.map((r, i) => `<tr class="is-clickable" data-run-id="${esc(r.run_id)}" style="--i:${Math.min(i, 30)}">
        <td><span class="cell-main">${esc(r.name)}</span><span class="cell-sub mono">${esc(r.run_id)} &middot; ${esc(r.run_by)}</span></td>
        <td>${runPill(r.status)}</td>
        <td class="hide-sm"><span class="wf-dots">${(r.steps || []).map((s) => `<i class="wf-dot wf-dot--${esc(s.status)}" title="${esc(`${s.id}: ${s.status}`)}"></i>`).join('')}</span></td>
        <td class="small" title="${stamp(r.created_at)}">${ago(r.created_at)}</td>
        <td class="hide-sm mono small">${r.duration_ms != null ? `${(r.duration_ms / 1000).toFixed(1)} s` : '-'}</td>
      </tr>`).join('')}</tbody></table></div>` : emptyState('No runs yet', 'Every run is kept with each step\'s result, so you can see what a workflow did and when.', 'activity')}
  </section>`;
  const all = $('#wf-all', body);
  if (all) all.onclick = () => load();
  $$('[data-run-id]', body).forEach((tr) => { tr.onclick = () => showRun(rows.find((r) => r.run_id === tr.dataset.runId)); });
}

function showRun(r) {
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">${esc(r.name)}</h2></div>
    <div class="modal__body">
      <div class="wf-run__head"><span class="mono small">${esc(r.run_id)} &middot; ${esc(r.run_by)} &middot; ${stamp(r.created_at)}</span><span>${runPill(r.status)}</span></div>
      ${Object.keys(r.input || {}).length ? `<pre class="snippet is-code">${esc(Object.entries(r.input).map(([k, v]) => `${k}: ${String(v).slice(0, 400)}`).join('\n'))}</pre>` : ''}
      <div class="wf-steps mt-12">${(r.steps || []).map((s, i) => stepRow(s, i)).join('')}</div>
    </div>
    <div class="modal__foot"><button class="btn btn--ghost" data-close>Close</button></div>`);
  panel.classList.add('modal--wide');
  hydrateIcons(panel);
}

// ---- Editor ------------------------------------------------------------------------
// A form for the common case (name, inputs, ordered steps with parameters and an
// optional condition) and a JSON tab for everything else.
function openEditor(w) {
  const draft = w ? JSON.parse(JSON.stringify({ name: w.name, description: w.description, inputs: w.inputs || [], steps: w.steps || [] }))
    : { name: '', description: '', inputs: [{ key: 'ip', label: 'Address', required: true }], steps: [{ id: 'intel', type: 'intel_lookup', params: { values: '{{input.ip}}' } }] };
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">${w ? `Edit ${esc(w.name)}` : 'New workflow'}</h2>
      <div class="seg wf-mode"><button class="is-on" data-mode="form">Steps</button><button data-mode="json">JSON</button></div></div>
    <div class="modal__body" id="wf-ed"></div>
    <div class="modal__foot"><span class="form-error" id="wf-ed-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="wf-ed-go">${icon('check')}Save</button></div>`);
  panel.classList.add('modal--wide');
  let mode = 'form';
  const ed = $('#wf-ed', panel);

  const paintForm = () => {
    const types = Object.entries(ctx.catalog.steps);
    ed.innerHTML = `
      <div class="form-grid">
        <label class="field"><span>Name</span><input class="input" id="wf-name" maxlength="120" value="${esc(draft.name)}" placeholder="e.g. Brute force follow-up"></label>
        <label class="field"><span>Inputs <small>key:Label, * marks required</small></span><input class="input mono" id="wf-inputs" value="${esc(draft.inputs.map((i) => `${i.key}:${i.label}${i.required ? '*' : ''}`).join(', '))}" placeholder="ip:Attacker IP*"></label>
        <label class="field span-2"><span>Description</span><input class="input" id="wf-desc" maxlength="1000" value="${esc(draft.description || '')}"></label>
      </div>
      <p class="small muted wf-help">Reference inputs as <code class="code">{{input.key}}</code> and earlier results as <code class="code">{{steps.id.field}}</code>.</p>
      <ol class="wf-ed-steps">${draft.steps.map((s, n) => {
        const def = ctx.catalog.steps[s.type] || { fields: [] };
        return `<li class="wf-ed-step" data-n="${n}">
          <div class="wf-ed-step__head">
            <span class="wf-ed-step__n mono">${n + 1}</span>
            <input class="input mono wf-ed-id" value="${esc(s.id)}" maxlength="31" aria-label="Step id">
            <select class="select wf-ed-type" aria-label="Step type">${types.map(([k, t]) => `<option value="${k}" ${k === s.type ? 'selected' : ''}>${esc(t.label)}${t.write ? ' *' : ''}</option>`).join('')}</select>
            <button class="icon-btn" data-up="${n}" title="Move up" ${n === 0 ? 'disabled' : ''}>${icon('arrow')}</button>
            <button class="icon-btn" data-rm="${n}" title="Remove step">${icon('trash')}</button>
          </div>
          <p class="small muted">${esc(def.help || '')}</p>
          <div class="wf-ed-fields">${def.fields.map((f) => {
            const v = s.params && s.params[f.key] != null ? String(s.params[f.key]) : '';
            return `<label class="field"><span>${esc(f.label)}${f.required ? ' *' : ''}</span>${f.options
              ? `<select class="select" data-p="${f.key}"><option value=""></option>${f.options.map((o) => `<option ${o === v ? 'selected' : ''}>${o}</option>`).join('')}</select>`
              : f.type === 'bool' ? `<select class="select" data-p="${f.key}"><option value=""></option><option value="true" ${v === 'true' ? 'selected' : ''}>Yes</option><option value="false" ${v === 'false' ? 'selected' : ''}>No</option></select>`
              : `<input class="input mono" data-p="${f.key}" value="${esc(v)}">`}</label>`;
          }).join('')}</div>
          <div class="wf-ed-when">
            <span class="small muted">Run only if</span>
            <input class="input mono" data-w="path" placeholder="steps.intel.flagged" value="${esc(s.when ? s.when.path : '')}">
            <select class="select" data-w="op"><option value=""></option>${ctx.catalog.operators.map((o) => `<option ${s.when && s.when.op === o ? 'selected' : ''}>${o}</option>`).join('')}</select>
            <input class="input mono" data-w="value" placeholder="value" value="${esc(s.when && s.when.value != null ? s.when.value : '')}">
            <label class="row small"><input type="checkbox" data-coe ${s.continue_on_error ? 'checked' : ''}>Continue on error</label>
          </div>
        </li>`;
      }).join('')}</ol>
      <button class="btn btn--sm" id="wf-add">${icon('plus')}Add step</button>`;
    hydrateIcons(ed);
    $('#wf-add', ed).onclick = (e) => { e.preventDefault(); readForm(); draft.steps.push({ id: `s${draft.steps.length + 1}`, type: 'notify', params: {} }); paintForm(); };
    $$('[data-rm]', ed).forEach((b) => { b.onclick = (e) => { e.preventDefault(); readForm(); draft.steps.splice(Number(b.dataset.rm), 1); paintForm(); }; });
    $$('[data-up]', ed).forEach((b) => { b.onclick = (e) => { e.preventDefault(); readForm(); const n = Number(b.dataset.up); [draft.steps[n - 1], draft.steps[n]] = [draft.steps[n], draft.steps[n - 1]]; paintForm(); }; });
    $$('.wf-ed-type', ed).forEach((s) => { s.onchange = () => { readForm(); const st = draft.steps[Number(s.closest('[data-n]').dataset.n)]; st.type = s.value; st.params = {}; paintForm(); }; });
  };

  const readForm = () => {
    if (mode !== 'form') return;
    draft.name = $('#wf-name', ed).value.trim();
    draft.description = $('#wf-desc', ed).value.trim();
    draft.inputs = $('#wf-inputs', ed).value.split(',').map((x) => x.trim()).filter(Boolean).map((x) => {
      const req = x.endsWith('*'); const [key, ...rest] = x.replace(/\*$/, '').split(':');
      return { key: key.trim(), label: rest.join(':').trim() || key.trim(), required: req, multiline: key.trim() === 'text' };
    });
    draft.steps = $$('.wf-ed-step', ed).map((li) => {
      const step = { id: $('.wf-ed-id', li).value.trim(), type: $('.wf-ed-type', li).value, params: {} };
      const def = ctx.catalog.steps[step.type];
      $$('[data-p]', li).forEach((x) => {
        if (x.value === '') return;
        const f = def.fields.find((ff) => ff.key === x.dataset.p);
        step.params[x.dataset.p] = f && f.type === 'bool' ? x.value === 'true' : f && f.type === 'number' && /^\d+(\.\d+)?$/.test(x.value) ? Number(x.value) : x.value;
      });
      const path = $('[data-w="path"]', li).value.trim(); const op = $('[data-w="op"]', li).value; const value = $('[data-w="value"]', li).value.trim();
      if (path && op) step.when = { path, op, ...(value ? { value } : {}) };
      if ($('[data-coe]', li).checked) step.continue_on_error = true;
      return step;
    });
  };

  const paintJson = () => { ed.innerHTML = `<label class="field"><span>Definition</span><textarea class="textarea mono wf-json" id="wf-json" rows="20" spellcheck="false">${esc(JSON.stringify(draft, null, 2))}</textarea></label>`; };
  const readJson = () => { const v = JSON.parse($('#wf-json', ed).value); Object.assign(draft, { name: v.name || '', description: v.description || '', inputs: v.inputs || [], steps: v.steps || [] }); };

  $$('[data-mode]', panel).forEach((b) => {
    b.onclick = (e) => {
      e.preventDefault();
      if (b.dataset.mode === mode) return;
      try { if (mode === 'form') readForm(); else readJson(); } catch (err) { $('#wf-ed-err', panel).textContent = `JSON: ${err.message}`; return; }
      $('#wf-ed-err', panel).textContent = '';
      mode = b.dataset.mode;
      $$('[data-mode]', panel).forEach((x) => x.classList.toggle('is-on', x === b));
      if (mode === 'form') paintForm(); else paintJson();
    };
  });
  paintForm();

  $('#wf-ed-go', panel).onclick = () => busy($('#wf-ed-go', panel), async () => {
    try { if (mode === 'form') readForm(); else readJson(); } catch (err) { $('#wf-ed-err', panel).textContent = `JSON: ${err.message}`; return; }
    try {
      const saved = w ? await api(`/workflows/${encodeURIComponent(w.workflow_id)}`, { method: 'PUT', body: draft }) : await api('/workflows', { method: 'POST', body: draft });
      closeLayer();
      toast(w ? 'Workflow saved' : 'Workflow created', saved.name, 'ok');
      ctx.tab = 'saved'; history.replaceState(null, '', '#/workflows');
      load();
    } catch (err) { $('#wf-ed-err', panel).textContent = err.message; }
  });
}