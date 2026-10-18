import { $, $$, api, esc, sev, pill, ago, stamp, num, label, emptyState, toast, busy, emit, can, modal, closeLayer, state } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { assignableUsers, openAlert } from '../panels.js';
import { VERDICT_C } from './intel-lookup.js';

// Case management: incidents that span several alerts, with their own tasks,
// indicators, evidence and timeline. #/cases is the board, #/cases/:id one case.

const FILTERS = [['open', 'Open', 'OPEN,IN_PROGRESS,CONTAINED'], ['escalated', 'Escalated', 'OPEN,IN_PROGRESS,CONTAINED'], ['closed', 'Closed', 'CLOSED'], ['all', 'All', '']];
const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUSES = ['OPEN', 'IN_PROGRESS', 'CONTAINED', 'CLOSED'];
const TASK_NEXT = { TODO: 'DOING', DOING: 'DONE', DONE: 'TODO', SKIPPED: 'TODO' };
const hours = (h) => (h == null ? '-' : h < 1 ? `${Math.round(h * 60)}m` : h < 48 ? `${h}h` : `${Math.round(h / 24)}d`);
const csv = (s) => String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
const initials = (name) => String(name || '?').split(/[\s@.:]+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('') || '?';

let ctx = null;

export async function render({ el, params, query, navigate }) {
  if (params[0]) return renderCase(el, params[0], navigate, query);
  ctx = { el, navigate, mode: 'list', filter: FILTERS.some(([k]) => k === query.filter) ? query.filter : 'open', q: '' };
  const respond = can('respond');
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Cases</h1>
        <p class="page-sub">Incidents that outgrow a single alert. Each case keeps its alerts, response checklist, indicators, evidence and decisions in one place.</p>
      </div>
      <div class="page-actions">${respond ? `<button class="btn" id="cs-kc">${icon('activity')}From kill chain</button><button class="btn btn--primary" id="cs-new">${icon('plus')}New case</button>` : ''}</div>
    </div>
    <div class="kpis grid grid-kpi reveal" id="cs-kpis">${'<div class="kpi"><div class="skeleton" style="height:11px;width:50%"></div><div class="skeleton mt-8" style="height:26px;width:30%"></div></div>'.repeat(5)}</div>
    <section class="panel reveal">
      <div class="toolbar">
        <div class="seg" id="cs-filter">${FILTERS.map(([k, t]) => `<button data-f="${k}" class="${k === ctx.filter ? 'is-on' : ''}">${t}</button>`).join('')}</div>
        <div class="grow"><input class="input" id="cs-q" placeholder="Search title, id or description" autocomplete="off" style="max-width:320px"></div>
        <div class="toolbar__end small muted" id="cs-sum"></div>
      </div>
      <div id="cs-table"><div style="padding:18px" class="stack">${'<div class="skeleton" style="height:42px"></div>'.repeat(4)}</div></div>
    </section>`;
  $$('#cs-filter button', el).forEach((b) => {
    b.onclick = () => {
      ctx.filter = b.dataset.f;
      $$('#cs-filter button', el).forEach((x) => x.classList.toggle('is-on', x === b));
      history.replaceState(null, '', ctx.filter === 'open' ? '#/cases' : `#/cases?filter=${ctx.filter}`);
      loadList();
    };
  });
  let t = null;
  $('#cs-q', el).oninput = (e) => { clearTimeout(t); t = setTimeout(() => { ctx.q = e.target.value.trim(); loadList(); }, 250); };
  if (respond) {
    $('#cs-new', el).onclick = () => openNewCase(navigate);
    $('#cs-kc', el).onclick = () => openKillchain(navigate, query.ip);
  }
  hydrateIcons(el);
  await Promise.all([loadList(), loadKpis()]);
  if (respond && (query.ip || query.kc)) openKillchain(navigate, query.ip || '');
}

export function onDataChanged() {
  if (!ctx || !document.body.contains(ctx.el)) return;
  if (ctx.mode === 'list') { loadList(); loadKpis(); } else if (ctx.reload) ctx.reload();
}

async function loadKpis() {
  let m;
  try { m = await api('/cases/metrics'); } catch { return; }
  const box = $('#cs-kpis', ctx.el);
  if (!box) return;
  box.innerHTML = `
    <div class="kpi"><div class="kpi__label">Open cases</div><div class="kpi__value">${num(m.open)}</div><div class="kpi__foot">${m.by_severity.CRITICAL} critical &middot; ${m.by_severity.HIGH} high</div></div>
    <div class="kpi ${m.escalated ? 'kpi--alert' : ''}"><div class="kpi__label">Escalated</div><div class="kpi__value">${num(m.escalated)}</div><div class="kpi__foot">open and raised to a lead</div></div>
    <div class="kpi"><div class="kpi__label">Unassigned</div><div class="kpi__value">${num(m.unassigned)}</div><div class="kpi__foot">open cases nobody owns</div></div>
    <div class="kpi"><div class="kpi__label">Time to close</div><div class="kpi__value">${esc(hours(m.mttr_hours))}</div><div class="kpi__foot">mean &middot; median ${esc(hours(m.median_hours))} over ${num(m.closed)} closed</div></div>
    <div class="kpi"><div class="kpi__label">Checklist done</div><div class="kpi__value">${m.tasks.rate == null ? '-' : `${m.tasks.rate}<small>%</small>`}</div><div class="kpi__foot">${num(m.tasks.done)} of ${num(m.tasks.total)} tasks</div></div>`;
}

async function loadList() {
  const { el } = ctx;
  const f = FILTERS.find(([k]) => k === ctx.filter);
  const qs = new URLSearchParams();
  if (f[2]) qs.set('status', f[2]);
  if (ctx.q) qs.set('q', ctx.q);
  let rows;
  try { rows = await api(`/cases?${qs}`); } catch (e) { $('#cs-table', el).innerHTML = emptyState('Could not load cases', e.message, 'alert'); return; }
  if (!document.body.contains(el) || ctx.mode !== 'list') return;
  if (ctx.filter === 'escalated') rows = rows.filter((c) => c.escalated);
  $('#cs-sum', el).textContent = `${rows.length} case${rows.length === 1 ? '' : 's'}`;
  $('#cs-table', el).innerHTML = rows.length ? `<div class="table-wrap"><table class="table">
    <thead><tr><th>Case</th><th>Severity</th><th>Status</th><th class="hide-sm">Owner</th><th class="num">Alerts</th><th class="num hide-sm">Indicators</th><th class="hide-sm">Checklist</th><th class="hide-sm">Updated</th></tr></thead>
    <tbody class="rows-in">${rows.map((c, i) => `
      <tr class="is-clickable ${c.status === 'CLOSED' ? 'is-dim' : ''}" data-case="${esc(c.case_id)}" style="--i:${i}" tabindex="0">
        <td><span class="cell-main">${esc(c.title)}</span><span class="cell-sub"><span class="mono">${esc(c.case_id)}</span>${c.escalated ? ' &middot; <span class="warn-text">escalated</span>' : ''}${(c.tags || []).slice(0, 3).map((x) => ` <span class="tag">${esc(x)}</span>`).join('')}</span></td>
        <td>${sev(c.severity)}</td>
        <td>${pill(c.status)}</td>
        <td class="hide-sm small">${c.assignee_name ? esc(c.assignee_name) : '<span class="muted">Unassigned</span>'}</td>
        <td class="num">${num(c.alerts)}</td>
        <td class="num hide-sm">${num(c.iocs)}${c.malicious_iocs ? ` <span class="tag tag--warn">${c.malicious_iocs} bad</span>` : ''}</td>
        <td class="hide-sm">${c.tasks ? `<span class="meter"><span class="meter__track"><span class="meter__fill" style="width:${Math.round(((c.tasks - c.tasks_open) / c.tasks) * 100)}%;--c:var(--ok)"></span></span><span class="mono small">${c.tasks - c.tasks_open}/${c.tasks}</span></span>` : '<span class="muted small">none</span>'}</td>
        <td class="hide-sm small muted"><span title="${stamp(c.updated_at)}">${ago(c.updated_at)}</span></td>
      </tr>`).join('')}</tbody></table></div>`
    : emptyState(ctx.q ? 'No case matches' : ctx.filter === 'closed' ? 'No closed cases yet' : 'No open cases',
      can('respond') ? 'Open a case from an alert (Add to case), from an attacker IP (From kill chain), or start one here.' : 'Analysts open cases when an incident spans several alerts.', 'file');
  $$('[data-case]', el).forEach((r) => {
    const go = () => ctx.navigate(`cases/${encodeURIComponent(r.dataset.case)}`);
    r.onclick = go;
    r.onkeydown = (e) => { if (e.key === 'Enter') go(); };
  });
}
function openNewCase(navigate) {
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">New case</h2></div>
    <form class="modal__body form-grid" id="nc-form" novalidate>
      <label class="field span-2"><span>Title</span><input class="input" name="title" maxlength="200" required placeholder="e.g. Credential stuffing against the VPN portal"></label>
      <label class="field"><span>Severity</span><select class="select" name="severity">${SEVS.map((s) => `<option ${s === 'MEDIUM' ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
      <label class="field"><span>Owner</span><select class="select" name="assignee_id" id="nc-owner"><option value="">Unassigned</option></select></label>
      <label class="field span-2"><span>Description</span><textarea class="textarea" name="description" rows="3" maxlength="8000" placeholder="Scope, impact, what triggered it"></textarea></label>
      <label class="field"><span>Alert ids</span><input class="input input--mono" name="alert_ids" placeholder="ALERT-..., comma separated"></label>
      <label class="field"><span>ATT&amp;CK techniques</span><input class="input input--mono" name="mitre" placeholder="T1190, T1110.003"></label>
      <label class="field span-2"><span>Tags</span><input class="input" name="tags" placeholder="vpn, customer-facing"></label>
    </form>
    <div class="modal__foot"><span class="form-error" id="nc-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="nc-save">${icon('plus')}Open case</button></div>`);
  assignableUsers().then((us) => {
    const sel = $('#nc-owner', panel);
    if (sel) sel.insertAdjacentHTML('beforeend', us.map((u) => `<option value="${u.id}">${esc(u.name)}${state.user && u.id === state.user.id ? ' (you)' : ''}</option>`).join(''));
  }).catch(() => {});
  const go = async (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData($('#nc-form', panel)));
    await busy($('#nc-save', panel), async () => {
      try {
        const c = await api('/cases', { method: 'POST', body: { ...f, assignee_id: f.assignee_id ? Number(f.assignee_id) : null, alert_ids: csv(f.alert_ids), mitre: csv(f.mitre), tags: csv(f.tags) } });
        toast(`Opened ${c.case_id}`, c.skipped ? `${c.skipped} alert id${c.skipped === 1 ? '' : 's'} not found` : c.title, c.skipped ? 'info' : 'ok');
        closeLayer();
        emit('data:changed');
        navigate(`cases/${encodeURIComponent(c.case_id)}`);
      } catch (err) { $('#nc-err', panel).textContent = err.message; }
    });
  };
  $('#nc-save', panel).onclick = go;
  $('#nc-form', panel).onsubmit = go;
}

function openKillchain(navigate, ip = '') {
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Case from kill chain</h2></div>
    <form class="modal__body" id="kc-form" novalidate>
      <p class="small muted" style="margin:0 0 12px">Collects every alert involving one address in the window, maps the ATT&amp;CK techniques and tactics from its investigations, and opens a case with a timeline and a response checklist built from what actually happened.</p>
      <div class="form-grid">
        <label class="field"><span>Attacker IP</span><input class="input input--mono" name="ip" required value="${esc(ip)}" placeholder="203.0.113.50"></label>
        <label class="field"><span>Look back</span><select class="select" name="hours">${[['24', '24 hours'], ['72', '3 days'], ['168', '7 days'], ['720', '30 days'], ['2160', '90 days']].map(([v, t]) => `<option value="${v}" ${v === '72' ? 'selected' : ''}>${t}</option>`).join('')}</select></label>
        <label class="field span-2"><span>Title <small>optional</small></span><input class="input" name="title" maxlength="200" placeholder="Generated from the evidence if left empty"></label>
      </div>
    </form>
    <div class="modal__foot"><span class="form-error" id="kc-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="kc-go">${icon('activity')}Build case</button></div>`);
  const go = async (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData($('#kc-form', panel)));
    await busy($('#kc-go', panel), async () => {
      try {
        const c = await api('/cases/from-killchain', { method: 'POST', body: { ...f, hours: Number(f.hours) } });
        toast(`Opened ${c.case_id}`, `${c.linked} alerts, ${c.techniques.length} techniques${c.compromised.length ? `, ${c.compromised.length} compromised` : ''}`, 'ok', 6000);
        closeLayer();
        emit('data:changed');
        navigate(`cases/${encodeURIComponent(c.case_id)}`);
      } catch (err) { $('#kc-err', panel).textContent = err.message; }
    });
  };
  $('#kc-go', panel).onclick = go;
  $('#kc-form', panel).onsubmit = go;
}

// ---- One case ---------------------------------------------------------------
async function renderCase(el, id, navigate, query) {
  ctx = { el, navigate, mode: 'case', id, tab: query.tab || 'timeline' };
  el.innerHTML = `<div class="page-head"><div class="page-head__text"><a class="small muted back-link" href="#/cases">${icon('arrow')}All cases</a><div class="skeleton mt-8" style="height:30px;width:60%"></div></div></div>
    <div class="grid grid-2-1"><div class="panel skeleton" style="height:360px"></div><div class="panel skeleton" style="height:360px"></div></div>`;
  hydrateIcons(el);
  ctx.reload = () => loadCase();
  await loadCase();
}

async function loadCase() {
  const { el, id } = ctx;
  let d;
  try { d = await api(`/cases/${encodeURIComponent(id)}`); } catch (e) {
    el.innerHTML = `<div class="page-head"><div class="page-head__text"><a class="small muted back-link" href="#/cases">${icon('arrow')}All cases</a></div></div>${emptyState(e.status === 404 ? `${id} does not exist` : 'Could not load case', e.status === 404 ? 'It may have been removed by retention.' : e.message, 'file')}`;
    hydrateIcons(el);
    return;
  }
  if (!document.body.contains(el) || ctx.mode !== 'case' || ctx.id !== id) return;
  ctx.data = d;
  paintCase();
}
const KIND_TEXT = { comment: 'Comment', evidence: 'Evidence', timeline: 'Timeline', event: 'System' };

function eventHtml(e) {
  const sys = e.kind === 'event';
  return `<li class="casefeed__item ${sys ? 'casefeed__item--event' : ''} cev--${esc(e.kind)}">
    <span class="casefeed__mark">${sys ? icon('dot') : e.kind === 'evidence' ? icon('lock') : e.kind === 'timeline' ? icon('activity') : esc(initials(e.author))}</span>
    <div class="grow">
      <div class="casefeed__meta"><b>${esc(e.author)}</b>${!sys ? `<span class="tag">${KIND_TEXT[e.kind]}</span>` : ''}<span class="mono" title="${e.kind === 'timeline' ? 'When it happened' : 'Logged'}">${stamp(e.occurred_at || e.created_at)}</span></div>
      ${e.title ? `<div class="cev__title">${esc(e.title)}</div>` : ''}
      <div class="casefeed__body">${esc(e.body)}</div>
      ${e.sha256 ? `<div class="small muted mono cev__hash" title="SHA-256 of the evidence text when it was filed">sha256 ${esc(e.sha256)}</div>` : ''}
    </div></li>`;
}

function taskHtml(t, open) {
  return `<li class="ctask ctask--${t.status}" data-task="${t.id}">
    <button class="ctask__box" ${open ? '' : 'disabled'} data-tnext="${t.id}" title="${t.status === 'DONE' ? 'Mark not done' : t.status === 'DOING' ? 'Mark done' : 'Start'}" aria-label="Advance task">${t.status === 'DONE' ? icon('check') : t.status === 'DOING' ? '<i class="ctask__doing"></i>' : t.status === 'SKIPPED' ? icon('x') : ''}</button>
    <div class="grow">
      <div class="ctask__title">${esc(t.title)}</div>
      <div class="small muted">${t.phase ? `${esc(t.phase)} &middot; ` : ''}${label(t.status)}${t.assignee_name ? ` &middot; ${esc(t.assignee_name)}` : ''}${t.done_at ? ` &middot; ${ago(t.done_at)}` : ''}${t.created_by === 'playbook' ? ' &middot; playbook' : ''}</div>
    </div>
    ${open && t.status !== 'DONE' && t.status !== 'SKIPPED' ? `<button class="icon-btn icon-btn--bare" data-tskip="${t.id}" title="Skip (not applicable)" aria-label="Skip task">${icon('x')}</button>` : ''}
  </li>`;
}

function paintCase() {
  const { el, data: d } = ctx;
  const c = d.case;
  const respond = can('respond');
  const open = respond && c.status !== 'CLOSED';
  const openTasks = d.tasks.filter((t) => t.status === 'TODO' || t.status === 'DOING').length;
  const pending = d.approvals.filter((a) => a.status === 'PENDING').length;
  const phases = [...new Set(d.tasks.map((t) => t.phase || 'Other'))];
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <a class="small muted back-link" href="#/cases">${icon('arrow')}All cases</a>
        <h1 class="page-title">${esc(c.title)}</h1>
        <div class="row wrap mt-8">${sev(c.severity)} ${pill(c.status)}${c.escalated ? ` <span class="tag tag--warn" title="${stamp(c.escalated_at)}">Escalated</span>` : ''} <span class="mono small muted">${esc(c.case_id)}</span>
          <span class="small muted">&middot; opened ${ago(c.created_at)} by ${esc(c.created_by)} &middot; ${c.assignee_name ? `owner <b>${esc(c.assignee_name)}</b>` : 'unassigned'}</span></div>
      </div>
      <div class="page-actions">
        ${open ? `<select class="select" id="cv-status" aria-label="Status">${STATUSES.filter((s) => s !== 'CLOSED').map((s) => `<option value="${s}" ${s === c.status ? 'selected' : ''}>${label(s)}</option>`).join('')}</select>` : ''}
        ${open && !c.escalated ? `<button class="btn" id="cv-esc">${icon('alert')}Escalate</button>` : ''}
        ${open ? `<button class="btn btn--primary" id="cv-close">${icon('check')}Close case</button>` : ''}
        ${respond && c.status === 'CLOSED' ? `<button class="btn" id="cv-reopen">${icon('rotate')}Reopen</button>` : ''}
        ${respond ? `<button class="icon-btn" id="cv-edit" title="Edit details" aria-label="Edit details">${icon('edit')}</button>` : ''}
      </div>
    </div>
    ${c.status === 'CLOSED' && c.resolution ? `<div class="notice reveal">${icon('check')}<div class="small"><b>Closed ${ago(c.closed_at)}.</b> ${esc(c.resolution)}</div></div>` : ''}
    <div class="grid grid-2-1 reveal">
      <section class="panel">
        <div class="tabs" role="tablist" id="cv-tabs">
          <button class="tab" data-tab="timeline" role="tab">Timeline <span class="tab__n mono">${d.events.length || ''}</span></button>
          <button class="tab" data-tab="alerts" role="tab">Alerts <span class="tab__n mono">${d.alerts.length || ''}</span></button>
          <button class="tab" data-tab="iocs" role="tab">Indicators <span class="tab__n mono">${d.iocs.length || ''}</span></button>
          <button class="tab" data-tab="response" role="tab">Containment <span class="tab__n mono">${pending ? `${pending} pending` : d.rules.length || ''}</span></button>
        </div>
        <div id="cv-pane"></div>
      </section>
      <div class="stack">
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Response checklist</h2><span class="panel__meta">${d.tasks.length - openTasks}/${d.tasks.length} done</span></div>
          ${d.tasks.length ? `<div class="ctasks">${phases.map((p) => `<div class="ctasks__phase">${esc(p)}</div><ol class="ctasks__list">${d.tasks.filter((t) => (t.phase || 'Other') === p).map((t) => taskHtml(t, open)).join('')}</ol>`).join('')}</div>` : '<div class="panel__body small muted">No tasks yet.</div>'}
          ${open ? `<form class="ctask-add" id="cv-task-form" novalidate><input class="input" id="cv-task" maxlength="240" placeholder="Add a task" autocomplete="off"><select class="select" id="cv-phase" aria-label="Phase">${['Triage', 'Containment', 'Eradication', 'Recovery', 'Lessons learned'].map((p) => `<option>${p}</option>`).join('')}</select><button class="btn btn--sm" id="cv-task-add">${icon('plus')}</button></form>` : ''}
        </section>
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Details</h2></div>
          <div class="panel__body">
            ${c.description ? `<p class="case-desc">${esc(c.description)}</p>` : '<p class="small muted" style="margin-top:0">No description.</p>'}
            <dl class="kv mt-12">
              <dt>ATT&amp;CK</dt><dd>${(c.mitre || []).length ? c.mitre.map((m) => `<a class="tag" href="https://attack.mitre.org/techniques/${esc(m.replace('.', '/'))}/" target="_blank" rel="noopener">${esc(m)}</a>`).join(' ') : '<span class="muted">none mapped</span>'}</dd>
              <dt>Tags</dt><dd>${(c.tags || []).length ? c.tags.map((x) => `<span class="tag">${esc(x)}</span>`).join(' ') : '<span class="muted">none</span>'}</dd>
              <dt>Source</dt><dd>${esc(c.source)}</dd>
              ${jiraRow(c, respond)}
              <dt>Last change</dt><dd><span title="${stamp(c.updated_at)}">${ago(c.updated_at)}</span></dd>
            </dl>
          </div>
        </section>
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Related cases</h2><span class="panel__meta">shared alerts or indicators</span></div>
          ${d.related.length ? `<div class="list">${d.related.map((r) => `<a class="list__item is-clickable" href="#/cases/${encodeURIComponent(r.case_id)}">${sev(r.severity)}<div class="grow"><div class="list__title truncate">${esc(r.title)}</div><div class="list__sub"><span class="mono">${esc(r.case_id)}</span> &middot; ${label(r.status)} &middot; ${esc(r.why)}</div></div></a>`).join('')}</div>` : '<div class="panel__body small muted">None found. Cases that share an alert or an indicator with this one show up here.</div>'}
        </section>
      </div>
    </div>`;
  $$('#cv-tabs [data-tab]', el).forEach((b) => { b.onclick = () => setCaseTab(b.dataset.tab); });
  bindCaseHead();
  bindJira();
  bindTasks();
  hydrateIcons(el);
  setCaseTab(ctx.tab);
}
const jiraOn = () => Boolean(state.health && state.health.integrations && state.health.integrations.jira);

function jiraRow(c, respond) {
  const j = c.jira;
  if (j && j.key && j.manual) {
    const key = j.url ? `<a class="mono" href="${esc(j.url)}" target="_blank" rel="noopener">${esc(j.key)}</a>` : `<span class="mono">${esc(j.key)}</span>`;
    return `<dt>Ticket</dt><dd><div class="jira-box"><span class="tag">${esc(j.system || 'Ticket')}</span>${key}${j.status ? `<span class="tag">${esc(j.status)}</span>` : ''}${respond ? `<button class="btn btn--sm btn--ghost" id="cv-ticket-link">Edit</button><button class="btn btn--sm btn--ghost" id="cv-ticket-unlink">Unlink</button>` : ''}</div></dd>`;
  }
  if (j && j.key) {
    const tone = j.category === 'done' ? 'tag--ok' : j.category === 'indeterminate' ? 'tag--warn' : '';
    return `<dt>Jira</dt><dd><div class="jira-box"><a class="mono" href="${esc(j.url)}" target="_blank" rel="noopener">${esc(j.key)}</a>${j.status ? `<span class="tag ${tone}">${esc(j.status)}</span>` : ''}${j.assignee ? `<span class="small muted">${esc(j.assignee)}</span>` : ''}${jiraOn() ? `<button class="btn btn--sm btn--ghost" id="cv-jira-sync" title="${j.synced_at ? `Synced ${stamp(j.synced_at)}` : 'Fetch status from Jira'}">${icon('refresh')}Sync</button>` : ''}</div></dd>`;
  }
  const link = respond ? `<button class="btn btn--sm${jiraOn() ? ' btn--ghost' : ''}" id="cv-ticket-link">${icon('plus')}Link ticket</button>` : '';
  if (!jiraOn()) return `<dt>Ticket</dt><dd>${link || '<span class="muted">not linked</span>'}</dd>`;
  return `<dt>Ticket</dt><dd>${respond ? `<div class="jira-box"><button class="btn btn--sm" id="cv-jira-new">${icon('plus')}Create Jira issue</button>${link}</div>` : '<span class="muted">not linked</span>'}</dd>`;
}

function linkTicketModal(c) {
  const j = c.jira && c.jira.manual ? c.jira : {};
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Link external ticket</h2><p class="small muted" style="margin:4px 0 0">Record the ticket this incident is tracked under in Jira, ServiceNow, GitHub or any other system.</p></div>
    <form class="modal__body" id="tk-form" novalidate>
      <div class="form-grid">
        <label class="field"><span>System</span><input class="input" name="system" maxlength="40" placeholder="Jira, ServiceNow, GitHub..." value="${esc(j.system || '')}"></label>
        <label class="field"><span>Ticket key</span><input class="input input--mono" name="key" required maxlength="80" placeholder="SEC-142 or INC0012345" value="${esc(j.key || '')}"></label>
        <label class="field span-2"><span>URL (optional)</span><input class="input" name="url" maxlength="500" placeholder="https://..." value="${esc(j.url || '')}"></label>
        <label class="field"><span>Status (optional)</span><input class="input" name="status" maxlength="40" placeholder="Open, In progress..." value="${esc(j.status || '')}"></label>
      </div>
    </form>
    <div class="modal__foot"><span class="form-error" id="tk-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="tk-save">Link ticket</button></div>`);
  const form = $('#tk-form', panel);
  const go = async (e) => {
    e.preventDefault();
    await busy($('#tk-save', panel), async () => {
      try {
        const t = await api(`/cases/${encodeURIComponent(c.case_id)}/ticket`, { method: 'PUT', body: Object.fromEntries(new FormData(form)) });
        closeLayer(); toast('Ticket linked', `${t.system} ${t.key}`, 'ok'); await loadCase();
      } catch (err) { $('#tk-err', panel).textContent = err.message; }
    });
  };
  $('#tk-save', panel).onclick = go;
  form.onsubmit = go;
}
function bindJira() {
  const { el, data: d } = ctx;
  const id = encodeURIComponent(d.case.case_id);
  const mk = $('#cv-jira-new', el);
  if (mk) mk.onclick = () => busy(mk, async () => {
    try { const j = await api(`/cases/${id}/jira`, { method: 'POST' }); toast('Jira issue created', j.key, 'ok'); await loadCase(); } catch (e) { toast('Jira issue not created', e.message, 'error'); }
  });
  const lk = $('#cv-ticket-link', el);
  if (lk) lk.onclick = () => linkTicketModal(d.case);
  const ul = $('#cv-ticket-unlink', el);
  if (ul) ul.onclick = () => busy(ul, async () => {
    try { await api(`/cases/${id}/ticket`, { method: 'DELETE' }); toast('Ticket unlinked', '', 'ok'); await loadCase(); } catch (e) { toast('Unlink failed', e.message, 'error'); }
  });
  const sy = $('#cv-jira-sync', el);
  if (sy) sy.onclick = () => busy(sy, async () => {
    try { const j = await api(`/cases/${id}/jira`); toast(`${j.key}: ${j.status || 'synced'}`, '', 'ok'); await loadCase(); } catch (e) { toast('Sync failed', e.message, 'error'); }
  });
}

function setCaseTab(tab) {
  const { el, data: d } = ctx;
  ctx.tab = ['timeline', 'alerts', 'iocs', 'response'].includes(tab) ? tab : 'timeline';
  $$('#cv-tabs [data-tab]', el).forEach((b) => { const on = b.dataset.tab === ctx.tab; b.classList.toggle('is-on', on); b.setAttribute('aria-selected', String(on)); });
  history.replaceState(null, '', `#/cases/${encodeURIComponent(ctx.id)}${ctx.tab === 'timeline' ? '' : `?tab=${ctx.tab}`}`);
  const pane = $('#cv-pane', el);
  const respond = can('respond');
  const open = respond && d.case.status !== 'CLOSED';
  if (ctx.tab === 'timeline') {
    const evs = [...d.events].sort((a, b) => String(b.occurred_at || b.created_at).localeCompare(String(a.occurred_at || a.created_at)));
    pane.innerHTML = `
      ${respond ? `<form class="cev-form" id="cv-ev-form" novalidate>
        <div class="seg" id="cv-kind"><button type="button" data-k="comment" class="is-on">Comment</button><button type="button" data-k="evidence">Evidence</button><button type="button" data-k="timeline">Timeline entry</button></div>
        <div class="row wrap mt-8" id="cv-ev-extra" hidden>
          <input class="input grow" id="cv-ev-title" maxlength="200" placeholder="Title (e.g. auth.log excerpt from bastion)">
          <input class="input input--mono" id="cv-ev-at" type="datetime-local" step="1" style="max-width:220px" hidden aria-label="When it happened">
        </div>
        <textarea class="textarea mt-8" id="cv-ev-body" rows="3" maxlength="20000" placeholder="What you found, what you did, who you spoke to"></textarea>
        <div class="row mt-8"><span class="small muted grow" id="cv-ev-hint">Ctrl+Enter to post.</span><button class="btn btn--sm btn--primary" id="cv-ev-add">Post</button></div>
      </form>` : ''}
      ${evs.length ? `<ol class="casefeed casefeed--case">${evs.map(eventHtml).join('')}</ol>` : emptyState('Nothing logged yet', 'Comments, evidence and status changes appear here.', 'inbox')}`;
    if (respond) bindEventForm(pane);
  } else if (ctx.tab === 'alerts') {
    pane.innerHTML = d.alerts.length ? `<div class="table-wrap"><table class="table">
      <thead><tr><th>Alert</th><th>Severity</th><th>Status</th><th class="hide-sm">Flow</th><th class="hide-sm">Detected</th>${open ? '<th style="width:1%"></th>' : ''}</tr></thead>
      <tbody class="rows-in">${[...d.alerts].sort((a, b) => String(b.detected_at).localeCompare(String(a.detected_at))).map((a, i) => `
        <tr style="--i:${i}"><td><a class="cell-main" href="#" data-alert="${esc(a.alert_id)}">${esc(a.signature)}</a><span class="cell-sub mono">${esc(a.alert_id)}</span></td>
        <td>${sev(a.severity)}</td><td>${pill(a.status)}</td>
        <td class="hide-sm mono small"><a class="ip-link" href="#/ip/${encodeURIComponent(a.source_ip)}">${esc(a.source_ip)}</a> &rarr; ${esc(a.dest_ip)}:${esc(a.dest_port)}</td>
        <td class="hide-sm small muted"><span title="${stamp(a.detected_at)}">${ago(a.detected_at)}</span></td>
        ${open ? `<td><button class="icon-btn icon-btn--bare" data-unlink="${esc(a.alert_id)}" title="Remove from case" aria-label="Remove ${esc(a.alert_id)}">${icon('x')}</button></td>` : ''}</tr>`).join('')}</tbody></table></div>
      ${open ? '<form class="row panel__body" id="cv-link-form" novalidate><input class="input input--mono grow" id="cv-link" placeholder="Link more alerts: ALERT-..., comma separated"><button class="btn btn--sm">Link</button></form>' : ''}`
      : `${emptyState('No alerts linked', 'Use Add to case from the alert queue, or paste alert ids below.', 'bell')}${open ? '<form class="row panel__body" id="cv-link-form" novalidate><input class="input input--mono grow" id="cv-link" placeholder="ALERT-..., comma separated"><button class="btn btn--sm">Link</button></form>' : ''}`;
    $$('[data-alert]', pane).forEach((a) => { a.onclick = (e) => { e.preventDefault(); openAlert(a.dataset.alert, ctx.navigate); }; });
    $$('[data-unlink]', pane).forEach((b) => {
      b.onclick = () => busy(b, async () => {
        try { await api(`/cases/${encodeURIComponent(ctx.id)}/alerts/${encodeURIComponent(b.dataset.unlink)}`, { method: 'DELETE' }); toast('Alert removed from case', b.dataset.unlink); await loadCase(); } catch (e) { toast('Could not remove', e.message, 'error'); }
      });
    });
    const lf = $('#cv-link-form', pane);
    if (lf) lf.onsubmit = (e) => {
      e.preventDefault();
      const ids = csv($('#cv-link', pane).value);
      if (!ids.length) return;
      busy($('button', lf), async () => {
        try { const r = await api(`/cases/${encodeURIComponent(ctx.id)}/alerts`, { method: 'POST', body: { alert_ids: ids } }); toast(`${r.added} alert${r.added === 1 ? '' : 's'} linked`, r.skipped ? `${r.skipped} not found or already linked` : '', r.added ? 'ok' : 'info'); await loadCase(); } catch (err) { toast('Could not link', err.message, 'error'); }
      });
    };
  } else if (ctx.tab === 'iocs') {
    paintIocs(pane, open);
  } else {
    paintResponse(pane, respond);
  }
  hydrateIcons(pane);
}

function bindEventForm(pane) {
  let kind = 'comment';
  const body = $('#cv-ev-body', pane);
  const at = $('#cv-ev-at', pane);
  const HINT = { comment: 'Ctrl+Enter to post.', evidence: 'Evidence is hashed with SHA-256 when filed, so later edits elsewhere are detectable.', timeline: 'Record when it actually happened, in your local time.' };
  $$('#cv-kind button', pane).forEach((b) => {
    b.onclick = () => {
      kind = b.dataset.k;
      $$('#cv-kind button', pane).forEach((x) => x.classList.toggle('is-on', x === b));
      $('#cv-ev-extra', pane).hidden = kind === 'comment';
      at.hidden = kind !== 'timeline';
      $('#cv-ev-hint', pane).textContent = HINT[kind];
      body.placeholder = kind === 'evidence' ? 'Paste the log excerpt, command output or file listing exactly as collected' : kind === 'timeline' ? 'What happened at that moment' : 'What you found, what you did, who you spoke to';
    };
  });
  const post = (e) => {
    e.preventDefault();
    if (!body.value.trim()) { body.classList.add('is-invalid'); setTimeout(() => body.classList.remove('is-invalid'), 1200); return; }
    const payload = { kind, body: body.value, title: $('#cv-ev-title', pane).value || undefined };
    if (kind === 'timeline') {
      if (!at.value) { toast('When did it happen?', 'Timeline entries need a time', 'error'); at.focus(); return; }
      payload.occurred_at = new Date(at.value).toISOString();
    }
    busy($('#cv-ev-add', pane), async () => {
      try { await api(`/cases/${encodeURIComponent(ctx.id)}/events`, { method: 'POST', body: payload }); toast(kind === 'evidence' ? 'Evidence filed' : kind === 'timeline' ? 'Timeline entry added' : 'Comment posted', '', 'ok'); await loadCase(); } catch (err) { toast('Not saved', err.message, 'error'); }
    });
  };
  $('#cv-ev-form', pane).onsubmit = post;
  $('#cv-ev-add', pane).onclick = post;
  body.onkeydown = (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) post(e); };
}
function paintIocs(pane, open) {
  const { data: d } = ctx;
  const respond = can('respond');
  pane.innerHTML = `
    ${d.iocs.length ? `<div class="table-wrap"><table class="table">
      <thead><tr><th>Indicator</th><th class="hide-sm">Type</th><th>Verdict</th><th class="hide-sm">Checked</th><th style="width:1%"></th></tr></thead>
      <tbody class="rows-in">${d.iocs.map((i, n) => `
        <tr style="--i:${n}" data-ioc-row="${i.id}">
          <td><span class="cell-main mono" style="overflow-wrap:anywhere">${esc(i.value)}</span>${i.note || i.summary ? `<span class="cell-sub">${esc(i.summary || i.note)}</span>` : ''}</td>
          <td class="hide-sm"><span class="tag">${esc(i.type)}</span></td>
          <td>${i.verdict ? `<span class="ioc-verdict" style="--c:${VERDICT_C[i.verdict] || 'var(--ink-3)'}">${esc(i.verdict)}</span>${i.score != null ? ` <span class="mono small">${i.score}</span>` : ''}` : '<span class="muted small">not checked</span>'}</td>
          <td class="hide-sm small muted">${i.checked_at ? `<span title="${stamp(i.checked_at)}">${ago(i.checked_at)}</span>` : '-'}</td>
          <td><div class="row" style="gap:2px;justify-content:flex-end">
            <a class="icon-btn icon-btn--bare" href="#/intel?q=${encodeURIComponent(i.value)}" title="Open full lookup" aria-label="Open lookup for ${esc(i.value)}">${icon('search')}</a>
            ${respond ? `<button class="btn btn--sm btn--ghost" data-check="${i.id}">${i.checked_at ? 'Recheck' : 'Check'}</button>` : ''}
            ${open ? `<button class="icon-btn icon-btn--bare" data-rm="${i.id}" title="Remove" aria-label="Remove ${esc(i.value)}">${icon('trash')}</button>` : ''}
          </div></td>
        </tr>`).join('')}</tbody></table></div>
      ${respond ? `<div class="table-foot"><span class="grow">Check runs the indicator through every configured source: abuse.ch, VirusTotal, MISP, RDAP and passive DNS.</span><button class="btn btn--sm" id="cv-check-all">Check all unchecked</button></div>` : ''}`
    : emptyState('No indicators yet', 'Paste text below; IPs, domains, URLs, hashes and ASNs are pulled out of it.', 'search')}
    ${open ? `<form class="panel__body" id="cv-ioc-form" novalidate>
      <textarea class="textarea input--mono" id="cv-ioc" rows="3" placeholder="Paste anything: log lines, a phishing email, a report. Defanged values like evil[.]com work too."></textarea>
      <div class="row mt-8"><input class="input grow" id="cv-ioc-note" maxlength="500" placeholder="Note (optional)"><button class="btn btn--sm btn--primary" id="cv-ioc-add">${icon('plus')}Extract and add</button></div>
    </form>` : ''}`;
  const check = (id, btn) => busy(btn, async () => {
    try {
      const r = await api(`/cases/${encodeURIComponent(ctx.id)}/iocs/${id}/check`, { method: 'POST' });
      toast(`${r.ioc.value}: ${r.lookup.verdict}`, `${(r.lookup.sources_ok || []).length} sources answered${(r.lookup.sources_failed || []).length ? `, ${r.lookup.sources_failed.length} failed` : ''}`, r.lookup.verdict === 'malicious' ? 'error' : 'ok');
      return true;
    } catch (e) { toast('Check failed', e.message, 'error'); return false; }
  });
  $$('[data-check]', pane).forEach((b) => { b.onclick = async () => { if (await check(b.dataset.check, b)) loadCase(); }; });
  const all = $('#cv-check-all', pane);
  if (all) all.onclick = () => busy(all, async () => {
    const todo = d.iocs.filter((i) => !i.checked_at).slice(0, 15);
    if (!todo.length) { toast('Everything has been checked', 'Use Recheck on a row for fresh results'); return; }
    for (const i of todo) await check(i.id, $(`[data-check="${i.id}"]`, pane));
    await loadCase();
  });
  $$('[data-rm]', pane).forEach((b) => {
    b.onclick = () => busy(b, async () => {
      try { const r = await api(`/cases/${encodeURIComponent(ctx.id)}/iocs/${b.dataset.rm}`, { method: 'DELETE' }); toast('Indicator removed', r.removed); await loadCase(); } catch (e) { toast('Could not remove', e.message, 'error'); }
    });
  });
  const f = $('#cv-ioc-form', pane);
  if (f) f.onsubmit = (e) => {
    e.preventDefault();
    const values = $('#cv-ioc', pane).value;
    if (!values.trim()) return;
    busy($('#cv-ioc-add', pane), async () => {
      try {
        const r = await api(`/cases/${encodeURIComponent(ctx.id)}/iocs`, { method: 'POST', body: { values, note: $('#cv-ioc-note', pane).value } });
        toast(`${r.added.length} indicator${r.added.length === 1 ? '' : 's'} added`, r.duplicates ? `${r.duplicates} already on the case` : '', r.added.length ? 'ok' : 'info');
        await loadCase();
      } catch (err) { toast('Nothing added', err.message, 'error'); }
    });
  };
  $('#cv-ioc-add', pane) && ($('#cv-ioc-add', pane).onclick = (e) => f.onsubmit(e));
}

function paintResponse(pane, respond) {
  const { data: d } = ctx;
  const ips = [...new Set([...d.iocs.filter((i) => i.type === 'ipv4' || i.type === 'ipv6').map((i) => i.value), ...d.alerts.map((a) => a.source_ip)])];
  pane.innerHTML = `
    <div class="panel__body">
      <h3 class="section-title" style="margin-top:0">Approval requests</h3>
      ${d.approvals.length ? `<div class="list">${d.approvals.map((a) => `
        <a class="list__item is-clickable" href="#/approvals${a.status === 'PENDING' ? '' : '?tab=history'}">
          ${pill(a.action)}
          <div class="grow"><div class="list__title"><span class="mono">${esc(a.target_ip)}</span> &middot; ${esc(a.route_text)}${a.confidence != null ? ` &middot; ${a.confidence}%` : ''}</div>
          <div class="list__sub">${esc(a.approval_id)} &middot; ${esc(a.reason)}</div></div>
          ${pill(a.status === 'APPROVED' ? 'ENFORCED' : a.status === 'REJECTED' ? 'REMOVED' : a.status, label(a.status))}
        </a>`).join('')}</div>` : '<p class="small muted">No containment has been proposed for this case.</p>'}
      <h3 class="section-title">Rules on case addresses</h3>
      ${d.rules.length ? `<div class="list">${d.rules.map((r) => `<a class="list__item is-clickable" href="#/containment">${pill(r.action)}<div class="grow"><div class="list__title"><span class="mono">${esc(r.target_ip)}</span> &middot; ${esc(r.rule_id)}</div><div class="list__sub">${esc(r.reason || '')}</div></div>${pill(r.enforcement ? r.enforcement.status : r.is_active ? 'RECORDED' : 'REMOVED')}</a>`).join('')}</div>` : '<p class="small muted">No block or isolation rule covers an address in this case.</p>'}
      ${respond ? `
      <h3 class="section-title">Propose containment</h3>
      <form class="form-grid" id="cv-prop" novalidate>
        <label class="field"><span>Target</span><input class="input input--mono" name="target_ip" list="cv-ips" placeholder="IP address"><datalist id="cv-ips">${ips.map((ip) => `<option value="${esc(ip)}">`).join('')}</datalist></label>
        <label class="field"><span>Action</span><select class="select" name="action"><option value="BLOCK">Block at perimeter</option><option value="ISOLATE">Isolate host</option></select></label>
        <label class="field span-2"><span>Reason</span><input class="input" name="reason" maxlength="500" placeholder="Evidence for the reviewer"></label>
        <div class="span-2 row"><span class="small muted grow">Goes to the approval queue. A second analyst approves it and the rule is enforced and verified.</span><button class="btn btn--primary btn--sm" id="cv-prop-go">${icon('send')}Request approval</button></div>
      </form>` : ''}
    </div>`;
  const f = $('#cv-prop', pane);
  if (f) f.onsubmit = (e) => {
    e.preventDefault();
    const body = { ...Object.fromEntries(new FormData(f)), case_id: ctx.id };
    busy($('#cv-prop-go', pane), async () => {
      try {
        const r = await api('/approvals', { method: 'POST', body });
        toast(r.duplicate ? `Joined pending ${r.approval.approval_id}` : `Requested ${r.approval.approval_id}`, `${body.action} ${body.target_ip}`, 'ok');
        emit('data:changed');
        await loadCase();
      } catch (err) { toast('Not requested', err.message, 'error'); }
    });
  };
  if (f) $('#cv-prop-go', pane).onclick = (e) => f.onsubmit(e);
}
function bindTasks() {
  const { el } = ctx;
  const patch = (tid, status, btn) => busy(btn, async () => {
    try { await api(`/cases/${encodeURIComponent(ctx.id)}/tasks/${tid}`, { method: 'PATCH', body: { status } }); await loadCase(); } catch (e) { toast('Task not updated', e.message, 'error'); }
  });
  $$('[data-tnext]', el).forEach((b) => {
    b.onclick = () => { const t = ctx.data.tasks.find((x) => String(x.id) === b.dataset.tnext); if (t) patch(t.id, TASK_NEXT[t.status], b); };
  });
  $$('[data-tskip]', el).forEach((b) => { b.onclick = () => patch(b.dataset.tskip, 'SKIPPED', b); });
  const f = $('#cv-task-form', el);
  if (f) f.onsubmit = (e) => {
    e.preventDefault();
    const title = $('#cv-task', el).value.trim();
    if (!title) return;
    busy($('#cv-task-add', el), async () => {
      try { await api(`/cases/${encodeURIComponent(ctx.id)}/tasks`, { method: 'POST', body: { title, phase: $('#cv-phase', el).value } }); await loadCase(); } catch (err) { toast('Task not added', err.message, 'error'); }
    });
  };
}

function bindCaseHead() {
  const { el, data: d } = ctx;
  const c = d.case;
  const st = $('#cv-status', el);
  if (st) st.onchange = async () => {
    try { await api(`/cases/${encodeURIComponent(c.case_id)}`, { method: 'PATCH', body: { status: st.value } }); toast(`Status: ${label(st.value)}`, c.case_id, 'ok'); emit('data:changed'); await loadCase(); } catch (e) { toast('Not changed', e.message, 'error'); st.value = c.status; }
  };
  const esc_ = $('#cv-esc', el);
  if (esc_) esc_.onclick = async () => {
    const people = await assignableUsers().catch(() => []);
    const panel = modal(`
      <div class="modal__head"><h2 class="modal__title">Escalate ${esc(c.case_id)}</h2></div>
      <form class="modal__body form-grid" id="es-form" novalidate>
        <label class="field span-2"><span>Reason</span><textarea class="textarea" name="reason" rows="3" maxlength="1000" placeholder="What makes this bigger than the current owner can handle"></textarea></label>
        <label class="field span-2"><span>Hand to</span><select class="select" name="assignee_id"><option value="">Keep current owner</option>${people.map((u) => `<option value="${u.id}">${esc(u.name)} (${esc(u.role)})</option>`).join('')}</select></label>
        <p class="small muted span-2" style="margin:0">Severity goes up one level${c.severity === 'CRITICAL' ? ' (already critical)' : ` (${c.severity} to ${{ LOW: 'MEDIUM', MEDIUM: 'HIGH', HIGH: 'CRITICAL' }[c.severity]})`} and the escalation is logged and audited.</p>
      </form>
      <div class="modal__foot"><span class="form-error" id="es-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="es-go">${icon('alert')}Escalate</button></div>`);
    const go = (e) => {
      e.preventDefault();
      const f = Object.fromEntries(new FormData($('#es-form', panel)));
      busy($('#es-go', panel), async () => {
        try { await api(`/cases/${encodeURIComponent(c.case_id)}/escalate`, { method: 'POST', body: { reason: f.reason, assignee_id: f.assignee_id ? Number(f.assignee_id) : undefined } }); toast('Case escalated', c.case_id, 'ok'); closeLayer(); emit('data:changed'); } catch (err) { $('#es-err', panel).textContent = err.message; }
      });
    };
    $('#es-go', panel).onclick = go;
    $('#es-form', panel).onsubmit = go;
  };
  const cl = $('#cv-close', el);
  if (cl) cl.onclick = () => {
    const open = d.tasks.filter((t) => t.status === 'TODO' || t.status === 'DOING');
    const panel = modal(`
      <div class="modal__head"><h2 class="modal__title">Close ${esc(c.case_id)}</h2></div>
      <form class="modal__body" id="cl-form" novalidate>
        <label class="field"><span>Resolution</span><textarea class="textarea" name="resolution" rows="4" maxlength="4000" placeholder="Root cause, what was contained, what changed so it does not happen again"></textarea></label>
        ${open.length ? `<div class="notice notice--warn mt-12">${icon('alert')}<div class="small">${open.length} task${open.length === 1 ? ' is' : 's are'} still open: ${open.slice(0, 4).map((t) => esc(t.title)).join('; ')}${open.length > 4 ? '...' : ''}.<label class="check mt-8"><input type="checkbox" name="force"> Close anyway</label></div></div>` : ''}
      </form>
      <div class="modal__foot"><span class="form-error" id="cl-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="cl-go">${icon('check')}Close case</button></div>`);
    const go = (e) => {
      e.preventDefault();
      const f = new FormData($('#cl-form', panel));
      busy($('#cl-go', panel), async () => {
        try { await api(`/cases/${encodeURIComponent(c.case_id)}/close`, { method: 'POST', body: { resolution: f.get('resolution'), force: f.get('force') === 'on' } }); toast('Case closed', c.case_id, 'ok'); closeLayer(); emit('data:changed'); } catch (err) { $('#cl-err', panel).textContent = err.message; }
      });
    };
    $('#cl-go', panel).onclick = go;
    $('#cl-form', panel).onsubmit = go;
  };
  const ro = $('#cv-reopen', el);
  if (ro) ro.onclick = () => busy(ro, async () => {
    try { await api(`/cases/${encodeURIComponent(c.case_id)}/reopen`, { method: 'POST' }); toast('Case reopened', c.case_id, 'ok'); emit('data:changed'); } catch (e) { toast('Not reopened', e.message, 'error'); }
  });
  const ed = $('#cv-edit', el);
  if (ed) ed.onclick = async () => {
    const people = await assignableUsers().catch(() => []);
    const panel = modal(`
      <div class="modal__head"><h2 class="modal__title">Edit ${esc(c.case_id)}</h2></div>
      <form class="modal__body form-grid" id="ed-form" novalidate>
        <label class="field span-2"><span>Title</span><input class="input" name="title" maxlength="200" value="${esc(c.title)}"></label>
        <label class="field"><span>Severity</span><select class="select" name="severity">${SEVS.map((s) => `<option ${s === c.severity ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
        <label class="field"><span>Owner</span><select class="select" name="assignee_id"><option value="">Unassigned</option>${people.map((u) => `<option value="${u.id}" ${u.id === c.assignee_id ? 'selected' : ''}>${esc(u.name)}</option>`).join('')}</select></label>
        <label class="field span-2"><span>Description</span><textarea class="textarea" name="description" rows="4" maxlength="8000">${esc(c.description)}</textarea></label>
        <label class="field"><span>ATT&amp;CK techniques</span><input class="input input--mono" name="mitre" value="${esc((c.mitre || []).join(', '))}"></label>
        <label class="field"><span>Tags</span><input class="input" name="tags" value="${esc((c.tags || []).join(', '))}"></label>
        <label class="field span-2"><span>Related cases</span><input class="input input--mono" name="related" value="${esc((c.related || []).join(', '))}" placeholder="CASE-..., comma separated"></label>
      </form>
      <div class="modal__foot"><span class="form-error" id="ed-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="ed-go">Save</button></div>`);
    const go = (e) => {
      e.preventDefault();
      const f = Object.fromEntries(new FormData($('#ed-form', panel)));
      busy($('#ed-go', panel), async () => {
        try {
          await api(`/cases/${encodeURIComponent(c.case_id)}`, { method: 'PATCH', body: { ...f, assignee_id: f.assignee_id ? Number(f.assignee_id) : null, mitre: csv(f.mitre), tags: csv(f.tags), related: csv(f.related) } });
          toast('Case updated', c.case_id, 'ok'); closeLayer(); emit('data:changed');
        } catch (err) { $('#ed-err', panel).textContent = err.message; }
      });
    };
    $('#ed-go', panel).onclick = go;
    $('#ed-form', panel).onsubmit = go;
  };
}