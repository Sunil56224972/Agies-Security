import { $, $$, api, esc, sev, pill, flow, ago, stamp, emptyState, can, state, toast, busy, emit } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { openAlert, openNewAlert, assignableUsers } from '../panels.js';

const SEVS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUSES = [['OPEN', 'Open'], ['', 'Any status'], ['NEW', 'New'], ['INVESTIGATING', 'Investigating'], ['CONFIRMED', 'Confirmed'], ['CONTAINED', 'Contained'], ['MITIGATED', 'Mitigated'], ['FALSE_POSITIVE', 'False positive'], ['CLOSED', 'Closed']];
const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const OPEN = ['NEW', 'INVESTIGATING', 'CONFIRMED'];
const SCOPES = [['all', 'Everyone'], ['mine', 'My queue'], ['none', 'Unassigned']];

let ctx = null;
const f = { sev: 'ALL', status: 'OPEN', q: '', sort: 'severity', scope: 'all' };
const PAGE = 200;
const initials = (n) => String(n || '').split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('');

export async function render({ el, navigate, query }) {
  ctx = { el, navigate, all: [], picked: new Set(), shown: PAGE };
  if (query.q) f.q = query.q;
  if (query.mine) f.scope = 'mine';
  const respond = can('respond');
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Alerts</h1>
        <p class="page-sub">Sensor detections and manual submissions.</p>
      </div>
      <div class="page-actions">
        <a class="btn btn--ghost" id="al-export" href="/api/export/alerts.csv?days=30" download title="Last 30 days, every status">${icon('download')}Export CSV</a>
        ${respond ? '<button class="btn btn--primary" id="al-new">New alert</button>' : ''}
      </div>
    </div>
    <section class="panel reveal">
      <div class="toolbar">
        <div class="input-icon">${icon('search')}<input class="input" id="al-q" placeholder="Filter: signature, IP, id" value="${esc(f.q)}"></div>
        <div class="seg" id="al-sev" role="tablist"></div>
        <div class="toolbar__end">
          <div class="seg" id="al-scope">${SCOPES.map(([v, t]) => `<button data-scope="${v}" class="${f.scope === v ? 'is-on' : ''}">${t}</button>`).join('')}</div>
          <select class="select" id="al-status" style="width:150px" aria-label="Status">${STATUSES.map(([v, t]) => `<option value="${v}" ${f.status === v ? 'selected' : ''}>${t}</option>`).join('')}</select>
          <select class="select" id="al-sort" style="width:120px" aria-label="Sort"><option value="severity">Severity</option><option value="newest">Newest</option></select>
        </div>
      </div>
      <div class="bulkbar" id="al-bulk" hidden></div>
      <div id="al-table"><div style="padding:18px" class="stack">${'<div class="skeleton" style="height:38px"></div>'.repeat(5)}</div></div>
    </section>`;
  if ($('#al-new', el)) $('#al-new', el).onclick = () => openNewAlert(navigate);
  let t;
  $('#al-q', el).oninput = (e) => { clearTimeout(t); t = setTimeout(() => { f.q = e.target.value.trim(); ctx.shown = PAGE; paint(); }, 120); };
  $('#al-status', el).onchange = (e) => { f.status = e.target.value; ctx.picked.clear(); ctx.shown = PAGE; paint(); };
  $('#al-sort', el).value = f.sort;
  $('#al-sort', el).onchange = (e) => { f.sort = e.target.value; paint(); };
  $$('[data-scope]', el).forEach((b) => {
    b.onclick = () => { f.scope = b.dataset.scope; $$('[data-scope]', el).forEach((x) => x.classList.toggle('is-on', x === b)); ctx.picked.clear(); paint(); };
  });
  hydrateIcons(el);
  await load();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) load(); }

async function load() {
  ctx.all = await api('/alerts?limit=2000');
  const ids = new Set(ctx.all.map((a) => a.alert_id));
  for (const id of [...ctx.picked]) if (!ids.has(id)) ctx.picked.delete(id);
  paint();
}

function visible() {
  const q = f.q.toLowerCase();
  const me = state.user ? state.user.id : null;
  return ctx.all
    .filter((a) => (f.status === 'OPEN' ? OPEN.includes(a.status) : !f.status || a.status === f.status))
    .filter((a) => f.scope === 'all' || (f.scope === 'mine' ? a.assignee_id === me : a.assignee_id == null))
    .filter((a) => !q || [a.alert_id, a.signature, a.source_ip, a.dest_ip, a.category, a.assignee_name].some((x) => String(x || '').toLowerCase().includes(q)));
}

function paint() {
  const { el, navigate, all, picked } = ctx;
  const respond = can('respond');
  const byStatus = visible();
  const counts = Object.fromEntries(SEVS.map((s) => [s, s === 'ALL' ? byStatus.length : byStatus.filter((a) => a.severity === s).length]));
  $('#al-sev', el).innerHTML = SEVS.map((s) => `<button class="${f.sev === s ? 'is-on' : ''}" data-sev="${s}" role="tab" aria-selected="${f.sev === s}">${s === 'ALL' ? 'All' : s[0] + s.slice(1).toLowerCase()} <span class="n">${counts[s]}</span></button>`).join('');
  $$('[data-sev]', el).forEach((b) => { b.onclick = () => { f.sev = b.dataset.sev; ctx.shown = PAGE; paint(); }; });

  const rows = byStatus.filter((a) => f.sev === 'ALL' || a.severity === f.sev)
    .sort((a, b) => (f.sort === 'severity' ? RANK[b.severity] - RANK[a.severity] : 0) || b.detected_at.localeCompare(a.detected_at));
  const selectable = rows.filter((a) => a.status !== 'INVESTIGATING');
  const allOn = selectable.length > 0 && selectable.every((a) => picked.has(a.alert_id));

  const empty = f.scope === 'mine'
    ? emptyState('Your queue is empty', 'Alerts you take or are assigned to show up here.', 'user')
    : emptyState(all.length ? 'No matches' : 'No alerts', all.length ? 'Try a different filter.' : 'Send Suricata EVE or JSON alerts to POST /api/ingest/alerts with an ingest API key (Settings, API keys).', 'inbox');

  $('#al-table', el).innerHTML = rows.length ? `
    <div class="table-wrap"><table class="table table--alerts">
      <thead><tr>
        ${respond ? `<th class="col-check"><input type="checkbox" class="cb" id="al-all" aria-label="Select all" ${allOn ? 'checked' : ''}></th>` : ''}
        <th style="width:104px">Severity</th><th>Signature</th><th class="hide-sm">Flow</th><th class="hide-md">Owner</th><th>Status</th><th class="num hide-sm">Detected</th><th style="width:1%"></th></tr></thead>
      <tbody class="rows-in">${rows.slice(0, ctx.shown).map((a, i) => `
        <tr class="is-clickable ${['CLOSED', 'FALSE_POSITIVE'].includes(a.status) ? 'is-dim' : ''} ${picked.has(a.alert_id) ? 'is-picked' : ''}" style="--i:${Math.min(i, 20)}" data-id="${esc(a.alert_id)}">
          ${respond ? `<td class="col-check"><input type="checkbox" class="cb" data-pick="${esc(a.alert_id)}" aria-label="Select ${esc(a.alert_id)}" ${picked.has(a.alert_id) ? 'checked' : ''} ${a.status === 'INVESTIGATING' ? 'disabled title="Under investigation"' : ''}></td>` : ''}
          <td class="al-sev">${sev(a.severity)}</td>
          <td class="al-sig"><span class="cell-main">${esc(a.signature)}</span><span class="cell-sub"><span class="mono">${esc(a.alert_id)}</span> &middot; ${esc(a.category)}${a.suppressed_by ? ' &middot; suppressed' : ''}</span></td>
          <td class="hide-sm al-flow">${flow(a.source_ip, a.dest_ip, a.dest_port)}</td>
          <td class="hide-md al-own">${a.assignee_name ? `<span class="owner-chip"><span class="owner-chip__i">${esc(initials(a.assignee_name))}</span>${esc(a.assignee_name)}</span>` : '<span class="small muted">-</span>'}</td>
          <td class="al-st">${pill(a.status)}</td>
          <td class="num hide-sm small muted nowrap al-time" title="${stamp(a.detected_at)}">${ago(a.detected_at)}</td>
          <td class="al-act">${respond ? `<button class="btn btn--sm ${OPEN.includes(a.status) && a.status !== 'INVESTIGATING' ? '' : 'btn--ghost'}" data-run="${esc(a.alert_id)}" ${a.status === 'INVESTIGATING' ? 'disabled' : ''} title="Run investigation">Run</button>` : ''}</td>
        </tr>`).join('')}</tbody>
    </table></div>
    <div class="table-foot">${Math.min(rows.length, ctx.shown)} of ${rows.length}${rows.length !== all.length ? ` (${all.length} loaded)` : ''}${rows.length > ctx.shown ? ` <button class="btn btn--ghost btn--sm" id="al-more">Show ${Math.min(PAGE, rows.length - ctx.shown)} more</button>` : ''}</div>` : empty;
  if ($('#al-more', el)) $('#al-more', el).onclick = () => { ctx.shown += PAGE; paint(); };

  $$('tr[data-id]', el).forEach((r) => { r.onclick = (e) => { if (!e.target.closest('[data-run], .col-check')) openAlert(r.dataset.id, navigate); }; });
  $$('[data-run]', el).forEach((b) => { b.onclick = (e) => { e.stopPropagation(); navigate(`investigate/${b.dataset.run}?run=1`); }; });
  $$('[data-pick]', el).forEach((c) => {
    c.onchange = () => {
      if (c.checked) picked.add(c.dataset.pick); else picked.delete(c.dataset.pick);
      c.closest('tr').classList.toggle('is-picked', c.checked);
      const head = $('#al-all', el);
      if (head) head.checked = selectable.every((a) => picked.has(a.alert_id));
      paintBulk();
    };
  });
  const head = $('#al-all', el);
  if (head) head.onchange = () => { selectable.forEach((a) => (head.checked ? picked.add(a.alert_id) : picked.delete(a.alert_id))); paint(); };
  paintBulk();
  hydrateIcons(el);
}

async function paintBulk() {
  const { el, picked } = ctx;
  const bar = $('#al-bulk', el);
  if (!picked.size) { bar.hidden = true; bar.innerHTML = ''; return; }
  const fresh = bar.hidden;
  bar.hidden = false;
  if (!fresh && $('.bulkbar__n', bar)) { $('.bulkbar__n', bar).textContent = `${picked.size} selected`; return; }
  let people = [];
  try { people = await assignableUsers(); } catch { /* assign menu stays empty */ }
  bar.innerHTML = `
    <span class="bulkbar__n">${picked.size} selected</span>
    <select class="select" id="bk-owner" aria-label="Assign to"><option value="">Assign to...</option><option value="none">Nobody (unassign)</option>${people.map((u) => `<option value="${u.id}">${esc(u.name)}</option>`).join('')}</select>
    <button class="btn btn--sm" data-bk="CLOSED">Close</button>
    <button class="btn btn--sm" data-bk="FALSE_POSITIVE">False positive</button>
    <button class="btn btn--sm btn--ghost" data-bk="NEW">Reopen</button>
    <button class="btn btn--sm btn--ghost bulkbar__clear" id="bk-clear">Clear</button>`;
  const run = (btn, body, msg) => busy(btn, async () => {
    try {
      const r = await api('/alerts/bulk', { method: 'POST', body: { ids: [...picked], ...body } });
      toast(msg(r.updated), r.skipped ? `${r.skipped} skipped (under investigation or gone)` : '', 'ok');
      picked.clear();
      emit('data:changed');
    } catch (e) { toast('Bulk action failed', e.message, 'error'); }
  });
  $('#bk-owner', bar).onchange = (e) => {
    const v = e.target.value;
    if (!v) return;
    const who = v === 'none' ? null : Number(v);
    run(null, { action: 'assign', user_id: who }, (n) => (who ? `${n} assigned to ${people.find((u) => u.id === who).name}` : `${n} unassigned`));
  };
  $$('[data-bk]', bar).forEach((b) => {
    b.onclick = () => run(b, { action: 'status', status: b.dataset.bk }, (n) => `${n} alert${n === 1 ? '' : 's'} set to ${b.textContent.toLowerCase()}`);
  });
  $('#bk-clear', bar).onclick = () => { picked.clear(); paint(); };
}