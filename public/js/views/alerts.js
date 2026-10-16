import { $, $$, api, esc, sev, pill, flow, ago, stamp, emptyState } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { openAlert, openNewAlert } from '../panels.js';

const SEVS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUSES = [['OPEN', 'Open'], ['', 'Any status'], ['NEW', 'New'], ['INVESTIGATING', 'Investigating'], ['CONFIRMED', 'Confirmed'], ['CONTAINED', 'Contained'], ['MITIGATED', 'Mitigated'], ['FALSE_POSITIVE', 'False positive'], ['CLOSED', 'Closed']];
const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const OPEN = ['NEW', 'INVESTIGATING', 'CONFIRMED'];

let ctx = null;
const f = { sev: 'ALL', status: 'OPEN', q: '', sort: 'severity' };

export async function render({ el, navigate, query }) {
  ctx = { el, navigate, all: [] };
  if (query.q) f.q = query.q;
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Alerts</h1>
        <p class="page-sub">Sensor detections and manual submissions.</p>
      </div>
      <div class="page-actions"><button class="btn btn--primary" id="al-new">New alert</button></div>
    </div>
    <section class="panel reveal">
      <div class="toolbar">
        <div class="input-icon">${icon('search')}<input class="input" id="al-q" placeholder="Filter: signature, IP, id" value="${esc(f.q)}"></div>
        <div class="seg" id="al-sev" role="tablist"></div>
        <div class="toolbar__end">
          <select class="select" id="al-status" style="width:160px">${STATUSES.map(([v, t]) => `<option value="${v}" ${f.status === v ? 'selected' : ''}>${t}</option>`).join('')}</select>
          <select class="select" id="al-sort" style="width:140px"><option value="severity">Severity</option><option value="newest">Newest</option></select>
        </div>
      </div>
      <div id="al-table"><div style="padding:18px" class="stack">${'<div class="skeleton" style="height:38px"></div>'.repeat(5)}</div></div>
    </section>`;
  $('#al-new', el).onclick = () => openNewAlert(navigate);
  let t;
  $('#al-q', el).oninput = (e) => { clearTimeout(t); t = setTimeout(() => { f.q = e.target.value.trim(); paint(); }, 120); };
  $('#al-status', el).onchange = (e) => { f.status = e.target.value; paint(); };
  $('#al-sort', el).value = f.sort;
  $('#al-sort', el).onchange = (e) => { f.sort = e.target.value; paint(); };
  await load();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) load(); }

async function load() {
  ctx.all = await api('/alerts');
  paint();
}

function paint() {
  const { el, navigate, all } = ctx;
  const q = f.q.toLowerCase();
  const byStatus = all.filter((a) => (f.status === 'OPEN' ? OPEN.includes(a.status) : !f.status || a.status === f.status))
    .filter((a) => !q || [a.alert_id, a.signature, a.source_ip, a.dest_ip, a.category].some((x) => String(x).toLowerCase().includes(q)));
  const counts = Object.fromEntries(SEVS.map((s) => [s, s === 'ALL' ? byStatus.length : byStatus.filter((a) => a.severity === s).length]));
  $('#al-sev', el).innerHTML = SEVS.map((s) => `<button class="${f.sev === s ? 'is-on' : ''}" data-sev="${s}" role="tab" aria-selected="${f.sev === s}">${s === 'ALL' ? 'All' : s[0] + s.slice(1).toLowerCase()} <span class="n">${counts[s]}</span></button>`).join('');
  $$('[data-sev]', el).forEach((b) => { b.onclick = () => { f.sev = b.dataset.sev; paint(); }; });

  const rows = byStatus.filter((a) => f.sev === 'ALL' || a.severity === f.sev)
    .sort((a, b) => (f.sort === 'severity' ? RANK[b.severity] - RANK[a.severity] : 0) || b.detected_at.localeCompare(a.detected_at));

  $('#al-table', el).innerHTML = rows.length ? `
    <div class="table-wrap"><table class="table">
      <thead><tr><th style="width:110px">Severity</th><th>Signature</th><th class="hide-sm">Flow</th><th>Status</th><th class="num hide-sm">Detected</th><th style="width:1%"></th></tr></thead>
      <tbody class="rows-in">${rows.map((a, i) => `
        <tr class="is-clickable ${['CLOSED', 'FALSE_POSITIVE'].includes(a.status) ? 'is-dim' : ''}" style="--i:${Math.min(i, 20)}" data-id="${esc(a.alert_id)}">
          <td>${sev(a.severity)}</td>
          <td><span class="cell-main">${esc(a.signature)}</span><span class="cell-sub"><span class="mono">${esc(a.alert_id)}</span> &middot; ${esc(a.category)} &middot; ${esc(a.sensor || '')}</span></td>
          <td class="hide-sm">${flow(a.source_ip, a.dest_ip, a.dest_port)}</td>
          <td>${pill(a.status)}</td>
          <td class="num hide-sm small muted" title="${stamp(a.detected_at)}">${ago(a.detected_at)}</td>
          <td><button class="btn btn--sm ${OPEN.includes(a.status) && a.status !== 'INVESTIGATING' ? '' : 'btn--ghost'}" data-run="${esc(a.alert_id)}" ${a.status === 'INVESTIGATING' ? 'disabled' : ''} title="Run investigation">Run</button></td>
        </tr>`).join('')}</tbody>
    </table></div>
    <div class="table-foot">${rows.length} of ${all.length}</div>`
    : emptyState(all.length ? 'No matches' : 'No alerts', all.length ? 'Try a different filter.' : 'Create one with New alert.', 'inbox');

  $$('tr[data-id]', el).forEach((r) => { r.onclick = (e) => { if (!e.target.closest('[data-run]')) openAlert(r.dataset.id, navigate); }; });
  $$('[data-run]', el).forEach((b) => { b.onclick = (e) => { e.stopPropagation(); navigate(`investigate/${b.dataset.run}?run=1`); }; });
  hydrateIcons(el);
}