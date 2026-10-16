import { $, $$, api, esc, stamp, markPayload, emptyState } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

const TYPES = [['', 'All sources'], ['http_access', 'HTTP access'], ['edr_process', 'EDR process'], ['auth_log', 'Auth log'], ['system', 'System']];
const TYPE_C = { http_access: 'var(--accent)', edr_process: 'var(--crit)', auth_log: 'var(--high)', system: 'var(--low)' };

let ctx = null;

export async function render({ el, navigate, query }) {
  ctx = { el, navigate, host: query.host || '', type: query.type || '', client: query.client || '' };
  const assets = await api('/assets');
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Telemetry</h1>
        <p class="page-sub">HTTP access, EDR, auth and system logs. Known attack markers are highlighted.</p>
      </div>
    </div>
    <section class="panel reveal">
      <div class="toolbar">
        <select class="select" id="tl-host" style="width:230px"><option value="">All hosts</option>${assets.map((a) => `<option value="${esc(a.ip_address)}">${esc(a.hostname)} (${esc(a.ip_address)})</option>`).join('')}</select>
        <select class="select" id="tl-type" style="width:160px">${TYPES.map(([v, t]) => `<option value="${v}">${t}</option>`).join('')}</select>
        <div class="input-icon">${icon('search')}<input class="input input--mono" id="tl-client" placeholder="Remote IP" value="${esc(ctx.client)}"></div>
        <div class="toolbar__end"><button class="btn btn--ghost btn--sm" id="tl-clear">Clear</button><span class="small muted" id="tl-count"></span></div>
      </div>
      <div id="tl-list"></div>
    </section>`;
  $('#tl-host', el).value = ctx.host;
  $('#tl-type', el).value = ctx.type;
  const sync = () => {
    const p = new URLSearchParams();
    if (ctx.host) p.set('host', ctx.host);
    if (ctx.type) p.set('type', ctx.type);
    if (ctx.client) p.set('client', ctx.client);
    history.replaceState(null, '', `#/telemetry${p.toString() ? `?${p}` : ''}`);
    load();
  };
  $('#tl-host', el).onchange = (e) => { ctx.host = e.target.value; sync(); };
  $('#tl-type', el).onchange = (e) => { ctx.type = e.target.value; sync(); };
  let t;
  $('#tl-client', el).oninput = (e) => { clearTimeout(t); t = setTimeout(() => { ctx.client = e.target.value.trim(); sync(); }, 250); };
  $('#tl-clear', el).onclick = () => {
    ctx.host = ''; ctx.type = ''; ctx.client = '';
    $('#tl-host', el).value = ''; $('#tl-type', el).value = ''; $('#tl-client', el).value = '';
    sync();
  };
  await load();
}

export function onDataChanged() {}

async function load() {
  const { el } = ctx;
  const p = new URLSearchParams({ limit: '200' });
  if (ctx.host) p.set('host_ip', ctx.host);
  if (ctx.type) p.set('log_type', ctx.type);
  if (ctx.client && /^[\d.]+$/.test(ctx.client)) p.set('client_ip', ctx.client);
  const logs = await api(`/logs?${p}`);
  $('#tl-count', el).textContent = `${logs.length} entr${logs.length === 1 ? 'y' : 'ies'}`;
  $('#tl-list', el).innerHTML = logs.length ? `<div class="rows-in">${logs.map((l, i) => `
    <div class="logline" style="--i:${Math.min(i, 24)}">
      <span class="muted" title="${stamp(l.logged_at)}">${stamp(l.logged_at).slice(11, 19)}</span>
      <span>${esc(l.host_ip)}</span>
      <span style="color:${TYPE_C[l.log_type] || 'var(--ink-3)'}">${esc(l.log_type)}</span>
      <span class="logline__raw">${markPayload(l.raw_entry)}</span>
    </div>`).join('')}</div>` : emptyState('No entries', 'Nothing matches this filter.', 'terminal');
  hydrateIcons(el);
}