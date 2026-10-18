import { $, $$, api, esc, ago, toast, drawer, emit } from './core.js';
import { icon } from './icons.js';

// Live view of what connected AI assistants (claude.ai, Claude Desktop, Cursor, ...)
// are doing in this console over MCP. The server writes a start and a finish row to
// the audit log for every tool call; this polls them and shows calls as they run.

const STALE_MS = 90000;           // a start with no finish after this is shown as "no result"
const RECENT_MS = 2 * 60000;
const calls = new Map();          // call key -> merged call
const grants = [];                // connector sign-ins / denials
const announced = new Set();
const rendered = new Set();
let lastId = 0;
let timer = null;
let panel = null;
let failures = 0;

const toastsOn = () => localStorage.getItem('aegis.aiToasts') !== 'off';
const keyOf = (e) => e.call_id || `r${e.id}`;
const startedAt = (c) => new Date(c.started_at || c.at).getTime();
const byNew = (a, b) => startedAt(b) - startedAt(a) || b.id - a.id;
const who = (c) => c.client || c.user || 'An assistant';
const isStale = (c) => c.status === 'running' && Date.now() - startedAt(c) > STALE_MS;
const running = () => [...calls.values()].filter((c) => c.status === 'running' && !isStale(c)).sort(byNew);
const ms = (n) => (n == null ? '' : n < 1000 ? `${n} ms` : `${(n / 1000).toFixed(1)} s`);

function absorb(events, fresh) {
  const touched = new Set();
  for (const e of [...events].reverse()) {
    lastId = Math.max(lastId, e.id);
    if (e.kind.startsWith('oauth.')) {
      if (e.kind === 'oauth.token') continue;
      grants.unshift(e);
      if (fresh && toastsOn()) toast(e.kind === 'oauth.granted' ? `${e.client} connected` : `${e.client} was denied`, e.kind === 'oauth.granted' ? `${e.user} gave it ${/write/.test(e.detail || '') ? 'read and action' : 'read-only'} access.` : `${e.user} refused the connection.`, e.kind === 'oauth.granted' ? 'ok' : 'info', 6000);
      continue;
    }
    const k = keyOf(e);
    const prev = calls.get(k);
    if (e.kind === 'mcp.start') {
      calls.set(k, prev ? { ...e, ...prev, args: prev.args || e.args, started_at: e.at } : { ...e, started_at: e.at });
    } else {
      calls.set(k, { ...(prev || {}), ...e, args: e.args || (prev && prev.args) || '', started_at: (prev && prev.started_at) || e.at, done_at: e.at });
    }
    touched.add(k);
  }
  grants.splice(12);
  if (calls.size > 150) [...calls.values()].sort(byNew).slice(120).forEach((c) => calls.delete(keyOf(c)));
  if (fresh) announce([...touched].map((k) => calls.get(k)).filter(Boolean));
}

// One toast when a call first shows up, and a second only if it failed or changed data.
function announce(list) {
  if (list.some((c) => c.write && c.status === 'ok' && !announced.has(`${keyOf(c)}:done`))) emit('data:changed');
  const out = [];
  for (const c of list.sort((a, b) => -byNew(a, b))) {
    const k = keyOf(c);
    if (!announced.has(k)) { announced.add(k); if (c.status !== 'ok' || c.write) announced.add(`${k}:done`); out.push(c); continue; }
    if (c.status !== 'running' && !announced.has(`${k}:done`) && (c.status === 'failed' || c.write)) { announced.add(`${k}:done`); out.push(c); }
    else if (c.status !== 'running') announced.add(`${k}:done`);
  }
  if (!toastsOn() || !out.length) return;
  if (out.length > 3) {
    toast(`${who(out[0])} made ${out.length} tool calls`, out.map((c) => c.title).slice(0, 6).join(', '), 'info', 6000);
    return;
  }
  for (const c of out) {
    const verb = c.status === 'running' ? 'is running' : c.status === 'failed' ? 'failed' : 'ran';
    const msg = [c.args, c.error, `as ${c.user}`].filter(Boolean).join(' \u00b7 ');
    toast(`${who(c)} ${verb} ${c.title}${c.write ? ' (changes data)' : ''}`, msg, c.status === 'failed' ? 'error' : c.status === 'ok' ? 'ok' : 'info', c.write ? 7000 : 4200);
  }
}

function paintChip() {
  const chip = $('#ai-live');
  if (!chip) return;
  const run = running();
  const last = [...calls.values()].sort(byNew)[0];
  const recent = last && Date.now() - new Date(last.done_at || last.started_at).getTime() < RECENT_MS;
  chip.classList.toggle('is-running', run.length > 0);
  chip.classList.toggle('is-write', run.some((c) => c.write));
  chip.classList.toggle('is-recent', !run.length && Boolean(recent));
  const text = run.length ? `${who(run[0])}: ${run[0].title}${run.length > 1 ? ` +${run.length - 1}` : ''}` : recent ? `${who(last)} active` : 'AI idle';
  $('.ai-live__text', chip).textContent = text;
  chip.title = run.length ? `${who(run[0])} is running ${run.map((c) => c.tool).join(', ')} as ${run[0].user}` : 'What connected AI assistants are doing';
}

function row(c) {
  const k = keyOf(c);
  const st = isStale(c) ? 'stale' : c.status;
  const isNew = !rendered.has(`${k}:${st}`);
  rendered.add(`${k}:${st}`);
  const label = { running: 'running', ok: 'done', failed: 'failed', stale: 'no result' }[st];
  return `<div class="ai-call ai-call--${st}${isNew ? ' is-new' : ''}">
    <span class="ai-call__st" title="${label}"></span>
    <div class="ai-call__main">
      <div class="ai-call__top"><b>${esc(c.title)}</b><span class="mono small muted">${esc(c.tool)}</span>${c.write ? '<span class="tag tag--warn">changes data</span>' : ''}<span class="ai-call__time" title="${esc(new Date(startedAt(c)).toLocaleString())}">${st === 'running' ? 'running' : ago(c.started_at)}</span></div>
      ${c.args ? `<div class="ai-call__args">${esc(c.args)}</div>` : ''}
      ${c.error ? `<div class="ai-call__err">${esc(c.error)}</div>` : ''}
      <div class="ai-call__who">${esc(c.user)}${c.client ? ` via <b>${esc(c.client)}</b>` : ''}${c.ms != null ? ` \u00b7 ${ms(c.ms)}` : ''}</div>
    </div>
  </div>`;
}

function paintPanel() {
  if (!panel || !panel.isConnected) { panel = null; return; }
  const list = [...calls.values()].sort(byNew);
  const run = running();
  $('#ai-sum', panel).innerHTML = run.length
    ? `<span class="live-dot ai-pulse"></span><b>${run.length} running now</b>`
    : list.length ? `<span class="live-dot"></span>Listening. Last call ${ago(list[0].done_at || list[0].started_at)}.` : '<span class="live-dot"></span>Listening for assistant activity.';
  $('#ai-feed', panel).innerHTML = list.length ? list.slice(0, 80).map(row).join('')
    : `<div class="empty" style="padding:28px 8px">${icon('cpu')}<b>No assistant activity yet</b><span class="small">Connect Claude under Settings, MCP server. Every tool it runs will appear here as it happens.</span></div>`;
  $('#ai-grants', panel).innerHTML = grants.length ? grants.map((g) => `<div class="ai-grant"><span class="tag ${g.kind === 'oauth.granted' ? 'tag--ok' : 'tag--warn'}">${g.kind === 'oauth.granted' ? 'connected' : 'denied'}</span><span><b>${esc(g.client || '')}</b> by ${esc(g.user)}${g.detail ? ` <span class="muted">${esc(g.detail)}</span>` : ''}</span><span class="ai-call__time">${ago(g.at)}</span></div>`).join('') : '<div class="small muted">No connector sign-ins yet.</div>';
}

export function openActivity() {
  panel = drawer(`
    <div class="drawer__head"><div class="grow"><div class="eyebrow">${icon('cpu')}Model Context Protocol</div><h2 class="drawer__title">AI assistant activity</h2><div class="ai-sum small" id="ai-sum"></div></div><button class="icon-btn icon-btn--bare" data-close aria-label="Close">${icon('x')}</button></div>
    <div class="drawer__body">
      <div><div class="section-title">Tool calls, live</div><div class="ai-feed" id="ai-feed"></div></div>
      <div><div class="section-title">Connections</div><div class="ai-grants" id="ai-grants"></div></div>
    </div>
    <div class="drawer__foot">
      <label class="row small grow"><input type="checkbox" id="ai-toasts" ${toastsOn() ? 'checked' : ''}> Pop up each call as it happens</label>
      <a class="btn btn--sm btn--ghost" href="#/settings" data-close>MCP settings</a>
    </div>
    <p class="small muted ai-foot">An assistant acts as the person who connected it, with their role, and every call is in the audit log. To cut it off, change that person's password (claude.ai) or revoke its API key.</p>`, { onClose: () => { panel = null; } });
  panel.classList.add('ai-drawer');
  $('#ai-toasts', panel).onchange = (e) => localStorage.setItem('aegis.aiToasts', e.target.checked ? 'on' : 'off');
  $$('[data-close]', panel).forEach((b) => b.addEventListener('click', () => { panel = null; }));
  paintPanel();
  poll();
}

async function poll() {
  clearTimeout(timer);
  if (document.hidden) { timer = setTimeout(poll, 15000); return; }
  try {
    const r = await api(`/mcp/activity?after=${lastId}&limit=${lastId ? 100 : 60}`);
    absorb(r.events, true);
    failures = 0;
  } catch (e) {
    failures += 1;
    if (e.status === 401 || e.status === 403) failures = Math.max(failures, 6);
  }
  paintChip();
  paintPanel();
  const run = running().length;
  const recent = [...calls.values()].some((c) => Date.now() - new Date(c.done_at || c.started_at).getTime() < RECENT_MS);
  timer = setTimeout(poll, failures ? Math.min(60000, 4000 * 2 ** Math.min(failures, 4)) : run ? 1500 : recent || panel ? 2500 : 5000);
}

// History loads quietly; only calls that arrive after sign-in pop up.
export async function startActivity() {
  const chip = $('#ai-live');
  if (chip) chip.onclick = openActivity;
  try {
    const r = await api('/mcp/activity?limit=60');
    absorb(r.events, false);
    for (const c of calls.values()) { announced.add(keyOf(c)); if (c.status !== 'running') announced.add(`${keyOf(c)}:done`); }
  } catch { /* first poll retries */ }
  paintChip();
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
  timer = setTimeout(poll, 2500);
}