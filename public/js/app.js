import { $, $$, api, esc, sev, pill, toast, on, emit, state, closeLayer, layerOpen, modal } from './core.js';
import { icon, hydrateIcons } from './icons.js';
import { showGate, signOut } from './gate.js';
import { startActivity, openActivity } from './mcp-live.js';

const ROUTES = {
  overview: { title: 'Overview', load: () => import('./views/overview.js') },
  alerts: { title: 'Alerts', load: () => import('./views/alerts.js') },
  investigate: { title: 'Investigate', load: () => import('./views/investigate.js') },
  cases: { title: 'Cases', load: () => import('./views/cases.js') },
  approvals: { title: 'Approvals', load: () => import('./views/approvals.js') },
  hunts: { title: 'Threat hunting', load: () => import('./views/hunts.js') },
  containment: { title: 'Containment', load: () => import('./views/containment.js') },
  assets: { title: 'Assets', load: () => import('./views/assets.js') },
  reports: { title: 'Reports', load: () => import('./views/reports.js') },
  ip: { title: 'IP profile', load: () => import('./views/ip.js') },
  intel: { title: 'Threat intel', load: () => import('./views/intel.js') },
  telemetry: { title: 'Telemetry', load: () => import('./views/telemetry.js') },
  assistant: { title: 'Assistant', load: () => import('./views/assistant.js') },
  workflows: { title: 'Workflows', load: () => import('./views/workflows.js') },
  detections: { title: 'Detections', load: () => import('./views/detections.js') },
  documents: { title: 'Documents', load: () => import('./views/documents.js') },
  decisions: { title: 'Decisions', load: () => import('./views/decisions.js') },
  settings: { title: 'Settings', load: () => import('./views/settings.js') }
};

// A browser that kept an older index.html runs these scripts against markup
// they do not know, and the first missing element throws before boot. Reload
// once with a fresh URL so the current page is fetched, instead of leaving an
// empty frame. The flag stops a loop if the markup really is broken.
const STALE = !['#gate', '#shell', '#analyst-role', '#signout-btn', '#search-btn', '#menu-btn', '#view'].every((s) => $(s));
if (STALE) {
  if (!sessionStorage.getItem('aegis-reloaded')) {
    sessionStorage.setItem('aegis-reloaded', '1');
    location.replace(`${location.pathname}?v=${Date.now()}${location.hash}`);
  }
  throw new Error('Aegis: page markup is out of date; reloading.');
}
sessionStorage.removeItem('aegis-reloaded');
if (/[?&]v=\d+/.test(location.search)) history.replaceState(null, '', location.pathname + location.hash);

const view = $('#view');
let current = { name: null, cleanup: null, token: 0 };

export function navigate(path) {
  const target = `#/${path.replace(/^#?\/?/, '')}`;
  if (location.hash === target) route(true); else location.hash = target;
}

function parse() {
  const raw = location.hash.replace(/^#\/?/, '') || 'overview';
  const [pathPart, qs = ''] = raw.split('?');
  const [name, ...params] = pathPart.split('/').filter(Boolean).map(decodeURIComponent);
  return { name: ROUTES[name] ? name : 'overview', params, query: Object.fromEntries(new URLSearchParams(qs)) };
}

async function route(force = false) {
  const { name, params, query } = parse();
  const sameView = current.name === name && !force;
  const token = ++current.token;
  closeLayer();
  setNav(false);

  $$('.nav__item').forEach((a) => {
    const on = a.dataset.route === name;
    a.classList.toggle('is-active', on);
    if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  });
  $('#crumb').textContent = ROUTES[name].title;
  document.title = `${ROUTES[name].title} - Aegis`;

  let mod;
  try { mod = await ROUTES[name].load(); } catch (e) { toast('Could not load view', e.message, 'error'); return; }
  if (token !== current.token) return;

  if (!sameView && current.name) {
    view.classList.remove('is-entering');
    view.classList.add('is-leaving');
    await new Promise((r) => setTimeout(r, 130));
    if (token !== current.token) return;
  }
  if (typeof current.cleanup === 'function') current.cleanup();
  current.cleanup = null;
  current.name = name;

  view.classList.remove('is-leaving');
  if (!sameView) {
    window.scrollTo({ top: 0 });
    void view.offsetWidth;
    view.classList.add('is-entering');
  }
  try {
    current.cleanup = await mod.render({ el: view, params, query, navigate, refresh: sameView });
  } catch (e) {
    view.innerHTML = `<div class="empty">${icon('alert')}<b>Something went wrong</b><span class="small">${esc(e.message)}</span><button class="btn mt-12" id="retry">Retry</button></div>`;
    $('#retry').onclick = () => route(true);
  }
  hydrateIcons(view);
}

// Views re-render in place when another view or panel mutates data.
on('data:changed', () => {
  scheduleChrome();
  if (current.name && !layerOpen()) {
    import(`./views/${current.name}.js`).then((m) => (m.onDataChanged ? m.onDataChanged() : null));
  }
});

// ---- Chrome: health, config, open count ----------------------------------
// Health and config barely change; the open count does. Health and config are
// re-read at most once a minute, the badge on every refresh.
let chromeAt = 0;
let chromeTimer = null;
function scheduleChrome() {
  clearTimeout(chromeTimer);
  chromeTimer = setTimeout(refreshChrome, 800);
}

async function refreshChrome() {
  clearTimeout(chromeTimer);
  try {
    const full = !state.health || Date.now() - chromeAt > 60000;
    const [health, config, count, appr] = await Promise.all([
      full ? api('/health') : state.health, full ? api('/config') : state.config, api('/alerts/count'), api('/approvals/count').catch(() => ({ pending: 0 }))
    ]);
    if (full) chromeAt = Date.now();
    state.health = health;
    state.config = config;
    const dot = $('#sys-dot');
    dot.className = `live-dot ${health.storage.ok ? (health.storage.kind === 'supabase' ? '' : 'live-dot--warn') : 'live-dot--off'}`;
    $('#sys-store').textContent = health.storage.kind === 'supabase' ? 'Supabase' : 'Local file';
    $('#sys-store').title = health.storage.detail || '';
    $('#brand-env').textContent = health.demo ? 'demo' : health.storage.kind === 'supabase' ? 'supabase' : 'local';
    $('#sys-engine').textContent = health.engine.llm && config.engine === 'llm' ? `LLM: ${health.engine.provider || 'model'}` : 'Rule-based';
    $('#sys-engine').title = health.engine.llm ? `Language model: ${health.engine.provider} ${health.engine.model}` : 'No language model connected';
    $('#nav-open').textContent = count.open ? String(count.open) : '';
    $('#nav-appr').textContent = appr.pending ? String(appr.pending) : '';
  } catch {
    $('#sys-dot').className = 'live-dot live-dot--off';
    $('#sys-store').textContent = 'Offline';
  }
}

function tickClock() {
  const d = new Date();
  $('#clock').textContent = `${d.toISOString().slice(11, 19)} UTC`;
}

// ---- Theme ---------------------------------------------------------------
$('#theme-btn').onclick = () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.classList.add('theme-anim');
  document.documentElement.dataset.theme = next;
  localStorage.setItem('aegis.theme', next);
  setTimeout(() => document.documentElement.classList.remove('theme-anim'), 400);
};

// Mobile drawer: the shell's ::after is the backdrop, so any tap outside the
// rail closes it, as do Escape and navigation.
function setNav(open) {
  const shell = $('#shell');
  if (!shell) return;
  shell.classList.toggle('nav-open', open);
  document.body.classList.toggle('nav-lock', open);
  $('#menu-btn').setAttribute('aria-expanded', String(open));
}
$('#menu-btn').onclick = (e) => { e.stopPropagation(); setNav(!$('#shell').classList.contains('nav-open')); };
document.addEventListener('click', (e) => {
  if ($('#shell').classList.contains('nav-open') && !e.target.closest('#rail')) setNav(false);
});
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && $('#shell').classList.contains('nav-open')) setNav(false); });
window.addEventListener('scroll', () => $('#topbar').classList.toggle('is-scrolled', window.scrollY > 4), { passive: true });

// ---- Command palette -----------------------------------------------------
const JUMPS = [
  { label: 'Go to overview', path: 'overview', ic: 'grid' },
  { label: 'Go to alerts', path: 'alerts', ic: 'bell' },
  { label: 'Open investigation workspace', path: 'investigate', ic: 'scan' },
  { label: 'Cases', path: 'cases', ic: 'file' },
  { label: 'New case from an attacker kill chain', path: 'cases?kc=1', ic: 'activity' },
  { label: 'Approval queue', path: 'approvals', ic: 'shieldCheck' },
  { label: 'Threat hunting', path: 'hunts', ic: 'search' },
  { label: 'ATT&CK technique rollup', path: 'hunts?tab=attack', ic: 'chart' },
  { label: 'Containment rules and probe', path: 'containment', ic: 'shield' },
  { label: 'Suppression rules', path: 'containment?tab=tuning', ic: 'filter' },
  { label: 'Reports: SLA, ATT&CK coverage, top attackers', path: 'reports', ic: 'chart' },
  { label: 'My queue', path: 'alerts?mine=1', ic: 'user' },
  { label: 'Assets and CVE knowledge base', path: 'assets', ic: 'server' },
  { label: 'Telemetry', path: 'telemetry', ic: 'terminal' },
  { label: 'Ask the assistant', path: 'assistant', ic: 'chat' },
  { label: 'Workflows and playbooks', path: 'workflows', ic: 'flow' },
  { label: 'Workflow run history', path: 'workflows?tab=runs', ic: 'activity' },
  { label: 'Custom detection rules (Sigma)', path: 'detections', ic: 'code' },
  { label: 'Upload a document or IOC list', path: 'documents', ic: 'upload' },
  { label: 'Decision accuracy', path: 'decisions', ic: 'scale' },
  { label: 'Backup and restore', path: 'settings?section=backup', ic: 'archive' },
  { label: 'Connect a language model', path: 'settings?section=llm', ic: 'cpu' },
  { label: 'Settings', path: 'settings', ic: 'sliders' }
];
const ACTIONS = [{ label: 'AI assistant activity (live)', run: openActivity, ic: 'cpu' }];

function openPalette() {
  if (layerOpen()) return;
  const panel = modal(`
    <div class="palette__input">${icon('search')}<input id="pal-q" placeholder="Alert id, IP, hostname, CVE, rule..." autocomplete="off" spellcheck="false" autofocus></div>
    <div class="palette__results" id="pal-res"></div>
    <div class="palette__foot"><span><span class="kbd">&uarr;</span> <span class="kbd">&darr;</span> move</span><span><span class="kbd">Enter</span> open</span><span><span class="kbd">Esc</span> close</span></div>`);
  panel.classList.add('palette');
  const input = $('#pal-q', panel);
  const res = $('#pal-res', panel);
  let items = [];
  let sel = 0;
  let seq = 0;

  const paint = (groups) => {
    items = [];
    res.innerHTML = groups.filter((g) => g.rows.length).map((g) => `
      <div class="palette__group">${esc(g.name)}</div>
      ${g.rows.map((r) => { items.push(r); return `<div class="palette__item" data-i="${items.length - 1}">${r.lead}<div class="grow"><div class="truncate">${esc(r.title)}</div>${r.sub ? `<div class="small muted truncate">${esc(r.sub)}</div>` : ''}</div>${r.tail || ''}</div>`; }).join('')}`).join('')
      || `<div class="palette__hint">Nothing matches "${esc(input.value)}". Try an IP like 10.0.4.88 or a CVE id.</div>`;
    sel = 0;
    mark();
    $$('.palette__item', res).forEach((el) => {
      el.onmouseenter = () => { sel = Number(el.dataset.i); mark(); };
      el.onclick = () => pick(Number(el.dataset.i));
    });
  };
  const mark = () => $$('.palette__item', res).forEach((el) => {
    const on = Number(el.dataset.i) === sel;
    el.classList.toggle('is-sel', on);
    if (on) el.scrollIntoView({ block: 'nearest' });
  });
  const pick = (i) => { const it = items[i]; if (!it) return; closeLayer(); setTimeout(() => (it.run ? it.run() : navigate(it.path)), 240); };

  const jumpRows = (q) => JUMPS.filter((j) => j.label.toLowerCase().includes(q.toLowerCase()))
    .map((j) => ({ lead: icon(j.ic), title: j.label, path: j.path, tail: '<span class="kbd">Go</span>' }))
    .concat(ACTIONS.filter((j) => j.label.toLowerCase().includes(q.toLowerCase())).map((j) => ({ lead: icon(j.ic), title: j.label, run: j.run, tail: '<span class="kbd">Open</span>' })));

  const search = async () => {
    const q = input.value.trim();
    const mine = ++seq;
    if (q.length < 2) { paint([{ name: 'Jump to', rows: jumpRows(q) }]); return; }
    let r;
    try { r = await api(`/search?q=${encodeURIComponent(q)}`); } catch { return; }
    if (mine !== seq) return;
    paint([
      { name: 'Address', rows: r.ip ? [{ lead: icon('globe'), title: `Profile for ${r.ip}`, sub: 'Every alert, rule, investigation and log line for this address', path: `ip/${r.ip}`, tail: '<span class="kbd">Open</span>' }] : [] },
      { name: 'Alerts', rows: r.alerts.map((a) => ({ lead: icon('bell'), title: a.signature, sub: `${a.alert_id} - ${a.source_ip} to ${a.dest_ip}`, tail: sev(a.severity), path: `investigate/${a.alert_id}` })) },
      { name: 'Investigations', rows: r.investigations.map((i) => ({ lead: icon('scan'), title: `${i.investigation_id} - ${i.alert_id}`, sub: i.summary, tail: pill(i.outcome), path: `investigate/${i.alert_id}` })) },
      { name: 'Assets', rows: r.assets.map((a) => ({ lead: icon('server'), title: a.hostname, sub: `${a.ip_address} - ${a.os_version}`, path: `telemetry?host=${a.ip_address}` })) },
      { name: 'CVEs', rows: r.cves.map((c) => ({ lead: icon('bug'), title: `${c.cve_id} - ${c.title}`, sub: `CVSS ${c.cvss_score}`, tail: sev(c.severity), path: `assets?tab=kb&q=${encodeURIComponent(c.cve_id)}` })) },
      { name: 'Rules', rows: r.rules.map((x) => ({ lead: icon('shield'), title: `${x.action} ${x.target_ip}`, sub: `${x.rule_id} - ${x.reason}`, tail: pill(x.is_active ? 'ACTIVE' : 'DISABLED'), path: 'containment' })) },
      { name: 'Jump to', rows: jumpRows(q) }
    ]);
  };
  let t;
  input.oninput = () => { clearTimeout(t); t = setTimeout(search, 140); };
  input.onkeydown = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); mark(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); mark(); }
    else if (e.key === 'Enter') { e.preventDefault(); pick(sel); }
  };
  search();
}

$('#search-btn').onclick = openPalette;
document.addEventListener('keydown', (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName) || document.activeElement?.isContentEditable;
  if ((e.key === 'k' && (e.ctrlKey || e.metaKey)) || (e.key === '/' && !typing)) { e.preventDefault(); openPalette(); }
});

// ---- Session ---------------------------------------------------------------
function paintUser(user) {
  state.user = user;
  const name = user.name || user.email;
  $('#analyst-name').textContent = name;
  $('#analyst-name').title = user.email;
  $('#analyst-role').textContent = { admin: 'Administrator', analyst: 'Analyst', viewer: 'Read only' }[user.role] || user.role;
  $('#analyst-initials').textContent = name.split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('');
  document.body.toggleAttribute('data-readonly', user.role === 'viewer');
}

$('#signout-btn').onclick = signOut;

let reauth = false;
on('auth:required', async () => {
  if (reauth || !state.user) return;
  reauth = true;
  closeLayer();
  toast('Session ended', 'Sign in again to continue.', 'info');
  const st = await fetch('/api/auth/state').then((r) => r.json()).catch(() => ({ needs_setup: false }));
  const user = await showGate(st);
  reauth = false;
  paintUser(user);
  $('#shell').hidden = false;
  chromeAt = 0;
  refreshChrome();
  route(true);
});

// ---- Boot ----------------------------------------------------------------
async function boot() {
  hydrateIcons(document);
  let st;
  try {
    st = await fetch('/api/auth/state', { credentials: 'same-origin' }).then((r) => r.json());
  } catch {
    document.body.innerHTML = '<div class="empty" style="min-height:100vh"><b>Aegis server is not reachable</b><span class="small">Check that the service is running, then reload.</span></div>';
    return;
  }
  state.demo = Boolean(st.demo);
  const user = st.user || await showGate(st);
  paintUser(user);
  $('#shell').hidden = false;
  tickClock();
  setInterval(tickClock, 1000);
  window.addEventListener('hashchange', () => route());
  await refreshChrome();
  const h = state.health;
  if (h && h.storage.warning) toast('Storage fallback', h.storage.warning, 'error', 9000);
  if (h && h.enforcement && h.enforcement.warning) toast('Enforcement', h.enforcement.warning, 'error', 9000);
  // Background tabs do not poll; coming back refreshes straight away.
  setInterval(() => { if (!document.hidden) refreshChrome(); }, 30000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) scheduleChrome(); });
  route();
  startActivity();
}
boot();

export { emit };