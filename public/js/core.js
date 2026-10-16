import { icon } from './icons.js';

// ---- DOM / formatting helpers ---------------------------------------------
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]);

export function ago(iso) {
  if (!iso) return '-';
  const s = Math.max(0, (Date.now() - new Date(iso)) / 1000);
  if (s < 45) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m ago`;
  return `${Math.round(s / 86400)}d ago`;
}
export const stamp = (iso) => (iso ? new Date(iso).toISOString().replace('T', ' ').slice(0, 19) + 'Z' : '-');
export const shortTime = (iso) => (iso ? new Date(iso).toISOString().slice(11, 19) : '-');
export const num = (n) => (n == null ? '-' : Number(n).toLocaleString('en-US'));
export const label = (s) => String(s || '').replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase());

export const sev = (s) => `<span class="sev sev--${esc(s)}">${esc(s)}</span>`;
export const pill = (s, text) => `<span class="pill pill--${esc(s)}">${esc(text || label(s))}</span>`;
export const flow = (a, b, port) => `<span class="flow">${esc(a)}${icon('arrow')}${esc(b)}${port ? `:${esc(port)}` : ''}</span>`;

// Highlights the parts of a payload that matter to an analyst.
export function markPayload(text) {
  return esc(text)
    .replace(/\$\{jndi:[^}]+\}/gi, (m) => `<mark>${m}</mark>`)
    .replace(/(\.%2e|%2e%2e)[^\s]*/gi, (m) => `<mark>${m}</mark>`)
    .replace(/(OR\+1=1--|union\s+select)/gi, (m) => `<mark>${m}</mark>`)
    .replace(/(Failed password[^\n]*)/g, (m) => `<mark>${m}</mark>`)
    .replace(/(JA3=[a-f0-9]+|SNI=[^\s]+)/gi, (m) => `<mark>${m}</mark>`);
}

export function emptyState(title, text, ic = 'inbox') {
  return `<div class="empty">${icon(ic)}<b>${esc(title)}</b><span class="small">${esc(text)}</span></div>`;
}

// Animated number counter for KPI tiles.
export function countUp(el, to, { duration = 900, format = num } = {}) {
  if (to == null || Number.isNaN(Number(to))) { el.textContent = '-'; return; }
  const from = Number(el.dataset.v || 0);
  el.dataset.v = to;
  if (matchMedia('(prefers-reduced-motion: reduce)').matches || from === to) { el.textContent = format(to); return; }
  const start = performance.now();
  const step = (t) => {
    const p = Math.min(1, (t - start) / duration);
    const e = 1 - Math.pow(1 - p, 3);
    el.textContent = format(Math.round(from + (to - from) * e));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// ---- API ---------------------------------------------------------------------
// Every state-changing request carries X-Aegis-Client; the server refuses
// cookie-authenticated writes without it (cross-site forms cannot set it).
function headersFor(method, body, type = 'application/json') {
  const h = {};
  if (body !== undefined) h['Content-Type'] = type;
  if (method !== 'GET') h['X-Aegis-Client'] = 'web';
  return h;
}

function failed(res, data) {
  if (res.status === 401) emit('auth:required');
  const err = new Error((data && data.error) || `Request failed (${res.status})`);
  err.status = res.status;
  return err;
}

export async function api(path, { method = 'GET', body, signal, raw, type } = {}) {
  const res = await fetch(`/api${path}`, {
    method,
    signal,
    credentials: 'same-origin',
    headers: headersFor(method, raw !== undefined ? raw : body, raw !== undefined ? type || 'text/plain' : undefined),
    body: raw !== undefined ? raw : body !== undefined ? JSON.stringify(body) : undefined
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) throw failed(res, data);
  return data;
}

// POST that consumes a server-sent event stream.
export async function stream(path, body, onEvent, signal) {
  const res = await fetch(`/api${path}`, { method: 'POST', credentials: 'same-origin', headers: headersFor('POST', body), body: JSON.stringify(body), signal });
  if (!res.ok || !res.body) {
    if (res.status === 401) emit('auth:required');
    let msg = `Request failed (${res.status})`;
    try { msg = (await res.json()).error || msg; } catch { /* not json */ }
    throw new Error(msg);
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf('\n\n')) >= 0) {
      const chunk = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      const line = chunk.split('\n').find((l) => l.startsWith('data: '));
      if (line) {
        try { onEvent(JSON.parse(line.slice(6))); } catch { /* ignore malformed */ }
      }
    }
  }
}

// ---- Toasts ------------------------------------------------------------------
export function toast(title, msg = '', kind = 'info', ms = 4200) {
  const host = $('#toasts');
  const el = document.createElement('div');
  el.className = `toast toast--${kind}`;
  el.innerHTML = `<span class="toast__bar"></span><div><div class="toast__title">${esc(title)}</div>${msg ? `<div class="toast__msg">${esc(msg)}</div>` : ''}</div><button aria-label="Dismiss">&times;</button>`;
  const close = () => { el.classList.add('is-leaving'); setTimeout(() => el.remove(), 240); };
  el.querySelector('button').onclick = close;
  host.appendChild(el);
  if (host.children.length > 4) host.firstElementChild.remove();
  setTimeout(close, ms);
}

// ---- Overlays (drawer / modal) -----------------------------------------------
let openLayer = null;

export function closeLayer() {
  if (!openLayer) return;
  const { scrim, panel, onClose, restore } = openLayer;
  openLayer = null;
  scrim.classList.add('is-leaving');
  panel.classList.add('is-leaving');
  setTimeout(() => { scrim.remove(); panel.remove(); }, 220);
  document.body.style.overflow = '';
  if (onClose) onClose();
  if (restore && restore.focus) restore.focus();
}

export function openLayer_(kind, html, { onClose } = {}) {
  closeLayer();
  const scrim = document.createElement('div');
  scrim.className = 'scrim';
  const panel = document.createElement('div');
  panel.className = kind;
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-modal', 'true');
  panel.innerHTML = html;
  scrim.onclick = closeLayer;
  document.body.append(scrim, panel);
  document.body.style.overflow = 'hidden';
  openLayer = { scrim, panel, onClose, restore: document.activeElement };
  panel.querySelectorAll('[data-close]').forEach((b) => { b.onclick = closeLayer; });
  setTimeout(() => {
    const f = panel.querySelector('[autofocus], input, textarea, select, button:not([data-close])');
    if (f) f.focus();
  }, 30);
  return panel;
}
export const drawer = (html, opts) => openLayer_('drawer', html, opts);
export const modal = (html, opts) => openLayer_('modal', html, opts);
export const layerOpen = () => Boolean(openLayer);

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && openLayer) closeLayer();
});

// Marks a button busy while an async action runs.
export async function busy(btn, fn) {
  if (!btn) return fn();
  btn.classList.add('is-busy');
  btn.disabled = true;
  try { return await fn(); } finally { btn.classList.remove('is-busy'); btn.disabled = false; }
}

// Shared app state: bus for cross-view refresh.
export const bus = new EventTarget();
export const emit = (name, detail) => bus.dispatchEvent(new CustomEvent(name, { detail }));
export const on = (name, fn) => { bus.addEventListener(name, fn); return () => bus.removeEventListener(name, fn); };

export const state = { health: null, config: null, user: null, demo: false };

// Role checks mirror the server (src/security/auth.js). The server is the
// authority; these only decide what to show.
const PERMS = { admin: ['respond', 'configure', 'manage'], analyst: ['respond'], viewer: [] };
export const can = (perm) => Boolean(state.user && (PERMS[state.user.role] || []).includes(perm));

export async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch { /* ignore */ }
    ta.remove();
  }
  if (btn && !btn.dataset.copied) { const h = btn.innerHTML; btn.dataset.copied = '1'; btn.textContent = 'Copied'; setTimeout(() => { btn.innerHTML = h; delete btn.dataset.copied; }, 1400); }
}