import { $, $$, api, stream, esc, ago, stamp, emptyState, toast, busy, can, modal, closeLayer, label } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

// Analyst assistant. The model answers from tool calls against this deployment;
// anything that would change state is held until a person approves it here.

const PROMPTS = [
  'What happened in the last 24 hours?',
  'Which attacking addresses are still not contained?',
  'Summarise the open cases by severity and owner.',
  'Which ATT&CK techniques did we see most this week?'
];

let ctx = null;

export async function render({ el, query, navigate }) {
  if (ctx && ctx.abort) ctx.abort.abort();
  ctx = { el, navigate, threads: [], thread: null, working: false, abort: null, id: query.t || null };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Assistant</h1>
        <p class="page-sub">Ask about alerts, cases, rules and intel in plain language. Every answer is built from live tool calls, and nothing changes until you approve it.</p>
      </div>
      <div class="page-actions" id="as-model"></div>
    </div>
    <div id="as-root" class="reveal"><div class="panel" style="padding:18px"><div class="skeleton" style="height:320px"></div></div></div>`;

  let status;
  try { status = await api('/workbench/status'); } catch (e) { $('#as-root', el).innerHTML = `<section class="panel">${emptyState('Could not reach the server', e.message, 'alert')}</section>`; return cleanup; }
  if (!document.body.contains(el)) return cleanup;
  if (status.pending_migration) { $('#as-root', el).innerHTML = `<section class="panel">${emptyState('Database update needed', `Apply the ${status.pending_migration} migration, then reload.`, 'database')}</section>`; return cleanup; }
  if (!status.assistant) {
    $('#as-root', el).innerHTML = `<section class="panel as-off">
      ${icon('key')}
      <h2>The assistant needs a language model</h2>
      <p>Set <code class="code">GROQ_API_KEY</code> on the server and redeploy. The key stays on the server; the browser never sees it.</p>
      <p class="small muted">Everything else in Aegis works without it. Investigations fall back to the deterministic engine.</p>
    </section>`;
    hydrateIcons(el);
    return cleanup;
  }
  $('#as-model', el).innerHTML = `<span class="as-model" title="Model used for answers">${icon('cpu')}<span class="mono">${esc(status.model)}</span></span>`;

  $('#as-root', el).innerHTML = `
    <div class="as">
      <aside class="as-side panel">
        <div class="as-side__head">
          <span class="panel__title">Conversations</span>
          <button class="btn btn--sm btn--primary" id="as-new">${icon('plus')}New</button>
        </div>
        <div class="as-threads" id="as-threads"></div>
      </aside>
      <section class="as-chat panel">
        <header class="as-chat__head" id="as-head"></header>
        <div class="as-log" id="as-log" aria-live="polite"></div>
        <form class="as-compose" id="as-form">
          <textarea class="textarea" id="as-input" rows="1" maxlength="4000" placeholder="Ask about an alert, an address, a case..." aria-label="Message"></textarea>
          <button class="btn btn--primary" id="as-send" type="submit" aria-label="Send">${icon('send')}<span class="hide-sm">Send</span></button>
        </form>
        <div class="as-hint small muted">Enter to send, Shift+Enter for a new line. Answers cite real ids; click them to open.</div>
      </section>
    </div>`;
  hydrateIcons(el);

  $('#as-new', el).onclick = () => newThread();
  const input = $('#as-input', el);
  input.addEventListener('input', () => grow(input));
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); } });
  $('#as-form', el).onsubmit = (e) => { e.preventDefault(); send(); };

  await loadThreads();
  if (ctx.id && ctx.threads.some((t) => t.thread_id === ctx.id)) await openThread(ctx.id);
  else if (ctx.threads.length) await openThread(ctx.threads[0].thread_id);
  else paintThread();
  return cleanup;
}

function cleanup() { if (ctx && ctx.abort) ctx.abort.abort(); }
export function onDataChanged() {}

const grow = (t) => { t.style.height = 'auto'; t.style.height = `${Math.min(t.scrollHeight, 180)}px`; };

async function loadThreads() {
  try { ctx.threads = await api('/assistant/threads'); } catch (e) { toast('Could not load conversations', e.message, 'error'); ctx.threads = []; }
  paintThreads();
}

function paintThreads() {
  const box = $('#as-threads', ctx.el);
  if (!box) return;
  const cur = ctx.thread && ctx.thread.thread_id;
  box.innerHTML = ctx.threads.length ? ctx.threads.map((t, i) => `
    <button class="as-thread ${t.thread_id === cur ? 'is-on' : ''}" data-t="${esc(t.thread_id)}" style="--i:${i}">
      <span class="as-thread__title">${esc(t.title)}</span>
      <span class="as-thread__meta">${t.pending ? '<span class="as-dot" title="Waiting for your approval"></span>' : ''}${ago(t.updated_at)} &middot; ${t.messages} msg</span>
    </button>`).join('') : '<p class="small muted as-threads__empty">No conversations yet.</p>';
  $$('[data-t]', box).forEach((b) => { b.onclick = () => { if (!ctx.working) openThread(b.dataset.t); }; });
}

async function newThread() {
  if (ctx.working) return;
  try {
    const t = await api('/assistant/threads', { method: 'POST', body: {} });
    ctx.threads.unshift({ thread_id: t.thread_id, title: t.title, messages: 0, pending: false, updated_at: t.updated_at || new Date().toISOString() });
    ctx.thread = t;
    setUrl();
    paintThreads();
    paintThread();
    $('#as-input', ctx.el).focus();
  } catch (e) { toast('Could not start a conversation', e.message, 'error'); }
}

async function openThread(id) {
  try { ctx.thread = await api(`/assistant/threads/${encodeURIComponent(id)}`); } catch (e) { toast('Could not open conversation', e.message, 'error'); return; }
  setUrl();
  paintThreads();
  paintThread();
}

function setUrl() {
  const h = ctx.thread ? `#/assistant?t=${encodeURIComponent(ctx.thread.thread_id)}` : '#/assistant';
  if (location.hash !== h) history.replaceState(null, '', h);
}

function paintHead() {
  const head = $('#as-head', ctx.el);
  const t = ctx.thread;
  if (!t) { head.innerHTML = '<span class="panel__title">New conversation</span>'; return; }
  head.innerHTML = `
    <span class="panel__title as-chat__title" title="${esc(t.title)}">${esc(t.title)}</span>
    <span class="panel__meta mono">${t.tokens ? `${Number(t.tokens).toLocaleString('en-US')} tokens` : ''}</span>
    <button class="icon-btn" id="as-rename" title="Rename">${icon('edit')}</button>
    <button class="icon-btn" id="as-del" title="Delete conversation">${icon('trash')}</button>`;
  $('#as-rename', head).onclick = rename;
  $('#as-del', head).onclick = remove;
}

function paintThread() {
  paintHead();
  const log = $('#as-log', ctx.el);
  const t = ctx.thread;
  const msgs = t ? t.messages || [] : [];
  if (!msgs.length) {
    log.innerHTML = `<div class="as-start">
      <div class="as-start__mark">${icon('chat')}</div>
      <p>Start with a question. The assistant reads the same alerts, investigations and intel you see in the console.</p>
      <div class="as-prompts">${PROMPTS.map((p) => `<button class="as-prompt" data-p="${esc(p)}">${esc(p)}${icon('arrow')}</button>`).join('')}</div>
    </div>`;
    $$('[data-p]', log).forEach((b) => { b.onclick = () => { $('#as-input', ctx.el).value = b.dataset.p; send(); }; });
    return;
  }
  log.innerHTML = renderMessages(msgs) + (t.pending ? pendingCard(t.pending) : '');
  bindLog(log);
  log.scrollTop = log.scrollHeight;
}

function renderMessages(msgs) {
  const out = [];
  for (const m of msgs) {
    if (m.role === 'user') out.push(`<div class="as-msg as-msg--user"><div class="as-bubble">${esc(m.content)}</div><div class="as-meta" title="${stamp(m.at)}">${esc(m.author || 'You')} &middot; ${ago(m.at)}</div></div>`);
    else if (m.role === 'assistant' && m.tool_calls) { if (m.content && m.content.trim()) out.push(assistantMsg(m)); }
    else if (m.role === 'assistant') out.push(assistantMsg(m));
    else if (m.role === 'tool') out.push(toolChip(m));
  }
  return out.join('');
}

const assistantMsg = (m) => `<div class="as-msg as-msg--bot"><div class="as-avatar">${icon('shield')}</div><div><div class="as-text">${md(m.content)}</div><div class="as-meta" title="${stamp(m.at)}">Aegis &middot; ${ago(m.at)}</div></div></div>`;

function toolChip(m, live = false) {
  const st = live ? m.status : m.ok ? 'ok' : 'error';
  const args = m.args && Object.keys(m.args).length ? Object.entries(m.args).map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`).join(' ') : '';
  return `<details class="as-tool as-tool--${st}">
    <summary><span class="as-tool__st"></span><span class="mono">${esc(m.name)}</span><span class="as-tool__args mono">${esc(args.slice(0, 90))}</span><span class="as-tool__ms mono">${m.ms != null ? `${m.ms} ms` : st === 'running' ? 'running' : ''}</span>${m.confirmed_by ? `<span class="tag tag--ok">approved by ${esc(m.confirmed_by)}</span>` : ''}</summary>
    ${m.content ? `<pre class="snippet is-code">${esc(pretty(m.content))}</pre>` : ''}
  </details>`;
}

function pretty(s) {
  try { return JSON.stringify(JSON.parse(s), null, 2).slice(0, 12000); } catch { return String(s).slice(0, 12000); }
}

function pendingCard(p) {
  const respond = can('respond');
  return `<div class="as-pending" id="as-pending">
    <div class="as-pending__head">${icon('lock')}<b>Waiting for approval</b><span class="small muted">The assistant wants to run ${p.calls.length === 1 ? 'this action' : `these ${p.calls.length} actions`}.</span></div>
    ${p.calls.map((c) => `<div class="as-pending__call"><span class="mono">${esc(c.title || label(c.name))}</span><pre class="snippet is-code">${esc(JSON.stringify(c.args, null, 2))}</pre></div>`).join('')}
    ${respond ? `<div class="row wrap"><button class="btn btn--primary btn--sm" id="as-approve">${icon('check')}Approve and run</button><button class="btn btn--sm" id="as-decline">${icon('x')}Decline</button></div>`
    : '<p class="small muted">Your role is read-only. An analyst has to approve this.</p>'}
  </div>`;
}

function bindLog(log) {
  const a = $('#as-approve', log);
  if (a) a.onclick = () => confirmPending(true);
  const d = $('#as-decline', log);
  if (d) d.onclick = () => declinePending();
}

// Minimal markdown: escape everything first, then add a small, safe set of tags.
function md(src) {
  const blocks = [];
  let s = esc(String(src || '')).replace(/```[\w-]*\n?([\s\S]*?)```/g, (_, code) => { blocks.push(code); return `\u0000${blocks.length - 1}\u0000`; });
  const inline = (x) => x
    .replace(/`([^`\n]+)`/g, '<code class="code">$1</code>')
    .replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>')
    .replace(/(^|[\s(])\*([^*\n]+)\*(?=[\s).,;:]|$)/g, '$1<i>$2</i>')
    .replace(/\b(ALERT-[A-Z0-9-]+)\b/g, '<a href="#/investigate/$1">$1</a>')
    .replace(/\b(CASE-[A-Z0-9]+)\b/g, '<a href="#/cases/$1">$1</a>')
    .replace(/\b(APR-[A-Z0-9]+)\b/g, '<a href="#/approvals">$1</a>')
    .replace(/\b(FW-[A-Z0-9]+)\b/g, '<a href="#/containment">$1</a>')
    .replace(/(^|[\s(>])((?:\d{1,3}\.){3}\d{1,3})(?![\d.]*<\/a>)(?=[\s).,;:<]|$)/g, '$1<a class="mono" href="#/ip/$2">$2</a>');
  const lines = s.split('\n');
  const html = [];
  let list = null;
  let table = null;
  const cells = (l) => l.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
  const flushTable = () => {
    if (!table) return;
    const [head, ...body] = table;
    html.push(`<div class="table-wrap as-table"><table class="table"><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>${body.map((r) => `<tr>${head.map((_, i) => `<td>${inline(r[i] || '')}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
    table = null;
  };
  const flush = () => { flushTable(); if (list) { html.push(`<${list.tag}>${list.items.map((i) => `<li>${inline(i)}</li>`).join('')}</${list.tag}>`); list = null; } };
  for (const line of lines) {
    if (/^\s*\|.*\|\s*$/.test(line)) {
      if (/^\s*\|[\s:|-]+\|\s*$/.test(line)) continue; // header separator row
      if (!table) { flush(); table = []; }
      table.push(cells(line));
      continue;
    }
    flushTable();
    const ul = line.match(/^\s*[-*]\s+(.*)$/);
    const ol = line.match(/^\s*\d+[.)]\s+(.*)$/);
    const h = line.match(/^#{1,4}\s+(.*)$/);
    if (ul || ol) {
      const tag = ul ? 'ul' : 'ol';
      if (!list || list.tag !== tag) { flush(); list = { tag, items: [] }; }
      list.items.push((ul || ol)[1]);
    } else {
      flush();
      if (h) html.push(`<p class="as-h">${inline(h[1])}</p>`);
      else if (/^\u0000\d+\u0000$/.test(line.trim())) html.push(line.trim());
      else if (line.trim()) html.push(`<p>${inline(line)}</p>`);
    }
  }
  flush();
  return html.join('').replace(/\u0000(\d+)\u0000/g, (_, n) => `<pre class="snippet is-code">${blocks[Number(n)]}</pre>`);
}

// ---- Sending -----------------------------------------------------------------------
async function ensureThread() {
  if (ctx.thread) return ctx.thread;
  const t = await api('/assistant/threads', { method: 'POST', body: {} });
  ctx.thread = t;
  ctx.threads.unshift({ thread_id: t.thread_id, title: t.title, messages: 0, pending: false, updated_at: new Date().toISOString() });
  setUrl();
  return t;
}

function setWorking(on) {
  ctx.working = on;
  const btn = $('#as-send', ctx.el);
  const input = $('#as-input', ctx.el);
  if (btn) { btn.disabled = on; btn.classList.toggle('is-busy', on); }
  if (input) input.disabled = on;
  ctx.el.querySelector('.as-chat').classList.toggle('is-working', on);
}

function liveArea(log) {
  let live = $('#as-live', log);
  if (!live) { live = document.createElement('div'); live.id = 'as-live'; live.className = 'as-live'; log.appendChild(live); }
  return live;
}

function typing(live, on) {
  let t = $('.as-typing', live);
  if (on && !t) { t = document.createElement('div'); t.className = 'as-typing'; t.innerHTML = '<span></span><span></span><span></span><em>Working through the evidence</em>'; live.appendChild(t); }
  if (!on && t) t.remove();
}

async function runStream(path, body) {
  const log = $('#as-log', ctx.el);
  const live = liveArea(log);
  typing(live, true);
  log.scrollTop = log.scrollHeight;
  const running = new Map();
  ctx.abort = new AbortController();
  let result = null; let failed = null;
  try {
    await stream(path, body, (e) => {
      if (e.type === 'tool') {
        const key = `${e.name}:${JSON.stringify(e.args)}`;
        const html = e.message ? toolChip(e.message) : toolChip({ name: e.name, args: e.args, status: e.status }, true);
        const tmp = document.createElement('div'); tmp.innerHTML = html;
        const node = tmp.firstElementChild;
        if (running.has(key)) running.get(key).replaceWith(node); else live.insertBefore(node, $('.as-typing', live));
        running.set(key, node);
      } else if (e.type === 'message') {
        typing(live, false);
        const tmp = document.createElement('div'); tmp.innerHTML = assistantMsg(e.message);
        live.appendChild(tmp.firstElementChild);
      } else if (e.type === 'done') result = e.result;
      else if (e.type === 'error') failed = e.message;
      log.scrollTop = log.scrollHeight;
    }, ctx.abort.signal);
  } catch (err) { if (err.name !== 'AbortError') failed = err.message; }
  if (!document.body.contains(ctx.el)) return;
  typing(live, false);
  if (failed) toast('The assistant stopped', failed, 'error', 7000);
  if (result) ctx.thread = result;
  else if (ctx.thread) { try { ctx.thread = await api(`/assistant/threads/${encodeURIComponent(ctx.thread.thread_id)}`); } catch { /* keep what we have */ } }
  const row = ctx.threads.find((x) => x.thread_id === ctx.thread.thread_id);
  if (row) Object.assign(row, { title: ctx.thread.title, pending: Boolean(ctx.thread.pending), updated_at: ctx.thread.updated_at || new Date().toISOString(), messages: (ctx.thread.messages || []).filter((m) => m.role === 'user' || (m.role === 'assistant' && !m.tool_calls)).length });
  ctx.threads.sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)));
  paintThreads();
  paintThread();
}

async function send() {
  if (ctx.working) return;
  const input = $('#as-input', ctx.el);
  const text = input.value.trim();
  if (!text) { input.focus(); return; }
  setWorking(true);
  try {
    const t = await ensureThread();
    input.value = ''; grow(input);
    t.messages = [...(t.messages || []), { role: 'user', content: text, author: 'You', at: new Date().toISOString() }];
    if (t.pending) t.pending = null;
    paintThread();
    await runStream(`/assistant/threads/${encodeURIComponent(t.thread_id)}/messages/stream`, { content: text });
  } catch (e) { toast('Message not sent', e.message, 'error'); input.value = text; }
  finally { if (document.body.contains(ctx.el)) { setWorking(false); $('#as-input', ctx.el).focus(); } }
}

async function confirmPending(approve, note) {
  if (ctx.working || !ctx.thread) return;
  setWorking(true);
  const card = $('#as-pending', ctx.el);
  if (card) card.classList.add('is-done');
  try { await runStream(`/assistant/threads/${encodeURIComponent(ctx.thread.thread_id)}/confirm/stream`, { approve, note }); }
  finally { if (document.body.contains(ctx.el)) setWorking(false); }
}

function declinePending() {
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Decline the proposed action</h2></div>
    <div class="modal__body"><label class="field"><span>Reason (optional, the assistant sees it)</span><textarea class="textarea" id="as-note" rows="3" maxlength="300" placeholder="e.g. That address is our partner's NAT gateway"></textarea></label></div>
    <div class="modal__foot"><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--danger" id="as-dec-go">Decline</button></div>`);
  $('#as-dec-go', panel).onclick = () => { const note = $('#as-note', panel).value.trim(); closeLayer(); confirmPending(false, note || undefined); };
}

function rename() {
  const t = ctx.thread;
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Rename conversation</h2></div>
    <form class="modal__body" id="as-rn"><label class="field"><span>Title</span><input class="input" name="title" maxlength="120" value="${esc(t.title)}" autofocus></label></form>
    <div class="modal__foot"><span class="form-error" id="as-rn-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="as-rn-go">Save</button></div>`);
  const go = (e) => {
    e.preventDefault();
    const title = new FormData($('#as-rn', panel)).get('title');
    busy($('#as-rn-go', panel), async () => {
      try {
        const next = await api(`/assistant/threads/${encodeURIComponent(t.thread_id)}`, { method: 'PATCH', body: { title } });
        ctx.thread.title = next.title;
        const row = ctx.threads.find((x) => x.thread_id === t.thread_id); if (row) row.title = next.title;
        closeLayer(); paintThreads(); paintHead();
      } catch (err) { $('#as-rn-err', panel).textContent = err.message; }
    });
  };
  $('#as-rn', panel).onsubmit = go;
  $('#as-rn-go', panel).onclick = go;
}

function remove() {
  const t = ctx.thread;
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Delete this conversation?</h2></div>
    <div class="modal__body"><p class="small muted" style="margin:0">${esc(t.title)}. Actions it already ran stay in the audit log.</p></div>
    <div class="modal__foot"><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--danger" id="as-del-go">Delete</button></div>`);
  $('#as-del-go', panel).onclick = () => busy($('#as-del-go', panel), async () => {
    try {
      await api(`/assistant/threads/${encodeURIComponent(t.thread_id)}`, { method: 'DELETE' });
      closeLayer();
      ctx.threads = ctx.threads.filter((x) => x.thread_id !== t.thread_id);
      ctx.thread = null;
      if (ctx.threads.length) await openThread(ctx.threads[0].thread_id); else { setUrl(); paintThreads(); paintThread(); }
    } catch (err) { toast('Not deleted', err.message, 'error'); }
  });
}