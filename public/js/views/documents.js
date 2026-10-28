import { $, $$, api, esc, ago, stamp, num, label, emptyState, toast, busy, emit, can, modal, closeLayer, drawer, copyText } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

// Documents: drop in a report, a log export or an e-mail source. Aegis pulls
// out every indicator and reference, checks the external ones against threat
// intel on request, and can attach them to a case as evidence.

let ctx = null;
const MAX = 5 * 1024 * 1024;
const ACCEPT = '.txt,.log,.csv,.tsv,.json,.jsonl,.ndjson,.xml,.yml,.yaml,.md,.ioc,.rules,.conf,.ini,.eml,.html,.htm';
const size = (b) => (b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(2)} MB`);
const VERDICT_CLS = { malicious: 'tag--warn', suspicious: 'doc-tag--sus', clean: 'tag--ok', benign: 'tag--ok', harmless: 'tag--ok' };

export async function render({ el, query }) {
  ctx = { el, docs: [], open: query.d || null };
  const respond = can('respond');
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Documents</h1>
        <p class="page-sub">Upload threat reports, log exports, e-mail sources or IOC lists. Indicators, CVEs and ATT&amp;CK references are extracted on the server; intel checks run against every configured source.</p>
      </div>
    </div>
    <div class="grid doc-top reveal">
      ${respond ? `<label class="doc-drop panel" id="doc-drop" tabindex="0">
        <input type="file" id="doc-file" accept="${ACCEPT}" multiple hidden>
        <span class="doc-drop__ic">${icon('upload')}</span>
        <b>Drop files here or choose</b>
        <span class="small muted">Text formats up to 5 MB: .txt .log .csv .json .xml .yaml .md .eml .html .ioc</span>
        <label class="row small doc-drop__check"><input type="checkbox" id="doc-check" checked>Check indicators against threat intel on upload</label>
      </label>` : ''}
      <section class="panel doc-paste">
        <div class="panel__head"><h2 class="panel__title">Quick extract</h2><span class="panel__meta">nothing is stored</span></div>
        <div class="panel__body">
          <textarea class="textarea mono" id="doc-text" rows="5" placeholder="Paste an advisory, a chat message or a block of logs"></textarea>
          <div class="row mt-8"><button class="btn btn--sm" id="doc-analyze">${icon('scan')}Extract</button><span class="small muted" id="doc-quick"></span></div>
          <div id="doc-quick-out"></div>
        </div>
      </section>
    </div>
    <section class="panel mt-12 reveal" id="doc-list"><div style="padding:18px"><div class="skeleton" style="height:120px"></div></div></section>`;
  hydrateIcons(el);
  if (respond) bindDrop();
  $('#doc-analyze', el).onclick = (e) => busy(e.currentTarget, quick);
  await load();
  if (ctx.open) openDoc(ctx.open);
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) load(); }

function bindDrop() {
  const drop = $('#doc-drop', ctx.el);
  const file = $('#doc-file', ctx.el);
  drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); file.click(); } });
  ['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('is-over'); }));
  ['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); if (t === 'dragleave' && drop.contains(e.relatedTarget)) return; drop.classList.remove('is-over'); }));
  drop.addEventListener('drop', (e) => upload([...(e.dataTransfer.files || [])]));
  file.onchange = () => { upload([...file.files]); file.value = ''; };
  $('.doc-drop__check', drop).addEventListener('click', (e) => e.stopPropagation());
}

const readText = (f) => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result)); r.onerror = () => rej(new Error('Could not read the file')); r.readAsText(f); });

async function upload(files) {
  if (!files.length) return;
  const drop = $('#doc-drop', ctx.el);
  const check = $('#doc-check', ctx.el).checked;
  drop.classList.add('is-busy');
  let last = null;
  for (const f of files.slice(0, 10)) {
    if (f.size > MAX) { toast(`${f.name} is too large`, 'Files are limited to 5 MB', 'error'); continue; }
    try {
      const content = await readText(f);
      const doc = await api('/documents', { method: 'POST', body: { name: f.name, mime: f.type || null, content, check } });
      last = doc;
      const flagged = doc.intel ? doc.intel.flagged.length : 0;
      toast(`${f.name} analysed`, `${doc.iocs.length} indicators${doc.intel ? `, ${flagged} flagged` : ''}${doc.duplicate_of ? `. Same content as ${doc.duplicate_of}` : ''}`, flagged ? 'error' : 'ok', 6000);
    } catch (e) { toast(`${f.name} not uploaded`, e.message, 'error', 7000); }
  }
  drop.classList.remove('is-busy');
  if (last) { emit('data:changed'); await load(); openDoc(last.doc_id); }
}

async function quick() {
  const text = $('#doc-text', ctx.el).value;
  if (!text.trim()) { $('#doc-text', ctx.el).focus(); return; }
  try {
    const r = await api('/documents/analyze', { method: 'POST', body: { text } });
    $('#doc-quick', ctx.el).textContent = `${r.iocs.length} indicators, ${r.refs.cves.length} CVEs, ${r.refs.techniques.length} techniques`;
    $('#doc-quick-out', ctx.el).innerHTML = r.iocs.length || r.refs.cves.length ? `<div class="doc-chips mt-8">${r.iocs.slice(0, 60).map((i) => `<a class="tag" href="#/intel?tab=lookup&q=${encodeURIComponent(i.value)}" title="${esc(i.type)}">${esc(i.value)}</a>`).join('')}${r.refs.cves.slice(0, 20).map((c) => `<span class="tag tag--kev">${esc(c)}</span>`).join('')}</div>` : '';
  } catch (e) { toast('Could not extract', e.message, 'error'); }
}

async function load() {
  try { ctx.docs = await api('/documents'); } catch (e) { $('#doc-list', ctx.el).innerHTML = emptyState('Could not load documents', e.message, 'alert'); return; }
  if (!document.body.contains(ctx.el)) return;
  const rows = ctx.docs;
  $('#doc-list', ctx.el).innerHTML = `
    <div class="panel__head"><h2 class="panel__title">Library</h2><span class="panel__meta">${num(rows.length)} documents</span></div>
    ${rows.length ? `<div class="table-wrap"><table class="table">
      <thead><tr><th>Document</th><th>Indicators</th><th>Intel</th><th class="hide-sm">Case</th><th class="hide-sm">Uploaded</th></tr></thead>
      <tbody class="rows-in">${rows.map((d, i) => `<tr class="is-clickable" data-doc="${esc(d.doc_id)}" style="--i:${Math.min(i, 30)}">
        <td><span class="cell-main">${icon('file')} ${esc(d.name)}</span><span class="cell-sub mono">${esc(d.doc_id)} &middot; ${size(d.size_bytes)} &middot; ${num(d.lines)} lines</span></td>
        <td class="mono">${num((d.iocs || []).length)}<span class="small muted">${(d.refs && d.refs.cves && d.refs.cves.length) ? ` &middot; ${d.refs.cves.length} CVE` : ''}</span></td>
        <td>${intelCell(d.intel)}</td>
        <td class="hide-sm">${d.case_id ? `<a class="mono small" href="#/cases/${encodeURIComponent(d.case_id)}">${esc(d.case_id)}</a>` : '<span class="muted small">-</span>'}</td>
        <td class="hide-sm small">${esc(d.uploaded_by)}<div class="muted" title="${stamp(d.created_at)}">${ago(d.created_at)}</div></td>
      </tr>`).join('')}</tbody></table></div>` : emptyState('No documents yet', 'Uploaded files are kept with their SHA-256, extracted indicators and intel results.', 'file')}`;
  hydrateIcons($('#doc-list', ctx.el));
  $$('[data-doc]', ctx.el).forEach((tr) => { tr.onclick = () => openDoc(tr.dataset.doc); });
}

function intelCell(intel) {
  if (!intel) return '<span class="small muted">not checked</span>';
  const m = intel.malicious.length; const s = intel.suspicious.length;
  if (!m && !s) return `<span class="tag tag--ok">clean &middot; ${intel.checked}</span>`;
  return `${m ? `<span class="tag tag--warn">${m} malicious</span> ` : ''}${s ? `<span class="tag doc-tag--sus">${s} suspicious</span>` : ''}`;
}

async function openDoc(id) {
  let d;
  try { d = await api(`/documents/${encodeURIComponent(id)}`); } catch (e) { toast('Could not open document', e.message, 'error'); return; }
  history.replaceState(null, '', `#/documents?d=${encodeURIComponent(id)}`);
  const respond = can('respond');
  const byVal = new Map(((d.intel && d.intel.results) || []).map((r) => [r.value, r]));
  const refs = d.refs || {};
  const by = refs.by_type || {};
  const panel = drawer(`
    <div class="drawer__head"><div><div class="eyebrow mono">${esc(d.doc_id)}</div><h2 class="drawer__title">${esc(d.name)}</h2></div><button class="icon-btn" data-close aria-label="Close">${icon('x')}</button></div>
    <div class="drawer__body">
      <dl class="kv">
        <dt>SHA-256</dt><dd class="mono small"><button class="doc-hash" id="doc-sha" title="Copy">${esc(d.sha256)}</button></dd>
        <dt>Size</dt><dd>${size(d.size_bytes)}, ${num(d.lines)} lines${d.truncated ? ' <span class="small muted">(first 1 MB kept)</span>' : ''}</dd>
        <dt>Uploaded</dt><dd>${esc(d.uploaded_by)} &middot; ${stamp(d.created_at)}</dd>
        <dt>Case</dt><dd>${d.case_id ? `<a class="mono" href="#/cases/${encodeURIComponent(d.case_id)}">${esc(d.case_id)}</a>` : '<span class="muted">not attached</span>'}</dd>
      </dl>
      ${Object.keys(by).length ? `<div class="doc-chips mt-12">${Object.entries(by).map(([k, n]) => `<span class="tag">${esc(label(k))} <b>${n}</b></span>`).join('')}</div>` : ''}
      ${d.intel ? `<div class="doc-intel mt-12"><b>${d.intel.checked}</b> checked &middot; <b class="crit-text">${d.intel.malicious.length}</b> malicious &middot; <b class="warn-text">${d.intel.suspicious.length}</b> suspicious <span class="muted small">${ago(d.intel.checked_at)}</span>${d.intel.skipped ? `<div class="small muted">${d.intel.skipped} more were not checked (25 per run)</div>` : ''}</div>` : ''}
      <div class="row wrap mt-12">
        ${respond ? `<button class="btn btn--sm btn--primary" id="doc-check-btn">${icon('shieldCheck')}${d.intel ? 'Check again' : 'Check against intel'}</button>
        <button class="btn btn--sm" id="doc-attach-btn">${icon('link')}Attach to case</button>` : ''}
        <button class="btn btn--sm btn--ghost" id="doc-hunt">${icon('search')}Hunt these</button>
        ${respond ? `<button class="btn btn--sm btn--ghost btn--danger-text" id="doc-del">${icon('trash')}Delete</button>` : ''}
      </div>
      <h3 class="section-title mt-16">Indicators <span class="muted mono">${(d.iocs || []).length}</span></h3>
      ${(d.iocs || []).length ? `<div class="table-wrap doc-iocs"><table class="table">
        <thead><tr><th>Value</th><th>Type</th><th>Verdict</th></tr></thead>
        <tbody>${d.iocs.slice(0, 300).map((i) => { const r = byVal.get(i.value); return `<tr>
          <td><a class="mono small doc-val" href="#/intel?tab=lookup&q=${encodeURIComponent(i.value)}">${esc(i.value)}</a></td>
          <td class="small">${esc(i.type)}${i.internal ? ' <span class="tag">internal</span>' : ''}</td>
          <td>${r ? `<span class="tag ${VERDICT_CLS[r.verdict] || ''}" title="${esc(r.summary || r.error || '')}">${esc(r.verdict)}${r.score != null ? ` ${r.score}` : ''}</span>` : '<span class="small muted">-</span>'}</td></tr>`; }).join('')}</tbody></table></div>` : '<p class="small muted">No indicators found.</p>'}
      ${refs.cves && refs.cves.length ? `<h3 class="section-title mt-16">CVEs</h3><div class="doc-chips">${refs.cves.map((c) => { const k = (refs.known_cves || []).find((x) => x.cve_id === c); return `<a class="tag ${k && k.kev ? 'tag--kev' : ''}" href="#/assets?tab=kb&q=${encodeURIComponent(c)}" title="${esc(k ? `${k.title} (CVSS ${k.cvss_score})` : 'Not in the local knowledge base')}">${esc(c)}${k ? ` <b>${k.cvss_score}</b>` : ''}</a>`; }).join('')}</div>` : ''}
      ${refs.techniques && refs.techniques.length ? `<h3 class="section-title mt-16">ATT&amp;CK</h3><div class="doc-chips">${refs.techniques.map((t) => `<a class="tag" href="#/hunts?tab=attack">${esc(t)}</a>`).join('')}</div>` : ''}
      ${['emails', 'registry', 'bitcoin'].filter((k) => refs[k] && refs[k].length).map((k) => `<h3 class="section-title mt-16">${k === 'registry' ? 'Registry keys' : label(k)}</h3><div class="doc-chips">${refs[k].slice(0, 60).map((v) => `<span class="tag">${esc(v)}</span>`).join('')}</div>`).join('')}
      <h3 class="section-title mt-16">Content</h3>
      <pre class="snippet is-code doc-content">${esc(String(d.content || '').slice(0, 60000))}${String(d.content || '').length > 60000 ? '\n...' : ''}</pre>
    </div>`, { onClose: () => { if (location.hash.startsWith('#/documents')) history.replaceState(null, '', '#/documents'); } });
  hydrateIcons(panel);
  $('#doc-sha', panel).onclick = () => copyText(d.sha256);
  $('#doc-hunt', panel).onclick = () => {
    const vals = (d.iocs || []).filter((i) => !i.internal).slice(0, 50).map((i) => i.value);
    closeLayer();
    location.hash = `#/hunts?indicators=${encodeURIComponent(vals.join(','))}`;
  };
  if (!respond) return;
  $('#doc-check-btn', panel).onclick = (e) => busy(e.currentTarget, async () => {
    try { const n = await api(`/documents/${encodeURIComponent(d.doc_id)}/check`, { method: 'POST', body: {} }); toast('Intel check finished', `${n.intel.checked} checked, ${n.intel.malicious.length} malicious`, n.intel.malicious.length ? 'error' : 'ok'); load(); openDoc(d.doc_id); } catch (err) { toast('Check failed', err.message, 'error'); }
  });
  $('#doc-attach-btn', panel).onclick = () => attach(d);
  $('#doc-del', panel).onclick = () => busy($('#doc-del', panel), async () => {
    try { await api(`/documents/${encodeURIComponent(d.doc_id)}`, { method: 'DELETE' }); closeLayer(); toast('Document deleted', d.name, 'ok'); load(); } catch (err) { toast('Not deleted', err.message, 'error'); }
  });
}

async function attach(d) {
  let cases = [];
  try { cases = await api('/cases?status=OPEN,IN_PROGRESS,CONTAINED&limit=200'); } catch { /* handled below */ }
  if (cases && !Array.isArray(cases) && cases.cases) cases = cases.cases;
  const flagged = d.intel && d.intel.flagged.length;
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Attach ${esc(d.name)}</h2></div>
    <form class="modal__body" id="doc-at" novalidate>
      ${cases.length ? `<label class="field"><span>Case</span><select class="select" name="case_id">${cases.map((c) => `<option value="${esc(c.case_id)}">${esc(c.case_id)} - ${esc(c.title)}</option>`).join('')}</select></label>`
      : '<label class="field"><span>Case id</span><input class="input mono" name="case_id" placeholder="CASE-..."></label>'}
      <label class="field mt-12"><span>Indicators to add</span><select class="select" name="only"><option value="all">All external indicators</option>${flagged ? `<option value="flagged" selected>Only the ${flagged} flagged by intel</option>` : ''}</select></label>
      <p class="small muted">The document is logged on the case timeline as evidence with its SHA-256.</p>
    </form>
    <div class="modal__foot"><span class="form-error" id="doc-at-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="doc-at-go">${icon('link')}Attach</button></div>`);
  hydrateIcons(panel);
  $('#doc-at-go', panel).onclick = () => busy($('#doc-at-go', panel), async () => {
    const f = new FormData($('#doc-at', panel));
    try {
      const r = await api(`/documents/${encodeURIComponent(d.doc_id)}/attach`, { method: 'POST', body: { case_id: f.get('case_id'), only: f.get('only') } });
      closeLayer();
      toast(`Attached to ${r.attached.case_id}`, `${r.attached.added} indicators added${r.attached.duplicates ? `, ${r.attached.duplicates} already there` : ''}`, 'ok');
      emit('data:changed');
    } catch (e) { $('#doc-at-err', panel).textContent = e.message; }
  });
}