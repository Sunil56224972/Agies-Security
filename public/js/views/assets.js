import { $, $$, api, esc, sev, ago, emptyState, toast, busy, emit, can } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { openAsset, openAssetForm, openAssetImport } from '../panels.js';

let ctx = null;

export async function render({ el, navigate, query }) {
  ctx = { el, navigate, tab: query.tab === 'kb' ? 'kb' : 'assets', q: query.q || '', hq: '' };
  const respond = can('respond');
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Assets</h1>
        <p class="page-sub">Your hosts, their owners, and which CVEs apply, matched on installed versions against NVD CPE ranges.</p>
      </div>
      <div class="page-actions">${respond ? `<button class="btn" id="as-import">${icon('upload')}Import</button><button class="btn btn--primary" id="as-add">${icon('plus')}Add host</button>` : ''}</div>
    </div>
    <section class="panel reveal">
      <div class="tabs" role="tablist"><button class="tab" data-tab="assets" role="tab">Hosts</button><button class="tab" data-tab="kb" role="tab">CVE records</button></div>
      <div id="as-body"></div>
    </section>`;
  if (respond) {
    $('#as-add', el).onclick = () => openAssetForm(null);
    $('#as-import', el).onclick = () => openAssetImport();
  }
  $$('[data-tab]', el).forEach((t) => { t.onclick = () => { ctx.tab = t.dataset.tab; paint(); }; });
  hydrateIcons(el);
  await paint();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) paint(); }

async function paint() {
  const { el } = ctx;
  $$('[data-tab]', el).forEach((t) => { const on = t.dataset.tab === ctx.tab; t.classList.toggle('is-on', on); t.setAttribute('aria-selected', on); });
  const body = $('#as-body', el);
  if (ctx.tab === 'assets') {
    ctx.assets = await api('/assets');
    if (!ctx.assets.length) {
      body.innerHTML = `<div class="empty">${icon('server')}<b>No hosts in the inventory</b>
        <span class="small">Exposure checks and investigation context depend on it. Add hosts one at a time or import a CSV export from your CMDB or scanner.</span>
        ${can('respond') ? `<div class="row mt-12"><button class="btn" id="e-import">${icon('upload')}Import CSV</button><button class="btn btn--primary" id="e-add">${icon('plus')}Add host</button></div>` : ''}</div>`;
      if ($('#e-add', body)) { $('#e-add', body).onclick = () => openAssetForm(null); $('#e-import', body).onclick = () => openAssetImport(); }
      hydrateIcons(body);
      return;
    }
    const exposed = ctx.assets.filter((a) => a.exposures.length).length;
    body.innerHTML = `<div class="toolbar"><div class="input-icon">${icon('search')}<input class="input" id="as-q" placeholder="Hostname, IP, owner, package" value="${esc(ctx.hq)}"></div>
      <div class="toolbar__end small muted">${ctx.assets.length} hosts &middot; ${exposed} with known CVEs</div></div><div id="as-grid"></div>`;
    let t;
    $('#as-q', body).oninput = (e) => { clearTimeout(t); t = setTimeout(() => { ctx.hq = e.target.value.trim(); grid(); }, 120); };
    grid();
  } else {
    const configure = can('configure');
    body.innerHTML = `<div class="toolbar"><div class="input-icon">${icon('search')}<input class="input" id="kb-q" placeholder="CVE id, product or keyword" value="${esc(ctx.q)}"></div>
      <div class="toolbar__end row">${configure ? `<form id="kb-add" class="row" novalidate><input class="input input--mono" id="kb-id" placeholder="CVE-2024-3400" style="width:150px" autocomplete="off"><button class="btn btn--sm" id="kb-add-btn">${icon('plus')}Add from NVD</button></form>
      <button class="btn btn--sm" id="kb-sync">${icon('refresh')}Sync from NVD</button>` : ''}</div></div><div id="kb-list"></div>`;
    let t;
    $('#kb-q', body).oninput = (e) => { clearTimeout(t); t = setTimeout(() => { ctx.q = e.target.value.trim(); kb(); }, 140); };
    if (configure) {
      $('#kb-add', body).onsubmit = (e) => {
        e.preventDefault();
        const id = $('#kb-id', body).value.trim();
        busy($('#kb-add-btn', body), async () => {
          try {
            const c = await api('/cves', { method: 'POST', body: { cve_id: id } });
            toast(`${c.cve_id} added`, `CVSS ${c.cvss_score}${c.kev ? ', on the CISA KEV list' : ''}`, 'ok');
            $('#kb-id', body).value = '';
            emit('data:changed');
          } catch (err) { toast('Could not add CVE', err.message, 'error'); }
        });
      };
      $('#kb-sync', body).onclick = (e) => busy(e.currentTarget, async () => {
        toast('Syncing with NVD', 'Without NVD_API_KEY this takes about 6 seconds per CVE.', 'info');
        try {
          const r = await api('/cves/sync', { method: 'POST', body: {} });
          toast(`NVD sync: ${r.updated} updated`, r.failed.length ? `${r.failed.length} failed: ${r.failed[0].error}` : 'All records refreshed', r.failed.length ? 'error' : 'ok', 8000);
          emit('data:changed');
        } catch (err) { toast('Sync failed', err.message, 'error'); }
      });
    }
    await kb();
  }
  hydrateIcons(body);
}

function grid() {
  const { navigate } = ctx;
  const q = ctx.hq.toLowerCase();
  const rows = ctx.assets.filter((a) => !q || [a.hostname, a.ip_address, a.owner, a.os_version, ...(a.installed_packages || [])].some((x) => x && String(x).toLowerCase().includes(q)));
  const box = $('#as-grid', ctx.el);
  box.innerHTML = rows.length ? `<div class="asset-grid rows-in">${rows.map((a, i) => `
      <button class="asset" style="--i:${Math.min(i, 20)}" data-ip="${esc(a.ip_address)}">
        <div class="asset__top"><div><div class="asset__name">${esc(a.hostname)}</div><div class="mono small muted">${esc(a.ip_address)} &middot; ${esc(a.os_version)}</div></div>${sev(a.criticality)}</div>
        <div class="asset__svc">${a.running_services.slice(0, 4).map((s) => `<div><span>:${s.port}</span>${esc(s.service)}</div>`).join('') || '<div class="muted">No services recorded</div>'}</div>
        <div class="asset__foot">
          ${a.exposures.length ? a.exposures.map((c) => `<span class="tag ${c.kev ? 'tag--kev' : 'tag--warn'}">${esc(c.cve_id)}</span>`).join('') : '<span class="tag tag--ok">no known CVE</span>'}
          ${a.open_alerts ? `<span class="tag">${a.open_alerts} open</span>` : ''}
          ${a.waf_enabled ? '<span class="tag">WAF</span>' : ''}
        </div>
      </button>`).join('')}</div>` : emptyState('No hosts match', 'Try an IP, hostname or package name.', 'search');
  $$('[data-ip]', box).forEach((b) => { b.onclick = () => openAsset(ctx.assets.find((a) => a.ip_address === b.dataset.ip), navigate); });
  hydrateIcons(box);
}

async function kb() {
  const list = $('#kb-list', ctx.el);
  const cves = await api(`/cves${ctx.q ? `?q=${encodeURIComponent(ctx.q)}` : ''}`);
  list.innerHTML = cves.length ? `<div class="rows-in">${cves.map((c, i) => `
    <div class="cve-row" style="--i:${Math.min(i, 20)}">
      <div><div class="mono" style="font-weight:600">${esc(c.cve_id)}</div><div class="row mt-8">${sev(c.severity)}<span class="cvss" style="color:${c.cvss_score >= 9 ? 'var(--crit)' : c.cvss_score >= 7 ? 'var(--high)' : 'var(--med)'}">${Number(c.cvss_score).toFixed(1)}</span></div>
        ${c.kev ? '<div class="mt-8"><span class="tag tag--kev" title="CISA Known Exploited Vulnerabilities catalog">KEV</span></div>' : ''}</div>
      <div style="min-width:0"><div style="font-weight:600">${esc(c.title)}</div><div class="small" style="color:var(--ink-2);margin-top:4px">${esc(c.description)}</div>
        <div class="row wrap mt-8">${(c.affected_products || []).map((p) => `<span class="tag">${esc(p)}</span>`).join('')}<span class="small muted">${esc(c.vulnerable_versions || '')}</span></div>
        ${c.remediation ? `<div class="small mt-8"><b>Fix:</b> <span style="color:var(--ink-2)">${esc(c.remediation)}</span></div>` : ''}
        <div class="small muted mt-8">${esc(c.source || 'NVD')}${c.published ? ` &middot; published ${esc(c.published.slice(0, 10))}` : ''}${c.synced_at ? ` &middot; synced ${ago(c.synced_at)}` : ''}${c.cpe_ranges ? ` &middot; ${c.cpe_ranges} CPE ranges` : ''}${c.cvss_vector ? ` &middot; <span class="mono">${esc(c.cvss_vector)}</span>` : ''}</div></div>
    </div>`).join('')}</div>` : emptyState('No matches', ctx.q ? 'Add it from NVD by id using the field above.' : 'Add CVEs from NVD by id.', 'bug');
}