import { $, $$, api, esc, sev, emptyState } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { openAsset } from '../panels.js';

let ctx = null;

export async function render({ el, navigate, query }) {
  ctx = { el, navigate, tab: query.tab === 'kb' ? 'kb' : 'assets', q: query.q || '' };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <div class="eyebrow">${icon('server')}Inventory</div>
        <h1 class="page-title">Assets &amp; <em>exposure</em></h1>
        <p class="page-sub">What we run, who owns it, and which known vulnerabilities actually apply. Exposure is matched against installed packages, not just product names.</p>
      </div>
    </div>
    <section class="panel reveal">
      <div class="tabs" role="tablist"><button class="tab" data-tab="assets" role="tab">Hosts</button><button class="tab" data-tab="kb" role="tab">Vulnerability knowledge base</button></div>
      <div id="as-body"></div>
    </section>`;
  $$('[data-tab]', el).forEach((t) => { t.onclick = () => { ctx.tab = t.dataset.tab; paint(); }; });
  await paint();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) paint(); }

async function paint() {
  const { el, navigate } = ctx;
  $$('[data-tab]', el).forEach((t) => { const on = t.dataset.tab === ctx.tab; t.classList.toggle('is-on', on); t.setAttribute('aria-selected', on); });
  const body = $('#as-body', el);
  if (ctx.tab === 'assets') {
    const assets = await api('/assets');
    body.innerHTML = `<div class="asset-grid rows-in">${assets.map((a, i) => `
      <button class="asset" style="--i:${i}" data-ip="${esc(a.ip_address)}">
        <div class="asset__top"><div><div class="asset__name">${esc(a.hostname)}</div><div class="mono small muted">${esc(a.ip_address)} &middot; ${esc(a.os_version)}</div></div>${sev(a.criticality)}</div>
        <div class="asset__svc">${a.running_services.map((s) => `<div><span>:${s.port}</span>${esc(s.service)}</div>`).join('')}</div>
        <div class="asset__foot">
          ${a.exposures.length ? a.exposures.map((c) => `<span class="tag tag--warn">${esc(c.cve_id)}</span>`).join('') : '<span class="tag tag--ok">No known exposure</span>'}
          ${a.open_alerts ? `<span class="tag">${a.open_alerts} open alert${a.open_alerts === 1 ? '' : 's'}</span>` : ''}
          ${a.waf_enabled ? '<span class="tag">WAF</span>' : ''}
        </div>
      </button>`).join('')}</div>`;
    $$('[data-ip]', body).forEach((b) => { b.onclick = () => openAsset(assets.find((a) => a.ip_address === b.dataset.ip), navigate); });
  } else {
    body.innerHTML = `<div class="toolbar"><div class="input-icon">${icon('search')}<input class="input" id="kb-q" placeholder="CVE id, product or keyword" value="${esc(ctx.q)}"></div></div><div id="kb-list"></div>`;
    let t;
    $('#kb-q', body).oninput = (e) => { clearTimeout(t); t = setTimeout(() => { ctx.q = e.target.value.trim(); kb(); }, 140); };
    await kb();
  }
  hydrateIcons(body);
}

async function kb() {
  const list = $('#kb-list', ctx.el);
  const cves = await api(`/cves${ctx.q ? `?q=${encodeURIComponent(ctx.q)}` : ''}`);
  list.innerHTML = cves.length ? `<div class="rows-in">${cves.map((c, i) => `
    <div class="cve-row" style="--i:${i}">
      <div><div class="mono" style="font-weight:600">${esc(c.cve_id)}</div><div class="mt-8">${sev(c.severity)}</div></div>
      <div style="min-width:0"><div style="font-weight:600">${esc(c.title)}</div><div class="small" style="color:var(--ink-2);margin-top:4px">${esc(c.description)}</div>
        <div class="row wrap mt-8">${c.affected_products.map((p) => `<span class="tag">${esc(p)}</span>`).join('')}<span class="small muted">${esc(c.vulnerable_versions)}</span></div>
        <div class="small mt-8"><b>Fix:</b> <span style="color:var(--ink-2)">${esc(c.remediation)}</span></div></div>
      <div style="text-align:right"><div class="cvss" style="color:${c.cvss_score >= 9 ? 'var(--crit)' : c.cvss_score >= 7 ? 'var(--high)' : 'var(--med)'}">${Number(c.cvss_score).toFixed(1)}</div><div class="small muted">CVSS</div></div>
    </div>`).join('')}</div>` : emptyState('No entries match', 'Try a CVE id such as CVE-2021-44228.', 'bug');
}