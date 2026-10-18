import { $, $$, api, esc, sev, pill, flow, ago, stamp, num, emptyState, can, toast, markPayload } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { openAlert, openNewRule, openSuppress } from '../panels.js';

// Everything Aegis knows about one address, on one page.
let ctx = null;
const SEV_C = { CRITICAL: 'var(--sev-1)', HIGH: 'var(--sev-2)', MEDIUM: 'var(--sev-3)', LOW: 'var(--sev-4)' };

export async function render({ el, params, navigate }) {
  const ip = params[0] || '';
  ctx = { el, ip, navigate };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <div class="eyebrow"><a href="#/alerts">Alerts</a> / address</div>
        <h1 class="page-title mono">${esc(ip || 'No address')}</h1>
        <p class="page-sub" id="ip-sub">Loading...</p>
      </div>
      <div class="page-actions" id="ip-actions"></div>
    </div>
    <div id="ip-body" class="stack"><div class="panel skeleton" style="height:110px"></div><div class="panel skeleton" style="height:300px"></div></div>`;
  if (!ip) { $('#ip-body', el).innerHTML = emptyState('No address', 'Open a profile from an alert, or search for an IP with /.', 'globe'); return; }
  await paint();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) paint(); }

async function paint() {
  const { el, ip, navigate } = ctx;
  let d;
  try { d = await api(`/ip/${encodeURIComponent(ip)}`); } catch (e) {
    $('#ip-sub', el).textContent = e.message;
    $('#ip-body', el).innerHTML = emptyState('Not a valid address', 'Check the URL and try again.', 'alert');
    return;
  }
  const respond = can('respond');
  const blocked = d.rules.find((r) => r.is_active && r.action === 'BLOCK');
  const isolated = d.rules.find((r) => r.is_active && r.action === 'ISOLATE');
  const c = d.counts;
  $('#ip-sub', el).innerHTML = [
    d.internal ? 'Internal address' : 'External address',
    d.asset ? `inventory host <b>${esc(d.asset.hostname)}</b>` : null,
    d.first_seen ? `first seen ${ago(d.first_seen)}, last ${ago(d.last_seen)}` : 'no alerts on record'
  ].filter(Boolean).join(' &middot; ');

  $('#ip-actions', el).innerHTML = `
    ${blocked ? `<span class="tag tag--ok">${icon('lock')}Blocked by ${esc(blocked.rule_id)}</span>` : ''}
    ${isolated ? `<span class="tag tag--warn">Isolated by ${esc(isolated.rule_id)}</span>` : ''}
    ${respond && !blocked && !d.internal ? `<button class="btn btn--primary" id="ip-block">${icon('lock')}Block</button>` : ''}
    ${respond && !isolated && d.internal ? `<button class="btn" id="ip-isolate">Isolate host</button>` : ''}
    ${can('configure') && c.as_source ? `<button class="btn btn--ghost" id="ip-tune">${icon('filter')}Suppress from this source</button>` : ''}
    ${d.asset ? `<a class="btn btn--ghost" href="#/telemetry?host=${encodeURIComponent(ip)}">${icon('terminal')}Logs</a>` : ''}`;

  const maxSev = Math.max(1, ...Object.values(c.by_severity));
  const intel = d.intel;
  const score = intel && intel.score != null ? intel.score : null;
  $('#ip-body', el).innerHTML = `
    <div class="kpis grid grid-kpi reveal">
      <div class="kpi ${c.open ? 'kpi--alert' : ''}"><div class="kpi__label">Open alerts</div><div class="kpi__value">${c.open}</div><div class="kpi__foot">${c.alerts} total</div></div>
      <div class="kpi"><div class="kpi__label">As source</div><div class="kpi__value">${c.as_source}</div><div class="kpi__foot">alerts it triggered</div></div>
      <div class="kpi"><div class="kpi__label">As target</div><div class="kpi__value">${c.as_target}</div><div class="kpi__foot">alerts aimed at it</div></div>
      <div class="kpi"><div class="kpi__label">Investigations</div><div class="kpi__value">${d.investigations.length}</div><div class="kpi__foot">${d.investigations.filter((i) => i.outcome === 'ATTACK_SUCCEEDED').length} confirmed compromise</div></div>
      <div class="kpi ${score >= 50 ? 'kpi--alert' : ''}"><div class="kpi__label">Threat score</div><div class="kpi__value">${score == null ? '-' : `${score}<small>/100</small>`}</div><div class="kpi__foot">${d.internal ? 'internal, not checked' : intel && !intel.error && !intel.skipped ? `${esc(intel.verdict || '')}, ${(intel.sources_ok || []).length} sources` : intel && intel.error ? 'lookup failed' : 'intel off'}</div></div>
    </div>

    <div class="grid grid-2-1">
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Alerts</h2><span class="panel__meta">${d.alerts.length < c.alerts ? `latest ${d.alerts.length}` : `${c.alerts}`}</span></div>
        ${d.alerts.length ? `<div class="table-wrap"><table class="table"><thead><tr><th style="width:104px">Severity</th><th>Signature</th><th class="hide-sm">Flow</th><th>Status</th><th class="num">When</th></tr></thead><tbody class="rows-in">
          ${d.alerts.slice(0, 60).map((a, i) => `<tr class="is-clickable ${['CLOSED', 'FALSE_POSITIVE'].includes(a.status) ? 'is-dim' : ''}" style="--i:${Math.min(i, 20)}" data-alert="${esc(a.alert_id)}">
            <td>${sev(a.severity)}</td><td><span class="cell-main">${esc(a.signature)}</span><span class="cell-sub mono">${esc(a.alert_id)}</span></td>
            <td class="hide-sm">${flow(a.source_ip, a.dest_ip, a.dest_port)}</td><td>${pill(a.status)}</td><td class="num small muted" title="${stamp(a.detected_at)}">${ago(a.detected_at)}</td></tr>`).join('')}
        </tbody></table></div>` : emptyState('No alerts', 'Nothing on record for this address.', 'inbox')}
      </section>
      <div class="stack">
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">${d.internal ? 'Host' : 'Reputation'}</h2></div>
          <div class="panel__body">
            ${d.asset ? `<dl class="kv"><dt>Hostname</dt><dd>${esc(d.asset.hostname)}</dd><dt>OS</dt><dd>${esc(d.asset.os_version || '-')}</dd><dt>Owner</dt><dd>${esc(d.asset.owner || '-')}</dd><dt>Criticality</dt><dd>${sev(d.asset.criticality)}</dd><dt>WAF</dt><dd>${d.asset.waf_enabled ? 'Yes' : 'No'}</dd></dl>` : ''}
            ${!d.internal && intel && !intel.error && !intel.skipped ? intelBlock(intel, score, Boolean(d.asset)) : ''}
            ${!d.internal && intel && intel.error ? `<div class="notice notice--warn">${icon('alert')}<div class="small">Reputation lookup failed: ${esc(intel.error)}</div></div>` : ''}
            ${!d.asset && (d.internal || !intel || intel.skipped) ? `<p class="small muted" style="margin:0">${d.internal ? 'Internal address with no inventory record. Add it under Assets so exposure and criticality are known.' : 'Threat intel is switched off on this server (AEGIS_INTEL=off).'}</p>` : ''}
          </div>
        </section>
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Severity</h2></div>
          <div class="panel__body">${Object.keys(SEV_C).map((s) => `<div class="hbar">${sev(s)}<div class="hbar__track"><div class="hbar__fill" style="--c:${SEV_C[s]};width:${(c.by_severity[s] / maxSev) * 100}%"></div></div><span class="hbar__n">${c.by_severity[s]}</span></div>`).join('')}</div>
        </section>
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Talks to</h2><span class="panel__meta">by alert count</span></div>
          ${d.peers.length ? `<div class="breakdown panel__body">${d.peers.map((p) => `<div><a class="ip ip-link" href="#/ip/${encodeURIComponent(p.ip)}">${esc(p.ip)}</a><b>${p.n}</b></div>`).join('')}</div>` : '<div class="panel__body small muted">No peers yet.</div>'}
        </section>
      </div>
    </div>

    <div class="grid grid-1-1">
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Signatures</h2></div>
        ${d.signatures.length ? `<div class="breakdown panel__body">${d.signatures.map((s) => `<div><span class="truncate">${esc(s.signature)}</span><b>${s.n}</b></div>`).join('')}</div>` : '<div class="panel__body small muted">None.</div>'}
      </section>
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Containment history</h2></div>
        ${d.rules.length ? `<div class="rows-in">${d.rules.map((r, i) => `<div class="list__item" style="--i:${i}">${pill(r.action, r.action === 'BLOCK' ? 'Block' : 'Isolate')}<div style="min-width:0"><div class="list__title truncate">${esc(r.reason)}</div><div class="list__sub"><span class="mono">${esc(r.rule_id)}</span><span>${esc(r.enacted_by || '')}</span><span>${ago(r.created_at)}</span>${r.expires_at ? `<span>${r.is_active ? 'lifts' : 'lifted'} ${stamp(r.expires_at)}</span>` : ''}</div></div>${pill(r.is_active ? (r.enforcement && r.enforcement.status) || 'RECORDED' : 'DISABLED')}</div>`).join('')}</div>` : emptyState('No rules', 'This address has never been blocked or isolated.', 'shield')}
      </section>
    </div>

    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">Investigations</h2></div>
      ${d.investigations.length ? `<div class="table-wrap"><table class="table"><thead><tr><th>Case</th><th>Verdict</th><th class="hide-sm">Tactic</th><th class="num">Confidence</th><th class="num">When</th></tr></thead><tbody class="rows-in">
        ${d.investigations.map((i, n) => `<tr class="is-clickable" style="--i:${n}" data-inv="${esc(i.alert_id)}"><td><span class="cell-main mono">${esc(i.investigation_id)}</span><span class="cell-sub">${esc(i.alert_id)}</span></td><td>${pill(i.outcome)}</td><td class="hide-sm small">${esc(i.mitre_tactic || '-')}</td><td class="num">${i.confidence}%</td><td class="num small muted">${ago(i.created_at)}</td></tr>`).join('')}
      </tbody></table></div>` : emptyState('No investigations', 'Run one from any alert involving this address.', 'scan')}
    </section>

    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">Server logs</h2><span class="panel__meta">${d.logs.length} lines</span></div>
      ${d.logs.length ? `<div style="max-height:360px;overflow:auto">${d.logs.map((l) => `<div class="logline"><span class="muted" title="${stamp(l.logged_at)}">${stamp(l.logged_at).slice(5, 16)}</span><span>${esc(l.host_ip)}</span><span class="muted">${esc(l.log_type)}</span><span class="logline__raw">${markPayload(l.raw_entry)}</span></div>`).join('')}</div>` : emptyState('No log lines', 'Ship web or auth logs to /api/ingest/logs to see this address in context.', 'terminal')}
    </section>`;

  $$('[data-alert]', el).forEach((r) => { r.onclick = () => openAlert(r.dataset.alert, navigate); });
  $$('[data-inv]', el).forEach((r) => { r.onclick = () => navigate(`investigate/${r.dataset.inv}`); });
  const blockBtn = $('#ip-block', el);
  if (blockBtn) blockBtn.onclick = () => openNewRule({ target_ip: ip, action: 'BLOCK', reason: d.signatures[0] ? `Source of ${d.signatures[0].signature}` : '' });
  const isoBtn = $('#ip-isolate', el);
  if (isoBtn) isoBtn.onclick = () => openNewRule({ target_ip: ip, action: 'ISOLATE', reason: '' });
  const tune = $('#ip-tune', el);
  if (tune) tune.onclick = () => openSuppress({ name: `Expected traffic from ${ip}`, source_cidr: ip });
  if (intel && intel.error && !ctx.warned) { ctx.warned = true; toast('Reputation lookup failed', intel.error, 'error'); }
  hydrateIcons(el);
  if (!d.internal && intel && !intel.error && !intel.skipped) registration(ip, el);
}

// RDAP owner, BGP origin and passive DNS load after the page so it never waits on them.
async function registration(ip, el) {
  const box = $('#ip-reg', el);
  if (!box) return;
  if (ctx.reg && ctx.reg.ip === ip) { box.innerHTML = ctx.reg.html; return; }
  box.innerHTML = '<div class="small muted row" style="gap:8px;margin-top:10px"><span class="spinner spinner--sm"></span>Registration, routing and passive DNS</div>';
  try {
    const r = await api(`/intel/lookup?q=${encodeURIComponent(ip)}&vt=0&poll=1&wait=6000`);
    const w = r.whois && r.whois.found ? r.whois : null;
    const b = r.bgp && r.bgp.asns ? r.bgp : null;
    const p = r.pdns && r.pdns.records ? r.pdns : null;
    const html = `<dl class="kv mt-12">
      ${w ? `<dt>Registered to</dt><dd>${esc(w.org || w.name || '-')}${w.range ? ` <span class="mono muted small">${esc(w.range)}</span>` : ''}</dd>${w.abuse ? `<dt>Abuse contact</dt><dd class="small">${esc(w.abuse)}</dd>` : ''}` : ''}
      ${b ? `<dt>BGP origin</dt><dd>${b.asns.map((a) => `<span class="mono">${esc(a.asn)}</span> ${esc(a.holder || '')}`).join(', ') || '-'}${b.prefix ? ` <span class="mono muted small">${esc(b.prefix)}</span>` : ''}</dd>` : ''}
      ${p ? `<dt>Passive DNS</dt><dd>${p.records.length ? `${p.records.slice(0, 4).map((x) => `<div class="mono small truncate">${esc(x.query)}</div>`).join('')}<span class="small muted">${num(p.total)} records since ${esc(String(p.first_seen || '').slice(0, 10))}</span>` : '<span class="muted">no names seen</span>'}</dd>` : ''}
    </dl><a class="small ip-link" href="#/intel?tab=lookup&q=${encodeURIComponent(ip)}">Full lookup</a>`;
    ctx.reg = { ip, html };
    if (document.body.contains(box)) box.innerHTML = html;
  } catch { if (document.body.contains(box)) box.innerHTML = ''; }
}
function intelBlock(intel, score, gap) {
  const g = intel.geo || {};
  const gn = intel.greynoise;
  const sh = intel.shodan;
  const ab = intel.abuseipdb;
  const color = score >= 75 ? 'var(--crit)' : score >= 40 ? 'var(--high)' : 'var(--ok)';
  const where = [g.city, g.country].filter(Boolean).join(', ');
  return `<dl class="kv ${gap ? 'mt-12' : ''}">
    <dt>Score</dt><dd><span class="meter"><span class="meter__track" style="width:90px"><span class="meter__fill" style="width:${score || 0}%;background:${color}"></span></span><span class="mono">${score ?? '-'}</span></span> <span class="small muted">${esc(intel.verdict || '')}</span></dd>
    ${intel.c2 ? '<dt>Botnet C2</dt><dd><span class="tag tag--warn">command and control</span></dd>' : ''}
    ${(intel.iocs || []).length ? `<dt>Threat feeds</dt><dd>${intel.iocs.slice(0, 6).map((h) => `<div class="small">${h.link ? `<a class="ip-link" href="${esc(h.link)}" target="_blank" rel="noopener noreferrer">${esc(h.source)}</a>` : esc(h.source)}: ${esc(h.kind)}${h.malware ? ` <b>${esc(h.malware)}</b>` : ''}${h.first_seen ? ` <span class="muted">since ${esc(String(h.first_seen).slice(0, 10))}</span>` : ''}</div>`).join('')}</dd>` : ''}
    <dt>Blocklists</dt><dd>${intel.listed && intel.listed.length ? intel.listed.map((l) => `<span class="tag tag--warn" title="${esc(l.detail)}">${esc(l.list)}</span>`).join(' ') : '<span class="muted">not listed</span>'}</dd>
    <dt>GreyNoise</dt><dd>${gn ? (gn.unseen ? '<span class="muted">not seen scanning</span>' : `${esc(gn.classification)}${gn.noise ? ', scanning the internet' : ''}${gn.riot ? ', known business service' : ''}${gn.last_seen ? ` <span class="muted small">last ${esc(gn.last_seen)}</span>` : ''}`) : '-'}</dd>
    ${ab ? `<dt>AbuseIPDB</dt><dd>${ab.score}/100 from ${num(ab.reports)} reports${ab.last_reported ? ` <span class="muted small">last ${ago(ab.last_reported)}</span>` : ''}</dd>` : ''}
    <dt>Network</dt><dd>${esc(g.org || intel.isp || '-')}${g.asn ? ` <span class="mono muted small">${esc(g.asn)}</span>` : ''}</dd>
    <dt>Location</dt><dd>${esc(where || '-')}</dd>
    ${sh && sh.ports.length ? `<dt>Open ports</dt><dd class="mono small">${sh.ports.slice(0, 14).map(esc).join(', ')}${sh.ports.length > 14 ? ' ...' : ''}</dd>` : ''}
    ${sh && sh.hostnames.length ? `<dt>Hostnames</dt><dd class="mono small truncate">${esc(sh.hostnames.slice(0, 3).join(', '))}</dd>` : ''}
    ${sh && sh.vulns.length ? `<dt>CVEs seen</dt><dd>${sh.vulns.slice(0, 6).map((v) => `<span class="tag">${esc(v)}</span>`).join(' ')}${sh.vulns.length > 6 ? ` <span class="small muted">+${sh.vulns.length - 6}</span>` : ''}</dd>` : ''}
  </dl>
  <div id="ip-reg" class="ip-reg"></div>
  <p class="small muted" style="margin:8px 0 0">${esc((intel.sources_ok || []).join(', '))}${intel.sources_failed && intel.sources_failed.length ? `. Unavailable: ${esc(intel.sources_failed.map((f) => f.source).join(', '))}` : ''}. ${intel.cached ? 'Cached' : 'Checked'} ${ago(intel.checked_at)}.</p>`;
}