import { $, $$, api, esc, sev, ago, stamp, emptyState, toast, busy, can, num } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

// Indicator lookup and the feed / Sigma status pages of Threat intel. Every value
// shown comes from a source that answered; a source that did not is named, not hidden.

export const VERDICT_C = { malicious: 'var(--crit)', suspicious: 'var(--high)', clean: 'var(--ok)', benign: 'var(--ok)', internal: 'var(--ink-3)', unknown: 'var(--ink-3)', error: 'var(--ink-3)' };
const TYPE_L = { ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL', md5: 'MD5', sha1: 'SHA1', sha256: 'SHA256', asn: 'ASN', ja3: 'JA3' };
const LEVEL_SEV = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', informational: 'LOW' };
const day = (iso) => (iso ? String(iso).slice(0, 10) : '-');
const bytes = (n) => (n == null ? '-' : n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);
const ext = (href, text) => `<a class="ip-link" href="${esc(href)}" target="_blank" rel="noopener noreferrer">${text}</a>`;
const meter = (score, c) => `<span class="meter"><span class="meter__track" style="width:90px"><span class="meter__fill" style="display:block;--c:${c};width:${Math.max(3, score)}%"></span></span><b class="mono">${score}</b><span class="small muted">/100</span></span>`;

// ---- Lookup ----------------------------------------------------------------------
let seq = 0;

export function lookupTab(body, { navigate, query = {} } = {}) {
  body.innerHTML = `
    <div class="panel__body lk-bar">
      <form class="lk-form" id="lk-form" autocomplete="off">
        <input class="input input--mono" id="lk-q" maxlength="2048" spellcheck="false" placeholder="IP, domain, URL, MD5/SHA1/SHA256 or AS number" aria-label="Indicator">
        <button class="btn btn--primary" id="lk-go">${icon('search')}Look up</button>
      </form>
      <div class="lk-samples" id="lk-samples"><span class="small muted">Defanged input works too: hxxp://bad[.]example/x</span></div>
    </div>
    <div id="lk-out">${emptyState('One query, every source', 'abuse.ch (ThreatFox, URLhaus, MalwareBazaar, Feodo, SSLBL), MISP OSINT, RDAP, RIPEstat BGP, passive DNS, certificate transparency and VirusTotal when a key is set.', 'search')}</div>`;
  const input = $('#lk-q', body);
  const go = (q, poll = false) => run(body, q, navigate, poll);
  $('#lk-form', body).onsubmit = (e) => { e.preventDefault(); const q = input.value.trim(); if (q) go(q); };
  api('/intel/samples').then((d) => {
    const box = $('#lk-samples', body);
    if (!box || !d.samples.length) return;
    box.innerHTML = `<span class="small muted">From today's feeds:</span>${d.samples.map((s) => `<button type="button" class="lk-chip" data-q="${esc(s.value)}" title="${esc(s.source)}: ${esc(s.value)}"><span>${esc(s.label)}</span><code>${esc(s.value.length > 34 ? `${s.value.slice(0, 31)}...` : s.value)}</code></button>`).join('')}`;
    $$('[data-q]', box).forEach((b) => { b.onclick = () => { input.value = b.dataset.q; go(b.dataset.q); }; });
  }).catch(() => {});
  if (query.q) { input.value = query.q; go(query.q); }
}

async function run(body, q, navigate, poll, tries = 0) {
  const out = $('#lk-out', body);
  const mine = ++seq;
  if (!poll) {
    history.replaceState(null, '', `#/intel?tab=lookup&q=${encodeURIComponent(q)}`);
    out.innerHTML = `<div class="panel__body"><div class="lk-wait"><span class="spinner"></span><div><b>Asking the sources</b><div class="small muted">Feeds are matched locally; RDAP, RIPEstat and passive DNS are queried live.</div></div></div></div>`;
  }
  const btn = $('#lk-go', body);
  if (btn && !poll) btn.disabled = true;
  try {
    const r = await api(`/intel/lookup?q=${encodeURIComponent(q)}${poll ? '&poll=1' : ''}`);
    if (mine !== seq || !document.body.contains(out)) return;
    out.innerHTML = result(r);
    hydrateIcons(out);
    $$('[data-nav]', out).forEach((a) => { a.onclick = (e) => { e.preventDefault(); navigate(a.dataset.nav); }; });
    $$('[data-pivot]', out).forEach((a) => { a.onclick = (e) => { e.preventDefault(); $('#lk-q', body).value = a.dataset.pivot; run(body, a.dataset.pivot, navigate, false); }; });
    const retry = $('#lk-retry', out);
    if (retry) retry.onclick = () => run(body, q, navigate, true);
    // Big feeds are still downloading: look again shortly, a few times at most.
    if (r.pending && r.pending.length && tries < 5) setTimeout(() => { if (mine === seq && document.body.contains(out)) run(body, q, navigate, true, tries + 1); }, 5000);
  } catch (e) {
    if (mine !== seq) return;
    out.innerHTML = `<div class="panel__body"><div class="notice notice--warn">${icon('alert')}<div>${esc(e.message)}</div></div></div>`;
    hydrateIcons(out);
  } finally { if (btn && !poll) btn.disabled = false; }
}

function result(r) {
  const ind = r.indicator;
  const c = VERDICT_C[r.verdict] || 'var(--ink-3)';
  if (r.skipped) return `<div class="panel__body"><div class="notice notice--warn">${icon('info')}<div>${esc(r.reason)}</div></div></div>`;
  if (r.verdict === 'internal') return `<div class="panel__body"><div class="notice">${icon('info')}<div><b class="mono">${esc(ind.display)}</b> is a private or reserved address. Public intel sources do not cover it; open the <a href="#" data-nav="ip/${esc(ind.value)}">host profile</a> instead.</div></div></div>`;
  const isIp = ind.type === 'ipv4' || ind.type === 'ipv6';
  const scored = r.signals.filter((s) => s.score != null);
  const ctxOnly = r.signals.filter((s) => s.score == null);
  return `
    <div class="lk-head" style="--c:${c}">
      <div class="lk-head__top">
        <span class="tag">${TYPE_L[ind.type] || esc(ind.type)}</span>
        <code class="lk-ind" title="${esc(ind.display)}">${esc(ind.display)}</code>
        ${isIp ? `<a class="btn btn--sm btn--ghost" href="#" data-nav="ip/${esc(ind.value)}">${icon('arrow')}IP profile</a>` : ''}
      </div>
      <div class="lk-head__verdict">
        <span class="lk-verdict">${esc(r.verdict)}</span>
        ${r.score != null ? meter(r.score, c) : '<span class="small muted">no source answered</span>'}
        ${r.c2 ? '<span class="tag tag--warn">command and control</span>' : ''}
        ${r.families.map((f) => `<span class="tag">${esc(f)}</span>`).join('')}
      </div>
      <p class="lk-summary">${esc(r.summary)}</p>
      ${r.local ? `<div class="small muted">In this workspace: ${r.local.alerts ? `<b>${r.local.alerts}</b> alert${r.local.alerts === 1 ? '' : 's'} (${r.local.open} open)` : 'no alerts'}${r.local.blocked ? ', <span class="tag tag--ok">blocked</span>' : ''}</div>` : ''}
    </div>
    ${scored.length || ctxOnly.length ? `<div class="lk-signals">${[...scored, ...ctxOnly].map((s) => `<div class="lk-sig${s.score == null ? ' is-ctx' : ''}"><span class="lk-sig__n mono">${s.score ?? '-'}</span><span class="lk-sig__src">${esc(s.source)}</span><span class="lk-sig__t">${esc(s.text)}</span></div>`).join('')}</div>` : ''}
    <div class="lk-grid">
      ${hitsPanel(r)}
      ${vtPanel(r.virustotal)}
      ${rdapPanel(r.whois, ind)}
      ${bgpPanel(r.bgp)}
      ${repPanel(r.reputation)}
      ${pdnsPanel(r.pdns, ind)}
      ${certPanel(r.certs)}
    </div>
    ${sourcesLine(r)}`;
}

const card = (title, sub, inner, wide = false) => `<section class="lk-card${wide ? ' lk-card--wide' : ''}"><header><h3>${title}</h3>${sub ? `<span class="small muted">${sub}</span>` : ''}</header>${inner}</section>`;

function hitsPanel(r) {
  if (!r.hits.length) return card('Feed matches', 'abuse.ch, MISP', `<p class="small muted lk-pad">No feed lists this indicator. Feeds only know what has been reported, so absence is not proof it is safe.</p>`, true);
  const rows = r.hits.slice(0, 40).map((h, i) => `<tr style="--i:${Math.min(i, 20)}">
    <td class="nowrap"><span class="cell-main">${esc(h.source)}</span>${h.score != null ? `<span class="cell-sub">score ${h.score}</span>` : '<span class="cell-sub">context</span>'}</td>
    <td><span class="cell-main">${esc(h.kind)}${h.malware ? ` <b>${esc(h.malware)}</b>` : ''}</span><span class="cell-sub">${esc(h.detail || '')}${h.match && h.match !== 'exact' ? ` (${esc(h.match)})` : ''}</span>${(h.tags || []).length ? `<div class="lk-tags">${h.tags.slice(0, 5).map((t) => `<span class="tag">${esc(t)}</span>`).join('')}</div>` : ''}</td>
    <td class="num small nowrap hide-sm">${day(h.first_seen)}${h.last_seen ? `<span class="cell-sub">${day(h.last_seen)}</span>` : ''}</td>
    <td class="small">${h.link ? ext(h.link, 'open') : ''}</td></tr>`).join('');
  return card('Feed matches', `${r.hits.length} entr${r.hits.length === 1 ? 'y' : 'ies'}`, `<div class="table-wrap"><table class="table"><thead><tr><th>Source</th><th>What it says</th><th class="num hide-sm">First / last</th><th></th></tr></thead><tbody class="rows-in">${rows}</tbody></table></div>`, true);
}

function vtPanel(v) {
  if (!v) return '';
  if (v.skipped) return card('VirusTotal', '', `<p class="small muted lk-pad">${esc(v.reason)}</p>`);
  if (v.error) return card('VirusTotal', '', `<p class="small lk-pad">${icon('alert')} ${esc(v.error)}</p>`);
  if (!v.found) return card('VirusTotal', '', `<p class="small muted lk-pad">Not in VirusTotal.${v.link ? ` ${ext(v.link, 'Search there')}` : ''}</p>`);
  const c = v.malicious >= 5 ? 'var(--crit)' : v.malicious ? 'var(--high)' : 'var(--ok)';
  return card('VirusTotal', v.cached ? 'cached' : 'live', `<div class="lk-pad">
    <div class="lk-vt"><b style="color:${c}">${v.malicious}</b><span>of ${v.total} engines flag it${v.suspicious ? `, ${v.suspicious} suspicious` : ''}</span></div>
    <dl class="kv mt-8">${v.label ? `<dt>Threat label</dt><dd>${esc(v.label)}</dd>` : ''}${v.type ? `<dt>File type</dt><dd>${esc(v.type)}</dd>` : ''}${v.names && v.names.length ? `<dt>Names</dt><dd class="mono small">${v.names.map(esc).join(', ')}</dd>` : ''}${v.as_owner ? `<dt>Network</dt><dd>${esc(v.asn || '')} ${esc(v.as_owner)}</dd>` : ''}${v.categories && v.categories.length ? `<dt>Categories</dt><dd>${v.categories.map(esc).join(', ')}</dd>` : ''}${v.last_analysis ? `<dt>Last analysis</dt><dd>${day(v.last_analysis)}</dd>` : ''}</dl>
    ${v.engines.length ? `<div class="lk-tags mt-8">${v.engines.map((e) => `<span class="tag tag--warn" title="${esc(e.result)}">${esc(e.engine)}</span>`).join('')}</div>` : ''}
    ${v.link ? `<div class="small mt-8">${ext(v.link, 'Full report on virustotal.com')}</div>` : ''}</div>`);
}

function rdapPanel(w, ind) {
  if (!w) return '';
  if (w.error) return card('Registration', 'RDAP', `<p class="small lk-pad">${esc(w.error)}</p>`);
  if (!w.found) return card('Registration', 'RDAP', `<p class="small muted lk-pad">${esc(w.server || 'The registry')} has no record for ${esc(w.query)}.</p>`);
  if (w.kind === 'domain') {
    const age = w.age_days != null ? `${num(w.age_days)} days${w.fresh ? ' <span class="tag tag--warn">new domain</span>' : w.young ? ' <span class="tag">under 6 months</span>' : ''}` : '-';
    return card('Registration', `RDAP via ${esc(w.server)}`, `<dl class="kv lk-pad">
      <dt>Domain</dt><dd class="mono">${esc(w.name)}</dd>
      <dt>Registrar</dt><dd>${esc(w.registrar || '-')}</dd>
      <dt>Registered</dt><dd>${day(w.registered)}</dd><dt>Age</dt><dd>${age}</dd>
      ${w.expires ? `<dt>Expires</dt><dd>${day(w.expires)}</dd>` : ''}
      ${w.nameservers.length ? `<dt>Name servers</dt><dd class="mono small">${w.nameservers.map(esc).join('<br>')}</dd>` : ''}
      ${w.abuse ? `<dt>Abuse contact</dt><dd>${esc(w.abuse)}</dd>` : ''}</dl>`);
  }
  return card('Owner', `RDAP via ${esc(w.server)}`, `<dl class="kv lk-pad">
    <dt>Network</dt><dd>${esc(w.name || '-')}${w.handle ? ` <span class="muted mono small">${esc(w.handle)}</span>` : ''}</dd>
    <dt>Range</dt><dd class="mono">${esc(w.range || '-')}</dd>
    <dt>Organisation</dt><dd>${esc(w.org || '-')}</dd>
    ${w.country ? `<dt>Country</dt><dd>${esc(w.country)}</dd>` : ''}
    ${w.registered ? `<dt>Allocated</dt><dd>${day(w.registered)}</dd>` : ''}
    ${w.abuse ? `<dt>Abuse contact</dt><dd>${esc(w.abuse)}</dd>` : ''}</dl>`);
}

function bgpPanel(b) {
  if (!b) return '';
  if (b.error) return card('Routing', 'RIPEstat', `<p class="small lk-pad">${esc(b.error)}</p>`);
  if (b.asn) {
    return card('Autonomous system', 'RIPEstat', `<dl class="kv lk-pad">
      <dt>ASN</dt><dd class="mono">${esc(b.asn)}</dd><dt>Holder</dt><dd>${esc(b.holder || '-')}</dd>
      <dt>Announced</dt><dd>${b.announced ? 'yes' : 'no'}</dd><dt>Prefixes</dt><dd>${num(b.prefixes)}</dd>
      ${b.sample_prefixes.length ? `<dt>Examples</dt><dd class="mono small">${b.sample_prefixes.map((p) => `<a href="#" class="ip-link" data-pivot="${esc(p.split('/')[0])}">${esc(p)}</a>`).join('<br>')}</dd>` : ''}</dl>`);
  }
  return card('Routing', 'RIPEstat', `<dl class="kv lk-pad">
    <dt>Announced</dt><dd>${b.announced ? `yes, as <span class="mono">${esc(b.prefix || '-')}</span>` : 'not announced'}</dd>
    <dt>Origin</dt><dd>${b.asns.length ? b.asns.map((a) => `<a href="#" class="ip-link mono" data-pivot="${esc(a.asn)}">${esc(a.asn)}</a> ${esc(a.holder || '')}`).join('<br>') : '-'}</dd>
    ${b.visibility != null ? `<dt>Visibility</dt><dd>${b.visibility}% of RIS peers</dd>` : ''}
    ${b.first_seen ? `<dt>Routed since</dt><dd>${day(b.first_seen)}</dd>` : ''}</dl>`);
}

function repPanel(rep) {
  if (!rep) return '';
  const listed = rep.listed || [];
  return card('Reputation', 'IP sources', `<dl class="kv lk-pad">
    ${rep.geo ? `<dt>Location</dt><dd>${esc([rep.geo.city, rep.geo.country].filter(Boolean).join(', ') || '-')}</dd>` : ''}
    <dt>Block lists</dt><dd>${listed.length ? listed.map((l) => `<span class="tag tag--warn" title="${esc(l.detail || '')}">${esc(l.list)}</span>`).join(' ') : 'none'}</dd>
    ${rep.greynoise ? `<dt>GreyNoise</dt><dd>${esc(rep.greynoise.classification || 'unknown')}${rep.greynoise.name ? `, ${esc(rep.greynoise.name)}` : ''}</dd>` : ''}
    ${rep.shodan ? `<dt>Open ports</dt><dd class="mono small">${rep.shodan.ports.length ? rep.shodan.ports.slice(0, 14).join(', ') : 'none seen'}</dd>${rep.shodan.vulns.length ? `<dt>Known CVEs</dt><dd>${rep.shodan.vulns.length}</dd>` : ''}` : ''}
    ${rep.abuseipdb && rep.abuseipdb.score != null ? `<dt>AbuseIPDB</dt><dd>${rep.abuseipdb.score}/100, ${num(rep.abuseipdb.reports)} reports</dd>` : ''}</dl>`);
}

function pdnsPanel(p, ind) {
  if (!p) return '';
  if (p.error) return card('Passive DNS', 'Mnemonic', `<p class="small lk-pad">${esc(p.error)}</p>`, true);
  if (!p.records.length) return card('Passive DNS', 'Mnemonic', '<p class="small muted lk-pad">No resolutions observed.</p>', true);
  const isIp = ind.type === 'ipv4' || ind.type === 'ipv6';
  const rows = p.records.slice(0, 25).map((x, i) => {
    const other = isIp ? x.query : x.answer;
    return `<tr style="--i:${Math.min(i, 20)}"><td class="mono small truncate" style="max-width:280px"><a href="#" class="ip-link" data-pivot="${esc(other)}" title="Look up ${esc(other)}">${esc(other)}</a>${!isIp && x.query !== ind.value && x.query !== ind.host ? `<span class="cell-sub">${esc(x.query)}</span>` : ''}</td><td class="small mono">${esc(x.rrtype)}</td><td class="num small nowrap">${day(x.first_seen)}</td><td class="num small nowrap hide-sm">${day(x.last_seen)}</td><td class="num small hide-sm">${num(x.times)}</td></tr>`;
  }).join('');
  return card('Passive DNS', `Mnemonic, ${num(p.total)} records since ${day(p.first_seen)}`, `<div class="table-wrap"><table class="table"><thead><tr><th>${isIp ? 'Name' : 'Answer'}</th><th>Type</th><th class="num">First seen</th><th class="num hide-sm">Last seen</th><th class="num hide-sm">Seen</th></tr></thead><tbody class="rows-in">${rows}</tbody></table></div>`, true);
}

function certPanel(c) {
  if (!c) return '';
  if (c.error) return card('Certificates', 'crt.sh', `<p class="small muted lk-pad">${esc(c.error)}. crt.sh is often slow; try again later.</p>`);
  if (!c.certificates) return card('Certificates', 'crt.sh', '<p class="small muted lk-pad">No certificates logged for this domain.</p>');
  return card('Certificates', 'crt.sh', `<dl class="kv lk-pad">
    <dt>Logged</dt><dd>${num(c.certificates)}</dd><dt>First issued</dt><dd>${day(c.first_issued)}</dd><dt>Latest</dt><dd>${day(c.last_issued)}</dd>
    ${c.issuers.length ? `<dt>Issuers</dt><dd class="small">${c.issuers.map(esc).join('<br>')}</dd>` : ''}
    ${c.names.length ? `<dt>Names</dt><dd class="mono small">${c.names.slice(0, 8).map(esc).join('<br>')}${c.names.length > 8 ? `<br><span class="muted">+${c.names.length - 8} more</span>` : ''}</dd>` : ''}</dl>`);
}

function sourcesLine(r) {
  const parts = [];
  if (r.sources_ok.length) parts.push(`<span><span class="live-dot"></span> ${r.sources_ok.map(esc).join(', ')}</span>`);
  if (r.pending.length) parts.push(`<span><span class="live-dot live-dot--warn"></span> still loading: ${r.pending.map(esc).join(', ')} <button class="btn btn--sm btn--ghost" id="lk-retry">${icon('refresh')}Check again</button></span>`);
  if (r.sources_failed.length) parts.push(`<span><span class="live-dot live-dot--off"></span> no answer: ${r.sources_failed.map((f) => `<span title="${esc(f.error)}">${esc(f.source)}</span>`).join(', ')}</span>`);
  return `<div class="lk-sources small muted">${parts.join('')}<span class="grow"></span><span>checked ${stamp(r.checked_at)}</span></div>`;
}

// ---- Feeds & Sigma ---------------------------------------------------------------
export async function feedsTab(body, { navigate }) {
  const [d, cfg] = await Promise.all([api('/intel/feeds'), api('/config')]);
  const configure = can('configure');
  const feeds = [...d.abusech.feeds, ...d.misp.feeds];
  const s = d.sigma;
  body.innerHTML = `
    <div class="panel__body row wrap" style="justify-content:space-between">
      <div class="small muted" style="max-width:72ch">Bulk feeds are downloaded and indexed in memory, so a lookup is a local match. A feed that fails to refresh keeps serving its last good copy.${d.offline ? ' <b>Threat intel is switched off on this server (AEGIS_INTEL=off).</b>' : ''}</div>
      ${configure && !d.offline ? `<button class="btn btn--sm" id="fd-refresh">${icon('refresh')}Refresh all</button>` : ''}
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th>Feed</th><th class="num">Entries</th><th class="num hide-sm">Size</th><th class="num">Updated</th><th>Status</th></tr></thead><tbody class="rows-in">
      ${feeds.map((f, i) => `<tr style="--i:${i}"><td><span class="cell-main">${esc(f.name)}</span><span class="cell-sub">${esc(f.note || f.provider)}</span></td>
        <td class="num">${num(f.entries)}</td><td class="num small hide-sm">${bytes(f.bytes)}</td>
        <td class="num small nowrap">${f.loaded_at ? ago(f.loaded_at) : '-'}${f.fetch_ms ? `<span class="cell-sub">${(f.fetch_ms / 1000).toFixed(1)} s</span>` : ''}</td>
        <td class="small">${feedState(f)}</td></tr>`).join('')}
      <tr><td><span class="cell-main">VirusTotal</span><span class="cell-sub">70+ engines; free key allows 4 lookups a minute, 500 a day</span></td><td class="num">-</td><td class="num hide-sm">-</td><td class="num small">${d.virustotal.configured ? `${d.virustotal.used_today} today` : '-'}</td><td class="small">${d.virustotal.configured ? '<span class="tag tag--ok">key set</span>' : '<span class="tag">set VT_API_KEY</span>'}</td></tr>
      <tr><td><span class="cell-main">Your MISP</span><span class="cell-sub">attributes/restSearch on your own instance</span></td><td class="num">-</td><td class="num hide-sm">-</td><td class="num">-</td><td class="small">${d.misp.own_instance ? `<span class="tag tag--ok">${esc(new URL(d.misp.own_instance).host)}</span>` : '<span class="tag">set MISP_URL and MISP_KEY</span>'}</td></tr>
      <tr><td><span class="cell-main">RDAP, RIPEstat, Mnemonic PDNS, crt.sh</span><span class="cell-sub">queried live per lookup, cached 12 hours</span></td><td class="num">-</td><td class="num hide-sm">-</td><td class="num">-</td><td class="small"><span class="tag tag--ok">no key needed</span></td></tr>
    </tbody></table></div>
    <div class="panel__body sg-head">
      <div>
        <h3 class="section-title" style="margin:0">Sigma rules</h3>
        <div class="small muted mt-8" id="sg-status">${sigmaLine(s, cfg)}</div>
      </div>
      ${configure ? `<div class="row wrap sg-policy">
        <label class="row small"><button class="switch" role="switch" id="sg-on" aria-checked="${cfg.sigmaEnabled !== false}" aria-label="Run Sigma rules on ingest"></button>Run on ingest</label>
        <label class="row small">Lowest level <select class="select" id="sg-min" style="width:auto">${['low', 'medium', 'high', 'critical'].map((l) => `<option${(cfg.sigmaMinLevel || 'medium') === l ? ' selected' : ''}>${l}</option>`).join('')}</select></label>
      </div>` : ''}
    </div>
    <div class="panel__body sg-filters">
      <input class="input" id="sg-q" placeholder="Search title, technique, CVE" aria-label="Search rules">
      <select class="select" id="sg-level" aria-label="Level"><option value="">All levels</option>${['critical', 'high', 'medium', 'low'].map((l) => `<option>${l}</option>`).join('')}</select>
      <select class="select" id="sg-target" aria-label="Log source"><option value="">All log sources</option><option value="web">Web server</option><option value="process">Process creation</option><option value="auditd">auditd</option><option value="linux">Linux syslog</option><option value="service">Services (sshd, sudo, cron)</option></select>
    </div>
    <div id="sg-list"><div class="panel__body"><div class="skeleton" style="height:160px"></div></div></div>`;
  hydrateIcons(body);
  let off = new Set(cfg.sigmaDisabled || []);
  const saveCfg = async (patch, what) => {
    try { await api('/config', { method: 'PUT', body: patch }); toast('Saved', what, 'ok'); } catch (e) { toast('Not saved', e.message, 'error'); }
  };
  const on = $('#sg-on', body);
  if (on) on.onclick = async () => { const v = on.getAttribute('aria-checked') !== 'true'; on.setAttribute('aria-checked', v); await saveCfg({ sigmaEnabled: v }, v ? 'Sigma rules run on every log batch.' : 'Sigma rules are paused.'); };
  const min = $('#sg-min', body);
  if (min) min.onchange = async () => { await saveCfg({ sigmaMinLevel: min.value }, `Rules below ${min.value} will not raise alerts.`); list(); };
  const rf = $('#fd-refresh', body);
  if (rf) rf.onclick = () => busy(rf, async () => {
    try {
      const r = await api('/intel/feeds/refresh', { method: 'POST', body: { which: 'all' } });
      const failed = (r.feeds && r.feeds.failed) || [];
      toast('Feeds refreshed', `${(r.ms / 1000).toFixed(1)} s${failed.length ? `, ${failed.length} kept their previous copy` : ''}`, failed.length ? 'info' : 'ok');
      feedsTab(body, { navigate });
    } catch (e) { toast('Refresh failed', e.message, 'error'); }
  });

  let timer = 0;
  let limit = 25;
  const list = async (tries = 0) => {
    const box = $('#sg-list', body);
    if (!box) return;
    const qs = new URLSearchParams({ q: $('#sg-q', body).value.trim(), level: $('#sg-level', body).value, target: $('#sg-target', body).value, limit: String(limit) });
    try {
      const r = await api(`/sigma/rules?${qs}`);
      if (!document.body.contains(box)) return;
      $('#sg-status', body).innerHTML = sigmaLine(r.status, cfg, r);
      if (!r.total) {
        box.innerHTML = `<div class="panel__body">${r.loading ? `<div class="lk-wait"><span class="spinner"></span><div><b>Downloading the SigmaHQ rule pack</b><div class="small muted">About 3 MB from GitHub, compiled once per server start.</div></div></div>` : emptyState('Rules not loaded', r.status.error || (r.status.enabled ? 'The rule pack has not been fetched yet.' : 'Sigma is off on this server (AEGIS_SIGMA=off or threat intel disabled).'), 'shield')}</div>`;
        hydrateIcons(box);
        if (r.loading && tries < 8) setTimeout(() => list(tries + 1), 4000);
        return;
      }
      box.innerHTML = r.rules.length ? `<div class="table-wrap"><table class="table sg-table"><thead><tr><th>Rule</th><th class="hide-sm">ATT&amp;CK</th><th class="hide-sm">Source</th><th class="num">30 days</th>${configure ? '<th></th>' : ''}</tr></thead><tbody class="rows-in">
        ${r.rules.map((x, i) => `<tr style="--i:${Math.min(i, 24)}" class="${x.enabled ? '' : 'is-dim'}">
          <td><span class="cell-main">${sev(LEVEL_SEV[x.level] || 'LOW')} ${x.link ? ext(x.link, esc(x.title)) : esc(x.title)}</span><span class="cell-sub sg-desc">${esc(x.description || '')}</span>${x.cve ? `<span class="tag tag--kev mt-4">${esc(x.cve)}</span>` : ''}</td>
          <td class="hide-sm small"><span class="mono">${esc(x.technique || '-')}</span><span class="cell-sub">${esc(x.tactic || '')}</span></td>
          <td class="hide-sm small">${esc(x.service || x.target)}<span class="cell-sub">${esc(x.status || '')}</span></td>
          <td class="num">${x.hits_30d ? `<b>${num(x.hits_30d)}</b>${x.open ? `<span class="cell-sub">${x.open} open</span>` : ''}` : '<span class="muted">-</span>'}</td>
          ${configure ? `<td style="width:56px"><button class="switch" role="switch" data-sg="${esc(x.id)}" aria-checked="${!off.has(x.id)}" aria-label="Enable ${esc(x.title)}"></button></td>` : ''}
        </tr>`).join('')}</tbody></table></div>${r.matched > r.rules.length ? `<div class="panel__body sg-more small muted"><span>Showing ${r.rules.length} of ${num(r.matched)} matching rules</span><button class="btn btn--sm" id="sg-more">Show ${Math.min(25, r.matched - r.rules.length)} more</button></div>` : ''}`
        : `<div class="panel__body">${emptyState('No rule matches', 'Try a technique id such as T1190, or a CVE.', 'search')}</div>`;
      hydrateIcons(box);
      const more = $('#sg-more', box);
      if (more) more.onclick = () => { limit += 25; list(); };
      $$('[data-sg]', box).forEach((sw) => {
        sw.onclick = async () => {
          const id = sw.dataset.sg;
          const next = new Set(off);
          if (next.has(id)) next.delete(id); else next.add(id);
          try {
            await api('/config', { method: 'PUT', body: { sigmaDisabled: [...next] } });
            off = next;
            sw.setAttribute('aria-checked', !off.has(id));
            sw.closest('tr').classList.toggle('is-dim', off.has(id));
          } catch (e) { toast('Not saved', e.message, 'error'); }
        };
      });
    } catch (e) { box.innerHTML = `<div class="panel__body">${emptyState('Could not load rules', e.message, 'alert')}</div>`; hydrateIcons(box); }
  };
  const later = () => { clearTimeout(timer); limit = 25; timer = setTimeout(list, 220); };
  $('#sg-q', body).oninput = later;
  $('#sg-level', body).onchange = list;
  $('#sg-target', body).onchange = list;
  list();
}

function feedState(f) {
  if (f.loading && !f.loaded) return '<span class="row" style="gap:6px"><span class="spinner spinner--sm"></span>downloading</span>';
  if (f.loaded && f.error) return `<span class="tag" title="${esc(f.error)}">stale copy</span>`;
  if (f.loaded) return '<span class="tag tag--ok">loaded</span>';
  if (f.error) return `<span class="tag tag--warn" title="${esc(f.error)}">failed</span> <span class="cell-sub">${esc(f.error)}</span>`;
  return '<span class="muted">loads on first lookup</span>';
}

function sigmaLine(s, cfg, r) {
  if (!s.enabled && !s.loaded) return 'Off on this server.';
  if (!s.loaded) return s.error ? `Last download failed: ${esc(s.error)}` : 'Rule pack loads on first use.';
  const t = s.by_target || {};
  const svc = Object.entries(t).filter(([k]) => k.startsWith('svc:')).reduce((n, [, v]) => n + v, 0);
  return `SigmaHQ <b class="mono">${esc(s.version || '')}</b>: ${num(s.entries)} rules compiled for the logs Aegis receives (web ${t.web || 0}, process ${t.process || 0}, auditd ${t.auditd || 0}, syslog ${t.linux || 0}, services ${svc}) out of ${num(s.considered)} in the pack. ${cfg.sigmaEnabled === false ? '<b>Paused.</b>' : `Raising alerts at ${esc(cfg.sigmaMinLevel || 'medium')} and above.`}${r && r.firing ? ` ${r.firing} fired in the last 30 days.` : ''}`;
}
