'use strict';

// IP reputation from public sources that need no account, plus AbuseIPDB when
// ABUSEIPDB_API_KEY is set. Each source is independent: one that times out or
// rate-limits shows up in `sources_failed` and the others still count.
//
//   Blocklists (downloaded, cached for 6 h)
//     Spamhaus DROP        hijacked and criminal netblocks
//     FireHOL level 1      aggregated attack sources
//     Tor exit list        current Tor exit relays
//   Per-address lookups (cached for 6 h)
//     GreyNoise community  is this address mass-scanning the internet?
//     Shodan InternetDB    open ports, hostnames and CVEs seen on the address
//     ipwho.is             country, city, ASN and network owner

const net = require('net');
const { Reputation } = require('./reputation');
const { isInternal } = require('../engine/analysis');

const LIST_TTL = 6 * 3600000;
const LIST_RETRY = 10 * 60000;
const IP_TTL = 6 * 3600000;
const IP_CACHE_MAX = 2000;

const ipv4ToInt = (ip) => ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0);

function cidrRange(cidr) {
  const [base, bitsRaw] = String(cidr).trim().split('/');
  if (!net.isIPv4(base)) return null;
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const size = 2 ** (32 - bits);
  const start = Math.floor(ipv4ToInt(base) / size) * size;
  return { start, end: start + size - 1 };
}

// One address or CIDR per line, '#' comments (FireHOL, Tor bulk exit list).
function parseNetset(text) {
  const ranges = []; const exact = new Set();
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    if (!line) continue;
    if (net.isIP(line)) { exact.add(line.toLowerCase()); continue; }
    const r = cidrRange(line);
    if (r) ranges.push({ ...r, label: line });
  }
  return { ranges, exact };
}

// Spamhaus DROP is NDJSON: {"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
function parseSpamhaus(text) {
  const ranges = [];
  for (const line of String(text).split(/\r?\n/)) {
    if (!line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    const r = row && row.cidr ? cidrRange(row.cidr) : null;
    if (r) ranges.push({ ...r, label: `${row.cidr}${row.sblid ? ` ${row.sblid}` : ''}` });
  }
  return { ranges, exact: new Set() };
}

const LISTS = [
  { id: 'spamhaus', name: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/drop_v4.json', score: 100, parse: parseSpamhaus },
  { id: 'firehol', name: 'FireHOL level 1', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', score: 90, parse: parseNetset },
  { id: 'tor', name: 'Tor exit list', url: 'https://check.torproject.org/torbulkexitlist', score: 60, parse: parseNetset }
];

class ThreatIntel {
  constructor({ abuseKey = null, fetchImpl = globalThis.fetch, timeoutMs = 6000, offline = false } = {}) {
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.offline = offline;
    this.abuse = abuseKey ? new Reputation({ apiKey: abuseKey, fetchImpl }) : null;
    this.lists = new Map();
    this.loading = new Map();
    this.cache = new Map();
    this.feeds = null;
  }

  // abuse.ch and MISP feed matches (src/intel/hub.js) count towards every IP verdict.
  attachFeeds(hub) { this.feeds = hub; }

  // Public sources need no key, so reputation is on unless explicitly disabled.
  get available() { return !this.offline; }

  describe() {
    return {
      abuseipdb: Boolean(this.abuse),
      sources: [...LISTS.map((l) => l.name), 'GreyNoise', 'Shodan InternetDB', 'ipwho.is', ...(this.feeds ? ['Feodo Tracker', 'ThreatFox', 'URLhaus', 'MISP OSINT'] : []), ...(this.abuse ? ['AbuseIPDB'] : [])],
      lists: LISTS.map((l) => {
        const s = this.lists.get(l.id);
        return { id: l.id, name: l.name, entries: s && s.data ? s.data.ranges.length + s.data.exact.size : null, loaded_at: s && s.data ? new Date(s.at).toISOString() : null, error: s ? s.error || null : null };
      })
    };
  }

  get(url) {
    return this.fetch(url, { headers: { Accept: 'application/json, text/plain', 'User-Agent': 'aegis-security/4' }, signal: AbortSignal.timeout(this.timeoutMs) });
  }

  async loadList(def) {
    const have = this.lists.get(def.id);
    if (have && have.data && Date.now() - have.at < LIST_TTL) return have;
    if (have && !have.data && Date.now() - have.at < LIST_RETRY) return have;
    if (this.loading.has(def.id)) return this.loading.get(def.id);
    const p = (async () => {
      try {
        const res = await this.get(def.url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = def.parse(await res.text());
        if (!data.ranges.length && !data.exact.size) throw new Error('list was empty');
        const rec = { at: Date.now(), data, error: null };
        this.lists.set(def.id, rec);
        return rec;
      } catch (err) {
        // A stale copy beats no copy.
        const rec = have && have.data ? { ...have, error: err.message } : { at: Date.now(), data: null, error: err.message };
        this.lists.set(def.id, rec);
        return rec;
      } finally { this.loading.delete(def.id); }
    })();
    this.loading.set(def.id, p);
    return p;
  }

  async json(url, notFound) {
    const res = await this.get(url);
    if (res.status === 404 && notFound) return notFound;
    if (res.status === 429) throw new Error('rate limited');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async check(ipIn) {
    const ip = String(ipIn || '').trim().toLowerCase();
    if (!net.isIP(ip)) throw new Error('Not an IP address');
    if (isInternal(ip)) return { ip, skipped: true, reason: 'Internal address' };
    if (this.offline) return { ip, skipped: true, reason: 'Threat intel disabled (AEGIS_INTEL=off)' };
    const hit = this.cache.get(ip);
    if (hit && Date.now() - hit.at < IP_TTL) return { ...hit.data, cached: true };

    const ok = []; const failed = [];
    const run = async (name, fn) => {
      try { const v = await fn(); ok.push(name); return v; } catch (err) { failed.push({ source: name, error: err.name === 'TimeoutError' ? 'timed out' : err.message }); return null; }
    };
    const v4 = net.isIPv4(ip) ? ipv4ToInt(ip) : null;
    const [listed, gn, sh, geo, abuse, feed] = await Promise.all([
      Promise.all(LISTS.map(async (def) => {
        const rec = await this.loadList(def);
        if (!rec.data) { failed.push({ source: def.name, error: rec.error }); return null; }
        ok.push(def.name);
        if (rec.data.exact.has(ip)) return { id: def.id, list: def.name, detail: ip, score: def.score };
        if (v4 != null) {
          const r = rec.data.ranges.find((x) => v4 >= x.start && v4 <= x.end);
          if (r) return { id: def.id, list: def.name, detail: r.label, score: def.score };
        }
        return null;
      })),
      run('GreyNoise', () => this.json(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, { classification: 'unknown', unseen: true })),
      run('Shodan InternetDB', () => this.json(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { ports: [], hostnames: [], vulns: [], tags: [] })),
      run('ipwho.is', async () => {
        const d = await this.json(`https://ipwho.is/${encodeURIComponent(ip)}`);
        if (d.success === false) throw new Error(d.message || 'lookup failed');
        return d;
      }),
      this.abuse ? run('AbuseIPDB', () => this.abuse.check(ip)) : null,
      this.feeds ? this.feeds.ipHits(ip).catch((err) => ({ hits: [], ok: [], failed: [{ source: 'abuse.ch', error: err.message }], pending: [] })) : null
    ]);
    const iocs = feed ? feed.hits : [];
    if (feed) { ok.push(...feed.ok); failed.push(...feed.failed); }

    const hits = listed.filter(Boolean);
    const greynoise = gn ? { classification: gn.classification || 'unknown', noise: Boolean(gn.noise), riot: Boolean(gn.riot), name: gn.name && gn.name !== 'unknown' ? gn.name : null, last_seen: gn.last_seen || null, unseen: Boolean(gn.unseen) } : null;
    const shodan = sh ? { ports: (sh.ports || []).slice(0, 40), hostnames: (sh.hostnames || []).slice(0, 10), vulns: (sh.vulns || []).slice(0, 25), tags: sh.tags || [] } : null;
    const conn = (geo && geo.connection) || {};
    const location = geo ? { country: geo.country || null, country_code: geo.country_code || null, city: geo.city || null, asn: conn.asn ? `AS${conn.asn}` : null, org: conn.org || conn.isp || null, domain: conn.domain || null } : null;

    // The score is the strongest single signal; AbuseIPDB counts when configured.
    const signals = hits.map((h) => h.score);
    if (greynoise && greynoise.classification === 'malicious') signals.push(90);
    else if (greynoise && greynoise.classification === 'suspicious') signals.push(50);
    if (shodan && shodan.tags.includes('malware')) signals.push(85);
    if (abuse && abuse.score != null) signals.push(abuse.score);
    for (const h of iocs) if (h.score != null) signals.push(h.score);
    const benign = Boolean(greynoise && (greynoise.riot || greynoise.classification === 'benign'));
    const score = signals.length ? Math.max(...signals) : ok.length ? 0 : null;
    const verdict = score == null ? 'unknown' : score >= 75 ? 'malicious' : score >= 40 ? 'suspicious' : benign ? 'benign' : 'clean';

    const parts = [];
    const c2 = iocs.find((h) => h.c2);
    if (c2) parts.push(`known ${c2.malware ? `${c2.malware} ` : ''}C2 server (${c2.source})`);
    else if (iocs.some((h) => h.score != null)) parts.push(`in ${[...new Set(iocs.map((h) => h.source))].join(', ')}${iocs[0].malware ? ` (${iocs[0].malware})` : ''}`);
    if (hits.length) parts.push(`listed on ${hits.map((h) => h.list).join(', ')}`);
    if (greynoise && !greynoise.unseen) parts.push(`GreyNoise ${greynoise.classification}${greynoise.noise ? ', scanning the internet' : ''}${greynoise.riot ? ', known business service' : ''}`);
    if (abuse && abuse.score != null) parts.push(`AbuseIPDB ${abuse.score}/100 from ${abuse.reports} reports`);
    if (shodan && shodan.vulns.length) parts.push(`${shodan.vulns.length} CVEs exposed on the address`);
    if (location && location.org) parts.push(`${location.org}${location.country_code ? `, ${location.country_code}` : ''}`);

    const data = {
      ip, source: ok.join(', '), score, verdict, listed: hits.map(({ score: _s, ...h }) => h), greynoise, shodan, geo: location,
      abuseipdb: abuse || null, iocs, c2: Boolean(c2), pending: feed ? feed.pending : [],
      reports: abuse ? abuse.reports : hits.length,
      country: (location && location.country_code) || (abuse && abuse.country) || null,
      isp: (location && location.org) || (abuse && abuse.isp) || null,
      usage: abuse ? abuse.usage : null,
      domain: (location && location.domain) || (abuse && abuse.domain) || null,
      last_reported: abuse ? abuse.last_reported : null,
      summary: parts.length ? `${ip}: ${parts.join('; ')}.` : `${ip}: not listed or reported in ${ok.length} sources.`,
      sources_ok: ok, sources_failed: failed, checked_at: new Date().toISOString()
    };
    if (ok.length) {
      if (this.cache.size >= IP_CACHE_MAX) this.cache.delete(this.cache.keys().next().value);
      // Feeds still downloading: keep the answer for a minute, not six hours.
      this.cache.set(ip, { at: feed && feed.pending.length ? Date.now() - IP_TTL + 60000 : Date.now(), data });
    }
    return data;
  }
}

module.exports = { ThreatIntel, parseNetset, parseSpamhaus, cidrRange, ipv4ToInt };