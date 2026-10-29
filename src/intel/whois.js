'use strict';

// Who owns an indicator and what it has resolved to.
//
//   RDAP       registration data, found through the IANA bootstrap files, so a
//              .com goes to Verisign, an IP in Europe to RIPE, and so on
//   RIPEstat   BGP: announcing ASN, routed prefix, first seen in the table, visibility
//   Mnemonic   passive DNS, free and without a key
//   crt.sh     certificate transparency, for when a domain first got a cert

const net = require('net');
const { httpGet, errText, TtlCache } = require('./feeds');
const { registered } = require('./indicator');
const { reservedRange } = require('./shared');

const DAY = 86400000;
const v4int = (ip) => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0);

function inV4Prefix(ip, prefix) {
  const [base, bits] = prefix.split('/');
  if (!net.isIPv4(base)) return false;
  const size = 2 ** (32 - Number(bits));
  return Math.floor(v4int(ip) / size) === Math.floor(v4int(base) / size);
}

function v6ToBig(ip) {
  let [head, tail] = ip.split('::');
  const h = head ? head.split(':') : []; const t = tail !== undefined ? (tail ? tail.split(':') : []) : [];
  const parts = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  return parts.reduce((a, p) => (a << 16n) + BigInt(parseInt(p || '0', 16)), 0n);
}
function inV6Prefix(ip, prefix) {
  const [base, bitsRaw] = prefix.split('/');
  const shift = BigInt(128 - Number(bitsRaw));
  return (v6ToBig(ip) >> shift) === (v6ToBig(base) >> shift);
}

const vcardName = (e) => {
  const fn = ((e.vcardArray || [])[1] || []).find((x) => x[0] === 'fn');
  return fn ? fn[3] : e.handle || null;
};
const eventDate = (events, act) => { const e = (events || []).find((x) => x.eventAction === act); return e ? e.eventDate : null; };

function entitiesByRole(list, out = {}) {
  for (const e of list || []) {
    for (const r of e.roles || []) if (!out[r]) out[r] = vcardName(e);
    if (e.entities) entitiesByRole(e.entities, out);
  }
  return out;
}

const ageDays = (iso) => (iso ? Math.floor((Date.now() - new Date(iso).getTime()) / DAY) : null);

class Whois {
  constructor({ fetchImpl = globalThis.fetch, offline = false } = {}) {
    this.fetch = fetchImpl;
    this.offline = offline;
    this.boot = new Map();
    this.cache = new TtlCache(1500, 12 * 3600000);
  }

  get available() { return !this.offline; }

  async getJson(url, { accept = 'application/json', timeoutMs = 10000, notFound } = {}) {
    const res = await httpGet(this.fetch, url, { timeoutMs, headers: { Accept: accept } });
    if (res.status === 404 && notFound !== undefined) return notFound;
    if (res.status === 429) throw new Error('rate limited');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async bootstrap(kind) {
    const have = this.boot.get(kind);
    if (have && Date.now() - have.at < 7 * DAY) return have.services;
    const j = await this.getJson(`https://data.iana.org/rdap/${kind}.json`, { timeoutMs: 15000 });
    this.boot.set(kind, { at: Date.now(), services: j.services || [] });
    return j.services || [];
  }

  async rdapBase(kind, value) {
    const services = await this.bootstrap(kind);
    let best = null; let bestLen = -1;
    for (const [keys, urls] of services) {
      for (const k of keys) {
        let hit = false; let len = 0;
        if (kind === 'dns') { hit = value === k || value.endsWith(`.${k}`); len = k.length; }
        else if (kind === 'ipv4') { hit = inV4Prefix(value, k); len = Number(k.split('/')[1]); }
        else if (kind === 'ipv6') { hit = inV6Prefix(value, k); len = Number(k.split('/')[1]); }
        if (hit && len > bestLen) { best = urls.find((u) => u.startsWith('https')) || urls[0]; bestLen = len; }
      }
    }
    return best ? best.replace(/\/?$/, '/') : null;
  }

  // Registration record for an IP or a domain.
  async rdap(ind) {
    const key = `rdap:${ind.type}:${ind.value}`;
    const have = this.cache.get(key);
    if (have) return { ...have, cached: true };
    if (this.offline) return { skipped: true, reason: 'Threat intel disabled (AEGIS_INTEL=off)' };
    const isIp = ind.type === 'ipv4' || ind.type === 'ipv6';
    const value = isIp ? ind.value : registered(ind.host || ind.value);
    const base = await this.rdapBase(isIp ? ind.type : 'dns', value);
    if (!base) {
      const resv = isIp ? reservedRange(value) : null;
      if (resv) {
        return this.cache.set(key, {
          query: value, server: 'iana.org', found: true, kind: 'ip', handle: 'IANA-RESERVED', name: 'IANA-RESERVED', type: 'RESERVED',
          range: null, country: null, org: resv, abuse: null, registered: null, updated: null, remarks: [resv]
        });
      }
      throw new Error(`no RDAP server publishes ${isIp ? 'this range' : `.${value.split('.').pop()}`}`);
    }
    const url = `${base}${isIp ? 'ip' : 'domain'}/${encodeURIComponent(value)}`;
    const j = await this.getJson(url, { accept: 'application/rdap+json, application/json', notFound: null });
    if (!j) return this.cache.set(key, { query: value, server: new URL(base).host, found: false });
    const roles = entitiesByRole(j.entities);
    let out;
    if (isIp) {
      const cidr = (j.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`)[0] || (j.startAddress && j.endAddress ? `${j.startAddress} - ${j.endAddress}` : null);
      out = {
        query: value, server: new URL(base).host, found: true, kind: 'ip', handle: j.handle || null, name: j.name || null, type: j.type || null,
        range: cidr, country: j.country || null, org: roles.registrant || roles.administrative || null, abuse: roles.abuse || null,
        registered: eventDate(j.events, 'registration'), updated: eventDate(j.events, 'last changed'),
        remarks: (j.remarks || []).flatMap((r) => r.description || []).slice(0, 3)
      };
    } else {
      const reg = eventDate(j.events, 'registration');
      const age = ageDays(reg);
      out = {
        query: value, server: new URL(base).host, found: true, kind: 'domain', handle: j.handle || null, name: (j.ldhName || value).toLowerCase(),
        registrar: roles.registrar || null, registrant: roles.registrant || null, abuse: roles.abuse || null,
        registered: reg, expires: eventDate(j.events, 'expiration'), updated: eventDate(j.events, 'last changed'),
        age_days: age, fresh: age != null && age < 30, young: age != null && age < 180,
        status: j.status || [], nameservers: (j.nameservers || []).map((n) => String(n.ldhName || '').toLowerCase()).filter(Boolean).slice(0, 6)
      };
    }
    return this.cache.set(key, out);
  }

  // BGP view from RIPEstat for an IP address or an ASN.
  async bgp(ind) {
    const key = `bgp:${ind.value}`;
    const have = this.cache.get(key);
    if (have) return { ...have, cached: true };
    if (this.offline) return { skipped: true, reason: 'Threat intel disabled (AEGIS_INTEL=off)' };
    const r = (path) => this.getJson(`https://stat.ripe.net/data/${path}&sourceapp=aegis-security`, { timeoutMs: 12000 });
    if (ind.type === 'asn') {
      const [ov, pf] = await Promise.all([r(`as-overview/data.json?resource=${ind.value}`), r(`announced-prefixes/data.json?resource=${ind.value}`).catch(() => null)]);
      const d = ov.data || {};
      return this.cache.set(key, { query: ind.value, asn: ind.value, holder: d.holder || null, announced: Boolean(d.announced), prefixes: pf && pf.data ? (pf.data.prefixes || []).length : null, sample_prefixes: pf && pf.data ? (pf.data.prefixes || []).slice(0, 6).map((p) => p.prefix) : [] });
    }
    const [ov, rs] = await Promise.all([r(`prefix-overview/data.json?resource=${ind.value}`), r(`routing-status/data.json?resource=${ind.value}`).catch(() => null)]);
    const d = ov.data || {}; const s = (rs && rs.data) || {};
    const asns = (d.asns || []).map((a) => ({ asn: `AS${a.asn}`, holder: a.holder }));
    const vis = s.visibility && s.visibility.v4 ? s.visibility.v4 : s.visibility && s.visibility.v6 ? s.visibility.v6 : null;
    return this.cache.set(key, {
      query: ind.value, announced: Boolean(d.announced), prefix: d.resource || null, block: d.block ? d.block.name || d.block.resource : null,
      asns, first_seen: s.first_seen ? s.first_seen.time : null, last_seen: s.last_seen ? s.last_seen.time : null,
      visibility: vis && vis.total_ris_peers ? Math.round((vis.ris_peers_seeing / vis.total_ris_peers) * 100) : null
    });
  }

  // Passive DNS from Mnemonic: what a domain resolved to, or which names pointed at an IP.
  async pdns(ind, { limit = 40 } = {}) {
    const q = ind.type === 'url' ? ind.host : ind.value;
    const key = `pdns:${q}`;
    const have = this.cache.get(key);
    if (have) return { ...have, cached: true };
    if (this.offline) return { skipped: true, reason: 'Threat intel disabled (AEGIS_INTEL=off)' };
    const j = await this.getJson(`https://api.mnemonic.no/pdns/v3/${encodeURIComponent(q)}?limit=${limit}`, { timeoutMs: 12000 });
    if (j.responseCode && j.responseCode >= 400) throw new Error((j.messages && j.messages[0] && j.messages[0].message) || `HTTP ${j.responseCode}`);
    const ts = (n) => (n ? new Date(n).toISOString() : null);
    const rows = (j.data || []).map((r) => ({
      query: r.query, answer: r.answer, rrtype: String(r.rrtype || '').toUpperCase(), times: r.times || 0,
      first_seen: ts(r.firstSeenTimestamp) || ts(r.createdTimestamp), last_seen: ts(r.lastSeenTimestamp) || ts(r.lastUpdatedTimestamp)
    })).sort((a, b) => String(b.last_seen).localeCompare(String(a.last_seen)));
    const firsts = rows.map((r) => r.first_seen).filter(Boolean).sort();
    return this.cache.set(key, {
      query: q, total: j.count || rows.length, shown: rows.length, records: rows,
      first_seen: firsts[0] || null, distinct_answers: new Set(rows.map((r) => r.answer)).size
    });
  }

  // Certificate transparency: when the domain first got a certificate, and by whom.
  async certs(ind) {
    const domain = registered(ind.type === 'url' ? ind.host : ind.value);
    const key = `crt:${domain}`;
    const have = this.cache.get(key);
    if (have) return { ...have, cached: true };
    if (this.offline) return { skipped: true, reason: 'Threat intel disabled (AEGIS_INTEL=off)' };
    // crt.sh is free but often answers 502/503 under load: retry once, then ask
    // SSLMate Cert Spotter, which reads the same CT logs.
    let list = null; let source = 'crt.sh'; let lastErr = null;
    for (let attempt = 0; attempt < 2 && !list; attempt++) {
      try {
        const res = await httpGet(this.fetch, `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&exclude=expired`, { timeoutMs: 10000, headers: { Accept: 'application/json' } });
        if (res.ok) { list = JSON.parse((await res.text()) || '[]'); break; }
        lastErr = new Error(`crt.sh HTTP ${res.status}`);
        if (res.status < 500 && res.status !== 429) break;
      } catch (err) { lastErr = err; }
      if (attempt === 0) await new Promise((r) => setTimeout(r, 800));
    }
    if (!list) {
      try {
        const res = await httpGet(this.fetch, `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`, { timeoutMs: 10000, headers: { Accept: 'application/json' } });
        if (!res.ok) throw new Error(`Cert Spotter HTTP ${res.status}`);
        list = (await res.json()).map((c) => ({ not_before: c.not_before, name_value: (c.dns_names || []).join('\n'), issuer_name: c.issuer ? `O=${c.issuer.friendly_name || (String(c.issuer.name || '').match(/O=([^,]+)/) || [])[1] || 'unknown'}` : '' }));
        source = 'Cert Spotter';
      } catch (err) {
        throw new Error(`${errText(lastErr)}; fallback ${errText(err)}`);
      }
    }
    const issued = list.map((c) => c.not_before).filter(Boolean).sort();
    const names = new Set();
    for (const c of list) for (const n of String(c.name_value || '').split('\n')) if (n && names.size < 30) names.add(n.toLowerCase());
    const issuers = {};
    for (const c of list) { const m = String(c.issuer_name || '').match(/O=([^,]+)/); if (m) issuers[m[1]] = (issuers[m[1]] || 0) + 1; }
    return this.cache.set(key, { domain, source, certificates: list.length, first_issued: issued[0] || null, last_issued: issued[issued.length - 1] || null, names: [...names], issuers: Object.entries(issuers).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k]) => k) });
  }
}

module.exports = { Whois, inV4Prefix, inV6Prefix, entitiesByRole, errText };
