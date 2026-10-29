'use strict';

// AlienVault OTX (LevelBlue Open Threat Exchange). The indicator endpoints answer
// without a key; OTX_API_KEY raises the rate limit. A pulse is a community
// report that lists the indicator, so the count is context, not a verdict on
// its own: OTX also lists resolvers and CDNs in pulses and marks them in the
// validation list (whitelisted, false positive), which is honoured here.

const { httpGet, errText, TtlCache } = require('./feeds');
const { reservedRange } = require('./shared');

const SECTION = { ipv4: 'IPv4', ipv6: 'IPv6', domain: 'domain', url: 'url', md5: 'file', sha1: 'file', sha256: 'file' };

class Otx {
  constructor({ apiKey = null, fetchImpl = globalThis.fetch, offline = false } = {}) {
    this.key = apiKey || null;
    this.fetch = fetchImpl;
    this.offline = offline;
    this.cache = new TtlCache(2000, 6 * 3600000);
  }

  get available() { return !this.offline; }
  supports(type) { return Boolean(SECTION[type]); }
  describe() { return { enabled: !this.offline, keyed: Boolean(this.key) }; }
  setKey(key) { const k = key ? String(key).trim() : null; if (k === this.key) return false; this.key = k; return true; }

  async lookup(ind) {
    if (this.offline) return { skipped: true, reason: 'Threat intel disabled (AEGIS_INTEL=off)' };
    const section = SECTION[ind.type];
    if (!section) return { skipped: true, reason: `OTX does not cover ${ind.type}` };
    const key = `${section}/${ind.value}`;
    const have = this.cache.get(key);
    if (have) return { ...have, cached: true };
    // A subdomain is a "hostname" in OTX, the registered name a "domain".
    const kind = ind.type === 'domain' && ind.value.split('.').length > 2 ? 'hostname' : section;
    const url = `https://otx.alienvault.com/api/v1/indicators/${kind}/${ind.type === 'url' ? ind.value : encodeURIComponent(ind.value)}/general`;
    try {
      const res = await httpGet(this.fetch, url, { timeoutMs: 12000, headers: { Accept: 'application/json', ...(this.key ? { 'X-OTX-API-KEY': this.key } : {}) } });
      if (res.status === 404 || res.status === 400) return this.cache.set(key, { found: false, pulses: 0, recent: [], validation: [], families: [], adversaries: [], link: this.link(ind) });
      if (res.status === 429) return { error: 'OTX rate limit reached; OTX_API_KEY raises it', rate_limited: true };
      if (res.status === 403 && this.key) throw new Error('OTX_API_KEY was rejected');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const d = await res.json();
      const p = d.pulse_info || {};
      const pulses = (p.pulses || []).slice(0, 8).map((x) => ({
        id: x.id, name: String(x.name || '').slice(0, 160), author: x.author_name || (x.author && x.author.username) || null,
        created: x.created || null, modified: x.modified || null, tlp: x.TLP || x.tlp || null,
        tags: (x.tags || []).slice(0, 6).map(String),
        families: (x.malware_families || []).map((f) => (typeof f === 'string' ? f : f && f.display_name)).filter(Boolean).slice(0, 4),
        adversary: x.adversary || null
      }));
      const validation = (d.validation || []).map((v) => ({ source: v.source || null, name: v.name || v.message || v.source || '' }));
      const resv = (ind.type === 'ipv4' || ind.type === 'ipv6') ? reservedRange(ind.value) : null;
      if (resv && !validation.length) validation.push({ source: 'iana', name: resv });
      const whitelisted = Boolean(resv) || (validation.length > 0 && validation.every((v) => !/blacklist|malicious/i.test(`${v.source} ${v.name}`)));
      const out = {
        found: true, pulses: Number(p.count) || 0, recent: pulses, validation,
        whitelisted,
        families: whitelisted ? [] : [...new Set(pulses.flatMap((x) => x.families))].slice(0, 5),
        adversaries: whitelisted ? [] : [...new Set(pulses.map((x) => x.adversary).filter(Boolean))].slice(0, 3),
        reputation: d.reputation ?? null, country: d.country_name || null, asn: d.asn || null,
        link: this.link(ind)
      };
      return this.cache.set(key, out);
    } catch (err) { return { error: errText(err) }; }
  }

  link(ind) {
    const kind = { ipv4: 'ip', ipv6: 'ip', domain: 'domain', url: 'url', md5: 'file', sha1: 'file', sha256: 'file' }[ind.type];
    return `https://otx.alienvault.com/indicator/${kind}/${encodeURIComponent(ind.value)}`;
  }
}

// Pulses on Aegis' 0-100 scale. Pulses are community reports that list every
// indicator seen in an incident, including resolvers, CDNs and victim sites, so
// the count alone never makes something suspicious. Only pulses that name a
// malware family push it over the line; whitelisted indicators score nothing.
function otxScore(o) {
  if (!o || !o.found || o.whitelisted || !o.pulses) return null;
  const fam = (o.families || []).length > 0;
  if (o.pulses >= 10) return fam ? 50 : 30;
  if (o.pulses >= 3) return fam ? 42 : 20;
  return fam ? 25 : 10;
}

module.exports = { Otx, otxScore };