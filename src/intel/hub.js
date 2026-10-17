'use strict';

// One place that knows every intel source. Given any indicator it runs the
// sources that apply in parallel and folds them into a single verdict. Each
// source is independent: one that fails or needs a key is reported as such and
// the others still count. Nothing here invents a value; a source that did not
// answer contributes nothing to the score.

const { classify, isIpType, isHashType } = require('./indicator');
const { AbuseCh } = require('./abusech');
const { Misp } = require('./misp');
const { Whois } = require('./whois');
const { VirusTotal, vtScore } = require('./virustotal');
const { errText } = require('./feeds');
const { isInternal } = require('../engine/analysis');

const offFlag = (v) => /^(0|off|false|no)$/i.test(String(v || ''));

class IntelHub {
  constructor({ reputation = null, abusech, misp, whois, vt, offline = false }) {
    this.reputation = reputation;
    this.abusech = abusech;
    this.misp = misp;
    this.whois = whois;
    this.vt = vt;
    this.offline = offline;
  }

  get available() { return !this.offline; }

  describe() {
    return {
      offline: this.offline,
      abusech: this.abusech.describe(),
      misp: this.misp.describe(),
      virustotal: this.vt.describe(),
      reputation_lists: this.reputation && this.reputation.describe ? this.reputation.describe().lists : []
    };
  }

  warm() { if (!this.offline) { this.abusech.warm(); this.misp.warm(); } }

  // Forces a fresh download of every feed. A feed that fails keeps its last good copy.
  async refresh() {
    if (this.offline) return { ok: [], failed: [] };
    const r = await Promise.allSettled([this.abusech.refresh(), this.misp.refresh()]);
    const failed = [];
    for (const f of [...this.abusech.describe().feeds, ...this.misp.describe().feeds]) if (f.error) failed.push({ source: f.name, error: f.error });
    return { ok: r.filter((x) => x.status === 'fulfilled').length, failed };
  }

  // Feed hits for an IP, used by ThreatIntel.check so every IP verdict in the
  // platform (alerts, investigations, bulk checks) sees abuse.ch and MISP too.
  async ipHits(ip, budgetMs = 5000) {
    const ind = classify(ip);
    if (!ind || this.offline) return { hits: [], ok: [], failed: [], pending: [] };
    const [a, m] = await Promise.all([this.abusech.lookup(ind, { budgetMs }), this.misp.lookup(ind, { budgetMs })]);
    return { hits: [...a.hits, ...m.hits], ok: [...a.ok, ...m.ok], failed: [...a.failed, ...m.failed], pending: [...a.pending, ...m.pending] };
  }

  async lookup(query, { budgetMs = 15000, vt = true } = {}) {
    const ind = classify(query);
    if (!ind) throw Object.assign(new Error('Not an IP, domain, URL, ASN, MD5, SHA1 or SHA256'), { status: 400 });
    const base = { query: String(query).trim(), indicator: ind, checked_at: new Date().toISOString() };
    if (isIpType(ind.type) && isInternal(ind.value)) return { ...base, verdict: 'internal', score: null, signals: [], hits: [], sources_ok: [], sources_failed: [], pending: [] };
    if (this.offline) return { ...base, verdict: 'unknown', score: null, skipped: true, reason: 'Threat intel disabled (AEGIS_INTEL=off)', signals: [], hits: [], sources_ok: [], sources_failed: [], pending: [] };

    const ok = []; const failed = []; const pending = [];
    const run = async (name, fn) => {
      try {
        const v = await fn();
        if (v && v.skipped) return v;
        if (v && v.error) { failed.push({ source: name, error: v.error }); return v; }
        ok.push(name);
        return v;
      } catch (err) { failed.push({ source: name, error: errText(err) }); return null; }
    };
    const merge = (r) => { if (!r) return []; ok.push(...r.ok); failed.push(...r.failed); pending.push(...r.pending); return r.hits; };
    const t = ind.type;
    const host = t === 'url' ? ind.host : t === 'domain' ? ind.value : null;
    const hostInd = host ? classify(host) : null;
    const hostIsIp = hostInd && isIpType(hostInd.type);

    const tasks = {
      rep: isIpType(t) && this.reputation ? run('Reputation', () => this.reputation.check(ind.value)) : null,
      abuse: !isIpType(t) && t !== 'asn' ? this.abusech.lookup(ind, { budgetMs }).then(merge) : null,
      misp: !isIpType(t) && t !== 'asn' && t !== 'ja3' ? this.misp.lookup(ind, { budgetMs }).then(merge) : null,
      vt: vt && this.vt.supports(t) ? run('VirusTotal', () => this.vt.lookup(ind)) : null,
      rdap: isIpType(t) || t === 'domain' || t === 'url' ? run('RDAP', () => this.whois.rdap(hostIsIp ? hostInd : t === 'url' ? hostInd : ind)) : null,
      bgp: isIpType(t) || t === 'asn' || hostIsIp ? run('RIPEstat', () => this.whois.bgp(hostIsIp ? hostInd : ind)) : null,
      pdns: isIpType(t) || t === 'domain' || t === 'url' ? run('Mnemonic PDNS', () => this.whois.pdns(t === 'url' ? hostInd : ind)) : null,
      certs: (t === 'domain' || (t === 'url' && !hostIsIp)) ? run('crt.sh', () => this.whois.certs(t === 'url' ? hostInd : ind)) : null
    };
    const keys = Object.keys(tasks);
    const vals = await Promise.all(keys.map((k) => tasks[k]));
    const r = Object.fromEntries(keys.map((k, i) => [k, vals[i]]));

    let hits = [...(r.abuse || []), ...(r.misp || [])];
    const rep = r.rep && !r.rep.skipped ? r.rep : null;
    if (rep) {
      hits = [...(rep.iocs || [])];
      ok.push(...(rep.sources_ok || []).filter((s) => !ok.includes(s)));
      failed.push(...(rep.sources_failed || []));
      ok.splice(ok.indexOf('Reputation'), 1);
    }

    // ---- Score: the strongest real signal wins -----------------------------------
    const signals = [];
    for (const h of hits) signals.push({ source: h.source, score: h.score ?? null, text: `${h.kind}${h.malware ? ` (${h.malware})` : ''}${h.match && h.match !== 'exact' ? `, ${h.match}` : ''}` });
    if (rep) {
      for (const l of rep.listed || []) if (!hits.some((h) => h.source === l.list)) signals.push({ source: l.list, score: l.score ?? null, text: `listed (${l.detail})` });
      if (rep.greynoise && rep.greynoise.classification === 'malicious') signals.push({ source: 'GreyNoise', score: 90, text: 'classified malicious' });
      if (rep.abuseipdb && rep.abuseipdb.score != null) signals.push({ source: 'AbuseIPDB', score: rep.abuseipdb.score, text: `${rep.abuseipdb.score}/100 from ${rep.abuseipdb.reports} reports` });
    }
    const vtv = r.vt && r.vt.found ? r.vt : null;
    const vs = vtScore(vtv);
    if (vtv && vs) signals.push({ source: 'VirusTotal', score: vs, text: `${vtv.malicious} of ${vtv.total} engines flag it` });
    const reg = r.rdap && r.rdap.kind === 'domain' ? r.rdap : null;
    if (reg && reg.fresh) signals.push({ source: 'RDAP', score: 45, text: `domain registered ${reg.age_days} days ago` });
    else if (reg && reg.young) signals.push({ source: 'RDAP', score: 20, text: `domain is ${reg.age_days} days old` });

    const scored = signals.filter((s) => s.score != null);
    const answered = ok.length > 0;
    let score = scored.length ? Math.max(...scored.map((s) => s.score)) : answered ? 0 : null;
    if (rep && rep.score != null) score = Math.max(score ?? 0, rep.score);
    // Several independent sources agreeing is stronger than any one of them.
    const strong = new Set(scored.filter((s) => s.score >= 60).map((s) => s.source));
    if (score != null && strong.size >= 3) score = Math.min(100, score + 5);
    const benign = Boolean((vtv && vtv.malicious === 0 && vtv.harmless > 10) || (rep && rep.verdict === 'benign'));
    const verdict = score == null ? 'unknown' : score >= 75 ? 'malicious' : score >= 40 ? 'suspicious' : benign ? 'benign' : 'clean';

    const c2 = hits.find((h) => h.c2);
    const families = [...new Set(hits.filter((h) => h.score != null).map((h) => h.malware).filter(Boolean))].slice(0, 4);
    const parts = [];
    if (c2) parts.push(`known ${c2.malware ? `${c2.malware} ` : ''}C2 (${c2.source})`);
    else if (hits.some((h) => h.score != null)) parts.push(`listed by ${[...new Set(hits.filter((h) => h.score != null).map((h) => h.source))].join(', ')}`);
    else if (hits.length) parts.push(`mentioned in ${hits.length} MISP event${hits.length === 1 ? '' : 's'} as context, not as an IOC`);
    if (families.length && !c2) parts.push(`linked to ${families.join(', ')}`);
    if (vtv) parts.push(`VirusTotal ${vtv.malicious}/${vtv.total}`);
    if (reg && reg.young) parts.push(`registered ${reg.age_days} days ago${reg.registrar ? ` via ${reg.registrar.replace(/\.$/, '')}` : ''}`);
    if (rep && rep.summary && !hits.length) parts.push(rep.summary.replace(/^[^:]+:\s*/, '').replace(/\.$/, ''));
    const summary = parts.length ? `${ind.display}: ${parts.join('; ')}.` : `${ind.display}: no listing in ${ok.length} sources.`;

    return {
      ...base, verdict, score, summary, c2: Boolean(c2), families, signals: signals.sort((a, b) => (b.score ?? -1) - (a.score ?? -1)), hits,
      reputation: rep ? { verdict: rep.verdict, score: rep.score, listed: rep.listed, greynoise: rep.greynoise, shodan: rep.shodan, geo: rep.geo, abuseipdb: rep.abuseipdb, cached: rep.cached || false } : null,
      virustotal: r.vt || null, whois: r.rdap || null, bgp: r.bgp || null, pdns: r.pdns || null, certs: r.certs || null,
      sources_ok: [...new Set(ok)], sources_failed: failed, pending: [...new Set(pending)]
    };
  }
}

function createHub({ env = process.env, reputation = null, fetchImpl = globalThis.fetch, offline } = {}) {
  const off = offline != null ? offline : offFlag(env.AEGIS_INTEL);
  const hub = new IntelHub({
    reputation,
    offline: off,
    abusech: new AbuseCh({ fetchImpl, offline: off, authKey: env.ABUSECH_AUTH_KEY }),
    misp: new Misp({ fetchImpl, offline: off, url: env.MISP_URL, key: env.MISP_KEY }),
    whois: new Whois({ fetchImpl, offline: off }),
    vt: new VirusTotal({ apiKey: env.VT_API_KEY, fetchImpl, offline: off })
  });
  if (reputation && typeof reputation.attachFeeds === 'function') reputation.attachFeeds(hub);
  return hub;
}

module.exports = { IntelHub, createHub };
