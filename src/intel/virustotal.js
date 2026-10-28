'use strict';

// VirusTotal v3 for IPs, domains, URLs and file hashes. Needs VT_API_KEY; the
// free community key allows 4 lookups a minute and 500 a day, so results are
// cached for 12 hours and calls are spaced out here rather than rejected by VT.

const { httpGet, errText, TtlCache } = require('./feeds');

const PATH = { ipv4: 'ip_addresses', ipv6: 'ip_addresses', domain: 'domains', url: 'urls', md5: 'files', sha1: 'files', sha256: 'files' };
const b64url = (s) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

class VirusTotal {
  constructor({ apiKey = null, fetchImpl = globalThis.fetch, offline = false, perMinute = 4 } = {}) {
    this.key = apiKey || null;
    this.fetch = fetchImpl;
    this.offline = offline;
    this.cache = new TtlCache(2000, 12 * 3600000);
    this.perMinute = perMinute;
    this.calls = [];
    this.used = { day: new Date().toISOString().slice(0, 10), n: 0 };
  }

  get available() { return Boolean(this.key) && !this.offline; }
  supports(type) { return Boolean(PATH[type]); }
  describe() { return { configured: Boolean(this.key), used_today: this.used.day === new Date().toISOString().slice(0, 10) ? this.used.n : 0, per_minute: this.perMinute }; }

  // Swaps the key at runtime (Settings). Answers cached under the old key are kept
  // only if they came from VirusTotal itself, which they did, so the cache stays.
  setKey(key) {
    const k = key ? String(key).trim() : null;
    if (k === this.key) return false;
    this.key = k;
    this.calls = [];
    return true;
  }

  // Waits for a free slot in the per-minute window, at most maxWaitMs.
  async slot(maxWaitMs) {
    const now = Date.now();
    this.calls = this.calls.filter((t) => now - t < 60000);
    if (this.calls.length < this.perMinute) { this.calls.push(now); return true; }
    const wait = 60000 - (now - this.calls[0]) + 50;
    if (wait > maxWaitMs) return false;
    await new Promise((r) => setTimeout(r, wait));
    return this.slot(0);
  }

  async lookup(ind, { maxWaitMs = 8000 } = {}) {
    if (!this.key) return { skipped: true, reason: 'Not connected: add a VirusTotal API key under Settings, Threat intel keys (or VT_API_KEY) for 70+ engine verdicts' };
    if (this.offline) return { skipped: true, reason: 'Threat intel disabled (AEGIS_INTEL=off)' };
    const path = PATH[ind.type];
    if (!path) return { skipped: true, reason: `VirusTotal does not cover ${ind.type}` };
    const id = ind.type === 'url' ? b64url(ind.value) : ind.value;
    const key = `${path}/${id}`;
    const have = this.cache.get(key);
    if (have) return { ...have, cached: true };
    if (!(await this.slot(maxWaitMs))) return { error: `VirusTotal limit of ${this.perMinute} lookups a minute reached, try again shortly (raise VT_RATE_PER_MIN on a premium key)`, rate_limited: true };
    const today = new Date().toISOString().slice(0, 10);
    if (this.used.day !== today) this.used = { day: today, n: 0 };
    this.used.n += 1;
    try {
      const res = await httpGet(this.fetch, `https://www.virustotal.com/api/v3/${path}/${encodeURIComponent(id)}`, { timeoutMs: 12000, headers: { 'x-apikey': this.key, Accept: 'application/json' } });
      if (res.status === 404) return this.cache.set(key, { found: false, link: this.link(ind) });
      if (res.status === 401 || res.status === 403) throw new Error('VT_API_KEY was rejected');
      if (res.status === 429) return { error: 'VirusTotal quota exhausted for now', rate_limited: true };
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const a = ((await res.json()).data || {}).attributes || {};
      const st = a.last_analysis_stats || {};
      const engines = Object.values(a.last_analysis_results || {}).filter((r) => r.category === 'malicious' || r.category === 'suspicious').slice(0, 12).map((r) => ({ engine: r.engine_name, result: r.result || r.category }));
      const total = ['malicious', 'suspicious', 'harmless', 'undetected', 'timeout'].reduce((n, k) => n + (st[k] || 0), 0);
      const out = {
        found: true, malicious: st.malicious || 0, suspicious: st.suspicious || 0, harmless: st.harmless || 0, undetected: st.undetected || 0, total,
        reputation: a.reputation ?? null, engines,
        last_analysis: a.last_analysis_date ? new Date(a.last_analysis_date * 1000).toISOString() : null,
        names: a.meaningful_name ? [a.meaningful_name] : (a.names || []).slice(0, 3),
        type: a.type_description || null, label: a.popular_threat_classification ? a.popular_threat_classification.suggested_threat_label : null,
        tags: (a.tags || []).slice(0, 8), asn: a.asn ? `AS${a.asn}` : null, as_owner: a.as_owner || null, country: a.country || null,
        categories: a.categories ? [...new Set(Object.values(a.categories))].slice(0, 4) : [],
        link: this.link(ind)
      };
      return this.cache.set(key, out);
    } catch (err) { return { error: errText(err) }; }
  }

  link(ind) {
    const kind = { ipv4: 'ip-address', ipv6: 'ip-address', domain: 'domain', url: 'url', md5: 'file', sha1: 'file', sha256: 'file' }[ind.type];
    const id = ind.type === 'url' ? require('crypto').createHash('sha256').update(ind.value).digest('hex') : ind.value;
    return `https://www.virustotal.com/gui/${kind}/${id}`;
  }
}

// VirusTotal detections expressed on Aegis' 0-100 scale.
// One or two vendors out of ~90 flagging something is routine noise (heuristic
// engines, stale lists); a real detection is several independent engines.
function vtScore(v) {
  if (!v || !v.found) return null;
  const m = Number(v.malicious) || 0;
  const s = Number(v.suspicious) || 0;
  if (m >= 10) return Math.min(100, 85 + Math.floor((m - 10) / 2));
  if (m >= 5) return 75 + (m - 5) * 2;
  if (m >= 3) return 50 + (m - 3) * 5;
  if (m === 2 || (m === 1 && s >= 2)) return 25;
  if (m === 1 || s >= 2) return 10;
  return 0;
}

module.exports = { VirusTotal, vtScore, b64url };
