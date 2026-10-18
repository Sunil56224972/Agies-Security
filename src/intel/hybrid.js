'use strict';

// Hybrid Analysis (CrowdStrike Falcon Sandbox) hash search. Needs
// HYBRID_ANALYSIS_API_KEY (free account). Returns the sandbox verdict and
// threat score of the public reports for a file hash.

const { httpGet, errText, TtlCache } = require('./feeds');

const HASHES = ['md5', 'sha1', 'sha256'];

class HybridAnalysis {
  constructor({ apiKey = null, fetchImpl = globalThis.fetch, offline = false } = {}) {
    this.key = apiKey || null;
    this.fetch = fetchImpl;
    this.offline = offline;
    this.cache = new TtlCache(1000, 12 * 3600000);
  }

  get available() { return Boolean(this.key) && !this.offline; }
  supports(type) { return HASHES.includes(type); }
  describe() { return { configured: Boolean(this.key) }; }

  async lookup(ind) {
    if (!this.key) return { skipped: true, reason: 'Add HYBRID_ANALYSIS_API_KEY (free at hybrid-analysis.com) for sandbox verdicts' };
    if (this.offline) return { skipped: true, reason: 'Threat intel disabled (AEGIS_INTEL=off)' };
    if (!this.supports(ind.type)) return { skipped: true, reason: 'Hybrid Analysis searches file hashes only' };
    const have = this.cache.get(ind.value);
    if (have) return { ...have, cached: true };
    const headers = { 'api-key': this.key, 'User-Agent': 'Falcon Sandbox', Accept: 'application/json' };
    try {
      let res = await httpGet(this.fetch, `https://www.hybrid-analysis.com/api/v2/search/hash?hash=${encodeURIComponent(ind.value)}`, { timeoutMs: 15000, headers });
      // Older API versions only take the form POST variant of the same search.
      if (res.status === 404 || res.status === 405) {
        res = await httpGet(this.fetch, 'https://www.hybrid-analysis.com/api/v2/search/hash', { method: 'POST', body: `hash=${encodeURIComponent(ind.value)}`, timeoutMs: 15000, headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' } });
      }
      if (res.status === 401 || res.status === 403) throw new Error('HYBRID_ANALYSIS_API_KEY was rejected');
      if (res.status === 429) return { error: 'Hybrid Analysis quota reached', rate_limited: true };
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      const list = Array.isArray(body) ? body : Array.isArray(body.reports) ? body.reports : Array.isArray(body.result) ? body.result : [];
      const reports = list.slice(0, 6).map((r) => ({
        verdict: r.verdict || null, threat_score: r.threat_score ?? null, family: r.vx_family || null, environment: r.environment_description || null,
        type: r.type_short ? [].concat(r.type_short).join(', ') : r.type || null, submitted: r.analysis_start_time || r.submit_time || null, name: r.submit_name || null
      }));
      const rank = { malicious: 3, suspicious: 2 };
      const worst = reports.reduce((m, r) => ((rank[r.verdict] || 0) > (rank[m] || 0) ? r.verdict : m || r.verdict), null);
      const out = {
        found: reports.length > 0 || Boolean(body.verdict), reports, verdict: body.verdict || worst,
        threat_score: body.threat_score ?? (reports.reduce((m, r) => Math.max(m, Number(r.threat_score) || 0), 0) || null),
        families: [...new Set(reports.map((r) => r.family).filter(Boolean))].slice(0, 4),
        link: `https://www.hybrid-analysis.com/search?query=${encodeURIComponent(ind.value)}`
      };
      return this.cache.set(ind.value, out);
    } catch (err) { return { error: errText(err) }; }
  }
}

function haScore(h) {
  if (!h || !h.found) return null;
  if (h.verdict === 'malicious') return Math.max(80, Math.min(100, Number(h.threat_score) || 80));
  if (h.verdict === 'suspicious') return 50;
  if (['no specific threat', 'whitelisted', 'no verdict'].includes(h.verdict)) return 0;
  return null;
}

module.exports = { HybridAnalysis, haScore };