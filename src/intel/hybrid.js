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
  setKey(key) { const k = key ? String(key).trim() : null; if (k === this.key) return false; this.key = k; return true; }

  async lookup(ind) {
    if (!this.key) return { skipped: true, reason: 'Add HYBRID_ANALYSIS_API_KEY (free at hybrid-analysis.com) for sandbox verdicts' };
    if (this.offline) return { skipped: true, reason: 'Threat intel disabled (AEGIS_INTEL=off)' };
    if (!this.supports(ind.type)) return { skipped: true, reason: 'Hybrid Analysis searches file hashes only' };
    const have = this.cache.get(ind.value);
    if (have) return { ...have, cached: true };
    const headers = { 'api-key': this.key, 'User-Agent': 'Falcon Sandbox', Accept: 'application/json' };
    try {
      let res = await httpGet(this.fetch, `https://www.hybrid-analysis.com/api/v2/search/hash?hash=${encodeURIComponent(ind.value)}`, { timeoutMs: 15000, headers });
      // The current API answers 404 for a hash it has never seen.
      if (res.status === 404) {
        const none = { found: false, reports: [], verdict: null, threat_score: null, families: [], link: `https://www.hybrid-analysis.com/search?query=${encodeURIComponent(ind.value)}` };
        return this.cache.set(ind.value, none);
      }
      // Older API versions only take the form POST variant of the same search.
      if (res.status === 405) {
        res = await httpGet(this.fetch, 'https://www.hybrid-analysis.com/api/v2/search/hash', { method: 'POST', body: `hash=${encodeURIComponent(ind.value)}`, timeoutMs: 15000, headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' } });
      }
      if (res.status === 401 || res.status === 403) throw new Error('HYBRID_ANALYSIS_API_KEY was rejected');
      if (res.status === 429) return { error: 'Hybrid Analysis quota reached', rate_limited: true };
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      const list = Array.isArray(body) ? body : Array.isArray(body.reports) ? body.reports : Array.isArray(body.result) ? body.result : [];
      // Runs the sandbox could not execute (wrong file type, timeouts) carry no verdict.
      const done = list.filter((r) => !r.state || r.state === 'SUCCESS');
      const reports = done.slice(0, 6).map((r) => ({
        id: r.id || r.job_id || null, verdict: r.verdict || null, threat_score: r.threat_score ?? null, family: r.vx_family || null,
        environment: r.environment_description || null, submitted: r.analysis_start_time || r.submit_time || null, name: r.submit_name || null
      }));
      const rank = { malicious: 3, suspicious: 2, 'no specific threat': 1, whitelisted: 1 };
      const worst = done.reduce((m, r) => ((rank[r.verdict] || 0) > (rank[m] || 0) ? r.verdict : m), null);
      const sha256 = (Array.isArray(body.sha256s) && body.sha256s[0]) || (ind.type === 'sha256' ? ind.value.toLowerCase() : null);
      // The search endpoint returns verdicts only; the overview has the score, family and file details.
      const ov = sha256 && list.length ? await this.overview(sha256, headers) : null;
      const out = {
        found: list.length > 0 || Boolean(body.verdict) || Boolean(ov && ov.verdict),
        reports, runs: list.length, completed: done.length,
        malicious_runs: done.filter((r) => r.verdict === 'malicious').length,
        verdict: (ov && ov.verdict) || body.verdict || worst,
        threat_score: (ov && ov.threat_score) ?? body.threat_score ?? (reports.reduce((m, r) => Math.max(m, Number(r.threat_score) || 0), 0) || null),
        families: [...new Set([ov && ov.vx_family, ...reports.map((r) => r.family)].filter(Boolean))].slice(0, 4),
        file_type: (ov && ov.type) || null,
        file_name: (ov && (ov.last_file_name || ov.submit_name)) || null,
        size: (ov && ov.size) ?? null,
        tags: ov && Array.isArray(ov.tags) ? ov.tags.filter((t) => t && t !== 'tag').slice(0, 12) : [],
        last_seen: (ov && (ov.analysis_start_time || ov.last_multi_scan)) || null,
        sha256,
        link: sha256 ? `https://www.hybrid-analysis.com/sample/${sha256}` : `https://www.hybrid-analysis.com/search?query=${encodeURIComponent(ind.value)}`
      };
      return this.cache.set(ind.value, out);
    } catch (err) { return { error: errText(err) }; }
  }

  async overview(sha256, headers) {
    try {
      const res = await httpGet(this.fetch, `https://www.hybrid-analysis.com/api/v2/overview/${encodeURIComponent(sha256)}`, { timeoutMs: 15000, headers });
      return res.ok ? await res.json() : null;
    } catch { return null; }
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