'use strict';

// AbuseIPDB v2 `check` lookup. Optional: without ABUSEIPDB_API_KEY the
// investigation simply skips the reputation step.
const URL_CHECK = 'https://api.abuseipdb.com/api/v2/check';
const TTL_MS = 6 * 60 * 60 * 1000;

class Reputation {
  constructor({ apiKey, fetchImpl = globalThis.fetch } = {}) {
    this.apiKey = apiKey || null;
    this.fetch = fetchImpl;
    this.cache = new Map();
  }

  get available() { return Boolean(this.apiKey); }

  async check(ip) {
    if (!this.apiKey) return { skipped: true, reason: 'ABUSEIPDB_API_KEY not set' };
    const hit = this.cache.get(ip);
    if (hit && hit.at > Date.now() - TTL_MS) return { ...hit.data, cached: true };
    const res = await this.fetch(`${URL_CHECK}?${new URLSearchParams({ ipAddress: ip, maxAgeInDays: '90' })}`, {
      headers: { Key: this.apiKey, Accept: 'application/json' },
      signal: AbortSignal.timeout(8000)
    });
    if (!res.ok) throw new Error(`AbuseIPDB returned HTTP ${res.status}`);
    const d = (await res.json()).data || {};
    const data = {
      source: 'AbuseIPDB', ip: d.ipAddress || ip, score: d.abuseConfidenceScore ?? null, reports: d.totalReports ?? 0,
      country: d.countryCode || null, isp: d.isp || null, usage: d.usageType || null, domain: d.domain || null,
      last_reported: d.lastReportedAt || null
    };
    this.cache.set(ip, { at: Date.now(), data });
    return data;
  }
}

module.exports = { Reputation };