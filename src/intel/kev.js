'use strict';

// CISA Known Exploited Vulnerabilities catalog. Public JSON, no key. Cached for
// 12 hours; a failed refresh keeps serving the last good copy.
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const TTL = 12 * 3600000;
const RETRY = 10 * 60000;

class KevCatalog {
  constructor({ fetchImpl = globalThis.fetch, url = KEV_URL, offline = false } = {}) {
    this.fetch = fetchImpl;
    this.url = url;
    this.offline = offline;
    this.data = null;
    this.at = 0;
    this.error = null;
    this.loading = null;
  }

  status() {
    return {
      source: 'CISA KEV', url: this.url, loaded: Boolean(this.data), entries: this.data ? this.data.map.size : 0,
      catalog_version: this.data ? this.data.version : null, released: this.data ? this.data.released : null,
      fetched_at: this.at && this.data ? new Date(this.at).toISOString() : null, error: this.error
    };
  }

  async load(force = false) {
    if (this.offline) { this.error = 'Threat intel disabled (AEGIS_INTEL=off)'; return this.data; }
    if (!force && this.data && Date.now() - this.at < TTL) return this.data;
    if (!force && !this.data && this.error && Date.now() - this.at < RETRY) return null;
    if (this.loading) return this.loading;
    this.loading = (async () => {
      try {
        const res = await this.fetch(this.url, { headers: { Accept: 'application/json', 'User-Agent': 'aegis-security/4' }, signal: AbortSignal.timeout(20000) });
        if (!res.ok) throw new Error(`CISA returned HTTP ${res.status}`);
        const body = await res.json();
        const map = new Map();
        for (const v of body.vulnerabilities || []) {
          if (!v.cveID) continue;
          map.set(String(v.cveID).toUpperCase(), {
            cve_id: String(v.cveID).toUpperCase(), vendor: v.vendorProject || null, product: v.product || null, name: v.vulnerabilityName || null,
            added: v.dateAdded || null, due: v.dueDate || null, ransomware: /known/i.test(String(v.knownRansomwareCampaignUse || '')),
            action: v.requiredAction || null, description: v.shortDescription || null, cwes: v.cwes || []
          });
        }
        if (!map.size) throw new Error('catalog was empty');
        this.data = { map, version: body.catalogVersion || null, released: body.dateReleased || null };
        this.error = null;
      } catch (err) {
        this.error = err.name === 'TimeoutError' ? 'CISA feed timed out' : err.message;
      } finally {
        this.at = Date.now();
        this.loading = null;
      }
      return this.data;
    })();
    return this.loading;
  }

  async lookup(id) {
    const d = await this.load();
    return d ? d.map.get(String(id).toUpperCase()) || null : null;
  }

  // Newest additions first; the "what did CISA add this week" view.
  async recent(limit = 20) {
    const d = await this.load();
    if (!d) return [];
    return [...d.map.values()].sort((a, b) => String(b.added).localeCompare(String(a.added))).slice(0, limit);
  }
}

module.exports = { KevCatalog, KEV_URL };