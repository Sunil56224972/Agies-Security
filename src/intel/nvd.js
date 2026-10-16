'use strict';

// NVD CVE API 2.0 client. Docs: https://nvd.nist.gov/developers/vulnerabilities
// Without an API key NVD allows 5 requests per 30 s; with one, 50 per 30 s.
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function pickMetric(metrics = {}) {
  for (const key of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
    const list = metrics[key];
    if (!list || !list.length) continue;
    const m = list.find((x) => x.type === 'Primary') || list[0];
    const d = m.cvssData || {};
    return {
      version: d.version || key.replace('cvssMetricV', '').replace(/(\d)(\d)/, '$1.$2'),
      score: Number(d.baseScore),
      severity: String(d.baseSeverity || m.baseSeverity || '').toUpperCase(),
      vector: d.vectorString || null,
      attackVector: d.attackVector || d.accessVector || null,
      attackComplexity: d.attackComplexity || d.accessComplexity || null
    };
  }
  return null;
}

function rangeText(m) {
  const v = String(m.criteria || '').split(':')[5];
  if (v && v !== '*' && v !== '-') return v;
  const lo = m.versionStartIncluding ? `${m.versionStartIncluding} <= ` : m.versionStartExcluding ? `${m.versionStartExcluding} < ` : '';
  const hi = m.versionEndExcluding ? ` < ${m.versionEndExcluding}` : m.versionEndIncluding ? ` <= ${m.versionEndIncluding}` : '';
  return lo || hi ? `${lo}v${hi}` : 'all versions';
}

// Converts one `vulnerabilities[].cve` object into a row for the cves table.
function normalizeNvd(cve) {
  const desc = (cve.descriptions || []).find((d) => d.lang === 'en');
  const metric = pickMetric(cve.metrics);
  const cpes = [];
  for (const conf of cve.configurations || []) {
    for (const node of conf.nodes || []) {
      if (node.negate) continue;
      for (const m of node.cpeMatch || []) {
        if (!m.vulnerable) continue;
        const { vulnerable, criteria, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding } = m;
        cpes.push(Object.fromEntries(Object.entries({ vulnerable, criteria, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding }).filter(([, v]) => v !== undefined)));
      }
    }
  }
  const products = [...new Set(cpes.map((m) => { const p = m.criteria.split(':'); return `${p[3]} ${p[4]}`.replace(/_/g, ' '); }))];
  const advisory = (cve.references || []).find((r) => (r.tags || []).some((t) => /patch|vendor advisory|mitigation/i.test(t)));
  const text = desc ? desc.value : 'No description published.';
  const score = metric && Number.isFinite(metric.score) ? metric.score : 0;
  const severity = metric && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(metric.severity) ? metric.severity
    : score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW';
  return {
    cve_id: cve.id,
    title: cve.cisaVulnerabilityName || text.split(/(?<=\.)\s/)[0].slice(0, 140),
    cvss_score: score,
    severity,
    cvss_vector: metric ? metric.vector : null,
    affected_products: products.slice(0, 12),
    vulnerable_versions: [...new Set(cpes.map(rangeText))].slice(0, 6).join(', ') || null,
    exploit_vector: metric ? [metric.attackVector, metric.attackComplexity && `${metric.attackComplexity} complexity`].filter(Boolean).join(' / ') : null,
    description: text,
    remediation: cve.cisaRequiredAction || (advisory ? `See vendor advisory: ${advisory.url}` : 'Apply the vendor fix referenced in the NVD record.'),
    cpe_matches: cpes,
    match_terms: [],
    kev: Boolean(cve.cisaExploitAdd),
    kev_added: cve.cisaExploitAdd || null,
    published: cve.published ? new Date(cve.published + (/[zZ]|[+-]\d\d:?\d\d$/.test(cve.published) ? '' : 'Z')).toISOString() : null,
    last_modified: cve.lastModified ? new Date(cve.lastModified + (/[zZ]|[+-]\d\d:?\d\d$/.test(cve.lastModified) ? '' : 'Z')).toISOString() : null,
    source: 'NVD',
    synced_at: new Date().toISOString()
  };
}

class NvdClient {
  constructor({ apiKey, fetchImpl = globalThis.fetch, timeoutMs = 15000 } = {}) {
    this.apiKey = apiKey || null;
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.gap = apiKey ? 700 : 6500;
    this.last = 0;
  }

  async request(params) {
    const wait = this.last + this.gap - Date.now();
    if (wait > 0) await sleep(wait);
    this.last = Date.now();
    const url = `${NVD_URL}?${new URLSearchParams(params)}`;
    const res = await this.fetch(url, {
      headers: { Accept: 'application/json', ...(this.apiKey ? { apiKey: this.apiKey } : {}) },
      signal: AbortSignal.timeout(this.timeoutMs)
    });
    if (res.status === 403 || res.status === 429) throw new Error(`NVD rate limit hit (HTTP ${res.status}). Set NVD_API_KEY for a higher quota.`);
    if (!res.ok) throw new Error(`NVD returned HTTP ${res.status}`);
    return res.json();
  }

  async fetchCve(id) {
    if (!CVE_RE.test(id)) throw new Error(`${id} is not a CVE id`);
    const body = await this.request({ cveId: id.toUpperCase() });
    const hit = (body.vulnerabilities || [])[0];
    if (!hit) return null;
    return normalizeNvd(hit.cve);
  }
}

module.exports = { NvdClient, normalizeNvd, CVE_RE };