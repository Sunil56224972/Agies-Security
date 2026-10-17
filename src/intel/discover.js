'use strict';

// Finds CVEs for the software a host actually runs. Each versioned package or
// service is mapped to its NVD CPE product and looked up with the CVE API's
// virtualMatchString, which returns every CVE whose configuration covers that
// exact version. Results are real NVD records; nothing is inferred locally.
//
// Caveat shown to the analyst: distributions backport fixes without changing the
// upstream version (Ubuntu's openssh 8.9p1-3ubuntu0.10 is patched for CVEs that
// NVD lists against 8.9p1), so a match means "upstream version is affected".
const { extractSoftware } = require('../engine/analysis');
const { normalizeNvd } = require('./nvd');

// Package or service name (normalised) -> NVD vendor:product.
const CPE = [
  [/^(apache ?)?(httpd|apache2|http_?server)$/, 'apache:http_server'],
  [/^(apache ?)?tomcat\d*$/, 'apache:tomcat'],
  [/^(with )?log4j(-core|2)?$/, 'apache:log4j'],
  [/^(openssh(-server|-client)?|sshd|ssh)$/, 'openbsd:openssh'],
  [/^(nginx(-core|-full|-light)?)$/, '*:nginx'],
  [/^(openssl|libssl\d*(\.\d+)*)$/, 'openssl:openssl'],
  [/^php(\d+(\.\d+)?)?(-fpm|-cli|-common)?$/, 'php:php'],
  [/^(mysql(-server|-community-server)?(-\d+(\.\d+)?)?|mysqld)$/, 'oracle:mysql'],
  [/^(mariadb(-server)?)$/, 'mariadb:mariadb'],
  [/^(postgresql(-\d+)?|postgres)$/, 'postgresql:postgresql'],
  [/^(redis(-server)?)$/, 'redis:redis'],
  [/^(nodejs|node)$/, 'nodejs:node.js'],
  [/^sudo$/, 'sudo_project:sudo'],
  [/^(curl|libcurl\d*)$/, 'haxx:curl'],
  [/^(xz-utils|xz|liblzma\d*)$/, 'tukaani:xz'],
  [/^bash$/, 'gnu:bash'],
  [/^(glibc|libc6|libc-bin)$/, 'gnu:glibc'],
  [/^(exim4?(-daemon-\w+)?)$/, 'exim:exim'],
  [/^samba$/, 'samba:samba'],
  [/^bind9?$/, 'isc:bind'],
  [/^vsftpd$/, 'beasts:vsftpd'],
  [/^proftpd(-basic)?$/, 'proftpd:proftpd'],
  [/^haproxy$/, 'haproxy:haproxy'],
  [/^squid\d*$/, 'squid-cache:squid'],
  [/^jenkins$/, 'jenkins:jenkins'],
  [/^grafana$/, 'grafana:grafana'],
  [/^elasticsearch$/, 'elastic:elasticsearch'],
  [/^(polkit|policykit-1)$/, 'polkit_project:polkit'],
  [/^(git)$/, 'git-scm:git'],
  [/^(vim)$/, 'vim:vim']
];

function cpeFor(sw) {
  const names = [sw.name, sw.last].map((n) => String(n).toLowerCase().trim());
  for (const [re, cpe] of CPE) if (names.some((n) => re.test(n))) return cpe;
  return null;
}

// NVD files most OpenSSH ranges against "8.9" with no portable suffix, so the
// suffix is dropped; a "p1" query matches almost nothing.
function cpeVersion(cpe, version) {
  const v = String(version).toLowerCase();
  if (cpe === 'openbsd:openssh') {
    const m = v.match(/^(\d+\.\d+)(p\d+)?/);
    return m ? m[1] : v;
  }
  return v.replace(/[^0-9a-z._-]/g, '');
}

// Distinct (product, version) pairs found on a host, most security-relevant first.
function softwareOf(asset) {
  const strings = [...(asset.running_services || []).map((s) => s.service), ...(asset.installed_packages || [])].map(String);
  const seen = new Map();
  for (const s of strings) {
    for (const sw of extractSoftware(s)) {
      const cpe = cpeFor(sw);
      if (!cpe) continue;
      const key = `${cpe}:${sw.version}`;
      if (!seen.has(key)) seen.set(key, { cpe, version: sw.version, evidence: s, match: `cpe:2.3:a:${cpe}:${cpeVersion(cpe, sw.version)}` });
    }
  }
  return [...seen.values()];
}

// `nvd` is an NvdClient (rate limited internally). Returns per-product results and
// the CVE rows to store. Only CVSS >= minScore or KEV-listed records are kept.
async function discover(asset, nvd, { maxProducts = 6, perProduct = 40, minScore = 7, kev = null } = {}) {
  const sw = softwareOf(asset).slice(0, maxProducts);
  const products = [];
  const rows = new Map();
  for (const s of sw) {
    try {
      const body = await nvd.request({ virtualMatchString: s.match, resultsPerPage: '200' });
      const all = (body.vulnerabilities || []).map((v) => normalizeNvd(v.cve));
      for (const r of all) {
        const k = kev ? await kev.lookup(r.cve_id) : null;
        if (k) { r.kev = true; r.kev_added = r.kev_added || k.added; }
      }
      const kept = all.filter((r) => r.kev || r.cvss_score >= minScore).sort((a, b) => Number(b.kev) - Number(a.kev) || b.cvss_score - a.cvss_score).slice(0, perProduct);
      for (const r of kept) rows.set(r.cve_id, r);
      products.push({ product: s.cpe.split(':')[1].replace(/_/g, ' '), cpe: s.match, version: s.version, evidence: s.evidence, total: body.totalResults ?? all.length, kept: kept.length, kev: kept.filter((r) => r.kev).length, top: kept.slice(0, 5).map((r) => ({ cve_id: r.cve_id, cvss_score: r.cvss_score, severity: r.severity, kev: r.kev })) });
    } catch (err) {
      products.push({ product: s.cpe.split(':')[1].replace(/_/g, ' '), cpe: s.match, version: s.version, evidence: s.evidence, error: err.message });
      if (/rate limit|fetch failed|ENOTFOUND|timeout/i.test(err.message)) break;
    }
  }
  return { products, rows: [...rows.values()], skipped: Math.max(0, softwareOf(asset).length - sw.length) };
}

module.exports = { discover, softwareOf, cpeFor, cpeVersion, CPE };