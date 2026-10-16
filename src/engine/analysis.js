'use strict';

const net = require('net');

const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

const isIP = (ip) => net.isIP(String(ip || '')) !== 0;
const isIPv4 = (ip) => net.isIPv4(String(ip || ''));

// RFC 1918, loopback, CGNAT, IPv6 unique-local and link-local.
function isInternal(ip) {
  const s = String(ip || '').toLowerCase();
  if (net.isIPv4(s)) return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(s);
  if (net.isIPv6(s)) return s === '::1' || /^f[cd][0-9a-f]{2}:/.test(s) || /^fe[89ab][0-9a-f]:/.test(s);
  return false;
}

// Payload heuristics. Order matters: the first match wins.
const TECHNIQUES = [
  { id: 'log4shell', label: 'JNDI lookup injection (Log4Shell)', test: /\$\{jndi:/i, cve: 'CVE-2021-44228',
    tactic: 'Initial Access', technique: 'T1190 Exploit Public-Facing Application', requiresExposure: true },
  { id: 'path_traversal', label: 'Encoded path traversal into CGI', test: /(\.%2e|%2e%2e|%%32%65|\.\.\/)/i, cve: 'CVE-2021-41773',
    tactic: 'Initial Access', technique: 'T1190 Exploit Public-Facing Application', requiresExposure: true },
  { id: 'sqli', label: 'SQL injection', test: /((%27|')\s*(\+|%20|\s)*or(\+|%20|\s)+\d+=\d+)|union(\+|%20|\s)+select/i, cve: 'CWE-89',
    tactic: 'Initial Access', technique: 'T1190 Exploit Public-Facing Application', requiresExposure: false },
  { id: 'ssh_bruteforce', label: 'SSH password spraying', test: /failed password|invalid user/i, cve: null,
    tactic: 'Credential Access', technique: 'T1110.003 Password Spraying', requiresExposure: false },
  { id: 'c2_beacon', label: 'Periodic beacon to external infrastructure', test: /beacon|interval=\d+s|ja3=/i, cve: null,
    tactic: 'Command and Control', technique: 'T1071.001 Application Layer Protocol: Web', requiresExposure: false }
];

function classifyPayload(payload) {
  const text = String(payload || '');
  const technique = TECHNIQUES.find(t => t.test.test(text)) || null;
  const indicators = [];
  const jndi = text.match(/\$\{jndi:[^}]+\}/gi);
  if (jndi) indicators.push(...new Set(jndi));
  const traversal = text.match(/\/(?:[.%2e]+\/)+[^\s]*/i);
  if (traversal && technique && technique.id === 'path_traversal') indicators.push(traversal[0]);
  const ua = text.match(/user-agent:\s*([^\r\n]+)/i);
  if (ua && !jndi) indicators.push(`UA ${ua[1]}`);
  const sni = text.match(/SNI=([^\s]+)/i);
  if (sni) indicators.push(`SNI ${sni[1]}`);
  const ja3 = text.match(/JA3=([a-f0-9]+)/i);
  if (ja3) indicators.push(`JA3 ${ja3[1]}`);
  const cves = text.match(/CVE-\d{4}-\d{4,7}/gi);
  if (cves) indicators.push(...new Set(cves.map(c => c.toUpperCase())));
  return { technique, indicators };
}

// ---- Software inventory matching ------------------------------------------

const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');

// CPE product names that do not look like the package or service name.
const PRODUCT_ALIASES = {
  http_server: ['httpd', 'apachehttpd', 'apachehttpserver', 'apache2'],
  log4j: ['log4j', 'log4jcore', 'log4j2'],
  openssh: ['openssh', 'opensshserver', 'sshd'],
  tomcat: ['tomcat', 'apachetomcat'],
  mysql: ['mysql', 'mysqlserver'],
  php: ['php', 'phpfpm'],
  nginx: ['nginx', 'nginxcore'],
  openssl: ['openssl', 'libssl']
};

// Pulls "name version" pairs out of free-form package and service strings,
// e.g. "log4j-core-2.14.1.jar", "Apache httpd 2.4.49 (PHP 7.4.3)".
function extractSoftware(text) {
  const out = [];
  const re = /([a-z][a-z0-9_+]*(?:[-.][a-z][a-z0-9_+]*)*(?:[ /][a-z][a-z0-9_+]*(?:[-.][a-z][a-z0-9_+]*)*)?)[\s/_-]+v?(\d+(?:\.\d+)+[a-z0-9]*)/gi;
  let m;
  while ((m = re.exec(String(text || '')))) {
    const name = m[1].toLowerCase();
    const words = name.split(/[ /]/);
    out.push({ name, last: words[words.length - 1], version: m[2] });
  }
  return out;
}

function compareVersions(a, b) {
  const pa = String(a).split(/[.\-_]/);
  const pb = String(b).split(/[.\-_]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || '0';
    const y = pb[i] || '0';
    const nx = parseInt(x, 10) || 0;
    const ny = parseInt(y, 10) || 0;
    if (nx !== ny) return nx < ny ? -1 : 1;
    const sx = x.replace(/^\d+/, '');
    const sy = y.replace(/^\d+/, '');
    if (sx !== sy) return sx < sy ? -1 : 1;
  }
  return 0;
}

function productMatches(softwareName, lastWord, product) {
  const names = PRODUCT_ALIASES[product] || [norm(product)];
  const a = norm(softwareName);
  const b = norm(lastWord);
  return names.some(n => a === n || b === n || (n.length >= 4 && (a.startsWith(n) || b.startsWith(n))));
}

// One NVD cpeMatch entry against one installed version.
function versionInRange(version, m) {
  const parts = String(m.criteria || '').split(':');
  const fixed = parts[5];
  if (fixed && fixed !== '*' && fixed !== '-') return compareVersions(version, fixed) === 0;
  if (m.versionStartIncluding && compareVersions(version, m.versionStartIncluding) < 0) return false;
  if (m.versionStartExcluding && compareVersions(version, m.versionStartExcluding) <= 0) return false;
  if (m.versionEndIncluding && compareVersions(version, m.versionEndIncluding) > 0) return false;
  if (m.versionEndExcluding && compareVersions(version, m.versionEndExcluding) >= 0) return false;
  return Boolean(m.versionStartIncluding || m.versionStartExcluding || m.versionEndIncluding || m.versionEndExcluding);
}

// Does the asset actually run something the CVE affects?
// Uses NVD CPE ranges when present, otherwise the curated match_terms.
function exposureFor(asset, cve) {
  if (!asset || !cve) return { exposed: false, evidence: null };
  const strings = [
    ...(asset.installed_packages || []),
    ...(asset.running_services || []).map(s => s.service)
  ].map(s => String(s));

  const cpes = (cve.cpe_matches || []).filter(m => m.vulnerable !== false);
  if (cpes.length) {
    for (const s of strings) {
      for (const sw of extractSoftware(s)) {
        for (const m of cpes) {
          const product = String(m.criteria || '').split(':')[4];
          if (product && productMatches(sw.name, sw.last, product) && versionInRange(sw.version, m)) {
            return { exposed: true, evidence: s };
          }
        }
      }
    }
    return { exposed: false, evidence: null };
  }

  const terms = (cve.match_terms || []).map(t => String(t).toLowerCase());
  const hit = strings.find(h => terms.some(t => h.toLowerCase().includes(t)));
  return { exposed: Boolean(hit), evidence: hit || null };
}

// Splits host log lines into execution signals and rejection signals.
function assessLogs(logs) {
  const execution = [];
  const rejection = [];
  const access = [];
  for (const l of logs) {
    const raw = l.raw_entry || '';
    if (l.log_type === 'edr_process') execution.push(l);
    else if (/accepted (password|publickey|keyboard-interactive)/i.test(raw)) access.push(l);
    else if ((l.status_code && l.status_code >= 400) || /rejected|\bban\b|no outbound|invalid authorization|failed password|denied/i.test(raw)) rejection.push(l);
    else if (/jndi lookup .*connecting|connecting to remote/i.test(raw)) execution.push(l);
  }
  const served = logs.filter(l => l.log_type === 'http_access' && l.status_code >= 200 && l.status_code < 300);
  return { execution, rejection, access, served };
}

const newId = (prefix) => `${prefix}-${Date.now().toString(36).toUpperCase().slice(-5)}${require('crypto').randomBytes(2).toString('hex').toUpperCase()}`;

module.exports = {
  SEVERITY_RANK, TECHNIQUES, isIP, isIPv4, isInternal, classifyPayload,
  extractSoftware, compareVersions, versionInRange, exposureFor, assessLogs, newId
};