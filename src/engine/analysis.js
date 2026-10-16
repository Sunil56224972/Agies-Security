'use strict';

const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const isInternal = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip || '');
const isIPv4 = (ip) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(ip || '');

// Payload heuristics. Order matters: the first match wins.
const TECHNIQUES = [
  { id: 'log4shell', label: 'JNDI lookup injection (Log4Shell)', test: /\$\{jndi:/i, cve: 'CVE-2021-44228',
    tactic: 'Initial Access', technique: 'T1190 Exploit Public-Facing Application', requiresExposure: true },
  { id: 'path_traversal', label: 'Encoded path traversal into CGI', test: /(\.%2e|%2e%2e|%%32%65|\.\.\/)/i, cve: 'CVE-2021-41773',
    tactic: 'Initial Access', technique: 'T1190 Exploit Public-Facing Application', requiresExposure: true },
  { id: 'sqli', label: 'SQL injection', test: /((%27|')\s*(\+|%20|\s)*or(\+|%20|\s)+\d+=\d+)|union(\+|%20|\s)+select/i, cve: 'CWE-89',
    tactic: 'Initial Access', technique: 'T1190 Exploit Public-Facing Application', requiresExposure: false },
  { id: 'ssh_bruteforce', label: 'SSH password spraying', test: /failed password|invalid user/i, cve: 'AEGIS-SSH-BF',
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
  return { technique, indicators };
}

// Does the asset actually run something the CVE affects?
function exposureFor(asset, cve) {
  if (!asset || !cve) return { exposed: false, evidence: null };
  const haystack = [
    ...(asset.installed_packages || []),
    ...(asset.running_services || []).map(s => s.service)
  ].map(s => String(s).toLowerCase());
  const terms = (cve.match_terms || []).map(t => String(t).toLowerCase());
  const hit = haystack.find(h => terms.some(t => h.includes(t)));
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
    else if (/accepted (password|publickey)/i.test(raw)) access.push(l);
    else if ((l.status_code && l.status_code >= 400) || /rejected|\bban\b|no outbound|invalid authorization|failed password|denied/i.test(raw)) rejection.push(l);
    else if (/jndi lookup .*connecting|connecting to remote/i.test(raw)) execution.push(l);
  }
  const served = logs.filter(l => l.log_type === 'http_access' && l.status_code >= 200 && l.status_code < 300);
  return { execution, rejection, access, served };
}

const newId = (prefix) => `${prefix}-${Date.now().toString(36).toUpperCase().slice(-5)}${Math.random().toString(36).slice(2, 4).toUpperCase()}`;

module.exports = { SEVERITY_RANK, TECHNIQUES, isInternal, isIPv4, classifyPayload, exposureFor, assessLogs, newId };