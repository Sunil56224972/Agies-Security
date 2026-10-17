'use strict';

// Built-in detections over host telemetry. These run on every batch that lands on
// /api/ingest/logs, so a host with nothing but the Aegis agent (no Suricata) still
// raises alerts. Every rule looks at stored log lines only; nothing is invented.
//
//   ssh-bruteforce    N failed SSH logins from one address inside the window
//   ssh-success-after A successful login from an address that just failed N times
//   web-exploit       exploit strings in a request line (JNDI, traversal, SQLi, ...)
//   web-scanner       N 403/404 answers to one client, or a scanner user-agent

const crypto = require('crypto');
const { isIP } = require('./analysis');

const RULES = [
  { id: 'ssh-bruteforce', name: 'SSH brute force', severity: 'HIGH', tactic: 'Credential Access', technique: 'T1110 Brute Force',
    help: 'Failed SSH passwords or unknown users from one address, at or above the threshold inside the window.' },
  { id: 'ssh-success-after', name: 'SSH login after failures', severity: 'CRITICAL', tactic: 'Initial Access', technique: 'T1078 Valid Accounts',
    help: 'An address logs in successfully after failing at least the brute-force threshold. Treat as a likely compromise.' },
  { id: 'web-exploit', name: 'Web exploit attempt', severity: 'HIGH', tactic: 'Initial Access', technique: 'T1190 Exploit Public-Facing Application',
    help: 'Request lines carrying JNDI lookups, path traversal, SQL injection, command injection, XSS or reads of secret files.' },
  { id: 'web-scanner', name: 'Web scanner', severity: 'MEDIUM', tactic: 'Reconnaissance', technique: 'T1595 Active Scanning',
    help: 'Many 403/404 answers to one client inside the window, or a request from a known scanning tool.' }
];

const SSH_FAIL = /failed (?:password|publickey|keyboard-interactive)|invalid user|authentication failure|maximum authentication attempts exceeded|did not receive identification string/i;
const SSH_OK = /accepted (?:password|publickey|keyboard-interactive)/i;
const SSH_USER = /(?:for (?:invalid user )?|invalid user )([a-z0-9._-]{1,32}) from/i;

// First match wins; ordered by how bad a hit would be.
const WEB = [
  { id: 'log4shell', label: 'JNDI lookup (Log4Shell)', severity: 'CRITICAL', re: /\$\{(?:jndi|\$\{[^}]*\}|lower:|upper:|::-j)/i, ref: 'CVE-2021-44228' },
  { id: 'traversal', label: 'Path traversal', severity: 'CRITICAL', re: /(?:\.\.|%2e%2e|\.%2e|%2e\.|%%32%65)(?:\/|%2f|\\|%5c)/i, ref: 'CWE-22' },
  { id: 'cmdi', label: 'Command injection', severity: 'CRITICAL', re: /(?:;|%3b|\||%7c|`|%60|\$\(|%24%28)\s*(?:id|uname|whoami|wget|curl|nc|bash|sh|cat\s|python|perl)\b/i, ref: 'CWE-78' },
  { id: 'sqli', label: 'SQL injection', severity: 'HIGH', re: /(?:union(?:\s|\+|%20|\/\*\*\/)+(?:all(?:\s|\+|%20)+)?select|(?:'|%27)(?:\s|\+|%20)*(?:or|and)(?:\s|\+|%20)+[\d'"]+(?:\s|\+|%20)*=|sleep\(\d+\)|benchmark\(\d+|information_schema|xp_cmdshell)/i, ref: 'CWE-89' },
  { id: 'secrets', label: 'Secret file probe', severity: 'HIGH', re: /\/(?:\.env|\.git\/(?:config|HEAD)|\.aws\/credentials|\.ssh\/id_|wp-config\.php\.bak|etc\/(?:passwd|shadow)|\.htpasswd|server-status|actuator\/env)/i, ref: 'CWE-538' },
  { id: 'xss', label: 'Cross-site scripting', severity: 'MEDIUM', re: /(?:<|%3c)\s*(?:script|svg|img)[^>]*?(?:>|%3e|onerror|onload)|javascript:/i, ref: 'CWE-79' }
];
const SCANNER_UA = /\b(sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|dirb|feroxbuster|wpscan|acunetix|nessus|openvas|wfuzz|ffuf|hydra|whatweb|jaeles|httpx|censysinspect|l9explore)\b/i;

const sha = (...p) => crypto.createHash('sha1').update(p.join('|')).digest('hex').slice(0, 12).toUpperCase();
const t = (l) => new Date(l.logged_at).getTime();
const short = (s, n = 600) => (String(s).length > n ? `${String(s).slice(0, n)}...` : String(s));
const fmtSpan = (ms) => (ms < 90000 ? `${Math.max(1, Math.round(ms / 1000))}s` : `${Math.round(ms / 60000)}m`);

function settings(cfg = {}) {
  return {
    enabled: cfg.detectEnabled !== false,
    sshThreshold: Number(cfg.detectSshThreshold) || 5,
    scanThreshold: Number(cfg.detectScanThreshold) || 20,
    windowMs: (Number(cfg.detectWindowMin) || 10) * 60000,
    disabled: new Set(Array.isArray(cfg.detectDisabled) ? cfg.detectDisabled : [])
  };
}

// One alert row in the shape store.alerts.insertMany expects. The id is derived from
// rule, flow and time bucket, so re-sending the same lines never raises it twice.
function makeAlert({ rule, key, bucket, signature, severity, client, host, port, protocol, lines, ref }) {
  const r = RULES.find((x) => x.id === rule);
  const first = lines[0];
  return {
    alert_id: `DET-${sha(rule, key, client, host, bucket)}`,
    signature: signature.slice(0, 240), category: r.tactic, severity: severity || r.severity,
    source_ip: client, dest_ip: host, dest_port: port, protocol, sensor: 'aegis-detect',
    raw_payload: short(lines.slice(0, 25).map((l) => `${l.logged_at}  ${l.raw_entry}`).join('\n') + (lines.length > 25 ? `\n... ${lines.length - 25} more lines` : ''), 8000),
    detected_at: first.logged_at, updated_at: first.logged_at, status: 'NEW',
    external_ref: `aegis:${rule}${ref ? ` ${ref}` : ''}`
  };
}

// Only the request line is judged, so a referrer or user agent cannot trip a rule
// (an Opera UA ending "; id)" is a locale, not a command). JNDI strings are the
// exception: Log4Shell is mostly delivered in headers, so the whole line is checked.
function classifyRequest(l) {
  const reqLine = l.request_uri || l.raw_entry || '';
  for (const w of WEB) if (w.re.test(w.id === 'log4shell' ? `${reqLine} ${l.raw_entry || ''}` : reqLine)) return w;
  return null;
}

// `logs` must be every stored line for the hosts/clients being judged, newest or oldest
// first. `now` bounds the window for brute-force style counts.
function evaluate(logs, cfg = {}, { now = Date.now() } = {}) {
  const s = settings(cfg);
  if (!s.enabled) return [];
  const on = (id) => !s.disabled.has(id);
  const out = [];
  const lines = logs.filter((l) => l && isIP(l.host_ip) && isIP(l.client_ip) && l.client_ip !== l.host_ip).sort((a, b) => t(a) - t(b));
  const groups = new Map();
  for (const l of lines) {
    const k = `${l.client_ip}|${l.host_ip}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(l);
  }

  for (const [k, group] of groups) {
    const [client, host] = k.split('|');
    const recent = group.filter((l) => t(l) >= now - s.windowMs * 6);

    // ---- SSH -----------------------------------------------------------------
    const auth = recent.filter((l) => l.log_type === 'auth_log' || /sshd/.test(l.raw_entry || ''));
    const fails = auth.filter((l) => SSH_FAIL.test(l.raw_entry));
    if (fails.length >= s.sshThreshold) {
      // Slide over the failures and report the first window that crosses the threshold.
      let hit = null;
      for (let i = 0, j = 0; j < fails.length; j++) {
        while (t(fails[j]) - t(fails[i]) > s.windowMs) i++;
        if (j - i + 1 >= s.sshThreshold) { hit = { from: i, to: j }; break; }
      }
      if (hit) {
        const inWindow = fails.filter((l) => t(l) >= t(fails[hit.from]) && t(l) <= t(fails[hit.from]) + s.windowMs);
        const users = [...new Set(inWindow.map((l) => (l.raw_entry.match(SSH_USER) || [])[1]).filter(Boolean))];
        const bucket = Math.floor(t(fails[hit.from]) / s.windowMs);
        const span = t(inWindow[inWindow.length - 1]) - t(inWindow[0]);
        if (on('ssh-bruteforce')) {
          out.push(makeAlert({
            rule: 'ssh-bruteforce', key: 'ssh', bucket, client, host, port: 22, protocol: 'TCP/SSH', lines: inWindow,
            signature: `AEGIS SSH brute force: ${inWindow.length} failed logins from ${client} in ${fmtSpan(span)}${users.length ? ` (users: ${users.slice(0, 4).join(', ')}${users.length > 4 ? ', ...' : ''})` : ''}`
          }));
        }
        const ok = auth.find((l) => SSH_OK.test(l.raw_entry) && t(l) >= t(fails[hit.from]) && t(l) <= t(fails[hit.to]) + s.windowMs * 6);
        if (ok && on('ssh-success-after')) {
          const user = (ok.raw_entry.match(/accepted \S+ for (\S+)/i) || [])[1];
          out.push(makeAlert({
            rule: 'ssh-success-after', key: `ok:${ok.id || ok.logged_at}`, bucket, client, host, port: 22, protocol: 'TCP/SSH', lines: [...inWindow.slice(-10), ok],
            signature: `AEGIS SSH login succeeded${user ? ` as ${user}` : ''} from ${client} after ${inWindow.length} failures`
          }));
        }
      }
    }

    // ---- Web -----------------------------------------------------------------
    const web = recent.filter((l) => l.log_type === 'http_access');
    if (on('web-exploit')) {
      const byKind = new Map();
      for (const l of web) {
        const w = classifyRequest(l);
        if (!w) continue;
        if (!byKind.has(w.id)) byKind.set(w.id, { w, lines: [] });
        byKind.get(w.id).lines.push(l);
      }
      for (const { w, lines: hits } of byKind.values()) {
        const served = hits.filter((l) => l.status_code >= 200 && l.status_code < 300);
        const first = hits[0];
        out.push(makeAlert({
          rule: 'web-exploit', key: w.id, bucket: Math.floor(t(first) / (s.windowMs * 6)), client, host, port: 80, protocol: 'TCP/HTTP', lines: hits, ref: w.ref, severity: w.severity,
          signature: `AEGIS ${w.label} from ${client}: ${hits.length} request${hits.length === 1 ? '' : 's'}${served.length ? `, ${served.length} answered 2xx` : ', all refused'} (${short(first.request_uri || '', 70)})`
        }));
      }
    }
    if (on('web-scanner')) {
      const misses = web.filter((l) => l.status_code === 404 || l.status_code === 403);
      let burst = null;
      for (let i = 0, j = 0; j < misses.length; j++) {
        while (t(misses[j]) - t(misses[i]) > s.windowMs) i++;
        if (j - i + 1 >= s.scanThreshold) { burst = misses.filter((l) => t(l) >= t(misses[i]) && t(l) <= t(misses[i]) + s.windowMs); break; }
      }
      const tool = web.find((l) => SCANNER_UA.test(l.raw_entry || ''));
      if (burst || tool) {
        const used = burst || web.filter((l) => SCANNER_UA.test(l.raw_entry || ''));
        const name = tool ? (tool.raw_entry.match(SCANNER_UA) || [])[1] : null;
        const paths = new Set(used.map((l) => l.request_uri).filter(Boolean)).size;
        out.push(makeAlert({
          rule: 'web-scanner', key: 'scan', bucket: Math.floor(t(used[0]) / (s.windowMs * 6)), client, host, port: 80, protocol: 'TCP/HTTP', lines: used,
          signature: burst
            ? `AEGIS Web scanning from ${client}: ${burst.length} not-found/forbidden answers across ${paths} paths${name ? ` (${name})` : ''}`
            : `AEGIS Scanner user-agent from ${client}: ${name} (${used.length} request${used.length === 1 ? '' : 's'})`
        }));
      }
    }
  }
  return out;
}

module.exports = { RULES, WEB, evaluate, settings, classifyRequest, SSH_FAIL, SSH_OK };