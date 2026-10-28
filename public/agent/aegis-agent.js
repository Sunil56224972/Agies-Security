#!/usr/bin/env node
'use strict';

// Aegis sensor agent. One file, no dependencies, Node 18+.
//
// Ships what a host actually sees to an Aegis console:
//   --eve PATH       Suricata eve.json        -> POST /api/ingest/alerts  (event_type "alert" only)
//   --access PATH    nginx / Apache access log -> POST /api/ingest/logs    (log_type http_access)
//   --auth PATH      sshd / sudo auth log      -> POST /api/ingest/logs    (log_type auth_log)
//   --syslog PATH    any other text log        -> POST /api/ingest/logs    (log_type system)
//   inventory        hostname, OS, listening services and installed packages
//                    -> POST /api/ingest/assets every --inventory-every minutes
//
// Every flag can be repeated. Read positions are kept in --state so a restart
// resumes where it stopped; rotated or truncated files are picked up from the start.
//
//   AEGIS_URL=https://aegis.example.com AEGIS_KEY=aeg_... \
//     node aegis-agent.js --eve /var/log/suricata/eve.json --access /var/log/nginx/access.log --auth /var/log/auth.log
//
// Other flags: --host-ip IP (address to report, default: first private IPv4), --criticality LEVEL,
// --owner TEAM, --no-inventory, --inventory-only, --from-start, --dry-run, --verbose.
//
// Enforcement (run as root / Administrator; the key needs the "feed" scope):
//   --enforce            pull /api/feeds/blocklist.txt and drop those addresses in the
//                        host firewall (iptables/ip6tables, Windows Firewall, macOS pf)
//   --enforce-only       enforce without shipping logs or inventory
//   --enforce-every SEC  pull interval, default 60   --feed-key KEY (or AEGIS_FEED_KEY)
//   --enforce-clear      remove every Aegis firewall rule from this host and exit

const fs = require('fs');
const os = require('os');
const net = require('net');
const dns = require('dns');
const path = require('path');
const { execFile } = require('child_process');

const VERSION = '1.0.0';
const BATCH_LINES = 500;
const FLUSH_MS = 2000;
const POLL_MS = 1000;
const MAX_QUEUE = 20000;
const MAX_READ = 4 * 1024 * 1024;

// ---- Arguments -----------------------------------------------------------------
function parseArgs(argv) {
  const o = { eve: [], access: [], auth: [], syslog: [], inventory: true, inventoryEvery: 60, state: null, dryRun: false, verbose: false, fromStart: false, inventoryOnly: false, enforce: false, enforceOnly: false, enforceEvery: 60, enforceClear: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { const v = argv[++i]; if (v === undefined) die(`${a} needs a value`); return v; };
    switch (a) {
      case '--eve': o.eve.push(val()); break;
      case '--access': o.access.push(val()); break;
      case '--auth': o.auth.push(val()); break;
      case '--syslog': o.syslog.push(val()); break;
      case '--url': o.url = val(); break;
      case '--key': o.key = val(); break;
      case '--host-ip': o.hostIp = val(); break;
      case '--hostname': o.hostname = val(); break;
      case '--owner': o.owner = val(); break;
      case '--criticality': o.criticality = val().toUpperCase(); break;
      case '--state': o.state = val(); break;
      case '--inventory-every': o.inventoryEvery = Math.max(5, Number(val()) || 60); break;
      case '--no-inventory': o.inventory = false; break;
      case '--inventory-only': o.inventoryOnly = true; break;
      case '--from-start': o.fromStart = true; break;
      case '--dry-run': o.dryRun = true; break;
      case '--enforce': o.enforce = true; break;
      case '--enforce-only': o.enforce = true; o.enforceOnly = true; break;
      case '--enforce-every': o.enforceEvery = Math.max(15, Number(val()) || 60); break;
      case '--enforce-clear': o.enforceClear = true; break;
      case '--feed-key': o.feedKey = val(); break;
      case '--verbose': case '-v': o.verbose = true; break;
      case '--version': console.log(VERSION); process.exit(0); break;
      case '--help': case '-h': console.log(fs.readFileSync(__filename, 'utf8').split('\n').slice(3, 29).map((l) => l.replace(/^\/\/ ?/, '')).join('\n')); process.exit(0); break;
      default: die(`Unknown option ${a}. Try --help.`);
    }
  }
  o.url = (o.url || process.env.AEGIS_URL || '').replace(/\/+$/, '');
  o.key = o.key || process.env.AEGIS_KEY || '';
  o.feedKey = o.feedKey || process.env.AEGIS_FEED_KEY || o.key;
  const needsConsole = !o.dryRun && !o.enforceClear;
  if (needsConsole && !/^https?:\/\//.test(o.url)) die('Set AEGIS_URL (or --url) to the console address, e.g. https://aegis.example.com');
  if (needsConsole && !o.enforceOnly && !o.key) die('Set AEGIS_KEY (or --key) to an API key with the "ingest" scope');
  if (needsConsole && o.enforce && !o.feedKey) die('Set AEGIS_FEED_KEY (or --feed-key, or AEGIS_KEY) to an API key with the "feed" scope');
  if (o.url.startsWith('http://') && !/^http:\/\/(localhost|127\.|\[::1\])/.test(o.url)) warn('AEGIS_URL is plain http; the API key travels unencrypted');
  o.state = o.state || process.env.AEGIS_STATE || path.join(process.platform === 'win32' ? os.tmpdir() : (fs.existsSync('/var/lib') && canWrite('/var/lib') ? '/var/lib' : os.tmpdir()), 'aegis-agent.state.json');
  return o;
}

function canWrite(dir) { try { fs.accessSync(dir, fs.constants.W_OK); return true; } catch { return false; } }
function stamp() { return new Date().toISOString(); }
function log(...m) { console.log(stamp(), ...m); }
function warn(...m) { console.warn(stamp(), 'WARN', ...m); }
function die(m) { console.error(`aegis-agent: ${m}`); process.exit(2); }

const opts = parseArgs(process.argv.slice(2));
const debug = (...m) => { if (opts.verbose) log(...m); };

// ---- Host facts ------------------------------------------------------------------
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
function primaryIp() {
  if (opts.hostIp) return opts.hostIp;
  const all = Object.values(os.networkInterfaces()).flat().filter((n) => n && !n.internal && n.family === 'IPv4' || n && !n.internal && n.family === 4);
  return (all.find((n) => PRIVATE.test(n.address)) || all[0] || { address: '127.0.0.1' }).address;
}
const HOST_IP = primaryIp();

// ---- HTTP with retry ---------------------------------------------------------------
async function post(pathname, body, type) {
  if (opts.dryRun) {
    log(`[dry-run] POST ${pathname} (${type}, ${Buffer.byteLength(body)} bytes)`);
    if (opts.verbose) console.log(body.slice(0, 2000));
    return { ok: true, json: { dry_run: true } };
  }
  let delay = 1000;
  for (let attempt = 1; ; attempt++) {
    try {
      const res = await fetch(`${opts.url}${pathname}`, {
        method: 'POST', body,
        headers: { Authorization: `Bearer ${opts.key}`, 'Content-Type': type, 'User-Agent': `aegis-agent/${VERSION} (${os.hostname()})` },
        signal: AbortSignal.timeout(30000)
      });
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch { /* not JSON */ }
      if (res.ok) return { ok: true, json };
      // Bad key or bad data will not get better by retrying.
      if ([400, 401, 403, 413].includes(res.status)) return { ok: false, status: res.status, json, fatal: res.status === 401 || res.status === 403 };
      throw new Error(`HTTP ${res.status}${json && json.error ? `: ${json.error}` : ''}`);
    } catch (err) {
      if (attempt >= 8) return { ok: false, error: err.message };
      warn(`POST ${pathname} failed (${err.message}); retry ${attempt} in ${Math.round(delay / 1000)}s`);
      await new Promise((r) => setTimeout(r, delay));
      delay = Math.min(delay * 2, 60000);
    }
  }
}

// ---- State ---------------------------------------------------------------------------
let state = {};
try { state = JSON.parse(fs.readFileSync(opts.state, 'utf8')); } catch { state = {}; }
let stateDirty = false;
function saveState() {
  if (!stateDirty) return;
  try {
    fs.writeFileSync(`${opts.state}.tmp`, JSON.stringify(state));
    fs.renameSync(`${opts.state}.tmp`, opts.state);
    stateDirty = false;
  } catch (err) { warn(`Cannot write state file ${opts.state}: ${err.message}`); }
}

// ---- File tailing ----------------------------------------------------------------------
// Polling instead of fs.watch: it behaves the same on every filesystem, including
// NFS and container bind mounts, and survives logrotate's create/copytruncate.
class Tail {
  constructor(file, kind) {
    this.file = path.resolve(file);
    this.kind = kind;
    this.partial = '';
    this.missingWarned = false;
    const s = state[this.file];
    this.pos = s ? s.pos : null;
    this.ino = s ? s.ino : null;
  }

  read() {
    let st;
    try { st = fs.statSync(this.file); } catch {
      if (!this.missingWarned) { warn(`${this.file} not found; waiting for it`); this.missingWarned = true; }
      return [];
    }
    this.missingWarned = false;
    if (this.pos === null) {
      // First sight of the file: ship new lines only unless --from-start.
      this.pos = opts.fromStart ? 0 : st.size;
      this.ino = st.ino;
      log(`Tailing ${this.file} (${this.kind}) from ${this.pos ? `byte ${this.pos}` : 'the start'}`);
    }
    if (st.ino !== this.ino || st.size < this.pos) {
      log(`${this.file} was rotated or truncated; reading from the start`);
      this.pos = 0; this.ino = st.ino; this.partial = '';
    }
    if (st.size === this.pos) return [];
    const len = Math.min(st.size - this.pos, MAX_READ);
    const buf = Buffer.alloc(len);
    const fd = fs.openSync(this.file, 'r');
    try { fs.readSync(fd, buf, 0, len, this.pos); } finally { fs.closeSync(fd); }
    this.pos += len;
    state[this.file] = { pos: this.pos, ino: this.ino };
    stateDirty = true;
    const text = this.partial + buf.toString('utf8');
    const lines = text.split(/\r?\n/);
    this.partial = lines.pop();
    return lines.filter((l) => l.trim());
  }
}

// ---- Shippers ------------------------------------------------------------------------------
const LOG_TYPE = { access: 'http_access', auth: 'auth_log', syslog: 'system' };
const queues = new Map();
const totals = { alerts: 0, logs: 0, dropped: 0, rejected: 0 };
let stopping = false;
let fatal = false;

function enqueue(key, lines) {
  if (!lines.length) return;
  const q = queues.get(key) || [];
  q.push(...lines);
  if (q.length > MAX_QUEUE) { totals.dropped += q.length - MAX_QUEUE; q.splice(0, q.length - MAX_QUEUE); warn(`Queue ${key} full; dropped oldest lines`); }
  queues.set(key, q);
}

async function flush() {
  for (const [key, q] of queues) {
    while (q.length && !fatal) {
      const batch = q.slice(0, BATCH_LINES);
      const [kind] = key.split('|');
      const r = kind === 'eve'
        ? await post('/api/ingest/alerts', `${batch.join('\n')}\n`, 'application/x-ndjson')
        : await post(`/api/ingest/logs?host_ip=${encodeURIComponent(HOST_IP)}&log_type=${LOG_TYPE[kind]}`, `${batch.join('\n')}\n`, 'text/plain');
      if (!r.ok) {
        if (r.fatal) { fatal = true; warn(`Console refused the API key (HTTP ${r.status}): ${r.json && r.json.error}. Stopping.`); return; }
        if (r.status) { totals.rejected += batch.length; q.splice(0, batch.length); warn(`Batch rejected (HTTP ${r.status}): ${r.json && r.json.error}`); continue; }
        warn(`Console unreachable; keeping ${q.length} lines queued`);
        return;
      }
      q.splice(0, batch.length);
      if (kind === 'eve') {
        totals.alerts += (r.json && r.json.accepted) || 0;
        debug(`alerts: ${JSON.stringify(r.json)}`);
      } else {
        totals.logs += (r.json && r.json.accepted) || 0;
        debug(`logs: ${JSON.stringify(r.json)}`);
      }
    }
  }
}

// ---- Inventory ---------------------------------------------------------------------------------
function run(cmd, args, timeout = 20000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, maxBuffer: 32 * 1024 * 1024, windowsHide: true }, (err, stdout) => resolve(err && !stdout ? '' : String(stdout || '')));
  });
}

function osRelease() {
  try {
    const kv = Object.fromEntries(fs.readFileSync('/etc/os-release', 'utf8').split('\n').map((l) => l.match(/^(\w+)=(.*)$/)).filter(Boolean).map((m) => [m[1], m[2].replace(/^"|"$/g, '')]));
    return kv.PRETTY_NAME || `${kv.NAME || ''} ${kv.VERSION_ID || ''}`.trim();
  } catch { return null; }
}

async function listeners() {
  const out = new Map();
  const add = (port, proc) => {
    port = Number(port);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) return;
    if (!out.has(port) || (proc && out.get(port) === 'listening')) out.set(port, proc || 'listening');
  };
  if (process.platform === 'linux') {
    const ss = await run('ss', ['-H', '-ltnp']);
    for (const line of ss.split('\n')) {
      const cols = line.trim().split(/\s+/);
      if (cols.length < 4) continue;
      const local = cols[3];
      if (/^(127\.|\[::1\]|::1)/.test(local)) continue;
      const proc = (line.match(/users:\(\("([^"]+)"/) || [])[1];
      add(local.split(':').pop(), proc);
    }
  } else if (process.platform === 'win32') {
    const ns = await run('netstat', ['-ano', '-p', 'TCP']);
    for (const line of ns.split('\n')) {
      const m = line.trim().match(/^TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING/i);
      if (m && !/^127\./.test(m[1])) add(m[2]);
    }
  } else {
    const ls = await run('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN']);
    for (const line of ls.split('\n').slice(1)) {
      const cols = line.trim().split(/\s+/);
      const addr = cols[8] || '';
      if (!addr || /^(127\.|\[::1\])/.test(addr)) continue;
      add(addr.split(':').pop(), cols[0]);
    }
  }
  return [...out].sort((a, b) => a[0] - b[0]).map(([port, service]) => ({ port, service }));
}

// Versioned names ("openssl 3.0.13") are what CVE matching keys on.
async function packages() {
  if (process.platform !== 'linux') return [];
  let text = await run('dpkg-query', ['-W', '-f=${Package} ${Version}\n']);
  if (!text.trim()) text = await run('rpm', ['-qa', '--qf', '%{NAME} %{VERSION}\n']);
  if (!text.trim()) text = await run('apk', ['info', '-v']);
  const list = text.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => l.replace(/^(\d+:)/, ''));
  // Prefer packages that matter for exposure; the console caps the list at 400.
  const interesting = /(openssl|openssh|nginx|apache|httpd|tomcat|log4j|java|jdk|jre|php|python3|node|mysql|mariadb|postgres|redis|mongo|docker|containerd|kernel|linux-image|sudo|bash|glibc|libc6|curl|exim|postfix|samba|bind9|vsftpd|proftpd|elasticsearch|jenkins|gitlab|grafana|confluence|jira|wordpress|haproxy|squid|xz|polkit)/i;
  const sorted = [...list.filter((p) => interesting.test(p)), ...list.filter((p) => !interesting.test(p))];
  return sorted.slice(0, 400);
}

async function versionOf(proc) {
  const probes = { nginx: ['nginx', ['-v']], sshd: ['sshd', ['-V']], apache2: ['apache2', ['-v']], httpd: ['httpd', ['-v']], mysqld: ['mysqld', ['--version']], postgres: ['postgres', ['--version']], node: ['node', ['--version']], redis: ['redis-server', ['--version']] };
  const p = probes[proc];
  if (!p) return null;
  const out = await new Promise((resolve) => execFile(p[0], p[1], { timeout: 4000 }, (err, so, se) => resolve(`${so || ''}${se || ''}`)));
  const m = out.match(/(\d+\.\d+(?:\.\d+)?[a-z0-9]*)/i);
  return m ? m[1] : null;
}

async function inventory() {
  const [svc, pkgs] = await Promise.all([listeners(), packages()]);
  for (const s of svc) {
    const v = s.service !== 'listening' ? await versionOf(s.service) : null;
    if (v) s.service = `${s.service} ${v}`;
  }
  const osName = osRelease() || `${os.type()} ${os.release()}`;
  const asset = {
    ip_address: HOST_IP,
    hostname: opts.hostname || os.hostname(),
    os_family: process.platform === 'win32' ? 'Windows' : process.platform === 'darwin' ? 'macOS' : process.platform === 'linux' ? 'Linux' : os.type(),
    os_version: osName,
    running_services: svc,
    installed_packages: pkgs,
    last_scanned: stamp()
  };
  if (opts.owner) asset.owner = opts.owner;
  if (opts.criticality) asset.criticality = opts.criticality;
  return asset;
}

async function shipInventory() {
  try {
    const asset = await inventory();
    const r = await post('/api/ingest/assets', JSON.stringify([asset]), 'application/json');
    if (r.ok) log(`Inventory sent: ${asset.hostname} ${asset.ip_address}, ${asset.running_services.length} listening ports, ${asset.installed_packages.length} packages`);
    else if (r.fatal) { fatal = true; warn(`Console refused the API key (HTTP ${r.status}). Stopping.`); }
    else warn(`Inventory not accepted: ${(r.json && r.json.error) || r.error || r.status}`);
  } catch (err) { warn(`Inventory failed: ${err.message}`); }
}

// ---- Enforcement -------------------------------------------------------------------------------
// Pulls the BLOCK feed and mirrors it into the host firewall, so a rule published in
// the console is actually dropped on this machine. Only blocklist.txt is pulled:
// pulling isolate.txt would tell the console those rules are enforced, and this
// agent does not quarantine hosts.
const FW_NAME = 'AEGIS-BLOCK';
const PF_ANCHOR = 'com.apple/aegis'; // macOS' default pf.conf evaluates com.apple/* anchors

function sh(cmd, args, timeout = 20000) {
  return new Promise((resolve) => {
    if (opts.dryRun) { log(`[dry-run] ${cmd} ${args.join(' ')}`); return resolve({ code: 0, stdout: '', stderr: '' }); }
    execFile(cmd, args, { timeout, maxBuffer: 8 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) =>
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: String(stdout || ''), stderr: String(stderr || (err && err.message) || '') }));
  });
}

async function mustSh(cmd, args) {
  const r = await sh(cmd, args);
  if (r.code !== 0) throw new Error(`${cmd} ${args.slice(0, 3).join(' ')}... failed: ${(r.stderr || r.stdout).trim().split('\n')[0] || `exit ${r.code}`}`);
  return r;
}

// Addresses that must never be blocked: this host and the console it reports to.
async function protectedIps() {
  const keep = new Set(['127.0.0.1', '::1', HOST_IP]);
  for (const n of Object.values(os.networkInterfaces()).flat()) if (n && n.address) keep.add(n.address);
  try {
    const host = new URL(opts.url).hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(host)) keep.add(host);
    else for (const a of await dns.promises.lookup(host, { all: true })) keep.add(a.address);
  } catch { /* console unresolvable right now; the fetch will fail anyway */ }
  return keep;
}

async function pullBlocklist() {
  const res = await fetch(`${opts.url}/api/feeds/blocklist.txt`, {
    headers: { Authorization: `Bearer ${opts.feedKey}`, 'User-Agent': `aegis-agent/${VERSION} (${os.hostname()})` },
    signal: AbortSignal.timeout(30000)
  });
  const text = await res.text();
  if (res.status === 401 || res.status === 403) { const e = new Error(`console refused the feed key (HTTP ${res.status}); it needs the "feed" scope`); e.fatal = true; throw e; }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
}

const firewall = {
  linux: {
    async apply(v4, v6) {
      for (const [bin, ips] of [['iptables', v4], ['ip6tables', v6]]) {
        if (bin === 'ip6tables' && !ips.length && (await sh('ip6tables', ['-w', '-L', FW_NAME, '-n'])).code !== 0) continue;
        await sh(bin, ['-w', '-N', FW_NAME]); // fails harmlessly when the chain exists
        for (const parent of ['INPUT', 'OUTPUT', 'FORWARD']) {
          if ((await sh(bin, ['-w', '-C', parent, '-j', FW_NAME])).code !== 0) await mustSh(bin, ['-w', '-I', parent, '1', '-j', FW_NAME]);
        }
        await mustSh(bin, ['-w', '-F', FW_NAME]);
        for (const ip of ips) {
          await mustSh(bin, ['-w', '-A', FW_NAME, '-s', ip, '-j', 'DROP']);
          await mustSh(bin, ['-w', '-A', FW_NAME, '-d', ip, '-j', 'DROP']);
        }
      }
    },
    async clear() {
      for (const bin of ['iptables', 'ip6tables']) {
        for (const parent of ['INPUT', 'OUTPUT', 'FORWARD']) while ((await sh(bin, ['-w', '-D', parent, '-j', FW_NAME])).code === 0 && !opts.dryRun) { /* remove every jump */ }
        await sh(bin, ['-w', '-F', FW_NAME]);
        await sh(bin, ['-w', '-X', FW_NAME]);
      }
    }
  },
  win32: {
    async apply(v4, v6) {
      await this.clear();
      const ips = [...v4, ...v6];
      // netsh caps the length of remoteip, so large lists are split over several rules with one name.
      for (let i = 0; i < ips.length; i += 200) {
        const list = ips.slice(i, i + 200).join(',');
        for (const dir of ['in', 'out']) {
          await mustSh('netsh', ['advfirewall', 'firewall', 'add', 'rule', `name=${FW_NAME}`, `dir=${dir}`, 'action=block', 'enable=yes', 'profile=any', `remoteip=${list}`]);
        }
      }
    },
    async clear() { await sh('netsh', ['advfirewall', 'firewall', 'delete', 'rule', `name=${FW_NAME}`]); }
  },
  darwin: {
    async apply(v4, v6) {
      const ips = [...v4, ...v6];
      const file = path.join(os.tmpdir(), 'aegis-pf.conf');
      fs.writeFileSync(file, `table <aegis_block> persist { ${ips.join(' ')} }\nblock drop quick from <aegis_block> to any\nblock drop quick from any to <aegis_block>\n`);
      await mustSh('pfctl', ['-a', PF_ANCHOR, '-f', file]);
      await sh('pfctl', ['-E']);
    },
    async clear() { await sh('pfctl', ['-a', PF_ANCHOR, '-F', 'all']); }
  }
};

async function enforceClear() {
  const fw = firewall[process.platform];
  if (!fw) die(`Enforcement is not supported on ${process.platform}`);
  await fw.clear();
  log('Removed Aegis firewall rules from this host');
}

let lastApplied = null;
let enforceFatal = false;
async function enforceOnce() {
  const fw = firewall[process.platform];
  try {
    const feed = await pullBlocklist();
    const keep = await protectedIps();
    const valid = [...new Set(feed.filter((ip) => net.isIP(ip)))];
    const skipped = valid.filter((ip) => keep.has(ip));
    if (skipped.length) warn(`Not blocking ${skipped.join(', ')}: this host or the console`);
    const ips = valid.filter((ip) => !keep.has(ip)).sort();
    const sig = ips.join(',');
    if (sig === lastApplied) { debug(`Blocklist unchanged (${ips.length} addresses)`); return; }
    const v4 = ips.filter((ip) => net.isIPv4(ip)), v6 = ips.filter((ip) => net.isIPv6(ip));
    await fw.apply(v4, v6);
    lastApplied = sig;
    log(`Firewall updated: blocking ${ips.length} address${ips.length === 1 ? '' : 'es'}${ips.length ? ` (${ips.slice(0, 5).join(', ')}${ips.length > 5 ? ', ...' : ''})` : ''}`);
  } catch (err) {
    if (err.fatal) { enforceFatal = true; warn(`Enforcement stopped: ${err.message}`); return; }
    warn(`Enforcement failed: ${err.message}${/permission|denied|not permitted|elevation|requires/i.test(err.message) ? ' (run the agent as root / Administrator)' : ''}`);
  }
}

async function startEnforcement() {
  if (!firewall[process.platform]) die(`Enforcement is not supported on ${process.platform}`);
  log(`Enforcing ${opts.url}/api/feeds/blocklist.txt into the ${process.platform === 'win32' ? 'Windows Firewall' : process.platform === 'darwin' ? 'pf' : 'iptables'} every ${opts.enforceEvery}s`);
  await enforceOnce();
  return setInterval(() => { if (!enforceFatal) enforceOnce(); }, opts.enforceEvery * 1000);
}

// ---- Main ------------------------------------------------------------------------------------------
async function main() {
  if (opts.enforceClear) { await enforceClear(); return; }
  log(`aegis-agent ${VERSION} on ${os.hostname()} (${HOST_IP}) -> ${opts.dryRun ? 'dry run' : opts.url}`);
  if (opts.inventoryOnly) { await shipInventory(); return; }
  if (opts.enforceOnly) {
    const t = await startEnforcement();
    const stop = () => { clearInterval(t); log('Stopping; firewall rules stay in place (use --enforce-clear to remove them)'); process.exit(0); };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    const watch = setInterval(() => { if (enforceFatal) process.exit(1); }, 1000);
    if (opts.dryRun) { clearInterval(t); clearInterval(watch); }
    return;
  }
  if (opts.enforce) await startEnforcement();

  const tails = [
    ...opts.eve.map((f) => new Tail(f, 'eve')), ...opts.access.map((f) => new Tail(f, 'access')),
    ...opts.auth.map((f) => new Tail(f, 'auth')), ...opts.syslog.map((f) => new Tail(f, 'syslog'))
  ];
  if (!tails.length && !opts.inventory && !opts.enforce) die('Nothing to do: pass --eve, --access, --auth or --syslog, or leave inventory on');

  if (opts.inventory) {
    await shipInventory();
    setInterval(() => { if (!fatal) shipInventory(); }, opts.inventoryEvery * 60000).unref();
  }
  if (!tails.length) { log('No log files given; sending inventory only'); }

  let busy = false;
  let lastFlush = Date.now();
  const tick = async () => {
    if (busy || stopping) return;
    busy = true;
    try {
      for (const t of tails) {
        const lines = t.read();
        // Suricata writes flows, DNS, TLS and stats to the same file; only alerts go up.
        enqueue(`${t.kind}|${t.file}`, t.kind === 'eve' ? lines.filter((l) => l.includes('"event_type":"alert"')) : lines);
      }
      const pending = [...queues.values()].reduce((n, q) => n + q.length, 0);
      if (pending >= BATCH_LINES || (pending && Date.now() - lastFlush >= FLUSH_MS)) { await flush(); lastFlush = Date.now(); }
      saveState();
    } catch (err) { warn(`Tail loop: ${err.message}`); } finally { busy = false; }
    if (fatal) process.exit(1);
  };
  const timer = setInterval(tick, POLL_MS);
  const report = setInterval(() => log(`Shipped ${totals.alerts} alerts, ${totals.logs} log lines${totals.rejected ? `, ${totals.rejected} rejected` : ''}${totals.dropped ? `, ${totals.dropped} dropped` : ''}`), 10 * 60000);
  report.unref();

  const stop = async () => {
    if (stopping) return;
    stopping = true;
    clearInterval(timer);
    log('Stopping; sending what is queued');
    await flush().catch(() => {});
    saveState();
    process.exit(0);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

main().catch((err) => { console.error(`aegis-agent: ${err.stack || err.message}`); process.exit(1); });