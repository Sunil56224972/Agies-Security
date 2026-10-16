'use strict';

require('dotenv').config();
const path = require('path');
const express = require('express');
const { createStore } = require('./src/store');
const { Investigator } = require('./src/engine/investigator');
const { createTools, TOOL_DEFINITIONS } = require('./src/engine/tools');
const { isIPv4, newId, SEVERITY_RANK } = require('./src/engine/analysis');

const PORT = Number(process.env.PORT) || 3000;
const SEVERITIES = Object.keys(SEVERITY_RANK);

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const bad = (res, msg) => res.status(400).json({ error: msg });

async function main() {
  const { store, warning } = await createStore();
  const investigator = new Investigator(store, { groqKey: process.env.GROQ_API_KEY, model: process.env.GROQ_MODEL });
  const tools = createTools(store);
  const bootedAt = Date.now();

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));
  app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'], maxAge: '1h' }));

  // ---- System ------------------------------------------------------------
  app.get('/api/health', wrap(async (req, res) => {
    const db = await store.health();
    res.json({
      status: db.ok ? 'ok' : 'degraded',
      storage: { kind: store.kind, label: store.label, ok: db.ok, detail: db.detail, warning },
      engine: { llm: investigator.llmAvailable, model: investigator.llmAvailable ? investigator.model : null },
      tools: TOOL_DEFINITIONS.map(t => t.function.name),
      uptime_s: Math.round((Date.now() - bootedAt) / 1000)
    });
  }));

  app.get('/api/overview', wrap(async (req, res) => {
    const [alerts, investigations, rules, assets, audit] = await Promise.all([
      store.alerts.list(), store.investigations.list(), store.rules.list(), store.assets.list(), store.audit.list(12)
    ]);
    const open = alerts.filter(a => ['NEW', 'INVESTIGATING', 'CONFIRMED'].includes(a.status));
    const bySeverity = Object.fromEntries(SEVERITIES.map(s => [s, open.filter(a => a.severity === s).length]));
    const outcomes = investigations.reduce((m, i) => ({ ...m, [i.outcome]: (m[i.outcome] || 0) + 1 }), {});
    const active = rules.filter(r => r.is_active);

    // Mean time to respond: alert detection -> investigation closed, for the latest run per alert.
    const latest = new Map();
    for (const i of investigations) if (!latest.has(i.alert_id)) latest.set(i.alert_id, i);
    const durations = [...latest.values()].map(i => {
      const a = alerts.find(x => x.alert_id === i.alert_id);
      return a ? (new Date(i.created_at) - new Date(a.detected_at)) / 60000 : null;
    }).filter(d => d != null && d >= 0);
    const runTimes = investigations.map(i => i.duration_ms).filter(Boolean);

    // 24 hourly buckets for the activity strip.
    const now = Date.now();
    const hourly = Array.from({ length: 24 }, (_, i) => ({ h: 23 - i, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }));
    for (const a of alerts) {
      const h = Math.floor((now - new Date(a.detected_at)) / 3600000);
      if (h >= 0 && h < 24) hourly[23 - h][a.severity] += 1;
    }

    const exposedAssets = assets.filter(a => (a.installed_packages || []).some(p => /log4j-core-2\.1[0-4]|httpd-2\.4\.49/.test(p))).length;

    res.json({
      counts: { alerts: alerts.length, open: open.length, investigations: investigations.length, active_rules: active.length, assets: assets.length, exposed_assets: exposedAssets },
      by_severity: bySeverity,
      outcomes,
      packets_dropped: active.reduce((s, r) => s + Number(r.packets_dropped || 0), 0),
      mttr_min: durations.length ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length) : null,
      avg_run_ms: runTimes.length ? Math.round(runTimes.reduce((a, b) => a + b, 0) / runTimes.length) : null,
      hourly,
      queue: open.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.detected_at.localeCompare(a.detected_at)).slice(0, 6),
      recent_investigations: investigations.slice(0, 5),
      activity: audit
    });
  }));

  // ---- Alerts ------------------------------------------------------------
  app.get('/api/alerts', wrap(async (req, res) => {
    const { severity, status, q } = req.query;
    res.json(await store.alerts.list({ severity, status, q }));
  }));

  app.get('/api/alerts/:id', wrap(async (req, res) => {
    const alert = await store.alerts.get(req.params.id);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    const [investigations, asset] = await Promise.all([store.investigations.list(), store.assets.get(alert.dest_ip)]);
    res.json({ alert, asset, investigations: investigations.filter(i => i.alert_id === alert.alert_id) });
  }));

  app.post('/api/alerts', wrap(async (req, res) => {
    const b = req.body || {};
    const severity = String(b.severity || 'HIGH').toUpperCase();
    if (!b.signature || String(b.signature).trim().length < 6) return bad(res, 'Signature must be at least 6 characters');
    if (!isIPv4(b.source_ip) || !isIPv4(b.dest_ip)) return bad(res, 'Source and destination must be valid IPv4 addresses');
    if (!SEVERITIES.includes(severity)) return bad(res, 'Unknown severity');
    const port = Number(b.dest_port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return bad(res, 'Port must be 1-65535');
    if (!b.raw_payload || !String(b.raw_payload).trim()) return bad(res, 'Payload is required');
    const alert = await store.alerts.insert({
      alert_id: newId('ALERT'), signature: String(b.signature).trim().slice(0, 240), category: String(b.category || 'Manual submission').slice(0, 80),
      severity, source_ip: b.source_ip, dest_ip: b.dest_ip, dest_port: port, protocol: String(b.protocol || 'TCP').slice(0, 20),
      sensor: 'analyst-console', raw_payload: String(b.raw_payload).slice(0, 4000), status: 'NEW'
    });
    await store.audit.add({ actor: b.analyst || 'Analyst', action: 'alert.created', target: alert.alert_id, detail: alert.signature });
    res.status(201).json(alert);
  }));

  app.post('/api/alerts/:id/status', wrap(async (req, res) => {
    const allowed = ['NEW', 'CLOSED', 'FALSE_POSITIVE'];
    const status = String(req.body.status || '').toUpperCase();
    if (!allowed.includes(status)) return bad(res, `Status must be one of ${allowed.join(', ')}`);
    const updated = await store.alerts.update(req.params.id, { status });
    if (!updated) return res.status(404).json({ error: 'Alert not found' });
    await store.audit.add({ actor: req.body.analyst || 'Analyst', action: 'alert.status', target: req.params.id, detail: status });
    res.json(updated);
  }));

  // ---- Investigations ----------------------------------------------------
  app.post('/api/investigations/stream', wrap(async (req, res) => {
    const { alert_id, engine } = req.body || {};
    if (!alert_id) return bad(res, 'alert_id is required');
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    let closed = false;
    // Listen on the response: req emits 'close' as soon as the body is consumed.
    res.on('close', () => { closed = true; });
    const send = (data) => { if (!closed) res.write(`data: ${JSON.stringify(data)}\n\n`); };
    try {
      send({ type: 'start', alert_id, engine: engine === 'llm' && investigator.llmAvailable ? 'llm' : 'playbook' });
      await investigator.run(alert_id, send, { engine });
    } catch (err) {
      send({ type: 'error', message: err.message });
    }
    send({ type: 'done' });
    res.end();
  }));

  app.get('/api/investigations', wrap(async (req, res) => res.json(await store.investigations.list())));

  app.get('/api/investigations/:id', wrap(async (req, res) => {
    const inv = await store.investigations.get(req.params.id);
    if (!inv) return res.status(404).json({ error: 'Investigation not found' });
    res.json(inv);
  }));

  app.post('/api/investigations/:id/override', wrap(async (req, res) => {
    const { outcome, notes, analyst } = req.body || {};
    if (!notes || String(notes).trim().length < 4) return bad(res, 'Add a short justification for the override');
    try {
      res.json(await investigator.override(req.params.id, { outcome, notes: String(notes).slice(0, 1000), analyst }));
    } catch (err) {
      bad(res, err.message);
    }
  }));

  // ---- Containment -------------------------------------------------------
  app.get('/api/rules', wrap(async (req, res) => res.json(await store.rules.list())));

  app.post('/api/rules', wrap(async (req, res) => {
    const { target_ip, action, reason, analyst } = req.body || {};
    if (!isIPv4(target_ip)) return bad(res, 'Enter a valid IPv4 address');
    if (!['BLOCK', 'ISOLATE'].includes(action)) return bad(res, 'Action must be BLOCK or ISOLATE');
    if (!reason || String(reason).trim().length < 4) return bad(res, 'Give a reason so the next shift knows why');
    const result = await tools.execute_firewall_action({ action, target_ip, reason: String(reason).slice(0, 500), actor: analyst || 'Analyst' });
    if (result.status === 'ALREADY_ENFORCED') return res.status(409).json({ error: `${target_ip} already has an active ${action} rule (${result.rule.rule_id})` });
    res.status(201).json(result.rule);
  }));

  app.post('/api/rules/:id/toggle', wrap(async (req, res) => {
    const rule = await store.rules.get(req.params.id);
    if (!rule) return res.status(404).json({ error: 'Rule not found' });
    const updated = await store.rules.update(rule.rule_id, { is_active: !rule.is_active });
    await store.audit.add({ actor: (req.body && req.body.analyst) || 'Analyst', action: updated.is_active ? 'rule.enabled' : 'rule.disabled', target: rule.target_ip, detail: rule.rule_id });
    res.json(updated);
  }));

  app.post('/api/probe', wrap(async (req, res) => {
    const ip = (req.body || {}).target_ip;
    if (!isIPv4(ip)) return bad(res, 'Enter a valid IPv4 address');
    const result = await tools.verify_defense_state({ target_ip: ip });
    await store.audit.add({ actor: 'Analyst', action: 'probe.sent', target: ip, detail: result.status });
    res.json(result);
  }));

  // ---- Inventory & telemetry ---------------------------------------------
  app.get('/api/assets', wrap(async (req, res) => {
    const [assets, cves, alerts] = await Promise.all([store.assets.list(), store.cves.list(), store.alerts.list()]);
    const { exposureFor } = require('./src/engine/analysis');
    res.json(assets.map(a => ({
      ...a,
      exposures: cves.filter(c => exposureFor(a, c).exposed).map(c => ({ cve_id: c.cve_id, cvss_score: c.cvss_score, severity: c.severity })),
      open_alerts: alerts.filter(x => (x.dest_ip === a.ip_address || x.source_ip === a.ip_address) && ['NEW', 'INVESTIGATING', 'CONFIRMED'].includes(x.status)).length
    })));
  }));

  app.get('/api/cves', wrap(async (req, res) => {
    const list = await store.cves.list(req.query.q);
    res.json(list.map(({ match_terms, ...c }) => c));
  }));

  app.get('/api/logs', wrap(async (req, res) => {
    const { host_ip, log_type, client_ip } = req.query;
    res.json(await store.logs.list({ host_ip, log_type, client_ip, limit: Math.min(Number(req.query.limit) || 100, 300) }));
  }));

  app.get('/api/audit', wrap(async (req, res) => res.json(await store.audit.list(Math.min(Number(req.query.limit) || 60, 200)))));

  app.get('/api/search', wrap(async (req, res) => {
    const q = String(req.query.q || '').trim();
    if (q.length < 2) return res.json({ alerts: [], assets: [], cves: [], rules: [], investigations: [] });
    const needle = q.toLowerCase();
    const has = (...f) => f.some(x => x != null && String(x).toLowerCase().includes(needle));
    const [alerts, assets, cves, rules, invs] = await Promise.all([store.alerts.list({ q }), store.assets.list(), store.cves.list(q), store.rules.list(), store.investigations.list()]);
    res.json({
      alerts: alerts.slice(0, 6),
      assets: assets.filter(a => has(a.ip_address, a.hostname, a.os_version, a.owner)).slice(0, 4),
      cves: cves.slice(0, 4).map(({ match_terms, ...c }) => c),
      rules: rules.filter(r => has(r.rule_id, r.target_ip, r.reason)).slice(0, 4),
      investigations: invs.filter(i => has(i.investigation_id, i.alert_id, i.attacker_ip, i.target_ip)).slice(0, 4)
    });
  }));

  // ---- Settings ----------------------------------------------------------
  app.get('/api/config', wrap(async (req, res) => res.json(await store.config.get())));

  app.put('/api/config', wrap(async (req, res) => {
    const b = req.body || {};
    const next = {};
    if (b.autoContainmentThreshold !== undefined) {
      if (!['OFF', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(b.autoContainmentThreshold)) return bad(res, 'Invalid threshold');
      next.autoContainmentThreshold = b.autoContainmentThreshold;
    }
    if (b.isolateOnCompromise !== undefined) next.isolateOnCompromise = Boolean(b.isolateOnCompromise);
    if (b.engine !== undefined) {
      if (!['playbook', 'llm'].includes(b.engine)) return bad(res, 'Invalid engine');
      next.engine = b.engine;
    }
    if (b.maxIterations !== undefined) {
      const n = Number(b.maxIterations);
      if (!Number.isInteger(n) || n < 4 || n > 30) return bad(res, 'Max iterations must be 4-30');
      next.maxIterations = n;
    }
    if (b.alertRetentionDays !== undefined) {
      const n = Number(b.alertRetentionDays);
      if (!Number.isInteger(n) || n < 7 || n > 730) return bad(res, 'Retention must be 7-730 days');
      next.alertRetentionDays = n;
    }
    if (b.analystName !== undefined) next.analystName = String(b.analystName).trim().slice(0, 60) || 'On-call analyst';
    const saved = await store.config.set(next);
    await store.audit.add({ actor: saved.analystName, action: 'config.updated', target: 'platform', detail: Object.keys(next).join(', ') });
    res.json(saved);
  }));

  app.post('/api/reset', wrap(async (req, res) => {
    await store.reset();
    res.json({ ok: true });
  }));

  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
  app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err);
    if (res.headersSent) return res.end();
    res.status(500).json({ error: err.message || 'Internal error' });
  });

  app.listen(PORT, () => {
    console.log(`\n  Aegis Security  http://localhost:${PORT}`);
    console.log(`  Storage   ${store.label}${store.kind === 'local' ? ' (.data/sandbox.json)' : ''}`);
    console.log(`  Engine    ${investigator.llmAvailable ? `playbook + ${investigator.model}` : 'playbook (set GROQ_API_KEY to enable the LLM agent)'}`);
    if (warning) console.warn(`  Warning   ${warning}`);
    console.log('');
  });
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});