'use strict';

const express = require('express');
const { TOOL_DEFINITIONS } = require('./engine/tools');
const { isIP, newId, exposureFor, SEVERITY_RANK } = require('./engine/analysis');
const { normalizeAlert, normalizeLog, normalizeAsset, parseCsv, parseBatch } = require('./ingest/normalize');
const { CVE_RE } = require('./intel/nvd');
const { CLOSED_STATUSES } = require('./store/shared');
const { findSuppression } = require('./engine/suppress');
const { parseNmapXml, looksLikeNmap } = require('./ingest/nmap');
const detect = require('./engine/detect');
const { toAlerts } = require('./engine/sigma');

const SEVERITIES = Object.keys(SEVERITY_RANK);
const OPEN = ['NEW', 'INVESTIGATING', 'CONFIRMED'];
const MAX_BATCH = 5000;
const ENF_STATES = ['ENFORCED', 'PENDING', 'RECORDED', 'FAILED'];

const stripCve = ({ match_terms, cpe_matches, ...c }) => ({ ...c, cpe_ranges: (cpe_matches || []).length });
const isSevere = (c) => c.severity === 'CRITICAL' || Number(c.cvss_score) >= 7;
// Webhook URLs and signing secrets stay server-side; /api/notify/channels shows masked copies.
const publicConfig = ({ notifyChannels, ...cfg }) => cfg;
const intIn = (v, lo, hi) => Number.isInteger(Number(v)) && Number(v) >= lo && Number(v) <= hi;

function registerRoutes(app, ctx) {
  const { store, investigator, enforcer, nvd, reputation, hub, sigma, demo, warnings, env, wrap, bad, need, requireKey, actor, bootedAt, notifier } = ctx;
  const origin = (req) => env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`;
  const timeline = (alertId, body, req) => store.notes.add({ alert_id: alertId, kind: 'event', author: actor(req), author_id: req.user ? req.user.id : null, body });
  const tools = investigator.tools;
  const bigJson = express.json({ limit: '5mb', type: ['application/json', '*/*+json'] });
  const bigText = express.text({ limit: '5mb', type: ['application/x-ndjson', 'text/plain', 'text/csv', 'application/xml', 'text/xml'] });

  // ---- System --------------------------------------------------------------
  app.get('/api/health', wrap(async (req, res) => {
    const db = await store.health();
    res.json({
      status: db.ok ? 'ok' : 'degraded',
      storage: { kind: store.kind, label: store.label, ok: db.ok, detail: db.detail, warning: warnings.find((w) => /supabase|store/i.test(w)) || null },
      engine: { llm: investigator.llmAvailable, model: investigator.llmAvailable ? investigator.model : null },
      enforcement: { ...enforcer.describe(), warning: warnings.find((w) => /ENFORCEMENT/.test(w)) || null },
      intel: { nvd: Boolean(nvd), nvd_key: Boolean(env.NVD_API_KEY), reputation: Boolean(reputation && reputation.available), abuseipdb: Boolean(env.ABUSEIPDB_API_KEY), sources: reputation && reputation.describe ? reputation.describe().sources : [],
        feeds: hub && hub.available, vt_key: Boolean(env.VT_API_KEY), abusech_key: Boolean(env.ABUSECH_AUTH_KEY), misp_own: Boolean(env.MISP_URL && env.MISP_KEY) },
      sigma: sigma ? (({ loaded, loading, entries, version, loaded_at, error }) => ({ enabled: sigma.available, loaded, loading, rules: entries, version, loaded_at, error }))(sigma.status()) : { enabled: false },
      demo,
      pending_migration: store.pending ? store.pending.migration : null,
      tools: TOOL_DEFINITIONS.map((t) => t.function.name),
      uptime_s: Math.round((Date.now() - bootedAt) / 1000)
    });
  }));

  app.get('/api/overview', wrap(async (req, res) => {
    const [alerts, investigations, rules, assets, cves, audit] = await Promise.all([
      store.alerts.list({ lite: true, limit: 100000 }), store.investigations.list({ lite: true }), store.rules.list(), store.assets.list(), store.cves.list(), store.audit.list(12)
    ]);
    const open = alerts.filter((a) => OPEN.includes(a.status));
    const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((a) => a.severity === s).length]));
    const outcomes = investigations.reduce((m, i) => ({ ...m, [i.outcome]: (m[i.outcome] || 0) + 1 }), {});
    const active = rules.filter((r) => r.is_active);
    const enforcement = Object.fromEntries(ENF_STATES.map((s) => [s, 0]));
    for (const r of active) {
      const s = (r.enforcement && r.enforcement.status) || 'RECORDED';
      if (s in enforcement) enforcement[s] += 1;
    }

    // Mean time to respond: alert detection -> investigation closed, latest run per alert.
    const byId = new Map(alerts.map((a) => [a.alert_id, a]));
    const latest = new Map();
    for (const i of investigations) if (!latest.has(i.alert_id)) latest.set(i.alert_id, i);
    const durations = [...latest.values()].map((i) => {
      const a = byId.get(i.alert_id);
      return a ? (new Date(i.created_at) - new Date(a.detected_at)) / 60000 : null;
    }).filter((d) => d != null && d >= 0);
    const runTimes = investigations.map((i) => i.duration_ms).filter(Boolean);

    const now = Date.now();
    const hourly = Array.from({ length: 24 }, (_, i) => ({ h: 23 - i, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }));
    for (const a of alerts) {
      const h = Math.floor((now - new Date(a.detected_at)) / 3600000);
      if (h >= 0 && h < 24 && hourly[23 - h][a.severity] !== undefined) hourly[23 - h][a.severity] += 1;
    }

    const severe = cves.filter(isSevere);
    const exposedAssets = assets.filter((a) => severe.some((c) => exposureFor(a, c).exposed)).length;

    res.json({
      counts: { alerts: alerts.length, open: open.length, investigations: investigations.length, active_rules: active.length, assets: assets.length, exposed_assets: exposedAssets, cves: cves.length },
      by_severity: bySeverity,
      outcomes,
      enforcement,
      enforcement_mode: enforcer.mode,
      mttr_min: durations.length ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length) : null,
      avg_run_ms: runTimes.length ? Math.round(runTimes.reduce((a, b) => a + b, 0) / runTimes.length) : null,
      hourly,
      queue: open.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.detected_at.localeCompare(a.detected_at)).slice(0, 6),
      recent_investigations: investigations.slice(0, 5),
      activity: audit
    });
  }));

  // ---- Alerts --------------------------------------------------------------
  app.get('/api/alerts', wrap(async (req, res) => {
    const { severity, status, q, ip } = req.query;
    let assignee = req.query.assignee;
    if (assignee === 'me') assignee = req.user.id;
    else if (assignee === 'none') assignee = 'none';
    else if (assignee !== undefined) assignee = Number(assignee) || undefined;
    const statuses = status === 'OPEN' ? OPEN : undefined;
    res.json(await store.alerts.list({ severity, status: statuses ? undefined : status, statuses, q, ip: ip && isIP(ip) ? ip : undefined, assignee, lite: true, limit: Math.min(Number(req.query.limit) || 500, 2000) }));
  }));

  // Cheap badge counter for the navigation; never ships alert rows.
  app.get('/api/alerts/count', wrap(async (req, res) => {
    const [open, total] = await Promise.all([store.alerts.count({ open: true }), store.alerts.count()]);
    res.json({ open, total });
  }));

  app.get('/api/alerts/:id', wrap(async (req, res) => {
    const alert = await store.alerts.get(req.params.id);
    if (!alert) return bad(res, 'Alert not found', 404);
    const [investigations, asset, notes, suppression] = await Promise.all([
      store.investigations.forAlert(alert.alert_id), store.assets.get(alert.dest_ip), store.notes.list(alert.alert_id),
      alert.suppressed_by ? store.suppressions.get(alert.suppressed_by) : null
    ]);
    res.json({ alert, asset, notes, suppression, investigations });
  }));

  app.post('/api/alerts', need('respond'), wrap(async (req, res) => {
    const b = req.body || {};
    const severity = String(b.severity || 'HIGH').toUpperCase();
    if (!b.signature || String(b.signature).trim().length < 6) return bad(res, 'Signature must be at least 6 characters');
    if (!isIP(b.source_ip) || !isIP(b.dest_ip)) return bad(res, 'Source and destination must be valid IP addresses');
    if (!SEVERITIES.includes(severity)) return bad(res, 'Unknown severity');
    const port = Number(b.dest_port);
    if (!Number.isInteger(port) || port < 0 || port > 65535) return bad(res, 'Port must be 0-65535');
    if (!b.raw_payload || !String(b.raw_payload).trim()) return bad(res, 'Payload is required');
    const alert = await store.alerts.insert({
      alert_id: newId('ALERT'), signature: String(b.signature).trim().slice(0, 240), category: String(b.category || 'Manual submission').slice(0, 80),
      severity, source_ip: b.source_ip, dest_ip: b.dest_ip, dest_port: port, protocol: String(b.protocol || 'TCP').slice(0, 20),
      sensor: `console:${req.user.email}`.slice(0, 80), raw_payload: String(b.raw_payload).slice(0, 8000), status: 'NEW'
    });
    await store.audit.add({ actor: actor(req), action: 'alert.created', target: alert.alert_id, detail: alert.signature });
    res.status(201).json(alert);
  }));

  app.post('/api/alerts/:id/status', need('respond'), wrap(async (req, res) => {
    const allowed = ['NEW', 'CLOSED', 'FALSE_POSITIVE'];
    const status = String((req.body || {}).status || '').toUpperCase();
    if (!allowed.includes(status)) return bad(res, `Status must be one of ${allowed.join(', ')}`);
    const current = await store.alerts.get(req.params.id);
    if (!current) return bad(res, 'Alert not found', 404);
    if (current.status === 'INVESTIGATING') return bad(res, 'An investigation is running on this alert; wait for the verdict', 409);
    if (current.status === status) return res.json(current);
    const updated = await store.alerts.update(req.params.id, { status });
    await timeline(updated.alert_id, `Status changed from ${current.status} to ${status}`, req);
    await store.audit.add({ actor: actor(req), action: 'alert.status', target: req.params.id, detail: status });
    res.json(updated);
  }));

  // ---- Investigations ------------------------------------------------------
  app.post('/api/investigations/stream', need('respond'), wrap(async (req, res) => {
    const { alert_id, engine } = req.body || {};
    if (!alert_id) return bad(res, 'alert_id is required');
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    let closed = false;
    res.on('close', () => { closed = true; });
    const send = (data) => { if (!closed) res.write(`data: ${JSON.stringify(data)}\n\n`); };
    try {
      send({ type: 'start', alert_id, engine: engine === 'llm' && investigator.llmAvailable ? 'llm' : 'playbook' });
      await investigator.run(alert_id, send, { engine });
      await store.audit.add({ actor: actor(req), action: 'investigation.started', target: alert_id, detail: engine || 'default' });
    } catch (err) {
      send({ type: 'error', message: err.message });
    }
    send({ type: 'done' });
    res.end();
  }));

  app.get('/api/investigations', wrap(async (req, res) => res.json(await store.investigations.list({ lite: true, limit: Math.min(Number(req.query.limit) || 500, 5000) }))));

  app.get('/api/investigations/:id', wrap(async (req, res) => {
    const inv = await store.investigations.get(req.params.id);
    if (!inv) return bad(res, 'Investigation not found', 404);
    res.json(inv);
  }));

  app.post('/api/investigations/:id/override', need('respond'), wrap(async (req, res) => {
    const { outcome, notes } = req.body || {};
    if (!notes || String(notes).trim().length < 4) return bad(res, 'Add a short justification for the override');
    try {
      res.json(await investigator.override(req.params.id, { outcome, notes: String(notes).slice(0, 1000), analyst: actor(req) }));
    } catch (err) {
      bad(res, err.message);
    }
  }));

  // ---- Containment ---------------------------------------------------------
  app.get('/api/rules', wrap(async (req, res) => res.json(await store.rules.list())));

  app.post('/api/rules', need('respond'), wrap(async (req, res) => {
    const { target_ip, action, reason, ttl_hours } = req.body || {};
    if (!isIP(target_ip)) return bad(res, 'Enter a valid IP address');
    if (!['BLOCK', 'ISOLATE'].includes(action)) return bad(res, 'Action must be BLOCK or ISOLATE');
    if (!reason || String(reason).trim().length < 4) return bad(res, 'Give a reason so the next shift knows why');
    const noTtl = ttl_hours === undefined || ttl_hours === null || ttl_hours === '' || Number(ttl_hours) === 0;
    if (!noTtl && !intIn(ttl_hours, 1, 8760)) return bad(res, 'Expiry must be 1-8760 hours, or empty for a permanent rule');
    const result = await tools.execute_firewall_action({ action, target_ip, reason: String(reason).slice(0, 500), actor: actor(req), ttl_hours: noTtl ? null : Number(ttl_hours) });
    if (result.error) return bad(res, result.error);
    if (result.status === 'ALREADY_ENFORCED') return bad(res, `${target_ip} already has an active ${action} rule (${result.rule.rule_id})`, 409);
    await notifier.emit('containment', { rule: result.rule, severity: 'HIGH' }, { origin: origin(req) });
    res.status(201).json(result.rule);
  }));

  app.post('/api/rules/:id/toggle', need('respond'), wrap(async (req, res) => {
    const rule = await store.rules.get(req.params.id);
    if (!rule) return bad(res, 'Rule not found', 404);
    const activate = !rule.is_active;
    if (activate) {
      const clash = (await store.rules.activeFor(rule.target_ip)).find((r) => r.action === rule.action);
      if (clash) return bad(res, `${rule.target_ip} already has an active ${rule.action} rule (${clash.rule_id})`, 409);
    }
    const enforcement = activate ? await enforcer.apply(rule) : await enforcer.remove(rule);
    // Re-enabling a rule that already ran out makes it permanent; otherwise the next sweep would drop it again.
    const stale = activate && rule.expires_at && rule.expires_at <= new Date().toISOString();
    const updated = await store.rules.update(rule.rule_id, { is_active: activate, enforcement, ...(stale ? { expires_at: null } : {}) });
    await store.audit.add({ actor: actor(req), action: activate ? 'rule.enabled' : 'rule.disabled', target: rule.target_ip, detail: `${rule.rule_id} ${enforcement.mode}:${enforcement.status}` });
    res.json(updated);
  }));

  app.post('/api/rules/:id/verify', need('respond'), wrap(async (req, res) => {
    const rule = await store.rules.get(req.params.id);
    if (!rule) return bad(res, 'Rule not found', 404);
    if (!rule.is_active) return bad(res, 'Rule is disabled; enable it first', 409);
    const enforcement = await enforcer.verify(rule);
    const updated = await store.rules.update(rule.rule_id, { enforcement });
    await store.audit.add({ actor: actor(req), action: 'rule.verified', target: rule.target_ip, detail: `${rule.rule_id} ${enforcement.status}` });
    res.json(updated);
  }));

  // Reads the enforcement state back for an IP. Kept at /api/probe for older clients.
  const verifyIp = wrap(async (req, res) => {
    const ip = String((req.body || {}).target_ip || '').trim();
    if (!isIP(ip)) return bad(res, 'Enter a valid IP address');
    const result = await tools.verify_defense_state({ target_ip: ip });
    await store.audit.add({ actor: actor(req), action: 'enforcement.verified', target: ip, detail: result.status });
    res.json(result);
  });
  app.post('/api/verify', need('respond'), verifyIp);
  app.post('/api/probe', need('respond'), verifyIp);

  // ---- Assets --------------------------------------------------------------
  app.get('/api/assets', wrap(async (req, res) => {
    const [assets, cves, alerts] = await Promise.all([store.assets.list(), store.cves.list(), store.alerts.list({ statuses: OPEN, lite: true, limit: 100000 })]);
    res.json(assets.map((a) => ({
      ...a,
      exposures: cves.map((c) => ({ c, e: exposureFor(a, c) })).filter((x) => x.e.exposed)
        .map(({ c, e }) => ({ cve_id: c.cve_id, cvss_score: c.cvss_score, severity: c.severity, kev: Boolean(c.kev), evidence: e.evidence })),
      open_alerts: alerts.filter((x) => (x.dest_ip === a.ip_address || x.source_ip === a.ip_address) && OPEN.includes(x.status)).length
    })));
  }));

  const canEditAssets = (req, res, next) => (req.user && ['admin', 'analyst'].includes(req.user.role) ? next() : bad(res, 'The viewer role cannot change the inventory', 403));

  app.post('/api/assets', canEditAssets, wrap(async (req, res) => {
    const r = normalizeAsset({ ...(req.body || {}), source: 'manual' });
    if (r.error) return bad(res, r.error);
    if (await store.assets.get(r.asset.ip_address)) return bad(res, `${r.asset.ip_address} is already in the inventory`, 409);
    const [saved] = await store.assets.upsert([r.asset]);
    await store.audit.add({ actor: actor(req), action: 'asset.created', target: saved.ip_address, detail: saved.hostname });
    res.status(201).json(saved);
  }));

  app.put('/api/assets/:ip', canEditAssets, wrap(async (req, res) => {
    const existing = await store.assets.get(req.params.ip);
    if (!existing) return bad(res, 'Host not found', 404);
    const r = normalizeAsset({ ...existing, ...(req.body || {}), ip_address: existing.ip_address, source: existing.source || 'manual' });
    if (r.error) return bad(res, r.error);
    const [saved] = await store.assets.upsert([r.asset]);
    await store.audit.add({ actor: actor(req), action: 'asset.updated', target: saved.ip_address, detail: saved.hostname });
    res.json(saved);
  }));

  app.delete('/api/assets/:ip', canEditAssets, wrap(async (req, res) => {
    const ok = await store.assets.remove(req.params.ip);
    if (!ok) return bad(res, 'Host not found', 404);
    await store.audit.add({ actor: actor(req), action: 'asset.deleted', target: req.params.ip, detail: null });
    res.json({ ok: true });
  }));

  // CSV, JSON or Nmap XML. Discovery sources (nmap, agent) refresh what they can
  // observe and keep what an analyst set by hand: owner, criticality and WAF.
  function readAssetRows(body) {
    if (typeof body === 'string') {
      const t = body.trim();
      if (looksLikeNmap(t)) return { rows: parseNmapXml(t), format: 'nmap' };
      if (t.startsWith('[') || t.startsWith('{')) {
        let v;
        try { v = JSON.parse(t); } catch { return { error: 'Body is not valid JSON' }; }
        return { rows: Array.isArray(v) ? v : Array.isArray(v.assets) ? v.assets : [v], format: 'json' };
      }
      return { rows: parseCsv(t), format: 'csv' };
    }
    if (Array.isArray(body)) return { rows: body, format: 'json' };
    if (body && Array.isArray(body.assets)) return { rows: body.assets, format: 'json' };
    if (body && typeof body === 'object' && (body.ip_address || body.ip)) return { rows: [body], format: 'json' };
    return { error: 'Send CSV, a JSON array of hosts, or Nmap XML (nmap -sV -oX)' };
  }

  async function importAssets(req, res, defaultSource) {
    const parsed = readAssetRows(req.body);
    if (parsed.error) return bad(res, parsed.error);
    const { rows, format } = parsed;
    if (!rows.length) return bad(res, format === 'nmap' ? 'The scan has no hosts that were up' : 'No rows found');
    if (rows.length > MAX_BATCH) return bad(res, `At most ${MAX_BATCH} hosts per import`);
    const good = []; const errors = [];
    rows.forEach((row, i) => {
      const r = normalizeAsset({ source: defaultSource, ...row });
      if (r.error) errors.push({ row: i + 1, error: r.error });
      else good.push({ asset: r.asset, given: row });
    });
    let created = 0;
    if (good.length) {
      const existing = new Map((await store.assets.list()).map((a) => [a.ip_address, a]));
      const merged = good.map(({ asset, given }) => {
        const prev = existing.get(asset.ip_address);
        if (!prev) { created += 1; return asset; }
        const out = { ...asset };
        for (const k of ['owner', 'criticality', 'waf_enabled']) {
          const supplied = given[k] !== undefined && given[k] !== '' || (k === 'waf_enabled' && given.waf !== undefined);
          if (!supplied) out[k] = prev[k];
        }
        // A network scan sees listening services only; keep packages an agent or analyst recorded.
        if (asset.source === 'nmap') out.installed_packages = [...new Set([...(prev.installed_packages || []), ...asset.installed_packages])].slice(0, 400);
        if (/^host-/.test(asset.hostname) && prev.hostname) out.hostname = prev.hostname;
        if (asset.os_version === 'Unknown' && prev.os_version) { out.os_version = prev.os_version; out.os_family = prev.os_family; }
        return out;
      });
      await store.assets.upsert(merged);
    }
    await store.audit.add({ actor: actor(req), action: 'asset.imported', target: `${good.length} hosts`, detail: [format, created && `${created} new`, errors.length && `${errors.length} rows rejected`].filter(Boolean).join(', ') });
    res.json({ imported: good.length, created, updated: good.length - created, format, errors: errors.slice(0, 50) });
  }

  app.post('/api/assets/import', canEditAssets, bigJson, bigText, wrap((req, res) => importAssets(req, res, 'import')));

  // ---- CVEs ----------------------------------------------------------------
  app.get('/api/cves', wrap(async (req, res) => res.json((await store.cves.list(req.query.q)).map(stripCve))));

  app.post('/api/cves', need('configure'), wrap(async (req, res) => {
    const id = String((req.body || {}).cve_id || '').trim().toUpperCase();
    if (!CVE_RE.test(id)) return bad(res, 'Enter a CVE id such as CVE-2024-3400');
    try {
      const rec = await nvd.fetchCve(id);
      if (!rec) return bad(res, `NVD has no record for ${id}`, 404);
      await store.cves.upsert([rec]);
      await store.audit.add({ actor: actor(req), action: 'cve.added', target: id, detail: `CVSS ${rec.cvss_score}${rec.kev ? ' KEV' : ''}` });
      res.status(201).json(stripCve(rec));
    } catch (err) {
      bad(res, `Could not reach NVD: ${err.message}`, 502);
    }
  }));

  app.delete('/api/cves/:id', need('configure'), wrap(async (req, res) => {
    const ok = await store.cves.remove(req.params.id.toUpperCase());
    if (!ok) return bad(res, 'CVE not found', 404);
    await store.audit.add({ actor: actor(req), action: 'cve.removed', target: req.params.id.toUpperCase(), detail: null });
    res.json({ ok: true });
  }));

  let syncing = null;
  app.post('/api/cves/sync', need('configure'), wrap(async (req, res) => {
    if (syncing) return bad(res, 'A sync is already running', 409);
    const extra = Array.isArray((req.body || {}).ids) ? req.body.ids.map((x) => String(x).trim().toUpperCase()).filter((x) => CVE_RE.test(x)) : [];
    const ids = [...new Set([...(await store.cves.list()).map((c) => c.cve_id).filter((x) => CVE_RE.test(x)), ...extra])].slice(0, 200);
    const updated = []; const failed = [];
    syncing = (async () => {
      for (const id of ids) {
        try {
          const rec = await nvd.fetchCve(id);
          if (rec) { await store.cves.upsert([rec]); updated.push(id); } else failed.push({ id, error: 'Not found in NVD' });
        } catch (err) {
          failed.push({ id, error: err.message });
          // Network down or rate limited: stop rather than burn through the list.
          if (/fetch failed|ENOTFOUND|ECONN|timeout|rate limit/i.test(err.message)) {
            for (const rest of ids.slice(ids.indexOf(id) + 1)) failed.push({ id: rest, error: 'Skipped after previous failure' });
            break;
          }
        }
      }
    })();
    try { await syncing; } finally { syncing = null; }
    await store.audit.add({ actor: actor(req), action: 'cve.synced', target: 'NVD', detail: `${updated.length} updated, ${failed.length} failed` });
    res.json({ updated: updated.length, ids: updated, failed });
  }));

  // ---- Telemetry, audit, search ----------------------------------------------
  app.get('/api/logs', wrap(async (req, res) => {
    const { host_ip, log_type, client_ip } = req.query;
    res.json(await store.logs.list({ host_ip, log_type, client_ip, limit: Math.min(Number(req.query.limit) || 100, 500) }));
  }));

  app.get('/api/audit', wrap(async (req, res) => res.json(await store.audit.list(Math.min(Number(req.query.limit) || 60, 500)))));

  app.get('/api/search', wrap(async (req, res) => {
    const q = String(req.query.q || '').trim();
    if (q.length < 2) return res.json({ ip: null, alerts: [], assets: [], cves: [], rules: [], investigations: [] });
    const needle = q.toLowerCase();
    const has = (...f) => f.some((x) => x != null && String(x).toLowerCase().includes(needle));
    const [alerts, assets, cves, rules, invs] = await Promise.all([store.alerts.list({ q, lite: true, limit: 6 }), store.assets.list(), store.cves.list(q), store.rules.list(), store.investigations.list({ lite: true, limit: 2000 })]);
    res.json({
      ip: isIP(q) ? q : null,
      alerts,
      assets: assets.filter((a) => has(a.ip_address, a.hostname, a.os_version, a.owner)).slice(0, 4),
      cves: cves.slice(0, 4).map(stripCve),
      rules: rules.filter((r) => has(r.rule_id, r.target_ip, r.reason)).slice(0, 4),
      investigations: invs.filter((i) => has(i.investigation_id, i.alert_id, i.attacker_ip, i.target_ip)).slice(0, 4)
    });
  }));

  // ---- Settings ------------------------------------------------------------
  app.get('/api/config', wrap(async (req, res) => res.json(publicConfig(await store.config.get()))));

  app.put('/api/config', need('configure'), wrap(async (req, res) => {
    const b = req.body || {};
    const next = {};
    if (b.autoContainmentThreshold !== undefined) {
      if (!['OFF', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(b.autoContainmentThreshold)) return bad(res, 'Invalid threshold');
      next.autoContainmentThreshold = b.autoContainmentThreshold;
    }
    if (b.isolateOnCompromise !== undefined) next.isolateOnCompromise = Boolean(b.isolateOnCompromise);
    if (b.autoInvestigate !== undefined) next.autoInvestigate = Boolean(b.autoInvestigate);
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
    if (b.autoBlockTtlHours !== undefined) {
      if (!intIn(b.autoBlockTtlHours, 0, 720)) return bad(res, 'Automatic block expiry must be 0-720 hours (0 keeps blocks until removed)');
      next.autoBlockTtlHours = Number(b.autoBlockTtlHours);
    }
    for (const k of ['slaCritical', 'slaHigh', 'slaMedium', 'slaLow']) {
      if (b[k] === undefined) continue;
      if (!intIn(b[k], 1, 10080)) return bad(res, 'Response targets must be 1-10080 minutes');
      next[k] = Number(b[k]);
    }
    if (b.detectEnabled !== undefined) next.detectEnabled = Boolean(b.detectEnabled);
    for (const [k, lo, hi, what] of [['detectSshThreshold', 2, 1000, 'SSH failure threshold'], ['detectScanThreshold', 3, 5000, 'Scanner threshold'], ['detectWindowMin', 1, 1440, 'Detection window']]) {
      if (b[k] === undefined) continue;
      if (!intIn(b[k], lo, hi)) return bad(res, `${what} must be ${lo}-${hi}`);
      next[k] = Number(b[k]);
    }
    if (b.detectDisabled !== undefined) {
      const ids = detect.RULES.map((r) => r.id);
      if (!Array.isArray(b.detectDisabled) || b.detectDisabled.some((x) => !ids.includes(x))) return bad(res, `detectDisabled must list rule ids from: ${ids.join(', ')}`);
      next.detectDisabled = [...new Set(b.detectDisabled)];
    }
    if (b.approvalMode !== undefined) {
      if (!['auto', 'confidence', 'manual'].includes(b.approvalMode)) return bad(res, 'Approval mode must be auto, confidence or manual');
      next.approvalMode = b.approvalMode;
    }
    for (const k of ['approvalAutoAt', 'approvalQuickAt', 'approvalReviewAt']) {
      if (b[k] === undefined) continue;
      if (!intIn(b[k], 1, 100)) return bad(res, 'Confidence bands must be 1-100');
      next[k] = Number(b[k]);
    }
    if (b.approvalExpiryHours !== undefined) {
      if (!intIn(b.approvalExpiryHours, 1, 720)) return bad(res, 'Approval expiry must be 1-720 hours');
      next.approvalExpiryHours = Number(b.approvalExpiryHours);
    }
    if (b.sigmaEnabled !== undefined) next.sigmaEnabled = Boolean(b.sigmaEnabled);
    if (b.sigmaMinLevel !== undefined) {
      if (!['low', 'medium', 'high', 'critical'].includes(b.sigmaMinLevel)) return bad(res, 'Sigma minimum level must be low, medium, high or critical');
      next.sigmaMinLevel = b.sigmaMinLevel;
    }
    if (b.sigmaDisabled !== undefined) {
      if (!Array.isArray(b.sigmaDisabled) || b.sigmaDisabled.length > 2000 || b.sigmaDisabled.some((x) => typeof x !== 'string' || x.length > 64)) return bad(res, 'sigmaDisabled must be a list of Sigma rule ids');
      next.sigmaDisabled = [...new Set(b.sigmaDisabled)];
    }
    if (!Object.keys(next).length) return bad(res, 'Nothing to change');
    const bands = { ...(await store.config.get()), ...next };
    if (!(bands.approvalAutoAt > bands.approvalQuickAt && bands.approvalQuickAt > bands.approvalReviewAt)) return bad(res, 'Confidence bands must descend: auto > quick review > analyst review');
    const saved = await store.config.set(next);
    await store.audit.add({ actor: actor(req), action: 'config.updated', target: 'platform', detail: Object.keys(next).join(', ') });
    res.json(publicConfig(saved));
  }));

  app.post('/api/reset', need('manage'), wrap(async (req, res) => {
    if (!demo) return bad(res, 'Reset is only available when AEGIS_DEMO=1', 403);
    await store.reset();
    await store.audit.add({ actor: actor(req), action: 'demo.reset', target: 'platform', detail: null });
    res.json({ ok: true });
  }));

  // ---- Sensor ingest (API key, scope "ingest") --------------------------------
  // Background triage for ingested alerts when config.autoInvestigate is on.
  const triageQueue = [];
  let triaging = false;
  async function drainTriage() {
    if (triaging) return;
    triaging = true;
    try {
      while (triageQueue.length) {
        const id = triageQueue.shift();
        try { await investigator.run(id, () => {}, { pace: 0 }); } catch (err) { console.warn(`  Auto-investigation of ${id} failed: ${err.message}`); }
      }
    } finally { triaging = false; }
  }

  app.post('/api/ingest/alerts', requireKey('ingest'), bigJson, bigText, wrap(async (req, res) => {
    const events = parseBatch(req);
    if (!events.length) return bad(res, 'Empty batch. Send EVE JSON lines, a JSON array, or {"events": [...]}');
    if (events.length > MAX_BATCH) return bad(res, `At most ${MAX_BATCH} events per request`, 413);
    const good = []; const rejected = []; let skipped = 0;
    events.forEach((e, index) => {
      if (typeof e === 'string') { rejected.push({ index, error: 'Line is not valid JSON' }); return; }
      const r = normalizeAlert(e);
      if (r.skip) skipped += 1;
      else if (r.error) rejected.push({ index, error: r.error });
      else good.push({ ...r.alert, sensor: r.alert.sensor === 'api' ? `key:${req.apiKey.name}`.slice(0, 80) : r.alert.sensor });
    });
    const { inserted, duplicates, quiet } = await landAlerts(good, req, { action: 'ingest.alerts', note: rejected.length ? `${rejected.length} rejected` : null });
    res.status(rejected.length && !inserted.length && !duplicates ? 400 : 202).json({ accepted: inserted.length, suppressed: quiet.length, duplicates, skipped, rejected: rejected.slice(0, 100) });
  }));

  // Suppression, idempotent insert, background triage and notification for alerts from
  // any source (sensors through the ingest API, or Aegis' own log detections).
  async function landAlerts(good, req, { action, note = null }) {
    // Tuning rules close known-benign traffic on arrival. The alert is still stored
    // (closed as a false positive and tagged with the rule) so nothing disappears silently.
    const at = new Date().toISOString();
    const supps = good.length ? (await store.suppressions.list()).filter((s) => s.enabled) : [];
    const hits = {};
    for (const a of good) {
      const s = supps.length ? findSuppression(supps, a, at) : null;
      if (!s) continue;
      a.status = 'FALSE_POSITIVE';
      a.suppressed_by = s.id;
      hits[s.id] = (hits[s.id] || 0) + 1;
    }
    const { inserted, duplicates } = good.length ? await store.alerts.insertMany(good) : { inserted: [], duplicates: 0 };
    const fresh = new Set(inserted);
    const landed = good.filter((a) => fresh.has(a.alert_id));
    const quiet = landed.filter((a) => a.suppressed_by);
    const loud = landed.filter((a) => !a.suppressed_by);
    if (quiet.length) {
      const counted = {};
      for (const a of quiet) counted[a.suppressed_by] = (counted[a.suppressed_by] || 0) + 1;
      await store.suppressions.recordHits(counted, at);
    }
    if (inserted.length) {
      await store.audit.add({ actor: actor(req), action, target: `${inserted.length} alerts`, detail: [note, quiet.length && `${quiet.length} suppressed`].filter(Boolean).join(', ') || null });
      const cfg = await store.config.get();
      if (cfg.autoInvestigate) {
        const floor = SEVERITY_RANK.HIGH;
        triageQueue.push(...loud.filter((a) => SEVERITY_RANK[a.severity] >= floor).map((a) => a.alert_id).slice(0, 50));
        setImmediate(drainTriage);
      }
      if (loud.length) await notifier.emit('alert', { alerts: loud }, { origin: origin(req) });
    }
    return { inserted, duplicates, quiet, loud };
  }
  ctx.landAlerts = landAlerts;

  // Built-in detections: judge each client that appears in the batch against its stored
  // history, so a brute force split over many agent posts is still seen as one burst.
  async function runDetection(batch, req) {
    const cfg = await store.config.get();
    if (cfg.detectEnabled === false) return { raised: 0, ids: [] };
    const sig = await runSigma(batch, req, cfg);
    const clients = [...new Set(batch.map((l) => l.client_ip).filter(Boolean))].slice(0, 100);
    const hosts = new Set(batch.map((l) => l.host_ip));
    if (!clients.length) return sig;
    const history = [];
    for (let i = 0; i < clients.length; i += 10) {
      const part = await Promise.all(clients.slice(i, i + 10).map((c) => store.logs.list({ client_ip: c, limit: 1000 })));
      for (const rows of part) history.push(...rows.filter((l) => hosts.has(l.host_ip)));
    }
    const now = Math.max(...batch.map((l) => new Date(l.logged_at).getTime()));
    const found = detect.evaluate(history, cfg, { now });
    if (!found.length) return sig;
    const { inserted } = await landAlerts(found, req, { action: 'detect.raised', note: [...new Set(found.map((a) => a.external_ref.split(' ')[0].replace('aegis:', '')))].join(', ') });
    return { raised: inserted.length + sig.raised, ids: [...inserted, ...sig.ids], sigma: sig.sigma };
  }

  // SigmaHQ rules are single-event, so they run over the new lines only. If the rule
  // set is still downloading the batch is not held up; the next one gets scanned.
  async function runSigma(batch, req, cfg) {
    if (!sigma || !sigma.available || cfg.sigmaEnabled === false) return { raised: 0, ids: [] };
    const s = await sigma.scan(batch, { budgetMs: 3000, minLevel: cfg.sigmaMinLevel || 'medium', disabled: cfg.sigmaDisabled || [] });
    if (!s) return { raised: 0, ids: [], sigma: 'loading' };
    if (!s.matches.length) return { raised: 0, ids: [], sigma: s.rules };
    const found = toAlerts(s.matches);
    const { inserted } = await landAlerts(found, req, { action: 'detect.raised', note: `sigma: ${[...new Set(s.matches.map((m) => m.rule.title))].slice(0, 4).join(', ')}`.slice(0, 300) });
    return { raised: inserted.length, ids: inserted, sigma: s.rules };
  }

  app.post('/api/ingest/logs', requireKey('ingest'), bigJson, bigText, wrap(async (req, res) => {
    const events = parseBatch(req);
    if (!events.length) return bad(res, 'Empty batch');
    if (events.length > MAX_BATCH * 4) return bad(res, `At most ${MAX_BATCH * 4} lines per request`, 413);
    const defaults = { host_ip: req.query.host_ip, log_type: req.query.log_type };
    const good = []; const rejected = [];
    events.forEach((e, index) => {
      const r = normalizeLog(e, defaults);
      if (r.error) rejected.push({ index, error: r.error }); else good.push(r.log);
    });
    let detections = { raised: 0, ids: [] };
    if (good.length) {
      await store.logs.insertMany(good);
      try { detections = await runDetection(good, req); } catch (err) { console.warn('  Detection failed:', err.message); detections = { raised: 0, ids: [], error: err.message }; }
    }
    res.status(rejected.length && !good.length ? 400 : 202).json({ accepted: good.length, rejected: rejected.slice(0, 100), detections });
  }));

  // Host inventory from the Aegis agent or a scheduled scanner.
  app.post('/api/ingest/assets', requireKey('ingest'), bigJson, bigText, wrap((req, res) => importAssets(req, res, 'agent')));

  // ---- Firewall pull feeds (API key, scope "feed") ----------------------------
  // Plain text, one address per line: the format PAN-OS EDL, FortiGate external
  // threat feeds and pfSense/OPNsense URL tables all accept.
  const feed = (action) => wrap(async (req, res) => {
    await expireRules();
    const at = new Date().toISOString();
    const rules = (await store.rules.active(action)).filter((r) => !r.expires_at || r.expires_at > at);
    const pending = rules.filter((r) => enforcer.mode === 'feed' && (!r.enforcement || r.enforcement.status === 'PENDING'));
    for (const r of pending) {
      await store.rules.update(r.rule_id, { enforcement: { mode: 'feed', status: 'ENFORCED', detail: `Pulled by ${req.apiKey.name} at ${at}`, puller: req.apiKey.name, at } });
    }
    if (pending.length) await store.audit.add({ actor: actor(req), action: 'feed.pulled', target: `${action.toLowerCase()} feed`, detail: `${pending.length} new rules picked up` });
    const ips = [...new Set(rules.map((r) => r.target_ip))];
    res.set({ 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Aegis-Count': String(ips.length) });
    res.send(ips.length ? `${ips.join('\n')}\n` : '');
  });
  app.get('/api/feeds/blocklist.txt', requireKey('feed'), feed('BLOCK'));
  app.get('/api/feeds/isolate.txt', requireKey('feed'), feed('ISOLATE'));

  // ---- Expiry and retention ----------------------------------------------------
  // Time-boxed rules are switched off (and pulled from the enforcement backend) once
  // they run out. Runs hourly, from the daily cron, and before every feed pull so a
  // firewall never receives an address whose block has lapsed.
  async function expireRules() {
    const now = new Date().toISOString();
    let due;
    try { due = await store.rules.expiredActive(now); } catch (err) { console.warn('  Rule expiry failed:', err.message); return 0; }
    for (const r of due) {
      let enforcement;
      try { enforcement = await enforcer.remove(r); } catch (err) { enforcement = { mode: enforcer.mode, status: 'FAILED', detail: `Removal failed: ${err.message}`, at: now }; }
      await store.rules.update(r.rule_id, { is_active: false, enforcement });
      await store.audit.add({ actor: 'system', action: 'rule.expired', target: r.target_ip, detail: `${r.rule_id} ${r.action} expired at ${r.expires_at}` });
    }
    return due.length;
  }

  async function retention() {
    const expired = await expireRules();
    const lapsed = ctx.approvals ? await ctx.approvals.expire().catch((err) => { console.warn('  Approval expiry failed:', err.message); return 0; }) : 0;
    try {
      const cfg = await store.config.get();
      const days = Number(cfg.alertRetentionDays) || 90;
      const before = new Date(Date.now() - days * 86400000).toISOString();
      const alerts = await store.alerts.purgeClosed(before);
      const logs = await store.logs.purge(before);
      if (alerts || logs) await store.audit.add({ actor: 'system', action: 'retention.purged', target: `${days} days`, detail: `${alerts} closed alerts, ${logs} log lines` });
      return { alerts, logs, expired_rules: expired, expired_approvals: lapsed };
    } catch (err) {
      console.warn('  Retention job failed:', err.message);
      return { error: err.message, expired_rules: expired };
    }
  }
  const timer = setInterval(retention, 3600000);
  timer.unref();

  // Called by Vercel Cron (vercel.json) with Authorization: Bearer $CRON_SECRET.
  app.get('/api/cron/retention', wrap(async (req, res) => {
    const secret = env.CRON_SECRET;
    const given = Buffer.from(req.get('authorization') || '');
    const want = Buffer.from(`Bearer ${secret}`);
    if (!secret || given.length !== want.length || !require('crypto').timingSafeEqual(given, want)) return bad(res, 'Forbidden', 403);
    res.json(await retention());
  }));
  return { retention, expireRules, stop: () => clearInterval(timer), closedStatuses: CLOSED_STATUSES };
}

module.exports = { registerRoutes };