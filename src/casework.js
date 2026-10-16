'use strict';

const crypto = require('crypto');
const { isIP, isInternal, SEVERITY_RANK } = require('./engine/analysis');
const { matches, normalizeSuppression, isLive } = require('./engine/suppress');
const { validateChannel, publicChannel, MAX_CHANNELS } = require('./notify');
const { CLOSED_STATUSES } = require('./store/shared');

// Case work on top of the core routes: ownership and notes, bulk triage,
// suppression rules, notification channels, per-IP profiles, reporting and exports.

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const OPEN = ['NEW', 'INVESTIGATING', 'CONFIRMED'];
const SETTABLE = ['NEW', 'CLOSED', 'FALSE_POSITIVE'];
const SLA_KEYS = { CRITICAL: 'slaCritical', HIGH: 'slaHigh', MEDIUM: 'slaMedium', LOW: 'slaLow' };
// Enterprise ATT&CK tactics in kill-chain order.
const TACTICS = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion',
  'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];

const minutes = (a, b) => (new Date(b) - new Date(a)) / 60000;
const round1 = (n) => (n == null ? null : Math.round(n * 10) / 10);
function stats(values) {
  if (!values.length) return { n: 0, mean: null, median: null, p90: null };
  const v = [...values].sort((a, b) => a - b);
  const at = (q) => v[Math.min(v.length - 1, Math.floor(q * (v.length - 1) + 0.5))];
  return { n: v.length, mean: round1(v.reduce((a, b) => a + b, 0) / v.length), median: round1(at(0.5)), p90: round1(at(0.9)) };
}

// Spreadsheet apps execute cells that start with = + - @; prefix them so an
// attacker-controlled signature cannot become a formula in someone's Excel.
function csvCell(v) {
  if (v == null) return '';
  let s = typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
const csv = (cols, rows) => `${cols.join(',')}\r\n${rows.map((r) => cols.map((c) => csvCell(r[c])).join(',')).join('\r\n')}${rows.length ? '\r\n' : ''}`;

function tacticOf(raw) {
  const s = String(raw || '').toLowerCase();
  if (!s) return null;
  return TACTICS.find((t) => s.includes(t.toLowerCase())) || 'Other';
}

function registerCasework(app, ctx) {
  const { store, notifier, reputation, env, wrap, bad, need, actor } = ctx;
  const production = env.NODE_ENV === 'production';
  const origin = (req) => env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`;
  const event = (alertId, body, req) => store.notes.add({ alert_id: alertId, kind: 'event', author: req ? actor(req) : 'system', author_id: req && req.user ? req.user.id : null, body: String(body).slice(0, 4000) });

  // ---- People who can own a case ----------------------------------------------
  app.get('/api/users/assignable', wrap(async (req, res) => {
    const users = await store.users.list();
    res.json(users.filter((u) => !u.disabled && u.role !== 'viewer').map((u) => ({ id: u.id, name: u.name, role: u.role })));
  }));

  async function resolveAssignee(userId) {
    if (userId === null || userId === undefined || userId === '') return { user: null };
    const u = await store.users.byId(Number(userId));
    if (!u || u.disabled) return { error: 'That user does not exist or is disabled' };
    if (u.role === 'viewer') return { error: 'Read-only users cannot own a case' };
    return { user: u };
  }

  // ---- Assignment and notes ---------------------------------------------------
  app.post('/api/alerts/:id/assign', need('respond'), wrap(async (req, res) => {
    const alert = await store.alerts.get(req.params.id);
    if (!alert) return bad(res, 'Alert not found', 404);
    const { user, error } = await resolveAssignee((req.body || {}).user_id);
    if (error) return bad(res, error);
    if ((alert.assignee_id || null) === (user ? user.id : null)) return res.json(alert);
    const now = new Date().toISOString();
    const updated = await store.alerts.update(alert.alert_id, {
      assignee_id: user ? user.id : null, assignee_name: user ? user.name : null,
      ...(user && !alert.acknowledged_at ? { acknowledged_at: now } : {})
    });
    const text = user ? (user.id === req.user.id ? `${user.name} took the case` : `Assigned to ${user.name}`) : 'Unassigned';
    await event(alert.alert_id, alert.assignee_name && user ? `${text} (was ${alert.assignee_name})` : text, req);
    await store.audit.add({ actor: actor(req), action: 'alert.assigned', target: alert.alert_id, detail: user ? user.name : 'nobody' });
    res.json(updated);
  }));

  app.get('/api/alerts/:id/notes', wrap(async (req, res) => res.json(await store.notes.list(req.params.id))));

  app.post('/api/alerts/:id/notes', need('respond'), wrap(async (req, res) => {
    const body = String((req.body || {}).body || '').trim();
    if (!body) return bad(res, 'Write something first');
    if (body.length > 4000) return bad(res, 'Notes are limited to 4000 characters');
    const alert = await store.alerts.get(req.params.id);
    if (!alert) return bad(res, 'Alert not found', 404);
    const note = await store.notes.add({ alert_id: alert.alert_id, kind: 'note', author: actor(req), author_id: req.user.id, body });
    if (!alert.acknowledged_at) await store.alerts.update(alert.alert_id, { acknowledged_at: note.created_at });
    await store.audit.add({ actor: actor(req), action: 'alert.note', target: alert.alert_id, detail: body.slice(0, 80) });
    res.status(201).json(note);
  }));

  // ---- Bulk triage --------------------------------------------------------------
  app.post('/api/alerts/bulk', need('respond'), wrap(async (req, res) => {
    const b = req.body || {};
    const ids = [...new Set((Array.isArray(b.ids) ? b.ids : []).map(String))];
    if (!ids.length) return bad(res, 'Select at least one alert');
    if (ids.length > 500) return bad(res, 'At most 500 alerts per bulk action');
    const all = await Promise.all(ids.map((id) => store.alerts.get(id)));
    // An alert under investigation belongs to the engine until the run finishes.
    const found = all.filter(Boolean).filter((a) => a.status !== 'INVESTIGATING');
    const skipped = ids.length - found.length;
    if (!found.length) return bad(res, 'None of the selected alerts can be changed right now', 409);
    let patch; let note;
    if (b.action === 'assign') {
      const { user, error } = await resolveAssignee(b.user_id);
      if (error) return bad(res, error);
      patch = { assignee_id: user ? user.id : null, assignee_name: user ? user.name : null };
      note = user ? `Assigned to ${user.name} (bulk)` : 'Unassigned (bulk)';
    } else if (b.action === 'status') {
      const status = String(b.status || '').toUpperCase();
      if (!SETTABLE.includes(status)) return bad(res, `Status must be one of ${SETTABLE.join(', ')}`);
      patch = { status };
      note = `Status set to ${status} (bulk)`;
    } else return bad(res, 'Action must be assign or status');
    const now = new Date().toISOString();
    const needsAck = found.filter((a) => !a.acknowledged_at && patch.assignee_id).map((a) => a.alert_id);
    const updated = await store.alerts.updateMany(found.map((a) => a.alert_id), patch);
    if (needsAck.length) await store.alerts.updateMany(needsAck, { acknowledged_at: now });
    await store.notes.addMany(found.map((a) => ({ alert_id: a.alert_id, kind: 'event', author: actor(req), author_id: req.user.id, body: note })));
    await store.audit.add({ actor: actor(req), action: 'alert.bulk', target: `${found.length} alerts`, detail: note });
    res.json({ updated: updated.length, skipped });
  }));

  // ---- Suppression rules -----------------------------------------------------------
  app.get('/api/suppressions', wrap(async (req, res) => {
    const at = new Date().toISOString();
    res.json((await store.suppressions.list()).map((s) => ({ ...s, live: isLive(s, at) })));
  }));

  // How many alerts from the last N days a draft rule would have caught.
  app.post('/api/suppressions/preview', need('respond'), wrap(async (req, res) => {
    const r = normalizeSuppression({ name: 'preview', ...(req.body || {}) });
    if (r.error) return bad(res, r.error);
    const days = Math.min(Math.max(Number((req.body || {}).days) || 30, 1), 90);
    const alerts = await store.alerts.list({ since: new Date(Date.now() - days * 86400000).toISOString(), limit: 20000 });
    const hit = alerts.filter((a) => matches(r.rule, a));
    const bySig = {};
    for (const a of hit) bySig[a.signature] = (bySig[a.signature] || 0) + 1;
    res.json({
      days, scanned: alerts.length, matched: hit.length, open: hit.filter((a) => OPEN.includes(a.status)).length,
      critical: hit.filter((a) => a.severity === 'CRITICAL').length,
      signatures: Object.entries(bySig).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([signature, n]) => ({ signature, n })),
      sample: hit.slice(0, 5).map((a) => ({ alert_id: a.alert_id, signature: a.signature, source_ip: a.source_ip, dest_ip: a.dest_ip, severity: a.severity }))
    });
  }));

  app.post('/api/suppressions', need('configure'), wrap(async (req, res) => {
    const b = req.body || {};
    const r = normalizeSuppression(b);
    if (r.error) return bad(res, r.error);
    const rule = await store.suppressions.insert({ ...r.rule, created_by: actor(req) });
    let closed = 0;
    if (b.apply_to_open) {
      const open = (await store.alerts.list({ status: 'NEW', limit: 20000 })).filter((a) => matches(rule, a));
      if (open.length) {
        await store.alerts.updateMany(open.map((a) => a.alert_id), { status: 'FALSE_POSITIVE', suppressed_by: rule.id });
        await store.notes.addMany(open.map((a) => ({ alert_id: a.alert_id, kind: 'event', author: actor(req), author_id: req.user.id, body: `Closed as false positive by suppression rule "${rule.name}"` })));
        await store.suppressions.recordHits({ [rule.id]: open.length }, new Date().toISOString());
        closed = open.length;
      }
    }
    await store.audit.add({ actor: actor(req), action: 'suppression.created', target: rule.name, detail: closed ? `${closed} open alerts closed` : null });
    res.status(201).json({ ...(await store.suppressions.get(rule.id)), closed });
  }));

  app.patch('/api/suppressions/:id', need('configure'), wrap(async (req, res) => {
    const existing = await store.suppressions.get(req.params.id);
    if (!existing) return bad(res, 'Rule not found', 404);
    const r = normalizeSuppression(req.body || {}, { partial: true });
    if (r.error) return bad(res, r.error);
    const merged = { ...existing, ...r.rule };
    if (!merged.signature && !merged.source_cidr && !merged.dest_cidr && merged.dest_port == null) return bad(res, 'A rule needs at least one condition');
    if (!Object.keys(r.rule).length) return bad(res, 'Nothing to change');
    const updated = await store.suppressions.update(existing.id, r.rule);
    await store.audit.add({ actor: actor(req), action: 'suppression.updated', target: existing.name, detail: Object.keys(r.rule).join(', ') });
    res.json(updated);
  }));

  app.delete('/api/suppressions/:id', need('configure'), wrap(async (req, res) => {
    const existing = await store.suppressions.get(req.params.id);
    if (!existing || !(await store.suppressions.remove(existing.id))) return bad(res, 'Rule not found', 404);
    await store.audit.add({ actor: actor(req), action: 'suppression.deleted', target: existing.name, detail: `${existing.hits} hits over its lifetime` });
    res.json({ ok: true });
  }));

  // ---- Notification channels (secrets never leave the server) ----------------------
  app.get('/api/notify/channels', need('configure'), wrap(async (req, res) => res.json((await notifier.channels()).map(publicChannel))));

  app.post('/api/notify/channels', need('configure'), wrap(async (req, res) => {
    const v = validateChannel(req.body || {}, { production });
    if (v.error) return bad(res, v.error);
    let host;
    try { host = new URL(v.channel.url).hostname.replace(/^\[|\]$/g, ''); } catch { host = ''; }
    if (production && isIP(host) && isInternal(host)) return bad(res, 'Webhook URL points at a private address');
    const list = await notifier.channels();
    if (list.length >= MAX_CHANNELS) return bad(res, `At most ${MAX_CHANNELS} channels`);
    const channel = { id: crypto.randomBytes(6).toString('hex'), ...v.channel, created_by: actor(req), created_at: new Date().toISOString(), last: null };
    await notifier.saveChannels([...list, channel]);
    await store.audit.add({ actor: actor(req), action: 'notify.channel_added', target: `${channel.kind}:${channel.name}`, detail: `>= ${channel.min_severity}; ${channel.events.join(', ')}` });
    res.status(201).json(publicChannel(channel));
  }));

  app.patch('/api/notify/channels/:id', need('configure'), wrap(async (req, res) => {
    const list = await notifier.channels();
    const c = list.find((x) => x.id === req.params.id);
    if (!c) return bad(res, 'Channel not found', 404);
    const b = req.body || {};
    if (b.enabled !== undefined) c.enabled = Boolean(b.enabled);
    if (b.min_severity !== undefined) {
      const m = String(b.min_severity).toUpperCase();
      if (!SEVERITY_RANK[m]) return bad(res, 'Unknown minimum severity');
      c.min_severity = m;
    }
    if (b.events !== undefined) {
      const ev = [...new Set((Array.isArray(b.events) ? b.events : []).filter((e) => ['alert', 'containment', 'verdict'].includes(e)))];
      if (!ev.length) return bad(res, 'Pick at least one event');
      c.events = ev;
    }
    await notifier.saveChannels(list);
    await store.audit.add({ actor: actor(req), action: 'notify.channel_updated', target: `${c.kind}:${c.name}`, detail: `${c.enabled === false ? 'paused' : 'active'}, >= ${c.min_severity}` });
    res.json(publicChannel(c));
  }));

  app.delete('/api/notify/channels/:id', need('configure'), wrap(async (req, res) => {
    const list = await notifier.channels();
    const c = list.find((x) => x.id === req.params.id);
    if (!c) return bad(res, 'Channel not found', 404);
    await notifier.saveChannels(list.filter((x) => x.id !== c.id));
    await store.audit.add({ actor: actor(req), action: 'notify.channel_removed', target: `${c.kind}:${c.name}`, detail: null });
    res.json({ ok: true });
  }));

  app.post('/api/notify/channels/:id/test', need('configure'), wrap(async (req, res) => {
    const r = await notifier.test(req.params.id, { origin: origin(req), actor: actor(req) });
    if (!r) return bad(res, 'Channel not found', 404);
    res.status(r.ok ? 200 : 502).json(r.ok ? r : { ...r, error: `Delivery failed: ${r.detail}` });
  }));

  // ---- IP profile -----------------------------------------------------------------
  app.get('/api/ip/:ip', wrap(async (req, res) => {
    const ip = String(req.params.ip).trim();
    if (!isIP(ip)) return bad(res, 'Not an IP address');
    const internal = isInternal(ip);
    const [alerts, rules, invs, asset, byClient] = await Promise.all([
      store.alerts.list({ ip, limit: 2000 }), store.rules.list(), store.investigations.list({ limit: 5000 }), store.assets.get(ip),
      store.logs.list({ client_ip: ip, limit: 100 })
    ]);
    const byHost = asset ? await store.logs.list({ host_ip: ip, limit: 100 }) : [];
    const seen = new Set();
    const logs = [...byClient, ...byHost].filter((l) => !seen.has(l.id) && seen.add(l.id)).sort((a, b) => b.logged_at.localeCompare(a.logged_at)).slice(0, 150);
    let intel = null;
    if (!internal && reputation && reputation.available) {
      try { intel = await reputation.check(ip); } catch (err) { intel = { error: err.message }; }
    }
    const sigs = {};
    const peers = {};
    for (const a of alerts) {
      sigs[a.signature] = (sigs[a.signature] || 0) + 1;
      const peer = a.source_ip === ip ? a.dest_ip : a.source_ip;
      peers[peer] = (peers[peer] || 0) + 1;
    }
    const times = alerts.map((a) => a.detected_at).sort();
    res.json({
      ip, internal, asset, intel,
      first_seen: times[0] || null, last_seen: times[times.length - 1] || null,
      counts: {
        alerts: alerts.length, open: alerts.filter((a) => OPEN.includes(a.status)).length,
        as_source: alerts.filter((a) => a.source_ip === ip).length, as_target: alerts.filter((a) => a.dest_ip === ip).length,
        by_severity: Object.fromEntries(SEVERITIES.map((s) => [s, alerts.filter((a) => a.severity === s).length]))
      },
      signatures: Object.entries(sigs).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([signature, n]) => ({ signature, n })),
      peers: Object.entries(peers).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([peer, n]) => ({ ip: peer, n })),
      alerts: alerts.slice(0, 200),
      rules: rules.filter((r) => r.target_ip === ip),
      investigations: invs.filter((i) => i.attacker_ip === ip || i.target_ip === ip).slice(0, 50),
      logs
    });
  }));

  // ---- Reporting --------------------------------------------------------------------
  app.get('/api/reports/summary', wrap(async (req, res) => {
    const days = [7, 30, 90].includes(Number(req.query.days)) ? Number(req.query.days) : 30;
    const now = Date.now();
    const since = new Date(now - days * 86400000).toISOString();
    const [cfg, alerts, invs, rules, supps] = await Promise.all([
      store.config.get(), store.alerts.list({ since, limit: 50000 }), store.investigations.list({ since, limit: 10000 }), store.rules.list(), store.suppressions.list()
    ]);
    const real = alerts.filter((a) => !a.suppressed_by);
    const sla = SEVERITIES.map((s) => {
      const target = Number(cfg[SLA_KEYS[s]]) || null;
      const rows = real.filter((a) => a.severity === s);
      const ack = rows.filter((a) => a.acknowledged_at).map((a) => Math.max(0, minutes(a.detected_at, a.acknowledged_at)));
      const fix = rows.filter((a) => a.resolved_at).map((a) => Math.max(0, minutes(a.detected_at, a.resolved_at)));
      const breached = target ? rows.filter((a) => (a.acknowledged_at ? minutes(a.detected_at, a.acknowledged_at) : (now - new Date(a.detected_at)) / 60000) > target) : [];
      const waiting = rows.filter((a) => !a.acknowledged_at);
      return {
        severity: s, target_min: target, total: rows.length, acknowledged: ack.length, resolved: fix.length,
        mtta: stats(ack), mttr: stats(fix), breached: breached.length,
        compliance: rows.length && target ? Math.round(((rows.length - breached.length) / rows.length) * 100) : null,
        overdue: waiting.filter((a) => target && (now - new Date(a.detected_at)) / 60000 > target).map((a) => ({ alert_id: a.alert_id, signature: a.signature, detected_at: a.detected_at })).slice(0, 5)
      };
    });

    // ATT&CK coverage: latest investigation per alert, so re-runs do not double count.
    const latest = new Map();
    for (const i of invs) if (!latest.has(i.alert_id)) latest.set(i.alert_id, i);
    const matrix = {};
    for (const i of latest.values()) {
      const t = tacticOf(i.mitre_tactic);
      if (!t) continue;
      const tech = String(i.mitre_technique || 'Unmapped').slice(0, 80);
      matrix[t] = matrix[t] || { tactic: t, total: 0, succeeded: 0, techniques: {} };
      matrix[t].total += 1;
      if (i.outcome === 'ATTACK_SUCCEEDED') matrix[t].succeeded += 1;
      matrix[t].techniques[tech] = (matrix[t].techniques[tech] || 0) + 1;
    }
    const mitre = [...TACTICS, 'Other'].map((t) => matrix[t] || { tactic: t, total: 0, succeeded: 0, techniques: {} })
      .filter((t) => t.tactic !== 'Other' || t.total)
      .map((t) => ({ ...t, techniques: Object.entries(t.techniques).sort((a, b) => b[1] - a[1]).map(([name, n]) => ({ name, n })) }));

    const daily = Array.from({ length: days }, (_, i) => {
      const d = new Date(now - (days - 1 - i) * 86400000).toISOString().slice(0, 10);
      return { day: d, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, suppressed: 0 };
    });
    const dayIdx = new Map(daily.map((d, i) => [d.day, i]));
    for (const a of alerts) {
      const i = dayIdx.get(a.detected_at.slice(0, 10));
      if (i === undefined) continue;
      if (a.suppressed_by) daily[i].suppressed += 1; else daily[i][a.severity] += 1;
    }

    const attackers = {};
    for (const a of real) if (!isInternal(a.source_ip)) attackers[a.source_ip] = attackers[a.source_ip] || { ip: a.source_ip, alerts: 0, critical: 0, last: a.detected_at };
    for (const a of real) {
      const x = attackers[a.source_ip];
      if (!x) continue;
      x.alerts += 1;
      if (a.severity === 'CRITICAL') x.critical += 1;
      if (a.detected_at > x.last) x.last = a.detected_at;
    }
    const blocked = new Set(rules.filter((r) => r.is_active && r.action === 'BLOCK').map((r) => r.target_ip));
    const top = Object.values(attackers).sort((a, b) => b.alerts - a.alerts || b.critical - a.critical).slice(0, 10).map((x) => ({ ...x, blocked: blocked.has(x.ip) }));

    const owners = {};
    for (const a of real) {
      const k = a.assignee_name || 'Unassigned';
      owners[k] = owners[k] || { name: k, assigned: 0, open: 0, resolved: 0 };
      owners[k].assigned += 1;
      if (OPEN.includes(a.status)) owners[k].open += 1;
      if (CLOSED_STATUSES.includes(a.status)) owners[k].resolved += 1;
    }
    const outcomes = {};
    for (const i of latest.values()) outcomes[i.outcome] = (outcomes[i.outcome] || 0) + 1;
    const contained = rules.filter((r) => r.created_at >= since);

    res.json({
      days, since, generated_at: new Date().toISOString(),
      totals: {
        alerts: alerts.length, actionable: real.length, suppressed: alerts.length - real.length,
        noise_reduction: alerts.length ? Math.round(((alerts.length - real.length) / alerts.length) * 100) : 0,
        investigated: latest.size, automated: [...latest.values()].filter((i) => !i.human_override).length,
        rules_created: contained.length, rules_auto: contained.filter((r) => /playbook|agent/i.test(r.enacted_by || '')).length,
        suppression_rules: supps.filter((s) => isLive(s)).length
      },
      sla, mitre, daily, outcomes,
      top_attackers: top,
      owners: Object.values(owners).sort((a, b) => b.assigned - a.assigned)
    });
  }));

  // ---- Exports ----------------------------------------------------------------------
  const sendCsv = (res, name, body) => {
    res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="${name}"`, 'Cache-Control': 'no-store' });
    res.send(`\ufeff${body}`);
  };

  app.get('/api/export/alerts.csv', wrap(async (req, res) => {
    const days = Math.min(Math.max(Number(req.query.days) || 30, 1), 730);
    const rows = await store.alerts.list({ since: new Date(Date.now() - days * 86400000).toISOString(), status: req.query.status || undefined, limit: 100000 });
    const cols = ['alert_id', 'detected_at', 'severity', 'status', 'signature', 'category', 'source_ip', 'dest_ip', 'dest_port', 'protocol', 'sensor', 'external_ref', 'assignee_name', 'acknowledged_at', 'resolved_at', 'suppressed_by'];
    await store.audit.add({ actor: actor(req), action: 'export.alerts', target: `${rows.length} alerts`, detail: `last ${days} days` });
    sendCsv(res, `aegis-alerts-${new Date().toISOString().slice(0, 10)}.csv`, csv(cols, rows));
  }));

  app.get('/api/export/audit.csv', need('manage'), wrap(async (req, res) => {
    const rows = await store.audit.list(Math.min(Number(req.query.limit) || 5000, 50000));
    await store.audit.add({ actor: actor(req), action: 'export.audit', target: `${rows.length} entries`, detail: null });
    sendCsv(res, `aegis-audit-${new Date().toISOString().slice(0, 10)}.csv`, csv(['id', 'created_at', 'actor', 'action', 'target', 'detail'], rows));
  }));

  // Full incident write-up: the engine report plus the alert, the case notes and the run log.
  app.get('/api/investigations/:id/report.md', wrap(async (req, res) => {
    const inv = await store.investigations.get(req.params.id);
    if (!inv) return bad(res, 'Investigation not found', 404);
    const [alert, notes] = await Promise.all([store.alerts.get(inv.alert_id), store.notes.list(inv.alert_id)]);
    const md = incidentMarkdown(inv, alert, notes);
    await store.audit.add({ actor: actor(req), action: 'export.report', target: inv.investigation_id, detail: null });
    res.set({ 'Content-Type': 'text/markdown; charset=utf-8', 'Content-Disposition': `attachment; filename="${inv.investigation_id}.md"`, 'Cache-Control': 'no-store' });
    res.send(md);
  }));

  // Runs inside the investigator once a verdict is stored.
  return {
    async onVerdict(inv, alert, status) {
      await event(alert.alert_id, `Investigation ${inv.investigation_id}: ${inv.outcome.replace(/_/g, ' ').toLowerCase()} (${inv.confidence}%), status ${status}`);
      await notifier.emit('verdict', { investigation: inv, severity: alert.severity });
    }
  };
}

function incidentMarkdown(inv, alert, notes) {
  const t = (iso) => (iso ? new Date(iso).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '-');
  const out = [
    `# Incident report: ${inv.investigation_id}`,
    '',
    `Generated ${t(new Date().toISOString())} by Aegis.`,
    '',
    '| Field | Value |', '| --- | --- |',
    `| Alert | ${alert ? alert.alert_id : inv.alert_id} |`,
    ...(alert ? [
      `| Signature | ${alert.signature.replace(/\|/g, '/')} |`, `| Severity | ${alert.severity} |`, `| Status | ${alert.status} |`,
      `| Flow | ${alert.source_ip} -> ${alert.dest_ip}:${alert.dest_port} (${alert.protocol}) |`, `| Sensor | ${alert.sensor || '-'} |`,
      `| Detected | ${t(alert.detected_at)} |`, `| First response | ${t(alert.acknowledged_at)} |`, `| Resolved | ${t(alert.resolved_at)} |`,
      `| Owner | ${alert.assignee_name || 'Unassigned'} |`
    ] : []),
    `| Engine | ${inv.engine} (${Math.round((inv.duration_ms || 0) / 100) / 10}s) |`,
    '',
    inv.report || '',
    ''
  ];
  if (inv.human_override) {
    const o = inv.human_override;
    out.push('### Analyst override', '', `${o.analyst} changed the verdict from ${o.previous_outcome} to ${o.outcome} at ${t(o.at)}.`, '', `> ${String(o.notes || '').replace(/\n/g, '\n> ')}`, '');
  }
  if (notes.length) {
    out.push('### Case timeline', '');
    for (const n of notes) out.push(`- ${t(n.created_at)} **${n.author}**${n.kind === 'event' ? ' ' : ': '}${n.body.replace(/\n/g, ' ')}`);
    out.push('');
  }
  if ((inv.steps || []).length) {
    out.push('### Run log', '', '| # | Phase | Step | Result | ms |', '| --- | --- | --- | --- | --- |');
    inv.steps.forEach((s, i) => out.push(`| ${i + 1} | ${s.phase} | ${String(s.title).replace(/\|/g, '/')} | ${s.error ? `error: ${String(s.error).replace(/\|/g, '/')}` : s.kind || 'ok'} | ${s.ms || 0} |`));
    out.push('');
  }
  if (alert) out.push('### Captured payload', '', '```', alert.raw_payload.replace(/```/g, "'''"), '```', '');
  return out.join('\n');
}

module.exports = { registerCasework, csvCell, tacticOf, TACTICS };