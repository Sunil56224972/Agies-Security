'use strict';

// Model Context Protocol server. Any MCP client (Claude Desktop, Cursor, VS Code,
// the OpenAI Agents SDK) can drive Aegis with an API key:
//
//   POST /mcp   (and /api/mcp)   JSON-RPC 2.0, Streamable HTTP transport, JSON responses
//   Authorization: Bearer aeg_...   key with the "mcp" scope (read tools) or
//                                    "mcp:write" (read tools plus response actions)
//
// Stateless: no session id, every request is authorised on its own. Tool calls
// run the same service code as the console, so validation, audit entries and
// case timelines are identical whichever way an action arrives.

const { isIP, isInternal, SEVERITY_RANK } = require('./engine/analysis');
const { normalizeLog } = require('./ingest/normalize');
const detect = require('./engine/detect');
const { toAlerts } = require('./engine/sigma');
const { extractAll, isIpType } = require('./intel/indicator');
const crypto = require('crypto');
const auth = require('./security/auth');
const pkg = require('../package.json');

const VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const OPEN = ['NEW', 'INVESTIGATING', 'CONFIRMED'];
const SCOPES = ['mcp', 'mcp:write'];

const S = (props, required = []) => ({ type: 'object', properties: props, required, additionalProperties: false });
const str = (description, extra = {}) => ({ type: 'string', description, ...extra });
const int = (description, extra = {}) => ({ type: 'integer', description, ...extra });
const SEV = { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] };

class ToolError extends Error {}
const need = (v, msg) => { if (v === undefined || v === null || v === '') throw new ToolError(msg); return v; };
const clamp = (v, d, lo, hi) => Math.min(Math.max(Number.isFinite(Number(v)) ? Number(v) : d, lo), hi);
const trimAlert = ({ raw_payload, ...a }) => a;

function buildTools(ctx, svc) {
  const { store, investigator, hub, sigma } = ctx;
  const tools = [];
  const def = (name, title, description, inputSchema, run, { write = false } = {}) => tools.push({ name, title, description, inputSchema, run, write });

  // ---- Read ------------------------------------------------------------------
  def('overview', 'SOC overview', 'Current posture: open alerts by severity, investigation outcomes, active containment rules, open cases and pending approvals.', S({}), async () => {
    const [alerts, invs, rules, cases, pending] = await Promise.all([
      store.alerts.list({ lite: true, limit: 100000 }), store.investigations.list({ lite: true, limit: 5000 }), store.rules.list(), svc.caseMetrics(), store.approvals.count('PENDING')
    ]);
    const open = alerts.filter((a) => OPEN.includes(a.status));
    return {
      alerts: { total: alerts.length, open: open.length, by_severity: Object.fromEntries(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => [s, open.filter((a) => a.severity === s).length])) },
      investigations: { total: invs.length, outcomes: invs.reduce((m, i) => ({ ...m, [i.outcome]: (m[i.outcome] || 0) + 1 }), {}) },
      containment: { active_rules: rules.filter((r) => r.is_active).length, mode: ctx.enforcer ? ctx.enforcer.mode : null },
      cases, approvals_pending: pending,
      top_open: open.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.detected_at.localeCompare(a.detected_at)).slice(0, 10)
    };
  });

  def('list_alerts', 'List alerts', 'Alerts newest first. Filter by status, severity, IP (source or destination) or free text.', S({
    status: str('NEW, INVESTIGATING, CONFIRMED, CONTAINED, MITIGATED, FALSE_POSITIVE or CLOSED; "open" for the first three'),
    severity: SEV, ip: str('IP address on either side of the alert'), q: str('Free text over id, signature, IPs, sensor'), limit: int('Max rows (default 25, max 200)')
  }), async (a) => {
    const st = a.status ? String(a.status).toUpperCase() : null;
    return store.alerts.list({ lite: true, severity: a.severity, ip: a.ip, q: a.q, limit: clamp(a.limit, 25, 1, 200), ...(st === 'OPEN' ? { statuses: OPEN } : st ? { status: st } : {}) });
  });

  def('get_alert', 'Get alert', 'One alert with its raw payload, notes, investigations and the cases it belongs to.', S({ alert_id: str('Alert id') }, ['alert_id']), async (a) => {
    const alert = await store.alerts.get(need(a.alert_id, 'alert_id is required'));
    if (!alert) throw new ToolError(`Alert ${a.alert_id} not found`);
    const [notes, invs, cases] = await Promise.all([store.notes.list(alert.alert_id), store.investigations.forAlert(alert.alert_id), svc.casesForAlert(alert.alert_id)]);
    return { alert, notes: notes.slice(-30), investigations: [].concat(invs || []).map((i) => ({ investigation_id: i.investigation_id, outcome: i.outcome, confidence: i.confidence, mitre_technique: i.mitre_technique, summary: i.summary, created_at: i.created_at })), cases };
  });

  def('get_investigation', 'Get investigation', 'Full investigation record: verdict, evidence steps, actions taken and the incident report.', S({ investigation_id: str('Investigation id (INV-...)') }, ['investigation_id']), async (a) => {
    const inv = await store.investigations.get(need(a.investigation_id, 'investigation_id is required'));
    if (!inv) throw new ToolError(`Investigation ${a.investigation_id} not found`);
    return inv;
  });

  def('search', 'Search', 'Search alerts, assets, firewall rules, investigations and cases for a term or IP.', S({ q: str('At least 2 characters') }, ['q']), async (a) => {
    const q = String(need(a.q, 'q is required')).trim();
    if (q.length < 2) throw new ToolError('Search needs at least 2 characters');
    const n = q.toLowerCase();
    const has = (...f) => f.some((x) => x != null && String(x).toLowerCase().includes(n));
    const [alerts, assets, rules, invs, cases] = await Promise.all([store.alerts.list({ q, lite: true, limit: 15 }), store.assets.list(), store.rules.list(), store.investigations.list({ lite: true, limit: 2000 }), store.cases.list({ q, limit: 10 })]);
    return {
      alerts, cases: cases.map((c) => ({ case_id: c.case_id, title: c.title, status: c.status, severity: c.severity })),
      assets: assets.filter((x) => has(x.ip_address, x.hostname, x.os_version, x.owner)).slice(0, 10),
      rules: rules.filter((r) => has(r.rule_id, r.target_ip, r.reason)).slice(0, 10),
      investigations: invs.filter((i) => has(i.investigation_id, i.alert_id, i.attacker_ip, i.target_ip)).slice(0, 10)
    };
  });

  def('ip_profile', 'IP profile', 'Everything Aegis knows about an address: alerts, peers, rules, investigations, asset record and live reputation.', S({ ip: str('IPv4 or IPv6 address') }, ['ip']), async (a) => {
    const ip = String(need(a.ip, 'ip is required')).trim();
    if (!isIP(ip)) throw new ToolError('Not an IP address');
    const [alerts, rules, invs, asset] = await Promise.all([store.alerts.list({ ip, lite: true, limit: 2000 }), store.rules.list(), store.investigations.forIp(ip), store.assets.get(ip)]);
    let reputation = null;
    if (!isInternal(ip) && ctx.reputation && ctx.reputation.available) {
      try { const r = await ctx.reputation.check(ip); reputation = { verdict: r.verdict, score: r.score, summary: r.summary, country: r.country, isp: r.isp }; } catch (err) { reputation = { error: err.message }; }
    }
    const times = alerts.map((x) => x.detected_at).sort();
    return {
      ip, internal: isInternal(ip), asset, reputation, first_seen: times[0] || null, last_seen: times[times.length - 1] || null,
      alerts: { total: alerts.length, open: alerts.filter((x) => OPEN.includes(x.status)).length, as_source: alerts.filter((x) => x.source_ip === ip).length, recent: alerts.slice(0, 15) },
      rules: rules.filter((r) => r.target_ip === ip), investigations: invs.slice(0, 15)
    };
  });

  def('lookup_indicator', 'Threat intel lookup', 'Live lookup of an IP, domain, URL, hash or ASN across abuse.ch (URLhaus, MalwareBazaar, ThreatFox, Feodo), MISP feeds, VirusTotal, RDAP/WHOIS, RIPEstat BGP, passive DNS and certificate transparency.', S({
    indicator: str('IP, domain, URL, MD5/SHA1/SHA256 or ASN; defanged forms such as hxxp://evil[.]com are accepted')
  }, ['indicator']), async (a) => {
    if (!hub) throw new ToolError('Threat intel is not available');
    let r;
    try { r = await hub.lookup(String(need(a.indicator, 'indicator is required')).slice(0, 2048), { budgetMs: 20000 }); } catch (err) { throw new ToolError(err.message); }
    return { indicator: r.indicator, verdict: r.verdict, score: r.score, summary: r.summary || r.reason, c2: r.c2, families: r.families, signals: r.signals, hits: (r.hits || []).slice(0, 15), whois: r.whois, bgp: r.bgp, virustotal: r.virustotal, sources_ok: r.sources_ok, sources_failed: r.sources_failed, pending: r.pending };
  });

  def('bulk_check', 'Bulk IOC check', 'Extract every IP, domain, URL and hash from free text (logs, CSV, a report) and check each one. At most 50.', S({ text: str('Any text containing indicators') }, ['text']), async (a) => {
    if (!hub) throw new ToolError('Threat intel is not available');
    const inds = extractAll(String(need(a.text, 'text is required')), { max: 51 }).filter((i) => i.type !== 'asn');
    if (!inds.length) throw new ToolError('No indicators found in the text');
    if (inds.length > 50) throw new ToolError('At most 50 indicators per call');
    const out = [];
    for (let i = 0; i < inds.length; i += 5) {
      out.push(...await Promise.all(inds.slice(i, i + 5).map(async (ind) => {
        if (isIpType(ind.type) && isInternal(ind.value)) return { value: ind.value, type: ind.type, verdict: 'internal' };
        try { const r = await hub.lookup(ind.value, { budgetMs: 8000, vt: false }); return { value: ind.value, type: ind.type, verdict: r.verdict, score: r.score, summary: r.summary }; } catch (err) { return { value: ind.value, type: ind.type, verdict: 'error', error: err.message }; }
      })));
    }
    return { checked: out.length, malicious: out.filter((r) => r.verdict === 'malicious').length, suspicious: out.filter((r) => r.verdict === 'suspicious').length, results: out };
  });

  def('detect_test', 'Test detections', 'Dry-run raw log lines through the built-in detections and the SigmaHQ rule set. Nothing is stored.', S({
    host_ip: str('IP of the host the lines came from'), lines: str('Log lines, one per line (syslog/auth.log, Apache/Nginx access, JSON events)'), log_type: str('Optional: http_access, auth_log, edr_process or system')
  }, ['host_ip', 'lines']), async (a) => {
    const host = String(need(a.host_ip, 'host_ip is required')).trim();
    if (!isIP(host)) throw new ToolError('host_ip must be an IP address');
    const lines = String(need(a.lines, 'lines is required')).split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, 2000);
    const parsed = []; let rejected = 0;
    lines.forEach((l, i) => {
      const r = normalizeLog(l, { host_ip: host, log_type: a.log_type || undefined });
      if (r.error) rejected += 1; else parsed.push({ ...r.log, id: i + 1, logged_at: new Date(Date.now() - (lines.length - i) * 1000).toISOString() });
    });
    const cfg = await store.config.get();
    const findings = detect.evaluate(parsed, { ...cfg, detectEnabled: true }, { now: Date.now() });
    let sig = { loaded: false };
    if (sigma && sigma.available) {
      const s = await sigma.scan(parsed, { budgetMs: 15000, minLevel: cfg.sigmaMinLevel || 'low', disabled: cfg.sigmaDisabled || [] });
      sig = s ? { loaded: true, rules: s.rules, findings: toAlerts(s.matches).map((x) => ({ signature: x.signature, severity: x.severity, ref: x.external_ref, source_ip: x.source_ip })) } : { loaded: false, loading: true };
    }
    return { parsed: parsed.length, rejected, findings: findings.map((f) => ({ signature: f.signature, severity: f.severity, ref: f.external_ref, source_ip: f.source_ip, dest_ip: f.dest_ip })), sigma: sig };
  });

  def('list_rules', 'List containment rules', 'Firewall BLOCK and host ISOLATE rules with their enforcement state.', S({ active_only: { type: 'boolean', description: 'Only active rules (default true)' } }), async (a) => {
    const rules = await store.rules.list();
    return (a.active_only === false ? rules : rules.filter((r) => r.is_active)).slice(0, 200);
  });

  def('list_cases', 'List cases', 'Incident cases with alert, task and IOC counts.', S({ status: str('OPEN, IN_PROGRESS, CONTAINED or CLOSED; comma separated'), q: str('Free text'), limit: int('Max rows (default 25)') }),
    (a) => svc.listCases({ status: a.status ? String(a.status).split(',') : undefined, q: a.q, limit: clamp(a.limit, 25, 1, 200) }));

  def('get_case', 'Get case', 'A case with its alerts, tasks, indicators, timeline, approvals, rules and related cases.', S({ case_id: str('Case id (CASE-...)') }, ['case_id']), (a) => svc.getCase(need(a.case_id, 'case_id is required')));

  def('list_approvals', 'List approvals', 'Containment actions waiting for (or past) a human decision.', S({ status: str('PENDING (default), APPROVED, REJECTED, EXPIRED, FAILED or ALL') }), (a) => {
    const st = String(a.status || 'PENDING').toUpperCase();
    return svc.listApprovals({ status: st === 'ALL' ? undefined : st.split(','), limit: 100 });
  });

  def('list_hunts', 'List hunts', 'Saved threat hunts with their criteria and last result.', S({}), () => svc.listHunts());

  def('technique_rollup', 'ATT&CK rollup', 'MITRE ATT&CK techniques seen in alerts and investigations, grouped by tactic.', S({ days: int('Window in days (default 30, max 365)') }), (a) => svc.techniques({ days: a.days }));

  // ---- Write -----------------------------------------------------------------
  def('investigate_alert', 'Investigate alert', 'Run the investigation engine on an alert: evidence collection, verdict, MITRE mapping and containment according to the approval policy. Takes 5-40 seconds.', S({
    alert_id: str('Alert id'), engine: { type: 'string', enum: ['playbook', 'llm'], description: 'Force an engine; defaults to the configured one' }
  }, ['alert_id']), async (a) => {
    let inv;
    try { inv = await investigator.run(need(a.alert_id, 'alert_id is required'), () => {}, { pace: 0, engine: a.engine }); } catch (err) { throw new ToolError(err.message); }
    return { investigation_id: inv.investigation_id, outcome: inv.outcome, confidence: inv.confidence, mitre_tactic: inv.mitre_tactic, mitre_technique: inv.mitre_technique, engine: inv.engine, summary: inv.summary, actions_taken: inv.actions_taken, verification: inv.verification, duration_ms: inv.duration_ms };
  }, { write: true });

  def('set_alert_status', 'Set alert status', 'Close an alert, mark it a false positive, or reopen it.', S({ alert_id: str('Alert id'), status: { type: 'string', enum: ['NEW', 'CLOSED', 'FALSE_POSITIVE'] }, note: str('Why') }, ['alert_id', 'status']), async (a, who) => {
    const alert = await store.alerts.get(need(a.alert_id, 'alert_id is required'));
    if (!alert) throw new ToolError(`Alert ${a.alert_id} not found`);
    if (alert.status === 'INVESTIGATING') throw new ToolError('The alert is under investigation');
    const status = String(a.status).toUpperCase();
    if (!['NEW', 'CLOSED', 'FALSE_POSITIVE'].includes(status)) throw new ToolError('status must be NEW, CLOSED or FALSE_POSITIVE');
    const next = await store.alerts.update(alert.alert_id, { status });
    await store.notes.add({ alert_id: alert.alert_id, kind: 'event', author: who.name, body: `Status ${alert.status} -> ${status}${a.note ? `: ${String(a.note).slice(0, 500)}` : ''}` });
    await store.audit.add({ actor: who.name, action: 'alert.status', target: alert.alert_id, detail: `${alert.status} -> ${status}` });
    return trimAlert(next);
  }, { write: true });

  def('block_ip', 'Contain an address', 'BLOCK an external IP or ISOLATE an internal host. Follows the approval policy: it either executes and verifies at once, or queues for a human and returns the approval id.', S({
    target_ip: str('Address to contain'), action: { type: 'string', enum: ['BLOCK', 'ISOLATE'], description: 'Default BLOCK' }, reason: str('Why; recorded on the rule'),
    confidence: int('Your confidence 0-100; drives the approval route'), ttl_hours: int('Expire after N hours; 0 = permanent'), alert_id: str('Related alert'), case_id: str('Related case')
  }, ['target_ip', 'reason']), (a, who) => svc.contain(a, who), { write: true });

  def('approve_action', 'Approve action', 'Approve a pending containment action; it is executed and verified immediately.', S({ approval_id: str('APR-...'), note: str('Optional note') }, ['approval_id']), (a, who) => svc.decide(need(a.approval_id, 'approval_id is required'), true, a, who), { write: true });
  def('reject_action', 'Reject action', 'Reject a pending containment action.', S({ approval_id: str('APR-...'), note: str('Why it is rejected (required)') }, ['approval_id', 'note']), (a, who) => svc.decide(need(a.approval_id, 'approval_id is required'), false, a, who), { write: true });

  def('create_case', 'Create case', 'Open an incident case, optionally linking alerts.', S({
    title: str('At least 4 characters'), description: str('Details'), severity: SEV, alert_ids: { type: 'array', items: { type: 'string' } }, tags: { type: 'array', items: { type: 'string' } }, mitre: { type: 'array', items: { type: 'string' }, description: 'ATT&CK ids' }
  }, ['title']), (a, who) => svc.createCase({ ...a, source: 'mcp' }, who), { write: true });

  def('create_case_from_killchain', 'Case from kill chain', 'Group every alert involving an attacker IP into one case, with derived ATT&CK techniques, a timeline and a response checklist.', S({ ip: str('Attacker address'), hours: int('Look-back window (default 72)'), title: str('Optional title') }, ['ip']), (a, who) => svc.fromKillchain(a, who), { write: true });
  def('update_case', 'Update case', 'Change a case status (OPEN, IN_PROGRESS, CONTAINED), severity, title, tags or MITRE ids.', S({ case_id: str('Case id'), status: { type: 'string', enum: ['OPEN', 'IN_PROGRESS', 'CONTAINED'] }, severity: SEV, title: str('Title'), tags: { type: 'array', items: { type: 'string' } }, mitre: { type: 'array', items: { type: 'string' } } }, ['case_id']), (a, who) => { const { case_id, ...rest } = a; return svc.updateCase(need(case_id, 'case_id is required'), rest, who); }, { write: true });
  def('add_alert_to_case', 'Link alerts', 'Link one or more alerts to a case.', S({ case_id: str('Case id'), alert_ids: { type: 'array', items: { type: 'string' } } }, ['case_id', 'alert_ids']), (a, who) => svc.linkAlerts(need(a.case_id, 'case_id is required'), a.alert_ids, who), { write: true });
  def('add_case_ioc', 'Add indicators', 'Add indicators to a case. Free text is accepted; every IP, domain, URL and hash in it is extracted. Set check=true to look each one up.', S({ case_id: str('Case id'), values: str('Indicators, any format'), note: str('Context'), check: { type: 'boolean' } }, ['case_id', 'values']), async (a, who) => {
    const out = await svc.addIocs(need(a.case_id, 'case_id is required'), a, who);
    if (a.check) for (const [i, ioc] of out.added.slice(0, 10).entries()) out.added[i] = (await svc.checkIoc(a.case_id, ioc.id, who)).ioc;
    return out;
  }, { write: true });
  def('add_case_task', 'Add task', 'Add a task to a case checklist.', S({ case_id: str('Case id'), title: str('Task'), phase: str('Identification, Containment, Eradication, Recovery or Lessons learned') }, ['case_id', 'title']), (a, who) => svc.addTask(need(a.case_id, 'case_id is required'), a, who), { write: true });
  def('update_case_task', 'Update task', 'Move a case task to TODO, DOING, DONE or SKIPPED.', S({ case_id: str('Case id'), task_id: int('Task id'), status: { type: 'string', enum: ['TODO', 'DOING', 'DONE', 'SKIPPED'] } }, ['case_id', 'task_id', 'status']), (a, who) => svc.updateTask(need(a.case_id, 'case_id is required'), a.task_id, a, who), { write: true });
  def('add_case_comment', 'Comment or evidence', 'Add a comment, an evidence item (SHA-256 hashed on arrival) or a timeline entry to a case.', S({ case_id: str('Case id'), body: str('Text'), kind: { type: 'string', enum: ['comment', 'evidence', 'timeline'] }, title: str('Optional title'), occurred_at: str('ISO time, required for timeline entries') }, ['case_id', 'body']), (a, who) => svc.addEvent(need(a.case_id, 'case_id is required'), a, who), { write: true });
  def('close_case', 'Close case', 'Close a case with its resolution. Fails while tasks are open unless force=true.', S({ case_id: str('Case id'), resolution: str('At least 10 characters'), force: { type: 'boolean' } }, ['case_id', 'resolution']), (a, who) => svc.closeCase(need(a.case_id, 'case_id is required'), a, who), { write: true });

  def('run_hunt', 'Run hunt', 'Run a saved hunt by id, or an ad-hoc hunt from criteria, over stored logs, alerts and investigations.', S({
    hunt_id: str('Saved hunt id; omit for ad-hoc'), window_hours: int('Look-back (default 168)'), text: str('Substring or /regex/'), ip: str('Address or IPv4 CIDR'),
    technique: str('ATT&CK id'), indicators: str('IPs, domains, URLs or hashes'), sigma: { type: 'boolean', description: 'Run SigmaHQ rules over the logs' }, intel: { type: 'boolean', description: 'Check every external address against threat feeds' },
    log_types: { type: 'array', items: { type: 'string', enum: ['http_access', 'auth_log', 'edr_process', 'system'] } }, min_severity: SEV
  }), async (a, who) => {
    const r = a.hunt_id ? await svc.runHunt(a.hunt_id, who) : await svc.adhoc({ criteria: a, name: 'MCP hunt' }, who);
    return { ...r, findings: r.findings.slice(0, 60), findings_total: r.findings.length };
  }, { write: true });

  // ---- Workbench ---------------------------------------------------------------
  const wb = () => { if (!ctx.workbench) throw new ToolError('The workbench is not available'); if (store.pendingExtras) throw new ToolError(`Needs the ${store.pendingExtras.migration} migration`); return ctx.workbench; };

  def('extract_iocs_document', 'Analyse document', 'Extract IPs, domains, URLs, hashes, CVE ids, ATT&CK ids, e-mail addresses and registry keys from a report, log or e-mail source. Known CVEs are matched to the local catalogue. Nothing is stored.', S({ text: str('Document text (up to 200k characters)') }, ['text']), (a) => {
    const t = String(need(a.text, 'text is required'));
    return wb().analyzeText(t.slice(0, 200000));
  });

  def('decision_accuracy', 'Decision accuracy', 'How often each investigation engine was right, judged by analyst overrides and feedback, with confidence calibration and the most common mistakes.', S({ days: int('Window in days (default 30)') }), async (a) => {
    const r = await wb().decisions({ days: a.days, limit: 20 });
    return { days: r.days, totals: r.totals, engines: r.engines, calibration: r.bands, mistakes: r.mistakes, recent_wrong: r.rows.filter((x) => x.correct === false).slice(0, 10) };
  });

  def('list_custom_rules', 'List custom detections', 'Analyst-written Sigma rules with their level, ATT&CK technique, state and hit count.', S({}), async () => (await wb().listCustom()).map(({ yaml, ...r }) => r));

  def('list_workflows', 'List workflows', 'Saved response workflows with their inputs, steps and last result.', S({}), async () => (await wb().listWorkflows()).map((w) => ({ workflow_id: w.workflow_id, name: w.name, description: w.description, enabled: w.enabled, inputs: w.inputs, steps: w.steps.map((s) => `${s.id}:${s.type}`), runs: w.runs, last_status: w.last_status, last_run_at: w.last_run_at })));

  def('run_workflow', 'Run workflow', 'Run a saved workflow with its inputs. Steps run in order; containment inside a workflow still follows the approval policy.', S({
    workflow_id: str('WF-...'), input: { type: 'object', description: 'Input values keyed by the workflow input keys', additionalProperties: { type: 'string' } }
  }, ['workflow_id']), async (a, who) => {
    const r = await wb().startRun(need(a.workflow_id, 'workflow_id is required'), a.input || {}, who);
    return { run_id: r.run_id, status: r.status, duration_ms: r.duration_ms, steps: r.steps.map(({ output, ...s }) => s) };
  }, { write: true });

  return tools;
}

function registerMcp(app, ctx, svc) {
  const { store, wrap, env } = ctx;
  const tools = buildTools(ctx, svc);
  // Web connectors send CORS preflights; tokens travel in the Authorization header, never cookies.
  const byName = new Map(tools.map((t) => [t.name, t]));
  const limiter = auth.rateLimit({ windowMs: 60000, max: Number(env.MCP_RATE_LIMIT) || 300, key: (req) => `mcp:${req.ip}` });

  const authKey = wrap(async (req, res, next) => {
    const raw = auth.bearer(req);
    const deny = (code, msg) => { if (code === 401) res.set('WWW-Authenticate', ctx.oauth ? ctx.oauth.challenge(req) : 'Bearer realm="aegis-mcp"'); res.status(code).json({ jsonrpc: '2.0', id: null, error: { code: -32001, message: msg } }); };
    if (!raw) return deny(401, 'Sign in with OAuth, or send an API key: Authorization: Bearer aeg_... (scope mcp or mcp:write)');
    // OAuth access tokens (claude.ai and other web connectors) act as the signed-in user.
    if (ctx.oauth && raw.startsWith('aeo_')) {
      const grant = await ctx.oauth.verify(raw);
      if (!grant) return deny(401, 'The access token is invalid, expired or revoked');
      req.apiKey = grant;
      return next();
    }
    const key = await store.apiKeys.byHash(auth.hashApiKey(raw));
    if (!key) return deny(401, 'Invalid or revoked API key');
    if (!(key.scopes || []).some((s) => SCOPES.includes(s))) return deny(403, 'This key has no MCP scope; create one with "mcp" or "mcp:write" in Settings');
    req.apiKey = key;
    store.apiKeys.touch(key.id).catch(() => {});
    next();
  });

  // Browsers must not be able to drive the server from another site, except the
  // Claude web app and any origin listed in MCP_ALLOWED_ORIGINS. Auth is a bearer
  // token in a header, never a cookie, so an allowed origin still needs a token.
  const allowed = new Set(['https://claude.ai', 'https://claude.com', ...String(env.MCP_ALLOWED_ORIGINS || '').split(',').map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean)]);
  const origin = (req, res, next) => {
    const o = req.get('origin');
    if (o && o !== 'null') {
      let host = null;
      try { host = new URL(o).host; } catch { host = null; }
      if (host !== req.get('host')) {
        if (!allowed.has(o)) return res.status(403).json({ jsonrpc: '2.0', id: null, error: { code: -32002, message: 'Cross-origin MCP requests are not allowed' } });
        res.set({ 'Access-Control-Allow-Origin': o, Vary: 'Origin', 'Access-Control-Allow-Headers': 'Content-Type, Authorization, MCP-Protocol-Version, Mcp-Session-Id', 'Access-Control-Allow-Methods': 'POST, GET, DELETE, OPTIONS', 'Access-Control-Expose-Headers': 'WWW-Authenticate, Mcp-Session-Id' });
        if (req.method === 'OPTIONS') return res.status(204).end();
      }
    }
    next();
  };

  async function handle(msg, req) {
    const id = msg && Object.prototype.hasOwnProperty.call(msg, 'id') ? msg.id : undefined;
    const reply = (result) => ({ jsonrpc: '2.0', id, result });
    const error = (code, message, data) => ({ jsonrpc: '2.0', id: id === undefined ? null : id, error: { code, message, ...(data ? { data } : {}) } });
    if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return error(-32600, 'Invalid request');
    if (id === undefined) return null; // notification: nothing to send back
    const p = msg.params || {};
    const writer = (req.apiKey.scopes || []).includes('mcp:write');
    switch (msg.method) {
      case 'initialize':
        return reply({
          protocolVersion: VERSIONS.includes(p.protocolVersion) ? p.protocolVersion : VERSIONS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'aegis-security', title: 'Aegis Security', version: pkg.version },
          instructions: `Aegis is a security operations platform. Start with "overview", then list_alerts / get_alert. investigate_alert runs the full engine. Containment (block_ip) follows the server's approval policy and may return a pending approval. This key is ${writer ? 'read-write' : 'read-only'}.`
        });
      case 'ping': return reply({});
      case 'tools/list':
        return reply({
          tools: tools.filter((t) => writer || !t.write).map((t) => ({
            name: t.name, title: t.title, description: t.description, inputSchema: t.inputSchema,
            annotations: { title: t.title, readOnlyHint: !t.write, destructiveHint: t.name === 'block_ip', openWorldHint: ['lookup_indicator', 'bulk_check', 'ip_profile', 'block_ip'].includes(t.name) }
          }))
        });
      case 'tools/call': {
        const tool = byName.get(p.name);
        if (!tool) return error(-32602, `Unknown tool: ${p.name}`);
        if (tool.write && !writer) return reply({ content: [{ type: 'text', text: `${tool.name} changes state; this key only has the read-only "mcp" scope.` }], isError: true });
        const args = p.arguments && typeof p.arguments === 'object' ? p.arguments : {};
        const who = { name: `mcp:${req.apiKey.name}`, id: null };
        const started = Date.now();
        const brief = Object.entries(args).filter(([, v]) => v != null && typeof v !== 'object').map(([k, v]) => `${k}=${String(v).slice(0, 40)}`).join(' ').slice(0, 200);
        // A start row lets the console show the call while it runs; the finish row shares its id.
        const cid = crypto.randomBytes(5).toString('hex');
        await store.audit.add({ actor: who.name, action: 'mcp.start', target: tool.name, detail: `#${cid} ${brief}`.trim() }).catch(() => {});
        let out; let failed = null;
        try { out = await tool.run(args, who); } catch (err) {
          if (!(err instanceof ToolError) && !err.status) console.error(err);
          failed = err instanceof ToolError || err.status ? err.message : 'Internal error';
        }
        await store.audit.add({ actor: who.name, action: 'mcp.call', target: tool.name, detail: `#${cid} ${failed ? 'failed' : 'ok'} ${Date.now() - started}ms ${brief}${failed ? ` :: ${failed.slice(0, 160)}` : ''}`.replace(/\s+::/, ' ::').trim() }).catch(() => {});
        if (failed) return reply({ content: [{ type: 'text', text: failed }], isError: true });
        return reply({ content: [{ type: 'text', text: JSON.stringify(out, null, 1) }], isError: false });
      }
      case 'resources/list': return reply({ resources: [] });
      case 'prompts/list': return reply({ prompts: [] });
      default: return error(-32601, `Method not found: ${msg.method}`);
    }
  }

  const endpoint = [origin, limiter, authKey, wrap(async (req, res) => {
    const body = req.body;
    if (body === undefined || body === null || (typeof body === 'object' && !Array.isArray(body) && !Object.keys(body).length && !req.is('json'))) {
      return res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Send a JSON-RPC 2.0 message with Content-Type: application/json' } });
    }
    const batch = Array.isArray(body);
    if (batch && !body.length) return res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Empty batch' } });
    if (batch && body.length > 20) return res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'At most 20 messages per batch' } });
    const out = [];
    for (const m of batch ? body : [body]) { const r = await handle(m, req); if (r) out.push(r); }
    if (!out.length) return res.status(202).end();
    res.json(batch ? out : out[0]);
  })];
  const noStream = (req, res) => res.status(405).set('Allow', 'POST').json({ jsonrpc: '2.0', id: null, error: { code: -32000, message: 'This server is stateless; use POST' } });

  // ---- Live activity for the console ----------------------------------------------------
  // Polled by every signed-in user so people can see what a connected assistant is doing.
  // Reads the audit log, so it works across serverless instances.
  const ACTIVITY = ['mcp.start', 'mcp.call', 'oauth.granted', 'oauth.denied', 'oauth.token'];
  app.get('/api/mcp/activity', wrap(async (req, res) => {
    const after = Math.max(0, Number(req.query.after) || 0);
    const limit = Math.min(Math.max(Number(req.query.limit) || 60, 1), 200);
    const rows = store.audit.since ? await store.audit.since({ after, actions: ACTIVITY, limit })
      : (await store.audit.list(500)).filter((a) => a.id > after && ACTIVITY.includes(a.action)).slice(0, limit);
    res.set('Cache-Control', 'no-store');
    res.json({ events: rows.map((a) => activityEvent(a, byName)), now: new Date().toISOString() });
  }));

  for (const p of ['/mcp', '/api/mcp']) {
    app.options(p, origin, (req, res) => res.status(204).end());
    app.post(p, ...endpoint);
    app.get(p, noStream);
    app.delete(p, noStream);
  }
  return { tools };
}

// Turns an audit row into a structured activity event. Handles rows written before
// call ids existed ("ok 12ms a=b" / "failed: why 12ms a=b").
function activityEvent(a, byName) {
  const actor = String(a.actor || '').replace(/^mcp:/, '');
  const via = actor.lastIndexOf(' via ');
  const base = { id: a.id, at: a.created_at, kind: a.action, user: via > 0 ? actor.slice(0, via) : actor, client: via > 0 ? actor.slice(via + 5) : null };
  if (a.action.startsWith('oauth.')) {
    return { ...base, user: a.action === 'oauth.token' ? actor : base.user, client: a.target, detail: a.detail || null };
  }
  const tool = byName.get(a.target);
  let d = String(a.detail || '');
  let callId = null;
  const m = /^#([0-9a-f]+)\s?/.exec(d);
  if (m) { callId = m[1]; d = d.slice(m[0].length); }
  const ev = { ...base, call_id: callId, tool: a.target, title: tool ? tool.title : a.target, write: Boolean(tool && tool.write), status: 'running', ms: null, args: '', error: null };
  if (a.action === 'mcp.start') return { ...ev, args: d };
  let r = /^(ok|failed) (\d+)ms ?(.*?)(?: :: (.*))?$/s.exec(d);
  if (r) return { ...ev, status: r[1], ms: Number(r[2]), args: r[3] || '', error: r[4] || null };
  r = /^(?:(ok)|failed: (.*?)) (\d+)ms ?(.*)$/s.exec(d);
  if (r) return { ...ev, status: r[1] ? 'ok' : 'failed', ms: Number(r[3]), args: r[4] || '', error: r[2] || null };
  return { ...ev, status: 'ok', args: d };
}

module.exports = { registerMcp, buildTools, activityEvent, SCOPES, VERSIONS };