'use strict';

const { classifyPayload, exposureFor, isInternal, newId } = require('./analysis');
const { RecordAdapter } = require('../enforce');
const { CVE_RE } = require('../intel/nvd');

const CONTAINED_STATES = ['ENFORCED'];

// Tool implementations shared by the deterministic playbook and the LLM agent.
// Every tool returns plain JSON and never throws; failures come back as { error }.
function createTools(store, { enforcer = new RecordAdapter(), nvd = null, reputation = null } = {}) {
  const tools = {
    async ingest_nids_alerts({ alert_id, severity } = {}) {
      if (alert_id) {
        const alert = await store.alerts.get(alert_id);
        return alert ? { alerts: [alert], count: 1 } : { error: `Alert ${alert_id} not found` };
      }
      const alerts = await store.alerts.list({ severity, limit: 20 });
      return { alerts, count: alerts.length };
    },

    async get_packet_metadata({ alert_id }) {
      const alert = await store.alerts.get(alert_id);
      if (!alert) return { error: `Alert ${alert_id} not found` };
      const { technique, indicators } = classifyPayload(alert.raw_payload);
      return {
        alert_id: alert.alert_id,
        flow: `${alert.source_ip} -> ${alert.dest_ip}:${alert.dest_port} (${alert.protocol})`,
        direction: isInternal(alert.source_ip) && !isInternal(alert.dest_ip) ? 'outbound' : 'inbound',
        bytes_captured: alert.raw_payload.length,
        technique: technique ? technique.label : 'Unclassified',
        technique_id: technique ? technique.id : null,
        sensor_rule: alert.external_ref || null,
        indicators,
        raw_payload: alert.raw_payload
      };
    },

    async lookup_asset_inventory({ ip_address }) {
      const asset = await store.assets.get(ip_address);
      if (!asset) return { error: `No inventory record for ${ip_address}` };
      return asset;
    },

    async check_ip_reputation({ ip_address }) {
      if (!ip_address) return { error: 'ip_address is required' };
      if (isInternal(ip_address)) return { ip: ip_address, skipped: true, reason: 'Internal address' };
      if (!reputation || !reputation.available) return { ip: ip_address, skipped: true, reason: 'No reputation provider configured' };
      try { return await reputation.check(ip_address); } catch (err) { return { error: err.message }; }
    },

    async query_cve_kb({ cve_id, keyword, asset_ip } = {}) {
      let fetched = null;
      // Unknown CVE id: pull the record from NVD and keep it.
      if (cve_id && CVE_RE.test(cve_id) && nvd && !(await store.cves.get(cve_id.toUpperCase()))) {
        try {
          const rec = await nvd.fetchCve(cve_id);
          if (rec) { await store.cves.upsert([rec]); fetched = 'NVD'; }
        } catch (err) { fetched = `NVD lookup failed: ${err.message}`; }
      }
      const matches = cve_id ? [await store.cves.get(String(cve_id).toUpperCase())].filter(Boolean) : await store.cves.list(keyword);
      const asset = asset_ip ? await store.assets.get(asset_ip) : null;
      return {
        query: cve_id || keyword || null,
        fetched,
        count: matches.length,
        matches: matches.slice(0, 10).map((c) => {
          const { match_terms, cpe_matches, ...rest } = c;
          const out = { ...rest, cpe_ranges: (cpe_matches || []).length };
          if (!asset) return out;
          const exp = exposureFor(asset, c);
          return { ...out, asset_exposed: exp.exposed, exposure_evidence: exp.evidence };
        })
      };
    },

    async query_server_logs({ host_ip, log_type, client_ip, limit = 20 }) {
      if (!host_ip) return { error: 'host_ip is required' };
      const logs = await store.logs.list({ host_ip, log_type, client_ip, limit: Math.min(Number(limit) || 20, 100) });
      return { host_ip, log_type: log_type || 'all', count: logs.length, logs };
    },

    async execute_firewall_action({ action, target_ip, reason, investigation_id = null, actor = 'Aegis playbook', ttl_hours }) {
      if (!target_ip) return { error: 'target_ip is required' };
      if (action === 'UNBLOCK') {
        const active = await store.rules.activeFor(target_ip);
        for (const r of active) await store.rules.update(r.rule_id, { is_active: false, enforcement: await enforcer.remove(r) });
        await store.audit.add({ actor, action: 'rule.rollback', target: target_ip, detail: reason || null });
        return { status: 'DEACTIVATED', target_ip, rules: active.map((r) => r.rule_id) };
      }
      if (!['BLOCK', 'ISOLATE'].includes(action)) return { error: `Unsupported action ${action}` };
      const existing = (await store.rules.activeFor(target_ip)).find((r) => r.action === action);
      if (existing) return { status: 'ALREADY_ENFORCED', rule: existing };
      // Engine-created blocks take the policy TTL; callers pass ttl_hours (or null) explicitly.
      let ttl = ttl_hours;
      if (ttl === undefined) ttl = action === 'BLOCK' ? Number((await store.config.get()).autoBlockTtlHours) || null : null;
      const draft = {
        rule_id: newId('FW'), target_ip, action, reason: reason || 'No justification supplied',
        enacted_by: actor, is_active: true, investigation_id,
        expires_at: ttl ? new Date(Date.now() + ttl * 3600000).toISOString() : null
      };
      const enforcement = await enforcer.apply(draft);
      const rule = await store.rules.insert({ ...draft, enforcement });
      await store.audit.add({ actor, action: `rule.${action.toLowerCase()}`, target: target_ip, detail: `${rule.rule_id} ${enforcement.mode}:${enforcement.status}${rule.expires_at ? ` until ${rule.expires_at}` : ''}` });
      return { status: 'APPLIED', enforcement: enforcement.status, rule };
    },

    // Reads the rule back from the enforcement backend. This does not send traffic.
    async verify_defense_state({ target_ip }) {
      if (!target_ip) return { error: 'target_ip is required' };
      const active = await store.rules.activeFor(target_ip);
      if (!active.length) {
        return { target_ip, status: 'NO_RULE', contained: false, mode: enforcer.mode, message: `No active rule covers ${target_ip}.` };
      }
      const checks = [];
      for (const rule of active) {
        const e = await enforcer.verify(rule);
        if (JSON.stringify(e) !== JSON.stringify(rule.enforcement)) await store.rules.update(rule.rule_id, { enforcement: e });
        checks.push({ rule_id: rule.rule_id, action: rule.action, ...e });
      }
      const best = checks.find((c) => CONTAINED_STATES.includes(c.status)) || checks.find((c) => c.status === 'PENDING') || checks[0];
      return {
        target_ip, status: best.status, contained: CONTAINED_STATES.includes(best.status), mode: best.mode,
        rule_id: best.rule_id, action: best.action, checked_at: new Date().toISOString(),
        rules: checks, message: `${best.rule_id} (${best.action}) via ${best.mode}: ${best.detail}`
      };
    },

    async record_investigation_verdict(args) {
      const alert = await store.alerts.get(args.alert_id);
      if (!alert) return { error: `Alert ${args.alert_id} not found` };
      return { accepted: true, note: 'Verdict captured; the platform persists it when the run completes.', ...args };
    }
  };
  return tools;
}
const TOOL_DEFINITIONS = [
  ['ingest_nids_alerts', 'Fetch one alert by id, or list recent NIDS alerts.', {
    alert_id: { type: 'string', description: 'Alert id, e.g. ALERT-2026-9001' },
    severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] } }, []],
  ['get_packet_metadata', 'Decode the captured payload for an alert: flow, direction, technique classification and indicators.', {
    alert_id: { type: 'string' } }, ['alert_id']],
  ['lookup_asset_inventory', 'Inventory lookup for an internal host: OS, services, installed packages, WAF, criticality.', {
    ip_address: { type: 'string' } }, ['ip_address']],
  ['check_ip_reputation', 'Reputation of an external IP from the configured threat-intel provider (AbuseIPDB).', {
    ip_address: { type: 'string' } }, ['ip_address']],
  ['query_cve_kb', 'Look up a CVE (fetched from NVD if not cached) or search by keyword. Pass asset_ip to get per-asset exposure from CPE version ranges.', {
    cve_id: { type: 'string' }, keyword: { type: 'string' }, asset_ip: { type: 'string' } }, []],
  ['query_server_logs', 'Read host telemetry (http_access, auth_log, edr_process, system) to see whether the exploit executed.', {
    host_ip: { type: 'string' }, client_ip: { type: 'string', description: 'Filter to lines involving this remote IP' },
    log_type: { type: 'string', enum: ['http_access', 'auth_log', 'edr_process', 'system'] }, limit: { type: 'number' } }, ['host_ip']],
  ['execute_firewall_action', 'Create a containment rule and push it to the enforcement backend. BLOCK an external IP, ISOLATE an internal host, or UNBLOCK to roll back.', {
    action: { type: 'string', enum: ['BLOCK', 'ISOLATE', 'UNBLOCK'] }, target_ip: { type: 'string' }, reason: { type: 'string' } }, ['action', 'target_ip', 'reason']],
  ['verify_defense_state', 'Read the rule for this IP back from the enforcement backend and report whether it is in force.', {
    target_ip: { type: 'string' } }, ['target_ip']],
  ['record_investigation_verdict', 'Submit the final verdict. Call exactly once, after containment is verified.', {
    alert_id: { type: 'string' }, attack_outcome: { type: 'string', enum: ['ATTACK_SUCCEEDED', 'ATTACK_FAILED', 'FALSE_POSITIVE', 'RECON_ONLY'] },
    confidence_score: { type: 'number' }, mitre_tactic: { type: 'string' }, mitre_technique: { type: 'string' },
    evidence_summary: { type: 'string' } }, ['alert_id', 'attack_outcome', 'confidence_score', 'evidence_summary']]
].map(([name, description, properties, required]) => ({
  type: 'function',
  function: { name, description, parameters: { type: 'object', properties, required } }
}));

module.exports = { createTools, TOOL_DEFINITIONS, CONTAINED_STATES };