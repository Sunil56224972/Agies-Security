'use strict';

const { classifyPayload, exposureFor, isInternal, newId } = require('./analysis');

// Tool implementations shared by the deterministic playbook and the LLM agent.
// Every tool returns plain JSON and never throws; failures come back as { error }.
function createTools(store) {
  const tools = {
    async ingest_nids_alerts({ alert_id, severity } = {}) {
      if (alert_id) {
        const alert = await store.alerts.get(alert_id);
        return alert ? { alerts: [alert], count: 1 } : { error: `Alert ${alert_id} not found` };
      }
      const alerts = await store.alerts.list({ severity });
      return { alerts: alerts.slice(0, 20), count: alerts.length };
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
        indicators,
        raw_payload: alert.raw_payload
      };
    },

    async lookup_asset_inventory({ ip_address }) {
      const asset = await store.assets.get(ip_address);
      if (!asset) return { error: `No CMDB record for ${ip_address}` };
      return asset;
    },

    async query_cve_kb({ cve_id, keyword, asset_ip } = {}) {
      const matches = await store.cves.list(cve_id || keyword);
      const asset = asset_ip ? await store.assets.get(asset_ip) : null;
      return {
        query: cve_id || keyword || null,
        count: matches.length,
        matches: matches.map(c => {
          const { match_terms, ...rest } = c;
          if (!asset) return rest;
          const exp = exposureFor(asset, c);
          return { ...rest, asset_exposed: exp.exposed, exposure_evidence: exp.evidence };
        })
      };
    },

    async query_server_logs({ host_ip, log_type, client_ip, limit = 20 }) {
      if (!host_ip) return { error: 'host_ip is required' };
      const logs = await store.logs.list({ host_ip, log_type, client_ip, limit: Math.min(Number(limit) || 20, 100) });
      return { host_ip, log_type: log_type || 'all', count: logs.length, logs };
    },

    async execute_firewall_action({ action, target_ip, reason, investigation_id = null, actor = 'Aegis playbook' }) {
      if (!target_ip) return { error: 'target_ip is required' };
      if (action === 'UNBLOCK') {
        const active = await store.rules.activeFor(target_ip);
        for (const r of active) await store.rules.update(r.rule_id, { is_active: false });
        await store.audit.add({ actor, action: 'rule.rollback', target: target_ip, detail: reason || null });
        return { status: 'DEACTIVATED', target_ip, rules: active.map(r => r.rule_id) };
      }
      if (!['BLOCK', 'ISOLATE'].includes(action)) return { error: `Unsupported action ${action}` };
      const existing = (await store.rules.activeFor(target_ip)).find(r => r.action === action);
      if (existing) return { status: 'ALREADY_ENFORCED', rule: existing };
      const rule = await store.rules.insert({
        rule_id: newId('FW'), target_ip, action, reason: reason || 'No justification supplied',
        enacted_by: actor, is_active: true, packets_dropped: 0, investigation_id
      });
      await store.audit.add({ actor, action: `rule.${action.toLowerCase()}`, target: target_ip, detail: rule.rule_id });
      return { status: 'ENFORCED', rule };
    },

    async verify_defense_state({ target_ip }) {
      if (!target_ip) return { error: 'target_ip is required' };
      const active = await store.rules.activeFor(target_ip);
      if (!active.length) {
        return { target_ip, status: 'EXPOSED', connection_state: 'SYN_ACK_RECEIVED', packets_dropped: 0,
          message: `Probe from ${target_ip} reached the service. No active rule matches.` };
      }
      // Simulated probe burst: a handful of SYNs land on the drop rule.
      const rule = active[0];
      const burst = 24 + Math.floor(Math.random() * 40);
      const updated = await store.rules.update(rule.rule_id, { packets_dropped: Number(rule.packets_dropped || 0) + burst });
      return { target_ip, status: 'CONTAINED', connection_state: 'DROPPED', rule_id: rule.rule_id, action: rule.action,
        probe_packets: burst, packets_dropped: updated.packets_dropped,
        message: `${burst}/${burst} probe packets from ${target_ip} dropped by ${rule.rule_id}.` };
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
  ['lookup_asset_inventory', 'CMDB lookup for an internal host: OS, services, installed packages, WAF, criticality.', {
    ip_address: { type: 'string' } }, ['ip_address']],
  ['query_cve_kb', 'Search the vulnerability knowledge base. Pass asset_ip to get per-asset exposure.', {
    cve_id: { type: 'string' }, keyword: { type: 'string' }, asset_ip: { type: 'string' } }, []],
  ['query_server_logs', 'Read host telemetry (http_access, auth_log, edr_process, system) to see whether the exploit executed.', {
    host_ip: { type: 'string' }, client_ip: { type: 'string', description: 'Filter to lines involving this remote IP' },
    log_type: { type: 'string', enum: ['http_access', 'auth_log', 'edr_process', 'system'] }, limit: { type: 'number' } }, ['host_ip']],
  ['execute_firewall_action', 'Apply a sandbox containment rule. BLOCK an external IP, ISOLATE an internal host, or UNBLOCK to roll back.', {
    action: { type: 'string', enum: ['BLOCK', 'ISOLATE', 'UNBLOCK'] }, target_ip: { type: 'string' }, reason: { type: 'string' } }, ['action', 'target_ip', 'reason']],
  ['verify_defense_state', 'Send a probe from the given IP and report whether containment drops it.', {
    target_ip: { type: 'string' } }, ['target_ip']],
  ['record_investigation_verdict', 'Submit the final verdict. Call exactly once, after containment is verified.', {
    alert_id: { type: 'string' }, attack_outcome: { type: 'string', enum: ['ATTACK_SUCCEEDED', 'ATTACK_FAILED', 'FALSE_POSITIVE', 'RECON_ONLY'] },
    confidence_score: { type: 'number' }, mitre_tactic: { type: 'string' }, mitre_technique: { type: 'string' },
    evidence_summary: { type: 'string' } }, ['alert_id', 'attack_outcome', 'confidence_score', 'evidence_summary']]
].map(([name, description, properties, required]) => ({
  type: 'function',
  function: { name, description, parameters: { type: 'object', properties, required } }
}));

module.exports = { createTools, TOOL_DEFINITIONS };