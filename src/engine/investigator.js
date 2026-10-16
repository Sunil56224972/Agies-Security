'use strict';

const Groq = require('groq-sdk');
const { SEVERITY_RANK, classifyPayload, exposureFor, assessLogs, isInternal, newId } = require('./analysis');
const { createTools, TOOL_DEFINITIONS } = require('./tools');
const { RecordAdapter } = require('../enforce');

const OUTCOME_STATUS = {
  ATTACK_SUCCEEDED: 'CONFIRMED',
  ATTACK_FAILED: 'MITIGATED',
  FALSE_POSITIVE: 'FALSE_POSITIVE',
  RECON_ONLY: 'CLOSED'
};

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

class Investigator {
  constructor(store, { groqKey, model, enforcer = new RecordAdapter(), nvd = null, reputation = null } = {}) {
    this.store = store;
    this.enforcer = enforcer;
    this.reputation = reputation;
    this.tools = createTools(store, { enforcer, nvd, reputation });
    this.model = model || 'llama-3.3-70b-versatile';
    this.groq = groqKey ? new Groq({ apiKey: groqKey }) : null;
    this.running = new Set();
  }

  get llmAvailable() { return Boolean(this.groq); }

  // Runs one tool and reports it as a timeline step.
  async call(ctx, phase, tool, args, title) {
    const started = Date.now();
    ctx.emit({ type: 'step', state: 'running', phase, tool, title });
    const result = await this.tools[tool](args);
    const step = { phase, tool, title, args, ms: Date.now() - started, ok: !result.error, error: result.error || null };
    ctx.steps.push(step);
    ctx.emit({ type: 'step', state: result.error ? 'error' : 'done', ...step, result });
    if (ctx.pace) await sleep(ctx.pace);
    return result;
  }

  note(ctx, phase, title, detail, kind = 'note') {
    const step = { phase, tool: null, title, detail, kind, ok: true, ms: 0 };
    ctx.steps.push(step);
    ctx.emit({ type: 'step', state: 'done', ...step });
  }

  async run(alertId, emit = () => {}, { engine, pace = 260 } = {}) {
    if (this.running.has(alertId)) throw new Error(`${alertId} is already under investigation`);
    this.running.add(alertId);
    const ctx = { alertId, emit, steps: [], actions: [], pace, started: Date.now() };
    try {
      const alert = await this.store.alerts.get(alertId);
      if (!alert) throw new Error(`Alert ${alertId} not found`);
      const config = await this.store.config.get();
      await this.store.alerts.update(alertId, { status: 'INVESTIGATING' });

      const useLlm = (engine || config.engine) === 'llm' && this.llmAvailable;
      let verdict = null;
      ctx.engine = 'playbook';
      if (useLlm) {
        try {
          ctx.engine = `llm:${this.model}`;
          verdict = await this.runLlm(ctx, alert);
        } catch (err) {
          this.note(ctx, 'adapt', 'Model unavailable, switching to deterministic playbook', err.message, 'adaptation');
          ctx.engine = 'playbook (llm fallback)';
        }
      }
      if (!verdict) verdict = await this.runPlaybook(ctx, alert, config);
      return await this.finish(ctx, alert, verdict);
    } catch (err) {
      await this.store.alerts.update(alertId, { status: 'NEW' }).catch(() => {});
      throw err;
    } finally {
      this.running.delete(alertId);
    }
  }

  async runPlaybook(ctx, alert, config) {
    await this.call(ctx, 'triage', 'ingest_nids_alerts', { alert_id: alert.alert_id }, 'Pull alert from sensor queue');
    const pkt = await this.call(ctx, 'triage', 'get_packet_metadata', { alert_id: alert.alert_id }, 'Decode captured payload');
    const { technique } = classifyPayload(alert.raw_payload);

    // Outbound traffic means the internal host is the suspect, not the victim.
    const outbound = pkt.direction === 'outbound';
    const hostIp = outbound ? alert.source_ip : alert.dest_ip;
    const remoteIp = outbound ? alert.dest_ip : alert.source_ip;
    ctx.hostIp = hostIp;
    ctx.remoteIp = remoteIp;

    const asset = await this.call(ctx, 'enrich', 'lookup_asset_inventory', { ip_address: hostIp }, `Inventory lookup for ${hostIp}`);
    const hasAsset = !asset.error;
    if (!hasAsset) this.note(ctx, 'adapt', 'Host missing from inventory', 'Exposure cannot be confirmed. Weighting host telemetry more heavily.', 'adaptation');

    let rep = null;
    if (this.reputation && this.reputation.available && !isInternal(remoteIp)) {
      rep = await this.call(ctx, 'enrich', 'check_ip_reputation', { ip_address: remoteIp }, `Reputation of ${remoteIp}`);
      if (rep.error) rep = null;
    }

    let exposure = { exposed: false, evidence: null };
    let cve = null;
    if (technique && technique.cve) {
      const kb = await this.call(ctx, 'enrich', 'query_cve_kb', { cve_id: technique.cve, asset_ip: hasAsset ? hostIp : undefined }, `Correlate with ${technique.cve}`);
      cve = (kb.matches || [])[0] || null;
      if (cve && hasAsset) exposure = exposureFor(asset, await this.store.cves.get(cve.cve_id));
    }

    const logRes = await this.call(ctx, 'correlate', 'query_server_logs', { host_ip: hostIp, client_ip: remoteIp, limit: 25 }, `Host telemetry on ${hostIp} for ${remoteIp}`);
    const logs = logRes.logs || [];
    const ev = assessLogs(logs);

    // --- Decide -----------------------------------------------------------
    let outcome; let confidence; const reasons = [];
    const tid = technique ? technique.id : null;
    if (technique && technique.requiresExposure && hasAsset && !exposure.exposed) {
      outcome = 'FALSE_POSITIVE'; confidence = ev.execution.length ? 60 : 94;
      reasons.push(`Payload targets ${cve ? cve.affected_products.join(', ') : technique.label}, but ${asset.hostname} runs ${(asset.running_services || []).map(s => s.service).join(', ')}.`);
      if (ev.rejection.length) reasons.push(`Host rejected the request: "${ev.rejection[0].raw_entry}"`);
      this.note(ctx, 'adapt', 'Replanning: target stack does not match exploit prerequisites', reasons[0], 'adaptation');
    } else if (ev.execution.length || ev.access.length) {
      outcome = 'ATTACK_SUCCEEDED';
      confidence = Math.min(99, 80 + 6 * ev.execution.length + (exposure.exposed ? 5 : 0));
      if (exposure.exposed) reasons.push(`${asset.hostname} runs vulnerable component: ${exposure.evidence}.`);
      reasons.push(...[...ev.execution, ...ev.access].slice(0, 3).map(l => `Telemetry: ${l.raw_entry}`));
    } else if (ev.rejection.length) {
      outcome = 'ATTACK_FAILED'; confidence = 88;
      reasons.push(...ev.rejection.slice(0, 2).map(l => `Rejected: ${l.raw_entry}`));
      if (tid === 'ssh_bruteforce') reasons.push('No successful authentication from the source address.');
    } else if (exposure.exposed) {
      outcome = 'ATTACK_FAILED'; confidence = 55;
      reasons.push(`Host is exposed (${exposure.evidence}) but no execution telemetry was found. Treating as unconfirmed.`);
      this.note(ctx, 'adapt', 'Evidence gap', 'Vulnerable host with no execution trace. Precautionary containment applies.', 'adaptation');
    } else {
      outcome = 'RECON_ONLY'; confidence = 70;
      reasons.push('No exposure and no host-side effect observed.');
    }
    if (rep && rep.score != null && rep.reports) {
      reasons.push(`AbuseIPDB: ${remoteIp} scores ${rep.score}/100 from ${rep.reports} reports${rep.isp ? ` (${rep.isp}${rep.country ? `, ${rep.country}` : ''})` : ''}.`);
      if (outcome === 'ATTACK_FAILED' && rep.score >= 75) confidence = Math.min(97, confidence + 4);
    }
    this.note(ctx, 'decide', `Verdict: ${outcome.replace('_', ' ').toLowerCase()} (${confidence}%)`, reasons.join(' '), 'verdict');

    // --- Contain ----------------------------------------------------------
    const threshold = config.autoContainmentThreshold || 'HIGH';
    const sevOk = threshold !== 'OFF' && SEVERITY_RANK[alert.severity] >= (SEVERITY_RANK[threshold] || 3);
    const shouldBlock = threshold !== 'OFF' && !isInternal(remoteIp) &&
      (outcome === 'ATTACK_SUCCEEDED' || (outcome === 'ATTACK_FAILED' && (sevOk || exposure.exposed)));
    const shouldIsolate = outcome === 'ATTACK_SUCCEEDED' && config.isolateOnCompromise && threshold !== 'OFF';

    if (shouldBlock) {
      const r = await this.call(ctx, 'contain', 'execute_firewall_action', { action: 'BLOCK', target_ip: remoteIp, reason: `${alert.alert_id}: ${outcome.toLowerCase()} - ${technique ? technique.label : alert.category}` }, `Block ${remoteIp} at perimeter`);
      if (r.rule) ctx.actions.push({ type: 'BLOCK', target: remoteIp, rule_id: r.rule.rule_id, status: r.status, enforcement: r.enforcement || (r.rule.enforcement && r.rule.enforcement.status) || null });
    }
    if (shouldIsolate) {
      const r = await this.call(ctx, 'contain', 'execute_firewall_action', { action: 'ISOLATE', target_ip: hostIp, reason: `${alert.alert_id}: confirmed compromise, quarantine pending forensics` }, `Isolate ${hostIp}`);
      if (r.rule) ctx.actions.push({ type: 'ISOLATE', target: hostIp, rule_id: r.rule.rule_id, status: r.status, enforcement: r.enforcement || (r.rule.enforcement && r.rule.enforcement.status) || null });
    }
    if (!shouldBlock && !shouldIsolate) {
      const why = outcome === 'FALSE_POSITIVE' ? 'False positive: no containment, avoiding collateral blocking.'
        : threshold === 'OFF' ? 'Auto-containment disabled in policy. Analyst action required.'
        : `Severity ${alert.severity} is below the ${threshold} auto-containment threshold. Recommendation logged.`;
      this.note(ctx, 'contain', 'No containment applied', why, 'policy');
    }

    // --- Verify -----------------------------------------------------------
    let verification = null;
    if (ctx.actions.length) {
      const first = ctx.actions[0];
      verification = await this.call(ctx, 'verify', 'verify_defense_state', { target_ip: first.target }, `Read back ${first.rule_id} from ${this.enforcer.label.toLowerCase()}`);
      if (verification.status === 'FAILED') {
        this.note(ctx, 'adapt', 'Enforcement backend did not confirm the rule, retrying once', verification.message, 'adaptation');
        verification = await this.call(ctx, 'verify', 'verify_defense_state', { target_ip: first.target }, 'Retry read-back');
      }
      if (!verification.contained) {
        const why = verification.status === 'PENDING' ? 'Rule is published but the firewall has not pulled it yet. The alert stays open until it does.'
          : verification.status === 'RECORDED' ? 'No enforcement backend is configured (ENFORCEMENT_MODE=record). Apply the rule on the firewall by hand.'
          : `Enforcement not confirmed: ${verification.message}`;
        this.note(ctx, 'verify', 'Containment not yet in force', why, 'policy');
      }
    }
    return {
      outcome, confidence, reasons,
      target_ip: hostIp, attacker_ip: remoteIp,
      mitre_tactic: technique ? technique.tactic : 'Discovery',
      mitre_technique: technique ? technique.technique : 'Unmapped',
      technique: technique ? technique.label : alert.category,
      cve: cve ? cve.cve_id : null,
      asset: hasAsset ? asset : null,
      exposure, verification,
      recommendations: recommend(outcome, cve, asset, tid)
    };
  }

  async runLlm(ctx, alert) {
    const system = `You are a tier-3 SOC analyst. Investigate the alert with the tools, in this order:
packet metadata -> asset inventory (for the internal host) -> IP reputation (external party) -> CVE knowledge base (pass asset_ip) -> host logs (pass client_ip).
Decide: ATTACK_SUCCEEDED needs host evidence of execution or access; ATTACK_FAILED when the host rejected it; FALSE_POSITIVE when the host does not run the targeted software.
If succeeded, BLOCK the external IP and ISOLATE the internal host, then verify_defense_state. Never block on a false positive.
Finish by calling record_investigation_verdict once, then reply with a short plain summary. Only use facts from tool output.`;
    const messages = [{ role: 'system', content: system }, { role: 'user', content: `Investigate ${alert.alert_id}.` }];
    const config = await this.store.config.get();
    let verdictArgs = null;
    let assetRes = null; let verification = null;

    for (let i = 0; i < (config.maxIterations || 12); i++) {
      const completion = await this.groq.chat.completions.create({
        model: this.model, messages, tools: TOOL_DEFINITIONS, tool_choice: 'auto', temperature: 0.1, max_tokens: 1200
      });
      const msg = completion.choices[0].message;
      messages.push(msg);
      if (!msg.tool_calls || !msg.tool_calls.length) {
        if (msg.content) this.note(ctx, 'decide', 'Analyst summary', msg.content, 'verdict');
        break;
      }
      for (const tc of msg.tool_calls) {
        let args = {};
        try { args = JSON.parse(tc.function.arguments || '{}'); } catch { args = {}; }
        const name = tc.function.name;
        if (!this.tools[name]) {
          messages.push({ role: 'tool', tool_call_id: tc.id, content: JSON.stringify({ error: `Unknown tool ${name}` }) });
          continue;
        }
        const phase = { get_packet_metadata: 'triage', ingest_nids_alerts: 'triage', lookup_asset_inventory: 'enrich', query_cve_kb: 'enrich', check_ip_reputation: 'enrich',
          query_server_logs: 'correlate', execute_firewall_action: 'contain', verify_defense_state: 'verify', record_investigation_verdict: 'decide' }[name];
        const res = await this.call(ctx, phase, name, { ...args, actor: name === 'execute_firewall_action' ? 'Aegis agent' : undefined }, labelFor(name, args));
        if (name === 'lookup_asset_inventory' && !res.error) assetRes = res;
        if (name === 'verify_defense_state') verification = res;
        if (name === 'execute_firewall_action' && res.rule) ctx.actions.push({ type: res.rule.action, target: res.rule.target_ip, rule_id: res.rule.rule_id, status: res.status, enforcement: res.enforcement || null });
        if (name === 'record_investigation_verdict' && res.accepted) verdictArgs = args;
        messages.push({ role: 'tool', tool_call_id: tc.id, content: JSON.stringify(res).slice(0, 6000) });
      }
    }
    if (!verdictArgs) throw new Error('Model ended without recording a verdict');

    const outbound = isInternal(alert.source_ip) && !isInternal(alert.dest_ip);
    const { technique } = classifyPayload(alert.raw_payload);
    return {
      outcome: verdictArgs.attack_outcome,
      confidence: Math.max(1, Math.min(100, Math.round(verdictArgs.confidence_score || 70))),
      reasons: [verdictArgs.evidence_summary],
      target_ip: outbound ? alert.source_ip : alert.dest_ip,
      attacker_ip: outbound ? alert.dest_ip : alert.source_ip,
      mitre_tactic: verdictArgs.mitre_tactic || (technique && technique.tactic) || null,
      mitre_technique: verdictArgs.mitre_technique || (technique && technique.technique) || null,
      technique: technique ? technique.label : alert.category,
      cve: technique ? technique.cve : null,
      asset: assetRes, exposure: null, verification,
      recommendations: recommend(verdictArgs.attack_outcome, technique && technique.cve ? { cve_id: technique.cve } : null, assetRes, technique && technique.id)
    };
  }

  async finish(ctx, alert, v) {
    const id = newId('INV');
    const contained = ctx.actions.length > 0 && Boolean(v.verification && v.verification.contained);
    let status = OUTCOME_STATUS[v.outcome] || 'CLOSED';
    if (v.outcome === 'ATTACK_SUCCEEDED' && contained) status = 'CONTAINED';

    const report = buildReport(alert, v, ctx.actions, id);
    const inv = await this.store.investigations.insert({
      investigation_id: id, alert_id: alert.alert_id, target_ip: v.target_ip, attacker_ip: v.attacker_ip,
      outcome: v.outcome, confidence: v.confidence, mitre_tactic: v.mitre_tactic, mitre_technique: v.mitre_technique,
      summary: v.reasons.join(' '), report, engine: ctx.engine, steps: ctx.steps, actions_taken: ctx.actions,
      verification: v.verification, duration_ms: Date.now() - ctx.started
    });
    for (const a of ctx.actions.filter(x => x.status === 'APPLIED')) await this.store.rules.update(a.rule_id, { investigation_id: id }).catch(() => {});
    await this.store.alerts.update(alert.alert_id, { status });
    await this.store.audit.add({ actor: ctx.engine.startsWith('llm') ? 'Aegis agent' : 'Aegis playbook', action: 'investigation.closed', target: alert.alert_id, detail: `${id} ${v.outcome} ${v.confidence}%` });
    ctx.emit({ type: 'verdict', investigation: inv, alert_status: status });
    return inv;
  }

  // Analyst disagrees with the verdict: apply the new outcome and reconcile containment.
  async override(investigationId, { outcome, notes, analyst }) {
    const inv = await this.store.investigations.get(investigationId);
    if (!inv) throw new Error('Investigation not found');
    if (!OUTCOME_STATUS[outcome]) throw new Error('Unknown outcome');
    const actor = analyst || 'Analyst';
    const changes = [];

    const rules = (await this.store.rules.list()).filter(r => r.investigation_id === investigationId && r.is_active);
    if (outcome === 'FALSE_POSITIVE' || outcome === 'RECON_ONLY') {
      for (const r of rules) {
        await this.store.rules.update(r.rule_id, { is_active: false, enforcement: await this.enforcer.remove(r) });
        changes.push(`Rolled back ${r.action} ${r.target_ip} (${r.rule_id})`);
      }
    } else if (outcome === 'ATTACK_SUCCEEDED' && !rules.some(r => r.target_ip === inv.attacker_ip) && !isInternal(inv.attacker_ip)) {
      const res = await this.tools.execute_firewall_action({ action: 'BLOCK', target_ip: inv.attacker_ip, reason: `Analyst override on ${investigationId}: ${notes || 'confirmed compromise'}`, investigation_id: investigationId, actor });
      if (res.rule) changes.push(`Blocked ${inv.attacker_ip} (${res.rule.rule_id})`);
      const check = await this.tools.verify_defense_state({ target_ip: inv.attacker_ip });
      changes.push(`Enforcement: ${check.status.toLowerCase()}`);
    }
    if (!changes.length) changes.push('Containment already consistent with new verdict');

    const override = { analyst: actor, notes: notes || '', previous_outcome: inv.outcome, outcome, changes, at: new Date().toISOString() };
    const updated = await this.store.investigations.update(investigationId, { outcome, human_override: override });
    const hasRule = (await this.store.rules.list()).some(r => r.investigation_id === investigationId && r.is_active && r.enforcement && r.enforcement.status === 'ENFORCED');
    await this.store.alerts.update(inv.alert_id, { status: outcome === 'ATTACK_SUCCEEDED' && hasRule ? 'CONTAINED' : OUTCOME_STATUS[outcome] });
    await this.store.audit.add({ actor, action: 'investigation.override', target: investigationId, detail: `${inv.outcome} -> ${outcome}` });
    return { investigation: updated, changes };
  }
}

function labelFor(name, a) {
  switch (name) {
    case 'get_packet_metadata': return 'Decode captured payload';
    case 'lookup_asset_inventory': return `Inventory lookup for ${a.ip_address}`;
    case 'check_ip_reputation': return `Reputation of ${a.ip_address}`;
    case 'query_cve_kb': return `Knowledge base: ${a.cve_id || a.keyword || 'search'}`;
    case 'query_server_logs': return `Host telemetry on ${a.host_ip}`;
    case 'execute_firewall_action': return `${a.action} ${a.target_ip}`;
    case 'verify_defense_state': return `Verify enforcement for ${a.target_ip}`;
    case 'record_investigation_verdict': return 'Submit verdict';
    default: return name;
  }
}

function recommend(outcome, cve, asset, tid) {
  const out = [];
  if (outcome === 'ATTACK_SUCCEEDED') {
    out.push('Capture memory and disk image before reimaging the host.');
    out.push('Rotate credentials and tokens reachable from the compromised service account.');
  }
  if (cve && cve.cve_id === 'CVE-2021-44228') out.push('Upgrade log4j-core to 2.17.1 and set log4j2.formatMsgNoLookups=true.');
  if (cve && /CVE-2021-4(1773|2013)/.test(cve.cve_id)) out.push('Upgrade Apache httpd to 2.4.51+ and disable mod_cgi where unused.');
  if (tid === 'sqli') out.push('Audit the targeted endpoint for string-built queries; keep the prepared-statement path.');
  if (tid === 'ssh_bruteforce') out.push('Disable SSH password auth on the target; keys only.');
  if (tid === 'c2_beacon') out.push('Hunt for the same JA3 / SNI across the fleet.');
  if (asset && !asset.waf_enabled && outcome !== 'FALSE_POSITIVE') out.push(`Put ${asset.hostname} behind the WAF.`);
  if (outcome === 'FALSE_POSITIVE') out.push('Tune the signature to skip hosts without the targeted runtime.');
  return out;
}

function buildReport(alert, v, actions, id) {
  const lines = [
    `## ${id} - ${alert.alert_id}`,
    '',
    `**Outcome:** ${v.outcome.replace(/_/g, ' ')} (${v.confidence}% confidence)`,
    `**Technique:** ${v.technique}${v.cve ? ` - ${v.cve}` : ''}`,
    `**MITRE ATT&CK:** ${v.mitre_tactic || 'n/a'} / ${v.mitre_technique || 'n/a'}`,
    `**Target:** ${v.target_ip}${v.asset ? ` (${v.asset.hostname}, ${v.asset.os_version})` : ''}`,
    `**Remote party:** ${v.attacker_ip}`,
    '',
    '### Evidence',
    ...v.reasons.map(r => `- ${r}`),
    '',
    '### Response',
    ...(actions.length ? actions.map(a => `- ${a.type} ${a.target} (${a.rule_id}, ${String(a.enforcement || a.status || '').toLowerCase()})`) : ['- No containment applied']),
    ...(v.verification ? [`- Verification: ${v.verification.message}`] : []),
    '',
    '### Next steps',
    ...v.recommendations.map(r => `- ${r}`)
  ];
  return lines.join('\n');
}

module.exports = { Investigator };