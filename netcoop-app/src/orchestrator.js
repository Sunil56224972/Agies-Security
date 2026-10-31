'use strict';

// NetCoop AI: top-level orchestrator that wires the bus, the agents and
// the normaliser, runs the protocol phases in order, and returns the
// finished report together with the full message log.

const { normalizeInput, REPORT_SCHEMA } = require('./schema');
const { MessageBus, createAgents, PROTOCOL, SCORING, ROLES } = require('./agents');
const { synthesizeWithGroq } = require('./groq');
const scenarios = require('./scenarios');

let _runSeq = 0;

/**
 * Run a full cooperative diagnosis.
 *
 * @param {string|object} input  Raw telemetry — JSON string, object, or CSV/NDJSON string
 * @param {object}        [opts] Optional overrides
 * @param {string}        [opts.runId]   Override auto-generated run id
 * @returns {{ report, messages, quality, meta, error? }}
 */
async function diagnose(input, opts = {}) {
  const t0 = Date.now();
  const runId = opts.runId || `R-${Date.now()}-${++_runSeq}`;

  // ── 1. Normalise input ──────────────────────────────────────────
  let raw = input;
  if (typeof raw === 'object' && raw !== null && !Array.isArray(raw) && raw.telemetry !== undefined) raw = raw.telemetry;
  if (typeof raw === 'object' && !Array.isArray(raw)) raw = JSON.stringify(raw);

  const norm = normalizeInput(raw);
  if (!norm.ok) {
    const errText = (norm.errors || []).map(e => typeof e === 'string' ? e : e.message || JSON.stringify(e)).join('; ');
    return {
      report: {
        schema: REPORT_SCHEMA, run_id: runId, timestamp: new Date().toISOString(),
        status: 'error', error: errText,
        root_cause: null, confidence: 0, category: 'unknown',
        evidence: [], alternatives: [], scope: { impaired: [], total: 0 },
        recommended_actions: [], data_quality: norm.quality, scoring_method: SCORING
      },
      messages: [], quality: norm.quality, meta: { elapsed_ms: Date.now() - t0, agents: 0, messages: 0 },
      error: errText
    };
  }

  const ds = norm.dataset;

  // ── 2. Create bus + agents ──────────────────────────────────────
  const env = {
    quality: norm.quality,
    meta: ds.meta || {},
    incidentId: (ds.meta && ds.meta.incident_id) || null,
    sourceName: (ds.meta && ds.meta.source) || null
  };
  const bus = new MessageBus(runId);
  const agents = createAgents(ds, bus, env);
  for (const agent of agents) bus.register(agent);

  // ── 3. Phase 1: send tasks to performance + infrastructure ─────
  const devices = ds.ids();
  // Collect all metric keys seen across all devices
  const metricKeySet = new Set();
  for (const id of devices) {
    for (const s of ds.samplesOf(id)) {
      if (s.metrics) for (const k of Object.keys(s.metrics)) metricKeySet.add(k);
    }
  }
  const taskPayload = { devices, metric_keys: [...metricKeySet], sample_count: ds.sampleCount };

  bus.send('orchestrator', 'performance_agent', 'task', taskPayload, { summary: 'Analyse performance metrics for all devices' });
  bus.send('orchestrator', 'infrastructure_agent', 'task', taskPayload, { summary: 'Analyse infrastructure metrics for all devices' });
  await bus.run();

  // ── 4. Phase 2: connectivity ───────────────────────────────────
  const findingRefs = bus.log.filter(m => m.type === 'finding').map(m => m.message_id);
  bus.send('orchestrator', 'connectivity_agent', 'task', { ...taskPayload, finding_refs: findingRefs }, { summary: 'Evaluate connectivity and topology impact' });
  await bus.run();

  // ── 5. Phase 3: correlation ────────────────────────────────────
  const allFindingRefs = bus.log.filter(m => m.type === 'finding' || m.type === 'result').map(m => m.message_id);
  bus.send('orchestrator', 'correlation_agent', 'task', { ...taskPayload, finding_refs: allFindingRefs }, { summary: 'Correlate findings and determine root cause' });
  await bus.run();

  // handle any challenges the correlation agent raised
  let safety = 0;
  while (bus.inbox.some(m => m.type === 'challenge') && safety++ < 10) {
    const challenges = bus.inbox.filter(m => m.type === 'challenge');
    bus.inbox = bus.inbox.filter(m => m.type !== 'challenge');
    for (const c of challenges) {
      // route challenge to the target agent
      const targetAgent = c.payload.target_agent || c.to;
      if (targetAgent !== 'orchestrator') {
        bus.send('orchestrator', targetAgent, 'challenge', c.payload, { inReplyTo: c.message_id, summary: 'Forwarding challenge from correlation' });
      }
    }
    await bus.run();
    // feed responses back to correlation
    const responses = bus.log.filter(m => m.type === 'challenge_response' && m.to === 'orchestrator');
    for (const r of responses) {
      bus.send('orchestrator', 'correlation_agent', 'challenge_response', r.payload, { inReplyTo: r.message_id, summary: 'Forwarding challenge response' });
    }
    await bus.run();
  }

  // ── 6. Phase 4: reporting ──────────────────────────────────────
  const corrResults = bus.log.filter(m => m.from === 'correlation_agent' && m.type === 'result');
  const lastCorr = corrResults[corrResults.length - 1] || null;
  if (lastCorr) {
    // Forward the correlation diagnosis result to the reporting agent (it expects type 'result' with kind 'diagnosis')
    bus.send('orchestrator', 'reporting_agent', 'result', lastCorr.payload, { summary: 'Generate final diagnosis report' });
  } else {
    bus.send('orchestrator', 'reporting_agent', 'task', { finding_refs: bus.log.filter(m => m.type === 'finding').map(m => m.message_id) }, { summary: 'Generate final diagnosis report' });
  }
  await bus.run();

  // ── 7. Collect the report ──────────────────────────────────────
  const reportMsgs = bus.log.filter(m => m.from === 'reporting_agent' && m.type === 'result');
  const reportMsg = reportMsgs[reportMsgs.length - 1];

  let report;
  if (reportMsg && reportMsg.payload && reportMsg.payload.report) {
    // The reporting agent wraps its output as { kind: 'report', report: { ... } }
    const agentReport = reportMsg.payload.report;
    report = {
      run_id: runId,
      timestamp: new Date().toISOString(),
      ...agentReport,
      data_quality: norm.quality,
      scoring_method: SCORING
    };
  } else if (reportMsg && reportMsg.payload) {
    report = {
      schema: REPORT_SCHEMA,
      run_id: runId,
      timestamp: new Date().toISOString(),
      status: 'complete',
      ...reportMsg.payload,
      data_quality: norm.quality,
      scoring_method: SCORING
    };
  } else {
    // fallback — build a minimal report from the correlation result
    const corr = lastCorr && lastCorr.payload ? lastCorr.payload : {};
    report = {
      schema: REPORT_SCHEMA,
      run_id: runId,
      timestamp: new Date().toISOString(),
      status: 'complete',
      root_cause: corr.root_cause || corr.hypothesis || 'undetermined',
      confidence: corr.confidence || 0,
      category: corr.category || 'unknown',
      evidence: corr.evidence || [],
      alternatives: corr.alternatives || [],
      scope: corr.scope || { impaired: devices.filter(d => ds.ancestors(d).length > 0), total: devices.length },
      recommended_actions: corr.recommended_actions || [],
      data_quality: norm.quality,
      scoring_method: SCORING
    };
  }

  // ── 8. Groq LLM reasoning & technical action synthesis ────────
  try {
    const rootCause = report.suspected_root_cause || report.root_cause || 'undetermined';
    const confidence = report.confidence || 0;
    const evidence = report.supporting_evidence || report.evidence || [];
    const affectedDevices = report.affected_devices || (report.scope && report.scope.impaired_devices) || [];
    const alternatives = report.alternative_cause_details || report.alternative_causes || report.alternatives || [];

    if (rootCause !== 'undetermined' && report.status !== 'error') {
      const llm = await synthesizeWithGroq({ rootCause, confidence, evidence, affectedDevices, alternatives }, bus);
      if (llm) {
        report.llm_synthesis = llm;
        if (llm.reasoning) report.llm_reasoning = llm.reasoning;
        if (llm.actions && llm.actions.length) {
          const baseline = report.recommended_actions || [];
          report.recommended_actions = [...llm.actions, ...baseline.filter(a => !llm.actions.includes(a))];
        }
        if (llm.prevention && llm.prevention.length) {
          report.preventive_measures = llm.prevention;
        }
      }
    }
  } catch (err) {
    console.warn('[NetCoop] Groq synthesis fallback:', err.message);
  }

  // attach agent failures if any
  if (bus.failures.length) report.agent_failures = bus.failures;

  const meta = {
    elapsed_ms: Date.now() - t0,
    agents: ROLES.length,
    messages: bus.log.length,
    devices: devices.length,
    samples: ds.sampleCount
  };

  return { report, messages: bus.log, quality: norm.quality, meta };
}

/**
 * Generate synthetic telemetry for a named test scenario.
 */
function generateScenario(key) {
  return scenarios.generate(key);
}

/**
 * List available test scenarios.
 */
function listScenarios() {
  return scenarios.SCENARIOS.map(s => ({ key: s.key, name: s.name, description: s.description }));
}

module.exports = { diagnose, generateScenario, listScenarios, PROTOCOL, SCORING, ROLES };

