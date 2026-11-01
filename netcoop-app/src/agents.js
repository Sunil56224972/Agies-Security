'use strict';

// NetCoop AI: the message bus and the five cooperating agents.
//
//   performance_agent     latency, jitter, loss, utilization, Wi-Fi signal, DNS and DHCP service checks
//   infrastructure_agent  device status, link flaps, CPU, memory, queue drops, interface errors
//   connectivity_agent    topology: which impaired devices share an upstream, and how far it reaches
//   correlation_agent     scores competing root causes, challenges the agents that disagree, resolves
//   reporting_agent       turns the agreed diagnosis into the unified report
//
// Agents never read each other's memory. They exchange the envelopes defined in
// PROTOCOL through the bus; the orchestrator sequences the phases and routes by
// message id, so every hand-off is in the message log of the report.

const { MESSAGE_SCHEMA, REPORT_SCHEMA, METRICS } = require('./schema');
const A = require('./analysis');

const AGENT_IDS = ['orchestrator', 'performance_agent', 'infrastructure_agent', 'connectivity_agent', 'correlation_agent', 'reporting_agent', 'groq_llm_agent'];
const MESSAGE_TYPES = ['task', 'finding', 'challenge', 'challenge_response', 'result', 'error'];
const MAX_MESSAGES = 3000;

const ownerOf = (metric) => (METRICS[metric] ? METRICS[metric].owner : metric === 'downstream_impact' ? 'connectivity_agent' : 'infrastructure_agent');

// ---- Bus -------------------------------------------------------------------------------------
class MessageBus {
  constructor(runId) {
    this.runId = runId;
    this.agents = new Map();
    this.log = [];
    this.queue = [];
    this.inbox = [];
    this.failures = [];
  }
  register(agent) { this.agents.set(agent.id, agent); }
  get(id) { return this.log.find((m) => m.message_id === id) || null; }
  send(from, to, type, payload, { inReplyTo = null, summary = '' } = {}) {
    if (!AGENT_IDS.includes(from) || !AGENT_IDS.includes(to)) throw new Error(`Unknown agent in message ${from} -> ${to}`);
    if (!MESSAGE_TYPES.includes(type)) throw new Error(`Unknown message type ${type}`);
    if (!payload || typeof payload !== 'object') throw new Error('Message payload must be an object');
    if (this.log.length >= MAX_MESSAGES) throw new Error(`Message limit of ${MAX_MESSAGES} reached; stopping a runaway exchange`);
    const msg = {
      schema: MESSAGE_SCHEMA, message_id: `M-${String(this.log.length + 1).padStart(4, '0')}`, run_id: this.runId, seq: this.log.length + 1,
      timestamp: new Date().toISOString(), from, to, type, in_reply_to: inReplyTo, summary, payload
    };
    this.log.push(msg);
    this.queue.push(msg);
    return msg;
  }
  // Delivers until nothing is waiting. A crashing agent is recorded and reported, never fatal.
  async run() {
    while (this.queue.length) {
      const msg = this.queue.shift();
      if (msg.to === 'orchestrator') { this.inbox.push(msg); continue; }
      const agent = this.agents.get(msg.to);
      if (!agent) { this.failures.push({ agent: msg.to, error: 'agent is not registered', message_id: msg.message_id }); continue; }
      try {
        const out = await agent.handle(msg);
        for (const o of out || []) this.send(agent.id, o.to, o.type, o.payload, { inReplyTo: msg.message_id, summary: o.summary || '' });
      } catch (err) {
        this.failures.push({ agent: agent.id, error: err.message, message_id: msg.message_id });
        this.send(agent.id, 'orchestrator', 'error', { agent: agent.id, error: err.message, while_handling: msg.message_id, message_type: msg.type }, { inReplyTo: msg.message_id, summary: `${agent.id} failed: ${err.message}` });
      }
    }
  }
}

// ---- Performance and infrastructure agents ----------------------------------------------------------
class AnalysisAgent {
  constructor(id, role, ds, bus, { owned, extra }) { Object.assign(this, { id, role, ds, bus, owned, extra }); }

  async handle(msg) {
    if (msg.type === 'task') return this.analyse();
    if (msg.type === 'challenge') return this.answer(msg);
    return [];
  }

  analyse() {
    const out = [];
    let devices = 0; let readings = 0; let flagged = 0;
    for (const device of this.ds.ids()) {
      const items = [];
      for (const m of this.owned) { const it = A.metricItem(device, m, this.ds); if (it) items.push(it); }
      if (this.extra) items.push(...this.extra(device, this.ds));
      if (!items.length) continue;
      devices += 1; readings += items.length;
      const bad = items.filter((i) => i.level === 'elevated' || i.level === 'critical' || i.level === 'conflict').length;
      flagged += bad;
      out.push({ to: 'orchestrator', type: 'finding', payload: { device_id: device, items }, summary: `${items.length} readings for ${device}${bad ? `, ${bad} outside normal` : ''}` });
    }
    out.push({ to: 'orchestrator', type: 'result', payload: { kind: 'analysis_complete', agent: this.id, devices, readings, flagged }, summary: `${this.id} finished: ${readings} readings over ${devices} devices, ${flagged} outside normal` });
    return out;
  }

  answer(msg) {
    const { challenge_id: id, requests } = msg.payload;
    const mine = (requests || []).filter((r) => ownerOf(r.metric) === this.id);
    const answers = mine.map((r) => A.answerFor(r.device_id, r.metric, this.ds));
    return [{ to: 'correlation_agent', type: 'challenge_response', payload: { challenge_id: id, agent: this.id, answers }, summary: `${this.id} re-checked ${answers.length} reading${answers.length === 1 ? '' : 's'}: ${answers.filter((a) => a.observed && a.sustained != null && a.sustained >= 0.5).length} sustained, ${answers.filter((a) => a.spike_only).length} spike-only` }];
  }
}

const SERVICE_IMPACT = ['latency_ms', 'jitter_ms', 'packet_loss_pct', 'retransmission_pct', 'signal_dbm', 'dns_failure_pct', 'dns_latency_ms', 'dhcp_failure_pct', 'dhcp_latency_ms', 'device_status'];

// ---- Connectivity agent ---------------------------------------------------------------------------------
class ConnectivityAgent {
  constructor(ds, bus) { Object.assign(this, { id: 'connectivity_agent', role: 'Connectivity Analysis Agent', ds, bus }); }

  async handle(msg) {
    if (msg.type === 'task') return this.analyse(msg);
    if (msg.type === 'challenge') return this.answer(msg);
    return [];
  }

  readItems(refs) {
    const m = new Map();
    for (const id of refs || []) {
      const f = this.bus.get(id);
      if (!f || f.type !== 'finding') continue;
      const dev = f.payload.device_id;
      if (!m.has(dev)) m.set(dev, new Map());
      for (const it of f.payload.items) m.get(dev).set(it.metric, it);
    }
    return m;
  }

  impairedSet(items) {
    const imp = new Set();
    for (const [dev, metrics] of items) {
      for (const k of SERVICE_IMPACT) { const it = metrics.get(k); if (it && it.degree >= 0.5) { imp.add(dev); break; } }
    }
    return imp;
  }

  analyse(msg) {
    const { ds } = this;
    const items = this.readItems(msg.payload.finding_refs);
    const impaired = this.impairedSet(items);
    const out = [];
    const total = ds.ids().length;
    // Group impaired devices that sit on the same branch of the topology.
    const list = [...impaired];
    const parent = new Map(list.map((d) => [d, d]));
    const find = (x) => { while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); } return x; };
    const join = (a, b) => parent.set(find(a), find(b));
    for (let i = 0; i < list.length; i++) {
      const ai = ds.ancestors(list[i]);
      for (let j = i + 1; j < list.length; j++) {
        const aj = ds.ancestors(list[j]);
        if (ai.includes(list[j]) || aj.includes(list[i]) || ai.some((x) => aj.includes(x))) join(list[i], list[j]);
      }
    }
    const groups = new Map();
    for (const d of list) { const r = find(d); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(d); }
    const segments = [...groups.values()].map((members, n) => {
      const chains = members.map((d) => [d, ...ds.ancestors(d)]);
      const common = chains[0].find((x) => chains.every((c) => c.includes(x))) || null;
      return { id: `S${n + 1}`, members: members.sort(), common_upstream: members.length > 1 || !ds.hasTopology() ? common : ds.parentOf(members[0]) };
    });
    let classification = 'none';
    if (impaired.size) {
      if (total >= 4 && impaired.size / total > 0.6) classification = 'widespread';
      else if (segments.length > 1) classification = 'multiple_segments';
      else if (segments[0].members.length > 1) classification = 'segment';
      else classification = 'isolated_device';
    }
    for (const dev of ds.ids()) {
      const kids = ds.descendants(dev).filter((d) => ds.samplesOf(d).length);
      if (!kids.length) continue;
      const hit = kids.filter((d) => impaired.has(d));
      const deg = hit.length >= 2 ? 1 : hit.length === 1 ? 0.5 : 0;
      out.push({
        to: 'orchestrator', type: 'finding',
        payload: {
          device_id: dev,
          items: [{
            device_id: dev, metric: 'downstream_impact', label: 'Downstream impact', value: hit.length, unit: `of ${kids.length} downstream`, level: A.levelOf(deg), degree: deg,
            interpretation: hit.length ? `${hit.length} of ${kids.length} downstream devices are impaired` : 'No downstream device is impaired',
            detail: hit.length ? `Impaired downstream: ${hit.join(', ')}` : `${kids.length} downstream devices all within normal range`,
            stats: { n: kids.length, sustained: null }
          }]
        },
        summary: `${dev}: ${hit.length} of ${kids.length} downstream devices impaired`
      });
    }
    const scope = {
      classification, devices_total: total, impaired: [...impaired].sort(), segments,
      topology_known: ds.hasTopology(),
      note: ds.hasTopology() ? null : 'No topology was supplied, so scope is judged per device and the upstream relationship cannot be used.'
    };
    out.push({ to: 'orchestrator', type: 'finding', payload: { device_id: null, items: [], scope }, summary: `Scope: ${classification.replace(/_/g, ' ')}; ${impaired.size} of ${total} devices impaired in ${segments.length} segment${segments.length === 1 ? '' : 's'}` });
    out.push({ to: 'orchestrator', type: 'result', payload: { kind: 'analysis_complete', agent: this.id, devices: total, readings: out.length - 1, flagged: impaired.size }, summary: `${this.id} finished: scope ${classification.replace(/_/g, ' ')}` });
    this.scope = scope; this.items = items;
    return out;
  }

  answer(msg) {
    const { challenge_id: id, requests } = msg.payload;
    const answers = (requests || []).filter((r) => ownerOf(r.metric) === this.id).map((r) => {
      const kids = this.ds.descendants(r.device_id);
      const hit = kids.filter((d) => (this.scope && this.scope.impaired.includes(d)));
      if (!kids.length) return { device_id: r.device_id, metric: r.metric, observed: false };
      // An impaired descendant counts as sustained when any of its service readings was elevated for most of the window.
      const sustained = hit.filter((d) => {
        const m = this.items && this.items.get(d);
        return m && SERVICE_IMPACT.some((k) => m.get(k) && m.get(k).degree >= 0.5 && (m.get(k).stats.sustained == null || m.get(k).stats.sustained >= 0.5));
      });
      return { device_id: r.device_id, metric: r.metric, observed: true, current: hit.length, degree: hit.length >= 2 ? 1 : hit.length === 1 ? 0.5 : 0, sustained: hit.length ? A.r2(sustained.length / hit.length) : null, spike_only: false };
    });
    return [{ to: 'correlation_agent', type: 'challenge_response', payload: { challenge_id: id, agent: this.id, answers }, summary: `${this.id} re-checked downstream impact for ${answers.length} device${answers.length === 1 ? '' : 's'}` }];
  }
}

// ---- Fault correlation agent ----------------------------------------------------------------------------------
class CorrelationAgent {
  constructor(ds, bus) { Object.assign(this, { id: 'correlation_agent', role: 'Fault Correlation Agent', ds, bus, st: null }); }

  async handle(msg) {
    if (msg.type === 'task') return this.start(msg);
    if (msg.type === 'challenge_response') return this.collect(msg);
    return [];
  }

  gather(refs) {
    const items = new Map();
    let scope = null;
    const sources = new Set();
    for (const id of refs || []) {
      const f = this.bus.get(id);
      if (!f || f.type !== 'finding') continue;
      if (f.payload.scope) scope = f.payload.scope;
      const dev = f.payload.device_id;
      if (dev == null) continue;
      if (!items.has(dev)) items.set(dev, new Map());
      for (const it of f.payload.items) { items.get(dev).set(it.metric, it); sources.add(f.from); }
    }
    return { items, scope, sources };
  }

  start(msg) {
    const { items, scope, sources } = this.gather(msg.payload.finding_refs);
    const ev1 = new A.Evidence(items, this.ds);
    const ranking1 = A.rank(ev1, this.ds);
    const anomalies = [];
    for (const m of items.values()) for (const it of m.values()) if (it.level === 'elevated' || it.level === 'critical') anomalies.push(it);
    const [r1, r2] = ranking1;
    const close = r1 && r2 && r1.score - r2.score < 0.15 && r2.score >= 0.3;
    const doubt = r1 && r1.contradiction >= 0.25;
    this.st = { items, scope, sources, ranking1, anomalies, pending: new Set(), answers: new Map(), reason: null };
    if (anomalies.length && r1.score >= 0.3 && (close || doubt)) {
      const wanted = new Map();
      for (const r of [r1, r2].filter((x) => x && x.score >= 0.2)) {
        for (const e of [...r.support, ...r.contra]) {
          if (!e.item || (e.item.degree === 0 && !e.inverse)) continue;
          wanted.set(`${e.item.device_id}|${e.item.metric}`, { device_id: e.item.device_id, metric: e.item.metric });
        }
      }
      const byAgent = new Map();
      for (const r of wanted.values()) { const a = ownerOf(r.metric); if (!byAgent.has(a)) byAgent.set(a, []); byAgent.get(a).push(r); }
      if (byAgent.size) {
        this.st.reason = close
          ? `${A.HYPOTHESES[r1.hypothesis].name} (${r1.score}) and ${A.HYPOTHESES[r2.hypothesis].name} (${r2.score}) are too close to separate on first reading`
          : `${A.HYPOTHESES[r1.hypothesis].name} leads (${r1.score}) but ${A.r2(r1.contradiction * 100)}% of the opposing evidence contradicts it`;
        const out = [];
        let n = 0;
        for (const [agent, requests] of byAgent) {
          const id = `C-${++n}`;
          this.st.pending.add(id);
          out.push({ to: agent, type: 'challenge', payload: { challenge_id: id, reason: this.st.reason, question: 'Is each reading sustained across the recent window, or only a spike?', requests }, summary: `Challenge to ${agent}: re-check ${requests.length} reading${requests.length === 1 ? '' : 's'}` });
        }
        return out;
      }
    }
    return this.finish(null);
  }

  collect(msg) {
    const st = this.st;
    st.pending.delete(msg.payload.challenge_id);
    for (const a of msg.payload.answers || []) st.answers.set(`${a.device_id}|${a.metric}`, a);
    if (st.pending.size) return [];
    const adjust = (it) => {
      const a = st.answers.get(`${it.device_id}|${it.metric}`);
      if (!a || !a.observed) return 1;
      let f = 1;
      if (a.sustained != null) f *= 0.5 + 0.5 * a.sustained;
      if (a.spike_only) f *= 0.6;
      return f;
    };
    return this.finish(adjust);
  }

  finish(adjust) {
    const { ds } = this;
    const st = this.st;
    const ev = new A.Evidence(st.items, ds, adjust || (() => 1));
    const ranking = adjust ? A.rank(ev, ds) : st.ranking1;
    const resolution = [];
    if (adjust) {
      resolution.push({ type: 'conflict', detail: st.reason });
      const answers = [...st.answers.values()].filter((a) => a.observed);
      const spikes = answers.filter((a) => a.spike_only);
      const sustained = answers.filter((a) => a.sustained != null && a.sustained >= 0.5);
      resolution.push({ type: 'challenge', detail: `${answers.length} reading${answers.length === 1 ? '' : 's'} re-checked by the owning agents: ${sustained.length} sustained across the window, ${spikes.length} spike-only` });
      const b = st.ranking1[0]; const a = ranking[0];
      resolution.push(b.hypothesis === a.hypothesis && b.device === a.device
        ? { type: 'outcome', detail: `Ranking confirmed: ${A.HYPOTHESES[a.hypothesis].name} on ${a.device} stays first (score ${b.score} -> ${a.score})` }
        : { type: 'outcome', detail: `Ranking changed: ${A.HYPOTHESES[b.hypothesis].name} on ${b.device} (${b.score}) gave way to ${A.HYPOTHESES[a.hypothesis].name} on ${a.device} (${a.score})` });
    }
    const impaired = new Set(st.scope ? st.scope.impaired : []);
    const diagnosis = this.decide(ranking, st, ev, impaired);
    diagnosis.conflict_resolution = resolution;
    diagnosis.passes = adjust ? 2 : 1;
    diagnosis.first_pass = adjust ? st.ranking1.slice(0, 3).map((r) => ({ hypothesis: r.hypothesis, device: r.device, score: r.score })) : null;
    return [{ to: 'reporting_agent', type: 'result', payload: { kind: 'diagnosis', diagnosis }, summary: `Diagnosis ready: ${diagnosis.status.replace(/_/g, ' ')}${diagnosis.top ? `, ${A.HYPOTHESES[diagnosis.top.hypothesis].name} on ${diagnosis.top.device} (${diagnosis.confidence})` : ''}` }];
  }

  decide(ranking, st, ev, impaired) {
    const { ds } = this;
    const [top, second] = ranking;
    const base = { ranking: ranking.map((r) => ({ hypothesis: r.hypothesis, device: r.device, score: r.score, coverage: r.coverage, contradiction: r.contradiction, gated: r.gated })), scope: st.scope, sources: [...st.sources] };
    if (!st.anomalies.length) {
      const families = A.coreFamiliesObserved(st.items);
      const perDevice = ds.ids().map((d) => ds.samplesOf(d).length).sort((a, b) => a - b);
      const medN = perDevice[Math.floor(perDevice.length / 2)] || 0;
      if (families >= 3) {
        const conf = A.r2(Math.min(0.9, Math.max(0.1, 0.9 * (families / 7) * Math.min(1, medN / 10))));
        return { ...base, status: 'no_fault_detected', confidence: conf, confidence_category: A.categoryOf(conf), top: null, families, evidence: [], contra: [], alternatives: [], affected: [], unobserved: [] };
      }
      return { ...base, status: 'insufficient_evidence', confidence: 0.1, confidence_category: 'low', top: null, families, evidence: [], contra: [], alternatives: [], affected: [], unobserved: [], reason: `Nothing abnormal was seen, but only ${families} of 7 core metric families were reported, so health cannot be confirmed.` };
    }
    const conf0 = A.confidenceFor(top, second);
    const used = top.support.filter((e) => e.deg > 0 || e.inverse).map((e) => e.item.stats.n);
    const adequacy = Math.min(1, (A.median(used.length ? used : [0]) || 0) / 10);
    const confidence = A.r2(Math.min(0.95, conf0 * (0.7 + 0.3 * adequacy)));
    const insufficient = top.score < 0.4 || top.coverage < 0.35;
    const evidence = top.support.filter((e) => e.item && (e.deg > 0 || e.inverse)).map((e) => ({
      device_id: e.item.device_id, metric: e.item.metric, value: e.item.value, unit: e.item.unit,
      interpretation: e.inverse ? `${e.item.label} is normal (${e.item.value}${e.item.unit}), so the path itself looks healthy and the fault is service-specific` : e.item.interpretation,
      level: e.inverse ? 'normal' : e.item.level, agent: ownerOf(e.item.metric), weight: e.ind.w, detail: e.item.detail, via: e.ind.mode === 'up' || (e.ind.mode === 'own_or_up' && e.item.device_id !== top.device) ? 'upstream' : 'own'
    })).sort((a, b) => b.weight - a.weight);
    const contra = top.contra.filter((e) => e.item && e.deg > 0).map((e) => ({
      device_id: e.item.device_id, metric: e.item.metric, value: e.item.value, unit: e.item.unit, interpretation: e.item.interpretation, level: e.item.level, agent: ownerOf(e.item.metric), detail: e.item.detail
    }));
    const alternatives = ranking.slice(1).filter((r) => r.score >= 0.25 && !r.gated).map((r) => ({
      hypothesis: r.hypothesis, device: r.device, score: r.score,
      for: r.support.filter((e) => e.deg >= 0.5 && !e.inverse).map((e) => e.item.metric),
      against: r.contra.filter((e) => e.deg >= 0.5).map((e) => e.item.metric)
    }));
    return {
      ...base, status: insufficient ? 'insufficient_evidence' : 'diagnosed', confidence, confidence_category: A.categoryOf(confidence), adequacy: A.r2(adequacy),
      top: { hypothesis: top.hypothesis, device: top.device, score: top.score, ratio: top.ratio, coverage: top.coverage, contradiction: top.contradiction },
      evidence, contra, alternatives, affected: insufficient ? [] : A.affectedDevices(top, ev, ds, impaired),
      unobserved: top.unobserved.map((i) => i.metric), unobservedContra: top.unobservedContra.map((i) => i.metric),
      reason: insufficient ? (top.coverage < 0.35 ? `Only ${Math.round(top.coverage * 100)}% of the telemetry this cause depends on was reported.` : `The best explanation scores ${top.score}, below the 0.40 needed to name a cause.`) : null
    };
  }
}

// ---- Reporting agent ---------------------------------------------------------------------------------------------------
const NAMES = {
  link_congestion: (d, x) => `link congestion on ${d}${x.has('queue_drops') ? ' causing egress queue drops' : ''}`,
  weak_wifi_signal: (d, x) => `weak Wi-Fi signal at ${d}${x.has('retransmission_pct') ? ' causing retransmissions' : ''}${x.has('packet_loss_pct') ? ' and packet loss' : ''}`,
  interface_fault: (d, x) => `physical or interface fault on ${d}${x.has('status_flaps') ? ' (link instability)' : x.has('interface_errors') ? ' (rising interface errors)' : ''}`,
  device_overload: (d, x) => `resource overload on ${d}${x.has('cpu_pct') ? ' (CPU' + (x.has('memory_pct') ? ' and memory' : '') + ')' : ' (memory)'}`,
  dns_failure: (d) => `DNS resolution failure or slowness seen at ${d}`,
  dhcp_failure: (d) => `DHCP failure or slowness seen at ${d}`,
  device_or_upstream_outage: (d, x, own) => (own ? `outage of ${d}` : `upstream outage affecting ${d}`)
};

function causeName(hyp, device, evidence, ds) {
  const metrics = new Set(evidence.filter((e) => e.level !== 'normal').map((e) => e.metric));
  const own = evidence.some((e) => e.metric === 'device_status' && e.device_id === device && e.level !== 'normal');
  return NAMES[hyp](device, metrics, own);
}

class ReportingAgent {
  constructor(ds, bus, env) { Object.assign(this, { id: 'reporting_agent', role: 'Recommendation and Reporting Agent', ds, bus, env }); }

  async handle(msg) {
    if (msg.type !== 'result' || msg.payload.kind !== 'diagnosis') return [];
    const report = this.build(msg.payload.diagnosis);
    return [{ to: 'orchestrator', type: 'result', payload: { kind: 'report', report }, summary: `Report assembled: ${report.status.replace(/_/g, ' ')}` }];
  }

  build(dx) {
    const { ds, env } = this;
    const q = env.quality;
    const top = dx.top;
    const cause = top ? causeName(top.hypothesis, top.device, dx.evidence, ds) : null;
    const likelihood = dx.confidence >= 0.65 ? 'Likely' : 'Possible';
    let root = null;
    if (dx.status === 'diagnosed') root = `${likelihood} ${cause}`;
    else if (dx.status === 'no_fault_detected') root = 'No fault detected: all reported metrics are within their expected ranges';
    else root = 'Insufficient evidence for a reliable diagnosis';

    const limitations = ['Derived from the supplied telemetry only; no device was queried and nothing was changed.', 'Root cause requires further verification by an engineer before any action is taken.'];
    if (env.meta.synthetic) limitations.push('The telemetry is synthetic test data from the scenario generator, not a measurement of a real network.');
    if (!env.meta.timestamped) limitations.push('The telemetry has no usable timestamps, so "recent" is taken from the order of the records.');
    if (!ds.hasTopology()) limitations.push('No topology was supplied, so upstream and downstream relationships could not be used.');
    if (dx.status === 'diagnosed') {
      if (dx.unobserved.length) limitations.push(`No ${dx.unobserved.map((m) => A.METRIC_LABEL(m).toLowerCase()).join(', ')} telemetry for the affected device, so this cause could not be fully verified.`);
      if (dx.unobservedContra && dx.unobservedContra.length) limitations.push(`Could not rule out competing causes that need ${dx.unobservedContra.map((m) => A.METRIC_LABEL(m).toLowerCase()).join(', ')}, which was not reported.`);
      if (dx.adequacy < 0.6) limitations.push(`The key readings come from few samples (data adequacy ${dx.adequacy}), which lowers confidence.`);
      if (dx.contra.length) limitations.push(`Some evidence points the other way: ${dx.contra.map((c) => `${A.METRIC_LABEL(c.metric)} on ${c.device_id}`).join(', ')}.`);
    }
    if (q.grade === 'repaired' || q.grade === 'poor') limitations.push(`Input needed repair: ${q.records_dropped} of ${q.records_in} records were dropped and ${q.unit_conversions.reduce((n, c) => n + c.count, 0)} values were unit-converted (see data quality).`);
    const conflicts = this.bus.log.filter((m) => m.type === 'finding').flatMap((m) => (m.payload.items || []).filter((i) => i.level === 'conflict'));
    for (const c of conflicts) limitations.push(`${c.device_id}: ${c.interpretation}.`);
    if (this.bus.failures.length) limitations.push(`Agent failure: ${this.bus.failures.map((f) => `${f.agent} (${f.error})`).join('; ')}. The diagnosis used the remaining agents' findings.`);
    limitations.push('Counters such as queue drops and interface errors are read as per-sample-interval values.');

    const actions = [];
    if (dx.status === 'diagnosed') {
      actions.push(...A.HYPOTHESES[top.hypothesis].actions(top.device).slice(0, 4));
      const alt = dx.alternatives[0];
      if (alt) actions.push(`To rule out ${A.HYPOTHESES[alt.hypothesis].name.toLowerCase()} on ${alt.device}, check ${A.HYPOTHESES[alt.hypothesis].primary.map(A.METRIC_LABEL).map((s) => s.toLowerCase()).join(' and ')}`);
      if (dx.unobserved.length) actions.push(`Collect ${dx.unobserved.map((m) => A.METRIC_LABEL(m).toLowerCase()).join(', ')} for ${top.device} to confirm or refute this diagnosis`);
    } else if (dx.status === 'no_fault_detected') {
      actions.push('No corrective action is indicated by this telemetry; keep monitoring.', 'If users still report problems, collect telemetry from the missing metric families (utilization, queue drops, interface errors, DNS and DHCP checks) and run again.');
    } else {
      actions.push('Collect more telemetry before acting: latency, packet loss, link utilization, CPU, memory, queue drops and interface errors for the suspect devices.', 'Provide a longer time window (at least 10 samples per device) and the network topology.');
      if (dx.top) actions.push(`Best candidate to verify first: ${A.HYPOTHESES[dx.top.hypothesis].name.toLowerCase()} on ${dx.top.device}`);
    }

    const sources = [...new Set((dx.evidence || []).map((e) => e.agent))];
    const alternatives = (dx.alternatives || []).map((a) => `${A.HYPOTHESES[a.hypothesis].name} on ${a.device}`);
    const dev = (id) => ds.typeOf(id);
    const fallbackIncId = 'INC-' + (Math.abs(String(this.bus.runId).split('').reduce((a, b) => ((a << 5) - a) + b.charCodeAt(0), 0)) % 9000 + 1000);
    return {
      schema: REPORT_SCHEMA,
      incident_id: env.incidentId || fallbackIncId,
      status: dx.status,
      suspected_root_cause: root,
      root_cause_category: dx.status === 'diagnosed' ? top.hypothesis : null,
      confidence: dx.confidence,
      confidence_category: dx.confidence_category,
      affected_devices: (dx.affected || []).map((a) => a.device_id),
      affected_detail: (dx.affected || []).map((a) => ({ device_id: a.device_id, device_type: dev(a.device_id), site: ds.siteOf(a.device_id), reason: a.reason })),
      supporting_evidence: (dx.evidence || []).map((e) => ({ metric: e.metric, value: e.value, unit: e.unit, device_id: e.device_id, interpretation: e.interpretation, level: e.level, agent: e.agent, ...(e.via === 'upstream' ? { via: 'upstream' } : {}) })),
      contradicting_evidence: (dx.contra || []).map((e) => ({ metric: e.metric, value: e.value, unit: e.unit, device_id: e.device_id, interpretation: e.interpretation, agent: e.agent })),
      alternative_causes: alternatives,
      alternative_cause_details: (dx.alternatives || []).map((a) => ({ cause: A.HYPOTHESES[a.hypothesis].name, device_id: a.device, score: a.score, supported_by: a.for, argued_against_by: a.against })),
      candidate_causes: dx.status === 'insufficient_evidence' ? (dx.ranking || []).filter((r) => r.score >= 0.15).slice(0, 3).map((r) => ({ cause: A.HYPOTHESES[r.hypothesis].name, device_id: r.device, score: r.score })) : [],
      recommended_actions: actions,
      evidence_sources: sources,
      limitations,
      scope: dx.scope ? { classification: dx.scope.classification, impaired_devices: dx.scope.impaired, segments: dx.scope.segments, note: dx.scope.note } : null,
      reason: dx.reason || null,
      conflict_resolution: dx.conflict_resolution || [],
      ranking: (dx.ranking || []).map((r) => ({ cause: A.HYPOTHESES[r.hypothesis].name, device_id: r.device, score: r.score, coverage: r.coverage, contradiction: r.contradiction, capped: r.gated })),
      passes: dx.passes,
      human_review_required: true,
      data_provenance: {
        source: env.meta.source || env.sourceName || null, synthetic: env.meta.synthetic, label: env.meta.label, format: env.meta.format, schema_version: env.meta.schema_version,
        window_start: env.meta.start, window_end: env.meta.end, devices: ds.ids().length, samples: ds.sampleCount
      },
      data_quality: q,
      scoring_method: SCORING
    };
  }
}

const SCORING = {
  summary: 'Each candidate cause is scored per device from weighted indicators. Evidence for a cause raises its score, opposing evidence lowers it, and a cause cannot rank above 0.20 unless one of its primary indicators is clearly abnormal.',
  evidence_ratio: 'sum(weight x degree) / sum(weight) over the cause\'s supporting indicators; degree is 0 below the warning threshold, 0.5 at it and 1 at the critical threshold',
  coverage: 'weight of the supporting indicators that have telemetry / total supporting weight',
  score: 'max(0, evidence_ratio - 0.35 x contradiction), capped at 0.20 without a primary indicator at degree >= 0.5',
  confidence: 'score x (0.55 + 0.45 x coverage) x (0.75 + 0.25 x min(1, margin / 0.3)) x (0.7 + 0.3 x data_adequacy), capped at 0.95; margin is the lead over the runner-up',
  categories: { high: '>= 0.75', medium: '0.50 - 0.74', low: '< 0.50' },
  insufficient_evidence: 'reported when the best score is below 0.40 or coverage is below 0.35',
  no_fault: 'reported when nothing is outside its warning threshold and at least 3 of 7 core metric families were reported',
  conflict_resolution: 'when the top two causes are within 0.15 or opposing evidence is >= 25%, the correlation agent challenges the owning agents to confirm each reading is sustained; spike-only readings are discounted and the causes are re-ranked',
  note: 'Confidence is a documented heuristic, not a statistically calibrated probability.'
};

const PROTOCOL = {
  version: '1.0.0',
  telemetry_schema: 'netcoop.telemetry/1.0',
  message_schema: MESSAGE_SCHEMA,
  report_schema: REPORT_SCHEMA,
  envelope: {
    message_id: 'string, "M-0001"; unique within a run',
    run_id: 'string; the diagnosis run this message belongs to',
    seq: 'integer; position in the run, starts at 1',
    timestamp: 'ISO 8601 UTC',
    from: `string; one of ${AGENT_IDS.join(', ')}`,
    to: 'string; same set as from',
    type: `string; one of ${MESSAGE_TYPES.join(', ')}`,
    in_reply_to: 'string or null; message_id this message answers',
    summary: 'string; one-line human description',
    payload: 'object; shape depends on type (below)'
  },
  payloads: {
    task: '{ kind: "analyze" | "correlate", finding_refs?: string[] }  finding_refs are message_ids the agent must read from the log',
    finding: '{ device_id: string | null, items: Item[], scope?: Scope }',
    challenge: '{ challenge_id, reason, question, requests: [{ device_id, metric }] }',
    challenge_response: '{ challenge_id, agent, answers: [{ device_id, metric, observed, current, peak?, degree, sustained, trend?, spike_only }] }',
    result: '{ kind: "analysis_complete" | "diagnosis" | "report", ... }',
    error: '{ agent, error, while_handling, message_type }'
  },
  item: {
    device_id: 'string', metric: 'string; canonical metric key', label: 'string', value: 'number or status text; the median of the most recent 30% of samples (min 3)',
    unit: 'string', level: 'normal | elevated | critical | conflict', degree: 'number 0..1; 0 below warning, 0.5 at warning, 1 at critical',
    interpretation: 'string', detail: 'string', stats: '{ n, window, median, p95, peak, sustained (fraction of recent samples past warning), baseline, trend }'
  },
  metrics: Object.fromEntries(Object.entries(METRICS).map(([k, d]) => [k, {
    unit: d.unit, owner: d.owner, valid_range: [d.min, d.max], warn: d.warn, crit: d.crit, lower_is_worse: Boolean(d.lowerIsWorse),
    accepted_names: d.aliases.map(([n]) => n)
  }])),
  topology: 'envelope.topology.links: [{ from: <upstream>, to: <downstream> }]; parent/child, upstream/downstream, source/target also accepted; a device may also carry "uplink"',
  status_values: 'up | down | degraded (online/offline/unreachable/warning/flapping and similar are mapped)',
  input_formats: ['JSON object { schema_version, incident_id?, scenario?, devices?, topology?, samples[] }', 'JSON array of samples', 'NDJSON, one sample per line', 'CSV with a header row'],
  state_machine: ['task(performance_agent), task(infrastructure_agent) -> findings', 'task(connectivity_agent, finding_refs) -> topology findings', 'task(correlation_agent, finding_refs) -> [challenge <-> challenge_response]* -> result(diagnosis)', 'result(diagnosis) -> reporting_agent -> result(report) -> orchestrator']
};

function createAgents(ds, bus, env) {
  const perf = new AnalysisAgent('performance_agent', 'Telemetry and Performance Agent', ds, bus, { owned: Object.keys(METRICS).filter((m) => METRICS[m].owner === 'performance_agent') });
  const infra = new AnalysisAgent('infrastructure_agent', 'Infrastructure Health Agent', ds, bus, { owned: Object.keys(METRICS).filter((m) => METRICS[m].owner === 'infrastructure_agent'), extra: (d, set) => A.statusItems(d, set) });
  const conn = new ConnectivityAgent(ds, bus);
  const corr = new CorrelationAgent(ds, bus);
  const rep = new ReportingAgent(ds, bus, env);
  return [perf, infra, conn, corr, rep];
}

const ROLES = [
  { id: 'performance_agent', name: 'Telemetry and Performance Agent', owns: 'latency, jitter, packet loss, utilization, Wi-Fi signal and retransmissions, DNS and DHCP checks', consumes: ['task'], produces: ['finding', 'result', 'challenge_response'] },
  { id: 'infrastructure_agent', name: 'Infrastructure Health Agent', owns: 'device status, link flaps, CPU, memory, queue drops, interface errors', consumes: ['task'], produces: ['finding', 'result', 'challenge_response'] },
  { id: 'connectivity_agent', name: 'Connectivity Analysis Agent', owns: 'topology, impaired segments, downstream impact', consumes: ['task (finding_refs)'], produces: ['finding', 'result', 'challenge_response'] },
  { id: 'correlation_agent', name: 'Fault Correlation Agent', owns: 'ranking competing causes, challenging disagreements, confidence', consumes: ['task (finding_refs)', 'challenge_response'], produces: ['challenge', 'result'] },
  { id: 'reporting_agent', name: 'Recommendation and Reporting Agent', owns: 'unified report, evidence, uncertainty, corrective actions', consumes: ['result (diagnosis)'], produces: ['result (report)'] },
  { id: 'groq_llm_agent', name: 'Groq LLM Reasoning Agent', owns: 'contextual root cause synthesis, LPU inference (openai/gpt-oss-120b), technical CLI remediation', consumes: ['result (diagnosis)'], produces: ['result (llm_synthesis)'] }
];

module.exports = { MessageBus, createAgents, PROTOCOL, SCORING, ROLES, AGENT_IDS, MESSAGE_TYPES, ownerOf };

