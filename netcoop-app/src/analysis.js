'use strict';

// NetCoop AI: measurement helpers, hypothesis catalogue and the scoring method used
// by the Fault Correlation Agent. Everything here is deterministic: the same
// telemetry always produces the same ranking, which is what makes a diagnosis
// auditable.

const { METRICS, CORE_FAMILIES } = require('./schema');

// ---- Statistics ------------------------------------------------------------------------
const median = (a) => {
  if (!a.length) return null;
  const s = [...a].sort((x, y) => x - y);
  const n = s.length;
  return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
};
const percentile = (a, p) => {
  if (!a.length) return null;
  const s = [...a].sort((x, y) => x - y);
  return s[Math.min(s.length - 1, Math.max(0, Math.ceil((p / 100) * s.length) - 1))];
};
const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));
const r2 = (x) => Math.round(x * 100) / 100;
const num = (x) => (x == null ? null : Math.round(x * 100) / 100);

// Interface flapping is counted from status changes; it has no raw metric of its own.
const FLAP_DEF = { warn: 2, crit: 5, unit: 'transitions', label: 'Link status changes', text: ['Link status stable', 'Link status changing', 'Link flapping'] };

// 0 below the warning threshold, 0.5 at it, 1 at the critical threshold or beyond.
function degreeOf(def, v) {
  if (def.warn == null || v == null) return 0;
  if (def.lowerIsWorse) {
    if (v > def.warn) return 0;
    return 0.5 + 0.5 * clamp((def.warn - v) / (def.warn - def.crit), 0, 1);
  }
  if (v < def.warn) return 0;
  return 0.5 + 0.5 * clamp((v - def.warn) / (def.crit - def.warn), 0, 1);
}
const levelOf = (deg) => (deg >= 0.99 ? 'critical' : deg > 0 ? 'elevated' : 'normal');

// The most recent 30% of a series (at least three points) is "now"; the rest is the baseline.
function windowStats(vals, def) {
  const n = vals.length;
  const k = Math.min(n, Math.max(3, Math.ceil(n * 0.3)));
  const recent = vals.slice(n - k);
  const base = vals.slice(0, n - k);
  const exceeds = (v) => (def.lowerIsWorse ? v <= def.warn : v >= def.warn);
  const current = median(recent);
  const peak = def.lowerIsWorse ? Math.min(...recent) : Math.max(...recent);
  return {
    n, window: k, current, median: median(vals), p95: percentile(vals, 95), peak,
    sustained: def.warn == null ? null : recent.filter(exceeds).length / k,
    baseline: base.length >= 3 ? median(base) : null,
    trend: base.length >= 3 ? current - median(base) : null
  };
}

function metricItem(device, metric, ds) {
  const def = METRICS[metric];
  const series = ds.series(device, metric);
  if (!series.length || def.info) return null;
  const st = windowStats(series.map((s) => s.v), def);
  const deg = degreeOf(def, st.current);
  const level = levelOf(deg);
  const trendNote = st.trend != null && st.baseline != null && Math.abs(st.trend) > Math.abs(def.warn || 1) * 0.25
    ? `, ${st.trend > 0 ? 'up' : 'down'} from a baseline of ${num(st.baseline)}${def.unit}` : '';
  return {
    device_id: device, metric, label: def.label, value: num(st.current), unit: def.unit, level, degree: r2(deg),
    interpretation: def.text[level === 'normal' ? 0 : level === 'elevated' ? 1 : 2],
    detail: `${def.label} ${num(st.current)}${def.unit} now (peak ${num(st.peak)}, ${st.n} samples${trendNote})`,
    stats: { n: st.n, window: st.window, median: num(st.median), p95: num(st.p95), peak: num(st.peak), sustained: st.sustained == null ? null : r2(st.sustained), baseline: num(st.baseline), trend: num(st.trend) }
  };
}

function statusItems(device, ds) {
  const out = [];
  const ser = ds.statusSeries(device);
  if (!ser.length) return out;
  const k = Math.min(ser.length, Math.max(3, Math.ceil(ser.length * 0.3)));
  const recent = ser.slice(ser.length - k).map((s) => s.v);
  const down = recent.filter((v) => v === 'down').length / k;
  const bad = recent.filter((v) => v !== 'up').length / k;
  const current = down >= 0.5 ? 'down' : bad >= 0.5 ? 'degraded' : 'up';
  const deg = current === 'down' ? 1 : current === 'degraded' ? 0.5 : 0;
  out.push({
    device_id: device, metric: 'device_status', label: 'Device status', value: current, unit: '', level: levelOf(deg), degree: deg,
    interpretation: current === 'down' ? 'Device reported down' : current === 'degraded' ? 'Device reported degraded' : 'Device reported up',
    detail: `Device status ${current} in ${Math.round(bad * k)} of the last ${k} samples`,
    stats: { n: ser.length, window: k, sustained: r2(bad) }
  });
  let flaps = 0;
  for (let i = 1; i < ser.length; i++) if ((ser[i - 1].v === 'up') !== (ser[i].v === 'up')) flaps += 1;
  const fdeg = degreeOf(FLAP_DEF, flaps);
  out.push({
    device_id: device, metric: 'status_flaps', label: FLAP_DEF.label, value: flaps, unit: 'transitions', level: levelOf(fdeg), degree: r2(fdeg),
    interpretation: FLAP_DEF.text[fdeg === 0 ? 0 : fdeg >= 0.99 ? 2 : 1],
    detail: `${flaps} status change${flaps === 1 ? '' : 's'} across ${ser.length} samples`,
    stats: { n: ser.length, sustained: null }
  });
  const stale = ds.samplesOf(device).filter((s) => s.status === 'down' && (s.metrics.latency_ms !== undefined || s.metrics.cpu_pct !== undefined || s.metrics.throughput_mbps > 0));
  if (stale.length) {
    out.push({
      device_id: device, metric: 'status_consistency', label: 'Status consistency', value: stale.length, unit: 'samples', level: 'conflict', degree: 0,
      interpretation: 'Device reported down while still reporting live metrics; its status or its telemetry may be stale',
      detail: `${stale.length} sample${stale.length === 1 ? '' : 's'} marked down but carrying metrics`, stats: { n: stale.length, sustained: null }
    });
  }
  return out;
}

// What an agent answers when the correlation agent doubts one of its readings.
function answerFor(device, metric, ds) {
  if (metric === 'device_status' || metric === 'status_flaps') {
    const it = statusItems(device, ds).find((i) => i.metric === metric);
    return it ? { device_id: device, metric, observed: true, current: it.value, degree: it.degree, sustained: it.stats.sustained, spike_only: false } : { device_id: device, metric, observed: false };
  }
  const it = METRICS[metric] ? metricItem(device, metric, ds) : null;
  if (!it) return { device_id: device, metric, observed: false };
  const def = METRICS[metric];
  const peakDeg = degreeOf(def, it.stats.peak);
  return {
    device_id: device, metric, observed: true, current: it.value, peak: it.stats.peak, degree: it.degree,
    sustained: it.stats.sustained, trend: it.stats.trend,
    spike_only: peakDeg >= 0.5 && it.degree === 0
  };
}

// ---- Hypotheses ---------------------------------------------------------------------------------
// Indicator modes: own = this device; own_or_up = this device or its worst ancestor;
// up = ancestors only; inverse = a healthy reading supports the hypothesis (service-only faults).
const I = (metric, w, mode = 'own') => ({ id: mode === 'up' ? `${metric}@upstream` : metric, metric, w, mode });

const HYPOTHESES = {
  link_congestion: {
    key: 'link_congestion', name: 'Link congestion',
    support: [I('link_utilization_pct', 3, 'own_or_up'), I('queue_drops', 3), I('latency_ms', 2), I('packet_loss_pct', 1.5), I('jitter_ms', 1), I('downstream_impact', 1)],
    contra: [I('interface_errors', 1.5), I('signal_dbm', 1), I('cpu_pct', 1)],
    primary: ['link_utilization_pct', 'queue_drops'],
    actions: (d) => [`Inspect link utilization and egress queue counters on ${d} and its upstream link`, `Review QoS and queue configuration on ${d} and how traffic is distributed across uplinks`, 'Identify the top talkers during the congested window (flow records or port counters)', 'Consider adding uplink capacity or rate-limiting heavy flows if the load is sustained']
  },
  weak_wifi_signal: {
    key: 'weak_wifi_signal', name: 'Weak Wi-Fi signal',
    support: [I('signal_dbm', 4), I('retransmission_pct', 3), I('packet_loss_pct', 1.5), I('latency_ms', 1), I('jitter_ms', 1)],
    contra: [I('link_utilization_pct', 1.5, 'own_or_up'), I('queue_drops', 1), I('interface_errors', 0.5)],
    primary: ['signal_dbm', 'retransmission_pct'],
    actions: (d) => [`Check coverage and client placement around ${d} (site survey or controller RF report)`, `Review ${d} channel, transmit power and nearby interference sources`, 'Look at client retry and roaming statistics on the wireless controller', 'Consider moving or adding an access point if clients sit below -70 dBm']
  },
  interface_fault: {
    key: 'interface_fault', name: 'Interface or cable fault',
    support: [I('interface_errors', 4), I('status_flaps', 2.5), I('packet_loss_pct', 2), I('jitter_ms', 1)],
    contra: [I('link_utilization_pct', 1.5), I('queue_drops', 1.5), I('cpu_pct', 0.5)],
    primary: ['interface_errors', 'status_flaps'],
    actions: (d) => [`Check physical layer on ${d}: cable, connectors and SFP/transceiver for CRC and input errors`, `Compare speed/duplex settings on both ends of the ${d} link`, 'Swap the cable or move the port to rule out a failing interface', 'Watch the error counters after the change to confirm they stop rising']
  },
  device_overload: {
    key: 'device_overload', name: 'Device resource overload',
    support: [I('cpu_pct', 4), I('memory_pct', 2), I('latency_ms', 1.5), I('queue_drops', 1), I('packet_loss_pct', 1), I('downstream_impact', 1)],
    contra: [I('interface_errors', 1), I('link_utilization_pct', 1)],
    primary: ['cpu_pct', 'memory_pct'],
    actions: (d) => [`Identify what is consuming CPU or memory on ${d} (process table, control-plane policing counters)`, `Check ${d} for routing-protocol churn, broadcast storms or management-plane load`, 'Review recent configuration or firmware changes on the device', 'Plan a maintenance window to restart or upgrade the device if the load is not explained']
  },
  dns_failure: {
    key: 'dns_failure', name: 'DNS failure',
    support: [I('dns_failure_pct', 4), I('dns_latency_ms', 3), I('latency_ms', 1.5, 'inverse'), I('packet_loss_pct', 1.5, 'inverse')],
    contra: [I('dhcp_failure_pct', 1.5)],
    primary: ['dns_failure_pct', 'dns_latency_ms'],
    actions: (d) => [`Test name resolution from ${d} against each configured resolver (dig/nslookup with timing)`, 'Check the health, forwarders and load of the campus DNS servers', 'Verify the resolver addresses handed out to clients are correct and reachable', 'Fail clients over to a secondary resolver while the primary is investigated']
  },
  dhcp_failure: {
    key: 'dhcp_failure', name: 'DHCP failure',
    support: [I('dhcp_failure_pct', 4), I('dhcp_latency_ms', 3), I('latency_ms', 1.5, 'inverse'), I('packet_loss_pct', 1.5, 'inverse')],
    contra: [I('dns_failure_pct', 1.5)],
    primary: ['dhcp_failure_pct', 'dhcp_latency_ms'],
    actions: (d) => [`Check lease availability and pool exhaustion for the scope serving ${d}`, 'Confirm DHCP relay (ip helper) configuration and that the DHCP server is reachable', 'Inspect DHCP server logs for NAK/decline storms or a rogue DHCP server', 'Temporarily extend the pool or lease time if addresses are running out']
  },
  device_or_upstream_outage: {
    key: 'device_or_upstream_outage', name: 'Device or upstream outage',
    support: [I('device_status', 4), I('device_status', 3, 'up'), I('packet_loss_pct', 2), I('downstream_impact', 1.5)],
    contra: [],
    primary: ['device_status', 'device_status@upstream'],
    actions: (d) => [`Verify power, uplink and management reachability of ${d}`, `Check the upstream device and link for ${d}, and any recent change or maintenance`, 'Confirm whether downstream devices are failing over to a redundant path', 'Escalate to the on-site team if the device does not respond to out-of-band access']
  }
};

const METRIC_LABEL = (m) => (METRICS[m] ? METRICS[m].label : m === 'device_status' ? 'Device status' : m === 'status_flaps' ? 'Link status changes' : m === 'downstream_impact' ? 'Downstream impact' : m);

// ---- Scoring ----------------------------------------------------------------------------------------
// ratio       = sum(weight x degree) / sum(weight)   over the supporting indicators
// coverage    = weight of supporting indicators that have data / total supporting weight
// contradiction = weighted mean degree of the contradicting indicators that have data
// score       = max(0, ratio - 0.35 x contradiction); capped at 0.2 unless a primary indicator reaches 0.5
// confidence  = score x (0.55 + 0.45 x coverage) x (0.75 + 0.25 x min(1, margin / 0.3)), margin = score - runner-up
const GATE_CAP = 0.2;
const CONTRA_WEIGHT = 0.35;

class Evidence {
  // items: Map<device, Map<metric, item>>; adjust: (item) => multiplier from challenge answers.
  constructor(items, ds, adjust = () => 1) { this.items = items; this.ds = ds; this.adjust = adjust; }
  deg(device, metric) {
    const it = this.items.get(device) && this.items.get(device).get(metric);
    if (!it) return null;
    return { deg: it.degree * this.adjust(it), item: it };
  }
  up(device, metric) {
    let best = null;
    for (const a of this.ds.ancestors(device)) { const d = this.deg(a, metric); if (d && (!best || d.deg > best.deg)) best = d; }
    return best;
  }
  read(device, ind) {
    if (ind.mode === 'own') return this.deg(device, ind.metric);
    if (ind.mode === 'up') return this.up(device, ind.metric);
    if (ind.mode === 'inverse') { const d = this.deg(device, ind.metric); return d ? { deg: 1 - d.deg, item: d.item, inverse: true } : null; }
    const own = this.deg(device, ind.metric);
    const up = this.up(device, ind.metric);
    if (!own && !up) return null;
    const upDeg = up ? up.deg * 0.9 : -1;
    return own && own.deg >= upDeg ? own : { ...up, deg: up.deg * 0.9 };
  }
}

function scoreHypothesis(h, device, ev) {
  let sw = 0; let sd = 0; let ow = 0;
  const support = []; const contra = []; const unobserved = []; const unobservedContra = [];
  for (const ind of h.support) {
    sw += ind.w;
    const r = ev.read(device, ind);
    if (!r) { unobserved.push(ind); continue; }
    ow += ind.w; sd += ind.w * r.deg;
    support.push({ ind, deg: r.deg, item: r.item, inverse: Boolean(r.inverse) });
  }
  let cw = 0; let cd = 0;
  for (const ind of h.contra) {
    const r = ev.read(device, ind);
    if (!r) { unobservedContra.push(ind); continue; }
    cw += ind.w; cd += ind.w * r.deg;
    contra.push({ ind, deg: r.deg, item: r.item });
  }
  const ratio = sw ? sd / sw : 0;
  const coverage = sw ? ow / sw : 0;
  const contradiction = cw ? cd / cw : 0;
  let score = Math.max(0, ratio - CONTRA_WEIGHT * contradiction);
  const gated = !h.primary.some((id) => { const e = support.find((s) => s.ind.id === id); return e && !e.inverse && e.deg >= 0.5; });
  if (gated) score = Math.min(score, GATE_CAP);
  return { hypothesis: h.key, device, score: r2(score), ratio: r2(ratio), coverage: r2(coverage), contradiction: r2(contradiction), gated, support, contra, unobserved, unobservedContra };
}

// Best (hypothesis, device) pair per hypothesis, strongest first.
function rank(ev, ds) {
  const out = [];
  for (const h of Object.values(HYPOTHESES)) {
    let best = null;
    for (const d of ds.ids()) {
      const s = scoreHypothesis(h, d, ev);
      if (!best || s.score > best.score || (s.score === best.score && s.coverage > best.coverage)) best = s;
    }
    if (best) out.push(best);
  }
  return out.sort((a, b) => b.score - a.score || b.coverage - a.coverage);
}

function confidenceFor(top, second) {
  const margin = top.score - (second ? second.score : 0);
  const c = top.score * (0.55 + 0.45 * top.coverage) * (0.75 + 0.25 * Math.min(1, margin / 0.3));
  return r2(Math.min(0.95, c));
}
const categoryOf = (c) => (c >= 0.75 ? 'high' : c >= 0.5 ? 'medium' : 'low');

// Devices a winning hypothesis plausibly touches: those scoring close to the best one, plus
// impaired devices downstream of it.
function affectedDevices(top, ev, ds, impaired) {
  const h = HYPOTHESES[top.hypothesis];
  const out = [{ device_id: top.device, reason: 'highest-scoring device for this cause' }];
  const floor = Math.max(0.35, top.score * 0.5);
  for (const d of ds.ids()) {
    if (d === top.device) continue;
    const s = scoreHypothesis(h, d, ev);
    if (s.score >= floor && !s.gated) out.push({ device_id: d, reason: `shows the same pattern (score ${s.score})` });
  }
  if (['link_congestion', 'device_overload', 'device_or_upstream_outage', 'interface_fault'].includes(top.hypothesis)) {
    for (const d of ds.descendants(top.device)) {
      if (impaired.has(d) && !out.some((o) => o.device_id === d)) out.push({ device_id: d, reason: `impaired and downstream of ${top.device}` });
    }
  }
  return out;
}

function coreFamiliesObserved(items) {
  const seen = new Set();
  for (const m of items.values()) for (const k of m.keys()) seen.add(k);
  return CORE_FAMILIES.filter((fam) => fam.some((m) => seen.has(m))).length;
}

module.exports = {
  median, percentile, clamp, r2, FLAP_DEF, degreeOf, levelOf, windowStats, metricItem, statusItems, answerFor,
  HYPOTHESES, METRIC_LABEL, Evidence, scoreHypothesis, rank, confidenceFor, categoryOf, affectedDevices, coreFamiliesObserved,
  GATE_CAP, CONTRA_WEIGHT
};

