'use strict';

// NetCoop AI: telemetry schema, metric catalogue and input normaliser.
//
// Real telemetry arrives in many shapes: other field names, other units, a
// different schema version, half-filled rows, broken JSON. This module reads
// JSON, NDJSON or CSV, maps every field it understands onto one canonical
// vocabulary (names and units below), converts units, and reports everything it
// had to repair or reject. Nothing is invented: a value that cannot be read is
// dropped and counted, never filled in.

const SCHEMA_ID = 'netcoop.telemetry/1.0';
const REPORT_SCHEMA = 'netcoop.report/1.0';
const MESSAGE_SCHEMA = 'netcoop.agent-message/1.0';
const SUPPORTED_MAJOR = 1;
const MAX_INPUT_CHARS = 5 * 1024 * 1024;
const MAX_RECORDS = 20000;
const MAX_DEVICES = 500;

class InputError extends Error {
  constructor(message, code = 'invalid_input') { super(message); this.code = code; }
}

// ---- Canonical metrics -----------------------------------------------------------
// kind decides which units are understood. warn/crit are the documented thresholds
// the agents judge against; lowerIsWorse flips the comparison (signal strength).
// Counters (queue_drops, interface_errors) are read as "per sample interval".
const METRICS = {
  latency_ms: {
    owner: 'performance_agent', unit: 'ms', kind: 'time', min: 0, max: 60000, warn: 100, crit: 250, label: 'Latency',
    text: ['Latency within expected range', 'Elevated network latency', 'Severely elevated network latency'],
    aliases: [['latency_ms', 1], ['latency', 1], ['rtt_ms', 1], ['rtt', 1], ['delay_ms', 1], ['round_trip_ms', 1], ['latency_avg_ms', 1], ['latency_s', 1000], ['latency_sec', 1000], ['rtt_s', 1000], ['latency_us', 0.001], ['rtt_us', 0.001]]
  },
  jitter_ms: {
    owner: 'performance_agent', unit: 'ms', kind: 'time', min: 0, max: 60000, warn: 30, crit: 80, label: 'Jitter',
    text: ['Jitter within expected range', 'Elevated jitter', 'Severe jitter'],
    aliases: [['jitter_ms', 1], ['jitter', 1], ['jitter_s', 1000], ['jitter_us', 0.001]]
  },
  packet_loss_pct: {
    owner: 'performance_agent', unit: '%', kind: 'pct', min: 0, max: 100, warn: 1, crit: 5, label: 'Packet loss',
    text: ['Packet loss within expected range', 'Elevated packet loss', 'Severe packet loss'],
    aliases: [['packet_loss_pct', 1], ['packet_loss', 1], ['loss_pct', 1], ['loss', 1], ['pkt_loss', 1], ['pkt_loss_pct', 1], ['packet_loss_percent', 1], ['packet_loss_ratio', 100], ['loss_ratio', 100], ['loss_fraction', 100]]
  },
  throughput_mbps: {
    owner: 'performance_agent', unit: 'Mbps', kind: 'rate', min: 0, max: 1e7, warn: null, crit: null, label: 'Throughput', info: true,
    text: ['Throughput', 'Throughput', 'Throughput'],
    aliases: [['throughput_mbps', 1], ['throughput', 1], ['tput_mbps', 1], ['thr_mbps', 1], ['throughput_kbps', 0.001], ['throughput_gbps', 1000], ['throughput_bps', 1e-6]]
  },
  bandwidth_mbps: {
    owner: 'performance_agent', unit: 'Mbps', kind: 'rate', min: 0, max: 1e7, warn: null, crit: null, label: 'Bandwidth', info: true,
    text: ['Bandwidth', 'Bandwidth', 'Bandwidth'],
    aliases: [['bandwidth_mbps', 1], ['bandwidth', 1], ['capacity_mbps', 1], ['link_speed_mbps', 1], ['link_capacity_mbps', 1], ['bandwidth_gbps', 1000], ['link_speed_gbps', 1000], ['bandwidth_kbps', 0.001], ['bandwidth_bps', 1e-6]]
  },
  link_utilization_pct: {
    owner: 'performance_agent', unit: '%', kind: 'pct', min: 0, max: 100, warn: 80, crit: 92, label: 'Link utilization',
    text: ['Link utilization within expected range', 'High link utilization', 'Saturated link'],
    aliases: [['link_utilization_pct', 1], ['link_utilization', 1], ['utilization', 1], ['utilisation', 1], ['utilization_pct', 1], ['util_pct', 1], ['link_util', 1], ['link_util_pct', 1], ['utilization_ratio', 100], ['link_utilization_ratio', 100], ['util_ratio', 100], ['utilization_fraction', 100]]
  },
  signal_dbm: {
    owner: 'performance_agent', unit: 'dBm', kind: 'dbm', min: -120, max: 0, warn: -70, crit: -80, lowerIsWorse: true, label: 'Wireless signal',
    text: ['Wireless signal strength is adequate', 'Weak wireless signal', 'Very weak wireless signal'],
    aliases: [['signal_dbm', 1], ['rssi', 1], ['rssi_dbm', 1], ['signal_strength', 1], ['signal_strength_dbm', 1], ['wifi_signal_dbm', 1], ['signal', 1]]
  },
  retransmission_pct: {
    owner: 'performance_agent', unit: '%', kind: 'pct', min: 0, max: 100, warn: 10, crit: 25, label: 'Retransmissions',
    text: ['Retransmissions within expected range', 'Elevated wireless retransmissions', 'Severe wireless retransmissions'],
    aliases: [['retransmission_pct', 1], ['retransmissions_pct', 1], ['retransmission_rate', 1], ['retry_pct', 1], ['wifi_retry_pct', 1], ['retransmit_pct', 1], ['retransmission_ratio', 100]]
  },
  dns_failure_pct: {
    owner: 'performance_agent', unit: '%', kind: 'pct', min: 0, max: 100, warn: 5, crit: 20, label: 'DNS failures',
    text: ['DNS resolution succeeding', 'Elevated DNS failures', 'Severe DNS failures'],
    aliases: [['dns_failure_pct', 1], ['dns_fail_pct', 1], ['dns_failure_rate', 1], ['dns_failures_pct', 1], ['dns_failure_ratio', 100]]
  },
  dns_latency_ms: {
    owner: 'performance_agent', unit: 'ms', kind: 'time', min: 0, max: 120000, warn: 200, crit: 800, label: 'DNS lookup time',
    text: ['DNS lookup time within expected range', 'Slow DNS lookups', 'Very slow DNS lookups'],
    aliases: [['dns_latency_ms', 1], ['dns_resolution_ms', 1], ['dns_lookup_ms', 1], ['dns_time_ms', 1], ['dns_latency_s', 1000]]
  },
  dhcp_failure_pct: {
    owner: 'performance_agent', unit: '%', kind: 'pct', min: 0, max: 100, warn: 5, crit: 20, label: 'DHCP failures',
    text: ['DHCP leases being issued', 'Elevated DHCP failures', 'Severe DHCP failures'],
    aliases: [['dhcp_failure_pct', 1], ['dhcp_fail_pct', 1], ['dhcp_failure_rate', 1], ['dhcp_failures_pct', 1], ['dhcp_failure_ratio', 100]]
  },
  dhcp_latency_ms: {
    owner: 'performance_agent', unit: 'ms', kind: 'time', min: 0, max: 120000, warn: 500, crit: 2000, label: 'DHCP response time',
    text: ['DHCP response time within expected range', 'Slow DHCP responses', 'Very slow DHCP responses'],
    aliases: [['dhcp_latency_ms', 1], ['dhcp_offer_ms', 1], ['dhcp_lease_ms', 1], ['dhcp_time_ms', 1], ['dhcp_latency_s', 1000]]
  },
  cpu_pct: {
    owner: 'infrastructure_agent', unit: '%', kind: 'pct', min: 0, max: 100, warn: 80, crit: 92, label: 'CPU utilization',
    text: ['CPU utilization within expected range', 'High CPU utilization', 'CPU saturated'],
    aliases: [['cpu_pct', 1], ['cpu', 1], ['cpu_utilization', 1], ['cpu_usage', 1], ['cpu_util', 1], ['cpu_percent', 1], ['cpu_load_pct', 1], ['cpu_ratio', 100]]
  },
  memory_pct: {
    owner: 'infrastructure_agent', unit: '%', kind: 'pct', min: 0, max: 100, warn: 85, crit: 95, label: 'Memory utilization',
    text: ['Memory utilization within expected range', 'High memory utilization', 'Memory nearly exhausted'],
    aliases: [['memory_pct', 1], ['memory', 1], ['mem_pct', 1], ['memory_utilization', 1], ['memory_usage', 1], ['mem_usage', 1], ['mem_util', 1], ['memory_percent', 1], ['memory_ratio', 100]]
  },
  queue_drops: {
    owner: 'infrastructure_agent', unit: 'drops/interval', kind: 'count', min: 0, max: 1e12, warn: 50, crit: 150, label: 'Egress queue drops',
    text: ['No significant queue drops', 'Elevated packet drops', 'Heavy packet drops'],
    aliases: [['queue_drops', 1], ['egress_queue_drops', 1], ['output_drops', 1], ['tx_drops', 1], ['egress_drops', 1], ['queue_drop_count', 1], ['output_queue_drops', 1]]
  },
  interface_errors: {
    owner: 'infrastructure_agent', unit: 'errors/interval', kind: 'count', min: 0, max: 1e12, warn: 10, crit: 100, label: 'Interface errors',
    text: ['Interface errors negligible', 'Rising interface errors', 'Heavy interface errors'],
    aliases: [['interface_errors', 1], ['if_errors', 1], ['crc_errors', 1], ['input_errors', 1], ['rx_errors', 1], ['interface_error_count', 1], ['errors', 1]]
  }
};

// Metrics the diagnosis is built on, grouped into the families a healthy report must cover.
const CORE_FAMILIES = [
  ['latency_ms', 'jitter_ms'], ['packet_loss_pct'], ['link_utilization_pct'], ['cpu_pct'], ['memory_pct'], ['queue_drops'], ['interface_errors']
];

const ALIAS = new Map();
for (const [metric, def] of Object.entries(METRICS)) {
  for (const [name, factor] of def.aliases) {
    if (ALIAS.has(name)) throw new Error(`netcoop schema: duplicate alias ${name}`);
    ALIAS.set(name, { metric, factor });
  }
}

const TIME_UNITS = { us: 0.001, 'µs': 0.001, ms: 1, s: 1000, sec: 1000, secs: 1000, seconds: 1000 };
const RATE_UNITS = { bps: 1e-6, kbps: 0.001, mbps: 1, gbps: 1000, 'kb/s': 0.001, 'mb/s': 1, 'gb/s': 1000 };
const PCT_UNITS = { '%': 1, pct: 1, percent: 1, ratio: 100, fraction: 100 };
const UNITS = { time: TIME_UNITS, rate: RATE_UNITS, pct: PCT_UNITS, dbm: { dbm: 1 }, count: null };

const STATUS_WORDS = {
  up: 'up', online: 'up', ok: 'up', active: 'up', healthy: 'up', running: 'up', '1': 'up', true: 'up',
  down: 'down', offline: 'down', unreachable: 'down', failed: 'down', dead: 'down', '0': 'down', false: 'down',
  degraded: 'degraded', warning: 'degraded', flapping: 'degraded', impaired: 'degraded', unstable: 'degraded'
};

const KEYS = {
  device: ['device_id', 'device', 'deviceid', 'node', 'node_id', 'host', 'hostname', 'switch_id', 'ap_id', 'router_id', 'name', 'id'],
  time: ['timestamp', 'ts', 'time', '@timestamp', 'datetime', 'collected_at', 'observed_at', 'epoch'],
  status: ['device_status', 'status', 'state', 'oper_status', 'operational_status'],
  type: ['device_type', 'type', 'role', 'kind', 'device_role'],
  site: ['site', 'location', 'building', 'zone', 'segment'],
  parent: ['uplink', 'uplink_device', 'parent', 'parent_id', 'upstream', 'upstream_device', 'connected_to'],
  container: ['metrics', 'telemetry', 'measurements', 'stats', 'counters']
};
const SAMPLE_LISTS = ['samples', 'records', 'measurements', 'telemetry', 'readings', 'data'];

const nk = (k) => String(k).toLowerCase().replace(/[^a-z0-9@]+/g, '_').replace(/^_+|_+$/g, '');
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const clip = (v, n = 80) => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s && s.length > n ? `${s.slice(0, n)}...` : s; };

// ---- Issue bookkeeping ----------------------------------------------------------------
class Quality {
  constructor() { this.issues = new Map(); this.conversions = new Map(); this.recordsIn = 0; this.recordsUsed = 0; }
  issue(code, message, example) {
    const hit = this.issues.get(code) || { code, message, count: 0, examples: [] };
    hit.count += 1;
    if (example !== undefined && hit.examples.length < 3) hit.examples.push(clip(example));
    this.issues.set(code, hit);
  }
  convert(metric, from, factor) {
    const key = `${metric}|${from}`;
    const hit = this.conversions.get(key) || { metric, from, to: METRICS[metric].unit, factor, count: 0 };
    hit.count += 1;
    this.conversions.set(key, hit);
  }
}

// ---- Parsing --------------------------------------------------------------------------------
function parseCsv(text) {
  const rows = []; let row = []; let field = ''; let q = false;
  const src = String(text).replace(/\r\n?/g, '\n');
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (q) {
      if (c === '"') { if (src[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  const [head, ...body] = rows.filter((r) => r.some((x) => x.trim() !== ''));
  if (!head) return [];
  return body.map((r) => Object.fromEntries(head.map((h, i) => [h.trim(), r[i] === undefined ? '' : r[i].trim()])));
}

function hasDeviceKey(o) { return isObj(o) && Object.keys(o).some((k) => KEYS.device.includes(nk(k))); }

function readInput(input, q) {
  let value;
  let format;
  if (typeof input === 'string') {
    const text = input.replace(/^\uFEFF/, '').trim();
    if (!text) throw new InputError('Input is empty. Paste telemetry as JSON, NDJSON or CSV.', 'empty_input');
    if (text.length > MAX_INPUT_CHARS) throw new InputError(`Input is larger than ${Math.round(MAX_INPUT_CHARS / 1048576)} MB. Split it into smaller files.`, 'too_large');
    try { value = JSON.parse(text); format = 'json'; } catch (err) {
      const looksJson = /^[{[]/.test(text);
      const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      const objs = [];
      if (looksJson) {
        for (const [n, line] of lines.entries()) {
          try { const o = JSON.parse(line); objs.push(o); } catch { q.issue('malformed_line', 'Line is not valid JSON and was skipped', `line ${n + 1}: ${line}`); }
        }
      }
      if (objs.length) { value = objs; format = 'ndjson'; } else if (!looksJson && lines.length > 1 && lines[0].includes(',')) { value = parseCsv(text); format = 'csv'; } else {
        throw new InputError(`Input is not valid JSON, NDJSON or CSV (${err.message}).`, 'unparsable');
      }
    }
  } else { value = input; format = 'object'; }

  if (Array.isArray(value)) return { records: value, envelope: {}, format };
  if (isObj(value)) {
    for (const k of SAMPLE_LISTS) {
      if (Array.isArray(value[k])) { const { [k]: records, ...envelope } = value; return { records, envelope, format }; }
    }
    if (hasDeviceKey(value)) return { records: [value], envelope: {}, format };
    throw new InputError(`The JSON object has no samples array. Expected one of: ${SAMPLE_LISTS.join(', ')}.`, 'no_samples');
  }
  throw new InputError('The top-level JSON value must be an object or an array of records.', 'bad_shape');
}

function parseSchemaVersion(raw) {
  if (raw == null || raw === '') return { major: SUPPORTED_MAJOR, assumed: true, text: '1.0' };
  const m = String(raw).match(/(\d+)(?:\.(\d+))?\s*$/);
  if (!m) return { major: NaN, assumed: false, text: String(raw) };
  return { major: Number(m[1]), assumed: false, text: String(raw) };
}

function toTime(v) {
  if (v == null || v === '') return { t: null, state: 'missing' };
  let ms;
  if (typeof v === 'number' || /^\d+(\.\d+)?$/.test(String(v).trim())) {
    const n = Number(v);
    ms = n > 1e14 ? n / 1000 : n > 1e11 ? n : n > 1e8 ? n * 1000 : NaN;
  } else ms = Date.parse(String(v));
  return Number.isFinite(ms) && ms > 0 ? { t: ms, state: 'ok' } : { t: null, state: 'invalid' };
}

const MISSING = new Set(['', 'n/a', 'na', 'nan', 'null', 'none', '-', '--', 'undefined']);

// Reads one metric value: number, numeric string ("12ms", "45%"), or { value, unit }.
function readValue(metric, raw, nameFactor, nameUnit, q) {
  const def = METRICS[metric];
  let num; let unit = null;
  if (isObj(raw)) {
    if (raw.value === undefined) return { drop: 'malformed' };
    unit = raw.unit != null ? String(raw.unit).toLowerCase() : null;
    raw = raw.value;
  }
  if (raw == null || (typeof raw === 'string' && MISSING.has(raw.trim().toLowerCase()))) return { missing: true };
  if (typeof raw === 'boolean') return { drop: 'malformed' };
  if (typeof raw === 'number') num = raw;
  else if (typeof raw === 'string') {
    const m = raw.trim().match(/^(-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)\s*([a-zµ%/]*)$/i);
    if (!m) return { drop: 'malformed' };
    num = Number(m[1]);
    if (m[2]) unit = unit || m[2].toLowerCase();
  } else return { drop: 'malformed' };
  if (!Number.isFinite(num)) return { drop: 'malformed' };

  let factor = nameFactor;
  let from = nameUnit;
  if (unit) {
    const table = UNITS[def.kind];
    if (table && table[unit] === undefined) return { drop: 'incompatible_unit', unit };
    if (table) { factor = table[unit]; from = unit; }
  }
  const value = num * factor;
  if (factor !== 1) q.convert(metric, from, factor);
  if (value < def.min || value > def.max) return { drop: 'out_of_range', value };
  return { value: Math.round(value * 1e6) / 1e6 };
}

function normalizeStatus(raw) {
  if (raw == null || raw === '') return null;
  const w = STATUS_WORDS[String(raw).trim().toLowerCase()];
  return w || 'unknown';
}

function normalizeRecord(raw, idx, q, topo) {
  if (!isObj(raw)) { q.issue('malformed_record', 'Record is not a JSON object and was skipped', raw); return null; }
  const flat = {};
  for (const [k, v] of Object.entries(raw)) flat[nk(k)] = v;

  const devKey = KEYS.device.find((k) => flat[k] != null && String(flat[k]).trim() !== '');
  if (!devKey) { q.issue('missing_device_id', 'Record has no device identifier and was skipped', raw); return null; }
  const device = String(flat[devKey]).trim();
  if (device.length > 120) { q.issue('malformed_record', 'Device identifier is longer than 120 characters; record skipped', device); return null; }

  const tk = KEYS.time.find((k) => flat[k] != null);
  const ts = toTime(tk ? flat[tk] : null);
  if (ts.state === 'missing') q.issue('missing_timestamp', 'Record has no timestamp; its position in the input is used for ordering');
  if (ts.state === 'invalid') q.issue('invalid_timestamp', 'Record has an unreadable timestamp; its position in the input is used for ordering', flat[tk]);

  // Metrics may sit in a nested object, at the top level, or both.
  const sources = [];
  for (const c of KEYS.container) if (isObj(flat[c])) sources.push(flat[c]);
  sources.push(raw);
  const metrics = {};
  for (const src of sources) {
    for (const [k, rawVal] of Object.entries(src)) {
      const alias = ALIAS.get(nk(k));
      if (!alias || metrics[alias.metric] !== undefined) continue;
      const r = readValue(alias.metric, rawVal, alias.factor, alias.factor !== 1 ? nk(k) : METRICS[alias.metric].unit, q);
      if (r.missing) continue;
      if (r.drop === 'out_of_range') { q.issue('out_of_range', `A ${alias.metric} value outside its plausible range was dropped`, `${alias.metric}=${rawVal && rawVal.value !== undefined ? rawVal.value : rawVal}`); continue; }
      if (r.drop === 'incompatible_unit') { q.issue('incompatible_unit', `A ${alias.metric} value used a unit that cannot be converted and was dropped`, `${alias.metric}: unit "${r.unit}"`); continue; }
      if (r.drop) { q.issue('malformed_value', `A ${alias.metric} value could not be read as a number and was dropped`, `${alias.metric}=${clip(rawVal)}`); continue; }
      metrics[alias.metric] = r.value;
    }
  }
  const derived = [];
  if (metrics.link_utilization_pct === undefined && metrics.throughput_mbps !== undefined && metrics.bandwidth_mbps > 0) {
    const u = (metrics.throughput_mbps / metrics.bandwidth_mbps) * 100;
    if (u <= 100.0001) { metrics.link_utilization_pct = Math.round(u * 100) / 100; derived.push('link_utilization_pct'); } else q.issue('inconsistent_throughput', 'Throughput exceeds bandwidth, so utilization could not be derived', `${metrics.throughput_mbps} > ${metrics.bandwidth_mbps} Mbps`);
  }

  const sk = KEYS.status.find((k) => flat[k] != null);
  const status = sk ? normalizeStatus(flat[sk]) : null;
  if (status === 'unknown') q.issue('unknown_status', 'Device status value is not recognised and was ignored', flat[sk]);

  const pk = KEYS.parent.find((k) => flat[k] != null && String(flat[k]).trim() !== '');
  if (pk && !topo.hints.has(device)) topo.hints.set(device, String(flat[pk]).trim());
  const typeKey = KEYS.type.find((k) => typeof flat[k] === 'string' && flat[k].trim());
  const siteKey = KEYS.site.find((k) => typeof flat[k] === 'string' && flat[k].trim());

  if (!Object.keys(metrics).length && (status == null || status === 'unknown')) { q.issue('no_usable_fields', 'Record carried no metric or status the agents understand and was skipped', raw); return null; }

  return {
    idx, device_id: device, t: ts.t, ts: ts.t ? new Date(ts.t).toISOString() : null,
    status: status === 'unknown' ? null : status, metrics, derived,
    device_type: typeKey ? flat[typeKey].trim().toLowerCase().slice(0, 40) : null,
    site: siteKey ? flat[siteKey].trim().slice(0, 80) : null
  };
}

// ---- Topology ---------------------------------------------------------------------------------
// A link {from, to} reads "from is upstream of to". parent/child, upstream/downstream and
// source/target are accepted spellings. Cycles and second uplinks are reported, not applied.
function buildTopology(envelope, hints, q) {
  const parents = new Map();
  const link = (up, down, why) => {
    up = String(up || '').trim(); down = String(down || '').trim();
    if (!up || !down) return;
    if (up === down) { q.issue('topology_cycle', 'A device is linked to itself; the link was ignored', up); return; }
    if (parents.has(down)) { if (parents.get(down) !== up) q.issue('multiple_uplinks', 'A device has more than one uplink; the first one is used for scope analysis', `${down}: ${parents.get(down)} / ${up} (${why})`); return; }
    for (let cur = up, hops = 0; cur && hops < 1000; cur = parents.get(cur), hops++) {
      if (cur === down) { q.issue('topology_cycle', 'A link would create a loop in the topology and was ignored', `${up} -> ${down}`); return; }
    }
    parents.set(down, up);
  };
  const topo = envelope.topology;
  const links = Array.isArray(topo) ? topo : isObj(topo) ? (topo.links || topo.edges || []) : [];
  if (Array.isArray(links)) {
    for (const l of links) {
      if (!isObj(l)) { q.issue('malformed_link', 'A topology link is not an object and was ignored', l); continue; }
      const f = {}; for (const [k, v] of Object.entries(l)) f[nk(k)] = v;
      const up = f.from ?? f.parent ?? f.upstream ?? f.source ?? f.a;
      const down = f.to ?? f.child ?? f.downstream ?? f.target ?? f.b;
      if (up == null || down == null) { q.issue('malformed_link', 'A topology link needs from/to (or parent/child) and was ignored', l); continue; }
      link(up, down, 'topology');
    }
  }
  if (isObj(topo) && isObj(topo.parents)) for (const [child, parent] of Object.entries(topo.parents)) link(parent, child, 'topology.parents');
  const devices = new Map();
  if (Array.isArray(envelope.devices)) {
    for (const d of envelope.devices) {
      if (!isObj(d)) continue;
      const f = {}; for (const [k, v] of Object.entries(d)) f[nk(k)] = v;
      const id = KEYS.device.map((k) => f[k]).find((v) => v != null && String(v).trim() !== '');
      if (id == null) { q.issue('malformed_record', 'A device entry has no identifier and was ignored', d); continue; }
      const key = String(id).trim();
      const pk = KEYS.parent.map((k) => f[k]).find((v) => v != null && String(v).trim() !== '');
      if (pk != null) link(pk, key, 'devices');
      const type = KEYS.type.map((k) => f[k]).find((v) => typeof v === 'string' && v.trim());
      const site = KEYS.site.map((k) => f[k]).find((v) => typeof v === 'string' && v.trim());
      devices.set(key, { type: type ? type.trim().toLowerCase().slice(0, 40) : null, site: site ? site.trim().slice(0, 80) : null });
    }
  }
  for (const [down, up] of hints) link(up, down, 'record');
  return { parents, devices };
}

// ---- Dataset ------------------------------------------------------------------------------------
class Dataset {
  constructor({ samples, parents, devices, meta }) {
    this.meta = meta;
    this.parents = parents;
    this.deviceMeta = devices;
    this.by = new Map();
    for (const s of samples) { if (!this.by.has(s.device_id)) this.by.set(s.device_id, []); this.by.get(s.device_id).push(s); }
    for (const list of this.by.values()) list.sort((a, b) => (a.t != null && b.t != null ? a.t - b.t : a.idx - b.idx));
    this.sampleCount = samples.length;
  }
  ids() { return [...this.by.keys()]; }
  samplesOf(id) { return this.by.get(id) || []; }
  series(id, metric) { return this.samplesOf(id).filter((s) => s.metrics[metric] !== undefined).map((s) => ({ t: s.t, v: s.metrics[metric] })); }
  statusSeries(id) { return this.samplesOf(id).filter((s) => s.status).map((s) => ({ t: s.t, v: s.status })); }
  typeOf(id) { return (this.deviceMeta.get(id) && this.deviceMeta.get(id).type) || (this.samplesOf(id).find((s) => s.device_type) || {}).device_type || null; }
  siteOf(id) { return (this.deviceMeta.get(id) && this.deviceMeta.get(id).site) || (this.samplesOf(id).find((s) => s.site) || {}).site || null; }
  parentOf(id) { return this.parents.get(id) || null; }
  ancestors(id) { const out = []; for (let c = this.parents.get(id), n = 0; c && n < 1000; c = this.parents.get(c), n++) out.push(c); return out; }
  children(id) { return [...this.parents].filter(([, p]) => p === id).map(([c]) => c); }
  descendants(id) { const out = []; const todo = this.children(id); while (todo.length) { const c = todo.shift(); out.push(c); todo.push(...this.children(c)); } return out; }
  hasTopology() { return this.parents.size > 0; }
}

// ---- Entry point ----------------------------------------------------------------------------------
function normalizeInput(input) {
  const q = new Quality();
  const fail = (message, code) => ({ ok: false, errors: [{ code, message }], dataset: null, quality: summarize(q, null, code) });
  let read;
  try { read = readInput(input, q); } catch (err) {
    if (err instanceof InputError) return fail(err.message, err.code);
    throw err;
  }
  const { records, envelope, format } = read;
  const ver = parseSchemaVersion(envelope.schema_version ?? envelope.schema ?? envelope.version);
  if (Number.isNaN(ver.major) || ver.major !== SUPPORTED_MAJOR) {
    return fail(`Incompatible schema version "${ver.text}". This build reads ${SCHEMA_ID} (major version ${SUPPORTED_MAJOR}).`, 'incompatible_schema');
  }
  if (ver.assumed) q.issue('schema_version_missing', `No schema_version in the input; ${SCHEMA_ID} is assumed`);
  if (!records.length) return fail('The input contains no telemetry records.', 'no_records');
  if (records.length > MAX_RECORDS) return fail(`The input has ${records.length} records; the limit is ${MAX_RECORDS} per run.`, 'too_many_records');

  const topoHints = { hints: new Map() };
  const samples = [];
  q.recordsIn = records.length;
  records.forEach((r, i) => { const s = normalizeRecord(r, i, q, topoHints); if (s) samples.push(s); });
  q.recordsUsed = samples.length;
  if (!samples.length) {
    const why = [...q.issues.values()].sort((a, b) => b.count - a.count).slice(0, 3).map((x) => `${x.count}x ${x.code}`).join(', ');
    return fail(`None of the ${records.length} records could be used (${why || 'no readable fields'}).`, 'no_usable_records');
  }
  const { parents, devices } = buildTopology(envelope, topoHints.hints, q);
  const ids = new Set(samples.map((s) => s.device_id));
  if (ids.size > MAX_DEVICES) return fail(`The input covers ${ids.size} devices; the limit is ${MAX_DEVICES} per run.`, 'too_many_devices');
  for (const [child, parent] of [...parents]) {
    if (!ids.has(child) && !ids.has(parent)) { parents.delete(child); q.issue('topology_unknown_device', 'A topology link between devices with no telemetry was ignored', `${parent} -> ${child}`); }
  }
  const silent = new Set([...devices.keys(), ...parents.keys(), ...parents.values()].filter((d) => !ids.has(d)));
  for (const d of silent) q.issue('no_telemetry_for_device', 'A device named in the topology or device list has no telemetry, so nothing can be said about it', d);
  const times = samples.map((s) => s.t).filter((t) => t != null);
  const meta = {
    format, schema_version: ver.text, schema_assumed: ver.assumed,
    incident_id: typeof envelope.incident_id === 'string' ? envelope.incident_id.slice(0, 60) : null,
    label: typeof envelope.scenario === 'string' ? envelope.scenario.slice(0, 80) : (typeof envelope.label === 'string' ? envelope.label.slice(0, 80) : null),
    synthetic: envelope.synthetic === true,
    source: typeof envelope.source === 'string' ? envelope.source.slice(0, 160) : null,
    start: times.length ? new Date(Math.min(...times)).toISOString() : null,
    end: times.length ? new Date(Math.max(...times)).toISOString() : null,
    timestamped: times.length
  };
  const dataset = new Dataset({ samples, parents, devices, meta });
  return { ok: true, errors: [], dataset, quality: summarize(q, dataset, null) };
}

function summarize(q, dataset, fatal) {
  const issues = [...q.issues.values()].sort((a, b) => b.count - a.count);
  const dropped = q.recordsIn - q.recordsUsed;
  const observed = {};
  const coverage = {};
  if (dataset) {
    for (const id of dataset.ids()) {
      const seen = new Set();
      for (const s of dataset.samplesOf(id)) for (const m of Object.keys(s.metrics)) { seen.add(m); }
      if (dataset.statusSeries(id).length) seen.add('device_status');
      coverage[id] = [...seen].sort();
      for (const m of seen) { observed[m] = observed[m] || { devices: 0, samples: 0 }; observed[m].devices += 1; }
      for (const s of dataset.samplesOf(id)) for (const m of Object.keys(s.metrics)) observed[m].samples += 1;
    }
  }
  let grade = 'clean';
  if (fatal) grade = 'rejected';
  else if (q.recordsIn && dropped / q.recordsIn > 0.5) grade = 'poor';
  else if (dropped || issues.length || q.conversions.size) grade = 'repaired';
  return {
    grade, records_in: q.recordsIn, records_used: q.recordsUsed, records_dropped: dropped,
    devices: dataset ? dataset.ids().length : 0,
    issues: issues.map((i) => ({ code: i.code, message: i.message, count: i.count, examples: i.examples })),
    unit_conversions: [...q.conversions.values()],
    metrics_observed: observed, device_coverage: coverage,
    topology_links: dataset ? dataset.parents.size : 0
  };
}

module.exports = {
  SCHEMA_ID, REPORT_SCHEMA, MESSAGE_SCHEMA, METRICS, CORE_FAMILIES, KEYS, SUPPORTED_MAJOR, MAX_RECORDS, MAX_DEVICES, MAX_INPUT_CHARS,
  Dataset, normalizeInput, parseCsv, InputError
};
