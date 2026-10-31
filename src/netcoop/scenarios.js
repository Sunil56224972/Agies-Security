'use strict';

// NetCoop AI: built-in test scenarios that generate realistic synthetic
// telemetry. Each scenario produces a valid telemetry envelope with
// devices, topology and samples that exercise the agents in a known way.

const { SCHEMA_ID } = require('./schema');

// ── Helpers ──────────────────────────────────────────────────────────────
const ts = (offset = 0) => new Date(Date.now() - offset * 60000).toISOString();
const jitter = (base, pct = 0.1) => +(base * (1 + (Math.random() - 0.5) * 2 * pct)).toFixed(2);
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const range = (n) => Array.from({ length: n }, (_, i) => i);

function makeSamples(devices, metrics, count, genFn) {
  const samples = [];
  for (const d of devices) {
    for (let i = 0; i < count; i++) {
      const row = { device_id: d, timestamp: ts(count - i) };
      for (const m of metrics) {
        const v = genFn(d, m, i, count);
        if (v !== undefined && v !== null) row[m] = v;
      }
      samples.push(row);
    }
  }
  return samples;
}

// ── Scenario definitions ────────────────────────────────────────────────
const SCENARIOS = [
  {
    key: 'normal',
    name: 'Normal Operation',
    description: 'Healthy network — all metrics within expected ranges. Should produce no significant findings.',
    generate() {
      const devices = ['core-sw-01', 'dist-sw-01', 'dist-sw-02', 'ap-floor1', 'ap-floor2', 'srv-web-01', 'srv-db-01'];
      const topology = { 'dist-sw-01': 'core-sw-01', 'dist-sw-02': 'core-sw-01', 'ap-floor1': 'dist-sw-01', 'ap-floor2': 'dist-sw-02', 'srv-web-01': 'dist-sw-01', 'srv-db-01': 'dist-sw-02' };
      const metrics = ['latency_ms', 'jitter_ms', 'packet_loss_pct', 'link_utilization_pct', 'cpu_pct', 'memory_pct', 'interface_errors', 'queue_drops'];
      const samples = makeSamples(devices, metrics, 20, (d, m) => {
        const vals = { latency_ms: jitter(12, 0.3), jitter_ms: jitter(3, 0.3), packet_loss_pct: jitter(0.05, 0.5), link_utilization_pct: jitter(35, 0.2), cpu_pct: jitter(25, 0.2), memory_pct: jitter(40, 0.15), interface_errors: 0, queue_drops: 0 };
        return vals[m];
      });
      return { schema: SCHEMA_ID, devices: devices.map(id => ({ device_id: id, parent: topology[id] || null, type: id.startsWith('ap') ? 'access_point' : id.startsWith('srv') ? 'server' : 'switch', name: id })), samples };
    }
  },
  {
    key: 'link_congestion',
    name: 'Link Congestion',
    description: 'Distribution switch uplink saturated — high utilization, queue drops, elevated latency and jitter on downstream devices.',
    generate() {
      const devices = ['core-rtr-01', 'dist-sw-01', 'dist-sw-02', 'acc-sw-01', 'acc-sw-02', 'srv-app-01', 'srv-app-02'];
      const topology = { 'dist-sw-01': 'core-rtr-01', 'dist-sw-02': 'core-rtr-01', 'acc-sw-01': 'dist-sw-01', 'acc-sw-02': 'dist-sw-01', 'srv-app-01': 'acc-sw-01', 'srv-app-02': 'acc-sw-02' };
      const congestedLink = 'dist-sw-01';
      const downstream = ['acc-sw-01', 'acc-sw-02', 'srv-app-01', 'srv-app-02'];
      const metrics = ['latency_ms', 'jitter_ms', 'packet_loss_pct', 'link_utilization_pct', 'throughput_mbps', 'bandwidth_mbps', 'cpu_pct', 'memory_pct', 'queue_drops', 'interface_errors'];
      const samples = makeSamples(devices, metrics, 25, (d, m, i, total) => {
        const ramp = Math.min(1, i / (total * 0.6));
        if (d === congestedLink) {
          if (m === 'link_utilization_pct') return +(40 + 55 * ramp + jitter(0, 3)).toFixed(2);
          if (m === 'queue_drops') return Math.round(ramp * jitter(80, 0.3));
          if (m === 'latency_ms') return jitter(15 + 200 * ramp, 0.15);
          if (m === 'jitter_ms') return jitter(4 + 60 * ramp, 0.2);
          if (m === 'packet_loss_pct') return +(0.1 + 4.5 * ramp).toFixed(2);
          if (m === 'throughput_mbps') return jitter(900 + 50 * ramp, 0.05);
          if (m === 'bandwidth_mbps') return 1000;
          if (m === 'cpu_pct') return jitter(30, 0.2);
          if (m === 'memory_pct') return jitter(45, 0.15);
        }
        if (downstream.includes(d)) {
          if (m === 'latency_ms') return jitter(20 + 150 * ramp, 0.2);
          if (m === 'jitter_ms') return jitter(5 + 40 * ramp, 0.2);
          if (m === 'packet_loss_pct') return +(0.1 + 3 * ramp).toFixed(2);
          if (m === 'link_utilization_pct') return jitter(30, 0.2);
          if (m === 'queue_drops') return 0;
          if (m === 'cpu_pct') return jitter(20, 0.2);
          if (m === 'memory_pct') return jitter(35, 0.15);
        }
        // healthy devices
        const healthy = { latency_ms: jitter(10, 0.2), jitter_ms: jitter(2, 0.3), packet_loss_pct: 0, link_utilization_pct: jitter(25, 0.2), cpu_pct: jitter(20, 0.2), memory_pct: jitter(40, 0.15), queue_drops: 0, interface_errors: 0, throughput_mbps: jitter(500, 0.1), bandwidth_mbps: 1000 };
        return healthy[m] !== undefined ? healthy[m] : undefined;
      });
      return { schema: SCHEMA_ID, devices: devices.map(id => ({ device_id: id, parent: topology[id] || null, type: id.startsWith('srv') ? 'server' : 'router' === id.split('-')[0] ? 'router' : 'switch', name: id })), samples };
    }
  },
  {
    key: 'weak_wifi',
    name: 'Weak Wi-Fi Signal',
    description: 'Access point showing poor signal strength — retransmissions, high loss, elevated latency for wireless clients.',
    generate() {
      const devices = ['core-sw-01', 'dist-sw-01', 'ap-office-01', 'ap-office-02', 'laptop-01', 'laptop-02', 'phone-01'];
      const topology = { 'dist-sw-01': 'core-sw-01', 'ap-office-01': 'dist-sw-01', 'ap-office-02': 'dist-sw-01', 'laptop-01': 'ap-office-01', 'laptop-02': 'ap-office-01', 'phone-01': 'ap-office-01' };
      const weakAp = 'ap-office-01';
      const wirelessClients = ['laptop-01', 'laptop-02', 'phone-01'];
      const metrics = ['latency_ms', 'jitter_ms', 'packet_loss_pct', 'signal_dbm', 'retransmission_pct', 'cpu_pct', 'memory_pct', 'link_utilization_pct'];
      const samples = makeSamples(devices, metrics, 20, (d, m) => {
        if (d === weakAp || wirelessClients.includes(d)) {
          if (m === 'signal_dbm') return jitter(-82, 0.05);
          if (m === 'retransmission_pct') return jitter(18, 0.2);
          if (m === 'latency_ms') return jitter(180, 0.2);
          if (m === 'jitter_ms') return jitter(45, 0.25);
          if (m === 'packet_loss_pct') return jitter(3.5, 0.3);
          if (m === 'cpu_pct') return jitter(15, 0.2);
          if (m === 'memory_pct') return jitter(30, 0.15);
          if (m === 'link_utilization_pct') return jitter(20, 0.2);
        }
        const healthy = { latency_ms: jitter(8, 0.2), jitter_ms: jitter(2, 0.2), packet_loss_pct: 0, cpu_pct: jitter(20, 0.2), memory_pct: jitter(40, 0.15), link_utilization_pct: jitter(25, 0.2) };
        return healthy[m] !== undefined ? healthy[m] : undefined;
      });
      return { schema: SCHEMA_ID, devices: devices.map(id => ({ device_id: id, parent: topology[id] || null, type: id.startsWith('ap') ? 'access_point' : id.startsWith('laptop') || id.startsWith('phone') ? 'endpoint' : 'switch', name: id })), samples };
    }
  },
  {
    key: 'interface_fault',
    name: 'Interface Fault',
    description: 'A switch interface is flapping — rising error counts, link status changes, packet loss spikes.',
    generate() {
      const devices = ['core-sw-01', 'agg-sw-01', 'acc-sw-01', 'acc-sw-02', 'srv-01', 'srv-02'];
      const topology = { 'agg-sw-01': 'core-sw-01', 'acc-sw-01': 'agg-sw-01', 'acc-sw-02': 'agg-sw-01', 'srv-01': 'acc-sw-01', 'srv-02': 'acc-sw-01' };
      const faultyDev = 'acc-sw-01';
      const metrics = ['latency_ms', 'jitter_ms', 'packet_loss_pct', 'interface_errors', 'link_status', 'cpu_pct', 'memory_pct', 'link_utilization_pct'];
      const samples = makeSamples(devices, metrics, 25, (d, m, i) => {
        if (d === faultyDev) {
          if (m === 'interface_errors') return Math.round(jitter(50 + i * 8, 0.2));
          if (m === 'link_status') return i % 4 === 0 ? 0 : 1; // flapping
          if (m === 'packet_loss_pct') return jitter(6 + i * 0.3, 0.2);
          if (m === 'latency_ms') return jitter(50 + i * 10, 0.15);
          if (m === 'jitter_ms') return jitter(15 + i * 3, 0.2);
          if (m === 'cpu_pct') return jitter(30, 0.2);
          if (m === 'memory_pct') return jitter(45, 0.15);
          if (m === 'link_utilization_pct') return jitter(40, 0.2);
        }
        if (d === 'srv-01' || d === 'srv-02') {
          if (m === 'packet_loss_pct') return jitter(3 + i * 0.15, 0.3);
          if (m === 'latency_ms') return jitter(30 + i * 5, 0.2);
        }
        const healthy = { latency_ms: jitter(10, 0.2), jitter_ms: jitter(3, 0.2), packet_loss_pct: 0, interface_errors: 0, link_status: 1, cpu_pct: jitter(20, 0.2), memory_pct: jitter(40, 0.15), link_utilization_pct: jitter(30, 0.2) };
        return healthy[m] !== undefined ? healthy[m] : undefined;
      });
      return { schema: SCHEMA_ID, devices: devices.map(id => ({ device_id: id, parent: topology[id] || null, type: id.startsWith('srv') ? 'server' : 'switch', name: id })), samples };
    }
  },
  {
    key: 'dns_failure',
    name: 'DNS Failure',
    description: 'DNS resolver is timing out — elevated DNS resolution times, failure responses, downstream impact on application servers.',
    generate() {
      const devices = ['core-rtr-01', 'dns-srv-01', 'dns-srv-02', 'app-srv-01', 'app-srv-02', 'db-srv-01'];
      const topology = { 'dns-srv-01': 'core-rtr-01', 'dns-srv-02': 'core-rtr-01', 'app-srv-01': 'core-rtr-01', 'app-srv-02': 'core-rtr-01', 'db-srv-01': 'core-rtr-01' };
      const failDns = 'dns-srv-01';
      const metrics = ['latency_ms', 'packet_loss_pct', 'dns_resolution_ms', 'dns_failure_pct', 'cpu_pct', 'memory_pct'];
      const samples = makeSamples(devices, metrics, 20, (d, m, i) => {
        if (d === failDns) {
          if (m === 'dns_resolution_ms') return jitter(4500 + i * 100, 0.1);
          if (m === 'dns_failure_pct') return jitter(65, 0.15);
          if (m === 'cpu_pct') return jitter(90, 0.05);
          if (m === 'memory_pct') return jitter(85, 0.05);
          if (m === 'latency_ms') return jitter(20, 0.2);
          if (m === 'packet_loss_pct') return 0;
        }
        if (d === 'dns-srv-02') {
          if (m === 'dns_resolution_ms') return jitter(15, 0.3);
          if (m === 'dns_failure_pct') return 0;
          if (m === 'cpu_pct') return jitter(60, 0.1);
          if (m === 'memory_pct') return jitter(55, 0.1);
        }
        if (d === 'app-srv-01' || d === 'app-srv-02') {
          if (m === 'dns_resolution_ms') return jitter(3000 + i * 50, 0.15);
          if (m === 'dns_failure_pct') return jitter(40, 0.2);
        }
        const healthy = { latency_ms: jitter(8, 0.2), packet_loss_pct: 0, cpu_pct: jitter(25, 0.2), memory_pct: jitter(40, 0.15) };
        return healthy[m] !== undefined ? healthy[m] : undefined;
      });
      return { schema: SCHEMA_ID, devices: devices.map(id => ({ device_id: id, parent: topology[id] || null, type: id.includes('dns') ? 'dns_server' : id.includes('rtr') ? 'router' : 'server', name: id })), samples };
    }
  },
  {
    key: 'dhcp_failure',
    name: 'DHCP Failure',
    description: 'DHCP server pool exhausted — clients failing to obtain addresses, connection timeouts.',
    generate() {
      const devices = ['core-sw-01', 'dhcp-srv-01', 'acc-sw-01', 'client-01', 'client-02', 'client-03'];
      const topology = { 'dhcp-srv-01': 'core-sw-01', 'acc-sw-01': 'core-sw-01', 'client-01': 'acc-sw-01', 'client-02': 'acc-sw-01', 'client-03': 'acc-sw-01' };
      const metrics = ['latency_ms', 'packet_loss_pct', 'dhcp_failure_pct', 'dhcp_lease_time_ms', 'cpu_pct', 'memory_pct'];
      const samples = makeSamples(devices, metrics, 20, (d, m, i) => {
        if (d === 'dhcp-srv-01') {
          if (m === 'dhcp_failure_pct') return jitter(75, 0.1);
          if (m === 'dhcp_lease_time_ms') return jitter(30000, 0.1);
          if (m === 'cpu_pct') return jitter(85, 0.05);
          if (m === 'memory_pct') return jitter(92, 0.03);
        }
        if (d.startsWith('client-')) {
          if (m === 'dhcp_failure_pct') return jitter(60, 0.15);
          if (m === 'dhcp_lease_time_ms') return jitter(25000, 0.15);
          if (m === 'latency_ms') return jitter(200, 0.3);
          if (m === 'packet_loss_pct') return jitter(5, 0.3);
        }
        const healthy = { latency_ms: jitter(10, 0.2), packet_loss_pct: 0, cpu_pct: jitter(20, 0.2), memory_pct: jitter(40, 0.15) };
        return healthy[m] !== undefined ? healthy[m] : undefined;
      });
      return { schema: SCHEMA_ID, devices: devices.map(id => ({ device_id: id, parent: topology[id] || null, type: id.includes('dhcp') ? 'dhcp_server' : id.startsWith('client') ? 'endpoint' : 'switch', name: id })), samples };
    }
  },
  {
    key: 'interop_failure',
    name: 'Interoperability Test',
    description: 'Telemetry with wrong field names, different units (seconds instead of ms), missing schema version — tests the normaliser\'s error handling.',
    generate() {
      // deliberately use wrong / alternative field names and different units
      const data = {
        version: '2.0', // wrong major version? Actually use no 'schema' key
        device_list: [
          { id: 'router-A', upstream: null, kind: 'router' },
          { id: 'switch-B', upstream: 'router-A', kind: 'switch' },
          { id: 'host-C', upstream: 'switch-B', kind: 'server' }
        ],
        records: []
      };
      for (let i = 0; i < 15; i++) {
        data.records.push(
          { device: 'router-A', time: ts(15 - i), rtt_s: jitter(0.015, 0.2), jitter_us: jitter(3000, 0.2), loss_ratio: jitter(0.001, 0.3), utilization_ratio: jitter(0.25, 0.2), cpu_percent: jitter(20, 0.2) },
          { device: 'switch-B', time: ts(15 - i), delay_ms: jitter(12, 0.2), pkt_loss: jitter(0.1, 0.3), util_pct: jitter(30, 0.2), cpu_percent: jitter(22, 0.2), mem_percent: jitter(45, 0.15) },
          { device: 'host-C', time: ts(15 - i), latency_avg_ms: jitter(15, 0.2), throughput_kbps: jitter(500000, 0.1), capacity_mbps: 1000 }
        );
      }
      return data; // intentionally no 'schema' key, wrong field names — the normaliser should handle it
    }
  },
  {
    key: 'device_overload',
    name: 'Device Overload',
    description: 'Core switch CPU and memory critically high — performance degradation cascading to all downstream devices.',
    generate() {
      const devices = ['core-sw-01', 'dist-sw-01', 'dist-sw-02', 'srv-web-01', 'srv-web-02', 'srv-db-01'];
      const topology = { 'dist-sw-01': 'core-sw-01', 'dist-sw-02': 'core-sw-01', 'srv-web-01': 'dist-sw-01', 'srv-web-02': 'dist-sw-01', 'srv-db-01': 'dist-sw-02' };
      const metrics = ['latency_ms', 'jitter_ms', 'packet_loss_pct', 'cpu_pct', 'memory_pct', 'queue_drops', 'link_utilization_pct'];
      const samples = makeSamples(devices, metrics, 20, (d, m, i) => {
        if (d === 'core-sw-01') {
          if (m === 'cpu_pct') return jitter(96, 0.03);
          if (m === 'memory_pct') return jitter(94, 0.03);
          if (m === 'queue_drops') return Math.round(jitter(200 + i * 15, 0.15));
          if (m === 'latency_ms') return jitter(300 + i * 10, 0.1);
          if (m === 'jitter_ms') return jitter(80, 0.15);
          if (m === 'packet_loss_pct') return jitter(7, 0.2);
          if (m === 'link_utilization_pct') return jitter(50, 0.15);
        }
        // downstream sees elevated latency and loss
        if (m === 'latency_ms') return jitter(100 + i * 5, 0.2);
        if (m === 'jitter_ms') return jitter(30, 0.2);
        if (m === 'packet_loss_pct') return jitter(3, 0.3);
        if (m === 'cpu_pct') return jitter(25, 0.2);
        if (m === 'memory_pct') return jitter(40, 0.15);
        if (m === 'queue_drops') return 0;
        if (m === 'link_utilization_pct') return jitter(30, 0.2);
      });
      return { schema: SCHEMA_ID, devices: devices.map(id => ({ device_id: id, parent: topology[id] || null, type: id.startsWith('srv') ? 'server' : 'switch', name: id })), samples };
    }
  }
];

function generate(key) {
  const s = SCENARIOS.find(sc => sc.key === key);
  if (!s) throw new Error(`Unknown scenario: ${key}. Available: ${SCENARIOS.map(sc => sc.key).join(', ')}`);
  return s.generate();
}

module.exports = { SCENARIOS, generate };

