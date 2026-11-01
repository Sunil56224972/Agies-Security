# NetCoop AI — Multi-Agent Cooperative Network Fault Diagnosis & Interoperability System

[![Node.js Version](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-339933?style=flat-square&logo=node.js)](https://nodejs.org/)
[![Groq LPU](https://img.shields.io/badge/Inference-Groq%20LPU%20(gpt--oss--120b)-F55036?style=flat-square&logo=speedtest)](https://groq.com/)
[![Protocol Version](https://img.shields.io/badge/Protocol-JSON--RPC%20v1.0.0-2D5BD1?style=flat-square)](https://github.com/Sunil56224972/Netcoop)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Hackathon](https://img.shields.io/badge/IIT%20Bhubaneswar-Agentic%20AI%20Grand%20Finale-blueviolet?style=flat-square)](#)

> **Autonomous multi-agent network fault localization, evidence correlation, and technical remediation engine developed for the IIT Bhubaneswar Campus Network Infrastructure.**

---

## 📑 Table of Contents

- [Executive Summary](#-executive-summary)
- [Problem Statement Alignment](#-problem-statement-alignment)
- [System Architecture](#-system-architecture)
- [Specialized Agent Roles](#-specialized-agent-roles)
- [JSON-RPC v1.0.0 Interoperability Protocol](#-json-rpc-v100-interoperability-protocol)
- [Mathematical Formulation & Scoring](#-mathematical-formulation--scoring)
- [Groq LPU AI Synthesis Engine](#-groq-lpu-ai-synthesis-engine)
- [IIT Bhubaneswar Campus Topology](#-iit-bhubaneswar-campus-topology)
- [Built-In Test Scenarios](#-built-in-test-scenarios)
- [Web Application UI/UX](#-web-application-uiux)
- [REST API Specification](#-rest-api-specification)
- [Quickstart Guide](#-quickstart-guide)
- [Automated Verification Suite](#-automated-verification-suite)
- [License](#-license)

---

## 🎯 Executive Summary

Modern campus network environments—such as the **IIT Bhubaneswar academic and residential infrastructure**—face heterogeneous, transient network anomalies ranging from wireless radio frequency degradation and link saturation to hardware interface flapping and core resolver timeouts. Traditional rule-based monitors fail because they isolate symptoms without understanding topological dependencies.

**NetCoop AI** implements a **collaborative multi-agent framework** in which five specialized diagnostic agents exchange structured JSON-RPC messages across an in-memory message bus, cross-examine competing hypotheses, validate telemetry data quality, and feed consensus findings into an ultra-low-latency **Groq LPU reasoning agent (`openai/gpt-oss-120b`)** to generate production-ready network CLI remediation procedures.

---

## 📋 Problem Statement Alignment

NetCoop AI addresses 100% of the requirements defined in the **Agentic AI Hackathon Round 2 Problem Statement**:

| Round 2 Requirement | NetCoop AI Implementation | Status |
| :--- | :--- | :---: |
| **Probable Root Cause Identification** | Bayesian evidence ranking across 8 fault categories with topological propagation analysis. | `VERIFIED` |
| **Affected Scope Localization** | Maps impaired nodes, downstream blast radiuses, and unaffected baselines across campus facilities. | `VERIFIED` |
| **Supporting Evidence Integration** | Correlates anomalous metrics against statistical medians, dynamic warning thresholds, and critical bounds. | `VERIFIED` |
| **Alternative Causes & Uncertainty** | Explicitly computes competing explanations, uncertainty scoring, and coverage ratios. | `VERIFIED` |
| **Calibrated Confidence Category** | Scores 0% to 100% mapped into calibrated bands (`High`, `Medium`, `Low`) based on metric coverage. | `VERIFIED` |
| **Practical Corrective Actions** | Generates vendor-specific CLI scripts (Cisco IOS, Aruba OS, Linux) and operational procedures. | `VERIFIED` |
| **Insufficient Evidence Guardrails** | **Hard rule:** The system never claims an exact root cause when telemetry coverage is inadequate. | `VERIFIED` |
| **Multi-Agent Interoperability** | Asynchronous JSON-RPC v1.0.0 message envelopes with typed payloads (`task`, `finding`, `challenge`, `result`). | `VERIFIED` |

---

## 🏗️ System Architecture

```
                       ┌───────────────────────────────────────────────┐
                       │     Raw Telemetry (JSON / NDJSON / CSV)       │
                       └───────────────────────┬───────────────────────┘
                                               │
                                     [ Input Normalizer ]
                                 (Schema & Range Validation)
                                               │
               ┌───────────────────────────────┴───────────────────────────────┐
               ▼                                                               ▼
  ┌─────────────────────────┐                                     ┌─────────────────────────┐
  │   Performance Agent     │                                     │  Infrastructure Agent   │
  │ (Latency, Jitter, Loss) │                                     │ (CPU, RAM, Queue Drops) │
  └────────────┬────────────┘                                     └────────────┬────────────┘
               │                                                               │
               │              ┌─────────────────────────────────┐              │
               └─────────────►│    JSON-RPC v1.0.0 MessageBus   │◄─────────────┘
                              │    (Asynchronous Agent Bus)     │
               ┌─────────────►│                                 │◄─────────────┐
               │              └────────────────┬────────────────┘              │
               │                               │                               │
  ┌────────────┴────────────┐                  │                  ┌────────────┴────────────┐
  │   Connectivity Agent    │                  ▼                  │ Fault Correlation Agent │
  │  (Topology & DNS/DHCP)  │     ┌─────────────────────────┐     │  (Consensus & Ranking)  │
  └─────────────────────────┘     │   Recommendation Agent  │     └─────────────────────────┘
                                  │ (Mitigations & Guardrails│
                                  └────────────┬────────────┘
                                               │
                                               ▼
                              ┌─────────────────────────────────┐
                              │     Groq LPU Reasoning Agent    │
                              │      (openai/gpt-oss-120b)      │
                              └────────────────┬────────────────┘
                                               │
                                               ▼
                       ┌───────────────────────────────────────────────┐
                       │    Unified Multi-Agent Diagnostic Report      │
                       └───────────────────────────────────────────────┘
```

---

## 🤖 Specialized Agent Roles

NetCoop AI deploys six cooperative autonomous agents with distinct diagnostic responsibilities:

### 1. Telemetry & Performance Agent (`telemetry_agent`)
- **Domain:** End-to-end transport performance and wireless physical layer health.
- **Metrics Evaluated:** `latency_ms`, `jitter_ms`, `packet_loss_pct`, `throughput_mbps`, `bandwidth_mbps`, `link_utilization_pct`, `signal_dbm`, `retransmission_pct`.
- **Triggers:** Flags packet loss exceeding 1%, RTT latency spikes past 100ms, and Wi-Fi RSSI degrading below -70 dBm.

### 2. Infrastructure Health Agent (`infrastructure_agent`)
- **Domain:** Node hardware telemetry, system resources, and physical interface metrics.
- **Metrics Evaluated:** `cpu_pct`, `memory_pct`, `queue_drops`, `interface_errors`, optical power levels.
- **Triggers:** Detects CPU/RAM saturation (>80%), egress buffer queue drops (>50 drops/interval), and interface flapping.

### 3. Connectivity Analysis Agent (`connectivity_agent`)
- **Domain:** Campus topology traversal, link adjacencies, upstream/downstream blast radius, and network infrastructure services.
- **Metrics Evaluated:** Graph connectivity, upstream parent dependencies, `dns_latency_ms`, `dns_failure_pct`, `dhcp_latency_ms`, `dhcp_failure_pct`.
- **Triggers:** Differentiates between localized node failures and cascaded upstream link outages.

### 4. Fault Correlation Agent (`fault_correlation_agent`)
- **Domain:** Multi-agent evidence synthesis, resolution of competing hypotheses, and root-cause localization.
- **Techniques:** Dispatches `challenge` messages to agents to verify whether anomalies are sustained or transient; computes coverage-penalized Bayesian cause ranking.

### 5. Recommendation & Reporting Agent (`recommendation_agent`)
- **Domain:** Report generation, safety gating, and operational mitigation planning.
- **Responsibilities:** Enforces the insufficient-evidence boundary, formats diagnostic summaries, and prescribes immediate actions.

### 6. Groq LPU Reasoning Agent (`groq_llm_agent`)
- **Domain:** High-speed LLM inference utilizing `openai/gpt-oss-120b` hosted on Groq Tensor Streaming Units.
- **Responsibilities:** Interprets consensus telemetry to generate contextual network engineering explanations and vendor-specific CLI configuration commands.

---

## 📡 JSON-RPC v1.0.0 Interoperability Protocol

All agents exchange structured messages conforming to the **NetCoop Agent Message Schema (`netcoop.agent-message/1.0`)**:

### Standard Message Envelope

```json
{
  "jsonrpc": "2.0",
  "id": "M-0004",
  "run_id": "R-1730424560000-1",
  "seq": 4,
  "timestamp": "2026-11-01T04:22:15.341Z",
  "from": "telemetry_agent",
  "to": "fault_correlation_agent",
  "type": "finding",
  "in_reply_to": "M-0001",
  "summary": "telemetry_agent flagged 3 indicators on ap-academic-01",
  "payload": {
    "device_id": "ap-academic-01",
    "items": [
      {
        "metric": "signal_dbm",
        "value": -82.4,
        "unit": "dBm",
        "level": "critical",
        "degree": 1.0,
        "interpretation": "Severe wireless signal degradation detected"
      }
    ]
  }
}
```

### Supported Message Types

| Type | Purpose | Sender $\rightarrow$ Receiver |
| :--- | :--- | :--- |
| `task` | Dispatches diagnostic work packages and provides reference finding IDs. | `orchestrator` $\rightarrow$ Agents |
| `finding` | Reports anomalous metrics, sustained trends, and device states. | Agents $\rightarrow$ `fault_correlation_agent` |
| `challenge` | Inquires whether a specific metric anomaly was persistent or an isolated spike. | `fault_correlation_agent` $\rightarrow$ Agents |
| `challenge_response` | Returns time-windowed median, peak, baseline, and degree of persistence. | Agents $\rightarrow$ `fault_correlation_agent` |
| `result` | Delivers finalized multi-agent diagnosis report or Groq LLM synthesis. | Agents $\rightarrow$ `orchestrator` |
| `error` | Signals unparseable inputs, schema violations, or normalization failures. | Agents / Schema $\rightarrow$ `orchestrator` |

---

## 📊 Normalized Metrics & Threshold Matrix

| Metric Key | Canonical Unit | Expected Range | Warning Threshold | Critical Threshold | Responsible Agent |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `latency_ms` | ms | 0 – 60,000 | 100 ms | 250 ms | `telemetry_agent` |
| `jitter_ms` | ms | 0 – 60,000 | 30 ms | 80 ms | `telemetry_agent` |
| `packet_loss_pct` | % | 0 – 100 | 1.0 % | 5.0 % | `telemetry_agent` |
| `throughput_mbps` | Mbps | 0 – 10,000,000 | — | — | `telemetry_agent` |
| `bandwidth_mbps` | Mbps | 0 – 10,000,000 | — | — | `telemetry_agent` |
| `link_utilization_pct` | % | 0 – 100 | 80.0 % | 92.0 % | `telemetry_agent` |
| `signal_dbm` | dBm | -120 – 0 | -70 dBm | -80 dBm | `telemetry_agent` |
| `retransmission_pct` | % | 0 – 100 | 10.0 % | 25.0 % | `telemetry_agent` |
| `cpu_pct` | % | 0 – 100 | 80.0 % | 92.0 % | `infrastructure_agent` |
| `memory_pct` | % | 0 – 100 | 85.0 % | 95.0 % | `infrastructure_agent` |
| `queue_drops` | drops/int | 0 – $10^{12}$ | 50 drops | 150 drops | `infrastructure_agent` |
| `interface_errors` | err/int | 0 – $10^{12}$ | 10 errors | 100 errors | `infrastructure_agent` |
| `dns_latency_ms` | ms | 0 – 120,000 | 200 ms | 800 ms | `connectivity_agent` |
| `dns_failure_pct` | % | 0 – 100 | 5.0 % | 20.0 % | `connectivity_agent` |
| `dhcp_latency_ms` | ms | 0 – 120,000 | 500 ms | 2,000 ms | `connectivity_agent` |
| `dhcp_failure_pct` | % | 0 – 100 | 5.0 % | 20.0 % | `connectivity_agent` |

---

## 🧮 Mathematical Formulation & Scoring

### 1. Bayesian Degree of Anomaly
For any observed metric value $x$, its normalized degree of anomaly $\delta \in [0, 1]$ is computed as:

$$\delta(x) = \begin{cases} 
0 & x < W \\
0.5 \cdot \frac{x - W}{C - W} & W \le x < C \\
0.5 + 0.5 \cdot \min\left(1, \frac{x - C}{C}\right) & x \ge C 
\end{cases}$$

*(where $W$ is the Warning threshold, and $C$ is the Critical threshold).*

### 2. Evidence Coverage Penalty & Confidence Gating
A candidate root cause $H$ with raw support score $S_{raw}(H) \in [0, 1]$ is evaluated against required diagnostic metrics $\mathcal{M}_{req}(H)$. If only a subset $\mathcal{M}_{obs} \subset \mathcal{M}_{req}$ is present in the input telemetry:

$$\text{Coverage}(H) = \frac{|\mathcal{M}_{obs} \cap \mathcal{M}_{req}(H)|}{|\mathcal{M}_{req}(H)|}$$

$$\text{Confidence}(H) = S_{raw}(H) \times \left(0.5 + 0.5 \times \text{Coverage}(H)\right)$$

### 3. Insufficient Evidence Safety Guardrail
If the maximum candidate score fails to meet the threshold:

$$\max_H \text{Confidence}(H) < 0.40 \quad \lor \quad \text{Coverage}(H) < 0.50$$

The system **refuses** to attribute an exact root cause. It transitions to `status: "insufficient_evidence"` and lists the unmonitored metrics required before an assessment can be made.

---

## ⚡ Groq LPU AI Synthesis Engine

NetCoop AI pairs deterministic multi-agent correlation with the **Groq LPU (Language Processing Unit)** running **`openai/gpt-oss-120b`**:

- **Sub-Second Latency:** Delivers full contextual reasoning in ~1.2 seconds.
- **Strict JSON Enforcement:** Operates under `response_format: { type: "json_object" }` to prevent prompt drift or unparseable text.
- **Actionable CLI Generation:** Synthesizes copy-pasteable terminal commands for network administrators:

```bash
# Generated Cisco Catalyst Remediation
configure terminal
interface GigabitEthernet1/0/24
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
 spanning-tree portfast trunk
 speed auto 1000
 duplex full
end
write memory
```

- **Offline Resilience:** If network access or the Groq API key is unavailable, NetCoop AI falls back automatically to its rule-based heuristic recommendations.

---

## 🏛️ IIT Bhubaneswar Campus Topology

The application simulates an 8-node tier-3 campus network architecture:

```
                      [ core-router-01 ] (Cisco ASR 9000 - Datacenter)
                              │
                      [ dist-switch-01 ] (Cisco Catalyst 9500 - Academic)
                              ├── [ srv-dns-01 ]  (BIND 9 Linux Resolver)
                              ├── [ srv-dhcp-01 ] (ISC Kea Scope Pool)
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
       [ ap-academic-01 ]            [ sw-hostel-01 ]
      (Aruba AP-555 Wi-Fi)        (Juniper EX4300 Switch)
         │           │                       │
     [laptop-01] [laptop-02]            [desktop-lab-01]
```

---

## 🧪 Built-In Test Scenarios

NetCoop AI includes 8 reproducible test scenarios available via the UI and API:

| Scenario Key | Root Cause Injected | Affected Nodes | Expected Outcome |
| :--- | :--- | :--- | :---: |
| `normal` | Clean telemetry within operational bounds. | None | `no_fault_detected` (90%) |
| `link_congestion` | Saturated uplink utilization (95%) on `dist-sw-01`. | `dist-sw-01`, downstream APs | `diagnosed` (87%) |
| `weak_wifi` | RSSI degradation (-82 dBm) and high retries on AP. | `laptop-02`, `ap-academic-01` | `diagnosed` (86%) |
| `interface_fault` | CRC error spikes and flapping on access switch. | `sw-hostel-01` | `diagnosed` (65%) |
| `dns_failure` | Resolution timeouts (>950ms) on `srv-dns-01`. | Campus-wide clients | `diagnosed` (95%) |
| `dhcp_failure` | Lease offer timeouts and scope pool starvation. | `srv-dhcp-01`, `laptop-01` | `diagnosed` (60%) |
| `interop_failure` | Incompatible schema version (`netcoop.telemetry/2.0`). | Global | `error` (Gated) |
| `device_overload` | CPU (98%) and RAM (96%) saturation on `core-router-01`. | Core infrastructure | `diagnosed` (95%) |

---

## 💻 Web Application UI/UX

The web application is built with vanilla ES modules, CSS variables, and zero heavy frontend frameworks:

1. **Diagnosis Studio Tab:**
   - 5-KPI live health ribbon.
   - Interactive Telemetry Input editor with syntax preservation.
   - 8-scenario quick-loader (*loads telemetry into editor for inspection prior to execution*).
   - High-fidelity verdict banner featuring progress bar, confidence rating, and affected asset count.
   - Evidence tables, cause rankings, data quality audits, and collapsible raw JSON reports.
2. **Agent Message Bus Tab:**
   - Live stream of all JSON-RPC v1.0.0 agent communications.
   - Inspect modal allowing deep inspection of message payloads and timing.
3. **Interoperability Protocol Tab:**
   - Interactive documentation of schemas, agent lifecycles, and metric thresholds.
4. **Campus Topology Tab:**
   - Visual cards detailing hardware models, locations, subnets, and active roles.
5. **Theme Engine:**
   - Seamless switching between dark and light themes with `localStorage` persistence.

---

## 🔌 REST API Specification

### 1. `POST /api/netcoop/diagnose`
Run a cooperative multi-agent diagnosis on provided telemetry.

```bash
curl -X POST http://localhost:4000/api/netcoop/diagnose \
  -H "Content-Type: application/json" \
  -d '{
    "telemetry": {
      "schema": "netcoop.telemetry/1.0",
      "devices": [{"device_id": "core-sw-01"}],
      "samples": [{"device_id": "core-sw-01", "cpu_pct": 98.5, "timestamp": "2026-11-01T04:00:00Z"}]
    }
  }'
```

### 2. `GET /api/netcoop/scenarios`
Retrieve all built-in test scenarios.

### 3. `POST /api/netcoop/scenarios/:key`
Generate complete simulated telemetry for a given scenario key.

### 4. `GET /api/netcoop/protocol`
Fetch the active JSON-RPC protocol specification, scoring weights, and role definitions.

---

## 🚀 Quickstart Guide

### Prerequisites
- [Node.js](https://nodejs.org/) v18.0.0 or higher
- (Optional) [Groq API Key](https://console.groq.com/) for LPU acceleration

### 1. Clone & Install
```bash
git clone https://github.com/Sunil56224972/Netcoop.git
cd Netcoop
npm install
```

### 2. Configure Environment
Create a `.env` file from the provided example:
```bash
cp .env.example .env
```
Edit `.env` to include your Groq API key:
```env
NETCOOP_PORT=4000
NETCOOP_GROQ_KEY=gsk_your_groq_api_key_here
NETCOOP_GROQ_MODEL=openai/gpt-oss-120b
```

### 3. Launch Application

**Web Dashboard (Interactive UI):**
```bash
npm start
```
Open your browser at: **`http://localhost:4000`**

**CLI Mode (Problem Statement Deliverable #5):**
```bash
# Run diagnosis on scenario
npm run cli -- --scenario link_congestion

# Print pure Section 6 JSON report
npm run cli -- --scenario weak_wifi --json

# List available scenarios
npm run cli -- --list
```

**Model Context Protocol (MCP) Server (Problem Statement §4 Optional Enhancement):**
```bash
# Launch standard JSON-RPC 2.0 MCP server over stdio
npm run mcp
```

For auto-reloading during development:
```bash
npm run dev
```

---

## 🧪 Automated Verification Suite

NetCoop AI includes a comprehensive standalone test suite verifying protocol compliance, normalization, and all 8 scenarios:

```bash
npm test
```

### Verification Output:
```text
======================================================
   NetCoop AI — Automated Test Suite
======================================================

[1/5] Verifying Protocol Schema & Metadata...
  ✓ Protocol v1.0.0 and 16 metric definitions verified

[2/5] Testing Telemetry Input Normalization...
  ✓ JSON telemetry parsed correctly
  ✓ CSV telemetry parsed correctly

[3/5] Testing Scenario Registry...
  ✓ Loaded 8 built-in test scenarios

[4/5] Running Multi-Agent Diagnosis on all 8 Scenarios...
  • normal               -> no_fault_detected  [90%] | No fault detected: all reported metrics are normal
  • link_congestion      -> diagnosed          [87%] | Likely link congestion on dist-sw-01
  • weak_wifi            -> diagnosed          [86%] | Likely weak Wi-Fi signal at ap-academic-01
  • interface_fault      -> diagnosed          [65%] | Likely physical or interface fault on sw-hostel-01
  • dns_failure          -> diagnosed          [95%] | Likely DNS resolution failure or slowness
  • dhcp_failure         -> diagnosed          [60%] | Possible DHCP failure or slowness seen at srv-dhcp-01
  • interop_failure      -> error              [0%]  | Incompatible schema version "2.0"
  • device_overload      -> diagnosed          [95%] | Likely resource overload on core-router-01

[5/5] Testing Guardrails (Must not claim exact root cause with insufficient evidence)...
  ✓ System correctly reports no false alarms when telemetry is clean/sparse

======================================================
   ALL NETCOOP TESTS PASSED SUCCESSFULLY (100%)
======================================================
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — free for academic, hackathon, and production use.

**Developed with ❤️ for the Agentic AI Hackathon (Round 2) — IIT Bhubaneswar Campus.**
