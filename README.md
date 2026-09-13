# 🛡️ Aegis Security — Autonomous SOC Investigation & Response Platform

[![Track](https://img.shields.io/badge/Hackathon-Track%205%3A%20Cybersecurity-059669?style=flat-square)](https://github.com/Sunil56224972/Agies-Security)
[![Problem Statement](https://img.shields.io/badge/Problem%20Statement-PS--9%20Autonomous%20SOC-2563EB?style=flat-square)](https://github.com/Sunil56224972/Agies-Security)
[![Node.js](https://img.shields.io/badge/Runtime-Node.js%2018%2B-339933?style=flat-square&logo=nodedotjs)](https://nodejs.org)
[![Database](https://img.shields.io/badge/Database-Neon%20Serverless%20PostgreSQL-00E599?style=flat-square)](https://neon.tech)
[![Inference](https://img.shields.io/badge/Inference-Groq%20LPU%20%7C%20LLaMA%203.3%2070B-F59E0B?style=flat-square)](https://groq.com)
[![License](https://img.shields.io/badge/License-MIT-7C3AED?style=flat-square)](LICENSE)
[![Standards](https://img.shields.io/badge/Standards-NIST%20SP%20800--61%20%7C%20MITRE%20ATT%26CK-DC2626?style=flat-square)](https://attack.mitre.org)

> **Enterprise-grade autonomous Security Operations Center (SOC) platform.**  
> Directly addresses **Track 5 (Cybersecurity) — Problem Statement 9**.  
> Features a multi-turn ReAct reasoning agent, 8 live environment tools, Neon PostgreSQL state persistence, dynamic replanning on changed conditions, and objective defense verification.

---

## 📋 Table of Contents

- [Demo Video](#-demo-video)
- [Screenshots](#-screenshots)
- [Source Code](#-source-code)
- [Dependencies](#-dependencies)
- [Environment Configuration](#-environment-configuration)
- [Setup Instructions](#-setup-instructions)
- [Architecture Documentation](#-architecture-documentation)
- [Common Agentic Requirements Compliance](#-common-agentic-requirements-compliance)
- [API Reference](#-api-reference)

---

## 🎬 Demo Video

**Workflow:** `Goal → Decision → Action → Intermediate Result → Adaptation → Final Outcome`

> The video demonstrates one complete investigation of a Log4Shell RCE attack **plus** a failure/unexpected condition — where the agent detects an incompatible runtime stack (Log4j exploit fired at a Python/FastAPI server) and dynamically replans its verdict to `FALSE_POSITIVE` instead of triggering an erroneous firewall block.

📹 **[`demo_video/aegis_demo_4min.mp4`](demo_video/aegis_demo_4min.mp4)** — H.264 MP4, ~10 MB

| Timestamp | Phase | Description |
|-----------|-------|-------------|
| `0:00` | **GOAL** | Live dashboard — real-time PostgreSQL metrics, MTTD, MTTR |
| `0:40` | **DECISION** | Alert feed — 4 NIDS threats; agent selects `ALERT-2026-9001` (Log4Shell CRITICAL) |
| `1:15` | **ACTION** | 8 SOC tools invoked autonomously (CMDB, CVE-KB, packet metadata, server logs) |
| `1:20` | **INTERMEDIATE RESULT** | HTTP 200 log + EDR confirms `java` spawned `/bin/sh` reverse shell |
| `3:00` | **FINAL OUTCOME** | Attacker IP blocked; Netfilter probe shows `RST_SENT_PACKETS_DROPPED` |
| `3:25` | ⚡ **FAILURE / UNEXPECTED** | `ALERT-2026-9003`: Log4j vs. Python FastAPI → incompatible stack → agent replans to `FALSE_POSITIVE` |
| `3:50` | **ADAPTATION** | Agentic Evaluator verifies all 7 compliance criteria with live data |

---

## 📸 Screenshots

### Executive Incident Dashboard
![Executive Incident Dashboard](screenshots/enterprise_dashboard_clean.png)

### Threat Alert Ingestion Feed
![Threat Alert Feed](screenshots/enterprise_alerts_clean.png)

### Autonomous Investigation Studio
![Investigation Studio](screenshots/enterprise_investigation_clean.png)

### Active Containment Rules & Defense Probe
![Active Containment Rules](screenshots/enterprise_containment_clean.png)

### Asset CMDB & CVE Knowledge Base
![Asset CMDB and CVE Intelligence](screenshots/enterprise_assets_clean.png)

### Agentic Compliance Evaluator (All 7 Criteria)
![Agentic Evaluation Matrix](screenshots/agentic_matrix_top_1789240873187.png)

### Global Search
![Global Search](screenshots/enterprise_search_clean.png)

---

## 💻 Source Code

### Repository Structure

```
Agies-Security/
├── server.js              # Main Express backend + AutonomousSocAgent kernel
├── init_db.sql            # PostgreSQL schema DDL + seed data
├── package.json           # npm manifest
├── .env.example           # Environment variable template
├── public/
│   ├── index.html         # Single-page application shell
│   └── script.js          # Frontend dashboard, agent chat, evaluator UI
├── screenshots/           # Application screenshots for README
├── demo_video/
│   ├── aegis_demo_4min.mp4    # Official 4-minute MP4 demo recording
│   └── record_demo.js         # Playwright recording automation script
├── docs/
│   └── walkthrough.md     # Detailed technical walkthrough
└── LICENSE
```

### Key Source Files

| File | Purpose |
|------|---------|
| [`server.js`](server.js) | Express REST server, `AutonomousSocAgent` ReAct loop, 8 tool executors, SSE streaming, Neon PostgreSQL integration |
| [`public/script.js`](public/script.js) | Frontend SPA — dashboard, alert feed, investigation studio, firewall view, agentic evaluator |
| [`public/index.html`](public/index.html) | HTML shell with dark-mode SOC UI layout |
| [`init_db.sql`](init_db.sql) | Full PostgreSQL DDL: 11 tables + seed alerts, assets, CVEs, and server logs |
| [`.env.example`](.env.example) | All required environment variables with descriptions |

---

## 📦 Dependencies

### Runtime Dependencies

```json
{
  "express": "^4.18.2",
  "groq-sdk": "^1.6.0",
  "@neondatabase/serverless": "^0.10.4",
  "pg": "^8.13.3",
  "dotenv": "^16.4.7",
  "cors": "^2.8.5",
  "ffmpeg-static": "^5.2.0"
}
```

| Package | Version | Purpose |
|---------|---------|---------|
| `express` | ^4.18.2 | HTTP server, REST routing, SSE middleware |
| `groq-sdk` | ^1.6.0 | LLaMA 3.3 70B inference via Groq LPU API |
| `@neondatabase/serverless` | ^0.10.4 | Neon PostgreSQL WebSocket driver (edge-compatible) |
| `pg` | ^8.13.3 | PostgreSQL connection pool + standard TCP driver |
| `dotenv` | ^16.4.7 | `.env` environment variable loader |
| `cors` | ^2.8.5 | Cross-Origin Resource Sharing headers |
| `ffmpeg-static` | ^5.2.0 | Bundled ffmpeg binary (demo video conversion) |

### Dev Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `playwright` | ^1.63.0 | Browser automation for demo video recording |

---

## ⚙️ Environment Configuration

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

### `.env` Variables

```ini
# ─────────────────────────────────────────────────────────
# GROQ LPU INFERENCE (required)
# Get your free key at: https://console.groq.com
# ─────────────────────────────────────────────────────────
GROQ_API_KEY=gsk_your_groq_api_key_here

# Groq model to use (recommended: llama-3.3-70b-versatile)
GROQ_MODEL=llama-3.3-70b-versatile

# ─────────────────────────────────────────────────────────
# NEON POSTGRESQL DATABASE (required)
# Create a free database at: https://neon.tech
# Copy the connection string from Neon Console → Connection Details
# ─────────────────────────────────────────────────────────
DATABASE_URL=postgresql://neondb_owner:your_password@ep-your-endpoint.aws.neon.tech/neondb?sslmode=require

# ─────────────────────────────────────────────────────────
# SERVER (optional, defaults shown)
# ─────────────────────────────────────────────────────────
PORT=3000
```

### How to get the credentials

| Variable | Where to get it |
|----------|----------------|
| `GROQ_API_KEY` | Sign up at [console.groq.com](https://console.groq.com) → API Keys → Create key |
| `DATABASE_URL` | Sign up at [neon.tech](https://neon.tech) → New Project → Connection Details → copy the **Pooler** connection string |

> **Security note:** Never commit your `.env` file. It is listed in `.gitignore` by default.

---

## 🚀 Setup Instructions

### Prerequisites

- **Node.js** v18 or higher ([download](https://nodejs.org))
- **npm** v9 or higher (bundled with Node.js)
- A free **Groq Cloud** API key — [console.groq.com](https://console.groq.com)
- A free **Neon PostgreSQL** database — [neon.tech](https://neon.tech)

---

### Step 1 — Clone the repository

```bash
git clone https://github.com/Sunil56224972/Agies-Security.git
cd Agies-Security
```

---

### Step 2 — Install dependencies

```bash
npm install
```

---

### Step 3 — Configure environment variables

```bash
cp .env.example .env
```

Open `.env` in any text editor and set:
- `GROQ_API_KEY` — your Groq Cloud API key
- `DATABASE_URL` — your Neon PostgreSQL connection string

---

### Step 4 — Bootstrap the database

**Option A — Automatic (recommended):**  
The server auto-creates all 11 tables and seeds baseline data on first boot. No manual steps needed.

**Option B — Manual:**  
Run [`init_db.sql`](init_db.sql) directly in the [Neon SQL Console](https://console.neon.tech):
```bash
# Copy the contents of init_db.sql and paste into Neon Console → SQL Editor → Run
```

---

### Step 5 — Start the platform

```bash
npm start
```

Expected output:
```
  ╔══════════════════════════════════════════════════════╗
  ║      AEGIS SECURITY — AUTONOMOUS SOC PLATFORM        ║
  ║      Track 5: Cybersecurity - Problem Statement 9    ║
  ╚══════════════════════════════════════════════════════╝

  Server running at http://localhost:3000
  Sandbox Tools loaded: 8
  Model: llama-3.3-70b-versatile via Groq LPU
  Database: connected (Neon PostgreSQL)
```

---

### Step 6 — Open in browser

```
http://localhost:3000
```

| Tab | What to do |
|-----|-----------|
| **Incident Dashboard** | View live metrics pulled from Neon PostgreSQL |
| **Threat Alerts** | See all 4 NIDS threats; click **Triage & Investigate** on ALERT-2026-9001 |
| **Investigation Studio** | Watch the agent reason through 8 tools in real time |
| **Containment Rules** | View active firewall rules; click **Run Defense Probe** |
| **Agentic Evaluator** | Click **Run Full Compliance Check** to verify all 7 requirements live |

---

### Step 7 — Verify the API health endpoint

```bash
curl http://localhost:3000/api/health
```

Expected response:
```json
{
  "status": "operational",
  "service": "Autonomous SOC Investigation & Response Platform",
  "model": "llama-3.3-70b-versatile",
  "database": "connected",
  "sandbox_tools": [
    "ingest_nids_alerts", "get_packet_metadata", "lookup_asset_inventory",
    "query_cve_kb", "query_server_logs", "execute_firewall_action",
    "verify_defense_state", "record_investigation_verdict"
  ]
}
```

---

## 🏗️ Architecture Documentation

### System Overview

```
                         AEGIS SECURITY PLATFORM
                        ─────────────────────────

    ┌─────────────────────────────────────────────────────────────────┐
    │                   NETWORK SENSOR INGESTION                       │
    │   Snort / Suricata NIDS Event Stream ──► Ingress Alert Queue     │
    └────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │           AUTONOMOUS SOC REASONING KERNEL (GROQ LPU)             │
    │   Model : LLaMA 3.3 70B via Groq Cloud High-Speed LPU            │
    │   Loop  : Multi-Turn ReAct (Reason ──► Tool Call ──► Observe)    │
    │   Max   : 16 reasoning turns per investigation                   │
    └──────────┬─────────────────┬───────────────────────┬────────────┘
               │                 │                       │
    [Observation Feedback]  [Tool Dispatch]        [State Commit]
               │                 │                       │
               ▼                 ▼                       ▼
 ┌──────────────────────┐ ┌─────────────────┐ ┌──────────────────────┐
 │  8 SOC SANDBOX TOOLS │ │ NETFILTER KERNEL│ │   NEON POSTGRESQL    │
 │                      │ │   SIMULATOR     │ │   (AWS ap-southeast) │
 │ ingest_nids_alerts   │ │                 │ │                      │
 │ get_packet_metadata  │ │ iptables DROP   │ │ soc_alerts           │
 │ lookup_asset_inv.    │ │ Connection RST  │ │ soc_assets           │
 │ query_cve_kb         │ │ Packet counter  │ │ soc_cve_kb           │
 │ query_server_logs    │ │ Probe endpoint  │ │ soc_firewall_rules   │
 │ execute_firewall_act │ └─────────────────┘ │ soc_investigations   │
 │ verify_defense_state │                     │ soc_server_logs      │
 │ record_investigation │                     │ execution_logs       │
 └──────────────────────┘                     │ tool_usage_stats     │
                                              │ app_config           │
                                              │ chat_sessions        │
                                              └──────────────────────┘
```

### Investigation Workflow

```
  ALERT RECEIVED
       │
       ▼
  [GOAL SET] ─────────────────────────────────────────────────────────────────┐
  "Investigate ALERT-2026-9001. Determine if attack succeeded. Contain."       │
       │                                                                        │
       ▼                                                                        │
  [DECISION] ── Which tools to call? In what order?                            │
       │                                                                        │
       ├──► ingest_nids_alerts()     → Alert signature, severity, IPs          │
       │                                                                        │
       ├──► get_packet_metadata()    → L7 payload: ${jndi:ldap://...}          │
       │                                                                        │
       ├──► lookup_asset_inventory() → Ubuntu 22.04, log4j-2.14.1 installed ✓ │
       │                                                                        │
       ├──► query_cve_kb()           → CVE-2021-44228, CVSS 10.0, RCE CRITICAL │
       │                                                                        │
       ├──► query_server_logs()      → HTTP 200 + EDR: java spawned /bin/sh    │
       │                                                                        │
  [INTERMEDIATE RESULT] ────────────────────────────────────────────────────── │
  Attack confirmed. Java process spawned reverse shell.                         │
       │                                                                        │
       ├──► execute_firewall_action() → BLOCK 185.220.101.45                   │
       │                                                                        │
       ├──► verify_defense_state()   → connection_state: RST_SENT              │
       │                                                                        │
       ├──► record_investigation()   → Verdict: VERIFIED_ATTACK, Confidence 96%│
       │                                                                        │
  [FINAL OUTCOME] ────────────────────────────────────────────────────────────┘
  MITRE: TA0001/T1190 (Initial Access / Exploit Public-Facing Application)
  Containment: ACTIVE. Attacker blocked. Investigation committed to PostgreSQL.
```

### Changed Condition / Failure Handling (Criterion 6)

```
  ALERT-2026-9003: Log4j exploit → 10.0.4.22
       │
       ├──► lookup_asset_inventory("10.0.4.22")
       │    └── Python 3.10 / FastAPI / Uvicorn — NO Java runtime, NO Log4j
       │
       ├──► query_server_logs("10.0.4.22")
       │    └── HTTP 401 Unauthorized — No outbound socket connections created
       │
  [CONDITION MISMATCH DETECTED]
  Exploit requires JVM + Log4j. Target has neither. Attack cannot execute.
       │
  [REPLAN] ─── Verdict: FALSE_POSITIVE / INCOMPATIBLE_STACK
               Action:  NO firewall block (avoids disrupting valid traffic)
               Record:  Zero erroneous drops enforced
```

### Database Schema (11 Tables)

| Table | Description |
|-------|-------------|
| `soc_alerts` | Ingested NIDS events — signature, severity, source/dest IPs, raw payload |
| `soc_assets` | CMDB inventory — OS, services, installed packages, WAF status |
| `soc_cve_kb` | CVE intelligence — CVSS score, affected products, remediation |
| `soc_server_logs` | Endpoint telemetry — HTTP access, auth logs, EDR process trees |
| `soc_firewall_rules` | Netfilter containment rules — active drop rules, packet counters |
| `soc_investigations` | Incident reports — MITRE mapping, confidence score, evidence summary |
| `execution_logs` | Full audit trace — every tool call with args, result, latency |
| `tool_usage_stats` | Tool performance — call counts, success/failure rates, avg latency |
| `app_config` | System policy — reasoning depth, confidence thresholds |
| `chat_sessions` | Agent conversation sessions |
| `chat_messages` | Agent conversation history with tool call transcripts |

### Technology Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Node.js + Express.js |
| **Agent Reasoning** | Groq LPU — LLaMA 3.3 70B Versatile |
| **Database** | Neon Serverless PostgreSQL (AWS ap-southeast-1) |
| **Frontend** | Vanilla HTML/CSS/JavaScript (zero framework dependencies) |
| **Streaming** | Server-Sent Events (SSE) for real-time agent token streaming |
| **Standards** | NIST SP 800-61, MITRE ATT&CK, MITRE D3FEND |

---

## ✅ Common Agentic Requirements Compliance

| # | Requirement | Implementation | Verification |
|---|-------------|----------------|-------------|
| **1** | Goal-driven multi-turn execution | Accepts operational goals; runs up to 16-turn ReAct loop autonomously | Live SSE stream at `/api/soc/investigate/stream` |
| **2** | Meaningful tool/environment interaction | 8 tools querying live Neon PostgreSQL — zero static mocks | SQL queries visible in `execution_logs` table |
| **3** | Persistent state across turns & sessions | All reasoning steps, tool calls, verdicts stored in PostgreSQL | Tables: `soc_investigations`, `execution_logs`, `chat_messages` |
| **4** | Action → Observation → Replanning | Agent re-evaluates hypothesis after each tool observation | Demonstrated in `AutonomousSocAgent.investigate()` |
| **5** | Objective outcome verification | `verify_defense_state` probes Netfilter sandbox, returns real packet drop counts | `/api/soc/firewall/probe` returns `RST_SENT_PACKETS_DROPPED` |
| **6** | Failure / changed-condition handling | Log4j vs. Python FastAPI → agent detects incompatibility → replans to `FALSE_POSITIVE` | 1-click demo in Agentic Evaluator tab |
| **7** | Open, modular architecture | Network Ingestion → Groq Kernel → 8 Tools → PostgreSQL → Netfilter Sandbox | Documented via `/api/health` and `/api/soc/config` |

---

## 📡 API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | `GET` | Platform health, DB status, tools, uptime |
| `/api/soc/stats` | `GET` | SOC telemetry metrics, MTTD/MTTR |
| `/api/soc/agentic-status` | `GET` | All 7 Common Agentic Requirements status |
| `/api/soc/alerts` | `GET`, `POST` | List alerts or ingest new test event |
| `/api/soc/alerts/:id` | `GET` | Fetch specific alert with decoded payload |
| `/api/soc/assets` | `GET` | CMDB asset inventory |
| `/api/soc/cve` | `GET` | CVE knowledge base (`?q=search`) |
| `/api/soc/logs` | `GET` | Server logs (`?host_ip=&log_type=&limit=`) |
| `/api/soc/firewall` | `GET` | Active containment rules |
| `/api/soc/firewall/rule` | `POST` | Deploy manual firewall rule |
| `/api/soc/firewall/toggle` | `POST` | Toggle rule `is_active` state |
| `/api/soc/firewall/probe` | `POST` | Run objective defense verification |
| `/api/soc/investigations` | `GET` | Historical investigation reports |
| `/api/soc/investigate/stream` | `POST` | **SSE stream** — live agent ReAct reasoning |
| `/api/soc/override` | `POST` | Submit analyst human override |
| `/api/soc/config` | `GET`, `POST` | System policy configuration |
| `/api/search` | `GET` | Global search across alerts, rules, assets |

---

## 📄 License

Distributed under the [MIT License](LICENSE).  
Built for hackathon demonstration — **Track 5: Cybersecurity (Problem Statement 9)**.  
All attack payloads and containment actions execute within an isolated sandboxed emulation environment.
