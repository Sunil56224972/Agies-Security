<p align="center"><img src="public/img/aegis-logo.png" alt="Aegis Security" width="200"></p>

# Aegis Security

An incident response console for a small SOC. Aegis takes IDS alerts from your sensors and works out whether each attack actually landed. It checks the target against your asset inventory and against NVD CVE data, matched by CPE version range, and reads the host's own logs for the attacker's address. It then records a verdict and pushes a containment rule to your firewall, and reports whether the firewall actually picked the rule up.

Express on Node, with Supabase Postgres or a local file for storage. There is no build step.

![Overview](docs/screens/overview.png)

## How it works

```
 Suricata / Zeek / any IDS --POST /api/ingest/alerts-->  +--------+  --feed / webhook / Cloudflare-->  firewall
 nginx, auth, EDR logs     --POST /api/ingest/logs---->  | Aegis  |  <--GET /api/feeds/blocklist.txt-- (pull)
 Nmap XML, CMDB CSV, agent --/api/ingest/assets------>  +--------+  <--NVD CVE API 2.0 (CPE ranges, CISA KEV)
                                                              ^
                       Spamhaus DROP, FireHOL, Tor exits, GreyNoise, Shodan InternetDB, AbuseIPDB (IP reputation)
          abuse.ch (ThreatFox, URLhaus, MalwareBazaar, Feodo, SSLBL), MISP, RDAP, RIPEstat, passive DNS, VirusTotal
                       SigmaHQ community rules (matched against every log batch)
```

The quickest way to feed a Linux server in is the bundled agent, `public/agent/aegis-agent.js` (served at `/agent/aegis-agent.js`). It is a single file with no dependencies. It tails Suricata `eve.json` and your access, auth and syslog files, and pushes a host inventory every hour: OS, listening ports with versions, and installed packages from dpkg, rpm or apk.

Every investigation runs six phases, streamed live to the console:

| Phase | What happens |
| --- | --- |
| Triage | Load the alert and classify the payload (JNDI, traversal, SQLi, brute force, beaconing) |
| Enrich | Find the target in the inventory and test its installed versions against NVD CPE ranges. Score the source IP against live blocklists and reputation services, and look up every domain, URL or hash in the payload against abuse.ch, MISP and RDAP. A JNDI callback to a known C2 is called out by name |
| Correlate | Read the target's ingested HTTP, auth and EDR logs for the attacker's address |
| Decide | Weigh exposure against host evidence and record a verdict with confidence and a MITRE mapping |
| Contain | Create a BLOCK rule for the source, and an ISOLATE rule for the host when compromise is confirmed |
| Verify | Read the rule back from the enforcement backend: `ENFORCED`, `PENDING`, `FAILED` or `RECORDED` |

Aegis never marks an alert *contained* until the backend has confirmed the rule. A rule that is only published shows as `PENDING`, and one the firewall rejected shows as `FAILED`. Both appear under Containment > Needs attention.

The **rule-based playbook** needs no API key: the same evidence always gives the same verdict, which is what you want for an audit trail. The optional **LLM agent** drives the same tools through OpenAI-style tool calling, so it cannot do anything the playbook cannot. Bring your own model: an administrator connects OpenAI, Google Gemini, Anthropic, Groq, OpenRouter, Mistral, DeepSeek, Together, a self-hosted Ollama or any other OpenAI-compatible API with their own key under Settings > Language model. The connection is tested before it is saved, the key is encrypted with AES-256-GCM under a key derived from `SESSION_SECRET`, and it never leaves the server (not in `/api/config`, exports or backups). With no provider saved, `GROQ_API_KEY` is the server default. It falls back to the playbook if the model errors.

## Screens

| | |
| --- | --- |
| ![Alerts](docs/screens/alerts.png) | ![Investigation](docs/screens/investigation.png) |
| Alert queue with severity filters | Live investigation timeline, verdict and report |
| ![Containment](docs/screens/containment.png) | ![Assets](docs/screens/assets.png) |
| Rules with enforcement read-back | Inventory from Nmap, CMDB or the agent, matched to NVD CVEs |
| ![IP profile](docs/screens/ip-profile.png) | ![Reports](docs/screens/reports.png) |
| IP profile with live blocklist, GreyNoise and Shodan data | SLA, MTTA/MTTR and ATT&CK coverage |
| ![Detections](docs/screens/intel-detect.png) | ![Exploited CVEs](docs/screens/intel-kev.png) |
| Built-in detection rules and the rule tester | CISA KEV catalog matched against your hosts |
| ![Indicator lookup](docs/screens/intel-lookup.png) | ![Feeds and Sigma](docs/screens/intel-feeds.png) |
| One indicator against abuse.ch, MISP, OTX, RDAP, BGP and passive DNS | Feed status and the SigmaHQ rule browser |
| ![IOC check](docs/screens/intel-ioc.png) | ![Settings](docs/screens/settings.png) |
| Bulk IOC check: IPs, domains, URLs and hashes | Team, API keys, integrations, policy |
| ![Cases](docs/screens/cases.png) | ![Case detail](docs/screens/case-detail.png) |
| Case queue with ownership, checklist progress and time to close | One case: timeline, linked alerts, indicators, containment, checklist |
| ![Approvals](docs/screens/approvals.png) | ![Threat hunting](docs/screens/hunting.png) |
| Containment held for a human, routed by verdict confidence | Hunt across logs, alerts and investigations; every hit links to its record |
| ![ATT&CK rollup](docs/screens/attack-rollup.png) | ![MCP server](docs/screens/mcp.png) |
| Techniques seen in your own detections, per tactic | MCP endpoint and client config in Settings |
| ![Assistant](docs/screens/assistant.png) | ![Workflows](docs/screens/workflows.png) |
| Assistant answering from live tool calls, with clickable ids | Saved workflows built from templates or the step editor |
| ![Workflow run](docs/screens/workflow-run.png) | ![Custom detections](docs/screens/detection-editor.png) |
| One workflow run, step by step, with skipped conditions | Custom Sigma rule with live lint and a dry run |
| ![Documents](docs/screens/documents.png) | ![Decisions](docs/screens/decisions.png) |
| Uploaded file: hash, extracted indicators, intel check, attach to case | Verdict accuracy, calibration and the engine's common mistakes |
| ![Dark theme](docs/screens/overview-dark.png) | ![Sign in](docs/screens/sign-in.png) |
| Dark theme | Sign-in screen |

On a phone the sidebar folds into a menu and tables scroll inside their card:

<p align="center">
  <img src="docs/screens/mobile-overview.png" alt="Overview on a phone" width="240">
  <img src="docs/screens/mobile-investigation.png" alt="Investigation on a phone" width="240">
  <img src="docs/screens/mobile-assistant.png" alt="Assistant on a phone" width="240">
</p>

## Quick start

Requires Node 18 or newer.

```bash
npm install
cp .env.example .env      # optional: fill in what applies
npm start
```

Open http://localhost:3000. On first run the console asks you to create the administrator account. On a host other people can reach, set `AEGIS_SETUP_TOKEN` first: the setup screen then asks for it, so nobody else can claim the account before you do.

A fresh install is empty, with no alerts, hosts or CVEs. To try it with sample incidents, start with `AEGIS_DEMO=1`, ideally against a throwaway file:

```bash
AEGIS_DEMO=1 AEGIS_DATA_FILE=.data/demo.json npm start
```

## Connecting your environment

### 1. Inventory

Three ways in, and they merge by IP address:

- **Nmap.** Run `nmap -sV -O -oX scan.xml 10.0.0.0/24` and drop `scan.xml` on Assets > Import, or POST it to `/api/ingest/assets` with `Content-Type: application/xml`. Open ports, service versions, CPEs and the OS guess are recorded. Packages, owner and criticality already on the host are kept.
- **The agent.** `node aegis-agent.js` (see section 3) reports what the host itself knows, including packages a network scan cannot see.
- **CSV or JSON** from a CMDB, Lansweeper or a spreadsheet, through Assets > Import or `/api/ingest/assets`. Columns:

```
ip_address,hostname,os_version,owner,criticality,waf_enabled,services,installed_packages
10.20.0.5,web-01,Ubuntu 22.04,Payments,HIGH,true,"443/nginx 1.24.0; 22/OpenSSH 8.9p1",log4j-core-2.17.1.jar
```

Include versions. Exposure comes from comparing them against NVD CPE version ranges, so `log4j-core-2.14.1` is exposed to CVE-2021-44228 and `2.17.1` is not.

### 2. CVE records

Assets > CVE records > Add from NVD fetches a CVE by id: CVSS, CWE, CPE ranges, references and the CISA KEV flag. Sync from NVD refreshes every record. Without `NVD_API_KEY`, NVD allows 5 requests per 30 seconds, and Aegis paces itself to match.

### 3. Sensor alerts

Create an API key with the `ingest` scope under Settings > API keys. The key is shown once, with ready-to-paste commands.

On a Linux host with Node 18 or newer, the agent covers alerts, logs and inventory in one process:

```bash
curl -fsSLO https://aegis.example.com/agent/aegis-agent.js
sudo AEGIS_URL=https://aegis.example.com AEGIS_KEY=$AEGIS_KEY node aegis-agent.js \
  --eve /var/log/suricata/eve.json --access /var/log/nginx/access.log --auth /var/log/auth.log
```

It remembers file positions in `--state`, follows log rotation, batches up to 500 lines, retries with backoff and stops on a revoked key. `--dry-run` prints what it would send; `--help` lists every flag. The Settings dialog also gives you a systemd unit.

Without the agent: Aegis accepts Suricata EVE JSON as NDJSON, a JSON array, or `{"events": [...]}`, up to 5000 events per request. Non-alert EVE records are skipped, and events that were already sent are de-duplicated.

```bash
# Stream Suricata alerts as they happen
tail -F /var/log/suricata/eve.json | grep --line-buffered '"event_type":"alert"' | \
  while read -r line; do printf '%s\n' "$line" | curl -sS -X POST https://aegis.example.com/api/ingest/alerts \
    -H "Authorization: Bearer $AEGIS_KEY" -H "Content-Type: application/x-ndjson" --data-binary @-; done
```

For production, ship with Filebeat or Vector rather than a shell loop. Use an HTTP output to `/api/ingest/alerts` with the bearer header and `application/x-ndjson`. Other IDSs can send generic JSON with `signature`, `severity`, `source_ip`, `dest_ip`, `dest_port`, `payload` and `timestamp`. The response reports `{accepted, duplicates, skipped, rejected}` with a reason for each rejected line.

Enable Settings > Investigate ingested alerts to triage every HIGH or CRITICAL alert automatically.

### 4. Host logs

The Correlate phase can only find evidence you have shipped:

```bash
curl -sS -X POST "https://aegis.example.com/api/ingest/logs?host_ip=10.20.0.5&log_type=http_access" \
  -H "Authorization: Bearer $AEGIS_KEY" -H "Content-Type: text/plain" --data-binary @/var/log/nginx/access.log
```

The log types are `http_access`, `auth_log`, `edr_process` and `system`. Plain lines, NDJSON and JSON arrays are all accepted. When `log_type` is left out, Aegis infers it from the line's format.

### Built-in detections

You do not need Suricata to get alerts. Every batch sent to `/api/ingest/logs` is run through Aegis' own rules, together with the last 1000 lines already stored for each client address:

| Rule | Fires on | Severity |
| --- | --- | --- |
| `ssh-bruteforce` | 5 failed passwords or invalid users from one address within 10 minutes | HIGH |
| `ssh-success-after` | A successful login from an address that crossed the brute-force threshold | CRITICAL |
| `web-exploit` | Request lines with JNDI lookups, path traversal, command or SQL injection, XSS, or reads of `.env`/`.git` | HIGH or CRITICAL |
| `web-scanner` | 20 or more 403/404 answers to one client inside the window, or a known scanner user agent | MEDIUM |

On top of these four, the SigmaHQ community rule pack is matched against the same batch; see [Sigma rules](#sigma-rules).

Thresholds, the window and per-rule switches live under Settings > Response policy. Alerts get a stable `DET-` id per rule, client and 10-minute bucket, so a re-sent log does not raise twice. They go through the same suppression, auto-triage and notification path as sensor alerts.

Try it against a real server, or paste the same lines into Threat intel > Detections > Rule tester, which runs the rules without storing anything:

```bash
for i in 1 2 3 4 5 6; do echo "Oct 17 09:41:0$i web01 sshd[2211]: Failed password for root from 203.0.113.50 port 5111$i ssh2"; done | \
  curl -sS -X POST "https://aegis.example.com/api/ingest/logs?host_ip=10.20.0.5&log_type=auth_log" \
    -H "Authorization: Bearer $AEGIS_KEY" -H "Content-Type: text/plain" --data-binary @-
# -> {"accepted":6, ..., "detections":{"raised":1,"ids":["DET-..."]}}
```

### 5. Enforcement

Set `ENFORCEMENT_MODE` in `.env`:

| Mode | How rules reach the firewall | When a rule counts as ENFORCED |
| --- | --- | --- |
| `feed` (default) | Firewall pulls `/api/feeds/blocklist.txt` and `/api/feeds/isolate.txt` | After the firewall's next pull |
| `webhook` | `POST` to `ENFORCEMENT_WEBHOOK_URL` for each create or remove | When the receiver answers 2xx |
| `cloudflare` | IP Access Rule on `CF_ZONE_ID` (BLOCK only) | When the rule reads back as `mode=block` |
| `record` | Nowhere. Rules are stored for you to apply by hand | Never; shown as RECORDED |

**Pull feed.** Create a key with the `feed` scope. The feed is plain text, one address per line. Firewalls that only support basic auth can use any username, with the key as the password.

- PAN-OS: Objects > External Dynamic Lists, type IP List, source the blocklist URL, then reference the EDL in a deny policy.
- FortiGate: Security Fabric > External Connectors > Threat Feeds > IP Address, then use it in a deny policy.
- pfSense / OPNsense: Firewall > Aliases, type URL Table (IPs), then use the alias in a block rule.

**Webhook.** The body is `{"event": "rule.created" | "rule.removed", "sent_at", "rule": {rule_id, action, target_ip, ip_version, reason, enacted_by, investigation_id}}`. When `ENFORCEMENT_WEBHOOK_SECRET` is set, each request carries `X-Aegis-Timestamp` and `X-Aegis-Signature: sha256=<hex>`, an HMAC-SHA256 of `"<timestamp>.<raw body>"`. Verify it and reject old timestamps:

```js
const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(`${req.get('x-aegis-timestamp')}.${rawBody}`).digest('hex');
const fresh = Math.abs(Date.now() / 1000 - Number(req.get('x-aegis-timestamp'))) < 300;
if (!fresh || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(req.get('x-aegis-signature')))) return res.sendStatus(401);
```

Reply `{"status": "failed", "detail": "..."}` to mark the rule FAILED, or `{"id": "..."}` to record the remote id.

**Cloudflare.** Create an API token with *Zone > Firewall Services > Edit*, and set `CF_API_TOKEN` and `CF_ZONE_ID`. ISOLATE rules are recorded only, because the edge cannot quarantine an internal host.

## Case work and reporting

**Ownership and notes.** Every alert has an owner. Take it from the alert drawer, or assign it to someone on the team. Notes are kept with the alert, and assignments, status changes and verdicts are added to the same timeline automatically. *First response* is the time from detection until the alert first leaves `NEW`. A Postgres trigger stamps it, so it cannot be backdated. The alert queue can be filtered to *My queue* or *Unassigned*.

**Bulk triage.** Tick rows in the alert queue to assign, close, mark false positive or reopen up to 200 alerts at once. Alerts under investigation are skipped.

**Suppression rules.** *Suppress similar* in the alert drawer drafts a rule from that alert. A rule matches on signature text, source or destination CIDR, and port. Before you save, the dialog shows how many alerts from the last 30 days it would have matched, and warns you if any of them were CRITICAL. Matching alerts are still stored, but they arrive closed as false positives. They never page anyone, trigger auto-triage or start a block. Each rule counts its hits and can expire after a set number of days. Rules are managed under Containment > Suppression rules.

**Time-boxed blocks.** Manual rules can lift themselves after 1 hour to 30 days. *Automatic block expiry* in Settings applies the same limit to blocks the engine creates. Expired rules leave the firewall feeds on the next pull and are switched off by the retention job.

**Notifications.** Under Settings > Notifications you can add Slack incoming webhooks, Microsoft Teams workflows or generic HTTPS webhooks. Each channel picks a minimum severity and which events it gets: new alerts, containment rules or verdicts. Generic webhooks can be signed with `X-Aegis-Signature: sha256=HMAC(secret, "<X-Aegis-Timestamp>.<body>")`. Every delivery is written to the audit log, and the URL and secret never leave the server.

**IP profile.** Click any address to see every alert it appears in, as source or target, along with its peers, signatures, rules, investigations and host logs. AbuseIPDB reputation is included when it is configured. You can block, isolate or suppress the address from the same page.

**Reports.** For 7, 30 or 90 days, the Reports page shows:
- MTTA and MTTR medians and p90 per severity, measured against your first-response targets;
- a list of alerts still waiting past target;
- MITRE ATT&CK coverage from investigation verdicts;
- daily volume, with suppressed alerts shown separately;
- top external sources, verdict mix and workload per analyst.

Reports print cleanly to PDF. You can export alerts and the audit log as CSV, with cells that could run as spreadsheet formulas escaped. Each investigation downloads as a markdown incident report with its case notes and run log.

## Cases, approvals and hunting

**Cases.** When an incident spans more than one alert, open a case. Do it from the alert drawer or the bulk bar (*Add to case*), from *New case*, or from *From kill chain*. That last one takes an attacker address and pulls in every alert and investigation that involves it, and orders the tactics it reached. Each case has:
- an owner;
- a response checklist split by phase (triage, investigate, contain, eradicate, recover), seeded from the alert category and editable;
- a timeline of comments, evidence and dated entries;
- linked alerts;
- indicators, each extracted from free text and checked against the intel hub one at a time or all at once;
- related cases that share an alert or indicator.

Closing a case with open tasks needs an explicit force. Escalating a case records the reason and marks it for a lead. The case metrics come from the stored cases themselves: open, escalated, unassigned, mean and median time to close, and checklist completion.

**Approvals.** Settings > Response policy > *Approval policy* decides whether containment runs at once:

| Mode | Behaviour |
| --- | --- |
| Run everything at once | The original behaviour. Every proposed block or isolation executes straight away |
| By confidence | Verdicts at or above *Auto at* execute. The rest go to quick review, analyst review or escalation, depending on the bands |
| Always ask | Every action waits in the queue |

A held action shows up under Approvals with its evidence, the case or alert it came from, and an expiry countdown. Approving it creates the real rule, and the rule then goes through the same enforcement read-back as any other. Rejecting it needs a note. Requests that nobody decides on expire after the configured number of hours, instead of being approved late against stale evidence. The investigation timeline, the alert notes and the case all record the outcome.

**Hunting.** A hunt is a set of criteria run against what Aegis has stored:
- text or `/regex/flags`;
- an address or CIDR;
- an ATT&CK technique;
- a list of indicators (defanged is fine);
- log sources, a time window and a minimum severity.

Two optional sweeps go further: one runs every loaded SigmaHQ rule over the logs in the window, and the other checks the window's external addresses against the reputation feeds. A run returns findings, each linked to its record, plus facets by source, host, remote address and technique. Saved hunts remember their last result, so a re-run marks only what is new. Every run is kept with its criteria and can be replayed. The ATT&CK rollup counts techniques per tactic from your own alerts and investigations. When an alert carries no explicit technique id, the payload classifier supplies one (T1190 for JNDI, traversal and SQLi; T1110.003 for spraying; T1071.001 for beacons). *Hunt* on any technique opens the builder with it filled in.

## MCP server

Aegis is also an MCP server, so Claude, Cursor or any other MCP client can triage alerts and work cases through the same API the console uses.

1. Settings > API keys > *New key*, with the `mcp` scope (read only) or `mcp:write` (also response actions). The key dialog shows a ready-made client config.
2. Point the client at `https://<your-host>/mcp` (Streamable HTTP, JSON-RPC 2.0, stateless):

```json
{
  "mcpServers": {
    "aegis": {
      "type": "http",
      "url": "https://agiessecurity.vercel.app/mcp",
      "headers": { "Authorization": "Bearer aeg_..." }
    }
  }
}
```

For clients that only speak stdio, the repo ships a bridge that forwards to the same endpoint:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["-y", "github:Sunil56224972/Agies-Security"],
      "env": { "AEGIS_URL": "https://agiessecurity.vercel.app", "AEGIS_API_KEY": "aeg_..." }
    }
  }
}
```

With an `mcp` key you get 19 read tools: `overview`, `list_alerts`, `get_alert`, `get_investigation`, `search`, `ip_profile`, `lookup_indicator`, `bulk_check`, `detect_test`, `list_rules`, `list_cases`, `get_case`, `list_approvals`, `list_hunts`, `technique_rollup`, `extract_iocs_document`, `decision_accuracy`, `list_custom_rules` and `list_workflows`.

An `mcp:write` key adds 16 more: `investigate_alert`, `set_alert_status`, `block_ip`, `approve_action`, `reject_action`, `create_case`, `create_case_from_killchain`, `update_case`, `add_alert_to_case`, `add_case_ioc`, `add_case_task`, `update_case_task`, `add_case_comment`, `close_case`, `run_hunt` and `run_workflow`.

`block_ip` follows the approval policy like everything else, so under *Always ask* an agent can only propose. Every call is written to the audit log as `mcp:<key name>`, with the tool name, its outcome and how long it took. `MCP_RATE_LIMIT` caps calls per minute per address (default 300).

## Users and roles

| Role | Can |
| --- | --- |
| Administrator | Everything: users, API keys, policy, CVE sync |
| Analyst | Investigate, override verdicts, create and toggle rules, edit inventory |
| Read only | View everything, change nothing |

Passwords are hashed with scrypt. Sessions are HMAC-signed, HttpOnly, SameSite=Strict cookies that last 12 hours. Changing a password or role, or disabling a user, ends that user's other sessions at once. Cookie-authenticated writes must carry an `X-Aegis-Client` header, which blocks cross-site form posts. API keys are stored as SHA-256 hashes and scoped to `ingest`, `feed`, `mcp` or `mcp:write`. Login attempts are rate limited, and failed sign-ins are written to the audit log. Behind HTTPS, set `COOKIE_SECURE=1`. Behind a reverse proxy, also set `TRUST_PROXY`.

## Supabase backend

With the Supabase CLI:

```bash
npx supabase login
npx supabase projects create aegis-security --org-id <org> --region ap-south-1 --db-password <pw>
npx supabase link --project-ref <ref>
npx supabase db push                                   # applies every file in supabase/migrations
npx supabase projects api-keys --project-ref <ref> --reveal
```

Put the project URL (`https://<ref>.supabase.co`) in `SUPABASE_URL` and the `sb_secret_...` key (or the legacy `service_role` JWT) in `SUPABASE_SERVICE_ROLE_KEY`, then restart. The startup banner and Settings > Integrations show `Supabase Postgres` when it is in use. The SQL editor or the Supabase MCP `apply_migration` tool work too; apply the migrations in filename order.

Row level security is on for every table, with no policies, and the third migration revokes table privileges from `anon` and `authenticated` outright, so a leaked publishable key reads nothing. Only the server, holding the secret key, has access. If Supabase is configured but unreachable, the server refuses to start rather than quietly writing incidents to a local file. Set `AEGIS_ALLOW_FALLBACK=1` if you would rather it fall back.

To let a coding agent manage the project, add Supabase's hosted MCP server (`https://mcp.supabase.com/mcp`, OAuth sign-in) to the agent's MCP config.

## Deploying on Vercel

`server.js` exports the Express app, so Vercel runs it as one function with zero config; `npm start` still runs it as a normal server. Files in `public/` are served from Vercel's CDN with the headers in `vercel.json`.

Set these in Project Settings > Environment Variables, then redeploy:

| Variable | Value |
| --- | --- |
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | Required. Without them each instance keeps data in `/tmp` and loses it on cold start. |
| `SESSION_SECRET` | 32+ random characters. Required: instances do not share a generated one. |
| `AEGIS_SETUP_TOKEN` | Asked for on the first-run screen, so nobody else claims the admin account. |
| `COOKIE_SECURE=1`, `TRUST_PROXY=1`, `NODE_ENV=production` | Vercel serves HTTPS behind one proxy hop. |
| `CRON_SECRET` | Vercel Cron sends it to `/api/cron/retention` (daily, 03:00 UTC). |

Rate limits are kept per function instance, so they are looser on Vercel than on a single server. Investigations stream over one request; a long LLM run is bounded by the function's max duration.

## Threat intel

Source IPs are scored during every investigation and on the IP profile page, with no key required:

| Source | What it adds |
| --- | --- |
| Spamhaus DROP, FireHOL level 1, Tor exit list | Downloaded and cached for 6 hours, matched locally by CIDR |
| GreyNoise community | Known scanner or benign service (for example a search engine crawler) |
| Shodan InternetDB | Open ports, hostnames and CVEs Shodan has seen on the address |
| ipwho.is | Country, ASN and network owner |
| AbuseIPDB | Abuse confidence and report count, when `ABUSEIPDB_API_KEY` is set |

Each lookup returns a 0-100 score, a verdict and the sources that answered. A source that is down is reported as such and does not block the investigation. Set `AEGIS_INTEL=off` on an air-gapped install.

The Threat intel page adds four tools on top of that:

- **IOC check.** Paste up to 100 addresses in any shape (a list, CSV, firewall log lines, defanged `203.0.113[.]7`). Each one is scored against the sources above, cross-referenced with your alerts and block rules, and the result can be exported as CSV.
- **Exploited CVEs.** The CISA Known Exploited Vulnerabilities catalog is downloaded and cached for 12 hours. The page lists the latest additions and every CVE record of yours that is on the list, with the hosts exposed to it. Flag CVE records writes the KEV flag back to stored CVEs.
- **Find CVEs on a host.** In an asset's drawer, Find CVEs in NVD maps each versioned package to an NVD CPE and pulls the CVEs that match, keeping CVSS 7.0 or higher and anything on KEV. Without `NVD_API_KEY` it checks 4 packages per run (about 7 seconds each because of the NVD rate limit); with a key, 12. NVD matches on upstream versions, so a distribution package with backported fixes can show CVEs that are already patched.
- **Attack origins.** The external sources behind your alerts in the chosen window, geolocated, with their reputation and how many alerts are still open.

### Indicator lookup

Threat intel > Lookup takes any IP, domain, URL, MD5/SHA1/SHA256 or AS number (defanged forms such as `hxxp://evil[.]com` are fine) and queries every source that applies, in parallel:

| Source | Key | What it adds |
| --- | --- | --- |
| ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker, SSLBL (abuse.ch) | none | Bulk exports downloaded and indexed in memory (about 180,000 IOCs), refreshed hourly. C2 servers, malware URLs, sample hashes and their families |
| abuse.ch live API | `ABUSECH_AUTH_KEY` | Exact URLhaus, MalwareBazaar and ThreatFox records for anything outside the exports |
| MISP OSINT feed (botvrij.eu) | none | Hashed attribute index of every published event, with event title, date and galaxy tags |
| Your own MISP | `MISP_URL`, `MISP_KEY` | `attributes/restSearch` on your instance |
| RDAP (IANA bootstrap) | none | Registrar, registration date and age for domains; network owner and abuse contact for IPs. A domain under 30 days old is a signal on its own |
| RIPEstat | none | Announcing ASN, prefix, visibility and routing history; for an AS number, its holder and prefixes |
| Mnemonic passive DNS | none | Which names pointed at an IP, and which IPs a domain resolved to, with first and last seen |
| crt.sh | none | Certificates logged for a domain |
| VirusTotal | `VT_API_KEY` | Engine verdicts, rate limited to 4 a minute and 500 a day as the free key allows |
| AlienVault OTX | optional `OTX_API_KEY` | Community pulses that mention the indicator, malware families and named adversaries. Indicators on OTX's own allowlist (public resolvers, CDNs) score nothing |
| Hybrid Analysis | `HYBRID_ANALYSIS_API_KEY` | Falcon sandbox verdict, threat score and family for file hashes, per analysis environment |

The verdict is the strongest real signal, with a small bump when three independent sources agree. A source that times out is listed as failed and does not count either way. Lookups are written to the audit log. The same lookup runs inside investigations (the `lookup_indicator` tool), in Bulk check, and on every IP profile.

### Sigma rules

The [SigmaHQ](https://github.com/SigmaHQ/sigma) release archive is downloaded on start and every rule whose log source Aegis receives is compiled: web server, Linux process creation, auditd, syslog and services such as sshd, sudo and cron (around 250 of the 3,000+ rules; Windows rules are skipped because Aegis does not ingest Windows event logs). Rules run on every `/api/ingest/logs` batch and in the rule tester. Hits become alerts with a stable `SIG-` id, the rule's ATT&CK technique and a link to the rule source. The lowest level that raises an alert (`medium` by default) and per-rule switches are under Threat intel > Feeds & Sigma. Set `AEGIS_SIGMA=off` to skip the download.

## Workbench

Five tools under the Workbench section of the sidebar. They need the `20261019000000_assistant_workflows_documents.sql` migration on Supabase; until it is applied those routes answer 503 and the rest of the console is unaffected.

- **Assistant.** A chat over this deployment's own data. It uses tool calling on the connected language model with the same tools the MCP server exposes, so every number it quotes comes from a tool result in the conversation, and each call is shown as a chip under the answer. Read tools run straight away. Anything that changes state (investigate, contain, open a case, run a hunt) is held as a pending action until an analyst approves it. Viewers get read tools only. It needs a language model (Settings > Language model, or `GROQ_API_KEY`); without one the page says so instead of answering.
- **Workflows.** Chain steps into a playbook you can rerun: investigate, extract indicators, intel lookup, hunt, case from kill chain, open case, add indicators, contain, notify. Steps pass results forward with `{{steps.<id>.<field>}}`, can run only when a condition holds (`nonempty`, `eq`, `in`, `gte` and so on), and can be marked to continue on error. Three templates are included (alert to incident, IOC triage, attacker sweep). Runs stream step by step and are kept with their inputs and outputs. Containment still goes through the approval policy.
- **Detections.** Write your own Sigma rules in the browser. Each rule is linted as you type and compiled by the same engine as the SigmaHQ pack. You can test it against pasted log lines or backtest it over stored logs before saving. Enabled rules run on every ingested batch and count their hits.
- **Documents.** Upload a threat report, log export, e-mail source or IOC list (text formats up to 5 MB). Aegis extracts IPs, domains, URLs, hashes, CVEs and ATT&CK ids, including defanged forms. It flags internal addresses and stores the file with its SHA-256. Indicators can be checked against every intel source, attached to a case as IOCs plus a hashed evidence entry, or sent to Hunting.
- **Decisions.** How often the investigation engine is right. Analysts mark a verdict right or wrong, give the correct outcome and a 1-5 rating. Overrides count too. The page shows accuracy per engine, calibration per confidence band (is a 90% verdict right 90% of the time?) and the most common mistakes.

Integrations in the same release:

- **Jira.** With `JIRA_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN` and `JIRA_PROJECT` set, a case gets a *Create Jira issue* button. The issue key is stored on the case, logged on its timeline, and *Sync* pulls the current status and assignee back.
- **PagerDuty.** A notification channel type next to Slack, Teams and webhook. Paste the 32-character Events API v2 integration key; events are sent to `events.pagerduty.com/v2/enqueue` and nowhere else.
- **Backup and restore.** Settings > Backup (admins) downloads every table as one JSON file and restores it on this or another deployment. Users, API keys and notification channel secrets are never exported or overwritten.

## What Aegis does not do for you

- It does not capture traffic. Alerts come from your IDS, and evidence comes from the logs you ship. A host that sends no logs gets a lower-confidence verdict.
- It does not touch your firewall directly. It publishes rules through one of the four modes above, and the firewall has to be configured to consume them.
- CVE data comes from NVD. Records are only as current as your last sync, and CPE matching is only as good as the versions in your inventory.
- Retention purges closed alerts, their investigations and telemetry older than the configured window, every hour. Open alerts are never purged.

## API

Browser endpoints use the session cookie. Ingest and feed endpoints use `Authorization: Bearer <key>`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Storage, enforcement, intel and engine status |
| GET / POST | `/api/auth/state`, `/setup`, `/login`, `/logout`, `/password` | Sessions |
| GET / POST / PATCH | `/api/users`, `/api/users/:id` | Team management (admin) |
| GET / POST | `/api/keys`, `/api/keys/:id/revoke` | API keys (admin) |
| POST | `/api/ingest/alerts`, `/api/ingest/logs`, `/api/ingest/assets` | Sensor and inventory ingest (`ingest` key) |
| GET | `/api/feeds/blocklist.txt`, `/api/feeds/isolate.txt` | Firewall feeds (`feed` key) |
| GET / POST | `/api/alerts`, `/api/alerts/:id/status` | Alert queue |
| POST | `/api/investigations/stream` | Run an investigation (server-sent events) |
| POST | `/api/investigations/:id/override` | Override a verdict; containment follows |
| GET / POST | `/api/rules`, `/rules/:id/toggle`, `/rules/:id/verify`, `/api/verify` | Containment and read-back |
| GET / POST / PUT / DELETE | `/api/assets`, `/api/assets/:ip`, `/api/assets/import` | Inventory |
| GET / POST / DELETE | `/api/cves`, `/api/cves/:id`, `/api/cves/sync` | NVD-backed CVE records |
| GET | `/api/logs`, `/api/audit`, `/api/search`, `/api/overview` | Read models |
| GET / PUT | `/api/config` | Response policy, SLA targets, block expiry |
| POST / GET | `/api/alerts/:id/assign`, `/api/alerts/:id/notes`, `/api/alerts/bulk` | Ownership, case notes, bulk triage |
| GET / POST / PATCH / DELETE | `/api/suppressions`, `/api/suppressions/preview` | Suppression rules and dry-run preview |
| GET / POST / PATCH / DELETE | `/api/notify/channels`, `/channels/:id/test` | Slack, Teams and webhook channels (admin) |
| GET | `/api/ip/:ip`, `/api/reports/summary?days=30` | IP profile, SLA and ATT&CK report |
| GET / POST | `/api/detect/rules`, `/api/detect/test` | Built-in rules with hit counts; dry-run rule tester |
| GET / POST | `/api/intel/kev`, `/api/intel/kev/sync` | CISA KEV status, overlap with your CVEs, flag records |
| POST | `/api/intel/bulk` | Score up to 100 IOCs (IPs, domains, URLs, hashes) |
| GET | `/api/intel/lookup?q=` | One indicator across every intel source |
| GET / POST | `/api/intel/feeds`, `/api/intel/feeds/refresh` | Feed status; force a re-download (admin) |
| GET | `/api/sigma/rules?q=&level=&target=` | Compiled SigmaHQ rules with 30-day hit counts |
| GET | `/api/intel/origins?days=30` | Geolocated alert sources |
| GET / POST | `/api/assets/:ip/software`, `/api/assets/:ip/discover` | Packages mapped to CPEs; pull matching CVEs from NVD |
| GET | `/api/export/alerts.csv`, `/api/export/audit.csv`, `/api/investigations/:id/report.md` | Exports |
| GET / POST / PATCH | `/api/cases`, `/api/cases/:id`, `/cases/metrics`, `/cases/from-killchain` | Cases, metrics, kill-chain case builder |
| POST / PATCH / DELETE | `/api/cases/:id/{close,reopen,escalate,alerts,tasks,iocs,events}` | Case lifecycle, checklist, indicators, timeline |
| GET / POST | `/api/approvals`, `/approvals/count`, `/approvals/:id/approve`, `/approvals/:id/reject` | Approval queue and decisions |
| GET / POST / PATCH / DELETE | `/api/hunts`, `/hunts/adhoc`, `/hunts/:id/run`, `/hunts/runs`, `/hunts/runs/:id/replay` | Saved and ad-hoc hunts, run history |
| GET | `/api/hunts/techniques?days=30` | ATT&CK technique rollup |
| POST | `/mcp` (alias `/api/mcp`) | MCP JSON-RPC endpoint (`mcp` or `mcp:write` key) |
| GET / POST | `/api/assistant/threads`, `/threads/:id/messages/stream`, `/threads/:id/confirm/stream` | Assistant conversations (SSE) and approval of proposed actions |
| GET / POST / PUT / DELETE | `/api/workflows`, `/workflows/catalog`, `/workflows/:id/run/stream`, `/workflows/runs/:id` | Workflows, templates and run history |
| GET / POST / PUT / DELETE | `/api/detections/custom`, `/custom/lint`, `/custom/test` | Custom Sigma rules |
| GET / POST / DELETE | `/api/documents`, `/documents/analyze`, `/documents/:id/check`, `/documents/:id/attach` | Document library and IOC extraction |
| GET / POST | `/api/decisions`, `/decisions/:id/feedback` | Verdict accuracy and analyst feedback |
| GET / POST | `/api/cases/:id/jira` | Create or sync the case's Jira issue |
| GET / POST | `/api/admin/backup`, `/api/admin/restore` | Full backup and restore (admin) |

## Tests

```bash
npm test
```

There are three suites. Unit tests cover CPE version matching, EVE normalisation, Nmap XML parsing, blocklist parsing, abuse.ch and MISP feed parsers, indicator extraction, the Sigma compiler, the intel hub verdict, password hashing and webhook signatures. The smoke test runs every sample incident through the playbook against each enforcement adapter. The HTTP suite makes 186 end-to-end checks. They cover auth, roles and CSRF; ingest and de-duplication; feeds, CSV and Nmap import, agent inventory push; enforcement read-back; case ownership and notes; bulk triage; suppression; rule expiry; signed webhook delivery, checked by a local receiver; reports, exports and retention; cases, approvals under every policy mode, hunts and replay, the ATT&CK rollup, the MCP server with its key scopes, custom Sigma rules, document extraction, workflow runs with conditions, decision feedback, PagerDuty validation and backup/restore. External APIs (NVD, AbuseIPDB, Cloudflare) are stubbed or exercised offline.

To run the HTTP suite against the Supabase project in `.env` instead of a temp file, set `AEGIS_TEST_SUPABASE=1`. It empties every Aegis table before and after the run, so use a staging project, never one holding real incidents.

To regenerate the screenshots or the walkthrough video, start a demo server (`AEGIS_DEMO=1 AEGIS_DATA_FILE=.data/demo.json npm start`), then run `npm run screenshots` or `node demo_video/record_demo.js`. Both need `npx playwright install chromium`.

## Project layout

```
server.js               boot: store, enforcer, intel clients, banner
src/app.js              HTTP hardening, sessions, auth, users, API keys
src/routes.js           console API, ingest, feeds, retention
src/casework.js         ownership, notes, bulk triage, suppressions, reports, exports
src/cases.js            cases, approvals and hunts: service layer and routes
src/mcp.js              MCP server (JSON-RPC over HTTP), tool registry and scopes
src/workbench.js        assistant, workflows, documents, custom detections, decisions, Jira, backup
bin/aegis-mcp.js        stdio bridge for MCP clients without HTTP transport
src/notify.js           Slack / Teams / signed webhook delivery
src/engine/             analysis rules, tools, playbook and LLM investigator
src/enforce/            record / feed / webhook / Cloudflare adapters
src/ingest/             EVE, generic alert, log, CSV and Nmap XML normalisation
src/intel/              NVD CVE API 2.0 client, blocklists and IP reputation
public/agent/           zero-dependency sensor agent for Linux hosts
src/security/           scrypt, signed sessions, API keys, rate limits
src/store/              Supabase and local file backends
supabase/migrations/    Postgres schema
public/                 single-page console (ES modules, no build step)
test/                   unit, smoke and HTTP suites
```

## License

MIT. See `LICENSE`.