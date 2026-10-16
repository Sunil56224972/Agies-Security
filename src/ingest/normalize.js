'use strict';

const crypto = require('crypto');
const { isIP } = require('../engine/analysis');

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
// Suricata/Snort priority: 1 is the most urgent.
const PRIORITY = { 1: 'CRITICAL', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW' };
const LOG_TYPES = ['http_access', 'auth_log', 'edr_process', 'system'];

const clip = (v, n) => (v == null ? null : String(v).slice(0, n));
const stableId = (prefix, ...parts) => `${prefix}-${crypto.createHash('sha1').update(parts.join('|')).digest('hex').slice(0, 12).toUpperCase()}`;

function toIso(v) {
  if (!v) return new Date().toISOString();
  // Suricata writes "2026-10-16T09:12:44.123456+0000"; Date wants "+00:00".
  const d = new Date(String(v).replace(/([+-]\d\d)(\d\d)$/, '$1:$2'));
  if (Number.isNaN(d.getTime())) return new Date().toISOString();
  // Clock-skewed sensors: never accept timestamps more than 5 minutes in the future.
  return d.getTime() > Date.now() + 300000 ? new Date().toISOString() : d.toISOString();
}

function decodePayload(e) {
  if (e.payload_printable) return String(e.payload_printable);
  if (e.payload) {
    try { return Buffer.from(String(e.payload), 'base64').toString('latin1').replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '.'); } catch { /* fall through */ }
  }
  // No payload logging: rebuild what we can from the HTTP/TLS/DNS metadata.
  if (e.http) {
    const h = e.http;
    return [`${h.http_method || 'GET'} ${h.url || '/'} ${h.protocol || 'HTTP/1.1'}`, h.hostname && `Host: ${h.hostname}`, h.http_user_agent && `User-Agent: ${h.http_user_agent}`]
      .filter(Boolean).join('\r\n');
  }
  if (e.tls) return `TLS ClientHello SNI=${e.tls.sni || '-'}${e.tls.ja3 && e.tls.ja3.hash ? ` JA3=${e.tls.ja3.hash}` : ''}`;
  if (e.dns && e.dns.rrname) return `DNS ${e.dns.type || 'query'} ${e.dns.rrname}`;
  return '';
}

// Suricata EVE JSON (event_type "alert").
function fromEve(e) {
  const a = e.alert || {};
  const proto = [e.proto, e.app_proto].filter(Boolean).map((s) => String(s).toUpperCase()).join('/');
  return {
    alert_id: stableId('EVE', e.flow_id || '', a.signature_id || '', e.timestamp || '', e.src_ip, e.dest_ip),
    signature: a.signature, category: a.category || 'Uncategorised', severity: PRIORITY[a.severity] || 'MEDIUM',
    source_ip: e.src_ip, dest_ip: e.dest_ip, dest_port: e.dest_port, protocol: proto || 'TCP',
    sensor: e.host || e.sensor_name || e.in_iface || 'suricata', raw_payload: decodePayload(e), detected_at: toIso(e.timestamp),
    external_ref: a.signature_id ? `sid:${a.signature_id}${a.rev ? `:${a.rev}` : ''}` : null
  };
}

// Aegis' own shape, also what most SIEM forwarders can be mapped to.
function fromGeneric(e) {
  let sev = String(e.severity || '').toUpperCase();
  if (!SEVERITIES.includes(sev)) sev = PRIORITY[Number(e.severity)] || 'MEDIUM';
  return {
    alert_id: e.alert_id ? clip(e.alert_id, 64) : stableId('EXT', e.sensor || '', e.signature || '', e.source_ip, e.dest_ip, e.dest_port, e.detected_at || e.timestamp || Date.now()),
    signature: e.signature || e.rule_name || e.title, category: e.category || 'Uncategorised', severity: sev,
    source_ip: e.source_ip || e.src_ip, dest_ip: e.dest_ip || e.dst_ip, dest_port: e.dest_port ?? e.dst_port,
    protocol: e.protocol || 'TCP', sensor: e.sensor || 'api', raw_payload: e.raw_payload || e.payload || '',
    detected_at: toIso(e.detected_at || e.timestamp), external_ref: e.external_ref || null
  };
}

function validateAlert(a) {
  if (!a.signature || String(a.signature).trim().length < 4) return 'signature is required';
  if (!isIP(a.source_ip)) return `source_ip "${a.source_ip}" is not an IP address`;
  if (!isIP(a.dest_ip)) return `dest_ip "${a.dest_ip}" is not an IP address`;
  const port = Number(a.dest_port ?? 0);
  if (!Number.isInteger(port) || port < 0 || port > 65535) return 'dest_port must be 0-65535';
  return null;
}

function normalizeAlert(input) {
  if (!input || typeof input !== 'object') return { error: 'Not a JSON object' };
  if (input.event_type && input.event_type !== 'alert') return { skip: `event_type ${input.event_type} ignored` };
  const a = input.event_type === 'alert' || input.alert ? fromEve(input) : fromGeneric(input);
  const err = validateAlert(a);
  if (err) return { error: err };
  return {
    alert: {
      ...a,
      signature: clip(String(a.signature).trim(), 240), category: clip(a.category, 80), protocol: clip(a.protocol, 20),
      sensor: clip(a.sensor, 80), dest_port: Number(a.dest_port || 0), raw_payload: clip(a.raw_payload || '(no payload captured)', 8000),
      status: 'NEW', updated_at: a.detected_at
    }
  };
}

// ---- Host telemetry -------------------------------------------------------
const COMBINED = /^(\S+) \S+ \S+ (?:\[[^\]]+\] )?"(\S+) (\S+)[^"]*" (\d{3})/;

function normalizeLog(input, defaults = {}) {
  const e = typeof input === 'string' ? { raw_entry: input } : { ...input };
  const host = e.host_ip || defaults.host_ip;
  const raw = e.raw_entry || e.message || e.line;
  if (!isIP(host)) return { error: 'host_ip is required and must be an IP address' };
  if (!raw || !String(raw).trim()) return { error: 'raw_entry is required' };
  let type = e.log_type || defaults.log_type;
  const m = String(raw).match(COMBINED);
  if (!type) type = m ? 'http_access' : /sshd|pam_unix|sudo:/.test(raw) ? 'auth_log' : 'system';
  if (!LOG_TYPES.includes(type)) return { error: `log_type must be one of ${LOG_TYPES.join(', ')}` };
  let client = e.client_ip;
  if (!client && m && isIP(m[1])) client = m[1];
  if (!client) {
    const f = String(raw).match(/from ([0-9a-f.:]+)/i) || String(raw).match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    if (f && isIP(f[1])) client = f[1];
  }
  const status = e.status_code != null ? Number(e.status_code) : m ? Number(m[4]) : null;
  return {
    log: {
      host_ip: host, log_type: type, raw_entry: clip(String(raw), 4000),
      client_ip: isIP(client) ? client : null,
      status_code: Number.isInteger(status) ? status : null,
      request_method: clip(e.request_method || (m ? m[2] : null), 12),
      request_uri: clip(e.request_uri || (m ? m[3] : null), 1000),
      logged_at: toIso(e.logged_at || e.timestamp)
    }
  };
}

// Accepts an array, a single object, or newline-delimited JSON (what Suricata writes to eve.json).
function parseBatch(req) {
  const b = req.body;
  if (Array.isArray(b)) return b;
  if (typeof b === 'string') {
    return b.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return l; } });
  }
  if (b && Array.isArray(b.events)) return b.events;
  if (b && Array.isArray(b.logs)) return b.logs;
  return b && typeof b === 'object' && Object.keys(b).length ? [b] : [];
}

// ---- Asset inventory ------------------------------------------------------
const CRIT = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function listOf(v) {
  if (Array.isArray(v)) return v;
  if (v == null || v === '') return [];
  return String(v).split(/[;\n|]+/).map((x) => x.trim()).filter(Boolean);
}

// Services as [{port, service}], "443/nginx 1.22.1; 22/OpenSSH 9.6p1", or ["443 nginx"].
function parseServices(v) {
  return listOf(v).map((s) => {
    if (s && typeof s === 'object') return { port: Number(s.port), service: String(s.service || s.name || '').trim() };
    const m = String(s).match(/^(\d{1,5})\s*[/:\s]\s*(.+)$/);
    return m ? { port: Number(m[1]), service: m[2].trim() } : { port: 0, service: String(s).trim() };
  }).filter((s) => s.service && Number.isInteger(s.port) && s.port >= 0 && s.port <= 65535).slice(0, 64);
}

function normalizeAsset(input) {
  const e = input || {};
  const ip = String(e.ip_address || e.ip || '').trim();
  if (!isIP(ip)) return { error: `ip_address "${ip}" is not an IP address` };
  const hostname = String(e.hostname || e.host || '').trim();
  if (!hostname) return { error: `hostname is required for ${ip}` };
  const crit = String(e.criticality || 'MEDIUM').toUpperCase();
  if (!CRIT.includes(crit)) return { error: `criticality must be one of ${CRIT.join(', ')}` };
  const packages = listOf(e.installed_packages || e.packages).map((x) => String(x).trim().slice(0, 160)).filter(Boolean).slice(0, 400);
  return {
    asset: {
      ip_address: ip, hostname: hostname.slice(0, 120),
      os_family: String(e.os_family || 'Unknown').slice(0, 40), os_version: String(e.os_version || e.os || 'Unknown').slice(0, 80),
      owner: e.owner ? String(e.owner).slice(0, 80) : null, criticality: crit,
      waf_enabled: /^(1|true|yes|on)$/i.test(String(e.waf_enabled ?? e.waf ?? '')),
      running_services: parseServices(e.running_services || e.services), installed_packages: packages,
      source: e.source ? String(e.source).slice(0, 40) : 'manual',
      last_scanned: e.last_scanned ? toIso(e.last_scanned) : new Date().toISOString()
    }
  };
}

// Minimal RFC 4180 CSV reader (quoted fields, escaped quotes, CRLF).
function parseCsv(text) {
  const rows = []; let row = []; let field = ''; let q = false;
  const src = String(text || '').replace(/^\uFEFF/, '');
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (q) {
      if (c === '"' && src[i + 1] === '"') { field += '"'; i++; } else if (c === '"') q = false; else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && src[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.some((x) => x.trim())) rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.some((x) => x.trim())) rows.push(row);
  if (!rows.length) return [];
  const head = rows[0].map((h) => h.trim().toLowerCase());
  return rows.slice(1).map((r) => Object.fromEntries(head.map((h, i) => [h, (r[i] || '').trim()])));
}

module.exports = { normalizeAlert, normalizeLog, normalizeAsset, parseCsv, parseBatch, LOG_TYPES, toIso };