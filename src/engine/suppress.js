'use strict';

const net = require('net');

// Suppression (tuning) rules. A rule matches when every condition it sets
// matches: signature is a case-insensitive substring, source and destination
// are an address or CIDR block, port is exact. Disabled or expired rules never match.

function parseCidr(value) {
  const s = String(value || '').trim();
  if (!s) return { ok: true, value: null };
  const [addr, bits, extra] = s.split('/');
  const family = net.isIP(addr);
  if (!family || extra !== undefined) return { ok: false, error: `${s} is not an IP address or CIDR block` };
  const max = family === 4 ? 32 : 128;
  const prefix = bits === undefined ? max : Number(bits);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max || (bits !== undefined && !/^\d+$/.test(bits))) return { ok: false, error: `${s} has an invalid prefix length` };
  return { ok: true, value: prefix === max ? addr.toLowerCase() : `${addr.toLowerCase()}/${prefix}`, family, addr, prefix };
}

function inCidr(ip, cidr) {
  if (!cidr) return true;
  const p = parseCidr(cidr);
  const fam = net.isIP(String(ip || ''));
  if (!p.ok || !fam || fam !== p.family) return false;
  const list = new net.BlockList();
  list.addSubnet(p.addr, p.prefix, p.family === 4 ? 'ipv4' : 'ipv6');
  return list.check(String(ip), fam === 4 ? 'ipv4' : 'ipv6');
}

function isLive(rule, at = new Date().toISOString()) {
  return rule.enabled && (!rule.expires_at || rule.expires_at > at);
}

function matches(rule, alert) {
  if (rule.signature && !String(alert.signature || '').toLowerCase().includes(rule.signature.toLowerCase())) return false;
  if (rule.dest_port != null && Number(alert.dest_port) !== Number(rule.dest_port)) return false;
  if (!inCidr(alert.source_ip, rule.source_cidr)) return false;
  if (!inCidr(alert.dest_ip, rule.dest_cidr)) return false;
  return true;
}

// First live rule that matches, or null.
function findSuppression(rules, alert, at) {
  return rules.find((r) => isLive(r, at) && matches(r, alert)) || null;
}

// Validates and normalises a create/update body. Returns { rule } or { error }.
function normalizeSuppression(b, { partial = false } = {}) {
  const out = {};
  if (!partial || b.name !== undefined) {
    const name = String(b.name || '').trim();
    if (name.length < 3) return { error: 'Name the rule so the next analyst knows why it exists (3+ characters)' };
    out.name = name.slice(0, 120);
  }
  if (!partial || b.signature !== undefined) {
    const sig = String(b.signature || '').trim();
    if (sig && sig.length < 4) return { error: 'Signature text must be at least 4 characters, or leave it empty' };
    out.signature = sig ? sig.slice(0, 240) : null;
  }
  for (const k of ['source_cidr', 'dest_cidr']) {
    if (partial && b[k] === undefined) continue;
    const p = parseCidr(b[k]);
    if (!p.ok) return { error: p.error };
    if (p.value && p.prefix < (p.family === 4 ? 8 : 32)) return { error: `${p.value} is too broad; use /${p.family === 4 ? 8 : 32} or narrower` };
    out[k] = p.value;
  }
  if (!partial || b.dest_port !== undefined) {
    if (b.dest_port === '' || b.dest_port == null) out.dest_port = null;
    else {
      const port = Number(b.dest_port);
      if (!Number.isInteger(port) || port < 0 || port > 65535) return { error: 'Port must be 0-65535' };
      out.dest_port = port;
    }
  }
  if (b.enabled !== undefined) out.enabled = Boolean(b.enabled);
  if (b.expires_in_days !== undefined) {
    if (b.expires_in_days === '' || b.expires_in_days == null || Number(b.expires_in_days) === 0) out.expires_at = null;
    else {
      const d = Number(b.expires_in_days);
      if (!Number.isInteger(d) || d < 1 || d > 365) return { error: 'Expiry must be 1-365 days, or empty for none' };
      out.expires_at = new Date(Date.now() + d * 86400000).toISOString();
    }
  }
  if (!partial && !out.signature && !out.source_cidr && !out.dest_cidr && out.dest_port == null) {
    return { error: 'Set at least one condition: signature, source, destination or port' };
  }
  return { rule: out };
}

module.exports = { parseCidr, inCidr, matches, isLive, findSuppression, normalizeSuppression };