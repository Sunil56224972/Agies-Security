'use strict';

const crypto = require('crypto');
const net = require('net');

// Enforcement adapters. Each one pushes a containment rule somewhere real (or
// says plainly that it did not) and can read the state back for verification.
//
//   record      store the rule only; nothing outside Aegis changes
//   feed        publish the rule on /api/feeds/*.txt for the firewall to pull
//               (PAN-OS External Dynamic List, FortiGate threat feed, pfSense/OPNsense URL table)
//   webhook     POST the rule as JSON to ENFORCEMENT_WEBHOOK_URL, HMAC-SHA256 signed
//   cloudflare  Cloudflare IP Access Rules on CF_ZONE_ID (BLOCK only)
//
// Statuses: ENFORCED (backend confirmed), PENDING (published, not yet picked up),
// RECORDED (no backend), FAILED (backend refused or unreachable), REMOVED.

const now = () => new Date().toISOString();

class RecordAdapter {
  constructor() { this.mode = 'record'; this.label = 'Record only'; }
  describe() { return { mode: this.mode, label: this.label, detail: 'Rules are stored in Aegis. Nothing is pushed to a firewall.' }; }
  async apply() { return { mode: this.mode, status: 'RECORDED', detail: 'Stored in Aegis only (ENFORCEMENT_MODE=record).', at: now() }; }
  async remove(rule) { return { ...(rule.enforcement || {}), mode: this.mode, status: 'REMOVED', detail: 'Rule disabled.', at: now() }; }
  async verify(rule) { return rule.enforcement || { mode: this.mode, status: 'RECORDED', detail: 'Stored in Aegis only.' }; }
}

class FeedAdapter {
  constructor() { this.mode = 'feed'; this.label = 'Pull feed'; }
  describe() { return { mode: this.mode, label: this.label, detail: 'Firewalls pull /api/feeds/blocklist.txt and /api/feeds/isolate.txt with an API key.' }; }
  async apply() { return { mode: this.mode, status: 'PENDING', detail: 'Published to the feed. Waiting for the firewall to pull it.', at: now() }; }
  async remove(rule) { return { ...(rule.enforcement || {}), mode: this.mode, status: 'REMOVED', detail: 'Dropped from the feed on the next pull.', at: now() }; }
  async verify(rule) { return rule.enforcement || { mode: this.mode, status: 'PENDING', detail: 'Not pulled yet.' }; }
}

class WebhookAdapter {
  constructor({ url, secret, fetchImpl = globalThis.fetch }) {
    this.mode = 'webhook'; this.label = 'Webhook';
    this.url = url; this.secret = secret || ''; this.fetch = fetchImpl;
  }
  describe() { return { mode: this.mode, label: this.label, detail: `POST to ${new URL(this.url).host}${this.secret ? ', signed' : ', unsigned'}` }; }

  async send(event, rule) {
    const body = JSON.stringify({
      event, sent_at: now(),
      rule: { rule_id: rule.rule_id, action: rule.action, target_ip: rule.target_ip, ip_version: net.isIP(rule.target_ip), reason: rule.reason, enacted_by: rule.enacted_by, investigation_id: rule.investigation_id || null }
    });
    const ts = Math.floor(Date.now() / 1000).toString();
    const headers = { 'Content-Type': 'application/json', 'User-Agent': 'aegis-enforcement/1', 'X-Aegis-Event': event, 'X-Aegis-Timestamp': ts };
    // Receivers should recompute HMAC(secret, "<timestamp>.<body>") and reject stale timestamps.
    if (this.secret) headers['X-Aegis-Signature'] = `sha256=${crypto.createHmac('sha256', this.secret).update(`${ts}.${body}`).digest('hex')}`;
    const started = Date.now();
    try {
      const res = await this.fetch(this.url, { method: 'POST', headers, body, signal: AbortSignal.timeout(10000) });
      let ack = null;
      try { ack = await res.json(); } catch { /* receiver may reply with no body */ }
      const ok = res.ok && !(ack && /fail|error|reject/i.test(String(ack.status || '')));
      return {
        mode: this.mode, status: ok ? (event === 'rule.removed' ? 'REMOVED' : 'ENFORCED') : 'FAILED',
        detail: ok ? `Receiver acknowledged with HTTP ${res.status} in ${Date.now() - started} ms${ack && ack.detail ? `: ${ack.detail}` : ''}` : `Receiver answered HTTP ${res.status}${ack && ack.detail ? `: ${ack.detail}` : ''}`,
        remote_id: ack && (ack.id || ack.remote_id) ? String(ack.id || ack.remote_id) : null, at: now()
      };
    } catch (err) {
      return { mode: this.mode, status: 'FAILED', detail: `Webhook unreachable: ${err.message}`, at: now() };
    }
  }
  apply(rule) { return this.send('rule.created', rule); }
  remove(rule) { return this.send('rule.removed', rule); }
  async verify(rule) {
    const e = rule.enforcement;
    // A failed delivery is retried on verification; a confirmed one is reported as is.
    if (!e || e.status === 'FAILED') return this.apply(rule);
    return e;
  }
}

class CloudflareAdapter {
  constructor({ token, zoneId, fetchImpl = globalThis.fetch }) {
    this.mode = 'cloudflare'; this.label = 'Cloudflare';
    this.token = token; this.zone = zoneId; this.fetch = fetchImpl;
    this.base = `https://api.cloudflare.com/client/v4/zones/${zoneId}/firewall/access_rules/rules`;
  }
  describe() { return { mode: this.mode, label: this.label, detail: `IP Access Rules on zone ${this.zone.slice(0, 6)}...` }; }

  async call(method, path = '', body) {
    const res = await this.fetch(`${this.base}${path}`, {
      method, headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(10000)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.success === false) {
      const msg = (data.errors || []).map((e) => e.message).join('; ') || `HTTP ${res.status}`;
      const err = new Error(msg); err.status = res.status; throw err;
    }
    return data.result;
  }

  async apply(rule) {
    if (rule.action !== 'BLOCK') {
      return { mode: this.mode, status: 'RECORDED', detail: 'Cloudflare can only block at the edge. Isolate this host on the internal network.', at: now() };
    }
    try {
      const r = await this.call('POST', '', {
        mode: 'block', configuration: { target: net.isIPv6(rule.target_ip) ? 'ip6' : 'ip', value: rule.target_ip },
        notes: `Aegis ${rule.rule_id}: ${String(rule.reason).slice(0, 400)}`
      });
      return { mode: this.mode, status: 'ENFORCED', remote_id: r.id, detail: `Access rule ${r.id} created`, at: now() };
    } catch (err) {
      return { mode: this.mode, status: 'FAILED', detail: `Cloudflare: ${err.message}`, at: now() };
    }
  }

  async remove(rule) {
    const id = rule.enforcement && rule.enforcement.remote_id;
    if (!id) return { ...(rule.enforcement || {}), mode: this.mode, status: 'REMOVED', detail: 'Nothing to remove at Cloudflare.', at: now() };
    try {
      await this.call('DELETE', `/${id}`);
      return { mode: this.mode, status: 'REMOVED', remote_id: id, detail: `Access rule ${id} deleted`, at: now() };
    } catch (err) {
      if (err.status === 404) return { mode: this.mode, status: 'REMOVED', remote_id: id, detail: 'Already gone at Cloudflare.', at: now() };
      return { ...rule.enforcement, status: 'FAILED', detail: `Delete failed: ${err.message}`, at: now() };
    }
  }

  async verify(rule) {
    const e = rule.enforcement || {};
    if (rule.action !== 'BLOCK') return e;
    if (!e.remote_id) return this.apply(rule);
    try {
      const r = await this.call('GET', `/${e.remote_id}`);
      const live = r && r.mode === 'block' && r.configuration && r.configuration.value === rule.target_ip;
      return { mode: this.mode, status: live ? 'ENFORCED' : 'FAILED', remote_id: e.remote_id,
        detail: live ? `Access rule ${e.remote_id} is live (mode=block)` : `Access rule ${e.remote_id} no longer blocks ${rule.target_ip}`, at: now() };
    } catch (err) {
      if (err.status === 404) return this.apply(rule);
      return { ...e, status: 'FAILED', detail: `Cloudflare read-back failed: ${err.message}`, at: now() };
    }
  }
}

function createEnforcer(env = process.env, { fetchImpl } = {}) {
  const mode = String(env.ENFORCEMENT_MODE || 'feed').toLowerCase();
  if (mode === 'webhook') {
    if (!env.ENFORCEMENT_WEBHOOK_URL) return { enforcer: new FeedAdapter(), warning: 'ENFORCEMENT_MODE=webhook but ENFORCEMENT_WEBHOOK_URL is empty. Using the pull feed.' };
    return { enforcer: new WebhookAdapter({ url: env.ENFORCEMENT_WEBHOOK_URL, secret: env.ENFORCEMENT_WEBHOOK_SECRET, fetchImpl }), warning: null };
  }
  if (mode === 'cloudflare') {
    if (!env.CF_API_TOKEN || !env.CF_ZONE_ID) return { enforcer: new FeedAdapter(), warning: 'ENFORCEMENT_MODE=cloudflare needs CF_API_TOKEN and CF_ZONE_ID. Using the pull feed.' };
    return { enforcer: new CloudflareAdapter({ token: env.CF_API_TOKEN, zoneId: env.CF_ZONE_ID, fetchImpl }), warning: null };
  }
  if (mode === 'record') return { enforcer: new RecordAdapter(), warning: null };
  return { enforcer: new FeedAdapter(), warning: mode === 'feed' ? null : `Unknown ENFORCEMENT_MODE "${mode}". Using the pull feed.` };
}

module.exports = { createEnforcer, RecordAdapter, FeedAdapter, WebhookAdapter, CloudflareAdapter };