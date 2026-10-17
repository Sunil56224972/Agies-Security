'use strict';

const crypto = require('crypto');
const { SEVERITY_RANK } = require('./engine/analysis');

// Outbound notifications. Channels live in app_config (key "platform", field
// notifyChannels) so admins manage them from the console without a redeploy.
//
//   slack    Slack incoming webhook (hooks.slack.com/services/...)
//   teams    Microsoft Teams incoming webhook or Workflows "post to channel" URL
//   webhook  Any HTTPS endpoint. JSON body, HMAC-SHA256 signed when a secret is set:
//            X-Aegis-Signature: sha256=hex(HMAC(secret, "<X-Aegis-Timestamp>.<body>"))
//
// Delivery is awaited inside the request that caused it (serverless platforms
// freeze the process after the response), with a short timeout per channel.

const KINDS = ['slack', 'teams', 'webhook'];
const EVENTS = ['alert', 'containment', 'verdict', 'approval'];
const MAX_CHANNELS = 10;
const TIMEOUT_MS = 6000;

const publicChannel = (c) => ({
  id: c.id, name: c.name, kind: c.kind, enabled: c.enabled !== false, min_severity: c.min_severity, events: c.events,
  url_hint: maskUrl(c.url), signed: Boolean(c.secret), last: c.last || null, created_by: c.created_by || null, created_at: c.created_at || null
});

function maskUrl(u) {
  try {
    const url = new URL(u);
    const tail = url.pathname.length > 8 ? `...${url.pathname.slice(-4)}` : url.pathname;
    return `${url.protocol}//${url.host}${tail}`;
  } catch { return 'invalid URL'; }
}

function validateChannel(b, { production }) {
  const name = String(b.name || '').trim();
  if (name.length < 2) return { error: 'Give the channel a name, e.g. #soc-alerts' };
  if (!KINDS.includes(b.kind)) return { error: `Type must be one of ${KINDS.join(', ')}` };
  let url;
  try { url = new URL(String(b.url || '').trim()); } catch { return { error: 'Enter the full webhook URL' }; }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local && !production)) return { error: 'Webhook URL must use https' };
  if (b.kind === 'slack' && url.hostname !== 'hooks.slack.com') return { error: 'Slack webhook URLs start with https://hooks.slack.com/' };
  const min = String(b.min_severity || 'HIGH').toUpperCase();
  if (!SEVERITY_RANK[min]) return { error: 'Unknown minimum severity' };
  const events = [...new Set((Array.isArray(b.events) ? b.events : EVENTS).filter((e) => EVENTS.includes(e)))];
  if (!events.length) return { error: 'Pick at least one event' };
  const secret = b.kind === 'webhook' && b.secret ? String(b.secret).trim() : '';
  if (secret && secret.length < 16) return { error: 'Signing secret must be at least 16 characters' };
  return { channel: { name: name.slice(0, 60), kind: b.kind, url: url.toString(), secret: secret || null, min_severity: min, events, enabled: true } };
}

// ---- Message formatting -----------------------------------------------------
function lines(evt) {
  const d = evt.data;
  const link = evt.console_url;
  if (evt.type === 'alert') {
    const head = d.alerts.length === 1 ? `${d.alerts[0].severity} alert: ${d.alerts[0].signature}` : `${d.alerts.length} new alerts at or above ${evt.min_severity}`;
    const rows = d.alerts.slice(0, 8).map((a) => `${a.severity}  ${a.alert_id}  ${a.source_ip} -> ${a.dest_ip}:${a.dest_port}  ${a.signature}`);
    if (d.alerts.length > 8) rows.push(`...and ${d.alerts.length - 8} more`);
    return { title: head, rows, link: link && (d.alerts.length === 1 ? `${link}#/investigate/${d.alerts[0].alert_id}` : `${link}#/alerts`) };
  }
  if (evt.type === 'containment') {
    const r = d.rule;
    return {
      title: `${r.action} ${r.target_ip} (${r.rule_id})`,
      rows: [`Reason: ${r.reason}`, `By: ${r.enacted_by}`, `Enforcement: ${(r.enforcement && r.enforcement.status) || 'RECORDED'}${r.expires_at ? `, expires ${r.expires_at}` : ''}`],
      link: link && `${link}#/containment`
    };
  }
  if (evt.type === 'verdict') {
    const i = d.investigation;
    return {
      title: `${i.outcome.replace(/_/g, ' ')} on ${i.alert_id} (${i.confidence}% confidence)`,
      rows: [`Attacker ${i.attacker_ip} -> target ${i.target_ip}`, `MITRE: ${i.mitre_tactic || 'n/a'} / ${i.mitre_technique || 'n/a'}`, ...(i.actions_taken || []).map((a) => `${a.type} ${a.target} (${a.rule_id}, ${String(a.enforcement || a.status || '').toLowerCase()})`)],
      link: link && `${link}#/investigate/${i.alert_id}`
    };
  }
  if (evt.type === 'approval') {
    const a = d.approval;
    return {
      title: `Approval needed: ${a.action} ${a.target_ip} (${a.approval_id})`,
      rows: [`Reason: ${a.reason}`, `Route: ${a.route.replace(/_/g, ' ')}${a.confidence != null ? `, confidence ${a.confidence}%` : ''}`, `Requested by ${a.requested_by}`],
      link: link && `${link}#/approvals`
    };
  }
  return { title: d.message || 'Test message from Aegis', rows: d.rows || [], link };
}

function payloadFor(kind, evt) {
  const m = lines(evt);
  if (kind === 'slack') {
    const text = [`*${m.title}*`, ...m.rows.map((r) => `\`${r.replace(/`/g, "'")}\``), m.link ? `<${m.link}|Open in Aegis>` : ''].filter(Boolean).join('\n');
    return { text };
  }
  if (kind === 'teams') {
    return {
      type: 'message',
      attachments: [{
        contentType: 'application/vnd.microsoft.card.adaptive',
        content: {
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', type: 'AdaptiveCard', version: '1.4',
          body: [
            { type: 'TextBlock', text: m.title, weight: 'Bolder', wrap: true },
            ...m.rows.map((r) => ({ type: 'TextBlock', text: r, wrap: true, fontType: 'Monospace', spacing: 'None' }))
          ],
          actions: m.link ? [{ type: 'Action.OpenUrl', title: 'Open in Aegis', url: m.link }] : []
        }
      }]
    };
  }
  return { event: evt.type, sent_at: new Date().toISOString(), title: m.title, data: evt.data, url: m.link || null };
}

// Highest severity carried by an event, for the per-channel floor.
function eventSeverity(evt) {
  if (evt.type === 'alert') return Math.max(...evt.data.alerts.map((a) => SEVERITY_RANK[a.severity] || 0));
  if (evt.type === 'containment' || evt.type === 'verdict' || evt.type === 'approval') return SEVERITY_RANK[evt.data.severity] || SEVERITY_RANK.HIGH;
  return SEVERITY_RANK.CRITICAL;
}

class Notifier {
  constructor(store, { fetchImpl = globalThis.fetch, consoleUrl = null } = {}) {
    this.store = store;
    this.fetch = fetchImpl;
    this.consoleUrl = consoleUrl;
  }

  async channels() {
    const cfg = await this.store.config.get();
    return Array.isArray(cfg.notifyChannels) ? cfg.notifyChannels : [];
  }

  async saveChannels(list) { await this.store.config.set({ notifyChannels: list }); }

  async deliver(channel, evt) {
    const body = JSON.stringify(payloadFor(channel.kind, evt));
    const headers = { 'Content-Type': 'application/json', 'User-Agent': 'Aegis-Notifier/1' };
    if (channel.kind === 'webhook') {
      const ts = String(Math.floor(Date.now() / 1000));
      headers['X-Aegis-Event'] = evt.type;
      headers['X-Aegis-Timestamp'] = ts;
      if (channel.secret) headers['X-Aegis-Signature'] = `sha256=${crypto.createHmac('sha256', channel.secret).update(`${ts}.${body}`).digest('hex')}`;
    }
    const started = Date.now();
    try {
      const res = await this.fetch(channel.url, { method: 'POST', headers, body, signal: AbortSignal.timeout(TIMEOUT_MS) });
      const ok = res.status >= 200 && res.status < 300;
      let detail = `HTTP ${res.status}`;
      if (!ok) { try { detail += `: ${(await res.text()).slice(0, 120)}`; } catch { /* ignore */ } }
      return { ok, status: res.status, detail, ms: Date.now() - started };
    } catch (err) {
      return { ok: false, status: null, detail: err.name === 'TimeoutError' ? `No response in ${TIMEOUT_MS / 1000}s` : err.message, ms: Date.now() - started };
    }
  }

  // Sends an event to every enabled channel subscribed to it whose severity
  // floor it meets. Records the outcome on the channel and in the audit log.
  async emit(type, data, { origin } = {}) {
    let list;
    try { list = await this.channels(); } catch { return []; }
    const evt = { type, data, console_url: origin || this.consoleUrl };
    const targets = list.filter((c) => c.enabled !== false && (c.events || []).includes(type) && eventSeverity(evt) >= (SEVERITY_RANK[c.min_severity] || 3));
    if (!targets.length) return [];
    const results = await Promise.all(targets.map(async (c) => ({ c, r: await this.deliver(c, { ...evt, min_severity: c.min_severity }) })));
    await this.record(results, type);
    return results.map(({ c, r }) => ({ channel: c.name, ...r }));
  }

  async test(id, { origin, actor } = {}) {
    const list = await this.channels();
    const c = list.find((x) => x.id === id);
    if (!c) return null;
    const r = await this.deliver(c, { type: 'test', console_url: origin, data: { message: `Test message from Aegis (${c.name})`, rows: [`Sent by ${actor || 'an administrator'} at ${new Date().toISOString()}`, `Events: ${c.events.join(', ')}; minimum severity ${c.min_severity}`] } });
    await this.record([{ c, r }], 'test');
    return r;
  }

  async record(results, type) {
    const at = new Date().toISOString();
    try {
      const list = await this.channels();
      for (const { c, r } of results) {
        const row = list.find((x) => x.id === c.id);
        if (row) row.last = { at, ok: r.ok, detail: r.detail, event: type };
      }
      await this.saveChannels(list);
    } catch { /* bookkeeping only */ }
    for (const { c, r } of results) {
      await this.store.audit.add({ actor: 'notifier', action: r.ok ? 'notify.sent' : 'notify.failed', target: `${c.kind}:${c.name}`, detail: `${type}: ${r.detail}` }).catch(() => {});
    }
  }
}

module.exports = { Notifier, validateChannel, publicChannel, payloadFor, KINDS, EVENTS, MAX_CHANNELS };