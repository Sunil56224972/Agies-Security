'use strict';

const { newId, isIP } = require('./analysis');

// Response actions proposed by the engine (or an MCP client) can be routed
// through a human before they touch the firewall. Routing follows the verdict
// confidence, in the same bands Vigil uses:
//   >= approvalAutoAt     executed straight away          (auto)
//   >= approvalQuickAt    one-click confirmation           (quick_review)
//   >= approvalReviewAt   analyst reviews the evidence     (analyst_review)
//   below                 senior analyst / lead            (escalate)
// approvalMode: 'auto' keeps the original behaviour (execute every proposed
// action), 'confidence' applies the bands, 'manual' queues everything.
const ROUTES = ['auto', 'quick_review', 'analyst_review', 'escalate'];
const ROUTE_TEXT = { auto: 'Auto-approved', quick_review: 'Quick review', analyst_review: 'Analyst review', escalate: 'Escalated' };

function routeFor(confidence, cfg = {}) {
  const mode = cfg.approvalMode || 'auto';
  const c = confidence == null ? null : Number(confidence);
  const band = c == null ? 'analyst_review'
    : c >= (cfg.approvalAutoAt ?? 90) ? 'auto'
    : c >= (cfg.approvalQuickAt ?? 85) ? 'quick_review'
    : c >= (cfg.approvalReviewAt ?? 70) ? 'analyst_review' : 'escalate';
  if (mode === 'auto') return { route: 'auto', execute: true };
  if (mode === 'manual') return { route: band === 'auto' ? 'quick_review' : band, execute: false };
  return { route: band, execute: band === 'auto' };
}

class Approvals {
  constructor(store, { tools, notifier = null }) {
    this.store = store;
    this.tools = tools;
    this.notifier = notifier;
  }

  async request({ action, target_ip, reason, alert_id = null, investigation_id = null, case_id = null, confidence = null, route, requested_by, ttl_hours = null }) {
    if (!['BLOCK', 'ISOLATE'].includes(action)) throw new Error('Action must be BLOCK or ISOLATE');
    if (!isIP(target_ip)) throw new Error('target_ip must be an IP address');
    if (!reason || String(reason).trim().length < 4) throw new Error('A reason is required');
    // One open request per action and address; a second proposal joins the first.
    const open = (await this.store.approvals.list({ status: 'PENDING', limit: 1000 })).find((a) => a.action === action && a.target_ip === target_ip);
    if (open) return { approval: open, duplicate: true };
    const active = (await this.store.rules.activeFor(target_ip)).find((r) => r.action === action);
    if (active) return { approval: null, already: active };
    const cfg = await this.store.config.get();
    const approval = await this.store.approvals.insert({
      approval_id: newId('APR'), action, target_ip, reason: String(reason).slice(0, 500), alert_id, investigation_id, case_id,
      confidence: confidence == null ? null : Math.max(0, Math.min(100, Math.round(confidence))),
      route: ROUTES.includes(route) ? route : routeFor(confidence, { ...cfg, approvalMode: 'confidence' }).route,
      requested_by: String(requested_by || 'system').slice(0, 80), ttl_hours: ttl_hours == null ? null : Number(ttl_hours)
    });
    await this.store.audit.add({ actor: approval.requested_by, action: 'approval.requested', target: target_ip, detail: `${approval.approval_id} ${action} (${ROUTE_TEXT[approval.route]}${approval.confidence != null ? `, ${approval.confidence}%` : ''})` });
    if (alert_id) await this.store.notes.add({ alert_id, kind: 'event', author: approval.requested_by, body: `${action} ${target_ip} proposed (${approval.approval_id}); waiting for approval: ${ROUTE_TEXT[approval.route].toLowerCase()}` }).catch(() => {});
    if (this.notifier) await this.notifier.emit('approval', { approval, severity: approval.route === 'escalate' ? 'CRITICAL' : 'HIGH' }).catch(() => {});
    return { approval };
  }

  // Lapsed requests are closed instead of approved late against stale evidence.
  async expire() {
    const cfg = await this.store.config.get();
    const hours = Number(cfg.approvalExpiryHours) || 24;
    const cutoff = new Date(Date.now() - hours * 3600000).toISOString();
    const stale = (await this.store.approvals.list({ status: 'PENDING', limit: 1000 })).filter((a) => a.created_at < cutoff);
    for (const a of stale) {
      await this.store.approvals.update(a.approval_id, { status: 'EXPIRED', decided_by: 'system', decided_at: new Date().toISOString(), decision_note: `No decision within ${hours} hours` });
      await this.store.audit.add({ actor: 'system', action: 'approval.expired', target: a.target_ip, detail: a.approval_id });
    }
    return stale.length;
  }

  async decide(id, { approve, actor, note = '' }) {
    const a = await this.store.approvals.get(id);
    if (!a) throw Object.assign(new Error('Approval not found'), { status: 404 });
    if (a.status !== 'PENDING') throw Object.assign(new Error(`Already ${a.status.toLowerCase()} by ${a.decided_by || 'system'}`), { status: 409 });
    const at = new Date().toISOString();
    if (!approve) {
      if (!note || String(note).trim().length < 4) throw Object.assign(new Error('Say why the action is rejected'), { status: 400 });
      const done = await this.store.approvals.update(id, { status: 'REJECTED', decided_by: actor, decided_at: at, decision_note: String(note).slice(0, 1000) });
      await this.store.audit.add({ actor, action: 'approval.rejected', target: a.target_ip, detail: `${id} ${a.action}: ${note}` });
      await this.reflect(a, { type: a.action, target: a.target_ip, approval_id: id, status: 'REJECTED', enforcement: null }, `${a.action} ${a.target_ip} rejected by ${actor}: ${note}`);
      return { approval: done };
    }
    const res = await this.tools.execute_firewall_action({
      action: a.action, target_ip: a.target_ip, reason: `${a.reason} (approved by ${actor}, ${id})`, actor, investigation_id: a.investigation_id,
      ...(a.ttl_hours != null ? { ttl_hours: a.ttl_hours || null } : {})
    });
    if (res.error) {
      const failed = await this.store.approvals.update(id, { status: 'FAILED', decided_by: actor, decided_at: at, decision_note: note || null, result: { error: res.error } });
      await this.store.audit.add({ actor, action: 'approval.failed', target: a.target_ip, detail: `${id}: ${res.error}` });
      return { approval: failed, error: res.error };
    }
    const check = await this.tools.verify_defense_state({ target_ip: a.target_ip });
    const rule = res.rule;
    const done = await this.store.approvals.update(id, {
      status: 'APPROVED', decided_by: actor, decided_at: at, decision_note: note ? String(note).slice(0, 1000) : null, rule_id: rule.rule_id,
      result: { status: res.status, enforcement: check.status, contained: check.contained, message: check.message }
    });
    await this.store.audit.add({ actor, action: 'approval.approved', target: a.target_ip, detail: `${id} -> ${rule.rule_id} ${check.status}` });
    await this.reflect(a, { type: a.action, target: a.target_ip, rule_id: rule.rule_id, approval_id: id, status: res.status, enforcement: check.status }, `${a.action} ${a.target_ip} approved by ${actor}: ${rule.rule_id}, enforcement ${check.status.toLowerCase()}`);
    // A confirmed compromise whose block is now enforced is contained.
    if (a.alert_id && check.contained) {
      const inv = a.investigation_id ? await this.store.investigations.get(a.investigation_id) : null;
      const alert = await this.store.alerts.get(a.alert_id);
      if (alert && inv && inv.outcome === 'ATTACK_SUCCEEDED' && alert.status === 'CONFIRMED') await this.store.alerts.update(a.alert_id, { status: 'CONTAINED' });
    }
    if (this.notifier) await this.notifier.emit('containment', { rule: { ...rule, enforcement: { status: check.status } }, severity: 'HIGH' }).catch(() => {});
    return { approval: done, rule, verification: check };
  }

  // Keeps the investigation record and the alert timeline in step with the decision.
  async reflect(a, entry, text) {
    if (a.investigation_id) {
      const inv = await this.store.investigations.get(a.investigation_id);
      if (inv) {
        const list = (inv.actions_taken || []).filter((x) => x.approval_id !== a.approval_id);
        await this.store.investigations.update(inv.investigation_id, { actions_taken: [...list, entry] }).catch(() => {});
        if (entry.rule_id) await this.store.rules.update(entry.rule_id, { investigation_id: inv.investigation_id }).catch(() => {});
      }
    }
    if (a.alert_id) await this.store.notes.add({ alert_id: a.alert_id, kind: 'event', author: 'approvals', body: text }).catch(() => {});
    if (a.case_id) await this.store.caseEvents.add({ case_id: a.case_id, kind: 'event', author: 'approvals', body: text }).catch(() => {});
  }
}

module.exports = { Approvals, routeFor, ROUTES, ROUTE_TEXT };
