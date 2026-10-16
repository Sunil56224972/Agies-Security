'use strict';

const minutesAgo = (m) => new Date(Date.now() - m * 60000).toISOString();

// Status values that count as "closed" for retention purposes.
const CLOSED_STATUSES = ['CONTAINED', 'MITIGATED', 'FALSE_POSITIVE', 'CLOSED'];

// Reference CVE records ship with every install (they are copies of public NVD
// data). Everything else in the seed is demo telemetry and is only loaded in demo mode.
function referenceCves(seed) {
  return seed.cves.map(({ match, ...c }) => ({
    cvss_vector: null, kev_added: null, last_modified: null, synced_at: null, ...c, match_terms: match || []
  }));
}

function materializeSeed(seed) {
  const now = new Date().toISOString();
  return {
    alerts: seed.alerts.map(({ minutes_ago, ...a }) => ({ external_ref: null, ...a, status: 'NEW', detected_at: minutesAgo(minutes_ago), updated_at: minutesAgo(minutes_ago) })),
    assets: seed.assets.map((a) => ({ ...a, source: 'demo', last_scanned: minutesAgo(90) })),
    cves: referenceCves(seed),
    logs: seed.logs.map(({ minutes_ago, ...l }, i) => ({ id: i + 1, status_code: null, request_method: null, request_uri: null, ...l, logged_at: minutesAgo(minutes_ago) })),
    rules: seed.firewallRules.map(({ minutes_ago, ...r }) => ({ ...r, investigation_id: null, created_at: minutesAgo(minutes_ago), updated_at: minutesAgo(minutes_ago) })),
    investigations: [],
    config: { ...seed.defaultConfig },
    audit: [{ id: 1, actor: 'system', action: 'demo.seeded', target: 'environment', detail: 'Demo dataset loaded', created_at: now }]
  };
}

function emptyState(seed) {
  return {
    alerts: [], assets: [], cves: referenceCves(seed), logs: [], rules: [], investigations: [],
    config: { ...seed.defaultConfig }, audit: [], users: [], api_keys: [], alert_notes: [], suppressions: []
  };
}

// Mirrors the alerts_lifecycle trigger in Postgres: acknowledged is the first
// time an alert leaves NEW, resolved is entering a closed status (cleared on reopen).
function applyLifecycle(prev, next) {
  const now = new Date().toISOString();
  const out = { ...next };
  if (out.status && out.status !== 'NEW' && !out.acknowledged_at) out.acknowledged_at = (prev && prev.acknowledged_at) || now;
  if (out.status && CLOSED_STATUSES.includes(out.status)) {
    if (!out.resolved_at) out.resolved_at = (prev && prev.resolved_at) || now;
  } else if (out.status) out.resolved_at = null;
  return out;
}

function matchesQuery(q, fields) {
  if (!q) return true;
  const needle = String(q).toLowerCase();
  return fields.some((f) => f != null && String(f).toLowerCase().includes(needle));
}

// Never hand password hashes or key hashes to route handlers by accident.
const publicUser = (u) => (u ? { id: u.id, email: u.email, name: u.name, role: u.role, disabled: Boolean(u.disabled), created_at: u.created_at, last_login_at: u.last_login_at || null } : null);
const publicKey = (k) => (k ? { id: k.id, name: k.name, prefix: k.prefix, scopes: k.scopes, created_by: k.created_by, created_at: k.created_at, last_used_at: k.last_used_at || null, revoked_at: k.revoked_at || null } : null);

const ALERT_DEFAULTS = { external_ref: null, assignee_id: null, assignee_name: null, acknowledged_at: null, resolved_at: null, suppressed_by: null };

module.exports = { materializeSeed, emptyState, referenceCves, matchesQuery, minutesAgo, publicUser, publicKey, applyLifecycle, ALERT_DEFAULTS, CLOSED_STATUSES };