'use strict';

const minutesAgo = (m) => new Date(Date.now() - m * 60000).toISOString();

// Turns the static seed module into rows with concrete timestamps.
function materializeSeed(seed) {
  const now = new Date().toISOString();
  return {
    alerts: seed.alerts.map(({ minutes_ago, ...a }) => ({ ...a, status: 'NEW', detected_at: minutesAgo(minutes_ago), updated_at: minutesAgo(minutes_ago) })),
    assets: seed.assets.map(a => ({ ...a, last_scanned: minutesAgo(90) })),
    cves: seed.cves.map(({ match, ...c }) => ({ ...c, match_terms: match })),
    logs: seed.logs.map(({ minutes_ago, ...l }, i) => ({ id: i + 1, status_code: null, request_method: null, request_uri: null, ...l, logged_at: minutesAgo(minutes_ago) })),
    rules: seed.firewallRules.map(({ minutes_ago, ...r }) => ({ ...r, investigation_id: null, created_at: minutesAgo(minutes_ago), updated_at: minutesAgo(minutes_ago) })),
    investigations: [],
    config: { ...seed.defaultConfig },
    audit: [{ id: 1, actor: 'system', action: 'sandbox.seeded', target: 'environment', detail: 'Seed telemetry loaded', created_at: now }]
  };
}

function matchesQuery(q, fields) {
  if (!q) return true;
  const needle = String(q).toLowerCase();
  return fields.some(f => f != null && String(f).toLowerCase().includes(needle));
}

module.exports = { materializeSeed, matchesQuery, minutesAgo };