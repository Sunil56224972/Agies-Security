'use strict';

// Hypothesis-driven threat hunting over what Aegis has stored: host and web
// logs, alerts and investigations. A hunt is a saved set of criteria; a run
// executes them against the data as it is now and keeps the findings, so the
// same hunt can be replayed later and compared with the previous run.
//
// Criteria (all optional, at least one required):
//   window_hours   how far back to look (1-2160, default 168)
//   text           substring or /regex/flags matched against raw log lines and alert payloads
//   ip             an address or IPv4 CIDR, matched as client, host, source or destination
//   technique      ATT&CK id (T1190, T1110.003) matched against alerts and verdicts
//   log_types      subset of http_access, auth_log, edr_process, system
//   indicators     list of IPs, domains, URLs or hashes searched for verbatim
//   sigma          run the loaded SigmaHQ rules over the window's logs
//   intel          check every external address in the window against the threat feeds
//   min_severity   floor for alert matches

const { isIP, isInternal, SEVERITY_RANK, classifyPayload } = require('./analysis');
const { extractAll, isIpType } = require('../intel/indicator');
const { scanWith } = require('./sigma');

const LOG_TYPES = ['http_access', 'auth_log', 'edr_process', 'system'];
const MAX_FINDINGS = 500;

function ipv4ToInt(ip) { return ip.split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0; }
function ipMatcher(spec) {
  if (!spec) return null;
  const s = String(spec).trim();
  const m = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (m && isIP(m[1]) && Number(m[2]) <= 32) {
    const bits = Number(m[2]);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    const net = (ipv4ToInt(m[1]) & mask) >>> 0;
    return (ip) => Boolean(ip) && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && ((ipv4ToInt(ip) & mask) >>> 0) === net;
  }
  if (isIP(s)) return (ip) => ip === s;
  throw new Error('ip must be an address or an IPv4 CIDR such as 10.0.0.0/8');
}

function textMatcher(spec) {
  if (!spec) return null;
  const s = String(spec);
  const re = s.match(/^\/(.+)\/([gimsuy]*)$/);
  if (re) {
    let rx;
    try { rx = new RegExp(re[1], re[2].replace('g', '')); } catch (err) { throw new Error(`Invalid regular expression: ${err.message}`); }
    return (v) => rx.test(String(v || ''));
  }
  const needle = s.toLowerCase();
  return (v) => String(v || '').toLowerCase().includes(needle);
}

const techId = (v) => { const m = String(v || '').match(/\bT\d{4}(?:\.\d{3})?\b/i); return m ? m[0].toUpperCase() : null; };
// Explicit ids (sensor reference, payload) win; otherwise the payload classifier's mapping.
const alertTechnique = (a) => { const t = techId(a.external_ref) || techId(a.raw_payload); if (t) return t; const c = classifyPayload(a.raw_payload).technique; return c ? techId(c.technique) : null; };
const techMatches = (want, have) => Boolean(want && have && (have === want || have.startsWith(`${want}.`) || want.startsWith(`${have}.`)));

function normalizeCriteria(c = {}) {
  const out = {};
  const hours = c.window_hours === undefined || c.window_hours === '' ? 168 : Number(c.window_hours);
  if (!Number.isInteger(hours) || hours < 1 || hours > 2160) throw new Error('window_hours must be 1-2160');
  out.window_hours = hours;
  if (c.text) { if (String(c.text).length > 300) throw new Error('text is at most 300 characters'); textMatcher(c.text); out.text = String(c.text); }
  if (c.ip) { ipMatcher(c.ip); out.ip = String(c.ip).trim(); }
  if (c.technique) { const t = techId(c.technique); if (!t) throw new Error('technique must be an ATT&CK id such as T1190 or T1110.003'); out.technique = t; }
  if (c.log_types && [].concat(c.log_types).length) {
    const lt = [...new Set([].concat(c.log_types))];
    if (lt.some((x) => !LOG_TYPES.includes(x))) throw new Error(`log_types must be from ${LOG_TYPES.join(', ')}`);
    out.log_types = lt;
  }
  if (c.indicators) {
    const raw = Array.isArray(c.indicators) ? c.indicators.join('\n') : String(c.indicators);
    const inds = extractAll(raw, { max: 100 }).filter((i) => i.type !== 'asn');
    if (!inds.length && raw.trim()) throw new Error('No IPs, domains, URLs or hashes found in indicators');
    if (inds.length) out.indicators = inds.map((i) => i.value);
  }
  if (c.sigma) out.sigma = true;
  if (c.intel) out.intel = true;
  if (c.min_severity) {
    const s = String(c.min_severity).toUpperCase();
    if (!SEVERITY_RANK[s]) throw new Error('min_severity must be LOW, MEDIUM, HIGH or CRITICAL');
    out.min_severity = s;
  }
  if (!out.text && !out.ip && !out.technique && !out.indicators && !out.sigma && !out.intel) throw new Error('Give the hunt at least one of: text, ip, technique, indicators, sigma or intel');
  return out;
}

class HuntEngine {
  constructor(store, { sigma = null, reputation = null, hub = null, custom = null } = {}) {
    this.custom = custom;
    this.store = store;
    this.sigma = sigma;
    this.reputation = reputation;
    this.hub = hub;
  }

  async execute(criteria, { budgetMs = 20000 } = {}) {
    const c = normalizeCriteria(criteria);
    const started = Date.now();
    const since = new Date(Date.now() - c.window_hours * 3600000).toISOString();
    const [logsAll, alerts, invs] = await Promise.all([
      this.store.logs.list({ since, limit: 20000 }),
      this.store.alerts.list({ since, limit: 20000 }),
      this.store.investigations.list({ since, lite: true, limit: 5000 })
    ]);
    const logs = c.log_types ? logsAll.filter((l) => c.log_types.includes(l.log_type)) : logsAll;
    const text = textMatcher(c.text);
    const ip = ipMatcher(c.ip);
    const inds = (c.indicators || []).map((v) => String(v).toLowerCase());
    const minRank = c.min_severity ? SEVERITY_RANK[c.min_severity] : 0;
    const findings = [];
    const add = (f) => { if (findings.length < MAX_FINDINGS) findings.push(f); };
    const notes = [];

    // Log lines: every selector given must hold (text AND ip AND indicator).
    const logSelectors = Boolean(text || ip || inds.length);
    if (logSelectors) {
      for (const l of logs) {
        const raw = String(l.raw_entry || '');
        if (text && !text(raw)) continue;
        if (ip && !ip(l.client_ip) && !ip(l.host_ip)) continue;
        let hit = null;
        if (inds.length) { const low = raw.toLowerCase(); hit = inds.find((v) => low.includes(v) || l.client_ip === v); if (!hit) continue; }
        add({ kind: 'log', at: l.logged_at, host: l.host_ip, remote: l.client_ip || null, log_type: l.log_type, title: hit ? `Indicator ${hit} in ${l.log_type}` : `${l.log_type} on ${l.host_ip}`, detail: raw.slice(0, 600), ref: String(l.id) });
      }
    }

    // Alerts and investigations.
    for (const a of alerts) {
      if (minRank && (SEVERITY_RANK[a.severity] || 0) < minRank) continue;
      const tech = alertTechnique(a);
      const checks = [];
      if (text) checks.push(text(`${a.signature}\n${a.raw_payload || ''}`));
      if (ip) checks.push(ip(a.source_ip) || ip(a.dest_ip));
      if (c.technique) checks.push(techMatches(c.technique, tech));
      if (inds.length) { const low = `${a.raw_payload || ''} ${a.source_ip} ${a.dest_ip}`.toLowerCase(); checks.push(inds.some((v) => low.includes(v))); }
      if (!checks.length || checks.some((x) => !x)) continue;
      add({ kind: 'alert', at: a.detected_at, host: a.dest_ip, remote: a.source_ip, severity: a.severity, title: a.signature, detail: `${a.source_ip} -> ${a.dest_ip}:${a.dest_port} ${a.status}${tech ? ` ${tech}` : ''}`, ref: a.alert_id, technique: tech });
    }
    for (const i of invs) {
      const tech = techId(i.mitre_technique);
      const checks = [];
      if (ip) checks.push(ip(i.attacker_ip) || ip(i.target_ip));
      if (c.technique) checks.push(techMatches(c.technique, tech));
      if (text) checks.push(text(i.summary));
      if (!checks.length || checks.some((x) => !x)) continue;
      add({ kind: 'investigation', at: i.created_at, host: i.target_ip, remote: i.attacker_ip, title: `${String(i.outcome).replace(/_/g, ' ').toLowerCase()} (${i.confidence}%)`, detail: i.summary.slice(0, 400), ref: i.investigation_id, alert_id: i.alert_id, technique: tech });
    }

    // SigmaHQ rules over the window's logs (narrowed by ip/text when given).
    let sigmaInfo = null;
    if (c.sigma) {
      const scope = logs.filter((l) => (!ip || ip(l.client_ip) || ip(l.host_ip)) && (!text || text(l.raw_entry)));
      const community = this.sigma && this.sigma.available ? await this.sigma.rules(Math.min(budgetMs, 15000)) : null;
      if (!community) notes.push(this.sigma && this.sigma.available ? 'SigmaHQ rules are still downloading; only custom rules ran.' : 'SigmaHQ is disabled on this server; only custom rules ran.');
      const own = this.custom ? await this.custom.compiled().catch(() => []) : [];
      const rules = community || own.length ? [...(community || []), ...own] : null;
      if (!rules) { notes.push('No Sigma rules are available.'); }
      else {
        const matches = scanWith(rules, scope, { minLevel: 'low' }).filter((m) => !c.technique || techMatches(c.technique, techId(m.rule.technique)));
        const rulesHit = new Set();
        for (const m of matches) {
          rulesHit.add(m.rule.id);
          add({ kind: 'sigma', at: m.log.logged_at, host: m.log.host_ip, remote: m.log.client_ip || null, severity: { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM' }[m.rule.level] || 'LOW', title: `Sigma: ${m.rule.title}`, detail: String(m.log.raw_entry).slice(0, 600), ref: m.rule.id, technique: techId(m.rule.technique) });
        }
        sigmaInfo = { rules: rules.length, lines: scope.length, matches: matches.length, rules_hit: rulesHit.size };
      }
    }

    // Every external address seen in the window against the reputation feeds.
    let intelInfo = null;
    if (c.intel) {
      if (!this.reputation || !this.reputation.available) notes.push('Threat intel is disabled on this server.');
      else {
        const addrs = new Set();
        for (const l of logs) if (l.client_ip && isIP(l.client_ip) && !isInternal(l.client_ip) && (!ip || ip(l.client_ip))) addrs.add(l.client_ip);
        for (const a of alerts) for (const x of [a.source_ip, a.dest_ip]) if (isIP(x) && !isInternal(x) && (!ip || ip(x))) addrs.add(x);
        const list = [...addrs].slice(0, 60);
        if (addrs.size > list.length) notes.push(`${addrs.size} external addresses in the window; checked the first ${list.length}.`);
        const deadline = started + budgetMs;
        let checked = 0;
        for (let k = 0; k < list.length && Date.now() < deadline; k += 6) {
          const batch = await Promise.all(list.slice(k, k + 6).map(async (x) => { try { return [x, await this.reputation.check(x)]; } catch { return [x, null]; } }));
          for (const [x, r] of batch) {
            checked += 1;
            if (!r || !['malicious', 'suspicious'].includes(r.verdict)) continue;
            const seen = logs.filter((l) => l.client_ip === x).length + alerts.filter((a) => a.source_ip === x || a.dest_ip === x).length;
            add({ kind: 'intel', at: new Date().toISOString(), host: null, remote: x, severity: r.verdict === 'malicious' ? 'HIGH' : 'MEDIUM', title: `${x} is ${r.verdict}${r.score != null ? ` (${r.score})` : ''}`, detail: `${r.summary || ''} Seen in ${seen} record${seen === 1 ? '' : 's'} in the window.`.trim(), ref: x });
          }
        }
        if (checked < list.length) notes.push(`Time budget reached after ${checked} of ${list.length} reputation checks.`);
        intelInfo = { addresses: addrs.size, checked };
      }
    }

    findings.sort((a, b) => String(b.at).localeCompare(String(a.at)));
    const hosts = new Set(findings.map((f) => f.host).filter(Boolean));
    const remotes = new Set(findings.map((f) => f.remote).filter(Boolean));
    const kinds = findings.reduce((m, f) => ({ ...m, [f.kind]: (m[f.kind] || 0) + 1 }), {});
    const techniques = findings.reduce((m, f) => (f.technique ? { ...m, [f.technique]: (m[f.technique] || 0) + 1 } : m), {});
    return {
      criteria: c,
      findings,
      summary: {
        since, scanned: { logs: logs.length, alerts: alerts.length, investigations: invs.length }, kinds, hosts: [...hosts].slice(0, 50), remotes: [...remotes].slice(0, 50),
        techniques, sigma: sigmaInfo, intel: intelInfo, notes, truncated: findings.length >= MAX_FINDINGS
      },
      duration_ms: Date.now() - started
    };
  }
}

// Stable key for comparing runs: what was found, not when the run happened.
const findingKey = (f) => `${f.kind}|${f.ref}|${f.at}`;

// ATT&CK rollup across alerts and investigations in a window.
function techniqueRollup(alerts, invs, tactics = []) {
  const map = new Map();
  const touch = (id, name, tactic) => {
    const t = map.get(id) || { technique: id, name: null, tactic: null, alerts: 0, open: 0, investigations: 0, confirmed: 0, hosts: new Set(), last_seen: null };
    if (name && !t.name) t.name = name;
    if (tactic && !t.tactic) t.tactic = tactic;
    map.set(id, t);
    return t;
  };
  const OPEN = ['NEW', 'INVESTIGATING', 'CONFIRMED'];
  for (const a of alerts) {
    const id = alertTechnique(a);
    if (!id) continue;
    const c = classifyPayload(a.raw_payload).technique;
    const named = c && techId(c.technique) === id ? c : null;
    const tactic = (named && named.tactic) || tactics.find((x) => x.toLowerCase() === String(a.category || '').toLowerCase()) || null;
    const t = touch(id, named ? named.technique.replace(id, '').trim() : null, tactic);
    t.alerts += 1;
    if (OPEN.includes(a.status)) t.open += 1;
    t.hosts.add(a.dest_ip);
    if (!t.last_seen || a.detected_at > t.last_seen) t.last_seen = a.detected_at;
  }
  for (const i of invs) {
    const id = techId(i.mitre_technique);
    if (!id) continue;
    const t = touch(id, String(i.mitre_technique).replace(id, '').trim() || null, tactics.find((x) => x === i.mitre_tactic) || i.mitre_tactic || null);
    t.investigations += 1;
    if (i.outcome === 'ATTACK_SUCCEEDED') t.confirmed += 1;
    t.hosts.add(i.target_ip);
    if (!t.last_seen || i.created_at > t.last_seen) t.last_seen = i.created_at;
  }
  return [...map.values()].map((t) => ({ ...t, hosts: t.hosts.size })).sort((a, b) => b.confirmed - a.confirmed || b.alerts + b.investigations - (a.alerts + a.investigations));
}

module.exports = { HuntEngine, normalizeCriteria, techniqueRollup, findingKey, ipMatcher, textMatcher, techId, alertTechnique, LOG_TYPES };
