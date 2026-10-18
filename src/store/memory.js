'use strict';

const fs = require('fs');
const path = require('path');
const seed = require('../seed');
const { materializeSeed, emptyState, matchesQuery, publicUser, publicKey, applyLifecycle, ALERT_DEFAULTS, CASE_DEFAULTS, CLOSED_STATUSES } = require('./shared');
const OPEN_STATUSES = ['NEW', 'INVESTIGATING', 'CONFIRMED'];

// File-backed store used when Supabase credentials are absent. Good for a
// single-node install or evaluation; use Supabase for anything shared.
const DEFAULT_FILE = path.join(__dirname, '..', '..', '.data', 'aegis.json');
const LOG_CAP = 50000;
const CASE_TABLES = ['cases', 'case_alerts', 'case_tasks', 'case_iocs', 'case_events', 'approvals', 'hunts', 'hunt_runs',
  'chat_threads', 'workflows', 'workflow_runs', 'decision_feedback', 'documents', 'custom_rules'];
// Row caps for tables that only grow; the oldest rows go first.
const CAPS = { workflow_runs: 500, chat_threads: 500, documents: 500 };
const byNewest = (k) => (a, b) => String(b[k]).localeCompare(String(a[k]));

class MemoryStore {
  constructor({ file = DEFAULT_FILE, demo = false } = {}) {
    this.kind = 'local';
    this.label = 'Local file store';
    this.file = file;
    this.demo = demo;
    this.db = null;
    this.saveTimer = null;
  }

  async init() {
    try {
      if (fs.existsSync(this.file)) this.db = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch (err) {
      // Keep the unreadable file for inspection instead of silently overwriting it.
      const bad = `${this.file}.corrupt-${Date.now()}`;
      try { fs.renameSync(this.file, bad); } catch { /* ignore */ }
      console.warn(`  Store file unreadable (${err.message}); moved to ${bad}`);
    }
    if (!this.db || !this.db.alerts) this.db = this.demo ? { ...emptyState(seed), ...materializeSeed(seed) } : emptyState(seed);
    for (const k of ['users', 'api_keys', 'audit', 'logs', 'rules', 'investigations', 'assets', 'cves', 'alert_notes', 'suppressions', ...CASE_TABLES]) if (!Array.isArray(this.db[k])) this.db[k] = [];
    this.seq = {
      log: Math.max(0, ...this.db.logs.map((l) => l.id)) + 1,
      audit: Math.max(0, ...this.db.audit.map((a) => a.id)) + 1,
      user: Math.max(0, ...this.db.users.map((u) => u.id)) + 1,
      key: Math.max(0, ...this.db.api_keys.map((k) => k.id)) + 1,
      note: Math.max(0, ...this.db.alert_notes.map((n) => n.id)) + 1,
      supp: Math.max(0, ...this.db.suppressions.map((x) => x.id)) + 1
    };
    for (const k of CASE_TABLES) this.seq[k] = Math.max(0, ...this.db[k].map((x) => Number(x.id) || 0)) + 1;
    this.persist();
  }

  persist() {
    clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => this.flush(), 150);
  }

  flush() {
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      // Write-then-rename so a crash mid-write never leaves a truncated file.
      const tmp = `${this.file}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(this.db));
      fs.renameSync(tmp, this.file);
    } catch (err) {
      console.warn('  Could not persist store:', err.message);
    }
  }

  async health() {
    return { ok: true, detail: `File store (${path.relative(process.cwd(), this.file) || this.file})` };
  }

  // Replaces telemetry with the demo dataset. Users and API keys are kept.
  async reset() {
    const keep = { users: this.db.users, api_keys: this.db.api_keys, suppressions: this.db.suppressions, hunts: this.db.hunts, workflows: this.db.workflows, custom_rules: this.db.custom_rules, chat_threads: this.db.chat_threads };
    this.db = { ...emptyState(seed), ...materializeSeed(seed), ...keep };
    this.seq.log = this.db.logs.length + 1;
    this.seq.audit = 2;
    this.persist();
  }

  clone(row) { return row ? JSON.parse(JSON.stringify(row)) : null; }
  touch(row, patch) {
    Object.assign(row, patch, { updated_at: new Date().toISOString() });
    this.persist();
    return this.clone(row);
  }

  async counts() {
    return { alerts: this.db.alerts.length, assets: this.db.assets.length, logs: this.db.logs.length, users: this.db.users.length };
  }

  get alerts() {
    const s = this;
    return {
      async list({ severity, status, statuses, q, ip, assignee, since, limit = 500 } = {}) {
        return s.db.alerts
          .filter((a) => (!severity || a.severity === severity) && (!status || a.status === status) && (!statuses || statuses.includes(a.status)) && (!since || a.detected_at >= since))
          .filter((a) => (!ip || a.source_ip === ip || a.dest_ip === ip) && (!assignee || (assignee === 'none' ? a.assignee_id == null : a.assignee_id === Number(assignee))))
          .filter((a) => matchesQuery(q, [a.alert_id, a.signature, a.source_ip, a.dest_ip, a.category, a.sensor]))
          .sort((a, b) => b.detected_at.localeCompare(a.detected_at))
          .slice(0, limit)
          .map((r) => s.clone(r));
      },
      async get(id) { return s.clone(s.db.alerts.find((a) => a.alert_id === id)); },
      async count({ open } = {}) { return open ? s.db.alerts.filter((a) => OPEN_STATUSES.includes(a.status)).length : s.db.alerts.length; },
      async insert(row) {
        const now = new Date().toISOString();
        const rec = applyLifecycle(null, { detected_at: now, updated_at: now, status: 'NEW', ...ALERT_DEFAULTS, ...row });
        s.db.alerts.push(rec);
        s.persist();
        return s.clone(rec);
      },
      // Idempotent bulk insert for sensors: rows whose alert_id exists are skipped.
      async insertMany(rows) {
        const have = new Set(s.db.alerts.map((a) => a.alert_id));
        const fresh = rows.filter((r) => !have.has(r.alert_id) && have.add(r.alert_id));
        const now = new Date().toISOString();
        s.db.alerts.push(...fresh.map((r) => applyLifecycle(null, { detected_at: now, updated_at: now, status: 'NEW', ...ALERT_DEFAULTS, ...r })));
        s.persist();
        return { inserted: fresh.map((r) => r.alert_id), duplicates: rows.length - fresh.length };
      },
      async update(id, patch) {
        const row = s.db.alerts.find((a) => a.alert_id === id);
        return row ? s.touch(row, applyLifecycle(row, { status: row.status, ...patch })) : null;
      },
      async updateMany(ids, patch) {
        const want = new Set(ids);
        return s.db.alerts.filter((a) => want.has(a.alert_id)).map((row) => s.touch(row, applyLifecycle(row, { status: row.status, ...patch })));
      },
      async purgeClosed(before) {
        const gone = new Set(s.db.alerts.filter((a) => CLOSED_STATUSES.includes(a.status) && a.updated_at < before).map((a) => a.alert_id));
        if (!gone.size) return 0;
        s.db.alerts = s.db.alerts.filter((a) => !gone.has(a.alert_id));
        s.db.alert_notes = s.db.alert_notes.filter((n) => !gone.has(n.alert_id));
        const invs = new Set(s.db.investigations.filter((i) => gone.has(i.alert_id)).map((i) => i.investigation_id));
        s.db.investigations = s.db.investigations.filter((i) => !invs.has(i.investigation_id));
        for (const r of s.db.rules) if (invs.has(r.investigation_id)) r.investigation_id = null;
        s.persist();
        return gone.size;
      }
    };
  }

  get assets() {
    const s = this;
    return {
      async list() { return [...s.db.assets].sort((a, b) => a.ip_address.localeCompare(b.ip_address, undefined, { numeric: true })).map((r) => s.clone(r)); },
      async get(ip) { return s.clone(s.db.assets.find((a) => a.ip_address === ip)); },
      async upsert(rows) {
        const now = new Date().toISOString();
        for (const r of rows) {
          const i = s.db.assets.findIndex((a) => a.ip_address === r.ip_address);
          const rec = { last_scanned: now, ...(i >= 0 ? s.db.assets[i] : {}), ...r };
          if (i >= 0) s.db.assets[i] = rec; else s.db.assets.push(rec);
        }
        s.persist();
        return rows.map((r) => s.clone(s.db.assets.find((a) => a.ip_address === r.ip_address)));
      },
      async remove(ip) {
        const n = s.db.assets.length;
        s.db.assets = s.db.assets.filter((a) => a.ip_address !== ip);
        s.persist();
        return s.db.assets.length < n;
      }
    };
  }

  get cves() {
    const s = this;
    return {
      async list(q) {
        return s.db.cves
          .filter((c) => matchesQuery(q, [c.cve_id, c.title, c.description, ...(c.affected_products || []), ...(c.match_terms || [])]))
          .sort((a, b) => b.cvss_score - a.cvss_score)
          .map((r) => s.clone(r));
      },
      async get(id) { return s.clone(s.db.cves.find((c) => c.cve_id === id)); },
      async upsert(rows) {
        for (const r of rows) {
          const i = s.db.cves.findIndex((c) => c.cve_id === r.cve_id);
          if (i >= 0) s.db.cves[i] = { ...s.db.cves[i], ...r }; else s.db.cves.push(r);
        }
        s.persist();
        return rows.length;
      },
      async remove(id) {
        const n = s.db.cves.length;
        s.db.cves = s.db.cves.filter((c) => c.cve_id !== id);
        s.persist();
        return s.db.cves.length < n;
      }
    };
  }

  get logs() {
    const s = this;
    return {
      async list({ host_ip, log_type, client_ip, since, limit = 50 } = {}) {
        return s.db.logs
          .filter((l) => (!host_ip || l.host_ip === host_ip) && (!log_type || l.log_type === log_type) && (!client_ip || l.client_ip === client_ip) && (!since || l.logged_at >= since))
          .sort((a, b) => b.logged_at.localeCompare(a.logged_at))
          .slice(0, limit)
          .map((r) => s.clone(r));
      },
      async insertMany(rows) {
        s.db.logs.push(...rows.map((r) => ({ id: s.seq.log++, ...r })));
        if (s.db.logs.length > LOG_CAP) s.db.logs.splice(0, s.db.logs.length - LOG_CAP);
        s.persist();
        return rows.length;
      },
      async purge(before) {
        const n = s.db.logs.length;
        s.db.logs = s.db.logs.filter((l) => l.logged_at >= before);
        if (s.db.logs.length !== n) s.persist();
        return n - s.db.logs.length;
      }
    };
  }

  get rules() {
    const s = this;
    return {
      async list({ limit = 5000 } = {}) { return [...s.db.rules].sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, limit).map((r) => s.clone(r)); },
      async get(id) { return s.clone(s.db.rules.find((r) => r.rule_id === id)); },
      async activeFor(ip) { return s.db.rules.filter((r) => r.target_ip === ip && r.is_active).map((r) => s.clone(r)); },
      async active(action) { return s.db.rules.filter((r) => r.is_active && (!action || r.action === action)).map((r) => s.clone(r)); },
      async insert(row) {
        const now = new Date().toISOString();
        const rec = { created_at: now, updated_at: now, is_active: true, investigation_id: null, enforcement: null, expires_at: null, ...row };
        s.db.rules.push(rec);
        s.persist();
        return s.clone(rec);
      },
      async update(id, patch) {
        const row = s.db.rules.find((r) => r.rule_id === id);
        return row ? s.touch(row, patch) : null;
      },
      async expiredActive(at) {
        return s.db.rules.filter((r) => r.is_active && r.expires_at && r.expires_at <= at).map((r) => s.clone(r));
      }
    };
  }

  get notes() {
    const s = this;
    return {
      async list(alertId) {
        return s.db.alert_notes.filter((n) => n.alert_id === alertId).sort((a, b) => a.id - b.id).map((r) => s.clone(r));
      },
      async add(row) {
        const rec = { id: s.seq.note++, created_at: new Date().toISOString(), kind: 'note', author_id: null, ...row };
        s.db.alert_notes.push(rec);
        s.persist();
        return s.clone(rec);
      },
      async addMany(rows) {
        const now = new Date().toISOString();
        s.db.alert_notes.push(...rows.map((r) => ({ id: s.seq.note++, created_at: now, kind: 'note', author_id: null, ...r })));
        s.persist();
        return rows.length;
      }
    };
  }

  get suppressions() {
    const s = this;
    return {
      async list() { return [...s.db.suppressions].sort((a, b) => b.id - a.id).map((r) => s.clone(r)); },
      async get(id) { return s.clone(s.db.suppressions.find((x) => x.id === Number(id))); },
      async insert(row) {
        const now = new Date().toISOString();
        const rec = { id: s.seq.supp++, signature: null, source_cidr: null, dest_cidr: null, dest_port: null, enabled: true, expires_at: null, hits: 0, last_hit_at: null, created_at: now, updated_at: now, ...row };
        s.db.suppressions.push(rec);
        s.persist();
        return s.clone(rec);
      },
      async update(id, patch) {
        const row = s.db.suppressions.find((x) => x.id === Number(id));
        return row ? s.touch(row, patch) : null;
      },
      async remove(id) {
        const n = s.db.suppressions.length;
        s.db.suppressions = s.db.suppressions.filter((x) => x.id !== Number(id));
        for (const a of s.db.alerts) if (a.suppressed_by === Number(id)) a.suppressed_by = null;
        s.persist();
        return s.db.suppressions.length < n;
      },
      async recordHits(counts, at) {
        for (const [id, n] of Object.entries(counts)) {
          const row = s.db.suppressions.find((x) => x.id === Number(id));
          if (row) { row.hits += n; row.last_hit_at = at; }
        }
        s.persist();
      }
    };
  }

  get investigations() {
    const s = this;
    return {
      async list({ since, limit = 500 } = {}) {
        return s.db.investigations.filter((i) => !since || i.created_at >= since)
          .sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, limit).map((r) => s.clone(r));
      },
      async get(id) { return s.clone(s.db.investigations.find((i) => i.investigation_id === id)); },
      async forAlert(alertId) {
        return s.db.investigations.filter((i) => i.alert_id === alertId).sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 100).map((r) => s.clone(r));
      },
      async forIp(ip, { limit = 50 } = {}) {
        return s.db.investigations.filter((i) => i.attacker_ip === ip || i.target_ip === ip).sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, limit).map((r) => s.clone(r));
      },
      async insert(row) {
        const now = new Date().toISOString();
        const rec = { created_at: now, updated_at: now, human_override: null, ...row };
        s.db.investigations.push(rec);
        s.persist();
        return s.clone(rec);
      },
      async update(id, patch) {
        const row = s.db.investigations.find((i) => i.investigation_id === id);
        return row ? s.touch(row, patch) : null;
      }
    };
  }

  get config() {
    const s = this;
    return {
      async get() { return { ...seed.defaultConfig, ...s.db.config }; },
      async set(values) {
        s.db.config = { ...s.db.config, ...values };
        s.persist();
        return { ...seed.defaultConfig, ...s.db.config };
      }
    };
  }

  get users() {
    const s = this;
    return {
      async count() { return s.db.users.length; },
      async list() { return s.db.users.map(publicUser); },
      // Returns the full row including password_hash; only the auth layer calls this.
      async byEmail(email) { return s.clone(s.db.users.find((u) => u.email === String(email).toLowerCase())); },
      async byId(id) { return s.clone(s.db.users.find((u) => u.id === Number(id))); },
      async insert(row) {
        if (s.db.users.some((u) => u.email === row.email)) throw new Error('A user with that email already exists');
        const rec = { id: s.seq.user++, created_at: new Date().toISOString(), disabled: false, session_version: 1, last_login_at: null, ...row };
        s.db.users.push(rec);
        s.persist();
        return publicUser(rec);
      },
      async update(id, patch) {
        const row = s.db.users.find((u) => u.id === Number(id));
        if (!row) return null;
        Object.assign(row, patch);
        s.persist();
        return publicUser(row);
      }
    };
  }

  get apiKeys() {
    const s = this;
    return {
      async list() { return [...s.db.api_keys].sort((a, b) => b.id - a.id).map(publicKey); },
      async byHash(hash) { return s.clone(s.db.api_keys.find((k) => k.hash === hash && !k.revoked_at)); },
      async insert(row) {
        const rec = { id: s.seq.key++, created_at: new Date().toISOString(), last_used_at: null, revoked_at: null, ...row };
        s.db.api_keys.push(rec);
        s.persist();
        return publicKey(rec);
      },
      async touch(id) {
        const k = s.db.api_keys.find((x) => x.id === id);
        if (k) { k.last_used_at = new Date().toISOString(); s.persist(); }
      },
      async revoke(id) {
        const k = s.db.api_keys.find((x) => x.id === Number(id));
        if (!k || k.revoked_at) return null;
        k.revoked_at = new Date().toISOString();
        s.persist();
        return publicKey(k);
      }
    };
  }

  // ---- Cases, approvals and hunts ------------------------------------------
  // Generic row helpers for the tables that share the same shape of access.
  table(name, key = 'id') {
    const s = this;
    const find = (id) => s.db[name].find((r) => String(r[key]) === String(id));
    return {
      rows: () => s.db[name],
      find,
      async get(id) { return s.clone(find(id)); },
      async insert(row) {
        const now = new Date().toISOString();
        const rec = { created_at: now, updated_at: now, ...row };
        if (key === 'id') rec.id = s.seq[name]++;
        s.db[name].push(rec);
        s.persist();
        return s.clone(rec);
      },
      async update(id, patch) { const row = find(id); return row ? s.touch(row, patch) : null; },
      async remove(id) {
        const n = s.db[name].length;
        s.db[name] = s.db[name].filter((r) => String(r[key]) !== String(id));
        s.persist();
        return s.db[name].length < n;
      }
    };
  }

  // Generic access for the workbench tables (assistant, workflows, feedback,
  // documents, custom rules). `eq` filters on exact column values.
  coll(name, key = 'id') {
    const s = this;
    const t = s.table(name, key);
    return {
      ...t,
      async list({ eq = {}, order = 'created_at', asc = false, limit = 200, omit = [] } = {}) {
        const rows = t.rows().filter((r) => Object.entries(eq).every(([k, v]) => String(r[k]) === String(v)))
          .sort((a, b) => (asc ? 1 : -1) * (String(a[order]).localeCompare(String(b[order])) || (Number(a.id) || 0) - (Number(b.id) || 0)))
          .slice(0, limit);
        return rows.map((r) => { const c = s.clone(r); for (const k of omit) delete c[k]; return c; });
      },
      async count(eq = {}) { return t.rows().filter((r) => Object.entries(eq).every(([k, v]) => String(r[k]) === String(v))).length; },
      async insert(row) {
        const rec = await t.insert(row);
        const cap = CAPS[name];
        if (cap && s.db[name].length > cap) s.db[name] = [...s.db[name]].sort(byNewest('created_at')).slice(0, cap);
        return rec;
      },
      async all() { return t.rows().map((r) => s.clone(r)); },
      // Insert-or-replace by key, used by restore.
      async put(rows) {
        for (const r of rows) {
          const i = s.db[name].findIndex((x) => String(x[key]) === String(r[key]));
          if (i >= 0) s.db[name][i] = { ...r }; else s.db[name].push({ ...r });
          if (key === 'id' && Number(r.id) >= s.seq[name]) s.seq[name] = Number(r.id) + 1;
        }
        s.persist();
        return rows.length;
      }
    };
  }

  // After a restore wrote rows with their own ids, move every counter past them.
  async afterRestore() {
    const max = (rows) => Math.max(0, ...rows.map((x) => Number(x.id) || 0)) + 1;
    Object.assign(this.seq, { log: max(this.db.logs), audit: max(this.db.audit), note: max(this.db.alert_notes), supp: max(this.db.suppressions) });
    for (const k of CASE_TABLES) this.seq[k] = max(this.db[k]);
    this.persist();
  }

  get cases() {
    const s = this;
    const t = s.table('cases', 'case_id');
    return {
      ...t,
      async list({ status, q, limit = 500 } = {}) {
        const want = status ? [].concat(status) : null;
        return t.rows().filter((c) => !want || want.includes(c.status))
          .filter((c) => matchesQuery(q, [c.case_id, c.title, c.description, c.assignee_name, ...(c.tags || [])]))
          .sort(byNewest('updated_at')).slice(0, limit).map((r) => s.clone(r));
      },
      async insert(row) { return t.insert({ ...CASE_DEFAULTS, ...row }); },
      async remove(id) {
        for (const k of ['case_alerts', 'case_tasks', 'case_iocs', 'case_events']) s.db[k] = s.db[k].filter((r) => r.case_id !== id);
        for (const a of s.db.approvals) if (a.case_id === id) a.case_id = null;
        return t.remove(id);
      }
    };
  }

  get caseAlerts() {
    const s = this;
    return {
      async list(caseId) { return s.db.case_alerts.filter((r) => r.case_id === caseId).sort((a, b) => a.id - b.id).map((r) => s.clone(r)); },
      async forAlert(alertId) { return s.db.case_alerts.filter((r) => r.alert_id === alertId).map((r) => s.clone(r)); },
      async all() { return s.db.case_alerts.map(({ case_id, alert_id }) => ({ case_id, alert_id })); },
      async add(caseId, alertIds, by) {
        const have = new Set(s.db.case_alerts.filter((r) => r.case_id === caseId).map((r) => r.alert_id));
        const known = new Set(s.db.alerts.map((a) => a.alert_id));
        const now = new Date().toISOString();
        const rows = [...new Set(alertIds)].filter((id) => known.has(id) && !have.has(id)).map((alert_id) => ({ id: s.seq.case_alerts++, case_id: caseId, alert_id, added_by: by, added_at: now }));
        s.db.case_alerts.push(...rows);
        s.persist();
        return rows.map((r) => s.clone(r));
      },
      async remove(caseId, alertId) {
        const n = s.db.case_alerts.length;
        s.db.case_alerts = s.db.case_alerts.filter((r) => !(r.case_id === caseId && r.alert_id === alertId));
        s.persist();
        return s.db.case_alerts.length < n;
      }
    };
  }

  get caseTasks() {
    const s = this;
    const t = s.table('case_tasks');
    return {
      ...t,
      async list(caseId) { return t.rows().filter((r) => r.case_id === caseId).sort((a, b) => a.id - b.id).map((r) => s.clone(r)); },
      async all() { return t.rows().map(({ case_id, status }) => ({ case_id, status })); },
      async insert(row) { return t.insert({ phase: null, status: 'TODO', assignee_name: null, due_at: null, done_at: null, ...row }); }
    };
  }

  get caseIocs() {
    const s = this;
    const t = s.table('case_iocs');
    return {
      ...t,
      async list(caseId) { return t.rows().filter((r) => r.case_id === caseId).sort((a, b) => a.id - b.id).map((r) => s.clone(r)); },
      async all({ limit = 5000 } = {}) { return t.rows().slice(-limit).map((r) => s.clone(r)); },
      // Returns null when the case already holds this value.
      async insert(row) {
        if (t.rows().some((r) => r.case_id === row.case_id && r.value === row.value)) return null;
        return t.insert({ note: null, verdict: null, score: null, summary: null, checked_at: null, ...row });
      }
    };
  }

  get caseEvents() {
    const s = this;
    const t = s.table('case_events');
    return {
      async list(caseId) { return t.rows().filter((r) => r.case_id === caseId).sort((a, b) => String(a.occurred_at).localeCompare(String(b.occurred_at)) || a.id - b.id).map((r) => s.clone(r)); },
      async add(row) {
        const now = new Date().toISOString();
        const { updated_at, ...rec } = await t.insert({ title: null, sha256: null, author_id: null, occurred_at: now, ...row });
        return rec;
      }
    };
  }

  get approvals() {
    const s = this;
    const t = s.table('approvals', 'approval_id');
    return {
      ...t,
      async list({ status, limit = 500 } = {}) {
        const want = status ? [].concat(status) : null;
        return t.rows().filter((a) => !want || want.includes(a.status)).sort(byNewest('created_at')).slice(0, limit).map((r) => s.clone(r));
      },
      async count(status = 'PENDING') { return t.rows().filter((a) => a.status === status).length; },
      async insert(row) { return t.insert({ status: 'PENDING', decided_by: null, decided_at: null, decision_note: null, rule_id: null, result: null, ttl_hours: null, alert_id: null, investigation_id: null, case_id: null, confidence: null, ...row }); }
    };
  }

  get hunts() {
    const s = this;
    const t = s.table('hunts', 'hunt_id');
    return {
      ...t,
      async list() { return [...t.rows()].sort(byNewest('updated_at')).map((r) => s.clone(r)); },
      async insert(row) { return t.insert({ technique: null, runs: 0, last_run_at: null, last_hits: null, ...row }); },
      async remove(id) { s.db.hunt_runs = s.db.hunt_runs.filter((r) => r.hunt_id !== id); return t.remove(id); }
    };
  }

  get huntRuns() {
    const s = this;
    const t = s.table('hunt_runs');
    return {
      get: t.get,
      async list({ hunt_id, limit = 50 } = {}) {
        return t.rows().filter((r) => !hunt_id || r.hunt_id === hunt_id).sort(byNewest('created_at')).slice(0, limit)
          .map(({ findings, ...r }) => ({ ...s.clone(r), findings_count: (findings || []).length }));
      },
      async insert(row) {
        const { updated_at, ...rec } = await t.insert(row);
        // Keep the newest 200 runs; findings carry evidence and add up.
        if (t.rows().length > 200) s.db.hunt_runs = [...t.rows()].sort(byNewest('created_at')).slice(0, 200);
        return rec;
      }
    };
  }

  get audit() {
    const s = this;
    return {
      async add(entry) {
        const rec = { id: s.seq.audit++, created_at: new Date().toISOString(), detail: null, ...entry };
        s.db.audit.push(rec);
        if (s.db.audit.length > 5000) s.db.audit.splice(0, s.db.audit.length - 5000);
        s.persist();
        return rec;
      },
      async list(limit = 50) { return [...s.db.audit].sort((a, b) => b.id - a.id).slice(0, limit).map((r) => s.clone(r)); },
      async since({ after = 0, actions, limit = 50 } = {}) {
        const want = new Set(actions);
        return s.db.audit.filter((a) => a.id > (Number(after) || 0) && want.has(a.action)).sort((a, b) => b.id - a.id).slice(0, limit).map((r) => s.clone(r));
      }
    };
  }
}

module.exports = { MemoryStore };