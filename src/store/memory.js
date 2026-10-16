'use strict';

const fs = require('fs');
const path = require('path');
const seed = require('../seed');
const { materializeSeed, emptyState, matchesQuery, publicUser, publicKey, applyLifecycle, ALERT_DEFAULTS, CLOSED_STATUSES } = require('./shared');
const OPEN_STATUSES = ['NEW', 'INVESTIGATING', 'CONFIRMED'];

// File-backed store used when Supabase credentials are absent. Good for a
// single-node install or evaluation; use Supabase for anything shared.
const DEFAULT_FILE = path.join(__dirname, '..', '..', '.data', 'aegis.json');
const LOG_CAP = 50000;

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
    for (const k of ['users', 'api_keys', 'audit', 'logs', 'rules', 'investigations', 'assets', 'cves', 'alert_notes', 'suppressions']) if (!Array.isArray(this.db[k])) this.db[k] = [];
    this.seq = {
      log: Math.max(0, ...this.db.logs.map((l) => l.id)) + 1,
      audit: Math.max(0, ...this.db.audit.map((a) => a.id)) + 1,
      user: Math.max(0, ...this.db.users.map((u) => u.id)) + 1,
      key: Math.max(0, ...this.db.api_keys.map((k) => k.id)) + 1,
      note: Math.max(0, ...this.db.alert_notes.map((n) => n.id)) + 1,
      supp: Math.max(0, ...this.db.suppressions.map((x) => x.id)) + 1
    };
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
    const keep = { users: this.db.users, api_keys: this.db.api_keys, suppressions: this.db.suppressions };
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
      async list({ host_ip, log_type, client_ip, limit = 50 } = {}) {
        return s.db.logs
          .filter((l) => (!host_ip || l.host_ip === host_ip) && (!log_type || l.log_type === log_type) && (!client_ip || l.client_ip === client_ip))
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
      async list(limit = 50) { return [...s.db.audit].sort((a, b) => b.id - a.id).slice(0, limit).map((r) => s.clone(r)); }
    };
  }
}

module.exports = { MemoryStore };