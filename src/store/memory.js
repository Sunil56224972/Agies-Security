'use strict';

const fs = require('fs');
const path = require('path');
const seed = require('../seed');
const { materializeSeed, matchesQuery } = require('./shared');

// File-backed sandbox used when Supabase credentials are absent. State is
// written to .data/sandbox.json so local demos survive a restart.
const DATA_FILE = path.join(__dirname, '..', '..', '.data', 'sandbox.json');

class MemoryStore {
  constructor() {
    this.kind = 'local';
    this.label = 'Local sandbox';
    this.db = null;
    this.saveTimer = null;
    this.logSeq = 1;
    this.auditSeq = 1;
  }

  async init() {
    try {
      if (fs.existsSync(DATA_FILE)) {
        this.db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      }
    } catch (err) {
      console.warn('  Local sandbox file unreadable, reseeding:', err.message);
    }
    if (!this.db || !this.db.alerts) this.db = materializeSeed(seed);
    this.logSeq = Math.max(0, ...this.db.logs.map(l => l.id)) + 1;
    this.auditSeq = Math.max(0, ...this.db.audit.map(a => a.id)) + 1;
    this.persist();
  }

  persist() {
    clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => {
      try {
        fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
        fs.writeFileSync(DATA_FILE, JSON.stringify(this.db, null, 2));
      } catch (err) {
        console.warn('  Could not persist local sandbox:', err.message);
      }
    }, 150);
  }

  async health() {
    return { ok: true, detail: 'File-backed sandbox (.data/sandbox.json)' };
  }

  async reset() {
    this.db = materializeSeed(seed);
    this.persist();
  }

  // Shallow copies keep callers from mutating stored rows by accident.
  clone(row) { return row ? JSON.parse(JSON.stringify(row)) : null; }
  touch(row, patch) {
    Object.assign(row, patch, { updated_at: new Date().toISOString() });
    this.persist();
    return this.clone(row);
  }

  get alerts() {
    const s = this;
    return {
      async list({ severity, status, q } = {}) {
        return s.db.alerts
          .filter(a => (!severity || a.severity === severity) && (!status || a.status === status))
          .filter(a => matchesQuery(q, [a.alert_id, a.signature, a.source_ip, a.dest_ip, a.category]))
          .sort((a, b) => b.detected_at.localeCompare(a.detected_at))
          .map(r => s.clone(r));
      },
      async get(id) { return s.clone(s.db.alerts.find(a => a.alert_id === id)); },
      async insert(row) {
        const now = new Date().toISOString();
        const rec = { detected_at: now, updated_at: now, status: 'NEW', ...row };
        s.db.alerts.push(rec);
        s.persist();
        return s.clone(rec);
      },
      async update(id, patch) {
        const row = s.db.alerts.find(a => a.alert_id === id);
        return row ? s.touch(row, patch) : null;
      }
    };
  }

  get assets() {
    const s = this;
    return {
      async list() { return [...s.db.assets].sort((a, b) => a.ip_address.localeCompare(b.ip_address, undefined, { numeric: true })).map(r => s.clone(r)); },
      async get(ip) { return s.clone(s.db.assets.find(a => a.ip_address === ip)); }
    };
  }

  get cves() {
    const s = this;
    return {
      async list(q) {
        return s.db.cves
          .filter(c => matchesQuery(q, [c.cve_id, c.title, c.description, ...(c.affected_products || []), ...(c.match_terms || [])]))
          .sort((a, b) => b.cvss_score - a.cvss_score)
          .map(r => s.clone(r));
      }
    };
  }

  get logs() {
    const s = this;
    return {
      async list({ host_ip, log_type, client_ip, limit = 50 } = {}) {
        return s.db.logs
          .filter(l => (!host_ip || l.host_ip === host_ip) && (!log_type || l.log_type === log_type) && (!client_ip || l.client_ip === client_ip))
          .sort((a, b) => b.logged_at.localeCompare(a.logged_at))
          .slice(0, limit)
          .map(r => s.clone(r));
      }
    };
  }

  get rules() {
    const s = this;
    return {
      async list() { return [...s.db.rules].sort((a, b) => b.created_at.localeCompare(a.created_at)).map(r => s.clone(r)); },
      async get(id) { return s.clone(s.db.rules.find(r => r.rule_id === id)); },
      async activeFor(ip) { return s.db.rules.filter(r => r.target_ip === ip && r.is_active).map(r => s.clone(r)); },
      async insert(row) {
        const now = new Date().toISOString();
        const rec = { created_at: now, updated_at: now, is_active: true, packets_dropped: 0, investigation_id: null, ...row };
        s.db.rules.push(rec);
        s.persist();
        return s.clone(rec);
      },
      async update(id, patch) {
        const row = s.db.rules.find(r => r.rule_id === id);
        return row ? s.touch(row, patch) : null;
      }
    };
  }

  get investigations() {
    const s = this;
    return {
      async list() { return [...s.db.investigations].sort((a, b) => b.created_at.localeCompare(a.created_at)).map(r => s.clone(r)); },
      async get(id) { return s.clone(s.db.investigations.find(i => i.investigation_id === id)); },
      async insert(row) {
        const now = new Date().toISOString();
        const rec = { created_at: now, updated_at: now, human_override: null, ...row };
        s.db.investigations.push(rec);
        s.persist();
        return s.clone(rec);
      },
      async update(id, patch) {
        const row = s.db.investigations.find(i => i.investigation_id === id);
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

  get audit() {
    const s = this;
    return {
      async add(entry) {
        const rec = { id: s.auditSeq++, created_at: new Date().toISOString(), detail: null, ...entry };
        s.db.audit.push(rec);
        if (s.db.audit.length > 500) s.db.audit.splice(0, s.db.audit.length - 500);
        s.persist();
        return rec;
      },
      async list(limit = 50) { return [...s.db.audit].sort((a, b) => b.id - a.id).slice(0, limit).map(r => s.clone(r)); }
    };
  }
}

module.exports = { MemoryStore };