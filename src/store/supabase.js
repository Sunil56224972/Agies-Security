'use strict';

const { createClient } = require('@supabase/supabase-js');
const seed = require('../seed');
const { materializeSeed, referenceCves, publicUser, publicKey, CLOSED_STATUSES } = require('./shared');

// PostgREST `or()` filters are comma/paren delimited; strip those from user input.
const safeTerm = (q) => String(q).replace(/[,()*%\\]/g, ' ').trim();
const USER_COLS = 'id,email,name,role,disabled,created_at,last_login_at';
const KEY_COLS = 'id,name,prefix,scopes,created_by,created_at,last_used_at,revoked_at';
const chunk = (arr, n) => Array.from({ length: Math.ceil(arr.length / n) }, (_, i) => arr.slice(i * n, i * n + n));

function unwrap({ data, error }) {
  if (error) throw new Error(`Supabase: ${error.message}`);
  return data;
}

// List views skip the bulky columns (payload text, agent transcripts). The
// detail endpoints still read the whole row.
const ALERT_LITE = 'alert_id,signature,category,severity,source_ip,dest_ip,dest_port,protocol,sensor,status,detected_at,updated_at,external_ref,assignee_id,assignee_name,acknowledged_at,resolved_at,suppressed_by';
const INV_LITE = 'investigation_id,alert_id,target_ip,attacker_ip,outcome,confidence,mitre_tactic,mitre_technique,summary,engine,human_override,duration_ms,created_at,updated_at';
const OPEN_STATUSES = ['NEW', 'INVESTIGATING', 'CONFIRMED'];

// PostgREST caps a response at 1000 rows (db-max-rows). The first page also
// returns the exact count, then the remaining pages are fetched a few at a time
// instead of one round trip after another. `make(opts)` builds a fresh, ordered
// query and passes `opts` to select().
const PAGE = 1000;
const PARALLEL = 4;
async function paged(make, limit) {
  const first = await make({ count: limit > PAGE ? 'exact' : undefined }).range(0, Math.min(limit, PAGE) - 1);
  const out = unwrap(first);
  const total = Math.min(limit, first.count == null ? out.length : first.count);
  if (out.length < PAGE || total <= PAGE) return out;
  const starts = [];
  for (let from = PAGE; from < total; from += PAGE) starts.push(from);
  for (let i = 0; i < starts.length; i += PARALLEL) {
    const batch = await Promise.all(starts.slice(i, i + PARALLEL).map((from) => make({}).range(from, Math.min(total, from + PAGE) - 1)));
    for (const r of batch) out.push(...unwrap(r));
  }
  return out;
}

class SupabaseStore {
  constructor(url, key, { demo = false } = {}) {
    this.kind = 'supabase';
    this.label = 'Supabase Postgres';
    this.url = url;
    this.demo = demo;
    this.sb = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
  }

  async init() {
    // Fails fast if either migration is missing.
    // Every probe runs at once; a cold start should cost one round trip, not ten.
    const probe = (table, col) => this.sb.from(table).select(col).limit(1);
    const [base, enf, cases, work, { count }] = await Promise.all([
      Promise.all([['alerts', 'alert_id'], ['users', 'id'], ['api_keys', 'id']].map(([t, c]) => probe(t, c))),
      probe('firewall_rules', 'enforcement'),
      Promise.all([['alert_notes', 'id'], ['suppressions', 'id'], ['firewall_rules', 'expires_at'], ['alerts', 'assignee_id']].map(([t, c]) => probe(t, c))),
      Promise.all([['cases', 'case_id'], ['case_alerts', 'id'], ['case_tasks', 'id'], ['case_iocs', 'id'], ['case_events', 'id'], ['approvals', 'approval_id'], ['hunts', 'hunt_id'], ['hunt_runs', 'id']].map(([t, c]) => probe(t, c))),
      this.sb.from('cves').select('cve_id', { count: 'exact', head: true })
    ]);
    const failed = (list) => list.find((r) => r.error);
    if (failed(base)) throw new Error(`${failed(base).error.message}. Apply every file in supabase/migrations first.`);
    if (enf.error) throw new Error(`${enf.error.message}. Apply supabase/migrations/20261016010000_real_integrations.sql.`);
    if (failed(cases)) throw new Error(`${failed(cases).error.message}. Apply supabase/migrations/20261017000000_cases_tuning_expiry.sql.`);
    // Casework tables are optional at boot: the core console keeps running and
    // /api/cases, /api/approvals and /api/hunts answer 503 until they exist.
    this.pending = failed(work) ? { migration: '20261018000000_cases_approvals_hunts.sql', error: failed(work).error.message } : null;
    if (this.pending) console.warn(`  Casework disabled: ${this.pending.error}. Apply supabase/migrations/${this.pending.migration}.`);
    if (!count) unwrap(await this.sb.from('cves').upsert(referenceCves(seed)));
    if (this.demo) {
      const { count: alerts } = await this.sb.from('alerts').select('alert_id', { count: 'exact', head: true });
      if (!alerts) await this.seedDemo();
    }
  }

  async seedDemo() {
    const data = materializeSeed(seed);
    unwrap(await this.sb.from('assets').upsert(data.assets));
    unwrap(await this.sb.from('cves').upsert(data.cves));
    unwrap(await this.sb.from('alerts').upsert(data.alerts));
    unwrap(await this.sb.from('server_logs').insert(data.logs.map(({ id, ...l }) => l)));
    unwrap(await this.sb.from('firewall_rules').upsert(data.rules));
    unwrap(await this.sb.from('app_config').upsert({ key: 'platform', value: data.config }));
    unwrap(await this.sb.from('audit_log').insert({ actor: 'system', action: 'demo.seeded', target: 'environment', detail: 'Demo dataset loaded' }));
  }

  async health() {
    const started = Date.now();
    const { error } = await this.sb.from('app_config').select('key').limit(1);
    if (error) return { ok: false, detail: error.message };
    return { ok: true, detail: `${new URL(this.url).host} (${Date.now() - started} ms)` };
  }

  async counts() {
    const n = async (t) => (await this.sb.from(t).select('*', { count: 'exact', head: true })).count || 0;
    const [alerts, assets, logs, users] = await Promise.all(['alerts', 'assets', 'server_logs', 'users'].map(n));
    return { alerts, assets, logs, users };
  }

  // Demo reset: wipes telemetry and reloads the demo dataset. Users and API keys stay.
  async reset() {
    for (const [table, col] of [['case_events', 'id'], ['case_iocs', 'id'], ['case_tasks', 'id'], ['case_alerts', 'id'], ['approvals', 'approval_id'], ['cases', 'case_id'], ['hunt_runs', 'id'], ['alert_notes', 'id'], ['firewall_rules', 'rule_id'], ['investigations', 'investigation_id'], ['server_logs', 'id'],
      ['alerts', 'alert_id'], ['assets', 'ip_address'], ['app_config', 'key'], ['audit_log', 'id']]) {
      unwrap(await this.sb.from(table).delete().not(col, 'is', null));
    }
    await this.seedDemo();
  }

  get alerts() {
    const sb = this.sb;
    return {
      async list({ severity, status, statuses, q, ip, assignee, since, lite, limit = 500 } = {}) {
        const make = (opts) => {
          let query = sb.from('alerts').select(lite ? ALERT_LITE : '*', opts).order('detected_at', { ascending: false }).order('alert_id');
          if (severity) query = query.eq('severity', severity);
          if (status) query = query.eq('status', status);
          if (statuses) query = query.in('status', statuses);
          if (since) query = query.gte('detected_at', since);
          if (assignee === 'none') query = query.is('assignee_id', null);
          else if (assignee) query = query.eq('assignee_id', Number(assignee));
          if (ip && safeTerm(ip)) query = query.or(`source_ip.eq.${safeTerm(ip)},dest_ip.eq.${safeTerm(ip)}`);
          if (q && safeTerm(q)) {
            const t = safeTerm(q);
            query = query.or(['alert_id', 'signature', 'source_ip', 'dest_ip', 'category', 'sensor'].map((c) => `${c}.ilike.*${t}*`).join(','));
          }
          return query;
        };
            return paged(make, limit);
      },
      async get(id) { return unwrap(await sb.from('alerts').select('*').eq('alert_id', id).maybeSingle()); },
      async count({ open } = {}) {
        let q = sb.from('alerts').select('alert_id', { count: 'exact', head: true });
        if (open) q = q.in('status', OPEN_STATUSES);
        const { count, error } = await q;
        if (error) throw new Error(`Supabase: ${error.message}`);
        return count || 0;
      },
      async insert(row) { return unwrap(await sb.from('alerts').insert(row).select().single()); },
      async insertMany(rows) {
        const inserted = [];
        for (const part of chunk(rows, 500)) {
          const data = unwrap(await sb.from('alerts').upsert(part, { onConflict: 'alert_id', ignoreDuplicates: true }).select('alert_id'));
          inserted.push(...data.map((r) => r.alert_id));
        }
        return { inserted, duplicates: rows.length - inserted.length };
      },
      async update(id, patch) {
        return unwrap(await sb.from('alerts').update({ ...patch, updated_at: new Date().toISOString() }).eq('alert_id', id).select().maybeSingle());
      },
      async updateMany(ids, patch) {
        const out = [];
        for (const part of chunk(ids, 200)) out.push(...unwrap(await sb.from('alerts').update({ ...patch, updated_at: new Date().toISOString() }).in('alert_id', part).select()));
        return out;
      },
      async purgeClosed(before) {
        // Investigations cascade; firewall rules keep their row with investigation_id set null.
        const data = unwrap(await sb.from('alerts').delete().in('status', CLOSED_STATUSES).lt('updated_at', before).select('alert_id'));
        return data.length;
      }
    };
  }

  get assets() {
    const sb = this.sb;
    return {
      async list() { return unwrap(await sb.from('assets').select('*').order('ip_address').limit(5000)); },
      async get(ip) { return unwrap(await sb.from('assets').select('*').eq('ip_address', ip).maybeSingle()); },
      async upsert(rows) { return unwrap(await sb.from('assets').upsert(rows.map((r) => ({ last_scanned: new Date().toISOString(), ...r }))).select()); },
      async remove(ip) { return unwrap(await sb.from('assets').delete().eq('ip_address', ip).select('ip_address')).length > 0; }
    };
  }

  get cves() {
    const sb = this.sb;
    return {
      async list(q) {
        let query = sb.from('cves').select('*').order('cvss_score', { ascending: false }).limit(2000);
        if (q && safeTerm(q)) {
          const t = safeTerm(q);
          query = query.or(['cve_id', 'title', 'description'].map((c) => `${c}.ilike.*${t}*`).join(','));
        }
        return unwrap(await query);
      },
      async get(id) { return unwrap(await sb.from('cves').select('*').eq('cve_id', id).maybeSingle()); },
      async upsert(rows) { unwrap(await sb.from('cves').upsert(rows)); return rows.length; },
      async remove(id) { return unwrap(await sb.from('cves').delete().eq('cve_id', id).select('cve_id')).length > 0; }
    };
  }

  get logs() {
    const sb = this.sb;
    return {
      async list({ host_ip, log_type, client_ip, since, limit = 50 } = {}) {
        return paged((o) => {
          let query = sb.from('server_logs').select('*', o).order('logged_at', { ascending: false }).order('id', { ascending: false });
          if (host_ip) query = query.eq('host_ip', host_ip);
          if (log_type) query = query.eq('log_type', log_type);
          if (client_ip) query = query.eq('client_ip', client_ip);
          if (since) query = query.gte('logged_at', since);
          return query;
        }, limit);
      },
      async insertMany(rows) {
        for (const part of chunk(rows, 1000)) unwrap(await sb.from('server_logs').insert(part));
        return rows.length;
      },
      async purge(before) {
        return unwrap(await sb.from('server_logs').delete().lt('logged_at', before).select('id')).length;
      }
    };
  }

  get rules() {
    const sb = this.sb;
    return {
      async list({ limit = 5000 } = {}) { return paged((o) => sb.from('firewall_rules').select('*', o).order('created_at', { ascending: false }).order('rule_id'), limit); },
      async get(id) { return unwrap(await sb.from('firewall_rules').select('*').eq('rule_id', id).maybeSingle()); },
      async activeFor(ip) { return unwrap(await sb.from('firewall_rules').select('*').eq('target_ip', ip).eq('is_active', true)); },
      async active(action) {
        let q = sb.from('firewall_rules').select('*').eq('is_active', true).limit(10000);
        if (action) q = q.eq('action', action);
        return unwrap(await q);
      },
      async insert(row) { return unwrap(await sb.from('firewall_rules').insert(row).select().single()); },
      async update(id, patch) {
        return unwrap(await sb.from('firewall_rules').update({ ...patch, updated_at: new Date().toISOString() }).eq('rule_id', id).select().maybeSingle());
      },
      async expiredActive(at) {
        return unwrap(await sb.from('firewall_rules').select('*').eq('is_active', true).not('expires_at', 'is', null).lte('expires_at', at).limit(1000));
      }
    };
  }

  get notes() {
    const sb = this.sb;
    return {
      async list(alertId) { return unwrap(await sb.from('alert_notes').select('*').eq('alert_id', alertId).order('id').limit(1000)); },
      async add(row) { return unwrap(await sb.from('alert_notes').insert(row).select().single()); },
      async addMany(rows) { for (const part of chunk(rows, 500)) unwrap(await sb.from('alert_notes').insert(part)); return rows.length; }
    };
  }

  get suppressions() {
    const sb = this.sb;
    return {
      async list() { return unwrap(await sb.from('suppressions').select('*').order('id', { ascending: false }).limit(1000)); },
      async get(id) { return unwrap(await sb.from('suppressions').select('*').eq('id', Number(id)).maybeSingle()); },
      async insert(row) { return unwrap(await sb.from('suppressions').insert(row).select().single()); },
      async update(id, patch) {
        return unwrap(await sb.from('suppressions').update({ ...patch, updated_at: new Date().toISOString() }).eq('id', Number(id)).select().maybeSingle());
      },
      async remove(id) { return unwrap(await sb.from('suppressions').delete().eq('id', Number(id)).select('id')).length > 0; },
      // Read-modify-write per rule. Hit counters are advisory, so a lost increment
      // under two concurrent ingests is acceptable.
      async recordHits(counts, at) {
        for (const [id, n] of Object.entries(counts)) {
          const row = unwrap(await sb.from('suppressions').select('hits').eq('id', Number(id)).maybeSingle());
          if (row) unwrap(await sb.from('suppressions').update({ hits: row.hits + n, last_hit_at: at }).eq('id', Number(id)));
        }
      }
    };
  }

  get investigations() {
    const sb = this.sb;
    return {
      async list({ since, lite, limit = 500 } = {}) {
        return paged((o) => {
          const q = sb.from('investigations').select(lite ? INV_LITE : '*', o).order('created_at', { ascending: false }).order('investigation_id');
          return since ? q.gte('created_at', since) : q;
        }, limit);
      },
      async forAlert(alertId) {
        return unwrap(await sb.from('investigations').select('*').eq('alert_id', alertId).order('created_at', { ascending: false }).limit(100));
      },
      async forIp(ip, { limit = 50 } = {}) {
        const t = safeTerm(ip);
        return unwrap(await sb.from('investigations').select(INV_LITE).or(`attacker_ip.eq.${t},target_ip.eq.${t}`).order('created_at', { ascending: false }).limit(limit));
      },
      async get(id) { return unwrap(await sb.from('investigations').select('*').eq('investigation_id', id).maybeSingle()); },
      async insert(row) { return unwrap(await sb.from('investigations').insert(row).select().single()); },
      async update(id, patch) {
        return unwrap(await sb.from('investigations').update({ ...patch, updated_at: new Date().toISOString() }).eq('investigation_id', id).select().maybeSingle());
      }
    };
  }

  get config() {
    const sb = this.sb;
    return {
      async get() {
        const row = unwrap(await sb.from('app_config').select('value').eq('key', 'platform').maybeSingle());
        return { ...seed.defaultConfig, ...(row ? row.value : {}) };
      },
      async set(values) {
        const current = await this.get();
        const next = { ...current, ...values };
        unwrap(await sb.from('app_config').upsert({ key: 'platform', value: next, updated_at: new Date().toISOString() }));
        return next;
      }
    };
  }

  get users() {
    const sb = this.sb;
    return {
      async count() { return (await sb.from('users').select('id', { count: 'exact', head: true })).count || 0; },
      async list() { return unwrap(await sb.from('users').select(USER_COLS).order('id')); },
      async byEmail(email) { return unwrap(await sb.from('users').select('*').eq('email', String(email).toLowerCase()).maybeSingle()); },
      async byId(id) { return unwrap(await sb.from('users').select('*').eq('id', Number(id)).maybeSingle()); },
      async insert(row) {
        const { data, error } = await sb.from('users').insert(row).select(USER_COLS).single();
        if (error && /duplicate|unique/i.test(error.message)) throw new Error('A user with that email already exists');
        if (error) throw new Error(`Supabase: ${error.message}`);
        return publicUser(data);
      },
      async update(id, patch) { return publicUser(unwrap(await sb.from('users').update(patch).eq('id', Number(id)).select(USER_COLS).maybeSingle())); }
    };
  }

  get apiKeys() {
    const sb = this.sb;
    return {
      async list() { return unwrap(await sb.from('api_keys').select(KEY_COLS).order('id', { ascending: false })); },
      async byHash(hash) { return unwrap(await sb.from('api_keys').select('*').eq('hash', hash).is('revoked_at', null).maybeSingle()); },
      async insert(row) { return publicKey(unwrap(await sb.from('api_keys').insert(row).select(KEY_COLS).single())); },
      async touch(id) { await sb.from('api_keys').update({ last_used_at: new Date().toISOString() }).eq('id', id); },
      async revoke(id) {
        return publicKey(unwrap(await sb.from('api_keys').update({ revoked_at: new Date().toISOString() }).eq('id', Number(id)).is('revoked_at', null).select(KEY_COLS).maybeSingle()));
      }
    };
  }

  // ---- Cases, approvals and hunts ------------------------------------------
  table(name, key = 'id') {
    const sb = this.sb;
    const k = (id) => (key === 'id' ? Number(id) : id);
    return {
      async get(id) { return unwrap(await sb.from(name).select('*').eq(key, k(id)).maybeSingle()); },
      async insert(row) { return unwrap(await sb.from(name).insert(row).select().single()); },
      async update(id, patch) { return unwrap(await sb.from(name).update({ ...patch, updated_at: new Date().toISOString() }).eq(key, k(id)).select().maybeSingle()); },
      async remove(id) { return unwrap(await sb.from(name).delete().eq(key, k(id)).select(key)).length > 0; }
    };
  }

  get cases() {
    const sb = this.sb;
    const t = this.table('cases', 'case_id');
    return {
      ...t,
      async list({ status, q, limit = 500 } = {}) {
        return paged((o) => {
          let query = sb.from('cases').select('*', o).order('updated_at', { ascending: false }).order('case_id');
          if (status) query = query.in('status', [].concat(status));
          if (q && safeTerm(q)) query = query.or(['case_id', 'title', 'description', 'assignee_name'].map((c) => `${c}.ilike.*${safeTerm(q)}*`).join(','));
          return query;
        }, limit);
      }
    };
  }

  get caseAlerts() {
    const sb = this.sb;
    return {
      async list(caseId) { return unwrap(await sb.from('case_alerts').select('*').eq('case_id', caseId).order('id').limit(5000)); },
      async forAlert(alertId) { return unwrap(await sb.from('case_alerts').select('*').eq('alert_id', alertId).limit(100)); },
      async all() { return paged((o) => sb.from('case_alerts').select('case_id,alert_id', o).order('id'), 50000); },
      async add(caseId, alertIds, by) {
        const ids = [...new Set(alertIds)];
        if (!ids.length) return [];
        const known = [];
        for (const part of chunk(ids, 200)) known.push(...unwrap(await sb.from('alerts').select('alert_id').in('alert_id', part)).map((r) => r.alert_id));
        if (!known.length) return [];
        return unwrap(await sb.from('case_alerts').upsert(known.map((alert_id) => ({ case_id: caseId, alert_id, added_by: by })), { onConflict: 'case_id,alert_id', ignoreDuplicates: true }).select());
      },
      async remove(caseId, alertId) { return unwrap(await sb.from('case_alerts').delete().eq('case_id', caseId).eq('alert_id', alertId).select('id')).length > 0; }
    };
  }

  get caseTasks() {
    const sb = this.sb;
    return {
      ...this.table('case_tasks'),
      async list(caseId) { return unwrap(await sb.from('case_tasks').select('*').eq('case_id', caseId).order('id').limit(1000)); },
      async all() { return paged((o) => sb.from('case_tasks').select('case_id,status', o).order('id'), 50000); }
    };
  }

  get caseIocs() {
    const sb = this.sb;
    return {
      ...this.table('case_iocs'),
      async list(caseId) { return unwrap(await sb.from('case_iocs').select('*').eq('case_id', caseId).order('id').limit(2000)); },
      async all({ limit = 5000 } = {}) { return paged((o) => sb.from('case_iocs').select('*', o).order('id', { ascending: false }), limit); },
      // Returns null when the case already holds this value.
      async insert(row) {
        const data = unwrap(await sb.from('case_iocs').upsert(row, { onConflict: 'case_id,value', ignoreDuplicates: true }).select());
        return data[0] || null;
      }
    };
  }

  get caseEvents() {
    const sb = this.sb;
    return {
      async list(caseId) { return unwrap(await sb.from('case_events').select('*').eq('case_id', caseId).order('occurred_at').order('id').limit(5000)); },
      async add(row) { return unwrap(await sb.from('case_events').insert(row).select().single()); }
    };
  }

  get approvals() {
    const sb = this.sb;
    return {
      ...this.table('approvals', 'approval_id'),
      async list({ status, limit = 500 } = {}) {
        return paged((o) => {
          const q = sb.from('approvals').select('*', o).order('created_at', { ascending: false }).order('approval_id');
          return status ? q.in('status', [].concat(status)) : q;
        }, limit);
      },
      async count(status = 'PENDING') {
        const { count, error } = await sb.from('approvals').select('approval_id', { count: 'exact', head: true }).eq('status', status);
        if (error) throw new Error(`Supabase: ${error.message}`);
        return count || 0;
      }
    };
  }

  get hunts() {
    const sb = this.sb;
    return {
      ...this.table('hunts', 'hunt_id'),
      async list() { return unwrap(await sb.from('hunts').select('*').order('updated_at', { ascending: false }).limit(500)); }
    };
  }

  get huntRuns() {
    const sb = this.sb;
    return {
      get: this.table('hunt_runs').get,
      async list({ hunt_id, limit = 50 } = {}) {
        let q = sb.from('hunt_runs').select('id,hunt_id,name,run_by,hits,new_hits,duration_ms,summary,created_at').order('created_at', { ascending: false }).limit(limit);
        if (hunt_id) q = q.eq('hunt_id', hunt_id);
        return unwrap(await q);
      },
      async insert(row) { return unwrap(await sb.from('hunt_runs').insert(row).select().single()); }
    };
  }

  get audit() {
    const sb = this.sb;
    return {
      async add(entry) { return unwrap(await sb.from('audit_log').insert(entry).select().single()); },
      async list(limit = 50) { return paged((o) => sb.from('audit_log').select('*', o).order('id', { ascending: false }), limit); }
    };
  }
}

module.exports = { SupabaseStore };