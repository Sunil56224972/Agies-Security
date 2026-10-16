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
    for (const [table, col] of [['alerts', 'alert_id'], ['users', 'id'], ['api_keys', 'id']]) {
      const { error } = await this.sb.from(table).select(col, { head: true, count: 'exact' });
      if (error) throw new Error(`${error.message}. Apply every file in supabase/migrations first.`);
    }
    const { error: colErr } = await this.sb.from('firewall_rules').select('enforcement').limit(1);
    if (colErr) throw new Error(`${colErr.message}. Apply supabase/migrations/20261016010000_real_integrations.sql.`);
    const { count } = await this.sb.from('cves').select('cve_id', { count: 'exact', head: true });
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
    for (const [table, col] of [['firewall_rules', 'rule_id'], ['investigations', 'investigation_id'], ['server_logs', 'id'],
      ['alerts', 'alert_id'], ['assets', 'ip_address'], ['app_config', 'key'], ['audit_log', 'id']]) {
      unwrap(await this.sb.from(table).delete().not(col, 'is', null));
    }
    await this.seedDemo();
  }

  get alerts() {
    const sb = this.sb;
    return {
      async list({ severity, status, q, limit = 500 } = {}) {
        let query = sb.from('alerts').select('*').order('detected_at', { ascending: false }).limit(limit);
        if (severity) query = query.eq('severity', severity);
        if (status) query = query.eq('status', status);
        if (q && safeTerm(q)) {
          const t = safeTerm(q);
          query = query.or(['alert_id', 'signature', 'source_ip', 'dest_ip', 'category', 'sensor'].map((c) => `${c}.ilike.*${t}*`).join(','));
        }
        return unwrap(await query);
      },
      async get(id) { return unwrap(await sb.from('alerts').select('*').eq('alert_id', id).maybeSingle()); },
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
      async list({ host_ip, log_type, client_ip, limit = 50 } = {}) {
        let query = sb.from('server_logs').select('*').order('logged_at', { ascending: false }).limit(limit);
        if (host_ip) query = query.eq('host_ip', host_ip);
        if (log_type) query = query.eq('log_type', log_type);
        if (client_ip) query = query.eq('client_ip', client_ip);
        return unwrap(await query);
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
      async list() { return unwrap(await sb.from('firewall_rules').select('*').order('created_at', { ascending: false }).limit(2000)); },
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
      }
    };
  }

  get investigations() {
    const sb = this.sb;
    return {
      async list() { return unwrap(await sb.from('investigations').select('*').order('created_at', { ascending: false }).limit(500)); },
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

  get audit() {
    const sb = this.sb;
    return {
      async add(entry) { return unwrap(await sb.from('audit_log').insert(entry).select().single()); },
      async list(limit = 50) { return unwrap(await sb.from('audit_log').select('*').order('id', { ascending: false }).limit(limit)); }
    };
  }
}

module.exports = { SupabaseStore };