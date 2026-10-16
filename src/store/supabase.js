'use strict';

const { createClient } = require('@supabase/supabase-js');
const seed = require('../seed');
const { materializeSeed } = require('./shared');

// PostgREST `or()` filters are comma/paren delimited; strip those from user input.
const safeTerm = (q) => String(q).replace(/[,()*%\\]/g, ' ').trim();

function unwrap({ data, error }) {
  if (error) throw new Error(`Supabase: ${error.message}`);
  return data;
}

class SupabaseStore {
  constructor(url, key) {
    this.kind = 'supabase';
    this.label = 'Supabase Postgres';
    this.url = url;
    this.sb = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
  }

  async init() {
    const { count, error } = await this.sb.from('alerts').select('alert_id', { count: 'exact', head: true });
    if (error) {
      throw new Error(`${error.message}. Apply supabase/migrations/*.sql to the project first.`);
    }
    if (!count) await this.seed();
  }

  async seed() {
    const data = materializeSeed(seed);
    unwrap(await this.sb.from('assets').upsert(data.assets));
    unwrap(await this.sb.from('cves').upsert(data.cves));
    unwrap(await this.sb.from('alerts').upsert(data.alerts));
    unwrap(await this.sb.from('server_logs').insert(data.logs.map(({ id, ...l }) => l)));
    unwrap(await this.sb.from('firewall_rules').upsert(data.rules));
    unwrap(await this.sb.from('app_config').upsert({ key: 'platform', value: data.config }));
    unwrap(await this.sb.from('audit_log').insert({ actor: 'system', action: 'sandbox.seeded', target: 'environment', detail: 'Seed telemetry loaded' }));
  }

  async health() {
    const started = Date.now();
    const { error } = await this.sb.from('app_config').select('key').limit(1);
    if (error) return { ok: false, detail: error.message };
    return { ok: true, detail: `${new URL(this.url).host} (${Date.now() - started} ms)` };
  }

  async reset() {
    // Order matters: children before parents.
    for (const [table, col] of [['firewall_rules', 'rule_id'], ['investigations', 'investigation_id'], ['server_logs', 'id'],
      ['alerts', 'alert_id'], ['cves', 'cve_id'], ['assets', 'ip_address'], ['app_config', 'key'], ['audit_log', 'id']]) {
      unwrap(await this.sb.from(table).delete().not(col, 'is', null));
    }
    await this.seed();
  }

  get alerts() {
    const sb = this.sb;
    return {
      async list({ severity, status, q } = {}) {
        let query = sb.from('alerts').select('*').order('detected_at', { ascending: false }).limit(200);
        if (severity) query = query.eq('severity', severity);
        if (status) query = query.eq('status', status);
        if (q && safeTerm(q)) {
          const t = safeTerm(q);
          query = query.or(['alert_id', 'signature', 'source_ip', 'dest_ip', 'category'].map(c => `${c}.ilike.*${t}*`).join(','));
        }
        return unwrap(await query);
      },
      async get(id) { return unwrap(await sb.from('alerts').select('*').eq('alert_id', id).maybeSingle()); },
      async insert(row) { return unwrap(await sb.from('alerts').insert(row).select().single()); },
      async update(id, patch) {
        return unwrap(await sb.from('alerts').update({ ...patch, updated_at: new Date().toISOString() }).eq('alert_id', id).select().maybeSingle());
      }
    };
  }

  get assets() {
    const sb = this.sb;
    return {
      async list() { return unwrap(await sb.from('assets').select('*').order('ip_address')); },
      async get(ip) { return unwrap(await sb.from('assets').select('*').eq('ip_address', ip).maybeSingle()); }
    };
  }

  get cves() {
    const sb = this.sb;
    return {
      async list(q) {
        let query = sb.from('cves').select('*').order('cvss_score', { ascending: false });
        if (q && safeTerm(q)) {
          const t = safeTerm(q);
          query = query.or(['cve_id', 'title', 'description'].map(c => `${c}.ilike.*${t}*`).join(','));
        }
        return unwrap(await query);
      }
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
      }
    };
  }

  get rules() {
    const sb = this.sb;
    return {
      async list() { return unwrap(await sb.from('firewall_rules').select('*').order('created_at', { ascending: false })); },
      async get(id) { return unwrap(await sb.from('firewall_rules').select('*').eq('rule_id', id).maybeSingle()); },
      async activeFor(ip) { return unwrap(await sb.from('firewall_rules').select('*').eq('target_ip', ip).eq('is_active', true)); },
      async insert(row) { return unwrap(await sb.from('firewall_rules').insert(row).select().single()); },
      async update(id, patch) {
        return unwrap(await sb.from('firewall_rules').update({ ...patch, updated_at: new Date().toISOString() }).eq('rule_id', id).select().maybeSingle());
      }
    };
  }

  get investigations() {
    const sb = this.sb;
    return {
      async list() { return unwrap(await sb.from('investigations').select('*').order('created_at', { ascending: false }).limit(100)); },
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

  get audit() {
    const sb = this.sb;
    return {
      async add(entry) { return unwrap(await sb.from('audit_log').insert(entry).select().single()); },
      async list(limit = 50) { return unwrap(await sb.from('audit_log').select('*').order('id', { ascending: false }).limit(limit)); }
    };
  }
}

module.exports = { SupabaseStore };