'use strict';

// Threat-intel API keys an administrator manages from Settings instead of the
// server environment. Keys are sealed with AES-256-GCM (same scheme as the LLM
// key), validated against the provider before they are saved, never returned to
// a browser, and picked up by every server instance within KEY_TTL_MS, so a
// multi-node or serverless deployment does not need a redeploy to rotate a key.
// A key saved here overrides the matching environment variable; removing it
// falls back to the environment again.

const { seal, unseal, hint } = require('../engine/llm');
const { httpGet, errText } = require('./feeds');

const KEY_TTL_MS = 30000;

const PROVIDERS = [
  { id: 'vt', label: 'VirusTotal', env: 'VT_API_KEY', keys_url: 'https://www.virustotal.com/gui/my-apikey', help: '70+ antivirus and URL engines for IPs, domains, URLs and file hashes.' },
  { id: 'abusech', label: 'abuse.ch', env: 'ABUSECH_AUTH_KEY', keys_url: 'https://auth.abuse.ch/', help: 'One Auth-Key unlocks ThreatFox, URLhaus and MalwareBazaar exports and live lookups.' },
  { id: 'abuseipdb', label: 'AbuseIPDB', env: 'ABUSEIPDB_API_KEY', keys_url: 'https://www.abuseipdb.com/account/api', help: 'Community abuse reports and confidence score for IP addresses.' },
  { id: 'otx', label: 'AlienVault OTX', env: 'OTX_API_KEY', keys_url: 'https://otx.alienvault.com/api', help: 'Pulses, malware families and adversaries; works keyless at a lower rate limit.' },
  { id: 'ha', label: 'Hybrid Analysis', env: 'HYBRID_ANALYSIS_API_KEY', keys_url: 'https://hybrid-analysis.com/my-account?tab=%23api-key-tab', help: 'Falcon Sandbox verdicts and threat scores for file hashes.' }
];
const BY_ID = new Map(PROVIDERS.map((p) => [p.id, p]));

const KEY_RE = /^[\x21-\x7e]{8,200}$/;

// One real, cheap call per provider. Returns { ok, ms, detail } or { ok:false, status, error }.
async function testKey(id, key, fetchImpl = globalThis.fetch) {
  const t0 = Date.now();
  const done = (detail) => ({ ok: true, ms: Date.now() - t0, detail });
  const fail = (status, error) => ({ ok: false, status: status || null, error });
  try {
    if (id === 'vt') {
      // /users/{apikey} reads the key's own account and does not count against the lookup quota.
      const res = await httpGet(fetchImpl, `https://www.virustotal.com/api/v3/users/${encodeURIComponent(key)}`, { timeoutMs: 12000, headers: { 'x-apikey': key, Accept: 'application/json' } });
      if (res.status === 401 || res.status === 403) return fail(res.status, 'VirusTotal rejected the key');
      if (res.status === 429) return fail(429, 'VirusTotal quota exhausted for this key right now');
      if (!res.ok) return fail(res.status, `VirusTotal answered HTTP ${res.status}`);
      const a = ((await res.json()).data || {}).attributes || {};
      const q = a.quotas || {};
      const day = q.api_requests_daily ? ` Daily quota ${q.api_requests_daily.allowed}${q.api_requests_daily.used != null ? `, used ${q.api_requests_daily.used}` : ''}.` : '';
      return done(`Key accepted.${day}`);
    }
    if (id === 'abusech') {
      const res = await httpGet(fetchImpl, 'https://threatfox-api.abuse.ch/api/v1/', { method: 'POST', timeoutMs: 15000, headers: { 'Auth-Key': key, 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ query: 'get_iocs', days: 1 }) });
      if (res.status === 401 || res.status === 403) return fail(res.status, 'abuse.ch rejected the Auth-Key');
      if (!res.ok) return fail(res.status, `abuse.ch answered HTTP ${res.status}`);
      const j = await res.json().catch(() => ({}));
      if (j.query_status && !['ok', 'no_result', 'no_results'].includes(j.query_status)) return fail(null, `abuse.ch: ${j.query_status}`);
      return done(`Auth-Key accepted. ThreatFox returned ${Array.isArray(j.data) ? j.data.length : 0} IOCs from the last 24 hours.`);
    }
    if (id === 'abuseipdb') {
      const res = await httpGet(fetchImpl, 'https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=30', { timeoutMs: 12000, headers: { Key: key, Accept: 'application/json' } });
      if (res.status === 401 || res.status === 403) return fail(res.status, 'AbuseIPDB rejected the key');
      if (res.status === 429) return fail(429, 'AbuseIPDB daily limit reached for this key');
      if (!res.ok) return fail(res.status, `AbuseIPDB answered HTTP ${res.status}`);
      const left = res.headers.get('x-ratelimit-remaining');
      return done(`Key accepted.${left ? ` ${left} checks left today.` : ''}`);
    }
    if (id === 'otx') {
      const res = await httpGet(fetchImpl, 'https://otx.alienvault.com/api/v1/user/me', { timeoutMs: 12000, headers: { 'X-OTX-API-KEY': key, Accept: 'application/json' } });
      if (res.status === 401 || res.status === 403) return fail(res.status, 'OTX rejected the key');
      if (!res.ok) return fail(res.status, `OTX answered HTTP ${res.status}`);
      const j = await res.json().catch(() => ({}));
      return done(`Key accepted${j.username ? ` for ${j.username}` : ''}.`);
    }
    if (id === 'ha') {
      const res = await httpGet(fetchImpl, 'https://hybrid-analysis.com/api/v2/key/current', { timeoutMs: 12000, headers: { 'api-key': key, 'User-Agent': 'Falcon Sandbox', Accept: 'application/json' } });
      if (res.status === 401 || res.status === 403) return fail(res.status, 'Hybrid Analysis rejected the key');
      if (!res.ok) return fail(res.status, `Hybrid Analysis answered HTTP ${res.status}`);
      const j = await res.json().catch(() => ({}));
      return done(`Key accepted${j.auth_level_name ? ` (${j.auth_level_name})` : ''}.`);
    }
    return fail(null, `Unknown provider ${id}`);
  } catch (err) {
    return fail(null, `Could not reach the provider: ${errText(err)}`);
  }
}

class IntelKeys {
  constructor({ store, secret, env = process.env, hub = null, reputation = null, fetchImpl = globalThis.fetch }) {
    this.store = store; this.secret = secret; this.env = env;
    this.hub = hub; this.reputation = reputation; this.fetch = fetchImpl;
    this.loadedAt = 0; this.inflight = null;
    this.saved = {};      // id -> sealed record from the config store
    this.active = {};     // id -> { source, key }
    this.errors = {};     // id -> unseal problem
    this.apply();
    if (hub) hub.beforeUse = () => this.sync();
    if (reputation) reputation.beforeUse = () => this.sync();
  }

  // Reloads saved keys at most every KEY_TTL_MS (or now, when forced).
  async sync(force = false) {
    if (!force && Date.now() - this.loadedAt < KEY_TTL_MS) return this.active;
    if (this.inflight) return this.inflight;
    this.inflight = (async () => {
      try {
        const cfg = await this.store.config.get();
        this.saved = (cfg && cfg.intelKeys) || {};
        this.loadedAt = Date.now();
        this.apply();
      } catch { this.loadedAt = Date.now() - KEY_TTL_MS + 5000; /* retry soon; keep current keys */ }
      finally { this.inflight = null; }
      return this.active;
    })();
    return this.inflight;
  }

  // Resolves settings-over-environment and pushes the result into the clients.
  apply() {
    const active = {}; const errors = {};
    for (const p of PROVIDERS) {
      const rec = this.saved[p.id];
      let key = null; let source = null;
      if (rec && rec.key_enc) {
        try { key = unseal(this.secret, rec.key_enc); source = 'settings'; } catch { errors[p.id] = 'The saved key can no longer be decrypted (SESSION_SECRET changed); paste it again'; }
      }
      if (!key && this.env[p.env]) { key = String(this.env[p.env]).trim(); source = 'env'; }
      active[p.id] = { key, source };
    }
    this.active = active; this.errors = errors;
    const h = this.hub;
    if (h) {
      if (h.vt && h.vt.setKey) h.vt.setKey(active.vt.key);
      if (h.abusech && h.abusech.setKey) { if (h.abusech.setKey(active.abusech.key) && active.abusech.key) h.abusech.warm(); }
      if (h.otx && h.otx.setKey) h.otx.setKey(active.otx.key);
      if (h.ha && h.ha.setKey) h.ha.setKey(active.ha.key);
    }
    if (this.reputation && this.reputation.setAbuseKey) this.reputation.setAbuseKey(active.abuseipdb.key);
  }

  has(id) { return Boolean(this.active[id] && this.active[id].key); }

  list() {
    return PROVIDERS.map((p) => {
      const rec = this.saved[p.id] || null;
      const a = this.active[p.id] || {};
      return {
        id: p.id, label: p.label, env: p.env, keys_url: p.keys_url, help: p.help,
        connected: Boolean(a.key), source: a.source || null,
        key_hint: a.source === 'settings' ? (rec && rec.key_hint) || null : a.source === 'env' ? hint(a.key) : null,
        saved: Boolean(rec && rec.key_enc), env_set: Boolean(this.env[p.env]),
        updated_by: rec ? rec.updated_by || null : null, updated_at: rec ? rec.updated_at || null : null,
        last_test: rec ? rec.last_test || null : null, error: this.errors[p.id] || null
      };
    });
  }

  provider(id) { return BY_ID.get(id) || null; }
  test(id, key) { return testKey(id, key, this.fetch); }

  async save(id, key, actor, test) {
    const cfg = await this.store.config.get();
    const all = { ...((cfg && cfg.intelKeys) || {}) };
    all[id] = { key_enc: seal(this.secret, key), key_hint: hint(key), updated_by: actor, updated_at: new Date().toISOString(), last_test: { ok: true, at: new Date().toISOString(), detail: test.detail } };
    await this.store.config.set({ intelKeys: all });
    await this.sync(true);
  }

  async remove(id) {
    const cfg = await this.store.config.get();
    const all = { ...((cfg && cfg.intelKeys) || {}) };
    if (!all[id]) return false;
    delete all[id];
    await this.store.config.set({ intelKeys: all });
    await this.sync(true);
    return true;
  }
}

function registerIntelKeys(app, ctx) {
  const { intelKeys, wrap, bad, need, actor, store } = ctx;

  app.get('/api/intel/keys', need('configure'), wrap(async (req, res) => {
    await intelKeys.sync(true);
    res.json({ providers: intelKeys.list() });
  }));

  // Tests a pasted key, or the key currently in use when none is pasted.
  app.post('/api/intel/keys/:id/test', need('configure'), wrap(async (req, res) => {
    const p = intelKeys.provider(req.params.id);
    if (!p) return bad(res, 'Unknown provider', 404);
    await intelKeys.sync(true);
    const pasted = String((req.body && req.body.key) || '').trim();
    const key = pasted || (intelKeys.active[p.id] && intelKeys.active[p.id].key);
    if (!key) return bad(res, `No ${p.label} key to test; paste one first`);
    if (pasted && !KEY_RE.test(pasted)) return bad(res, 'That does not look like an API key');
    const r = await intelKeys.test(p.id, key);
    await store.audit.add({ actor: actor(req), action: 'intel_key.tested', target: p.label, detail: r.ok ? `ok ${r.ms}ms` : String(r.error).slice(0, 200) });
    res.json(r);
  }));

  app.put('/api/intel/keys/:id', need('configure'), wrap(async (req, res) => {
    const p = intelKeys.provider(req.params.id);
    if (!p) return bad(res, 'Unknown provider', 404);
    const key = String((req.body && req.body.key) || '').trim();
    if (!KEY_RE.test(key)) return bad(res, 'Paste the API key (8 to 200 printable characters, no spaces)');
    // Never save a key the provider refuses: it would quietly turn the source off.
    const r = await intelKeys.test(p.id, key);
    if (!r.ok) return bad(res, r.error, 422);
    await intelKeys.save(p.id, key, actor(req), r);
    await store.audit.add({ actor: actor(req), action: 'intel_key.saved', target: p.label, detail: `key ${hint(key)}; test ${r.ms}ms` });
    res.json({ provider: intelKeys.list().find((x) => x.id === p.id), test: r });
  }));

  app.delete('/api/intel/keys/:id', need('configure'), wrap(async (req, res) => {
    const p = intelKeys.provider(req.params.id);
    if (!p) return bad(res, 'Unknown provider', 404);
    if (!(await intelKeys.remove(p.id))) return bad(res, `No ${p.label} key is saved in Settings`, 404);
    await store.audit.add({ actor: actor(req), action: 'intel_key.removed', target: p.label, detail: intelKeys.has(p.id) ? `falling back to ${p.env}` : 'source off' });
    res.json({ provider: intelKeys.list().find((x) => x.id === p.id) });
  }));
}

module.exports = { IntelKeys, registerIntelKeys, testKey, PROVIDERS };
