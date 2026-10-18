'use strict';

// Bring-your-own language model: an administrator connects any OpenAI-compatible
// provider with their own key. The key is sealed with AES-256-GCM before it reaches
// the config store and is never sent back to a browser, an export or a backup.
const llm = require('./engine/llm');

const masked = (p) => (p && p.base_url ? {
  provider: p.provider, label: p.label, base_url: p.base_url, model: p.model,
  has_key: Boolean(p.key_enc), key_hint: p.key_hint || null, updated_by: p.updated_by || null, updated_at: p.updated_at || null
} : null);

function registerLlm(app, ctx) {
  const { store, investigator, env, secret, wrap, bad, need, actor } = ctx;
  const production = env.NODE_ENV === 'production';

  // Resolves the request into a client: a pasted key, or the saved one when the
  // operator only changes the model.
  async function prepare(body) {
    const saved = (await store.config.get()).llmProvider || null;
    const v = llm.validateProvider(body || {}, { production, existing: saved });
    if (v.error) return v;
    let key = v.key;
    if (v.keep) {
      try { key = llm.unseal(secret, saved.key_enc); } catch { return { error: 'The saved key can no longer be read; paste it again' }; }
    }
    return { ...v, key, client: llm.createClient({ baseUrl: v.provider.base_url, apiKey: key, timeoutMs: 20000, retries: 0 }), saved };
  }

  async function check(v) {
    try { return { ok: true, ...(await llm.probe(v.client, v.provider.model)) }; } catch (err) {
      const s = err.status;
      const why = s === 401 || s === 403 ? 'The provider rejected the API key'
        : s === 404 ? `The provider does not know the model ${v.provider.model}, or the base URL is wrong`
        : s === 429 ? 'Rate limit or quota reached on this key'
        : s === 400 && /tool/i.test(err.message) ? `The model ${v.provider.model} does not support tool calling, which Aegis needs`
        : 'The provider did not accept the request';
      return { ok: false, status: s || null, error: `${why}: ${String(err.message).slice(0, 240)}` };
    }
  }

  app.get('/api/llm', need('configure'), wrap(async (req, res) => {
    const cfg = await store.config.get();
    res.json({
      active: await investigator.llmStatus(),
      saved: masked(cfg.llmProvider),
      server_default: env.GROQ_API_KEY ? { provider: 'Groq', model: env.GROQ_MODEL || 'openai/gpt-oss-120b' } : null,
      providers: llm.PROVIDERS,
      production
    });
  }));

  app.post('/api/llm/test', need('configure'), wrap(async (req, res) => {
    const v = await prepare(req.body);
    if (v.error) return bad(res, v.error);
    const r = await check(v);
    await store.audit.add({ actor: actor(req), action: 'llm.tested', target: `${v.provider.provider}:${v.provider.model}`, detail: r.ok ? `ok ${r.ms}ms` : String(r.error).slice(0, 200) });
    res.json(r);
  }));

  app.put('/api/llm', need('configure'), wrap(async (req, res) => {
    const v = await prepare(req.body);
    if (v.error) return bad(res, v.error);
    // Never save a provider that cannot answer: a broken key would silently push
    // every investigation onto the playbook.
    const r = await check(v);
    if (!r.ok) return bad(res, r.error, 422);
    const record = {
      ...v.provider,
      key_enc: v.key ? llm.seal(secret, v.key) : null,
      key_hint: v.key ? llm.hint(v.key) : null,
      updated_by: actor(req), updated_at: new Date().toISOString()
    };
    await store.config.set({ llmProvider: record });
    investigator.forget();
    await store.audit.add({ actor: actor(req), action: 'llm.connected', target: `${record.provider}:${record.model}`, detail: `${new URL(record.base_url).host}${record.key_hint ? ` key ${record.key_hint}` : ' no key'}; test ${r.ms}ms` });
    res.json({ saved: masked(record), active: await investigator.llmStatus(), test: r });
  }));

  app.delete('/api/llm', need('configure'), wrap(async (req, res) => {
    const cfg = await store.config.get();
    if (!cfg.llmProvider) return bad(res, 'No provider is connected', 404);
    await store.config.set({ llmProvider: null });
    investigator.forget();
    await store.audit.add({ actor: actor(req), action: 'llm.removed', target: `${cfg.llmProvider.provider}:${cfg.llmProvider.model}`, detail: env.GROQ_API_KEY ? 'reverted to the server default' : 'no model configured' });
    res.json({ saved: null, active: await investigator.llmStatus() });
  }));
}

module.exports = { registerLlm };