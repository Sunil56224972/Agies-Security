'use strict';

// Minimal OpenAI-compatible chat client. Groq, OpenAI, Gemini, Anthropic, OpenRouter,
// Mistral, DeepSeek, Together, Ollama, LM Studio and vLLM all speak this protocol, so
// one client covers every provider an operator can bring a key for.
const crypto = require('crypto');
const net = require('net');
const { isInternal } = require('./analysis');

const PROVIDERS = [
  { id: 'groq', label: 'Groq', base_url: 'https://api.groq.com/openai/v1', model: 'openai/gpt-oss-120b', models: ['openai/gpt-oss-120b', 'openai/gpt-oss-20b', 'llama-3.3-70b-versatile', 'moonshotai/kimi-k2-instruct'], keys_url: 'https://console.groq.com/keys' },
  { id: 'openai', label: 'OpenAI', base_url: 'https://api.openai.com/v1', model: 'gpt-4.1-mini', models: ['gpt-4.1-mini', 'gpt-4.1', 'gpt-4o-mini', 'gpt-4o'], keys_url: 'https://platform.openai.com/api-keys' },
  { id: 'gemini', label: 'Google Gemini', base_url: 'https://generativelanguage.googleapis.com/v1beta/openai', model: 'gemini-2.5-flash', models: ['gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-2.0-flash'], keys_url: 'https://aistudio.google.com/apikey' },
  { id: 'anthropic', label: 'Anthropic', base_url: 'https://api.anthropic.com/v1', model: 'claude-sonnet-4-5', models: ['claude-sonnet-4-5', 'claude-haiku-4-5', 'claude-opus-4-1'], keys_url: 'https://console.anthropic.com/settings/keys' },
  { id: 'openrouter', label: 'OpenRouter', base_url: 'https://openrouter.ai/api/v1', model: 'openai/gpt-4.1-mini', models: ['openai/gpt-4.1-mini', 'anthropic/claude-sonnet-4.5', 'google/gemini-2.5-flash', 'openai/gpt-oss-120b'], keys_url: 'https://openrouter.ai/keys' },
  { id: 'mistral', label: 'Mistral', base_url: 'https://api.mistral.ai/v1', model: 'mistral-large-latest', models: ['mistral-large-latest', 'mistral-medium-latest', 'mistral-small-latest'], keys_url: 'https://console.mistral.ai/api-keys' },
  { id: 'deepseek', label: 'DeepSeek', base_url: 'https://api.deepseek.com/v1', model: 'deepseek-chat', models: ['deepseek-chat'], keys_url: 'https://platform.deepseek.com/api_keys' },
  { id: 'together', label: 'Together AI', base_url: 'https://api.together.xyz/v1', model: 'meta-llama/Llama-3.3-70B-Instruct-Turbo', models: ['meta-llama/Llama-3.3-70B-Instruct-Turbo', 'Qwen/Qwen2.5-72B-Instruct-Turbo'], keys_url: 'https://api.together.ai/settings/api-keys' },
  { id: 'ollama', label: 'Ollama (self-hosted)', base_url: 'http://localhost:11434/v1', model: 'llama3.1', models: ['llama3.1', 'qwen2.5', 'mistral-nemo'], keys_url: null, keyless: true },
  { id: 'custom', label: 'Other OpenAI-compatible', base_url: '', model: '', models: [], keys_url: null, keyless: true }
];
const PRESET = new Map(PROVIDERS.map((p) => [p.id, p]));
const GROQ_URL = PRESET.get('groq').base_url;

class LlmError extends Error {
  constructor(message, status = 0) { super(message); this.status = status; }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function errorText(body, status) {
  try {
    const j = JSON.parse(body);
    const e = Array.isArray(j) ? j[0] && j[0].error : j.error;
    const m = e && (e.message || (typeof e === 'string' ? e : null));
    if (m) return String(m);
  } catch { /* not JSON */ }
  return String(body || `HTTP ${status}`).replace(/\s+/g, ' ').slice(0, 300);
}

// Returns an object shaped like the official SDKs: client.chat.completions.create(req).
function createClient({ baseUrl, apiKey = '', timeoutMs = 25000, retries = 1, fetchImpl = fetch } = {}) {
  const url = `${String(baseUrl).replace(/\/+$/, '')}/chat/completions`;
  // Some models reject max_tokens or a custom temperature; learn that once per client.
  const quirks = { maxCompletion: false, noTemperature: false };

  function shape(req) {
    const body = { ...req };
    if (quirks.maxCompletion && body.max_tokens !== undefined) { body.max_completion_tokens = body.max_tokens; delete body.max_tokens; }
    if (quirks.noTemperature) delete body.temperature;
    return body;
  }

  async function send(req) {
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
    let res;
    try {
      res = await fetchImpl(url, { method: 'POST', headers, body: JSON.stringify(shape(req)), signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
    } catch (err) {
      const timeout = err && (err.name === 'TimeoutError' || err.name === 'AbortError');
      throw new LlmError(timeout ? `No answer within ${Math.round(timeoutMs / 1000)} s` : `Could not reach ${new URL(url).host}: ${(err.cause && err.cause.message) || err.message}`, 0);
    }
    const text = await res.text();
    if (!res.ok) {
      const e = new LlmError(errorText(text, res.status), res.status);
      e.retryAfter = Number(res.headers.get('retry-after')) || 0;
      throw e;
    }
    let json;
    try { json = JSON.parse(text); } catch { throw new LlmError('The provider answered with something other than JSON', 502); }
    if (!json || !Array.isArray(json.choices) || !json.choices[0] || !json.choices[0].message) throw new LlmError(`Unexpected response: ${errorText(text, res.status)}`, 502);
    return json;
  }

  async function create(req) {
    for (let attempt = 0; ; attempt += 1) {
      try { return await send(req); } catch (err) {
        if (err.status === 400 && !quirks.maxCompletion && /max_tokens/i.test(err.message) && /max_completion_tokens|not supported|unsupported/i.test(err.message)) { quirks.maxCompletion = true; continue; }
        if (err.status === 400 && !quirks.noTemperature && /temperature/i.test(err.message)) { quirks.noTemperature = true; continue; }
        const transient = err.status === 0 || err.status === 429 || err.status >= 500;
        if (!transient || attempt >= retries || /No answer within/.test(err.message)) throw err;
        await sleep(Math.min(3000, (err.retryAfter || 0) * 1000 || 800));
      }
    }
  }

  return { chat: { completions: { create } } };
}

// gpt-oss models think by default; low effort keeps tool loops fast.
const extras = (model) => (/gpt-oss/.test(String(model)) ? { reasoning_effort: 'low' } : {});

// ---- Key sealing: AES-256-GCM under a key derived from the session secret ------------------
const sealKey = (secret) => Buffer.from(crypto.hkdfSync('sha256', Buffer.from(String(secret)), Buffer.from('aegis'), Buffer.from('llm-provider-key'), 32));
function seal(secret, plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', sealKey(secret), iv);
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return ['v1', iv.toString('base64url'), c.getAuthTag().toString('base64url'), ct.toString('base64url')].join(':');
}
function unseal(secret, sealed) {
  const [v, iv, tag, ct] = String(sealed || '').split(':');
  if (v !== 'v1' || !iv || !tag || ct === undefined) throw new Error('Unknown key format');
  const d = crypto.createDecipheriv('aes-256-gcm', sealKey(secret), Buffer.from(iv, 'base64url'));
  d.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]).toString('utf8');
}
const hint = (key) => (key ? `${key.slice(0, 4)}...${key.slice(-4)}` : null);

// Validates an operator-supplied provider. Private and plain-http endpoints (a local
// Ollama) are allowed on a workstation but refused in production, where the server
// would otherwise become a proxy into its own network.
function validateProvider(b, { production = false, existing = null } = {}) {
  const preset = PRESET.get(String(b.provider || ''));
  if (!preset) return { error: `Provider must be one of ${PROVIDERS.map((p) => p.id).join(', ')}` };
  const base = String(b.base_url || preset.base_url || '').trim().replace(/\/+$/, '');
  if (!base) return { error: 'Enter the base URL of the OpenAI-compatible API (it ends before /chat/completions)' };
  let u;
  try { u = new URL(base); } catch { return { error: 'Base URL is not a valid URL' }; }
  if (!['https:', 'http:'].includes(u.protocol)) return { error: 'Base URL must start with https://' };
  if (u.username || u.password) return { error: 'Put the key in the API key field, not in the URL' };
  if (/\/chat\/completions$/.test(u.pathname)) return { error: 'Leave /chat/completions off the base URL' };
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (production) {
    if (u.protocol !== 'https:') return { error: 'Base URL must use https on a production server' };
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local') || (net.isIP(host) && (isInternal(host) || /^(0\.|169\.254\.)/.test(host) || host === '::')))
      return { error: 'Base URL points at a private address; a production server will not call it' };
  }
  const model = String(b.model || '').trim();
  if (!model || model.length > 120 || /\s/.test(model)) return { error: 'Enter a model id, for example gpt-4.1-mini' };
  let key = typeof b.api_key === 'string' ? b.api_key.trim() : '';
  if (key.length > 400 || /\s/.test(key)) return { error: 'That API key does not look right' };
  let keep = false;
  if (!key && existing && existing.key_enc && existing.base_url === base) keep = true;
  if (!key && !keep && !preset.keyless) return { error: `Paste your ${preset.label} API key` };
  return { provider: { provider: preset.id, label: preset.id === 'custom' ? (host || 'Custom') : preset.label, base_url: base, model }, key, keep };
}

// A tiny request that also proves the endpoint accepts tool definitions.
async function probe(client, model) {
  const started = Date.now();
  const res = await client.chat.completions.create({
    model, temperature: 0, max_tokens: 64, tool_choice: 'auto', ...extras(model),
    messages: [{ role: 'system', content: 'You are a connectivity check. Reply with the single word OK.' }, { role: 'user', content: 'Reply OK.' }],
    tools: [{ type: 'function', function: { name: 'noop', description: 'Does nothing. Do not call it.', parameters: { type: 'object', properties: {} } } }]
  });
  return { ms: Date.now() - started, model: res.model || model, reply: String(res.choices[0].message.content || '').trim().slice(0, 60) };
}

module.exports = { PROVIDERS, PRESET, GROQ_URL, LlmError, createClient, extras, seal, unseal, hint, validateProvider, probe };