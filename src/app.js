'use strict';

const path = require('path');
const express = require('express');
const { Investigator } = require('./engine/investigator');
const auth = require('./security/auth');
const { registerRoutes } = require('./routes');

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PUBLIC_API = new Set(['/health', '/auth/state', '/auth/login', '/auth/setup', '/auth/logout', '/cron/retention']);

const CSP = [
  "default-src 'self'", "script-src 'self'", "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com", "img-src 'self' data:", "connect-src 'self'",
  "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'", "object-src 'none'"
].join('; ');

function securityHeaders(req, res, next) {
  res.set({
    'Content-Security-Policy': CSP,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
  });
  if (req.secure) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
}

function validateNewUser({ email, name, password, role }, { needPassword = true } = {}) {
  if (!email || !EMAIL_RE.test(String(email).trim())) return 'Enter a valid email address';
  if (!name || String(name).trim().length < 2) return 'Name must be at least 2 characters';
  if (role !== undefined && !auth.ROLES.includes(role)) return `Role must be one of ${auth.ROLES.join(', ')}`;
  if (needPassword) return auth.passwordProblem(password);
  return null;
}

function createApp({ store, enforcer, nvd = null, reputation = null, env = process.env, demo = false, warnings = [] }) {
  const investigator = new Investigator(store, { groqKey: env.GROQ_API_KEY, model: env.GROQ_MODEL, enforcer, nvd, reputation });
  const secret = auth.loadSecret(env);
  const secureCookie = /^(1|true|yes)$/i.test(String(env.COOKIE_SECURE || ''));
  const app = express();
  app.disable('x-powered-by');
  if (env.TRUST_PROXY) app.set('trust proxy', /^\d+$/.test(env.TRUST_PROXY) ? Number(env.TRUST_PROXY) : env.TRUST_PROXY);
  app.use(securityHeaders);

  // Ingest and import routes take large bodies and their own parsers.
  const smallJson = express.json({ limit: '128kb' });
  app.use((req, res, next) => (/^\/api\/(ingest\/|assets\/import)/.test(req.path) ? next() : smallJson(req, res, next)));

  // ---- Session ------------------------------------------------------------
  const userCache = new Map();
  const forgetUser = (id) => userCache.delete(Number(id));
  async function loadUser(uid) {
    const hit = userCache.get(uid);
    if (hit && hit.at > Date.now() - 30000) return hit.user;
    const user = await store.users.byId(uid);
    userCache.set(uid, { at: Date.now(), user });
    return user;
  }
  const issue = (res, user) => res.set('Set-Cookie', auth.sessionCookie(auth.signSession(secret, user), { secure: secureCookie }));
  const pub = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role });

  app.use('/api', wrap(async (req, res, next) => {
    const token = auth.parseCookies(req.headers.cookie)[auth.COOKIE];
    const s = token && auth.readSession(secret, token);
    if (s) {
      const u = await loadUser(s.uid);
      if (u && !u.disabled && (u.session_version || 1) === s.v) req.user = pub(u);
    }
    next();
  }));

  // Everything under /api needs a signed-in user except auth, health, ingest and feeds
  // (the last two use API keys). Cookie-authenticated writes must carry the client
  // header, which a cross-site form or image tag cannot set.
  app.use('/api', (req, res, next) => {
    if (PUBLIC_API.has(req.path) || /^\/(ingest|feeds)\//.test(req.path)) return next();
    if (!req.user) return bad(res, 'Sign in required', 401);
    if (!['GET', 'HEAD'].includes(req.method) && req.get('x-aegis-client') !== 'web') return bad(res, 'Missing X-Aegis-Client header', 403);
    next();
  });

  const need = (perm) => (req, res, next) => (auth.can(req.user, perm) ? next() : bad(res, `The ${req.user ? req.user.role : 'anonymous'} role cannot do this`, 403));

  const requireKey = (scope) => wrap(async (req, res, next) => {
    const raw = auth.bearer(req);
    if (!raw) { res.set('WWW-Authenticate', 'Bearer'); return bad(res, 'API key required: Authorization: Bearer aeg_...', 401); }
    const key = await store.apiKeys.byHash(auth.hashApiKey(raw));
    if (!key) return bad(res, 'Invalid or revoked API key', 401);
    if (!(key.scopes || []).includes(scope)) return bad(res, `This key does not have the "${scope}" scope`, 403);
    req.apiKey = key;
    store.apiKeys.touch(key.id).catch(() => {});
    next();
  });

  const actor = (req) => (req.user ? req.user.name : req.apiKey ? `key:${req.apiKey.name}` : 'system');
  const loginLimit = auth.rateLimit({ windowMs: 15 * 60000, max: Number(env.LOGIN_RATE_LIMIT) || 10 });
  app.use('/api', auth.rateLimit({ windowMs: 60000, max: Number(env.API_RATE_LIMIT) || 1200, key: (req) => (req.user ? `u${req.user.id}` : req.ip) }));

  // ---- Auth ---------------------------------------------------------------
  app.get('/api/auth/state', wrap(async (req, res) => {
    res.json({ needs_setup: (await store.users.count()) === 0, user: req.user || null, demo, setup_token: Boolean(env.AEGIS_SETUP_TOKEN) });
  }));

  app.post('/api/auth/setup', loginLimit, wrap(async (req, res) => {
    if ((await store.users.count()) > 0) return bad(res, 'Setup is already complete. Sign in instead.', 409);
    const b = req.body || {};
    if (env.AEGIS_SETUP_TOKEN && b.setup_token !== env.AEGIS_SETUP_TOKEN) return bad(res, 'Setup token does not match AEGIS_SETUP_TOKEN', 403);
    const err = validateNewUser(b);
    if (err) return bad(res, err);
    const user = await store.users.insert({ email: String(b.email).trim().toLowerCase(), name: String(b.name).trim().slice(0, 60), role: 'admin', password_hash: auth.hashPassword(b.password), last_login_at: new Date().toISOString() });
    await store.audit.add({ actor: user.name, action: 'user.created', target: user.email, detail: 'Initial administrator' });
    issue(res, { ...user, session_version: 1 });
    res.status(201).json({ user: pub(user) });
  }));

  app.post('/api/auth/login', loginLimit, wrap(async (req, res) => {
    const { email, password } = req.body || {};
    const u = email ? await store.users.byEmail(String(email).trim()) : null;
    // Hash anyway when the user is unknown so response time does not reveal valid emails.
    const ok = u ? auth.verifyPassword(password, u.password_hash) : (auth.hashPassword(String(password || '')), false);
    if (!ok || u.disabled) {
      await store.audit.add({ actor: String(email || 'unknown').slice(0, 80), action: 'auth.failed', target: req.ip, detail: u && u.disabled ? 'account disabled' : null });
      return bad(res, u && u.disabled && ok ? 'This account is disabled' : 'Email or password is incorrect', 401);
    }
    await store.users.update(u.id, { last_login_at: new Date().toISOString() });
    forgetUser(u.id);
    issue(res, u);
    await store.audit.add({ actor: u.name, action: 'auth.login', target: req.ip, detail: null });
    res.json({ user: pub(u) });
  }));

  app.post('/api/auth/logout', (req, res) => {
    res.set('Set-Cookie', auth.sessionCookie('', { secure: secureCookie, clear: true }));
    res.json({ ok: true });
  });

  app.get('/api/auth/me', (req, res) => res.json({ user: req.user }));

  app.post('/api/auth/password', wrap(async (req, res) => {
    const { current_password, new_password } = req.body || {};
    const u = await store.users.byId(req.user.id);
    if (!u || !auth.verifyPassword(current_password, u.password_hash)) return bad(res, 'Current password is incorrect', 403);
    const problem = auth.passwordProblem(new_password);
    if (problem) return bad(res, problem);
    const version = (u.session_version || 1) + 1;
    await store.users.update(u.id, { password_hash: auth.hashPassword(new_password), session_version: version });
    forgetUser(u.id);
    issue(res, { ...u, session_version: version });
    await store.audit.add({ actor: u.name, action: 'user.password', target: u.email, detail: 'Password changed; other sessions signed out' });
    res.json({ ok: true });
  }));

  // ---- Users (admin) -------------------------------------------------------
  app.get('/api/users', need('manage'), wrap(async (req, res) => res.json(await store.users.list())));

  app.post('/api/users', need('manage'), wrap(async (req, res) => {
    const b = req.body || {};
    const role = b.role || 'analyst';
    const err = validateNewUser({ ...b, role });
    if (err) return bad(res, err);
    try {
      const user = await store.users.insert({ email: String(b.email).trim().toLowerCase(), name: String(b.name).trim().slice(0, 60), role, password_hash: auth.hashPassword(b.password) });
      await store.audit.add({ actor: actor(req), action: 'user.created', target: user.email, detail: role });
      res.status(201).json(user);
    } catch (e) { bad(res, e.message, 409); }
  }));

  app.patch('/api/users/:id', need('manage'), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const b = req.body || {};
    const target = await store.users.byId(id);
    if (!target) return bad(res, 'User not found', 404);
    const patch = {};
    const changes = [];
    if (b.role !== undefined) {
      if (!auth.ROLES.includes(b.role)) return bad(res, 'Unknown role');
      patch.role = b.role; changes.push(`role=${b.role}`);
    }
    if (b.disabled !== undefined) { patch.disabled = Boolean(b.disabled); changes.push(patch.disabled ? 'disabled' : 'enabled'); }
    if (b.password !== undefined) {
      const problem = auth.passwordProblem(b.password);
      if (problem) return bad(res, problem);
      patch.password_hash = auth.hashPassword(b.password); changes.push('password reset');
    }
    if (!changes.length) return bad(res, 'Nothing to change');
    const losesAdmin = target.role === 'admin' && ((patch.role && patch.role !== 'admin') || patch.disabled);
    if (losesAdmin) {
      const admins = (await store.users.list()).filter((u) => u.role === 'admin' && !u.disabled);
      if (admins.length <= 1) return bad(res, 'Keep at least one active administrator', 409);
    }
    // Any security-relevant change signs the user out everywhere.
    patch.session_version = (target.session_version || 1) + 1;
    const updated = await store.users.update(id, patch);
    forgetUser(id);
    if (id === req.user.id && !patch.disabled) issue(res, { ...target, ...patch });
    await store.audit.add({ actor: actor(req), action: 'user.updated', target: target.email, detail: changes.join(', ') });
    res.json(updated);
  }));

  // ---- API keys (admin) ----------------------------------------------------
  app.get('/api/keys', need('manage'), wrap(async (req, res) => res.json(await store.apiKeys.list())));

  app.post('/api/keys', need('manage'), wrap(async (req, res) => {
    const b = req.body || {};
    const name = String(b.name || '').trim();
    if (name.length < 3) return bad(res, 'Name the key after the sensor or firewall that will use it');
    const scopes = [...new Set((Array.isArray(b.scopes) ? b.scopes : ['ingest']).filter((s) => ['ingest', 'feed'].includes(s)))];
    if (!scopes.length) return bad(res, 'Pick at least one scope: ingest or feed');
    const k = auth.generateApiKey();
    const rec = await store.apiKeys.insert({ name: name.slice(0, 60), prefix: k.prefix, hash: k.hash, scopes, created_by: actor(req) });
    await store.audit.add({ actor: actor(req), action: 'key.created', target: rec.name, detail: `${rec.prefix}... ${scopes.join('+')}` });
    res.status(201).json({ ...rec, key: k.raw });
  }));

  app.post('/api/keys/:id/revoke', need('manage'), wrap(async (req, res) => {
    const rec = await store.apiKeys.revoke(req.params.id);
    if (!rec) return bad(res, 'Key not found or already revoked', 404);
    await store.audit.add({ actor: actor(req), action: 'key.revoked', target: rec.name, detail: `${rec.prefix}...` });
    res.json(rec);
  }));

  const ctx = { store, investigator, enforcer, nvd, reputation, demo, warnings, env, wrap, bad, need, requireKey, actor, bootedAt: Date.now() };
  const jobs = registerRoutes(app, ctx);

  app.use('/api', (req, res) => bad(res, 'Not found', 404));
  app.use(express.static(path.join(__dirname, '..', 'public'), { extensions: ['html'], maxAge: env.NODE_ENV === 'production' ? '1h' : 0 }));
  app.get('*', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') return bad(res, 'Request body too large', 413);
    if (err.type === 'entity.parse.failed') return bad(res, `Body is not valid JSON: ${err.message}`);
    console.error(err);
    if (res.headersSent) return res.end();
    res.status(500).json({ error: env.NODE_ENV === 'production' ? 'Internal error' : err.message || 'Internal error' });
  });

  return { app, investigator, jobs };
}

module.exports = { createApp };