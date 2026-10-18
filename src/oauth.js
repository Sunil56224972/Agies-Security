'use strict';

// OAuth 2.1 for the MCP endpoint, so web clients such as claude.ai custom connectors
// can connect with a normal sign-in instead of a pasted API key.
//
//   /.well-known/oauth-protected-resource      where to authenticate (RFC 9728)
//   /.well-known/oauth-authorization-server    endpoints and capabilities (RFC 8414)
//   POST /oauth/register                       dynamic client registration (RFC 7591)
//   GET  /oauth/authorize                      sign-in and consent page (PKCE S256 only)
//   POST /oauth/token                          code and refresh-token grants
//
// Everything is stateless (signed with keys derived from SESSION_SECRET), so it works
// across serverless instances without new tables. Tokens carry the user's session
// version: a password change, role change or disabled account revokes them at once.
const crypto = require('crypto');
const express = require('express');
const auth = require('./security/auth');

const ACCESS_TTL = 60 * 60 * 1000;
const REFRESH_TTL = 30 * 24 * 60 * 60 * 1000;
const CODE_TTL = 5 * 60 * 1000;
const SCOPES = ['mcp', 'mcp:write'];

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('base64url');

function originOf(req, env) {
  if (env.PUBLIC_URL) return String(env.PUBLIC_URL).replace(/\/+$/, '');
  const proto = String(req.get('x-forwarded-proto') || req.protocol || 'http').split(',')[0].trim();
  return `${proto}://${req.get('host')}`;
}

function goodRedirect(u) {
  let url;
  try { url = new URL(u); } catch { return false; }
  if (url.hash || url.username || url.password) return false;
  if (url.protocol === 'https:') return true;
  // Native clients (Claude Code, MCP Inspector) listen on a loopback port.
  return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
}

function createOauth(secret) {
  const keyFor = (info) => Buffer.from(crypto.hkdfSync('sha256', Buffer.from(String(secret)), Buffer.from('aegis-oauth'), Buffer.from(info), 32));
  const keys = { client: keyFor('client'), code: keyFor('code'), token: keyFor('token'), csecret: keyFor('client-secret') };
  const mac = (k, body) => crypto.createHmac('sha256', k).update(body).digest('base64url');
  const sign = (k, prefix, data) => { const body = b64(data); return `${prefix}${body}.${mac(k, body)}`; };
  function open(k, prefix, token) {
    const s = String(token || '');
    if (!s.startsWith(prefix)) return null;
    const [body, m] = s.slice(prefix.length).split('.');
    if (!body || !m) return null;
    const want = mac(k, body);
    if (want.length !== m.length || !crypto.timingSafeEqual(Buffer.from(want), Buffer.from(m))) return null;
    try {
      const d = JSON.parse(Buffer.from(body, 'base64url').toString());
      return d.exp && d.exp < Date.now() ? null : d;
    } catch { return null; }
  }
  // Codes are single use within one instance; PKCE stops a stolen code elsewhere.
  const usedCodes = new Map();
  const burn = (jti, exp) => {
    const now = Date.now();
    for (const [k, v] of usedCodes) if (v < now) usedCodes.delete(k);
    if (usedCodes.has(jti)) return false;
    usedCodes.set(jti, exp);
    return true;
  };

  return {
    client: (meta) => sign(keys.client, 'aec_', meta),
    readClient: (id) => open(keys.client, 'aec_', id),
    clientSecret: (id) => `aes_${mac(keys.csecret, String(id))}`,
    code: (data) => sign(keys.code, 'aeg_code_', { ...data, jti: crypto.randomBytes(9).toString('base64url'), exp: Date.now() + CODE_TTL }),
    readCode: (c) => open(keys.code, 'aeg_code_', c),
    burn,
    access: (data) => sign(keys.token, 'aeo_', { ...data, t: 'a', exp: Date.now() + ACCESS_TTL }),
    refresh: (data) => sign(keys.token, 'aer_', { ...data, t: 'r', exp: Date.now() + REFRESH_TTL }),
    readAccess: (t) => { const d = open(keys.token, 'aeo_', t); return d && d.t === 'a' ? d : null; },
    readRefresh: (t) => { const d = open(keys.token, 'aer_', t); return d && d.t === 'r' ? d : null; }
  };
}

function registerOauth(app, ctx) {
  const { store, env, secret, wrap, actor } = ctx;
  const o = createOauth(secret);
  const limit = auth.rateLimit({ windowMs: 60000, max: 60, key: (req) => `oauth:${req.ip}` });
  const form = express.urlencoded({ extended: false, limit: '16kb' });
  // Discovery and token calls come from other origins and never carry cookies.
  const cors = (req, res, next) => {
    res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization, MCP-Protocol-Version', 'Cache-Control': 'no-store' });
    if (req.method === 'OPTIONS') return res.status(204).end();
    next();
  };
  const oerr = (res, error, description, code = 400) => res.status(code).json({ error, error_description: description });

  const metadata = (req) => {
    const base = originOf(req, env);
    return {
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      registration_endpoint: `${base}/oauth/register`,
      scopes_supported: SCOPES,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
      code_challenge_methods_supported: ['S256'],
      service_documentation: `${base}/#/settings`
    };
  };
  const resource = (req) => {
    const base = originOf(req, env);
    return { resource: `${base}/mcp`, authorization_servers: [base], scopes_supported: SCOPES, bearer_methods_supported: ['header'], resource_name: 'Aegis Security' };
  };
  for (const p of ['/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server/mcp', '/.well-known/openid-configuration']) app.all(p, cors, (req, res) => res.json(metadata(req)));
  for (const p of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource/api/mcp']) app.all(p, cors, (req, res) => res.json(resource(req)));

  // ---- Dynamic client registration --------------------------------------------------
  app.options('/oauth/register', cors);
  app.post('/oauth/register', cors, limit, (req, res) => {
    const b = req.body || {};
    const uris = Array.isArray(b.redirect_uris) ? b.redirect_uris.map(String) : [];
    if (!uris.length || uris.length > 5 || uris.some((u) => u.length > 500 || !goodRedirect(u))) return oerr(res, 'invalid_redirect_uri', 'redirect_uris must be 1-5 https URLs (or http on localhost)');
    const method = ['client_secret_post', 'client_secret_basic'].includes(b.token_endpoint_auth_method) ? b.token_endpoint_auth_method : 'none';
    const name = String(b.client_name || 'MCP client').replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, 60) || 'MCP client';
    const iat = Math.floor(Date.now() / 1000);
    const id = o.client({ n: name, r: uris, m: method, iat });
    res.status(201).json({
      client_id: id, client_id_issued_at: iat, client_name: name, redirect_uris: uris,
      grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: method,
      ...(method === 'none' ? {} : { client_secret: o.clientSecret(id), client_secret_expires_at: 0 })
    });
  });

  // Checks an authorization request; the page and the approval call both use it.
  function check(q) {
    const client = o.readClient(q.client_id);
    if (!client) return { fatal: 'Unknown client. Remove the connector and add it again.' };
    const redirect = String(q.redirect_uri || (client.r.length === 1 ? client.r[0] : ''));
    if (!client.r.includes(redirect)) return { fatal: 'The redirect address does not match the one this client registered.' };
    if (q.response_type !== 'code') return { client, redirect, error: 'unsupported_response_type', why: 'Only response_type=code is supported' };
    if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(String(q.code_challenge || '')) || (q.code_challenge_method || 'plain') !== 'S256') return { client, redirect, error: 'invalid_request', why: 'PKCE with code_challenge_method=S256 is required' };
    const asked = String(q.scope || '').split(/\s+/).filter(Boolean);
    return { client, redirect, wantsWrite: asked.length === 0 || asked.includes('mcp:write'), state: q.state == null ? null : String(q.state).slice(0, 500) };
  }
  const back = (redirect, params) => {
    const u = new URL(redirect);
    for (const [k, v] of Object.entries(params)) if (v != null) u.searchParams.set(k, v);
    return u.toString();
  };

  app.get('/oauth/authorize', (req, res) => {
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
    res.sendFile(require('path').join(__dirname, '..', 'public', 'oauth.html'));
  });

  app.get('/oauth/authorize/info', limit, (req, res) => {
    res.set('Cache-Control', 'no-store');
    const c = check(req.query);
    if (c.fatal) return res.status(400).json({ error: c.fatal });
    if (c.error) return res.json({ redirect: back(c.redirect, { error: c.error, error_description: c.why, state: c.state }), error: c.why });
    res.json({ client_name: c.client.n, redirect_host: new URL(c.redirect).host, wants_write: c.wantsWrite });
  });

  // Called by the consent page with the console session (cookie + client header).
  app.post('/api/oauth/approve', wrap(async (req, res) => {
    const b = req.body || {};
    const c = check(b);
    if (c.fatal) return res.status(400).json({ error: c.fatal });
    if (c.error) return res.json({ redirect: back(c.redirect, { error: c.error, error_description: c.why, state: c.state }) });
    if (b.decision !== 'allow') {
      await store.audit.add({ actor: actor(req), action: 'oauth.denied', target: c.client.n, detail: new URL(c.redirect).host });
      return res.json({ redirect: back(c.redirect, { error: 'access_denied', error_description: 'The user denied access', state: c.state }) });
    }
    const u = await store.users.byId(req.user.id);
    const write = Boolean(b.allow_write) && c.wantsWrite && auth.can(req.user, 'respond');
    const scope = write ? 'mcp mcp:write' : 'mcp';
    const code = o.code({ uid: u.id, sv: u.session_version || 1, cid: b.client_id, ru: c.redirect, cc: b.code_challenge, sc: scope, cn: c.client.n });
    await store.audit.add({ actor: actor(req), action: 'oauth.granted', target: c.client.n, detail: `${scope} to ${new URL(c.redirect).host}` });
    res.json({ redirect: back(c.redirect, { code, state: c.state, iss: originOf(req, env) }) });
  }));

  // ---- Token endpoint ------------------------------------------------------------------
  async function liveUser(d) {
    const u = await store.users.byId(d.uid);
    if (!u || u.disabled || (u.session_version || 1) !== d.sv) return null;
    return u;
  }
  // Never grant more than the user's current role allows.
  const capScope = (u, sc) => (auth.can(u, 'respond') ? sc : 'mcp');
  function issue(res, u, d) {
    const scope = capScope(u, d.sc);
    const data = { uid: u.id, sv: u.session_version || 1, sc: scope, cn: d.cn, cid: d.cid };
    res.json({ access_token: o.access(data), token_type: 'Bearer', expires_in: ACCESS_TTL / 1000, refresh_token: o.refresh(data), scope });
  }

  app.options('/oauth/token', cors);
  app.post('/oauth/token', cors, limit, form, wrap(async (req, res) => {
    const b = req.body || {};
    let clientId = b.client_id; let clientSecret = b.client_secret;
    const basic = /^basic\s+/i.test(req.get('authorization') || '') ? Buffer.from(req.get('authorization').replace(/^basic\s+/i, ''), 'base64').toString() : null;
    if (basic) { const i = basic.indexOf(':'); clientId = decodeURIComponent(basic.slice(0, i)); clientSecret = decodeURIComponent(basic.slice(i + 1)); }
    const client = o.readClient(clientId);
    if (!client) return oerr(res, 'invalid_client', 'Unknown client', 401);
    if (client.m !== 'none') {
      const want = o.clientSecret(clientId);
      if (typeof clientSecret !== 'string' || clientSecret.length !== want.length || !crypto.timingSafeEqual(Buffer.from(clientSecret), Buffer.from(want))) return oerr(res, 'invalid_client', 'Client authentication failed', 401);
    }
    if (b.grant_type === 'authorization_code') {
      const d = o.readCode(b.code);
      if (!d || d.cid !== clientId) return oerr(res, 'invalid_grant', 'The code is invalid, expired or for another client');
      if (b.redirect_uri && b.redirect_uri !== d.ru) return oerr(res, 'invalid_grant', 'redirect_uri does not match the authorization request');
      if (typeof b.code_verifier !== 'string' || !/^[A-Za-z0-9\-._~]{43,128}$/.test(b.code_verifier) || sha256(b.code_verifier) !== d.cc) return oerr(res, 'invalid_grant', 'PKCE verification failed');
      if (!o.burn(d.jti, d.exp)) return oerr(res, 'invalid_grant', 'The code was already used');
      const u = await liveUser(d);
      if (!u) return oerr(res, 'invalid_grant', 'The account changed since sign-in; connect again');
      await store.audit.add({ actor: `${u.name}`, action: 'oauth.token', target: d.cn, detail: d.sc });
      return issue(res, u, d);
    }
    if (b.grant_type === 'refresh_token') {
      const d = o.readRefresh(b.refresh_token);
      if (!d || d.cid !== clientId) return oerr(res, 'invalid_grant', 'The refresh token is invalid or expired');
      const u = await liveUser(d);
      if (!u) return oerr(res, 'invalid_grant', 'Access was revoked (password, role or account changed); connect again');
      return issue(res, u, d);
    }
    return oerr(res, 'unsupported_grant_type', 'Use authorization_code or refresh_token');
  }));

  // Used by the MCP endpoint: turns an OAuth access token into the same shape as an API key.
  async function verify(raw) {
    const d = o.readAccess(raw);
    if (!d) return null;
    const u = await liveUser(d);
    if (!u) return null;
    return { name: `${u.name} via ${d.cn}`, scopes: capScope(u, d.sc).split(' '), oauth: true, user_id: u.id };
  }
  const challenge = (req) => `Bearer realm="aegis-mcp", resource_metadata="${originOf(req, env)}/.well-known/oauth-protected-resource"`;

  return { verify, challenge };
}

module.exports = { registerOauth, createOauth, goodRedirect };