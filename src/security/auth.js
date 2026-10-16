'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---- Passwords (scrypt, per-user salt) -------------------------------------
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPassword(password, stored) {
  const [scheme, n, saltB64, hashB64] = String(stored || '').split('$');
  if (scheme !== 'scrypt' || !saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = crypto.scryptSync(String(password), Buffer.from(saltB64, 'base64'), expected.length, { N: Number(n), r: SCRYPT.r, p: SCRYPT.p });
  return crypto.timingSafeEqual(expected, actual);
}

function passwordProblem(pw) {
  const s = String(pw || '');
  if (s.length < 10) return 'Password must be at least 10 characters';
  if (!/[a-z]/i.test(s) || !/\d/.test(s)) return 'Password needs letters and at least one digit';
  return null;
}

// ---- Session cookies (stateless, HMAC-signed) ------------------------------
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const COOKIE = 'aegis_session';

function loadSecret(env = process.env) {
  if (env.SESSION_SECRET && env.SESSION_SECRET.length >= 32) return env.SESSION_SECRET;
  const file = path.join(__dirname, '..', '..', '.data', 'session.secret');
  try {
    if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const s = crypto.randomBytes(48).toString('base64url');
    fs.writeFileSync(file, s, { mode: 0o600 });
    return s;
  } catch {
    return crypto.randomBytes(48).toString('base64url');
  }
}

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

function signSession(secret, user) {
  // `v` is the user's session version: bumping it (password change, disable) kills old cookies.
  const body = b64({ uid: user.id, v: user.session_version || 1, exp: Date.now() + SESSION_TTL_MS });
  const mac = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function readSession(secret, token) {
  const [body, mac] = String(token || '').split('.');
  if (!body || !mac) return null;
  const want = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  if (want.length !== mac.length || !crypto.timingSafeEqual(Buffer.from(want), Buffer.from(mac))) return null;
  try {
    const data = JSON.parse(Buffer.from(body, 'base64url').toString());
    return data.exp > Date.now() ? data : null;
  } catch { return null; }
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function sessionCookie(token, { secure, clear = false } = {}) {
  const attrs = [`${COOKIE}=${clear ? '' : token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${clear ? 0 : SESSION_TTL_MS / 1000}`];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

// ---- API keys (for sensors and firewall feeds) -----------------------------
// Only the SHA-256 is stored. The prefix lets an admin recognise a key in the list.
function generateApiKey() {
  const raw = `aeg_${crypto.randomBytes(24).toString('base64url')}`;
  return { raw, prefix: raw.slice(0, 10), hash: hashApiKey(raw) };
}
const hashApiKey = (raw) => crypto.createHash('sha256').update(String(raw)).digest('hex');

function bearer(req) {
  const h = req.headers.authorization || '';
  if (/^bearer\s+/i.test(h)) return h.replace(/^bearer\s+/i, '').trim();
  if (/^basic\s+/i.test(h)) {
    // Firewalls that only do basic auth: any username, API key as the password.
    const decoded = Buffer.from(h.replace(/^basic\s+/i, ''), 'base64').toString();
    return decoded.slice(decoded.indexOf(':') + 1);
  }
  return null;
}

// ---- Fixed-window rate limiter --------------------------------------------
function rateLimit({ windowMs, max, key = (req) => req.ip }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
  }, windowMs).unref();
  return (req, res, next) => {
    const k = key(req);
    const now = Date.now();
    let e = hits.get(k);
    if (!e || e.reset < now) { e = { n: 0, reset: now + windowMs }; hits.set(k, e); }
    e.n += 1;
    if (e.n > max) {
      res.set('Retry-After', String(Math.ceil((e.reset - now) / 1000)));
      return res.status(429).json({ error: 'Too many requests. Try again shortly.' });
    }
    next();
  };
}

const ROLES = ['admin', 'analyst', 'viewer'];
// What each role may do beyond reading.
const CAN = {
  admin: new Set(['respond', 'configure', 'manage']),
  analyst: new Set(['respond']),
  viewer: new Set()
};
const can = (user, perm) => Boolean(user && CAN[user.role] && CAN[user.role].has(perm));

module.exports = {
  hashPassword, verifyPassword, passwordProblem,
  loadSecret, signSession, readSession, parseCookies, sessionCookie, COOKIE, SESSION_TTL_MS,
  generateApiKey, hashApiKey, bearer, rateLimit, ROLES, can
};