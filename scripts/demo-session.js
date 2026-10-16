// Signs a capture script into a demo server (AEGIS_DEMO=1) and returns the
// session cookie. Creates the administrator on a fresh install.
const BASE = process.env.AEGIS_URL || 'http://localhost:3000';
const EMAIL = process.env.AEGIS_DEMO_EMAIL || 'priya.raman@example.com';
const PASSWORD = process.env.AEGIS_DEMO_PASSWORD || 'demo-console-2026';
const NAME = process.env.AEGIS_DEMO_NAME || 'Priya Raman';

async function call(path, body, cookie) {
  const res = await fetch(`${BASE}/api${path}`, {
    method: body ? 'POST' : 'GET',
    headers: { 'Content-Type': 'application/json', 'X-Aegis-Client': 'web', ...(cookie ? { Cookie: cookie } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${path}: ${data.error || res.status}`);
  return { data, cookie: (res.headers.get('set-cookie') || '').split(';')[0] || cookie };
}

async function signIn({ reset = false } = {}) {
  const st = (await call('/auth/state').catch(() => { throw new Error(`No server at ${BASE}. Start it with AEGIS_DEMO=1 npm start.`); })).data;
  if (!st.demo) throw new Error('The server is not in demo mode. Start it with AEGIS_DEMO=1 so captures use sample data.');
  const auth = st.needs_setup
    ? await call('/auth/setup', { name: NAME, email: EMAIL, password: PASSWORD, setup_token: process.env.AEGIS_SETUP_TOKEN })
    : await call('/auth/login', { email: EMAIL, password: PASSWORD });
  if (reset) await call('/reset', {}, auth.cookie);
  const [name, value] = auth.cookie.split('=');
  return { base: BASE, cookie: { name, value, url: BASE } };
}

module.exports = { signIn, BASE };