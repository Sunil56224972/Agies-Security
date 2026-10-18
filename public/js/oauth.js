// OAuth consent page for MCP connectors (claude.ai and others).
const $ = (s, r = document) => r.querySelector(s);
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
const card = $('#card');
const params = Object.fromEntries(new URLSearchParams(location.search));
$('#host').textContent = location.host;

async function call(path, body) {
  const res = await fetch(path, {
    method: body ? 'POST' : 'GET',
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json', 'X-Aegis-Client': 'web' } : {},
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || `HTTP ${res.status}`), { status: res.status });
  return data;
}

function fatal(msg) {
  card.innerHTML = `<h1 class="gate__title">Cannot connect</h1><p class="gate__sub">${esc(msg)}</p><a class="btn" href="/">Open the console</a>`;
}

function signIn(info, needsSetup) {
  if (needsSetup) return fatal('This Aegis install has no accounts yet. Open the console, create the administrator, then connect again.');
  card.innerHTML = `
    <h1 class="gate__title">Sign in to connect</h1>
    <p class="gate__sub"><b>${esc(info.client_name)}</b> wants to use Aegis as you. Sign in first.</p>
    <form id="f" class="gate__form" novalidate>
      <label class="field"><span>Email</span><input class="input" name="email" type="email" autocomplete="username" required autofocus></label>
      <label class="field"><span>Password</span><input class="input" name="password" type="password" autocomplete="current-password" required></label>
      <div class="gate__err" id="err" role="alert"></div>
      <button class="btn btn--primary gate__submit" type="submit">Sign in</button>
    </form>`;
  $('#f').onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    const btn = f.querySelector('button');
    btn.disabled = true;
    try {
      await call('/api/auth/login', { email: f.email.value.trim(), password: f.password.value });
      start();
    } catch (err) { $('#err').textContent = err.message; btn.disabled = false; }
  };
}

function consent(info, user) {
  const canWrite = user.role === 'admin' || user.role === 'analyst';
  card.innerHTML = `
    <h1 class="gate__title">Allow ${esc(info.client_name)}?</h1>
    <p class="gate__sub">It will act as <b>${esc(user.name)}</b> (${esc(user.role)}) and send results back to <span class="mono">${esc(info.redirect_host)}</span>.</p>
    <div class="stack" style="gap:10px;margin-bottom:18px">
      <div class="notice"><span><b>Read</b> alerts, investigations, cases, containment rules, hunts and threat intel.</span></div>
      ${info.wants_write && canWrite ? `<label class="check"><input type="checkbox" id="write"><span>Also allow actions: investigate, block or isolate (still subject to the approval policy), cases and hunts.</span></label>` : ''}
      ${info.wants_write && !canWrite ? '<p class="small muted" style="margin:0">Your role is read-only, so the connector gets read access only.</p>' : ''}
    </div>
    <div class="gate__err" id="err" role="alert"></div>
    <div class="row" style="justify-content:flex-end;gap:8px">
      <button class="btn btn--ghost" id="deny">Deny</button>
      <button class="btn btn--primary" id="allow">Allow access</button>
    </div>
    <p class="small muted gate__note">Not ${esc(user.name)}? <a href="#" id="switch">Use another account</a></p>`;
  const decide = async (decision) => {
    $('#allow').disabled = $('#deny').disabled = true;
    try {
      const w = $('#write');
      const r = await call('/api/oauth/approve', { ...params, decision, allow_write: Boolean(w && w.checked) });
      card.innerHTML = `<h1 class="gate__title">${decision === 'allow' ? 'Connected' : 'Access denied'}</h1><p class="gate__sub">Returning to ${esc(info.client_name)}...</p>`;
      location.replace(r.redirect);
    } catch (err) { $('#err').textContent = err.message; $('#allow').disabled = $('#deny').disabled = false; }
  };
  $('#allow').onclick = () => decide('allow');
  $('#deny').onclick = () => decide('deny');
  $('#switch').onclick = async (e) => { e.preventDefault(); await call('/api/auth/logout', {}).catch(() => {}); start(); };
}

async function start() {
  let info;
  try { info = await call(`/oauth/authorize/info?${new URLSearchParams(params)}`); } catch (err) { return fatal(err.message); }
  if (info.redirect) { if (info.error) card.innerHTML = `<p class="gate__sub">${esc(info.error)}. Returning...</p>`; return location.replace(info.redirect); }
  const st = await call('/api/auth/state').catch(() => ({}));
  if (!st.user) return signIn(info, st.needs_setup);
  consent(info, st.user);
}
start();