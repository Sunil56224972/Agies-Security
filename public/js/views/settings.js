import { $, $$, api, esc, ago, stamp, toast, busy, emit, state, modal, closeLayer, can, copyText, pill, label } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

let ctx = null;
const ROLE_TEXT = { admin: 'Administrator', analyst: 'Analyst', viewer: 'Read only' };
const ROLE_HELP = { admin: 'Everything, including users, keys and settings', analyst: 'Investigate, contain, edit inventory', viewer: 'Read only' };

export async function render({ el, navigate }) {
  ctx = { el, navigate };
  const manage = can('manage');
  const configure = can('configure');
  const [config, health, audit, users, keys, channels] = await Promise.all([
    api('/config'), api('/health'), api('/audit?limit=40'),
    manage ? api('/users') : Promise.resolve(null), manage ? api('/keys') : Promise.resolve(null),
    configure ? api('/notify/channels').catch(() => []) : Promise.resolve(null)
  ]);
  state.health = health;
  ctx.users = users;
  ctx.keys = keys;
  ctx.channels = channels;

  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Settings</h1>
        <p class="page-sub">Every change here is written to the audit log with your name on it.</p>
      </div>
      ${configure ? '<div class="page-actions"><button class="btn btn--primary" id="st-save" disabled>Save policy</button></div>' : ''}
    </div>
    <div class="grid grid-2-1 reveal">
      <div class="stack">
        ${policyPanel(health, configure)}
        ${manage ? '<section class="panel" id="st-team"></section><section class="panel" id="st-keys"></section>' : ''}
        ${accountPanel()}
      </div>
      <div class="stack">
        ${configure ? '<section class="panel" id="st-notify"></section>' : ''}
        ${integrationsPanel(health)}
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Audit log</h2><span class="panel__meta">last ${audit.length}</span>${manage ? `<a class="btn btn--sm btn--ghost" style="margin-left:12px" href="/api/export/audit.csv?limit=10000" download>${icon('download')}Export</a>` : ''}</div>
          ${audit.length ? `<div class="feed" style="max-height:440px;overflow:auto">${audit.map((a) => `<div class="feed__item" title="${esc(stamp(a.created_at))}"><span class="feed__time">${new Date(a.created_at).toTimeString().slice(0, 5)}</span><div><div class="feed__text"><b>${esc(a.actor)}</b> <span class="mono small">${esc(a.action)}</span> ${esc(a.target || '')}</div>${a.detail ? `<div class="feed__detail">${esc(String(a.detail).slice(0, 90))}</div>` : ''}</div></div>`).join('')}</div>` : '<div class="empty"><b>Nothing logged yet</b></div>'}
        </section>
      </div>
    </div>`;

  if (configure) bindPolicy(config);
  if (manage) { paintTeam(); paintKeys(); }
  if (configure) paintNotify();
  bindAccount();
  const reset = $('#st-reset', el);
  if (reset) reset.onclick = openReset;
  hydrateIcons(el);
}

export function onDataChanged() {}

// ---- Response policy -------------------------------------------------------
function policyPanel(health, configure) {
  const dis = configure ? '' : 'disabled';
  return `<section class="panel">
    <div class="panel__head"><h2 class="panel__title">Response policy</h2>${configure ? '' : '<span class="tag panel__meta">admins only</span>'}</div>
    <div class="setting"><div><div class="setting__label">Auto-containment threshold</div><div class="setting__help">Lowest alert severity at which a confirmed or attempted attack is blocked at the perimeter without asking. Off means the engine only recommends.</div></div>
      <select class="select" name="autoContainmentThreshold" ${dis}>${['OFF', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((v) => `<option value="${v}">${v === 'OFF' ? 'Off (recommend only)' : `${v[0]}${v.slice(1).toLowerCase()} and above`}</option>`).join('')}</select></div>
    <div class="setting"><div><div class="setting__label">Isolate compromised hosts</div><div class="setting__help">On a confirmed compromise, also publish an ISOLATE rule for the internal host.</div></div>
      <button class="switch" role="switch" name="isolateOnCompromise" aria-label="Isolate compromised hosts" ${dis}></button></div>
    <div class="setting"><div><div class="setting__label">Investigate ingested alerts</div><div class="setting__help">Run the engine in the background for every HIGH or CRITICAL alert that arrives through the ingest API.</div></div>
      <button class="switch" role="switch" name="autoInvestigate" aria-label="Investigate ingested alerts" ${dis}></button></div>
    <div class="setting"><div><div class="setting__label">Investigation engine</div><div class="setting__help">The rule-based playbook runs the same steps every time and needs no external service. The LLM agent drives the same tools through Groq and falls back to the playbook on error.</div></div>
      <div class="seg" id="st-engine"><button data-e="playbook" ${dis}>Rule-based playbook</button><button data-e="llm" ${health.engine.llm && configure ? '' : 'disabled'} ${health.engine.llm ? '' : 'title="Set GROQ_API_KEY to enable"'}>LLM agent</button></div></div>
    <div class="setting"><div><div class="setting__label">Max agent iterations</div><div class="setting__help">Upper bound on model round-trips per LLM run (4 to 30).</div></div>
      <input class="input input--mono" type="number" min="4" max="30" name="maxIterations" ${dis}></div>
    <div class="setting"><div><div class="setting__label">Retention</div><div class="setting__help">Closed alerts, their investigations and telemetry older than this are purged hourly (7 to 730 days).</div></div>
      <input class="input input--mono" type="number" min="7" max="730" name="alertRetentionDays" ${dis}></div>
    <div class="setting"><div><div class="setting__label">Automatic block expiry</div><div class="setting__help">Blocks published by the engine lift themselves after this many hours, so a shared or reassigned address is not shut out forever. 0 keeps them until someone removes them.</div></div>
      <input class="input input--mono" type="number" min="0" max="720" name="autoBlockTtlHours" ${dis}></div>
    <div class="setting setting--stack"><div><div class="setting__label">First-response targets</div><div class="setting__help">Minutes from detection to the first owner, note or status change. Reports measure every alert against these.</div></div>
      <div class="sla-inputs">${[['slaCritical', 'Critical'], ['slaHigh', 'High'], ['slaMedium', 'Medium'], ['slaLow', 'Low']].map(([k, t]) => `<label class="field"><span>${t}</span><input class="input input--mono" type="number" min="1" max="10080" name="${k}" ${dis}></label>`).join('')}</div></div>
  </section>`;
}

function bindPolicy(config) {
  const { el } = ctx;
  const base = () => ({ ...config, engine: config.engine || 'playbook' });
  const draft = base();
  const saveBtn = $('#st-save', el);
  const dirty = () => { saveBtn.disabled = JSON.stringify(draft) === JSON.stringify(base()); };
  $$('.panel [name]', el).forEach((f) => {
    const k = f.getAttribute('name');
    if (!(k in draft) && !['autoInvestigate', 'autoBlockTtlHours'].includes(k)) return;
    if (f.classList.contains('switch')) {
      f.setAttribute('aria-checked', String(Boolean(draft[k])));
      f.onclick = () => { draft[k] = !draft[k]; f.setAttribute('aria-checked', String(draft[k])); dirty(); };
    } else {
      f.value = draft[k] ?? '';
      f.oninput = f.onchange = () => { draft[k] = f.type === 'number' ? Number(f.value) : f.value; dirty(); };
    }
  });
  const paintEngine = () => $$('#st-engine button', el).forEach((b) => b.classList.toggle('is-on', b.dataset.e === draft.engine));
  $$('#st-engine button', el).forEach((b) => { b.onclick = () => { draft.engine = b.dataset.e; paintEngine(); dirty(); }; });
  paintEngine();
  saveBtn.onclick = () => busy(saveBtn, async () => {
    try {
      const { autoContainmentThreshold, isolateOnCompromise, autoInvestigate, engine, maxIterations, alertRetentionDays, autoBlockTtlHours, slaCritical, slaHigh, slaMedium, slaLow } = draft;
      const saved = await api('/config', { method: 'PUT', body: { autoContainmentThreshold, isolateOnCompromise, autoInvestigate: Boolean(autoInvestigate), engine, maxIterations, alertRetentionDays, autoBlockTtlHours: autoBlockTtlHours ?? 0, slaCritical, slaHigh, slaMedium, slaLow } });
      Object.assign(config, saved);
      state.config = saved;
      toast('Policy saved', 'Applies to the next investigation.', 'ok');
      emit('data:changed');
      dirty();
    } catch (e) { toast('Not saved', e.message, 'error'); }
  });
}

// ---- Integrations ----------------------------------------------------------
function integrationsPanel(h) {
  const e = h.enforcement || {};
  const isSb = h.storage.kind === 'supabase';
  const row = (name, ok, text, env) => `<div class="setting"><div><div class="setting__label row"><span class="live-dot ${ok === true ? '' : ok === 'warn' ? 'live-dot--warn' : 'live-dot--off'}"></span>${name}</div><div class="setting__help">${text}${env ? `<br><span class="mono">${env}</span>` : ''}</div></div></div>`;
  return `<section class="panel">
    <div class="panel__head"><h2 class="panel__title">Integrations</h2><span class="panel__meta small muted">set in .env, restart to apply</span></div>
    ${row(`Enforcement: ${esc(e.label || e.mode)}`, e.mode === 'record' ? 'warn' : e.warning ? 'warn' : true, esc(e.warning || e.detail || ''), 'ENFORCEMENT_MODE=feed | webhook | cloudflare | record')}
    ${row(`Storage: ${isSb ? 'Supabase Postgres' : 'Local JSON file'}`, h.storage.ok ? (isSb ? true : 'warn') : false, esc(h.storage.warning || h.storage.detail || (h.storage.ok ? 'Connected' : 'Unavailable')) + (isSb ? '' : '. Fine for one node; use Supabase for anything shared.'), isSb ? '' : 'SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY')}
    ${row('NVD CVE API', h.intel.nvd_key ? true : 'warn', h.intel.nvd_key ? 'API key set: 50 requests per 30 s.' : 'No key: NVD allows 5 requests per 30 s, so sync is slow.', 'NVD_API_KEY')}
    ${row('IP reputation', h.intel.reputation ? true : 'warn', h.intel.reputation ? `Checked live against ${esc((h.intel.sources || []).join(', '))}.${h.intel.abuseipdb ? '' : ' Add an AbuseIPDB key for community report counts.'}` : 'Off (AEGIS_INTEL=off).', 'ABUSEIPDB_API_KEY (optional)')}
    ${row('LLM agent (Groq)', h.engine.llm ? true : 'warn', h.engine.llm ? `Model ${esc(h.engine.model)}.` : 'Off. The rule-based playbook handles every run. Add a free key from console.groq.com to turn it on.', 'GROQ_API_KEY')}
    ${h.demo && can('manage') ? `<div class="setting"><div><div class="setting__label">Demo mode</div><div class="setting__help">AEGIS_DEMO=1 is set. Sample data can be restored; never enable this in production.</div></div><button class="btn btn--danger btn--sm" id="st-reset">Reset sample data</button></div>` : ''}
  </section>`;
}

// ---- Account ----------------------------------------------------------------
function accountPanel() {
  const u = state.user || {};
  return `<section class="panel">
    <div class="panel__head"><h2 class="panel__title">Your account</h2><span class="panel__meta">${pill(u.role, ROLE_TEXT[u.role])}</span></div>
    <div class="panel__body">
      <dl class="kv"><dt>Name</dt><dd>${esc(u.name)}</dd><dt>Email</dt><dd class="mono">${esc(u.email)}</dd><dt>Last sign-in</dt><dd>${u.last_login_at ? esc(stamp(u.last_login_at)) : 'this session'}</dd></dl>
      <form id="pw-form" class="form-grid mt-12" novalidate>
        <label class="field"><span>Current password</span><input class="input" type="password" name="current_password" autocomplete="current-password" required></label>
        <label class="field"><span>New password</span><input class="input" type="password" name="new_password" autocomplete="new-password" minlength="10" required></label>
        <div class="span-2 row"><span class="form-error grow" id="pw-err"></span><button class="btn" id="pw-btn">${icon('lock')}Change password</button></div>
      </form>
      <p class="small muted" style="margin:6px 0 0">At least 10 characters with letters and a digit. Changing it signs out your other sessions.</p>
    </div>
  </section>`;
}

function bindAccount() {
  const form = $('#pw-form', ctx.el);
  form.onsubmit = (e) => {
    e.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    busy($('#pw-btn', form), async () => {
      $('#pw-err', form).textContent = '';
      try {
        await api('/auth/password', { method: 'POST', body });
        form.reset();
        toast('Password changed', 'Other sessions have been signed out.', 'ok');
      } catch (err) { $('#pw-err', form).textContent = err.message; }
    });
  };
}

// ---- Team -----------------------------------------------------------------
function paintTeam() {
  const box = $('#st-team', ctx.el);
  const me = state.user.id;
  box.innerHTML = `
    <div class="panel__head"><h2 class="panel__title">Team</h2><span class="panel__meta">${ctx.users.filter((u) => !u.disabled).length} active</span><button class="btn btn--sm" style="margin-left:12px" id="u-add">${icon('plus')}Add user</button></div>
    <div class="table-wrap"><table class="table">
      <thead><tr><th>User</th><th style="width:150px">Role</th><th class="hide-sm">Last sign-in</th><th style="width:1%"></th></tr></thead>
      <tbody class="rows-in">${ctx.users.map((u, i) => `
        <tr style="--i:${i}" class="${u.disabled ? 'is-dim' : ''}" data-uid="${u.id}">
          <td><span class="cell-main">${esc(u.name)}${u.id === me ? ' <span class="tag">you</span>' : ''}${u.disabled ? ' <span class="tag tag--warn">disabled</span>' : ''}</span><span class="cell-sub mono">${esc(u.email)}</span></td>
          <td><select class="select" data-role ${u.disabled ? 'disabled' : ''}>${Object.entries(ROLE_TEXT).map(([k, t]) => `<option value="${k}" ${u.role === k ? 'selected' : ''}>${t}</option>`).join('')}</select></td>
          <td class="hide-sm small muted">${u.last_login_at ? ago(u.last_login_at) : 'never'}</td>
          <td><div class="row" style="flex-wrap:nowrap"><button class="btn btn--sm btn--ghost" data-pw title="Set a new password">${icon('key')}</button>
            ${u.id === me ? '' : `<button class="btn btn--sm btn--ghost" data-toggle>${u.disabled ? 'Enable' : 'Disable'}</button>`}</div></td>
        </tr>`).join('')}</tbody>
    </table></div>`;
  $('#u-add', box).onclick = openAddUser;
  $$('tr[data-uid]', box).forEach((tr) => {
    const u = ctx.users.find((x) => x.id === Number(tr.dataset.uid));
    const sel = $('[data-role]', tr);
    sel.onchange = () => patchUser(u, { role: sel.value }, `${u.name} is now ${ROLE_TEXT[sel.value]}`, () => { sel.value = u.role; });
    const t = $('[data-toggle]', tr);
    if (t) t.onclick = () => busy(t, () => patchUser(u, { disabled: !u.disabled }, u.disabled ? `${u.name} can sign in again` : `${u.name} is signed out and blocked`));
    $('[data-pw]', tr).onclick = () => openResetPassword(u);
  });
  hydrateIcons(box);
}

async function patchUser(u, body, msg, revert) {
  try {
    const updated = await api(`/users/${u.id}`, { method: 'PATCH', body });
    Object.assign(u, updated);
    toast('User updated', msg, 'ok');
    paintTeam();
  } catch (err) {
    toast('Not changed', err.message, 'error');
    if (revert) revert();
  }
}

function openAddUser() {
  const m = modal(`
    <div class="modal__head"><h2 class="modal__title">Add user</h2><p class="small muted" style="margin:4px 0 0">Share the initial password out of band. They can change it under Settings.</p></div>
    <form class="modal__body" id="u-form" novalidate><div class="form-grid">
      <label class="field"><span>Name</span><input class="input" name="name" required maxlength="60" autocomplete="off"></label>
      <label class="field"><span>Email</span><input class="input" type="email" name="email" required autocomplete="off"></label>
      <label class="field"><span>Role</span><select class="select" name="role">${Object.entries(ROLE_TEXT).map(([k, t]) => `<option value="${k}" ${k === 'analyst' ? 'selected' : ''}>${t}: ${ROLE_HELP[k]}</option>`).join('')}</select></label>
      <label class="field"><span>Initial password</span><div class="row" style="flex-wrap:nowrap"><input class="input input--mono grow" name="password" required minlength="10" autocomplete="new-password"><button type="button" class="btn btn--sm" id="u-gen">Generate</button></div></label>
    </div></form>
    <div class="modal__foot"><span class="form-error" id="u-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="u-save">Add user</button></div>`);
  const form = $('#u-form', m);
  $('#u-gen', m).onclick = () => { form.elements.namedItem('password').value = generatePassword(); };
  const go = (e) => {
    e.preventDefault();
    busy($('#u-save', m), async () => {
      try {
        const u = await api('/users', { method: 'POST', body: Object.fromEntries(new FormData(form)) });
        ctx.users.push(u);
        closeLayer();
        toast('User added', `${u.email} as ${ROLE_TEXT[u.role]}`, 'ok');
        paintTeam();
      } catch (err) { $('#u-err', m).textContent = err.message; }
    });
  };
  form.onsubmit = go;
  $('#u-save', m).onclick = go;
}

function openResetPassword(u) {
  const m = modal(`
    <div class="modal__head"><h2 class="modal__title">New password for ${esc(u.name)}</h2><p class="small muted" style="margin:4px 0 0">Their current sessions end immediately.</p></div>
    <div class="modal__body"><div class="row" style="flex-wrap:nowrap"><input class="input input--mono grow" id="rp-pw" value="${esc(generatePassword())}" autocomplete="off"><button class="btn btn--sm" id="rp-copy">${icon('copy')}Copy</button></div></div>
    <div class="modal__foot"><span class="form-error" id="rp-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="rp-go">Set password</button></div>`);
  $('#rp-copy', m).onclick = (e) => copyText($('#rp-pw', m).value, e.currentTarget);
  $('#rp-go', m).onclick = (e) => busy(e.currentTarget, async () => {
    try {
      await api(`/users/${u.id}`, { method: 'PATCH', body: { password: $('#rp-pw', m).value } });
      closeLayer();
      toast('Password set', `${u.email} must sign in again.`, 'ok');
    } catch (err) { $('#rp-err', m).textContent = err.message; }
  });
  hydrateIcons(m);
}

function generatePassword() {
  const abc = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
  const b = crypto.getRandomValues(new Uint8Array(16));
  const s = [...b].map((x) => (abc + '23456789')[x % (abc.length + 8)]).join('');
  return `${s.slice(0, 5)}-${s.slice(5, 10)}-${s.slice(10, 15)}${(b[15] % 8) + 2}`;
}

// ---- API keys ----------------------------------------------------------------
function paintKeys() {
  const box = $('#st-keys', ctx.el);
  const live = ctx.keys.filter((k) => !k.revoked_at);
  const dead = ctx.keys.filter((k) => k.revoked_at);
  box.innerHTML = `
    <div class="panel__head"><h2 class="panel__title">API keys</h2><span class="panel__meta">for sensors and firewalls</span><button class="btn btn--sm" style="margin-left:12px" id="k-add">${icon('key')}New key</button></div>
    ${live.length ? `<div class="table-wrap"><table class="table">
      <thead><tr><th>Name</th><th>Scope</th><th class="hide-sm">Last used</th><th style="width:1%"></th></tr></thead>
      <tbody class="rows-in">${live.map((k, i) => `<tr style="--i:${i}" data-kid="${k.id}">
        <td><span class="cell-main">${esc(k.name)}</span><span class="cell-sub"><span class="mono">${esc(k.prefix)}...</span> &middot; ${esc(k.created_by || '')} &middot; ${ago(k.created_at)}</span></td>
        <td>${k.scopes.map((s) => `<span class="tag">${esc(s)}</span>`).join(' ')}</td>
        <td class="hide-sm small muted">${k.last_used_at ? ago(k.last_used_at) : 'never'}</td>
        <td><button class="btn btn--sm btn--ghost" data-revoke>Revoke</button></td></tr>`).join('')}</tbody></table></div>`
      : `<div class="empty">${icon('key')}<b>No API keys</b><span class="small">Sensors need an <b>ingest</b> key to post alerts and logs. Firewalls need a <b>feed</b> key to pull the blocklist.</span></div>`}
    ${dead.length ? `<div class="table-foot">${dead.length} revoked key${dead.length === 1 ? '' : 's'} kept for the audit trail</div>` : ''}`;
  $('#k-add', box).onclick = openNewKey;
  $$('tr[data-kid]', box).forEach((tr) => {
    const btn = $('[data-revoke]', tr);
    btn.onclick = () => {
      if (!btn.dataset.armed) { btn.dataset.armed = '1'; btn.textContent = 'Confirm revoke'; btn.classList.add('btn--danger'); setTimeout(() => { if (btn.isConnected) { delete btn.dataset.armed; btn.textContent = 'Revoke'; btn.classList.remove('btn--danger'); } }, 4000); return; }
      busy(btn, async () => {
        try {
          const rec = await api(`/keys/${tr.dataset.kid}/revoke`, { method: 'POST', body: {} });
          Object.assign(ctx.keys.find((k) => String(k.id) === tr.dataset.kid), rec);
          toast('Key revoked', `${rec.name} stops working on its next request.`, 'ok');
          paintKeys();
        } catch (err) { toast('Not revoked', err.message, 'error'); }
      });
    };
  });
  hydrateIcons(box);
}

function openNewKey() {
  const m = modal(`
    <div class="modal__head"><h2 class="modal__title">New API key</h2><p class="small muted" style="margin:4px 0 0">Name it after the device that will use it, so the audit log stays readable.</p></div>
    <form class="modal__body" id="k-form" novalidate>
      <label class="field"><span>Name</span><input class="input" name="name" required maxlength="60" placeholder="suricata-dmz-01" autocomplete="off"></label>
      <div class="field mt-12"><span>Scope</span>
        <label class="row small"><input type="checkbox" name="ingest" checked> <b>ingest</b><span class="muted">post alerts, logs and inventory to /api/ingest/*</span></label>
        <label class="row small mt-8"><input type="checkbox" name="feed"> <b>feed</b><span class="muted">pull /api/feeds/blocklist.txt and isolate.txt</span></label>
      </div>
    </form>
    <div class="modal__foot"><span class="form-error" id="k-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="k-go">Create key</button></div>`);
  const form = $('#k-form', m);
  const go = (e) => {
    e.preventDefault();
    const scopes = ['ingest', 'feed'].filter((s) => form.elements.namedItem(s).checked);
    busy($('#k-go', m), async () => {
      try {
        const rec = await api('/keys', { method: 'POST', body: { name: form.elements.namedItem('name').value, scopes } });
        const { key, ...pub } = rec;
        ctx.keys.unshift(pub);
        paintKeys();
        showKey(m, rec);
      } catch (err) { $('#k-err', m).textContent = err.message; }
    });
  };
  form.onsubmit = go;
  $('#k-go', m).onclick = go;
}

function showKey(m, rec) {
  const o = location.origin;
  const snippets = [];
  if (rec.scopes.includes('ingest')) {
    snippets.push(['Install the Aegis agent on a Linux host (Node 18+)', `curl -fsSLO ${o}/agent/aegis-agent.js\nsudo AEGIS_URL=${o} AEGIS_KEY=${rec.key} \\\n  node aegis-agent.js --eve /var/log/suricata/eve.json \\\n  --access /var/log/nginx/access.log --auth /var/log/auth.log \\\n  --criticality HIGH --owner Platform`]);
    snippets.push(['Run it as a service (systemd)', `# /etc/systemd/system/aegis-agent.service\n[Unit]\nDescription=Aegis sensor agent\nAfter=network-online.target\n\n[Service]\nEnvironment=AEGIS_URL=${o}\nEnvironment=AEGIS_KEY=${rec.key}\nExecStart=/usr/bin/node /opt/aegis/aegis-agent.js --eve /var/log/suricata/eve.json --auth /var/log/auth.log --state /var/lib/aegis-agent.json\nRestart=always\n\n[Install]\nWantedBy=multi-user.target`]);
    snippets.push(['Push an Nmap scan into the inventory', `nmap -sV -O -oX scan.xml 10.0.0.0/24\ncurl -sS -X POST ${o}/api/ingest/assets \\\n  -H "Authorization: Bearer ${rec.key}" -H "Content-Type: application/xml" \\\n  --data-binary @scan.xml`]);
    snippets.push(['Stream Suricata EVE alerts (without the agent)', `tail -F /var/log/suricata/eve.json | grep --line-buffered '"event_type":"alert"' | \\\n  while read -r line; do printf '%s\\n' "$line" | curl -sS -X POST ${o}/api/ingest/alerts \\\n    -H "Authorization: Bearer ${rec.key}" -H "Content-Type: application/x-ndjson" --data-binary @-; done`]);
    snippets.push(['Send a batch of alerts (JSON)', `curl -sS -X POST ${o}/api/ingest/alerts \\\n  -H "Authorization: Bearer ${rec.key}" -H "Content-Type: application/json" \\\n  --data @alerts.json`]);
    snippets.push(['Send host logs', `curl -sS -X POST "${o}/api/ingest/logs?host_ip=10.0.0.5" \\\n  -H "Authorization: Bearer ${rec.key}" -H "Content-Type: text/plain" \\\n  --data-binary @/var/log/nginx/access.log`]);
  }
  if (rec.scopes.includes('feed')) {
    snippets.push(['Firewall feed URL (PAN-OS EDL, FortiGate threat feed, pfSense URL table)', `${o}/api/feeds/blocklist.txt\nAuth: Basic, any username, password = the key\n\ncurl -sS -H "Authorization: Bearer ${rec.key}" ${o}/api/feeds/blocklist.txt`]);
  }
  // The raw key exists only in this dialog, so a stray backdrop click must not close it.
  const scrim = document.querySelector('.scrim:last-of-type');
  if (scrim) scrim.onclick = null;
  m.querySelector('.modal__head').innerHTML = `<h2 class="modal__title">${esc(rec.name)} is ready</h2><p class="small muted" style="margin:4px 0 0">Copy the key now. Only its hash is stored, so it cannot be shown again.</p>`;
  m.querySelector('.modal__body').outerHTML = `<div class="modal__body">
    <div class="secret"><code class="mono">${esc(rec.key)}</code><button class="btn btn--sm" id="k-copy">${icon('copy')}Copy</button></div>
    ${snippets.map(([t, s], i) => `<div class="mt-12"><div class="row small" style="margin-bottom:6px"><b class="grow">${esc(t)}</b><button class="btn btn--sm btn--ghost" data-snip="${i}">${icon('copy')}</button></div><pre class="snippet mono">${esc(s)}</pre></div>`).join('')}
  </div>`;
  m.querySelector('.modal__foot').innerHTML = '<button class="btn btn--primary" data-close>I have stored the key</button>';
  $('#k-copy', m).onclick = (e) => copyText(rec.key, e.currentTarget);
  $$('[data-snip]', m).forEach((b) => { b.onclick = () => copyText(snippets[Number(b.dataset.snip)][1], b); });
  $$('[data-close]', m).forEach((b) => { b.onclick = closeLayer; });
  hydrateIcons(m);
}

// ---- Demo reset ------------------------------------------------------------
function openReset() {
  const m = modal(`
    <div class="modal__head"><h2 class="modal__title">Reset sample data?</h2></div>
    <div class="modal__body"><p style="margin:0;color:var(--ink-2)">Alerts, investigations, rules, telemetry, assets and settings go back to the sample state. Users and API keys are kept. Type <b class="mono">reset</b> to confirm.</p>
      <input class="input input--mono mt-12" id="rs-confirm" autocomplete="off"></div>
    <div class="modal__foot"><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--danger" id="rs-go" disabled>Reset</button></div>`);
  const input = $('#rs-confirm', m);
  input.oninput = () => { $('#rs-go', m).disabled = input.value.trim().toLowerCase() !== 'reset'; };
  $('#rs-go', m).onclick = (e) => busy(e.currentTarget, async () => {
    try {
      await api('/reset', { method: 'POST', body: {} });
      closeLayer();
      toast('Sample data restored', '', 'ok');
      emit('data:changed');
      render(ctx);
    } catch (err) { toast('Reset failed', err.message, 'error'); }
  });
}
// ---- Notifications -----------------------------------------------------------
const KIND_TEXT = { slack: 'Slack', teams: 'Microsoft Teams', webhook: 'Webhook' };
const EVENT_TEXT = { alert: 'New alerts', containment: 'Containment rules', verdict: 'Verdicts' };

function paintNotify() {
  const box = $('#st-notify', ctx.el);
  const list = ctx.channels || [];
  box.innerHTML = `
    <div class="panel__head"><h2 class="panel__title">Notifications</h2><span class="panel__meta">Slack, Teams or a signed webhook</span><button class="btn btn--sm" style="margin-left:12px" id="n-add">${icon('plus')}Add</button></div>
    ${list.length ? `<div class="channels">${list.map((c) => `
      <div class="channel ${c.enabled ? '' : 'is-dim'}" data-cid="${esc(c.id)}">
        <div class="channel__top">
          <span class="channel__kind channel__kind--${esc(c.kind)}">${esc(KIND_TEXT[c.kind] || c.kind)}</span>
          <b class="grow truncate">${esc(c.name)}</b>
          <button class="switch" role="switch" aria-checked="${c.enabled}" aria-label="Deliver to ${esc(c.name)}" data-n-toggle></button>
        </div>
        <div class="channel__url mono small truncate" title="${esc(c.url_hint)}">${esc(c.url_hint)}${c.signed ? ' <span class="tag">signed</span>' : ''}</div>
        <div class="small muted">${esc(label(c.min_severity))} and above &middot; ${c.events.map((e) => esc(EVENT_TEXT[e] || e)).join(', ')}</div>
        <div class="channel__foot">
          <span class="small grow ${c.last ? (c.last.ok ? '' : 'warn-text') : 'muted'}" title="${c.last ? esc(c.last.detail || '') : ''}">${c.last ? `${c.last.ok ? 'Delivered' : 'Failed'} ${ago(c.last.at)} &middot; ${esc(c.last.event)}${c.last.ok ? '' : `: ${esc(String(c.last.detail || '').slice(0, 60))}`}` : 'Nothing sent yet'}</span>
          <button class="btn btn--sm btn--ghost" data-n-test>${icon('send')}Test</button>
          <button class="icon-btn icon-btn--bare" title="Remove channel" aria-label="Remove ${esc(c.name)}" data-n-del>${icon('trash')}</button>
        </div>
      </div>`).join('')}</div>`
      : `<div class="empty">${icon('send')}<b>No channels</b><span class="small">Post critical alerts, new blocks and verdicts to the room your on-call team already watches.</span></div>`}`;

  $('#n-add', box).onclick = openNewChannel;
  $$('[data-cid]', box).forEach((row) => {
    const c = list.find((x) => x.id === row.dataset.cid);
    const sw = $('[data-n-toggle]', row);
    sw.onclick = async () => {
      sw.disabled = true;
      try {
        Object.assign(c, await api(`/notify/channels/${c.id}`, { method: 'PATCH', body: { enabled: !c.enabled } }));
        toast(c.enabled ? 'Channel resumed' : 'Channel paused', c.name, 'ok');
        paintNotify();
      } catch (e) { toast('Not changed', e.message, 'error'); sw.disabled = false; }
    };
    const test = $('[data-n-test]', row);
    test.onclick = () => busy(test, async () => {
      try {
        const r = await api(`/notify/channels/${c.id}/test`, { method: 'POST', body: {} });
        toast('Test delivered', `${c.name}: ${r.detail}`, 'ok');
      } catch (e) { toast('Test failed', e.message, 'error'); }
      ctx.channels = await api('/notify/channels').catch(() => ctx.channels);
      paintNotify();
    });
    const del = $('[data-n-del]', row);
    del.onclick = async () => {
      if (!del.dataset.armed) {
        del.dataset.armed = '1';
        del.classList.add('is-armed');
        del.title = 'Click again to remove';
        setTimeout(() => { if (del.isConnected) { delete del.dataset.armed; del.classList.remove('is-armed'); del.title = 'Remove channel'; } }, 3000);
        return;
      }
      try {
        await api(`/notify/channels/${c.id}`, { method: 'DELETE' });
        ctx.channels = list.filter((x) => x !== c);
        toast('Channel removed', c.name, 'ok');
        paintNotify();
      } catch (e) { toast('Not removed', e.message, 'error'); }
    };
  });
  hydrateIcons(box);
}

function openNewChannel() {
  const m = modal(`
    <div class="modal__head"><h2 class="modal__title">Add notification channel</h2><p class="small muted" style="margin:4px 0 0">The URL and secret stay on the server. Only a masked hint is shown after saving.</p></div>
    <form class="modal__body form-grid" id="n-form" novalidate>
      <label class="field"><span>Name</span><input class="input" name="name" maxlength="60" placeholder="#soc-alerts" autocomplete="off"></label>
      <label class="field"><span>Type</span><select class="select" name="kind"><option value="slack">Slack incoming webhook</option><option value="teams">Microsoft Teams workflow</option><option value="webhook">Generic webhook (JSON)</option></select></label>
      <label class="field span-2"><span>Webhook URL</span><input class="input input--mono" name="url" placeholder="https://hooks.slack.com/services/..." autocomplete="off" spellcheck="false"></label>
      <label class="field span-2" id="n-secret" hidden><span>Signing secret <span class="muted">(optional, 16+ characters)</span></span><input class="input input--mono" name="secret" autocomplete="off" spellcheck="false" placeholder="Used for the X-Aegis-Signature HMAC header"></label>
      <label class="field"><span>Minimum severity</span><select class="select" name="min_severity">${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => `<option value="${s}" ${s === 'HIGH' ? 'selected' : ''}>${label(s)} and above</option>`).join('')}</select></label>
      <div class="field"><span>Send</span><div class="stack" style="gap:4px">${Object.entries(EVENT_TEXT).map(([k, t]) => `<label class="check"><input type="checkbox" name="ev_${k}" checked><span>${t}</span></label>`).join('')}</div></div>
    </form>
    <div class="modal__foot"><span class="form-error" id="n-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="n-go">Add channel</button></div>`);
  const form = $('#n-form', m);
  const kind = form.elements.namedItem('kind');
  const hints = { slack: 'https://hooks.slack.com/services/...', teams: 'https://prod-00.westus.logic.azure.com/workflows/...', webhook: 'https://soar.example.com/hooks/aegis' };
  kind.onchange = () => { $('#n-secret', m).hidden = kind.value !== 'webhook'; form.elements.namedItem('url').placeholder = hints[kind.value]; };
  const go = (e) => {
    e.preventDefault();
    const v = (n) => form.elements.namedItem(n).value;
    const body = { name: v('name'), kind: v('kind'), url: v('url').trim(), min_severity: v('min_severity'), events: Object.keys(EVENT_TEXT).filter((k) => form.elements.namedItem(`ev_${k}`).checked) };
    if (body.kind === 'webhook' && v('secret').trim()) body.secret = v('secret').trim();
    busy($('#n-go', m), async () => {
      try {
        const c = await api('/notify/channels', { method: 'POST', body });
        ctx.channels = [...(ctx.channels || []), c];
        closeLayer();
        toast('Channel added', 'Send a test to confirm it works.', 'ok');
        paintNotify();
      } catch (err) { $('#n-err', m).textContent = err.message; }
    });
  };
  form.onsubmit = go;
  $('#n-go', m).onclick = go;
}