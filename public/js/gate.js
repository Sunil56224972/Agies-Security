import { $, esc, api, toast } from './core.js';
import { icon, hydrateIcons } from './icons.js';

// Sign-in and first-run setup. Resolves once a session exists.
const gate = () => $('#gate');

function frame(inner) {
  return `
    <div class="gate__side">
      <div class="gate__brand">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round" stroke-linecap="round" aria-hidden="true"><path d="M12 2.5 4 5.5v6c0 5 3.4 8.4 8 10 4.6-1.6 8-5 8-10v-6z"/><path d="M12 2.5v19"/></svg>
        <span>Aegis</span>
      </div>
      <div class="gate__copy">
        <p class="gate__lede">Alert triage, evidence and containment in one place.</p>
        <ul class="gate__facts">
          <li><span>Ingest</span>Suricata EVE and host logs over an API key</li>
          <li><span>Context</span>Inventory matched against NVD CPE ranges</li>
          <li><span>Contain</span>Rules pushed to your firewall and read back</li>
        </ul>
      </div>
      <div class="gate__foot mono" id="gate-host"></div>
    </div>
    <div class="gate__main"><div class="gate__card">${inner}</div></div>`;
}

const field = (name, label, type = 'text', extra = '') =>
  `<label class="field"><span>${label}</span><input class="input" name="${name}" type="${type}" ${extra}></label>`;

function render(st) {
  const g = gate();
  if (st.needs_setup) {
    g.innerHTML = frame(`
      <h1 class="gate__title">Create the first administrator</h1>
      <p class="gate__sub">This install has no accounts yet. The person who completes this form owns it; add your team from Settings afterwards.</p>
      <form id="gate-form" class="gate__form" novalidate>
        ${field('name', 'Full name', 'text', 'autocomplete="name" required autofocus')}
        ${field('email', 'Work email', 'email', 'autocomplete="username" required')}
        ${field('password', 'Password', 'password', 'autocomplete="new-password" minlength="10" required')}
        <small class="gate__help">At least 10 characters with letters and a digit.</small>
        ${st.setup_token ? field('setup_token', 'Setup token', 'password', 'autocomplete="off" required') + '<small class="gate__help">The value of <code>AEGIS_SETUP_TOKEN</code> on the server.</small>' : ''}
        <div class="gate__err" id="gate-err" role="alert"></div>
        <button class="btn btn--primary gate__submit" type="submit">Create account and sign in</button>
      </form>`);
  } else {
    g.innerHTML = frame(`
      <h1 class="gate__title">Sign in</h1>
      <p class="gate__sub">Use the account your Aegis administrator created for you.</p>
      <form id="gate-form" class="gate__form" novalidate>
        ${field('email', 'Email', 'email', 'autocomplete="username" required autofocus')}
        ${field('password', 'Password', 'password', 'autocomplete="current-password" required')}
        <div class="gate__err" id="gate-err" role="alert"></div>
        <button class="btn btn--primary gate__submit" type="submit">Sign in</button>
      </form>
      <p class="gate__note small muted">Forgot your password? An administrator can reset it under Settings &rsaquo; Team.</p>`);
  }
  $('#gate-host').textContent = location.host;
  hydrateIcons(g);
}

export function showGate(st) {
  return new Promise((resolve) => {
    $('#shell').hidden = true;
    const g = gate();
    g.hidden = false;
    render(st);
    requestAnimationFrame(() => g.classList.add('is-in'));
    const form = $('#gate-form');
    const errEl = $('#gate-err');
    setTimeout(() => { const f = form.querySelector('[autofocus]'); if (f) f.focus(); }, 60);
    form.onsubmit = async (e) => {
      e.preventDefault();
      const body = Object.fromEntries(new FormData(form));
      const btn = form.querySelector('button[type=submit]');
      errEl.textContent = '';
      form.classList.remove('is-shake');
      btn.disabled = true;
      btn.classList.add('is-busy');
      try {
        const r = await api(st.needs_setup ? '/auth/setup' : '/auth/login', { method: 'POST', body });
        g.classList.remove('is-in');
        g.classList.add('is-out');
        setTimeout(() => { g.hidden = true; g.classList.remove('is-out'); g.innerHTML = ''; resolve(r.user); }, 260);
        if (st.needs_setup) toast('Administrator created', 'Next: add hosts under Assets and issue a sensor key under Settings.', 'ok', 7000);
      } catch (err) {
        errEl.textContent = err.message;
        void form.offsetWidth;
        form.classList.add('is-shake');
        if (err.status === 409) setTimeout(() => location.reload(), 900);
      } finally {
        btn.disabled = false;
        btn.classList.remove('is-busy');
      }
    };
  });
}

export async function signOut() {
  try { await api('/auth/logout', { method: 'POST' }); } catch { /* already gone */ }
  location.hash = '';
  location.reload();
}

export { icon, esc };