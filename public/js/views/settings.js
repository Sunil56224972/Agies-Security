import { $, $$, api, esc, ago, toast, busy, emit, state, modal, closeLayer } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

let ctx = null;

export async function render({ el, navigate }) {
  ctx = { el, navigate };
  const [config, health, audit] = await Promise.all([api('/config'), api('/health'), api('/audit?limit=30')]);
  const isSb = health.storage.kind === 'supabase';
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <div class="eyebrow">${icon('sliders')}Platform</div>
        <h1 class="page-title">Settings</h1>
        <p class="page-sub">Response policy, engine and storage. Changes apply to the next investigation and are written to the audit trail.</p>
      </div>
      <div class="page-actions"><button class="btn btn--primary" id="st-save" disabled>${icon('check')}Save changes</button></div>
    </div>
    <div class="grid grid-2-1 reveal">
      <div class="stack">
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Response policy</h2></div>
          <div class="setting"><div><div class="setting__label">Auto-containment threshold</div><div class="setting__help">Lowest alert severity at which a failed or successful attack triggers a perimeter block without asking. Confirmed compromises are always blocked unless this is off.</div></div>
            <select class="select" name="autoContainmentThreshold">${['OFF', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((v) => `<option value="${v}">${v === 'OFF' ? 'Off (recommend only)' : `${v[0]}${v.slice(1).toLowerCase()} and above`}</option>`).join('')}</select></div>
          <div class="setting"><div><div class="setting__label">Isolate compromised hosts</div><div class="setting__help">When an attack is confirmed, also quarantine the internal host from everything except the management VLAN.</div></div>
            <button class="switch" role="switch" name="isolateOnCompromise" aria-label="Isolate compromised hosts"></button></div>
          <div class="setting"><div><div class="setting__label">Alert retention</div><div class="setting__help">Days to keep closed alerts and their investigations (7 to 730).</div></div>
            <input class="input input--mono" type="number" min="7" max="730" name="alertRetentionDays"></div>
        </section>
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Investigation engine</h2>${health.engine.llm ? `<span class="tag tag--ok panel__meta">${esc(health.engine.model)}</span>` : '<span class="tag panel__meta">no GROQ_API_KEY</span>'}</div>
          <div class="setting"><div><div class="setting__label">Default engine</div><div class="setting__help">The playbook is deterministic and always available. The LLM agent drives the same tools through Groq, and falls back to the playbook if the model fails.</div></div>
            <div class="seg" id="st-engine"><button data-e="playbook">Playbook</button><button data-e="llm" ${health.engine.llm ? '' : 'disabled title="Set GROQ_API_KEY to enable"'}>LLM agent</button></div></div>
          <div class="setting"><div><div class="setting__label">Max agent iterations</div><div class="setting__help">Upper bound on model round-trips per run (4 to 30).</div></div>
            <input class="input input--mono" type="number" min="4" max="30" name="maxIterations"></div>
        </section>
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">You</h2></div>
          <div class="setting"><div><div class="setting__label">Analyst name</div><div class="setting__help">Recorded on rules, overrides and status changes you make.</div></div>
            <input class="input" name="analystName" maxlength="60"></div>
        </section>
      </div>
      <div class="stack">
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Storage</h2><span class="panel__meta row"><span class="live-dot ${health.storage.ok ? (isSb ? '' : 'live-dot--warn') : 'live-dot--off'}"></span>${esc(health.storage.label)}</span></div>
          <div class="panel__body stack">
            <dl class="dl" style="grid-template-columns:90px 1fr"><dt>Backend</dt><dd>${isSb ? 'Supabase Postgres' : 'Local JSON sandbox'}</dd><dt>Status</dt><dd>${esc(health.storage.detail || (health.storage.ok ? 'Connected' : 'Unavailable'))}</dd><dt>Uptime</dt><dd class="mono">${Math.floor(health.uptime_s / 60)}m ${health.uptime_s % 60}s</dd></dl>
            ${isSb ? '' : `<div class="notice notice--warn">${icon('database')}<div>${health.storage.warning ? `${esc(health.storage.warning)}<br>` : ''}To persist to Supabase, set <span class="mono">SUPABASE_URL</span> and <span class="mono">SUPABASE_SERVICE_ROLE_KEY</span> in <span class="mono">.env</span>, apply <span class="mono">supabase/migrations</span>, and restart.</div></div>`}
            <button class="btn btn--danger" id="st-reset">${icon('refresh')}Reset demo data</button>
          </div>
        </section>
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Audit trail</h2><span class="panel__meta">last ${audit.length}</span></div>
          <div class="feed" style="max-height:420px;overflow:auto">${audit.map((a) => `<div class="feed__item"><span class="feed__dot"></span><div><div class="feed__text"><b>${esc(a.actor)}</b> <span class="mono small">${esc(a.action)}</span> ${esc(a.target || '')}</div><div class="feed__time">${ago(a.created_at)}${a.detail ? ` &middot; ${esc(String(a.detail).slice(0, 80))}` : ''}</div></div></div>`).join('')}</div>
        </section>
      </div>
    </div>`;

  const draft = { ...config, engine: config.engine || 'playbook' };
  const saveBtn = $('#st-save', el);
  const dirty = () => { saveBtn.disabled = JSON.stringify(draft) === JSON.stringify({ ...config, engine: config.engine || 'playbook' }); };
  $$('[name]', el).forEach((f) => {
    const k = f.getAttribute('name');
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
      const saved = await api('/config', { method: 'PUT', body: draft });
      Object.assign(config, saved);
      state.config = saved;
      toast('Settings saved', 'Applies to the next investigation.', 'ok');
      emit('data:changed');
      dirty();
    } catch (e) { toast('Not saved', e.message, 'error'); }
  });

  $('#st-reset', el).onclick = () => {
    const m = modal(`
      <div class="modal__head"><div class="eyebrow">Destructive</div><h2 class="modal__title">Reset demo data?</h2></div>
      <div class="modal__body"><p style="margin:0;color:var(--ink-2)">Alerts, investigations, rules, telemetry and settings go back to the seed state. This also applies to Supabase if it is connected. Type <b class="mono">reset</b> to confirm.</p>
        <input class="input input--mono mt-12" id="rs-confirm" autocomplete="off"></div>
      <div class="modal__foot"><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--danger" id="rs-go" disabled>Reset everything</button></div>`);
    const input = $('#rs-confirm', m);
    input.oninput = () => { $('#rs-go', m).disabled = input.value.trim().toLowerCase() !== 'reset'; };
    $('#rs-go', m).onclick = (e) => busy(e.currentTarget, async () => {
      try {
        await api('/reset', { method: 'POST' });
        closeLayer();
        toast('Demo data restored', 'Seed alerts and telemetry are back.', 'ok');
        emit('data:changed');
        render(ctx);
      } catch (err) { toast('Reset failed', err.message, 'error'); }
    });
  };
  hydrateIcons(el);
}

export function onDataChanged() {}