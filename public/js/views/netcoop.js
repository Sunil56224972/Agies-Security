import { $, $$, api, esc, label, emptyState, toast, busy, pill, copyText, num } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

// NetCoop AI — Multi-agent cooperative network fault diagnosis.
// Completely self-contained: does NOT call any Aegis API endpoint.
// All calls go to /api/netcoop/*.

let ctx = null;

const r2 = (v) => (v == null ? '-' : Math.round(v * 100) / 100);

const CONF_COLORS = { high: 'var(--ok, #22c55e)', moderate: 'var(--warn, #eab308)', low: 'var(--crit, #ef4444)', negligible: 'var(--muted, #6b7280)' };
const confBar = (pct) => {
  const p = Math.max(0, Math.min(100, Math.round(pct)));
  const cat = p >= 80 ? 'high' : p >= 50 ? 'moderate' : p >= 25 ? 'low' : 'negligible';
  return `<div class="nc-conf"><div class="nc-conf__track"><div class="nc-conf__fill nc-conf--${cat}" style="width:${p}%"></div></div><span class="nc-conf__val mono">${p}%</span><span class="nc-conf__cat">${cat}</span></div>`;
};

const levelPill = (lvl) => {
  const m = { critical: 'crit', elevated: 'med', normal: 'ok' };
  return pill(m[lvl] || 'ok', lvl || 'normal');
};

const agentLabel = (id) => label((id || '').replace(/_agent$/, '').replace(/_/g, ' '));

// ─── Render ──────────────────────────────────────────────────────────────────
export async function render({ el }) {
  ctx = { el, result: null, scenarios: [] };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">${icon('activity')} NetCoop AI</h1>
        <p class="page-sub">Multi-agent cooperative network fault diagnosis. Five specialised agents analyse telemetry, exchange structured messages, and collaboratively diagnose network faults.</p>
      </div>
    </div>

    <div class="nc-top">
      <!-- Input panel -->
      <section class="panel nc-panel-input">
        <div class="panel__head"><h2 class="panel__title">${icon('upload')} Telemetry input</h2></div>
        <div class="nc-input-body">
          <textarea id="nc-raw" class="textarea nc-textarea" rows="12" spellcheck="false" placeholder='Paste JSON, NDJSON or CSV telemetry here...\n\nOr click a test scenario on the right →'></textarea>
          <div class="nc-input-actions">
            <button class="btn btn--primary" id="nc-run">${icon('play')} Run diagnosis</button>
            <button class="btn" id="nc-clear">${icon('x')} Clear</button>
            <span class="nc-status small mono" id="nc-status"></span>
          </div>
        </div>
      </section>

      <!-- Scenarios panel -->
      <section class="panel nc-panel-scenarios">
        <div class="panel__head"><h2 class="panel__title">${icon('database')} Test scenarios</h2><span class="panel__meta">click to load &amp; run</span></div>
        <div class="nc-scenarios-body" id="nc-scenarios">
          <div class="skeleton" style="height:200px"></div>
        </div>
      </section>
    </div>

    <div id="nc-results"></div>`;
  hydrateIcons(el);

  $('#nc-run', el).onclick = () => runDiagnosis();
  $('#nc-clear', el).onclick = () => {
    $('#nc-raw', el).value = '';
    $('#nc-results', el).innerHTML = '';
    ctx.result = null;
    $('#nc-status', el).textContent = '';
  };

  try {
    const data = await api('/netcoop/scenarios');
    ctx.scenarios = data.scenarios || [];
    paintScenarios();
  } catch (e) {
    $('#nc-scenarios', el).innerHTML = emptyState('Could not load scenarios', e.message, 'alert');
  }
}

// ─── Scenarios ───────────────────────────────────────────────────────────────
function paintScenarios() {
  const wrap = $('#nc-scenarios', ctx.el);
  if (!ctx.scenarios.length) {
    wrap.innerHTML = emptyState('No scenarios', 'Built-in test cases appear here.', 'database');
    return;
  }
  wrap.innerHTML = ctx.scenarios.map((s) => `
    <button class="nc-sc is-clickable" data-key="${esc(s.key)}">
      <span class="nc-sc__icon">${icon('play')}</span>
      <span class="nc-sc__text">
        <span class="nc-sc__name">${esc(s.name)}</span>
        <span class="nc-sc__desc">${esc(s.description)}</span>
      </span>
    </button>`).join('');
  hydrateIcons(wrap);
  $$('.nc-sc', wrap).forEach((btn) => {
    btn.onclick = () => loadAndRunScenario(btn.dataset.key);
  });
}

async function loadAndRunScenario(key) {
  const statusEl = $('#nc-status', ctx.el);
  // highlight the selected scenario
  $$('.nc-sc', ctx.el).forEach((b) => b.classList.toggle('is-active', b.dataset.key === key));
  statusEl.textContent = 'Loading scenario…';
  try {
    const data = await api(`/netcoop/scenarios/${key}`, { method: 'POST' });
    $('#nc-raw', ctx.el).value = JSON.stringify(data.telemetry, null, 2);
    statusEl.textContent = 'Running diagnosis…';
    await runDiagnosis();
  } catch (e) {
    statusEl.textContent = '';
    toast('Scenario error', e.message, 'error');
  }
}

// ─── Diagnosis ───────────────────────────────────────────────────────────────
async function runDiagnosis() {
  const raw = $('#nc-raw', ctx.el).value.trim();
  if (!raw) { toast('Empty input', 'Paste telemetry or pick a test scenario.', 'error'); return; }
  const btn = $('#nc-run', ctx.el);
  const statusEl = $('#nc-status', ctx.el);
  await busy(btn, async () => {
    statusEl.textContent = 'Agents analysing…';
    try {
      let telemetry = raw;
      try { telemetry = JSON.parse(raw); } catch (_e) { /* send as string */ }
      const result = await api('/netcoop/diagnose', { method: 'POST', body: { telemetry } });
      ctx.result = result;
      statusEl.textContent = `Done — ${result.meta.messages} messages in ${result.meta.elapsed_ms} ms`;
      paintResults();
    } catch (e) {
      statusEl.textContent = '';
      toast('Diagnosis failed', e.message, 'error');
      $('#nc-results', ctx.el).innerHTML = `<section class="panel mt-12">${emptyState('Diagnosis error', e.message, 'alert')}</section>`;
    }
  });
}

// ─── Results ─────────────────────────────────────────────────────────────────
function paintResults() {
  const { result } = ctx;
  if (!result) return;
  const r = result.report || {};
  const meta = result.meta || {};
  const msgs = result.messages || [];
  const q = result.quality || {};

  const rootCause = r.suspected_root_cause || r.root_cause || 'undetermined';
  const confidence = Math.round((r.confidence || 0) * 100);
  const evidence = r.supporting_evidence || r.evidence || [];
  const alternatives = r.alternative_cause_details || r.alternative_causes || r.alternatives || [];
  const actions = r.recommended_actions || [];
  const impaired = r.affected_devices || (r.scope || {}).impaired_devices || [];
  const limitations = r.limitations || [];
  const ranking = r.ranking || [];
  const dq = r.data_quality || q;

  const diagnosed = r.status === 'diagnosed';
  const noFault = r.status === 'no_fault_detected';
  const isError = r.status === 'error';
  const statusClass = isError ? 'crit' : diagnosed || noFault ? 'ok' : 'med';
  const statusText = diagnosed ? 'Diagnosed' : noFault ? 'No fault' : isError ? 'Error' : label(r.status || 'complete');

  let html = '';

  // ── KPI row ────────────────────────────────────────────────────────────────
  html += `
  <div class="nc-kpi-grid">
    <div class="kpi"><div class="kpi__label">Status</div><div class="kpi__value">${pill(statusClass, statusText)}</div></div>
    <div class="kpi"><div class="kpi__label">Root cause</div><div class="kpi__value nc-root">${esc(rootCause)}</div></div>
    <div class="kpi"><div class="kpi__label">Confidence</div><div class="kpi__value">${confBar(confidence)}</div></div>
    <div class="kpi"><div class="kpi__label">Affected</div><div class="kpi__value">${impaired.length} <small>/ ${meta.devices || '-'}</small></div></div>
    <div class="kpi"><div class="kpi__label">Agents</div><div class="kpi__value">${meta.agents || 5}</div></div>
    <div class="kpi"><div class="kpi__label">Messages</div><div class="kpi__value">${meta.messages || msgs.length}</div></div>
    <div class="kpi"><div class="kpi__label">Devices</div><div class="kpi__value">${meta.devices || '-'}</div></div>
    <div class="kpi"><div class="kpi__label">Samples</div><div class="kpi__value">${num(meta.samples)}</div></div>
  </div>`;

  // ── Evidence ───────────────────────────────────────────────────────────────
  if (evidence.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('search')} Supporting evidence</h2><span class="panel__meta">${evidence.length} indicators</span></div>
      <table class="table">
        <thead><tr><th>Device</th><th>Metric</th><th>Value</th><th>Level</th><th>Interpretation</th></tr></thead>
        <tbody>${evidence.map((e) => `
          <tr class="${e.level === 'critical' ? 'nc-row--crit' : e.level === 'elevated' ? 'nc-row--warn' : ''}">
            <td class="mono">${esc(e.device_id || '-')}</td>
            <td>${esc(label(e.metric || ''))}</td>
            <td class="mono">${e.value != null ? e.value : '-'}${e.unit ? ' ' + esc(e.unit) : ''}</td>
            <td>${levelPill(e.level)}</td>
            <td class="small">${esc(e.interpretation || '-')}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </section>`;
  }

  // ── Alternatives ───────────────────────────────────────────────────────────
  if (alternatives.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('filter')} Alternative causes</h2></div>
      <table class="table">
        <thead><tr><th>Cause</th><th>Device</th><th>Score</th></tr></thead>
        <tbody>${alternatives.map((a) => {
          const name = typeof a === 'string' ? a : (a.cause || a.hypothesis || '');
          const dev = typeof a === 'object' ? (a.device_id || '') : '';
          const score = typeof a === 'object' && a.score != null ? Math.round(a.score * 100) : null;
          return `<tr><td>${esc(label(name))}</td><td class="mono">${esc(dev)}</td><td class="mono">${score != null ? score + '%' : '-'}</td></tr>`;
        }).join('')}
        </tbody>
      </table>
    </section>`;
  }

  // ── Actions ────────────────────────────────────────────────────────────────
  if (actions.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('zap')} Recommended actions</h2></div>
      <div class="panel__body nc-pad">
        <ol class="nc-actions">${actions.map((a) => `<li>${esc(typeof a === 'string' ? a : (a.action || a.description || JSON.stringify(a)))}</li>`).join('')}</ol>
      </div>
    </section>`;
  }

  // ── Affected devices ───────────────────────────────────────────────────────
  if (impaired.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('server')} Affected devices</h2><span class="panel__meta">${impaired.length} of ${meta.devices || '-'}</span></div>
      <div class="panel__body nc-pad nc-devices">
        ${impaired.map((d) => `<span class="nc-dev">${icon('alert')} ${esc(d)}</span>`).join('')}
      </div>
    </section>`;
  }

  // ── Ranking ────────────────────────────────────────────────────────────────
  if (ranking.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('chart')} Cause ranking</h2></div>
      <table class="table">
        <thead><tr><th>Cause</th><th>Device</th><th>Score</th><th>Coverage</th><th>Gated</th></tr></thead>
        <tbody>${ranking.map((rk) => `
          <tr>
            <td>${esc(rk.cause || '')}</td>
            <td class="mono">${esc(rk.device_id || '')}</td>
            <td class="mono">${rk.score != null ? Math.round(rk.score * 100) + '%' : '-'}</td>
            <td class="mono">${rk.coverage != null ? Math.round(rk.coverage * 100) + '%' : '-'}</td>
            <td>${rk.capped ? pill('med', 'gated') : pill('ok', 'no')}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </section>`;
  }

  // ── Limitations ────────────────────────────────────────────────────────────
  if (limitations.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('info')} Limitations &amp; caveats</h2></div>
      <div class="panel__body nc-pad">
        <ul class="nc-limits">${limitations.map((l) => `<li>${esc(l)}</li>`).join('')}</ul>
      </div>
    </section>`;
  }

  // ── Data quality ───────────────────────────────────────────────────────────
  if (dq) {
    const gradeClass = dq.grade === 'clean' ? 'ok' : dq.grade === 'repaired' ? 'med' : 'crit';
    const issues = dq.issues || [];
    const conversions = dq.unit_conversions || dq.conversions || [];
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('shield')} Data quality</h2><span class="panel__meta">${pill(gradeClass, dq.grade || 'unknown')}</span></div>
      ${issues.length || conversions.length ? `<div class="panel__body nc-pad">
        ${issues.length ? `<div class="section-title">Issues (${issues.length})</div><ul class="nc-limits">${issues.map((i) => `<li>${esc(typeof i === 'string' ? i : (i.message || JSON.stringify(i)))}</li>`).join('')}</ul>` : ''}
        ${conversions.length ? `<div class="section-title" style="margin-top:var(--sp-2)">Unit conversions (${conversions.length})</div><ul class="nc-limits">${conversions.map((c) => `<li>${esc(typeof c === 'string' ? c : (c.from || '') + ' → ' + (c.to || ''))}</li>`).join('')}</ul>` : ''}
      </div>` : ''}
    </section>`;
  }

  // ── Agent message log ──────────────────────────────────────────────────────
  if (msgs.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head">
        <h2 class="panel__title">${icon('chat')} Agent communication log</h2>
        <span class="panel__meta">${msgs.length} messages</span>
        <button class="btn btn--sm nc-toggle" id="nc-toggle-msgs">Show</button>
      </div>
      <div id="nc-msgs-body" style="display:none">
        <table class="table nc-msg-table">
          <thead><tr><th>#</th><th>From</th><th>To</th><th>Type</th><th>Summary</th></tr></thead>
          <tbody>${msgs.map((m, i) => `
            <tr class="nc-msg--${esc(m.type)}">
              <td class="mono small">${i + 1}</td>
              <td class="small">${pill('ok', agentLabel(m.from))}</td>
              <td class="small">${pill('med', agentLabel(m.to))}</td>
              <td class="small">${pill(m.type === 'error' ? 'crit' : m.type === 'challenge' ? 'med' : 'ok', m.type)}</td>
              <td class="small">${esc(m.summary || '-')}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </section>`;
  }

  // ── Full JSON ──────────────────────────────────────────────────────────────
  html += `
  <section class="panel mt-12">
    <div class="panel__head">
      <h2 class="panel__title">${icon('code')} Full JSON report</h2>
      <div style="display:flex;gap:var(--sp-1)">
        <button class="btn btn--sm" id="nc-copy-json">${icon('copy')} Copy</button>
        <button class="btn btn--sm nc-toggle" id="nc-toggle-json">Show</button>
      </div>
    </div>
    <div id="nc-json-body" style="display:none">
      <pre class="snippet mono nc-json">${esc(JSON.stringify(result, null, 2))}</pre>
    </div>
  </section>`;

  // ── Mount ──────────────────────────────────────────────────────────────────
  $('#nc-results', ctx.el).innerHTML = html;
  hydrateIcons($('#nc-results', ctx.el));

  // toggle handlers
  const bind = (btnId, bodyId) => {
    const btn = $(`#${btnId}`, ctx.el);
    const body = $(`#${bodyId}`, ctx.el);
    if (btn && body) btn.onclick = () => {
      const open = body.style.display !== 'none';
      body.style.display = open ? 'none' : '';
      btn.textContent = open ? 'Show' : 'Hide';
    };
  };
  bind('nc-toggle-msgs', 'nc-msgs-body');
  bind('nc-toggle-json', 'nc-json-body');

  const copyBtn = $('#nc-copy-json', ctx.el);
  if (copyBtn) copyBtn.onclick = () => copyText(JSON.stringify(result, null, 2), copyBtn);
}

function categoryOf(conf) {
  if (conf >= 80) return 'high';
  if (conf >= 50) return 'moderate';
  if (conf >= 25) return 'low';
  return 'negligible';
}
