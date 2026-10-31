import { $, $$, api, esc, label, emptyState, toast, busy, pill, copyText, num } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

// NetCoop AI — Multi-agent cooperative network fault diagnosis.
// Completely self-contained: does NOT call any Aegis API endpoint.
// All calls go to /api/netcoop/*.

let ctx = null;

const pct2 = (v) => (v == null ? '-' : `${Math.round(v * 100) / 100}%`);
const r2 = (v) => (v == null ? '-' : Math.round(v * 100) / 100);

const CONF_COLORS = { high: '#22c55e', moderate: '#eab308', low: '#ef4444', negligible: '#6b7280' };
const confBar = (pct) => {
  const p = Math.max(0, Math.min(100, Math.round(pct)));
  const cat = p >= 80 ? 'high' : p >= 50 ? 'moderate' : p >= 25 ? 'low' : 'negligible';
  return `<div class="nc-conf"><div class="nc-conf__track"><div class="nc-conf__fill" style="width:${p}%;background:${CONF_COLORS[cat]}"></div></div><span class="nc-conf__val mono">${p}%</span><span class="nc-conf__cat pill pill--${cat === 'high' ? 'ok' : cat === 'moderate' ? 'med' : 'crit'}">${cat}</span></div>`;
};

const levelPill = (lvl) => {
  const m = { critical: 'crit', elevated: 'med', normal: 'ok' };
  return pill(m[lvl] || 'ok', lvl || 'normal');
};

const agentLabel = (id) => label((id || '').replace(/_agent$/, '').replace(/_/g, ' '));

export async function render({ el }) {
  ctx = { el, result: null, scenarios: [] };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">${icon('activity')} NetCoop AI</h1>
        <p class="page-sub">Multi-agent cooperative network fault diagnosis. Paste telemetry or pick a scenario — five specialised agents analyse, debate, and produce a structured root-cause report.</p>
      </div>
    </div>
    <div class="grid grid-1-1 mt-12" id="nc-input-row">
      <section class="panel" id="nc-input-panel">
        <div class="panel__head"><h2 class="panel__title">${icon('upload')} Telemetry input</h2></div>
        <div class="panel__body" style="padding:var(--sp-3)">
          <textarea id="nc-raw" class="textarea" rows="10" placeholder="Paste JSON, NDJSON or CSV telemetry here..."></textarea>
          <div style="margin-top:var(--sp-2);display:flex;gap:var(--sp-2);align-items:center">
            <button class="btn btn--primary" id="nc-run">${icon('play')} Run diagnosis</button>
            <button class="btn" id="nc-clear">${icon('x')} Clear</button>
            <span class="small muted" id="nc-status"></span>
          </div>
        </div>
      </section>
      <section class="panel" id="nc-scenarios-panel">
        <div class="panel__head"><h2 class="panel__title">${icon('database')} Test scenarios</h2><span class="panel__meta">click to load &amp; run</span></div>
        <div class="panel__body" id="nc-scenarios" style="padding:var(--sp-3)">
          <div class="skeleton" style="height:180px"></div>
        </div>
      </section>
    </div>
    <div id="nc-results"></div>`;
  hydrateIcons(el);

  $('#nc-run', el).onclick = () => runDiagnosis();
  $('#nc-clear', el).onclick = () => { $('#nc-raw', el).value = ''; $('#nc-results', el).innerHTML = ''; ctx.result = null; $('#nc-status', el).textContent = ''; };

  // load scenarios
  try {
    const data = await api('/netcoop/scenarios');
    ctx.scenarios = data.scenarios || [];
    paintScenarios();
  } catch (e) {
    $('#nc-scenarios', el).innerHTML = emptyState('Could not load scenarios', e.message, 'alert');
  }
}

function paintScenarios() {
  const wrap = $('#nc-scenarios', ctx.el);
  if (!ctx.scenarios.length) { wrap.innerHTML = emptyState('No scenarios', 'Scenarios are built-in test cases.', 'database'); return; }
  wrap.innerHTML = `<div class="nc-scenario-list">${ctx.scenarios.map(s => `
    <div class="nc-scenario-card is-clickable" data-key="${esc(s.key)}">
      <div class="nc-scenario-card__name">${icon('play')} ${esc(s.name)}</div>
      <div class="nc-scenario-card__desc small muted">${esc(s.description)}</div>
    </div>`).join('')}</div>`;
  hydrateIcons(wrap);
  $$('.nc-scenario-card', wrap).forEach(card => {
    card.onclick = () => loadAndRunScenario(card.dataset.key);
  });
}

async function loadAndRunScenario(key) {
  const statusEl = $('#nc-status', ctx.el);
  statusEl.textContent = `Loading scenario "${key}"...`;
  try {
    const data = await api(`/netcoop/scenarios/${key}`, { method: 'POST' });
    const text = JSON.stringify(data.telemetry, null, 2);
    $('#nc-raw', ctx.el).value = text;
    statusEl.textContent = 'Scenario loaded. Running diagnosis...';
    await runDiagnosis();
  } catch (e) {
    statusEl.textContent = '';
    toast('Scenario error', e.message, 'error');
  }
}

async function runDiagnosis() {
  const raw = $('#nc-raw', ctx.el).value.trim();
  if (!raw) { toast('Empty input', 'Paste telemetry or pick a test scenario.', 'error'); return; }
  const btn = $('#nc-run', ctx.el);
  const statusEl = $('#nc-status', ctx.el);
  await busy(btn, async () => {
    statusEl.textContent = 'Agents analysing...';
    try {
      let telemetry = raw;
      try { telemetry = JSON.parse(raw); } catch { /* send as string */ }
      const result = await api('/netcoop/diagnose', { method: 'POST', body: { telemetry } });
      ctx.result = result;
      statusEl.textContent = `Done — ${result.meta.messages} messages, ${result.meta.elapsed_ms}ms`;
      paintResults();
    } catch (e) {
      statusEl.textContent = '';
      toast('Diagnosis failed', e.message, 'error');
      $('#nc-results', ctx.el).innerHTML = `<section class="panel mt-12">${emptyState('Diagnosis error', e.message, 'alert')}</section>`;
    }
  });
}

function paintResults() {
  const { result } = ctx;
  if (!result) return;
  const r = result.report || {};
  const meta = result.meta || {};
  const msgs = result.messages || [];
  const q = result.quality || {};

  const rootCause = r.suspected_root_cause || r.root_cause || 'undetermined';
  const confidence = Math.round((r.confidence || 0) * 100);
  const category = r.confidence_category || categoryOf(confidence);
  const evidence = r.supporting_evidence || r.evidence || [];
  const contraEvidence = r.contradicting_evidence || [];
  const alternatives = r.alternative_cause_details || r.alternative_causes || r.alternatives || [];
  const scope = r.scope || {};
  const actions = r.recommended_actions || [];
  const impaired = r.affected_devices || scope.impaired_devices || scope.impaired || [];
  const affectedDetail = r.affected_detail || [];
  const limitations = r.limitations || [];
  const ranking = r.ranking || [];
  const dq = r.data_quality || q;

  const statusClass = r.status === 'error' ? 'crit' : r.status === 'diagnosed' ? 'ok' : r.status === 'no_fault_detected' ? 'ok' : confidence >= 50 ? 'med' : 'crit';
  const statusText = r.status === 'diagnosed' ? 'Diagnosed' : r.status === 'no_fault_detected' ? 'No fault' : r.status === 'error' ? 'Error' : r.status || 'complete';

  let html = `
    <!-- KPIs -->
    <div class="kpis grid grid-kpi mt-12">
      <div class="kpi"><div class="kpi__label">Status</div><div class="kpi__value">${pill(statusClass, statusText)}</div></div>
      <div class="kpi"><div class="kpi__label">Root cause</div><div class="kpi__value" style="font-size:var(--fs-4)">${esc(label(rootCause))}</div></div>
      <div class="kpi"><div class="kpi__label">Confidence</div><div class="kpi__value">${confBar(confidence)}</div></div>
      <div class="kpi"><div class="kpi__label">Affected devices</div><div class="kpi__value">${impaired.length}<small> / ${meta.devices || '-'}</small></div></div>
    </div>
    <div class="kpis grid grid-kpi mt-4">
      <div class="kpi"><div class="kpi__label">Agents</div><div class="kpi__value">${meta.agents || 5}</div></div>
      <div class="kpi"><div class="kpi__label">Messages</div><div class="kpi__value">${meta.messages || msgs.length}</div></div>
      <div class="kpi"><div class="kpi__label">Devices scanned</div><div class="kpi__value">${meta.devices || '-'}</div></div>
      <div class="kpi"><div class="kpi__label">Samples</div><div class="kpi__value">${num(meta.samples)}</div></div>
    </div>`;

  // Evidence table
  if (evidence.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('search')} Supporting evidence</h2><span class="panel__meta">${evidence.length} indicators</span></div>
      <table class="table">
        <thead><tr><th>Device</th><th>Metric</th><th>Value</th><th>Threshold</th><th>Level</th><th>Interpretation</th></tr></thead>
        <tbody>${evidence.map(e => `
          <tr class="${e.level === 'critical' ? 'nc-row--crit' : e.level === 'elevated' ? 'nc-row--warn' : ''}">
            <td class="mono">${esc(e.device_id || e.device || '-')}</td>
            <td>${esc(label(e.metric || e.indicator || ''))}</td>
            <td class="mono">${e.value != null ? e.value : '-'}${e.unit ? ' ' + esc(e.unit) : ''}</td>
            <td class="mono small muted">${e.threshold != null ? esc(e.threshold) : '-'}</td>
            <td>${levelPill(e.level)}</td>
            <td class="small">${esc(e.interpretation || '-')}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </section>`;
  }

  // Alternatives
  if (alternatives.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('filter')} Alternative causes</h2></div>
      <table class="table">
        <thead><tr><th>Hypothesis</th><th>Confidence</th><th>Device</th><th>Score</th></tr></thead>
        <tbody>${alternatives.map(a => {
          const name = typeof a === 'string' ? a : (a.cause || a.hypothesis || '');
          const dev = typeof a === 'object' ? (a.device_id || a.device || '') : '';
          const score = typeof a === 'object' && a.score != null ? Math.round(a.score * 100) : '';
          return `
          <tr>
            <td>${esc(label(name))}</td>
            <td>${score ? confBar(score) : '-'}</td>
            <td class="mono">${esc(dev)}</td>
            <td class="mono">${score || '-'}</td>
          </tr>`;
        }).join('')}
        </tbody>
      </table>
    </section>`;
  }

  // Recommended actions
  if (actions.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('zap')} Recommended actions</h2></div>
      <div class="panel__body" style="padding:var(--sp-3)">
        <ol class="nc-actions">${actions.map(a => {
          const text = typeof a === 'string' ? a : (a.action || a.description || JSON.stringify(a));
          const priority = typeof a === 'object' && a.priority ? ` ${pill(a.priority === 'high' ? 'crit' : a.priority === 'medium' ? 'med' : 'ok', a.priority)}` : '';
          return `<li>${esc(text)}${priority}</li>`;
        }).join('')}</ol>
      </div>
    </section>`;
  }

  // Scope — impaired devices
  if (impaired.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('server')} Affected devices</h2><span class="panel__meta">${impaired.length} of ${meta.devices || '-'} devices</span></div>
      <div class="panel__body" style="padding:var(--sp-3);display:flex;flex-wrap:wrap;gap:var(--sp-1)">
        ${impaired.map(d => `<span class="tag tag--warn">${icon('alert')} ${esc(d)}</span>`).join('')}
      </div>
    </section>`;
  }

  // Ranking
  if (ranking.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('chart')} Cause ranking</h2><span class="panel__meta">${ranking.length} candidates scored</span></div>
      <table class="table">
        <thead><tr><th>Cause</th><th>Device</th><th>Score</th><th>Coverage</th><th>Contradiction</th><th>Gated</th></tr></thead>
        <tbody>${ranking.map(rk => `
          <tr>
            <td>${esc(rk.cause || '')}</td>
            <td class="mono">${esc(rk.device_id || '')}</td>
            <td class="mono">${rk.score != null ? Math.round(rk.score * 100) + '%' : '-'}</td>
            <td class="mono">${rk.coverage != null ? Math.round(rk.coverage * 100) + '%' : '-'}</td>
            <td class="mono">${rk.contradiction != null ? r2(rk.contradiction) : '-'}</td>
            <td>${rk.capped ? pill('med', 'yes') : pill('ok', 'no')}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </section>`;
  }

  // Limitations
  if (limitations.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('info')} Limitations</h2></div>
      <div class="panel__body" style="padding:var(--sp-3)">
        <ul class="nc-issues">${limitations.map(l => `<li class="small">${icon('info')} ${esc(l)}</li>`).join('')}</ul>
      </div>
    </section>`;
  }

  // Data quality
  if (dq) {
    const gradeClass = dq.grade === 'clean' ? 'ok' : dq.grade === 'repaired' ? 'med' : 'crit';
    const issues = dq.issues || [];
    const conversions = dq.unit_conversions || dq.conversions || [];
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title">${icon('shield')} Data quality</h2><span class="panel__meta">${pill(gradeClass, dq.grade || 'unknown')}</span></div>
      ${issues.length || conversions.length ? `<div class="panel__body" style="padding:var(--sp-3)">
        ${issues.length ? `<div class="section-title">Issues (${issues.length})</div><ul class="nc-issues">${issues.map(i => `<li class="small">${icon('alert')} ${esc(typeof i === 'string' ? i : (i.message || JSON.stringify(i)))}</li>`).join('')}</ul>` : ''}
        ${conversions.length ? `<div class="section-title" style="margin-top:var(--sp-2)">Unit conversions (${conversions.length})</div><ul class="nc-issues">${conversions.map(c => `<li class="small">${icon('refresh')} ${esc(typeof c === 'string' ? c : (c.from || '') + ' → ' + (c.to || ''))}</li>`).join('')}</ul>` : ''}
      </div>` : ''}
    </section>`;
  }

  // Agent message log
  if (msgs.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head">
        <h2 class="panel__title">${icon('chat')} Agent communication log</h2>
        <span class="panel__meta">${msgs.length} messages</span>
        <button class="btn btn--sm" id="nc-toggle-msgs">${icon('arrow')} Toggle</button>
      </div>
      <div class="panel__body nc-msgs-wrap" id="nc-msgs-body" style="display:none;padding:var(--sp-3);max-height:500px;overflow-y:auto">
        <table class="table nc-msg-table">
          <thead><tr><th>#</th><th>From</th><th>To</th><th>Type</th><th>Summary</th><th>Time</th></tr></thead>
          <tbody>${msgs.map((m, i) => `
            <tr class="nc-msg nc-msg--${esc(m.type)}">
              <td class="mono small">${i + 1}</td>
              <td>${pill('ok', agentLabel(m.from))}</td>
              <td>${pill('med', agentLabel(m.to))}</td>
              <td>${pill(m.type === 'error' ? 'crit' : m.type === 'challenge' ? 'med' : 'ok', m.type)}</td>
              <td class="small">${esc(m.summary || '-')}</td>
              <td class="mono small">${m.timestamp ? m.timestamp.slice(11, 23) : '-'}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </section>`;
  }

  // Full JSON report
  html += `
    <section class="panel mt-12">
      <div class="panel__head">
        <h2 class="panel__title">${icon('code')} Full JSON report</h2>
        <div style="display:flex;gap:var(--sp-1)">
          <button class="btn btn--sm" id="nc-copy-json">${icon('copy')} Copy</button>
          <button class="btn btn--sm" id="nc-toggle-json">${icon('arrow')} Toggle</button>
        </div>
      </div>
      <div id="nc-json-body" style="display:none;padding:var(--sp-2)">
        <pre class="snippet mono" style="max-height:500px;overflow:auto;font-size:12px;white-space:pre-wrap">${esc(JSON.stringify(result, null, 2))}</pre>
      </div>
    </section>`;

  $('#nc-results', ctx.el).innerHTML = html;
  hydrateIcons($('#nc-results', ctx.el));

  // Toggle handlers
  const msgsBody = $('#nc-msgs-body', ctx.el);
  const msgsBtn = $('#nc-toggle-msgs', ctx.el);
  if (msgsBtn) msgsBtn.onclick = () => { msgsBody.style.display = msgsBody.style.display === 'none' ? '' : 'none'; };

  const jsonBody = $('#nc-json-body', ctx.el);
  const jsonBtn = $('#nc-toggle-json', ctx.el);
  if (jsonBtn) jsonBtn.onclick = () => { jsonBody.style.display = jsonBody.style.display === 'none' ? '' : 'none'; };

  const copyBtn = $('#nc-copy-json', ctx.el);
  if (copyBtn) copyBtn.onclick = () => copyText(JSON.stringify(result, null, 2), copyBtn);
}

function categoryOf(conf) {
  if (conf >= 80) return 'high';
  if (conf >= 50) return 'moderate';
  if (conf >= 25) return 'low';
  return 'negligible';
}

function fmtVal(e) {
  if (e.value != null) return String(e.value);
  if (e.current != null) return String(e.current);
  if (e.median != null) return String(e.median);
  return '-';
}

