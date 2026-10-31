import { $, $$, api, esc, label, emptyState, toast, busy, pill, copyText, num } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

// NetCoop AI — Multi-agent cooperative network fault diagnosis.
// Completely self-contained: does NOT call any Aegis API endpoint.
// All calls go to /api/netcoop/*.

let ctx = null;

const OUTCOME = {
  diagnosed:        ['ATTACK_FAILED',    'Root cause identified'],
  no_fault_detected:['FALSE_POSITIVE',   'No fault detected'],
  error:            ['ATTACK_SUCCEEDED', 'Diagnosis error'],
  inconclusive:     ['RECON_ONLY',       'Inconclusive']
};

const agentLabel = (id) => label((id || '').replace(/_agent$/, '').replace(/_/g, ' '));

// ─── Render ──────────────────────────────────────────────────────────────────
export async function render({ el }) {
  ctx = { el, result: null, scenarios: [] };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">NetCoop AI</h1>
        <p class="page-sub">Multi-agent cooperative network fault diagnosis.</p>
      </div>
    </div>
    <div class="stack reveal" id="nc-body">
      <div class="grid grid-1-1">
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Telemetry input</h2></div>
          <div class="panel__body">
            <textarea id="nc-raw" class="textarea" rows="14" spellcheck="false" placeholder="Paste JSON, NDJSON or CSV telemetry here…"></textarea>
            <div class="row wrap" style="margin-top:10px;gap:8px">
              <button class="btn btn--primary" id="nc-run">${icon('play')} Run diagnosis</button>
              <button class="btn" id="nc-clear">${icon('x')} Clear</button>
              <span class="small mono" style="color:var(--ink-3);margin-left:auto" id="nc-status"></span>
            </div>
          </div>
        </section>
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Test scenarios</h2><span class="panel__meta">click to load &amp; run</span></div>
          <div id="nc-scenarios" style="overflow-y:auto;max-height:380px;scrollbar-width:thin"><div class="skeleton" style="height:200px;margin:14px"></div></div>
        </section>
      </div>
      <div id="nc-results"></div>
    </div>`;
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
  wrap.innerHTML = `<div class="rows-in">${ctx.scenarios.map((s, i) => `
    <div class="list__item is-clickable nc-sc" style="--i:${i}" data-key="${esc(s.key)}">
      <span style="width:84px">${pill('ok', 'scenario')}</span>
      <div style="min-width:0"><div class="list__title">${esc(s.name)}</div><div class="list__sub">${esc(s.description)}</div></div>
      <span class="small mono" style="color:var(--accent)">${icon('play')}</span>
    </div>`).join('')}</div>`;
  hydrateIcons(wrap);
  $$('.nc-sc', wrap).forEach((btn) => {
    btn.onclick = () => loadAndRunScenario(btn.dataset.key);
  });
}

async function loadAndRunScenario(key) {
  const statusEl = $('#nc-status', ctx.el);
  $$('.nc-sc', ctx.el).forEach((b) => {
    b.style.background = b.dataset.key === key ? 'var(--accent-soft)' : '';
  });
  statusEl.textContent = 'Loading scenario…';
  try {
    const data = await api(`/netcoop/scenarios/${key}`, { method: 'POST' });
    $('#nc-raw', ctx.el).value = JSON.stringify(data.telemetry, null, 2);
    statusEl.textContent = 'Scenario loaded — click Run diagnosis';
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
      $('#nc-results', ctx.el).innerHTML = `<section class="panel">${emptyState('Diagnosis error', e.message, 'alert')}</section>`;
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

  const [outcomeClass, outcomeText] = OUTCOME[r.status] || OUTCOME.inconclusive;

  let html = '';

  // ── Verdict ────────────────────────────────────────────────────────────
  html += `
  <div class="verdict verdict--${esc(outcomeClass)}">
    <div class="verdict__top">
      <span class="verdict__label">${esc(outcomeText)}</span>
      <span class="verdict__conf">confidence ${confidence}%</span>
      <span class="verdict__id">${meta.elapsed_ms || '-'} ms · ${meta.messages || msgs.length} messages</span>
    </div>
    <p class="verdict__summary">${esc(rootCause)}</p>
    <div class="facts">
      <div><span>Devices</span>${meta.devices || '-'}</div>
      <div><span>Affected</span>${impaired.length} of ${meta.devices || '-'}</div>
      <div><span>Agents</span>${meta.agents || 5}</div>
      <div><span>Samples</span><span class="mono">${num(meta.samples)}</span></div>
    </div>
  </div>`;

  // ── Evidence + side panels ────────────────────────────────────────────
  html += `<div class="grid grid-2-1">`;

  // Left column — evidence table
  html += `<section class="panel">`;
  if (evidence.length) {
    html += `
      <div class="panel__head"><h2 class="panel__title">Supporting evidence</h2><span class="panel__meta">${evidence.length} indicators</span></div>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>Device</th><th>Metric</th><th class="num">Value</th><th>Level</th><th class="hide-sm">Interpretation</th></tr></thead>
        <tbody class="rows-in">${evidence.map((e, i) => `
          <tr style="--i:${i}">
            <td class="mono">${esc(e.device_id || '-')}</td>
            <td>${esc(label(e.metric || ''))}</td>
            <td class="num">${e.value != null ? e.value : '-'}${e.unit ? ' ' + esc(e.unit) : ''}</td>
            <td>${pill(e.level === 'critical' ? 'CONFIRMED' : e.level === 'elevated' ? 'INVESTIGATING' : 'CLOSED', e.level || 'normal')}</td>
            <td class="hide-sm small" style="color:var(--ink-2)">${esc(e.interpretation || '-')}</td>
          </tr>`).join('')}
        </tbody>
      </table></div>`;
  } else {
    html += emptyState('No evidence', 'The diagnosis found no anomalous indicators.', 'shield');
  }
  html += `</section>`;

  // Right column — actions + affected
  html += `<div class="stack">`;

  if (actions.length) {
    html += `
    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">Recommended actions</h2></div>
      <div class="panel__body">
        <ol style="padding-left:18px;margin:0">${actions.map((a) => `<li style="margin-bottom:6px;line-height:1.5;font-size:13px">${esc(typeof a === 'string' ? a : (a.action || a.description || JSON.stringify(a)))}</li>`).join('')}</ol>
      </div>
    </section>`;
  }

  if (impaired.length) {
    html += `
    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">Affected devices</h2><span class="panel__meta">${impaired.length} of ${meta.devices || '-'}</span></div>
      <div class="panel__body">
        <div style="display:flex;flex-wrap:wrap;gap:5px">${impaired.map((d) => `<span class="tag">${esc(d)}</span>`).join('')}</div>
      </div>
    </section>`;
  }

  if (dq) {
    const issues = dq.issues || [];
    html += `
    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">Data quality</h2><span class="panel__meta">${pill(dq.grade === 'clean' ? 'CONTAINED' : dq.grade === 'repaired' ? 'INVESTIGATING' : 'CONFIRMED', dq.grade || 'unknown')}</span></div>
      ${issues.length ? `<div class="panel__body"><div class="breakdown">${issues.map((i) => `<div><span>${esc(typeof i === 'string' ? i : (i.message || JSON.stringify(i)))}</span></div>`).join('')}</div></div>` : ''}
    </section>`;
  }

  html += `</div>`; // end .stack
  html += `</div>`; // end .grid-2-1

  // ── Ranking + alternatives ────────────────────────────────────────────
  if (ranking.length || alternatives.length) {
    html += `<div class="grid grid-1-1">`;

    if (ranking.length) {
      html += `
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Cause ranking</h2></div>
        <div class="table-wrap"><table class="table">
          <thead><tr><th>Cause</th><th>Device</th><th class="num">Score</th><th class="num">Coverage</th><th>Gated</th></tr></thead>
          <tbody class="rows-in">${ranking.map((rk, i) => `
            <tr style="--i:${i}">
              <td>${esc(rk.cause || '')}</td>
              <td class="mono">${esc(rk.device_id || '')}</td>
              <td class="num">${rk.score != null ? Math.round(rk.score * 100) + '%' : '-'}</td>
              <td class="num">${rk.coverage != null ? Math.round(rk.coverage * 100) + '%' : '-'}</td>
              <td>${rk.capped ? pill('INVESTIGATING', 'gated') : pill('CLOSED', 'no')}</td>
            </tr>`).join('')}
          </tbody>
        </table></div>
      </section>`;
    }

    if (alternatives.length) {
      html += `
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Alternative causes</h2></div>
        <div class="table-wrap"><table class="table">
          <thead><tr><th>Cause</th><th>Device</th><th class="num">Score</th></tr></thead>
          <tbody class="rows-in">${alternatives.map((a, i) => {
            const name = typeof a === 'string' ? a : (a.cause || a.hypothesis || '');
            const dev = typeof a === 'object' ? (a.device_id || '') : '';
            const score = typeof a === 'object' && a.score != null ? Math.round(a.score * 100) : null;
            return `<tr style="--i:${i}"><td>${esc(label(name))}</td><td class="mono">${esc(dev)}</td><td class="num">${score != null ? score + '%' : '-'}</td></tr>`;
          }).join('')}
          </tbody>
        </table></div>
      </section>`;
    }

    html += `</div>`; // end .grid-1-1
  }

  // ── Limitations ───────────────────────────────────────────────────────
  if (limitations.length) {
    html += `
    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">Limitations</h2></div>
      <div class="panel__body"><div class="breakdown">${limitations.map((l) => `<div><span>${esc(l)}</span></div>`).join('')}</div></div>
    </section>`;
  }

  // ── Agent communication log ───────────────────────────────────────────
  if (msgs.length) {
    html += `
    <section class="panel">
      <div class="panel__head">
        <h2 class="panel__title">Agent communication log</h2>
        <span class="panel__meta">${msgs.length} messages</span>
        <button class="panel__link" id="nc-toggle-msgs">Show</button>
      </div>
      <div id="nc-msgs-body" style="display:none">
        <div class="table-wrap"><table class="table">
          <thead><tr><th>#</th><th>From</th><th>To</th><th>Type</th><th class="hide-sm">Summary</th></tr></thead>
          <tbody class="rows-in">${msgs.map((m, i) => `
            <tr style="--i:${i}">
              <td class="mono small">${i + 1}</td>
              <td class="small">${pill('CONTAINED', agentLabel(m.from))}</td>
              <td class="small">${pill('INVESTIGATING', agentLabel(m.to))}</td>
              <td class="small">${pill(m.type === 'error' ? 'CONFIRMED' : m.type === 'challenge' ? 'INVESTIGATING' : 'CONTAINED', m.type)}</td>
              <td class="small hide-sm" style="color:var(--ink-2)">${esc(m.summary || '-')}</td>
            </tr>`).join('')}
          </tbody>
        </table></div>
      </div>
    </section>`;
  }

  // ── Full JSON ─────────────────────────────────────────────────────────
  html += `
  <section class="panel">
    <div class="panel__head">
      <h2 class="panel__title">Full JSON report</h2>
      <button class="panel__link" id="nc-copy-json">Copy</button>
      <button class="panel__link" id="nc-toggle-json">Show</button>
    </div>
    <div id="nc-json-body" style="display:none">
      <pre class="code" style="max-height:500px;overflow:auto;padding:14px;font-size:12px;margin:0">${esc(JSON.stringify(result, null, 2))}</pre>
    </div>
  </section>`;

  // ── Mount ──────────────────────────────────────────────────────────────
  const wrap = $('#nc-results', ctx.el);
  wrap.innerHTML = `<div class="stack reveal">${html}</div>`;
  hydrateIcons(wrap);

  // Toggle handlers
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
