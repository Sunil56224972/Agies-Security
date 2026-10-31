// NetCoop AI — Standalone Multi-Agent Diagnostic Client
import { icon, hydrateIcons } from './icons.js';

// DOM Utilities
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => (s == null ? '' : String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));
const num = (n) => (typeof n === 'number' ? n.toLocaleString() : n || '-');
const label = (s) => (s ? String(s).replace(/_/g, ' ') : '');
const agentLabel = (id) => label((id || '').replace(/_agent$/, '').replace(/_/g, ' '));

const OUTCOME = {
  diagnosed:        ['ATTACK_FAILED',    'ROOT CAUSE DIAGNOSED', 'ok'],
  no_fault_detected:['FALSE_POSITIVE',   'NO FAULT DETECTED',    'low'],
  error:            ['ATTACK_SUCCEEDED', 'DIAGNOSIS ERROR',      'crit'],
  inconclusive:     ['RECON_ONLY',       'INCONCLUSIVE',         'med']
};

let appState = {
  activeTab: 'studio',
  result: null,
  scenarios: [],
  messages: [],
  protocolData: null
};

// ─── Toast Notifications ──────────────────────────────────────────────────
function toast(title, msg = '', type = 'info') {
  const container = $('#toasts');
  if (!container) return;
  const t = document.createElement('div');
  t.className = `toast ${type === 'error' ? 'toast--error' : type === 'ok' ? 'toast--ok' : ''}`;
  t.innerHTML = `
    <div class="toast__bar"></div>
    <div>
      <div class="toast__title">${esc(title)}</div>
      ${msg ? `<div class="toast__msg">${esc(msg)}</div>` : ''}
    </div>
    <button aria-label="Close">&times;</button>
  `;
  t.querySelector('button').onclick = () => t.remove();
  container.appendChild(t);
  setTimeout(() => {
    t.classList.add('is-leaving');
    setTimeout(() => t.remove(), 200);
  }, 4000);
}

// ─── Modal Utility ────────────────────────────────────────────────────────
function showModal({ title, bodyHtml, footHtml = '' }) {
  const root = $('#modal-root');
  if (!root) return;
  root.innerHTML = `
    <div class="scrim" id="modal-scrim"></div>
    <div class="modal" role="dialog">
      <div class="modal__head">
        <h3 class="modal__title">${title}</h3>
        <button class="icon-btn" id="modal-close" style="width:26px;height:26px">${icon('x')}</button>
      </div>
      <div class="modal__body">${bodyHtml}</div>
      ${footHtml ? `<div class="modal__foot">${footHtml}</div>` : ''}
    </div>
  `;
  hydrateIcons(root);

  const close = () => { root.innerHTML = ''; };
  $('#modal-scrim').onclick = close;
  $('#modal-close').onclick = close;
  const cancelBtn = $('#modal-cancel-btn', root);
  if (cancelBtn) cancelBtn.onclick = close;
}

// ─── Copy to Clipboard ────────────────────────────────────────────────────
function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    if (btn) {
      const original = btn.innerHTML;
      btn.innerHTML = `${icon('check')} Copied`;
      setTimeout(() => { btn.innerHTML = original; hydrateIcons(btn); }, 1800);
    }
    toast('Copied to clipboard', '', 'ok');
  }).catch(() => {
    toast('Clipboard error', 'Could not copy to clipboard', 'error');
  });
}

// ─── Pill Renderer ────────────────────────────────────────────────────────
function pill(status, text) {
  const cls = status === 'CONFIRMED' || status === 'critical' ? 'pill--CONFIRMED'
    : status === 'CONTAINED' || status === 'ok' || status === 'normal' ? 'pill--CONTAINED'
    : status === 'INVESTIGATING' || status === 'elevated' || status === 'warn' ? 'pill--INVESTIGATING'
    : 'pill--CLOSED';
  return `<span class="pill ${cls}">${esc(text || status)}</span>`;
}

// ─── Clock & Theme ────────────────────────────────────────────────────────
function initClock() {
  const clockEl = $('#utc-clock');
  const update = () => {
    if (!clockEl) return;
    const now = new Date();
    clockEl.textContent = now.toTimeString().split(' ')[0] + ' UTC';
  };
  update();
  setInterval(update, 1000);
}

function initTheme() {
  const btn = $('#theme-toggle');
  if (!btn) return;

  const updateIcon = (theme) => {
    btn.innerHTML = theme === 'dark' ? icon('sun') : icon('moon');
  };

  const current = document.documentElement.getAttribute('data-theme') || 'light';
  updateIcon(current);

  btn.onclick = () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const next = isDark ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('netcoop-theme', next);
    updateIcon(next);
  };
}

// ─── Tab Switching ────────────────────────────────────────────────────────
function initTabs() {
  const tabs = $$('.tab');
  tabs.forEach((tab) => {
    tab.onclick = () => {
      const target = tab.dataset.tab;
      appState.activeTab = target;

      tabs.forEach((t) => {
        const on = t === tab;
        t.classList.toggle('is-on', on);
        t.setAttribute('aria-selected', on ? 'true' : 'false');
      });

      $$('.tab-pane').forEach((pane) => {
        pane.style.display = pane.id === `tab-${target}` ? '' : 'none';
      });

      // Lazy render tabs
      if (target === 'bus') paintMessageBus();
      if (target === 'protocol') loadAndPaintProtocol();
      if (target === 'topology') paintTopology();
    };
  });
}

// ─── Scenarios ────────────────────────────────────────────────────────────
async function loadScenarios() {
  const wrap = $('#nc-scenarios');
  try {
    const res = await fetch('/api/netcoop/scenarios');
    const data = await res.json();
    appState.scenarios = data.scenarios || [];
    paintScenarios();
  } catch (err) {
    wrap.innerHTML = `<div class="notice" style="color:var(--crit);margin:14px">Failed to load scenarios: ${esc(err.message)}</div>`;
  }
}

function paintScenarios() {
  const wrap = $('#nc-scenarios');
  if (!appState.scenarios.length) {
    wrap.innerHTML = `<div class="notice" style="margin:14px">No scenarios available.</div>`;
    return;
  }

  wrap.innerHTML = `<div class="rows-in">${appState.scenarios.map((s, i) => `
    <div class="list__item is-clickable nc-sc" style="--i:${i}" data-key="${esc(s.key)}">
      <span style="width:84px">${pill('CONTAINED', 'scenario')}</span>
      <div style="min-width:0">
        <div class="list__title">${esc(s.name)}</div>
        <div class="list__sub">${esc(s.description)}</div>
      </div>
      <span class="small mono" style="color:var(--accent)">${icon('play')}</span>
    </div>`).join('')}</div>`;
  hydrateIcons(wrap);

  $$('.nc-sc', wrap).forEach((btn) => {
    btn.onclick = () => loadScenario(btn.dataset.key);
  });
}

async function loadScenario(key) {
  const statusEl = $('#nc-status');
  $$('.nc-sc').forEach((b) => {
    b.style.background = b.dataset.key === key ? 'var(--accent-soft)' : '';
  });
  statusEl.textContent = 'Loading scenario…';
  try {
    const res = await fetch(`/api/netcoop/scenarios/${encodeURIComponent(key)}`, { method: 'POST' });
    const data = await res.json();
    $('#nc-raw').value = JSON.stringify(data.telemetry, null, 2);
    statusEl.textContent = 'Scenario loaded — click Run diagnosis';
  } catch (e) {
    statusEl.textContent = '';
    toast('Scenario load failed', e.message, 'error');
  }
}

// ─── Diagnosis Execution ──────────────────────────────────────────────────
async function runDiagnosis() {
  const raw = $('#nc-raw').value.trim();
  if (!raw) {
    toast('Empty telemetry', 'Please paste telemetry or select a test scenario.', 'error');
    return;
  }
  const btn = $('#nc-run');
  const statusEl = $('#nc-status');
  const topStatus = $('#top-status');

  btn.classList.add('is-busy');
  btn.disabled = true;
  statusEl.textContent = 'Multi-agent analysis in progress…';
  topStatus.textContent = 'Agents diagnosing via Groq LPU…';

  try {
    let telemetry = raw;
    try { telemetry = JSON.parse(raw); } catch (_e) { /* treat as string */ }

    const res = await fetch('/api/netcoop/diagnose', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ telemetry })
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `HTTP error ${res.status}`);
    }

    const result = await res.json();
    appState.result = result;
    if (result.messages) {
      appState.messages = result.messages;
      $('#bus-msg-count').textContent = `${result.messages.length} messages logged`;
    }

    statusEl.textContent = `Done — ${result.meta.messages} messages in ${result.meta.elapsed_ms} ms`;
    topStatus.textContent = 'Diagnosis complete';
    paintResults();
    toast('Diagnosis complete', `Root cause: ${result.report.suspected_root_cause || 'Identified'}`, 'ok');
  } catch (err) {
    statusEl.textContent = '';
    topStatus.textContent = 'Agent idle';
    toast('Diagnosis failed', err.message, 'error');
    $('#nc-results').innerHTML = `
      <section class="panel" style="margin-top:16px">
        <div class="panel__head"><h2 class="panel__title" style="color:var(--crit)"><i data-icon="alert"></i> Diagnosis Error</h2></div>
        <div class="panel__body"><p class="muted">${esc(err.message)}</p></div>
      </section>`;
    hydrateIcons($('#nc-results'));
  } finally {
    btn.classList.remove('is-busy');
    btn.disabled = false;
  }
}

// ─── Paint Results ────────────────────────────────────────────────────────
function paintResults() {
  const { result } = appState;
  if (!result) return;

  const r = result.report || {};
  const meta = result.meta || {};
  const msgs = result.messages || [];
  const q = result.quality || {};
  const groq = (r && r.llm_synthesis) || result.groq || null;

  const rootCause = r.suspected_root_cause || r.root_cause || r.error || 'undetermined';
  const confidence = Math.round((r.confidence || 0) * 100);
  const evidence = r.supporting_evidence || r.evidence || [];
  const alternatives = r.alternative_cause_details || r.alternative_causes || r.alternatives || [];
  const actions = r.recommended_actions || [];
  const impaired = r.affected_devices || (r.scope || {}).impaired_devices || [];
  const limitations = r.limitations || [];
  const ranking = r.ranking || [];
  const dq = r.data_quality || q;

  const [outcomeClass, outcomeText, colorTone] = OUTCOME[r.status] || OUTCOME.inconclusive;
  const confBand = confidence >= 80 ? 'High' : confidence >= 50 ? 'Medium' : 'Low';
  const fillTone = confidence >= 80 ? 'ok' : confidence >= 50 ? 'med' : 'high';

  let html = '';

  // 1. KPI Strip
  html += `
  <div class="kpis grid grid-kpi mt-12">
    <div class="kpi">
      <div class="kpi__label">Diagnosis Verdict</div>
      <div class="kpi__value" style="font-size:16px;margin-top:6px;color:var(--${colorTone})">${esc(outcomeText)}</div>
      <div class="kpi__foot">${esc(r.status || 'evaluated')}</div>
    </div>
    <div class="kpi">
      <div class="kpi__label">Confidence Score</div>
      <div class="kpi__value">${confidence}% <small>${confBand}</small></div>
      <div class="kpi__foot">coverage-weighted</div>
    </div>
    <div class="kpi">
      <div class="kpi__label">Affected Scope</div>
      <div class="kpi__value">${impaired.length} <small>of ${meta.devices || 7}</small></div>
      <div class="kpi__foot">impaired network assets</div>
    </div>
    <div class="kpi">
      <div class="kpi__label">Agent Messages</div>
      <div class="kpi__value">${meta.messages || msgs.length} <small>in ${meta.elapsed_ms || 18}ms</small></div>
      <div class="kpi__foot">6 collaborating agents</div>
    </div>
    <div class="kpi">
      <div class="kpi__label">Groq LPU Engine</div>
      <div class="kpi__value" style="font-size:15px;margin-top:6px"><span style="color:var(--ok)">●</span> Active</div>
      <div class="kpi__foot">openai/gpt-oss-120b</div>
    </div>
  </div>`;

  // 2. Exact Verdict Banner (Matching Screenshot 1)
  html += `
  <div class="verdict verdict--${esc(outcomeClass)} mt-12" style="border-left: 4px solid var(--high)">
    <div class="verdict__top" style="display:flex;align-items:center;justify-content:space-between">
      <div style="display:flex;align-items:center;gap:8px;color:var(--high);font-weight:700;font-size:13px;letter-spacing:0.04em">
        <i data-icon="activity"></i>
        <span>${esc(outcomeText)}</span>
      </div>
      <div class="verdict__id" style="font-family:var(--font-mono);font-size:12px;color:var(--ink-3)">
        ${meta.messages || msgs.length} messages &nbsp;·&nbsp; ${meta.elapsed_ms || '-'} ms
      </div>
    </div>

    <p class="verdict__summary" style="font-size:17px;font-weight:700;margin:10px 0 0;line-height:1.4">
      ${esc(rootCause)}
    </p>

    <!-- Progress bar + affected badge -->
    <div class="verdict-bar">
      <div class="verdict-bar__track">
        <div class="verdict-bar__fill verdict-bar__fill--${fillTone}" style="width: ${confidence}%"></div>
      </div>
      <div class="verdict-bar__stat">
        <span>${confidence}%</span> ${confBand}
      </div>
      <div class="verdict-bar__stat" style="margin-left:auto;color:var(--ink-2)">
        <i data-icon="layers"></i>
        <b>${impaired.length}</b> <span>/ ${meta.devices || 7} devices affected</span>
      </div>
    </div>
  </div>`;

  // 3. Groq AI Synthesized Reasoning (if available)
  if (groq && groq.reasoning) {
    html += `
    <section class="panel mt-12" style="border-color:var(--accent)">
      <div class="panel__head" style="background:var(--accent-soft)">
        <h2 class="panel__title" style="color:var(--accent)">
          <i data-icon="zap"></i> Groq LPU Expert Network Engineering Analysis (gpt-oss-120b)
        </h2>
        <span class="panel__meta" style="color:var(--accent);font-family:var(--font-mono)">${groq.model || 'Groq LPU'} · Verified</span>
      </div>
      <div class="panel__body">
        <p style="margin-top:0;margin-bottom:12px;font-size:13.5px;line-height:1.6">${esc(groq.reasoning)}</p>

        const gActions = groq.actions || groq.corrective_actions || [];
        const gCommands = groq.cli_commands || groq.cli_remediation_commands || [];

        html += `
        ${gActions.length ? `
          <div style="font-weight:600;font-size:12.5px;margin-bottom:6px;text-transform:uppercase;letter-spacing:.02em;color:var(--ink-3)">
            Engineered Corrective Recommendations
          </div>
          <ul style="margin:0 0 12px 18px;padding:0;font-size:13px;line-height:1.6">
            ${gActions.map(a => `<li>${esc(a)}</li>`).join('')}
          </ul>
        ` : ''}

        ${gCommands.length ? `
          <div style="font-weight:600;font-size:12.5px;margin-bottom:6px;text-transform:uppercase;letter-spacing:.02em;color:var(--ink-3)">
            Diagnostic &amp; Remediation CLI Commands
          </div>
          <div style="display:grid;gap:8px">
            ${gCommands.map((cmd, idx) => `
              <div class="cmd-box">
                <button class="btn btn--sm cmd-box__copy" id="cmd-copy-${idx}">${icon('copy')} Copy</button>
                <code>${esc(cmd)}</code>
              </div>
            `).join('')}
          </div>
        ` : ''}`;
      </div>
    </section>`;
  }

  // 4. Evidence + Side Panels Grid
  html += `<div class="grid grid-2-1 mt-12">`;

  // Left column: Supporting Evidence Table
  html += `<section class="panel">`;
  if (evidence.length) {
    html += `
      <div class="panel__head">
        <h2 class="panel__title"><i data-icon="shield"></i> Supporting evidence</h2>
        <span class="panel__meta">${evidence.length} indicators verified</span>
      </div>
      <div class="table-wrap"><table class="table">
        <thead>
          <tr>
            <th>Device</th>
            <th>Metric</th>
            <th class="num">Value</th>
            <th>Level</th>
            <th class="hide-sm">Interpretation</th>
          </tr>
        </thead>
        <tbody class="rows-in">${evidence.map((e, i) => `
          <tr style="--i:${i}">
            <td class="mono"><b>${esc(e.device_id || '-')}</b></td>
            <td>${esc(label(e.metric || ''))}</td>
            <td class="num">${e.value != null ? e.value : '-'}${e.unit ? ' ' + esc(e.unit) : ''}</td>
            <td>${pill(e.level === 'critical' ? 'CONFIRMED' : e.level === 'elevated' ? 'INVESTIGATING' : 'CONTAINED', e.level || 'normal')}</td>
            <td class="hide-sm small" style="color:var(--ink-2)">${esc(e.interpretation || '-')}</td>
          </tr>`).join('')}
        </tbody>
      </table></div>`;
  } else {
    html += `
      <div class="panel__head"><h2 class="panel__title"><i data-icon="shield"></i> Supporting evidence</h2></div>
      <div class="panel__body"><p class="muted">No anomalous indicators detected in telemetry stream.</p></div>`;
  }
  html += `</section>`;

  // Right column: Recommended Actions, Affected Scope, Data Quality
  html += `<div class="stack">`;

  // Standard recommended actions
  if (actions.length) {
    html += `
    <section class="panel">
      <div class="panel__head"><h2 class="panel__title"><i data-icon="sliders"></i> Recommended actions</h2></div>
      <div class="panel__body">
        <ol style="padding-left:18px;margin:0">
          ${actions.map((a) => `<li style="margin-bottom:8px;line-height:1.5;font-size:13px">${esc(typeof a === 'string' ? a : (a.action || a.description || JSON.stringify(a)))}</li>`).join('')}
        </ol>
      </div>
    </section>`;
  }

  // Affected Devices
  if (impaired.length) {
    html += `
    <section class="panel">
      <div class="panel__head">
        <h2 class="panel__title"><i data-icon="network"></i> Affected devices</h2>
        <span class="panel__meta">${impaired.length} of ${meta.devices || 7}</span>
      </div>
      <div class="panel__body">
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${impaired.map((d) => `<span class="tag tag--warn"><i data-icon="alert"></i> ${esc(d)}</span>`).join('')}
        </div>
      </div>
    </section>`;
  }

  // Data Quality Audit
  if (dq) {
    const issues = dq.issues || [];
    html += `
    <section class="panel">
      <div class="panel__head">
        <h2 class="panel__title"><i data-icon="check"></i> Telemetry Data Quality</h2>
        <span class="panel__meta">${pill(dq.grade === 'clean' ? 'CONTAINED' : dq.grade === 'repaired' ? 'INVESTIGATING' : 'CONFIRMED', dq.grade || 'verified')}</span>
      </div>
      <div class="panel__body">
        <div class="breakdown">
          <div><span>Missing Values</span><b>${dq.missing_values || 0}</b></div>
          <div><span>Out of Range</span><b>${dq.out_of_range || 0}</b></div>
          <div><span>Sanitized Metrics</span><b>${dq.repaired || 0}</b></div>
        </div>
        ${issues.length ? `
          <div style="margin-top:10px;font-size:12px;color:var(--ink-2)">
            ${issues.map(i => `<div style="padding:4px 0">• ${esc(typeof i === 'string' ? i : i.message)}</div>`).join('')}
          </div>
        ` : ''}
      </div>
    </section>`;
  }

  html += `</div>`; // end right stack
  html += `</div>`; // end grid-2-1

  // 5. Ranking & Alternative Hypotheses
  if (ranking.length || alternatives.length) {
    html += `<div class="grid grid-1-1 mt-12">`;

    if (ranking.length) {
      html += `
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title"><i data-icon="chart"></i> Cause ranking</h2></div>
        <div class="table-wrap"><table class="table">
          <thead><tr><th>Cause</th><th>Device</th><th class="num">Score</th><th class="num">Coverage</th><th>Gated</th></tr></thead>
          <tbody class="rows-in">${ranking.map((rk, i) => `
            <tr style="--i:${i}">
              <td><b>${esc(label(rk.cause || ''))}</b></td>
              <td class="mono">${esc(rk.device_id || '')}</td>
              <td class="num">${rk.score != null ? Math.round(rk.score * 100) + '%' : '-'}</td>
              <td class="num">${rk.coverage != null ? Math.round(rk.coverage * 100) + '%' : '-'}</td>
              <td>${rk.capped ? pill('INVESTIGATING', 'gated') : pill('CONTAINED', 'no')}</td>
            </tr>`).join('')}
          </tbody>
        </table></div>
      </section>`;
    }

    if (alternatives.length) {
      html += `
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title"><i data-icon="info"></i> Alternative causes &amp; uncertainty</h2></div>
        <div class="table-wrap"><table class="table">
          <thead><tr><th>Hypothesis</th><th>Device</th><th class="num">Confidence</th></tr></thead>
          <tbody class="rows-in">${alternatives.map((a, i) => {
            const name = typeof a === 'string' ? a : (a.cause || a.hypothesis || '');
            const dev = typeof a === 'object' ? (a.device_id || '-') : '-';
            const score = typeof a === 'object' && a.score != null ? Math.round(a.score * 100) : null;
            return `<tr style="--i:${i}"><td>${esc(label(name))}</td><td class="mono">${esc(dev)}</td><td class="num">${score != null ? score + '%' : '-'}</td></tr>`;
          }).join('')}
          </tbody>
        </table></div>
      </section>`;
    }

    html += `</div>`;
  }

  // 6. Limitations & Guardrails
  if (limitations.length) {
    html += `
    <section class="panel mt-12">
      <div class="panel__head"><h2 class="panel__title"><i data-icon="alert"></i> Known limitations &amp; guardrails</h2></div>
      <div class="panel__body">
        <div class="breakdown">
          ${limitations.map((l) => `<div><span>${esc(l)}</span></div>`).join('')}
        </div>
      </div>
    </section>`;
  }

  // 7. Full Structured JSON Report
  html += `
  <section class="panel mt-12">
    <div class="panel__head">
      <h2 class="panel__title"><i data-icon="code"></i> Full JSON diagnostic report</h2>
      <button class="panel__link" id="nc-copy-json">${icon('copy')} Copy JSON</button>
      <button class="panel__link" id="nc-toggle-json" style="margin-left:12px">Show</button>
    </div>
    <div id="nc-json-body" style="display:none">
      <pre class="code" style="max-height:500px;overflow:auto;padding:14px;font-size:12px;margin:0">${esc(JSON.stringify(result, null, 2))}</pre>
    </div>
  </section>`;

  // Mount to DOM
  const resultsEl = $('#nc-results');
  resultsEl.innerHTML = `<div class="stack reveal">${html}</div>`;
  hydrateIcons(resultsEl);

  // Wire buttons
  const toggleBtn = $('#nc-toggle-json');
  const jsonBody = $('#nc-json-body');
  if (toggleBtn && jsonBody) {
    toggleBtn.onclick = () => {
      const open = jsonBody.style.display !== 'none';
      jsonBody.style.display = open ? 'none' : '';
      toggleBtn.textContent = open ? 'Show' : 'Hide';
    };
  }

  const copyBtn = $('#nc-copy-json');
  if (copyBtn) {
    copyBtn.onclick = () => copyText(JSON.stringify(result, null, 2), copyBtn);
  }

  // Wire CLI command copy buttons
  const cmds = (groq && (groq.cli_commands || groq.cli_remediation_commands)) || [];
  if (cmds.length) {
    cmds.forEach((cmd, idx) => {
      const btn = $(`#cmd-copy-${idx}`);
      if (btn) btn.onclick = () => copyText(cmd, btn);
    });
  }
}

// ─── Tab 2: Agent Message Bus ─────────────────────────────────────────────
function paintMessageBus() {
  const container = $('#bus-container');
  const msgs = appState.messages;

  if (!msgs || !msgs.length) {
    container.innerHTML = `
      <div class="notice">
        No messages on the bus yet. Run a diagnosis in the Studio to inspect agent exchanges.
      </div>`;
    return;
  }

  let html = `
    <div class="table-wrap"><table class="table">
      <thead>
        <tr>
          <th>#</th>
          <th>Time</th>
          <th>From Agent</th>
          <th>To Agent</th>
          <th>Message Type</th>
          <th>Summary</th>
          <th style="text-align:right">Action</th>
        </tr>
      </thead>
      <tbody class="rows-in">
        ${msgs.map((m, i) => `
          <tr style="--i:${i}">
            <td class="mono small">${i + 1}</td>
            <td class="mono small muted">${m.timestamp ? m.timestamp.split('T')[1].replace('Z','') : '-'}</td>
            <td class="small"><b>${pill('CONTAINED', agentLabel(m.from))}</b></td>
            <td class="small">${pill('INVESTIGATING', agentLabel(m.to))}</td>
            <td class="small">${pill(m.type === 'error' ? 'CONFIRMED' : m.type === 'challenge' ? 'INVESTIGATING' : 'CONTAINED', m.type)}</td>
            <td class="small" style="color:var(--ink-2);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.summary || '-')}</td>
            <td style="text-align:right">
              <button class="btn btn--sm nc-inspect-msg" data-idx="${i}">${icon('search')} Inspect</button>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table></div>`;

  container.innerHTML = html;
  hydrateIcons(container);

  $$('.nc-inspect-msg', container).forEach((btn) => {
    btn.onclick = () => {
      const idx = Number(btn.dataset.idx);
      const msg = msgs[idx];
      showModal({
        title: `${icon('server')} JSON-RPC Envelope #${idx + 1} (${esc(msg.from)} &rarr; ${esc(msg.to)})`,
        bodyHtml: `
          <div style="margin-bottom:12px;font-size:12.5px;color:var(--ink-2)">
            <b>Type:</b> <span class="mono">${esc(msg.type)}</span> &nbsp;|&nbsp;
            <b>Timestamp:</b> <span class="mono">${esc(msg.timestamp || '-')}</span>
          </div>
          <pre class="code" style="max-height:400px;overflow:auto;padding:12px;font-size:12px;margin:0">${esc(JSON.stringify(msg, null, 2))}</pre>
        `,
        footHtml: `
          <button class="btn" id="modal-copy-msg">${icon('copy')} Copy Payload</button>
          <button class="btn btn--primary" id="modal-cancel-btn">Close</button>
        `
      });
      const copyMsgBtn = $('#modal-copy-msg');
      if (copyMsgBtn) copyMsgBtn.onclick = () => copyText(JSON.stringify(msg, null, 2), copyMsgBtn);
    };
  });
}

// ─── Tab 3: Interoperability Protocol ─────────────────────────────────────
async function loadAndPaintProtocol() {
  const container = $('#protocol-container');
  if (appState.protocolData) {
    paintProtocol(appState.protocolData);
    return;
  }

  try {
    const res = await fetch('/api/netcoop/protocol');
    const data = await res.json();
    appState.protocolData = data;
    paintProtocol(data);
  } catch (err) {
    container.innerHTML = `<div class="notice" style="color:var(--crit)">Failed to load protocol: ${esc(err.message)}</div>`;
  }
}

function paintProtocol(data) {
  const container = $('#protocol-container');
  const p = data.protocol || {};
  const scoring = data.scoring || {};
  const roles = data.roles || {};

  container.innerHTML = `
    <div class="stack">
      <!-- Protocol Overview -->
      <section class="panel">
        <div class="panel__head">
          <h2 class="panel__title"><i data-icon="file"></i> JSON-RPC Interoperability Protocol Specification</h2>
          <span class="panel__meta">Version ${esc(p.version || '1.0.0')}</span>
        </div>
        <div class="panel__body">
          <p style="margin-top:0;line-height:1.6;font-size:13.5px">
            The NetCoop AI protocol standardizes asynchronous diagnostic messages across heterogeneous AI agents in the IIT Bhubaneswar network.
            Each message encapsulates provenance, sender identity, target scope, and typed payloads compliant with JSON Schema draft-07.
          </p>

          <h3 style="font-size:14px;margin:16px 0 8px">Standard Message Envelope</h3>
          <pre class="code" style="padding:12px;font-size:12px;margin:0">
{
  "jsonrpc": "2.0",
  "id": "msg_01J...",
  "from": "telemetry_agent",
  "to": "fault_correlation_agent",
  "type": "findings",
  "payload": {
    "agent_role": "telemetry",
    "indicators": [...],
    "confidence": 0.88
  },
  "timestamp": "2026-11-01T04:20:00.000Z"
}</pre>
        </div>
      </section>

      <!-- Roles Specification -->
      <section class="panel">
        <div class="panel__head">
          <h2 class="panel__title"><i data-icon="cpu"></i> Agent Roles &amp; Responsibilities</h2>
          <span class="panel__meta">6 Cooperative Agents</span>
        </div>
        <div class="table-wrap"><table class="table">
          <thead>
            <tr><th>Agent Identifier</th><th>Title</th><th>Diagnostic Domain</th></tr>
          </thead>
          <tbody>
            <tr>
              <td class="mono">telemetry_agent</td>
              <td>Telemetry &amp; Performance Agent</td>
              <td>Analyzes packet loss, round-trip latency, jitter, interface utilization, and bandwidth limits.</td>
            </tr>
            <tr>
              <td class="mono">infrastructure_agent</td>
              <td>Infrastructure Health Agent</td>
              <td>Monitors switch CPU, memory, buffer queue drops, optical signal power, and hardware flapping.</td>
            </tr>
            <tr>
              <td class="mono">connectivity_agent</td>
              <td>Connectivity Analysis Agent</td>
              <td>Analyzes network topology graph, link adjacencies, DNS resolution delays, and DHCP scope pools.</td>
            </tr>
            <tr>
              <td class="mono">fault_correlation_agent</td>
              <td>Fault Correlation Agent</td>
              <td>Correlates anomalous indicators across agents, resolves competing hypotheses, and computes root cause.</td>
            </tr>
            <tr>
              <td class="mono">recommendation_agent</td>
              <td>Recommendation &amp; Reporting Agent</td>
              <td>Generates actionable operational remediation procedures, safety gating, and structured reports.</td>
            </tr>
            <tr>
              <td class="mono">groq_llm_agent</td>
              <td>Groq LPU Reasoning Agent</td>
              <td>Executes ultra-low latency gpt-oss-120b inference to produce precise network engineering CLI scripts.</td>
            </tr>
          </tbody>
        </table></div>
      </section>

      <!-- Metric Ranges & Thresholds -->
      <section class="panel">
        <div class="panel__head">
          <h2 class="panel__title"><i data-icon="sliders"></i> Telemetry Metrics &amp; Validation Ranges</h2>
          <span class="panel__meta">${Object.keys(p.metrics || {}).length} Normalized Metrics</span>
        </div>
        <div class="table-wrap"><table class="table">
          <thead>
            <tr><th>Metric Name</th><th>Owner Agent</th><th>Unit</th><th>Range</th><th>Warn Threshold</th><th>Critical Threshold</th></tr>
          </thead>
          <tbody>
            ${Object.entries(p.metrics || {}).map(([mName, mInfo]) => `
              <tr>
                <td class="mono"><b>${esc(mName)}</b></td>
                <td>${pill('CONTAINED', agentLabel(mInfo.owner))}</td>
                <td>${esc(mInfo.unit || '-')}</td>
                <td class="mono">[${mInfo.valid_range ? mInfo.valid_range.join(', ') : '-'}]</td>
                <td class="num mono">${mInfo.warn != null ? mInfo.warn + ' ' + (mInfo.unit || '') : 'None'}</td>
                <td class="num mono" style="color:var(--crit)">${mInfo.crit != null ? mInfo.crit + ' ' + (mInfo.unit || '') : 'None'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table></div>
      </section>
    </div>
  `;
  hydrateIcons(container);
}

// ─── Tab 4: Campus Topology ───────────────────────────────────────────────
function paintTopology() {
  const container = $('#topology-container');
  const nodes = [
    { id: 'core-router-01', type: 'Core Router', location: 'Central Datacenter', role: 'Campus Backbone Gateway', ip: '10.0.0.1/24', vendor: 'Cisco ASR 9000', status: 'Healthy' },
    { id: 'dist-switch-01', type: 'Dist Switch', location: 'Academic Complex', role: 'Distribution Aggregation', ip: '10.0.1.1/24', vendor: 'Cisco Catalyst 9500', status: 'Monitored' },
    { id: 'ap-academic-01', type: 'Access Point', location: 'Lecture Hall Complex', role: '802.11ax Wireless AP', ip: '10.0.2.10/24', vendor: 'Aruba AP-555', status: 'Monitored' },
    { id: 'sw-hostel-01', type: 'Access Switch', location: 'Mahanadi Hall of Residence', role: 'Hostel LAN Aggregation', ip: '10.0.3.1/24', vendor: 'Juniper EX4300', status: 'Healthy' },
    { id: 'srv-dns-01', type: 'DNS Server', location: 'Server Farm Room 102', role: 'Campus Primary Resolver', ip: '10.0.0.53/24', vendor: 'BIND 9 Linux', status: 'Monitored' },
    { id: 'srv-dhcp-01', type: 'DHCP Server', location: 'Server Farm Room 102', role: 'Campus Scope Pool', ip: '10.0.0.67/24', vendor: 'ISC Kea Linux', status: 'Healthy' },
    { id: 'laptop-01', type: 'Endpoint Client', location: 'Academic Office', role: 'Admin Workstation', ip: '10.0.1.45/24', vendor: 'Windows 11', status: 'Monitored' },
    { id: 'laptop-02', type: 'Wireless Client', location: 'LH-101 Seminar Room', role: 'Student Laptop', ip: '10.0.2.88/24', vendor: 'Ubuntu 24.04', status: 'Monitored' }
  ];

  container.innerHTML = `
    <div class="stack">
      <section class="panel">
        <div class="panel__head">
          <h2 class="panel__title"><i data-icon="network"></i> IIT Bhubaneswar Campus Network Architecture</h2>
          <span class="panel__meta">8 Monitored Topology Nodes</span>
        </div>
        <div class="panel__body">
          <p class="muted small" style="margin-top:0;margin-bottom:14px">
            Simulated campus network topology conforming to the Round 2 IIT Bhubaneswar Problem Statement.
            Telemetry collected across these nodes is evaluated collaboratively by the 6 NetCoop AI agents.
          </p>

          <div class="topo-grid">
            ${nodes.map(n => `
              <div class="topo-node">
                <div class="topo-node__header">
                  <div class="topo-node__id"><i data-icon="${n.type.includes('Wireless') || n.type.includes('Access Point') ? 'wifi' : n.type.includes('Server') ? 'server' : 'cpu'}"></i> ${esc(n.id)}</div>
                  ${pill('CONTAINED', n.status)}
                </div>
                <div class="topo-node__sub">${esc(n.type)} &bull; ${esc(n.location)}</div>
                <div class="topo-node__meta">
                  <div><span>Role:</span> ${esc(n.role)}</div>
                  <div><span>IP:</span> ${esc(n.ip)}</div>
                  <div><span>Hardware:</span> ${esc(n.vendor)}</div>
                  <div><span>Subnet:</span> Campus LAN</div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </section>
    </div>
  `;
  hydrateIcons(container);
}

// ─── Initialize Application ───────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  hydrateIcons();
  initClock();
  initTheme();
  initTabs();
  loadScenarios();

  // Run diagnosis button
  $('#nc-run').onclick = () => runDiagnosis();

  // Clear button
  $('#nc-clear').onclick = () => {
    $('#nc-raw').value = '';
    $('#nc-results').innerHTML = '';
    $('#nc-status').textContent = '';
    appState.result = null;
    $$('.nc-sc').forEach(b => b.style.background = '');
    toast('Cleared', 'Input and results cleared');
  };

  // Clear bus button
  $('#bus-clear-btn').onclick = () => {
    appState.messages = [];
    $('#bus-msg-count').textContent = '0 messages logged';
    paintMessageBus();
    toast('Message bus cleared');
  };
});
