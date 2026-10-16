import { $, $$, api, esc, sev, pill, flow, ago, num, label, emptyState } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { openAlert, openNewAlert } from '../panels.js';

let ctx = null;

const SEV_C = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };
const ACT = {
  'investigation.closed': ['accent', 'closed investigation'],
  'investigation.override': ['warn', 'overrode verdict on'],
  'rule.block': ['crit', 'blocked'],
  'rule.isolate': ['crit', 'isolated'],
  'rule.enabled': ['ok', 're-enabled rule for'],
  'rule.disabled': ['warn', 'disabled rule for'],
  'rule.rollback': ['warn', 'rolled back rule for'],
  'alert.created': ['accent', 'submitted'],
  'alert.status': ['', 'updated status of'],
  'probe.sent': ['', 'probed'],
  'config.updated': ['', 'changed settings'],
  'sandbox.seeded': ['ok', 'seeded'],
  'sandbox.reset': ['warn', 'reset']
};

export async function render({ el, navigate }) {
  ctx = { el, navigate };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Overview</h1>
        <p class="page-sub" id="ov-sub">Loading...</p>
      </div>
      <div class="page-actions">
        <button class="btn" id="ov-new">New alert</button>
        <button class="btn btn--primary" id="ov-next">Investigate next</button>
      </div>
    </div>
    <div class="stack reveal" id="ov-body">
      <div class="kpis grid grid-kpi">${'<div class="kpi"><div class="skeleton" style="height:11px;width:50%"></div><div class="skeleton mt-8" style="height:26px;width:30%"></div></div>'.repeat(5)}</div>
      <div class="grid grid-2-1"><div class="panel skeleton" style="height:260px"></div><div class="panel skeleton" style="height:260px"></div></div>
    </div>`;
  $('#ov-new', el).onclick = () => openNewAlert(navigate);
  await paint();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) paint(); }

async function paint() {
  const { el, navigate } = ctx;
  const d = await api('/overview');
  const body = $('#ov-body', el);
  if (!body) return;
  const c = d.counts;
  const top = d.queue[0];

  $('#ov-sub', el).innerHTML = c.open
    ? `${c.open} open${d.by_severity.CRITICAL ? `, ${d.by_severity.CRITICAL} critical` : ''}${top ? ` &middot; top of queue ${ago(top.detected_at)}` : ''}`
    : 'No open alerts.';
  const next = $('#ov-next', el);
  next.disabled = !top;
  next.onclick = () => top && navigate(`investigate/${top.alert_id}?run=1`);

  const max = Math.max(4, ...d.hourly.map((h) => h.CRITICAL + h.HIGH + h.MEDIUM + h.LOW));
  const totalSev = Math.max(1, ...Object.values(d.by_severity));
  const outcomes = [['ATTACK_SUCCEEDED', 'Compromise confirmed'], ['ATTACK_FAILED', 'Attempt failed'], ['FALSE_POSITIVE', 'False positive'], ['RECON_ONLY', 'Recon only']];
  const totalOut = Object.values(d.outcomes).reduce((a, b) => a + b, 0);

  body.innerHTML = `
    <div class="kpis grid grid-kpi">
      <div class="kpi ${c.open ? 'kpi--alert' : ''}"><div class="kpi__label">Open alerts</div><div class="kpi__value">${c.open}</div><div class="kpi__foot">${c.alerts} total</div></div>
      <div class="kpi"><div class="kpi__label">Investigations</div><div class="kpi__value">${c.investigations}</div><div class="kpi__foot">${d.avg_run_ms ? `avg ${(d.avg_run_ms / 1000).toFixed(1)}s per run` : 'none yet'}</div></div>
      <div class="kpi"><div class="kpi__label">Active rules</div><div class="kpi__value">${c.active_rules}</div><div class="kpi__foot"><span class="mono">${num(d.packets_dropped)}</span> packets dropped</div></div>
      <div class="kpi"><div class="kpi__label">Exposed assets</div><div class="kpi__value">${c.exposed_assets}<small>/ ${c.assets}</small></div><div class="kpi__foot">with a critical CVE</div></div>
      <div class="kpi"><div class="kpi__label">MTTR</div><div class="kpi__value">${d.mttr_min == null ? '-' : `${d.mttr_min}<small>min</small>`}</div><div class="kpi__foot">detection to verdict</div></div>
    </div>
    <div class="grid grid-2-1">
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Alerts, last 24h</h2>
          <div class="legend panel__meta">${Object.keys(SEV_C).map((s) => `<span><i style="background:${SEV_C[s]}"></i>${label(s)}</span>`).join('')}</div></div>
        <div class="panel__body">
          <div class="bars">${d.hourly.map((h, i) => {
            const t = h.CRITICAL + h.HIGH + h.MEDIUM + h.LOW;
            return `<div class="bars__col" title="${h.h === 0 ? 'This hour' : `${h.h}h ago`}: ${t} alert${t === 1 ? '' : 's'}">${['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].filter((s) => h[s]).map((s) => `<div class="bars__seg" style="--i:${i};height:${(h[s] / max) * 100}%;background:${SEV_C[s]}"></div>`).join('')}</div>`;
          }).join('')}</div>
          <div class="bars__axis"><span>-24h</span><span>-18h</span><span>-12h</span><span>-6h</span><span>now</span></div>
        </div>
      </section>
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Open by severity</h2></div>
        <div class="panel__body">
          ${Object.keys(SEV_C).map((s) => `<div class="hbar">${sev(s)}<div class="hbar__track"><div class="hbar__fill" style="--c:${SEV_C[s]};width:${(d.by_severity[s] / totalSev) * 100}%"></div></div><span class="hbar__n">${d.by_severity[s]}</span></div>`).join('')}
          <h3 class="section-title" style="margin-top:18px">Verdicts</h3>
          <div class="breakdown">${outcomes.map(([k, t]) => `<div><span>${t}</span><b>${d.outcomes[k] || 0}${totalOut ? `<span class="muted"> / ${Math.round(((d.outcomes[k] || 0) / totalOut) * 100)}%</span>` : ''}</b></div>`).join('')}</div>
        </div>
      </section>
    </div>

    <div class="grid grid-2-1">
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Triage queue</h2><span class="panel__meta">by severity</span><button class="panel__link" style="margin-left:12px" data-go="alerts">View all</button></div>
        ${d.queue.length ? `<div class="rows-in">${d.queue.map((a, i) => `
          <div class="list__item is-clickable" style="--i:${i}" data-alert="${esc(a.alert_id)}">
            ${sev(a.severity)}
            <div style="min-width:0"><div class="list__title truncate">${esc(a.signature)}</div><div class="list__sub"><span class="mono">${esc(a.alert_id)}</span>${flow(a.source_ip, a.dest_ip, a.dest_port)}<span>${ago(a.detected_at)}</span></div></div>
            ${pill(a.status)}
          </div>`).join('')}</div>` : emptyState('Nothing open', 'New alerts will show up here.', 'shieldCheck')}
      </section>
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Audit log</h2></div>
        ${d.activity.length ? `<div class="feed rows-in">${d.activity.slice(0, 9).map((a, i) => {
          const [kind, verb] = ACT[a.action] || ['', a.action];
          const t = new Date(a.created_at);
          const hhmm = t.toTimeString().slice(0, 5);
          return `<div class="feed__item ${kind === 'crit' || kind === 'warn' ? `feed__item--${kind}` : ''}" style="--i:${i}" title="${esc(t.toLocaleString())}"><span class="feed__time">${hhmm}</span><div><div class="feed__text"><b>${esc(a.actor)}</b> ${esc(verb)} <span class="mono">${esc(a.target || '')}</span></div>${a.detail ? `<div class="feed__detail">${esc(String(a.detail).slice(0, 80))}</div>` : ''}</div></div>`;
        }).join('')}</div>` : emptyState('No entries', 'Analyst and engine actions are logged here.')}
      </section>
    </div>

    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">Recent investigations</h2><button class="panel__link" data-go="investigate">View all</button></div>
      ${d.recent_investigations.length ? `<div class="table-wrap"><table class="table"><thead><tr><th>Case</th><th>Verdict</th><th class="hide-sm">Flow</th><th class="hide-sm">Engine</th><th class="num">Confidence</th><th class="num">When</th></tr></thead><tbody class="rows-in">
        ${d.recent_investigations.map((i, n) => `<tr class="is-clickable" style="--i:${n}" data-inv="${esc(i.alert_id)}">
          <td><span class="cell-main mono">${esc(i.investigation_id)}</span><span class="cell-sub">${esc(i.alert_id)}${i.human_override ? ' &middot; overridden' : ''}</span></td>
          <td>${pill(i.outcome)}</td><td class="hide-sm">${flow(i.attacker_ip, i.target_ip)}</td><td class="hide-sm small muted">${esc(i.engine)}</td>
          <td class="num">${i.confidence}%</td><td class="num small muted">${ago(i.created_at)}</td></tr>`).join('')}
      </tbody></table></div>` : emptyState('No investigations', 'Run one from the alert queue.', 'scan')}
    </section>`;

  $$('[data-alert]', body).forEach((r) => { r.onclick = () => openAlert(r.dataset.alert, navigate); });
  $$('[data-inv]', body).forEach((r) => { r.onclick = () => navigate(`investigate/${r.dataset.inv}`); });
  $$('[data-go]', body).forEach((b) => { b.onclick = () => navigate(b.dataset.go); });
  hydrateIcons(body);
}