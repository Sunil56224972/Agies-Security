import { $, $$, api, esc, sev, pill, flow, ago, num, label, countUp, emptyState } from '../core.js';
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

function greeting() {
  const h = new Date().getHours();
  return h < 5 ? 'Quiet hours' : h < 12 ? 'Morning shift' : h < 18 ? 'Afternoon shift' : 'Evening shift';
}

export async function render({ el, navigate }) {
  ctx = { el, navigate };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <div class="eyebrow"><span class="live-dot"></span>${greeting()} &middot; ${new Date().toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long' })}</div>
        <h1 class="page-title">Where things <em>stand</em></h1>
        <p class="page-sub" id="ov-sub">Loading the queue...</p>
      </div>
      <div class="page-actions">
        <button class="btn" id="ov-new">${icon('plus')}Submit alert</button>
        <button class="btn btn--primary" id="ov-next">${icon('play')}Work next alert</button>
      </div>
    </div>
    <div class="stack reveal" id="ov-body">
      <div class="grid grid-kpi">${'<div class="panel kpi"><div class="skeleton" style="height:12px;width:60%"></div><div class="skeleton mt-12" style="height:34px;width:40%"></div></div>'.repeat(5)}</div>
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
    ? `<b>${c.open}</b> open alert${c.open === 1 ? '' : 's'}${d.by_severity.CRITICAL ? `, <b style="color:var(--crit)">${d.by_severity.CRITICAL} critical</b>` : ''}. ${top ? `Oldest high-priority item came in ${ago(top.detected_at)}.` : ''}`
    : 'The queue is clear. New alerts from the sensors land here first.';
  const next = $('#ov-next', el);
  next.disabled = !top;
  next.onclick = () => top && navigate(`investigate/${top.alert_id}?run=1`);

  const max = Math.max(4, ...d.hourly.map((h) => h.CRITICAL + h.HIGH + h.MEDIUM + h.LOW));
  const totalSev = Math.max(1, ...Object.values(d.by_severity));
  const outcomes = [['ATTACK_SUCCEEDED', 'Compromise confirmed'], ['ATTACK_FAILED', 'Attempt failed'], ['FALSE_POSITIVE', 'False positive'], ['RECON_ONLY', 'Recon only']];
  const totalOut = Object.values(d.outcomes).reduce((a, b) => a + b, 0);

  body.innerHTML = `
    <div class="grid grid-kpi">
      <div class="panel kpi ${c.open ? 'kpi--alert' : ''}" style="--kpi-c:var(--crit)"><div class="kpi__label">${icon('bell')}Open alerts</div><div class="kpi__value" data-count="${c.open}">0</div><div class="kpi__foot">${c.alerts} received in total</div></div>
      <div class="panel kpi"><div class="kpi__label">${icon('scan')}Investigations</div><div class="kpi__value" data-count="${c.investigations}">0</div><div class="kpi__foot">${d.avg_run_ms ? `avg run ${(d.avg_run_ms / 1000).toFixed(1)}s` : 'none run yet'}</div></div>
      <div class="panel kpi" style="--kpi-c:var(--ok)"><div class="kpi__label">${icon('shield')}Active rules</div><div class="kpi__value" data-count="${c.active_rules}">0</div><div class="kpi__foot"><span class="mono">${num(d.packets_dropped)}</span> packets dropped</div></div>
      <div class="panel kpi" style="--kpi-c:var(--high)"><div class="kpi__label">${icon('server')}Exposed assets</div><div class="kpi__value"><span data-count="${c.exposed_assets}">0</span><small>/ ${c.assets}</small></div><div class="kpi__foot">match a known critical CVE</div></div>
      <div class="panel kpi" style="--kpi-c:var(--med)"><div class="kpi__label">${icon('activity')}Mean time to respond</div><div class="kpi__value">${d.mttr_min == null ? '<span>-</span>' : `<span data-count="${d.mttr_min}">0</span><small>min</small>`}</div><div class="kpi__foot">detection to verdict</div></div>
    </div>

    <div class="grid grid-2-1">
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Alert volume, last 24 hours</h2>
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
          <h3 class="section-title mt-16" style="margin-top:22px">Verdicts so far</h3>
          <div class="posture__list">${outcomes.map(([k, t]) => `<div><span>${pill(k, t)}</span><b>${d.outcomes[k] || 0}${totalOut ? `<span class="muted" style="font-weight:400"> &middot; ${Math.round(((d.outcomes[k] || 0) / totalOut) * 100)}%</span>` : ''}</b></div>`).join('')}</div>
        </div>
      </section>
    </div>

    <div class="grid grid-2-1">
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Triage queue</h2><span class="panel__meta">highest severity first</span><button class="panel__link" style="margin-left:12px" data-go="alerts">All alerts</button></div>
        ${d.queue.length ? `<div class="rows-in">${d.queue.map((a, i) => `
          <div class="list__item is-clickable" style="--i:${i}" data-alert="${esc(a.alert_id)}">
            ${sev(a.severity)}
            <div style="min-width:0"><div class="list__title truncate">${esc(a.signature)}</div><div class="list__sub"><span class="mono">${esc(a.alert_id)}</span>${flow(a.source_ip, a.dest_ip, a.dest_port)}<span>${ago(a.detected_at)}</span></div></div>
            ${pill(a.status)}
          </div>`).join('')}</div>` : emptyState('Queue is clear', 'Nothing open right now.', 'shieldCheck')}
      </section>
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Activity</h2><span class="panel__meta">audit trail</span></div>
        ${d.activity.length ? `<div class="feed rows-in">${d.activity.slice(0, 9).map((a, i) => {
          const [dot, verb] = ACT[a.action] || ['', a.action];
          return `<div class="feed__item" style="--i:${i}"><span class="feed__dot ${dot ? `feed__dot--${dot}` : ''}"></span><div><div class="feed__text"><b>${esc(a.actor)}</b> ${esc(verb)} <span class="mono">${esc(a.target || '')}</span></div><div class="feed__time">${ago(a.created_at)}${a.detail ? ` &middot; ${esc(String(a.detail).slice(0, 70))}` : ''}</div></div></div>`;
        }).join('')}</div>` : emptyState('No activity yet', 'Actions by analysts and the engine appear here.')}
      </section>
    </div>

    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">Recent investigations</h2><button class="panel__link" data-go="investigate">Open workspace</button></div>
      ${d.recent_investigations.length ? `<div class="table-wrap"><table class="table"><thead><tr><th>Case</th><th>Verdict</th><th class="hide-sm">Flow</th><th class="hide-sm">Engine</th><th class="num">Confidence</th><th class="num">When</th></tr></thead><tbody class="rows-in">
        ${d.recent_investigations.map((i, n) => `<tr class="is-clickable" style="--i:${n}" data-inv="${esc(i.alert_id)}">
          <td><span class="cell-main mono">${esc(i.investigation_id)}</span><span class="cell-sub">${esc(i.alert_id)}${i.human_override ? ' &middot; overridden by analyst' : ''}</span></td>
          <td>${pill(i.outcome)}</td><td class="hide-sm">${flow(i.attacker_ip, i.target_ip)}</td><td class="hide-sm small muted">${esc(i.engine)}</td>
          <td class="num">${i.confidence}%</td><td class="num small muted">${ago(i.created_at)}</td></tr>`).join('')}
      </tbody></table></div>` : emptyState('No investigations yet', 'Pick an alert from the queue and run the playbook.', 'scan')}
    </section>`;

  $$('[data-count]', body).forEach((n) => countUp(n, Number(n.dataset.count)));
  $$('[data-alert]', body).forEach((r) => { r.onclick = () => openAlert(r.dataset.alert, navigate); });
  $$('[data-inv]', body).forEach((r) => { r.onclick = () => navigate(`investigate/${r.dataset.inv}`); });
  $$('[data-go]', body).forEach((b) => { b.onclick = () => navigate(b.dataset.go); });
  hydrateIcons(body);
}