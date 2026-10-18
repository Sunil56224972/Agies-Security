import { $, $$, api, esc, sev, num, label, stamp, ago, emptyState, can } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { openNewRule } from '../panels.js';

let ctx = null;
const SEV_C = { CRITICAL: 'var(--sev-1)', HIGH: 'var(--sev-2)', MEDIUM: 'var(--sev-3)', LOW: 'var(--sev-4)' };
const OUTCOMES = [['ATTACK_SUCCEEDED', 'Compromise confirmed', 'var(--crit)'], ['ATTACK_FAILED', 'Attempt failed', 'var(--ok)'], ['RECON_ONLY', 'Recon only', 'var(--low)'], ['FALSE_POSITIVE', 'False positive', 'var(--ink-3)']];

const mins = (m) => {
  if (m == null) return '-';
  if (m < 1) return `${Math.max(1, Math.round(m * 60))}s`;
  if (m < 90) return `${Math.round(m)}m`;
  if (m < 2880) return `${Math.floor(m / 60)}h ${String(Math.round(m % 60)).padStart(2, '0')}m`;
  return `${(m / 1440).toFixed(1)}d`;
};

export async function render({ el, navigate, query }) {
  ctx = { el, navigate, days: [7, 30, 90].includes(Number(query.days)) ? Number(query.days) : 30 };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Reports</h1>
        <p class="page-sub" id="rp-sub">How fast the team responds, what attackers are trying, and what the tuning saves.</p>
      </div>
      <div class="page-actions no-print">
        <div class="seg" id="rp-days">${[7, 30, 90].map((d) => `<button data-d="${d}" class="${d === ctx.days ? 'is-on' : ''}">${d} days</button>`).join('')}</div>
        <a class="btn btn--ghost" id="rp-csv" href="/api/export/alerts.csv?days=${ctx.days}" download>${icon('download')}CSV</a>
        <button class="btn" id="rp-print">${icon('printer')}Print</button>
      </div>
    </div>
    <div id="rp-body" class="stack"><div class="kpis grid grid-kpi">${'<div class="kpi"><div class="skeleton" style="height:11px;width:50%"></div><div class="skeleton mt-8" style="height:26px;width:30%"></div></div>'.repeat(5)}</div><div class="panel skeleton" style="height:240px"></div></div>`;
  $$('[data-d]', el).forEach((b) => {
    b.onclick = () => {
      ctx.days = Number(b.dataset.d);
      $$('[data-d]', el).forEach((x) => x.classList.toggle('is-on', x === b));
      $('#rp-csv', el).href = `/api/export/alerts.csv?days=${ctx.days}`;
      history.replaceState(null, '', `#/reports?days=${ctx.days}`);
      paint();
    };
  });
  $('#rp-print', el).onclick = () => window.print();
  hydrateIcons(el);
  await paint();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) paint(); }

async function paint() {
  const { el, navigate, days } = ctx;
  const body = $('#rp-body', el);
  const d = await api(`/reports/summary?days=${days}`);
  if (days !== ctx.days || !document.body.contains(body)) return;
  const t = d.totals;
  $('#rp-sub', el).innerHTML = `Last ${days} days, generated ${stamp(d.generated_at)}<span class="print-only"> &middot; Aegis</span>`;

  const crit = d.sla.find((s) => s.severity === 'CRITICAL');
  const breached = d.sla.reduce((n, s) => n + s.breached, 0);
  const tracked = d.sla.reduce((n, s) => n + s.total, 0);
  const compliance = tracked ? Math.round(((tracked - breached) / tracked) * 100) : null;
  const max = Math.max(4, ...d.daily.map((x) => x.CRITICAL + x.HIGH + x.MEDIUM + x.LOW + x.suppressed));
  const step = days <= 7 ? 1 : days <= 30 ? 5 : 15;
  const mitreMax = Math.max(1, ...d.mitre.map((m) => m.total));
  const totalOut = Object.values(d.outcomes).reduce((a, b) => a + b, 0);

  body.innerHTML = `
    <div class="kpis grid grid-kpi reveal">
      <div class="kpi"><div class="kpi__label">Actionable alerts</div><div class="kpi__value">${num(t.actionable)}</div><div class="kpi__foot">${num(t.alerts)} received</div></div>
      <div class="kpi"><div class="kpi__label">Noise removed</div><div class="kpi__value">${t.noise_reduction}<small>%</small></div><div class="kpi__foot">${num(t.suppressed)} by ${t.suppression_rules} live rule${t.suppression_rules === 1 ? '' : 's'}</div></div>
      <div class="kpi ${compliance != null && compliance < 90 ? 'kpi--alert' : ''}"><div class="kpi__label">Within SLA</div><div class="kpi__value">${compliance == null ? '-' : `${compliance}<small>%</small>`}</div><div class="kpi__foot">${breached} breach${breached === 1 ? '' : 'es'} of first-response target</div></div>
      <div class="kpi"><div class="kpi__label">MTTA, critical</div><div class="kpi__value">${crit.mtta.median == null ? '-' : esc(mins(crit.mtta.median))}</div><div class="kpi__foot">median, target ${mins(crit.target_min)}</div></div>
      <div class="kpi"><div class="kpi__label">Automated</div><div class="kpi__value">${num(t.automated)}<small>/ ${num(t.investigated)}</small></div><div class="kpi__foot">verdicts not overridden &middot; ${t.rules_created} rules</div></div>
    </div>

    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">Response times by severity</h2><span class="panel__meta">MTTA = detection to first response (owner, note or status) &middot; MTTR = detection to closed</span></div>
      <div class="table-wrap"><table class="table sla">
        <thead><tr><th>Severity</th><th class="num">Alerts</th><th class="num">Target</th><th class="num">MTTA median</th><th class="num hide-sm">MTTA p90</th><th class="num">MTTR median</th><th class="num hide-sm">MTTR p90</th><th>Compliance</th><th class="hide-sm">Waiting past target</th></tr></thead>
        <tbody>${d.sla.map((s) => `<tr>
          <td>${sev(s.severity)}</td><td class="num">${s.total}</td><td class="num muted">${mins(s.target_min)}</td>
          <td class="num ${s.mtta.median != null && s.target_min && s.mtta.median > s.target_min ? 'bad' : ''}">${mins(s.mtta.median)}</td><td class="num hide-sm">${mins(s.mtta.p90)}</td>
          <td class="num">${mins(s.mttr.median)}</td><td class="num hide-sm">${mins(s.mttr.p90)}</td>
          <td>${s.compliance == null ? '<span class="muted small">no alerts</span>' : `<span class="meter"><span class="meter__track" style="width:80px"><span class="meter__fill" style="width:${s.compliance}%;background:${s.compliance >= 95 ? 'var(--ok)' : s.compliance >= 80 ? 'var(--high)' : 'var(--crit)'}"></span></span><span class="mono small">${s.compliance}%</span></span>`}</td>
          <td class="hide-sm">${s.overdue.length ? s.overdue.map((o) => `<a class="mono small overdue" href="#/investigate/${encodeURIComponent(o.alert_id)}" title="${esc(o.signature)}">${esc(o.alert_id)}</a>`).join(' ') : '<span class="muted small">none</span>'}</td>
        </tr>`).join('')}</tbody>
      </table></div>
      <div class="table-foot no-print">Targets are set under Settings, Response policy. ${can('configure') ? '<a href="#/settings">Change targets</a>' : ''}</div>
    </section>

    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">MITRE ATT&amp;CK coverage</h2><span class="panel__meta">tactics seen in investigations, latest run per alert</span></div>
      ${d.mitre.some((m) => m.total) ? `<div class="attack" style="--cols:${d.mitre.length}">${d.mitre.map((m, i) => `
        <div class="attack__col ${m.total ? 'is-hit' : ''}" style="--i:${i};--heat:${m.total / mitreMax}">
          <div class="attack__head"><span class="attack__name">${esc(m.tactic)}</span><span class="attack__n mono">${m.total || ''}</span></div>
          <div class="attack__body">${m.techniques.length ? m.techniques.slice(0, 4).map((x) => `<div class="attack__tech" title="${esc(x.name)}"><span class="truncate">${esc(x.name)}</span><b class="mono">${x.n}</b></div>`).join('') : '<span class="attack__none">-</span>'}
            ${m.succeeded ? `<div class="attack__hit">${m.succeeded} succeeded</div>` : ''}</div>
        </div>`).join('')}</div>` : emptyState('No mapped investigations yet', 'Run investigations and their ATT&CK tactic and technique land here.', 'scan')}
    </section>

    <section class="panel">
      <div class="panel__head"><h2 class="panel__title">Alert volume</h2>
        <div class="legend panel__meta">${Object.keys(SEV_C).map((s) => `<span><i style="background:${SEV_C[s]}"></i>${label(s)}</span>`).join('')}<span><i class="hatch"></i>Suppressed</span></div></div>
      <div class="panel__body">
        <div class="bars" style="grid-template-columns:repeat(${d.daily.length}, 1fr)">${d.daily.map((x, i) => {
          const tot = x.CRITICAL + x.HIGH + x.MEDIUM + x.LOW;
          return `<div class="bars__col" title="${x.day}: ${tot} actionable${x.suppressed ? `, ${x.suppressed} suppressed` : ''}">${['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].filter((s) => x[s]).map((s) => `<div class="bars__seg" style="--i:${Math.min(i, 40)};height:${(x[s] / max) * 100}%;background:${SEV_C[s]}"></div>`).join('')}${x.suppressed ? `<div class="bars__seg bars__seg--quiet" style="--i:${Math.min(i, 40)};height:${(x.suppressed / max) * 100}%"></div>` : ''}</div>`;
        }).join('')}</div>
        <div class="bars__axis">${d.daily.filter((_, i) => i % step === 0 || i === d.daily.length - 1).map((x) => `<span>${x.day.slice(5)}</span>`).join('')}</div>
      </div>
    </section>

    <div class="grid grid-2-1">
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Top external sources</h2><span class="panel__meta">by actionable alerts</span></div>
        ${d.top_attackers.length ? `<div class="table-wrap"><table class="table"><thead><tr><th>Address</th><th class="num">Alerts</th><th class="num">Critical</th><th class="num hide-sm">Last seen</th><th style="width:1%"></th></tr></thead><tbody class="rows-in">
          ${d.top_attackers.map((a, i) => `<tr style="--i:${i}"><td><a class="ip ip-link" href="#/ip/${encodeURIComponent(a.ip)}">${esc(a.ip)}</a></td><td class="num">${a.alerts}</td><td class="num">${a.critical || '<span class="muted">0</span>'}</td><td class="num small muted hide-sm">${ago(a.last)}</td>
            <td class="no-print">${a.blocked ? '<span class="tag tag--ok">blocked</span>' : can('respond') ? `<button class="btn btn--sm" data-block="${esc(a.ip)}" data-n="${a.alerts}">Block</button>` : '<span class="tag">open</span>'}</td></tr>`).join('')}
        </tbody></table></div>` : emptyState('No external sources', 'Nothing actionable from outside your network in this window.', 'globe')}
      </section>
      <div class="stack">
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Verdicts</h2><span class="panel__meta">${totalOut} cases</span></div>
          <div class="panel__body">${OUTCOMES.map(([k, txt, c]) => `<div class="hbar" style="grid-template-columns:140px 1fr 32px"><span class="small">${txt}</span><div class="hbar__track"><div class="hbar__fill" style="--c:${c};width:${totalOut ? ((d.outcomes[k] || 0) / totalOut) * 100 : 0}%"></div></div><span class="hbar__n">${d.outcomes[k] || 0}</span></div>`).join('')}</div>
        </section>
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Workload</h2><span class="panel__meta">alerts by owner</span></div>
          ${d.owners.length ? `<div class="table-wrap"><table class="table"><thead><tr><th>Owner</th><th class="num">Assigned</th><th class="num">Open</th><th class="num">Resolved</th></tr></thead><tbody>
            ${d.owners.map((o) => `<tr><td class="${o.name === 'Unassigned' ? 'muted' : ''}">${esc(o.name)}</td><td class="num">${o.assigned}</td><td class="num">${o.open}</td><td class="num">${o.resolved}</td></tr>`).join('')}
          </tbody></table></div>` : '<div class="panel__body small muted">No alerts in this window.</div>'}
        </section>
      </div>
    </div>`;

  $$('[data-block]', body).forEach((b) => {
    b.onclick = () => openNewRule({ target_ip: b.dataset.block, action: 'BLOCK', reason: `Top source in the ${days}-day report (${b.dataset.n} alerts)`, ttl_hours: 720 });
  });
  hydrateIcons(body);
  void navigate;
}