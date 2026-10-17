import { $, $$, api, esc, pill, ago, stamp, num, label, emptyState, toast, busy, emit, can, modal, closeLayer, state } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

// The approval queue: containment the policy would not run on its own. A
// reviewer approves (the rule is created, pushed and read back) or rejects
// with a reason. Requests that sit too long expire instead of running late.

const ROUTE_HELP = {
  quick_review: 'High confidence. A glance at the evidence and one click.',
  analyst_review: 'Medium confidence. Read the investigation before deciding.',
  escalate: 'Low confidence or no verdict. A lead should decide.',
  auto: 'Within the auto-approve band.'
};
const ROUTE_ORDER = { escalate: 0, analyst_review: 1, quick_review: 2, auto: 3 };

let ctx = null;

export async function render({ el, query, navigate }) {
  ctx = { el, navigate, tab: query.tab === 'history' ? 'history' : 'pending' };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Approvals</h1>
        <p class="page-sub">Containment waiting for a human. What lands here, and when it runs on its own, is set by the approval policy.</p>
      </div>
      <div class="page-actions" id="ap-policy"></div>
    </div>
    <div class="tabs tabs--page" role="tablist" id="ap-tabs">
      <button class="tab" role="tab" data-tab="pending">Pending <span class="tab__n mono" id="ap-n"></span></button>
      <button class="tab" role="tab" data-tab="history">History</button>
    </div>
    <div id="ap-body" class="reveal"><div class="panel" style="padding:18px"><div class="stack">${'<div class="skeleton" style="height:64px"></div>'.repeat(3)}</div></div></div>`;
  $$('[data-tab]', el).forEach((b) => { b.onclick = () => { ctx.tab = b.dataset.tab; history.replaceState(null, '', ctx.tab === 'history' ? '#/approvals?tab=history' : '#/approvals'); load(); }; });
  paintPolicy();
  await load();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) load(); }

function paintPolicy() {
  const cfg = state.config || {};
  const mode = cfg.approvalMode || 'auto';
  const text = mode === 'auto' ? 'Policy: run everything at once'
    : mode === 'manual' ? 'Policy: every action needs approval'
    : `Policy: auto at ${cfg.approvalAutoAt ?? 90}%+, review below`;
  $('#ap-policy', ctx.el).innerHTML = `<span class="small muted">${esc(text)}</span>${can('configure') ? ` <a class="btn btn--sm btn--ghost" href="#/settings?section=approvals">${icon('sliders')}Change</a>` : ''}`;
  hydrateIcons($('#ap-policy', ctx.el));
}

async function load() {
  const { el } = ctx;
  $$('[data-tab]', el).forEach((b) => { const on = b.dataset.tab === ctx.tab; b.classList.toggle('is-on', on); b.setAttribute('aria-selected', String(on)); });
  let rows;
  try {
    rows = await api(ctx.tab === 'pending' ? '/approvals?status=PENDING' : '/approvals?status=APPROVED,REJECTED,EXPIRED,FAILED&limit=300');
  } catch (e) { $('#ap-body', el).innerHTML = `<section class="panel">${emptyState('Could not load approvals', e.message, 'alert')}</section>`; return; }
  if (!document.body.contains(el)) return;
  if (ctx.tab === 'pending') {
    $('#ap-n', el).textContent = rows.length || '';
    paintPending(rows);
  } else paintHistory(rows);
  hydrateIcons(el);
}

const ageClass = (iso) => { const h = (Date.now() - new Date(iso)) / 3600000; return h > 4 ? 'warn-text' : ''; };

function paintPending(rows) {
  const { el } = ctx;
  const respond = can('respond');
  const me = state.user ? state.user.name : '';
  rows.sort((a, b) => (ROUTE_ORDER[a.route] ?? 9) - (ROUTE_ORDER[b.route] ?? 9) || String(a.created_at).localeCompare(String(b.created_at)));
  const expiry = Number((state.config || {}).approvalExpiryHours) || 24;
  $('#ap-body', el).innerHTML = rows.length ? `
    <div class="ap-list">${rows.map((a, i) => `
      <article class="ap-card ap-card--${esc(a.route)}" style="--i:${i}" data-ap="${esc(a.approval_id)}">
        <div class="ap-card__main">
          <div class="row wrap">${pill(a.action)}<span class="ap-card__target mono">${esc(a.target_ip)}</span><span class="ap-route ap-route--${esc(a.route)}">${esc(a.route_text)}</span>${a.confidence != null ? `<span class="mono small muted">${a.confidence}% confidence</span>` : ''}</div>
          <p class="ap-card__reason">${esc(a.reason)}</p>
          <div class="small muted">${esc(a.approval_id)} &middot; requested by <b>${esc(a.requested_by)}</b> <span class="${ageClass(a.created_at)}" title="${stamp(a.created_at)}">${ago(a.created_at)}</span> &middot; expires ${expiresIn(a.created_at, expiry)}${a.ttl_hours ? ` &middot; lifts after ${a.ttl_hours}h` : ''}</div>
          <div class="row wrap mt-8 small">
            ${a.alert_id ? `<a href="#/investigate/${encodeURIComponent(a.alert_id)}">${icon('scan')}${esc(a.alert_id)}</a>` : ''}
            ${a.case_id ? `<a href="#/cases/${encodeURIComponent(a.case_id)}">${icon('file')}${esc(a.case_id)}</a>` : ''}
            <a href="#/ip/${encodeURIComponent(a.target_ip)}">${icon('globe')}Address profile</a>
          </div>
          <div class="small muted mt-8">${esc(a.confidence == null && !a.investigation_id ? 'Proposed by hand, no verdict score. Check the linked evidence before deciding.' : ROUTE_HELP[a.route] || '')}</div>
        </div>
        ${respond ? `<div class="ap-card__act">
          <button class="btn btn--primary btn--sm" data-approve="${esc(a.approval_id)}" ${a.requested_by === me ? 'title="You requested this; a second person approving is better practice"' : ''}>${icon('check')}Approve</button>
          <button class="btn btn--sm btn--danger" data-reject="${esc(a.approval_id)}">${icon('x')}Reject</button>
        </div>` : ''}
      </article>`).join('')}</div>`
    : `<section class="panel">${emptyState('Nothing waiting', 'Containment the policy holds back for review shows up here, with the evidence that triggered it.', 'shieldCheck')}</section>`;
  $$('[data-approve]', el).forEach((b) => {
    b.onclick = () => busy(b, async () => {
      try {
        const r = await api(`/approvals/${encodeURIComponent(b.dataset.approve)}/approve`, { method: 'POST', body: {} });
        if (r.error) toast('Approved, but the rule failed', r.error, 'error', 7000);
        else toast(`${r.rule.rule_id} ${String(r.verification.status).toLowerCase()}`, r.verification.message || `${r.rule.action} ${r.rule.target_ip}`, r.verification.status === 'FAILED' ? 'error' : 'ok', 6000);
        emit('data:changed');
      } catch (e) { toast('Not approved', e.message, 'error'); load(); }
    });
  });
  $$('[data-reject]', el).forEach((b) => { b.onclick = () => openReject(rows.find((x) => x.approval_id === b.dataset.reject)); });
}

function expiresIn(created, hours) {
  const ms = new Date(created).getTime() + hours * 3600000 - Date.now();
  if (ms <= 0) return 'now';
  const mins = Math.ceil(ms / 60000);
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return h ? `in ${h}h ${m}m` : `in ${m}m`;
}

function openReject(a) {
  if (!a) return;
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Reject ${esc(a.action.toLowerCase())} of ${esc(a.target_ip)}</h2></div>
    <form class="modal__body" id="rj-form" novalidate>
      <p class="small muted" style="margin:0 0 10px">${esc(a.reason)}</p>
      <label class="field"><span>Why not</span><textarea class="textarea" name="note" rows="3" maxlength="1000" placeholder="e.g. Shared NAT address of a partner; would cut off their whole office"></textarea></label>
    </form>
    <div class="modal__foot"><span class="form-error" id="rj-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--danger" id="rj-go">Reject</button></div>`);
  const go = (e) => {
    e.preventDefault();
    const note = new FormData($('#rj-form', panel)).get('note');
    busy($('#rj-go', panel), async () => {
      try { await api(`/approvals/${encodeURIComponent(a.approval_id)}/reject`, { method: 'POST', body: { note } }); toast('Rejected', `${a.approval_id}: nothing was changed`, 'ok'); closeLayer(); emit('data:changed'); } catch (err) { $('#rj-err', panel).textContent = err.message; }
    });
  };
  $('#rj-go', panel).onclick = go;
  $('#rj-form', panel).onsubmit = go;
}

function paintHistory(rows) {
  const { el } = ctx;
  const n = (s) => rows.filter((r) => r.status === s).length;
  const decided = rows.filter((r) => r.decided_at && r.decided_by !== 'system');
  const waits = decided.map((r) => (new Date(r.decided_at) - new Date(r.created_at)) / 60000).sort((x, y) => x - y);
  const med = waits.length ? waits[Math.floor(waits.length / 2)] : null;
  $('#ap-body', el).innerHTML = `
    <div class="kpis grid grid-kpi">
      <div class="kpi"><div class="kpi__label">Approved</div><div class="kpi__value">${num(n('APPROVED'))}</div><div class="kpi__foot">rule created and verified</div></div>
      <div class="kpi"><div class="kpi__label">Rejected</div><div class="kpi__value">${num(n('REJECTED'))}</div><div class="kpi__foot">with a written reason</div></div>
      <div class="kpi"><div class="kpi__label">Expired</div><div class="kpi__value">${num(n('EXPIRED'))}</div><div class="kpi__foot">nobody decided in time</div></div>
      <div class="kpi ${n('FAILED') ? 'kpi--alert' : ''}"><div class="kpi__label">Failed</div><div class="kpi__value">${num(n('FAILED'))}</div><div class="kpi__foot">approved, enforcement refused</div></div>
      <div class="kpi"><div class="kpi__label">Time to decision</div><div class="kpi__value">${med == null ? '-' : med < 60 ? `${Math.round(med)}<small>m</small>` : `${(med / 60).toFixed(1)}<small>h</small>`}</div><div class="kpi__foot">median over ${num(decided.length)}</div></div>
    </div>
    <section class="panel mt-12">
      ${rows.length ? `<div class="table-wrap"><table class="table">
        <thead><tr><th>Action</th><th>Outcome</th><th class="hide-sm">Route</th><th>Decided</th><th class="hide-sm">Note / result</th></tr></thead>
        <tbody class="rows-in">${rows.map((a, i) => `<tr style="--i:${Math.min(i, 30)}">
          <td><span class="cell-main">${esc(label(a.action))} <span class="mono">${esc(a.target_ip)}</span></span><span class="cell-sub">${esc(a.approval_id)} &middot; ${esc(a.requested_by)}${a.case_id ? ` &middot; <a href="#/cases/${encodeURIComponent(a.case_id)}">${esc(a.case_id)}</a>` : ''}</span></td>
          <td>${pill(a.status === 'APPROVED' ? 'ENFORCED' : a.status === 'REJECTED' || a.status === 'EXPIRED' ? 'REMOVED' : a.status, label(a.status))}</td>
          <td class="hide-sm small">${esc(a.route_text)}${a.confidence != null ? ` <span class="muted mono">${a.confidence}%</span>` : ''}</td>
          <td class="small">${esc(a.decided_by || '-')}<div class="muted" title="${stamp(a.decided_at)}">${a.decided_at ? ago(a.decided_at) : ''}</div></td>
          <td class="hide-sm small">${a.rule_id ? `<a class="mono" href="#/containment">${esc(a.rule_id)}</a> ` : ''}${esc(a.decision_note || (a.result && (a.result.error || a.result.message)) || '')}</td>
        </tr>`).join('')}</tbody></table></div>` : emptyState('No decisions yet', 'Approved, rejected and expired requests are kept here for the audit trail.', 'inbox')}
    </section>`;
}