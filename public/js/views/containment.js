import { $, $$, api, esc, pill, ago, stamp, num, emptyState, toast, busy, emit, state } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { openNewRule } from '../panels.js';

let ctx = null;

export async function render({ el, navigate, query }) {
  ctx = { el, navigate, show: 'active' };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Containment</h1>
        <p class="page-sub">Firewall and isolation rules. Disabled rules keep their history.</p>
      </div>
      <div class="page-actions"><button class="btn btn--primary" id="cn-new">Add rule</button></div>
    </div>
    <div class="grid grid-2-1 reveal">
      <section class="panel">
        <div class="toolbar">
          <div class="seg" id="cn-show"><button data-s="active" class="is-on">Active</button><button data-s="all">All</button></div>
          <div class="toolbar__end small muted" id="cn-sum"></div>
        </div>
        <div id="cn-table"><div style="padding:18px" class="stack">${'<div class="skeleton" style="height:42px"></div>'.repeat(3)}</div></div>
      </section>
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Probe</h2><span class="panel__meta">simulated SYN burst</span></div>
        <div class="panel__body">
          <form id="probe-form" class="row" novalidate>
            <div class="grow"><input class="input input--mono" id="probe-ip" placeholder="185.220.101.45" value="${esc(query.ip || '')}"></div>
            <button class="btn btn--primary" id="probe-btn">Send</button>
          </form>
          <div class="small muted mt-8">Sends a burst from the given source and reports whether a rule drops it.</div>
          <div id="probe-out"></div>
        </div>
      </section>
    </div>`;
  $('#cn-new', el).onclick = () => openNewRule();
  $$('#cn-show button', el).forEach((b) => {
    b.onclick = () => { ctx.show = b.dataset.s; $$('#cn-show button', el).forEach((x) => x.classList.toggle('is-on', x === b)); paint(); };
  });
  $('#probe-form', el).onsubmit = (e) => { e.preventDefault(); probe(); };
  await load();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) load(); }

async function load() {
  ctx.rules = await api('/rules');
  paint();
}

function paint() {
  const { el, rules } = ctx;
  const active = rules.filter((r) => r.is_active);
  const rows = ctx.show === 'active' ? active : rules;
  $('#cn-sum', el).innerHTML = `${active.length} active &middot; <span class="mono">${num(active.reduce((s, r) => s + Number(r.packets_dropped || 0), 0))}</span> packets dropped`;
  $('#cn-table', el).innerHTML = rows.length ? `
    <div class="table-wrap"><table class="table">
      <thead><tr><th>Target</th><th>Action</th><th class="hide-sm">Reason</th><th class="num">Dropped</th><th style="width:1%">On</th></tr></thead>
      <tbody class="rows-in">${rows.map((r, i) => `
        <tr class="${r.is_active ? '' : 'is-dim'}" style="--i:${i}">
          <td><span class="cell-main mono">${esc(r.target_ip)}</span><span class="cell-sub"><span class="mono">${esc(r.rule_id)}</span> &middot; ${esc(r.enacted_by || 'Analyst')} &middot; <span title="${stamp(r.created_at)}">${ago(r.created_at)}</span></span></td>
          <td>${pill(r.action, r.action === 'BLOCK' ? 'Block' : 'Isolate')}</td>
          <td class="hide-sm small" style="max-width:320px;color:var(--ink-2)">${esc(r.reason)}${r.investigation_id ? `<span class="cell-sub mono">${esc(r.investigation_id)}</span>` : ''}</td>
          <td class="num">${num(r.packets_dropped)}</td>
          <td><button class="switch" role="switch" aria-checked="${r.is_active}" aria-label="Toggle ${esc(r.rule_id)}" data-toggle="${esc(r.rule_id)}"></button></td>
        </tr>`).join('')}</tbody>
    </table></div>` : emptyState(ctx.show === 'active' ? 'No active rules' : 'No rules yet', 'Created by investigations or added manually.', 'shield');

  $$('[data-toggle]', el).forEach((b) => {
    b.onclick = async () => {
      const on = b.getAttribute('aria-checked') === 'true';
      b.setAttribute('aria-checked', String(!on));
      try {
        const r = await api(`/rules/${b.dataset.toggle}/toggle`, { method: 'POST', body: { analyst: state.config && state.config.analystName } });
        toast(r.is_active ? 'Rule enabled' : 'Rule disabled', `${r.action} ${r.target_ip}`, r.is_active ? 'ok' : 'info');
        emit('data:changed');
      } catch (e) {
        b.setAttribute('aria-checked', String(on));
        toast('Could not toggle rule', e.message, 'error');
      }
    };
  });
  hydrateIcons(el);
}

async function probe() {
  const { el } = ctx;
  const ip = $('#probe-ip', el).value.trim();
  const out = $('#probe-out', el);
  await busy($('#probe-btn', el), async () => {
    try {
      const r = await api('/probe', { method: 'POST', body: { target_ip: ip } });
      const drop = r.status === 'CONTAINED';
      out.innerHTML = `
        <div class="probe-out ${drop ? 'probe-out--drop' : ''}">
          <dl class="dl">
            <dt>Result</dt><dd>${pill(r.status)}</dd>
            <dt>State</dt><dd class="mono">${esc(r.connection_state)}</dd>
            <dt>Packets</dt><dd class="mono">${drop ? `${r.probe_packets} dropped` : 'delivered'}</dd>
            <dt>Rule</dt><dd class="mono">${esc(r.rule_id || '-')}</dd>
          </dl>
          <div class="probe-out__msg">${esc(r.message)}${r.status === 'EXPOSED' ? `<div class="mt-8"><button class="btn btn--sm" id="probe-block">Block ${esc(ip)}</button></div>` : ''}</div>
        </div>`;
      const pb = $('#probe-block', out);
      if (pb) pb.onclick = () => openNewRule({ target_ip: ip, reason: 'Probe reached service; blocking pending review' });
      hydrateIcons(out);
      if (r.status === 'CONTAINED') emit('data:changed');
    } catch (e) {
      $('#probe-ip', el).classList.add('is-invalid');
      toast('Probe not sent', e.message, 'error');
      setTimeout(() => $('#probe-ip', el)?.classList.remove('is-invalid'), 1600);
    }
  });
}