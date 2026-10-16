import { $, $$, api, esc, pill, ago, stamp, num, emptyState, toast, busy, emit, state, can, copyText } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';
import { openNewRule, enforcementCopy } from '../panels.js';

let ctx = null;
const STATES = ['ENFORCED', 'PENDING', 'RECORDED', 'FAILED'];
const enf = (r) => (r.enforcement && r.enforcement.status) || (r.is_active ? 'RECORDED' : 'REMOVED');

export async function render({ el, navigate, query }) {
  ctx = { el, navigate, show: 'active' };
  const respond = can('respond');
  const mode = state.health?.enforcement || { mode: 'feed', label: 'Pull feed', detail: '' };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Containment</h1>
        <p class="page-sub">Block and isolation rules, and whether your firewall has actually picked them up.</p>
      </div>
      <div class="page-actions">${respond ? `<button class="btn btn--primary" id="cn-new">${icon('plus')}Add rule</button>` : ''}</div>
    </div>
    <div class="grid grid-2-1 reveal">
      <section class="panel">
        <div class="toolbar">
          <div class="seg" id="cn-show"><button data-s="active" class="is-on">Active</button><button data-s="attention">Needs attention</button><button data-s="all">All</button></div>
          <div class="toolbar__end small muted" id="cn-sum"></div>
        </div>
        <div id="cn-table"><div style="padding:18px" class="stack">${'<div class="skeleton" style="height:42px"></div>'.repeat(3)}</div></div>
      </section>
      <div class="stack">
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Verify enforcement</h2><span class="panel__meta">${esc(mode.label)}</span></div>
          <div class="panel__body">
            <form id="probe-form" class="row" novalidate>
              <div class="grow"><input class="input input--mono" id="probe-ip" placeholder="IP address" value="${esc(query.ip || '')}" autocomplete="off"></div>
              <button class="btn btn--primary" id="probe-btn" ${respond ? '' : 'disabled'}>Check</button>
            </form>
            <div class="small muted mt-8">Reads the rule state back from the enforcement backend. No traffic is sent.</div>
            <div id="probe-out"></div>
          </div>
        </section>
        <section class="panel">
          <div class="panel__head"><h2 class="panel__title">Enforcement backend</h2><a class="panel__meta" href="#/settings">Settings</a></div>
          <div class="panel__body">
            <dl class="kv">
              <dt>Mode</dt><dd><b>${esc(mode.label)}</b> <span class="mono muted small">${esc(mode.mode)}</span></dd>
              <dt>Detail</dt><dd class="small">${esc(mode.detail || '')}</dd>
            </dl>
            <p class="small muted" style="margin:10px 0 0">${esc(enforcementCopy())}</p>
            ${mode.mode === 'feed' ? `
            <div class="mt-12 stack" style="gap:6px">
              <div class="secret"><code>${esc(location.origin)}/api/feeds/blocklist.txt</code><button class="btn btn--sm btn--ghost" data-copy="${esc(location.origin)}/api/feeds/blocklist.txt">Copy</button></div>
              <div class="secret"><code>${esc(location.origin)}/api/feeds/isolate.txt</code><button class="btn btn--sm btn--ghost" data-copy="${esc(location.origin)}/api/feeds/isolate.txt">Copy</button></div>
              <span class="small muted">Authenticate with an API key that has the <code>feed</code> scope (Bearer, or Basic with the key as password).</span>
            </div>` : ''}
            ${mode.warning ? `<div class="notice notice--warn mt-12">${icon('alert')}<div class="small">${esc(mode.warning)}</div></div>` : ''}
          </div>
        </section>
      </div>
    </div>`;
  if ($('#cn-new', el)) $('#cn-new', el).onclick = () => openNewRule();
  $$('[data-copy]', el).forEach((b) => { b.onclick = () => copyText(b.dataset.copy, b); });
  $$('#cn-show button', el).forEach((b) => {
    b.onclick = () => { ctx.show = b.dataset.s; $$('#cn-show button', el).forEach((x) => x.classList.toggle('is-on', x === b)); paint(); };
  });
  $('#probe-form', el).onsubmit = (e) => { e.preventDefault(); probe(); };
  hydrateIcons(el);
  await load();
  if (query.ip && respond) probe();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) load(); }

async function load() {
  ctx.rules = await api('/rules');
  paint();
}

function paint() {
  const { el, rules } = ctx;
  const respond = can('respond');
  const active = rules.filter((r) => r.is_active);
  const counts = Object.fromEntries(STATES.map((s) => [s, active.filter((r) => enf(r) === s).length]));
  const rows = ctx.show === 'active' ? active : ctx.show === 'attention' ? active.filter((r) => ['PENDING', 'FAILED'].includes(enf(r))) : rules;
  $('#cn-sum', el).innerHTML = `${active.length} active${STATES.filter((s) => counts[s]).map((s) => ` &middot; <span class="mono">${counts[s]}</span> ${s.toLowerCase()}`).join('')}`;
  $('#cn-table', el).innerHTML = rows.length ? `
    <div class="table-wrap"><table class="table">
      <thead><tr><th>Target</th><th>Action</th><th class="hide-sm">Reason</th><th>Enforcement</th><th style="width:1%">On</th></tr></thead>
      <tbody class="rows-in">${rows.map((r, i) => {
        const e = r.enforcement || {};
        return `
        <tr class="${r.is_active ? '' : 'is-dim'}" style="--i:${i}">
          <td><span class="cell-main mono">${esc(r.target_ip)}</span><span class="cell-sub"><span class="mono">${esc(r.rule_id)}</span> &middot; ${esc(r.enacted_by || 'Analyst')} &middot; <span title="${stamp(r.created_at)}">${ago(r.created_at)}</span></span></td>
          <td>${pill(r.action, r.action === 'BLOCK' ? 'Block' : 'Isolate')}</td>
          <td class="hide-sm small" style="max-width:300px;color:var(--ink-2)">${esc(r.reason)}${r.investigation_id ? `<span class="cell-sub mono">${esc(r.investigation_id)}</span>` : ''}</td>
          <td style="max-width:240px"><div class="row" style="gap:6px">${pill(enf(r))}${respond && r.is_active ? `<button class="icon-btn icon-btn--bare" title="Re-check now" aria-label="Re-check ${esc(r.rule_id)}" data-verify="${esc(r.rule_id)}">${icon('refresh')}</button>` : ''}</div>
            <span class="cell-sub" title="${esc(e.detail || '')}">${esc(e.mode || '-')}${e.at ? ` &middot; ${ago(e.at)}` : ''}${e.detail ? ` &middot; ${esc(e.detail)}` : ''}</span></td>
          <td><button class="switch" role="switch" aria-checked="${r.is_active}" aria-label="Toggle ${esc(r.rule_id)}" data-toggle="${esc(r.rule_id)}" ${respond ? '' : 'disabled'}></button></td>
        </tr>`;
      }).join('')}</tbody>
    </table></div>`
    : emptyState(ctx.show === 'attention' ? 'Nothing waiting' : ctx.show === 'active' ? 'No active rules' : 'No rules yet',
      ctx.show === 'attention' ? 'Every active rule has been confirmed by the enforcement backend.' : 'Rules come from investigations or are added by hand.', 'shield');

  $$('[data-toggle]', el).forEach((b) => {
    b.onclick = async () => {
      const on = b.getAttribute('aria-checked') === 'true';
      b.setAttribute('aria-checked', String(!on));
      b.disabled = true;
      try {
        const r = await api(`/rules/${b.dataset.toggle}/toggle`, { method: 'POST' });
        toast(r.is_active ? 'Rule enabled' : 'Rule disabled', `${r.action} ${r.target_ip}: ${r.enforcement ? r.enforcement.detail : ''}`, r.enforcement && r.enforcement.status === 'FAILED' ? 'error' : 'ok');
        emit('data:changed');
      } catch (e) {
        b.setAttribute('aria-checked', String(on));
        toast('Could not change rule', e.message, 'error');
      } finally { b.disabled = false; }
    };
  });
  $$('[data-verify]', el).forEach((b) => {
    b.onclick = () => busy(b, async () => {
      try {
        const r = await api(`/rules/${b.dataset.verify}/verify`, { method: 'POST' });
        toast(`${r.rule_id}: ${r.enforcement.status.toLowerCase()}`, r.enforcement.detail, r.enforcement.status === 'FAILED' ? 'error' : 'ok');
        emit('data:changed');
      } catch (e) { toast('Check failed', e.message, 'error'); }
    });
  });
  hydrateIcons(el);
}

async function probe() {
  const { el } = ctx;
  const ip = $('#probe-ip', el).value.trim();
  const out = $('#probe-out', el);
  await busy($('#probe-btn', el), async () => {
    try {
      const r = await api('/verify', { method: 'POST', body: { target_ip: ip } });
      out.innerHTML = `
        <div class="probe-out ${r.contained ? 'probe-out--drop' : ''}">
          <dl class="dl">
            <dt>Status</dt><dd>${pill(r.status, r.status === 'NO_RULE' ? 'No rule' : undefined)}</dd>
            <dt>Backend</dt><dd class="mono">${esc(r.mode || '-')}</dd>
            <dt>Rule</dt><dd class="mono">${esc(r.rule_id ? `${r.rule_id} (${r.action})` : '-')}</dd>
            <dt>Checked</dt><dd class="mono">${stamp(r.checked_at || new Date().toISOString())}</dd>
          </dl>
          <div class="probe-out__msg">${esc(r.message)}${r.status === 'NO_RULE' && can('respond') ? `<div class="mt-8"><button class="btn btn--sm" id="probe-block">Block ${esc(ip)}</button></div>` : ''}</div>
        </div>`;
      const pb = $('#probe-block', out);
      if (pb) pb.onclick = () => openNewRule({ target_ip: ip, reason: '' });
      hydrateIcons(out);
      emit('data:changed');
    } catch (e) {
      $('#probe-ip', el).classList.add('is-invalid');
      toast('Check failed', e.message, 'error');
      setTimeout(() => $('#probe-ip', el)?.classList.remove('is-invalid'), 1600);
    }
  });
}