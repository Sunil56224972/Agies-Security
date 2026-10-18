import { $, $$, api, esc, ago, stamp, num, label, emptyState, toast, busy, emit, can, modal, closeLayer, pill, state } from '../core.js';
import { icon, hydrateIcons } from '../icons.js';

// The decisions log: every verdict the investigation engine produced, scored
// against what analysts later said was true (an override, or their feedback).
// Accuracy is only computed over decisions somebody actually judged.

let ctx = null;
const pct = (v) => (v == null ? '-' : `${v}%`);

export async function render({ el, query }) {
  ctx = { el, days: Number(query.days) || 30, engine: query.engine || '', judged: query.judged || '', data: null };
  el.innerHTML = `
    <div class="page-head">
      <div class="page-head__text">
        <h1 class="page-title">Decisions</h1>
        <p class="page-sub">How often the investigation engine is right, measured against analyst overrides and feedback. Judge a verdict and it counts from then on.</p>
      </div>
      <div class="page-actions">
        <div class="seg" id="dc-days">${[7, 30, 90, 365].map((d) => `<button data-days="${d}">${d === 365 ? '1y' : `${d}d`}</button>`).join('')}</div>
      </div>
    </div>
    <div id="dc-body" class="reveal"><div class="kpis grid grid-kpi">${'<div class="skeleton" style="height:86px"></div>'.repeat(4)}</div></div>`;
  $$('[data-days]', el).forEach((b) => { b.onclick = () => { ctx.days = Number(b.dataset.days); sync(); load(); }; });
  await load();
}

export function onDataChanged() { if (ctx && document.body.contains(ctx.el)) load(); }

function sync() {
  const q = new URLSearchParams();
  if (ctx.days !== 30) q.set('days', ctx.days);
  if (ctx.engine) q.set('engine', ctx.engine);
  if (ctx.judged) q.set('judged', ctx.judged);
  history.replaceState(null, '', `#/decisions${q.toString() ? `?${q}` : ''}`);
}

async function load() {
  const { el } = ctx;
  $$('[data-days]', el).forEach((b) => b.classList.toggle('is-on', Number(b.dataset.days) === ctx.days));
  const q = new URLSearchParams({ days: ctx.days });
  if (ctx.engine) q.set('engine', ctx.engine);
  if (ctx.judged) q.set('judged', ctx.judged);
  try { ctx.data = await api(`/decisions?${q}`); } catch (e) { $('#dc-body', el).innerHTML = `<section class="panel">${emptyState('Could not load decisions', e.message, 'alert')}</section>`; return; }
  if (!document.body.contains(el)) return;
  paint();
  hydrateIcons(el);
}

function gauge(v) {
  const p = v == null ? 0 : Math.max(0, Math.min(100, v));
  const tone = v == null ? 'none' : v >= 90 ? 'ok' : v >= 75 ? 'med' : 'crit';
  return `<span class="dc-gauge dc-gauge--${tone}"><span style="--w:${p}%"></span></span>`;
}

function paint() {
  const d = ctx.data;
  const t = d.totals;
  const wrong = t.judged - t.correct;
  $('#dc-body', ctx.el).innerHTML = `
    <div class="kpis grid grid-kpi">
      <div class="kpi"><div class="kpi__label">Accuracy</div><div class="kpi__value">${t.accuracy == null ? '-' : `${t.accuracy}<small>%</small>`}</div><div class="kpi__foot">${num(t.correct)} of ${num(t.judged)} judged were right</div></div>
      <div class="kpi"><div class="kpi__label">Review coverage</div><div class="kpi__value">${t.coverage == null ? '-' : `${t.coverage}<small>%</small>`}</div><div class="kpi__foot">${num(t.judged)} of ${num(t.decisions)} decisions judged</div></div>
      <div class="kpi ${wrong ? 'kpi--alert' : ''}"><div class="kpi__label">Wrong verdicts</div><div class="kpi__value">${num(wrong)}</div><div class="kpi__foot">overridden or marked wrong</div></div>
      <div class="kpi"><div class="kpi__label">Decisions</div><div class="kpi__value">${num(t.decisions)}</div><div class="kpi__foot">last ${d.days} days</div></div>
    </div>
    ${!t.judged && t.decisions ? `<div class="notice mt-12">${icon('info')}<span>Nobody has judged a verdict in this window yet, so accuracy is unknown rather than 100%. Use <b>Judge</b> on a few rows below, or override an outcome from the investigation view.</span></div>` : ''}
    <div class="grid grid-1-1 mt-12">
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">By engine</h2><span class="panel__meta">click to filter</span></div>
        ${d.engines.length ? `<table class="table dc-table"><thead><tr><th>Engine</th><th>Accuracy</th><th class="num">Judged</th><th class="num">Total</th></tr></thead><tbody>${d.engines.map((e) => `
          <tr class="is-clickable ${ctx.engine === e.engine ? 'is-sel' : ''}" data-engine="${esc(e.engine)}"><td>${esc(e.engine)}</td><td><span class="row">${gauge(e.accuracy)}<span class="mono small">${pct(e.accuracy)}</span></span></td><td class="num mono">${num(e.judged)}</td><td class="num mono">${num(e.decisions)}</td></tr>`).join('')}</tbody></table>`
        : emptyState('No decisions', 'Investigations in this window show up here by engine.', 'cpu')}
      </section>
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Calibration</h2><span class="panel__meta">is a 90% verdict right 90% of the time?</span></div>
        <table class="table dc-table"><thead><tr><th>Stated confidence</th><th>Observed accuracy</th><th class="num">Judged</th></tr></thead><tbody>${d.bands.map((b) => `
          <tr><td class="mono">${esc(b.band)}%</td><td><span class="row">${gauge(b.accuracy)}<span class="mono small">${pct(b.accuracy)}</span>${calNote(b)}</span></td><td class="num mono">${num(b.judged)}</td></tr>`).join('')}</tbody></table>
      </section>
    </div>
    ${d.mistakes.length ? `<section class="panel mt-12"><div class="panel__head"><h2 class="panel__title">Most common mistakes</h2></div>
      <div class="dc-mistakes">${d.mistakes.slice(0, 6).map((m) => `<div class="dc-mistake"><span>${pill(m.predicted)}</span>${icon('arrow')}<span>${pill(m.actual)}</span><b class="mono">${num(m.count)}</b></div>`).join('')}</div></section>` : ''}
    <section class="panel mt-12">
      <div class="toolbar">
        <div class="seg" id="dc-judged">${[['', 'All'], ['no', 'Not judged'], ['yes', 'Judged'], ['wrong', 'Wrong']].map(([k, v]) => `<button data-j="${k}" class="${ctx.judged === k ? 'is-on' : ''}">${v}</button>`).join('')}</div>
        ${ctx.engine ? `<span class="tag">${esc(ctx.engine)} <button class="icon-btn icon-btn--bare" id="dc-clear" title="Clear engine filter">${icon('x')}</button></span>` : ''}
        <span class="small muted toolbar__end">${num(d.rows.length)} shown</span>
      </div>
      ${d.rows.length ? `<div class="table-wrap"><table class="table">
        <thead><tr><th>Decision</th><th>Verdict</th><th class="hide-sm">Engine</th><th>Judgement</th><th class="hide-sm">When</th><th></th></tr></thead>
        <tbody class="rows-in">${d.rows.map((r, i) => `<tr style="--i:${Math.min(i, 30)}">
          <td><a class="cell-main mono" href="#/investigate/${encodeURIComponent(r.alert_id)}">${esc(r.investigation_id)}</a><span class="cell-sub">${esc(r.alert_id)}${r.attacker_ip ? ` &middot; <a class="mono" href="#/ip/${encodeURIComponent(r.attacker_ip)}">${esc(r.attacker_ip)}</a>` : ''}</span></td>
          <td>${pill(r.predicted)}<span class="mono small muted"> ${r.confidence ?? '-'}%</span></td>
          <td class="hide-sm small">${esc(r.family)}</td>
          <td>${judgement(r)}</td>
          <td class="hide-sm small" title="${stamp(r.created_at)}">${ago(r.created_at)}</td>
          <td>${can('respond') ? `<button class="btn btn--sm btn--ghost" data-judge="${esc(r.investigation_id)}">${icon('check')}Judge</button>` : ''}</td>
        </tr>`).join('')}</tbody></table></div>` : emptyState('Nothing matches', 'Change the window or the filter.', 'inbox')}
    </section>`;
  $$('[data-engine]', ctx.el).forEach((tr) => { tr.onclick = () => { ctx.engine = ctx.engine === tr.dataset.engine ? '' : tr.dataset.engine; sync(); load(); }; });
  $$('[data-j]', ctx.el).forEach((b) => { b.onclick = () => { ctx.judged = b.dataset.j; sync(); load(); }; });
  const c = $('#dc-clear', ctx.el);
  if (c) c.onclick = () => { ctx.engine = ''; sync(); load(); };
  $$('[data-judge]', ctx.el).forEach((b) => { b.onclick = () => openJudge(d.rows.find((r) => r.investigation_id === b.dataset.judge)); });
}

function calNote(b) {
  if (b.accuracy == null || b.judged < 3) return '';
  const lo = Number(b.band.split('-')[0]);
  if (b.accuracy + 5 < lo) return '<span class="tag tag--warn" title="Right less often than it claims">overconfident</span>';
  return '';
}

function judgement(r) {
  if (r.correct === true) return `<span class="dc-j dc-j--ok">${icon('check')}Correct</span>${r.rating ? `<span class="mono small muted"> ${r.rating}/5</span>` : ''}`;
  if (r.correct === false) return `<span class="dc-j dc-j--bad">${icon('x')}Wrong</span>${r.actual ? `<span class="small muted"> was ${esc(label(r.actual).toLowerCase())}</span>` : ''}`;
  if (r.judged_by === 'split') return '<span class="small muted">Split vote</span>';
  return '<span class="small muted">Not judged</span>';
}

function openJudge(r) {
  if (!r) return;
  const me = (r.feedback || []).find((f) => f.analyst === (state.user ? state.user.name : ''));
  const outcomes = ctx.data.outcomes.filter((o) => o !== r.predicted);
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Judge ${esc(r.investigation_id)}</h2></div>
    <form class="modal__body" id="dc-form" novalidate>
      <div class="dc-verdict">${pill(r.predicted)}<span class="mono small">${r.confidence ?? '-'}% &middot; ${esc(r.family)}</span></div>
      ${r.summary ? `<p class="small" style="margin:8px 0 12px">${esc(r.summary)}</p>` : ''}
      <div class="seg dc-yn"><button type="button" data-c="1" class="is-on">${icon('check')}Verdict was right</button><button type="button" data-c="0">${icon('x')}Verdict was wrong</button></div>
      <label class="field mt-12" id="dc-actual" hidden><span>What actually happened</span><select class="select" name="correct_outcome">${outcomes.map((o) => `<option value="${o}">${esc(label(o))}</option>`).join('')}</select></label>
      <div class="field mt-12"><span>Quality of the write-up</span><div class="dc-stars" id="dc-stars">${[1, 2, 3, 4, 5].map((n) => `<button type="button" data-r="${n}" aria-label="${n} of 5">${n}</button>`).join('')}</div></div>
      <label class="field mt-12"><span>Notes <small>(optional)</small></span><textarea class="textarea" name="notes" rows="3" maxlength="1000" placeholder="What did it miss, or what made it right?">${esc(me ? me.notes || '' : '')}</textarea></label>
      ${(r.feedback || []).length ? `<div class="small muted mt-12">Already judged by ${r.feedback.map((f) => `${esc(f.analyst)} (${f.correct ? 'right' : 'wrong'})`).join(', ')}. Your judgement replaces your own earlier one.</div>` : ''}
    </form>
    <div class="modal__foot"><span class="form-error" id="dc-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="dc-go">Save judgement</button></div>`);
  hydrateIcons(panel);
  let correct = true; let rating = null;
  $$('[data-c]', panel).forEach((b) => { b.onclick = () => { correct = b.dataset.c === '1'; $$('[data-c]', panel).forEach((x) => x.classList.toggle('is-on', x === b)); $('#dc-actual', panel).hidden = correct; }; });
  $$('[data-r]', panel).forEach((b) => { b.onclick = () => { rating = rating === Number(b.dataset.r) ? null : Number(b.dataset.r); $$('[data-r]', panel).forEach((x) => x.classList.toggle('is-on', rating != null && Number(x.dataset.r) <= rating)); }; });
  $('#dc-go', panel).onclick = () => busy($('#dc-go', panel), async () => {
    const f = new FormData($('#dc-form', panel));
    try {
      await api(`/decisions/${encodeURIComponent(r.investigation_id)}/feedback`, { method: 'POST', body: { correct, correct_outcome: correct ? undefined : f.get('correct_outcome'), rating, notes: f.get('notes') } });
      closeLayer();
      toast('Judgement saved', `${r.investigation_id} marked ${correct ? 'correct' : 'wrong'}`, 'ok');
      emit('data:changed');
    } catch (e) { $('#dc-err', panel).textContent = e.message; }
  });
}