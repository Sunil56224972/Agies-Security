import { $, $$, api, esc, sev, pill, ago, stamp, markPayload, drawer, modal, closeLayer, toast, busy, emit, num, label, state, can } from './core.js';
import { icon, hydrateIcons } from './icons.js';

// Overlays reused by several views.

const MODE_COPY = {
  feed: 'The rule is published on the pull feed and counts as enforced once your firewall fetches it.',
  webhook: 'The rule is POSTed to your enforcement webhook and counts as enforced when the receiver acknowledges it.',
  cloudflare: 'Blocks become Cloudflare IP Access Rules and are read back from the Cloudflare API. Isolation is recorded only.',
  record: 'Enforcement is set to record only: the rule is stored in Aegis and nothing outside changes.'
};
export const enforcementCopy = () => MODE_COPY[state.health?.enforcement?.mode] || '';

const initials = (name) => String(name || '?').split(/[\s@.:]+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('') || '?';
const OPEN_STATES = ['NEW', 'INVESTIGATING', 'CONFIRMED'];
const ipLink = (ip) => `<a class="ip ip-link" href="#/ip/${encodeURIComponent(ip)}">${esc(ip)}</a>`;

let assignable = null;
export async function assignableUsers() {
  if (!assignable || assignable.at < Date.now() - 60000) assignable = { at: Date.now(), list: await api('/users/assignable') };
  return assignable.list;
}

function noteHtml(n) {
  const event = n.kind === 'event';
  return `<li class="casefeed__item ${event ? 'casefeed__item--event' : ''}">
    <span class="casefeed__mark">${event ? icon('dot') : esc(initials(n.author))}</span>
    <div class="grow"><div class="casefeed__meta"><b>${esc(n.author)}</b><span title="${stamp(n.created_at)}">${ago(n.created_at)}</span></div>
    <div class="casefeed__body">${esc(n.body)}</div></div></li>`;
}

export async function openAlert(alertId, navigate) {
  const panel = drawer(`<div class="drawer__head"><div class="grow"><div class="eyebrow">${esc(alertId)}</div><div class="skeleton" style="height:28px;margin-top:8px;width:80%"></div></div><button class="icon-btn icon-btn--bare" data-close aria-label="Close">${icon('x')}</button></div><div class="drawer__body"><div class="skeleton" style="height:120px"></div><div class="skeleton" style="height:160px"></div></div>`);
  let data;
  let people = [];
  try {
    [data, people] = await Promise.all([api(`/alerts/${encodeURIComponent(alertId)}`), can('respond') ? assignableUsers().catch(() => []) : []]);
  } catch (e) { toast('Could not load alert', e.message, 'error'); closeLayer(); return; }
  const { alert: a, asset, investigations, notes = [], suppression } = data;
  const last = investigations[0];
  const respond = can('respond');
  const me = state.user || {};
  const mine = a.assignee_id === me.id;
  panel.innerHTML = `
    <div class="drawer__head">
      <div class="grow">
        <div class="eyebrow">${esc(a.alert_id)} &middot; ${esc(a.sensor || 'sensor')} &middot; ${ago(a.detected_at)}</div>
        <h2 class="drawer__title">${esc(a.signature)}</h2>
        <div class="row wrap mt-12">${sev(a.severity)} ${pill(a.status)} <span class="tag">${esc(a.category)}</span>${a.external_ref ? ` <span class="tag" title="Sensor rule reference">${esc(a.external_ref)}</span>` : ''}</div>
      </div>
      <button class="icon-btn icon-btn--bare" data-close aria-label="Close">${icon('x')}</button>
    </div>
    <div class="drawer__body">
      ${suppression || a.suppressed_by ? `<div class="notice">${icon('info')}<div class="small">Closed on arrival by suppression rule <b>${esc(suppression ? suppression.name : `#${a.suppressed_by}`)}</b>${suppression && !suppression.enabled ? ' (now paused)' : ''}. Reopen it if the rule is wrong, then fix the rule under Containment.</div></div>` : ''}
      <section class="owner">
        <span class="avatar avatar--soft">${a.assignee_name ? esc(initials(a.assignee_name)) : icon('user')}</span>
        <div class="grow">
          <div class="small muted">Owner</div>
          ${respond ? `<select class="select select--bare" id="d-owner" aria-label="Owner">
            <option value="">Unassigned</option>
            ${people.map((u) => `<option value="${u.id}" ${u.id === a.assignee_id ? 'selected' : ''}>${esc(u.name)}${u.id === me.id ? ' (you)' : ''}</option>`).join('')}
            ${a.assignee_id && !people.some((u) => u.id === a.assignee_id) ? `<option value="${a.assignee_id}" selected>${esc(a.assignee_name)}</option>` : ''}
          </select>` : `<div><b>${esc(a.assignee_name || 'Unassigned')}</b></div>`}
        </div>
        ${respond && !mine && me.role !== 'viewer' ? '<button class="btn btn--sm" id="d-take">Take it</button>' : ''}
        <dl class="owner__times">
          <dt>First response</dt><dd class="mono">${a.acknowledged_at ? `${durationText(a.detected_at, a.acknowledged_at)}` : OPEN_STATES.includes(a.status) ? `<span class="warn-text">waiting ${durationText(a.detected_at, new Date().toISOString())}</span>` : '-'}</dd>
          <dt>Resolved</dt><dd class="mono">${a.resolved_at ? durationText(a.detected_at, a.resolved_at) : '-'}</dd>
        </dl>
      </section>
      <section>
        <h3 class="section-title">Flow</h3>
        <dl class="dl">
          <dt>Source</dt><dd>${ipLink(a.source_ip)}</dd>
          <dt>Destination</dt><dd>${ipLink(a.dest_ip)}<span class="ip">:${esc(a.dest_port)}</span> <span class="muted">${esc(a.protocol)}</span></dd>
          <dt>Detected</dt><dd class="mono">${stamp(a.detected_at)}</dd>
          ${asset ? `<dt>Target host</dt><dd>${esc(asset.hostname)} <span class="muted">&middot; ${esc(asset.os_version)} &middot; tier ${esc(asset.criticality.toLowerCase())}</span></dd>` : '<dt>Target host</dt><dd class="muted">Not in the inventory</dd>'}
        </dl>
      </section>
      <section>
        <div class="row"><h3 class="section-title grow" style="margin:0">Captured payload</h3><button class="btn btn--ghost btn--sm" id="copy-payload">${icon('copy')}Copy</button></div>
        <pre class="code mt-8">${markPayload(a.raw_payload)}</pre>
      </section>
      ${last ? `
      <section>
        <h3 class="section-title">Latest investigation</h3>
        <div class="list__item is-clickable" style="border:1px solid var(--line);border-radius:var(--r);padding:12px 14px" id="open-inv">
          ${pill(last.outcome)}
          <div><div class="list__title">${esc(last.investigation_id)} &middot; ${last.confidence}% confidence</div><div class="list__sub">${esc(last.engine)} &middot; ${ago(last.created_at)}${last.human_override ? ' &middot; overridden' : ''}</div></div>
          ${icon('arrow')}
        </div>
      </section>` : ''}
      <section>
        <div class="row"><h3 class="section-title grow" style="margin:0">Case notes</h3><span class="small muted" id="d-ncount">${notes.length || ''}</span></div>
        <ol class="casefeed mt-8" id="d-notes">${notes.length ? notes.map(noteHtml).join('') : '<li class="casefeed__empty small muted">Nothing yet. Assignments, status changes and verdicts are logged here automatically.</li>'}</ol>
        ${respond ? `<form class="note-form" id="d-note-form" novalidate>
          <textarea class="textarea" id="d-note" rows="2" maxlength="4000" placeholder="What did you check, who did you talk to, what is next?"></textarea>
          <div class="row"><span class="small muted grow">Ctrl+Enter to post. Notes go into the incident report.</span><button class="btn btn--sm" id="d-note-add">Add note</button></div>
        </form>` : ''}
      </section>
    </div>
    <div class="drawer__foot">
      <button class="btn btn--primary" id="d-investigate" ${a.status === 'INVESTIGATING' || !respond ? 'disabled' : ''}>${icon('play')}${last ? 'Re-investigate' : 'Investigate'}</button>
      ${respond && ['NEW', 'CONFIRMED'].includes(a.status) ? '<button class="btn" id="d-fp">False positive</button>' : ''}
      ${respond && a.status !== 'CLOSED' && a.status !== 'NEW' && a.status !== 'INVESTIGATING' ? '<button class="btn btn--ghost" id="d-close">Close</button>' : ''}
      ${respond && (a.status === 'CLOSED' || a.status === 'FALSE_POSITIVE') ? '<button class="btn btn--ghost" id="d-reopen">Reopen</button>' : ''}
      ${respond ? `<button class="btn btn--ghost" id="d-case">${icon('file')}Add to case</button>` : ''}
      ${can('configure') && !a.suppressed_by ? `<button class="btn btn--ghost" id="d-suppress" title="Stop alerting on traffic like this">${icon('filter')}Suppress similar</button>` : ''}
      ${!respond ? '<span class="small muted">Read-only role</span>' : ''}
    </div>`;
  $('#copy-payload', panel).onclick = async () => {
    try { await navigator.clipboard.writeText(a.raw_payload); toast('Payload copied'); } catch { toast('Clipboard unavailable', '', 'error'); }
  };
  $$('.ip-link', panel).forEach((l) => { l.onclick = () => closeLayer(); });
  $('#d-investigate', panel).onclick = () => { closeLayer(); navigate(`investigate/${a.alert_id}`); };
  const oi = $('#open-inv', panel);
  if (oi) oi.onclick = () => { closeLayer(); navigate(`investigate/${a.alert_id}`); };
  const setStatus = (status, msg) => async (e) => {
    await busy(e.currentTarget, async () => {
      try {
        await api(`/alerts/${a.alert_id}/status`, { method: 'POST', body: { status } });
        toast(msg, a.alert_id, 'ok');
        emit('data:changed');
        closeLayer();
      } catch (err) { toast('Update failed', err.message, 'error'); }
    });
  };
  if ($('#d-fp', panel)) $('#d-fp', panel).onclick = setStatus('FALSE_POSITIVE', 'Marked as false positive');
  if ($('#d-close', panel)) $('#d-close', panel).onclick = setStatus('CLOSED', 'Alert closed');
  if ($('#d-reopen', panel)) $('#d-reopen', panel).onclick = setStatus('NEW', 'Alert reopened');

  const assign = async (userId, btn) => busy(btn, async () => {
    try {
      const r = await api(`/alerts/${a.alert_id}/assign`, { method: 'POST', body: { user_id: userId } });
      toast(r.assignee_name ? `Assigned to ${r.assignee_name}` : 'Unassigned', a.alert_id, 'ok');
      emit('data:changed');
      openAlert(a.alert_id, navigate);
    } catch (err) { toast('Could not assign', err.message, 'error'); }
  });
  const owner = $('#d-owner', panel);
  if (owner) owner.onchange = () => assign(owner.value ? Number(owner.value) : null, null);
  const take = $('#d-take', panel);
  if (take) take.onclick = () => assign(me.id, take);

  const form = $('#d-note-form', panel);
  if (form) {
    const box = $('#d-note', panel);
    const post = (e) => {
      e.preventDefault();
      const body = box.value.trim();
      if (!body) { box.classList.add('is-invalid'); setTimeout(() => box.classList.remove('is-invalid'), 1200); return; }
      busy($('#d-note-add', panel), async () => {
        try {
          const n = await api(`/alerts/${a.alert_id}/notes`, { method: 'POST', body: { body } });
          const list = $('#d-notes', panel);
          $('.casefeed__empty', list)?.remove();
          list.insertAdjacentHTML('beforeend', noteHtml(n));
          list.lastElementChild.classList.add('is-new');
          $('#d-ncount', panel).textContent = String(list.children.length);
          box.value = '';
        } catch (err) { toast('Note not saved', err.message, 'error'); }
      });
    };
    form.onsubmit = post;
    $('#d-note-add', panel).onclick = post;
    box.onkeydown = (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) post(e); };
  }
  const dc = $('#d-case', panel);
  if (dc) dc.onclick = () => openAddToCase([a.alert_id], { title: a.signature, severity: a.severity });
  api(`/alerts/${encodeURIComponent(a.alert_id)}/cases`).then((cs) => {
    if (!cs.length || !panel.isConnected) return;
    const head = $('.drawer__head .row', panel);
    if (head) head.insertAdjacentHTML('beforeend', cs.map((c) => ` <a class="tag" href="#/cases/${encodeURIComponent(c.case_id)}" title="${esc(c.title)}">${esc(c.case_id)}</a>`).join(''));
    $$('.drawer__head .row a.tag', panel).forEach((l) => { l.onclick = () => closeLayer(); });
  }).catch(() => {});
  const sup = $('#d-suppress', panel);
  if (sup) sup.onclick = () => openSuppress({ name: `Tune: ${a.signature}`.slice(0, 120), signature: a.signature, source_cidr: a.source_ip, dest_port: a.dest_port });
}

export function durationText(from, to) {
  const m = Math.max(0, (new Date(to) - new Date(from)) / 60000);
  if (m < 1) return `${Math.max(1, Math.round(m * 60))}s`;
  if (m < 90) return `${Math.round(m)}m`;
  if (m < 2880) return `${Math.floor(m / 60)}h ${Math.round(m % 60)}m`;
  return `${Math.round(m / 1440)}d`;
}

// ---- Suppression (tuning) rule -----------------------------------------------
// Opens with a draft built from an alert or empty. The preview runs against
// the last 30 days so the analyst sees what the rule would have hidden.
export function openSuppress(prefill = {}, onSaved) {
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Suppression rule</h2><p class="small muted" style="margin:4px 0 0">Matching alerts are still stored, but arrive closed as false positives and skip triage, notifications and auto-containment. Every condition you fill in must match.</p></div>
    <form class="modal__body" id="sp-form" novalidate>
      <div class="form-grid">
        <label class="field span-2"><span>Name</span><input class="input" name="name" required value="${esc(prefill.name || '')}" placeholder="Why this traffic is expected, e.g. Quarterly Qualys scan"></label>
        <label class="field span-2"><span>Signature contains</span><input class="input" name="signature" value="${esc(prefill.signature || '')}" placeholder="Case-insensitive text, e.g. ET SCAN Qualys"></label>
        <label class="field"><span>Source address or CIDR</span><input class="input input--mono" name="source_cidr" value="${esc(prefill.source_cidr || '')}" placeholder="64.39.96.0/20"></label>
        <label class="field"><span>Destination address or CIDR</span><input class="input input--mono" name="dest_cidr" value="${esc(prefill.dest_cidr || '')}" placeholder="any"></label>
        <label class="field"><span>Destination port</span><input class="input input--mono" name="dest_port" type="number" min="0" max="65535" value="${esc(prefill.dest_port ?? '')}" placeholder="any"></label>
        <label class="field"><span>Expires</span><select class="select" name="expires_in_days"><option value="7">After 7 days</option><option value="30" selected>After 30 days</option><option value="90">After 90 days</option><option value="">Never</option></select></label>
        <label class="check span-2"><input type="checkbox" name="apply_to_open" checked><span>Also close open alerts that match right now</span></label>
      </div>
      <div class="preview" id="sp-preview" aria-live="polite"><span class="small muted">Checking the last 30 days...</span></div>
    </form>
    <div class="modal__foot"><span class="form-error" id="sp-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="sp-save">Create rule</button></div>`);
  const form = $('#sp-form', panel);
  const out = $('#sp-preview', panel);
  const read = () => {
    const b = Object.fromEntries(new FormData(form));
    b.apply_to_open = form.apply_to_open.checked;
    return b;
  };
  let seq = 0;
  let timer;
  const preview = async () => {
    const mine = ++seq;
    try {
      const r = await api('/suppressions/preview', { method: 'POST', body: { ...read(), days: 30 } });
      if (mine !== seq) return;
      out.classList.toggle('preview--warn', r.critical > 0);
      out.innerHTML = `
        <div class="preview__n"><b class="mono">${num(r.matched)}</b><span>of ${num(r.scanned)} alerts in the last ${r.days} days would match${r.open ? `, <b>${r.open}</b> still open` : ''}.</span></div>
        ${r.critical ? `<div class="small" style="color:var(--crit);margin-top:4px">${r.critical} of them are CRITICAL. Narrow the rule unless you are sure.</div>` : ''}
        ${r.signatures.length ? `<ul class="preview__list">${r.signatures.map((s) => `<li><span class="truncate">${esc(s.signature)}</span><span class="mono">${s.n}</span></li>`).join('')}</ul>` : ''}`;
      $('#sp-err', panel).textContent = '';
    } catch (e) {
      if (mine !== seq) return;
      out.classList.remove('preview--warn');
      out.innerHTML = `<span class="small muted">${esc(e.message)}</span>`;
    }
  };
  form.oninput = () => { clearTimeout(timer); timer = setTimeout(preview, 280); };
  preview();
  const go = async (e) => {
    e.preventDefault();
    await busy($('#sp-save', panel), async () => {
      try {
        const r = await api('/suppressions', { method: 'POST', body: read() });
        toast('Suppression rule created', r.closed ? `${r.closed} open alert${r.closed === 1 ? '' : 's'} closed as false positive` : r.name, 'ok', 6000);
        emit('data:changed');
        closeLayer();
        if (onSaved) onSaved(r);
      } catch (err) { $('#sp-err', panel).textContent = err.message; }
    });
  };
  $('#sp-save', panel).onclick = go;
  form.onsubmit = go;
}
// Manual entry for detections that did not come through a sensor
// (a user report, a vendor notification, a SIEM search hit).
export async function openNewAlert(navigate) {
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Log an alert by hand</h2><p class="small muted" style="margin:4px 0 0">Sensors should post to <code>/api/ingest/alerts</code> instead. Use this for detections that reached you some other way.</p></div>
    <form class="modal__body" id="alert-form" novalidate>
      <div class="form-grid">
        <label class="field span-2"><span>Signature</span><input class="input" name="signature" required placeholder="What was detected, in one line"></label>
        <label class="field"><span>Source IP</span><input class="input input--mono" name="source_ip" required placeholder="Attacker or origin"></label>
        <label class="field"><span>Destination IP</span><input class="input input--mono" name="dest_ip" required placeholder="Affected host" list="asset-ips" autocomplete="off"></label>
        <label class="field"><span>Port</span><input class="input input--mono" name="dest_port" type="number" min="0" max="65535" value="443"></label>
        <label class="field"><span>Severity</span><select class="select" name="severity"><option>CRITICAL</option><option selected>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label>
        <label class="field"><span>Protocol</span><input class="input" name="protocol" value="TCP/HTTP"></label>
        <label class="field"><span>Category</span><input class="input" name="category" value="Manual report"></label>
        <label class="field span-2"><span>Evidence</span><textarea class="textarea" name="raw_payload" required placeholder="Raw request, log line or packet excerpt"></textarea></label>
      </div>
      <datalist id="asset-ips"></datalist>
    </form>
    <div class="modal__foot"><span class="form-error" id="af-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn" id="af-save">Save</button><button class="btn btn--primary" id="af-run">${icon('play')}Save &amp; investigate</button></div>`);
  api('/assets').then((assets) => {
    const dl = $('#asset-ips', panel);
    if (dl) dl.innerHTML = assets.map((a) => `<option value="${esc(a.ip_address)}">${esc(a.hostname)}</option>`).join('');
  }).catch(() => {});
  const form = $('#alert-form', panel);
  const submit = (andRun) => async (e) => {
    e.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    body.dest_port = Number(body.dest_port);
    body.raw_payload = body.raw_payload.replace(/\r?\n/g, '\r\n');
    await busy(e.currentTarget, async () => {
      try {
        const created = await api('/alerts', { method: 'POST', body });
        toast('Alert saved', created.alert_id, 'ok');
        emit('data:changed');
        closeLayer();
        if (andRun) navigate(`investigate/${created.alert_id}?run=1`);
      } catch (err) { $('#af-err', panel).textContent = err.message; }
    });
  };
  $('#af-save', panel).onclick = submit(false);
  $('#af-run', panel).onclick = submit(true);
  form.onsubmit = submit(false);
}

export function openNewRule(prefill = {}) {
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Add containment rule</h2></div>
    <form class="modal__body" id="rule-form" novalidate>
      <div class="form-grid">
        <label class="field"><span>Target IP</span><input class="input input--mono" name="target_ip" required value="${esc(prefill.target_ip || '')}" placeholder="IPv4 or IPv6"></label>
        <label class="field"><span>Action</span><select class="select" name="action"><option value="BLOCK" ${prefill.action !== 'ISOLATE' ? 'selected' : ''}>Block at perimeter</option><option value="ISOLATE" ${prefill.action === 'ISOLATE' ? 'selected' : ''}>Isolate host</option></select></label>
        <label class="field"><span>Reason</span><input class="input" name="reason" required value="${esc(prefill.reason || '')}" placeholder="Why this rule exists (shown to the next shift)"></label>
        <label class="field"><span>Lift automatically</span><select class="select" name="ttl_hours">${[['', 'Never (remove by hand)'], ['1', 'After 1 hour'], ['24', 'After 24 hours'], ['168', 'After 7 days'], ['720', 'After 30 days']].map(([v, t]) => `<option value="${v}" ${String(prefill.ttl_hours ?? '') === v ? 'selected' : ''}>${t}</option>`).join('')}</select></label>
      </div>
      <p class="small muted mt-12">${esc(enforcementCopy())}</p>
    </form>
    <div class="modal__foot"><span class="form-error" id="rf-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="rf-save">${icon('lock')}Create rule</button></div>`);
  const form = $('#rule-form', panel);
  const go = async (e) => {
    e.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    await busy($('#rf-save', panel), async () => {
      try {
        const r = await api('/rules', { method: 'POST', body });
        const st = r.enforcement ? r.enforcement.status : 'RECORDED';
        toast(`Rule ${r.rule_id} ${st.toLowerCase()}`, r.enforcement ? r.enforcement.detail : `${r.action} ${r.target_ip}`, st === 'FAILED' ? 'error' : 'ok', 6000);
        emit('data:changed');
        closeLayer();
      } catch (err) { $('#rf-err', panel).textContent = err.message; }
    });
  };
  $('#rf-save', panel).onclick = go;
  form.onsubmit = go;
}

const svcText = (list) => (list || []).map((s) => `${s.port}/${s.service}`).join('\n');

export function openAssetForm(existing, onSaved) {
  const a = existing || {};
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">${existing ? `Edit ${esc(a.hostname)}` : 'Add host'}</h2></div>
    <form class="modal__body" id="asset-form" novalidate>
      <div class="form-grid">
        <label class="field"><span>IP address</span><input class="input input--mono" name="ip_address" required value="${esc(a.ip_address || '')}" ${existing ? 'readonly' : ''}></label>
        <label class="field"><span>Hostname</span><input class="input" name="hostname" required value="${esc(a.hostname || '')}"></label>
        <label class="field"><span>Operating system</span><input class="input" name="os_version" value="${esc(a.os_version || '')}" placeholder="Ubuntu 22.04 LTS"></label>
        <label class="field"><span>Owner</span><input class="input" name="owner" value="${esc(a.owner || '')}" placeholder="Team responsible"></label>
        <label class="field"><span>Criticality</span><select class="select" name="criticality">${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((c) => `<option ${(a.criticality || 'MEDIUM') === c ? 'selected' : ''}>${c}</option>`).join('')}</select></label>
        <label class="field"><span>Web application firewall</span><select class="select" name="waf_enabled"><option value="false">None in front</option><option value="true" ${a.waf_enabled ? 'selected' : ''}>Protected by a WAF</option></select></label>
        <label class="field span-2"><span>Listening services</span><textarea class="textarea" name="services" rows="3" placeholder="One per line: port/product version&#10;443/nginx 1.22.1&#10;22/OpenSSH 9.6p1">${esc(svcText(a.running_services))}</textarea></label>
        <label class="field span-2"><span>Installed packages</span><textarea class="textarea" name="installed_packages" rows="3" placeholder="One per line, with versions: log4j-core-2.17.1.jar">${esc((a.installed_packages || []).join('\n'))}</textarea>
          <small>Versions matter: exposure is computed from NVD CPE version ranges.</small></label>
      </div>
    </form>
    <div class="modal__foot"><span class="form-error" id="as-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="as-save">${existing ? 'Save changes' : 'Add host'}</button></div>`);
  const form = $('#asset-form', panel);
  const go = async (e) => {
    e.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    body.services = body.services.split(/\r?\n/).filter((x) => x.trim()).join(';');
    body.installed_packages = body.installed_packages.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
    body.os_family = /windows/i.test(body.os_version) ? 'Windows' : /mac ?os|darwin/i.test(body.os_version) ? 'macOS' : body.os_version ? 'Linux' : 'Unknown';
    await busy($('#as-save', panel), async () => {
      try {
        const saved = existing
          ? await api(`/assets/${encodeURIComponent(a.ip_address)}`, { method: 'PUT', body })
          : await api('/assets', { method: 'POST', body });
        toast(existing ? 'Host updated' : 'Host added', `${saved.hostname} (${saved.ip_address})`, 'ok');
        emit('data:changed');
        closeLayer();
        if (onSaved) onSaved(saved);
      } catch (err) { $('#as-err', panel).textContent = err.message; }
    });
  };
  $('#as-save', panel).onclick = go;
  form.onsubmit = go;
}

const CSV_HEAD = 'ip_address,hostname,os_version,owner,criticality,waf_enabled,services,installed_packages';

export function openAssetImport() {
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Import hosts</h2><p class="small muted" style="margin:4px 0 0">An Nmap XML scan, CSV with a header row, or a JSON array. Existing IPs are updated in place.</p></div>
    <div class="modal__body">
      <div class="row wrap" style="margin-bottom:10px">
        <label class="btn btn--sm">${icon('upload')}Choose file<input type="file" id="imp-file" accept=".xml,.csv,.json,text/xml,text/csv,application/json" hidden></label>
        <span class="small muted grow truncate" id="imp-name">or paste below</span>
      </div>
      <textarea class="textarea" id="imp-text" rows="9" spellcheck="false" placeholder="${CSV_HEAD}&#10;10.20.0.5,web-01,Ubuntu 22.04,Payments,HIGH,true,&quot;443/nginx 1.24.0; 22/OpenSSH 8.9p1&quot;,log4j-core-2.17.1.jar"></textarea>
      <p class="small muted mt-8">Columns: <code style="word-break:break-all">${CSV_HEAD}</code>. Separate multiple services or packages with <code>;</code>. CMDB or Lansweeper exports map to these columns.</p>
      <p class="small muted">Network scan: run <code>nmap -sV -O -oX scan.xml 10.0.0.0/24</code> and drop <code>scan.xml</code> here. Open ports, service versions and OS guesses are merged into existing hosts; owner and criticality you set by hand are kept.</p>
      <div id="imp-result"></div>
    </div>
    <div class="modal__foot"><span class="form-error" id="imp-err"></span><button class="btn btn--ghost" data-close>Close</button><button class="btn btn--primary" id="imp-go">${icon('upload')}Import</button></div>`);
  const ta = $('#imp-text', panel);
  $('#imp-file', panel).onchange = async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    if (f.size > 5 * 1024 * 1024) { $('#imp-err', panel).textContent = 'File is larger than 5 MB'; return; }
    ta.value = await f.text();
    $('#imp-name', panel).textContent = `${f.name} (${num(f.size)} bytes)`;
  };
  $('#imp-go', panel).onclick = (e) => busy(e.currentTarget, async () => {
    $('#imp-err', panel).textContent = '';
    const text = ta.value.trim();
    if (!text) { $('#imp-err', panel).textContent = 'Nothing to import'; return; }
    const type = text.startsWith('<') ? 'application/xml' : text.startsWith('[') || text.startsWith('{') ? 'application/json' : 'text/csv';
    try {
      const r = await api('/assets/import', { method: 'POST', raw: text, type });
      $('#imp-result', panel).innerHTML = `
        <div class="notice ${r.errors.length ? 'notice--warn' : ''} mt-12">${icon(r.errors.length ? 'alert' : 'check')}<div><b>${num(r.imported)} ${r.imported === 1 ? 'host' : 'hosts'} imported</b> <span class="muted">(${num(r.created || 0)} new, ${num(r.updated || 0)} updated${r.format === 'nmap' ? ' from Nmap' : ''})</span>${r.errors.length ? `, ${r.errors.length} rows skipped` : ''}
        ${r.errors.length ? `<ul class="small" style="margin:6px 0 0;padding-left:16px">${r.errors.slice(0, 8).map((x) => `<li>Row ${x.row}: ${esc(x.error)}</li>`).join('')}</ul>` : ''}</div></div>`;
      if (r.imported) emit('data:changed');
    } catch (err) { $('#imp-err', panel).textContent = err.message; }
  });
}

export function openAsset(a, navigate) {
  const respond = can('respond');
  const panel = drawer(`
    <div class="drawer__head">
      <div class="grow">
        <div class="eyebrow">${esc(a.ip_address)} &middot; ${esc(a.owner || 'no owner')} &middot; ${esc(a.source || 'manual')}</div>
        <h2 class="drawer__title">${esc(a.hostname)}</h2>
        <div class="row wrap mt-12">${sev(a.criticality)} <span class="tag">${esc(a.os_version)}</span> ${a.waf_enabled ? '<span class="tag tag--ok">WAF</span>' : '<span class="tag">No WAF</span>'}</div>
      </div>
      <button class="icon-btn icon-btn--bare" data-close aria-label="Close">${icon('x')}</button>
    </div>
    <div class="drawer__body">
      <section><h3 class="section-title">Listening services</h3>
        ${a.running_services.length ? `<div class="table-wrap"><table class="table"><tbody>${a.running_services.map((s) => `<tr><td class="mono" style="width:70px">${s.port}</td><td>${esc(s.service)}</td></tr>`).join('')}</tbody></table></div>` : '<p class="muted small" style="margin:0">None recorded.</p>'}
      </section>
      <section><h3 class="section-title">Installed packages</h3>${a.installed_packages.length ? `<div class="row wrap">${a.installed_packages.map((p) => `<span class="tag">${esc(p)}</span>`).join('')}</div>` : '<p class="muted small" style="margin:0">None recorded. Add versioned packages to get CVE matching.</p>'}</section>
      <section><h3 class="section-title row">Known exposure${respond ? `<span class="grow"></span><button class="btn btn--sm" id="a-disc" title="Look up every CVE NVD lists for the versions on this host">${icon('search')}Find CVEs in NVD</button>` : ''}</h3>
        <div id="a-disc-out"></div>
        ${a.exposures.length ? a.exposures.map((c) => `<div class="row wrap" style="padding:6px 0">${sev(c.severity)}<b class="mono">${esc(c.cve_id)}</b>${c.kev ? '<span class="tag tag--kev" title="CISA Known Exploited Vulnerabilities">KEV</span>' : ''}<span class="muted small">CVSS ${c.cvss_score}</span>${c.evidence ? `<span class="small muted grow truncate" title="${esc(c.evidence)}">matched ${esc(c.evidence)}</span>` : ''}</div>`).join('') : '<p class="muted small" style="margin:0">No match against the CVE records in Aegis.</p>'}
      </section>
      <section><h3 class="section-title">Recent telemetry</h3><div id="asset-logs"><div class="skeleton" style="height:80px"></div></div></section>
      <p class="small muted" style="margin:0">Last updated ${ago(a.last_scanned)}</p>
    </div>
    <div class="drawer__foot">
      <button class="btn" id="a-logs">${icon('terminal')}Telemetry</button>
      ${respond ? `<button class="btn" id="a-edit">${icon('edit')}Edit</button><button class="btn btn--danger" id="a-iso">${icon('lock')}Isolate</button><button class="btn btn--ghost btn--danger" id="a-del" style="margin-left:auto">${icon('trash')}Remove</button>` : ''}
    </div>`);
  api(`/logs?host_ip=${encodeURIComponent(a.ip_address)}&limit=6`).then((logs) => {
    $('#asset-logs', panel).innerHTML = logs.length
      ? `<pre class="code">${logs.map((l) => `${esc(l.log_type.padEnd(12))} ${markPayload(l.raw_entry)}`).join('\n')}</pre>`
      : '<p class="muted small" style="margin:0">No telemetry received for this host.</p>';
  }).catch(() => {});
  $('#a-logs', panel).onclick = () => { closeLayer(); navigate(`telemetry?host=${a.ip_address}`); };
  if (!respond) return;
  $('#a-edit', panel).onclick = () => openAssetForm(a);
  $('#a-disc', panel).onclick = (e) => busy(e.currentTarget, async () => {
    const out = $('#a-disc-out', panel);
    out.innerHTML = '<p class="small muted" style="margin:0 0 8px">Asking NVD about each versioned product. Without an NVD API key this takes about 7 seconds per product.</p>';
    try {
      const r = await api(`/assets/${encodeURIComponent(a.ip_address)}/discover`, { method: 'POST', body: {} });
      out.innerHTML = `<div class="notice ${r.matched ? 'notice--warn' : ''}" style="margin-bottom:8px">${icon(r.matched ? 'alert' : 'check')}<div><b>${r.imported} CVE${r.imported === 1 ? '' : 's'} imported</b>, ${r.matched} matched to this host${r.kev ? `, ${r.kev} on the CISA KEV list` : ''}.
        <div class="small muted mt-8">${r.products.map((p) => `${esc(p.product)} ${esc(p.version)}: ${p.error ? esc(p.error) : `${p.total} in NVD, ${p.kept} kept (CVSS 7+ or KEV)`}`).join('<br>')}${r.skipped ? `<br>${r.skipped} more products not checked; set NVD_API_KEY for a higher quota.` : ''}</div>
        <div class="small muted mt-8">Distribution packages often carry backported fixes, so confirm against the vendor advisory before patching.</div></div></div>`;
      hydrateIcons(out);
      emit('data:changed');
    } catch (err) { out.innerHTML = `<div class="notice notice--warn" style="margin-bottom:8px">${icon('alert')}<div>${esc(err.message)}</div></div>`; hydrateIcons(out); }
  });
  $('#a-iso', panel).onclick = () => openNewRule({ target_ip: a.ip_address, action: 'ISOLATE', reason: `Manual isolation of ${a.hostname}` });
  let armed = false;
  $('#a-del', panel).onclick = (e) => {
    const b = e.currentTarget;
    if (!armed) { armed = true; b.textContent = 'Click again to remove'; setTimeout(() => { armed = false; b.innerHTML = `${icon('trash')}Remove`; }, 3000); return; }
    busy(b, async () => {
      try {
        await api(`/assets/${encodeURIComponent(a.ip_address)}`, { method: 'DELETE' });
        toast('Host removed', `${a.hostname} (${a.ip_address})`, 'ok');
        emit('data:changed');
        closeLayer();
      } catch (err) { toast('Could not remove host', err.message, 'error'); }
    });
  };
}

export { num, label };
// Adds alerts to an open case, or opens a new case around them.
export async function openAddToCase(alertIds, prefill = {}, onDone) {
  const ids = [...new Set(alertIds)].filter(Boolean);
  if (!ids.length) return;
  const panel = modal(`
    <div class="modal__head"><h2 class="modal__title">Add ${ids.length === 1 ? esc(ids[0]) : `${ids.length} alerts`} to a case</h2></div>
    <div class="modal__body">
      <div class="seg" id="atc-mode"><button data-m="existing" class="is-on">Existing case</button><button data-m="new">New case</button></div>
      <div id="atc-existing" class="mt-12"><div class="skeleton" style="height:36px"></div></div>
      <form id="atc-new" class="form-grid mt-12" hidden novalidate>
        <label class="field span-2"><span>Title</span><input class="input" name="title" maxlength="200" value="${esc(prefill.title || '')}" placeholder="What is going on, in one line"></label>
        <label class="field"><span>Severity</span><select class="select" name="severity">${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => `<option ${s === (prefill.severity || 'MEDIUM') ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
        <label class="field"><span>Tags</span><input class="input" name="tags" placeholder="comma separated"></label>
        <label class="field span-2"><span>Description</span><textarea class="textarea" name="description" rows="3" maxlength="8000" placeholder="Scope, what you know so far"></textarea></label>
      </form>
    </div>
    <div class="modal__foot"><span class="form-error" id="atc-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="atc-go">${icon('file')}Add to case</button></div>`);
  let mode = 'existing';
  let cases = [];
  const box = $('#atc-existing', panel);
  try {
    cases = await api('/cases?status=OPEN,IN_PROGRESS,CONTAINED&limit=200');
  } catch (e) { box.innerHTML = `<div class="small muted">${esc(e.message)}</div>`; }
  if (!panel.isConnected) return;
  const setMode = (m) => {
    mode = m;
    $$('#atc-mode button', panel).forEach((b) => b.classList.toggle('is-on', b.dataset.m === m));
    box.hidden = m !== 'existing';
    $('#atc-new', panel).hidden = m !== 'new';
    $('#atc-go', panel).lastChild.textContent = m === 'new' ? 'Open case' : 'Add to case';
  };
  $$('#atc-mode button', panel).forEach((b) => { b.onclick = () => setMode(b.dataset.m); });
  if (cases.length) {
    box.innerHTML = `<label class="field"><span>Case</span><select class="select" id="atc-case">${cases.map((c) => `<option value="${esc(c.case_id)}">${esc(c.case_id)} - ${esc(c.title)} (${c.alerts} alert${c.alerts === 1 ? '' : 's'})</option>`).join('')}</select></label>`;
  } else {
    box.innerHTML = '<div class="small muted">No open cases. Start a new one.</div>';
    setMode('new');
  }
  const go = async (e) => {
    e.preventDefault();
    $('#atc-err', panel).textContent = '';
    await busy($('#atc-go', panel), async () => {
      try {
        let caseId;
        if (mode === 'existing') {
          caseId = $('#atc-case', panel)?.value;
          if (!caseId) throw new Error('Pick a case');
          const r = await api(`/cases/${encodeURIComponent(caseId)}/alerts`, { method: 'POST', body: { alert_ids: ids } });
          toast(r.added ? `Added to ${caseId}` : 'Already in that case', r.skipped ? `${r.skipped} already linked` : '', r.added ? 'ok' : 'info');
        } else {
          const f = Object.fromEntries(new FormData($('#atc-new', panel)));
          const c = await api('/cases', { method: 'POST', body: { ...f, tags: f.tags ? f.tags.split(',').map((s) => s.trim()).filter(Boolean) : [], alert_ids: ids } });
          caseId = c.case_id;
          toast(`Opened ${c.case_id}`, c.title, 'ok');
        }
        closeLayer();
        emit('data:changed');
        if (onDone) onDone(caseId); else location.hash = `#/cases/${encodeURIComponent(caseId)}`;
      } catch (err) { $('#atc-err', panel).textContent = err.message; }
    });
  };
  $('#atc-go', panel).onclick = go;
  $('#atc-new', panel).onsubmit = go;
}