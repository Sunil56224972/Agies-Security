import { $, $$, api, esc, sev, pill, ago, stamp, markPayload, drawer, modal, closeLayer, toast, busy, emit, num, label, state, can } from './core.js';
import { icon } from './icons.js';

// Overlays reused by several views.

const MODE_COPY = {
  feed: 'The rule is published on the pull feed and counts as enforced once your firewall fetches it.',
  webhook: 'The rule is POSTed to your enforcement webhook and counts as enforced when the receiver acknowledges it.',
  cloudflare: 'Blocks become Cloudflare IP Access Rules and are read back from the Cloudflare API. Isolation is recorded only.',
  record: 'Enforcement is set to record only: the rule is stored in Aegis and nothing outside changes.'
};
export const enforcementCopy = () => MODE_COPY[state.health?.enforcement?.mode] || '';

export async function openAlert(alertId, navigate) {
  const panel = drawer(`<div class="drawer__head"><div class="grow"><div class="eyebrow">${esc(alertId)}</div><div class="skeleton" style="height:28px;margin-top:8px;width:80%"></div></div><button class="icon-btn icon-btn--bare" data-close aria-label="Close">${icon('x')}</button></div><div class="drawer__body"><div class="skeleton" style="height:120px"></div><div class="skeleton" style="height:160px"></div></div>`);
  let data;
  try { data = await api(`/alerts/${encodeURIComponent(alertId)}`); } catch (e) { toast('Could not load alert', e.message, 'error'); closeLayer(); return; }
  const { alert: a, asset, investigations } = data;
  const last = investigations[0];
  const respond = can('respond');
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
      <section>
        <h3 class="section-title">Flow</h3>
        <dl class="dl">
          <dt>Source</dt><dd class="ip">${esc(a.source_ip)}</dd>
          <dt>Destination</dt><dd class="ip">${esc(a.dest_ip)}:${esc(a.dest_port)} <span class="muted">${esc(a.protocol)}</span></dd>
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
    </div>
    <div class="drawer__foot">
      <button class="btn btn--primary" id="d-investigate" ${a.status === 'INVESTIGATING' || !respond ? 'disabled' : ''}>${icon('play')}${last ? 'Re-investigate' : 'Investigate'}</button>
      ${respond && ['NEW', 'CONFIRMED'].includes(a.status) ? '<button class="btn" id="d-fp">Mark false positive</button>' : ''}
      ${respond && a.status !== 'CLOSED' && a.status !== 'NEW' ? '<button class="btn btn--ghost" id="d-close">Close alert</button>' : ''}
      ${respond && (a.status === 'CLOSED' || a.status === 'FALSE_POSITIVE') ? '<button class="btn btn--ghost" id="d-reopen">Reopen</button>' : ''}
      ${!respond ? '<span class="small muted">Read-only role</span>' : ''}
    </div>`;
  $('#copy-payload', panel).onclick = async () => {
    try { await navigator.clipboard.writeText(a.raw_payload); toast('Payload copied'); } catch { toast('Clipboard unavailable', '', 'error'); }
  };
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
        <label class="field span-2"><span>Reason</span><input class="input" name="reason" required value="${esc(prefill.reason || '')}" placeholder="Why this rule exists (shown to the next shift)"></label>
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
    <div class="modal__head"><h2 class="modal__title">Import hosts</h2><p class="small muted" style="margin:4px 0 0">CSV with a header row, or a JSON array. Existing IPs are updated in place.</p></div>
    <div class="modal__body">
      <div class="row wrap" style="margin-bottom:10px">
        <label class="btn btn--sm">${icon('upload')}Choose file<input type="file" id="imp-file" accept=".csv,.json,text/csv,application/json" hidden></label>
        <span class="small muted grow truncate" id="imp-name">or paste below</span>
      </div>
      <textarea class="textarea" id="imp-text" rows="9" spellcheck="false" placeholder="${CSV_HEAD}&#10;10.20.0.5,web-01,Ubuntu 22.04,Payments,HIGH,true,&quot;443/nginx 1.24.0; 22/OpenSSH 8.9p1&quot;,log4j-core-2.17.1.jar"></textarea>
      <p class="small muted mt-8">Columns: <code>${CSV_HEAD}</code>. Separate multiple services or packages with <code>;</code>. Exports from Nmap, Lansweeper or a CMDB can be mapped to these columns.</p>
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
    const json = text.startsWith('[') || text.startsWith('{');
    try {
      const r = await api('/assets/import', { method: 'POST', raw: text, type: json ? 'application/json' : 'text/csv' });
      $('#imp-result', panel).innerHTML = `
        <div class="notice ${r.errors.length ? 'notice--warn' : ''} mt-12">${icon(r.errors.length ? 'alert' : 'check')}<div><b>${num(r.imported)} hosts imported</b>${r.errors.length ? `, ${r.errors.length} rows skipped` : ''}
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
      <section><h3 class="section-title">Known exposure</h3>
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