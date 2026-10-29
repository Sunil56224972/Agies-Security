'use strict';

const crypto = require('crypto');
const { isIP, isInternal, newId, SEVERITY_RANK } = require('./engine/analysis');
const { classify, extractAll } = require('./intel/indicator');
const { normalizeCriteria, techniqueRollup, findingKey, techId, alertTechnique } = require('./engine/hunt');
const { ROUTE_TEXT, routeFor } = require('./engine/approvals');
const { TACTICS, tacticOf } = require('./casework');

// Incident cases, the approval queue and saved hunts. Every operation lives in
// a service function so the HTTP routes and the MCP server share validation,
// audit entries and case timelines.

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const CASE_STATUS = ['OPEN', 'IN_PROGRESS', 'CONTAINED', 'CLOSED'];
const TASK_STATUS = ['TODO', 'DOING', 'DONE', 'SKIPPED'];
const EVENT_KINDS = ['comment', 'evidence', 'timeline'];

const fail = (msg, status = 400) => Object.assign(new Error(msg), { status });
const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
const list = (v, max = 30, len = 60) => [...new Set((Array.isArray(v) ? v : String(v || '').split(',')).map((x) => str(x, len)).filter(Boolean))].slice(0, max);
const hoursBetween = (a, b) => (new Date(b) - new Date(a)) / 3600000;
const round1 = (n) => (n == null ? null : Math.round(n * 10) / 10);
const median = (v) => { if (!v.length) return null; const s = [...v].sort((a, b) => a - b); return s[Math.floor((s.length - 1) / 2)]; };
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

// Response checklist seeded on kill-chain cases, by NIST 800-61 phase.
function playbookTasks({ ip, hosts, compromised, techniques }) {
  const t = [
    ['Identification', `Confirm the scope: every host ${ip} reached (${hosts.length} so far)`],
    ['Identification', `Pull ${ip} reputation and WHOIS; attach the verdict to the case`],
    ['Containment', `Block ${ip} at the perimeter and verify the rule is enforced`]
  ];
  for (const h of compromised) t.push(['Containment', `Isolate ${h}; the attack against it succeeded`]);
  if (techniques.some((x) => /^T1110/.test(x))) t.push(['Eradication', 'Reset credentials for every account targeted by the brute force']);
  if (techniques.some((x) => /^(T1190|T1059|T1505)/.test(x))) t.push(['Eradication', 'Patch the exploited service and look for web shells or new processes']);
  if (compromised.length) t.push(['Eradication', 'Image the compromised hosts before cleanup']);
  t.push(['Recovery', 'Restore service and watch the affected hosts for 72 hours']);
  t.push(['Lessons learned', 'Write up the root cause and tune the detections that fired']);
  return t;
}

function createCaseService(ctx) {
  const { store, hub, investigator, approvals, hunter } = ctx;
  const audit = (who, action, target, detail) => store.audit.add({ actor: who.name, action, target, detail: detail ? String(detail).slice(0, 300) : null });
  const log = (caseId, who, body) => store.caseEvents.add({ case_id: caseId, kind: 'event', author: who.name, author_id: who.id || null, body: String(body).slice(0, 20000) });

  async function mustCase(id) {
    const c = await store.cases.get(id);
    if (!c) throw fail('Case not found', 404);
    return c;
  }
  async function writable(id) {
    const c = await mustCase(id);
    if (c.status === 'CLOSED') throw fail('The case is closed; reopen it first', 409);
    return c;
  }
  async function assignee(userId) {
    if (userId === null || userId === undefined || userId === '') return null;
    const u = await store.users.byId(Number(userId));
    if (!u || u.disabled) throw fail('That user does not exist or is disabled');
    if (u.role === 'viewer') throw fail('Read-only users cannot own a case');
    return u;
  }
  // ATT&CK techniques named by the linked alerts and their investigations.
  async function deriveMitre(alertIds) {
    const out = new Set();
    for (const id of alertIds.slice(0, 200)) {
      const a = await store.alerts.get(id);
      if (!a) continue;
      const t = alertTechnique(a);
      if (t) out.add(t);
      const invs = await store.investigations.forAlert(id).catch(() => null);
      for (const i of [].concat(invs || [])) { const x = techId(i && i.mitre_technique); if (x) out.add(x); }
    }
    return [...out];
  }
  async function attach(id, title, ids, who) {
    const added = await store.caseAlerts.add(id, ids, who.name);
    if (!added.length) return added;
    await log(id, who, `Linked ${plural(added.length, 'alert')}: ${added.map((l) => l.alert_id).slice(0, 12).join(', ')}${added.length > 12 ? ' ...' : ''}`);
    const c = await store.cases.get(id);
    const mitre = [...new Set([...(c.mitre || []), ...(await deriveMitre(added.map((l) => l.alert_id)))])];
    if (mitre.length !== (c.mitre || []).length) await store.cases.update(id, { mitre });
    for (const l of added) await store.notes.add({ alert_id: l.alert_id, kind: 'event', author: who.name, body: `Added to case ${id}: ${title}` }).catch(() => {});
    return added;
  }

  // ---- Cases ------------------------------------------------------------------
  async function listCases({ status, q, limit = 200 } = {}) {
    const st = status ? [].concat(status).map((s) => String(s).toUpperCase()).filter((s) => CASE_STATUS.includes(s)) : [];
    const [cases, links, tasks, iocs] = await Promise.all([
      store.cases.list({ status: st.length ? st : undefined, q, limit }), store.caseAlerts.all(), store.caseTasks.all(), store.caseIocs.all({ limit: 20000 })
    ]);
    const tally = (rows, f = () => true) => rows.reduce((m, r) => (f(r) ? m.set(r.case_id, (m.get(r.case_id) || 0) + 1) : m), new Map());
    const nAlerts = tally(links); const nIocs = tally(iocs); const nBad = tally(iocs, (r) => r.verdict === 'malicious');
    const nTasks = tally(tasks); const nOpen = tally(tasks, (r) => r.status === 'TODO' || r.status === 'DOING');
    return cases.map((c) => ({
      ...c, alerts: nAlerts.get(c.case_id) || 0, iocs: nIocs.get(c.case_id) || 0, malicious_iocs: nBad.get(c.case_id) || 0,
      tasks: nTasks.get(c.case_id) || 0, tasks_open: nOpen.get(c.case_id) || 0
    }));
  }

  async function createCase(b, who) {
    const title = str(b.title, 200);
    if (title.length < 4) throw fail('Give the case a title of at least 4 characters');
    const severity = String(b.severity || 'MEDIUM').toUpperCase();
    if (!SEVERITIES.includes(severity)) throw fail(`Severity must be one of ${SEVERITIES.join(', ')}`);
    const owner = await assignee(b.assignee_id);
    const ids = list(b.alert_ids, 500, 80);
    const c = await store.cases.insert({
      case_id: newId('CASE'), title, description: str(b.description, 8000), severity,
      assignee_id: owner ? owner.id : null, assignee_name: owner ? owner.name : null,
      tags: list(b.tags, 20, 40), mitre: list(b.mitre, 30, 20).map((x) => techId(x)).filter(Boolean), source: str(b.source || 'manual', 40), created_by: who.name
    });
    await log(c.case_id, who, `Case opened by ${who.name}${owner ? `, owned by ${owner.name}` : ''}`);
    const linked = ids.length ? await attach(c.case_id, title, ids, who) : [];
    await audit(who, 'case.created', c.case_id, `${severity} ${title}${linked.length ? ` (${plural(linked.length, 'alert')})` : ''}`);
    return { ...(await store.cases.get(c.case_id)), linked: linked.length, skipped: ids.length - linked.length };
  }
  async function getCase(id) {
    const c = await mustCase(id);
    const [links, tasks, iocs, events, allCases, allLinks, allApprovals, rules] = await Promise.all([
      store.caseAlerts.list(id), store.caseTasks.list(id), store.caseIocs.list(id), store.caseEvents.list(id),
      store.cases.list({ limit: 2000 }), store.caseAlerts.all(), store.approvals.list({ limit: 1000 }), store.rules.list()
    ]);
    const alerts = (await Promise.all(links.map((l) => store.alerts.get(l.alert_id)))).filter(Boolean)
      .map(({ raw_payload, ...a }) => ({ ...a, added_by: (links.find((l) => l.alert_id === a.alert_id) || {}).added_by }));
    const alertIds = new Set(alerts.map((a) => a.alert_id));
    const ips = new Set([...alerts.flatMap((a) => [a.source_ip, a.dest_ip]), ...iocs.filter((i) => i.type === 'ipv4' || i.type === 'ipv6').map((i) => i.value)]);
    // Related: other cases sharing an alert or an IOC value, plus explicit links.
    const iocVals = new Set(iocs.map((i) => i.value));
    const otherIocs = iocVals.size ? (await store.caseIocs.all({ limit: 20000 })).filter((i) => i.case_id !== id && iocVals.has(i.value)) : [];
    const related = new Map();
    for (const r of c.related || []) related.set(r, 'linked by an analyst');
    for (const l of allLinks) if (l.case_id !== id && alertIds.has(l.alert_id) && !related.has(l.case_id)) related.set(l.case_id, `shares alert ${l.alert_id}`);
    for (const i of otherIocs) if (!related.has(i.case_id)) related.set(i.case_id, `shares indicator ${i.value}`);
    return {
      case: c, alerts, tasks, iocs, events,
      approvals: allApprovals.filter((a) => a.case_id === id || (a.alert_id && alertIds.has(a.alert_id))).map((a) => ({ ...a, route_text: ROUTE_TEXT[a.route] || a.route })),
      rules: rules.filter((r) => ips.has(r.target_ip)),
      related: [...related].map(([cid, why]) => { const o = allCases.find((x) => x.case_id === cid); return o ? { case_id: cid, title: o.title, status: o.status, severity: o.severity, why } : null; }).filter(Boolean)
    };
  }

  async function updateCase(id, b, who) {
    const c = await mustCase(id);
    const patch = {}; const changes = [];
    if (b.title !== undefined) { const t = str(b.title, 200); if (t.length < 4) throw fail('Title must be at least 4 characters'); if (t !== c.title) { patch.title = t; changes.push('title'); } }
    if (b.description !== undefined && str(b.description, 8000) !== c.description) { patch.description = str(b.description, 8000); changes.push('description'); }
    if (b.severity !== undefined) {
      const s = String(b.severity).toUpperCase();
      if (!SEVERITIES.includes(s)) throw fail(`Severity must be one of ${SEVERITIES.join(', ')}`);
      if (s !== c.severity) { patch.severity = s; changes.push(`severity ${c.severity} -> ${s}`); }
    }
    if (b.status !== undefined) {
      const s = String(b.status).toUpperCase();
      if (!CASE_STATUS.includes(s)) throw fail(`Status must be one of ${CASE_STATUS.join(', ')}`);
      if (s === 'CLOSED' && c.status !== 'CLOSED') throw fail('Close a case with a resolution (POST /api/cases/:id/close)');
      if (s !== c.status) { patch.status = s; changes.push(`status ${c.status} -> ${s}`); if (c.status === 'CLOSED') patch.closed_at = null; }
    }
    if (b.assignee_id !== undefined) {
      const u = await assignee(b.assignee_id);
      if ((u ? u.id : null) !== (c.assignee_id || null)) { patch.assignee_id = u ? u.id : null; patch.assignee_name = u ? u.name : null; changes.push(u ? `owner ${u.name}` : 'unassigned'); }
    }
    if (b.tags !== undefined) { patch.tags = list(b.tags, 20, 40); changes.push('tags'); }
    if (b.mitre !== undefined) {
      const m = list(b.mitre, 30, 20).map((x) => techId(x));
      if (m.some((x) => !x)) throw fail('MITRE entries must be ATT&CK ids such as T1190');
      patch.mitre = [...new Set(m)]; changes.push('MITRE');
    }
    if (b.related !== undefined) {
      const r = list(b.related, 20, 40).filter((x) => x !== id);
      for (const x of r) if (!(await store.cases.get(x))) throw fail(`Case ${x} does not exist`);
      patch.related = r; changes.push('related cases');
    }
    if (!changes.length) return c;
    const next = await store.cases.update(id, patch);
    await log(id, who, `${who.name} changed ${changes.join(', ')}`);
    await audit(who, 'case.updated', id, changes.join(', '));
    return next;
  }

  async function closeCase(id, b, who) {
    const c = await writable(id);
    const resolution = str(b.resolution, 4000);
    if (resolution.length < 10) throw fail('Write a resolution of at least 10 characters');
    const open = (await store.caseTasks.list(id)).filter((t) => t.status === 'TODO' || t.status === 'DOING');
    if (open.length && !b.force) throw fail(`${plural(open.length, 'task')} still open; finish or skip them first`, 409);
    const next = await store.cases.update(id, { status: 'CLOSED', resolution, closed_at: new Date().toISOString() });
    await log(id, who, `Closed by ${who.name}: ${resolution}`);
    await audit(who, 'case.closed', id, `${hoursBetween(c.created_at, next.closed_at).toFixed(1)}h after opening`);
    return next;
  }

  async function reopenCase(id, who) {
    const c = await mustCase(id);
    if (c.status !== 'CLOSED') throw fail('The case is not closed', 409);
    const next = await store.cases.update(id, { status: 'IN_PROGRESS', closed_at: null });
    await log(id, who, `Reopened by ${who.name}`);
    await audit(who, 'case.reopened', id, null);
    return next;
  }

  async function escalateCase(id, b, who) {
    const c = await writable(id);
    if (c.escalated) throw fail('The case is already escalated', 409);
    const reason = str(b.reason, 1000);
    if (reason.length < 4) throw fail('Say why the case is escalated');
    const bump = { LOW: 'MEDIUM', MEDIUM: 'HIGH', HIGH: 'CRITICAL', CRITICAL: 'CRITICAL' }[c.severity];
    const owner = b.assignee_id !== undefined && b.assignee_id !== '' ? await assignee(b.assignee_id) : null;
    const next = await store.cases.update(id, {
      escalated: true, escalated_at: new Date().toISOString(), severity: bump, status: c.status === 'OPEN' ? 'IN_PROGRESS' : c.status,
      ...(owner ? { assignee_id: owner.id, assignee_name: owner.name } : {})
    });
    await log(id, who, `Escalated by ${who.name}${bump !== c.severity ? ` (${c.severity} -> ${bump})` : ''}${owner ? ` to ${owner.name}` : ''}: ${reason}`);
    await audit(who, 'case.escalated', id, reason);
    return next;
  }

  async function linkAlerts(id, ids, who) {
    const c = await writable(id);
    const want = list(ids, 500, 80);
    if (!want.length) throw fail('Give at least one alert id');
    const added = await attach(id, c.title, want, who);
    if (added.length) await audit(who, 'case.alerts', id, `+${added.length}`);
    return { added: added.length, skipped: want.length - added.length };
  }

  async function unlinkAlert(id, alertId, who) {
    await writable(id);
    if (!(await store.caseAlerts.remove(id, alertId))) throw fail('That alert is not in the case', 404);
    await log(id, who, `Removed alert ${alertId}`);
    return { removed: alertId };
  }

  async function addTask(id, b, who) {
    await writable(id);
    const title = str(b.title, 240);
    if (title.length < 2) throw fail('Describe the task');
    let due = null;
    if (b.due_at) { const d = new Date(b.due_at); if (Number.isNaN(d.getTime())) throw fail('due_at is not a date'); due = d.toISOString(); }
    const t = await store.caseTasks.insert({ case_id: id, title, phase: str(b.phase, 40) || null, assignee_name: str(b.assignee_name, 80) || null, due_at: due, created_by: who.name });
    await log(id, who, `Task added: ${title}`);
    return t;
  }

  async function updateTask(id, taskId, b, who) {
    const c = await writable(id);
    const t = (await store.caseTasks.list(id)).find((x) => String(x.id) === String(taskId));
    if (!t) throw fail('Task not found', 404);
    const patch = {};
    if (b.status !== undefined) {
      const s = String(b.status).toUpperCase();
      if (!TASK_STATUS.includes(s)) throw fail(`Status must be one of ${TASK_STATUS.join(', ')}`);
      patch.status = s; patch.done_at = s === 'DONE' ? new Date().toISOString() : null;
    }
    if (b.title !== undefined) { const v = str(b.title, 240); if (v.length < 2) throw fail('Describe the task'); patch.title = v; }
    if (b.assignee_name !== undefined) patch.assignee_name = str(b.assignee_name, 80) || null;
    const next = await store.caseTasks.update(t.id, patch);
    if (patch.status && patch.status !== t.status) await log(id, who, `Task "${t.title}" ${patch.status === 'DONE' ? 'completed' : `moved to ${patch.status}`}`);
    // The first task picked up moves the case out of OPEN.
    if (c.status === 'OPEN' && (patch.status === 'DOING' || patch.status === 'DONE')) await store.cases.update(id, { status: 'IN_PROGRESS' });
    return next;
  }
  async function addIocs(id, b, who) {
    await writable(id);
    const text = Array.isArray(b.values) ? b.values.join('\n') : String(b.values || b.value || '');
    const found = extractAll(text, { max: 200 });
    const one = !found.length && text.trim() ? classify(text.trim()) : null;
    const inds = found.length ? found : one ? [one] : [];
    if (!inds.length) throw fail('No IPs, domains, URLs, hashes or ASNs found');
    const note = str(b.note, 500) || null;
    const added = [];
    for (const i of inds) {
      const r = await store.caseIocs.insert({ case_id: id, type: i.type, value: i.value, note, created_by: who.name });
      if (r) added.push(r);
    }
    if (hub && hub.available && added.length <= 25) {
      await Promise.all(added.map(async (ioc) => {
        try {
          const r = await hub.lookup(ioc.value, { budgetMs: 8000 });
          if (r && !r.skipped) {
            const u = await store.caseIocs.update(ioc.id, { verdict: r.verdict, score: r.score, summary: r.summary || r.reason || null, checked_at: r.checked_at });
            if (u) Object.assign(ioc, u);
          }
        } catch { /* analyst can re-check manually */ }
      }));
    }
    if (added.length) await log(id, who, `Added ${plural(added.length, 'indicator')}: ${added.map((x) => x.value).slice(0, 8).join(', ')}`);
    return { added, duplicates: inds.length - added.length };
  }

  async function checkIoc(id, iocId, who) {
    await mustCase(id);
    const ioc = (await store.caseIocs.list(id)).find((x) => String(x.id) === String(iocId));
    if (!ioc) throw fail('Indicator not found', 404);
    if (!hub) throw fail('Threat intel is not available on this server', 503);
    const r = await hub.lookup(ioc.value, { budgetMs: 12000 });
    const next = await store.caseIocs.update(ioc.id, { verdict: r.verdict, score: r.score, summary: r.summary || r.reason || null, checked_at: r.checked_at });
    await log(id, who, `${ioc.value} checked: ${r.verdict}${r.score != null ? ` (${r.score}/100)` : ''}, ${plural((r.sources_ok || []).length, 'source')} answered`);
    return { ioc: next, lookup: { verdict: r.verdict, score: r.score, summary: r.summary || r.reason || null, sources_ok: r.sources_ok, sources_failed: r.sources_failed } };
  }

  async function removeIoc(id, iocId, who) {
    await writable(id);
    const ioc = (await store.caseIocs.list(id)).find((x) => String(x.id) === String(iocId));
    if (!ioc) throw fail('Indicator not found', 404);
    await store.caseIocs.remove(ioc.id);
    await log(id, who, `Removed indicator ${ioc.value}`);
    return { removed: ioc.value };
  }

  async function addEvent(id, b, who) {
    await mustCase(id);
    const kind = String(b.kind || 'comment').toLowerCase();
    if (!EVENT_KINDS.includes(kind)) throw fail(`kind must be one of ${EVENT_KINDS.join(', ')}`);
    const body = String(b.body || '').trim();
    if (!body) throw fail('Write something first');
    if (body.length > 20000) throw fail('At most 20000 characters');
    let occurred = new Date().toISOString();
    if (kind === 'timeline') {
      if (!b.occurred_at) throw fail('Timeline entries need occurred_at: when it happened');
      const d = new Date(b.occurred_at);
      if (Number.isNaN(d.getTime())) throw fail('occurred_at is not a date');
      if (d.getTime() > Date.now() + 300000) throw fail('occurred_at is in the future');
      occurred = d.toISOString();
    }
    // Evidence is hashed on arrival so later tampering is detectable.
    const sha256 = kind === 'evidence' ? crypto.createHash('sha256').update(body).digest('hex') : null;
    const ev = await store.caseEvents.add({ case_id: id, kind, author: who.name, author_id: who.id || null, title: str(b.title, 200) || null, body, sha256, occurred_at: occurred });
    await store.cases.update(id, {});
    if (kind !== 'comment') await audit(who, `case.${kind}`, id, b.title || body.slice(0, 80));
    return ev;
  }

  // Every alert from one attacker address in a window becomes one case: scope,
  // ATT&CK techniques, timeline and a response checklist.
  async function fromKillchain(b, who) {
    const ip = str(b.ip, 64);
    if (!isIP(ip)) throw fail('Give the attacker IP address');
    const hours = b.hours === undefined || b.hours === '' ? 72 : Number(b.hours);
    if (!Number.isFinite(hours) || hours < 1 || hours > 2160) throw fail('hours must be 1-2160');
    const since = new Date(Date.now() - hours * 3600000).toISOString();
    const alerts = await store.alerts.list({ ip, since, limit: 2000 });
    if (!alerts.length) throw fail(`No alerts involving ${ip} in the last ${hours} hours`, 404);
    const invs = (await store.investigations.forIp(ip, { limit: 200 })).filter((i) => i.created_at >= since);
    const hosts = [...new Set(alerts.map((a) => (a.source_ip === ip ? a.dest_ip : a.source_ip)))];
    const compromised = [...new Set(invs.filter((i) => i.outcome === 'ATTACK_SUCCEEDED').map((i) => i.target_ip))];
    const techniques = [...new Set([...alerts.map(alertTechnique), ...invs.map((i) => techId(i.mitre_technique))].filter(Boolean))];
    const tactics = [...new Set(invs.map((i) => tacticOf(i.mitre_tactic)).filter((t) => t && t !== 'Other'))].sort((x, y) => TACTICS.indexOf(x) - TACTICS.indexOf(y));
    const top = alerts.reduce((m, a) => ((SEVERITY_RANK[a.severity] || 0) > (SEVERITY_RANK[m] || 0) ? a.severity : m), 'LOW');
    const times = alerts.map((a) => a.detected_at).sort();
    const sigs = [...new Set(alerts.map((a) => a.signature))];
    const description = [
      `Activity involving ${ip} between ${times[0]} and ${times[times.length - 1]}: ${plural(alerts.length, 'alert')} across ${plural(hosts.length, 'host')}.`,
      tactics.length ? `Kill chain: ${tactics.join(' -> ')}.` : null,
      compromised.length ? `Confirmed compromise on ${compromised.join(', ')}.` : invs.length ? `${plural(invs.length, 'investigation')}, no confirmed compromise.` : 'Not investigated yet.',
      `Signatures: ${sigs.slice(0, 6).join('; ')}${sigs.length > 6 ? ` and ${sigs.length - 6} more` : ''}.`
    ].filter(Boolean).join('\n');
    const c = await createCase({
      title: str(b.title, 200) || `${compromised.length ? 'Compromise' : 'Activity'} from ${ip} against ${plural(hosts.length, 'host')}`,
      description, severity: compromised.length ? 'CRITICAL' : top, mitre: techniques, source: 'kill-chain',
      tags: ['kill-chain', ...tactics.slice(0, 4).map((t) => t.toLowerCase().replace(/\s+/g, '-'))], alert_ids: alerts.map((a) => a.alert_id)
    }, who);
    const ind = classify(ip);
    await store.caseIocs.insert({ case_id: c.case_id, type: ind ? ind.type : 'ipv4', value: ip, note: 'Attacker address', created_by: who.name });
    for (const [phase, title] of playbookTasks({ ip, hosts, compromised, techniques })) await store.caseTasks.insert({ case_id: c.case_id, title, phase, created_by: 'playbook' });
    for (const a of [...alerts].reverse().slice(0, 40)) await store.caseEvents.add({ case_id: c.case_id, kind: 'timeline', author: 'kill-chain', title: a.severity, body: `${a.signature} (${a.source_ip} -> ${a.dest_ip}:${a.dest_port}) ${a.alert_id}`, occurred_at: a.detected_at });
    return { ...c, hosts, compromised, tactics, techniques };
  }

  async function caseMetrics() {
    const [cases, tasks] = await Promise.all([store.cases.list({ limit: 5000 }), store.caseTasks.all()]);
    const open = cases.filter((c) => c.status !== 'CLOSED');
    const closed = cases.filter((c) => c.status === 'CLOSED' && c.closed_at);
    const ttc = closed.map((c) => hoursBetween(c.created_at, c.closed_at));
    const done = tasks.filter((t) => t.status === 'DONE' || t.status === 'SKIPPED').length;
    return {
      total: cases.length, open: open.length, escalated: open.filter((c) => c.escalated).length, unassigned: open.filter((c) => !c.assignee_id).length,
      by_severity: Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((c) => c.severity === s).length])),
      by_status: Object.fromEntries(CASE_STATUS.map((s) => [s, cases.filter((c) => c.status === s).length])),
      closed: closed.length, mttr_hours: ttc.length ? round1(ttc.reduce((x, y) => x + y, 0) / ttc.length) : null, median_hours: round1(median(ttc)),
      tasks: { total: tasks.length, done, rate: tasks.length ? Math.round((done / tasks.length) * 100) : null }
    };
  }

  async function casesForAlert(alertId) {
    const links = await store.caseAlerts.forAlert(alertId);
    return (await Promise.all(links.map((l) => store.cases.get(l.case_id)))).filter(Boolean).map((c) => ({ case_id: c.case_id, title: c.title, status: c.status, severity: c.severity }));
  }
  // ---- Approvals ----------------------------------------------------------------
  async function listApprovals({ status, limit = 200 } = {}) {
    await approvals.expire().catch(() => 0);
    const st = status ? [].concat(status).map((s) => String(s).toUpperCase()) : undefined;
    return (await store.approvals.list({ status: st, limit })).map((a) => ({ ...a, route_text: ROUTE_TEXT[a.route] || a.route }));
  }

  function checkTarget(action, ip) {
    if (!['BLOCK', 'ISOLATE'].includes(action)) throw fail('Action must be BLOCK or ISOLATE');
    if (!isIP(ip)) throw fail('target_ip must be an IP address');
    if (action === 'BLOCK' && isInternal(ip)) throw fail('Blocking an internal address cuts off your own network; isolate the host instead');
  }
  function ttlOf(v) {
    if (v === undefined || v === null || v === '') return null;
    const n = Number(v);
    if (!Number.isInteger(n) || n < 0 || n > 8760) throw fail('ttl_hours must be 0-8760 (0 = permanent)');
    return n;
  }

  async function proposeAction(b, who) {
    const action = String(b.action || 'BLOCK').toUpperCase();
    const ip = str(b.target_ip, 64);
    checkTarget(action, ip);
    if (b.case_id) await mustCase(String(b.case_id));
    if (b.alert_id && !(await store.alerts.get(String(b.alert_id)))) throw fail('Alert not found', 404);
    let r;
    try {
      r = await approvals.request({
        action, target_ip: ip, reason: str(b.reason, 500), alert_id: b.alert_id || null, case_id: b.case_id || null,
        confidence: b.confidence == null || b.confidence === '' ? null : Number(b.confidence), route: b.route, requested_by: who.name, ttl_hours: ttlOf(b.ttl_hours)
      });
    } catch (err) { throw fail(err.message); }
    if (r.already) throw fail(`${r.already.rule_id} already ${action === 'BLOCK' ? 'blocks' : 'isolates'} ${ip}`, 409);
    if (r.approval && b.case_id && !r.duplicate) await log(b.case_id, who, `${action} ${ip} proposed (${r.approval.approval_id})`);
    return r;
  }

  async function decide(id, approve, b, who) {
    try { return await approvals.decide(id, { approve, actor: who.name, note: str(b.note, 1000) }); } catch (err) { throw fail(err.message, err.status || 400); }
  }

  // Containment that respects the approval policy: it runs at once when the
  // policy allows it, otherwise it lands in the queue.
  async function contain(b, who) {
    const action = String(b.action || 'BLOCK').toUpperCase();
    const ip = str(b.target_ip, 64);
    checkTarget(action, ip);
    const reason = str(b.reason, 500);
    if (reason.length < 4) throw fail('A reason is required');
    const plan = routeFor(b.confidence == null || b.confidence === '' ? null : Number(b.confidence), await store.config.get());
    if (!plan.execute) return { queued: true, ...(await proposeAction({ ...b, action, target_ip: ip, route: plan.route }, who)) };
    const ttl = ttlOf(b.ttl_hours);
    const res = await investigator.tools.execute_firewall_action({ action, target_ip: ip, reason, actor: who.name, ...(ttl != null ? { ttl_hours: ttl || null } : {}) });
    if (res.error) throw fail(res.error, 409);
    const check = await investigator.tools.verify_defense_state({ target_ip: ip });
    await audit(who, 'rule.created', ip, `${res.rule.rule_id} ${action}: ${reason}`);
    return { queued: false, rule: res.rule, verification: check };
  }

  // ---- Hunts --------------------------------------------------------------------
  async function saveHunt(b, who) {
    const name = str(b.name, 160);
    if (name.length < 4) throw fail('Name the hunt (at least 4 characters)');
    const hypothesis = str(b.hypothesis, 2000);
    if (hypothesis.length < 10) throw fail('State the hypothesis being tested (at least 10 characters)');
    let criteria;
    try { criteria = normalizeCriteria(b.criteria || {}); } catch (err) { throw fail(err.message); }
    const h = await store.hunts.insert({ hunt_id: newId('HUNT'), name, hypothesis, technique: criteria.technique || null, criteria, created_by: who.name });
    await audit(who, 'hunt.saved', h.hunt_id, name);
    return h;
  }

  async function updateHunt(id, b, who) {
    const h = await store.hunts.get(id);
    if (!h) throw fail('Hunt not found', 404);
    const patch = {};
    if (b.name !== undefined) { const v = str(b.name, 160); if (v.length < 4) throw fail('Name the hunt (at least 4 characters)'); patch.name = v; }
    if (b.hypothesis !== undefined) { const v = str(b.hypothesis, 2000); if (v.length < 10) throw fail('State the hypothesis (at least 10 characters)'); patch.hypothesis = v; }
    if (b.criteria !== undefined) { try { patch.criteria = normalizeCriteria(b.criteria); } catch (err) { throw fail(err.message); } patch.technique = patch.criteria.technique || null; }
    if (!Object.keys(patch).length) return h;
    const next = await store.hunts.update(id, patch);
    await audit(who, 'hunt.updated', id, Object.keys(patch).join(', '));
    return next;
  }

  async function deleteHunt(id, who) {
    const h = await store.hunts.get(id);
    if (!h) throw fail('Hunt not found', 404);
    await store.hunts.remove(id);
    await audit(who, 'hunt.deleted', id, h.name);
    return { deleted: id };
  }

  async function execute(criteria, { hunt = null, name = null, who }) {
    let out;
    try { out = await hunter.execute(criteria, { budgetMs: 20000 }); } catch (err) { throw fail(err.message); }
    // Compare with the previous run of the same hunt to flag what is new.
    let fresh = null;
    if (hunt) {
      const prev = (await store.huntRuns.list({ hunt_id: hunt.hunt_id, limit: 1 }))[0];
      const full = prev ? await store.huntRuns.get(prev.id) : null;
      if (full) {
        const seen = new Set((full.findings || []).map(findingKey));
        for (const f of out.findings) f.new = !seen.has(findingKey(f));
        fresh = out.findings.filter((f) => f.new).length;
      }
    }
    const run = await store.huntRuns.insert({
      hunt_id: hunt ? hunt.hunt_id : null, name: name || (hunt ? hunt.name : 'Ad-hoc hunt'), run_by: who.name,
      hits: out.findings.length, new_hits: fresh, duration_ms: out.duration_ms, summary: { ...out.summary, criteria: out.criteria }, findings: out.findings
    });
    if (hunt) await store.hunts.update(hunt.hunt_id, { runs: (hunt.runs || 0) + 1, last_run_at: run.created_at, last_hits: out.findings.length });
    await audit(who, 'hunt.run', hunt ? hunt.hunt_id : `run ${run.id}`, `${plural(out.findings.length, 'finding')}${fresh != null ? `, ${fresh} new` : ''} in ${out.duration_ms} ms`);
    return { run_id: run.id, hunt_id: run.hunt_id, name: run.name, hits: run.hits, new_hits: fresh, duration_ms: out.duration_ms, criteria: out.criteria, summary: out.summary, findings: out.findings, created_at: run.created_at };
  }

  async function runHunt(id, who) {
    const h = await store.hunts.get(id);
    if (!h) throw fail('Hunt not found', 404);
    return execute(h.criteria, { hunt: h, who });
  }

  const adhoc = (b, who) => execute(b.criteria || b, { name: str(b.name, 160) || null, who });

  async function getRun(id) {
    const r = await store.huntRuns.get(id);
    if (!r) throw fail('Run not found', 404);
    return r;
  }

  async function replay(runId, who) {
    const r = await getRun(runId);
    const crit = r.summary && r.summary.criteria;
    if (!crit) throw fail('That run did not record its criteria', 409);
    const hunt = r.hunt_id ? await store.hunts.get(r.hunt_id) : null;
    return execute(crit, { hunt, name: `${r.name.replace(/ \(replay of #\d+\)$/, '')} (replay of #${r.id})`, who });
  }

  async function techniques({ days = 30 } = {}) {
    const d = Math.min(Math.max(Number(days) || 30, 1), 365);
    const since = new Date(Date.now() - d * 86400000).toISOString();
    const [alerts, invs] = await Promise.all([store.alerts.list({ since, limit: 20000 }), store.investigations.list({ since, lite: true, limit: 5000 })]);
    const rows = techniqueRollup(alerts, invs, TACTICS).map((r) => ({ ...r, group: r.tactic ? tacticOf(r.tactic) : null }));
    const tactics = TACTICS.map((t) => {
      const own = rows.filter((r) => r.group === t);
      return { tactic: t, techniques: own.length, hits: own.reduce((n, r) => n + r.alerts + r.investigations, 0), confirmed: own.reduce((n, r) => n + r.confirmed, 0) };
    });
    return { days: d, alerts: alerts.length, untagged: alerts.filter((a) => !alertTechnique(a)).length, tactics, techniques: rows };
  }

  return {
    listCases, createCase, getCase, updateCase, closeCase, reopenCase, escalateCase, linkAlerts, unlinkAlert, addTask, updateTask, addIocs, checkIoc, removeIoc,
    addEvent, fromKillchain, caseMetrics, casesForAlert, listApprovals, proposeAction, decide, contain,
    listHunts: () => store.hunts.list(), saveHunt, updateHunt, deleteHunt, runHunt, adhoc, getRun, replay, techniques
  };
}
function registerCases(app, ctx) {
  const { wrap, bad, need, actor, store } = ctx;
  const svc = createCaseService(ctx);
  const who = (req) => ({ name: actor(req), id: req.user ? req.user.id : null });
  // Service errors carry an HTTP status; anything else is a real 500.
  const h = (fn, code = 200) => wrap(async (req, res) => {
    let out;
    try { out = await fn(req); } catch (err) { if (err.status) return bad(res, err.message, err.status); throw err; }
    res.status(code).json(out);
  });
  const b = (req) => req.body || {};
  const csvq = (v) => (v ? String(v).split(',') : undefined);
  const cap = (v, d, m) => Math.min(Number(v) || d, m);
  // A Supabase project that has not run the casework migration yet.
  const pending = (req, res, next) => (store.pending ? bad(res, `Cases, approvals and hunts need the ${store.pending.migration} migration. Apply it to the database and reload.`, 503) : next());
  app.use(['/api/cases', '/api/approvals', '/api/hunts', '/api/alerts/:id/cases'], pending);

  app.get('/api/cases', h((req) => svc.listCases({ status: csvq(req.query.status), q: req.query.q, limit: cap(req.query.limit, 200, 1000) })));
  app.get('/api/cases/metrics', h(() => svc.caseMetrics()));
  app.post('/api/cases', need('respond'), h((req) => svc.createCase(b(req), who(req)), 201));
  app.post('/api/cases/from-killchain', need('respond'), h((req) => svc.fromKillchain(b(req), who(req)), 201));
  app.get('/api/cases/:id', h((req) => svc.getCase(req.params.id)));
  app.patch('/api/cases/:id', need('respond'), h((req) => svc.updateCase(req.params.id, b(req), who(req))));
  app.post('/api/cases/:id/close', need('respond'), h((req) => svc.closeCase(req.params.id, b(req), who(req))));
  app.post('/api/cases/:id/reopen', need('respond'), h((req) => svc.reopenCase(req.params.id, who(req))));
  app.post('/api/cases/:id/escalate', need('respond'), h((req) => svc.escalateCase(req.params.id, b(req), who(req))));
  app.post('/api/cases/:id/alerts', need('respond'), h((req) => svc.linkAlerts(req.params.id, b(req).alert_ids, who(req))));
  app.delete('/api/cases/:id/alerts/:alertId', need('respond'), h((req) => svc.unlinkAlert(req.params.id, req.params.alertId, who(req))));
  app.post('/api/cases/:id/tasks', need('respond'), h((req) => svc.addTask(req.params.id, b(req), who(req)), 201));
  app.patch('/api/cases/:id/tasks/:tid', need('respond'), h((req) => svc.updateTask(req.params.id, req.params.tid, b(req), who(req))));
  app.post('/api/cases/:id/iocs', need('respond'), h((req) => svc.addIocs(req.params.id, b(req), who(req)), 201));
  app.post('/api/cases/:id/iocs/:iid/check', need('respond'), h((req) => svc.checkIoc(req.params.id, req.params.iid, who(req))));
  app.delete('/api/cases/:id/iocs/:iid', need('respond'), h((req) => svc.removeIoc(req.params.id, req.params.iid, who(req))));
  app.post('/api/cases/:id/events', need('respond'), h((req) => svc.addEvent(req.params.id, b(req), who(req)), 201));
  app.get('/api/alerts/:id/cases', h((req) => svc.casesForAlert(req.params.id)));

  app.get('/api/approvals', h((req) => svc.listApprovals({ status: csvq(req.query.status), limit: cap(req.query.limit, 200, 1000) })));
  app.get('/api/approvals/count', h(async () => ({ pending: await store.approvals.count('PENDING') })));
  app.post('/api/approvals', need('respond'), h((req) => svc.proposeAction(b(req), who(req)), 201));
  app.post('/api/approvals/:id/approve', need('respond'), h((req) => svc.decide(req.params.id, true, b(req), who(req))));
  app.post('/api/approvals/:id/reject', need('respond'), h((req) => svc.decide(req.params.id, false, b(req), who(req))));

  app.get('/api/hunts', h(() => svc.listHunts()));
  app.post('/api/hunts', need('respond'), h((req) => svc.saveHunt(b(req), who(req)), 201));
  app.post('/api/hunts/adhoc', need('respond'), h((req) => svc.adhoc(b(req), who(req))));
  app.get('/api/hunts/runs', h((req) => store.huntRuns.list({ hunt_id: req.query.hunt_id || undefined, limit: cap(req.query.limit, 50, 200) })));
  app.get('/api/hunts/runs/:id', h((req) => svc.getRun(req.params.id)));
  app.post('/api/hunts/runs/:id/replay', need('respond'), h((req) => svc.replay(req.params.id, who(req))));
  app.get('/api/hunts/techniques', h((req) => svc.techniques({ days: req.query.days })));
  app.patch('/api/hunts/:id', need('respond'), h((req) => svc.updateHunt(req.params.id, b(req), who(req))));
  app.delete('/api/hunts/:id', need('respond'), h((req) => svc.deleteHunt(req.params.id, who(req))));
  app.post('/api/hunts/:id/run', need('respond'), h((req) => svc.runHunt(req.params.id, who(req))));

  return svc;
}

module.exports = { registerCases, createCaseService, playbookTasks, CASE_STATUS, TASK_STATUS };