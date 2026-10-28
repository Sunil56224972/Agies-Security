'use strict';

// The analyst workbench: the AI assistant, workflows, the decisions log,
// document analysis, custom detection rules, the Jira hand-off and backups.
// Everything here calls the same services as the console and the MCP server,
// so a workflow step or an assistant tool call is audited exactly like a click.

const crypto = require('crypto');
const express = require('express');
const { isIP, isInternal, newId, SEVERITY_RANK } = require('./engine/analysis');
const { classify, extractAll, isIpType } = require('./intel/indicator');
const { normalizeLog } = require('./ingest/normalize');
const { scanWith } = require('./engine/sigma');
const { lintRule } = require('./engine/customrules');
const auth = require('./security/auth');
const { extras } = require('./engine/llm');

const fail = (msg, status = 400) => Object.assign(new Error(msg), { status });
const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const clip = (v, n) => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s.length > n ? `${s.slice(0, n)}... [truncated ${s.length - n} chars]` : s; };
const OUTCOMES = ['ATTACK_SUCCEEDED', 'ATTACK_FAILED', 'FALSE_POSITIVE', 'RECON_ONLY'];

// ---- Workflow step catalogue -----------------------------------------------------
// Each field may hold a literal or a template: {{input.key}} or {{steps.<id>.<path>}}.
const F = (key, label, extra = {}) => ({ key, label, ...extra });
const STEP_TYPES = {
  investigate: { label: 'Investigate alert', write: true, help: 'Runs the investigation engine. Containment follows the approval policy.', fields: [F('alert_id', 'Alert id', { required: true })] },
  extract_iocs: { label: 'Extract indicators', help: 'Pulls IPs, domains, URLs and hashes out of text.', fields: [F('text', 'Text', { required: true, multiline: true })] },
  intel_lookup: { label: 'Threat intel lookup', help: 'Checks up to 25 indicators against every configured intel source.', fields: [F('values', 'Indicators', { required: true })] },
  hunt: { label: 'Threat hunt', write: true, help: 'Searches stored logs, alerts and investigations; the run is saved under Hunts.', fields: [F('ip', 'IP or CIDR'), F('text', 'Text or /regex/'), F('indicators', 'Indicators'), F('technique', 'ATT&CK id'), F('window_hours', 'Window (hours)', { type: 'number' }), F('sigma', 'Run Sigma rules', { type: 'bool' }), F('intel', 'Check addresses against intel', { type: 'bool' })] },
  case_from_killchain: { label: 'Case from kill chain', write: true, help: 'Groups every alert involving an address into one case.', fields: [F('ip', 'Attacker IP', { required: true }), F('hours', 'Look-back (hours)', { type: 'number' })] },
  create_case: { label: 'Open case', write: true, help: 'Opens an incident case.', fields: [F('title', 'Title', { required: true }), F('severity', 'Severity', { options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] }), F('description', 'Description', { multiline: true }), F('alert_ids', 'Alert ids')] },
  add_iocs: { label: 'Add indicators to case', write: true, help: 'Adds indicators to an existing case.', fields: [F('case_id', 'Case id', { required: true }), F('values', 'Indicators', { required: true }), F('note', 'Note')] },
  contain: { label: 'Contain addresses', write: true, help: 'BLOCK or ISOLATE each address. Below the auto-approve confidence it goes to Approvals.', fields: [F('ips', 'Addresses', { required: true }), F('action', 'Action', { options: ['BLOCK', 'ISOLATE'] }), F('reason', 'Reason', { required: true }), F('confidence', 'Confidence 0-100', { type: 'number' }), F('ttl_hours', 'Expire after (hours)', { type: 'number' })] },
  notify: { label: 'Notify channels', help: 'Posts a message to every enabled Slack, Teams, PagerDuty or webhook channel.', fields: [F('message', 'Message', { required: true, multiline: true })] }
};
const WHEN_OPS = ['nonempty', 'empty', 'eq', 'neq', 'in', 'gte', 'lte'];

const TEMPLATES = [
  {
    key: 'incident-response', name: 'Alert to incident', description: 'Investigate an alert, profile the attacker in threat intel, hunt for the same address across a week of telemetry, and open a kill-chain case when the verdict is a real attack.',
    inputs: [{ key: 'alert_id', label: 'Alert id', required: true }],
    steps: [
      { id: 'inv', type: 'investigate', params: { alert_id: '{{input.alert_id}}' } },
      { id: 'intel', type: 'intel_lookup', params: { values: '{{steps.inv.attacker_ip}}' }, continue_on_error: true },
      { id: 'sweep', type: 'hunt', params: { ip: '{{steps.inv.attacker_ip}}', window_hours: 168, sigma: true } },
      { id: 'case', type: 'case_from_killchain', params: { ip: '{{steps.inv.attacker_ip}}', hours: 168 }, when: { path: 'steps.inv.outcome', op: 'in', value: 'ATTACK_SUCCEEDED,ATTACK_FAILED' } },
      { id: 'tell', type: 'notify', params: { message: '{{steps.inv.outcome}} on {{input.alert_id}} ({{steps.inv.confidence}}%). Hunt found {{steps.sweep.hits}} related events. Case: {{steps.case.case_id}}' }, continue_on_error: true }
    ]
  },
  {
    key: 'ioc-triage', name: 'IOC triage', description: 'Extract every indicator from a report or a paste, check each one, open a case for the bad ones and send malicious addresses to containment through the approval policy.',
    inputs: [{ key: 'text', label: 'Report text or indicator list', required: true, multiline: true }],
    steps: [
      { id: 'iocs', type: 'extract_iocs', params: { text: '{{input.text}}' } },
      { id: 'intel', type: 'intel_lookup', params: { values: '{{steps.iocs.values}}' } },
      { id: 'case', type: 'create_case', params: { title: 'IOC triage: {{steps.intel.flagged_count}} flagged indicators', severity: 'HIGH', description: 'Opened by the IOC triage workflow. Malicious: {{steps.intel.malicious}}' }, when: { path: 'steps.intel.flagged', op: 'nonempty' } },
      { id: 'attach', type: 'add_iocs', params: { case_id: '{{steps.case.case_id}}', values: '{{steps.intel.flagged}}', note: 'Flagged by threat intel during triage' }, when: { path: 'steps.intel.flagged', op: 'nonempty' } },
      { id: 'block', type: 'contain', params: { ips: '{{steps.intel.malicious_ips}}', action: 'BLOCK', reason: 'Known-malicious address from IOC triage', confidence: 80, ttl_hours: 168 }, when: { path: 'steps.intel.malicious_ips', op: 'nonempty' }, continue_on_error: true }
    ]
  },
  {
    key: 'attacker-sweep', name: 'Attacker sweep', description: 'Given one address: reputation and intel, a 30-day hunt with Sigma, and a kill-chain case if the hunt finds anything.',
    inputs: [{ key: 'ip', label: 'Attacker IP', required: true }],
    steps: [
      { id: 'intel', type: 'intel_lookup', params: { values: '{{input.ip}}' } },
      { id: 'sweep', type: 'hunt', params: { ip: '{{input.ip}}', window_hours: 720, sigma: true } },
      { id: 'case', type: 'case_from_killchain', params: { ip: '{{input.ip}}', hours: 720 }, when: { path: 'steps.sweep.alerts', op: 'gte', value: 1 }, continue_on_error: true }
    ]
  }
];

// ---- Templates ---------------------------------------------------------------------
function pathGet(obj, path) {
  return String(path).split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}
function resolve(v, scope) {
  if (typeof v !== 'string') return v;
  const whole = v.match(/^\{\{\s*([\w.]+)\s*\}\}$/);
  if (whole) return pathGet(scope, whole[1]);
  return v.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (_, p) => {
    const x = pathGet(scope, p);
    if (x == null) return '';
    return Array.isArray(x) ? x.join(', ') : typeof x === 'object' ? JSON.stringify(x) : String(x);
  });
}
function test(when, scope) {
  if (!when) return true;
  const x = pathGet(scope, when.path);
  const list = (v) => (Array.isArray(v) ? v : String(v == null ? '' : v).split(',')).map((s) => String(s).trim());
  switch (when.op) {
    case 'nonempty': return Array.isArray(x) ? x.length > 0 : x != null && x !== '' && x !== false && x !== 0;
    case 'empty': return Array.isArray(x) ? !x.length : x == null || x === '' || x === 0;
    case 'eq': return String(x) === String(when.value);
    case 'neq': return String(x) !== String(when.value);
    case 'in': return list(when.value).includes(String(x));
    case 'gte': return Number(x) >= Number(when.value);
    case 'lte': return Number(x) <= Number(when.value);
    default: return false;
  }
}
const toList = (v) => (Array.isArray(v) ? v.map(String) : String(v == null ? '' : v).split(/[\s,;]+/)).map((s) => s.trim()).filter(Boolean);

function validateWorkflow(b) {
  const name = str(b.name, 120);
  if (name.length < 3) throw fail('Name the workflow (at least 3 characters)');
  const inputs = (Array.isArray(b.inputs) ? b.inputs : []).slice(0, 6).map((i) => ({ key: str(i.key, 30), label: str(i.label, 80) || str(i.key, 30), required: Boolean(i.required), multiline: Boolean(i.multiline) }));
  for (const i of inputs) if (!/^[a-z][a-z0-9_]{0,29}$/.test(i.key)) throw fail(`Input key "${i.key}" must be lower_case letters, digits and underscores`);
  if (new Set(inputs.map((i) => i.key)).size !== inputs.length) throw fail('Input keys must be unique');
  const raw = Array.isArray(b.steps) ? b.steps : [];
  if (!raw.length) throw fail('Add at least one step');
  if (raw.length > 20) throw fail('At most 20 steps');
  const seen = new Set();
  const steps = raw.map((s, n) => {
    const id = str(s.id, 31) || `s${n + 1}`;
    if (!/^[a-z][a-z0-9_]{0,30}$/.test(id)) throw fail(`Step ${n + 1}: id must be lower_case letters, digits and underscores`);
    if (seen.has(id)) throw fail(`Step id "${id}" is used twice`);
    const def = STEP_TYPES[s.type];
    if (!def) throw fail(`Step ${id}: unknown type "${s.type}"`);
    const params = {};
    for (const f of def.fields) {
      const v = s.params ? s.params[f.key] : undefined;
      if (v === undefined || v === null || v === '') { if (f.required) throw fail(`Step ${id}: ${f.label} is required`); continue; }
      if (typeof v === 'object') throw fail(`Step ${id}: ${f.label} must be text, a number or true/false`);
      params[f.key] = typeof v === 'string' ? v.slice(0, 4000) : v;
      for (const m of String(v).matchAll(/\{\{\s*([\w.]+)\s*\}\}/g)) {
        const [root, ref] = m[1].split('.');
        if (root === 'input' && !inputs.some((i) => i.key === ref)) throw fail(`Step ${id}: {{${m[1]}}} names an input the workflow does not declare`);
        if (root === 'steps' && !seen.has(ref)) throw fail(`Step ${id}: {{${m[1]}}} refers to a step that does not run before it`);
        if (root !== 'input' && root !== 'steps') throw fail(`Step ${id}: templates start with input. or steps.`);
      }
    }
    let when = null;
    if (s.when && s.when.path) {
      if (!WHEN_OPS.includes(s.when.op)) throw fail(`Step ${id}: condition must be one of ${WHEN_OPS.join(', ')}`);
      const [root, ref] = String(s.when.path).split('.');
      if (!(root === 'input' || (root === 'steps' && seen.has(ref)))) throw fail(`Step ${id}: the condition must test an input or an earlier step`);
      when = { path: str(s.when.path, 120), op: s.when.op, ...(s.when.value !== undefined ? { value: s.when.value } : {}) };
    }
    seen.add(id);
    return { id, type: s.type, name: str(s.name, 80) || null, params, ...(when ? { when } : {}), ...(s.continue_on_error ? { continue_on_error: true } : {}) };
  });
  return { name, description: str(b.description, 1000), inputs, steps };
}

function createWorkbench(ctx, svc) {
  const { store, investigator, hub, notifier, env, customRules } = ctx;
  const T = {
    threads: () => store.coll('chat_threads', 'thread_id'),
    workflows: () => store.coll('workflows', 'workflow_id'),
    runs: () => store.coll('workflow_runs', 'run_id'),
    feedback: () => store.coll('decision_feedback', 'id'),
    docs: () => store.coll('documents', 'doc_id'),
    rules: () => store.coll('custom_rules', 'rule_id')
  };
  const audit = (who, action, target, detail) => store.audit.add({ actor: who.name, action, target, detail: detail ? String(detail).slice(0, 300) : null }).catch(() => {});

  // ---- Threat intel helper shared by workflows and documents ------------------------
  async function lookupMany(values, { budgetMs = 9000 } = {}) {
    if (!hub) throw fail('Threat intel is not available on this server', 503);
    const inds = []; const seen = new Set();
    for (const v of values) {
      const found = extractAll(v, { max: 30 });
      for (const c of found.length ? found : [classify(v)].filter(Boolean)) {
        if (c.type === 'asn' || seen.has(c.value)) continue;
        seen.add(c.value); inds.push(c);
      }
    }
    const pick = inds.slice(0, 25);
    const out = [];
    for (let i = 0; i < pick.length; i += 5) {
      out.push(...await Promise.all(pick.slice(i, i + 5).map(async (ind) => {
        if (isIpType(ind.type) && isInternal(ind.value)) return { value: ind.value, type: ind.type, verdict: 'internal', score: null };
        try {
          const r = await hub.lookup(ind.value, { budgetMs, vt: false });
          return { value: ind.value, type: ind.type, verdict: r.verdict, score: r.score, summary: r.summary || r.reason || null, families: r.families || [], sources: (r.sources_ok || []).length };
        } catch (err) { return { value: ind.value, type: ind.type, verdict: 'error', error: err.message }; }
      })));
    }
    const mal = out.filter((r) => r.verdict === 'malicious');
    const sus = out.filter((r) => r.verdict === 'suspicious');
    return {
      checked: out.length, skipped: Math.max(0, inds.length - pick.length), results: out,
      malicious: mal.map((r) => r.value), suspicious: sus.map((r) => r.value), flagged: [...mal, ...sus].map((r) => r.value),
      malicious_ips: mal.filter((r) => isIpType(r.type)).map((r) => r.value), malicious_count: mal.length, flagged_count: mal.length + sus.length,
      checked_at: new Date().toISOString()
    };
  }

  // ---- Workflows -------------------------------------------------------------------------
  const STEP_RUN = {
    async investigate(p) {
      const id = str(p.alert_id, 80);
      if (!id) throw fail('No alert id');
      const inv = await investigator.run(id, () => {}, { pace: 0 });
      return {
        investigation_id: inv.investigation_id, outcome: inv.outcome, confidence: inv.confidence, attacker_ip: inv.attacker_ip, target_ip: inv.target_ip,
        mitre_technique: inv.mitre_technique, engine: inv.engine, summary: inv.summary, actions: (inv.actions_taken || []).map((a) => `${a.type} ${a.target}`)
      };
    },
    async extract_iocs(p) {
      const found = extractAll(String(p.text || ''), { max: 200 });
      const by = found.reduce((m, i) => ({ ...m, [i.type]: (m[i.type] || 0) + 1 }), {});
      return { count: found.length, values: found.map((i) => i.value), by_type: by, ips: found.filter((i) => isIpType(i.type)).map((i) => i.value) };
    },
    async intel_lookup(p) {
      const values = toList(p.values);
      if (!values.length) throw fail('No indicators to look up');
      return lookupMany(values);
    },
    async hunt(p, who) {
      const criteria = {};
      for (const k of ['ip', 'text', 'indicators', 'technique']) if (p[k]) criteria[k] = Array.isArray(p[k]) ? p[k].join('\n') : String(p[k]);
      if (p.window_hours) criteria.window_hours = Number(p.window_hours);
      if (p.sigma === true || p.sigma === 'true') criteria.sigma = true;
      if (p.intel === true || p.intel === 'true') criteria.intel = true;
      const r = await svc.adhoc({ criteria, name: 'Workflow hunt' }, who);
      const kinds = r.findings.reduce((m, f) => ({ ...m, [f.kind]: (m[f.kind] || 0) + 1 }), {});
      return { run_id: r.run_id, hits: r.hits, new_hits: r.new_hits, alerts: kinds.alert || 0, logs: kinds.log || 0, sigma: kinds.sigma || 0, by_kind: kinds, notes: r.summary && r.summary.notes };
    },
    async case_from_killchain(p, who) {
      const c = await svc.fromKillchain({ ip: str(p.ip, 64), hours: p.hours || 72 }, who);
      return { case_id: c.case_id, title: c.title, severity: c.severity, hosts: c.hosts, compromised: c.compromised, techniques: c.techniques };
    },
    async create_case(p, who) {
      const c = await svc.createCase({ title: p.title, severity: p.severity || 'MEDIUM', description: p.description, alert_ids: toList(p.alert_ids), source: 'workflow' }, who);
      return { case_id: c.case_id, title: c.title, severity: c.severity, linked: c.linked };
    },
    async add_iocs(p, who) {
      const r = await svc.addIocs(str(p.case_id, 60), { values: toList(p.values), note: p.note }, who);
      return { case_id: p.case_id, added: r.added.length, duplicates: r.duplicates };
    },
    async contain(p, who) {
      const ips = toList(p.ips).filter((x) => isIP(x)).slice(0, 20);
      if (!ips.length) throw fail('No addresses to contain');
      const executed = []; const queued = []; const failed = [];
      for (const ip of ips) {
        try {
          const r = await svc.contain({ action: p.action || 'BLOCK', target_ip: ip, reason: p.reason, confidence: p.confidence, ttl_hours: p.ttl_hours }, who);
          if (r.queued) queued.push({ ip, approval_id: r.approval && r.approval.approval_id });
          else executed.push({ ip, rule_id: r.rule.rule_id, enforcement: r.verification && r.verification.status });
        } catch (err) { failed.push({ ip, error: err.message }); }
      }
      if (!executed.length && !queued.length) throw fail(failed.map((f) => `${f.ip}: ${f.error}`).join('; '));
      return { executed, queued, failed };
    },
    async notify(p, who, run) {
      const list = (await notifier.channels()).filter((c) => c.enabled !== false);
      // No channels is a setup choice, not a failure of the run.
      if (!list.length) return { skip: 'No notification channels configured (Settings > Notifications)' };
      const rows = run.steps.filter((s) => s.status !== 'pending').map((s) => `${s.id}: ${s.status}${s.summary ? ` - ${s.summary}` : ''}`).slice(0, 10);
      const evt = { type: 'test', console_url: env.PUBLIC_URL || null, data: { message: `[${run.name}] ${String(p.message).slice(0, 500)}`, rows } };
      const results = await Promise.all(list.map(async (c) => ({ c, r: await notifier.deliver(c, evt) })));
      await notifier.record(results, 'workflow');
      return { channels: results.length, delivered: results.filter((x) => x.r.ok).length, failed: results.filter((x) => !x.r.ok).map((x) => `${x.c.name}: ${x.r.detail}`) };
    }
  };

  // One line an analyst can read in the run view.
  function summarize(type, o) {
    switch (type) {
      case 'investigate': return `${String(o.outcome).replace(/_/g, ' ').toLowerCase()} at ${o.confidence}%, attacker ${o.attacker_ip}`;
      case 'extract_iocs': return `${plural(o.count, 'indicator')} found`;
      case 'intel_lookup': return `${o.checked} checked, ${o.malicious.length} malicious, ${o.suspicious.length} suspicious`;
      case 'hunt': return `${plural(o.hits, 'finding')} (${o.alerts} alerts, ${o.logs} log lines, ${o.sigma} Sigma)`;
      case 'case_from_killchain': case 'create_case': return `${o.case_id}: ${o.title}`;
      case 'add_iocs': return `${o.added} added to ${o.case_id}`;
      case 'contain': return `${o.executed.length} enforced, ${o.queued.length} sent for approval${o.failed.length ? `, ${o.failed.length} failed` : ''}`;
      case 'notify': return `${o.delivered}/${o.channels} channels delivered`;
      default: return null;
    }
  }

  async function runWorkflow(wf, input, who, emit = () => {}) {
    const vals = {};
    for (const i of wf.inputs || []) {
      const v = input && input[i.key] != null ? String(input[i.key]).slice(0, 200000) : '';
      if (i.required && !v.trim()) throw fail(`${i.label || i.key} is required`);
      vals[i.key] = v;
    }
    const started = Date.now();
    const run = {
      run_id: newId('RUN'), workflow_id: wf.workflow_id, name: wf.name, input: Object.fromEntries(Object.entries(vals).map(([k, v]) => [k, v.slice(0, 4000)])),
      status: 'RUNNING', run_by: who.name, steps: wf.steps.map((s) => ({ id: s.id, type: s.type, name: s.name || STEP_TYPES[s.type].label, status: 'pending' }))
    };
    await T.runs().insert(run);
    emit({ type: 'start', run_id: run.run_id, name: wf.name, steps: run.steps });
    const scope = { input: vals, steps: {} };
    let failed = false; let partial = false;
    for (const [n, s] of wf.steps.entries()) {
      const rec = run.steps[n];
      if (failed) { rec.status = 'cancelled'; emit({ type: 'step', index: n, ...rec }); continue; }
      if (!test(s.when, scope)) {
        rec.status = 'skipped'; rec.summary = `Condition not met: ${s.when.path} ${s.when.op}${s.when.value !== undefined ? ` ${s.when.value}` : ''}`;
        scope.steps[s.id] = null;
        emit({ type: 'step', index: n, ...rec });
        continue;
      }
      const params = Object.fromEntries(Object.entries(s.params || {}).map(([k, v]) => [k, resolve(v, scope)]));
      rec.status = 'running'; rec.started_at = new Date().toISOString();
      emit({ type: 'step', index: n, ...rec, params });
      const t0 = Date.now();
      try {
        const out = await STEP_RUN[s.type](params, who, run);
        if (out && typeof out.skip === 'string' && Object.keys(out).length === 1) {
          Object.assign(rec, { status: 'skipped', ms: Date.now() - t0, summary: out.skip });
          scope.steps[s.id] = null;
          emit({ type: 'step', index: n, ...rec });
          continue;
        }
        scope.steps[s.id] = out;
        // Large outputs (hunt findings, bulk intel) are stored trimmed; the full
        // record lives on the hunt run, case or rule the step created.
        const json = JSON.stringify(out);
        Object.assign(rec, { status: 'ok', ms: Date.now() - t0, summary: summarize(s.type, out), output: json.length > 8000 ? { truncated: true, preview: json.slice(0, 8000) } : out });
      } catch (err) {
        if (!err.status) console.warn(`  Workflow step ${s.id} failed:`, err.message);
        Object.assign(rec, { status: 'failed', ms: Date.now() - t0, error: String(err.message).slice(0, 500) });
        scope.steps[s.id] = null;
        if (s.continue_on_error) partial = true; else failed = true;
      }
      emit({ type: 'step', index: n, ...rec });
    }
    const status = failed ? 'FAILED' : partial ? 'PARTIAL' : 'SUCCEEDED';
    const done = await T.runs().update(run.run_id, { status, steps: run.steps, duration_ms: Date.now() - started, finished_at: new Date().toISOString() });
    if (wf.workflow_id && !wf.adhoc) {
      const cur = await T.workflows().get(wf.workflow_id);
      if (cur) await T.workflows().update(wf.workflow_id, { runs: (cur.runs || 0) + 1, last_run_at: done.finished_at, last_status: status });
    }
    await audit(who, 'workflow.run', run.run_id, `${wf.name}: ${status} in ${Date.now() - started} ms`);
    emit({ type: 'finish', run_id: run.run_id, status, duration_ms: done.duration_ms });
    return done;
  }

  async function mustWorkflow(id) {
    const wf = await T.workflows().get(id);
    if (!wf) throw fail('Workflow not found', 404);
    return wf;
  }
  async function saveWorkflow(b, who, id = null) {
    if (b.template && !id) {
      const t = TEMPLATES.find((x) => x.key === b.template);
      if (!t) throw fail('Unknown template');
      b = { ...t, name: b.name || t.name };
    }
    const v = validateWorkflow(b);
    if (id) {
      await mustWorkflow(id);
      const next = await T.workflows().update(id, { ...v, ...(b.enabled !== undefined ? { enabled: Boolean(b.enabled) } : {}) });
      await audit(who, 'workflow.updated', id, v.name);
      return next;
    }
    const wf = await T.workflows().insert({ workflow_id: newId('WF'), ...v, enabled: true, created_by: who.name, runs: 0 });
    await audit(who, 'workflow.created', wf.workflow_id, v.name);
    return wf;
  }
  async function setEnabled(id, enabled, who) {
    await mustWorkflow(id);
    const next = await T.workflows().update(id, { enabled: Boolean(enabled) });
    await audit(who, enabled ? 'workflow.enabled' : 'workflow.disabled', id, next.name);
    return next;
  }
  async function deleteWorkflow(id, who) {
    const wf = await mustWorkflow(id);
    await T.workflows().remove(id);
    await audit(who, 'workflow.deleted', id, wf.name);
    return { deleted: id };
  }
  async function startRun(id, input, who, emit) {
    const wf = await mustWorkflow(id);
    if (wf.enabled === false) throw fail('The workflow is disabled', 409);
    return runWorkflow(wf, input, who, emit);
  }
  // ---- AI assistant ----------------------------------------------------------------------
  // OpenAI-style tool calling (any configured provider) over the same tools the MCP server exposes. Read tools run at
  // once; anything that changes state waits in `pending` until the analyst confirms.
  const { buildTools } = require('./mcp');
  const tools = buildTools(ctx, svc);
  const toolByName = new Map(tools.map((t) => [t.name, t]));
  const MAX_ROUNDS = 6;
  const KEEP = 60;

  function system(user) {
    return [
      'You are the analyst assistant inside Aegis, a security operations platform. You answer questions about this deployment\'s alerts, investigations, cases, containment rules, hunts and threat intelligence by calling tools.',
      'Rules:',
      '- Every fact about this environment must come from a tool result in this conversation. Never invent alert ids, IPs, case ids, counts or verdicts. If a tool returns nothing, say so.',
      '- Quote ids exactly (ALERT-..., INV-..., CASE-..., APR-..., FW-...) so the analyst can click through.',
      '- Prefer one well-chosen tool call over many. For "what is happening" start with overview.',
      '- Actions that change state (investigate, contain, open or update cases, run hunts) are only proposed; the analyst confirms them in the console. Propose them only when the analyst asks or the evidence clearly calls for it, and say why.',
      '- Answer in short paragraphs or tight lists. Lead with the answer, then the evidence. No filler.',
      `Analyst: ${user.name} (${user.role}). ${auth.can(user, 'respond') ? 'May approve actions.' : 'Read-only: do not propose actions.'} Current time: ${new Date().toISOString()}.`
    ].join('\n');
  }

  const toolSpecs = (user) => tools.filter((t) => !t.write || auth.can(user, 'respond')).map((t) => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.inputSchema } }));

  // The conversation as the model sees it: the most recent messages, never starting
  // in the middle of a tool exchange.
  function context(thread, user) {
    let msgs = (thread.messages || []).slice(-KEEP);
    while (msgs.length && (msgs[0].role === 'tool' || (msgs[0].role === 'assistant' && msgs[0].tool_calls))) msgs = msgs.slice(1);
    return [{ role: 'system', content: system(user) }, ...msgs.map((m) => {
      if (m.role === 'tool') return { role: 'tool', tool_call_id: m.tool_call_id, content: m.content };
      if (m.role === 'assistant' && m.tool_calls) return { role: 'assistant', content: m.content || '', tool_calls: m.tool_calls };
      return { role: m.role, content: m.content };
    })];
  }

  async function complete(messages, user, llm) {
    const req = { model: llm.model, messages, tools: toolSpecs(user), tool_choice: 'auto', temperature: 0.2, max_tokens: 1600, ...extras(llm.model) };
    const name = llm.label || 'The model provider';
    try { return await llm.client.chat.completions.create(req); } catch (err) {
      // gpt-oss occasionally emits a malformed tool call; one retry usually clears it.
      if (err.status === 400 && /tool/i.test(String(err.message))) {
        try { return await llm.client.chat.completions.create(req); } catch (e2) { throw fail(`The model could not form a valid tool call: ${String(e2.message).slice(0, 200)}`, 502); }
      }
      const where = llm.source === 'env' ? 'GROQ_API_KEY on the server' : 'the key under Settings, Language model';
      if (err.status === 401 || err.status === 403) throw fail(`${name} rejected the API key; check ${where}`, 502);
      if (err.status === 404) throw fail(`${name} does not know the model ${llm.model}; pick another under Settings, Language model`, 502);
      if (err.status === 429) throw fail(`${name} rate limit or quota reached; wait a few seconds and send again`, 429);
      throw fail(`${name} request failed: ${String(err.message).slice(0, 200)}`, 502);
    }
  }

  async function callTool(name, args, who) {
    const tool = toolByName.get(name);
    if (!tool) return { ok: false, text: `Unknown tool ${name}` };
    const t0 = Date.now();
    try {
      const out = await tool.run(args || {}, who);
      await audit(who, 'assistant.tool', name, `ok ${Date.now() - t0}ms`);
      return { ok: true, text: clip(out, 7000), ms: Date.now() - t0 };
    } catch (err) {
      if (!err.status && err.constructor.name !== 'ToolError') console.warn('  Assistant tool failed:', err.message);
      return { ok: false, text: `Error: ${String(err.message).slice(0, 400)}`, ms: Date.now() - t0 };
    }
  }

  // Runs the model until it answers or proposes a write action.
  async function converse(thread, user, emit) {
    const who = { name: user.name, id: user.id };
    const started = Date.now();
    const llm = await ensureLlm();
    let tokens = 0;
    for (let round = 0; round < MAX_ROUNDS; round += 1) {
      if (Date.now() - started > 42000) {
        thread.messages.push({ role: 'assistant', content: 'I ran out of time gathering evidence for this one. Ask a narrower question, or ask me to continue.', at: new Date().toISOString() });
        break;
      }
      emit({ type: 'thinking', round });
      const res = await complete(context(thread, user), user, llm);
      tokens += (res.usage && res.usage.total_tokens) || 0;
      const m = res.choices[0].message;
      const calls = (m.tool_calls || []).slice(0, 6);
      if (!calls.length) {
        const msg = { role: 'assistant', content: String(m.content || '').trim() || 'I have nothing further to add.', at: new Date().toISOString() };
        thread.messages.push(msg);
        emit({ type: 'message', message: msg });
        break;
      }
      const asst = { role: 'assistant', content: m.content || '', tool_calls: calls.map((c) => ({ id: c.id, type: 'function', function: { name: c.function.name, arguments: c.function.arguments || '{}' } })), at: new Date().toISOString() };
      thread.messages.push(asst);
      const deferred = [];
      for (const c of asst.tool_calls) {
        let args = {};
        try { args = JSON.parse(c.function.arguments || '{}') || {}; } catch { args = null; }
        const tool = toolByName.get(c.function.name);
        if (args && tool && tool.write) { deferred.push({ id: c.id, name: tool.name, title: tool.title, args }); continue; }
        emit({ type: 'tool', name: c.function.name, args, status: 'running' });
        const r = args ? await callTool(c.function.name, args, who) : { ok: false, text: 'Error: arguments were not valid JSON' };
        const msg = { role: 'tool', tool_call_id: c.id, name: c.function.name, args, ok: r.ok, ms: r.ms, content: r.text, at: new Date().toISOString() };
        thread.messages.push(msg);
        emit({ type: 'tool', name: c.function.name, args, status: r.ok ? 'ok' : 'error', ms: r.ms, message: msg });
      }
      if (deferred.length) {
        thread.pending = { calls: deferred, at: new Date().toISOString() };
        emit({ type: 'pending', pending: thread.pending });
        break;
      }
    }
    return tokens;
  }

  async function ensureLlm() {
    const l = await investigator.llm();
    if (!l.client) throw fail('The assistant needs a language model. An administrator can connect one under Settings, Language model.', 503);
    return l;
  }
  async function mustThread(id, user) {
    const t = await T.threads().get(id);
    if (!t || String(t.user_id) !== String(user.id)) throw fail('Conversation not found', 404);
    return t;
  }
  async function saveThread(t, tokens) {
    const messages = t.messages.slice(-200);
    return T.threads().update(t.thread_id, { messages, pending: t.pending || null, title: t.title, tokens: (t.tokens || 0) + (tokens || 0) });
  }

  async function listThreads(user) {
    const rows = await T.threads().list({ eq: { user_id: user.id }, order: 'updated_at', limit: 100 });
    return rows.map((t) => ({ thread_id: t.thread_id, title: t.title, messages: (t.messages || []).filter((m) => m.role === 'user' || (m.role === 'assistant' && !m.tool_calls)).length, pending: Boolean(t.pending), tokens: t.tokens, created_at: t.created_at, updated_at: t.updated_at }));
  }
  async function createThread(user) {
    return T.threads().insert({ thread_id: newId('CHAT'), title: 'New conversation', user_id: user.id, user_name: user.name, messages: [], pending: null, tokens: 0 });
  }
  async function sendMessage(id, b, user, emit = () => {}) {
    await ensureLlm();
    const t = await mustThread(id, user);
    const text = str(b.content, 4000);
    if (!text) throw fail('Write a message first');
    // A new message supersedes an unanswered proposal.
    if (t.pending) {
      for (const c of t.pending.calls) t.messages.push({ role: 'tool', tool_call_id: c.id, name: c.name, args: c.args, ok: false, content: 'Not executed: the analyst moved on without confirming.', at: new Date().toISOString() });
      t.pending = null;
    }
    t.messages.push({ role: 'user', content: text, author: user.name, at: new Date().toISOString() });
    if (t.title === 'New conversation') t.title = text.replace(/\s+/g, ' ').slice(0, 70);
    let tokens = 0;
    try { tokens = await converse(t, user, emit); } finally { await saveThread(t, tokens); }
    return T.threads().get(id);
  }
  async function confirm(id, b, user, emit = () => {}) {
    await ensureLlm();
    const t = await mustThread(id, user);
    if (!t.pending) throw fail('Nothing is waiting for confirmation', 409);
    const approve = b.approve === true;
    const who = { name: user.name, id: user.id };
    for (const c of t.pending.calls) {
      if (!approve) { t.messages.push({ role: 'tool', tool_call_id: c.id, name: c.name, args: c.args, ok: false, content: `The analyst declined this action${b.note ? `: ${str(b.note, 300)}` : ''}.`, at: new Date().toISOString() }); continue; }
      emit({ type: 'tool', name: c.name, args: c.args, status: 'running' });
      const r = await callTool(c.name, c.args, who);
      const msg = { role: 'tool', tool_call_id: c.id, name: c.name, args: c.args, ok: r.ok, ms: r.ms, confirmed_by: user.name, content: r.text, at: new Date().toISOString() };
      t.messages.push(msg);
      emit({ type: 'tool', name: c.name, args: c.args, status: r.ok ? 'ok' : 'error', ms: r.ms, message: msg });
    }
    await audit(who, approve ? 'assistant.approved' : 'assistant.declined', t.thread_id, t.pending.calls.map((c) => c.name).join(', '));
    t.pending = null;
    let tokens = 0;
    try { tokens = await converse(t, user, emit); } finally { await saveThread(t, tokens); }
    return T.threads().get(id);
  }
  async function renameThread(id, b, user) {
    await mustThread(id, user);
    const title = str(b.title, 120);
    if (title.length < 2) throw fail('Give the conversation a title');
    return T.threads().update(id, { title });
  }
  async function deleteThread(id, user) {
    await mustThread(id, user);
    await T.threads().remove(id);
    return { deleted: id };
  }

  // ---- Decisions log ----------------------------------------------------------------------
  const family = (e) => (!e ? 'unknown' : /fallback/.test(e) ? 'playbook (llm fallback)' : /^llm:/.test(e) ? 'llm' : e);
  const band = (c) => (c == null ? 'n/a' : c >= 90 ? '90-100' : c >= 75 ? '75-89' : c >= 50 ? '50-74' : '0-49');

  // Ground truth for one decision: an analyst override wins; otherwise the
  // majority of analyst feedback. Null when nobody has judged it.
  function judge(inv, fb) {
    const o = inv.human_override;
    const predicted = o ? o.previous_outcome : inv.outcome;
    if (o) return { predicted, actual: o.outcome, correct: o.previous_outcome === o.outcome, source: 'override' };
    if (!fb.length) return { predicted, actual: null, correct: null, source: null };
    const yes = fb.filter((f) => f.correct).length;
    if (yes * 2 === fb.length) return { predicted, actual: null, correct: null, source: 'split' };
    const correct = yes * 2 > fb.length;
    const wrong = fb.filter((f) => !f.correct && f.correct_outcome).map((f) => f.correct_outcome);
    return { predicted, actual: correct ? predicted : wrong[0] || null, correct, source: 'feedback' };
  }

  async function decisions({ days = 30, engine, judged, limit = 300 } = {}) {
    const d = Math.min(Math.max(Number(days) || 30, 1), 365);
    const since = new Date(Date.now() - d * 86400000).toISOString();
    const [invs, fbAll] = await Promise.all([store.investigations.list({ since, lite: true, limit: 5000 }), T.feedback().list({ limit: 20000 })]);
    const fbBy = fbAll.reduce((m, f) => m.set(f.investigation_id, [...(m.get(f.investigation_id) || []), f]), new Map());
    const rows = invs.map((i) => {
      const fb = fbBy.get(i.investigation_id) || [];
      const j = judge(i, fb);
      const ratings = fb.map((f) => f.rating).filter((x) => x != null);
      return {
        investigation_id: i.investigation_id, alert_id: i.alert_id, created_at: i.created_at, engine: i.engine, family: family(i.engine),
        outcome: i.outcome, predicted: j.predicted, actual: j.actual, correct: j.correct, judged_by: j.source, confidence: i.confidence,
        attacker_ip: i.attacker_ip, target_ip: i.target_ip, mitre_technique: i.mitre_technique, summary: i.summary, duration_ms: i.duration_ms,
        override: i.human_override || null, feedback: fb.map((f) => ({ analyst: f.analyst, correct: f.correct, correct_outcome: f.correct_outcome, rating: f.rating, notes: f.notes, at: f.updated_at || f.created_at })),
        rating: ratings.length ? Math.round((ratings.reduce((a, b) => a + b, 0) / ratings.length) * 10) / 10 : null
      };
    });
    const stat = (list) => {
      const j = list.filter((r) => r.correct !== null);
      const ok = j.filter((r) => r.correct).length;
      return { decisions: list.length, judged: j.length, correct: ok, accuracy: j.length ? Math.round((ok / j.length) * 1000) / 10 : null, coverage: list.length ? Math.round((j.length / list.length) * 1000) / 10 : null };
    };
    const engines = [...new Set(rows.map((r) => r.family))].map((f) => ({ engine: f, ...stat(rows.filter((r) => r.family === f)) }));
    // Calibration: within each confidence band, how often the engine was right.
    const bands = ['90-100', '75-89', '50-74', '0-49'].map((b) => ({ band: b, ...stat(rows.filter((r) => band(r.confidence) === b)) }));
    const confusion = {};
    for (const r of rows) if (r.correct !== null && r.actual) { const k = `${r.predicted}>${r.actual}`; confusion[k] = (confusion[k] || 0) + 1; }
    const mistakes = Object.entries(confusion).filter(([k]) => k.split('>')[0] !== k.split('>')[1]).map(([k, n]) => ({ predicted: k.split('>')[0], actual: k.split('>')[1], count: n })).sort((a, b) => b.count - a.count);
    let list = rows;
    if (engine) list = list.filter((r) => r.family === engine);
    if (judged === 'yes') list = list.filter((r) => r.correct !== null);
    if (judged === 'no') list = list.filter((r) => r.correct === null);
    if (judged === 'wrong') list = list.filter((r) => r.correct === false);
    return { days: d, totals: stat(rows), engines, bands, mistakes, outcomes: OUTCOMES, rows: list.slice(0, Math.min(Number(limit) || 300, 1000)) };
  }

  async function giveFeedback(invId, b, user) {
    const inv = await store.investigations.get(invId);
    if (!inv) throw fail('Investigation not found', 404);
    if (typeof b.correct !== 'boolean') throw fail('Say whether the verdict was correct (correct: true or false)');
    const predicted = inv.human_override ? inv.human_override.previous_outcome : inv.outcome;
    let correctOutcome = null;
    if (!b.correct) {
      correctOutcome = String(b.correct_outcome || '').toUpperCase();
      if (!OUTCOMES.includes(correctOutcome)) throw fail(`Pick the right outcome: ${OUTCOMES.join(', ')}`);
      if (correctOutcome === predicted) throw fail('That is the outcome the engine gave; mark it correct instead');
    }
    let rating = null;
    if (b.rating !== undefined && b.rating !== null && b.rating !== '') {
      rating = Number(b.rating);
      if (!Number.isInteger(rating) || rating < 1 || rating > 5) throw fail('Rating is 1-5');
    }
    const row = { investigation_id: invId, alert_id: inv.alert_id, engine: inv.engine, outcome: predicted, confidence: inv.confidence, correct: b.correct, correct_outcome: correctOutcome, rating, notes: str(b.notes, 1000) || null, analyst: user.name, analyst_id: user.id || null };
    const [mine] = await T.feedback().list({ eq: { investigation_id: invId, analyst: user.name }, limit: 1 });
    const saved = mine ? await T.feedback().update(mine.id, row) : await T.feedback().insert(row);
    await audit({ name: user.name }, 'decision.feedback', invId, `${b.correct ? 'correct' : `wrong, should be ${correctOutcome}`}${rating ? `, rated ${rating}/5` : ''}`);
    return saved;
  }

  async function decision(invId) {
    const inv = await store.investigations.get(invId);
    if (!inv) throw fail('Investigation not found', 404);
    const fb = await T.feedback().list({ eq: { investigation_id: invId }, limit: 100 });
    return { investigation: inv, feedback: fb, judgement: judge(inv, fb) };
  }
  // ---- Documents ------------------------------------------------------------------------
  const DOC_MAX = 5 * 1024 * 1024;
  const KEEP_CONTENT = 1024 * 1024;
  const TEXT_EXT = /\.(txt|log|csv|tsv|json|jsonl|ndjson|xml|yml|yaml|md|ioc|rules|conf|ini|eml|html?|evtx\.txt)$/i;

  function references(text) {
    const uniq = (re, f = (x) => x) => [...new Set([...text.matchAll(re)].map((m) => f(m[0])))];
    return {
      cves: uniq(/\bCVE-\d{4}-\d{4,7}\b/gi, (x) => x.toUpperCase()).slice(0, 200),
      techniques: uniq(/\bT1\d{3}(?:\.\d{3})?\b/g).slice(0, 200),
      emails: uniq(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b/gi, (x) => x.toLowerCase()).slice(0, 200),
      bitcoin: uniq(/\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g).filter((x) => x.startsWith('bc1') || /[a-z]/.test(x) && /[A-Z]/.test(x) && /\d/.test(x)).slice(0, 50),
      registry: uniq(/\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s"'<>]+/g).slice(0, 100)
    };
  }

  // Pure analysis, used by the upload route and the MCP tool. Nothing is stored.
  async function analyzeText(text) {
    const iocs = extractAll(text, { max: 500 });
    const refs = references(text);
    const known = [];
    for (const id of refs.cves.slice(0, 60)) {
      const c = await store.cves.get(id).catch(() => null);
      if (c) known.push({ cve_id: c.cve_id, cvss_score: c.cvss_score, severity: c.severity, kev: Boolean(c.kev), title: c.title });
    }
    const by = iocs.reduce((m, i) => ({ ...m, [i.type]: (m[i.type] || 0) + 1 }), {});
    return { iocs: iocs.map((i) => ({ type: i.type, value: i.value, ...(isIpType(i.type) ? { internal: isInternal(i.value) } : {}) })), by_type: by, refs: { ...refs, known_cves: known } };
  }

  async function uploadDocument(b, who) {
    const name = str(b.name, 200).replace(/[\\/]/g, '_');
    if (!name) throw fail('The file needs a name');
    if (typeof b.content !== 'string' || !b.content.length) throw fail('The file is empty');
    const buf = Buffer.from(b.content, 'utf8');
    if (buf.length > DOC_MAX) throw fail('Files are limited to 5 MB', 413);
    if (/\u0000/.test(b.content.slice(0, 65536))) throw fail('That looks like a binary file. Upload text: logs, CSV, JSON, reports, e-mail sources or IOC lists.', 415);
    if (!TEXT_EXT.test(name) && !/^text\/|json|xml|csv/.test(String(b.mime || ''))) throw fail('Supported files: .txt .log .csv .tsv .json .jsonl .xml .yaml .md .eml .html .ioc', 415);
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const [dupe] = await T.docs().list({ eq: { sha256 }, limit: 1, omit: ['content'], select: 'doc_id,name,created_at' });
    const a = await analyzeText(b.content);
    let intel = null;
    if (b.check && a.iocs.length) {
      const external = a.iocs.filter((i) => i.type !== 'asn' && !i.internal).map((i) => i.value);
      intel = external.length ? await lookupMany(external) : null;
    }
    const caseId = str(b.case_id, 60) || null;
    if (caseId && !(await store.cases.get(caseId))) throw fail(`Case ${caseId} does not exist`, 404);
    const doc = await T.docs().insert({
      doc_id: newId('DOC'), name, mime: str(b.mime, 100) || null, size_bytes: buf.length, sha256, lines: b.content.split(/\r?\n/).length,
      content: b.content.length > KEEP_CONTENT ? b.content.slice(0, KEEP_CONTENT) : b.content, truncated: b.content.length > KEEP_CONTENT,
      iocs: a.iocs, refs: { ...a.refs, by_type: a.by_type }, intel, case_id: null, uploaded_by: who.name
    });
    await audit(who, 'document.uploaded', doc.doc_id, `${name} (${buf.length} bytes, ${plural(a.iocs.length, 'indicator')})`);
    const out = caseId ? await attachDocument(doc.doc_id, { case_id: caseId }, who) : doc;
    return { ...out, duplicate_of: dupe ? dupe.doc_id : null };
  }

  async function mustDoc(id) {
    const d = await T.docs().get(id);
    if (!d) throw fail('Document not found', 404);
    return d;
  }
  async function listDocuments() {
    return T.docs().list({ limit: 300, omit: ['content'], select: 'doc_id,name,mime,size_bytes,sha256,lines,truncated,iocs,refs,intel,case_id,uploaded_by,created_at,updated_at' });
  }
  async function checkDocument(id, who) {
    const d = await mustDoc(id);
    const external = (d.iocs || []).filter((i) => i.type !== 'asn' && !i.internal).map((i) => i.value);
    if (!external.length) throw fail('The document has no external indicators to check');
    const intel = await lookupMany(external);
    await audit(who, 'document.checked', id, `${intel.checked} checked, ${intel.malicious.length} malicious`);
    return T.docs().update(id, { intel });
  }
  async function attachDocument(id, b, who) {
    const d = await mustDoc(id);
    const caseId = str(b.case_id, 60);
    const c = await store.cases.get(caseId);
    if (!c) throw fail('Case not found', 404);
    if (c.status === 'CLOSED') throw fail('The case is closed; reopen it first', 409);
    const only = b.only === 'flagged' && d.intel ? new Set(d.intel.flagged) : null;
    const values = (d.iocs || []).filter((i) => i.type !== 'asn' && !i.internal && (!only || only.has(i.value))).map((i) => i.value).slice(0, 200);
    let added = 0; let duplicates = 0;
    if (values.length) { const r = await svc.addIocs(caseId, { values, note: `From document ${d.name} (${d.doc_id})` }, who); added = r.added.length; duplicates = r.duplicates; }
    await svc.addEvent(caseId, { kind: 'evidence', title: `Document ${d.name}`, body: `${d.name}\nSHA-256 ${d.sha256}\n${d.size_bytes} bytes, ${d.lines} lines, ${plural((d.iocs || []).length, 'indicator')}\nUploaded by ${d.uploaded_by} as ${d.doc_id}` }, who);
    const next = await T.docs().update(id, { case_id: caseId });
    return { ...next, attached: { case_id: caseId, added, duplicates } };
  }
  async function deleteDocument(id, who) {
    const d = await mustDoc(id);
    await T.docs().remove(id);
    await audit(who, 'document.deleted', id, d.name);
    return { deleted: id };
  }

  // ---- Custom detection rules ------------------------------------------------------------------
  const lintOut = (r) => ({ ok: r.ok, errors: r.errors, warnings: r.warnings, rule: r.rule ? { title: r.rule.title, level: r.rule.level, target: r.rule.target, service: r.rule.service, technique: r.rule.technique, tactic: r.rule.tactic } : null });

  async function listCustom() { return T.rules().list({ limit: 500, order: 'updated_at' }); }
  async function mustRule(id) {
    const r = await T.rules().get(id);
    if (!r) throw fail('Rule not found', 404);
    return r;
  }
  async function saveCustom(b, who, id = null) {
    const prev = id ? await mustRule(id) : null;
    const text = b.yaml !== undefined ? String(b.yaml) : prev && prev.yaml;
    const r = lintRule(text, id || 'new');
    if (!r.ok) throw Object.assign(fail(`The rule does not lint: ${r.errors[0]}`), { lint: lintOut(r) });
    const row = { title: r.rule.title, yaml: text, level: r.rule.level, technique: r.rule.technique, target: r.rule.target, ...(b.enabled !== undefined ? { enabled: Boolean(b.enabled) } : {}) };
    let saved;
    if (prev) { saved = await T.rules().update(id, { ...row, updated_by: who.name }); await audit(who, 'detection.updated', id, row.title); }
    else { saved = await T.rules().insert({ rule_id: newId('CR'), ...row, enabled: b.enabled !== false, hits: 0, created_by: who.name, updated_by: who.name }); await audit(who, 'detection.created', saved.rule_id, row.title); }
    customRules.invalidate();
    return { ...saved, lint: lintOut(r) };
  }
  async function deleteCustom(id, who) {
    const r = await mustRule(id);
    await T.rules().remove(id);
    customRules.invalidate();
    await audit(who, 'detection.deleted', id, r.title);
    return { deleted: id };
  }

  // Dry run of one rule: over pasted lines, or backtest over stored logs.
  async function testCustom(b) {
    const text = b.rule_id ? (await mustRule(b.rule_id)).yaml : String(b.yaml || '');
    const r = lintRule(text, b.rule_id || 'draft');
    if (!r.ok) return { lint: lintOut(r), matches: [], parsed: 0 };
    let logs = []; let rejected = 0; let source;
    const lines = String(b.lines || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (lines.length) {
      if (lines.length > 5000) throw fail('At most 5000 lines per test');
      const host = str(b.host_ip, 64) || '10.0.0.10';
      if (!isIP(host)) throw fail('host_ip must be an IP address');
      lines.forEach((l, i) => {
        const x = normalizeLog(l, { host_ip: host, log_type: b.log_type || undefined });
        if (x.error) rejected += 1; else logs.push({ ...x.log, id: i + 1, logged_at: x.log.logged_at || new Date().toISOString() });
      });
      source = 'pasted';
    } else {
      const hours = Math.min(Math.max(Number(b.hours) || 168, 1), 2160);
      logs = await store.logs.list({ since: new Date(Date.now() - hours * 3600000).toISOString(), limit: 20000 });
      source = `stored logs, last ${hours} h`;
    }
    const t0 = Date.now();
    const matches = scanWith([{ ...r.rule, id: b.rule_id || 'draft' }], logs);
    return {
      lint: lintOut(r), source, parsed: logs.length, rejected, ms: Date.now() - t0, hits: matches.length,
      matches: matches.slice(0, 100).map((m) => ({ logged_at: m.log.logged_at, host_ip: m.log.host_ip, client_ip: m.log.client_ip || null, log_type: m.log.log_type, line: String(m.log.raw_entry).slice(0, 500) }))
    };
  }

  // ---- Jira -----------------------------------------------------------------------------------
  const jiraCfg = () => {
    const url = String(env.JIRA_URL || '').replace(/\/+$/, '');
    if (!url || !env.JIRA_EMAIL || !env.JIRA_API_TOKEN || !env.JIRA_PROJECT) return null;
    return { url, auth: `Basic ${Buffer.from(`${env.JIRA_EMAIL}:${env.JIRA_API_TOKEN}`).toString('base64')}`, project: env.JIRA_PROJECT, type: env.JIRA_ISSUE_TYPE || 'Task' };
  };
  async function jiraFetch(cfg, path, init = {}) {
    let res;
    try {
      res = await fetch(`${cfg.url}${path}`, { ...init, headers: { Authorization: cfg.auth, Accept: 'application/json', 'Content-Type': 'application/json', ...(init.headers || {}) }, signal: AbortSignal.timeout(12000) });
    } catch (err) { throw fail(`Jira did not answer: ${err.name === 'TimeoutError' ? 'timed out' : err.message}`, 502); }
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      const why = [...(body.errorMessages || []), ...Object.entries(body.errors || {}).map(([k, v]) => `${k}: ${v}`)].join('; ') || `HTTP ${res.status}`;
      throw fail(`Jira rejected the request: ${why}`, res.status === 401 || res.status === 403 ? 502 : 400);
    }
    return body;
  }
  const adf = (paras) => ({ type: 'doc', version: 1, content: paras.filter(Boolean).map((p) => ({ type: 'paragraph', content: [{ type: 'text', text: String(p).slice(0, 30000) }] })) });

  async function jiraCreate(caseId, who, origin) {
    const cfg = jiraCfg();
    if (!cfg) throw fail('Jira is not configured. Set JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN and JIRA_PROJECT on the server.', 503);
    const full = await svc.getCase(caseId);
    const c = full.case;
    if (c.jira && c.jira.key) throw fail(`Already linked to ${c.jira.key}`, 409);
    const link = `${env.PUBLIC_URL || origin}/#/cases/${c.case_id}`;
    const body = await jiraFetch(cfg, '/rest/api/3/issue', {
      method: 'POST',
      body: JSON.stringify({
        fields: {
          project: { key: cfg.project }, issuetype: { name: cfg.type }, summary: `[${c.severity}] ${c.title} (${c.case_id})`.slice(0, 250),
          labels: ['aegis', `severity-${c.severity.toLowerCase()}`],
          description: adf([
            c.description || 'No description.',
            `Status: ${c.status}. Owner: ${c.assignee_name || 'unassigned'}. ATT&CK: ${(c.mitre || []).join(', ') || 'none'}.`,
            `${plural(full.alerts.length, 'alert')}, ${plural(full.iocs.length, 'indicator')}, ${plural(full.tasks.filter((t) => t.status === 'TODO' || t.status === 'DOING').length, 'open task')}.`,
            full.iocs.length ? `Indicators: ${full.iocs.slice(0, 40).map((i) => `${i.value}${i.verdict ? ` (${i.verdict})` : ''}`).join(', ')}` : null,
            `Aegis case: ${link}`
          ])
        }
      })
    });
    const jira = { key: body.key, id: body.id, url: `${cfg.url}/browse/${body.key}`, created_by: who.name, created_at: new Date().toISOString() };
    await store.cases.update(caseId, { jira });
    await svc.addEvent(caseId, { kind: 'comment', body: `Jira issue ${body.key} created: ${jira.url}` }, who);
    await audit(who, 'case.jira', caseId, body.key);
    return jira;
  }
  async function jiraStatus(caseId) {
    const c = await store.cases.get(caseId);
    if (!c) throw fail('Case not found', 404);
    if (!c.jira || !c.jira.key) throw fail('This case has no Jira issue', 404);
    if (c.jira.manual) return c.jira;
    const cfg = jiraCfg();
    if (!cfg) throw fail('Jira is not configured on this server', 503);
    const body = await jiraFetch(cfg, `/rest/api/3/issue/${encodeURIComponent(c.jira.key)}?fields=status,assignee,updated,resolution`);
    const f = body.fields || {};
    const jira = { ...c.jira, status: f.status ? f.status.name : null, category: f.status && f.status.statusCategory ? f.status.statusCategory.key : null, assignee: f.assignee ? f.assignee.displayName : null, resolution: f.resolution ? f.resolution.name : null, synced_at: new Date().toISOString() };
    await store.cases.update(caseId, { jira });
    return jira;
  }

  // Link an existing ticket from any tracker (Jira, ServiceNow, GitHub...) by key and URL.
  // Stored in the same jira column with manual: true, so no tracker credentials are needed.
  async function linkTicket(caseId, input, who) {
    const c = await store.cases.get(caseId);
    if (!c) throw fail('Case not found', 404);
    const key = str(input.key, 80);
    const url = str(input.url, 500);
    const system = str(input.system, 40) || 'Ticket';
    if (!/^[\w.#:\/-]{2,80}$/.test(key)) throw fail('Ticket key must be 2-80 characters: letters, digits, - _ . # : /');
    if (url && !/^https?:\/\/[^\s]+$/i.test(url)) throw fail('Ticket URL must start with http:// or https://');
    if (c.jira && c.jira.key && !c.jira.manual) throw fail(`Already linked to ${c.jira.key}`, 409);
    const jira = { key, url: url || null, system, manual: true, status: str(input.status, 40) || null, created_by: who.name, created_at: new Date().toISOString() };
    await store.cases.update(caseId, { jira });
    await svc.addEvent(caseId, { kind: 'comment', body: `${system} ticket ${key} linked${url ? `: ${url}` : ''}` }, who);
    await audit(who, 'case.ticket', caseId, `${system} ${key}`);
    return jira;
  }
  async function unlinkTicket(caseId, who) {
    const c = await store.cases.get(caseId);
    if (!c) throw fail('Case not found', 404);
    if (!c.jira || !c.jira.key) throw fail('This case has no linked ticket', 404);
    await store.cases.update(caseId, { jira: null });
    await svc.addEvent(caseId, { kind: 'comment', body: `Ticket ${c.jira.key} unlinked` }, who);
    await audit(who, 'case.ticket', caseId, `unlinked ${c.jira.key}`);
    return { ok: true };
  }

  // ---- Backup and restore ---------------------------------------------------------------------
  const SB = store.kind === 'supabase';
  const TABLES = [
    ['assets', 'ip_address'], ['cves', 'cve_id'], ['alerts', 'alert_id'], ['investigations', 'investigation_id'], [SB ? 'firewall_rules' : 'rules', 'rule_id', 'rules'],
    ['alert_notes', 'id'], ['suppressions', 'id'], ['cases', 'case_id'], ['case_alerts', 'id'], ['case_tasks', 'id'], ['case_iocs', 'id'], ['case_events', 'id'],
    ['approvals', 'approval_id'], ['hunts', 'hunt_id'], ['hunt_runs', 'id'],
    ['workflows', 'workflow_id', null, true], ['workflow_runs', 'run_id', null, true], ['documents', 'doc_id', null, true], ['decision_feedback', 'id', null, true], ['custom_rules', 'rule_id', null, true], ['chat_threads', 'thread_id', null, true],
    [SB ? 'audit_log' : 'audit', 'id', 'audit'], [SB ? 'server_logs' : 'logs', 'id', 'logs']
  ].map(([table, key, alias, extra]) => ({ table, key, name: alias || table, extra: Boolean(extra) }));
  const USER_FK = ['assignee_id', 'author_id', 'analyst_id'];

  async function backup(who, { logs = false } = {}) {
    const out = { format: 'aegis-backup', version: 1, created_at: new Date().toISOString(), created_by: who.name, store: store.kind, tables: {}, counts: {} };
    for (const t of TABLES) {
      if (t.extra && store.pendingExtras) continue;
      if (t.name === 'logs' && !logs) continue;
      if (store.pending && /^(cases|case_|approvals|hunt)/.test(t.name)) continue;
      let rows = await store.coll(t.table, t.key).all();
      if (t.name === 'logs' || t.name === 'audit') rows = rows.sort((a, b) => Number(b.id) - Number(a.id)).slice(0, 20000);
      out.tables[t.name] = rows;
      out.counts[t.name] = rows.length;
    }
    const cfg = await store.config.get();
    // Webhook URLs, routing keys and the model key are credentials; they are not exported.
    out.config = { ...cfg, notifyChannels: undefined, llmProvider: undefined, intelKeys: undefined };
    out.users = (await store.users.list()).map((u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, disabled: u.disabled }));
    await audit(who, 'backup.exported', 'platform', Object.entries(out.counts).map(([k, n]) => `${k}:${n}`).join(' ').slice(0, 280));
    return out;
  }

  async function restore(b, who) {
    if (!b || b.format !== 'aegis-backup') throw fail('That is not an Aegis backup file');
    if (b.version !== 1) throw fail(`Backup version ${b.version} is not supported by this server`);
    if (!b.tables || typeof b.tables !== 'object') throw fail('The backup has no tables');
    const known = new Map(TABLES.map((t) => [t.name, t]));
    const unknown = Object.keys(b.tables).filter((k) => !known.has(k));
    if (unknown.length) throw fail(`Unknown tables in backup: ${unknown.join(', ')}`);
    const users = new Set((await store.users.list()).map((u) => String(u.id)));
    const restored = {}; const skipped = {};
    for (const t of TABLES) {
      const rows = b.tables[t.name];
      if (rows === undefined) continue;
      if (!Array.isArray(rows)) throw fail(`${t.name} must be a list of rows`);
      if (rows.length > 200000) throw fail(`${t.name} has too many rows`);
      if (t.extra && store.pendingExtras) { skipped[t.name] = rows.length; continue; }
      const good = [];
      for (const r of rows) {
        if (!r || typeof r !== 'object' || Array.isArray(r) || r[t.key] === undefined || r[t.key] === null) throw fail(`A row in ${t.name} has no ${t.key}`);
        const row = { ...r };
        for (const k of USER_FK) if (row[k] != null && !users.has(String(row[k]))) row[k] = null;
        if (t.name === 'chat_threads' && !users.has(String(row.user_id))) continue;
        good.push(row);
      }
      if (good.length) await store.coll(t.table, t.key).put(good);
      restored[t.name] = good.length;
      if (good.length < rows.length) skipped[t.name] = rows.length - good.length;
    }
    if (b.config && typeof b.config === 'object') {
      const { notifyChannels, llmProvider, intelKeys, ...rest } = b.config;
      await store.config.set(rest);
    }
    if (store.afterRestore) await store.afterRestore();
    customRules.invalidate();
    await audit(who, 'backup.restored', 'platform', Object.entries(restored).map(([k, n]) => `${k}:${n}`).join(' ').slice(0, 280));
    return { restored, skipped, note: 'Users, API keys, notification channels and the model provider are never restored from a file; they stay as they are on this server.' };
  }

  // ---- Status ---------------------------------------------------------------------------------
  async function integrations() {
    const l = await investigator.llmStatus();
    return {
      assistant: l.llm, model: l.model, provider: l.provider,
      jira: Boolean(jiraCfg()), jira_project: jiraCfg() ? env.JIRA_PROJECT : null,
      otx: Boolean(hub && hub.otx && hub.otx.available), otx_key: Boolean(env.OTX_API_KEY), hybrid_analysis: Boolean(hub && hub.ha && hub.ha.available),
      pagerduty: true, pending_migration: store.pendingExtras ? store.pendingExtras.migration : null
    };
  }

  return {
    TEMPLATES, STEP_TYPES, integrations,
    listWorkflows: () => T.workflows().list({ limit: 200, order: 'updated_at' }), getWorkflow: mustWorkflow, saveWorkflow, setEnabled, deleteWorkflow, startRun, runWorkflow,
    listRuns: (q = {}) => T.runs().list({ eq: q.workflow_id ? { workflow_id: q.workflow_id } : {}, limit: Math.min(Number(q.limit) || 50, 200) }),
    getRun: async (id) => { const r = await T.runs().get(id); if (!r) throw fail('Run not found', 404); return r; },
    ensureLlm, mustThread, listThreads, createThread, sendMessage, confirm, renameThread, deleteThread,
    decisions, decision, giveFeedback,
    analyzeText, uploadDocument, listDocuments, getDocument: mustDoc, checkDocument, attachDocument, deleteDocument, lookupMany,
    listCustom, getCustom: mustRule, saveCustom, deleteCustom, testCustom, lint: (text) => lintOut(lintRule(text)),
    jiraCreate, jiraStatus, linkTicket, unlinkTicket, backup, restore
  };
}

function registerWorkbench(app, ctx, svc) {
  const { wrap, bad, need, actor, store, env } = ctx;
  const wb = createWorkbench(ctx, svc);
  ctx.workbench = wb;
  const who = (req) => ({ name: actor(req), id: req.user ? req.user.id : null });
  const origin = (req) => env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`;
  const h = (fn, code = 200) => wrap(async (req, res) => {
    let out;
    try { out = await fn(req); } catch (err) {
      if (err.status) return res.status(err.status).json({ error: err.message, ...(err.lint ? { lint: err.lint } : {}) });
      throw err;
    }
    res.status(code).json(out);
  });
  const b = (req) => req.body || {};
  // Server-sent events over a POST, the same framing as /api/investigations/stream.
  const sse = (pre, fn) => wrap(async (req, res) => {
    try { if (pre) await pre(req); } catch (err) { if (err.status) return bad(res, err.message, err.status); throw err; }
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    let closed = false;
    res.on('close', () => { closed = true; });
    const send = (data) => { if (!closed) res.write(`data: ${JSON.stringify(data)}\n\n`); };
    const beat = setInterval(() => { if (!closed) res.write(': keep-alive\n\n'); }, 10000);
    try { send({ type: 'done', result: await fn(req, send) }); } catch (err) {
      if (!err.status) console.error(err);
      send({ type: 'error', message: err.status ? err.message : 'Internal error', status: err.status || 500 });
    } finally { clearInterval(beat); res.end(); }
  });
  const pending = (req, res, next) => (store.pendingExtras ? bad(res, `This feature needs the ${store.pendingExtras.migration} migration. Apply it to the database and reload.`, 503) : next());
  app.use(['/api/assistant', '/api/workflows', '/api/decisions', '/api/documents', '/api/detections/custom', '/api/cases/:id/jira', '/api/cases/:id/ticket'], pending);

  app.get('/api/workbench/status', h(() => wb.integrations()));

  // Assistant
  app.get('/api/assistant/threads', h((req) => wb.listThreads(req.user)));
  app.post('/api/assistant/threads', h((req) => wb.createThread(req.user), 201));
  app.get('/api/assistant/threads/:id', h((req) => wb.mustThread(req.params.id, req.user)));
  app.patch('/api/assistant/threads/:id', h((req) => wb.renameThread(req.params.id, b(req), req.user)));
  app.delete('/api/assistant/threads/:id', h((req) => wb.deleteThread(req.params.id, req.user)));
  app.post('/api/assistant/threads/:id/messages', h((req) => wb.sendMessage(req.params.id, b(req), req.user)));
  app.post('/api/assistant/threads/:id/messages/stream', sse(async (req) => { await wb.ensureLlm(); await wb.mustThread(req.params.id, req.user); }, (req, send) => wb.sendMessage(req.params.id, b(req), req.user, send)));
  app.post('/api/assistant/threads/:id/confirm/stream', need('respond'), sse(async (req) => { await wb.ensureLlm(); await wb.mustThread(req.params.id, req.user); }, (req, send) => wb.confirm(req.params.id, b(req), req.user, send)));
  app.post('/api/assistant/threads/:id/confirm', need('respond'), h((req) => wb.confirm(req.params.id, b(req), req.user)));

  // Workflows
  app.get('/api/workflows/catalog', h(() => ({ steps: wb.STEP_TYPES, templates: wb.TEMPLATES, operators: WHEN_OPS })));
  app.get('/api/workflows', h(() => wb.listWorkflows()));
  app.post('/api/workflows', need('respond'), h((req) => wb.saveWorkflow(b(req), who(req)), 201));
  app.get('/api/workflows/runs', h((req) => wb.listRuns(req.query)));
  app.get('/api/workflows/runs/:id', h((req) => wb.getRun(req.params.id)));
  app.get('/api/workflows/:id', h((req) => wb.getWorkflow(req.params.id)));
  app.put('/api/workflows/:id', need('respond'), h((req) => wb.saveWorkflow(b(req), who(req), req.params.id)));
  app.post('/api/workflows/:id/enabled', need('respond'), h((req) => wb.setEnabled(req.params.id, b(req).enabled !== false, who(req))));
  app.delete('/api/workflows/:id', need('respond'), h((req) => wb.deleteWorkflow(req.params.id, who(req))));
  app.post('/api/workflows/:id/run', need('respond'), h((req) => wb.startRun(req.params.id, b(req).input || {}, who(req))));
  app.post('/api/workflows/:id/run/stream', need('respond'), sse(async (req) => { await wb.getWorkflow(req.params.id); }, (req, send) => wb.startRun(req.params.id, b(req).input || {}, who(req), send)));

  // Decisions
  app.get('/api/decisions', h((req) => wb.decisions(req.query)));
  app.get('/api/decisions/:id', h((req) => wb.decision(req.params.id)));
  app.post('/api/decisions/:id/feedback', need('respond'), h((req) => wb.giveFeedback(req.params.id, b(req), req.user)));

  // Documents
  const docJson = express.json({ limit: '6mb' });
  app.get('/api/documents', h(() => wb.listDocuments()));
  app.post('/api/documents', need('respond'), docJson, h((req) => wb.uploadDocument(b(req), who(req)), 201));
  app.post('/api/documents/analyze', h(async (req) => { const t = String(b(req).text || ''); if (!t.trim()) throw fail('Paste some text'); return wb.analyzeText(t.slice(0, 200000)); }));
  app.get('/api/documents/:id', h((req) => wb.getDocument(req.params.id)));
  app.post('/api/documents/:id/check', need('respond'), h((req) => wb.checkDocument(req.params.id, who(req))));
  app.post('/api/documents/:id/attach', need('respond'), h((req) => wb.attachDocument(req.params.id, b(req), who(req))));
  app.delete('/api/documents/:id', need('respond'), h((req) => wb.deleteDocument(req.params.id, who(req))));

  // Custom detections
  app.get('/api/detections/custom', h(() => wb.listCustom()));
  app.post('/api/detections/custom/lint', h((req) => wb.lint(b(req).yaml)));
  app.post('/api/detections/custom/test', h((req) => wb.testCustom(b(req))));
  app.post('/api/detections/custom', need('respond'), h((req) => wb.saveCustom(b(req), who(req)), 201));
  app.get('/api/detections/custom/:id', h((req) => wb.getCustom(req.params.id)));
  app.put('/api/detections/custom/:id', need('respond'), h((req) => wb.saveCustom(b(req), who(req), req.params.id)));
  app.delete('/api/detections/custom/:id', need('respond'), h((req) => wb.deleteCustom(req.params.id, who(req))));

  // Jira
  app.post('/api/cases/:id/jira', need('respond'), h((req) => wb.jiraCreate(req.params.id, who(req), origin(req)), 201));
  app.get('/api/cases/:id/jira', h((req) => wb.jiraStatus(req.params.id)));
  app.put('/api/cases/:id/ticket', need('respond'), h((req) => wb.linkTicket(req.params.id, b(req), who(req))));
  app.delete('/api/cases/:id/ticket', need('respond'), h((req) => wb.unlinkTicket(req.params.id, who(req))));

  // Backup
  app.get('/api/admin/backup', need('manage'), h(async (req) => wb.backup(who(req), { logs: req.query.logs === '1' })));
  app.post('/api/admin/restore', need('manage'), express.json({ limit: '40mb' }), h((req) => wb.restore(b(req), who(req))));

  return wb;
}

module.exports = { registerWorkbench, createWorkbench, validateWorkflow, resolve, test, TEMPLATES, STEP_TYPES };