'use strict';

// Sigma rules from the SigmaHQ release, compiled and run against the telemetry
// Aegis stores. Only rules whose log source Aegis actually receives are kept:
//
//   webserver                 http_access lines (combined log format)
//   linux process_creation    edr_process lines, sudo COMMAND=, cron CMD, auditd EXECVE
//   linux auditd              raw auditd records (type=... msg=audit(...))
//   linux sshd/sudo/cron/...  keyword rules over auth_log and system lines
//
// Supported: field modifiers contains, startswith, endswith, all, re, cidr,
// exists, cased; wildcards * and ?; conditions with and/or/not, parentheses,
// "1 of x*", "all of x*", "1 of them". Rules using anything else (aggregations,
// base64offset, windash, field references) are counted as skipped, not guessed at.

const crypto = require('crypto');
const yaml = require('js-yaml');
const { FeedCache, unzip } = require('../intel/feeds');
const { cidrRange, ipv4ToInt } = require('../intel/threatintel');

const SOURCE = 'https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip';
const LEVELS = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };
const SEVERITY = { informational: 'LOW', low: 'LOW', medium: 'MEDIUM', high: 'HIGH', critical: 'CRITICAL' };
const SKIP_DIRS = /^(deprecated|unsupported|rules-placeholder|rules-threat-hunting|rules-compliance|regression_data|tests?)\//;
const SERVICE_RE = {
  sshd: /\bsshd(?:\[\d+\])?:/, sudo: /\bsudo(?:\[\d+\])?:/, cron: /\b(?:CRON|crond?)(?:\[\d+\])?:/, vsftpd: /vsftpd/i,
  clamav: /\b(?:clamd|freshclam|clamav)/i, guacamole: /guac(?:d|amole)/i, auth: null, syslog: null
};
const TACTICS = ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact', 'stealth', 'defense-impairment'];
const title = (s) => s.split('-').map((w) => w[0].toUpperCase() + w.slice(1)).join(' ').replace('And', 'and');

class Unsupported extends Error {}

// ---- Value matchers ------------------------------------------------------------
function wildcardRe(v, { anchorStart = true, anchorEnd = true } = {}) {
  let out = '';
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (c === '\\' && (v[i + 1] === '*' || v[i + 1] === '?' || v[i + 1] === '\\')) { out += `\\${v[i + 1]}`; i++; continue; }
    if (c === '*') out += '[\\s\\S]*';
    else if (c === '?') out += '[\\s\\S]';
    else out += c.replace(/[.+^${}()|[\]\\/-]/g, '\\$&');
  }
  return new RegExp(`${anchorStart ? '^' : ''}${out}${anchorEnd ? '$' : ''}`, 'i');
}
const hasWild = (v) => /(^|[^\\])[*?]/.test(v);

function valueMatcher(raw, mods) {
  if (raw === null) return { nul: true };
  if (typeof raw === 'object') throw new Unsupported('nested value');
  const cased = mods.includes('cased');
  const v = String(raw);
  if (mods.includes('re')) {
    let src = v; let flags = '';
    if (src.startsWith('(?i)')) { src = src.slice(4); flags = 'i'; }
    if (mods.includes('i')) flags = 'i';
    try { const re = new RegExp(src, flags + (mods.includes('s') ? 's' : '') + (mods.includes('m') ? 'm' : '')); return { test: (s) => re.test(s), raw: true }; } catch { throw new Unsupported('regex'); }
  }
  if (mods.includes('cidr')) {
    const r = cidrRange(v);
    if (!r) throw new Unsupported('ipv6 cidr');
    return { test: (s) => /^\d+\.\d+\.\d+\.\d+$/.test(s) && ipv4ToInt(s) >= r.start && ipv4ToInt(s) <= r.end, raw: true };
  }
  const kind = mods.includes('contains') ? 'contains' : mods.includes('startswith') ? 'starts' : mods.includes('endswith') ? 'ends' : 'eq';
  if (hasWild(v)) {
    const re = wildcardRe(v, { anchorStart: kind === 'eq' || kind === 'starts', anchorEnd: kind === 'eq' || kind === 'ends' });
    const cre = cased ? new RegExp(re.source) : re;
    return { test: (s) => cre.test(s), raw: true };
  }
  const plain = v.replace(/\\([*?\\])/g, '$1');
  const needle = cased ? plain : plain.toLowerCase();
  const raw2 = cased;
  if (kind === 'contains') return { test: (s) => s.includes(needle), raw: raw2 };
  if (kind === 'starts') return { test: (s) => s.startsWith(needle), raw: raw2 };
  if (kind === 'ends') return { test: (s) => s.endsWith(needle), raw: raw2 };
  return { test: (s) => s === needle, raw: raw2 };
}

const KNOWN_MODS = new Set(['contains', 'startswith', 'endswith', 'all', 're', 'cidr', 'exists', 'cased', 'i', 'm', 's']);

// One "field|mods: value(s)" entry.
function fieldMatcher(key, value) {
  const [field, ...mods] = key.split('|');
  for (const m of mods) if (!KNOWN_MODS.has(m)) throw new Unsupported(`modifier ${m}`);
  if (mods.includes('exists')) {
    const want = value === true || value === 'true';
    return (ev) => (ev.get(field) !== undefined) === want;
  }
  const values = (Array.isArray(value) ? value : [value]).map((v) => valueMatcher(v, mods));
  const all = mods.includes('all');
  return (ev) => {
    const got = ev.get(field);
    const test = (m) => {
      if (m.nul) return got === undefined || got.raw.every((s) => s === '');
      if (got === undefined) return false;
      const list = m.raw ? got.raw : got.low;
      for (const s of list) if (m.test(s)) return true;
      return false;
    };
    return all ? values.every(test) : values.some(test);
  };
}

// A named selection: map (AND of fields), list of maps (OR), or keyword list.
function selectionMatcher(def) {
  if (def === null || def === undefined) throw new Unsupported('empty selection');
  if (Array.isArray(def)) {
    if (def.every((x) => x !== null && typeof x === 'object' && !Array.isArray(x))) {
      const parts = def.map(selectionMatcher);
      return (ev) => parts.some((p) => p(ev));
    }
    if (def.every((x) => typeof x !== 'object')) {
      const ms = def.map((v) => valueMatcher(v, ['contains']));
      return (ev) => { const k = ev.keywords(); return ms.some((m) => k.some((s) => m.test(m.raw ? s : s.toLowerCase()))); };
    }
    throw new Unsupported('mixed selection list');
  }
  if (typeof def === 'object') {
    const entries = Object.entries(def);
    if (!entries.length) throw new Unsupported('empty map');
    const fs = entries.map(([k, v]) => {
      // "|contains" with no field name is a keyword search.
      if (k === '' || k.startsWith('|')) {
        const mods = k.split('|').filter(Boolean);
        const ms = (Array.isArray(v) ? v : [v]).map((x) => valueMatcher(x, mods.length ? mods : ['contains']));
        const all = mods.includes('all');
        return (ev) => { const kw = ev.keywords(); const t = (m) => kw.some((s) => m.test(m.raw ? s : s.toLowerCase())); return all ? ms.every(t) : ms.some(t); };
      }
      return fieldMatcher(k, v);
    });
    return (ev) => fs.every((f) => f(ev));
  }
  const m = valueMatcher(def, ['contains']);
  return (ev) => ev.keywords().some((s) => m.test(m.raw ? s : s.toLowerCase()));
}

// ---- Condition parser ----------------------------------------------------------
function compileCondition(cond, sels) {
  if (Array.isArray(cond)) {
    const parts = cond.map((c) => compileCondition(c, sels));
    return (ev) => parts.some((p) => p(ev));
  }
  const src = String(cond);
  if (src.includes('|')) throw new Unsupported('aggregation');
  const toks = src.replace(/\(/g, ' ( ').replace(/\)/g, ' ) ').trim().split(/\s+/);
  let i = 0;
  const peek = () => toks[i];
  const names = Object.keys(sels);
  const pick = (pat) => {
    if (pat === 'them') return names.filter((n) => !n.startsWith('_'));
    const re = wildcardRe(pat);
    return names.filter((n) => re.test(n));
  };
  const orExpr = () => {
    let left = andExpr();
    while (peek() && peek().toLowerCase() === 'or') { i++; const l = left; const r = andExpr(); left = (ev) => l(ev) || r(ev); }
    return left;
  };
  const andExpr = () => {
    let left = notExpr();
    while (peek() && peek().toLowerCase() === 'and') { i++; const l = left; const r = notExpr(); left = (ev) => l(ev) && r(ev); }
    return left;
  };
  const notExpr = () => {
    if (peek() && peek().toLowerCase() === 'not') { i++; const inner = notExpr(); return (ev) => !inner(ev); }
    return primary();
  };
  const primary = () => {
    const t = toks[i++];
    if (t === undefined) throw new Unsupported('truncated condition');
    if (t === '(') { const e = orExpr(); if (toks[i++] !== ')') throw new Unsupported('unbalanced condition'); return e; }
    const q = t.toLowerCase();
    if ((q === '1' || q === 'any' || q === 'all') && toks[i] && toks[i].toLowerCase() === 'of') {
      i++;
      const list = pick(toks[i++] || '');
      if (!list.length) throw new Unsupported('quantifier matched nothing');
      const fns = list.map((n) => sels[n]);
      return q === 'all' ? (ev) => fns.every((f) => f(ev)) : (ev) => fns.some((f) => f(ev));
    }
    if (!sels[t]) throw new Unsupported(`unknown selection ${t}`);
    return sels[t];
  };
  const fn = orExpr();
  if (i !== toks.length) throw new Unsupported('trailing tokens in condition');
  return fn;
}

// ---- Log sources ----------------------------------------------------------------
function targetOf(ls) {
  if (!ls) return null;
  if (ls.category === 'webserver') return 'web';
  if (ls.product !== 'linux') return null;
  if (ls.category === 'process_creation') return 'process';
  if (ls.category) return null;
  if (ls.service === 'auditd') return 'auditd';
  if (!ls.service) return 'linux';
  return ls.service in SERVICE_RE ? `svc:${ls.service}` : null;
}

function compileRule(doc, path) {
  if (!doc || typeof doc !== 'object' || !doc.detection || !doc.logsource) return null;
  const target = targetOf(doc.logsource);
  if (!target) return null;
  if (doc.status === 'deprecated' || doc.status === 'unsupported') return null;
  const det = doc.detection;
  const sels = {};
  for (const [name, def] of Object.entries(det)) {
    if (name === 'condition' || name === 'timeframe') continue;
    sels[name] = selectionMatcher(def);
  }
  if (det.timeframe) throw new Unsupported('timeframe');
  const match = compileCondition(det.condition, sels);
  const tags = Array.isArray(doc.tags) ? doc.tags.map(String) : [];
  const tactic = tags.map((t) => t.replace(/^attack\./, '')).find((t) => TACTICS.includes(t.replace(/_/g, '-')));
  const technique = tags.map((t) => t.match(/^attack\.(t\d{4}(?:\.\d{3})?)$/i)).find(Boolean);
  const level = LEVELS[doc.level] != null ? doc.level : 'medium';
  return {
    id: String(doc.id || crypto.createHash('sha1').update(path).digest('hex').slice(0, 16)), title: String(doc.title || path).slice(0, 200),
    description: String(doc.description || '').replace(/\s+/g, ' ').trim().slice(0, 600), level, status: doc.status || null,
    author: doc.author ? String(doc.author).slice(0, 120) : null, date: doc.date ? String(doc.date) : null, modified: doc.modified ? String(doc.modified) : null,
    references: (Array.isArray(doc.references) ? doc.references : []).slice(0, 4).map(String),
    falsepositives: (Array.isArray(doc.falsepositives) ? doc.falsepositives : []).slice(0, 3).map(String),
    tactic: tactic ? title(tactic.replace(/_/g, '-')) : null, technique: technique ? technique[1].toUpperCase() : null,
    cve: (tags.find((t) => /^cve\.\d{4}-\d+/i.test(t)) || '').replace(/^cve\./i, 'CVE-') || null,
    target, service: doc.logsource.service || null, path, match
  };
}

function parseBundle(buf) {
  const rules = []; const skipped = {};
  let considered = 0; let version = null;
  for (const e of unzip(buf)) {
    const name = e.name.replace(/^[^/]*sigma[^/]*\//i, '');
    if (/(^|\/)version\.txt$/i.test(e.name)) {
      const m = e.data().toString('utf8').match(/Label:\s*(r\d{4}-\d{2}-\d{2})/);
      if (m) version = m[1];
      continue;
    }
    if (!/\.ya?ml$/i.test(name) || SKIP_DIRS.test(name)) continue;
    let doc;
    try { doc = yaml.load(e.data().toString('utf8')); } catch { continue; }
    if (!doc || !targetOf(doc.logsource)) continue;
    considered += 1;
    try {
      const r = compileRule(doc, name);
      if (r) rules.push(r);
    } catch (err) {
      const why = err instanceof Unsupported ? err.message.split(' ')[0] : 'error';
      skipped[why] = (skipped[why] || 0) + 1;
    }
  }
  return { rules, considered, skipped, version };
}

// ---- Event mapping --------------------------------------------------------------
const COMBINED_FULL = /^(\S+) \S+ (\S+) \[[^\]]*\] "(\S+) (\S+)(?: [^"]*)?" (\d{3}) \S+(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?/;
const decode = (s) => { try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return s; } };

function makeEvent(fields, keywordLines) {
  const map = new Map();
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined || v === null || v === '') continue;
    const raw = [...new Set((Array.isArray(v) ? v : [v]).map(String))];
    map.set(k, { raw, low: raw.map((s) => s.toLowerCase()) });
  }
  return { get: (f) => map.get(f), keywords: () => keywordLines, fields };
}

function webEvent(l) {
  const m = String(l.raw_entry || '').match(COMBINED_FULL);
  const uri = l.request_uri || (m ? m[4] : null);
  if (!uri && !m) return null;
  const q = uri ? uri.indexOf('?') : -1;
  const stem = uri ? (q >= 0 ? uri.slice(0, q) : uri) : null;
  const query = uri && q >= 0 ? uri.slice(q + 1) : null;
  const ua = m && m[7] && m[7] !== '-' ? m[7] : null;
  const ref = m && m[6] && m[6] !== '-' ? m[6] : null;
  const both = (s) => (s ? [s, decode(s)] : null);
  // Most SigmaHQ web rules put path fragments in cs-uri-query, so it carries the
  // whole request target; cs-uri-stem is the path alone.
  return makeEvent({
    'cs-method': l.request_method || (m ? m[3] : null), 'cs-uri-stem': both(stem), 'cs-uri-query': both(uri), 'cs-uri': both(uri), 'c-uri-query': both(query),
    'sc-status': l.status_code != null ? String(l.status_code) : m ? m[5] : null, 'cs-user-agent': ua, 'cs-referer': ref,
    'cs-username': m && m[2] !== '-' ? m[2] : null, 'c-ip': l.client_ip, 'cs-host': (String(l.raw_entry).match(/Host: (\S+)/i) || [])[1]
  }, [String(l.raw_entry), decode(String(l.raw_entry))]);
}

function auditFields(raw) {
  const out = {};
  for (const m of raw.matchAll(/\b([A-Za-z0-9_]+)=("(?:[^"\\]|\\.)*"|\S+)/g)) out[m[1]] = m[2].replace(/^"|"$/g, '');
  return out;
}

function processEvent(l) {
  const raw = String(l.raw_entry || '');
  let cmd = null; let parent = null; let user = null; let cwd = null;
  let m;
  if ((m = raw.match(/^EDR:\s*(\S+)\s*\((?:pid|ppid)[^)]*\)\s*spawned\s+(?:unexpected\s+)?(?:child\s+)?(.+?)(?:\s+as user\s+(\S+))?$/i))) { parent = m[1]; cmd = m[2]; user = m[3] || null; }
  else if ((m = raw.match(/\bsudo(?:\[\d+\])?:\s*(\S+)\s*:.*?(?:PWD=(\S+)\s*;.*?)?USER=(\S+)\s*;\s*COMMAND=(.+)$/))) { parent = 'sudo'; user = m[3]; cwd = m[2] || null; cmd = m[4]; }
  else if ((m = raw.match(/\bCRON\[\d+\]:\s*\((\S+)\)\s*CMD\s*\((.+)\)\s*$/))) { parent = 'cron'; user = m[1]; cmd = m[2]; }
  else if (/type=EXECVE\b/.test(raw)) {
    const f = auditFields(raw);
    const args = Object.keys(f).filter((k) => /^a\d+$/.test(k)).sort((a, b) => Number(a.slice(1)) - Number(b.slice(1))).map((k) => (/^[0-9A-F]+$/.test(f[k]) && f[k].length % 2 === 0 && f[k].length > 6 ? Buffer.from(f[k], 'hex').toString('utf8') : f[k]));
    cmd = args.join(' ');
  } else if ((m = raw.match(/\b(?:cmdline|command|cmd)=("([^"]*)"|\S+)/i))) cmd = m[2] || m[1];
  else if (l.log_type === 'edr_process') cmd = raw.replace(/^EDR:\s*/, '');
  if (!cmd) return null;
  const first = cmd.trim().match(/^"([^"]+)"|^(\S+)/);
  const image = first ? first[1] || first[2] : null;
  const exe = (raw.match(/\bexe="?([^"\s]+)/) || [])[1] || null;
  return makeEvent({ CommandLine: cmd.trim(), Image: exe || image, ParentImage: parent, ParentCommandLine: parent, User: user, CurrentDirectory: cwd }, [raw]);
}

// ---- Engine ---------------------------------------------------------------------
class SigmaEngine {
  constructor({ fetchImpl = globalThis.fetch, offline = false, url = SOURCE } = {}) {
    this.offline = offline;
    this.cache = new FeedCache({ fetchImpl, offline });
    this.def = { id: 'sigma', name: 'SigmaHQ rule set', provider: 'SigmaHQ', url, binary: true, ttl: 24 * 3600000, retry: 15 * 60000, timeoutMs: 60000, parse: parseBundle, size: (d) => d.rules.length, note: 'Community detection rules, compiled for the log sources Aegis receives' };
  }

  get available() { return !this.offline; }
  status() {
    const s = this.cache.status(this.def);
    const d = this.cache.state.get('sigma');
    const data = d && d.data;
    return { ...s, version: data ? data.version : null, considered: data ? data.considered : null, skipped: data ? data.skipped : null, by_target: data ? data.rules.reduce((m, r) => ({ ...m, [r.target]: (m[r.target] || 0) + 1 }), {}) : null };
  }
  async rules(budgetMs = 0) { const r = await this.cache.within(this.def, budgetMs); return r.data ? r.data.rules : null; }
  refresh() { return this.cache.load(this.def, { force: true }); }
  warm() { if (!this.offline) this.cache.load(this.def).catch(() => {}); }

  // Runs every applicable rule over the lines. Returns { matches:[{rule, log}], rules } or null when not loaded.
  async scan(logs, { budgetMs = 15000, minLevel = 'informational', disabled = [] } = {}) {
    const rules = await this.rules(budgetMs);
    if (!rules) return null;
    return { matches: scanWith(rules, logs, { minLevel, disabled }), rules: rules.length };
  }
}

function scanWith(rules, logs, { minLevel = 'informational', disabled = [] } = {}) {
  const off = new Set(disabled);
  const min = LEVELS[minLevel] ?? 0;
  const active = rules.filter((r) => LEVELS[r.level] >= min && !off.has(r.id));
  const by = { web: [], process: [], auditd: [], linux: [] };
  const svc = {};
  for (const r of active) {
    if (r.target.startsWith('svc:')) (svc[r.service] = svc[r.service] || []).push(r);
    else by[r.target].push(r);
  }
  const out = [];
  const run = (list, ev, log) => { if (!ev) return; for (const r of list) { try { if (r.match(ev)) out.push({ rule: r, log }); } catch { /* a rule that throws on odd input never fires */ } } };
  for (const l of logs) {
    const raw = String(l.raw_entry || '');
    if (l.log_type === 'http_access') { run(by.web, webEvent(l), l); continue; }
    run(by.process, processEvent(l), l);
    if (/\btype=[A-Z_]+ msg=audit\(/.test(raw)) run(by.auditd, makeEvent(auditFields(raw), [raw]), l);
    if (l.log_type === 'auth_log' || l.log_type === 'system') {
      const kw = makeEvent({}, [raw]);
      run(by.linux, kw, l);
      for (const [name, list] of Object.entries(svc)) {
        const re = SERVICE_RE[name];
        const applies = re ? re.test(raw) : name === 'auth' ? l.log_type === 'auth_log' : name === 'syslog' ? l.log_type === 'system' : false;
        if (applies) run(list, kw, l);
      }
    }
  }
  return out;
}

const sha = (...p) => crypto.createHash('sha1').update(p.join('|')).digest('hex').slice(0, 12).toUpperCase();
const PORTS = { web: [80, 'TCP/HTTP'], 'svc:sshd': [22, 'TCP/SSH'], 'svc:vsftpd': [21, 'TCP/FTP'] };

// Groups matches into alerts: one per rule, remote party and host per hour.
function toAlerts(matches) {
  const groups = new Map();
  for (const { rule, log } of matches) {
    const t = new Date(log.logged_at).getTime() || Date.now();
    const client = log.client_ip || log.host_ip;
    const key = `${rule.id}|${client}|${log.host_ip}|${Math.floor(t / 3600000)}`;
    const g = groups.get(key) || { rule, client, host: log.host_ip, lines: [] };
    g.lines.push(log);
    groups.set(key, g);
  }
  return [...groups.entries()].map(([key, g]) => {
    const lines = g.lines.sort((a, b) => String(a.logged_at).localeCompare(String(b.logged_at)));
    const [port, protocol] = PORTS[g.rule.target] || [0, 'HOST'];
    const head = `Sigma rule: ${g.rule.title} (${g.rule.level})${g.rule.technique ? `\nATT&CK: ${g.rule.technique}${g.rule.tactic ? ` ${g.rule.tactic}` : ''}` : ''}\nRule id: ${g.rule.id}\n\n`;
    const body = lines.slice(0, 25).map((l) => `${l.logged_at}  ${l.raw_entry}`).join('\n') + (lines.length > 25 ? `\n... ${lines.length - 25} more lines` : '');
    return {
      alert_id: `SIG-${sha(key)}`, signature: `${g.rule.title}${lines.length > 1 ? ` (${lines.length} lines)` : ''}`.slice(0, 240),
      category: g.rule.tactic || 'Detection', severity: SEVERITY[g.rule.level] || 'MEDIUM',
      source_ip: g.client, dest_ip: g.host, dest_port: port, protocol, sensor: 'sigma',
      raw_payload: (head + body).slice(0, 8000), detected_at: lines[0].logged_at, updated_at: lines[0].logged_at, status: 'NEW',
      external_ref: `sigma:${g.rule.id}${g.rule.cve ? ` ${g.rule.cve}` : g.rule.technique ? ` ${g.rule.technique}` : ''}`
    };
  });
}

// The rule as the API shows it, with a link to its source in the SigmaHQ repository.
const publicRule = ({ match, ...r }) => ({ ...r, link: /^rules[\w-]*\//.test(r.path || '') ? `https://github.com/SigmaHQ/sigma/blob/master/${r.path}` : null });

module.exports = { SigmaEngine, compileRule, compileCondition, selectionMatcher, scanWith, toAlerts, parseBundle, webEvent, processEvent, publicRule, LEVELS, SOURCE };
