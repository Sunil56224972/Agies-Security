'use strict';

// Analyst-written Sigma rules. They go through the same compiler as the SigmaHQ
// bundle, so a rule that lints clean here behaves exactly like a community rule:
// it runs on every ingested batch, in hunts and in the detection dry run.

const yaml = require('js-yaml');
const { compileRule, scanWith, LEVELS } = require('./sigma');

const SUPPORTED = 'logsource must be one of: category webserver; product linux with category process_creation; product linux with service auditd, sshd, sudo, cron, vsftpd, clamav, guacamole, auth or syslog; or product linux alone (keyword rules over auth and system logs)';
const MAX_YAML = 60000;

// Returns { ok, errors, warnings, doc, rule }. `rule` is the compiled matcher.
function lintRule(text, id = 'draft') {
  const errors = []; const warnings = [];
  const src = String(text == null ? '' : text);
  if (src.trim().length < 10) return { ok: false, errors: ['The rule is empty'], warnings, doc: null, rule: null };
  if (src.length > MAX_YAML) return { ok: false, errors: [`The rule is longer than ${MAX_YAML} characters`], warnings, doc: null, rule: null };
  let doc;
  try { doc = yaml.load(src, { json: false }); } catch (err) {
    const where = err.mark ? ` (line ${err.mark.line + 1}, column ${err.mark.column + 1})` : '';
    return { ok: false, errors: [`YAML does not parse${where}: ${err.reason || err.message}`], warnings, doc: null, rule: null };
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { ok: false, errors: ['The rule must be a YAML mapping (title:, logsource:, detection: ...)'], warnings, doc: null, rule: null };
  if (!doc.title || String(doc.title).trim().length < 4) errors.push('title is required (at least 4 characters)');
  if (!doc.logsource || typeof doc.logsource !== 'object') errors.push('logsource is required');
  if (!doc.detection || typeof doc.detection !== 'object') errors.push('detection is required');
  else if (!doc.detection.condition) errors.push('detection.condition is required');
  if (doc.level === undefined) errors.push(`level is required (${Object.keys(LEVELS).join(', ')})`);
  else if (LEVELS[doc.level] === undefined) errors.push(`level must be one of ${Object.keys(LEVELS).join(', ')}`);
  if (errors.length) return { ok: false, errors, warnings, doc, rule: null };

  let rule = null;
  try {
    rule = compileRule({ ...doc, status: doc.status === 'deprecated' || doc.status === 'unsupported' ? 'experimental' : doc.status }, `custom/${id}`);
    if (!rule) errors.push(SUPPORTED);
  } catch (err) {
    errors.push(`The detection cannot be compiled: ${err.message || 'unsupported construct'}`);
  }
  if (rule) {
    if (!rule.technique) warnings.push('No ATT&CK technique tag (for example attack.t1110.001); hunts and the coverage map will not attribute hits');
    if (!doc.description) warnings.push('No description; the next analyst will not know what the rule is for');
    if (!doc.falsepositives) warnings.push('No falsepositives section');
    if (doc.detection.timeframe) warnings.push('timeframe is ignored; rules run per event');
  }
  return { ok: !errors.length, errors, warnings, doc, rule };
}

// Compiles a stored row into a matcher whose id is the row id, so alerts and hit
// counters point back at the custom rule.
function compileStored(row) {
  const r = lintRule(row.yaml, row.rule_id);
  if (!r.ok) return null;
  return { ...r.rule, id: row.rule_id, path: `custom/${row.rule_id}`, custom: true };
}

class CustomRules {
  constructor(store) {
    this.store = store;
    this.cache = null;
    this.at = 0;
  }

  get ready() { return Boolean(this.store.coll) && !this.store.pendingExtras; }
  coll() { return this.store.coll('custom_rules', 'rule_id'); }
  invalidate() { this.cache = null; }

  // Enabled rules, compiled. Cached for 30 seconds or until a rule changes.
  async compiled() {
    if (!this.ready) return [];
    if (this.cache && Date.now() - this.at < 30000) return this.cache;
    const rows = await this.coll().list({ limit: 500, eq: { enabled: true } });
    this.cache = rows.map(compileStored).filter(Boolean);
    this.at = Date.now();
    return this.cache;
  }

  async scan(logs) {
    const rules = await this.compiled();
    return rules.length ? scanWith(rules, logs) : [];
  }

  // Bumps hit counters; one update per rule however many lines matched.
  async recordHits(matches) {
    if (!matches.length || !this.ready) return;
    const by = new Map();
    for (const m of matches) by.set(m.rule.id, (by.get(m.rule.id) || 0) + 1);
    const c = this.coll();
    const at = new Date().toISOString();
    for (const [id, n] of by) {
      const row = await c.get(id);
      if (row) await c.update(id, { hits: (row.hits || 0) + n, last_hit_at: at });
    }
  }
}

module.exports = { lintRule, compileStored, CustomRules, SUPPORTED };