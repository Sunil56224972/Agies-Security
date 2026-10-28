'use strict';

// Threat-intel and detection endpoints. Everything here works on live public data
// (CISA KEV, NVD, the reputation sources in intel/threatintel.js) or on telemetry
// the platform has stored; there are no fixtures.
const { isIP, isInternal, exposureFor } = require('./engine/analysis');
const { normalizeLog } = require('./ingest/normalize');
const detect = require('./engine/detect');
const { discover, softwareOf } = require('./intel/discover');
const { extractAll, isIpType } = require('./intel/indicator');
const { scanWith, toAlerts, publicRule, LEVELS } = require('./engine/sigma');

const OPEN = ['NEW', 'INVESTIGATING', 'CONFIRMED'];
const BULK_MAX = 100;

// Runs fn over items with at most `n` in flight.
async function pool(items, n, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  }));
  return out;
}

function registerIntel(app, ctx) {
  const { store, reputation, nvd, kev, hub, sigma, env, wrap, bad, need, actor } = ctx;
  const intelOn = () => Boolean(reputation && reputation.available);

  // ---- CISA KEV --------------------------------------------------------------
  app.get('/api/intel/kev', wrap(async (req, res) => {
    await kev.load();
    const [cves, assets] = await Promise.all([store.cves.list(), store.assets.list()]);
    const local = [];
    for (const c of cves) {
      const k = await kev.lookup(c.cve_id);
      if (!k) continue;
      const hosts = assets.filter((a) => exposureFor(a, c).exposed).map((a) => ({ ip: a.ip_address, hostname: a.hostname }));
      local.push({ cve_id: c.cve_id, title: c.title, cvss_score: c.cvss_score, severity: c.severity, added: k.added, due: k.due, ransomware: k.ransomware, action: k.action, hosts });
    }
    local.sort((a, b) => b.hosts.length - a.hosts.length || String(a.due).localeCompare(String(b.due)));
    res.json({ status: kev.status(), recent: await kev.recent(Math.min(Number(req.query.limit) || 15, 100)), local });
  }));

  // Flags every stored CVE that CISA lists, and clears the flag on ones it no longer does.
  app.post('/api/intel/kev/sync', need('configure'), wrap(async (req, res) => {
    const data = await kev.load(true);
    if (!data) return bad(res, `Could not load the CISA catalog: ${kev.status().error}`, 502);
    const cves = await store.cves.list();
    const changed = [];
    for (const c of cves) {
      const k = data.map.get(String(c.cve_id).toUpperCase());
      const want = Boolean(k);
      if (Boolean(c.kev) === want && (!want || c.kev_added)) continue;
      const { match_terms, ...row } = c;
      changed.push({ ...row, match_terms: match_terms || [], kev: want, kev_added: k ? k.added : null });
    }
    if (changed.length) await store.cves.upsert(changed);
    await store.audit.add({ actor: actor(req), action: 'kev.synced', target: 'CISA KEV', detail: `${data.map.size} catalog entries, ${changed.length} records updated` });
    res.json({ catalog: kev.status(), updated: changed.length, ids: changed.map((c) => c.cve_id) });
  }));

  // ---- Per-host CVE discovery (NVD) --------------------------------------------
  const running = new Set();
  app.get('/api/assets/:ip/software', wrap(async (req, res) => {
    const a = await store.assets.get(req.params.ip);
    if (!a) return bad(res, 'Host not found', 404);
    res.json(softwareOf(a).map(({ cpe, version, evidence, match }) => ({ product: cpe.split(':')[1], version, evidence, cpe: match })));
  }));

  app.post('/api/assets/:ip/discover', need('respond'), wrap(async (req, res) => {
    const a = await store.assets.get(req.params.ip);
    if (!a) return bad(res, 'Host not found', 404);
    if (!softwareOf(a).length) return bad(res, 'No versioned software on this host that Aegis can map to NVD. Run the agent or add packages such as "openssh-server 8.9p1".');
    if (running.has(a.ip_address)) return bad(res, 'A lookup for this host is already running', 409);
    running.add(a.ip_address);
    try {
      // Without a key NVD allows 5 requests per 30 s, which is what keeps this to 4 products.
      const r = await discover(a, nvd, { maxProducts: env.NVD_API_KEY ? 12 : 4, kev });
      if (r.rows.length) await store.cves.upsert(r.rows);
      const exposed = r.rows.filter((c) => exposureFor(a, c).exposed);
      await store.audit.add({ actor: actor(req), action: 'cve.discovered', target: a.ip_address, detail: `${r.rows.length} CVEs from ${r.products.length} products, ${exposed.length} matched` });
      res.json({ host: a.ip_address, products: r.products, imported: r.rows.length, matched: exposed.length, kev: r.rows.filter((c) => c.kev).length, skipped: r.skipped });
    } finally { running.delete(a.ip_address); }
  }));

  // ---- Indicator lookup (abuse.ch, MISP, RDAP, RIPEstat, PDNS, VirusTotal) ---------
  app.get('/api/intel/lookup', wrap(async (req, res) => {
    const q = String(req.query.q || '').trim();
    if (!q) return bad(res, 'Enter an IP, domain, URL, hash or ASN');
    if (q.length > 2048) return bad(res, 'Indicator is too long');
    let r;
    try { r = await hub.lookup(q, { budgetMs: Math.min(Number(req.query.wait) || 15000, 25000), vt: req.query.vt !== '0' }); } catch (err) {
      if (err.status === 400) return bad(res, err.message);
      throw err;
    }
    // Repeat polls while feeds are still downloading are not separate lookups.
    if (!req.query.poll) await store.audit.add({ actor: actor(req), action: 'intel.lookup', target: r.indicator.display.slice(0, 200), detail: `${r.indicator.type}: ${r.verdict}${r.score != null ? ` (${r.score})` : ''}` });
    const ip = isIpType(r.indicator.type) ? r.indicator.value : r.indicator.host && isIP(r.indicator.host) ? r.indicator.host : null;
    if (ip) {
      const alerts = (await store.alerts.list({ lite: true, limit: 5000 })).filter((a) => a.source_ip === ip || a.dest_ip === ip);
      r.local = { alerts: alerts.length, open: alerts.filter((a) => OPEN.includes(a.status)).length, blocked: (await store.rules.list()).some((x) => x.is_active && x.target_ip === ip && x.action === 'BLOCK') };
    }
    res.json(r);
  }));

  app.get('/api/intel/samples', wrap(async (req, res) => {
    if (!hub.available) return res.json({ samples: [], offline: true });
    await hub.ready();
    res.json({ samples: await hub.abusech.samples() });
  }));

  app.get('/api/intel/feeds', wrap(async (req, res) => {
    await hub.ready();
    res.json({ ...hub.describe(), sigma: { enabled: sigma.available, ...sigma.status() } });
  }));

  app.post('/api/intel/feeds/refresh', need('configure'), wrap(async (req, res) => {
    if (!hub.available) return bad(res, 'Threat intel is disabled on this server (AEGIS_INTEL=off)', 503);
    const which = String((req.body || {}).which || 'all');
    const started = Date.now();
    const out = {};
    if (which === 'all' || which === 'feeds') out.feeds = await hub.refresh();
    if ((which === 'all' || which === 'sigma') && sigma.available) {
      try { await sigma.refresh(); out.sigma = { ok: true }; } catch (err) { out.sigma = { ok: false, error: err.message }; }
    }
    await store.audit.add({ actor: actor(req), action: 'intel.feeds_refreshed', target: which, detail: `${Date.now() - started} ms` });
    res.json({ ...out, ms: Date.now() - started, ...hub.describe(), sigma_status: sigma.status() });
  }));

  // ---- Sigma rules ---------------------------------------------------------------
  app.get('/api/sigma/rules', wrap(async (req, res) => {
    const cfg = await store.config.get();
    const status = { enabled: sigma.available && cfg.sigmaEnabled !== false, ...sigma.status() };
    const rules = sigma.available ? await sigma.rules(Math.min(Number(req.query.wait) || 8000, 20000)) : null;
    if (!rules) return res.json({ status, rules: [], total: 0, loading: sigma.available && !status.error });
    const since = new Date(Date.now() - 30 * 86400000).toISOString();
    const per = {};
    for (const a of (await store.alerts.list({ since, lite: true, limit: 20000 })).filter((x) => x.sensor === 'sigma')) {
      const id = String(a.external_ref || '').split(' ')[0].replace('sigma:', '');
      per[id] = per[id] || { total: 0, open: 0, last: null };
      per[id].total += 1;
      if (OPEN.includes(a.status)) per[id].open += 1;
      if (!per[id].last || a.detected_at > per[id].last) per[id].last = a.detected_at;
    }
    const q = String(req.query.q || '').toLowerCase().trim();
    const level = String(req.query.level || '');
    const target = String(req.query.target || '');
    const off = new Set(cfg.sigmaDisabled || []);
    const min = LEVELS[cfg.sigmaMinLevel || 'low'] ?? 0;
    let list = rules.map((r) => ({ ...publicRule(r), enabled: !off.has(r.id) && LEVELS[r.level] >= min, hits_30d: per[r.id] ? per[r.id].total : 0, open: per[r.id] ? per[r.id].open : 0, last_hit: per[r.id] ? per[r.id].last : null }));
    if (q) list = list.filter((r) => `${r.title} ${r.id} ${r.technique || ''} ${r.cve || ''} ${(r.tags || []).join(' ')} ${r.description || ''}`.toLowerCase().includes(q));
    if (level) list = list.filter((r) => r.level === level);
    if (target) list = list.filter((r) => (target === 'service' ? r.target.startsWith('svc:') : r.target === target));
    list.sort((a, b) => b.hits_30d - a.hits_30d || (LEVELS[b.level] - LEVELS[a.level]) || a.title.localeCompare(b.title));
    const limit = Math.min(Number(req.query.limit) || 60, 300);
    res.json({ status, total: rules.length, matched: list.length, rules: list.slice(0, limit), firing: Object.keys(per).length });
  }));

  // ---- Bulk IOC check ----------------------------------------------------------
  app.post('/api/intel/bulk', wrap(async (req, res) => {
    if (!intelOn()) return bad(res, 'Threat intel is disabled on this server (AEGIS_INTEL=off)', 503);
    const b = req.body || {};
    const raw = b.ips ?? b.text ?? b.indicators;
    const text = Array.isArray(raw) ? raw.join('\n') : String(raw || '');
    // Accept anything pasted: CSV, firewall logs, defanged IOCs like 1.2.3[.]4.
    // IPs, domains, URLs and hashes in any order; ASNs are left to the single lookup.
    const inds = extractAll(text).filter((i) => i.type !== 'asn');
    const ips = inds.map((i) => i.value);
    if (!inds.length) return bad(res, 'No IP addresses, domains, URLs or hashes found in the input');
    if (inds.length > BULK_MAX) return bad(res, `At most ${BULK_MAX} indicators per check (found ${inds.length})`, 413);
    const results = await pool(inds, 5, async (ind) => {
      const ip = ind.value;
      if (!isIpType(ind.type)) {
        try {
          const r = await hub.lookup(ind.value, { budgetMs: 8000, vt: false });
          return { ip, type: ind.type, verdict: r.verdict, score: r.score, listed: [...new Set(r.hits.filter((h) => h.score != null).map((h) => h.source))], families: r.families, c2: r.c2, org: r.whois ? r.whois.registrar || r.whois.org || null : null, age_days: r.whois ? r.whois.age_days ?? null : null, summary: r.summary, sources_failed: r.sources_failed.length, pending: r.pending.length };
        } catch (err) { return { ip, type: ind.type, verdict: 'error', score: null, error: err.message }; }
      }
      if (isInternal(ip)) return { ip, type: ind.type, internal: true, verdict: 'internal', score: null };
      try {
        const r = await reputation.check(ip);
        return { ip, type: ind.type, verdict: r.verdict || 'unknown', score: r.score, listed: [...new Set([...(r.listed || []).map((l) => l.list), ...(r.iocs || []).filter((h) => h.score != null).map((h) => h.source)])], c2: Boolean(r.c2), country: r.country, org: r.isp, asn: r.geo ? r.geo.asn : null, greynoise: r.greynoise ? r.greynoise.classification : null, ports: r.shodan ? r.shodan.ports.slice(0, 8) : [], vulns: r.shodan ? r.shodan.vulns.length : 0, summary: r.summary, sources_failed: (r.sources_failed || []).length, cached: Boolean(r.cached) };
      } catch (err) { return { ip, type: ind.type, verdict: 'error', score: null, error: err.message }; }
    });
    const seen = await store.alerts.list({ statuses: undefined, lite: true, limit: 5000 });
    const counts = {};
    for (const a of seen) { counts[a.source_ip] = (counts[a.source_ip] || 0) + 1; counts[a.dest_ip] = (counts[a.dest_ip] || 0) + 1; }
    const rules = (await store.rules.list()).filter((r) => r.is_active);
    for (const r of results) { r.alerts = counts[r.ip] || 0; r.blocked = rules.some((x) => x.target_ip === r.ip && x.action === 'BLOCK'); }
    const by = (v) => results.filter((r) => r.verdict === v).length;
    await store.audit.add({ actor: actor(req), action: 'intel.bulk', target: `${ips.length} indicators`, detail: `${by('malicious')} malicious, ${by('suspicious')} suspicious` });
    res.json({ checked: results.length, summary: { malicious: by('malicious'), suspicious: by('suspicious'), clean: by('clean') + by('benign'), internal: by('internal'), unknown: by('unknown') + by('error') }, results });
  }));

  // ---- Attacker origins --------------------------------------------------------
  // Real geolocation for the external sources behind recent alerts. Lookups go
  // through the same 6-hour cache as the IP profile.
  app.get('/api/intel/origins', wrap(async (req, res) => {
    const days = Math.min(Math.max(Number(req.query.days) || 7, 1), 90);
    const alerts = await store.alerts.list({ since: new Date(Date.now() - days * 86400000).toISOString(), lite: true, limit: 20000 });
    const tally = new Map();
    for (const a of alerts) {
      if (!isIP(a.source_ip) || isInternal(a.source_ip)) continue;
      const t = tally.get(a.source_ip) || { ip: a.source_ip, alerts: 0, open: 0 };
      t.alerts += 1;
      if (OPEN.includes(a.status)) t.open += 1;
      tally.set(a.source_ip, t);
    }
    const top = [...tally.values()].sort((a, b) => b.alerts - a.alerts).slice(0, 25);
    if (!intelOn()) return res.json({ days, sources: tally.size, located: 0, countries: [], networks: [], ips: top, intel: false });
    const rows = await pool(top, 5, async (t) => {
      try {
        const r = await reputation.check(t.ip);
        return { ...t, country: r.geo ? r.geo.country : null, country_code: r.country, city: r.geo ? r.geo.city : null, asn: r.geo ? r.geo.asn : null, org: r.isp, verdict: r.verdict, score: r.score };
      } catch { return { ...t }; }
    });
    const group = (key, label) => {
      const m = new Map();
      for (const r of rows) {
        if (!r[key]) continue;
        const g = m.get(r[key]) || { key: r[key], label: label(r), ips: 0, alerts: 0 };
        g.ips += 1; g.alerts += r.alerts;
        m.set(r[key], g);
      }
      return [...m.values()].sort((a, b) => b.alerts - a.alerts).slice(0, 8);
    };
    res.json({
      days, sources: tally.size, located: rows.filter((r) => r.country_code).length, intel: true,
      countries: group('country_code', (r) => r.country || r.country_code),
      networks: group('asn', (r) => r.org || r.asn),
      ips: rows
    });
  }));

  // ---- Detection rules ---------------------------------------------------------
  app.get('/api/detect/rules', wrap(async (req, res) => {
    const cfg = await store.config.get();
    const s = detect.settings(cfg);
    const since = new Date(Date.now() - 30 * 86400000).toISOString();
    const raised = (await store.alerts.list({ since, lite: true, limit: 20000 })).filter((a) => a.sensor === 'aegis-detect');
    const per = {};
    for (const a of raised) {
      const id = String(a.external_ref || '').split(' ')[0].replace('aegis:', '');
      per[id] = per[id] || { total: 0, open: 0, last: null };
      per[id].total += 1;
      if (OPEN.includes(a.status)) per[id].open += 1;
      if (!per[id].last || a.detected_at > per[id].last) per[id].last = a.detected_at;
    }
    res.json({
      enabled: s.enabled,
      settings: { detectSshThreshold: s.sshThreshold, detectScanThreshold: s.scanThreshold, detectWindowMin: s.windowMs / 60000 },
      rules: detect.RULES.map((r) => ({ ...r, enabled: !s.disabled.has(r.id), hits_30d: per[r.id] ? per[r.id].total : 0, open: per[r.id] ? per[r.id].open : 0, last_hit: per[r.id] ? per[r.id].last : null })),
      web_patterns: detect.WEB.map((w) => ({ id: w.id, label: w.label, severity: w.severity, ref: w.ref })),
      recent: raised.slice(0, 12)
    });
  }));

  // Dry run: what would the current rules raise for these lines? Nothing is stored.
  app.post('/api/detect/test', wrap(async (req, res) => {
    const b = req.body || {};
    const host = String(b.host_ip || '').trim();
    if (!isIP(host)) return bad(res, 'Enter the IP of the host these lines came from');
    const lines = String(b.lines || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (!lines.length) return bad(res, 'Paste at least one log line');
    if (lines.length > 2000) return bad(res, 'At most 2000 lines per test');
    const parsed = []; const rejected = [];
    lines.forEach((l, i) => {
      const r = normalizeLog(l, { host_ip: host, log_type: b.log_type || undefined });
      if (r.error) rejected.push({ line: i + 1, error: r.error });
      // Pasted lines are replayed one second apart, in order, as if they had just arrived.
      else parsed.push({ ...r.log, id: i + 1, logged_at: new Date(Date.now() - (lines.length - i) * 1000).toISOString() });
    });
    const cfg = await store.config.get();
    const findings = detect.evaluate(parsed, { ...cfg, detectEnabled: true }, { now: Date.now() });
    let sigmaOut = { loaded: false, rules: 0, findings: [] };
    // Custom rules are reported separately so an analyst sees exactly what their own rules caught.
    let customOut = { rules: 0, findings: [] };
    if (ctx.customRules) {
      const own = await ctx.customRules.compiled().catch(() => []);
      const byId = new Map(own.map((r) => [r.id, r]));
      const m = own.length ? scanWith(own, parsed) : [];
      customOut = {
        rules: own.length,
        findings: toAlerts(m).map((a) => {
          const rule = byId.get(a.external_ref.split(' ')[0].replace('sigma:', ''));
          return { rule: rule.id, title: rule.title, level: rule.level, technique: rule.technique || null, severity: a.severity, source_ip: a.source_ip, dest_ip: a.dest_ip, evidence: a.raw_payload.split('\n\n')[1].split('\n').slice(0, 4) };
        })
      };
    }
    if (sigma.available) {
      const s = await sigma.scan(parsed, { budgetMs: 15000, minLevel: cfg.sigmaMinLevel || 'low', disabled: cfg.sigmaDisabled || [] });
      if (s) {
        const byId = new Map(s.matches.map((m) => [m.rule.id, m.rule]));
        sigmaOut = {
          loaded: true, rules: s.rules, version: sigma.status().version,
          findings: toAlerts(s.matches).map((a) => {
            const rule = publicRule(byId.get(a.external_ref.split(' ')[0].replace('sigma:', '')));
            return { rule: rule.id, title: rule.title, level: rule.level, technique: rule.technique || null, cve: rule.cve || null, link: rule.link || null, severity: a.severity, source_ip: a.source_ip, dest_ip: a.dest_ip, evidence: a.raw_payload.split('\n\n')[1].split('\n').slice(0, 4) };
          })
        };
      } else sigmaOut.loading = true;
    }
    res.json({
      sigma: sigmaOut, custom: customOut,
      parsed: parsed.length, rejected: rejected.slice(0, 20),
      without_client: parsed.filter((l) => !l.client_ip).length,
      by_type: parsed.reduce((m, l) => ({ ...m, [l.log_type]: (m[l.log_type] || 0) + 1 }), {}),
      findings: findings.map((f) => ({ rule: f.external_ref.split(' ')[0].replace('aegis:', ''), ref: f.external_ref.split(' ')[1] || null, severity: f.severity, signature: f.signature, source_ip: f.source_ip, dest_ip: f.dest_ip, evidence: f.raw_payload.split('\n').slice(0, 6) }))
    });
  }));
}

module.exports = { registerIntel, pool };