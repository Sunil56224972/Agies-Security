'use strict';

// abuse.ch threat feeds. The bulk exports need no account, so they are the
// default; per-indicator APIs are used on top when ABUSECH_AUTH_KEY is set.
//
//   URLhaus        malware URLs that are online right now (csv_online)
//   ThreatFox      the full IOC database: C2 servers, payload hosts, hashes
//   MalwareBazaar  latest malware samples (sha256/md5/sha1, family, file type)
//   Feodo Tracker  botnet C2 servers (QakBot, Emotet, Pikabot, ...)
//   SSLBL          TLS certificates and JA3 fingerprints seen on C2 servers

const net = require('net');
const { FeedCache, eachCsvRow, unzip, httpGet, errText, TtlCache } = require('./feeds');

const HOUR = 3600000;
const clean = (v) => (v == null || v === '' || v === 'None' || v === 'n/a' || v === 'null' ? null : v);
const tagList = (v) => (clean(v) ? String(v).split(',').map((s) => s.trim()).filter(Boolean).slice(0, 8) : []);
const hostOf = (u) => { try { return new URL(u).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch { return null; } };
const addTo = (map, k, v, cap = 25) => { const a = map.get(k); if (a) { if (a.length < cap) a.push(v); } else map.set(k, [v]); };
const textOf = (b) => (Buffer.isBuffer(b) ? b.toString('utf8') : String(b));

function splitHostPort(v) {
  const s = String(v);
  if (s.startsWith('[')) { const i = s.indexOf(']'); return [s.slice(1, i).toLowerCase(), Number(s.slice(i + 2)) || null]; }
  const i = s.lastIndexOf(':');
  return i > 0 && net.isIPv4(s.slice(0, i)) ? [s.slice(0, i), Number(s.slice(i + 1)) || null] : [s.toLowerCase(), null];
}

// ThreatFox: either the zipped full dump or a plain CSV export.
function parseThreatFox(body) {
  let text;
  if (Buffer.isBuffer(body) && body[0] === 0x50 && body[1] === 0x4b) {
    const entry = unzip(body).find((e) => /\.csv$/i.test(e.name));
    if (!entry) throw new Error('no CSV inside the ThreatFox archive');
    text = entry.data().toString('utf8');
  } else text = textOf(body);
  const ip = new Map(); const domain = new Map(); const url = new Map(); const urlHost = new Map(); const hash = new Map();
  const newest = {};
  let rows = 0;
  eachCsvRow(text, (r) => {
    if (r.length < 10 || !r[2]) return;
    const type = r[3];
    const rec = {
      id: r[1], value: r[2], type, threat: r[4], malware: clean(r[7]) || clean(r[5]), malware_id: clean(r[5]), alias: clean(r[6]),
      first_seen: clean(r[0]), last_seen: clean(r[8]), confidence: Number(r[9]) || null, tags: tagList(r[12]), reporter: clean(r[14])
    };
    rows += 1;
    if (type === 'ip:port') { const [h, p] = splitHostPort(r[2]); rec.port = p; addTo(ip, h, rec); }
    else if (type === 'domain') addTo(domain, r[2].toLowerCase(), rec);
    else if (type === 'url') { url.set(r[2], rec); const h = hostOf(r[2]); if (h) addTo(urlHost, h, rec); }
    else if (/_hash$/.test(type)) hash.set(r[2].toLowerCase(), rec);
    else return;
    if (!newest[type] || String(rec.first_seen) > String(newest[type].first_seen)) newest[type] = rec;
  });
  return { ip, domain, url, urlHost, hash, rows, newest };
}

// The keyed v2 exports may arrive zipped or as plain CSV.
function csvText(body) {
  if (Buffer.isBuffer(body) && body[0] === 0x50 && body[1] === 0x4b) {
    const entries = unzip(body);
    const entry = entries.find((e) => /\.(csv|txt)$/i.test(e.name)) || entries[0];
    if (!entry) throw new Error('empty archive');
    return entry.data().toString('utf8');
  }
  return textOf(body);
}

// URLhaus: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter.
// Rows in another layout still count by their URL column.
function parseUrlhaus(body) {
  const url = new Map(); const host = new Map();
  let rows = 0; let newest = null;
  eachCsvRow(csvText(body), (r) => {
    let rec;
    if (r.length >= 8 && /^\w+:\/\//.test(r[2] || '')) {
      rec = { id: r[0], added: r[1], url: r[2], status: r[3], last_online: clean(r[4]), threat: clean(r[5]), tags: tagList(r[6]), link: clean(r[7]), reporter: clean(r[8]) };
    } else {
      const i = r.findIndex((v) => /^https?:\/\//i.test(v || ''));
      if (i < 0) return;
      rec = { id: null, added: r.find((v) => /^\d{4}-\d{2}-\d{2}/.test(v || '')) || null, url: r[i], status: r.find((v) => /^(online|offline)$/i.test(v || '')) || null, last_online: null, threat: null, tags: [], link: r.find((v, j) => j !== i && /urlhaus\.abuse\.ch\/url\//.test(v || '')) || null, reporter: null };
    }
    rows += 1;
    url.set(rec.url, rec);
    const h = hostOf(rec.url);
    if (h) addTo(host, h, rec, 15);
    if (!newest || String(rec.added) > String(newest.added)) newest = rec;
  });
  return { url, host, rows, newest };
}

// MalwareBazaar: first_seen_utc, sha256, md5, sha1, reporter, file_name, file_type_guess, mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh
function parseBazaar(body) {
  const hash = new Map();
  let rows = 0; let newest = null;
  eachCsvRow(csvText(body), (r) => {
    if (r.length < 9 || !/^[a-f0-9]{64}$/i.test(r[1] || '')) return;
    const rec = { first_seen: r[0], sha256: r[1].toLowerCase(), md5: clean(r[2]), sha1: clean(r[3]), reporter: clean(r[4]), file_name: clean(r[5]), file_type: clean(r[6]), mime: clean(r[7]), signature: clean(r[8]), clamav: clean(r[9]), vt_percent: clean(r[10]) };
    rows += 1;
    hash.set(rec.sha256, rec);
    if (rec.md5) hash.set(rec.md5.toLowerCase(), rec);
    if (rec.sha1) hash.set(rec.sha1.toLowerCase(), rec);
    if (!newest || rec.first_seen > newest.first_seen) newest = rec;
  });
  return { hash, rows, newest };
}

function parseFeodo(body) {
  const list = JSON.parse(textOf(body));
  if (!Array.isArray(list)) throw new Error('unexpected Feodo format');
  const ip = new Map();
  for (const e of list) if (e && e.ip_address) ip.set(e.ip_address, { ip: e.ip_address, port: e.port, status: e.status, hostname: e.hostname || null, asn: e.as_number ? `AS${e.as_number}` : null, as_name: e.as_name || null, country: e.country || null, first_seen: e.first_seen || null, last_online: e.last_online || null, malware: e.malware || null });
  return { ip, rows: ip.size, list: [...ip.values()] };
}

// sslblacklist.csv: Listingdate, SHA1, Listingreason
function parseSslbl(body) {
  const cert = new Map();
  eachCsvRow(textOf(body), (r) => { if (/^[a-f0-9]{40}$/i.test(r[1] || '')) cert.set(r[1].toLowerCase(), { listed: r[0], reason: r[2] || null }); });
  return { cert, rows: cert.size };
}

// ja3_fingerprints.csv: ja3_md5, Firstseen, Lastseen, Listingreason
function parseJa3(body) {
  const ja3 = new Map();
  eachCsvRow(textOf(body), (r) => { if (/^[a-f0-9]{32}$/i.test(r[0] || '')) ja3.set(r[0].toLowerCase(), { first_seen: r[1], last_seen: r[2], reason: r[3] || null }); });
  return { ja3, rows: ja3.size };
}

// ThreatFox, URLhaus and MalwareBazaar retired their keyless downloads (HTTP 410)
// in favour of v2 exports with the Auth-Key in the path. Feodo Tracker and SSLBL
// are still public. `files` are tried in order; the key never appears in `url`,
// which is what the console shows.
const v2 = (host) => `https://${host}/v2/files/exports`;
const FEEDS = {
  threatfox: { id: 'threatfox', name: 'ThreatFox IOC database', provider: 'ThreatFox', auth: true, base: v2('threatfox-api.abuse.ch'), files: ['full.csv.zip', 'recent.csv'], url: `${v2('threatfox-api.abuse.ch')}/<auth-key>/full.csv.zip`, binary: true, ttl: 3 * HOUR, timeoutMs: 90000, parse: parseThreatFox, size: (d) => d.rows, note: 'C2 servers, payload hosts and malware hashes shared by researchers' },
  urlhaus: { id: 'urlhaus', name: 'URLhaus malware URLs', provider: 'URLhaus', auth: true, base: v2('urlhaus-api.abuse.ch'), files: ['online.csv', 'recent.csv'], url: `${v2('urlhaus-api.abuse.ch')}/<auth-key>/online.csv`, binary: true, ttl: HOUR, timeoutMs: 60000, parse: parseUrlhaus, size: (d) => d.rows, note: 'Malware distribution URLs, refreshed every 5 minutes by abuse.ch' },
  bazaar: { id: 'bazaar', name: 'MalwareBazaar recent samples', provider: 'MalwareBazaar', auth: true, base: v2('mb-api.abuse.ch'), files: ['recent.csv'], url: `${v2('mb-api.abuse.ch')}/<auth-key>/recent.csv`, binary: true, ttl: HOUR, timeoutMs: 45000, parse: parseBazaar, size: (d) => d.rows, note: 'Newest submissions; any other sample is looked up live through the API' },
  feodo: { id: 'feodo', name: 'Feodo Tracker C2 list', provider: 'Feodo Tracker', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json', ttl: HOUR, timeoutMs: 20000, parse: parseFeodo, size: (d) => d.rows, note: 'Botnet C2 servers for QakBot, Emotet, Pikabot and similar' },
  sslbl: { id: 'sslbl', name: 'SSLBL certificate blacklist', provider: 'SSLBL', url: 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv', ttl: 6 * HOUR, timeoutMs: 30000, parse: parseSslbl, size: (d) => d.rows, note: 'SHA1 of TLS certificates used by malware C2' },
  ja3: { id: 'ja3', name: 'SSLBL JA3 fingerprints', provider: 'SSLBL', url: 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv', ttl: 24 * HOUR, timeoutMs: 20000, parse: parseJa3, size: (d) => d.rows, note: 'TLS client fingerprints of malware; no longer updated by abuse.ch' }
};
const NEEDS_KEY = 'needs an abuse.ch Auth-Key (free at auth.abuse.ch), set it under Settings, Threat intel keys';

const NEEDS = {
  ipv4: ['feodo', 'threatfox', 'urlhaus'], ipv6: ['threatfox', 'urlhaus'],
  domain: ['threatfox', 'urlhaus'], url: ['threatfox', 'urlhaus'],
  md5: ['threatfox', 'bazaar'], sha1: ['threatfox', 'bazaar', 'sslbl'], sha256: ['threatfox', 'bazaar'],
  ja3: ['ja3']
};

const THREAT_LABEL = { botnet_cc: 'C2 server', payload_delivery: 'Payload delivery', payload: 'Malware payload' };

function tfHit(rec, how) {
  const c2 = rec.threat === 'botnet_cc';
  const base = c2 ? 95 : rec.threat === 'payload' ? 95 : 85;
  return {
    source: 'ThreatFox', kind: THREAT_LABEL[rec.threat] || rec.threat, c2, malware: rec.malware, match: how,
    detail: `${rec.value}${rec.port && !String(rec.value).endsWith(`:${rec.port}`) ? `:${rec.port}` : ''}`,
    first_seen: rec.first_seen, last_seen: rec.last_seen, confidence: rec.confidence, tags: rec.tags, reporter: rec.reporter,
    link: `https://threatfox.abuse.ch/ioc/${rec.id}/`,
    score: Math.round(base * Math.max(0.6, (rec.confidence || 75) / 100))
  };
}

function uhHit(rec, how) {
  const online = rec.status === 'online';
  return {
    source: 'URLhaus', kind: rec.threat === 'malware_download' ? 'Malware download' : rec.threat || 'Malicious URL', c2: false, match: how,
    malware: rec.tags.find((t) => /^[A-Z]/.test(t)) || null, detail: rec.url, status: rec.status,
    first_seen: rec.added, last_seen: rec.last_online, tags: rec.tags, reporter: rec.reporter, link: rec.link, score: online ? 90 : 75
  };
}

class AbuseCh {
  constructor({ fetchImpl = globalThis.fetch, offline = false, authKey = null } = {}) {
    this.fetch = fetchImpl;
    this.offline = offline;
    this.authKey = authKey || null;
    this.cache = new FeedCache({ fetchImpl, offline });
    this.api = new TtlCache(1000, 6 * HOUR);
  }

  get available() { return !this.offline; }

  // Swaps the Auth-Key at runtime (Settings). Keyed feeds and API answers made
  // with the old key are dropped so the next lookup uses the new one.
  setKey(key) {
    const k = key ? String(key).trim() : null;
    if (k === this.authKey) return false;
    this.authKey = k;
    for (const f of Object.values(FEEDS)) if (f.auth) this.cache.forget(f.id);
    this.api = new TtlCache(1000, 6 * HOUR);
    return true;
  }

  // The feed definition with this deployment's key filled in.
  feed(id) {
    const f = FEEDS[id];
    if (!f.auth) return f;
    if (!this.authKey) return { ...f, unavailable: NEEDS_KEY };
    return { ...f, urls: f.files.map((name) => `${f.base}/${encodeURIComponent(this.authKey)}/${name}`), authError: 'abuse.ch rejected the Auth-Key; check it at auth.abuse.ch' };
  }

  describe() {
    return { auth_key: Boolean(this.authKey), feeds: Object.values(FEEDS).map((f) => ({ ...this.cache.status(f), needs_key: Boolean(f.auth && !this.authKey), error: f.auth && !this.authKey ? NEEDS_KEY : this.cache.status(f).error })) };
  }

  refresh() { return Promise.all(Object.keys(FEEDS).filter((id) => !FEEDS[id].auth || this.authKey).map((id) => this.cache.load(this.feed(id), { force: true }))); }

  // Loads the light feeds now so the first lookup is not the one paying for downloads.
  warm() { if (!this.offline) for (const id of ['feodo', 'bazaar', 'urlhaus', 'threatfox']) if (!FEEDS[id].auth || this.authKey) this.cache.load(this.feed(id)).catch(() => {}); }

  // The newest real entry from each feed, used as one-click examples in the console.
  async samples() {
    const [tf, uh, mb, fe] = await Promise.all(['threatfox', 'urlhaus', 'bazaar', 'feodo'].map((id) => (FEEDS[id].auth && !this.authKey ? { data: null } : this.cache.within(this.feed(id), 1500))));
    const out = [];
    const c2 = fe.data && (fe.data.list.find((e) => e.status === 'online') || fe.data.list[0]);
    if (c2) out.push({ type: 'ipv4', value: c2.ip, label: `${c2.malware || 'Botnet'} C2`, source: 'Feodo Tracker' });
    if (tf.data && tf.data.newest.domain) out.push({ type: 'domain', value: tf.data.newest.domain.value, label: `${tf.data.newest.domain.malware || 'Malware'} domain`, source: 'ThreatFox' });
    if (tf.data && tf.data.newest['ip:port']) out.push({ type: 'ipv4', value: splitHostPort(tf.data.newest['ip:port'].value)[0], label: `${tf.data.newest['ip:port'].malware || 'Malware'} server`, source: 'ThreatFox' });
    if (uh.data && uh.data.newest) out.push({ type: 'url', value: uh.data.newest.url, label: 'Live malware URL', source: 'URLhaus' });
    if (mb.data && mb.data.newest) out.push({ type: 'sha256', value: mb.data.newest.sha256, label: `${mb.data.newest.signature || mb.data.newest.file_type || 'Malware'} sample`, source: 'MalwareBazaar' });
    return out;
  }

  async lookup(ind, { budgetMs = 15000 } = {}) {
    const out = { hits: [], ok: [], failed: [], pending: [], skipped: [] };
    if (this.offline) return { ...out, skipped: true };
    // Keyed feeds without a key are reported as skipped, not as failures.
    const all = NEEDS[ind.type] || [];
    for (const id of all) if (FEEDS[id].auth && !this.authKey && !out.skipped.includes(FEEDS[id].provider)) out.skipped.push(FEEDS[id].provider);
    const need = all.filter((id) => !FEEDS[id].auth || this.authKey);
    const recs = await Promise.all(need.map((id) => this.cache.within(this.feed(id), budgetMs)));
    const d = {};
    need.forEach((id, i) => {
      const prov = FEEDS[id].provider;
      if (recs[i].data) { d[id] = recs[i].data; if (!out.ok.includes(prov)) out.ok.push(prov); }
      else if (recs[i].loading) out.pending.push(prov);
      else out.failed.push({ source: prov, error: recs[i].error });
    });
    const v = String(ind.value);
    const hostChecks = (host, how) => {
      if (d.threatfox) {
        for (const r of d.threatfox.ip.get(host) || []) out.hits.push(tfHit(r, how));
        for (const r of (d.threatfox.domain.get(host) || [])) out.hits.push(tfHit(r, how));
        for (const r of (d.threatfox.urlHost.get(host) || []).slice(0, 5)) out.hits.push(tfHit(r, `${how}, URL on this host`));
      }
      if (d.urlhaus) for (const r of (d.urlhaus.host.get(host) || []).slice(0, 8)) out.hits.push(uhHit(r, `${how}, URL on this host`));
    };

    if (ind.type === 'ipv4' || ind.type === 'ipv6') {
      if (d.feodo) {
        const f = d.feodo.ip.get(v);
        if (f) out.hits.push({ source: 'Feodo Tracker', kind: 'C2 server', c2: true, malware: f.malware, match: 'exact', detail: `${f.ip}:${f.port} ${f.status}`, status: f.status, first_seen: f.first_seen, last_seen: f.last_online, tags: [f.as_name, f.country].filter(Boolean), link: `https://feodotracker.abuse.ch/browse/host/${f.ip}/`, score: f.status === 'online' ? 100 : 75 });
      }
      hostChecks(v, 'exact');
    } else if (ind.type === 'domain') {
      hostChecks(v, 'exact');
      // A listed parent domain (evil.com for cdn.evil.com) still counts.
      const parts = v.split('.');
      for (let i = 1; i < parts.length - 1 && d.threatfox; i++) {
        const parent = parts.slice(i).join('.');
        for (const r of d.threatfox.domain.get(parent) || []) out.hits.push({ ...tfHit(r, `parent domain ${parent}`), score: Math.round(tfHit(r).score * 0.85) });
      }
    } else if (ind.type === 'url') {
      const alt = v.endsWith('/') ? v.slice(0, -1) : `${v}/`;
      if (d.urlhaus) for (const u of [v, alt]) { const r = d.urlhaus.url.get(u); if (r) out.hits.push(uhHit(r, 'exact URL')); }
      if (d.threatfox) for (const u of [v, alt]) { const r = d.threatfox.url.get(u); if (r) out.hits.push(tfHit(r, 'exact URL')); }
      if (ind.host) hostChecks(ind.host, 'host');
    } else if (ind.type === 'md5' || ind.type === 'sha1' || ind.type === 'sha256') {
      if (d.threatfox) { const r = d.threatfox.hash.get(v); if (r) out.hits.push(tfHit(r, 'exact hash')); }
      if (d.bazaar) {
        const r = d.bazaar.hash.get(v);
        if (r) out.hits.push(bazaarHit(r));
      }
      if (d.sslbl) { const r = d.sslbl.cert.get(v); if (r) out.hits.push({ source: 'SSLBL', kind: 'C2 TLS certificate', c2: true, malware: (r.reason || '').replace(/\s*C&C$/i, '') || null, match: 'certificate SHA1', detail: r.reason, first_seen: r.listed, tags: [], link: `https://sslbl.abuse.ch/ssl-certificates/sha1/${v}/`, score: 90 }); }
      if (this.authKey && !out.hits.some((h) => h.source === 'MalwareBazaar')) {
        const r = await this.bazaarApi(v);
        if (r.error) out.failed.push({ source: 'MalwareBazaar API', error: r.error });
        else { out.ok.push('MalwareBazaar API'); if (r.hit) out.hits.push(r.hit); }
      }
    } else if (ind.type === 'ja3') {
      if (d.ja3) { const r = d.ja3.ja3.get(v); if (r) out.hits.push({ source: 'SSLBL', kind: 'Malware JA3 fingerprint', c2: false, malware: r.reason, match: 'JA3', detail: r.reason, first_seen: r.first_seen, last_seen: r.last_seen, tags: [], link: 'https://sslbl.abuse.ch/ja3-fingerprints/', score: 60 }); }
    }

    if (this.authKey && (ind.type === 'domain' || ind.type === 'ipv4') && !out.hits.some((h) => h.source === 'URLhaus')) {
      const r = await this.urlhausHost(v);
      if (r.error) out.failed.push({ source: 'URLhaus API', error: r.error });
      else { out.ok.push('URLhaus API'); out.hits.push(...r.hits); }
    }
    // One row per source/detail pair, strongest first.
    const seen = new Set();
    out.hits = out.hits.filter((h) => { const k = `${h.source}|${h.detail}`; if (seen.has(k)) return false; seen.add(k); return true; })
      .sort((a, b) => b.score - a.score).slice(0, 20);
    return out;
  }

  async post(url, body, json = false) {
    const res = await httpGet(this.fetch, url, { method: 'POST', timeoutMs: 10000, headers: { 'Auth-Key': this.authKey, Accept: 'application/json', 'Content-Type': json ? 'application/json' : 'application/x-www-form-urlencoded' }, body: json ? JSON.stringify(body) : new URLSearchParams(body).toString() });
    if (res.status === 401 || res.status === 403) throw new Error('auth key rejected');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async bazaarApi(hash) {
    const k = `mb:${hash}`;
    const c = this.api.get(k);
    if (c) return c;
    try {
      const j = await this.post('https://mb-api.abuse.ch/api/v1/', { query: 'get_info', hash });
      if (j.query_status === 'hash_not_found' || j.query_status === 'no_results') return this.api.set(k, { hit: null });
      if (j.query_status !== 'ok' || !Array.isArray(j.data) || !j.data[0]) throw new Error(j.query_status || 'unexpected reply');
      const s = j.data[0];
      return this.api.set(k, { hit: bazaarHit({ sha256: s.sha256_hash, first_seen: s.first_seen, file_name: s.file_name, file_type: s.file_type, signature: s.signature, reporter: s.reporter, tags: s.tags || [] }) });
    } catch (err) { return { error: errText(err) }; }
  }

  async urlhausHost(host) {
    const k = `uh:${host}`;
    const c = this.api.get(k);
    if (c) return c;
    try {
      const j = await this.post('https://urlhaus-api.abuse.ch/v1/host/', { host });
      if (j.query_status === 'no_results') return this.api.set(k, { hits: [] });
      if (j.query_status !== 'ok') throw new Error(j.query_status || 'unexpected reply');
      const hits = (j.urls || []).slice(0, 8).map((u) => uhHit({ url: u.url, status: u.url_status, added: u.date_added, last_online: null, threat: u.threat, tags: u.tags || [], link: u.urlhaus_reference, reporter: u.reporter }, 'host (URLhaus API)'));
      return this.api.set(k, { hits });
    } catch (err) { return { error: errText(err) }; }
  }
}

function bazaarHit(r) {
  return {
    source: 'MalwareBazaar', kind: 'Malware sample', c2: false, malware: r.signature || null, match: 'exact hash',
    detail: [r.file_name, r.file_type].filter(Boolean).join(', ') || r.sha256,
    first_seen: r.first_seen, tags: [r.file_type, r.clamav, ...(r.tags || [])].filter(Boolean).slice(0, 6), reporter: r.reporter,
    link: `https://bazaar.abuse.ch/sample/${r.sha256}/`, score: 100
  };
}

module.exports = { AbuseCh, FEEDS, parseThreatFox, parseUrlhaus, parseBazaar, parseFeodo, parseSslbl, parseJa3, splitHostPort };
