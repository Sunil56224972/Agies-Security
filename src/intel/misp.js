'use strict';

// MISP threat sharing. By default Aegis reads the public botvrij.eu OSINT feed,
// which is published in MISP's own feed format: a manifest of events and a
// hashes.csv of md5(attribute value) -> event uuid. A hit loads the event JSON to
// show the analyst which report the indicator came from.
//
// With MISP_URL and MISP_KEY set, the organisation's own MISP instance is
// searched as well through /attributes/restSearch.

const crypto = require('crypto');
const { FeedCache, httpGet, errText, TtlCache } = require('./feeds');

const BASE = 'https://www.botvrij.eu/data/feed-osint';
const md5 = (s) => crypto.createHash('md5').update(String(s), 'utf8').digest('hex');

function parseHashes(text) {
  const map = new Map();
  for (const line of String(text).split('\n')) {
    const i = line.indexOf(',');
    if (i !== 32) continue;
    const h = line.slice(0, 32); const ev = line.slice(33).trim();
    const have = map.get(h);
    if (!have) map.set(h, ev);
    else if (Array.isArray(have)) { if (have.length < 10 && !have.includes(ev)) have.push(ev); }
    else if (have !== ev) map.set(h, [have, ev]);
  }
  return map;
}

function parseManifest(text) {
  const raw = JSON.parse(text);
  const events = new Map();
  for (const [uuid, e] of Object.entries(raw)) events.set(uuid, { uuid, info: e.info, date: e.date, org: e.Orgc ? e.Orgc.name : null, threat_level: Number(e.threat_level_id) || null, tags: (e.Tag || []).map((t) => t.name).filter((n) => !/^tlp:/i.test(n)) });
  return events;
}

const LEVEL = { 1: 'high', 2: 'medium', 3: 'low', 4: 'undefined' };
// Only galaxy tags name an actor, family or technique; the rest are workflow labels.
const prettyTag = (t) => (/^misp-galaxy:/i.test(t) ? String(t).replace(/^misp-galaxy:[a-z-]+="?/i, '').replace(/"$/, '') : null);

const FEEDS = {
  hashes: { id: 'misp-hashes', name: 'botvrij.eu OSINT attribute index', provider: 'MISP OSINT', url: `${BASE}/hashes.csv`, ttl: 12 * 3600000, timeoutMs: 45000, parse: parseHashes, size: (d) => d.size, note: 'MISP feed: hashed values of every published attribute' },
  manifest: { id: 'misp-manifest', name: 'botvrij.eu OSINT events', provider: 'MISP OSINT', url: `${BASE}/manifest.json`, ttl: 12 * 3600000, timeoutMs: 30000, parse: parseManifest, size: (d) => d.size, note: 'Event titles, dates, publishing org and galaxy tags' }
};

class Misp {
  constructor({ fetchImpl = globalThis.fetch, offline = false, url = null, key = null } = {}) {
    this.fetch = fetchImpl;
    this.offline = offline;
    this.cache = new FeedCache({ fetchImpl, offline });
    this.events = new TtlCache(200, 12 * 3600000);
    this.own = url && key ? { url: String(url).replace(/\/+$/, ''), key } : null;
    this.ownCache = new TtlCache(1000, 3600000);
  }

  get available() { return !this.offline; }
  describe() { return { own_instance: this.own ? this.own.url : null, feeds: Object.values(FEEDS).map((f) => this.cache.status(f)) }; }
  warm() { if (!this.offline) Object.values(FEEDS).forEach((f) => this.cache.load(f).catch(() => {})); }
  refresh() { return Promise.all(Object.values(FEEDS).map((f) => this.cache.load(f, { force: true }))); }

  // The attributes of one event that match the indicator (type, category, IDS flag).
  async event(uuid) {
    const have = this.events.get(uuid);
    if (have) return have;
    const res = await httpGet(this.fetch, `${BASE}/${encodeURIComponent(uuid)}.json`, { timeoutMs: 10000, headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`event ${uuid}: HTTP ${res.status}`);
    const e = (await res.json()).Event || {};
    const attrs = [...(e.Attribute || []), ...(e.Object || []).flatMap((o) => (o.Attribute || []).map((a) => ({ ...a, object: o.name })))];
    return this.events.set(uuid, { uuid, info: e.info, date: e.date, org: e.Orgc ? e.Orgc.name : null, attrs: attrs.map((a) => ({ type: a.type, category: a.category, value: a.value, to_ids: Boolean(a.to_ids), comment: a.comment || '', object: a.object || null })), size: attrs.length });
  }

  async lookup(ind, { budgetMs = 15000 } = {}) {
    const out = { hits: [], ok: [], failed: [], pending: [] };
    if (this.offline) return { ...out, skipped: true };
    const [h, m] = await Promise.all([this.cache.within(FEEDS.hashes, budgetMs), this.cache.within(FEEDS.manifest, budgetMs)]);
    if (h.data) {
      out.ok.push('MISP OSINT');
      const v = String(ind.value);
      // Feed values are hashed exactly as published, so try the common spellings.
      const tries = [...new Set([v, v.toLowerCase(), ind.port ? `${v}|${ind.port}` : null, ind.type === 'url' && v.endsWith('/') ? v.slice(0, -1) : null].filter(Boolean))];
      const uuids = new Set();
      for (const t of tries) { const got = h.data.get(md5(t)); if (got) (Array.isArray(got) ? got : [got]).forEach((u) => uuids.add(u)); }
      for (const uuid of [...uuids].slice(0, 6)) {
        const meta = (m.data && m.data.get(uuid)) || { uuid };
        let attr = null;
        try {
          const ev = await this.event(uuid);
          attr = ev.attrs.find((a) => String(a.value).toLowerCase() === v.toLowerCase() || String(a.value).toLowerCase().split('|')[0] === v.toLowerCase()) || null;
          if (!meta.info) Object.assign(meta, { info: ev.info, date: ev.date, org: ev.org, tags: [] });
        } catch (err) { out.failed.push({ source: 'MISP event', error: errText(err) }); }
        out.hits.push({
          source: 'MISP OSINT', kind: attr ? `${attr.category}: ${attr.type}` : 'Event attribute', c2: Boolean(attr && /c2|c&c|command/i.test(`${attr.comment} ${meta.info}`)),
          malware: (meta.tags || []).map(prettyTag).find((t) => t && !/^T\d{4}/.test(t) && t.length < 40) || null,
          match: 'attribute value', detail: meta.info || uuid, event: uuid, event_date: meta.date || null, org: meta.org || null,
          threat_level: LEVEL[meta.threat_level] || null, to_ids: attr ? attr.to_ids : null, comment: attr ? attr.comment : null,
          tags: (meta.tags || []).map(prettyTag).filter(Boolean).slice(0, 6), first_seen: meta.date || null,
          link: `${BASE}/${uuid}.json`,
          // Attributes not flagged for IDS are context (report links, victims, tooling) and do not score.
          score: attr && attr.to_ids ? 80 : null
        });
      }
    } else if (h.loading) out.pending.push('MISP OSINT');
    else out.failed.push({ source: 'MISP OSINT', error: h.error });

    if (this.own) {
      const r = await this.searchOwn(ind.value);
      if (r.error) out.failed.push({ source: 'MISP (own)', error: r.error });
      else { out.ok.push('MISP (own)'); out.hits.push(...r.hits); }
    }
    return out;
  }

  async searchOwn(value) {
    const have = this.ownCache.get(value);
    if (have) return have;
    try {
      const res = await httpGet(this.fetch, `${this.own.url}/attributes/restSearch`, {
        method: 'POST', timeoutMs: 10000,
        headers: { Authorization: this.own.key, Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ returnFormat: 'json', value, limit: 20, includeEventTags: true })
      });
      if (res.status === 401 || res.status === 403) throw new Error('MISP_KEY rejected');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const j = await res.json();
      const attrs = (j.response && j.response.Attribute) || [];
      const hits = attrs.slice(0, 10).map((a) => ({
        source: 'MISP (own)', kind: `${a.category}: ${a.type}`, c2: false, malware: null, match: 'attribute value',
        detail: (a.Event && a.Event.info) || `event ${a.event_id}`, event: a.event_id, org: a.Event && a.Event.Orgc ? a.Event.Orgc.name : null,
        to_ids: Boolean(a.to_ids), comment: a.comment || null, first_seen: a.first_seen || (a.timestamp ? new Date(Number(a.timestamp) * 1000).toISOString() : null),
        tags: (a.Tag || []).map((t) => prettyTag(t.name)).filter(Boolean).slice(0, 6), link: `${this.own.url}/events/view/${a.event_id}`, score: a.to_ids ? 85 : null
      }));
      return this.ownCache.set(value, { hits });
    } catch (err) { return { error: errText(err) }; }
  }
}

module.exports = { Misp, parseHashes, parseManifest, md5 };
