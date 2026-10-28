'use strict';

// Shared plumbing for downloaded threat feeds: a cache that keeps the last good
// copy when a refresh fails, a quoted-CSV reader, and a zip reader good enough
// for the single-archive exports abuse.ch and SigmaHQ publish.

const zlib = require('zlib');

const UA = 'aegis-security/4 (+https://github.com/Sunil56224972/Agies-Security)';

function httpGet(fetchImpl, url, { timeoutMs = 15000, headers = {}, method = 'GET', body } = {}) {
  return fetchImpl(url, { method, body, headers: { 'User-Agent': UA, Accept: '*/*', ...headers }, signal: AbortSignal.timeout(timeoutMs) });
}

const errText = (err) => (err && err.name === 'TimeoutError' ? 'timed out' : (err && err.message) || String(err));

// One CSV row. Handles quoted fields, doubled quotes and the ", " separator
// ThreatFox and MalwareBazaar use.
function parseCsvRow(line) {
  const out = [];
  const n = line.length;
  let i = 0;
  while (i <= n) {
    while (i < n && line[i] === ' ') i++;
    if (line[i] === '"') {
      let v = '';
      i++;
      while (i < n) {
        const c = line[i];
        if (c === '"') {
          if (line[i + 1] === '"') { v += '"'; i += 2; continue; }
          i++;
          break;
        }
        v += c;
        i++;
      }
      out.push(v);
      while (i < n && line[i] !== ',') i++;
      i++;
    } else {
      const j = line.indexOf(',', i);
      const end = j === -1 ? n : j;
      out.push(line.slice(i, end).trim());
      i = end + 1;
    }
  }
  return out;
}

// Calls fn(row) for every data row; '#' lines are comments in every abuse.ch export.
function eachCsvRow(text, fn) {
  const s = String(text);
  let start = 0;
  while (start < s.length) {
    let end = s.indexOf('\n', start);
    if (end === -1) end = s.length;
    let line = s.slice(start, end);
    start = end + 1;
    if (line.endsWith('\r')) line = line.slice(0, -1);
    if (!line || line[0] === '#') continue;
    fn(parseCsvRow(line));
  }
}

// Reads the central directory of a zip and returns [{ name, data() }].
function unzip(buf) {
  const eocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0) throw new Error('not a zip archive');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const entries = [];
  for (let k = 0; k < count; k++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) throw new Error('corrupt zip directory');
    const method = buf.readUInt16LE(off + 10);
    const csize = buf.readUInt32LE(off + 20);
    const nl = buf.readUInt16LE(off + 28);
    const el = buf.readUInt16LE(off + 30);
    const cl = buf.readUInt16LE(off + 32);
    const local = buf.readUInt32LE(off + 42);
    const name = buf.toString('utf8', off + 46, off + 46 + nl);
    off += 46 + nl + el + cl;
    entries.push({
      name,
      data() {
        const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
        const raw = buf.subarray(start, start + csize);
        if (method === 0) return raw;
        if (method === 8) return zlib.inflateRawSync(raw);
        throw new Error(`zip method ${method} not supported`);
      }
    });
  }
  return entries;
}

// Downloads, parses and caches named feeds. A failed refresh keeps the previous
// copy and records the error; a feed that never loaded is retried after `retry`.
class FeedCache {
  constructor({ fetchImpl = globalThis.fetch, offline = false } = {}) {
    this.fetch = fetchImpl;
    this.offline = offline;
    this.state = new Map();
    this.inflight = new Map();
  }

  async load(def, { force = false } = {}) {
    if (this.offline) return { data: null, error: 'Threat intel disabled (AEGIS_INTEL=off)' };
    const have = this.state.get(def.id);
    if (!force && have && have.data && Date.now() - have.at < (def.ttl || 6 * 3600000)) return have;
    if (!force && have && !have.data && Date.now() - have.at < (def.retry || 10 * 60000)) return have;
    if (this.inflight.has(def.id)) return this.inflight.get(def.id);
    const p = (async () => {
      const t0 = Date.now();
      try {
        if (def.unavailable) throw new Error(def.unavailable);
        // def.urls lists candidates in order of preference; a 404 moves on to the next one.
        const urls = Array.isArray(def.urls) && def.urls.length ? def.urls : [def.url];
        const get = async (url) => {
          try { return await httpGet(this.fetch, url, { timeoutMs: def.timeoutMs || 30000, headers: def.headers }); }
          catch (err) {
            // One retry for a dropped connection; a timeout already waited long enough.
            if (err && err.name === 'TimeoutError') throw err;
            await new Promise((r) => setTimeout(r, 1500));
            return httpGet(this.fetch, url, { timeoutMs: def.timeoutMs || 30000, headers: def.headers });
          }
        };
        let body;
        if (Array.isArray(def.mergeUrls) && def.mergeUrls.length) {
          const parts = await Promise.all(def.mergeUrls.map(async (u) => {
            const r = await get(u);
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return def.binary ? Buffer.from(await r.arrayBuffer()) : await r.text();
          }));
          body = def.binary ? Buffer.concat(parts) : parts.join('\n');
        } else {
          let res;
          for (let i = 0; i < urls.length; i++) {
            res = await get(urls[i]);
            if (res.status !== 404 || i === urls.length - 1) break;
          }
          if (res.status === 401 || res.status === 403) throw new Error(def.authError || `HTTP ${res.status}: access refused`);
          if (res.status === 410) throw new Error('HTTP 410: the provider retired this download');
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          body = def.binary ? Buffer.from(await res.arrayBuffer()) : await res.text();
        }
        const data = def.parse(body);
        const entries = def.size ? def.size(data) : null;
        if (entries === 0) throw new Error('feed was empty');
        const rec = { at: Date.now(), data, error: null, entries, bytes: Buffer.isBuffer(body) ? body.length : Buffer.byteLength(body, 'utf8'), ms: Date.now() - t0 };
        this.state.set(def.id, rec);
        return rec;
      } catch (err) {
        // A stale copy beats no copy.
        const rec = have && have.data ? { ...have, error: errText(err) } : { at: Date.now(), data: null, error: errText(err) };
        this.state.set(def.id, rec);
        return rec;
      } finally { this.inflight.delete(def.id); }
    })();
    this.inflight.set(def.id, p);
    return p;
  }

  // Waits at most budgetMs for a feed. A slow first download keeps running in the
  // background and serves the next request.
  async within(def, budgetMs) {
    const p = this.load(def);
    if (!budgetMs) return p;
    let timer;
    const late = new Promise((resolve) => { timer = setTimeout(() => resolve({ data: null, loading: true, error: 'still downloading, ask again in a few seconds' }), budgetMs); });
    try { return await Promise.race([p, late]); } finally { clearTimeout(timer); }
  }

  // Drops what is known about a feed, e.g. after its credentials change.
  forget(id) { this.state.delete(id); }

  status(def) {
    const s = this.state.get(def.id);
    const ok = Boolean(s && s.data);
    return {
      id: def.id, name: def.name, provider: def.provider, url: def.url, note: def.note || null,
      loaded: ok, loading: this.inflight.has(def.id),
      entries: ok ? s.entries : null, bytes: ok ? s.bytes : null,
      loaded_at: ok ? new Date(s.at).toISOString() : null, fetch_ms: ok ? s.ms : null,
      error: s ? s.error : null
    };
  }
}

// Bounded cache for per-indicator lookups.
class TtlCache {
  constructor(max = 2000, ttl = 6 * 3600000) { this.max = max; this.ttl = ttl; this.m = new Map(); }
  get(k) {
    const v = this.m.get(k);
    if (!v) return undefined;
    if (Date.now() > v.exp) { this.m.delete(k); return undefined; }
    return v.data;
  }
  set(k, data, ttl = this.ttl) {
    if (this.m.size >= this.max) this.m.delete(this.m.keys().next().value);
    this.m.set(k, { data, exp: Date.now() + ttl });
    return data;
  }
}

module.exports = { httpGet, errText, parseCsvRow, eachCsvRow, unzip, FeedCache, TtlCache, UA };
