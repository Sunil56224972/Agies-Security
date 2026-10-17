'use strict';

// Recognises the indicator types analysts paste (IPs, domains, URLs, file
// hashes, JA3 fingerprints) and pulls them out of free text and alert payloads.
// Defanged forms such as hxxp://evil[.]com and 1.2.3[.]4 are accepted.

const net = require('net');

const HEX = { 32: 'md5', 40: 'sha1', 64: 'sha256' };
// Second-level labels that act like a TLD, so "evil.co.uk" is a registered domain.
const SLD = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'gob', 'mil', 'nic']);
// File-name endings that look like a TLD but show up in logs as paths, not hosts.
const NOT_TLD = new Set(['php', 'html', 'htm', 'asp', 'aspx', 'jsp', 'js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'txt', 'log', 'conf', 'json', 'xml', 'yml', 'yaml', 'sh', 'py', 'pl', 'rb', 'exe', 'dll', 'bin', 'so', 'jar', 'war', 'zip', 'gz', 'tar', 'tmp', 'bak', 'old', 'ini', 'env', 'cgi', 'do', 'action', 'map', 'woff', 'woff2', 'ttf', 'local', 'internal', 'lan', 'localdomain', 'arpa', 'example', 'invalid', 'test']);

function refang(s) {
  return String(s || '').trim()
    .replace(/^hxxp/i, 'http').replace(/^fxp/i, 'ftp')
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
    .replace(/\[:\]/g, ':').replace(/\[\/\]/g, '/')
    .replace(/\[at\]|\(at\)/gi, '@');
}

const DOMAIN_RE = /^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/i;

function isDomain(s) {
  if (!DOMAIN_RE.test(s)) return false;
  const tld = s.slice(s.lastIndexOf('.') + 1).toLowerCase();
  return !NOT_TLD.has(tld) && !/^\d+$/.test(tld);
}

// The registrable part of a host name: a.b.example.com -> example.com.
function registered(host) {
  const parts = String(host).toLowerCase().split('.');
  if (parts.length <= 2) return parts.join('.');
  const n = SLD.has(parts[parts.length - 2]) && parts[parts.length - 1].length === 2 ? 3 : 2;
  return parts.slice(-n).join('.');
}

// { type, value, host?, display } or null. type: ipv4 | ipv6 | domain | url | md5 | sha1 | sha256 | asn
function classify(input) {
  let s = refang(input);
  if (!s) return null;
  if (/^as\d{1,10}$/i.test(s)) return { type: 'asn', value: s.toUpperCase(), display: s.toUpperCase() };
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      if (!/^(https?|ftp|tcp|udp)$/i.test(u.protocol.replace(':', ''))) return null;
      const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
      if (!net.isIP(host) && !isDomain(host)) return null;
      return { type: 'url', value: s, host, display: s };
    } catch { return null; }
  }
  s = s.replace(/^\[|\]$/g, '');
  if (net.isIPv4(s)) return { type: 'ipv4', value: s, display: s };
  if (net.isIPv6(s)) return { type: 'ipv6', value: s.toLowerCase(), display: s.toLowerCase() };
  const ipPort = s.match(/^((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})$/);
  if (ipPort && net.isIPv4(ipPort[1])) return { type: 'ipv4', value: ipPort[1], port: Number(ipPort[2]), display: s };
  if (/^[a-f0-9]+$/i.test(s) && HEX[s.length]) return { type: HEX[s.length], value: s.toLowerCase(), display: s.toLowerCase() };
  const host = s.toLowerCase().replace(/\.$/, '');
  if (isDomain(host)) return { type: 'domain', value: host, display: host };
  // A bare host with a path, e.g. "evil.com/payload.sh".
  const hp = s.match(/^([a-z0-9_.-]+\.[a-z]{2,63})(:\d+)?(\/\S*)$/i);
  if (hp && isDomain(hp[1].toLowerCase())) return classify(`http://${s}`);
  return null;
}

const isIpType = (t) => t === 'ipv4' || t === 'ipv6';
const isHashType = (t) => t === 'md5' || t === 'sha1' || t === 'sha256';

// Every distinct indicator in a block of pasted text, in order of appearance.
function extractAll(text, { max = 500 } = {}) {
  const src = refang(String(text || '').replace(/hxxp/gi, 'http'));
  const out = []; const seen = new Set();
  const add = (v) => {
    const c = classify(v);
    if (!c) return;
    const key = `${c.type}:${c.value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key); out.push(c);
  };
  const tokenRe = /(?:https?|ftp):\/\/[^\s"'<>`,;|]+|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b|\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b|\bAS\d{1,10}\b|(?:\b[a-z0-9_-]+\.)+[a-z]{2,63}\b|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}/gi;
  let m;
  while ((m = tokenRe.exec(src)) && out.length < max) {
    let tok = m[0].replace(/[).\]]+$/, '');
    if (/^[0-9a-f:]+$/i.test(tok) && tok.includes(':') && !net.isIPv6(tok)) continue;
    // A domain inside a URL that was already taken whole is skipped by the regex order.
    add(tok);
  }
  return out;
}

// Network and file indicators worth looking up from an alert payload: TLS SNI,
// Host headers, DNS queries, URLs, hashes and JA3. IPs are handled elsewhere.
function fromPayload(payload) {
  const text = String(payload || '');
  const out = []; const seen = new Set();
  const push = (c, where) => {
    if (!c) return;
    const key = `${c.type}:${c.value}`;
    if (seen.has(key)) return;
    seen.add(key); out.push({ ...c, where });
  };
  for (const m of text.matchAll(/SNI[=:]\s*([^\s,;"]+)/gi)) push(classify(m[1]), 'TLS SNI');
  for (const m of text.matchAll(/^host:\s*([^\s:]+)/gim)) push(classify(m[1]), 'HTTP Host');
  for (const m of text.matchAll(/(?:query|rrname|qname)[=:]\s*"?([a-z0-9_.-]+\.[a-z]{2,63})/gi)) push(classify(m[1]), 'DNS query');
  for (const m of text.matchAll(/(?:https?|ftp):\/\/[^\s"'<>`]+/gi)) {
    const c = classify(m[0].replace(/[)\]}.,;]+$/, ''));
    if (c && !net.isIP(c.host)) push(c, 'URL');
  }
  for (const m of text.matchAll(/ldaps?:\/\/([a-z0-9_.-]+\.[a-z]{2,63})/gi)) push(classify(m[1]), 'JNDI callback');
  for (const m of text.matchAll(/JA3S?[=:]\s*([a-f0-9]{32})/gi)) push({ type: 'ja3', value: m[1].toLowerCase(), display: m[1].toLowerCase() }, 'JA3');
  for (const m of text.matchAll(/(?:sha256|sha1|md5|hash)[=:]\s*([a-f0-9]{32,64})\b/gi)) push(classify(m[1]), 'File hash');
  return out.filter((c) => c.type !== 'domain' || isDomain(c.value)).slice(0, 8);
}

module.exports = { classify, refang, extractAll, fromPayload, registered, isDomain, isIpType, isHashType };
