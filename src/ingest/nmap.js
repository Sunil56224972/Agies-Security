'use strict';

// Nmap XML (`nmap -sV -O -oX scan.xml ...`) to Aegis asset rows. A small,
// purpose-built reader: Nmap's output is regular, machine-generated XML, so
// attribute extraction per element is enough and avoids a parser dependency.

const { isIP } = require('../engine/analysis');

const decode = (s) => String(s)
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'")
  .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
  .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
  .replace(/&amp;/g, '&');

function attrs(tag) {
  const out = {};
  const re = /([\w:-]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let m;
  while ((m = re.exec(tag))) out[m[1]] = decode(m[3] !== undefined ? m[3] : m[4]);
  return out;
}

const looksLikeNmap = (text) => /<nmaprun[\s>]/.test(String(text).slice(0, 4000));

function osFamily(name) {
  const n = String(name || '').toLowerCase();
  if (/windows/.test(n)) return 'Windows';
  if (/mac ?os|darwin|ios\b/.test(n)) return 'macOS';
  if (/freebsd|openbsd|netbsd/.test(n)) return 'BSD';
  if (/linux|ubuntu|debian|centos|red hat|rhel|fedora|alpine|suse|android/.test(n)) return 'Linux';
  if (/cisco|juniper|fortinet|palo alto|routeros|embedded|printer/.test(n)) return 'Network device';
  return n ? 'Other' : 'Unknown';
}

function parseNmapXml(text) {
  const src = String(text || '');
  const hosts = [];
  const scanned = (src.match(/<nmaprun[^>]*\sstart="(\d+)"/) || [])[1];
  const blocks = src.split(/<host[\s>]/).slice(1).map((b) => b.split('</host>')[0]);
  for (const b of blocks) {
    const status = attrs((b.match(/<status\b[^>]*>/) || [''])[0]);
    if (status.state && status.state !== 'up') continue;
    const addrs = [...b.matchAll(/<address\b[^>]*>/g)].map((m) => attrs(m[0]));
    const ipRow = addrs.find((a) => a.addrtype === 'ipv4') || addrs.find((a) => a.addrtype === 'ipv6');
    if (!ipRow || !isIP(ipRow.addr)) continue;
    const mac = addrs.find((a) => a.addrtype === 'mac');
    const names = [...b.matchAll(/<hostname\b[^>]*>/g)].map((m) => attrs(m[0]));
    const name = (names.find((n) => n.type === 'user') || names.find((n) => n.type === 'PTR') || names[0] || {}).name;

    const services = []; const packages = [];
    for (const pm of b.matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/g)) {
      const p = attrs(pm[1]);
      const state = attrs((pm[2].match(/<state\b[^>]*>/) || [''])[0]);
      if (state.state !== 'open') continue;
      const svc = attrs((pm[2].match(/<service\b[^>]*>/) || [''])[0]);
      const label = [svc.product, svc.version, svc.extrainfo ? `(${svc.extrainfo})` : null].filter(Boolean).join(' ') || svc.name || 'unknown';
      services.push({ port: Number(p.portid), service: `${label}${p.protocol === 'udp' ? ' udp' : ''}`.slice(0, 120) });
      // Versioned products double as packages so CVE matching sees them.
      if (svc.product && svc.version) packages.push(`${svc.product} ${svc.version}`.slice(0, 160));
      for (const c of pm[2].matchAll(/<cpe>([^<]+)<\/cpe>/g)) packages.push(decode(c[1]).slice(0, 160));
    }
    const osMatch = attrs((b.match(/<osmatch\b[^>]*>/) || [''])[0]);
    const osName = osMatch.name || null;
    const ostype = (services.length && (b.match(/ostype="([^"]+)"/) || [])[1]) || null;
    hosts.push({
      ip_address: ipRow.addr,
      hostname: name || `host-${ipRow.addr.replace(/[.:]/g, '-')}`,
      os_family: osFamily(osName || ostype),
      os_version: (osName ? `${osName}${osMatch.accuracy ? ` (${osMatch.accuracy}%)` : ''}` : ostype || 'Unknown').slice(0, 80),
      running_services: services.slice(0, 64),
      installed_packages: [...new Set(packages)].slice(0, 400),
      mac: mac ? `${mac.addr}${mac.vendor ? ` ${mac.vendor}` : ''}` : null,
      source: 'nmap',
      last_scanned: scanned ? new Date(Number(scanned) * 1000).toISOString() : new Date().toISOString()
    });
  }
  return hosts;
}

module.exports = { parseNmapXml, looksLikeNmap, osFamily };