'use strict';

// Shared platforms and infrastructure. abuse.ch lists individual malicious URLs
// and C2 endpoints; when those sit on GitHub, Google Drive, Discord's CDN or a
// Cloudflare address, the URL is bad but the platform is not. Matches on these
// hosts are kept as context and never score the host itself.

const SHARED_HOSTS = [
  // Code and file hosting
  'github.com', 'githubusercontent.com', 'github.io', 'gitlab.com', 'gitlab.io', 'bitbucket.org', 'sourceforge.net',
  'drive.google.com', 'docs.google.com', 'sites.google.com', 'storage.googleapis.com', 'googleusercontent.com', 'firebasestorage.googleapis.com', 'appspot.com', 'web.app', 'firebaseapp.com',
  'dropbox.com', 'dropboxusercontent.com', 'onedrive.live.com', '1drv.ms', 'sharepoint.com', 'live.com',
  'mediafire.com', 'mega.nz', 'box.com', 'wetransfer.com', 'transfer.sh', 'archive.org', 'pastebin.com', 'paste.ee',
  'discord.com', 'discordapp.com', 'discordapp.net', 't.me', 'telegram.org', 'telegra.ph',
  // Cloud object storage, CDNs and app platforms
  'amazonaws.com', 'cloudfront.net', 'azureedge.net', 'azurewebsites.net', 'core.windows.net', 'windows.net', 'cloudapp.net',
  'workers.dev', 'pages.dev', 'r2.dev', 'trycloudflare.com', 'netlify.app', 'vercel.app', 'herokuapp.com', 'glitch.me', 'replit.app', 'repl.co', 'onrender.com', 'fly.dev', 'ngrok.io', 'ngrok-free.app', 'ngrok.app',
  'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com', 'square.site', 'webflow.io', 'notion.site', 'canva.site', 'godaddysites.com',
  'bit.ly', 'tinyurl.com', 'is.gd', 'rebrand.ly', 'cutt.ly',
  // Major services whose own domains are not malicious
  'google.com', 'gstatic.com', 'youtube.com', 'microsoft.com', 'office.com', 'office365.com', 'outlook.com', 'apple.com', 'icloud.com',
  'amazon.com', 'cloudflare.com', 'facebook.com', 'fbcdn.net', 'instagram.com', 'whatsapp.net', 'twitter.com', 'x.com', 'linkedin.com',
  'akamaihd.net', 'akamaized.net', 'fastly.net', 'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com', 'npmjs.org', 'pypi.org', 'pythonhosted.org'
];

// Dynamic DNS parents: the zone is not malicious, a sub-domain under it can be.
const DDNS_PARENTS = ['duckdns.org', 'no-ip.com', 'no-ip.org', 'ddns.net', 'hopto.org', 'zapto.org', 'sytes.net', 'serveo.net', 'dynu.net', 'freedns.afraid.org', 'mooo.com'];

function under(host, list) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  return Boolean(h) && list.some((d) => h === d || h.endsWith(`.${d}`));
}

const isSharedHost = (host) => under(host, SHARED_HOSTS);
const isDdnsParent = (host) => DDNS_PARENTS.includes(String(host || '').toLowerCase());

// Network owners whose addresses front thousands of unrelated customers. A C2
// domain that resolves to a Cloudflare edge IP lists that IP in ThreatFox; the
// address itself is not the attacker.
const CDN_ORG = /\b(cloudflare|akamai|fastly|amazon|aws|cloudfront|google|microsoft|azure|incapsula|imperva|sucuri|stackpath|edgecast|limelight|bunny|cdn77|cdnetworks|vercel|netlify|github|digitalocean app platform)\b/i;
const isCdnOrg = (org) => Boolean(org) && CDN_ORG.test(String(org));

module.exports = { isSharedHost, isDdnsParent, isCdnOrg, SHARED_HOSTS };

