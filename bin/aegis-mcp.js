#!/usr/bin/env node
'use strict';
// stdio <-> HTTP bridge for MCP clients that only speak stdio.
// Reads newline-delimited JSON-RPC from stdin, forwards each message to the
// Aegis /mcp endpoint and writes the reply to stdout.
//
//   AEGIS_URL       base URL of the console (default https://agiessecurity.vercel.app)
//   AEGIS_API_KEY   key with the "mcp" or "mcp:write" scope (Settings > API keys)

const readline = require('readline');

const base = (process.env.AEGIS_URL || 'https://agiessecurity.vercel.app').replace(/\/+$/, '');
const key = process.env.AEGIS_API_KEY || '';
const endpoint = `${base}/mcp`;

if (!key) {
  process.stderr.write('aegis-mcp: AEGIS_API_KEY is not set. Create a key with the mcp scope in Settings > API keys.\n');
  process.exit(1);
}
if (typeof fetch !== 'function') {
  process.stderr.write('aegis-mcp: Node 18 or newer is required.\n');
  process.exit(1);
}

let pending = 0;
let closing = false;
const write = (obj) => process.stdout.write(`${JSON.stringify(obj)}\n`);
const idsOf = (msg) => (Array.isArray(msg) ? msg : [msg]).filter((m) => m && m.id !== undefined && m.id !== null).map((m) => m.id);
const fail = (msg, code, message) => idsOf(msg).forEach((id) => write({ jsonrpc: '2.0', id, error: { code, message } }));
const done = () => { pending--; if (closing && pending === 0) process.exit(0); };

async function forward(line) {
  let msg;
  try { msg = JSON.parse(line); } catch {
    write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  pending++;
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        authorization: `Bearer ${key}`,
        'user-agent': 'aegis-mcp-bridge/1.0',
      },
      body: JSON.stringify(msg),
    });
    if (res.status === 202) return;
    const text = await res.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
    if (body && (body.result !== undefined || body.error !== undefined || Array.isArray(body))) {
      // A key error comes back with id null; re-address it to the caller's ids.
      if (!Array.isArray(body) && body.id === null && body.error && idsOf(msg).length) fail(msg, body.error.code, body.error.message);
      else write(body);
      if (!res.ok) process.stderr.write(`aegis-mcp: HTTP ${res.status} ${body.error ? body.error.message : ''}\n`);
      return;
    }
    process.stderr.write(`aegis-mcp: HTTP ${res.status} from ${endpoint}\n`);
    fail(msg, -32603, `Aegis returned HTTP ${res.status}`);
  } catch (err) {
    process.stderr.write(`aegis-mcp: ${err.message}\n`);
    fail(msg, -32603, `Cannot reach ${endpoint}: ${err.message}`);
  } finally {
    done();
  }
}

const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => { if (line.trim()) forward(line.trim()); });
rl.on('close', () => { closing = true; if (pending === 0) process.exit(0); });