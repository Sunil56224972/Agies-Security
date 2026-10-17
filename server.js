'use strict';

// Entry point for both `npm start` (long-running server) and Vercel, which
// imports this module and sends every request to the exported Express app.
require('dotenv').config();
const express = require('express');
const { createStore } = require('./src/store');
const { createEnforcer } = require('./src/enforce');
const { NvdClient } = require('./src/intel/nvd');
const { ThreatIntel } = require('./src/intel/threatintel');
const { createApp } = require('./src/app');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

async function build() {
  const { store, warning: storeWarning, demo } = await createStore(process.env);
  const { enforcer, warning: enforceWarning } = createEnforcer(process.env);
  const nvd = new NvdClient({ apiKey: process.env.NVD_API_KEY });
  const reputation = new ThreatIntel({ abuseKey: process.env.ABUSEIPDB_API_KEY, offline: /^(0|off|false|no)$/i.test(String(process.env.AEGIS_INTEL || '')) });
  const warnings = [storeWarning, enforceWarning].filter(Boolean);
  const { app, investigator } = createApp({ store, enforcer, nvd, reputation, env: process.env, demo, warnings });
  return { app, investigator, store, enforcer, reputation, warnings, demo };
}

// Built once per process (or per serverless instance). A failed boot is not
// cached, so the next request retries instead of serving errors forever.
let booting = null;
function boot() {
  if (!booting) booting = build().catch((err) => { booting = null; throw err; });
  return booting;
}

const handler = express();
handler.disable('x-powered-by');
handler.use((req, res, next) => boot().then(({ app }) => app(req, res, next), next));
// eslint-disable-next-line no-unused-vars
handler.use((err, req, res, next) => {
  console.error(`Boot failed: ${err.message}`);
  res.status(503).json({ error: 'Aegis could not start. The server log has the reason.' });
});

module.exports = handler;

async function main() {
  const { store, enforcer, investigator, reputation, warnings, demo } = await boot();
  const users = await store.users.count();
  const server = handler.listen(PORT, HOST, () => {
    const line = (k, v) => console.log(`  ${k.padEnd(12)}${v}`);
    console.log(`\n  Aegis Security  http://localhost:${PORT}`);
    line('Storage', store.label);
    line('Enforcement', `${enforcer.label} (${enforcer.mode})`);
    line('Engine', investigator.llmAvailable ? `rule-based playbook + ${investigator.model}` : 'rule-based playbook (add GROQ_API_KEY to enable the LLM agent)');
    line('Intel', `NVD${process.env.NVD_API_KEY ? ' (keyed)' : ' (public quota)'}, ${reputation.describe().sources.length} reputation sources`);
    if (demo) line('Mode', 'DEMO dataset loaded (AEGIS_DEMO=1)');
    for (const w of warnings) line('Warning', w);
    if (!users) line('Setup', `No users yet. Open http://localhost:${PORT} to create the first administrator.`);
    console.log('');
  });

  const shutdown = () => {
    server.close(() => {
      if (typeof store.flush === 'function') store.flush();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`Fatal: ${err.message}`);
    process.exit(1);
  });
}