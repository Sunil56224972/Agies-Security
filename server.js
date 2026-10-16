'use strict';

require('dotenv').config();
const { createStore } = require('./src/store');
const { createEnforcer } = require('./src/enforce');
const { NvdClient } = require('./src/intel/nvd');
const { Reputation } = require('./src/intel/reputation');
const { createApp } = require('./src/app');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

async function main() {
  const { store, warning: storeWarning, demo } = await createStore(process.env);
  const { enforcer, warning: enforceWarning } = createEnforcer(process.env);
  const nvd = new NvdClient({ apiKey: process.env.NVD_API_KEY });
  const reputation = new Reputation({ apiKey: process.env.ABUSEIPDB_API_KEY });
  const warnings = [storeWarning, enforceWarning].filter(Boolean);

  const { app, investigator } = createApp({ store, enforcer, nvd, reputation, env: process.env, demo, warnings });
  const users = await store.users.count();

  const server = app.listen(PORT, HOST, () => {
    const line = (k, v) => console.log(`  ${k.padEnd(12)}${v}`);
    console.log(`\n  Aegis Security  http://localhost:${PORT}`);
    line('Storage', store.label);
    line('Enforcement', `${enforcer.label} (${enforcer.mode})`);
    line('Engine', investigator.llmAvailable ? `playbook + ${investigator.model}` : 'playbook (set GROQ_API_KEY for the LLM agent)');
    line('Intel', `NVD${process.env.NVD_API_KEY ? ' (keyed)' : ' (public quota)'}${reputation.available ? ', AbuseIPDB' : ''}`);
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

main().catch((err) => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});