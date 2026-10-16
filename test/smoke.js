'use strict';
// Smoke test: runs the playbook against every seeded alert using an isolated local store.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { MemoryStore } = require('../src/store/memory');
const { Investigator } = require('../src/engine/investigator');

const expected = {
  'ALERT-2026-9001': ['ATTACK_SUCCEEDED', 'CONTAINED'],
  'ALERT-2026-9002': ['ATTACK_SUCCEEDED', 'CONTAINED'],
  'ALERT-2026-9003': ['FALSE_POSITIVE', 'FALSE_POSITIVE'],
  'ALERT-2026-9004': ['ATTACK_FAILED', 'MITIGATED'],
  'ALERT-2026-9005': ['ATTACK_FAILED', 'MITIGATED'],
  'ALERT-2026-9006': ['ATTACK_SUCCEEDED', 'CONTAINED']
};

(async () => {
  const file = path.join(__dirname, '..', '.data', 'sandbox.json');
  const backup = fs.existsSync(file) ? fs.readFileSync(file) : null;
  const store = new MemoryStore();
  store.persist = () => {};
  await store.init();
  await store.reset();
  const inv = new Investigator(store);
  let failed = 0;
  for (const [id, [outcome, status]] of Object.entries(expected)) {
    const events = [];
    const r = await inv.run(id, e => events.push(e), { pace: 0 });
    const alert = await store.alerts.get(id);
    const ok = r.outcome === outcome && alert.status === status;
    if (!ok) failed++;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${id} ${r.outcome} ${r.confidence}% -> ${alert.status} (${r.actions_taken.map(a => a.type + ' ' + a.target).join(', ') || 'no action'})`);
  }
  const fp = (await store.investigations.list()).find(i => i.alert_id === 'ALERT-2026-9001');
  const o = await inv.override(fp.investigation_id, { outcome: 'FALSE_POSITIVE', notes: 'pen test window', analyst: 'test' });
  const active = (await store.rules.list()).filter(r => r.investigation_id === fp.investigation_id && r.is_active);
  assert.strictEqual(active.length, 0, 'override should roll back rules');
  console.log('PASS override rollback:', o.changes.join('; '));
  if (backup) fs.writeFileSync(file, backup);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });