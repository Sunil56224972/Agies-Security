'use strict';
// Playbook regression: runs every demo alert through the investigator with an
// isolated temp-file store. Two passes: an enforcer that confirms rules (so
// containment can be proven) and the default pull feed (where it cannot yet).
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { MemoryStore } = require('../src/store/memory');
const { Investigator } = require('../src/engine/investigator');
const { FeedAdapter } = require('../src/enforce');

const confirming = {
  mode: 'test', label: 'Test backend',
  describe() { return { mode: 'test', label: 'Test backend', detail: 'unit test' }; },
  async apply() { return { mode: 'test', status: 'ENFORCED', detail: 'acknowledged by test backend', at: new Date().toISOString() }; },
  async remove(r) { return { ...(r.enforcement || {}), mode: 'test', status: 'REMOVED', detail: 'removed', at: new Date().toISOString() }; },
  async verify(r) { return r.enforcement; }
};

const enforcedExpect = {
  'ALERT-2026-9001': ['ATTACK_SUCCEEDED', 'CONTAINED'],
  'ALERT-2026-9002': ['ATTACK_SUCCEEDED', 'CONTAINED'],
  'ALERT-2026-9003': ['FALSE_POSITIVE', 'FALSE_POSITIVE'],
  'ALERT-2026-9004': ['ATTACK_FAILED', 'MITIGATED'],
  'ALERT-2026-9005': ['ATTACK_FAILED', 'MITIGATED'],
  'ALERT-2026-9006': ['ATTACK_SUCCEEDED', 'CONTAINED']
};

async function freshStore() {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-smoke-')), 'store.json');
  const store = new MemoryStore({ file, demo: true });
  await store.init();
  return store;
}

async function pass(label, enforcer, expected) {
  console.log(`\n${label}`);
  const store = await freshStore();
  const inv = new Investigator(store, { enforcer });
  let failed = 0;
  for (const [id, [outcome, status]] of Object.entries(expected)) {
    const r = await inv.run(id, () => {}, { pace: 0 });
    const alert = await store.alerts.get(id);
    const ok = r.outcome === outcome && alert.status === status;
    if (!ok) failed++;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${id} ${r.outcome} ${r.confidence}% -> ${alert.status} (${r.actions_taken.map((a) => `${a.type} ${a.target}`).join(', ') || 'no action'})`);
  }
  return { store, inv, failed };
}

(async () => {
  let failed = 0;
  const a = await pass('Confirming backend', confirming, enforcedExpect);
  failed += a.failed;

  const fp = (await a.store.investigations.list()).find((i) => i.alert_id === 'ALERT-2026-9001');
  const o = await a.inv.override(fp.investigation_id, { outcome: 'FALSE_POSITIVE', notes: 'pen test window', analyst: 'test' });
  const active = (await a.store.rules.list()).filter((r) => r.investigation_id === fp.investigation_id && r.is_active);
  assert.strictEqual(active.length, 0, 'override should roll back rules');
  console.log('PASS override rollback:', o.changes.join('; '));

  // With the pull feed nothing has picked the rule up yet, so the alert must stay open.
  const feedExpect = { 'ALERT-2026-9001': ['ATTACK_SUCCEEDED', 'CONFIRMED'], 'ALERT-2026-9003': ['FALSE_POSITIVE', 'FALSE_POSITIVE'] };
  const b = await pass('Pull feed backend (nothing pulled yet)', new FeedAdapter(), feedExpect);
  failed += b.failed;
  const rule = (await b.store.rules.list()).find((r) => r.investigation_id && r.is_active);
  assert.ok(rule, 'feed run should still create a rule');
  assert.strictEqual(rule.enforcement.status, 'PENDING');
  console.log('PASS rule left PENDING until the firewall pulls the feed');

  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });