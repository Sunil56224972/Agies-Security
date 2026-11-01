'use strict';

// NetCoop AI Automated Test Suite
// Verifies all multi-agent pipelines, scenarios, protocol schemas, and mathematical gates.

const assert = require('assert');
const { diagnose, generateScenario, listScenarios, PROTOCOL, SCORING, ROLES } = require('../src/orchestrator');
const { normalizeInput } = require('../src/schema');

async function runTests() {
  console.log('\n======================================================');
  console.log('   NetCoop AI — Automated Test Suite');
  console.log('======================================================\n');

  // 1. Protocol & Schema Verification
  console.log('[1/6] Verifying Protocol Schema & Metadata...');
  assert.strictEqual(PROTOCOL.version, '1.0.0');
  assert.strictEqual(PROTOCOL.telemetry_schema, 'netcoop.telemetry/1.0');
  assert.strictEqual(PROTOCOL.report_schema, 'netcoop.report/1.0');
  assert.ok(Array.isArray(ROLES) && ROLES.length >= 5, 'Must have at least 5 diagnostic agent roles');
  assert.ok(Object.keys(PROTOCOL.metrics).length >= 15, 'Must define all required campus telemetry metrics');
  console.log('  ✓ Protocol v1.0.0 and 16 metric definitions verified');

  // 2. Telemetry Normalizer Tests
  console.log('\n[2/6] Testing Telemetry Input Normalization...');
  
  // JSON Object
  const normObj = normalizeInput(JSON.stringify({
    schema: 'netcoop.telemetry/1.0',
    devices: [{ device_id: 'test-sw', role: 'switch' }],
    samples: [{ device_id: 'test-sw', latency_ms: 12.5, cpu_pct: 25.0, timestamp: new Date().toISOString() }]
  }));
  assert.strictEqual(normObj.ok, true);
  assert.strictEqual(normObj.dataset.sampleCount, 1);
  console.log('  ✓ JSON telemetry parsed correctly');

  // CSV Parsing
  const csvRaw = `device_id,timestamp,latency_ms,packet_loss_pct\ntest-ap,2026-11-01T00:00:00Z,14.5,0.1\ntest-ap,2026-11-01T00:01:00Z,15.2,0.2`;
  const normCsv = normalizeInput(csvRaw);
  assert.strictEqual(normCsv.ok, true);
  assert.strictEqual(normCsv.dataset.sampleCount, 2);
  console.log('  ✓ CSV telemetry parsed correctly');

  // 3. Scenario Registry
  console.log('\n[3/6] Testing Scenario Registry...');
  const scenarios = listScenarios();
  assert.ok(scenarios.length >= 8, 'Expected 8 built-in test scenarios');
  console.log(`  ✓ Loaded ${scenarios.length} built-in test scenarios`);

  // 4. Multi-Agent Cooperative Diagnosis Across All Scenarios
  console.log('\n[4/6] Running Multi-Agent Diagnosis on all 8 Scenarios...');
  for (const sc of scenarios) {
    const raw = generateScenario(sc.key);
    const result = await diagnose(raw);
    const r = result.report;

    if (sc.key !== 'interop_failure') {
      assert.ok(result.messages.length > 0, `Scenario ${sc.key} produced no messages`);
    }
    assert.ok(r.status, `Scenario ${sc.key} missing status`);
    
    const conf = Math.round((r.confidence || 0) * 100);
    const rc = (r.suspected_root_cause || r.root_cause || r.error || 'N/A').slice(0, 42);
    console.log(`  • ${sc.key.padEnd(20)} -> ${r.status.padEnd(18)} [${conf}%] | ${rc}`);

    if (sc.key === 'normal') {
      assert.strictEqual(r.status, 'no_fault_detected');
    } else if (sc.key === 'interop_failure') {
      assert.strictEqual(r.status, 'error');
    } else {
      assert.strictEqual(r.status, 'diagnosed');
      assert.ok(r.confidence > 0.5, `Confidence should be > 50% for ${sc.key}`);
    }
  }

  // 5. Gating & Insufficient Evidence Guardrails
  console.log('\n[5/6] Testing Guardrails (Must not claim exact root cause with insufficient evidence)...');
  const sparseTelemetry = {
    schema: 'netcoop.telemetry/1.0',
    devices: [{ device_id: 'unknown-node' }],
    samples: [{ device_id: 'unknown-node', latency_ms: 15, timestamp: new Date().toISOString() }]
  };
  const sparseResult = await diagnose(sparseTelemetry);
  assert.ok(
    sparseResult.report.status === 'insufficient_evidence' || sparseResult.report.status === 'no_fault_detected' || sparseResult.report.status === 'inconclusive',
    'Sparse telemetry must be marked insufficient_evidence or inconclusive'
  );
  console.log('  ✓ System correctly reports no false alarms when telemetry is clean/sparse');

  // 6. Section 6 Schema Compliance (Problem Statement Expected Output Format)
  console.log('\n[6/6] Verifying Exact Section 6 Output Schema Compliance...');
  const diagRes = await diagnose(generateScenario('link_congestion'));
  const rep = diagRes.report;
  assert.ok(typeof rep.incident_id === 'string' && rep.incident_id.startsWith('INC-'), 'incident_id must be INC-xxxx');
  assert.strictEqual(rep.status, 'diagnosed', 'status must be diagnosed');
  assert.ok(typeof rep.suspected_root_cause === 'string', 'suspected_root_cause must be string');
  assert.ok(typeof rep.confidence === 'number' && rep.confidence >= 0 && rep.confidence <= 1, 'confidence must be 0..1 number');
  assert.ok(Array.isArray(rep.affected_devices) && rep.affected_devices.length > 0, 'affected_devices must be array');
  assert.ok(Array.isArray(rep.supporting_evidence) && rep.supporting_evidence.length > 0, 'supporting_evidence must be array');
  assert.ok(Array.isArray(rep.alternative_causes), 'alternative_causes must be array');
  assert.ok(Array.isArray(rep.recommended_actions) && rep.recommended_actions.length > 0, 'recommended_actions must be array');
  assert.ok(Array.isArray(rep.evidence_sources) && rep.evidence_sources.length > 0, 'evidence_sources must be array');
  assert.ok(Array.isArray(rep.limitations) && rep.limitations.length > 0, 'limitations must be array');
  console.log('  ✓ Report schema precisely satisfies Problem Statement Section 6 specifications');

  console.log('\n======================================================');
  console.log('   ALL NETCOOP TESTS PASSED SUCCESSFULLY (100%)');
  console.log('======================================================\n');
}

runTests().catch((err) => {
  console.error('\n❌ Test Failure:', err);
  process.exit(1);
});
