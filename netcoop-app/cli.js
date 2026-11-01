#!/usr/bin/env node
'use strict';

/**
 * NetCoop AI — Multi-Agent Network Fault Diagnosis CLI
 * Fulfills Problem Statement Deliverable #5: Runnable Application with CLI.
 *
 * Usage:
 *   node cli.js --scenario <scenario_key> [--json]
 *   node cli.js --list
 *   node cli.js <telemetry_file.json> [--json]
 *   cat telemetry.json | node cli.js [--json]
 */

const fs = require('fs');
const path = require('path');
const { diagnose, generateScenario, listScenarios } = require('./src/orchestrator');

const args = process.argv.slice(2);
const isJson = args.includes('--json');

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

async function main() {
  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('--list')) {
    const list = listScenarios();
    console.log(`\n${c.bold}Available NetCoop AI Test Scenarios:${c.reset}\n`);
    for (const s of list) {
      console.log(`  ${c.cyan}${s.key.padEnd(20)}${c.reset} ${c.bold}${s.name}${c.reset}`);
      console.log(`  ${' '.repeat(20)} ${c.gray}${s.description}${c.reset}\n`);
    }
    process.exit(0);
  }

  let rawTelemetry = null;

  const scIdx = args.indexOf('--scenario');
  if (scIdx !== -1 && args[scIdx + 1]) {
    const key = args[scIdx + 1];
    try {
      rawTelemetry = generateScenario(key);
    } catch (e) {
      console.error(`${c.red}Error:${c.reset} Unknown scenario "${key}". Run with --list to see available scenarios.`);
      process.exit(1);
    }
  } else {
    // Check for file argument or stdin
    const fileArg = args.find(a => !a.startsWith('--'));
    if (fileArg && fs.existsSync(fileArg)) {
      rawTelemetry = fs.readFileSync(fileArg, 'utf8');
    } else if (!process.stdin.isTTY) {
      rawTelemetry = fs.readFileSync(0, 'utf-8');
    }
  }

  if (!rawTelemetry) {
    printHelp();
    process.exit(1);
  }

  // Run Diagnosis
  const t0 = Date.now();
  const res = await diagnose(rawTelemetry);
  const elapsed = Date.now() - t0;

  if (isJson) {
    console.log(JSON.stringify(res.report, null, 2));
    process.exit(0);
  }

  printTerminalReport(res, elapsed);
}

function printHelp() {
  console.log(`
${c.bold}NetCoop AI — Multi-Agent Network Fault Diagnosis CLI${c.reset}
IIT Bhubaneswar Hackathon Challenge • Autonomous Cooperative Diagnostic Engine

${c.bold}USAGE:${c.reset}
  node cli.js --scenario <key>        Run diagnosis on a built-in test scenario
  node cli.js --scenario <key> --json Output raw structured JSON report (Problem Statement §6)
  node cli.js <file.json>             Run diagnosis on local telemetry file
  node cli.js --list                  List all available test scenarios
  cat telemetry.json | node cli.js    Read telemetry from stdin

${c.bold}EXAMPLES:${c.reset}
  node cli.js --scenario link_congestion
  node cli.js --scenario weak_wifi --json
  node cli.js --scenario dns_failure
`);
}

function printTerminalReport(res, elapsed) {
  const r = res.report || {};
  const meta = res.meta || {};
  const msgs = res.messages || [];
  const status = r.status || 'unknown';
  const confidence = Math.round((r.confidence || 0) * 100);

  const statusColor = status === 'diagnosed' ? c.green : status === 'no_fault_detected' ? c.cyan : c.red;

  console.log('\n' + '━'.repeat(72));
  console.log(`  ${c.bold}NETCOOP AI — MULTI-AGENT DIAGNOSTIC REPORT${c.reset}`);
  console.log('━'.repeat(72));

  console.log(`\n  ${c.bold}Incident ID:${c.reset}  ${c.cyan}${r.incident_id || 'INC-AUTO'}${c.reset}     ${c.bold}Status:${c.reset} ${statusColor}${status.toUpperCase()}${c.reset} (${confidence}% Confidence)`);
  console.log(`  ${c.bold}Elapsed:${c.reset}      ${elapsed} ms           ${c.bold}Agent Messages:${c.reset} ${msgs.length}`);
  console.log(`  ${c.bold}Root Cause:${c.reset}   ${c.bold}${r.suspected_root_cause || r.root_cause || 'Undetermined'}${c.reset}`);

  if (r.affected_devices && r.affected_devices.length) {
    console.log(`  ${c.bold}Affected:${c.reset}     ${r.affected_devices.map(d => `${c.yellow}${d}${c.reset}`).join(', ')}`);
  }

  // Evidence Table
  const evidence = r.supporting_evidence || [];
  if (evidence.length) {
    console.log(`\n${c.bold}  SUPPORTING EVIDENCE (${evidence.length} Indicators):${c.reset}`);
    console.log(`  ${'DEVICE'.padEnd(16)} ${'METRIC'.padEnd(22)} ${'VALUE'.padEnd(14)} ${'LEVEL'.padEnd(12)} INTERPRETATION`);
    console.log(`  ${'─'.repeat(16)} ${'─'.repeat(22)} ${'─'.repeat(14)} ${'─'.repeat(12)} ${'─'.repeat(24)}`);
    for (const e of evidence) {
      const lvlColor = e.level === 'critical' ? c.red : e.level === 'elevated' ? c.yellow : c.green;
      const valStr = `${e.value != null ? e.value : '-'}${e.unit ? ' ' + e.unit : ''}`;
      console.log(`  ${(e.device_id || '-').padEnd(16)} ${(e.metric || '-').padEnd(22)} ${valStr.padEnd(14)} ${lvlColor}${e.level.padEnd(12)}${c.reset} ${e.interpretation || '-'}`);
    }
  }

  // Recommended Actions
  const actions = r.recommended_actions || [];
  if (actions.length) {
    console.log(`\n${c.bold}  RECOMMENDED CORRECTIVE ACTIONS:${c.reset}`);
    actions.forEach((a, i) => {
      console.log(`   ${c.cyan}${i + 1}.${c.reset} ${typeof a === 'string' ? a : a.action || JSON.stringify(a)}`);
    });
  }

  // CLI Remediation Commands (Groq Synthesis)
  const groq = r.llm_synthesis || null;
  const cmds = (groq && (groq.cli_commands || groq.cli_remediation_commands)) || [];
  if (cmds.length) {
    console.log(`\n${c.bold}  REMEDIATION CLI COMMANDS (Groq LPU Verified):${c.reset}`);
    for (const cmd of cmds) {
      console.log(`    ${c.gray}$${c.reset} ${c.bold}${cmd}${c.reset}`);
    }
  }

  // Limitations
  const limits = r.limitations || [];
  if (limits.length) {
    console.log(`\n${c.bold}  UNCERTAINTY & LIMITATIONS:${c.reset}`);
    for (const l of limits) {
      console.log(`    ${c.gray}• ${l}${c.reset}`);
    }
  }

  console.log('\n' + '━'.repeat(72) + '\n');
}

main().catch(err => {
  console.error(`${c.red}Execution failed:${c.reset}`, err);
  process.exit(1);
});
