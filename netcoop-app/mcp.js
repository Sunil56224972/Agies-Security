#!/usr/bin/env node
'use strict';

/**
 * NetCoop AI — Model Context Protocol (MCP) Server
 * Fulfills Problem Statement Section 4 Optional Enhancement:
 * "Model Context Protocol (MCP): May be used to expose diagnostic tools,
 * telemetry or contextual resources to agents."
 *
 * Implements standard MCP (Model Context Protocol) JSON-RPC 2.0 over stdio.
 */

const readline = require('readline');
const { diagnose, generateScenario, listScenarios, PROTOCOL, SCORING, ROLES } = require('./src/orchestrator');

const SERVER_NAME = 'netcoop-mcp-server';
const SERVER_VERSION = '1.0.0';

const TOOLS = [
  {
    name: 'diagnose_network_fault',
    description: 'Run multi-agent cooperative fault diagnosis on network telemetry (JSON, NDJSON, or CSV). Identifies probable root cause, affected devices, supporting evidence, confidence rating, and recommended corrective actions.',
    inputSchema: {
      type: 'object',
      properties: {
        telemetry: {
          description: 'Network telemetry data as JSON object, JSON string, NDJSON, or CSV format.',
          type: ['string', 'object']
        }
      },
      required: ['telemetry']
    }
  },
  {
    name: 'list_test_scenarios',
    description: 'List all pre-configured synthetic network telemetry test scenarios for IIT Bhubaneswar campus infrastructure.',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'generate_scenario_telemetry',
    description: 'Generate synthetic network telemetry for a named test scenario (e.g. normal, link_congestion, weak_wifi, interface_fault, dns_failure, dhcp_failure, interop_failure, device_overload).',
    inputSchema: {
      type: 'object',
      properties: {
        scenario_key: {
          type: 'string',
          description: 'Key of the scenario to generate (e.g. "link_congestion", "weak_wifi", "dns_failure").'
        }
      },
      required: ['scenario_key']
    }
  },
  {
    name: 'get_protocol_specification',
    description: 'Retrieve the NetCoop AI multi-agent JSON-RPC communication protocol specification, metrics catalogue, and scoring methodology.',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  }
];

const RESOURCES = [
  {
    uri: 'netcoop://protocol',
    name: 'NetCoop AI Protocol Specification',
    mimeType: 'application/json',
    description: 'Standard JSON-RPC 2.0 multi-agent message envelopes and metric catalogue.'
  },
  {
    uri: 'netcoop://scenarios',
    name: 'NetCoop AI Test Scenarios',
    mimeType: 'application/json',
    description: 'Registry of 8 pre-configured test scenarios conforming to Hackathon requirements.'
  }
];

async function handleToolCall(name, args) {
  switch (name) {
    case 'diagnose_network_fault': {
      if (!args || !args.telemetry) {
        throw new Error('Missing "telemetry" argument.');
      }
      const res = await diagnose(args.telemetry);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(res.report, null, 2)
          }
        ]
      };
    }
    case 'list_test_scenarios': {
      const list = listScenarios();
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(list, null, 2)
          }
        ]
      };
    }
    case 'generate_scenario_telemetry': {
      const key = (args && args.scenario_key) || 'normal';
      const data = generateScenario(key);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(data, null, 2)
          }
        ]
      };
    }
    case 'get_protocol_specification': {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ protocol: PROTOCOL, scoring: SCORING, roles: ROLES }, null, 2)
          }
        ]
      };
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });

rl.on('line', async (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let request;
  try {
    request = JSON.parse(trimmed);
  } catch (e) {
    return;
  }

  const { id, method, params } = request;

  try {
    if (method === 'initialize') {
      sendResponse(id, {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {}, resources: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION }
      });
    } else if (method === 'notifications/initialized') {
      // client acknowledgment
    } else if (method === 'tools/list') {
      sendResponse(id, { tools: TOOLS });
    } else if (method === 'tools/call') {
      const result = await handleToolCall(params.name, params.arguments);
      sendResponse(id, result);
    } else if (method === 'resources/list') {
      sendResponse(id, { resources: RESOURCES });
    } else if (method === 'resources/read') {
      if (params.uri === 'netcoop://protocol') {
        sendResponse(id, {
          contents: [{ uri: params.uri, mimeType: 'application/json', text: JSON.stringify({ protocol: PROTOCOL, scoring: SCORING, roles: ROLES }, null, 2) }]
        });
      } else if (params.uri === 'netcoop://scenarios') {
        sendResponse(id, {
          contents: [{ uri: params.uri, mimeType: 'application/json', text: JSON.stringify(listScenarios(), null, 2) }]
        });
      } else {
        sendError(id, -32602, `Resource not found: ${params.uri}`);
      }
    } else if (method === 'ping') {
      sendResponse(id, {});
    } else {
      sendError(id, -32601, `Method not found: ${method}`);
    }
  } catch (err) {
    sendError(id, -32000, err.message);
  }
});

function sendResponse(id, result) {
  if (id !== undefined && id !== null) {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
  }
}

function sendError(id, code, message) {
  if (id !== undefined && id !== null) {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\n');
  }
}
