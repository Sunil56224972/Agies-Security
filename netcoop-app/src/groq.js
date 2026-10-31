'use strict';

// NetCoop AI: Groq LLM Integration for Multi-Agent Network Fault Synthesis.
// Powered by Groq's LPU inference engine running openai/gpt-oss-120b.
// Provides contextual network reasoning, specific technical remediation,
// and long-term preventive measures for IIT Bhubaneswar campus network.

try { require('dotenv').config(); } catch (_e) {}

const GROQ_KEY = process.env.NETCOOP_GROQ_KEY || process.env.GROQ_API_KEY || '';
const GROQ_MODEL = process.env.NETCOOP_GROQ_MODEL || 'openai/gpt-oss-120b';
const GROQ_ENDPOINT = 'https://api.groq.com/openai/v1/chat/completions';

function toList(val) {
  if (Array.isArray(val)) return val.map(String).filter(Boolean);
  if (typeof val === 'string') {
    return val
      .split(/(?:\r?\n|\d+\.\s+)/)
      .map(s => s.trim().replace(/^[-*•]\s*/, ''))
      .filter(s => s.length > 5);
  }
  return [];
}

/**
 * Enhance the multi-agent diagnosis report with Groq LLM reasoning.
 *
 * @param {object} params
 * @param {string} params.rootCause
 * @param {number} params.confidence
 * @param {Array}  params.evidence
 * @param {Array}  params.affectedDevices
 * @param {Array}  params.alternatives
 * @param {object} [bus] Optional MessageBus to log the LLM agent message
 * @returns {Promise<{ reasoning: string, actions: string[], prevention: string[], model: string, elapsed_ms: number } | null>}
 */
async function synthesizeWithGroq({ rootCause, confidence, evidence = [], affectedDevices = [], alternatives = [] }, bus = null) {
  if (!GROQ_KEY) return null;
  const t0 = Date.now();

  const evidenceText = evidence.slice(0, 6).map(e => `${e.device_id}: ${e.metric}=${e.value}${e.unit ? ' ' + e.unit : ''} (${e.level})`).join(', ');
  const affectedText = affectedDevices.join(', ') || 'None specified';
  const altText = alternatives.map(a => typeof a === 'string' ? a : (a.cause || a.hypothesis || '')).filter(Boolean).join(', ');

  const systemPrompt = `You are the Lead Network Engineer and Chief AI Diagnostic Specialist for the IIT Bhubaneswar campus network infrastructure.
You analyze telemetry findings from 4 specialized agents (Performance, Infrastructure, Connectivity, and Correlation agents) and produce a high-precision, production-grade root cause synthesis and practical remediation plan.
Always respond in strictly valid JSON format with keys:
- "reasoning": string (2-3 sentences explaining the root cause and why it cascades through campus facilities)
- "actions": array of strings (3 to 5 actionable technical engineering steps to resolve the issue)
- "cli_commands": array of strings (2 to 4 exact Cisco IOS, Aruba, or Linux terminal commands to verify and fix the issue, e.g. "show interface Gi0/1", "nmcli dev wifi rescan")
- "prevention": array of strings (2 to 3 long-term monitoring or architectural recommendations)`;

  const userPrompt = `Multi-Agent Consensus Findings:
- Suspected Root Cause: ${rootCause}
- Confidence: ${Math.round((confidence || 0) * 100)}%
- Key Telemetry Evidence: ${evidenceText || 'No anomalies'}
- Affected Campus Devices: ${affectedText}
- Alternative Causes Considered: ${altText || 'None'}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 9000);

    const res = await fetch(GROQ_ENDPOINT, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.2,
        max_tokens: 1500
      }),
      signal: controller.signal
    });

    clearTimeout(timeout);

    if (!res.ok) {
      console.warn(`[NetCoop Groq] API returned ${res.status}: ${await res.text()}`);
      return null;
    }

    const data = await res.json();
    const content = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
    if (!content) return null;

    let cleaned = content.trim();
    if (cleaned.startsWith('```json')) cleaned = cleaned.replace(/^```json\s*/, '').replace(/\s*```$/, '');
    else if (cleaned.startsWith('```')) cleaned = cleaned.replace(/^```\s*/, '').replace(/\s*```$/, '');

    const parsed = JSON.parse(cleaned);
    const elapsed = Date.now() - t0;

    const result = {
      model: GROQ_MODEL,
      elapsed_ms: elapsed,
      reasoning: parsed.reasoning || null,
      actions: toList(parsed.actions),
      cli_commands: toList(parsed.cli_commands),
      prevention: toList(parsed.prevention)
    };

    // Log to agent bus if provided
    if (bus && typeof bus.send === 'function') {
      bus.send('groq_llm_agent', 'reporting_agent', 'result', {
        kind: 'llm_synthesis',
        model: GROQ_MODEL,
        reasoning: result.reasoning,
        actions: result.actions,
        elapsed_ms: elapsed
      }, { summary: `Groq LLM (${GROQ_MODEL}) completed contextual root cause & remediation synthesis` });
    }

    return result;
  } catch (err) {
    console.warn(`[NetCoop Groq] Inference fallback: ${err.message}`);
    return null;
  }
}

module.exports = { synthesizeWithGroq, GROQ_KEY, GROQ_MODEL };
