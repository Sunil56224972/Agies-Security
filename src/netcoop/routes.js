'use strict';

// NetCoop AI: Express router for the multi-agent network fault diagnosis API.
// All routes are self-contained — they do NOT access any Aegis store tables,
// investigation engine, or existing API endpoints.

const express = require('express');
const { diagnose, generateScenario, listScenarios, PROTOCOL, SCORING, ROLES } = require('./orchestrator');

module.exports = function netcoopRoutes(ctx) {
  const router = express.Router();
  const auth = ctx.store ? ctx.store.auth : null;
  const protect = auth && auth.protect ? auth.protect() : (req, res, next) => next();

  // POST /api/netcoop/diagnose — run a full cooperative diagnosis
  router.post('/diagnose', protect, async (req, res) => {
    try {
      const input = req.body.telemetry || req.body;
      const result = await diagnose(input, { runId: req.body.run_id });
      res.json(result);
    } catch (err) {
      console.error('[NetCoop] diagnose error:', err);
      res.status(400).json({ error: err.message || 'Diagnosis failed' });
    }
  });

  // GET /api/netcoop/protocol — return the agent protocol documentation
  router.get('/protocol', protect, (req, res) => {
    res.json({ protocol: PROTOCOL, scoring: SCORING, roles: ROLES });
  });

  // GET /api/netcoop/scenarios — list available test scenarios
  router.get('/scenarios', protect, (req, res) => {
    res.json({ scenarios: listScenarios() });
  });

  // POST /api/netcoop/scenarios/:key — generate telemetry for a scenario
  router.post('/scenarios/:key', protect, (req, res) => {
    try {
      const data = generateScenario(req.params.key);
      res.json({ scenario: req.params.key, telemetry: data });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  return router;
};

