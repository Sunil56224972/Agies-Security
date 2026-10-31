'use strict';

// NetCoop AI: Standalone Web Application Server.
// Multi-Agent Network Fault Diagnosis and Interoperability System.
// Grand Finale Hackathon Solution — IIT Bhubaneswar Campus Infrastructure.

require('dotenv').config();
const path = require('path');
const express = require('express');
const netcoopRoutes = require('./src/routes');

const PORT = Number(process.env.NETCOOP_PORT) || 4000;
const HOST = process.env.HOST || '0.0.0.0';

const app = express();
app.disable('x-powered-by');

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Mount NetCoop API routes
const router = netcoopRoutes({});
app.use('/api/netcoop', router);
app.use('/api', router); // Convenient alias

// Serve frontend static assets
app.use(express.static(path.join(__dirname, 'public')));

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
if (require.main === module) {
  const server = app.listen(PORT, HOST, () => {
    console.log('\n=============================================================');
    console.log('   NetCoop AI — Multi-Agent Network Fault Diagnosis');
    console.log(`   Running at:  http://localhost:${PORT}`);
    console.log('=============================================================');
    console.log('  Target Network : IIT Bhubaneswar Campus Facilities');
    console.log('  Agents Active  : 5 Specialized Diagnostic Agents + Groq LLM Agent');
    console.log('  Groq AI Model  : openai/gpt-oss-120b (Groq LPUs)');
    console.log('  Protocol       : JSON-RPC v1.0.0 Interoperable Bus');
    console.log('  Status         : Ready for live telemetry analysis\n');
  });

  const shutdown = () => {
    console.log('\nShutting down NetCoop AI server...');
    server.close(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

module.exports = app;
