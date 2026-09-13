/**
 * Aegis Security — Clean Demo Recording Script v2
 * Uses exact DOM selectors verified from live page snapshot
 * Workflow: Goal → Decision → Action → Intermediate Result → Adaptation → Final Outcome
 */

const { chromium } = require('playwright');
const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const BASE = 'http://localhost:3000';
const OUT_DIR = path.resolve(__dirname, '..', 'demo_video');
const VIDEO_DIR = path.join(OUT_DIR, 'rec_tmp');
const FINAL_MP4 = path.join(OUT_DIR, 'aegis_demo_4min.mp4');

if (!fs.existsSync(VIDEO_DIR)) fs.mkdirSync(VIDEO_DIR, { recursive: true });

const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  console.log('Launching Chromium (non-headless for recording)...');
  const browser = await chromium.launch({
    headless: false,
    args: ['--start-maximized']
  });

  const ctx = await browser.newContext({
    viewport: { width: 1400, height: 860 },
    recordVideo: { dir: VIDEO_DIR, size: { width: 1400, height: 860 } }
  });
  const page = await ctx.newPage();

  // ─────────────────────────────────────────────────────────────────────────
  // PHASE 1 — GOAL: Show the dashboard with live metrics (the mission)
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[1] GOAL — Loading dashboard...');
  await page.goto(BASE, { waitUntil: 'networkidle' });
  await sleep(4000); // Let metrics and charts render

  // Scroll slowly to show metrics
  await page.evaluate(() => window.scrollBy({ top: 400, behavior: 'smooth' }));
  await sleep(2500);
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(2000);

  // ─────────────────────────────────────────────────────────────────────────
  // PHASE 2 — DECISION: Navigate to Alert Feed, filter Critical threats
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[2] DECISION — Navigating to Alert Feed...');
  await page.click('a:has-text("Alert Feed")');
  await sleep(3000); // Alerts load from Neon PostgreSQL

  // Click "Critical (4)" filter button
  await page.click('button:has-text("Critical")');
  await sleep(2000);

  // Hover over the Log4Shell alert (ALERT-2026-9001) card
  await page.hover('text=ALERT-2026-9001');
  await sleep(2500);

  // ─────────────────────────────────────────────────────────────────────────
  // PHASE 3 — ACTION: Trigger autonomous investigation on Log4Shell
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[3] ACTION — Starting Log4Shell investigation...');

  // Find the card with ALERT-2026-9001 and click its Triage button
  const log4jCard = page.locator('text=ALERT-2026-9001').locator('xpath=ancestor::*[contains(@class,"alert") or contains(@class,"card") or contains(@class,"item")][1]');
  const triageBtn = page.locator('text=ALERT-2026-9001').locator('xpath=ancestor::*[5]//button[contains(text(),"Triage")]');

  // Fallback: click all "Triage & Investigate" buttons and find the right one
  const allTriageBtns = page.locator('button:has-text("Triage")');
  const count = await allTriageBtns.count();
  console.log(`   Found ${count} Triage buttons`);

  // Button index: ALERT-2026-9001 is the 6th alert in the list (0-indexed: 5)
  // From DOM: e396 is the button for ALERT-2026-9001
  // All alerts in order: e291, e312, e333, e354, e375, e396, e417, e438, e459, e480
  // ALERT-2026-9001 is index 5 (0-based)
  if (count > 5) {
    await allTriageBtns.nth(5).click();
  } else {
    await allTriageBtns.first().click();
  }
  await sleep(2000);

  // ─────────────────────────────────────────────────────────────────────────
  // PHASE 4 — INTERMEDIATE RESULT: Watch agent reasoning & tool calls
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[4] INTERMEDIATE RESULT — Watching agent tool execution...');

  // Navigate to Investigation Studio to see the live stream
  await page.click('a:has-text("Investigation Studio")');
  await sleep(2000);

  // If there's a "Start" or "Run Investigation" button, click it
  const startBtn = page.locator('button:has-text("Start Investigation"), button:has-text("Run Investigation"), button:has-text("Begin Triage")');
  if (await startBtn.count() > 0) {
    await startBtn.first().click();
    await sleep(1000);
  }

  // Wait and scroll to show all 8 tools being called (65 seconds)
  console.log('   Watching agent tools for 65 seconds...');
  for (let i = 0; i < 13; i++) {
    await sleep(5000);
    await page.evaluate(() => window.scrollBy({ top: 120, behavior: 'smooth' }));
    const progress = (i + 1) * 5;
    console.log(`   ${progress}s / 65s`);
  }
  await sleep(5000); // last 5s

  // Scroll back to top to show final verdict
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(3000);

  // ─────────────────────────────────────────────────────────────────────────
  // PHASE 5 — FINAL OUTCOME: Containment rules & defense probe
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[5] FINAL OUTCOME — Checking containment...');
  await page.click('a:has-text("Containment Rules")');
  await sleep(3500); // Load firewall rules from DB

  // Scroll to show the active block rules
  await page.evaluate(() => window.scrollBy({ top: 300, behavior: 'smooth' }));
  await sleep(2000);

  // Click Run Defense Probe
  const probeBtn = page.locator('button:has-text("Run Defense Probe")');
  if (await probeBtn.count() > 0) {
    await probeBtn.first().click();
    await sleep(5000); // Show probe result
  }

  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(2000);

  // ─────────────────────────────────────────────────────────────────────────
  // PHASE 6 — ADAPTATION: False positive on Python/FastAPI server (Criterion 6)
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[6] ADAPTATION — False positive demonstration...');
  await page.click('a:has-text("Alert Feed")');
  await sleep(2500);

  // Click "All (10)" to show all alerts
  await page.click('button:has-text("All")');
  await sleep(1500);

  // Scroll to ALERT-2026-9003 (Python FastAPI false positive — index 8 in list)
  await page.evaluate(() => window.scrollBy({ top: 600, behavior: 'smooth' }));
  await sleep(2000);

  // Hover over the Python/FastAPI false positive alert — scoped to alerts container
  const fastApiText = page.locator('#alerts-container').locator('text=Python FastAPI').first();
  if (await fastApiText.count() > 0) {
    await fastApiText.hover();
    await sleep(1500);
  }

  // Click Triage button for ALERT-2026-9003 — scoped to alerts container
  const allBtns2 = page.locator('#alerts-container button:has-text("Triage")');
  const cnt2 = await allBtns2.count();
  console.log(`   Found ${cnt2} Triage buttons in alerts container`);
  if (cnt2 > 8) {
    await allBtns2.nth(8).click();
  } else if (cnt2 > 0) {
    await allBtns2.last().click();
  }
  await sleep(2000);

  // Go to Investigation Studio to watch false positive detection
  await page.click('a:has-text("Investigation Studio")');
  await sleep(1500);

  const startBtn2 = page.locator('button:has-text("Start Investigation"), button:has-text("Run Investigation")');
  if (await startBtn2.count() > 0) {
    await startBtn2.first().click();
    await sleep(1000);
  }

  console.log('   Watching false positive detection for 35 seconds...');
  for (let i = 0; i < 7; i++) {
    await sleep(5000);
    await page.evaluate(() => window.scrollBy({ top: 100, behavior: 'smooth' }));
    console.log(`   ${(i + 1) * 5}s / 35s`);
  }

  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(3000);

  // ─────────────────────────────────────────────────────────────────────────
  // PHASE 7 — COMPLIANCE: Agentic Evaluation Matrix (7/7 PASS)
  // ─────────────────────────────────────────────────────────────────────────
  console.log('[7] COMPLIANCE — Agentic Evaluation Matrix...');
  await page.click('a:has-text("Agentic Evaluation Matrix")');
  await sleep(3000);

  // Click Open Judging Matrix / Run Compliance Check
  const judgeBtn = page.locator('button:has-text("Open Judging Matrix"), button:has-text("Run"), button:has-text("Check")');
  if (await judgeBtn.count() > 0) {
    await judgeBtn.first().click();
    await sleep(3000);
  }

  // Scroll through all 7 criteria
  for (let i = 0; i < 5; i++) {
    await page.evaluate(() => window.scrollBy({ top: 300, behavior: 'smooth' }));
    await sleep(1800);
  }

  // Scroll back to show the full 7/7 badge
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(5000);

  // ─────────────────────────────────────────────────────────────────────────
  // END — Close and convert
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\nRecording complete. Closing browser...');
  await ctx.close();
  await browser.close();

  // Find the recorded WebM
  const webmFiles = fs.readdirSync(VIDEO_DIR).filter(f => f.endsWith('.webm'));
  if (!webmFiles.length) {
    console.error('ERROR: No WebM recording found in', VIDEO_DIR);
    process.exit(1);
  }

  const webmPath = path.join(VIDEO_DIR, webmFiles[webmFiles.length - 1]); // latest
  console.log('Converting:', path.basename(webmPath), '→', path.basename(FINAL_MP4));

  const ffmpegBin = require('ffmpeg-static');
  execSync(
    `"${ffmpegBin}" -y -i "${webmPath}" -c:v libx264 -preset fast -crf 20 -movflags +faststart -pix_fmt yuv420p "${FINAL_MP4}"`,
    { stdio: 'inherit' }
  );

  const sizeMB = (fs.statSync(FINAL_MP4).size / 1024 / 1024).toFixed(1);
  console.log(`\n✅  MP4 saved: ${FINAL_MP4} (${sizeMB} MB)`);
  console.log('✅  Done!');
})();
