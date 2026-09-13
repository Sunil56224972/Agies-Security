/**
 * AEGIS SOC — Official Demo Recorder
 * Workflow: Goal → Decision → Action → Intermediate Result → Adaptation → Final Outcome
 * Demonstrates: Successful attack containment + FAILURE/UNEXPECTED CONDITION replanning
 * Duration: ~4 minutes
 */
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const ffmpegPath = require('ffmpeg-static');
const path = require('path');
const fs = require('fs');

const SITE = 'http://localhost:3000';
const VIDEO_DIR = path.join(__dirname, 'video_tmp');
const FINAL_MP4 = path.join(__dirname, 'aegis_demo_4min.mp4');

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function slowType(page, selector, text) {
  await page.click(selector);
  for (const ch of text) {
    await page.keyboard.type(ch);
    await sleep(40);
  }
}

(async () => {
  console.log('\n════════════════════════════════════════════════════');
  console.log('  AEGIS SOC — 4-Minute Demo Recording Started');
  console.log('  Workflow: Goal→Decision→Action→Result→Adapt→Final');
  console.log('════════════════════════════════════════════════════\n');

  fs.mkdirSync(VIDEO_DIR, { recursive: true });

  const browser = await chromium.launch({
    headless: false,
    args: ['--start-maximized', '--disable-infobars']
  });

  const context = await browser.newContext({
    viewport: { width: 1400, height: 860 },
    recordVideo: { dir: VIDEO_DIR, size: { width: 1400, height: 860 } }
  });

  const page = await context.newPage();

  // ═══════════════════════════════════════════════════
  // PHASE 0 — Opening (0:00–0:15)
  // ═══════════════════════════════════════════════════
  console.log('[0:00] Loading Aegis SOC Platform...');
  await page.goto(SITE, { waitUntil: 'networkidle', timeout: 30000 });
  await sleep(4000);

  // ═══════════════════════════════════════════════════
  // PHASE 1 — DASHBOARD & LIVE METRICS (0:15–0:40)
  // ═══════════════════════════════════════════════════
  console.log('[0:15] Dashboard — live PostgreSQL metrics...');
  await page.waitForSelector('#soc-stat-alerts', { timeout: 10000 }).catch(() => {});
  await sleep(3000);
  // Scroll down to show asset list
  await page.evaluate(() => document.querySelector('.dashboard-grid')?.scrollIntoView({ behavior: 'smooth', block: 'end' }));
  await sleep(2500);
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(2500);

  // ═══════════════════════════════════════════════════
  // PHASE 2 — ALERT FEED (0:40–1:05)
  // Show the 4 NIDS alerts, highlight ALERT-2026-9001
  // ═══════════════════════════════════════════════════
  console.log('[0:40] Alert Feed — NIDS threat queue...');
  await page.click('[data-view="alerts"]');
  await sleep(3500);

  // Filter to CRITICAL
  const critPill = page.locator('.filter-pill').filter({ hasText: /Critical/ }).first();
  if (await critPill.isVisible({ timeout: 3000 }).catch(() => false)) {
    await critPill.click();
    await sleep(2500);
    // Back to all
    const allPill = page.locator('.filter-pill').filter({ hasText: /All/ }).first();
    await allPill.click();
    await sleep(2000);
  }

  // ═══════════════════════════════════════════════════
  // PHASE 3 — GOAL FORMULATION (1:05–1:15)
  // Navigate to Investigation Studio, show the goal
  // ═══════════════════════════════════════════════════
  console.log('[1:05] Setting the GOAL — Log4Shell investigation...');
  await page.click('[data-view="agent"]');
  await sleep(2000);

  // ═══════════════════════════════════════════════════
  // PHASE 4 — ACTION: TRIGGER REAL INVESTIGATION (1:15–3:00)
  // Agent autonomously: Decision→Action→Intermediate Result→Adaptation
  // ═══════════════════════════════════════════════════
  console.log('[1:15] TRIGGERING autonomous investigation on ALERT-2026-9001...');
  // Click the Alerts view to find ALERT-2026-9001 and click Triage
  await page.click('[data-view="alerts"]');
  await sleep(1500);

  // Find the first "Triage & Investigate" button (ALERT-2026-9001 is CRITICAL/first)
  const triageBtn = page.locator('button').filter({ hasText: 'Triage & Investigate' }).first();
  const hasTriage = await triageBtn.isVisible({ timeout: 5000 }).catch(() => false);

  if (hasTriage) {
    await triageBtn.click();
  } else {
    // Fallback: go to agent view and type the goal
    await page.click('[data-view="agent"]');
    await sleep(800);
    const input = page.locator('#chat-input');
    await slowType(page, '#chat-input', 'Investigate ALERT-2026-9001 — Log4Shell RCE against prod-web-core. Determine if attack succeeded, contain the threat, and record final verdict.');
    await sleep(500);
    await page.click('#btn-send');
  }

  // Watch the investigation unfold — 90 seconds (the LLM runs all 8 tools)
  console.log('[1:20] Agent running — watching tool calls & reasoning steps...');
  await sleep(100000); // 100 seconds for investigation to fully complete

  // ═══════════════════════════════════════════════════
  // PHASE 5 — CONTAINMENT VIEW (3:00–3:25)
  // Show the active firewall BLOCK rule, packets dropped
  // ═══════════════════════════════════════════════════
  console.log('[3:00] FINAL OUTCOME — Containment rules & defense verification...');
  await page.click('[data-view="firewall"]');
  await sleep(3000);

  // Run defense probe
  const probeBtn = page.locator('button').filter({ hasText: /Defense Probe|Probe/ }).first();
  if (await probeBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
    await probeBtn.click();
    await sleep(3000);
  }
  await sleep(3000);

  // ═══════════════════════════════════════════════════
  // PHASE 6 — FAILURE / UNEXPECTED CONDITION (3:25–3:50)
  // ALERT-2026-9003: Log4j → Python FastAPI = FALSE POSITIVE
  // Agent detects incompatible stack, ADAPTS verdict, skips block
  // ═══════════════════════════════════════════════════
  console.log('[3:25] UNEXPECTED CONDITION — Scenario 6A: False Positive detection...');
  await page.click('[data-view="evaluator"]');
  await sleep(2000);

  // Run Scenario 6A
  const sc6aBtn = page.locator('button').filter({ hasText: /6A|Scenario.*A|Incompatible|False Positive/i }).first();
  if (await sc6aBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
    await sc6aBtn.click();
    await sleep(8000);
  } else {
    // Try the criterion 4 button which also shows the replanning
    const req4Btn = page.locator('button').filter({ hasText: /Criterion 4|Req 4|Action.*Observation/i }).first();
    if (await req4Btn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await req4Btn.click();
      await sleep(8000);
    }
  }

  // ═══════════════════════════════════════════════════
  // PHASE 7 — FINAL OUTCOME: Agentic Evaluator (3:50–4:15)
  // All 7 requirements verified with live data
  // ═══════════════════════════════════════════════════
  console.log('[3:50] FINAL — Agentic compliance evaluation...');
  await sleep(2000);
  const runAllBtn = page.locator('button').filter({ hasText: /Run All|All Criteria|Verify All/i }).first();
  if (await runAllBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
    await runAllBtn.click();
    await sleep(10000);
  }

  // Final scroll to show terminal output
  const evalTerminal = page.locator('#eval-terminal-output');
  if (await evalTerminal.isVisible({ timeout: 2000 }).catch(() => false)) {
    await evalTerminal.evaluate(el => el.scrollTop = el.scrollHeight);
  }
  await sleep(5000);

  console.log('\n[DONE] Recording finished. Saving video...');
  const videoPath = await page.video()?.path();
  await context.close();
  await browser.close();
  console.log('Raw video path:', videoPath);

  // Find webm if path unavailable
  let sourceVideo = videoPath;
  if (!sourceVideo || !fs.existsSync(sourceVideo)) {
    const files = fs.readdirSync(VIDEO_DIR).filter(f => f.endsWith('.webm')).sort();
    if (files.length === 0) {
      console.error('ERROR: No .webm recording found in', VIDEO_DIR);
      process.exit(1);
    }
    sourceVideo = path.join(VIDEO_DIR, files[files.length - 1]);
    console.log('Found video at:', sourceVideo);
  }

  console.log('\nConverting .webm → .mp4 (H.264)...');
  try {
    execFileSync(ffmpegPath, [
      '-y',
      '-i', sourceVideo,
      '-c:v', 'libx264',
      '-pix_fmt', 'yuv420p',
      '-preset', 'fast',
      '-crf', '18',
      '-movflags', '+faststart',
      FINAL_MP4
    ], { stdio: 'inherit' });
    const stats = fs.statSync(FINAL_MP4);
    console.log('\n════════════════════════════════════════════════════');
    console.log('  VIDEO SAVED SUCCESSFULLY!');
    console.log('  File :', FINAL_MP4);
    console.log('  Size :', (stats.size / 1024 / 1024).toFixed(1), 'MB');
    console.log('════════════════════════════════════════════════════\n');
  } catch (e) {
    console.error('ffmpeg conversion failed:', e.message);
    // Copy webm as fallback
    fs.copyFileSync(sourceVideo, FINAL_MP4.replace('.mp4', '.webm'));
    console.log('Saved as .webm fallback');
  }
})().catch(err => {
  console.error('Fatal recording error:', err);
  process.exit(1);
});
