/**
 * Aegis SOC — 4-minute demo recorder
 * Uses Playwright's native video recording → .webm → converted to .mp4
 */
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const ffmpegPath = require('ffmpeg-static');
const path = require('path');
const fs = require('fs');

const SITE = 'http://localhost:3000';
const OUT_DIR = path.join(__dirname);
const VIDEO_DIR = path.join(OUT_DIR, 'video_tmp');
const FINAL_MP4 = path.join(OUT_DIR, 'aegis_demo_4min.mp4');

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

(async () => {
  fs.mkdirSync(VIDEO_DIR, { recursive: true });

  const browser = await chromium.launch({ headless: false, args: ['--start-maximized'] });
  const context = await browser.newContext({
    viewport: { width: 1400, height: 900 },
    recordVideo: {
      dir: VIDEO_DIR,
      size: { width: 1400, height: 900 }
    }
  });

  const page = await context.newPage();
  console.log('[1/8] Opening Aegis SOC Platform...');
  await page.goto(SITE, { waitUntil: 'networkidle' });
  await sleep(3000);

  // ── SECTION 1: Dashboard (30s) ──────────────────────────────
  console.log('[2/8] Dashboard — metrics & infrastructure...');
  await page.waitForSelector('#soc-stat-alerts', { timeout: 10000 }).catch(() => {});
  await sleep(4000);

  // Scroll dashboard a bit
  await page.evaluate(() => window.scrollBy(0, 300));
  await sleep(2000);
  await page.evaluate(() => window.scrollBy(0, -300));
  await sleep(2000);

  // ── SECTION 2: Alert Feed (40s) ─────────────────────────────
  console.log('[3/8] Alert Feed — all 4 NIDS alerts...');
  await page.click('[data-view="alerts"]');
  await sleep(4000);

  // Filter critical
  const critBtn = page.locator('.filter-pill').filter({ hasText: 'Critical' });
  if (await critBtn.isVisible()) {
    await critBtn.click();
    await sleep(2500);
    const allBtn = page.locator('.filter-pill').filter({ hasText: 'All' });
    await allBtn.click();
    await sleep(2000);
  }

  // ── SECTION 3: Autonomous Investigation (90s) ───────────────
  console.log('[4/8] Investigation Studio — ALERT-2026-9001 (Log4Shell)...');
  await page.click('[data-view="agent"]');
  await sleep(1500);

  // Trigger ALERT-2026-9001
  await page.click('[data-view="alerts"]');
  await sleep(1500);
  const investigateBtn = page.locator('button').filter({ hasText: 'Triage & Investigate' }).first();
  if (await investigateBtn.isVisible({ timeout: 5000 }).catch(() => false)) {
    await investigateBtn.click();
  } else {
    // Navigate directly and trigger
    await page.click('[data-view="agent"]');
    await sleep(800);
    await page.evaluate(() => triggerInvestigation('ALERT-2026-9001'));
  }
  await sleep(90000); // Wait for full investigation to complete

  // ── SECTION 4: Containment / Firewall (25s) ─────────────────
  console.log('[5/8] Containment rules & defense probe...');
  await page.click('[data-view="firewall"]');
  await sleep(4000);

  // Run defense probe
  const probeBtn = page.locator('button').filter({ hasText: 'Run Defense Probe' }).first();
  if (await probeBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
    await probeBtn.click();
    await sleep(3000);
  }
  await sleep(3000);

  // ── SECTION 5: Asset CMDB & CVE Library (20s) ───────────────
  console.log('[6/8] Asset CMDB & CVE Knowledge Base...');
  await page.click('[data-view="library"]');
  await sleep(4000);
  // Search for log4j
  const cmdbSearch = page.locator('#cmdb-search-input');
  if (await cmdbSearch.isVisible({ timeout: 3000 }).catch(() => false)) {
    await cmdbSearch.fill('log4j');
    await sleep(2000);
    await cmdbSearch.fill('');
    await sleep(1500);
  }

  // ── SECTION 6: Configuration (15s) ──────────────────────────
  console.log('[7/8] System Configuration panel...');
  await page.click('[data-view="preferences"]');
  await sleep(4000);

  // ── SECTION 7: Agentic Evaluator (40s) ──────────────────────
  console.log('[8/8] Agentic Compliance Evaluator — all 7 criteria...');
  await page.click('[data-view="evaluator"]');
  await sleep(3000);

  // Run all automated tests
  const runAllBtn = page.locator('button').filter({ hasText: 'Run All' }).first();
  if (await runAllBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
    await runAllBtn.click();
    await sleep(15000);
  } else {
    // Run individual criteria buttons
    const critButtons = page.locator('button').filter({ hasText: 'Verify' });
    const count = await critButtons.count();
    for (let i = 0; i < Math.min(count, 3); i++) {
      await critButtons.nth(i).click().catch(() => {});
      await sleep(4000);
    }
  }

  // Scenario 6A — changed condition
  const sc6aBtn = page.locator('button').filter({ hasText: '6A' }).first();
  if (await sc6aBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
    await sc6aBtn.click();
    await sleep(5000);
  }

  // Final pause on evaluator screen
  await sleep(5000);
  console.log('\nRecording complete. Closing browser...');

  const pages = context.pages();
  const videoPath = await pages[0].video()?.path();

  await context.close();
  await browser.close();

  if (!videoPath || !fs.existsSync(videoPath)) {
    console.error('ERROR: Video file not found at', videoPath);
    // Find newest webm in dir
    const files = fs.readdirSync(VIDEO_DIR).filter(f => f.endsWith('.webm'));
    if (files.length === 0) { console.error('No .webm files found!'); process.exit(1); }
    const newest = files.sort().pop();
    const resolvedPath = path.join(VIDEO_DIR, newest);
    console.log('Using fallback video:', resolvedPath);
    convertToMp4(resolvedPath);
  } else {
    console.log('Video saved:', videoPath);
    convertToMp4(videoPath);
  }
})();

function convertToMp4(webmPath) {
  console.log('\nConverting to MP4:', FINAL_MP4);
  try {
    execFileSync(ffmpegPath, [
      '-y',
      '-i', webmPath,
      '-c:v', 'libx264',
      '-pix_fmt', 'yuv420p',
      '-preset', 'fast',
      '-crf', '20',
      FINAL_MP4
    ], { stdio: 'inherit' });
    console.log('\n✓ MP4 saved at:', FINAL_MP4);
  } catch (e) {
    console.error('ffmpeg conversion failed:', e.message);
  }
}
