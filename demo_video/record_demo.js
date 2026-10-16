// Records a walkthrough of the console and encodes it to MP4.
//   npm start                     (in one terminal)
//   node demo_video/record_demo.js (in another)
// Resets the demo data first so the recording always starts from the seeded state.
const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');
const { chromium } = require('playwright');
const ffmpeg = require('ffmpeg-static');

const BASE = process.env.AEGIS_URL || 'http://localhost:3000';
const TMP = path.join(__dirname, 'rec_tmp');
const OUT = path.join(__dirname, 'aegis_demo.mp4');
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

async function step(label, fn) {
  process.stdout.write(`  ${label.padEnd(44)}`);
  const t = Date.now();
  await fn();
  console.log(`${((Date.now() - t) / 1000).toFixed(1)}s`);
}

(async () => {
  const health = await fetch(`${BASE}/api/health`).catch(() => null);
  if (!health || !health.ok) {
    console.error(`No server at ${BASE}. Run "npm start" first.`);
    process.exit(1);
  }
  await fetch(`${BASE}/api/reset`, { method: 'POST' });

  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(TMP, { recursive: true });

  const size = { width: 1440, height: 900 };
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: size, recordVideo: { dir: TMP, size } });
  await ctx.addInitScript(() => localStorage.setItem('aegis.theme', 'light'));
  const page = await ctx.newPage();
  const go = (route) => page.evaluate((r) => { location.hash = r; }, route);

  console.log('Recording');
  await step('Overview', async () => {
    await page.goto(`${BASE}/#/overview`);
    await pause(4500);
    await page.mouse.wheel(0, 600);
    await pause(2500);
    await page.mouse.wheel(0, -600);
    await pause(1200);
  });

  await step('Alert queue and drawer', async () => {
    await go('#/alerts');
    await pause(2200);
    await page.fill('#al-q', 'log4');
    await pause(1800);
    await page.fill('#al-q', '');
    await pause(1000);
    await page.click('tr[data-id="ALERT-2026-9001"]');
    await pause(3500);
    await page.keyboard.press('Escape');
    await pause(800);
  });

  await step('Investigation: Log4Shell (succeeded)', async () => {
    await go('#/investigate/ALERT-2026-9001?run=1');
    await page.waitForSelector('.verdict', { timeout: 60000 });
    await pause(3000);
    await page.mouse.wheel(0, 900);
    await pause(3500);
    await page.mouse.wheel(0, -900);
    await pause(1200);
  });

  await step('Investigation: Log4j vs FastAPI (false positive)', async () => {
    await go('#/investigate/ALERT-2026-9003?run=1');
    await page.waitForSelector('.verdict', { timeout: 60000 });
    await pause(3500);
  });

  await step('Containment and probe', async () => {
    await go('#/containment');
    await pause(2500);
    await page.fill('#probe-ip', '185.220.101.45');
    await pause(600);
    await page.click('#probe-btn');
    await pause(3500);
  });

  await step('Assets and CVE knowledge base', async () => {
    await go('#/assets');
    await pause(2500);
    await go('#/assets?tab=kb&q=log4j');
    await pause(3000);
  });

  await step('Telemetry', async () => {
    await go('#/telemetry');
    await pause(2500);
    await page.fill('#tl-client', '185.220.101.45');
    await pause(2500);
  });

  await step('Command palette', async () => {
    await page.keyboard.press('Control+k');
    await pause(700);
    await page.keyboard.type('apache', { delay: 90 });
    await pause(2200);
    await page.keyboard.press('Escape');
    await pause(600);
  });

  await step('Settings and dark theme', async () => {
    await go('#/settings');
    await pause(2500);
    await page.click('#theme-btn').catch(() => {});
    await pause(1500);
    await go('#/overview');
    await pause(3000);
  });

  const video = page.video();
  await ctx.close();
  await browser.close();
  const webm = await video.path();

  console.log('Encoding');
  execFileSync(ffmpeg, ['-y', '-loglevel', 'error', '-i', webm, '-c:v', 'libx264', '-pix_fmt', 'yuv420p',
    '-preset', 'medium', '-crf', '22', '-movflags', '+faststart', OUT], { stdio: 'inherit' });
  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(`Saved ${path.relative(process.cwd(), OUT)}`);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});