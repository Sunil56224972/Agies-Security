// Captures README screenshots from a running server.
//   npm start            (in one terminal)
//   npm run screenshots  (in another)
const path = require('path');
const fs = require('fs');
const { chromium } = require('playwright');

const BASE = process.env.AEGIS_URL || 'http://localhost:3000';
const OUT = path.join(__dirname, '..', 'docs', 'images');

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const shot = (name, opts = {}) => page.screenshot({ path: path.join(OUT, `${name}.png`), ...opts });
  const open = async (route, wait = 1200) => { await page.goto(`${BASE}/#/${route}`); await page.waitForTimeout(wait); };

  await page.addInitScript(() => localStorage.setItem('aegis.theme', 'light'));
  await open('overview', 1800);
  await shot('overview');
  await open('alerts');
  await shot('alerts');
  await page.click('tr[data-id]');
  await page.waitForTimeout(700);
  await shot('alert-drawer');
  await page.keyboard.press('Escape');

  await page.goto(`${BASE}/#/investigate/ALERT-2026-9001?run=1`);
  await page.waitForSelector('.verdict', { timeout: 60000 });
  await page.waitForTimeout(1500);
  await page.addStyleTag({ content: '.toasts{display:none}' });
  await page.setViewportSize({ width: 1440, height: 1500 });
  await shot('investigation');
  await page.setViewportSize({ width: 1440, height: 900 });

  await open('containment');
  await page.fill('#probe-ip', '185.220.101.45');
  await page.click('#probe-btn');
  await page.waitForTimeout(1200);
  await shot('containment');
  await open('assets');
  await shot('assets');
  await open('telemetry?host=10.0.4.15');
  await shot('telemetry');

  const dark = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await dark.addInitScript(() => localStorage.setItem('aegis.theme', 'dark'));
  await dark.goto(`${BASE}/#/overview`);
  await dark.waitForTimeout(1800);
  await dark.screenshot({ path: path.join(OUT, 'overview-dark.png') });

  await browser.close();
  if (errors.length) { console.error(errors); process.exit(1); }
  console.log(`Saved to ${OUT}`);
})().catch((e) => { console.error(e); process.exit(1); });