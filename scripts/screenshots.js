// Captures README screenshots from a demo server.
//   AEGIS_DEMO=1 AEGIS_DATA_FILE=.data/demo.json npm start   (in one terminal)
//   npm run screenshots                                      (in another)
const path = require('path');
const fs = require('fs');
const { chromium } = require('playwright');
const { signIn, BASE } = require('./demo-session');

const OUT = path.join(__dirname, '..', 'docs', 'screens');

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { cookie } = await signIn({ reset: true });
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  await context.addCookies([cookie]);
  const page = await context.newPage();
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
  await open('settings', 1500);
  await shot('settings');
  await open('reports', 2000);
  await shot('reports');
  await open('intel?tab=detect', 1800);
  await page.click('#dt-sample');
  await page.click('#dt-run');
  await page.waitForTimeout(1500);
  await shot('intel-detect');
  await open('intel?tab=kev', 6000);
  await shot('intel-kev');
  await open('intel?tab=ioc', 1200);
  await page.fill('#ioc-in', '185.220.101.45\n45.95.147.236\n8.8.8.8');
  await page.click('#ioc-go');
  await page.waitForTimeout(8000);
  await shot('intel-ioc');
  await open('ip/185.220.101.45', 6000);
  await shot('ip-profile');
  // Overview again, now that an investigation and rules exist.
  await open('overview', 1800);
  await shot('overview');

  const darkCtx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await darkCtx.addCookies([cookie]);
  const dark = await darkCtx.newPage();
  await dark.addInitScript(() => localStorage.setItem('aegis.theme', 'dark'));
  await dark.goto(`${BASE}/#/overview`);
  await dark.waitForTimeout(1800);
  await dark.screenshot({ path: path.join(OUT, 'overview-dark.png') });

  // Signed-out view, without the session cookie.
  const anon = await (await browser.newContext({ viewport: { width: 1280, height: 760 } })).newPage();
  await anon.goto(BASE);
  await anon.waitForSelector('.gate.is-in .gate__emblem');
  await anon.waitForTimeout(1200);
  await anon.screenshot({ path: path.join(OUT, 'sign-in.png') });

  await browser.close();
  if (errors.length) { console.error(errors); process.exit(1); }
  console.log(`Saved to ${OUT}`);
})().catch((e) => { console.error(e); process.exit(1); });