// Run with Playwright available on NODE_PATH. All browser requests are local fixtures.
const {chromium} = require('playwright');
const {readFile} = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
(async () => {
  const browser = await chromium.launch({headless:true,
    ...(process.env.BURNISO_TEST_BROWSER ? {executablePath:process.env.BURNISO_TEST_BROWSER} : {})});
  try {
    for (const scenario of ['success','none','error']) {
      const page = await browser.newPage({viewport:{width:1000,height:1100}});
      const errors = [];
      page.on('pageerror', e => errors.push(e.message));
      await page.route('**/*', async route => {
        const url = new URL(route.request().url());
        const file = path.resolve(root, '.' + url.pathname);
        if (!file.startsWith(root + path.sep)) return route.abort();
        try {
          const type = {'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript',
            '.css':'text/css','.json':'application/json','.svg':'image/svg+xml'}[path.extname(file)];
          await route.fulfill({body:await readFile(file),contentType:type || 'application/octet-stream'});
        } catch { await route.fulfill({status:404,body:''}); }
      });
      await page.goto('http://burniso.test/tests/app-preview.html?f3=' + scenario);
      const app = page.frameLocator('iframe');
      await app.locator('#diagnose-disk-select option:nth-child(2)').waitFor({state:'attached'});
      await app.locator('[data-tab="diagnose"]').click();
      await app.locator('#diagnose-disk-select').selectOption({index:1});
      await app.locator('input[name="diagnose-mode"][value="f3"]').check();
      if (scenario === 'none') {
        await app.locator('#f3-volume-select option').filter({hasText:/Kein|No suitable/}).waitFor({state:'attached'});
        assert(await app.locator('#diagnose-btn').isDisabled());
      } else {
        await app.locator('#f3-volume-select option:nth-child(2)').waitFor({state:'attached'});
        await app.locator('#diagnose-btn').click();
        await app.locator('#confirm-ok-btn').click();
        assert(await app.locator('#f3-volume-select').isDisabled());
        if (scenario === 'success') {
          await app.locator('#diagnose-details').filter({hasText:/F3-Dateiprüfung|F3 file test/}).waitFor();
          assert.match(await app.locator('#diagnose-details').innerText(), /1024.0 MiB/);
        } else {
          await app.locator('#diagnose-log').filter({hasText:'.burniso-f3-fixture'}).waitFor();
        }
        assert(!(await app.locator('#f3-volume-select').isDisabled()));
        const calls = await page.frames()[1].evaluate(() => window.__mockCalls);
        const invocation = calls.find(c => c.command === 'diagnose_f3');
        assert.deepEqual(invocation.args,{diskId:'disk99',volumeId:'disk100s1',volumeUuid:'fixture-uuid'});
        assert(!calls.some(c => c.command === 'diagnose_full_test'));
        assert(!(await app.locator('#password-modal').isVisible()));
        if (scenario === 'success') await page.screenshot({path:'/private/tmp/burniso-f3-ui.png',fullPage:true});
      }
      assert.deepEqual(errors, []);
      await page.close();
      console.log('F3 UI:', scenario, 'passed');
    }
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exitCode = 1; });
