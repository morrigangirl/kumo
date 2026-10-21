// Integration QA uses a disposable profile. No user accounts or saved credentials are touched.
import assert from 'node:assert/strict';
import {cp, mkdtemp, mkdir, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createServer} from 'node:http';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const app = path.join(root, 'dist/Kumo.app');
const eid = (await readFile(path.join(root, 'config/extension-id.txt'), 'utf8')).trim();
const runtime = await mkdtemp(path.join(tmpdir(), 'kumo-qa-'));
const profile = path.join(runtime, 'profile');
const extension = path.join(runtime, 'kumo-extension');
const output = path.join(root, 'dist/screenshots'); await mkdir(output, {recursive: true});
const errors = [];
const server = createServer((req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.setHeader('Set-Cookie', 'kumo_test=retained; Max-Age=600; SameSite=Lax');
  res.end('<!doctype html><html><head><title>Kumo QA fixture</title></head><body><h1>Local test page</h1><form><input id="username" autocomplete="username"><input id="password" type="password" value="must-not-leak"><textarea id="draft">private draft</textarea><input id="otp" autocomplete="one-time-code"><button id="go" type="button" onclick="this.textContent=\'Clicked\'">Continue</button></form><div style="display:none">hidden secret</div><p id="result">Visible content</p><a href="/next">Next</a></body></html>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const fixture = `http://127.0.0.1:${server.address().port}`;
let context;
const launch = () => chromium.launchPersistentContext(profile, {
  executablePath: path.join(app, 'Contents/MacOS/Chromium'), headless: true, chromiumSandbox: true,
  ignoreDefaultArgs: ['--disable-extensions'],
  args: [`--load-extension=${extension}`, `--disable-extensions-except=${extension}`, '--no-first-run', '--disable-sync'],
  env: {...process.env, KUMO_AGENT_DIR: path.join(runtime, 'agents')}, viewport: {width: 1440, height: 960}
});
try {
  await cp(path.join(app, 'Contents/Resources/KumoExtension'), extension, {recursive: true});
  context = await launch();
  context.setDefaultTimeout(15000);
  const metadata = JSON.parse(await readFile(path.join(extension, 'build-info.json'), 'utf8'));
  const diagnostics = await context.newCDPSession(context.pages()[0]);
  const runtimeVersion = await diagnostics.send('Browser.getVersion');
  assert.equal(runtimeVersion.product.match(/\d+\.\d+\.\d+\.\d+/)?.[0], metadata.engineVersion.split('-')[0], 'Packaged metadata must match the executing Chromium engine');
  await diagnostics.detach();
  console.log('Chromium started with the sandbox enabled.');
  context.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message));
  await page.goto(`chrome-extension://${eid}/newtab.html`);
  await page.getByRole('heading', {name: 'A little room to explore.'}).waitFor();
  console.log('New-tab UI loaded.');
  // Build metadata loads asynchronously after the static heading is visible.
  await page.waitForFunction(version => document.getElementById('engineDescription')?.textContent.includes(version), metadata.engineVersion);
  assert.match(await page.locator('#engineDescription').textContent(), new RegExp(metadata.engineVersion.replaceAll('.', '\\.')),
    'About must identify the packaged engine rather than a hard-coded preview version');
  assert.equal(await page.locator('[data-panel="passwords"], #panel-passwords, #passwordFeatureTitle').count(), 0,
    'Kumo must not expose its removed built-in password integration');
  await page.screenshot({path: path.join(output, 'home.png'), fullPage: true});
  await page.getByRole('button', {name: 'Open settings'}).click();
  await page.getByRole('button', {name: 'Forest', exact: true}).click();
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'forest');
  await page.locator('[data-panel="search"]').click();
  await page.locator('#engineName').fill('QA engine');
  await page.locator('#engineURL').fill('https://search.example/?q={searchTerms}');
  await page.getByRole('button', {name: 'Add engine'}).click();
  assert.equal(await page.locator('#defaultEngine option:checked').textContent(), 'QA engine');
  await page.reload();
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'forest');
  await page.getByRole('button', {name: 'Open settings'}).click();
  const preferences = await page.evaluate(async () => (await chrome.storage.local.get('preferences')).preferences);
  await page.locator('#importSettings').setInputFiles({name: 'untrusted-preferences.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({...preferences, background: 'data:image/png;base64,"), url("https://tracker.invalid/pixel'}))});
  await page.getByText('Preferences imported.', {exact: true}).waitFor();
  assert.equal(await page.evaluate(() => document.body.style.backgroundImage), '');
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j4/0AAAAASUVORK5CYII=', 'base64');
  await page.locator('#wallpaper').setInputFiles({name: 'local-wallpaper.png', mimeType: 'image/png', buffer: png});
  await page.getByText('Background saved on this Mac.', {exact: true}).waitFor();
  assert.match(await page.evaluate(() => document.body.style.backgroundImage), /data:image\/png;base64,/);
  await page.screenshot({path: path.join(output, 'settings.png'), fullPage: true});
  await page.getByRole('button', {name: 'Close settings'}).click();
  console.log('Themes and custom search persisted; imported wallpaper URLs rejected and local image accepted.');
  const fixturePage = await context.newPage(); await fixturePage.goto(fixture);
  const cookies = await context.cookies(fixture); assert(cookies.some(c => c.name === 'kumo_test'));
  const coreState = await page.evaluate(async () => Promise.race([
    chrome.runtime.sendMessage({type: 'agent.status'}),
    new Promise((_, reject) => setTimeout(() => reject(new Error('Agent status timed out')), 10000))
  ]));
  assert.equal(coreState.enabled, false);
  // Open Chromium's native settings, proving this is a full browser rather than a webview.
  const native = await context.newPage(); await native.goto('chrome://settings/security');
  assert.match(await native.title(), /Settings/i);
  console.log('Native settings and agent status checked.');
  await context.close(); context = await launch();
  assert((await context.cookies(fixture)).some(c => c.name === 'kumo_test'), 'Website sessions must survive process restarts');
  await context.close(); context = undefined;
  assert.deepEqual(errors, [], 'No extension page errors');
  console.log('PASS: packaged Chromium, local extension UI, theme persistence, custom engines, native settings, disabled agents, persistent cookies.');
  console.log(`Screenshots: ${output}`);
} finally {
  await context?.close(); server.close();
  await rm(runtime, {recursive: true, force: true});
}
