// Packaged status-card QA uses a disposable profile. The actual click's
// chrome.tabs.create URL is recorded; its navigation is redirected to a local
// extension page only in this test, so no remote release page is fetched.
import assert from 'node:assert/strict';
import {cp, mkdtemp, mkdir, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {engineSecurityStatus} from '../extension/security.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const resources = path.join(root, 'dist/Kumo.app/Contents/Resources');
const extensionSource = process.env.KUMO_QA_EXTENSION ? path.resolve(process.env.KUMO_QA_EXTENSION) : path.join(resources, 'KumoExtension');
const info = JSON.parse(await readFile(path.join(extensionSource, 'build-info.json'), 'utf8'));
const lock = JSON.parse(await readFile(path.join(root, 'config/source-lock.json'), 'utf8'));
assert.equal(info.sourceTargetVersion, lock.chromiumVersion);
const expected = engineSecurityStatus(info);
const releases = 'https://github.com/morrigangirl/kumo/releases';
const updateCommand = 'open -n -b app.kumo.browser --args --kumo-check-for-updates';
assert.equal(info.appUpdates?.included, true);
assert.equal(info.appUpdates.provider, 'github-releases');
assert.equal(info.appUpdates.repository, 'morrigangirl/kumo');
assert.equal(info.appUpdates.releasesURL, releases);
assert.equal(info.appUpdates.feedURL, `${releases}/latest/download/appcast.xml`);
assert.equal(info.appUpdates.checkCommand, updateCommand);
assert.match(info.appUpdates.version, /^\d+\.\d+\.\d+(?:[.-][0-9A-Za-z.-]+)?$/);
assert.match(info.appUpdates.build, /^\d+$/);
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-security-qa-'));
const extension = path.join(temporary, 'kumo-extension');
const output = process.env.KUMO_QA_OUTPUT ? path.resolve(process.env.KUMO_QA_OUTPUT) : path.join(root, 'dist/screenshots');
const externalRequests = [];
const errors = [];
let context;
try {
  await cp(extensionSource, extension, {recursive: true});
  context = await chromium.launchPersistentContext(path.join(temporary, 'profile'), {
    executablePath: path.join(root, 'dist/Kumo.app/Contents/MacOS/Chromium'),
    headless: true, chromiumSandbox: true, timeout: 90000,
    ignoreDefaultArgs: ['--disable-extensions'],
    args: [`--load-extension=${extension}`, `--disable-extensions-except=${extension}`, '--no-first-run', '--disable-sync', '--use-mock-keychain'],
  });
  context.setDefaultTimeout(15000);
  context.on('request', request => { if (/^https?:/.test(request.url())) externalRequests.push(request.url()); });
  const page = await context.newPage();
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(`chrome-extension://${info.extensionId}/newtab.html`);
  await page.getByRole('heading', {name: 'A little room to explore.'}).waitFor();
  const localResult = `chrome-extension://${info.extensionId}/popup.html`;
  await page.evaluate(localURL => {
    globalThis.__kumoReleaseRequests = [];
    globalThis.__kumoUpdateCommands = [];
    Object.defineProperty(navigator, 'clipboard', {value: {writeText: async text => globalThis.__kumoUpdateCommands.push(text)}, configurable: true});
    const create = chrome.tabs.create.bind(chrome.tabs);
    chrome.tabs.create = options => {
      globalThis.__kumoReleaseRequests.push(options.url);
      return create({...options, url: localURL});
    };
  }, localResult);
  await page.getByRole('button', {name: 'Open settings'}).click();
  await mkdir(output, {recursive: true});
  for (const panel of ['privacy', 'about']) {
    await page.locator(`[data-panel="${panel}"]`).click();
    const card = page.locator(`#panel-${panel} [data-engine-status]`);
    assert.equal(await card.getAttribute('data-engine-status'), expected.kind);
    assert.equal(await card.locator('[data-engine-status-title]').textContent(), expected.title);
    assert.equal(await card.locator('[data-engine-status-versions]').textContent(), expected.versions);
    assert.match(await card.textContent(), /does not check the current release or establish security support/);
    const updates = page.locator(`#panel-${panel} [data-app-updates]`);
    assert.match(await updates.textContent(), /App updates · GitHub Releases/);
    assert.equal(await updates.locator('[data-app-update-version]').textContent(), `Kumo ${info.appUpdates.version} · Build ${info.appUpdates.build}`);
    assert.equal(await updates.locator('[data-app-update-status]').textContent(), info.appUpdates.ready === true
      ? 'Release channel: GitHub Releases. The native updater verifies signed updates before installation.'
      : 'Local development build. Release updates require Developer ID signing, notarization and a configured update verification key.');
    await updates.locator('[data-app-check-updates]').click();
    await page.getByRole('status').filter({hasText: 'Command copied. Run it in Terminal to open Kumo’s native updater.'}).waitFor();
    await page.screenshot({path: path.join(output, `${panel}-security.png`), fullPage: true});
  }
  assert.deepEqual(await page.evaluate(() => globalThis.__kumoReleaseRequests), [], 'Opening status panels must not open releases automatically');
  assert.deepEqual(externalRequests, [], 'Opening status panels must not make external requests');
  const copiedCommands = await page.evaluate(() => globalThis.__kumoUpdateCommands);
  assert.deepEqual(copiedCommands, [updateCommand, updateCommand], 'Both real buttons must copy the portable native updater command');
  const opened = context.waitForEvent('page');
  await page.locator('#panel-about [data-app-releases]').click();
  const releasePage = await opened;
  await releasePage.waitForURL(localResult);
  const requested = await page.evaluate(() => globalThis.__kumoReleaseRequests);
  assert.deepEqual(requested, [releases]);
  assert.deepEqual(externalRequests, []);
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({passed: true, engineVersion: info.engineVersion, sourceTargetVersion: info.sourceTargetVersion, status: expected.kind, appVersion: info.appUpdates.version, appBuild: info.appUpdates.build, updateChannel: info.appUpdates.provider, updateReady: info.appUpdates.ready === true, copiedUpdateCommands: copiedCommands, automaticReleaseRequests: 0, clickedReleaseURL: requested[0], testNavigationRedirectedLocally: true}, null, 2));
} finally {
  await context?.close();
  await rm(temporary, {recursive: true, force: true});
}
