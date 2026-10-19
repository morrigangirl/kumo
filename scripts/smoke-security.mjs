// Packaged status-card QA uses a disposable profile. The actual click's
// chrome.tabs.create URL is recorded; its navigation is redirected to a local
// extension page only in this test, so no remote release page is fetched.
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {engineSecurityStatus} from '../extension/security.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const resources = path.join(root, 'dist/Kumo.app/Contents/Resources');
const extension = path.join(resources, 'KumoExtension');
const info = JSON.parse(await readFile(path.join(extension, 'build-info.json'), 'utf8'));
const lock = JSON.parse(await readFile(path.join(root, 'config/source-lock.json'), 'utf8'));
assert.equal(info.sourceTargetVersion, lock.chromiumVersion);
const expected = engineSecurityStatus(info);
const releases = 'https://github.com/ungoogled-software/ungoogled-chromium/releases';
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-security-qa-'));
const output = path.join(root, 'dist/screenshots');
const externalRequests = [];
const errors = [];
let context;
try {
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
    assert.match(await card.textContent(), /no automatic updater or live security-status check/);
    await page.screenshot({path: path.join(output, `${panel}-security.png`), fullPage: true});
  }
  assert.deepEqual(await page.evaluate(() => globalThis.__kumoReleaseRequests), [], 'Opening status panels must not open releases automatically');
  assert.deepEqual(externalRequests, [], 'Opening status panels must not make external requests');
  const opened = context.waitForEvent('page');
  await page.locator('#panel-about [data-engine-releases]').click();
  const releasePage = await opened;
  await releasePage.waitForURL(localResult);
  const requested = await page.evaluate(() => globalThis.__kumoReleaseRequests);
  assert.deepEqual(requested, [releases]);
  assert.deepEqual(externalRequests, []);
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({passed: true, engineVersion: info.engineVersion, sourceTargetVersion: info.sourceTargetVersion, status: expected.kind, automaticReleaseRequests: 0, clickedReleaseURL: requested[0], testNavigationRedirectedLocally: true}, null, 2));
} finally {
  await context?.close();
  await rm(temporary, {recursive: true, force: true});
}
