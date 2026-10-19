// Model-free release checks use packaged assets and an owned disposable profile.
import assert from 'node:assert/strict';
import {access, cp, mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = path.resolve(process.env.KUMO_QA_APP || path.join(root, 'dist/Kumo.app'));
const resources = path.join(app, 'Contents/Resources');
const source = path.join(resources, 'KumoExtension');
const info = JSON.parse(await readFile(path.join(source, 'build-info.json'), 'utf8'));
assert.equal(info.phishingProtection?.included, false);
assert.equal(info.phishingProtection.reason, 'omitted-from-release');
assert.equal(info.malwareProtection?.included, true);
assert.equal(info.malwareProtection.downloadAntivirusIncluded, true);
for (const item of [path.join(app, 'Contents/Helpers/KumoPhishing.app'), path.join(resources, 'phishing-host-template.json')]) {
  await assert.rejects(access(item), {code: 'ENOENT'});
}

const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-model-free-qa-'));
const extension = path.join(temporary, 'extension');
const profile = path.join(temporary, 'profile');
let context;
const errors = [], externalRequests = [];
const launch = async () => {
  context = await chromium.launchPersistentContext(profile, {
    executablePath: path.join(app, 'Contents/MacOS/Chromium'),
    headless: true, chromiumSandbox: true, timeout: 90000,
    ignoreDefaultArgs: ['--disable-extensions'],
    args: [`--load-extension=${extension}`, `--disable-extensions-except=${extension}`,
      '--no-first-run', '--disable-background-networking', '--disable-sync',
      '--use-mock-keychain', '--password-store=basic', '--host-resolver-rules=MAP * ~NOTFOUND'],
  });
  context.setDefaultTimeout(15000);
  context.on('request', request => { if (/^https?:/.test(request.url())) externalRequests.push(request.url()); });
  const page = await context.newPage();
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(`chrome-extension://${info.extensionId}/newtab.html`);
  await page.getByRole('heading', {name: 'A little room to explore.'}).waitFor();
  return page;
};

try {
  await cp(source, extension, {recursive: true});
  // A single inert QA origin permits a real persisted script fixture. No page
  // at that origin is opened; all DNS is denied. The signed app is unchanged.
  const manifestPath = path.join(extension, 'manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  manifest.host_permissions = [...new Set([...(manifest.host_permissions || []), 'https://model-free-fixture.invalid/*'])];
  await writeFile(manifestPath, JSON.stringify(manifest));
  let page = await launch();
  const status = () => page.evaluate(() => chrome.runtime.sendMessage({type: 'phishing.status'}));
  assert.deepEqual(await status(), {ok: true, included: false, enabled: false, health: 'not-included', modelVersion: null, currentTab: null});
  // Seed the actual extension stores, as a previous model-inclusive install
  // would leave them, and prove the next worker startup retires them.
  await page.evaluate(async () => {
    await chrome.storage.local.set({phishingProtection: {enabled: true}});
    await chrome.scripting.registerContentScripts([{
      id: 'kumo-local-phishing', matches: ['https://model-free-fixture.invalid/*'],
      js: ['phishing-content.js'], runAt: 'document_idle', persistAcrossSessions: true,
    }]);
    if (!(await chrome.scripting.getRegisteredContentScripts()).some(item => item.id === 'kumo-local-phishing')) {
      throw new Error('The persisted upgrade fixture was not registered.');
    }
  });
  await context.close(); context = null;
  page = await launch();
  assert.deepEqual(await status(), {ok: true, included: false, enabled: false, health: 'not-included', modelVersion: null, currentTab: null});
  const retired = await page.evaluate(async () => ({
    preference: (await chrome.storage.local.get('phishingProtection')).phishingProtection,
    scripts: await chrome.scripting.getRegisteredContentScripts({ids: ['kumo-local-phishing']}),
  }));
  assert.deepEqual(retired, {preference: {enabled: false}, scripts: []});
  let worker = context.serviceWorkers().find(item => item.url().startsWith(`chrome-extension://${info.extensionId}/`));
  worker ||= await context.waitForEvent('serviceworker');
  await worker.evaluate(() => {
    globalThis.__modelFreeNativeCalls = [];
    const original = chrome.runtime.connectNative.bind(chrome.runtime);
    chrome.runtime.connectNative = name => { globalThis.__modelFreeNativeCalls.push(name); return original(name); };
  });
  const rejected = await page.evaluate(() => chrome.runtime.sendMessage({type: 'phishing.enable'}));
  assert.match(rejected.error, /experimental phishing model is not included/);
  assert.notEqual(rejected.ok, true);
  assert.deepEqual(await worker.evaluate(() => globalThis.__modelFreeNativeCalls), []);
  assert.equal((await status()).enabled, false);
  await page.getByRole('button', {name: 'Open settings'}).click();
  await page.locator('[data-panel="privacy"]').click();
  assert.match(await page.locator('#phishingStatus').textContent(), /Not included in this release/);
  assert.equal(await page.locator('#enablePhishing').isDisabled(), true);
  assert.equal(await page.locator('#disablePhishing').isDisabled(), true);
  for (const details of await page.locator('[data-phishing-details]').all()) {
    assert.equal(await details.isHidden(), true);
  }
  assert.deepEqual(externalRequests, []);
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({passed: true, app, engineVersion: info.engineVersion,
    modelIncluded: false, modelHelperAbsent: true, dangerousDomainsIncluded: true,
    downloadAntivirusIncluded: true, oldPreferenceDisabled: true, oldScriptRemoved: true,
    enableRejectedWithoutNativeCall: true, settingsTruthfulAndDisabled: true,
    browserStarts: 2, automaticExternalPageRequests: 0,
    scope: 'Disposable profile, copied packaged extension with one inert QA permission, real sandboxed Chromium, all DNS denied; no account or real credential used.'}, null, 2));
} finally {
  await context?.close();
  await rm(temporary, {recursive: true, force: true});
}
