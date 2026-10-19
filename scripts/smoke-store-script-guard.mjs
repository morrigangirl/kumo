// Source-only policy QA. Every website document is fixed inert HTML supplied
// locally through Playwright routing. No real Store page, CRX, or account is used.
import assert from 'node:assert/strict';
import {access, cp, mkdtemp, mkdir, readFile, realpath, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash, randomUUID} from 'node:crypto';

const arguments_ = process.argv.slice(2);
if (arguments_.includes('--help')) {
  console.log(`Usage: node scripts/smoke-store-script-guard.mjs [--app /path/to/Kumo.app]
Requires a locally compiled source app; the upstream preview is refused before
launch. Loads its unchanged bundled Kumo helper and a separate random-ID MV3
probe in a disposable headless sandbox/mock-keychain profile. Both extensions
are loaded through --load-extension (kCommandLine), without a scripting allowlist.
The probe has mandatory matching host permissions and a declared content script.
Its background chrome.scripting injection must work on example.com, and both
ordinary injection forms must be denied on modern/legacy Store URLs.
All HTTP(S) page requests are locally fulfilled with fixed inert text/html.
The helper is checked through category/detail/detail/category SPA transitions.
The owned helper worker's tabs.create API is replaced before any fixture click
with a recording function that rejects before dispatch. Trusted helper DOM clicks
must reach that barrier with the exact current public CRX URL, after the real
document-bound validation. No CRX navigation, download, native Add confirmation,
Store login, or account is used. Native navigation/installation is not tested.
HTTP/userinfo negatives are explicitly reported as skipped if Chromium normalizes
their URL first. These fixtures test URL policy, not server TLS or all networking.`);
  process.exit(0);
}
assert(arguments_.length === 0 || (arguments_.length === 2 && arguments_[0] === '--app'), 'Use --help for supported arguments.');

// Works both from the audit candidate directory and after promotion to scripts/.
async function projectRoot() {
  let directory = path.dirname(fileURLToPath(import.meta.url));
  while (true) {
    try {
      const candidate = JSON.parse(await readFile(path.join(directory, 'package.json'), 'utf8'));
      if (candidate.name === 'kumo-browser') {
        await access(path.join(directory, 'config/extension-id.txt'));
        return directory;
      }
    } catch (error) {
      if (!['ENOENT', 'ENOTDIR'].includes(error.code)) throw error;
    }
    const parent = path.dirname(directory);
    assert.notEqual(parent, directory, 'Run this script inside the Kumo project.');
    directory = parent;
  }
}
const root = await projectRoot();
const app = path.resolve(arguments_[1] ?? path.join(root, 'dist/Kumo.app'));
const extensionSource = path.join(app, 'Contents/Resources/KumoExtension');
const metadata = JSON.parse(await readFile(path.join(extensionSource, 'build-info.json'), 'utf8'));
assert.equal(metadata.sourceCompiledLocally, true, 'Store scripting-guard QA requires the locally compiled source app.');
const helperId = 'eldkgppmnhligdekahicdcdndcoongio';
assert.equal((await readFile(path.join(root, 'config/extension-id.txt'), 'utf8')).trim(), helperId);
const helperManifest = JSON.parse(await readFile(path.join(extensionSource, 'manifest.json'), 'utf8'));
const idFromKey = createHash('sha256').update(Buffer.from(helperManifest.key, 'base64')).digest('hex').slice(0, 32)
  .replace(/[0-9a-f]/g, value => String.fromCharCode(97 + Number.parseInt(value, 16)));
assert.equal(idFromKey, helperId, 'Use the unchanged fixed-ID bundled helper.');
assert(helperManifest.content_scripts?.some(script => script.js?.includes('store.js') &&
  script.matches?.includes('https://chromewebstore.google.com/*')), 'The helper must be registered on Store category pages for SPA transitions.');
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-store-guard-qa-'));
const profile = path.join(temporary, 'profile');
const extension = path.join(temporary, 'kumo-extension');
const probeDirectory = path.join(temporary, 'ordinary-probe');
const token = randomUUID();
const probeName = `Kumo Store scripting QA ${token}`;
const hostPatterns = ['https://*.chromewebstore.google.com/*', 'http://chromewebstore.google.com/*',
  'https://chrome.google.com/*', 'https://example.com/*'];
const detailA = 'aghfnjkcakhmadgdomlmlhhaocbkloab';
const detailB = 'ddkjiahejlhfcafbddmgiahcphecmpfh';
const origin = 'https://chromewebstore.google.com';
const category = `${origin}/category/extensions`;
const html = '<!doctype html><html><head><meta charset="utf-8"><title>Kumo inert Store policy fixture</title></head><body><h1>Owned inert policy fixture</h1><p>No Store script, network resource, account, or install data.</p></body></html>';
const checks = [], skipped = [], intercepted = [];
let context, engineVersion, probeId, helperWorker;
const blockedNavigationMessage = 'Guard QA stopped navigation before dispatch.';
let closed = false;

async function findWorker() {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    for (const worker of context.serviceWorkers()) {
      if (!worker.url().startsWith('chrome-extension://') || worker.url().startsWith(`chrome-extension://${helperId}/`)) continue;
      try {
        // A component extension may also have a worker. Match the unique owned
        // manifest name, rather than assuming every non-Kumo worker is ours.
        if (await worker.evaluate(() => chrome.runtime.getManifest().name) === probeName) return worker;
      } catch { /* A worker may stop between enumeration and inspection. */ }
    }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('The randomly named owned MV3 probe worker did not start.');
}
async function settingsFor(id) {
  for (const file of ['Preferences', 'Secure Preferences']) {
    try {
      const preferences = JSON.parse(await readFile(path.join(profile, 'Default', file), 'utf8'));
      if (preferences.extensions?.settings?.[id]) return preferences.extensions.settings[id];
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  throw new Error(`No saved location for the owned QA extension ${id}.`);
}

try {
  await cp(extensionSource, extension, {recursive: true});
  await mkdir(probeDirectory, {recursive: true});
  await writeFile(path.join(probeDirectory, 'manifest.json'), JSON.stringify({
    manifest_version: 3, name: probeName, version: '1.0.0',
    permissions: ['tabs', 'scripting'], host_permissions: hostPatterns,
    background: {service_worker: 'background.js'},
    content_scripts: [{matches: hostPatterns, js: ['content.js'], run_at: 'document_end'}],
  }, null, 2));
  await writeFile(path.join(probeDirectory, 'content.js'),
    `document.documentElement.setAttribute('data-kumo-ordinary-content', ${JSON.stringify(token)});\n`);
  await writeFile(path.join(probeDirectory, 'probe.html'), '<!doctype html><title>Owned ordinary extension probe</title><h1>Owned ordinary extension probe</h1>');
  await writeFile(path.join(probeDirectory, 'background.js'), `
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL('')) || message.type !== 'probe.inject') return;
  (async () => {
    const result = await chrome.scripting.executeScript({target: {tabId: message.tabId}, args: [message.token], func: value => {
      document.documentElement.setAttribute('data-kumo-ordinary-programmatic', value);
      return {url: location.href, token: value};
    }});
    return {ok: true, result};
  })().then(reply, error => reply({ok: false, error: error.message}));
  return true;
});
`);
  context = await chromium.launchPersistentContext(profile, {
    executablePath: path.join(app, 'Contents/MacOS/Chromium'), headless: true,
    chromiumSandbox: true, timeout: 90000, viewport: {width: 1280, height: 900},
    ignoreDefaultArgs: ['--disable-extensions'],
    args: [`--load-extension=${extension},${probeDirectory}`, `--disable-extensions-except=${extension},${probeDirectory}`,
      '--no-first-run', '--no-default-browser-check', '--disable-sync', '--use-mock-keychain', '--password-store=basic'],
    env: {...process.env, KUMO_AGENT_DIR: path.join(temporary, 'agents')},
  });
  context.setDefaultTimeout(15000);
  // Install this before any fixture navigation or helper click. There is never
  // route.continue(): even unexpected HTTP(S) requests receive this inert body.
  await context.route(url => ['http:', 'https:'].includes(url.protocol), async route => {
    const request = route.request(), url = request.url();
    intercepted.push({url, method: request.method(), navigation: request.isNavigationRequest(), contentType: 'text/html; charset=utf-8'});
    await route.fulfill({status: 200, contentType: 'text/html; charset=utf-8', headers: {'Cache-Control': 'no-store'}, body: html});
  });
  const page = context.pages()[0] ?? await context.newPage();
  const diagnostics = await context.newCDPSession(page);
  engineVersion = (await diagnostics.send('Browser.getVersion')).product.match(/\d+\.\d+\.\d+\.\d+/)?.[0];
  assert.equal(engineVersion, metadata.engineVersion.split('-')[0], 'Actual native engine must match packaged source metadata.');
  await diagnostics.detach();
  const worker = await findWorker();
  const identity = await worker.evaluate(() => ({id: chrome.runtime.id, manifest: chrome.runtime.getManifest()}));
  probeId = identity.id;
  assert.match(probeId, /^[a-p]{32}$/); assert.notEqual(probeId, helperId);
  assert.equal(identity.manifest.name, probeName);
  assert.equal(identity.manifest.manifest_version, 3);
  assert.equal(identity.manifest.key, undefined, 'The ordinary probe must have no trusted fixed key.');
  assert.deepEqual(identity.manifest.host_permissions, hostPatterns);
  assert.deepEqual(identity.manifest.content_scripts[0].matches, hostPatterns);
  helperWorker = context.serviceWorkers().find(worker => worker.url().startsWith(`chrome-extension://${helperId}/`));
  assert(helperWorker, 'The packaged Kumo helper worker must be present before any fixture click.');
  const barrier = await helperWorker.evaluate(blockedMessage => {
    const attempts = [];
    const block = async properties => {
      attempts.push(structuredClone(properties));
      throw new Error(blockedMessage);
    };
    chrome.tabs.create = block;
    if (chrome.tabs.create !== block) throw new Error('Could not install the fail-closed navigation barrier.');
    globalThis.__kumoGuardCreateRequests = attempts;
    return {installed: true, initialRequests: attempts.length};
  }, blockedNavigationMessage);
  assert.deepEqual(barrier, {installed: true, initialRequests: 0});
  const controls = await context.newPage();
  await controls.goto(`chrome-extension://${probeId}/probe.html`);
  assert.equal(await controls.evaluate(origins => chrome.permissions.contains({origins}), hostPatterns), true,
    'All mandatory matching host permissions must be granted before checking denial.');

  async function injection(url, expectedAllowed, expectedHelper, {normalizationMaySkip = false} = {}) {
    await page.goto(url, {waitUntil: 'load'});
    if (normalizationMaySkip && page.url() !== url) {
      skipped.push({url, actualURL: page.url(), reason: 'Chromium normalized the requested URL before the fixture retained it.'});
      return;
    }
    assert.equal(page.url(), url, 'The policy fixture must retain the exact URL being tested.');
    const declared = await page.locator('html').getAttribute('data-kumo-ordinary-content');
    assert.equal(declared, expectedAllowed ? token : null, `Declared ordinary content-script policy: ${url}`);
    assert.equal(await page.locator('html').getAttribute('data-kumo-ordinary-programmatic'), null);
    const result = await controls.evaluate(async ({url, token}) => {
      const tabs = (await chrome.tabs.query({})).filter(tab => tab.url === url);
      if (tabs.length !== 1) throw new Error(`Expected exactly one fixture tab for ${url}; found ${tabs.length}.`);
      return chrome.runtime.sendMessage({type: 'probe.inject', tabId: tabs[0].id, token});
    }, {url, token});
    assert.equal(result?.ok, expectedAllowed, `Background ordinary chrome.scripting policy: ${url} (${result?.error || ''})`);
    if (expectedAllowed) {
      assert.equal(result.result.length, 1); assert.deepEqual(result.result[0].result, {url, token});
      assert.equal(await page.locator('html').getAttribute('data-kumo-ordinary-programmatic'), token);
    } else {
      assert.match(result.error, /gallery|cannot access|cannot script|not allowed|restricted/i);
      assert.equal(await page.locator('html').getAttribute('data-kumo-ordinary-programmatic'), null);
    }
    // Give any late incorrectly permitted helper a bounded opportunity to
    // appear before accepting a negative, regardless of its run_at setting.
    if (!expectedHelper) await page.waitForTimeout(250);
    await page.waitForFunction(count => document.querySelectorAll('#kumo-store-install').length === count, expectedHelper ? 1 : 0);
    if (expectedHelper) assert.equal(await page.locator('#kumo-store-install').textContent(), 'Install in Kumo');
    checks.push({url, mandatoryHostPermissionGranted: true, declaredAllowed: expectedAllowed,
      backgroundProgrammaticAllowed: expectedAllowed, trustedHelperPresent: expectedHelper});
  }
  await injection('https://example.com/kumo-policy-control', true, false);
  await injection(`${origin}/detail/${detailA}`, false, true);
  await injection('https://chrome.google.com/webstore/detail/fixture/' + detailA, false, false);
  await injection('https://chrome.google.com/kumo-policy-arbitrary-path', false, false);
  await injection('https://sub.chromewebstore.google.com/detail/' + detailA, false, false);
  // The mandatory HTTPS host pattern covers all ports; denial here cannot be
  // attributed to missing host access. The fixed helper exception requires 443.
  await injection('https://chromewebstore.google.com:8443/detail/' + detailA, false, false);
  await injection('http://chromewebstore.google.com/detail/' + detailA, false, false, {normalizationMaySkip: true});
  await injection('https://fixture:inert@chromewebstore.google.com/detail/' + detailA, false, false, {normalizationMaySkip: true});

  async function helperClick(expectedId) {
    const previous = await helperWorker.evaluate(() => globalThis.__kumoGuardCreateRequests.length);
    const pages = context.pages().length;
    await page.locator('#kumo-store-install').click();
    await page.waitForFunction(message => document.getElementById('kumo-store-install')?.textContent === message, blockedNavigationMessage);
    const attempts = await helperWorker.evaluate(() => globalThis.__kumoGuardCreateRequests);
    assert.equal(attempts.length, previous + 1, 'Exactly one create attempt must reach the pre-dispatch barrier.');
    const request = attempts.at(-1);
    assert.deepEqual(Object.keys(request), ['url']);
    const url = new URL(request.url);
    assert.equal(url.origin, 'https://clients2.google.com'); assert.equal(url.pathname, '/service/update2/crx');
    assert.deepEqual([...url.searchParams.keys()].sort(), ['acceptformat', 'prodversion', 'response', 'x']);
    assert.equal(url.searchParams.get('response'), 'redirect'); assert.equal(url.searchParams.get('acceptformat'), 'crx3');
    assert.equal(url.searchParams.get('prodversion'), engineVersion);
    assert.equal(url.searchParams.get('x'), `id=${expectedId}&installsource=ondemand&uc`);
    assert.equal(context.pages().length, pages, 'The barrier must not create a native navigation/page.');
    checks.push({spaHelperClickId: expectedId, backgroundCRXURLVerifiedBeforeDispatch: true,
      nativeNavigationDispatched: false, nativeInstallPrompt: false});
  }
  await page.goto(category, {waitUntil: 'load'});
  assert.equal(await page.locator('#kumo-store-install').count(), 0);
  for (const [pathname, id] of [[`/detail/${detailA}`, detailA], [`/detail/second-fixture/${detailB}`, detailB]]) {
    await page.evaluate(value => history.pushState({}, '', value), pathname);
    await page.waitForFunction(() => document.querySelectorAll('#kumo-store-install').length === 1 &&
      document.getElementById('kumo-store-install').textContent === 'Install in Kumo');
    assert.equal(await page.locator('html').getAttribute('data-kumo-ordinary-content'), null);
    await helperClick(id);
  }
  await page.evaluate(() => history.pushState({}, '', '/category/extensions'));
  await page.waitForFunction(() => document.querySelectorAll('#kumo-store-install').length === 0);
  checks.push({spaSequence: 'category → detail A → detail B → category', ordinaryContentAbsent: true,
    trustedButtonCardinality: [0, 1, 1, 0], trustedClickIds: [detailA, detailB]});

  assert.equal(await helperWorker.evaluate(() => globalThis.__kumoGuardCreateRequests.length), 2);
  await context.close(); closed = true;
  // Inspect only this generated QA profile after the owned browser has exited.
  const [savedProbe, savedHelper] = await Promise.all([settingsFor(probeId), settingsFor(helperId)]);
  assert.equal(savedProbe.location, 8, 'The random ordinary probe must be kCommandLine, not component/policy/global allowlist.');
  assert.equal(savedHelper.location, 8, 'The fixed Kumo helper must use the same kCommandLine location.');
  // Chromium deliberately does not cache unpacked/command-line manifests in
  // preferences (extension_prefs.cc); bind the persisted IDs to their real
  // loaded paths instead. The live probe manifest/name was checked above.
  for (const [saved, loaded] of [[savedProbe, probeDirectory], [savedHelper, extension]]) {
    assert.equal(typeof saved.path, 'string');
    assert.equal(await realpath(path.resolve(profile, 'Default/Extensions', saved.path)), await realpath(loaded));
  }
  assert(intercepted.length > 0); assert(intercepted.every(request => request.contentType.startsWith('text/html')));
  assert.equal(intercepted.filter(request => new URL(request.url).hostname === 'clients2.google.com').length, 0,
    'The worker barrier must prevent CRX endpoint navigation, even if native handling bypasses page routing.');
  console.log(JSON.stringify({passed: true, sourceCompiledLocally: true, engineVersion, sandbox: true, mockKeychain: true,
    helperId, ordinaryProbeId: probeId, bothManifestLocations: 'kCommandLine (8)', checks, skipped,
    websiteRequestCount: intercepted.length, allWebsiteResponsesLocallyFulfilledAsInertHTML: true,
    realStoreContentFetched: false, backgroundRequestURLVerifiedBeforeDispatch: true,
    nativeCRXNavigationDispatched: false, crxOrNativeInstallationTested: false, serverTLSValidated: false,
    unrelatedBrowserBackgroundNetworkingAudited: false}, null, 2));
} finally {
  // A failed close deliberately preserves the owned files; never delete an
  // active browser's profile or pretend a forced/unobserved shutdown succeeded.
  if (context && !closed) { await context.close(); closed = true; }
  await rm(temporary, {recursive: true, force: true});
}
