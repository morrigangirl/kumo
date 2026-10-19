// Source-only native WebUI QA. The actual sidebar href is inspected and its
// user-click navigation is aborted locally; no Google page is fetched.
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const arguments_ = process.argv.slice(2);
if (arguments_.includes('--help')) {
  console.log(`Usage: node scripts/smoke-native-store-link.mjs [--app /path/to/Kumo.app]
Requires a locally compiled source app. Uses its actual native Extensions sidebar
in a disposable headless profile with sandbox and mock keychain. Checks the real
#discover-more-text a href/target, then clicks it with HTTP(S) requests intercepted
and aborted locally. No Store listing, account, install, or user profile is used.
The current upstream preview is refused before launching a browser.`);
  process.exit(0);
}
assert(arguments_.length === 0 || (arguments_.length === 2 && arguments_[0] === '--app'), 'Use --help for supported arguments.');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = path.resolve(arguments_[1] ?? path.join(root, 'dist/Kumo.app'));
const metadata = JSON.parse(await readFile(path.join(app, 'Contents/Resources/KumoExtension/build-info.json'), 'utf8'));
assert.equal(metadata.sourceCompiledLocally, true, 'Native Store-link QA requires the locally compiled source app.');
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-native-store-link-qa-'));
const expected = 'https://chromewebstore.google.com/category/extensions';
let context, timer;
try {
  context = await chromium.launchPersistentContext(path.join(temporary, 'profile'), {
    executablePath: path.join(app, 'Contents/MacOS/Chromium'),
    headless: true, chromiumSandbox: true, timeout: 90000, viewport: {width: 1280, height: 900},
    args: ['--no-first-run', '--no-default-browser-check', '--disable-sync', '--use-mock-keychain', '--password-store=basic'],
  });
  const page = context.pages()[0] ?? await context.newPage();
  const diagnostics = await context.newCDPSession(page);
  const engineVersion = (await diagnostics.send('Browser.getVersion')).product.match(/\d+\.\d+\.\d+\.\d+/)?.[0];
  assert.equal(engineVersion, metadata.engineVersion.split('-')[0], 'Actual native engine must match packaged source metadata.');
  await diagnostics.detach();
  await page.goto('chrome://extensions', {waitUntil: 'domcontentloaded'});
  const link = page.locator('extensions-sidebar').locator('#discover-more-text a');
  await link.waitFor({state: 'visible', timeout: 15000});
  const native = await link.evaluate(element => ({href: element.href, attribute: element.getAttribute('href'), target: element.target}));
  assert.equal(native.href, expected); assert.equal(native.attribute, expected); assert.equal(native.target, '_blank');
  let resolveRequest, rejectRequest;
  const requested = new Promise((resolve, reject) => { resolveRequest = resolve; rejectRequest = reject; });
  const httpRequest = url => ['http:', 'https:'].includes(url.protocol);
  const intercept = async route => {
    if (!route.request().isNavigationRequest()) { await route.abort(); return; }
    const target = route.request().url();
    try {
      await route.abort('blockedbyclient');
      resolveRequest(target);
    } catch (error) { rejectRequest(error); }
  };
  await context.route(httpRequest, intercept);
  let target;
  try {
    timer = setTimeout(() => rejectRequest(new Error('The native sidebar click did not issue an intercepted navigation.')), 15000);
    [, target] = await Promise.all([link.click(), requested]);
    assert.equal(target, expected, 'The actual native sidebar click must request the modern Store category URL.');
  } finally { clearTimeout(timer); await context.unroute(httpRequest, intercept); }
  console.log(JSON.stringify({passed: true, engineVersion, sourceCompiledLocally: true,
    actualNativeSidebarLinkVisible: true, nativeSidebarHref: native.href, nativeSidebarTarget: native.target,
    nativeUserClickTarget: target, nativeStoreNavigationAbortedLocally: true,
    nativeStorePageFetchedFromGoogle: false, storeInstallationVerified: false}));
} finally {
  clearTimeout(timer); await context?.close();
  await rm(temporary, {recursive: true, force: true});
}
