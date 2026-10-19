// Interactive Store-extension QA. CUA accepts the native installation prompt in
// this generated QA app only; CDP attaches AFTER installation to inspect APIs.
// Official uBO Lite project links this exact Store ID (checked 2026-10-18):
// https://github.com/uBlockOrigin/uBOL-home#ubo-lite
import assert from 'node:assert/strict';
import {execFile as execFileCallback, spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {cp, mkdtemp, mkdir, open, readFile, writeFile, readdir, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash, randomUUID} from 'node:crypto';
import {createInterface} from 'node:readline';
import {requestNativeUpdateCheck, verifyNativeUpdateLog} from './extension-update-qa.mjs';

const execFile = promisify(execFileCallback);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const arguments_ = process.argv.slice(2);
if (arguments_.includes('--help')) {
  console.log(`Usage: node scripts/smoke-extension.mjs [--app /path/to/Kumo.app] [--fixture ubol|theme] [--update-check] [--prepare-only]
Requires a locally compiled source build and .cache/qa/node_modules/playwright-core.
Creates a separately signed QA app with a unique bundle ID and fixed disposable
profile. CUA must target the printed QA app path, never the original app or engine.
All re-signing uses the configured development identity, preserves verified
source runtime flags/entitlements and checks the resulting masks, Team IDs and
both main executables' unique QA identifiers. Nested signatures stay unchanged.
--prepare-only verifies this setup without launching the browser or contacting
Store, then cleans up. It accepts the preview for setup evidence only; functional
installation/update checks always require the locally compiled source app.

In that QA window, confirm the official uBlock Origin Lite Store listing from
Raymond Hill (gorhill). Click Install in Kumo; review and accept the native Add
extension prompt. Do not sign in, import a profile, or install another extension.
Only after this step, send status: CDP then opens the installed extension's own
local options page and checks MV3, its module worker and enabled DNR rulesets.
No ad, tracker, malware, third-party test URL, or user account is used.
--fixture theme selects Google's official Just Black theme instead. Observe the
native Add theme confirmation, then check installed: it requires a packed theme,
matching public key/Store ID, no extension permissions, active native Appearance
state and a real #openTheme click requesting the modern Store detail URL. That
click's HTTP(S) navigation is aborted locally by the test before any fetch.
--update-check is supported only with the default uBO Lite fixture.

Commands: status, check installed, check updates, finish, close.
check installed records your explicit observation of native installation consent
and requires a normal packed install, public-key/Store-ID match, active extension
APIs, an observed service worker, and enabled nonempty packaged DNR rulesets.
Signature verification belongs to Chromium's native CRX installer; this harness
does not independently verify a detached signature or bypass installation checks.
finish requires check installed; close/EOF aborts. All QA processes/files are removed.
With --update-check, run check updates twice in the same owned fixture:
1. Keep bundled Kumo enabled for the first check.
2. Use CUA to turn ONLY Kumo off with its real native Extensions switch, then
   run check updates again. Keep uBO Lite enabled. Do not use programmatic toggles.
Each check records native/saved helper state and requires its numeric command-line
location 8, exact bundle path and enabled/disabled state to survive native Update.
A synthetic .google.com cookie tests omission at clients2.google.com. The harness
clicks the real Update button and requires its completion within 60 seconds.
finish closes the owned browser and independently verifies both request windows
in the finalized Default NetLog. Each must contain a successful CWS manifest
request without Cookie/Authorization, ping/account parameters or redirects.
A failed attempt requires a fresh QA run; no later response can rescue it.
No-update responses/unchanged versions do not prove update download, publisher
proof on an update CRX, automatic scheduling, or an update installation.
This checks installation/local APIs and optional update transport, not filtering.`);
  process.exit(0);
}
const updateCheck = arguments_.includes('--update-check');
const prepareOnly = arguments_.includes('--prepare-only');
assert(arguments_.filter(argument => argument === '--update-check').length <= 1, 'Pass --update-check only once.');
assert(arguments_.filter(argument => argument === '--prepare-only').length <= 1, 'Pass --prepare-only only once.');
assert(arguments_.filter(argument => argument === '--fixture').length <= 1, 'Pass --fixture only once.');
const fixtureAt = arguments_.indexOf('--fixture');
const fixtureName = fixtureAt === -1 ? 'ubol' : arguments_[fixtureAt + 1];
assert(['ubol', 'theme'].includes(fixtureName), 'Use --fixture ubol or --fixture theme.');
const themeFixture = fixtureName === 'theme';
assert(!updateCheck || !themeFixture, '--update-check requires the default uBO Lite fixture.');
const extensionId = themeFixture ? 'aghfnjkcakhmadgdomlmlhhaocbkloab' : 'ddkjiahejlhfcafbddmgiahcphecmpfh';
const storeURL = `https://chromewebstore.google.com/detail/${themeFixture ? 'just-black' : 'ublock-origin-lite'}/${extensionId}`;
const officialFixture = themeFixture ? storeURL : 'https://github.com/uBlockOrigin/uBOL-home';
const appArguments = arguments_.filter((argument, index) =>
  !['--update-check', '--prepare-only'].includes(argument) && (fixtureAt < 0 || (index !== fixtureAt && index !== fixtureAt + 1)));
assert(appArguments.length === 0 || (appArguments.length === 2 && appArguments[0] === '--app'),
  'Use --help for supported arguments.');
assert(process.platform === 'darwin' && process.arch === 'arm64', 'This QA target requires Apple Silicon macOS.');
const original = path.resolve(appArguments[1] ?? path.join(root, 'dist/Kumo.app'));
const buildInfo = JSON.parse(await readFile(path.join(original, 'Contents/Resources/KumoExtension/build-info.json'), 'utf8'));
assert(prepareOnly || buildInfo.sourceCompiledLocally === true, 'Functional extension QA requires the locally compiled source app.');
if (updateCheck) assert.equal(buildInfo.extensionId, 'eldkgppmnhligdekahicdcdndcoongio', 'Update QA requires the pinned bundled Kumo helper ID.');
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const runtime = await mkdtemp(path.join(tmpdir(), 'kumo-extension-qa-'));
const suffix = randomUUID().replaceAll('-', '');
const displayName = `Kumo Extension QA ${suffix.slice(0, 8)}`;
const app = path.join(runtime, `${displayName}.app`);
const bundleId = `app.kumo.extensionqa.${suffix}`;
const profile = path.join(runtime, 'profile');
const engine = path.join(app, 'Contents/MacOS/Chromium');
const launcher = path.join(app, 'Contents/MacOS/KumoExtensionQA');
const bundledExtension = path.join(runtime, 'kumo-extension');
const statePath = path.join(runtime, 'qa-state.json');
const netLogPath = updateCheck ? path.join(runtime, 'update-check-netlog.json') : undefined;
let child, browser, context, optionsPage, appearancePage, input, cleanupPromise;
let observedWorker = false, checked = false, finished = false;
const updateRequests = [];
let updateAttemptFailed = false;

async function signingPolicy(target) {
  const result = await execFile('codesign', ['-d', '--verbose=4', target]);
  const details = result.stdout + result.stderr;
  const flags = details.match(/\bflags=(0x[\da-f]+)/i);
  const identifier = details.match(/^Identifier=(.+)$/m);
  const team = details.match(/^TeamIdentifier=([A-Z0-9]{10})$/m);
  const cdhash = details.match(/^CDHash=(.+)$/m);
  assert(flags && identifier && team && cdhash, 'The verified QA source must expose signing flags, identifier, Team ID and code hash.');
  // Keep the source policy, removing only ad-hoc/linker-signature bookkeeping.
  return {options: (Number.parseInt(flags[1], 16) & ~0x20002) >>> 0,
    identifier: identifier[1], team: team[1], cdhash: cdhash[1]};
}

async function nestedSignatures(base, expectedTeam) {
  const result = new Map();
  const machoMagic = new Set([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe,
    0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca]);
  async function visit(directory) {
    for (const entry of await readdir(directory, {withFileTypes: true})) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) { await visit(file); continue; }
      if (!entry.isFile()) continue;
      const handle = await open(file, 'r');
      let magic;
      try {
        const buffer = Buffer.alloc(4);
        const {bytesRead} = await handle.read(buffer, 0, 4, 0);
        if (bytesRead === 4) magic = buffer.readUInt32BE();
      } finally { await handle.close(); }
      if (!machoMagic.has(magic)) continue;
      const policy = await signingPolicy(file);
      assert.equal(policy.team, expectedTeam, 'All retained nested code must belong to the configured development team.');
      result.set(path.relative(base, file), policy);
    }
  }
  await visit(path.join(base, 'Contents/Frameworks'));
  assert(result.size > 0, 'The QA source must include signed nested browser code.');
  return result;
}

async function stopOwnedProcesses() {
  // Only executable paths inside this generated app match; never kill by name,
  // shared bundle ID, the user's profile, or broad Chromium process patterns.
  const owned = async () => {
    const {stdout} = await execFile('ps', ['-axo', 'pid=,command=']);
    return stdout.split('\n').flatMap(line => {
      const match = line.trim().match(/^(\d+)\s+(.+)$/);
      return match && match[2].startsWith(`${app}/Contents/`) ? [Number(match[1])] : [];
    });
  };
  for (const pid of await owned()) { try { process.kill(pid, 'SIGTERM'); } catch {} }
  for (let attempt = 0; attempt < 15; attempt++) {
    if ((await owned()).length === 0) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  for (const pid of await owned()) { try { process.kill(pid, 'SIGKILL'); } catch {} }
}
async function boundedOwnedClose(name, action) {
  console.log(JSON.stringify({nativeUpdateStage: name, status: 'begin'}));
  let timer;
  try {
    const result = await Promise.race([Promise.resolve().then(action), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Owned QA shutdown stage timed out: ${name}`)), 5000);
    })]);
    console.log(JSON.stringify({nativeUpdateStage: name, status: 'complete'}));
    return result;
  } finally { clearTimeout(timer); }
}
async function closeOwnedNativeBrowser() {
  assert(browser && child?.pid, 'Only the attached, owned QA browser may be shut down.');
  const attached = browser;
  // browser.close() on a CDP attachment can only disconnect. Explicitly request
  // native shutdown, then observe the launcher/engine process exit before any
  // NetLog read. A transport error is acceptable only if that exit is observed.
  try {
    const session = await boundedOwnedClose('create-owned-close-session', () => attached.newBrowserCDPSession());
    await boundedOwnedClose('request-owned-browser-exit', () => session.send('Browser.close'));
  } catch { /* Native shutdown can close CDP before its response arrives. */ }
  const deadline = Date.now() + 15000;
  while (child.exitCode === null && child.signalCode === null && Date.now() < deadline)
    await new Promise(resolve => setTimeout(resolve, 100));
  const exited = child.exitCode !== null || child.signalCode !== null;
  await boundedOwnedClose('disconnect-owned-browser', () => attached.close()).catch(() => {});
  browser = undefined; context = undefined; optionsPage = undefined; appearancePage = undefined;
  assert(exited, 'The owned native QA process must exit before NetLog verification.');
}
function cleanup() {
  return cleanupPromise ??= (async () => {
    input?.close();
    if (browser) await closeOwnedNativeBrowser().catch(() => {});
    if (browser) await boundedOwnedClose('disconnect-owned-browser-fallback', () => browser.close()).catch(() => {});
    await stopOwnedProcesses();
    await rm(runtime, {recursive: true, force: true});
  })();
}
for (const signal of ['SIGINT', 'SIGTERM'])
  process.once(signal, () => { void cleanup().finally(() => process.exit(130)); });

async function readJSONIfPresent(file) {
  try { return JSON.parse(await readFile(file, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return undefined; throw error; }
}
async function installedVersions() {
  const base = path.join(profile, 'Default/Extensions', extensionId);
  let versions;
  try { versions = await readdir(base, {withFileTypes: true}); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  return Promise.all(versions.filter(entry => entry.isDirectory()).map(async entry => {
    const directory = path.join(base, entry.name);
    return {directory, manifest: JSON.parse(await readFile(path.join(directory, 'manifest.json'), 'utf8'))};
  }));
}
function publicKeyMatchesId(key) {
  if (typeof key !== 'string' || key.length === 0) return false;
  const digest = createHash('sha256').update(Buffer.from(key, 'base64')).digest('hex').slice(0, 32);
  return [...digest].map(character => String.fromCharCode(97 + parseInt(character, 16))).join('') === extensionId;
}
function extensionPath(directory, relative) {
  assert.equal(typeof relative, 'string', 'The extension must declare a local resource path.');
  const result = path.resolve(directory, relative.replace(/^\/+/, ''));
  assert(result.startsWith(`${directory}${path.sep}`), 'Extension resource must stay inside its installed directory.');
  return result;
}
async function attachAfterInstall() {
  if (browser) return;
  const activePort = await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8');
  const port = Number(activePort.split('\n')[0]);
  assert(Number.isInteger(port) && port > 0 && port < 65536, 'QA loopback debugging port is missing.');
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, {timeout: 10000});
  context = browser.contexts()[0];
  assert(context, 'QA browser context is missing.');
  context.setDefaultTimeout(10000);
  context.setDefaultNavigationTimeout(15000);
  const ownsWorker = worker => worker.url().startsWith(`chrome-extension://${extensionId}/`);
  observedWorker ||= context.serviceWorkers().some(ownsWorker);
  context.on('serviceworker', worker => { observedWorker ||= ownsWorker(worker); });
}
async function themeStatus(installed) {
  const prefs = await readJSONIfPresent(path.join(profile, 'Default/Preferences'));
  const securePrefs = await readJSONIfPresent(path.join(profile, 'Default/Secure Preferences'));
  const saved = securePrefs?.extensions?.settings?.[extensionId] ?? prefs?.extensions?.settings?.[extensionId];
  const current = installed.find(entry => entry.manifest.version === saved?.manifest?.version) ?? installed[0];
  const manifest = current.manifest;
  assert(manifest.theme && typeof manifest.theme === 'object' && Object.keys(manifest.theme).length > 0,
    'The fixture must be an installed, nonempty Chromium theme.');
  const noPermissions = ['permissions', 'host_permissions', 'optional_permissions', 'optional_host_permissions']
    .every(key => manifest[key] === undefined || (Array.isArray(manifest[key]) && manifest[key].length === 0));
  assert(noPermissions && !manifest.background && !(manifest.content_scripts?.length),
    'The official theme fixture must declare no extension permissions or executable content.');
  // Close the already user-visited Store tab before testing the installed-theme
  // link. Only this one owned QA context is affected.
  for (const page of context.pages()) {
    if (page.url().startsWith('https://chromewebstore.google.com/')) await page.close();
  }
  if (!appearancePage || appearancePage.isClosed()) {
    appearancePage = await context.newPage();
    await appearancePage.goto('chrome://settings/appearance', {waitUntil: 'domcontentloaded'});
  }
  const appearance = appearancePage.locator('settings-appearance-page');
  await appearance.waitFor({state: 'attached', timeout: 15000});
  let native;
  const deadline = Date.now() + 15000;
  do {
    native = await appearance.evaluate(element => ({id: element.themeIdPref_?.value,
      name: element.themeSublabel_, forced: element.isForcedTheme_}));
    if (native.id === extensionId && typeof native.name === 'string' && native.name.trim()) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  } while (Date.now() < deadline);
  assert.equal(native.id, extensionId, 'Native Appearance must identify the actual installed theme.');
  assert(typeof native.name === 'string' && native.name.trim(), 'Native Appearance must resolve the installed theme name.');
  assert.equal(native.forced, false, 'The owned fixture must use an ordinary, non-forced theme.');
  const openTheme = appearance.locator('#openTheme');
  await openTheme.waitFor({state: 'visible'});
  await openTheme.getByText(native.name, {exact: true}).waitFor({state: 'visible'});
  // #openTheme is a cr-link-row whose real native click handler navigates; it
  // has no href. Intercept the navigation request, including a new popup's
  // first request, at the context before issuing the user click.
  const expected = `https://chromewebstore.google.com/detail/${extensionId}`;
  const existingPages = new Set(context.pages());
  const httpRequest = url => ['http:', 'https:'].includes(url.protocol);
  let timer, resolveRequest, rejectRequest;
  const requestedURL = new Promise((resolve, reject) => {
    resolveRequest = resolve; rejectRequest = reject;
  });
  const intercept = async route => {
    if (!route.request().isNavigationRequest()) { await route.abort(); return; }
    const url = route.request().url();
    try {
      await route.abort('blockedbyclient');
      resolveRequest(url);
    } catch (error) { rejectRequest(error); }
  };
  let target;
  await context.route(httpRequest, intercept);
  try {
    timer = setTimeout(() => rejectRequest(new Error('The native theme click did not issue an intercepted navigation.')), 15000);
    [, target] = await Promise.all([openTheme.click(), requestedURL]);
    assert.equal(target, expected, 'The actual native theme click must request the modern installed-theme Store URL.');
  } finally {
    clearTimeout(timer); await context.unroute(httpRequest, intercept);
  }
  for (const page of context.pages()) {
    if (!existingPages.has(page)) await page.close();
  }
  await appearancePage.bringToFront();
  const packed = saved?.location === 1;
  const keyMatchesStoreId = publicKeyMatchesId(manifest.key);
  return {fixture: fixtureName, installed: true, extensionId, version: manifest.version,
    manifestVersion: manifest.manifest_version, actualPackedTheme: true,
    normalPackedInstall: packed, keyMatchesStoreId, noExtensionPermissions: noPermissions,
    nativeAppearanceInstalledTheme: true, nativeThemeNameRendered: true,
    nativeThemeStoreClickTarget: target, nativeThemeStoreNavigationAbortedLocally: true,
    cdpAttachedAfterInstallation: true, signatureVerification: 'Chromium native CRX installer',
    pass: packed && keyMatchesStoreId && noPermissions};
}
async function status() {
  const installed = await installedVersions();
  if (installed.length === 0) return {installed: false, pass: false, cdpAttached: false};
  // Native CRX installation has completed before automation attaches. CDP's
  // download handling is therefore never involved in downloading/installing it.
  await attachAfterInstall();
  if (themeFixture) return themeStatus(installed);
  const declared = installed[0].manifest;
  assert.equal(declared.manifest_version, 3, 'The fixture must be an ordinary MV3 extension.');
  assert(!declared.theme, 'A theme is not sufficient for this extension check.');
  assert(declared.background?.service_worker, 'An MV3 service worker must be declared.');
  const localOptions = declared.options_ui?.page ?? declared.options_page;
  extensionPath(installed[0].directory, localOptions);
  const optionsURL = new URL(localOptions, `chrome-extension://${extensionId}/`).href;
  assert(optionsURL.startsWith(`chrome-extension://${extensionId}/`), 'Only this extension\'s local options page may open.');
  if (!optionsPage || optionsPage.isClosed()) {
    optionsPage = context.pages().find(page => page.url() === optionsURL) ?? await context.newPage();
    await optionsPage.goto(optionsURL, {waitUntil: 'load', timeout: 15000});
  }
  const live = await optionsPage.evaluate(async () => {
    const manifest = chrome.runtime.getManifest();
    return {id: chrome.runtime.id, version: manifest.version, manifestVersion: manifest.manifest_version,
      worker: manifest.background?.service_worker,
      enabledRulesets: await chrome.declarativeNetRequest.getEnabledRulesets(),
      availableStaticRuleCount: await chrome.declarativeNetRequest.getAvailableStaticRuleCount()};
  });
  // The extension's own options page wakes its worker. A stopped worker is
  // normal during filtering, so remember an actual observed worker event.
  for (let attempt = 0; attempt < 15 && !observedWorker; attempt++) {
    observedWorker ||= context.serviceWorkers().some(worker => worker.url().startsWith(`chrome-extension://${extensionId}/`));
    if (!observedWorker) await new Promise(resolve => setTimeout(resolve, 100));
  }
  const current = installed.find(entry => entry.manifest.version === live.version);
  assert(current, 'The executing extension must match an installed package version.');
  const resources = current.manifest.declarative_net_request?.rule_resources ?? [];
  let packagedRuleCount = 0;
  for (const id of live.enabledRulesets) {
    const resource = resources.find(item => item.id === id);
    assert(resource, 'Every enabled ruleset must belong to this installed manifest.');
    const rules = JSON.parse(await readFile(extensionPath(current.directory, resource.path), 'utf8'));
    assert(Array.isArray(rules), 'A packaged DNR ruleset must contain an array.');
    packagedRuleCount += rules.length;
  }
  const prefs = await readJSONIfPresent(path.join(profile, 'Default/Preferences'));
  const securePrefs = await readJSONIfPresent(path.join(profile, 'Default/Secure Preferences'));
  const saved = securePrefs?.extensions?.settings?.[extensionId] ?? prefs?.extensions?.settings?.[extensionId];
  // ManifestLocation::kInternal == 1: a packed CRX installed by the user, unlike
  // kUnpacked == 4 or kCommandLine == 8. Read only this generated QA profile.
  const normalPackedInstall = saved?.location === 1;
  const keyMatchesStoreId = publicKeyMatchesId(current.manifest.key);
  const APIsReady = live.id === extensionId && live.manifestVersion === 3 &&
    typeof live.worker === 'string' && Number.isInteger(live.availableStaticRuleCount);
  const rulesReady = live.enabledRulesets.length > 0 && packagedRuleCount > 0;
  return {installed: true, extensionId, version: live.version, manifestVersion: live.manifestVersion,
    normalPackedInstall, keyMatchesStoreId, extensionAPIsReady: APIsReady,
    serviceWorkerObserved: observedWorker, enabledRulesetCount: live.enabledRulesets.length,
    packagedRuleCount, cdpAttachedAfterInstallation: true,
    signatureVerification: 'Chromium native CRX installer', updateURL: current.manifest.update_url,
    pass: normalPackedInstall && keyMatchesStoreId && APIsReady && observedWorker && rulesReady};
}

try {
  const signingConfig = JSON.parse(await readFile(path.join(root, 'config/apple-signing.json'), 'utf8'));
  // Public certificate/identity lookup only. codesign uses the selected key in
  // place; no private key material is read or exported by this harness.
  const selected = await execFile('python3', ['-c',
    'import json,runpy,sys; print(json.dumps(runpy.run_path(sys.argv[1])["development_identity"]()))',
    path.join(root, 'scripts/package.py')]);
  const [identity, team] = JSON.parse(selected.stdout);
  assert.equal(team, signingConfig.teamId, 'QA must use the configured development team.');
  assert.match(identity, /^[A-F0-9]{40}$/, 'The selected development certificate identity is missing.');
  await execFile('codesign', ['--verify', '--deep', '--strict', original]);
  const originalPolicy = await signingPolicy(original);
  const originalEnginePolicy = await signingPolicy(path.join(original, 'Contents/MacOS/Chromium'));
  assert.equal(originalPolicy.team, team, 'The original app must use the configured development team.');
  assert.equal(originalEnginePolicy.team, team, 'The original browser engine must use the configured development team.');
  assert(originalPolicy.options & 0x10000, 'The original app must enable the hardened runtime.');
  assert(originalEnginePolicy.options & 0x10000, 'The original browser engine must enable the hardened runtime.');
  const originalNested = await nestedSignatures(original, team);
  const sourceExecutable = (await execFile('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleExecutable',
    path.join(original, 'Contents/Info.plist')])).stdout.trim();
  assert(sourceExecutable && path.basename(sourceExecutable) === sourceExecutable && !['.', '..'].includes(sourceExecutable),
    'The original app must declare a local executable basename.');
  await execFile('ditto', ['--norsrc', '--noextattr', original, app]);
  await cp(path.join(original, 'Contents/Resources/KumoExtension'), bundledExtension, {recursive: true});
  const plist = path.join(app, 'Contents/Info.plist');
  for (const [key, value] of Object.entries({CFBundleExecutable: 'KumoExtensionQA',
    CFBundleIdentifier: bundleId, CFBundleName: displayName, CFBundleDisplayName: displayName}))
    await execFile('/usr/libexec/PlistBuddy', ['-c', `Set :${key} ${value}`, plist]);
  // A copied, superseded wrapper keeps a signature bound to the original
  // Info.plist. Remove that unused QA-copy executable rather than retaining an
  // invalid nested signature after the app identity changes. The real engine
  // remains and is re-signed below; the original application is never changed.
  const supersededLauncherRemoved = !['Chromium', 'KumoExtensionQA'].includes(sourceExecutable);
  if (supersededLauncherRemoved) await rm(path.join(app, 'Contents/MacOS', sourceExecutable));
  const swift = path.join(runtime, 'launcher.swift');
  const literal = value => `String(data: Data(base64Encoded: "${Buffer.from(value).toString('base64')}")!, encoding: .utf8)!`;
  await writeFile(swift, `import Darwin\nimport Foundation
let engine = ${literal(engine)}
let profile = ${literal(profile)}
let bundledExtension = ${literal(bundledExtension)}
let netLog = ${literal(netLogPath || '')}
var forwarded: [String] = []
var skip = false
for argument in CommandLine.arguments.dropFirst() {
    if skip { skip = false; continue }
    if argument == "--" { break }
    if argument == "--user-data-dir" || argument == "--profile-directory" { skip = true; continue }
    if argument.hasPrefix("--user-data-dir=") || argument.hasPrefix("--profile-directory=") || argument.hasPrefix("-psn_") { continue }
    forwarded.append(argument)
}
let forced = ["--user-data-dir=\\(profile)", "--profile-directory=Default", "--no-first-run", "--no-default-browser-check", "--disable-sync", "--password-store=basic", "--use-mock-keychain", "--load-extension=\\(bundledExtension)", "--extension-mime-request-handling=always-prompt-for-install", "--remote-debugging-port=0", "--remote-debugging-address=127.0.0.1"]
let capture: [String] = ${updateCheck ? '["--log-net-log=\\(netLog)", "--net-log-capture-mode=Default"]' : '[]'}
let args = [engine] + forwarded + forced + capture
let pointers = args.map { strdup($0) } + [nil]
let result = pointers.withUnsafeBufferPointer { execv(engine, $0.baseAddress!) }
fputs("QA browser launch failed.\\n", stderr)
exit(result == -1 ? 1 : result)
`, {mode: 0o600});
  await execFile('swiftc', ['-O', '-target', 'arm64-apple-macos13.0', swift, '-o', launcher]);
  const entitlements = path.join(runtime, 'entitlements.plist');
  const engineEntitlements = path.join(runtime, 'engine-entitlements.plist');
  const originalEntitlements = await execFile('codesign', ['-d', '--entitlements', ':-', original]);
  const originalEngineEntitlements = await execFile('codesign', ['-d', '--entitlements', ':-', path.join(original, 'Contents/MacOS/Chromium')]);
  await writeFile(entitlements, originalEntitlements.stdout, {mode: 0o600});
  await writeFile(engineEntitlements, originalEngineEntitlements.stdout, {mode: 0o600});
  for (const [target, policy, originalEntitlementsFile] of [[engine, originalEnginePolicy, engineEntitlements], [launcher, originalPolicy, entitlements], [app, originalPolicy, entitlements]]) {
    await execFile('codesign', ['--force', '--sign', identity, '--timestamp=none', '--options', String(policy.options), '--identifier', bundleId, '--entitlements', originalEntitlementsFile, target]);
    const signed = await signingPolicy(target);
    assert.equal(signed.options, policy.options, 'QA signing must preserve the original runtime policy flags.');
    assert.equal(signed.identifier, bundleId, 'Both QA main executables and the outer bundle must use the unique QA identifier.');
    assert.equal(signed.team, team, 'QA code must use the same configured development team as retained nested code.');
    const actualEntitlements = await execFile('codesign', ['-d', '--entitlements', ':-', target]);
    const actualFile = path.join(runtime, 'verified-entitlements.plist');
    await writeFile(actualFile, actualEntitlements.stdout, {mode: 0o600});
    const toJSON = async file => JSON.parse((await execFile('plutil', ['-convert', 'json', '-o', '-', file])).stdout);
    assert.deepEqual(await toJSON(actualFile), await toJSON(originalEntitlementsFile), 'QA signing must preserve the corresponding original entitlements.');
  }
  await execFile('codesign', ['--verify', '--deep', '--strict', app]);
  const copiedNested = await nestedSignatures(app, team);
  assert.deepEqual(copiedNested, originalNested, 'QA must retain the original nested code signatures and policies.');
  const codeSigningPolicy = {teamId: team, outerOptions: originalPolicy.options,
    engineOptions: originalEnginePolicy.options, allResignedIdentifiers: bundleId,
    entitlementsPreserved: true, retainedNestedSignatures: copiedNested.size,
    supersededLauncherRemoved};
  await mkdir(path.join(profile, 'Default'), {recursive: true, mode: 0o700});
  await writeFile(path.join(profile, 'Default/Preferences'), JSON.stringify({
    signin: {allowed: false}, credentials_enable_service: false,
    profile: {password_manager_enabled: false}, browser: {check_default_browser: false},
    download: {default_directory: path.join(runtime, 'downloads'), prompt_for_download: false}
  }), {mode: 0o600});
  await writeFile(statePath, JSON.stringify({app, bundleId, profile, fixture: fixtureName, extensionId, storeURL, netLogPath, updateCheck,
    codeSigningPolicy,
    officialProject: officialFixture,
    warning: 'CUA must use this generated app path. No accounts/imports or original browser.'}, null, 2), {mode: 0o600});
  if (prepareOnly) {
    console.log(JSON.stringify({setupVerified: true, fixture: fixtureName, browserLaunched: false, sourceCompiledLocally: buildInfo.sourceCompiledLocally,
      codeSigningPolicy,
      defaultNetLogConfigured: updateCheck, storeInstallationVerified: false,
      nativeThemeAppearanceVerified: false, cwsUpdateCheckVerified: false, updateInstallationVerified: false}));
  } else {
  child = spawn(launcher, [storeURL], {stdio: 'ignore'});
  await new Promise((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
  console.log(JSON.stringify({ready: true, fixture: fixtureName, pid: child.pid, app, bundleId, statePath, storeURL, extensionId, updateCheck,
    instructions: `CUA: Install in Kumo, then native Add ${themeFixture ? 'theme' : 'extension'}. Afterwards: status, check installed, ${updateCheck ? 'check updates, ' : ''}finish. close aborts.`}));
  input = createInterface({input: process.stdin, crlfDelay: Infinity});
  for await (const line of input) {
    const command = line.trim();
    if (!command) continue;
    try {
      if (command === 'status') console.log(JSON.stringify(await status()));
      else if (command === 'check installed') {
        const result = await status();
        assert.equal(result.pass, true, themeFixture ?
          'Theme/native Appearance checks are incomplete; inspect status and retry after installation/preferences settle.' :
          'Extension API/package checks are incomplete; inspect status and retry after installation/preferences settle.');
        checked = true;
        console.log(JSON.stringify({...result, nativeInstallConsentConfirmedByOperator: true}));
      } else if (command === 'check updates') {
        assert(updateCheck, 'Start the harness with --update-check and the patched source app.');
        assert(checked, 'Complete check installed after observing native consent first.');
        assert(!updateAttemptFailed, 'An earlier update attempt failed; close and start a fresh QA run.');
        assert(updateRequests.length < 2, 'This fixture requires exactly two successful native update checks.');
        const result = await status();
        assert.equal(result.pass, true, 'The packed Store fixture must still pass.');
        const expectedHelperState = updateRequests.length === 0 ? 'ENABLED' : 'DISABLED';
        let request;
        try {
          request = await requestNativeUpdateCheck({context, extensionId, version: result.version,
            updateURL: result.updateURL, profile, bundledExtensionPath: bundledExtension, expectedHelperState});
        } catch (error) { updateAttemptFailed = true; throw error; }
        updateRequests.push(request);
        console.log(JSON.stringify({...request, updateCheckNumber: updateRequests.length, pendingNetLogVerification: true,
          instructions: updateRequests.length === 1 ?
            'CUA: turn only Kumo off using its real native Extensions switch, keep uBO Lite enabled, then send check updates again.' :
            'Run finish to close the owned browser and verify both finalized NetLog windows.'}));
      } else if (command === 'finish') {
        assert(checked, 'Complete check installed after observing native consent.');
        const result = await status();
        assert.equal(result.pass, true, 'The installed extension must still pass.');
        let updateEvidence;
        if (updateCheck) {
          assert(!updateAttemptFailed, 'An earlier update attempt failed; this run cannot pass.');
          assert.equal(updateRequests.length, 2, 'Complete native Update with Kumo enabled, then manually disabled, before finish.');
          assert.equal(updateRequests[0].helperBefore.nativeState, 'ENABLED');
          assert.equal(updateRequests[1].helperBefore.nativeState, 'DISABLED');
          assert(updateRequests[0].beforeUnixMs <= updateRequests[1].afterUnixMs, 'Native update verification windows must not overlap.');
          await closeOwnedNativeBrowser();
          const checks = [];
          for (const request of updateRequests) checks.push(await verifyNativeUpdateLog(netLogPath, request, result.version));
          updateEvidence = {checks, enabledThenDisabledHelperChecksVerified: true,
            bundledHelperLocationAndStatePreservedForBothChecks: true,
            ownedNativeProcessExitedBeforeNetLogRead: true};
        }
        finished = true; console.log(JSON.stringify({pass: true, fixture: fixtureName,
          ordinaryMV3StoreExtension: !themeFixture, ordinaryPackedStoreTheme: themeFixture, updateEvidence})); break;
      } else if (command === 'close') break;
      else throw new Error('Unknown command; use status, check installed, check updates, finish, or close.');
    } catch (error) {
      console.error(`QA command failed: ${error.message}`);
      if (updateRequests.length > 0 && !browser) { process.exitCode = 1; break; }
    }
  }
  if (!finished) { process.exitCode = 1; console.log(JSON.stringify({pass: false, aborted: true})); }
  }
} finally {
  await cleanup();
}
