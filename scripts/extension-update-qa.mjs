import assert from 'node:assert/strict';
import {readFile, realpath} from 'node:fs/promises';
import path from 'node:path';
import {verifyAnonymousCwsCheck} from './extension-update-netlog.mjs';

const UPDATE_URL = 'https://clients2.google.com/service/update2/crx';
const HELPER_ID = 'eldkgppmnhligdekahicdcdndcoongio';
const COOKIE_NAME = 'kumo_update_qa_synthetic';
const COOKIE_VALUE = 'synthetic-not-an-authentication-token';

async function step(name, action, milliseconds = 10000) {
  console.log(JSON.stringify({nativeUpdateStage: name, status: 'begin'}));
  let timer;
  try {
    const result = await Promise.race([Promise.resolve().then(action), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Native update QA stage timed out: ${name}`)), milliseconds);
    })]);
    console.log(JSON.stringify({nativeUpdateStage: name, status: 'complete'}));
    return result;
  } finally { clearTimeout(timer); }
}
async function readJSONIfPresent(file) {
  try { return JSON.parse(await readFile(file, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return undefined; throw error; }
}
async function bundledHelperState(page, profile, bundledExtensionPath, expectedState) {
  assert(path.isAbsolute(profile) && path.isAbsolute(bundledExtensionPath), 'Use the signed QA harness\'s absolute owned profile/helper paths.');
  assert(['ENABLED', 'DISABLED'].includes(expectedState), 'An explicit expected native helper state is required.');
  const expectedPath = await realpath(bundledExtensionPath);
  const deadline = Date.now() + 14000;
  let last;
  do {
    // Read only this browser-bundled helper through the native internal WebUI
    // API. No configuration mutation or direct update invocation is performed.
    const native = await page.evaluate(async id => {
      const info = await chrome.developerPrivate.getExtensionInfo(id);
      return {id: info.id, state: info.state, location: info.location, path: info.path};
    }, HELPER_ID);
    const prefs = await readJSONIfPresent(path.join(profile, 'Default/Preferences'));
    const secure = await readJSONIfPresent(path.join(profile, 'Default/Secure Preferences'));
    const saved = secure?.extensions?.settings?.[HELPER_ID] ?? prefs?.extensions?.settings?.[HELPER_ID];
    const reasons = saved?.disable_reasons ?? [];
    const validReasons = Array.isArray(reasons) && reasons.every(value => Number.isInteger(value) && value > 0);
    let nativePath, savedPath;
    if (typeof native.path === 'string' && path.isAbsolute(native.path)) nativePath = await realpath(native.path);
    if (typeof saved?.path === 'string' && path.isAbsolute(saved.path)) savedPath = await realpath(saved.path);
    last = {id: native.id, nativeState: native.state, nativeLocation: native.location,
      nativePath: native.path, savedPath: saved?.path, canonicalPath: savedPath,
      manifestLocation: saved?.location,
      disableReasons: validReasons ? [...reasons].sort((a, b) => a - b) : null};
    const stateAgrees = expectedState === 'ENABLED' ? validReasons && reasons.length === 0 :
      validReasons && reasons.length === 1 && reasons[0] === 1; // DISABLE_USER_ACTION.
    if (native.id === HELPER_ID && native.state === expectedState && native.location === 'UNPACKED' &&
        saved?.location === 8 && nativePath === expectedPath && savedPath === expectedPath && stateAgrees) return last;
    await new Promise(resolve => setTimeout(resolve, 100));
  } while (Date.now() < deadline);
  assert.equal(last?.manifestLocation, 8, 'Bundled helper must retain native kCommandLine location 8.');
  assert.equal(last?.nativeState, expectedState, 'Use the real native Extensions switch to select the required helper state.');
  assert.equal(last?.canonicalPath, expectedPath, 'Saved helper path must identify the signed QA bundle.');
  throw new Error('Native and saved helper state/path did not settle consistently.');
}

// Called only after an ordinary packed Store install was confirmed. Explicit
// paths come from the separately signed QA harness, never a personal profile.
export async function requestNativeUpdateCheck({context, extensionId, version, updateURL,
  profile, bundledExtensionPath, expectedHelperState}) {
  assert.equal(extensionId, 'ddkjiahejlhfcafbddmgiahcphecmpfh', 'Use only the pinned official uBO Lite update fixture.');
  assert.equal(updateURL, UPDATE_URL, 'The packed fixture must declare the exact approved Store update endpoint.');
  for (const page of context.pages()) {
    if (page.url().startsWith('https://chromewebstore.google.com/'))
      await step('close-owned-store-tab', () => page.close());
  }
  const versionPage = await step('open-version-page', () => context.newPage());
  await step('load-version-page', () => versionPage.goto('chrome://version', {waitUntil: 'domcontentloaded', timeout: 15000}), 15000);
  const commandLine = await step('read-version-flags', () => versionPage.locator('#command_line').textContent());
  assert(!commandLine.includes('--disable-background-networking'), 'Background-network suppression would invalidate native update QA.');
  await step('close-version-page', () => versionPage.close());

  // A synthetic domain cookie tests omission at the actual manifest host.
  await step('clear-owned-cookies', () => context.clearCookies());
  await step('add-synthetic-cookie', () => context.addCookies([{name: COOKIE_NAME, value: COOKIE_VALUE,
    domain: '.google.com', path: '/', secure: true, httpOnly: true, sameSite: 'None',
    expires: Math.floor(Date.now() / 1000) + 3600}]));
  const applicable = await step('verify-synthetic-cookie-scope', () => context.cookies(UPDATE_URL));
  assert(applicable.some(cookie => cookie.name === COOKIE_NAME && cookie.value === COOKIE_VALUE), 'Synthetic cookie must be applicable to the actual manifest host.');

  const page = await step('open-extensions-page', () => context.newPage());
  await step('load-extensions-page', () => page.goto('chrome://extensions', {waitUntil: 'domcontentloaded', timeout: 15000}), 15000);
  const toolbar = page.locator('extensions-toolbar');
  const toggle = toolbar.locator('#devMode');
  if (!await step('read-developer-mode', () => toggle.evaluate(element => element.checked)))
    await step('enable-developer-mode', () => toggle.click({timeout: 10000}));
  const updateButton = toolbar.locator('#updateNow');
  await step('find-native-update-button', () => updateButton.waitFor({timeout: 10000}));
  const helperBefore = await step('helper-before-update',
    () => bundledHelperState(page, profile, bundledExtensionPath, expectedHelperState), 15000);
  const afterUnixMs = Date.now();
  await step('click-native-update-button', () => updateButton.click({timeout: 10000}));
  // Strict completion still belongs to the real native toolbar. Timer polling
  // works when another QA window covers the page; no lifecycle state is forced.
  await step('wait-native-update-completion', () => page.waitForFunction(() => {
    const toolbar = document.querySelector('extensions-manager')?.shadowRoot?.querySelector('extensions-toolbar');
    return toolbar && toolbar.isUpdating_ === false;
  }, undefined, {timeout: 60000, polling: 100}), 60000);
  const beforeUnixMs = Date.now();
  assert(beforeUnixMs > afterUnixMs, 'The native update interval must be nonempty.');
  const helperAfter = await step('helper-after-update',
    () => bundledHelperState(page, profile, bundledExtensionPath, expectedHelperState), 15000);
  assert.deepEqual(helperAfter, helperBefore, 'Native Update changed the bundled helper\'s location/path or exact enabled/disabled state.');
  await step('close-extensions-page', () => page.close());
  return {extensionId, version, afterUnixMs, beforeUnixMs, nativeUpdateButtonClicked: true,
    nativeUpdateToolbarCompleted: true, helperBefore, helperAfter,
    bundledHelperStateAndCommandLineLocationPreserved: true,
    syntheticCookieApplicableToManifestHost: true, syntheticCookieDomain: '.google.com',
    netLogCaptureMode: 'Default', backgroundNetworkingSuppressionAbsent: true};
}

export async function verifyNativeUpdateLog(netLogPath, state, installedVersionAfter) {
  // The caller observes native process exit before any complete-JSON read.
  const deadline = Date.now() + 15000;
  let log;
  let lastError;
  while (Date.now() < deadline) {
    try { log = JSON.parse(await readFile(netLogPath, 'utf8')); break; }
    catch (error) {
      if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;
      lastError = error;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  assert(log, `The closed QA browser did not flush a complete NetLog: ${lastError?.name || 'unavailable'}`);
  const result = verifyAnonymousCwsCheck(log, state);
  return {...state, ...result, installedVersionBefore: state.version, installedVersionAfter,
    installedVersionChanged: installedVersionAfter !== state.version,
    note: 'Each manual native update is verified only within its own request-start window. A no-update/unchanged result does not verify automatic scheduling, an update install, or publisher-proof validation of an update CRX.'};
}
