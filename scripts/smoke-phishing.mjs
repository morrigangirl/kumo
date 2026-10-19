// Actual Chromium → isolated content script → Native Messaging → Core ML QA.
// Uses owned synthetic pages, a disposable profile and the normal Chromium sandbox.
// The copied QA manifest pregrants website access to exercise the real enable button
// headlessly. Page requests are restricted to the owned loopback fixture server.
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, writeFile, cp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createServer} from 'node:http';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = path.resolve(process.env.KUMO_QA_APP || path.join(root, 'dist/Kumo.app'));
const resources = path.join(app, 'Contents/Resources');
const host = path.join(app, 'Contents/Helpers/KumoPhishing.app/Contents/MacOS/KumoPhishingHost');
const eid = (await readFile(path.join(root, 'config/extension-id.txt'), 'utf8')).trim();
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-phishing-qa-'));
const profile = path.join(temporary, 'profile'), extension = path.join(temporary, 'extension');
const artifacts = path.resolve(process.env.KUMO_PHISHING_QA_ARTIFACTS || path.join(root, '.cache/qa/phishlang-port-2026-10-19', `runtime-${Date.now()}`));
await mkdir(artifacts, {recursive: true});
const netlog = path.join(artifacts, 'netlog.json');
const checks = [], errors = [], externalRequests = [];
let context, worker, origin, helperEvidence, result;

const fixture = createServer((request, response) => {
  response.setHeader('Content-Type', 'text/html; charset=utf-8');
  response.setHeader('Cache-Control', 'no-store');
  const route = new URL(request.url, 'http://fixture.invalid').pathname;
  if (route === '/privacy') {
    response.end(`<!doctype html><title>Example account sign in</title><h1>Example account sign in</h1>
      <form name="PRIVATE_FORM_NAME" action="/?token=PRIVATE_FORM_ACTION"><p>PRIVATE_FORM_TEXT</p>
      <input type="email" name="PRIVATE_EMAIL_NAME" placeholder="PRIVATE_EMAIL_PLACEHOLDER" value="PRIVATE_EMAIL_VALUE">
      <input type="password" value="PRIVATE_PASSWORD_VALUE"><input autocomplete="section-login ONE-TIME-CODE" value="PRIVATE_OTP_VALUE">
      <input type="checkbox" checked value="PRIVATE_CHECKBOX_VALUE"><button>PRIVATE_FORM_BUTTON</button></form>
      <textarea>PRIVATE_TEXTAREA_VALUE</textarea><select><option>PRIVATE_SELECT_VALUE</option></select>
      <p>Public page text <span contenteditable="true">PRIVATE_EDITABLE_VALUE</span><span hidden>PRIVATE_HIDDEN_VALUE</span></p>
      <script>const fixtureOnly='PRIVATE_SCRIPT_VALUE';</script>
      <a href="/account/PRIVATE_PATH_VALUE?token=PRIVATE_LINK_QUERY#PRIVATE_LINK_FRAGMENT">Account</a>`);
  } else if (route === '/suspicious') {
    response.end('<!doctype html><title>Account suspended</title><p>Urgent verify your account immediately to avoid closure.</p><a href="/verify">verify</a>');
  } else {
    response.end('<!doctype html><title>Public library hours</title><h1>Public library</h1><p>Our library opens Monday at nine. Read books and attend community events.</p>');
  }
});
const tick = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function eventually(operation, description, timeout = 20000) {
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    try { const value = await operation(); if (value) return value; } catch (error) { lastError = error; }
    await tick(75);
  }
  throw new Error(`${description}: ${lastError?.message || 'condition did not become true'}`);
}
const processRows = async () => (await promisify(execFile)('/bin/ps', ['-axo', 'pid=,ppid=,command='])).stdout.trim().split('\n')
  .map(line => { const match = line.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/); return match ? {pid: +match[1], ppid: +match[2], command: match[3]} : null; }).filter(Boolean);
async function ownedHelperSockets() {
  const rows = await processRows();
  const browser = rows.find(row => row.command.includes(profile) && row.command.includes('/Contents/MacOS/Chromium') && !row.command.includes('--type='));
  assert(browser, 'The owned Chromium process must be identifiable by its disposable profile');
  const helper = rows.find(row => row.ppid === browser.pid && row.command.includes(host));
  assert(helper, 'The actual packaged native host must be a child of the owned Chromium process');
  let sockets = '';
  try { sockets = (await promisify(execFile)('/usr/sbin/lsof', ['-nP', '-a', '-p', String(helper.pid), '-i'])).stdout; }
  catch (error) { if (error.code !== 1 || error.stdout) throw error; }
  assert.equal(sockets, '', 'The live local inference helper must have no Internet sockets');
  return {browserPid: browser.pid, helperPid: helper.pid, noInternetSocketsAtObservation: true};
}

try {
  await readFile(host);
  await cp(path.join(resources, 'KumoExtension'), extension, {recursive: true});
  const manifestPath = path.join(extension, 'manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  manifest.host_permissions = ['http://*/*', 'https://*/*'];
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
  const hosts = path.join(profile, 'NativeMessagingHosts');
  await mkdir(hosts, {recursive: true});
  await writeFile(path.join(hosts, 'com.kumo.phishing.json'), JSON.stringify({
    name: 'com.kumo.phishing', description: 'Kumo local phishing QA', path: host, type: 'stdio', allowed_origins: [`chrome-extension://${eid}/`],
  }, null, 2));
  await new Promise((resolve, reject) => { fixture.once('error', reject); fixture.listen(0, '127.0.0.1', resolve); });
  origin = `http://127.0.0.1:${fixture.address().port}`;
  console.log(JSON.stringify({qaPaths: {temporary, profile, extension, artifacts}, host, fixtureOrigin: origin}));
  context = await chromium.launchPersistentContext(profile, {
    executablePath: path.join(app, 'Contents/MacOS/Chromium'), headless: true, chromiumSandbox: true,
    timeout: 60000, ignoreDefaultArgs: ['--disable-extensions'], viewport: {width: 1280, height: 900},
    args: [`--load-extension=${extension}`, `--disable-extensions-except=${extension}`, '--no-first-run', '--disable-sync',
      '--use-mock-keychain', '--password-store=basic', `--log-net-log=${netlog}`],
  });
  context.setDefaultTimeout(15000);
  await context.route(/^https?:\/\//, route => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    externalRequests.push(route.request().url()); return route.abort();
  });
  context.on('page', page => page.on('pageerror', error => errors.push(error.message)));
  const target = await context.newPage(); await target.goto(`${origin}/benign`);
  const controls = await context.newPage(); await controls.goto(`chrome-extension://${eid}/newtab.html`);
  worker = context.serviceWorkers().find(item => item.url() === `chrome-extension://${eid}/background.js`) ||
    await context.waitForEvent('serviceworker', {predicate: item => item.url() === `chrome-extension://${eid}/background.js`});
  // Observe the actual native port without changing requests, replies or execution.
  await worker.evaluate(() => {
    globalThis.__kumoPhishingQATrace = {requests: [], replies: []};
    const connectNative = chrome.runtime.connectNative.bind(chrome.runtime);
    chrome.runtime.connectNative = name => {
      const port = connectNative(name);
      if (name === 'com.kumo.phishing') {
        const postMessage = port.postMessage.bind(port);
        port.postMessage = message => { globalThis.__kumoPhishingQATrace.requests.push(structuredClone(message)); return postMessage(message); };
        port.onMessage.addListener(message => globalThis.__kumoPhishingQATrace.replies.push(structuredClone(message)));
      }
      return port;
    };
  });
  const trace = () => worker.evaluate(() => structuredClone(globalThis.__kumoPhishingQATrace));
  const status = tabId => controls.evaluate(tabId => chrome.runtime.sendMessage({type: 'phishing.status', tabId}), tabId);
  const tabIdFor = url => controls.evaluate(async url => (await chrome.tabs.query({})).find(tab => tab.url === url)?.id, url);
  const currentStatus = async () => status(await tabIdFor(target.url()));
  const registrations = () => controls.evaluate(() => chrome.scripting.getRegisteredContentScripts());
  const installed = tabId => controls.evaluate(async tabId => (await chrome.scripting.executeScript({target: {tabId}, func: () => globalThis[Symbol.for('app.kumo.phishing-content.v1')] === true}))[0].result, tabId);
  assert.equal((await status()).enabled, false);
  assert.deepEqual(await registrations(), []);
  assert.equal((await trace()).requests.length, 0);
  checks.push('default off: no registered phishing script or native inference request');
  await controls.locator('#openSettings').click(); await controls.locator('[data-panel="privacy"]').click();
  await controls.locator('#enablePhishing').click();
  const enabled = await eventually(async () => { const state = await status(); return state.enabled && state.health === 'ready' ? state : false; }, 'Actual enable button must connect the packaged model');
  assert.match(await controls.locator('#phishingStatus').textContent(), /enabled/i);
  assert((await registrations()).some(script => script.id === 'kumo-local-phishing'));
  await target.bringToFront();
  const benign = await eventually(async () => { const state = await currentStatus(); return ['no-signal', 'partial'].includes(state.currentTab?.status) ? state : false; }, 'Actual library fixture must receive a model result');
  assert.equal(target.url(), `${origin}/benign`);
  const actualAgentState = await controls.evaluate(() => chrome.runtime.sendMessage({type: 'agent.status'}));
  assert.equal(actualAgentState.enabled, false); assert.deepEqual(actualAgentState.grants, []);
  checks.push('actual UI enable, registered top-frame content script, real Native Messaging/Core ML, benign fixture no warning, agent grants remain off');
  helperEvidence = await ownedHelperSockets();

  const privateURL = `${origin}/privacy?token=PRIVATE_DOCUMENT_QUERY#PRIVATE_DOCUMENT_FRAGMENT`;
  await target.goto(privateURL);
  await eventually(() => target.url().startsWith(`chrome-extension://${eid}/phishing-warning.html#`), 'Actual model must warn for synthetic login structure');
  await target.locator('#continueSite').waitFor({state: 'visible'});
  await eventually(async () => !await target.locator('#continueSite').isDisabled(), 'Warning ticket must bind to its actual tab');
  assert.equal(await target.locator('#warningOrigin').textContent(), origin);
  const privacyTrace = await trace();
  const privacyRequest = privacyTrace.requests.filter(request => request.type === 'classify').find(request => request.text.includes('INPUT:'));
  assert(privacyRequest, 'Real extracted control structure must reach the actual native model');
  assert.match(privacyRequest.text, /"type":"password"/);
  assert.doesNotMatch(privacyRequest.text, /PRIVATE_|DOCUMENT_QUERY|DOCUMENT_FRAGMENT/i);
  assert.equal(new TextEncoder().encode(privacyRequest.text).length <= 24576, true);
  for (const request of privacyTrace.requests) assert.deepEqual(Object.keys(request).sort(), request.type === 'classify' ? ['id', 'text', 'type'] : ['id', 'type']);
  const privacyReply = privacyTrace.replies.find(reply => reply.id === privacyRequest.id);
  assert(privacyReply?.probability >= 0.9, 'Actual model probability must meet the production threshold');
  await target.screenshot({path: path.join(artifacts, 'actual-warning.png')});
  await target.locator('#leaveSite').click();
  await eventually(() => target.url() === `chrome-extension://${eid}/newtab.html`, 'Actual leave button must return to Kumo');
  checks.push('actual login warning excludes private field/editable/script/link/document-query sentinels from native payload; trusted warning displays only origin; Leave works');

  const suspiciousURL = `${origin}/suspicious`;
  await target.goto(suspiciousURL);
  await eventually(() => target.url().startsWith(`chrome-extension://${eid}/phishing-warning.html#`), 'Actual urgent fixture must trigger warning');
  await eventually(async () => !await target.locator('#continueSite').isDisabled(), 'Actual Continue button must become available');
  await target.locator('#continueSite').click();
  await eventually(() => target.url() === suspiciousURL, 'Actual Continue must return to the exact site');
  await tick(2500); assert.equal(target.url(), suspiciousURL, 'The returned document must receive its one-time bypass');
  await target.reload();
  await eventually(() => target.url().startsWith(`chrome-extension://${eid}/phishing-warning.html#`), 'Reloading must not inherit the previous document bypass');
  checks.push('actual urgent-page warning, Continue works once for its returned document, same-URL reload warns again');

  await target.goto(`${origin}/benign`); await target.bringToFront();
  await eventually(async () => ['no-signal', 'partial'].includes((await currentStatus()).currentTab?.status), 'Owned article must be active before disable');
  const targetId = await tabIdFor(target.url()); assert.equal(await installed(targetId), true);
  await controls.bringToFront(); await controls.locator('#disablePhishing').click();
  await eventually(async () => !(await status()).enabled, 'Actual Turn off button must revoke protection');
  assert.deepEqual(await registrations(), []); assert.equal(await installed(targetId), false);
  const requestsBeforeOffNavigation = (await trace()).requests.length;
  await target.goto(suspiciousURL); await target.bringToFront(); await tick(2500);
  assert.equal(target.url(), suspiciousURL); assert.equal((await trace()).requests.length, requestsBeforeOffNavigation);
  checks.push('actual Turn off unregisters scripts, retires existing instances and prevents further local inference');
  await controls.bringToFront(); await controls.locator('#enablePhishing').click();
  await eventually(async () => (await status()).enabled, 'Actual enable must work again');
  await target.bringToFront();
  await eventually(() => target.url().startsWith(`chrome-extension://${eid}/phishing-warning.html#`), 'Re-enable must reinject into an already-open owned page');
  await controls.bringToFront(); await controls.locator('#disablePhishing').click();
  await eventually(async () => !(await status()).enabled, 'Final disable must finish');
  checks.push('actual re-enable reinjects cleanly and flags an already-open synthetic page');
  assert.deepEqual(errors, []); assert.deepEqual(externalRequests, []);
  const finalTrace = await trace();
  result = {passed: true, checks, sandbox: true, profile: 'disposable', accountAccess: false,
    qaManifestPregrantsWebsiteAccess: true, productionFilesModified: false,
    modelVersion: enabled.modelVersion, benignStatus: benign.currentTab, helperEvidence,
    nativeRequests: finalTrace.requests.map(request => ({id: request.id, type: request.type, fields: Object.keys(request).sort(),
      ...(request.type === 'classify' ? {textBytes: Buffer.byteLength(request.text), textSHA256: createHash('sha256').update(request.text).digest('hex'), privateSentinelPresent: /PRIVATE_/i.test(request.text)} : {})})),
    nativeReplies: finalTrace.replies, externalPageRequests: externalRequests,
    privacyProbability: privacyReply.probability,
    limits: ['Synthetic fixtures establish integration, not phishing accuracy or calibration.',
      'The no-sockets observation is a point-in-time check of the actual native helper.',
      'Permission prompts are pregranted only in the copied disposable QA manifest.']};
} finally {
  await context?.close();
  if (fixture.listening) await new Promise(resolve => fixture.close(resolve));
  const rows = await processRows();
  const ownedRemaining = rows.filter(row => row.command.includes(profile) || helperEvidence && row.pid === helperEvidence.helperPid && row.command.includes(host));
  await rm(temporary, {recursive: true, force: true});
  const cleanup = {temporaryRemoved: true, ownedRemaining, passed: ownedRemaining.length === 0};
  await writeFile(path.join(artifacts, 'cleanup.json'), JSON.stringify(cleanup, null, 2));
  if (result) {
    result.cleanup = cleanup;
    await writeFile(path.join(artifacts, 'results.json'), JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result, null, 2));
  }
  assert.equal(ownedRemaining.length, 0, 'All owned Chromium and native helper processes must exit');
}
