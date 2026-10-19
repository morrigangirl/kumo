// Real Chromium ↔ extension ↔ Native Messaging ↔ broker QA. All data is disposable.
// The copied test extension receives loopback-only host access; production is unchanged.
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, writeFile, cp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createServer} from 'node:http';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = path.join(root, 'dist/Kumo.app');
const resources = path.join(app, 'Contents/Resources');
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const {privateRuntime} = await import(path.join(resources, 'agent-bridge/lib/runtime.mjs'));
const {startBroker, connectBroker, requestBrowser} = await import(path.join(resources, 'agent-bridge/lib/broker.mjs'));
const eid = (await readFile(path.join(root, 'config/extension-id.txt'), 'utf8')).trim();
// Use the system temporary directory for Chromium and a separate short directory
// for the bridge, keeping its Unix socket path within the platform limit.
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-agent-qa-'));
const profile = path.join(temporary, 'profile');
const extension = path.join(temporary, 'extension');
const runtimeDirectory = await mkdtemp('/tmp/kumo-bridge-qa-');
const runtime = await privateRuntime(runtimeDirectory);
const errors = [];
const checks = [];
const sensitiveFields = [
  {id: 'password', type: 'password', value: 'PASSWORD_VALUE_PRIVATE', label: 'PASSWORD_LABEL_PRIVATE'},
  {id: 'otp', autocomplete: 'one-time-code', value: 'OTP_VALUE_PRIVATE', label: 'OTP_LABEL_PRIVATE'},
  {id: 'otp-section', autocomplete: 'section-login one-time-code', value: 'OTP_SECTION_VALUE_PRIVATE', label: 'OTP_SECTION_LABEL_PRIVATE'},
  {id: 'otp-case', autocomplete: 'ONE-TIME-CODE', value: 'OTP_CASE_VALUE_PRIVATE', label: 'OTP_CASE_LABEL_PRIVATE'},
  {id: 'otp-whitespace', autocomplete: 'section-login\t \nONE-TIME-CODE', value: 'OTP_WHITESPACE_VALUE_PRIVATE', label: 'OTP_WHITESPACE_LABEL_PRIVATE'},
  {id: 'card', autocomplete: 'cc-number', value: 'CARD_VALUE_PRIVATE', label: 'CARD_LABEL_PRIVATE'},
  {id: 'card-case', autocomplete: 'SECTION-CHECKOUT BILLING CC-NUMBER', value: 'CARD_CASE_VALUE_PRIVATE', label: 'CARD_CASE_LABEL_PRIVATE'},
  {id: 'password-token-case', autocomplete: 'SECTION-LOGIN CURRENT-PASSWORD', value: 'PASSWORD_TOKEN_VALUE_PRIVATE', label: 'PASSWORD_TOKEN_LABEL_PRIVATE'},
  {id: 'new-password-token-case', autocomplete: 'SECTION-SIGNUP NEW-PASSWORD', value: 'NEW_PASSWORD_TOKEN_VALUE_PRIVATE', label: 'NEW_PASSWORD_TOKEN_LABEL_PRIVATE'},
];
const escapeAttribute = value => value.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;');
const sensitiveInputs = sensitiveFields.map(field => `<input id="${field.id}" type="${field.type || 'text'}"${field.autocomplete ? ` autocomplete="${escapeAttribute(field.autocomplete)}"` : ''} value="${field.value}" aria-label="${field.label}" data-click-count="0" onclick="this.dataset.clickCount=String(Number(this.dataset.clickCount)+1)">`).join('\n');
let staleOriginEvidence;
let context;
let broker;
let connection;

const destination = createServer((_request, response) => {
  response.setHeader('Content-Type', 'text/html');
  response.end('<!doctype html><title>Other origin</title><h1>Destination fixture</h1>');
});
const fixture = createServer((request, response) => {
  if (request.url === '/redirect') {
    response.writeHead(302, {Location: `http://127.0.0.1:${destination.address().port}/destination`});
    response.end(); return;
  }
  response.setHeader('Content-Type', 'text/html');
  response.end(`<!doctype html><html><head><title>Kumo Agent QA fixture</title></head><body>
    <h1>Public fixture heading</h1><p id="result">Visible fixture text</p>
    <button id="click" type="button" onclick="document.getElementById('result').textContent='Button clicked'">Click fixture</button>
    <input id="normal" aria-label="Public text field" value="FORM_VALUE_PRIVATE" autocomplete="off">
    <textarea id="draft" aria-label="Public textarea">TEXTAREA_VALUE_PRIVATE</textarea>
    ${sensitiveInputs}
    <input id="hidden" type="hidden" value="HIDDEN_VALUE_PRIVATE">
    <input style="visibility:hidden" aria-label="INVISIBLE_CONTROL_PRIVATE">
    <div style="display:none">DISPLAY_NONE_PRIVATE</div><div style="visibility:hidden">VISIBILITY_HIDDEN_PRIVATE</div>
    <div style="opacity:0">OPACITY_ZERO_PRIVATE</div><div aria-hidden="true">ARIA_HIDDEN_PRIVATE</div>
    <div contenteditable="true">EDITABLE_CONTENT_PRIVATE</div>
    <a href="/next">Public link</a><a style="visibility:hidden" href="/private">HIDDEN_LINK_PRIVATE</a>
  </body></html>`);
});

const listen = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
const closeServer = server => new Promise(resolve => server.close(resolve));
async function eventually(operation, description) {
  const deadline = Date.now() + 10000;
  let lastError;
  while (Date.now() < deadline) {
    try { const result = await operation(); if (result) return result; }
    catch (error) { lastError = error; }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`${description}: ${lastError?.message || 'condition did not become true'}`);
}

try {
  await cp(process.env.KUMO_QA_EXTENSION_SOURCE || path.join(resources, 'KumoExtension'), extension, {recursive: true});
  const manifestPath = path.join(extension, 'manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  manifest.host_permissions = ['http://127.0.0.1/*'];
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
  await mkdir(profile, {recursive: true});
  await promisify(execFile)(process.execPath, [path.join(resources, 'agent-bridge/cli.mjs'), 'install', '--extension-id', eid, '--browser-profile', profile], {
    env: {...process.env, KUMO_AGENT_DIR: runtime.runtimeDir},
  });
  broker = await startBroker(runtime);
  await Promise.all([listen(fixture), listen(destination)]);
  const fixtureURL = `http://127.0.0.1:${fixture.address().port}`;
  const destinationURL = `http://127.0.0.1:${destination.address().port}`;
  console.log(JSON.stringify({qaPaths: {temporary, profile, extension, runtimeDirectory}, extensionSource: process.env.KUMO_QA_EXTENSION_SOURCE || path.join(resources, 'KumoExtension')}));
  console.error('Agent QA: launching isolated Chromium.');
  context = await chromium.launchPersistentContext(profile, {
    executablePath: path.join(app, 'Contents/MacOS/Chromium'), headless: true,
    timeout: 60000,
    chromiumSandbox: true, ignoreDefaultArgs: ['--disable-extensions'],
    args: [`--load-extension=${extension}`, `--disable-extensions-except=${extension}`, '--no-first-run', '--disable-sync', '--use-mock-keychain', '--password-store=basic'],
    env: {...process.env, KUMO_AGENT_DIR: runtime.runtimeDir}, viewport: {width: 1280, height: 900},
  });
  context.setDefaultTimeout(15000);
  context.on('page', page => page.on('pageerror', error => errors.push(error.message)));
  console.error('Agent QA: Chromium connected; opening local fixture and Kumo UI.');
  const target = await context.newPage();
  await target.goto(fixtureURL);
  const controls = await context.newPage();
  await controls.goto(`chrome-extension://${eid}/newtab.html`);
  const agentStatus = () => controls.evaluate(() => chrome.runtime.sendMessage({type: 'agent.status'}));
  const reopenAgentDialog = async () => {
    if (await controls.locator('#agentsDialog').evaluate(dialog => dialog.open)) {
      await controls.locator('#agentsDialog [data-close]').click();
    }
    await controls.locator('#openAgents').click();
  };
  const selectChoice = async (title, expectedOrigin) => {
    const choice = controls.locator('#tabChoices label').filter({hasText: title});
    await choice.waitFor({state: 'visible'});
    assert.equal(await choice.count(), 1, `Exactly one owned fixture must be listed: ${title}`);
    assert.equal(await choice.locator('small').textContent(), expectedOrigin, 'The actual dialog must display the expected origin');
    const checkbox = choice.locator('input');
    assert.equal(await checkbox.getAttribute('data-origin'), expectedOrigin, 'The selected checkbox must retain that displayed origin');
    await checkbox.check();
    return checkbox;
  };
  console.log(JSON.stringify({layout: await controls.evaluate(() => {
    const rect = element => { const r = element?.getBoundingClientRect(); return r ? {x: r.x, y: r.y, width: r.width, height: r.height} : null; };
    return {headers: document.querySelectorAll('header').length, footers: document.querySelectorAll('footer').length, body: rect(document.body), footer: rect(document.querySelector('footer')), footerText: document.querySelector('footer')?.innerText};
  })}));
  await controls.locator('#openAgents').click();
  // Capture the actual button output without replacing the user's clipboard or
  // launching a client. The packaged commands must survive moving this app.
  await controls.evaluate(() => {
    globalThis.kumoQACopiedCommands = [];
    Object.defineProperty(navigator, 'clipboard', {value: {writeText: async text => globalThis.kumoQACopiedCommands.push(text)}, configurable: true});
  });
  assert.equal(await controls.getByRole('heading', {name: 'Codex Desktop', exact: true}).count(), 1);
  assert.equal(await controls.getByRole('heading', {name: 'Claude Desktop', exact: true}).count(), 1);
  await controls.locator('#copyCodex').click();
  await controls.locator('#copyClaude').click();
  assert.deepEqual(await controls.evaluate(() => globalThis.kumoQACopiedCommands), [
    'open -n -b app.kumo.browser --args --kumo-connect-codex-desktop',
    'open -n -b app.kumo.browser --args --kumo-connect-claude-desktop',
  ]);
  checks.push('Desktop setup buttons copy portable commands for the correct clients');
  const choice = controls.locator('#tabChoices label').filter({hasText: 'Kumo Agent QA fixture'});
  await choice.locator('input').check();
  await controls.locator('#grantAgents').click();
  console.error('Agent QA: tab granted through UI; waiting for native connection.');
  await eventually(async () => {
    const state = await controls.evaluate(() => chrome.runtime.sendMessage({type: 'agent.status'}));
    if (state.bridgeError) throw new Error(state.bridgeError);
    return state.enabled && state.bridgeConnected && state.grants.length === 1;
  }, 'Native host must connect after the actual grant button is clicked');
  checks.push('actual internal grant UI and authenticated Native Messaging host');
  connection = await connectBroker(runtime);
  const tabs = await eventually(async () => {
    const rows = await requestBrowser(connection, 'tabs.list', {});
    return rows.length === 1 ? rows : false;
  }, 'Granted tabs must reach the actual broker');
  const tabId = tabs[0].tabId;
  assert.equal(tabs[0].url, fixtureURL + '/');
  const snapshot = await requestBrowser(connection, 'tab.snapshot', {tabId});
  assert.match(snapshot.text, /Public fixture heading/);
  assert.match(snapshot.text, /Visible fixture text/);
  assert.doesNotMatch(JSON.stringify(snapshot), /_PRIVATE/);
  assert(snapshot.controls.some(control => control.id === 'normal'));
  for (const field of sensitiveFields) {
    assert(!snapshot.controls.some(control => control.id === field.id), `Snapshot must omit ${field.id} metadata`);
    if (field.autocomplete) assert.equal(await target.locator(`#${field.id}`).getAttribute('autocomplete'), field.autocomplete, 'The real DOM must preserve the tested autocomplete spelling and whitespace');
  }
  checks.push('visible DOM snapshot excludes form values, hidden content and sensitive metadata');

  await requestBrowser(connection, 'tab.click', {tabId, selector: '#click'});
  assert.equal(await target.locator('#result').textContent(), 'Button clicked');
  await requestBrowser(connection, 'tab.type', {tabId, selector: '#normal', text: 'Agent entered fixture text'});
  assert.equal(await target.locator('#normal').inputValue(), 'Agent entered fixture text');
  await requestBrowser(connection, 'tab.type', {tabId, selector: '#draft', text: 'Agent fixture draft'});
  assert.equal(await target.locator('#draft').inputValue(), 'Agent fixture draft');
  for (const field of sensitiveFields) {
    const selector = `#${field.id}`;
    await assert.rejects(requestBrowser(connection, 'tab.type', {tabId, selector, text: 'Must be rejected'}), /password|payment|verification/);
    await assert.rejects(requestBrowser(connection, 'tab.click', {tabId, selector}), /password|payment|verification/);
    assert.equal(await target.locator(selector).inputValue(), field.value, `Rejected actions must leave ${field.id} unchanged`);
    assert.equal(await target.locator(selector).getAttribute('data-click-count'), '0', `Rejected actions must not click ${field.id}`);
  }
  checks.push('real normal clicks/text entry work; exact, section-prefixed, case-varied and tab/newline OTP tokens plus case-varied payment/password tokens reject click/type and omit snapshot metadata/values');

  await controls.locator('#revokeAgents').click();
  await eventually(async () => (await controls.evaluate(() => chrome.runtime.sendMessage({type: 'agent.status'}))).enabled === false, 'User revocation must complete');
  await assert.rejects(requestBrowser(connection, 'tab.snapshot', {tabId}), /disabled|revoked/);
  checks.push('actual revoke button prevents further browser access');

  // Regrant the fixture, then let an actual server redirect cross the origin boundary.
  await controls.locator('#agentsDialog [data-close]').click();
  await controls.locator('#openAgents').click();
  await controls.locator('#tabChoices label').filter({hasText: 'Kumo Agent QA fixture'}).locator('input').check();
  await controls.locator('#grantAgents').click();
  await eventually(async () => (await requestBrowser(connection, 'tabs.list', {})).length === 1, 'Fixture must be granted again');
  await target.goto(fixtureURL + '/redirect');
  await eventually(async () => (await controls.evaluate(() => chrome.runtime.sendMessage({type: 'agent.status'}))).grants.length === 0, 'Redirect to another port must revoke the origin grant');
  assert.deepEqual(await requestBrowser(connection, 'tabs.list', {}), []);
  await assert.rejects(requestBrowser(connection, 'tab.snapshot', {tabId}), /not been granted/);
  checks.push('real cross-origin HTTP redirect removes the grant and hides the tab');

  // Give the destination a legitimate UI grant first, then revoke it. The copied
  // QA manifest's existing loopback-only access remains available for this port.
  // This models retained host permission without touching a personal profile.
  await controls.locator('#revokeAgents').click();
  await eventually(async () => (await agentStatus()).enabled === false, 'Revocation before destination setup must complete');
  await reopenAgentDialog();
  await selectChoice('Other origin', destinationURL);
  await controls.locator('#grantAgents').click();
  await eventually(async () => {
    const state = await agentStatus();
    return state.enabled && state.grants.length === 1 && state.grants[0].tabId === tabId && state.grants[0].origin === destinationURL;
  }, 'The owned destination must receive a legitimate UI grant');
  const destinationSetupTabs = await eventually(async () => {
    const rows = await requestBrowser(connection, 'tabs.list', {});
    return rows.length === 1 && rows[0].tabId === tabId && rows[0].url === `${destinationURL}/destination` ? rows : false;
  }, 'The legitimate destination setup grant must reach the actual bridge');
  assert.deepEqual(destinationSetupTabs.map(tab => ({tabId: tab.tabId, url: tab.url})), [{tabId, url: `${destinationURL}/destination`}]);
  await controls.locator('#revokeAgents').click();
  await eventually(async () => (await agentStatus()).enabled === false, 'Destination grant revocation must complete');
  const retainedDestinationPermission = await controls.evaluate(origin => chrome.permissions.contains({origins: [`${origin}/*`]}), destinationURL);
  assert.equal(retainedDestinationPermission, true, 'The stale-origin scenario requires host permission for the destination');

  await target.goto(fixtureURL);
  await reopenAgentDialog();
  const staleChoice = await selectChoice('Kumo Agent QA fixture', fixtureURL);
  await target.goto(`${destinationURL}/destination`);
  assert.equal(await staleChoice.getAttribute('data-origin'), fixtureURL, 'Navigation must leave the already-displayed choice stale');
  assert.equal(new URL(target.url()).origin, destinationURL);
  const previousToast = await controls.locator('#agentToast').textContent();
  await controls.locator('#grantAgents').click();
  const rejection = await eventually(async () => {
    const text = await controls.locator('#agentToast').textContent();
    return text !== previousToast && /changed|origin|site|refresh|again/i.test(text) && !/^Access enabled\./.test(text) ? text : false;
  }, 'The actual grant UI must report rejection of its stale origin');
  const rejectedState = await agentStatus();
  assert.equal(rejectedState.enabled, false, 'A stale selection must not enable agents');
  assert.deepEqual(rejectedState.grants, [], 'A stale selection must not publish any tab grant');
  await eventually(async () => {
    try { await requestBrowser(connection, 'tabs.list', {}); return false; }
    catch (error) { assert.match(error.message, /off|disabled|revoked/i); return true; }
  }, 'The native bridge must also observe disabled access after rejection');

  await reopenAgentDialog();
  await selectChoice('Other origin', destinationURL);
  await controls.locator('#grantAgents').click();
  await eventually(async () => {
    const state = await agentStatus();
    return state.enabled && state.grants.length === 1 && state.grants[0].tabId === tabId && state.grants[0].origin === destinationURL;
  }, 'Refreshing the dialog must allow a new explicit destination grant');
  const legitimateTabs = await eventually(async () => {
    const rows = await requestBrowser(connection, 'tabs.list', {});
    return rows.length === 1 && rows[0].tabId === tabId && new URL(rows[0].url).origin === destinationURL ? rows : false;
  }, 'The refreshed legitimate grant must reach the actual bridge');
  const destinationSnapshot = await requestBrowser(connection, 'tab.snapshot', {tabId});
  assert.match(destinationSnapshot.text, /Destination fixture/);
  staleOriginEvidence = {displayedOrigin: fixtureURL, navigatedOrigin: destinationURL, retainedDestinationPermission, rejection, rejectedState: {enabled: rejectedState.enabled, grants: rejectedState.grants}, legitimateAfterRefresh: legitimateTabs.length === 1};
  checks.push('actual UI rejects a stale selected origin even with retained destination host permission; refreshed explicit destination grant works through Native Messaging');

  await controls.locator('#revokeAgents').click();
  await eventually(async () => (await agentStatus()).enabled === false, 'Final revocation must complete');
  assert.deepEqual(errors, [], 'No extension page errors');
  console.log(JSON.stringify({passed: true, checks, sensitiveFixtureIds: sensitiveFields.map(field => field.id), staleOriginEvidence, sandbox: true, profile: 'disposable', accountAccess: false}, null, 2));
} finally {
  await context?.close();
  connection?.close();
  await broker?.close();
  await Promise.all([closeServer(fixture), closeServer(destination)]);
  await rm(temporary, {recursive: true, force: true});
  await rm(runtimeDirectory, {recursive: true, force: true});
}
