import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import vm from 'node:vm';
import {phishingView, pageResultText} from '../addons/phishlang/extension/settings-state.js';
import {installSettings, WEBSITE_ORIGINS} from '../addons/phishlang/extension/settings.js';
import {installWarning} from '../addons/phishlang/extension/phishing-warning.js';

const addon = new URL('../addons/phishlang/extension/', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('manifest.json', addon), 'utf8'));
const extensionId = (await readFile(new URL('../config/phishlang-extension-id.txt', import.meta.url), 'utf8')).trim();
const eventLoop = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return {promise, resolve}; };
function fakeDocument() {
  const elements = new Map();
  return {visibilityState: 'visible', getElementById(id) {
    if (!elements.has(id)) elements.set(id, {textContent: '', dataset: {}, disabled: false});
    return elements.get(id);
  }};
}
function settingsFixture({permission = false, enabled = false, health = 'off', allow = true, requestError = null, result = null} = {}) {
  const document = fakeDocument(), messages = [], requests = [], removals = [];
  const state = {permission, enabled, health, requestError};
  const api = {
    tabs: {async query() { return [{id: 7}]; }},
    permissions: {
      async contains(value) { assert.deepEqual(value.origins, WEBSITE_ORIGINS); return state.permission; },
      async request(value) { requests.push(structuredClone(value)); if (allow) state.permission = true; return allow; },
      async remove(value) { removals.push(structuredClone(value)); state.permission = false; return true; },
    },
    runtime: {async sendMessage(message) {
      messages.push(structuredClone(message));
      if (state.requestError) return {error: state.requestError};
      if (message.type === 'phishing.enable') { assert.equal(state.permission, true); state.enabled = true; state.health = 'ready'; return {ok: true}; }
      if (message.type === 'phishing.disable') { state.enabled = false; state.health = 'off'; return {ok: true}; }
      assert.equal(message.type, 'phishing.status');
      return {ok: true, included: true, enabled: state.enabled, health: state.health,
        modelVersion: state.enabled ? 'a'.repeat(40) : null, currentTab: result};
    }},
  };
  const settings = installSettings(api, document);
  return {document, api, state, messages, requests, removals, settings, element: id => document.getElementById(id)};
}

test('standalone manifest has a dedicated stable ID and only optional website access', () => {
  assert.match(extensionId, /^[a-p]{32}$/);
  assert.equal(extensionId, 'ejmohaggcahgfhmgkdiicnmmlpnhgfmi');
  const derived = createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest('hex').slice(0, 32)
    .split('').map(value => String.fromCharCode(97 + parseInt(value, 16))).join('');
  assert.equal(derived, extensionId);
  assert.deepEqual(manifest.permissions.slice().sort(), ['nativeMessaging', 'scripting', 'storage', 'tabs', 'webNavigation'].sort());
  assert.deepEqual(manifest.optional_host_permissions, WEBSITE_ORIGINS);
  for (const property of ['host_permissions', 'chrome_url_overrides', 'declarative_net_request', 'externally_connectable', 'content_scripts', 'web_accessible_resources']) assert.equal(manifest[property], undefined);
  assert.equal(manifest.incognito, 'not_allowed');
  assert.equal(manifest.options_page, 'settings.html'); assert.equal(manifest.action.default_popup, 'settings.html');
  assert.equal(manifest.background.service_worker, 'background.js');
  assert.equal(manifest.content_security_policy.extension_pages, "script-src 'self'; object-src 'none'; base-uri 'none'; connect-src 'self'; img-src 'self' data:;");
});

test('bootstrap binds the dedicated native host/settings and forwards only phishing messages', async () => {
  let configuration, listener, stopped = false;
  const source = (await readFile(new URL('background.js', addon), 'utf8')).replace(/^import[^\n]+\n/, '');
  vm.runInNewContext(source, {chrome: {runtime: {onMessage: {addListener(value) { listener = value; }}, onSuspend: {addListener(value) { stopped = value; }}}},
    createPhishingProtection(api, options) { configuration = options; return {handleMessage: async (message, sender) => ({message, sender}), shutdown() { stopped = true; }}; }});
  assert.equal(configuration.nativeHost, 'com.kumo.phishlang');
  assert.equal(configuration.settingsPath, 'settings.html'); assert.equal(configuration.leaveURL, 'about:blank');
  assert.match(configuration.nativeUnavailableMessage, /install.command/);
  let reply;
  assert.equal(listener({type: 'agent.enable'}, {}, value => { reply = value; }), false); assert.equal(reply, undefined);
  assert.equal(listener({type: 'phishing.status'}, {id: extensionId}, value => { reply = value; }), true);
  await eventLoop(); assert.equal(reply.message.type, 'phishing.status'); assert.equal(reply.sender.id, extensionId);
  const onSuspend = stopped; assert.equal(typeof onSuspend, 'function'); onSuspend(); assert.equal(stopped, true);
});

test('view states never describe a low score or missing model as a safe website', () => {
  assert.equal(phishingView({ok: true, included: true, enabled: false, health: 'off'}, false).label, 'Off');
  assert.equal(phishingView({ok: true, included: true, enabled: true, health: 'ready'}, true).label, 'Enabled');
  for (const status of [null, {ok: false}, {ok: true, included: false}, {ok: true, included: true, enabled: true, health: 'unavailable'}]) {
    const view = phishingView(status, true);
    assert.equal(view.label, 'Unavailable'); assert.equal(view.disableDisabled, false);
    assert.doesNotMatch(view.description, /website is safe|fully protected|all pages checked/i);
  }
  assert.match(pageResultText({status: 'no-signal'}, true), /does not establish/);
  assert.match(pageResultText({status: 'partial'}, true), /Only part/);
  assert.match(pageResultText({status: 'unavailable'}, true), /could not/);
  assert.match(pageResultText(null, true), /No result/);
  assert.match(pageResultText({status: 'suspicious'}, false), /off/);
});

test('opening settings starts no native request, page permission prompt or enable operation', async () => {
  const h = settingsFixture(); await h.settings.ready;
  assert.deepEqual(h.messages, [{type: 'phishing.status', tabId: 7}]);
  assert.deepEqual(h.requests, []); assert.deepEqual(h.removals, []);
  assert.equal(h.element('protectionStatus').textContent, 'Off');
  assert.equal(h.element('enablePhishing').disabled, false); assert.equal(h.element('disablePhishing').disabled, true);
  assert.equal(h.element('modelVersion').textContent, 'Not loaded');
});

test('enable requests website access synchronously from the click before it enables protection', async () => {
  const h = settingsFixture(); await h.settings.ready;
  const clicked = h.element('enablePhishing').onclick();
  assert.deepEqual(h.requests, [{origins: WEBSITE_ORIGINS}]);
  assert.equal(h.messages.filter(message => message.type === 'phishing.enable').length, 0);
  await clicked;
  assert.equal(h.state.enabled, true); assert.equal(h.element('protectionStatus').textContent, 'Enabled');
  assert.equal(h.element('enablePhishing').disabled, true); assert.equal(h.element('disablePhishing').disabled, false);
  assert.equal(h.element('modelVersion').textContent, 'a'.repeat(12));
});

test('denied website access never enables protection or retries automatically', async () => {
  const h = settingsFixture({allow: false}); await h.settings.ready;
  await h.element('enablePhishing').onclick();
  assert.equal(h.state.enabled, false); assert.equal(h.state.permission, false);
  assert.equal(h.messages.filter(message => message.type === 'phishing.enable').length, 0);
  assert.match(h.element('settingsError').textContent, /not granted/);
  assert.equal(h.element('protectionStatus').textContent, 'Off');
});

test('turning off retires protection and removes this extension’s website grant', async () => {
  const h = settingsFixture({permission: true, enabled: true, health: 'ready'}); await h.settings.ready;
  await h.element('disablePhishing').onclick();
  assert.equal(h.state.enabled, false); assert.equal(h.state.permission, false);
  assert.deepEqual(h.removals, [{origins: WEBSITE_ORIGINS}]);
  assert.equal(h.messages.filter(message => message.type === 'phishing.disable').length, 1);
  assert.equal(h.element('disablePhishing').disabled, true);
});

test('unavailable worker still offers grant removal and disable failure cannot retain website access', async () => {
  const h = settingsFixture({permission: true, requestError: 'Worker unavailable'}); await h.settings.ready;
  assert.equal(h.element('protectionStatus').textContent, 'Unavailable');
  assert.equal(h.element('enablePhishing').disabled, true); assert.equal(h.element('disablePhishing').disabled, false);
  await h.element('disablePhishing').onclick();
  assert.equal(h.state.permission, false); assert.equal(h.removals.length, 1);
  assert.match(h.element('settingsError').textContent, /Worker unavailable/);
});

function warningFixture({error = null, coverageLimited = false, gate = null, continueError = false} = {}) {
  const document = fakeDocument(), messages = [], navigations = [];
  const location = {hash: '#ticket', replace(value) { navigations.push(value); }};
  const api = {runtime: {async sendMessage(message) {
    messages.push(structuredClone(message));
    if (gate && message.type === 'phishing.warning') await gate.promise;
    return error || continueError && message.type === 'phishing.continue' ? {error: error || 'Expired continuation'} : {ok: true, origin: 'https://example.test', coverageLimited};
  }}};
  const warning = installWarning(api, document, location);
  return {document, warning, messages, navigations, element: id => document.getElementById(id)};
}

test('warning shows only the supplied origin, coverage caveat and ticket-bound actions', async () => {
  const h = warningFixture({coverageLimited: true}); await h.warning.ready;
  assert.equal(h.element('warningOrigin').textContent, 'https://example.test');
  assert.match(h.element('warningCoverage').textContent, /Only part/);
  assert.equal(h.element('continueSite').disabled, false);
  await h.element('continueSite').onclick(); await h.element('continueSite').onclick();
  assert.deepEqual(h.messages, [{type: 'phishing.warning', token: 'ticket'}, {type: 'phishing.continue', token: 'ticket'}]);
  assert.deepEqual(h.navigations, []);
});

test('warning Leave asks the bound backend to clear the ticket and leave the site', async () => {
  const h = warningFixture(); await h.warning.ready;
  await h.element('leaveSite').onclick();
  assert.deepEqual(h.messages.at(-1), {type: 'phishing.leave', token: 'ticket'});
  assert.deepEqual(h.navigations, []); assert.equal(h.element('continueSite').disabled, true);
});

test('expired warning cannot continue and Leave has a fixed blank-page fallback', async () => {
  const h = warningFixture({error: 'Expired'}); await h.warning.ready;
  assert.equal(h.element('continueSite').disabled, true); assert.match(h.element('warningStatus').textContent, /expired/);
  await h.element('continueSite').onclick(); assert.equal(h.messages.length, 1);
  await h.element('leaveSite').onclick(); assert.deepEqual(h.navigations, ['about:blank']);
});

test('a warning result arriving after Leave cannot reenable Continue', async () => {
  const gate = deferred(), h = warningFixture({gate});
  await h.element('leaveSite').onclick(); gate.resolve(); await h.warning.ready;
  assert.equal(h.element('continueSite').disabled, true);
  assert.equal(h.messages.filter(message => message.type === 'phishing.continue').length, 0);
});

test('standalone pages contain no inline executable script, remote resources or new-tab override', async () => {
  for (const name of ['settings.html', 'phishing-warning.html']) {
    const html = await readFile(new URL(name, addon), 'utf8');
    assert.doesNotMatch(html, /on(?:click|load|error)\s*=|<script(?![^>]*\bsrc=)|(?:src|href)=["']https?:/i);
  }
  const settings = await readFile(new URL('settings.html', addon), 'utf8');
  for (const id of ['enablePhishing', 'disablePhishing', 'phishingStatus']) assert(settings.includes(`id="${id}"`));
  assert.match(settings, /Experimental/); assert.match(settings, /starts off/); assert.match(settings, /8 GB/);
});


test('a failed Continue still permits the user to leave the warning', async () => {
  const h = warningFixture({continueError: true}); await h.warning.ready;
  await h.element('continueSite').onclick();
  assert.equal(h.element('continueSite').disabled, true); assert.match(h.element('warningStatus').textContent, /expired/);
  await h.element('leaveSite').onclick();
  assert.deepEqual(h.messages.at(-1), {type: 'phishing.leave', token: 'ticket'});
});
