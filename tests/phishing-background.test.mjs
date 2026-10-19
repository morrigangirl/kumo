import test from 'node:test';
import assert from 'node:assert/strict';
import {createPhishingProtection} from '../extension/phishing-background.js';

class Event {
  listeners = [];
  addListener(fn) { this.listeners.push(fn); }
  async emit(...args) { return Promise.all(this.listeners.map(fn => fn(...args))); }
}
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return {promise, resolve}; }
async function harness(t, {stored = false, permission = true, probability = 0.99,
  buildInfo = {phishingProtection: {included: true}}, registered = false, openTabs = [], storedWarnings = {},
  configuration = {}, nativeAvailable = true, nativeConnectFailure = false, extensionId = 'eldkgppmnhligdekahicdcdndcoongio'} = {}) {
  const id = extensionId, base = `chrome-extension://${id}/`;
  const local = {phishingProtection: {enabled: stored}}, session = {}, scripts = new Map(), tabs = new Map();
  if (registered) scripts.set('kumo-local-phishing', {id: 'kumo-local-phishing'});
  if (Object.keys(storedWarnings).length) session.phishingWarnings = structuredClone(storedWarnings);
  for (const tab of openTabs) tabs.set(tab.id, structuredClone(tab));
  const h = {local, session, scripts, tabs, sent: [], updates: [], confirmations: [], stopped: [], ports: [], permission, probability,
    nativeGate: null, storeGate: null, beforeStore: null, beforeGet: null, beforeFrame: null, revision: 0, clock: 100000, counter: 0};
  const api = {
    runtime: {id, getURL: path => base + path, connectNative(name) {
      assert.equal(name, configuration.nativeHost || 'com.kumo.phishing');
      if (nativeConnectFailure) throw new Error('Native host missing');
      const port = {onMessage: new Event(), onDisconnect: new Event(), disconnect() {}, postMessage(message) {
        h.sent.push(structuredClone(message));
        void (async () => {
          if (h.nativeGate && message.type === h.nativeGate.type) await h.nativeGate.promise;
          const reply = message.type === 'status' ? {id: message.id, ok: true, available: nativeAvailable, modelVersion: 'a'.repeat(40)} :
            {id: message.id, ok: true, available: true, probability: h.probability, windows: 1, tokenCount: 30, coverageLimited: false};
          await port.onMessage.emit(reply);
        })();
      }};
      h.ports.push(port); return port;
    }},
    permissions: {onRemoved: new Event(), async contains() { return h.permission; }},
    storage: {
      local: {async get(key) { return {[key]: structuredClone(local[key])}; }, async set(value) { Object.assign(local, structuredClone(value)); }},
      session: {async get(key) { return {[key]: structuredClone(session[key])}; }, async set(value) {
        if (h.beforeStore) await h.beforeStore(value);
        if (h.storeGate) await h.storeGate.promise;
        Object.assign(session, structuredClone(value));
      }},
    },
    scripting: {async getRegisteredContentScripts() { return [...scripts.values()]; }, async unregisterContentScripts() { scripts.clear(); },
      async registerContentScripts(values) { values.forEach(value => scripts.set(value.id, value)); }, async executeScript() { return []; }},
    tabs: {onUpdated: new Event(), onRemoved: new Event(), async query() { return structuredClone([...tabs.values()]); }, async get(tabId) {
      if (h.beforeGet) await h.beforeGet(tabId);
      if (!tabs.has(tabId)) throw new Error('Tab missing'); return structuredClone(tabs.get(tabId));
    }, async update(tabId, values) { h.updates.push({tabId, ...values}); Object.assign(tabs.get(tabId), values); return structuredClone(tabs.get(tabId)); },
    async sendMessage(tabId, message, options) {
      if (message.type === 'phishing.stop') { h.stopped.push(tabId); return {stopped: true}; }
      h.confirmations.push({tabId, message, options}); return {url: tabs.get(tabId).url, revision: h.revision};
    }},
    webNavigation: {async getFrame({tabId}) { if (h.beforeFrame) await h.beforeFrame(tabId); const tab = tabs.get(tabId); return {documentId: tab.documentId, url: tab.url}; }},
  };
  h.api = api;
  h.protection = createPhishingProtection(api, {...configuration, now: () => h.clock, randomId: () => `qa-${++h.counter}`,
    readBuildInfo: async () => { if (buildInfo instanceof Error) throw buildInfo; return buildInfo; }});
  t.after(() => h.protection.shutdown());
  await h.protection.ready;
  h.internal = {id, url: base + (configuration.settingsPath || 'newtab.html') + '#settings', tab: {id: 99}, frameId: 0, documentLifecycle: 'active'};
  h.message = (value, sender = h.internal) => h.protection.handleMessage(value, sender);
  h.enable = () => h.message({type: 'phishing.enable'});
  h.disable = () => h.message({type: 'phishing.disable'});
  h.addTab = (tabId = 1, url = 'https://example.com/login?session=PRIVATE_QUERY#PRIVATE_FRAGMENT') => {
    const tab = {id: tabId, url, incognito: false, documentId: `doc-${tabId}`}; tabs.set(tabId, tab);
    return {id, url, frameId: 0, documentLifecycle: 'active', documentId: tab.documentId, tab: structuredClone(tab)};
  };
  h.scan = (sender, extra = {}) => h.message({type: 'phishing.scan', url: tabs.get(sender.tab.id).url,
    revision: 0, text: 'TITLE: { "text": "Synthetic public fixture" }', coverageLimited: false, ...extra}, sender);
  return h;
}

test('phishing starts off without starting a native model or registering page access', async t => {
  const h = await harness(t);
  assert.deepEqual(await h.message({type: 'phishing.status'}), {ok: true, included: true, enabled: false, health: 'off', modelVersion: null, currentTab: null});
  assert.equal(h.sent.length, 0); assert.equal(h.scripts.size, 0);
});

test('model-free upgrades retire persisted analysis, warning tickets and scripts without a native request', async t => {
  const h = await harness(t, {stored: true, registered: true,
    buildInfo: {phishingProtection: {included: false, reason: 'omitted-from-release'}},
    storedWarnings: {old: {url: 'https://example.com/', tabId: 1}},
    openTabs: [{id: 1, url: 'https://example.com/', incognito: false}, {id: 2, url: 'https://private.example/', incognito: true}],
  });
  assert.deepEqual(await h.message({type: 'phishing.status'}), {ok: true, included: false, enabled: false,
    health: 'not-included', modelVersion: null, currentTab: null});
  assert.equal(h.local.phishingProtection.enabled, false);
  assert.equal(h.scripts.size, 0); assert.deepEqual(h.stopped, [1]);
  assert.deepEqual(h.session.phishingWarnings, {});
  for (let attempt = 0; attempt < 3; attempt++) await assert.rejects(h.enable(), /not included/);
  assert.equal((await h.scan(h.addTab())).status, 'off');
  await h.disable();
  assert.equal((await h.message({type: 'phishing.status'})).health, 'not-included');
  assert.equal(h.ports.length, 0); assert.deepEqual(h.sent, []);
});

test('missing, malformed or unreadable package feature metadata fails closed without inference', async t => {
  for (const buildInfo of [{}, {phishingProtection: {included: 'true'}}, {phishingProtection: {included: 1}}, null, new Error('read failed')]) {
    const h = await harness(t, {stored: true, registered: true, buildInfo});
    const status = await h.message({type: 'phishing.status'});
    assert.equal(status.included, false); assert.equal(status.enabled, false); assert.equal(status.health, 'unavailable');
    await assert.rejects(h.enable(), /not included/);
    assert.equal(h.local.phishingProtection.enabled, false); assert.equal(h.scripts.size, 0); assert.equal(h.ports.length, 0);
  }
});

test('model-inclusive builds retain enabled preference and initialize the packaged native model', async t => {
  const h = await harness(t, {stored: true});
  const status = await h.message({type: 'phishing.status'});
  assert.equal(status.included, true); assert.equal(status.enabled, true); assert.equal(status.health, 'ready');
  assert.equal(h.local.phishingProtection.enabled, true); assert.equal(h.scripts.size, 1);
  assert.deepEqual(h.sent.map(request => request.type), ['status']);
});

test('settings accept the actual extension-tab sender and hash, and reject web/foreign page controls', async t => {
  const h = await harness(t);
  for (const url of ['https://example.com/newtab.html', 'chrome-extension://other/newtab.html', h.api.runtime.getURL('phishing-warning.html')]) {
    await assert.rejects(h.message({type: 'phishing.enable'}, {...h.internal, url}), /settings/);
  }
  await assert.rejects(h.message({type: 'phishing.enable'}, {...h.internal, id: 'b'.repeat(32)}), /Unsupported/);
  assert.deepEqual(await h.enable(), {ok: true, enabled: true});
  assert.equal(h.local.phishingProtection.enabled, true); assert.equal(h.scripts.size, 1);
  assert.equal(h.sent[0].type, 'status');
});

test('website access is required before enabling and default-off scans never reach inference', async t => {
  const h = await harness(t, {permission: false});
  await assert.rejects(h.enable(), /website access/);
  assert.equal(h.local.phishingProtection.enabled, false); assert.equal(h.sent.length, 0);
  assert.equal((await h.scan(h.addTab())).status, 'off');
});

test('a persisted enabled preference without retained permission disables itself', async t => {
  const h = await harness(t, {stored: true, permission: false});
  assert.equal((await h.message({type: 'phishing.status'})).enabled, false);
  assert.equal(h.local.phishingProtection.enabled, false); assert.equal(h.sent.length, 0);
});

test('model receives only bounded text, and warning tickets hide private URL query/fragment from the UI', async t => {
  const h = await harness(t); await h.enable(); const sender = h.addTab();
  assert.equal((await h.scan(sender)).status, 'warning');
  const request = h.sent.find(value => value.type === 'classify');
  assert.deepEqual(Object.keys(request).sort(), ['id', 'text', 'type']); assert.doesNotMatch(JSON.stringify(request), /PRIVATE|example\.com/);
  assert.equal(h.confirmations.length, 2);
  assert(h.confirmations.every(value => value.options.documentId === sender.documentId && value.options.frameId === 0));
  const token = new URL(h.updates[0].url).hash.slice(1);
  const warningSender = {...sender, url: h.updates[0].url};
  const details = await h.message({type: 'phishing.warning', token}, warningSender);
  assert.equal(details.origin, 'https://example.com'); assert.doesNotMatch(JSON.stringify(details), /PRIVATE/);
});

test('low model scores are no-signal, partial analysis stays partial, and empty input is never benign', async t => {
  const h = await harness(t, {probability: 0.01}); await h.enable();
  assert.equal((await h.scan(h.addTab(1))).status, 'no-signal');
  assert.equal((await h.scan(h.addTab(2), {coverageLimited: true})).status, 'partial');
  const count = h.sent.length;
  assert.equal((await h.scan(h.addTab(3), {text: ''})).status, 'partial');
  assert.equal(h.sent.length, count); assert.deepEqual(h.updates, []);
});

test('child/private/Store/malformed/oversized scans cannot invoke the model', async t => {
  const h = await harness(t); await h.enable();
  const sender = h.addTab(); const count = h.sent.length;
  for (const changed of [{frameId: 1}, {documentLifecycle: 'cached'}, {documentId: ''}, {tab: {...sender.tab, incognito: true}}, {url: 'https://chromewebstore.google.com/category/extensions'}]) {
    await assert.rejects(h.scan({...sender, ...changed}), /Unsupported/);
  }
  for (const extra of [{text: 'x'.repeat(24577)}, {revision: -1}, {url: 'file:///private'}, {url: 'https://user:pass@example.com'}]) {
    await assert.rejects(h.scan(sender, extra), /Unsupported/);
  }
  assert.equal(h.sent.length, count);
});

test('a native result is discarded after cross-origin navigation or same-URL document replacement', async t => {
  for (const sameURL of [false, true]) {
    const h = await harness(t); await h.enable(); const sender = h.addTab();
    const gate = deferred(); h.nativeGate = {...gate, type: 'classify'};
    const result = h.scan(sender); while (!h.sent.some(value => value.type === 'classify')) await tick();
    h.tabs.get(1).documentId = 'replacement'; if (!sameURL) h.tabs.get(1).url = 'https://other.example/';
    gate.resolve(); assert.equal((await result).status, 'stale'); assert.deepEqual(h.updates, []);
  }
});

test('a changed DOM revision rejects a suspicious result before warning publication', async t => {
  const h = await harness(t); await h.enable(); h.revision = 1;
  assert.equal((await h.scan(h.addTab())).status, 'stale'); assert.deepEqual(h.updates, []);
});

test('same-origin SPA navigation during the live-frame lookup invalidates the old URL', async t => {
  const h = await harness(t); await h.enable(); const sender = h.addTab();
  h.beforeFrame = tabId => { h.tabs.get(tabId).url = 'https://example.com/different-page'; };
  assert.equal((await h.scan(sender)).status, 'stale');
  assert.equal(h.sent.filter(request => request.type === 'classify').length, 0); assert.deepEqual(h.updates, []);
});

test('disable retires every open eligible document in bounded batches, including beyond tab64', async t => {
  const h = await harness(t); await h.enable();
  for (let id = 1; id <= 70; id++) h.addTab(id);
  h.api.tabs.query = async () => structuredClone([...h.tabs.values()]);
  await h.disable();
  assert.equal(h.stopped.length, 70); assert.equal(h.scripts.size, 0);
});

test('DOM mutation during queued warning-ticket storage is checked again before navigation', async t => {
  const h = await harness(t); await h.enable();
  h.beforeStore = value => { if (Object.keys(value.phishingWarnings || {}).length) h.revision++; };
  assert.equal((await h.scan(h.addTab())).status, 'stale'); assert.deepEqual(h.updates, []);
  assert.equal(h.confirmations.length, 2);
});

test('disabling while inference is pending cannot publish a warning', async t => {
  const h = await harness(t); await h.enable(); const gate = deferred(); h.nativeGate = {...gate, type: 'classify'};
  const result = h.scan(h.addTab()); while (!h.sent.some(value => value.type === 'classify')) await tick();
  const rejected = assert.rejects(result, /unavailable/);
  await h.disable(); gate.resolve(); await rejected;
  assert.deepEqual(h.updates, []); assert.deepEqual(h.session.phishingWarnings, {});
});

test('disabling during initial document lookup prevents a new native request after revocation', async t => {
  const h = await harness(t); await h.enable(); const sender = h.addTab(); const gate = deferred();
  let entered = false;
  h.beforeFrame = async () => { entered = true; await gate.promise; };
  const result = h.scan(sender); const rejected = assert.rejects(result, /changed/);
  while (!entered) await tick();
  await h.disable(); gate.resolve(); await rejected;
  assert.equal(h.sent.filter(request => request.type === 'classify').length, 0);
  assert.equal((await h.message({type: 'phishing.status'})).health, 'off');
});

test('disabling during result document lookup cannot restore ready health or page results', async t => {
  const h = await harness(t, {probability: 0.01}); await h.enable(); const sender = h.addTab(); const gate = deferred();
  let entered = false, frames = 0;
  h.beforeFrame = async () => { if (++frames === 2) { entered = true; await gate.promise; } };
  const result = h.scan(sender); const rejected = assert.rejects(result, /unavailable/);
  while (!entered) await tick();
  await h.disable(); gate.resolve(); await rejected;
  const status = await h.message({type: 'phishing.status', tabId: 1});
  assert.equal(status.health, 'off'); assert.equal(status.currentTab, null);
});

test('permission revocation invalidates an in-progress enable operation', async t => {
  const h = await harness(t); const gate = deferred(); h.nativeGate = {...gate, type: 'status'};
  const enabling = h.enable(); const rejected = assert.rejects(enabling, /unavailable|changed/);
  while (!h.sent.length) await tick();
  h.permission = false; await h.api.permissions.onRemoved.emit({origins: ['https://*/*']}); gate.resolve();
  await rejected; await tick();
  assert.equal((await h.message({type: 'phishing.status'})).enabled, false); assert.equal(h.scripts.size, 0);
});

test('concurrent suspicious tabs retain both independent warning tickets', async t => {
  const h = await harness(t); await h.enable();
  await Promise.all([h.scan(h.addTab(1)), h.scan(h.addTab(2, 'https://second.example/login'))]);
  assert.equal(Object.keys(h.session.phishingWarnings).length, 2); assert.equal(h.updates.length, 2);
  assert.deepEqual(new Set(Object.values(h.session.phishingWarnings).map(value => value.tabId)), new Set([1, 2]));
});

test('warning continuation is bound to its current tab and expires after use', async t => {
  const h = await harness(t); await h.enable(); const sender = h.addTab(); await h.scan(sender);
  const url = h.tabs.get(1).url, token = new URL(url).hash.slice(1), warningSender = {...sender, url};
  await assert.rejects(h.message({type: 'phishing.continue', token}, {...warningSender, tab: {id: 2}}), /Unsupported|expired/);
  await h.message({type: 'phishing.continue', token}, warningSender);
  assert.equal(h.tabs.get(1).url, sender.url); assert.deepEqual(h.session.phishingWarnings, {});
  await assert.rejects(h.message({type: 'phishing.continue', token}, warningSender), /expired/);
  h.tabs.get(1).documentId = 'allowed-document';
  const allowed = {...sender, documentId: 'allowed-document'};
  assert.equal((await h.scan(allowed)).status, 'bypassed');
  h.tabs.get(1).documentId = 'different-document';
  assert.equal((await h.scan({...sender, documentId: 'different-document'})).status, 'warning');
});

test('a warning cannot redirect a tab that navigated while continuation storage was pending', async t => {
  const h = await harness(t); await h.enable(); const sender = h.addTab(); await h.scan(sender);
  const url = h.tabs.get(1).url, token = new URL(url).hash.slice(1);
  h.beforeStore = () => { h.tabs.get(1).url = 'https://unrelated.example/'; };
  await assert.rejects(h.message({type: 'phishing.continue', token}, {...sender, url}), /no longer current/);
  assert.equal(h.updates.length, 1); assert.equal(h.tabs.get(1).url, 'https://unrelated.example/');
});

test('invalid/nonfinite model output reports unavailable without a safe result or warning', async t => {
  const h = await harness(t, {probability: Infinity}); await h.enable();
  await assert.rejects(h.scan(h.addTab()), /unavailable/);
  const status = await h.message({type: 'phishing.status', tabId: 1});
  assert.equal(status.health, 'unavailable'); assert.equal(status.currentTab.status, 'unavailable'); assert.deepEqual(h.updates, []);
});

test('request concurrency and repeated-page work are bounded with explicit partial status', async t => {
  const h = await harness(t, {probability: 0.01}); await h.enable(); const gate = deferred(); h.nativeGate = {...gate, type: 'classify'};
  const requests = [1, 2, 3, 4].map(id => h.scan(h.addTab(id)));
  while (h.sent.filter(value => value.type === 'classify').length < 4) await tick();
  assert.equal((await h.scan(h.addTab(5))).status, 'busy');
  gate.resolve(); await Promise.all(requests); h.nativeGate = null;
  const sender = h.addTab(6);
  assert.equal((await h.scan(sender)).status, 'no-signal');
  assert.equal((await h.scan(sender)).status, 'limited');
  for (let count = 0; count < 7; count++) { h.clock += 2000; assert.equal((await h.scan(sender)).status, 'no-signal'); }
  h.clock += 2000; assert.equal((await h.scan(sender)).status, 'limited');
});


test('standalone identity accepts only its configured settings page and native host', async t => {
  const h = await harness(t, {extensionId: 'ejmohaggcahgfhmgkdiicnmmlpnhgfmi', configuration: {
    nativeHost: 'com.kumo.phishlang', settingsPath: 'settings.html', leaveURL: 'about:blank',
  }});
  for (const url of [h.api.runtime.getURL('newtab.html'), h.api.runtime.getURL('settings.html/other'),
    'https://example.com/settings.html', 'chrome-extension://eldkgppmnhligdekahicdcdndcoongio/settings.html']) {
    await assert.rejects(h.message({type: 'phishing.enable'}, {...h.internal, url}), /settings/);
  }
  await assert.rejects(h.message({type: 'phishing.enable'}, {...h.internal, id: 'eldkgppmnhligdekahicdcdndcoongio'}), /Unsupported/);
  assert.deepEqual(await h.enable(), {ok: true, enabled: true});
  assert.equal(h.sent[0].type, 'status'); assert.equal(h.scripts.size, 1);
  const sender = h.addTab(); await h.scan(sender);
  const url = h.tabs.get(1).url, token = new URL(url).hash.slice(1);
  await h.message({type: 'phishing.leave', token}, {...sender, url});
  assert.equal(h.tabs.get(1).url, 'about:blank');
  assert.deepEqual(h.session.phishingWarnings, {});
});

test('default integrated warning Leave still returns to the built-in new tab', async t => {
  const h = await harness(t); await h.enable(); const sender = h.addTab(); await h.scan(sender);
  const url = h.tabs.get(1).url, token = new URL(url).hash.slice(1);
  await h.message({type: 'phishing.leave', token}, {...sender, url});
  assert.equal(h.tabs.get(1).url, h.api.runtime.getURL('newtab.html'));
});

test('standalone missing companion errors give the configured install instructions', async t => {
  for (const nativeConnectFailure of [false, true]) {
    const h = await harness(t, {nativeAvailable: false, nativeConnectFailure, configuration: {
      nativeHost: 'com.kumo.phishlang', settingsPath: 'settings.html', nativeUnavailableMessage: 'Install the local companion and retry.',
    }});
    await assert.rejects(h.enable(), /Install the local companion and retry/);
    assert.equal(h.local.phishingProtection.enabled, false); assert.equal(h.scripts.size, 0);
    assert.equal((await h.message({type: 'phishing.status'})).enabled, false);
  }
});
