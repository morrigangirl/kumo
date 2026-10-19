import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';

let loadId = 0;
const tick = () => new Promise(resolve => setImmediate(resolve));
class Event {
  listeners = [];
  addListener(listener) { this.listeners.push(listener); }
  async emit(...args) { return Promise.all(this.listeners.map(listener => listener(...args))); }
}
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }

async function worker(t, {initializationGate} = {}) {
  const original = globalThis.chrome;
  const data = {};
  const tabs = new Map([
    [1, { id: 1, title: 'Example', url: 'https://example.com/', incognito: false }],
    [2, { id: 2, title: 'Private', url: 'https://private.example/', incognito: true }],
    [3, { id: 3, title: 'Other', url: 'https://other.example/', incognito: false }],
  ]);
  const allowed = new Set(['https://example.com/*']);
  const sent = [];
  const ports = [];
  const actions = [];
  const harness = { data, tabs, allowed, sent, ports, actions, beforeGet: null, afterCreate: null, beforeInject: null, page: null, requestGranted: true,
    storeResponse: null, beforeStoreConfirm: null, confirmations: [], beforeContains: null, beforeRequest: null, messages: [] };
  const chrome = {
    storage: {
      session: {
        async get(key) { return { [key]: structuredClone(data[key]) }; },
        async set(values) { if (initializationGate && Object.hasOwn(values, 'bridgeConnected')) await initializationGate.promise; Object.assign(data, structuredClone(values)); },
        async remove(key) { delete data[key]; },
      },
      local: { async get() { return {}; }, async set() {} },
      onChanged: new Event(),
    },
    action: { async setBadgeText() {}, async setBadgeBackgroundColor() {} },
    runtime: {
      id: 'a'.repeat(32),
      getURL: value => `chrome-extension://${'a'.repeat(32)}/${value}`,
      onStartup: new Event(), onMessage: new Event(),
      connectNative(name) {
        assert.equal(name, 'com.kumo.agent_bridge');
        const port = { onMessage: new Event(), onDisconnect: new Event(), postMessage(value) { sent.push(structuredClone(value)); } };
        ports.push(port); return port;
      },
    },
    permissions: {
      onRemoved: new Event(),
      async contains({ origins }) { if (harness.beforeContains) await harness.beforeContains(origins); return origins.every(origin => allowed.has(origin) || allowed.has('https://*/*') && origin.startsWith('https:') || allowed.has('http://*/*') && origin.startsWith('http:')); },
      request({ origins }) { actions.push({ request: origins }); return (async () => { if (harness.beforeRequest) await harness.beforeRequest(origins); if (harness.requestGranted) origins.forEach(origin => allowed.add(origin)); return harness.requestGranted; })(); },
    },
    tabs: {
      async query() { return structuredClone([...tabs.values()]); },
      async get(id) { if (harness.beforeGet) await harness.beforeGet(id); if (!tabs.has(id)) throw new Error('Tab missing'); return structuredClone(tabs.get(id)); },
      async sendMessage(tabId, message, options) {
        harness.confirmations.push(structuredClone({tabId, message, options}));
        if (harness.beforeStoreConfirm) await harness.beforeStoreConfirm(tabId, message, options);
        return structuredClone(harness.storeResponse);
      },
      async create({ url }) { const tab = { id: 10 + tabs.size, title: 'Created', url, incognito: false }; tabs.set(tab.id, tab); actions.push({ create: tab.id }); if (harness.afterCreate) await harness.afterCreate(tab); return structuredClone(tab); },
      async update(id, values) { Object.assign(tabs.get(id), values); actions.push({ update: id }); return structuredClone(tabs.get(id)); },
      async remove(id) { tabs.delete(id); actions.push({ remove: id }); await chrome.tabs.onRemoved.emit(id); },
      onUpdated: new Event(), onRemoved: new Event(),
    },
    scripting: {
      async executeScript({ func, args }) {
        actions.push({ inject: args[0] });
        if (harness.beforeInject) await harness.beforeInject();
        return [{ result: harness.page ? vm.runInNewContext(`(${func.toString()})(...args)`, { ...harness.page, args }) : { text: 'Visible content' } }];
      },
    },
  };
  globalThis.chrome = chrome;
  t.after(() => { globalThis.chrome = original; });
  await import(new URL(`../extension/background.js?agent-test=${++loadId}`, import.meta.url));
  harness.chrome = chrome;
  harness.message = (message, sender = { id: chrome.runtime.id, url: chrome.runtime.getURL('newtab.html') }) => new Promise(resolve => {
    const active = chrome.runtime.onMessage.listeners[0](message, sender, resolve);
    if (!active) resolve(undefined);
  });
  chrome.runtime.sendMessage = message => { harness.messages.push(structuredClone(message)); return harness.message(message); };
  harness.configure = (tabIds = [1], allowNewTabs = false) => harness.message({ type: 'agent.configure', grants: tabIds.map(tabId => ({tabId, origin: new URL(tabs.get(tabId).url).origin})), allowNewTabs });
  harness.disable = () => harness.message({ type: 'agent.disable' });
  harness.command = async (action, params = {}) => {
    const id = `test-${Math.random()}`;
    await ports.at(-1).onMessage.emit({ type: 'command', id, action, params });
    for (let attempt = 0; attempt < 100; attempt++) {
      const reply = sent.find(value => value.type === 'result' && value.id === id);
      if (reply) return reply;
      await tick();
    }
    throw new Error('Worker command did not reply');
  };
  return harness;
}

test('MV3 listeners register before initialization storage resolves', async t => {
  const initializationGate = deferred();
  t.after(() => initializationGate.resolve());
  const h = await Promise.race([
    worker(t, {initializationGate}),
    new Promise((_, reject) => { const timer = setTimeout(() => reject(new Error('Worker registration awaited storage; MV3 listeners must register synchronously')), 1000); timer.unref(); }),
  ]);
  assert.equal(h.chrome.runtime.onMessage.listeners.length, 1);
  assert.equal(h.chrome.runtime.onStartup.listeners.length, 1);
  const configuring = h.configure();
  assert.equal(h.ports.length, 0);
  initializationGate.resolve();
  assert.deepEqual(await configuring, {ok: true});
});

const storeOrigin = 'https://chromewebstore.google.com';
const storeIdA = 'aghfnjkcakhmadgdomlmlhhaocbkloab';
const storeIdB = 'ddkjiahejlhfcafbddmgiahcphecmpfh';
const storeDocumentId = '9D6B4BAFEE24C9F40FF7D4A9DDFC2EFF';
function storeSender(h, {initial = `${storeOrigin}/detail/just-black/${storeIdA}`,
  current = initial, extensionId = storeIdA} = {}) {
  h.tabs.set(4, {id: 4, title: 'Store fixture', url: current, incognito: false});
  h.storeResponse = {url: current, extensionId};
  return {id: h.chrome.runtime.id, url: initial, origin: storeOrigin, frameId: 0,
    documentId: storeDocumentId, documentLifecycle: 'active', tab: {id: 4, url: current}};
}
function createdStoreURLs(h) {
  return h.actions.filter(action => action.create).map(action => new URL(h.tabs.get(action.create).url));
}

test('Store helper accepts a bound direct detail page and creates only a versioned CRX3 request', async t => {
  const h = await worker(t);
  const extensionId = storeIdA, sender = storeSender(h);
  assert.match((await h.message({type: 'store.install', extensionId})).error, /Unsupported/);
  assert.match((await h.message({type: 'store.install', extensionId: 'invalid&x=anything'}, sender)).error, /Invalid extension ID/);
  assert.equal(h.actions.length, 0);
  assert.deepEqual(await h.message({type: 'store.install', extensionId}, sender), {ok: true});
  const [url] = createdStoreURLs(h);
  assert.equal(url.origin, 'https://clients2.google.com');
  assert.equal(url.pathname, '/service/update2/crx');
  assert.match(url.searchParams.get('prodversion'), /^\d+\.\d+\.\d+\.\d+$/);
  assert.equal(url.searchParams.get('response'), 'redirect');
  assert.equal(url.searchParams.get('acceptformat'), 'crx3');
  assert.equal(url.searchParams.get('x'), `id=${extensionId}&installsource=ondemand&uc`);
  assert.deepEqual([...url.searchParams.keys()].sort(), ['acceptformat', 'prodversion', 'response', 'x']);
  assert.deepEqual(h.confirmations, [{tabId: 4, message: {type: 'store.confirm'}, options: {documentId: storeDocumentId, frameId: 0}}]);
});

test('Store SPA category document can request A then B only through their current document-bound listings', async t => {
  const h = await worker(t);
  for (const [current, extensionId] of [[`${storeOrigin}/detail/${storeIdA}`, storeIdA], [`${storeOrigin}/detail/other/${storeIdB}/`, storeIdB]]) {
    const sender = storeSender(h, {initial: `${storeOrigin}/category/extensions`, current, extensionId});
    assert.deepEqual(await h.message({type: 'store.install', extensionId}, sender), {ok: true});
  }
  assert.deepEqual(createdStoreURLs(h).map(url => url.searchParams.get('x')),
    [storeIdA, storeIdB].map(id => `id=${id}&installsource=ondemand&uc`));
  assert.equal(h.confirmations.length, 2);
});

test('Store requests reject wrong sender origin, frame, lifecycle or document metadata without installation', async t => {
  const h = await worker(t);
  const sender = storeSender(h);
  for (const replacement of [
    {url: `https://example.com/detail/${storeIdA}`}, {url: `http://chromewebstore.google.com/detail/${storeIdA}`},
    {url: `https://sub.chromewebstore.google.com/detail/${storeIdA}`}, {url: `${storeOrigin}:8443/detail/${storeIdA}`},
    {url: `https://user:pass@chromewebstore.google.com/detail/${storeIdA}`}, {url: 'not a URL'},
    {origin: undefined}, {origin: 'null'}, {origin: 'https://example.com'}, {origin: `${storeOrigin}:8443`},
    {frameId: 1}, {frameId: undefined}, {documentLifecycle: 'cached'}, {documentLifecycle: undefined},
    {documentId: ''}, {documentId: undefined}, {documentId: 17},
    {tab: undefined}, {tab: {}}, {tab: {id: -1}}, {tab: {id: '4'}}, {tab: {id: 4.5}},
  ]) {
    const result = await h.message({type: 'store.install', extensionId: storeIdA}, {...sender, ...replacement});
    assert.match(result.error, /Unsupported/, JSON.stringify(replacement));
  }
  assert.equal(await h.message({type: 'store.install', extensionId: storeIdA}, {...sender, id: 'foreign'}), undefined);
  assert.equal(h.actions.length, 0); assert.equal(h.confirmations.length, 0);
});

test('Store requests reject invalid IDs, stale tab snapshots and fresh noncanonical or nonmatching listings', async t => {
  const h = await worker(t);
  const sender = storeSender(h);
  for (const extensionId of [undefined, null, 123, [storeIdA], {}, 'invalid&x=anything', 'q'.repeat(32), 'a'.repeat(31)]) {
    assert.match((await h.message({type: 'store.install', extensionId}, sender)).error, /Invalid extension ID/);
  }
  for (const current of [`${storeOrigin}/category/extensions`, `${storeOrigin}/detail/${storeIdB}`,
    `${storeOrigin}/other/${storeIdA}`, `${storeOrigin}/detail/${storeIdA}/extra`,
    `http://chromewebstore.google.com/detail/${storeIdA}`, `https://sub.chromewebstore.google.com/detail/${storeIdA}`,
    `${storeOrigin}:8443/detail/${storeIdA}`, `https://user:pass@chromewebstore.google.com/detail/${storeIdA}`]) {
    h.tabs.get(4).url = current;
    assert.match((await h.message({type: 'store.install', extensionId: storeIdA}, sender)).error, /Store detail page changed/);
  }
  h.tabs.get(4).url = sender.tab.url;
  h.tabs.get(4).pendingUrl = `${storeOrigin}/category/themes`;
  assert.match((await h.message({type: 'store.install', extensionId: storeIdA}, sender)).error, /Store detail page changed/);
  delete h.tabs.get(4).pendingUrl;
  assert.match((await h.message({type: 'store.install', extensionId: storeIdA}, {...sender, tab: {id: 4, url: `${storeOrigin}/detail/${storeIdB}`}})).error, /Store detail page changed/);
  assert.equal(h.actions.length, 0); assert.equal(h.confirmations.length, 0);
});

test('Store requests fail closed for a missing tab or navigation while the fresh tab lookup is pending', async t => {
  const h = await worker(t);
  const sender = storeSender(h);
  h.tabs.delete(4);
  assert.match((await h.message({type: 'store.install', extensionId: storeIdA}, sender)).error, /Tab missing/);
  storeSender(h);
  const entered = deferred(), release = deferred();
  h.beforeGet = async () => { entered.resolve(); await release.promise; };
  const pending = h.message({type: 'store.install', extensionId: storeIdA}, sender);
  await entered.promise;
  h.tabs.get(4).url = 'https://example.com/after-navigation';
  release.resolve();
  assert.match((await pending).error, /Store detail page changed/);
  assert.equal(h.actions.length, 0); assert.equal(h.confirmations.length, 0);
});

test('Store document confirmation rejects replacement, mismatch and navigation before the final tab check', async t => {
  const h = await worker(t);
  const sender = storeSender(h);
  h.beforeStoreConfirm = async (_tabId, _message, options) => {
    assert.deepEqual(options, {documentId: storeDocumentId, frameId: 0});
    throw new Error('Receiving end does not exist: original document was replaced.');
  };
  assert.match((await h.message({type: 'store.install', extensionId: storeIdA}, sender)).error, /original document was replaced/);
  h.beforeStoreConfirm = null;
  for (const response of [undefined, {}, {url: sender.tab.url, extensionId: storeIdB},
    {url: `${storeOrigin}/category/extensions`, extensionId: storeIdA},
    {url: `https://example.com/detail/${storeIdA}`, extensionId: storeIdA}]) {
    h.storeResponse = response;
    assert.match((await h.message({type: 'store.install', extensionId: storeIdA}, sender)).error, /Store detail page changed/);
  }
  h.storeResponse = {url: sender.tab.url, extensionId: storeIdA};
  h.beforeStoreConfirm = async () => { h.tabs.get(4).url = 'https://example.com/after-confirmation'; };
  assert.match((await h.message({type: 'store.install', extensionId: storeIdA}, sender)).error, /Store detail page changed/);
  assert.equal(h.actions.length, 0);
});

test('a valid Store sender cannot configure, read or disable agent grants', async t => {
  const h = await worker(t), sender = storeSender(h);
  for (const message of [{type: 'agent.configure', grants: [{tabId: 1, origin: 'https://example.com'}], allowNewTabs: true}, {type: 'agent.status'}, {type: 'agent.disable'}]) {
    assert.match((await h.message(message, sender)).error, /Unsupported/);
  }
  assert.equal(h.ports.length, 0); assert.equal(h.actions.length, 0);
  assert.deepEqual(h.data.agentAccess, {enabled: false, allowNewTabs: false, grants: []});
});

test('real service worker requires internal user grants, excludes incognito and gates every command', async t => {
  const h = await worker(t);
  assert.equal(await h.message({ type: 'agent.configure', grants: [{tabId: 1, origin: 'https://example.com'}], allowNewTabs: false }, { id: 'foreign', url: 'https://example.com' }), undefined);
  assert.match((await h.message({ type: 'agent.configure', grants: [{tabId: 1, origin: 'https://example.com'}], allowNewTabs: false }, { id: h.chrome.runtime.id, url: 'https://example.com' })).error, /Unsupported/);
  assert.deepEqual(await h.configure([1, 2]), { ok: true });
  assert.deepEqual(h.data.agentAccess.grants, [{ tabId: 1, origin: 'https://example.com' }]);
  assert.deepEqual((await h.command('tabs.list')).result, [{ tabId: 1, title: 'Example', url: 'https://example.com/' }]);
  assert.match((await h.command('tab.snapshot', { tabId: 3 })).error.message, /Grant this tab/);
  assert.match((await h.command('tab.navigate', { tabId: 1, url: 'https://other.example/' })).error.message, /Cross-site/);
  assert.match((await h.command('tab.open', { url: 'https://example.com/' })).error.message, /disabled/);
  await h.disable();
  assert.match((await h.command('tab.snapshot', { tabId: 1 })).error.message, /off|revoked/);
});

test('redirected tabs lose origin grants and native disconnect resets control', async t => {
  const h = await worker(t);
  await h.configure();
  h.tabs.get(1).url = 'https://other.example/redirect';
  await h.chrome.tabs.onUpdated.emit(1, { url: h.tabs.get(1).url }, h.tabs.get(1));
  assert.deepEqual(h.data.agentAccess.grants, []);
  assert.match((await h.command('tab.snapshot', { tabId: 1 })).error.message, /Grant this tab/);
  await h.ports[0].onDisconnect.emit();
  await tick();
  assert.deepEqual(h.data.agentAccess, { enabled: false, allowNewTabs: false, grants: [] });
  assert.match(h.data.bridgeError, /disconnected/i);
});

test('a pending grant cannot re-enable control after the user revokes it', async t => {
  const h = await worker(t);
  const entered = deferred(); const release = deferred();
  h.beforeGet = async () => { entered.resolve(); await release.promise; };
  const granting = h.configure();
  await entered.promise;
  await h.disable();
  release.resolve();
  await granting;
  assert.deepEqual(h.data.agentAccess, { enabled: false, allowNewTabs: false, grants: [] });
});

test('tab events cannot publish a stale enabled state after revocation', async t => {
  const h = await worker(t);
  await h.configure();
  h.tabs.get(1).url = 'https://other.example/';
  const updating = h.chrome.tabs.onUpdated.emit(1, { url: h.tabs.get(1).url }, h.tabs.get(1));
  const disabling = h.disable();
  await Promise.all([updating, disabling]);
  assert.equal(h.data.agentAccess.enabled, false);
  assert.deepEqual(h.data.agentAccess.grants, []);
});

test('revocation while fetching a tab prevents injection', async t => {
  const h = await worker(t);
  await h.configure();
  const entered = deferred(); const release = deferred();
  h.beforeGet = async () => { entered.resolve(); await release.promise; };
  const command = h.command('tab.snapshot', { tabId: 1 });
  await entered.promise;
  await h.disable();
  release.resolve();
  assert.match((await command).error.message, /off|revoked|Grant this tab/);
  assert.equal(h.actions.filter(action => action.inject).length, 0);
});

test('native disconnect cancels pending grants and permission removal revokes existing grants', async t => {
  const h = await worker(t);
  await h.configure();
  const entered = deferred(); const release = deferred();
  h.beforeGet = async () => { entered.resolve(); await release.promise; };
  const configuring = h.configure();
  await entered.promise;
  await h.ports[0].onDisconnect.emit();
  release.resolve();
  await configuring;
  assert.equal(h.data.agentAccess.enabled, false);
  h.beforeGet = null;
  await h.configure();
  await h.chrome.permissions.onRemoved.emit({origins: ['https://example.com/*']});
  assert.deepEqual(h.data.agentAccess, {enabled: false, allowNewTabs: false, grants: []});
});

test('revocation drops an in-flight page result and cleans up only the agent-created tab', async t => {
  const h = await worker(t);
  await h.configure();
  const entered = deferred(); const release = deferred();
  h.beforeInject = async () => { entered.resolve(); await release.promise; };
  const snapshot = h.command('tab.snapshot', {tabId: 1});
  await entered.promise;
  await h.disable();
  release.resolve();
  const blocked = await snapshot;
  assert.match(blocked.error.message, /revoked/);
  assert.equal(blocked.result, undefined);
  h.beforeInject = null;
  await h.configure([], true);
  const created = deferred(); const finishCreate = deferred();
  h.afterCreate = async tab => { created.resolve(tab.id); await finishCreate.promise; };
  const opening = h.command('tab.open', {url: 'https://example.com/new'});
  const createdId = await created.promise;
  await h.disable();
  finishCreate.resolve();
  assert.match((await opening).error.message, /revoked/);
  assert.equal(h.tabs.has(createdId), false);
  assert.deepEqual([...h.tabs.keys()], [1, 2, 3]);
});

test('concurrent tab removals clear both grants without restoring stale state', async t => {
  const h = await worker(t);
  h.allowed.add('https://other.example/*');
  await h.configure([1, 3]);
  await Promise.all([h.chrome.tabs.onRemoved.emit(1), h.chrome.tabs.onRemoved.emit(3)]);
  assert.deepEqual(h.data.agentAccess.grants, []);
});

test('native status messages never execute page actions and ready reflects the actual connection', async t => {
  const h = await worker(t);
  await h.configure();
  assert.equal(h.data.bridgeConnected, false);
  await h.ports[0].onMessage.emit({type: 'ready'});
  await h.ports[0].onMessage.emit({type: 'stateApplied', enabled: true, grantCount: 1});
  assert.equal(h.data.bridgeConnected, true);
  assert.equal(h.actions.length, 0);
});

function snapshotPage() {
  const make = (text, { sensitive = false, visible = true, visibility = 'visible' } = {}) => ({ textContent: text, parentElement: { closest: () => sensitive, getClientRects: () => visible ? [{}] : [], style: { display: visible ? 'block' : 'none', visibility } } });
  const nodes = [make('Public heading'), make('CSS hidden secret', { visible: false }), make('Invisible secret', { visibility: 'hidden' }), make('Password secret', { sensitive: true }), make('Textarea secret', { sensitive: true })];
  const document = {
    title: 'Example', body: {},
    createTreeWalker(_root, _type, filter) { const accepted = nodes.filter(node => filter.acceptNode(node) === 1); return { nextNode: () => accepted.shift() || null }; },
    querySelectorAll() { return []; },
  };
  return { document, location: { origin: 'https://example.com', href: 'https://example.com/' }, NodeFilter: { SHOW_TEXT: 4, FILTER_ACCEPT: 1, FILTER_REJECT: 2 }, getComputedStyle: element => element.style };
}

test('actual injected snapshot omits hidden text and editable field contents and checks current origin', async t => {
  const h = await worker(t);
  await h.configure();
  h.page = snapshotPage();
  const snapshot = await h.command('tab.snapshot', { tabId: 1 });
  assert.equal(snapshot.result.text, 'Public heading');
  assert.doesNotMatch(JSON.stringify(snapshot.result), /secret/);
  h.page.location.origin = 'https://attacker.example';
  assert.match((await h.command('tab.snapshot', { tabId: 1 })).error.message, /changed origin/);
});

test('snapshot metadata excludes invisible and sensitive controls and actions reject those fields', async t => {
  const h = await worker(t);
  await h.configure();
  h.page = snapshotPage();
  const makeElement = ({label, tag = 'input', type = 'text', hidden = false, sensitive = false}) => ({
    tagName: tag.toUpperCase(), type, id: label, name: label, parentElement: null,
    innerText: label, href: 'https://example.com/visible', value: 'Do not expose this value',
    style: {display: 'block', visibility: hidden ? 'hidden' : 'visible'},
    getClientRects: () => [{}],
    matches: () => type === 'password' || type === 'file' || type === 'hidden',
    closest: selector => sensitive && selector.includes('autocomplete') ? {} : null,
    getAttribute: () => label,
  });
  const normal = makeElement({label: 'Public field'});
  const invisible = makeElement({label: 'Invisible secret', hidden: true});
  const password = makeElement({label: 'Password secret', type: 'password'});
  const card = makeElement({label: 'Card secret', sensitive: true});
  const visibleLink = makeElement({label: 'Public link', tag: 'a'});
  const hiddenLink = makeElement({label: 'Hidden link secret', tag: 'a', hidden: true});
  h.page.document.querySelectorAll = selector => selector === 'a[href]' ? [visibleLink, hiddenLink] : [normal, invisible, password, card];
  const snapshot = await h.command('tab.snapshot', {tabId: 1});
  assert.deepEqual(snapshot.result.controls.map(value => value.label), ['Public field']);
  assert.deepEqual(snapshot.result.links.map(value => value.text), ['Public link']);
  assert.doesNotMatch(JSON.stringify(snapshot.result), /secret|Do not expose/);
  for (const field of [invisible, password, card]) {
    h.page.document.querySelector = () => field;
    assert.ok((await h.command('tab.click', {tabId: 1, selector: 'input'})).error);
  }
});

class UIElement {
  children = []; dataset = {}; style = { setProperty() {} }; checked = false; value = ''; textContent = ''; open = false;
  classList = { toggle() {} };
  constructor(tagName = 'div') { this.tagName = tagName.toUpperCase(); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute() {}
  showModal() { this.open = true; }
  close() { this.open = false; }
}

async function newtabUI(t, h) {
  const originals = { document: globalThis.document, location: globalThis.location, fetch: globalThis.fetch };
  t.after(() => Object.assign(globalThis, originals));
  const elements = new Map();
  const element = id => { if (!elements.has(id)) elements.set(id, new UIElement()); return elements.get(id); };
  globalThis.document = {
    documentElement: new UIElement(), body: new UIElement(),
    getElementById: element, createElement: tag => new UIElement(tag),
    querySelectorAll(selector) {
      if (selector === '#tabChoices input:checked') return element('tabChoices').children.flatMap(label => label.children).filter(child => child.tagName === 'INPUT' && child.checked);
      return [];
    },
  };
  globalThis.location = { hash: '' };
  globalThis.fetch = async () => ({ json: async () => ({}) });
  await import(new URL(`../extension/newtab.js?agent-ui-test=${++loadId}`, import.meta.url));
  return element;
}

test('newtab requests website permission from the click before configuring selected tabs and revokes access', async t => {
  const h = await worker(t);
  const element = await newtabUI(t, h);
  await element('openAgents').onclick();
  assert.equal(element('tabChoices').children.length, 2, 'incognito tab is absent');
  element('tabChoices').children[0].children[0].checked = true;
  await element('grantAgents').onclick();
  assert.deepEqual(h.actions[0], { request: ['https://example.com/*'] });
  assert.deepEqual(h.messages.find(message => message.type === 'agent.configure'), {type: 'agent.configure', grants: [{tabId: 1, origin: 'https://example.com'}], allowNewTabs: false});
  assert.equal(h.data.agentAccess.enabled, true);
  assert.deepEqual(h.data.agentAccess.grants, [{ tabId: 1, origin: 'https://example.com' }]);
  await element('revokeAgents').onclick();
  assert.equal(h.data.agentAccess.enabled, false);
  h.requestGranted = false;
  await element('grantAgents').onclick();
  assert.equal(h.data.agentAccess.enabled, false);
  assert.match(element('agentToast').textContent, /not granted/);
});

for (const retainedPermission of ['https://other.example/*', 'https://*/*']) {
  test(`newtab keeps the displayed origin binding after navigation despite ${retainedPermission}`, async t => {
    const h = await worker(t);
    h.allowed.add(retainedPermission);
    const element = await newtabUI(t, h);
    await element('openAgents').onclick();
    const checkbox = element('tabChoices').children[0].children[0];
    checkbox.checked = true;
    assert.equal(checkbox.dataset.origin, 'https://example.com');
    h.tabs.get(1).url = 'https://other.example/account';
    await element('grantAgents').onclick();
    assert.deepEqual(h.messages.find(message => message.type === 'agent.configure'), {
      type: 'agent.configure', grants: [{tabId: 1, origin: 'https://example.com'}], allowNewTabs: false,
    });
    assert.equal(h.data.agentAccess.enabled, false);
    assert.deepEqual(h.data.agentAccess.grants, []);
    assert.ok(element('agentToast').textContent, 'the stale selection needs a visible error');
    const refreshed = element('tabChoices').children[0].children[0];
    assert.equal(refreshed.dataset.origin, 'https://other.example');
    assert.equal(refreshed.checked, false, 'the new origin needs a fresh user selection');
    assert.equal(h.sent.some(message => message.type === 'state' && message.enabled), false);
  });
}

test('newtab preserves the displayed origin while its website permission request is pending', async t => {
  const h = await worker(t);
  h.allowed.add('https://other.example/*');
  const element = await newtabUI(t, h);
  await element('openAgents').onclick();
  element('tabChoices').children[0].children[0].checked = true;
  const entered = deferred(), release = deferred();
  t.after(() => release.resolve());
  h.beforeRequest = async () => { entered.resolve(); await release.promise; };
  const granting = element('grantAgents').onclick();
  await entered.promise;
  h.tabs.get(1).url = 'https://other.example/after-permission-prompt';
  release.resolve();
  await granting;
  assert.deepEqual(h.messages.find(message => message.type === 'agent.configure').grants,
    [{tabId: 1, origin: 'https://example.com'}]);
  assert.equal(h.data.agentAccess.enabled, false);
  assert.deepEqual(h.data.agentAccess.grants, []);
});

test('worker rejects malformed grants and the obsolete tabIds-only configuration contract', async t => {
  const h = await worker(t);
  for (const grants of [undefined, null, {}, '1', [null], [1], [{}], [{tabId: 1}],
    [{tabId: 1, origin: undefined}], [{tabId: 1, origin: null}], [{tabId: 1, origin: 42}],
    [{tabId: -1, origin: 'https://example.com'}], [{tabId: 1.5, origin: 'https://example.com'}],
    [{tabId: '1', origin: 'https://example.com'}],
    [{tabId: 1, origin: 'https://example.com'}, {tabId: 1, origin: 'https://example.com'}],
  ]) {
    assert.ok((await h.message({type: 'agent.configure', grants, allowNewTabs: false})).error,
      `malformed grants must reject: ${JSON.stringify(grants)?.slice(0, 180)}`);
  }
  assert.ok((await h.message({type: 'agent.configure', tabIds: [1], allowNewTabs: false})).error);
  assert.deepEqual(h.data.agentAccess.grants, []);
  assert.equal(h.data.agentAccess.enabled, false);
  assert.equal(h.sent.some(message => message.type === 'state' && message.enabled), false);
});

test('worker requires the exact canonical HTTP(S) origin displayed for a grant', async t => {
  const h = await worker(t);
  for (const origin of ['not a URL', 'null', 'file:///tmp/page', 'chrome://settings',
    'https://user:pass@example.com', 'https://example.com/', 'https://example.com/path',
    'https://example.com?query=1', 'https://example.com#fragment', 'HTTPS://EXAMPLE.COM', 'https://example.com:443']) {
    assert.ok((await h.message({type: 'agent.configure', grants: [{tabId: 1, origin}], allowNewTabs: false})).error, origin);
  }
  assert.deepEqual(await h.configure(), {ok: true});
  assert.deepEqual(h.data.agentAccess.grants, [{tabId: 1, origin: 'https://example.com'}]);
});

test('worker refuses a changed or unpermitted destination even when the request binds its former origin', async t => {
  const h = await worker(t);
  const grants = [{tabId: 1, origin: 'https://example.com'}];
  h.tabs.get(1).url = 'https://other.example/account';
  assert.ok((await h.message({type: 'agent.configure', grants, allowNewTabs: false})).error);
  assert.ok((await h.configure()).error, 'the actual destination also needs its own host permission');
  assert.deepEqual(h.data.agentAccess.grants, []);
  assert.equal(h.data.agentAccess.enabled, false);
});

test('worker rejects navigation that happens while checking website permission', async t => {
  const h = await worker(t);
  h.allowed.add('https://other.example/*');
  const entered = deferred(), release = deferred();
  t.after(() => release.resolve());
  let checks = 0;
  h.beforeContains = async () => { if (++checks === 1) { entered.resolve(); await release.promise; } };
  const granting = h.configure();
  await entered.promise;
  h.tabs.get(1).url = 'https://other.example/changed-during-check';
  release.resolve();
  assert.ok((await granting).error);
  assert.deepEqual(h.data.agentAccess.grants, []);
  assert.equal(h.data.agentAccess.enabled, false);
  assert.equal(h.sent.some(message => message.type === 'state' && message.enabled), false);
});

test('worker revalidates the current tab before the serialized grant commit', async t => {
  const h = await worker(t);
  h.allowed.add('https://other.example/*');
  let reads = 0;
  h.beforeGet = async tabId => {
    if (tabId === 1 && ++reads === 2) h.tabs.get(1).url = 'https://other.example/changed-before-commit';
  };
  assert.ok((await h.configure()).error);
  assert.ok(reads >= 2, 'a fresh tab lookup is required at commit');
  assert.deepEqual(h.data.agentAccess.grants, []);
  assert.equal(h.data.agentAccess.enabled, false);
  assert.equal(h.sent.some(message => message.type === 'state' && message.enabled), false);
});

test('worker rejects pending navigation at the initial check and the final commit', async t => {
  const h = await worker(t);
  for (const pendingUrl of ['https://other.example/destination', 'https://example.com/new-document']) {
    h.tabs.get(1).pendingUrl = pendingUrl;
    assert.ok((await h.configure()).error, pendingUrl);
    assert.deepEqual(h.data.agentAccess.grants, []);
  }
  delete h.tabs.get(1).pendingUrl;
  let reads = 0;
  h.beforeGet = async tabId => {
    if (tabId === 1 && ++reads === 2) h.tabs.get(1).pendingUrl = 'https://example.com/late-navigation';
  };
  assert.ok((await h.configure()).error);
  assert.ok(reads >= 2);
  assert.equal(h.data.agentAccess.enabled, false);
  assert.deepEqual(h.data.agentAccess.grants, []);
});

test('a multi-tab configuration fails atomically when any selected origin is stale', async t => {
  const h = await worker(t);
  h.allowed.add('https://other.example/*');
  const grants = [{tabId: 1, origin: 'https://example.com'}, {tabId: 3, origin: 'https://other.example'}];
  h.tabs.get(3).url = 'https://example.com/changed-second-tab';
  assert.ok((await h.message({type: 'agent.configure', grants, allowNewTabs: false})).error);
  assert.deepEqual(h.data.agentAccess.grants, []);
  assert.equal(h.data.agentAccess.enabled, false);
  assert.equal(h.sent.some(message => message.type === 'state' && message.enabled), false);
  h.tabs.get(3).url = 'https://other.example/unchanged';
  assert.deepEqual(await h.message({type: 'agent.configure', grants, allowNewTabs: false}), {ok: true});
  assert.deepEqual(h.data.agentAccess.grants, grants);
});

test('revocation during a pending website-permission check prevents grant publication', async t => {
  const h = await worker(t);
  const entered = deferred(), release = deferred();
  t.after(() => release.resolve());
  h.beforeContains = async () => { entered.resolve(); await release.promise; };
  const granting = h.configure();
  await entered.promise;
  const revoking = h.disable();
  release.resolve();
  const [result] = await Promise.all([granting, revoking]);
  assert.ok(result.error);
  assert.equal(h.data.agentAccess.enabled, false);
  assert.deepEqual(h.data.agentAccess.grants, []);
  assert.equal(h.sent.some(message => message.type === 'state' && message.enabled), false);
});

test('worker requires an explicit boolean for the new-tab grant setting', async t => {
  const h = await worker(t);
  for (const allowNewTabs of [undefined, null, 0, 1, '', 'false', [], {}]) {
    assert.ok((await h.message({type: 'agent.configure', grants: [{tabId: 1, origin: 'https://example.com'}], allowNewTabs})).error);
  }
  assert.equal(h.data.agentAccess.enabled, false);
  assert.deepEqual(h.data.agentAccess.grants, []);
});

test('a tab accepted initially cannot become incognito before the final grant commit', async t => {
  const h = await worker(t);
  let reads = 0;
  h.beforeGet = async tabId => { if (tabId === 1 && ++reads === 2) h.tabs.get(1).incognito = true; };
  assert.ok((await h.configure()).error);
  assert.ok(reads >= 2);
  assert.equal(h.data.agentAccess.enabled, false);
  assert.deepEqual(h.data.agentAccess.grants, []);
});

// A deliberately small DOM shim, not a browser selector engine. Interpret the
// relevant attribute operators independently so exact-match, token-match and
// case-folding regressions exercise the actual injected production function.
function sensitiveFieldPage() {
  const attributeSelector = /^([a-z]+)?(?:\[([\w-]+)(?:(~=|\*=|=)(?:"([^"]*)"|'([^']*)'|([^\]\s]+))(?:\s+(i))?)?\])?$/i;
  const matches = (element, selector) => selector.split(',').some(part => {
    const match = part.trim().match(attributeSelector);
    assert.ok(match, `Unsupported selector in the deterministic DOM fixture: ${part}`);
    const [, tag, attribute, operator, doubleQuoted, singleQuoted, bare, insensitive] = match;
    if (tag && tag.toUpperCase() !== element.tagName) return false;
    if (!attribute) return true;
    let value = element.getAttribute(attribute);
    if (value === null) return false;
    if (!operator) return true;
    let expected = doubleQuoted ?? singleQuoted ?? bare;
    if (insensitive) { value = value.toLowerCase(); expected = expected.toLowerCase(); }
    if (operator === '=') return value === expected;
    if (operator === '*=') return value.includes(expected);
    return value.split(/[\t\n\f\r ]+/).includes(expected);
  });
  class Element {
    constructor(tag, id, autocomplete = '') {
      this.tagName = tag.toUpperCase(); this.id = id; this.name = id;
      this.attributes = {autocomplete}; this.parentElement = null;
      this.style = {display: 'block', visibility: 'visible', opacity: '1'};
      this.innerText = ''; this.placeholder = id; this.disabled = false; this.readOnly = false;
    }
    getAttribute(name) { return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null; }
    getClientRects() { return [{}]; }
    matches(selector) { return matches(this, selector); }
    closest(selector) {
      for (let current = this; current; current = current.parentElement) if (current.matches(selector)) return current;
      return null;
    }
    click() { this.clicks = (this.clicks || 0) + 1; }
    dispatchEvent(event) { (this.events ||= []).push(event.type); }
  }
  class Input extends Element {
    constructor(id, autocomplete) { super('input', id, autocomplete); this.type = 'text'; this.attributes.type = 'text'; this._value = 'SYNTHETIC_FIELD_VALUE'; }
    get value() { return this._value; }
    set value(value) { this._value = value; }
  }
  const sensitive = [
    'one-time-code', 'section-login one-time-code', 'section-login\tone-time-code',
    '  SECTION-LOGIN\nONE-TIME-CODE\r ', 'section-login\fone-time-code',
    'one-time-code webauthn', 'NEW-PASSWORD', 'section-login CURRENT-PASSWORD',
    'SECTION-CHECKOUT CC-NUMBER',
  ].map((autocomplete, index) => new Input(`private-${index}`, autocomplete));
  const nested = new Input('private-ancestor', '');
  nested.parentElement = new Element('div', 'otp-section', 'section-login ONE-TIME-CODE');
  sensitive.push(nested);
  const normal = [new Input('public-email', 'section-login email'), new Input('public-similar-token', 'one-time-code-extra')];
  const fields = [...sensitive, ...normal];
  const document = {
    title: 'Synthetic form', body: {},
    createTreeWalker() { return {nextNode: () => null}; },
    querySelectorAll(selector) { assert.ok(['a[href]', 'button,input,textarea,select'].includes(selector)); return selector === 'a[href]' ? [] : fields; },
    querySelector(selector) { return fields.find(element => selector === `#${element.id}`) || null; },
  };
  return {sensitive, normal, page: {
    document, location: {origin: 'https://example.com', href: 'https://example.com/'},
    NodeFilter: {SHOW_TEXT: 4, FILTER_ACCEPT: 1, FILTER_REJECT: 2}, getComputedStyle: element => element.style,
    HTMLInputElement: Input, HTMLTextAreaElement: class {}, Event: class {constructor(type) {this.type = type;}},
  }};
}

test('tokenized and case-insensitive sensitive fields are absent from snapshots and reject click/type', async t => {
  const h = await worker(t);
  await h.configure();
  const fixture = sensitiveFieldPage();
  h.page = fixture.page;
  const snapshot = await h.command('tab.snapshot', {tabId: 1});
  assert.deepEqual(snapshot.result.controls.map(control => control.id), fixture.normal.map(element => element.id));
  assert.doesNotMatch(JSON.stringify(snapshot.result), /private-|SYNTHETIC_FIELD_VALUE/);
  for (const element of fixture.sensitive) {
    for (const action of ['tab.click', 'tab.type']) {
      const params = {tabId: 1, selector: `#${element.id}`, ...(action === 'tab.type' ? {text: '123456'} : {})};
      const result = await h.command(action, params);
      assert.match(result.error?.message || '', /password, payment, file, or verification-code fields/, `${element.getAttribute('autocomplete')} ${action}`);
      assert.equal(element.value, 'SYNTHETIC_FIELD_VALUE');
      assert.equal(element.clicks || 0, 0);
      assert.equal(element.events, undefined);
    }
  }
});

test('ordinary text fields and similar non-sensitive tokens remain usable without returning their values', async t => {
  const h = await worker(t);
  await h.configure();
  const fixture = sensitiveFieldPage();
  h.page = fixture.page;
  for (const element of fixture.normal) {
    assert.deepEqual((await h.command('tab.click', {tabId: 1, selector: `#${element.id}`})).result, {clicked: true});
    assert.deepEqual((await h.command('tab.type', {tabId: 1, selector: `#${element.id}`, text: 'Ordinary text'})).result, {typed: 13});
    assert.equal(element.value, 'Ordinary text');
    assert.equal(element.clicks, 1);
    assert.deepEqual(element.events, ['input', 'change']);
  }
  assert.doesNotMatch(JSON.stringify((await h.command('tab.snapshot', {tabId: 1})).result), /Ordinary text|SYNTHETIC_FIELD_VALUE/);
});

test('download scanner status is read-only and restricted to the exact Kumo settings page', async t => {
  const h = await worker(t);
  const native = [];
  h.chrome.runtime.sendNativeMessage = async (name, payload) => {
    native.push({name, payload});
    return {id: payload.id, installed: false, available: false, reason: 'setup-required'};
  };
  for (const url of ['https://example.com/', 'https://chromewebstore.google.com/detail/fixture', h.chrome.runtime.getURL('popup.html')]) {
    assert.match((await h.message({type: 'downloadProtection.status'}, {id: h.chrome.runtime.id, url})).error, /Kumo settings/);
  }
  assert.match((await h.message({type: 'downloadProtection.status', path: '/private/test-file'})).error, /Kumo settings/);
  assert.equal(native.length, 0);
  assert.deepEqual(await h.message({type: 'downloadProtection.status'}), {id: 'settings-status', installed: false, available: false, reason: 'setup-required'});
  assert.deepEqual(native, [{name: 'com.kumo.malware', payload: {id: 'settings-status', type: 'status'}}]);
});
