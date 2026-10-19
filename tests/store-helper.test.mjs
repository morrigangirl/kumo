import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';

const source = readFileSync(new URL('../extension/store.js', import.meta.url), 'utf8');
const idA = 'a'.repeat(32), idB = 'b'.repeat(32);
const store = 'https://chromewebstore.google.com';
const helperId = 'eldkgppmnhligdekahicdcdndcoongio';
const background = `chrome-extension://${helperId}/background.js`;

function fixture(url, send = async () => ({ok: true}), rootReady = true) {
  const nodes = [], timers = [], mutations = [], microtasks = [], messages = [], listeners = [];
  const location = {href: url};
  const root = {append(node) { nodes.push(node); node.isConnected = true; }};
  const document = {
    documentElement: rootReady ? root : null,
    createElement() {
      const handlers = new Map();
      return {style: {}, disabled: false, isConnected: false,
        addEventListener(name, fn) { handlers.set(name, fn); },
        remove() { const index = nodes.indexOf(this); if (index >= 0) nodes.splice(index, 1); this.isConnected = false; },
        click(trusted = true) { return handlers.get('click')?.({isTrusted: trusted}); }};
    },
  };
  const context = vm.createContext({URL, location, document,
    chrome: {runtime: {id: helperId, getURL: value => `chrome-extension://${helperId}/${value}`,
      onMessage: {addListener(listener) { listeners.push(listener); }}, async sendMessage(message) {
      messages.push(JSON.parse(JSON.stringify(message))); return send(message);
    }}},
    MutationObserver: class { constructor(callback) { mutations.push(callback); } observe() {} },
    queueMicrotask(fn) { microtasks.push(fn); },
    addEventListener() {}, setInterval(fn, interval) { timers.push({fn, interval}); },
  });
  vm.runInContext(source, context);
  const flush = () => { while (microtasks.length) microtasks.shift()(); };
  return {nodes, messages, timers,
    confirm(message = {type: 'store.confirm'}, sender = {id: helperId, url: background}) {
      const responses = [];
      listeners.forEach(listener => listener(message, sender, response => responses.push(JSON.parse(JSON.stringify(response)))));
      return responses;
    },
    route(next, notify = true) { location.href = next; if (notify) mutations.forEach(fn => fn()); flush(); },
    tick() { timers.forEach(timer => timer.fn()); flush(); },
    ready() { document.documentElement = root; mutations.forEach(fn => fn()); flush(); },
    mutate() { mutations.forEach(fn => fn()); flush(); },
    reinject() { vm.runInContext(source, context); },
  };
}

test('Store helper recognizes only canonical detail paths and IDs', () => {
  for (const url of [`${store}/detail/${idA}`, `${store}/detail/a-name/${idA}/?hl=en#reviews`, `${store}:443/detail/${idA}`]) {
    const f = fixture(url);
    assert.equal(f.nodes.length, 1, url);
    assert.equal(f.nodes[0].id, 'kumo-store-install');
    assert.equal(f.nodes[0].type, 'button');
  }
  for (const url of [`${store}/category/extensions`, `${store}/detail/${idA}/extra`, `${store}/other/${idA}`,
    `${store}/detail/${'q'.repeat(32)}`, `${store}/detail/${'a'.repeat(31)}`, `${store}/detail/x/y/${idA}`,
    `http://chromewebstore.google.com/detail/${idA}`, `https://sub.chromewebstore.google.com/detail/${idA}`,
    `${store}:8443/detail/${idA}`, `https://user:pass@chromewebstore.google.com/detail/${idA}`,
    `https://chrome.google.com/detail/${idA}`, `https://example.com/detail/${idA}`]) {
    assert.equal(fixture(url).nodes.length, 0, url);
  }
});

test('same-document routing creates, replaces and removes exactly one helper', async () => {
  const f = fixture(`${store}/category/extensions`);
  assert.equal(f.nodes.length, 0);
  f.route(`${store}/detail/${idA}`, false);
  assert.equal(f.nodes.length, 0);
  f.tick();
  assert.equal(f.nodes.length, 1);
  const first = f.nodes[0];
  await first.click();
  f.route(`${store}/detail/name/${idB}`);
  assert.equal(f.nodes.length, 1);
  assert.notEqual(f.nodes[0], first);
  await f.nodes[0].click();
  assert.deepEqual(f.messages.map(message => message.extensionId), [idA, idB]);
  f.route(`${store}/category/themes`);
  assert.equal(f.nodes.length, 0);
});

test('untrusted and stale-route clicks never request installation', async () => {
  const f = fixture(`${store}/detail/${idA}`);
  const old = f.nodes[0];
  await old.click(false);
  f.route(`${store}/detail/${idB}`, false);
  await old.click();
  assert.equal(f.messages.length, 0);
  assert.equal(f.nodes.length, 1);
  await f.nodes[0].click();
  assert.deepEqual(f.messages, [{type: 'store.install', extensionId: idB}]);
});

test('a reply from the previous route cannot change the new helper', async () => {
  let resolve;
  const f = fixture(`${store}/detail/${idA}`, () => new Promise(done => { resolve = done; }));
  const old = f.nodes[0];
  const pending = old.click();
  assert.equal(old.disabled, true);
  f.route(`${store}/detail/${idB}`);
  const current = f.nodes[0];
  resolve({error: 'previous-route result'});
  await pending;
  assert.equal(current.textContent, 'Install in Kumo');
  assert.equal(current.disabled, false);
});

test('document-start without a root, DOM replacement and reinjection remain stable', () => {
  const f = fixture(`${store}/detail/${idA}`, undefined, false);
  assert.equal(f.nodes.length, 0);
  f.ready();
  assert.equal(f.nodes.length, 1);
  f.nodes[0].remove();
  f.mutate();
  f.reinject();
  assert.equal(f.nodes.length, 1);
  assert.equal(f.timers.length, 1);
  assert.equal(f.timers[0].interval, 1000);
});

test('runtime errors use a fixed retry message and restore the helper', async () => {
  const f = fixture(`${store}/detail/${idA}`, async () => { throw new Error('private implementation detail'); });
  await f.nodes[0].click();
  assert.equal(f.nodes[0].textContent, 'Could not request installation. Try again.');
  assert.equal(f.nodes[0].disabled, false);
});

test('document confirmation returns only the current public URL and ID to its own background worker', () => {
  const f = fixture(`${store}/category/extensions`);
  assert.deepEqual(f.confirm(), [{url: `${store}/category/extensions`, extensionId: null}]);
  f.route(`${store}/detail/${idA}`);
  const button = f.nodes[0];
  assert.deepEqual(f.confirm(), [{url: `${store}/detail/${idA}`, extensionId: idA}]);
  assert.equal(f.nodes[0], button); assert.equal(button.disabled, false);
  f.route(`${store}/detail/name/${idB}`);
  assert.deepEqual(f.confirm(), [{url: `${store}/detail/name/${idB}`, extensionId: idB}]);
  assert.equal(f.messages.length, 0, 'Read-only confirmation cannot request an install.');
});

test('document confirmation ignores wrong message types and non-background senders', () => {
  const f = fixture(`${store}/detail/${idA}`), own = {id: helperId, url: background};
  for (const message of [null, {}, {type: 'store.install'}, {type: 'agent.configure'}]) assert.deepEqual(f.confirm(message, own), []);
  for (const sender of [
    {id: 'foreign', url: background}, {id: helperId},
    {id: helperId, url: `chrome-extension://${helperId}/newtab.html`},
    {id: helperId, url: `${store}/detail/${idA}`},
    {id: helperId, url: background, tab: {id: 4}},
  ]) assert.deepEqual(f.confirm({type: 'store.confirm'}, sender), []);
  assert.equal(f.nodes.length, 1); assert.equal(f.messages.length, 0);
});
