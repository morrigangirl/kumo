import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';

const source = await readFile(new URL('../extension/phishing-content.js', import.meta.url), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
class TextNode {
  nodeType = 3;
  constructor(text) { this.nodeValue = text; }
}
class Element {
  nodeType = 1;
  children = [];
  constructor(name, attributes = {}, ...children) {
    this.localName = name;
    this.attributes = attributes;
    this.append(...children);
  }
  append(...children) {
    for (const value of children) {
      const node = typeof value === 'string' ? new TextNode(value) : value;
      const previous = this.children.at(-1);
      if (previous) previous.nextSibling = node;
      node.parentNode = this; node.nextSibling = null;
      this.children.push(node);
    }
    this.firstChild = this.children[0] || null;
    return this;
  }
  getAttribute(name) { return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null; }
  get hidden() { return Object.hasOwn(this.attributes, 'hidden'); }
  get isContentEditable() { return this.attributes.contenteditable === '' || this.attributes.contenteditable === 'true'; }
  checkVisibility() {
    for (let node = this; node; node = node.parentNode) {
      if (node.hidden || node.attributes?.style === 'display:none' || node.attributes?.style === 'visibility:hidden') return false;
    }
    return this.attributes.type !== 'hidden';
  }
  get value() { throw new Error('Private field value was read'); }
  get checked() { throw new Error('Private field state was read'); }
  get textContent() { throw new Error('Unbounded textContent was read'); }
  get innerText() { throw new Error('Unbounded innerText was read'); }
  get outerHTML() { throw new Error('Raw HTML was read'); }
}
const el = (name, attributes = {}, ...children) => new Element(name, attributes, ...children);

function fixture({url = 'https://example.com/login?token=URL_SECRET#FRAGMENT_SECRET', children = [], frame = false, visibility = 'visible'} = {}) {
  let now = 0, nextTimer = 0, response;
  const timers = new Map(), events = new Map(), sent = [], listeners = [], observers = [];
  const document = {documentElement: el('html', {}, ...children), visibilityState: visibility};
  for (const key of ['cookie', 'forms', 'activeElement']) Object.defineProperty(document, key, {get() { throw new Error(`Private document.${key} read`); }});
  const location = {href: url};
  const window = {};
  window.top = frame ? {} : window;
  const chrome = {runtime: {
    id: 'k'.repeat(32), getURL: path => `chrome-extension://${'k'.repeat(32)}/${path}`,
    onMessage: {addListener(listener) { listeners.push(listener); }, removeListener(listener) { const index = listeners.indexOf(listener); if (index >= 0) listeners.splice(index, 1); }},
    sendMessage(message) { sent.push(structuredClone(message)); return Promise.resolve(typeof response === 'function' ? response(message) : response); },
  }};
  const addTimer = (callback, delay, interval = null) => {
    const id = ++nextTimer; timers.set(id, {callback, at: now + Math.max(0, delay), interval}); return id;
  };
  const context = vm.createContext({window, location, document, chrome, URL, TextEncoder,
    Date: class extends Date { static now() { return now; } },
    setTimeout: (callback, delay) => addTimer(callback, delay), clearTimeout: id => timers.delete(id),
    setInterval: (callback, delay) => addTimer(callback, delay, delay), clearInterval: id => timers.delete(id),
    addEventListener(name, listener) { if (!events.has(name)) events.set(name, []); events.get(name).push(listener); },
    removeEventListener(name, listener) { const list = events.get(name) || []; const index = list.indexOf(listener); if (index >= 0) list.splice(index, 1); },
    MutationObserver: class {
      constructor(callback) { this.callback = callback; observers.push(this); }
      observe(target, options) { this.target = target; this.options = options; this.connected = true; }
      disconnect() { this.connected = false; }
    },
    getComputedStyle: () => ({display: 'block', visibility: 'visible', opacity: '1'}),
  });
  for (const key of ['localStorage', 'sessionStorage', 'navigator', 'fetch', 'XMLHttpRequest']) {
    Object.defineProperty(context, key, {get() { throw new Error(`${key} is forbidden`); }});
  }
  const run = () => vm.runInContext(source, context, {timeout: 1500});
  run();
  return {context, document, location, sent, chrome, observers, listeners, run, timers,
    setResponse(value) { response = value; },
    emit(name, event = {}) { for (const listener of events.get(name) || []) listener(event); },
    mutate() { for (const observer of observers) if (observer.connected) observer.callback([]); },
    advance(milliseconds) {
      const target = now + milliseconds;
      let count = 0;
      while (true) {
        const entry = [...timers.entries()].filter(([, timer]) => timer.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
        if (!entry) break;
        if (++count > 1000) throw new Error('Timer loop');
        const [id, timer] = entry;
        now = timer.at;
        if (timer.interval === null) timers.delete(id); else timer.at += timer.interval;
        timer.callback();
      }
      now = target;
    },
  };
}

test('actual isolated script produces upstream-style structure and never reads private fields or page APIs', () => {
  const input = el('input', {type: 'password', name: 'PRIVATE_NAME', placeholder: 'PRIVATE_PLACEHOLDER', value: 'PRIVATE_PASSWORD'});
  const originalGet = input.getAttribute.bind(input);
  input.getAttribute = name => {
    assert.ok(!['name', 'placeholder', 'value', 'checked', 'text'].includes(name), `Private ${name} was read`);
    return originalGet(name);
  };
  const h = fixture({children: [
    el('head', {}, el('title', {}, 'Example login'), el('script', {src: 'https://secret.example/?key=SCRIPT_SOURCE'}, 'SCRIPT_BODY_SECRET')),
    el('body', {},
      el('h1', {}, 'Sign in to Example'),
      el('form', {name: 'PRIVATE_FORM_NAME', action: '/?session=FORM_ACTION_SECRET'},
        el('p', {}, 'PRIVATE_FORM_TEXT'), input,
        el('input', {type: 'checkbox', checked: 'PRIVATE_CHECKED'}),
        el('button', {onclick: 'HANDLER_SECRET'}, 'PRIVATE_FORM_BUTTON')),
      el('textarea', {}, 'PRIVATE_TEXTAREA'), el('select', {}, el('option', {}, 'PRIVATE_SELECTED')),
      el('p', {}, 'Public paragraph ', el('span', {contenteditable: 'true'}, 'PRIVATE_EDITABLE'),
        el('span', {hidden: ''}, 'PRIVATE_HIDDEN'), el('span', {style: 'display:none'}, 'PRIVATE_CSS_HIDDEN')),
      el('p', {}, 'Email alice@example.com, code=SHORT_SECRET, OTP 123456, card 4111 1111 1111 1111'),
      el('a', {href: 'https://user:LINK_PASSWORD@accounts.example/login/PathSecret?token=LINK_QUERY#LINK_FRAGMENT'}, 'Continue'),
      el('p', {}, 'Go https://user:TEXT_PASSWORD@accounts.example/verify/SecretCode?token=TEXT_QUERY#TEXT_FRAGMENT'),
      el('button', {onclick: 'PUBLIC_HANDLER_SECRET'}, 'Continue')),
  ]});
  h.advance(0);
  assert.equal(h.sent.length, 1);
  const message = h.sent[0];
  assert.equal(message.type, 'phishing.scan');
  assert.equal(message.url, h.location.href);
  assert.match(message.text, /^TITLE: /);
  assert.match(message.text, /FORM: \{"name":"Form"\}/);
  assert.match(message.text, /INPUT: \{"type":"password","name":"","placeholder":""\}/);
  assert.match(message.text, /CHECKBOX: /);
  assert.match(message.text, /SCRIPT: \{"content":"<EMPTY>"\}/);
  assert.match(message.text, /sign in to example/);
  assert.match(message.text, /public paragraph/);
  assert.match(message.text, /accounts.example\/login\/<REDACTED>/);
  assert.match(message.text, /<redacted_email>/);
  for (const secret of ['PRIVATE_', 'SCRIPT_BODY_SECRET', 'SCRIPT_SOURCE', 'HANDLER_SECRET', 'URL_SECRET', 'FRAGMENT_SECRET',
    'SHORT_SECRET', '123456', '4111', 'alice@example.com', 'PathSecret', 'LINK_PASSWORD', 'LINK_QUERY', 'LINK_FRAGMENT',
    'TEXT_PASSWORD', 'SecretCode', 'TEXT_QUERY', 'TEXT_FRAGMENT']) {
    assert.ok(!message.text.toLowerCase().includes(secret.toLowerCase()), `Model input disclosed ${secret}`);
  }
  assert.deepEqual(Object.keys(message).sort(), ['coverageLimited', 'coverageReasons', 'revision', 'text', 'type', 'url']);
  assert.equal(message.revision, 0);
});

test('URLs retain only origins and known public path terms and never propagate non-web or malformed sources', () => {
  const h = fixture({children: [el('body', {},
    el('a', {href: '/account/alice@example.com/12345678?password=QUERY#HASH'}, 'Account'),
    el('a', {href: 'javascript:alert("SECRET")'}, 'Other'),
    el('a', {href: 'https://invalid.example/%ZZ/token'}, 'Invalid encoding'),
    el('a', {href: '/login/' + 'x'.repeat(3000)}, 'Large URL'),
    el('p', {}, 'Code １２３４５６ and ١٢٣٤٥٦; token=abcdefg'))]});
  h.advance(0);
  const text = h.sent[0].text;
  assert.match(text, /https:\/\/example.com\/account\/<REDACTED>\/<REDACTED>/);
  assert.match(text, /<NON_WEB_URL>/);
  assert.match(text, /<REDACTED_URL>/);
  assert.doesNotMatch(text, /alice|123456|١٢٣٤٥٦|QUERY|HASH|alert|abcdefg|%ZZ/);
});

test('prioritizes login structure before filler, caps UTF-8 output, and marks incomplete coverage', () => {
  const paragraphs = Array.from({length: 250}, () => el('p', {}, '界'.repeat(500)));
  const h = fixture({children: [el('body', {}, ...paragraphs,
    el('form', {}, el('input', {type: 'password'})), el('iframe'), Object.assign(el('div'), {shadowRoot: {}}))]});
  h.advance(0);
  const result = h.sent[0];
  assert.match(result.text, /^FORM: /);
  assert.match(result.text, /INPUT: \{"type":"password"/);
  assert.ok(new TextEncoder().encode(result.text).length <= 24 * 1024);
  assert.equal(result.coverageLimited, true);
  assert.ok(result.coverageReasons.includes('output-limit'));
  assert.ok(result.coverageReasons.includes('element-limit'));
  assert.ok(result.coverageReasons.includes('embedded-frame'));
  assert.ok(result.coverageReasons.includes('shadow-dom'));
});

test('node discovery and text traversal are bounded even for adversarial deep or wide DOMs', () => {
  const body = el('body');
  for (let index = 0; index < 13000; index++) body.append(el('div'));
  body.append(el('form', {}, el('input', {type: 'password'})));
  const h = fixture({children: [body]});
  h.advance(0);
  assert.equal(h.sent[0].coverageLimited, true);
  assert.ok(h.sent[0].coverageReasons.includes('node-limit'));
  assert.ok(h.sent[0].coverageReasons.includes('no-readable-features'));
  const deep = el('body'); let parent = deep;
  for (let index = 0; index < 100; index++) { const child = el('div'); parent.append(child); parent = child; }
  parent.append(el('p', {}, 'Do not walk unlimited ancestors'));
  const second = fixture({children: [deep]}); second.advance(0);
  assert.ok(second.sent[0].coverageReasons.includes('ancestor-limit'));
});

test('no readable features is reported as limited rather than a fabricated benign scan', () => {
  const h = fixture({children: [el('body', {}, el('div'))]});
  h.advance(0);
  assert.equal(h.sent[0].text, '');
  assert.equal(h.sent[0].coverageLimited, true);
  assert.deepEqual(h.sent[0].coverageReasons, ['no-readable-features']);
  const scriptOnly = fixture({children: [el('script', {}, 'private script content')]});
  scriptOnly.advance(0);
  assert.ok(scriptOnly.sent[0].coverageReasons.includes('no-readable-features'));
  const componentOnly = fixture({children: [el('login-component')]});
  componentOnly.advance(0);
  assert.ok(componentOnly.sent[0].coverageReasons.includes('shadow-dom'));
});

test('refuses child frames, non-web pages, and Chrome Web Store documents', () => {
  for (const options of [{frame: true}, {url: 'chrome://settings/'}, {url: 'file:///private/document'},
    {url: 'https://chromewebstore.google.com/detail/example'}, {url: 'https://chrome.google.com/webstore/detail/example'}]) {
    const h = fixture({...options, children: [el('p', {}, 'Sign in')]});
    h.advance(10000);
    assert.equal(h.sent.length, 0);
    assert.equal(h.observers.length, 0);
    assert.equal(h.listeners.length, 0);
  }
});

test('trusted worker confirmation returns the current document URL and revision, rejecting forged senders', () => {
  const h = fixture({children: [el('p', {}, 'Public')]});
  assert.equal(h.listeners.length, 1, 'Confirmation must register before initial scan');
  const sender = {id: h.chrome.runtime.id, url: h.chrome.runtime.getURL('background.js')};
  for (const replacement of [{id: 'other'}, {url: undefined}, {url: h.chrome.runtime.getURL('newtab.html')},
    {tab: {id: 1}}, {url: 'https://example.com/'}]) {
    let reply;
    h.listeners[0]({type: 'phishing.confirm'}, {...sender, ...replacement}, value => { reply = value; });
    assert.equal(reply, undefined);
  }
  h.location.href = 'https://example.com/verify?code=private#private';
  let reply;
  h.listeners[0]({type: 'phishing.confirm'}, sender, value => { reply = structuredClone(value); });
  assert.deepEqual(reply, {url: h.location.href, revision: 0});
  h.advance(0);
  const requested = h.sent[0];
  h.mutate();
  h.listeners[0]({type: 'phishing.confirm'}, sender, value => { reply = structuredClone(value); });
  assert.ok(reply.revision > requested.revision, 'In-flight results must become distinguishable before mutation debounce');
});

test('debounces mutations, revisions same-URL changes, observes SPA URLs without patching history, and guards reinjection', () => {
  const h = fixture({children: [el('p', {}, 'Public')]});
  h.advance(0);
  h.run();
  assert.equal(h.listeners.length, 1);
  assert.equal(h.observers.length, 1);
  for (let index = 0; index < 100; index++) h.mutate();
  h.advance(1999); assert.equal(h.sent.length, 1);
  h.advance(1); assert.equal(h.sent.length, 2);
  assert.ok(h.sent[1].revision > h.sent[0].revision, 'A changed document must rebind its scan even if its bounded text is unchanged');
  h.location.href = 'https://example.com/account';
  h.advance(2000); assert.equal(h.sent.length, 3);
  assert.equal(h.sent[2].url, h.location.href);
  assert.equal(h.sent[2].text, h.sent[0].text);
  h.advance(4000); assert.equal(h.sent.length, 3, 'Polling unchanged URLs must not consume scan budget');
  assert.deepEqual(Array.from(h.observers[0].options.attributeFilter), ['type', 'hidden', 'aria-hidden', 'style', 'href', 'contenteditable', 'autocomplete']);
});

test('only a trusted stop removes observers and permits clean reinjection', () => {
  const h = fixture({children: [el('p', {}, 'Public')]});
  h.advance(0);
  let reply;
  h.listeners[0]({type: 'phishing.stop'}, {id: h.chrome.runtime.id, url: 'https://example.com/'}, value => { reply = value; });
  assert.equal(reply, undefined);
  assert.equal(h.observers[0].connected, true);
  h.listeners[0]({type: 'phishing.stop'}, {id: h.chrome.runtime.id, url: h.chrome.runtime.getURL('background.js')}, value => { reply = structuredClone(value); });
  assert.deepEqual(reply, {stopped: true});
  assert.equal(h.listeners.length, 0);
  assert.equal(h.observers[0].connected, false);
  assert.equal(h.timers.size, 0);
  h.location.href = 'https://example.com/new'; h.emit('pageshow', {persisted: true}); h.emit('popstate'); h.mutate(); h.advance(5000);
  assert.equal(h.sent.length, 1);
  h.run(); h.advance(0);
  assert.equal(h.sent.length, 2);
  assert.equal(h.listeners.length, 1);
  assert.equal(h.observers.length, 2);
});

test('busy or limited worker responses retry at two-second intervals within the eight-request budget', async () => {
  const h = fixture({children: [el('p', {}, 'Public')]});
  h.setResponse({ok: true, status: 'busy'});
  h.advance(0); await tick();
  h.advance(1999); assert.equal(h.sent.length, 1);
  for (let index = 0; index < 10; index++) {
    h.advance(2000); await tick();
  }
  assert.equal(h.sent.length, 8);
  assert.ok(h.sent.at(-1).coverageReasons.includes('scan-limit'));
  assert.equal(h.timers.size, 0);
  const off = fixture({children: [el('p', {}, 'Public')]});
  off.setResponse({status: 'disabled'}); off.advance(0); await tick();
  assert.equal(off.observers[0].connected, false);
  assert.equal(off.timers.size, 0);
});

test('worker error envelopes, rejected transport, and synchronous transport errors retry without exceeding the budget', async () => {
  for (const response of [{error: 'Local analysis unavailable'}, () => Promise.reject(new Error('Transport disconnected')),
    () => { throw new Error('Extension context unavailable'); }]) {
    const h = fixture({children: [el('p', {}, 'Unchanged public page')]});
    h.setResponse(response); h.advance(0); await tick();
    h.advance(1999); assert.equal(h.sent.length, 1);
    for (let index = 0; index < 9; index++) { h.advance(2000); await tick(); }
    assert.equal(h.sent.length, 8);
    assert.ok(h.sent.at(-1).coverageReasons.includes('scan-limit'));
    assert.equal(h.observers[0].connected, false);
    assert.equal(h.timers.size, 0);
  }
});

test('pagehide cancels pending work and hidden documents wait until visible', () => {
  const h = fixture({children: [el('p', {}, 'Public')], visibility: 'hidden'});
  h.advance(0); assert.equal(h.sent.length, 0);
  h.document.visibilityState = 'visible'; h.emit('visibilitychange'); h.advance(0);
  assert.equal(h.sent.length, 1);
  h.location.href = 'https://example.com/new'; h.emit('popstate');
  h.emit('pagehide'); h.advance(5000);
  assert.equal(h.sent.length, 1);
  assert.equal(h.observers[0].connected, false);
  assert.equal(h.timers.size, 0);
  h.emit('pageshow', {persisted: true}); h.advance(0);
  assert.equal(h.sent.length, 2);
});

test('at most eight changed scans run per document and the last scan advertises exhausted coverage', async () => {
  const h = fixture({children: [el('p', {}, 'Public')]});
  h.advance(0);
  for (let index = 1; index < 20; index++) {
    h.location.href = `https://example.com/page/${index}`;
    h.emit('popstate'); h.mutate(); h.advance(2000); await tick();
  }
  assert.equal(h.sent.length, 8);
  assert.equal(h.sent.at(-1).coverageLimited, true);
  assert.ok(h.sent.at(-1).coverageReasons.includes('scan-limit'));
  assert.equal(h.observers[0].connected, false);
  assert.equal(h.timers.size, 0);
});

test('the final pending inference still sees revision changes before coverage cleanup', async () => {
  let resolve;
  const pending = new Promise(done => { resolve = done; });
  const h = fixture({children: [el('p', {}, 'Public')]});
  h.advance(0);
  for (let index = 1; index < 8; index++) {
    if (index === 7) h.setResponse(pending);
    h.location.href = `https://example.com/page/${index}`; h.emit('popstate'); h.advance(2000);
  }
  await tick(); // Earlier replies cannot clean up a later inference still in flight.
  assert.equal(h.sent.length, 8);
  assert.equal(h.observers[0].connected, true);
  h.mutate();
  let confirmed;
  h.listeners[0]({type: 'phishing.confirm'}, {id: h.chrome.runtime.id, url: h.chrome.runtime.getURL('background.js')}, value => { confirmed = value; });
  assert.ok(confirmed.revision > h.sent.at(-1).revision);
  resolve({ok: true}); await tick();
  assert.equal(h.observers[0].connected, false);
  assert.equal(h.timers.size, 0);
});

test('overlong page URLs cause only an empty limited request', () => {
  const h = fixture({url: 'https://example.com/?token=' + 'a'.repeat(9000), children: [el('p', {}, 'Public')]});
  h.advance(0);
  assert.equal(h.sent[0].text, '');
  assert.equal(h.sent[0].coverageLimited, true);
  assert.deepEqual(h.sent[0].coverageReasons, ['document-url-limit']);
});
