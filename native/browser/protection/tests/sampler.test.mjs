import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
const source = await readFile(new URL('../resources/phishing_sampler.js', import.meta.url), 'utf8');
class Text { nodeType = 3; constructor(value) { this.nodeValue = value; } }
class Element {
  nodeType = 1;
  constructor(localName, attributes = {}, ...children) {
    this.localName = localName; this.attributes = attributes; this.children = []; this.append(...children);
  }
  append(...children) {
    for (const value of children) {
      const child = typeof value === 'string' ? new Text(value) : value;
      const previous = this.children.at(-1); if (previous) previous.nextSibling = child;
      child.parentNode = this; child.nextSibling = null; this.children.push(child);
    }
    this.firstChild = this.children[0] || null;
  }
  getAttribute(name) {
    assert(!['value', 'checked', 'name', 'placeholder', 'onclick'].includes(name), `Private ${name} read`);
    return this.attributes[name] ?? null;
  }
  get hidden() { return 'hidden' in this.attributes; }
  get isContentEditable() { return this.attributes.contenteditable === 'true'; }
  checkVisibility() {
    for (let n = this; n; n = n.parentNode) if (n.hidden) return false;
    return this.attributes.type !== 'hidden';
  }
  get value() { throw Error('Field value read'); }
  get checked() { throw Error('Field state read'); }
  get textContent() { throw Error('Unbounded text read'); }
  get innerText() { throw Error('Unbounded text read'); }
  get outerHTML() { throw Error('Raw HTML read'); }
}
const el = (name, attrs, ...children) => new Element(name, attrs, ...children);
function fixture(children, {url = 'https://example.com/login?PRIVATE_QUERY#PRIVATE_FRAGMENT', child = false} = {}) {
  const observers = [], location = {href: url, protocol: new URL(url).protocol};
  const document = {documentElement: el('html', {}, ...children)};
  for (const key of ['cookie', 'forms', 'activeElement']) Object.defineProperty(document, key, {get() { throw Error(`Private ${key} read`); }});
  const window = {}; window.top = child ? {} : window;
  const context = vm.createContext({window, location, document, URL, TextEncoder,
    MutationObserver: class { constructor(fn) { this.fn = fn; observers.push(this); } observe() {} },
    getComputedStyle: () => ({display: 'block', visibility: 'visible', opacity: '1'})});
  for (const key of ['chrome', 'navigator', 'localStorage', 'sessionStorage', 'fetch', 'XMLHttpRequest'])
    Object.defineProperty(context, key, {get() { throw Error(`${key} access forbidden`); }});
  return {document, location, observers, run: () => vm.runInContext(source, context, {timeout: 1500}),
    mutate() { for (const observer of observers) observer.fn([]); }};
}
test('actual native sampler excludes credentials/editable/script/URL secrets and has no extension dependency', () => {
  const h = fixture([
    el('head', {}, el('title', {}, 'Example login'), el('script', {src: 'https://private.example/?PRIVATE_SCRIPT'}, 'PRIVATE_SCRIPT_BODY')),
    el('body', {}, el('h1', {}, 'Welcome'),
      el('form', {action: '/?PRIVATE_ACTION'}, el('input', {type: 'password', value: 'PRIVATE_PASSWORD'}), el('button', {}, 'PRIVATE_FORM_TEXT')),
      el('textarea', {}, 'PRIVATE_TEXTAREA'), el('p', {contenteditable: 'true'}, 'PRIVATE_EDITABLE'),
      el('p', {hidden: ''}, 'PRIVATE_HIDDEN'),
      el('p', {}, 'Email alice@example.com token=PRIVATE_TOKEN 4111 1111 1111 1111'),
      el('a', {href: 'https://user:PRIVATE_PASSWORD@example.com/login/PRIVATE_PATH?PRIVATE_QUERY#PRIVATE_FRAGMENT'}, 'Continue'))]);
  const result = h.run();
  assert.equal(result.url, h.location.href, 'URL is returned only to browser document validation');
  assert.equal(result.revision, 0); assert(result.text.includes('FORM:'));
  assert(!result.text.includes('PRIVATE')); assert(!result.text.includes('alice@example.com'));
  assert(!result.text.includes('4111')); assert(!result.text.includes('user:'));
  assert(result.text.includes('<redacted_email>')); assert.equal(h.observers.length, 1);
});
test('native polling avoids duplicate extraction, tracks DOM changes and notices same-document URL changes', () => {
  const p = el('p', {}, 'First public paragraph'); const h = fixture([p]);
  const first = h.run(); assert.equal(first.revision, 0);
  const same = h.run(); assert.equal(same.unchanged, true); assert.equal(same.text, undefined);
  p.append('Second public paragraph'); h.mutate();
  const changed = h.run(); assert.equal(changed.revision, 1); assert(changed.text.includes('second public paragraph'));
  h.location.href = 'https://example.com/account'; const navigated = h.run();
  assert.equal(navigated.url, h.location.href); assert.equal(navigated.unchanged, undefined);
  assert.equal(h.observers.length, 1);
});
test('huge documents and Unicode inputs stay bounded and identify partial coverage', () => {
  const root = el('body', {});
  for (let i = 0; i < 25000; i++) root.append(el('p', {}, '界'.repeat(500)));
  const result = fixture([root]).run();
  assert(Buffer.byteLength(result.text) <= 24576); assert.equal(result.coverageLimited, true);
  assert(result.coverageReasons.length > 0);
});
test('subframes and non-web pages yield no sample', () => {
  assert.equal(fixture([el('p', {}, 'Child')], {child: true}).run(), null);
  for (const url of ['chrome://settings/', 'file:///tmp/example', 'about:blank',
                     'https://chromewebstore.google.com/category/themes',
                     'https://chrome.google.com/webstore/detail/example', 'https://user:secret@example.com/login'])
    assert.equal(fixture([el('p', {}, 'Internal')], {url}).run(), null);
});
