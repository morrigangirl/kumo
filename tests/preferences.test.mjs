import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {DEFAULTS, validateEngine, validateSettings, webURL, searchURL, canControl, chromeTheme} from '../extension/shared.js';

test('search encodes queries, preserves HTTPS URLs and supports user engines', () => {
  const settings = validateSettings(DEFAULTS);
  assert.equal(searchURL('snow & 雲', settings), 'https://duckduckgo.com/?q=snow%20%26%20%E9%9B%B2');
  assert.equal(searchURL('example.com/a?x=1', settings), 'https://example.com/a?x=1');
  assert.equal(searchURL('https://example.com/path', settings), 'https://example.com/path');
  const engine = validateEngine({name: 'Private search', url: 'https://search.example/?q={searchTerms}'});
  settings.engines = [engine]; settings.engine = engine.id;
  assert.equal(searchURL('two words', settings), 'https://search.example/?q=two%20words');
  const local = validateEngine({name: 'Local search', url: 'http://localhost:8888/?q={searchTerms}'});
  assert.equal(searchURL('local query', {...settings, engines: [local], engine: local.id}), 'http://localhost:8888/?q=local%20query');
  assert.equal(searchURL('   ', settings), null);
});
test('import rejects executable search/shortcut URLs and normalizes theme data', () => {
  for (const url of ['javascript:alert(1)', 'file:///tmp/passwords', 'https://user:pass@example.com/']) assert.throws(() => webURL(url));
  assert.throws(() => validateEngine({name: 'Bad', url: 'javascript:alert("{searchTerms}")'}));
  assert.throws(() => validateEngine({name: 'Bad', url: 'https://example.com?q=search'}));
  assert.throws(() => validateSettings({...DEFAULTS, engines: []}));
  assert.throws(() => validateSettings({...DEFAULTS, shortcuts: [{name: 'bad', url: 'javascript:alert(1)'}]}));
  const clean = validateSettings({...DEFAULTS, theme: '__proto__', accent: 'url(javascript:alert(1))', background: 'https://tracker.example/pixel'});
  assert.equal(clean.theme, 'paper'); assert.equal(clean.accent, DEFAULTS.accent); assert.equal(clean.background, '');
  const injectedBackground = 'data:image/png;base64,"), url("https://tracker.example/pixel';
  assert.equal(validateSettings({...DEFAULTS, background: injectedBackground}).background, '');
  const localImage = 'data:image/png;base64,aGVsbG8=';
  assert.equal(validateSettings({...DEFAULTS, background: localImage}).background, localImage);
});
test('tab grants bind enabled state, tab identity and exact origin; private/internal tabs are excluded', () => {
  const state = {enabled: true, grants: [{tabId: 3, origin: 'https://example.com'}]};
  assert.equal(canControl({id: 3, url: 'https://example.com/a'}, state), true);
  assert.equal(canControl({id: 4, url: 'https://example.com/a'}, state), false);
  assert.equal(canControl({id: 3, url: 'https://example.com:8443/a'}, state), false);
  assert.equal(canControl({id: 3, url: 'https://example.com.attacker.test/a'}, state), false);
  assert.equal(canControl({id: 3, url: 'chrome://settings'}, state), false);
  assert.equal(canControl({id: 3, url: 'https://example.com/a', incognito: true}, state), false);
  assert.equal(canControl({id: 3, url: 'https://example.com/a'}, {...state, enabled: false}), false);
});
test('exported browser themes use valid integer RGB colors', () => {
  const theme = chromeTheme(validateSettings({...DEFAULTS, theme: 'forest', accent: '#12abcd'}));
  assert.equal(theme.manifest_version, 3); assert.deepEqual(theme.theme.colors.frame, [23, 43, 37]);
  assert.deepEqual(theme.theme.colors.button_background, [18, 171, 205, 1]);
});
test('extension identity is stable and uses a public key; no remote code or broad default host grant', async () => {
  const manifest = JSON.parse(await readFile(new URL('../extension/manifest.json', import.meta.url)));
  const expected = (await readFile(new URL('../config/extension-id.txt', import.meta.url), 'utf8')).trim();
  const hex = createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest('hex').slice(0, 32);
  const id = [...hex].map(c => String.fromCharCode(97 + parseInt(c, 16))).join('');
  assert.equal(id, expected); assert.deepEqual(manifest.host_permissions, ['https://raw.githubusercontent.com/*']);
  assert(!manifest.permissions.includes('debugger')); assert(!manifest.permissions.includes('cookies'));
  assert.equal(manifest.content_security_policy.extension_pages, "script-src 'self'; object-src 'none'; base-uri 'none'; img-src 'self' data: blob:; connect-src 'self' https://raw.githubusercontent.com");
  assert.deepEqual(manifest.declarative_net_request.rule_resources, [{id: 'kumo_malware', enabled: true, path: 'malware/rules.json'}]);
});
