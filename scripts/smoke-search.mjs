// Disposable native Settings/default-engine integration QA; no user accounts.
// Real Settings controls add/select the engine. chrome://omnibox exercises the
// native autocomplete controller, then its returned link loads a local fixture.
// Headless page key events do not drive the native address-bar text field.
// Internal diagnostic pages are enabled only inside this disposable profile;
// the sandbox remains enabled and no remote-debugging port is exposed.
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createServer} from 'node:http';
import {nativeQAApp, nativeQAEnvironment} from './native-browser-qa.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const {executable, verifyUnchanged} = await nativeQAApp();
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-search-qa-'));
const environment = await nativeQAEnvironment(temporary);
const profile = path.join(temporary, 'profile');
const engineName = 'Kumo Local QA';
const requests = [];
const server = createServer((request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  response.setHeader('Content-Type', 'text/html; charset=utf-8');
  if (url.pathname === '/search') requests.push(url.searchParams.get('q'));
  response.end('<!doctype html><title>Kumo local search QA</title><h1>Local search received</h1>');
});
let context;
const launch = () => chromium.launchPersistentContext(profile, {
  executablePath: executable, env: environment,
  headless: true, chromiumSandbox: true, timeout: 90000,
  args: ['--no-first-run', '--no-default-browser-check', '--disable-sync', '--use-mock-keychain'],
});
const getSelected = page => page.evaluate(async () => {
  const {sendWithPromise} = await import('chrome://resources/js/cr.js');
  return Object.values(await sendWithPromise('getSearchEnginesList')).filter(Array.isArray).flat().find(engine => engine.default);
});
async function queryUsingNativeOmnibox(query) {
  const omnibox = await context.newPage();
  await omnibox.goto('chrome://omnibox');
  if (await omnibox.getByRole('heading', {name: 'Internal debugging pages are currently disabled.', exact: true}).count()) {
    await omnibox.goto('chrome://chrome-urls');
    await omnibox.getByRole('button', {name: 'Enable internal debugging pages', exact: true}).click();
    await omnibox.goto('chrome://omnibox');
  }
  await omnibox.locator('#input-text').fill(query);
  const result = omnibox.locator('output-results-group:not([hidden])').locator(`a[href^="http://127.0.0.1:${server.address().port}/search"]`).first();
  await result.waitFor();
  const match = await result.evaluate(link => ({
    url: link.href, target: link.target,
    type: link.closest('tr').querySelector('.cell-provider-and-type')?.innerText,
  }));
  const destination = new URL(match.url);
  assert.equal(destination.origin, `http://127.0.0.1:${server.address().port}`);
  assert.equal(destination.searchParams.get('q'), query);
  assert.match(match.type, /search-what-you-typed/);
  let loaded = omnibox;
  if (match.target === '_blank') {
    [loaded] = await Promise.all([context.waitForEvent('page'), result.click()]);
  } else {
    await result.click();
  }
  await loaded.waitForURL(url => url.origin === destination.origin && url.pathname === '/search');
  assert.equal(new URL(loaded.url()).searchParams.get('q'), query);
  await loaded.getByRole('heading', {name: 'Local search received', exact: true}).waitFor();
  assert(requests.includes(query), 'The local HTTP engine must receive the actual query');
  await loaded.close();
  if (loaded !== omnibox) await omnibox.close();
  return match;
}
try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const template = `http://127.0.0.1:${server.address().port}/search?q=%s`;
  await mkdir(path.join(profile, 'Default'), {recursive: true});
  await writeFile(path.join(profile, 'Default/Preferences'), JSON.stringify({signin: {allowed: false}, search: {suggest_enabled: false}}));
  context = await launch();
  context.setDefaultTimeout(15000);
  let settings = await context.newPage();
  await settings.goto('chrome://settings/searchEngines');
  await settings.locator('settings-search-engines-page').waitFor({state: 'attached'});
  assert.equal((await getSelected(settings)).name, 'No Search', 'A fresh profile must retain its intentional default');
  await settings.locator('#addSearchEngine').click();
  const dialog = settings.locator('settings-search-engine-edit-dialog');
  await dialog.locator('#searchEngine input').fill(engineName);
  await dialog.locator('#keyword input').fill('kumo-qa.local');
  await dialog.locator('#queryUrl input').fill(template);
  await dialog.locator('#actionButton').click();
  const row = settings.locator('settings-search-engine-entry').filter({hasText: engineName});
  await row.getByRole('button', {name: 'More actions for Kumo Local QA', exact: true}).click();
  await row.getByRole('menuitem', {name: 'Make default', exact: true}).click();
  const selected = await getSelected(settings);
  assert.equal(selected.name, engineName);
  assert.equal(selected.url, template);
  assert.equal(selected.suggestionsUrl, '');
  assert.equal(selected.isManaged, false);
  await row.locator('#name-column').getByText(`${engineName} (Default)`, {exact: true}).waitFor();
  const before = await queryUsingNativeOmnibox('kumo native search before restart');
  await context.close();
  context = await launch();
  context.setDefaultTimeout(15000);
  settings = await context.newPage();
  await settings.goto('chrome://settings/searchEngines');
  await settings.locator('settings-search-engines-page').waitFor({state: 'attached'});
  const persisted = await getSelected(settings);
  assert.equal(persisted.name, engineName);
  assert.equal(persisted.url, template);
  assert.equal(persisted.suggestionsUrl, '');
  await settings.locator('settings-search-engine-entry').filter({hasText: engineName}).locator('#name-column').getByText(`${engineName} (Default)`, {exact: true}).waitFor();
  const after = await queryUsingNativeOmnibox('kumo native search after restart');
  assert.deepEqual(requests, ['kumo native search before restart', 'kumo native search after restart']);
  console.log(JSON.stringify({passed: true, freshDefault: 'No Search', selected: engineName, template, restartPersisted: true, nativeOmniboxMatches: [before, after], localRequests: requests}, null, 2));
} finally {
  try { await context?.close(); }
  finally {
    try { await new Promise(resolve => server.close(resolve)); }
    finally {
      try { await rm(temporary, {recursive: true, force: true}); }
      finally { await verifyUnchanged(); }
    }
  }
}
