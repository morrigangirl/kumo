// Native Secure DNS QA in a disposable profile. Only explicit fixture domains
// and Quad9's public resolver are used; system and personal DNS settings stay intact.
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {nativeQAApp, nativeQAEnvironment} from './native-browser-qa.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const {executable, verifyUnchanged} = await nativeQAApp();
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-dns-qa-'));
const environment = await nativeQAEnvironment(temporary);
const template = 'https://dns.quad9.net/dns-query';
let context;
const launch = () => chromium.launchPersistentContext(path.join(temporary, 'profile'), {
  executablePath: executable, env: environment,
  headless: true, chromiumSandbox: true, timeout: 90000,
  args: ['--no-first-run', '--no-default-browser-check', '--disable-sync', '--use-mock-keychain'],
});
const configuration = page => page.evaluate(async () => {
  const {sendWithPromise} = await import('chrome://resources/js/cr.js');
  return sendWithPromise('getSecureDnsSetting');
});
try {
  context = await launch(); context.setDefaultTimeout(15000);
  let settings = await context.newPage();
  await settings.goto('chrome://settings/security');
  await settings.locator('settings-secure-dns, settings-secure-dns-v2').waitFor({state: 'attached'});
  const redesigned = await settings.locator('settings-secure-dns-v2').count() > 0;
  const dns = settings.locator(redesigned ? 'settings-secure-dns-v2' : 'settings-secure-dns');
  if (redesigned) {
    await dns.locator('#featureRow #expandButton').click();
    const toggle = dns.locator('#toggleButton cr-toggle');
    if (await toggle.getAttribute('aria-checked') !== 'true') await toggle.click();
    await dns.locator('#customRadioButton').click();
  } else {
    const toggle = dns.locator('#secureDnsToggle cr-toggle');
    if (await toggle.getAttribute('aria-checked') !== 'true') await toggle.click();
  }
  await dns.locator('#resolverSelect').selectOption('custom');
  await dns.locator('secure-dns-input textarea').fill(template);
  await dns.locator('secure-dns-input textarea').press('Tab');
  await settings.waitForFunction(async expected => {
    const {sendWithPromise} = await import('chrome://resources/js/cr.js');
    const state = await sendWithPromise('getSecureDnsSetting');
    return state.mode === 'secure' && state.config === expected;
  }, template);
  const selected = await configuration(settings);
  assert.equal(selected.mode, 'secure'); assert.equal(selected.config, template);
  const probeSucceeded = await settings.evaluate(async endpoint => {
    const {sendWithPromise} = await import('chrome://resources/js/cr.js');
    return sendWithPromise('probeConfig', endpoint);
  }, template);
  assert.equal(probeSucceeded, true, 'Chromium must complete its real DNS probe using the chosen resolver');
  await context.close(); context = await launch();
  settings = await context.newPage(); await settings.goto('chrome://settings/security');
  await settings.locator('settings-secure-dns, settings-secure-dns-v2').waitFor({state: 'attached'});
  const persisted = await configuration(settings);
  assert.equal(persisted.mode, 'secure'); assert.equal(persisted.config, template);
  console.log(JSON.stringify({passed: true, nativeSettings: true, template,
    mode: persisted.mode, dnsProbeSucceeded: probeSucceeded, restartPersisted: true,
    scope: 'DNS configuration and Chromium resolver probe, not URL/download reputation'}, null, 2));
} finally {
  try { await context?.close(); }
  finally {
    try { await rm(temporary, {recursive: true, force: true}); }
    finally { await verifyUnchanged(); }
  }
}
