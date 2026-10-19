// Learn/verify Default NetLog schema using loopback fixtures only. This does not
// exercise the CWS updater or install an extension. Every cookie/auth value is
// synthetic, lives in a disposable profile, and is sent only to the local server.
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createServer} from 'node:http';
import {netLogRequests} from './extension-update-netlog.mjs';

if (process.argv.includes('--help')) {
  console.log('Usage: node scripts/smoke-update-netlog.mjs\nRuns only loopback Default-NetLog positive/negative cookie/auth controls with the packaged preview. Does not contact the Chrome Web Store or test update installation.');
  process.exit(0);
}
assert.equal(process.argv.length, 2, 'Use --help for supported arguments.');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-update-log-qa-'));
const logPath = path.join(temporary, 'default-netlog.json');
const observed = [];
const server = createServer((request, response) => {
  observed.push({path: request.url, cookie: request.headers.cookie, authorization: request.headers.authorization});
  response.setHeader('Content-Type', 'text/html');
  response.end('<!doctype html><title>NetLog loopback fixture</title><h1>Local fixture</h1>');
});
let context;
try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  context = await chromium.launchPersistentContext(path.join(temporary, 'profile'), {
    executablePath: path.join(root, 'dist/Kumo.app/Contents/MacOS/Chromium'),
    headless: true, chromiumSandbox: true, timeout: 90000,
    ignoreDefaultArgs: ['--disable-background-networking'],
    args: ['--no-first-run', '--disable-sync', '--use-mock-keychain', `--log-net-log=${logPath}`, '--net-log-capture-mode=Default'],
  });
  const page = await context.newPage(); await page.goto(origin);
  await context.addCookies([{url: origin, name: 'kumo_update_log_qa', value: 'synthetic-cookie-value'}]);
  const before = Date.now();
  await page.evaluate(async () => {
    await fetch('/include', {credentials: 'include', headers: {Authorization: 'Synthetic local-fixture-only'}});
    await fetch('/omit', {credentials: 'omit'});
  });
  await context.close(); context = undefined;
  const log = JSON.parse(await readFile(logPath, 'utf8'));
  const requests = netLogRequests(log);
  const included = requests.find(request => request.url === `${origin}/include`);
  const omitted = requests.find(request => request.url === `${origin}/omit`);
  assert(included && omitted, 'Both loopback requests must appear in Default NetLog.');
  assert(included.sentHeaderEvents > 0 && omitted.sentHeaderEvents > 0);
  assert(included.headerNames.includes('cookie') && included.headerNames.includes('authorization'), 'Default NetLog must retain sensitive header names for positive controls.');
  assert(!omitted.headerNames.includes('cookie') && !omitted.headerNames.includes('authorization'));
  assert(included.responseCodes.includes(200) && omitted.responseCodes.includes(200));
  assert.deepEqual(included.responseMimeTypes, ['text/html']);
  assert.deepEqual(omitted.responseMimeTypes, ['text/html']);
  assert(included.startedAtUnixMs >= before - 100 && included.startedAtUnixMs <= Date.now(), 'NetLog timeTickOffset must convert event time to the manual-click wall clock.');
  assert(observed.find(request => request.path === '/include')?.cookie?.includes('synthetic-cookie-value'));
  assert.equal(observed.find(request => request.path === '/include')?.authorization, 'Synthetic local-fixture-only');
  assert.equal(observed.find(request => request.path === '/omit')?.cookie, undefined);
  assert.equal(observed.find(request => request.path === '/omit')?.authorization, undefined);
  console.log(JSON.stringify({passed: true, scope: 'loopback NetLog schema only', captureMode: 'Default', sandbox: true,
    backgroundNetworkingDefaultDisabledFlagRemoved: true,
    includeHeaderNames: included.headerNames, omitHeaderNames: omitted.headerNames,
    cookieAndAuthorizationPositiveControlsDetected: true, eventWallClockConversionVerified: true,
    responseMimeCaptureVerified: true,
    cwsUpdateCheckVerified: false, updateInstallationVerified: false}, null, 2));
} finally {
  await context?.close();
  await new Promise(resolve => server.close(resolve));
  await rm(temporary, {recursive: true, force: true});
}
