// Bounded startup observation only. No real profile, account, navigation to a
// Google website, request blocking, or Playwright launch defaults are involved.
import assert from 'node:assert/strict';
import {execFile as execFileCallback, spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {cp, mkdtemp, mkdir, readFile, writeFile, rm} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {netLogRequests} from './extension-update-netlog.mjs';

const arguments_ = process.argv.slice(2);
if (arguments_.includes('--help')) {
  console.log(`Usage: node scripts/smoke-privacy.mjs [--headless]
Observes actual packaged Chromium startup and Kumo new-tab traffic for a bounded
15-second quiet period with a disposable profile and mock keychain. Default is
headed; --headless labels the different scope. Uses the actual launcher flags
and fresh-profile preferences without background-network/component suppression.
An owned loopback HTTP positive control proves Default NetLog is recording.
Reports only unique HTTP(S) hosts and boolean evidence. Fails on requests to the
listed Google-service domains; this is not an exhaustive privacy audit.
Never launches the normal Kumo profile or contacts a Google website deliberately.`);
  process.exit(0);
}
assert(arguments_.length === 0 || (arguments_.length === 1 && arguments_[0] === '--headless'),
  'Use --help for supported arguments.');
assert(process.platform === 'darwin' && process.arch === 'arm64', 'This QA target requires Apple Silicon macOS.');
const headed = !arguments_.includes('--headless');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = path.join(root, 'dist/Kumo.app');
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const execFile = promisify(execFileCallback);
// This diagnostic returns paths/flags before the launcher creates or reads a
// Kumo profile. The returned real profile path is replaced and never accessed.
const config = JSON.parse((await execFile(path.join(app, 'Contents/MacOS/Kumo'), ['--kumo-print-config'])).stdout);
assert.equal(config.engine, path.join(app, 'Contents/MacOS/Chromium'));
assert.equal(config.bundledExtension, path.join(app, 'Contents/Resources/KumoExtension'));
assert(config.extension.startsWith(path.join(config.profile, 'ExtensionRuntime') + path.sep));
assert(Array.isArray(config.flags) && config.flags.every(flag => typeof flag === 'string'));
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-privacy-qa-'));
const profile = path.join(temporary, 'profile');
const extension = path.join(temporary, 'kumo-extension');
const logPath = path.join(temporary, 'default-netlog.json');
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
// Explicit, finite coverage: exact domains or their subdomains only. Third-party
// sites hosted on these services are irrelevant here because none are visited.
const googleServiceDomains = [
  'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
  'google-analytics.com', 'googletagmanager.com', 'googletagservices.com',
  'googlezip.net', 'googlevideo.com', 'youtube.com', 'ytimg.com',
  'gvt1.com', 'gvt2.com', 'gvt3.com', '2mdn.net', 'recaptcha.net',
  'chrome.com', '1e100.net',
];
const forbiddenFlags = [
  '--disable-background-networking', '--disable-component-update',
  '--disable-default-apps', '--disable-extensions', '--disable-extensions-except',
  '--disable-features', '--no-sandbox', '--ignore-certificate-errors',
  '--host-resolver-rules', '--proxy-server', '--proxy-pac-url',
];
let child, browser, cleanupPromise;
let controlReceived = false;
const server = createServer((request, response) => {
  if (request.url === '/positive-control') controlReceived = true;
  response.writeHead(200, {'Content-Type': 'text/html',
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; form-action 'none'"});
  response.end('<!doctype html><title>Owned privacy capture control</title>');
});

function cleanup() {
  return cleanupPromise ??= (async () => {
    await browser?.close().catch(() => {});
    browser = undefined;
    if (child?.pid) {
      try { process.kill(-child.pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
      await delay(100);
      try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    }
    if (server.listening) await new Promise(resolve => server.close(resolve));
    await rm(temporary, {recursive: true, force: true});
  })();
}
for (const signal of ['SIGINT', 'SIGTERM'])
  process.once(signal, () => { void cleanup().finally(() => process.exit(130)); });

async function readFinalNetLog() {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try { return JSON.parse(await readFile(logPath, 'utf8')); }
    catch (error) {
      if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;
      await delay(100);
    }
  }
  throw new Error('Owned browser did not flush a complete Default NetLog.');
}

async function closeNativeBrowser() {
  // For a CDP attachment, Playwright close() can merely disconnect. Ask the
  // owned native process to exit so its Default NetLog receives a JSON footer.
  const session = await browser.newBrowserCDPSession();
  try { await session.send('Browser.close'); }
  catch { /* Closing the native process can close CDP before its reply. */ }
  const deadline = Date.now() + 15000;
  while (child.exitCode === null && child.signalCode === null && Date.now() < deadline)
    await delay(100);
  assert(child.exitCode !== null || child.signalCode !== null, 'Owned native Chromium did not exit after Browser.close.');
  await browser.close().catch(() => {});
  browser = undefined;
}

try {
  await cp(config.bundledExtension, extension, {recursive: true});
  await mkdir(path.join(profile, 'Default'), {recursive: true, mode: 0o700});
  // Exactly the fresh-profile preference values in native/launcher/main.swift.
  await writeFile(path.join(profile, 'Default/Preferences'), JSON.stringify({
    browser: {check_default_browser: false}, signin: {allowed: false},
    search: {suggest_enabled: false}, session: {restore_on_startup: 1},
    credentials_enable_service: false, profile: {password_manager_enabled: false},
  }), {mode: 0o600});
  const profileFlags = config.flags.filter(flag => flag.startsWith('--user-data-dir='));
  assert.equal(profileFlags.length, 1, 'The actual launcher must declare exactly one profile flag.');
  const flags = config.flags.map(flag => flag.startsWith('--user-data-dir=') ? `--user-data-dir=${profile}` : flag.startsWith('--load-extension=') ? `--load-extension=${extension}` : flag);
  for (const forbidden of forbiddenFlags)
    assert(!flags.some(flag => flag === forbidden || flag.startsWith(`${forbidden}=`)), 'Normal launcher must not suppress or redirect network traffic for this capture.');
  flags.push('--use-mock-keychain', '--password-store=basic', '--remote-debugging-port=0',
    '--remote-debugging-address=127.0.0.1', `--log-net-log=${logPath}`, '--net-log-capture-mode=Default');
  if (!headed) flags.push('--headless=new');
  // No startup URL is added: Chromium opens its ordinary new tab. No Playwright
  // launch() call can introduce its automation/background suppression defaults.
  child = spawn(config.engine, flags, {detached: true, stdio: 'ignore',
    env: {...process.env, KUMO_AGENT_DIR: path.join(temporary, 'agents')}});
  await new Promise((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
  const launchDeadline = Date.now() + 90000;
  let port;
  while (Date.now() < launchDeadline) {
    assert(child.exitCode === null, 'Owned Chromium exited before its loopback debugging endpoint was ready.');
    try {
      const file = await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8');
      const number = Number(file.split('\n')[0]);
      if (Number.isInteger(number) && number > 0 && number < 65536) { port = number; break; }
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await delay(100);
  }
  assert(port, 'Owned Chromium did not expose its loopback QA endpoint.');
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, {timeout: 15000});
  const context = browser.contexts()[0];
  assert(context, 'Owned browser context is missing.');
  context.setDefaultTimeout(15000);
  const eid = (await readFile(path.join(root, 'config/extension-id.txt'), 'utf8')).trim();
  assert(/^[a-p]{32}$/.test(eid));
  const workerDeadline = Date.now() + 15000;
  while (!context.serviceWorkers().some(worker => worker.url().startsWith(`chrome-extension://${eid}/`)) && Date.now() < workerDeadline)
    await delay(100);
  assert(context.serviceWorkers().some(worker => worker.url().startsWith(`chrome-extension://${eid}/`)), 'The normal launcher extension must load.');
  const newtab = await context.newPage();
  await newtab.goto('chrome://newtab', {waitUntil: 'domcontentloaded'});
  await newtab.locator('#greeting').waitFor({state: 'visible'});
  assert((await newtab.title()).includes('Kumo'), 'An ordinary new tab must render Kumo.');

  const versionPage = await context.newPage(); await versionPage.goto('chrome://version');
  const commandLine = await versionPage.locator('#command_line').textContent();
  for (const forbidden of forbiddenFlags)
    assert(!commandLine.includes(forbidden), 'The running QA browser must have no network suppression or sandbox/certificate bypass flags.');
  assert(!commandLine.includes('--enable-automation'), 'A raw browser spawn must not add Playwright launch automation flags.');
  await versionPage.close();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const controlURL = `http://127.0.0.1:${server.address().port}/positive-control`;
  const controlPage = await context.newPage();
  await controlPage.goto(controlURL, {waitUntil: 'load'});
  assert(controlReceived, 'The owned loopback positive control must reach the server.');
  await controlPage.close();
  await newtab.bringToFront();
  await delay(15000);
  await closeNativeBrowser();
  const requests = netLogRequests(await readFinalNetLog());
  const control = requests.find(request => request.url === controlURL);
  assert(control && control.sentHeaderEvents > 0 && control.responseCodes.includes(200), 'Default NetLog must contain the successful loopback positive control.');
  const hosts = [...new Set(requests.flatMap(request => {
    try { const url = new URL(request.url); return ['http:', 'https:'].includes(url.protocol) ? [url.hostname] : []; }
    catch { return []; }
  }))].sort();
  const googleHosts = hosts.filter(host => googleServiceDomains.some(domain => host === domain || host.endsWith(`.${domain}`)));
  const externalHosts = hosts.filter(host => !['127.0.0.1', '[::1]', 'localhost'].includes(host));
  console.log(JSON.stringify({passed: googleHosts.length === 0, headed, headless: !headed,
    rawSpawnWithoutPlaywrightLaunchDefaults: true, normalLauncherFlagsAndFreshPreferences: true,
    sandboxAndCertificateBypassFlagsAbsent: true, qaNetworkSuppressionOrBlockingAbsent: true,
    defaultNetLogCapture: true, normalKumoNewtabRendered: true,
    fifteenSecondQuietObservationCompleted: true, loopbackPositiveControlObserved: true,
    hostsObserved: hosts, googleServiceHostsObserved: googleHosts,
    externalHostsObserved: externalHosts, googleServiceRequestsAbsent: googleHosts.length === 0,
    allObservedHTTPHostsAreLoopback: externalHosts.length === 0, exhaustivePrivacyAudit: false}, null, 2));
  assert.equal(googleHosts.length, 0, 'Unsolicited Google-service HTTP(S) requests were observed.');
} finally {
  await cleanup();
}
