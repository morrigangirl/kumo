// Explicit, disposable 0.1.2 -> native 0.2 migration QA. Neither app is edited.
// The copied legacy manifest retains its public key but runs a minimal owned
// storage-only worker: the old protection background cannot rewrite the seed.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createServer, request} from 'node:http';
import {createConnection} from 'node:net';
import {chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import {nativeQAApp, nativeQAEnvironment} from './native-browser-qa.mjs';

const execute = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LEGACY_ID = 'eldkgppmnhligdekahicdcdndcoongio';
const LEGACY_KEYS = ['preferences', 'phishingProtection', 'malwareProtection'];
const team = 'PV65ZWXCWX';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function eventually(operation, description, milliseconds = 45000) {
  const deadline = Date.now() + milliseconds; let last;
  while (Date.now() < deadline) {
    try { const value = await operation(); if (value) return value; } catch (error) { last = error; }
    await sleep(100);
  }
  throw new Error(`${description}: ${last?.message || 'timed out'}`);
}

function extensionId(key) {
  assert(typeof key === 'string' && key.length > 100, 'A signed legacy public key is required');
  return hash(Buffer.from(key, 'base64')).slice(0, 32).replace(/[0-9a-f]/g, digit => String.fromCharCode(97 + parseInt(digit, 16)));
}

function appearance(theme, greeting) {
  return {theme, accent: '#385a74', background: '', greeting, engine: 'owned',
    engines: [{id: 'owned', name: 'Owned migration QA', url: 'https://search.kumo-qa.invalid/?q={searchTerms}'}],
    shortcuts: [{name: 'Owned migration fixture', url: 'https://fixture.kumo-qa.invalid/'}]};
}

function cases() {
  return [
    {name: 'legacy-intent', legacy: {preferences: appearance('forest', 'Saved legacy appearance'),
      phishingProtection: {enabled: false}, malwareProtection: {schemaVersion: 1, enabled: true}},
    expected: {preferences: appearance('forest', 'Saved legacy appearance'), phishing: false, malware: true}},
    {name: 'native-precedence', legacy: {preferences: appearance('ocean', 'Legacy appearance must not win'),
      phishingProtection: {enabled: true}, malwareProtection: {schemaVersion: 1, enabled: false}},
    native: {start_page: appearance('sand', 'Existing native appearance wins'),
      protection: {phishing_enabled: false, malware_enabled: true}},
    expected: {preferences: appearance('sand', 'Existing native appearance wins'), phishing: false, malware: true}},
  ];
}

function assertLegacySeed(value) {
  assert.deepEqual(Object.keys(value).sort(), [...LEGACY_KEYS].sort());
  assert.equal(typeof value.phishingProtection.enabled, 'boolean');
  assert.equal(value.malwareProtection.schemaVersion, 1);
  assert.equal(typeof value.malwareProtection.enabled, 'boolean');
  assert.deepEqual(Object.keys(value.preferences).sort(), ['accent', 'background', 'engine', 'engines', 'greeting', 'shortcuts', 'theme']);
}

function assertOutputOutsideApps(output, apps) {
  for (const app of apps) assert(output !== app && !output.startsWith(app + path.sep), 'Evidence must be outside both sealed apps');
}

async function appInfo(app) {
  return JSON.parse((await execute('/usr/bin/plutil', ['-convert', 'json', '-o', '-', path.join(app, 'Contents/Info.plist')])).stdout);
}

async function legacyApp() {
  assert(process.env.KUMO_QA_LEGACY_APP, 'Set KUMO_QA_LEGACY_APP to the sealed, signed 0.1.2 app');
  const app = await realpath(process.env.KUMO_QA_LEGACY_APP);
  assert(app.endsWith('/Kumo.app') && !app.split(path.sep).includes('Applications'), 'Use a separate legacy app outside system and user Applications folders');
  const plist = await appInfo(app);
  assert.equal(plist.CFBundleIdentifier, 'app.kumo.browser');
  assert.equal(plist.CFBundleShortVersionString, '0.1.2');
  const resources = path.join(app, 'Contents/Resources/KumoExtension');
  const info = JSON.parse(await readFile(path.join(resources, 'build-info.json'), 'utf8'));
  assert.equal(info.sourceCompiledLocally, true);
  assert.equal(info.extensionId, LEGACY_ID);
  assert.equal(info.codeSigningTeamId, team);
  assert.equal(info.appUpdates?.version, '0.1.2');
  assert.equal(String(plist.CFBundleVersion), info.appUpdates.build);
  const manifest = JSON.parse(await readFile(path.join(resources, 'manifest.json'), 'utf8'));
  assert.equal(manifest.version, '0.1.2');
  assert.equal(extensionId(manifest.key), LEGACY_ID);
  const seal = async () => {
    await execute('/usr/bin/codesign', ['--verify', '--deep', '--strict', '-R', `=anchor apple generic and identifier "app.kumo.browser" and certificate leaf[subject.OU] = "${team}"`, app]);
    const result = await execute('/usr/bin/codesign', ['-dvvv', app]);
    const cdHash = /^CDHash=([a-f0-9]{40})$/m.exec(result.stdout + result.stderr)?.[1];
    assert(cdHash, 'The legacy app must have an inspectable code signature');
    return {codeDirectoryHash: cdHash, resourceSealSHA256: hash(await readFile(path.join(app, 'Contents/_CodeSignature/CodeResources')))};
  };
  const before = await seal();
  return {app, resources, info, manifest, executable: path.join(app, 'Contents/MacOS/Chromium'),
    async verifyUnchanged() { const after = await seal(); assert.deepEqual(after, before, 'The sealed legacy app changed'); return {before, after, unchanged: true}; }};
}

async function copyRegularTree(source, target) {
  const stat = await lstat(source);
  assert(!stat.isSymbolicLink(), 'The legacy fixture copy must contain no symlinks');
  if (stat.isDirectory()) {
    await mkdir(target, {mode: 0o700});
    for (const entry of await readdir(source)) await copyRegularTree(path.join(source, entry), path.join(target, entry));
  } else {
    assert(stat.isFile(), 'Only regular signed resources may be copied');
    await copyFile(source, target); await chmod(target, 0o600);
  }
}

async function legacyFixture(source, target, manifest) {
  await copyRegularTree(source, target);
  // Only this owned copy is adapted. No startup writes, host calls, alarms,
  // content scripts, requests, or installed product background are exercised.
  await writeFile(path.join(target, 'manifest.json'), JSON.stringify({manifest_version: 3,
    name: 'Owned legacy storage migration fixture', version: '0.1.2', key: manifest.key,
    permissions: ['storage'], background: {service_worker: 'migration-fixture-worker.js'}}), {mode: 0o600});
  await writeFile(path.join(target, 'migration-fixture-worker.js'),
    "chrome.runtime.onMessage.addListener((m,s,reply)=>{if(m?.qa==='ping')reply({id:chrome.runtime.id});});\n", {mode: 0o600});
  await writeFile(path.join(target, 'migration-fixture.html'), '<!doctype html><title>Owned legacy storage fixture</title>', {mode: 0o600});
}

async function ordinaryFixture(directory) {
  await mkdir(directory, {mode: 0o700});
  await writeFile(path.join(directory, 'manifest.json'), JSON.stringify({manifest_version: 3,
    name: 'Owned ordinary extension migration fixture', version: '1.0', permissions: ['storage', 'management'],
    background: {service_worker: 'worker.js'}}), {mode: 0o600});
  await writeFile(path.join(directory, 'worker.js'), "chrome.runtime.onMessage.addListener((m,s,reply)=>{if(m?.qa==='ping')reply({id:chrome.runtime.id});});\n", {mode: 0o600});
  await writeFile(path.join(directory, 'fixture.html'), '<!doctype html><title>Owned ordinary extension fixture</title>', {mode: 0o600});
}

async function foundationProof(directory, home, environment) {
  const source = path.join(directory, 'home-probe.m'), binary = path.join(directory, 'home-probe');
  await writeFile(source, '#import <Foundation/Foundation.h>\nint main(){@autoreleasepool{NSData*d=[NSJSONSerialization dataWithJSONObject:@{@"home":NSHomeDirectory(),@"support":[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject.path} options:0 error:nil];fwrite(d.bytes,1,d.length,stdout);}}\n', {mode: 0o600});
  await execute('/usr/bin/clang', ['-fobjc-arc', '-framework', 'Foundation', source, '-o', binary]);
  const result = JSON.parse((await execute(binary, [], {env: environment})).stdout);
  assert.equal(await realpath(result.home), await realpath(home));
  const support = path.join(home, 'Library/Application Support'); await mkdir(support, {recursive: true, mode: 0o700});
  assert.equal(await realpath(result.support), await realpath(support));
  return {passed: true, foundationHomeIsDisposable: true, applicationSupportIsDisposable: true};
}

async function rejectingProxy() {
  const observations = [], sockets = new Set();
  const observe = (method, target) => {
    // Bounded, disposable-fixture metadata only; never retain browser headers.
    if (observations.length < 4096) observations.push({method, target: target.slice(0, 2048)});
  };
  const server = createServer((incoming, response) => {
    observe(incoming.method, incoming.url);
    response.writeHead(403, {'Content-Type': 'text/plain', 'Cache-Control': 'no-store', Connection: 'close'});
    response.end('Owned migration QA proxy rejects every request.');
  });
  server.on('connect', (incoming, socket) => {
    observe('CONNECT', incoming.url);
    // Never establish a tunnel or open any outbound connection.
    socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  });
  server.on('upgrade', (_incoming, socket) => socket.destroy());
  server.on('clientError', (_error, socket) => socket.destroy());
  server.on('connection', socket => {
    sockets.add(socket); socket.setTimeout(10000, () => socket.destroy());
    socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
  });
  server.headersTimeout = 10000; server.requestTimeout = 10000; server.maxHeadersCount = 32;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  return {port, observations,
    // Chromium156 net/docs/proxy.md: <-loopback> removes implicit localhost
    // and link-local bypasses. One fixed HTTP proxy has no DIRECT fallback.
    browserArgs: [`--proxy-server=http://127.0.0.1:${port}`, '--proxy-bypass-list=<-loopback>',
      '--disable-quic', '--host-resolver-rules=MAP * ^NOTFOUND, EXCLUDE 127.0.0.1'],
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
    }};
}

async function proxySelfTest(proxy) {
  const httpTarget = 'http://192.0.2.1/owned-proxy-self-test';
  const response = await new Promise((resolve, reject) => {
    const outgoing = request({host: '127.0.0.1', port: proxy.port, method: 'GET', path: httpTarget}, incoming => {
      incoming.resume(); incoming.once('end', () => resolve(incoming.statusCode));
    });
    outgoing.once('error', reject); outgoing.setTimeout(10000, () => outgoing.destroy(new Error('Proxy HTTP self-test timed out'))); outgoing.end();
  });
  assert.equal(response, 403);
  const connect = await new Promise((resolve, reject) => {
    const socket = createConnection({host: '127.0.0.1', port: proxy.port}); let text = '';
    socket.setTimeout(10000, () => socket.destroy(new Error('Proxy CONNECT self-test timed out')));
    socket.once('connect', () => socket.write('CONNECT 192.0.2.2:443 HTTP/1.1\r\nHost: 192.0.2.2:443\r\n\r\n'));
    socket.on('data', bytes => { text += bytes; assert(text.length < 1024); });
    socket.once('error', reject); socket.once('end', () => { socket.destroy(); resolve(text); });
  });
  assert.match(connect, /^HTTP\/1\.1 403 Forbidden\r\n/);
  assert(proxy.observations.some(item => item.method === 'GET' && item.target === httpTarget));
  assert(proxy.observations.some(item => item.method === 'CONNECT' && item.target === '192.0.2.2:443'));
  assert.deepEqual(proxy.browserArgs.slice(1), ['--proxy-bypass-list=<-loopback>', '--disable-quic', '--host-resolver-rules=MAP * ^NOTFOUND, EXCLUDE 127.0.0.1']);
  return {passed: true, httpRejected: true, connectRejected: true, fixedLoopbackProxy: true, noDirectFallback: true,
    proxyOpensNoOutboundConnections: true, scope: 'Browser HTTP/HTTPS requests; this is not an OS firewall or helper-network denial proof'};
}

async function browserProxyProof(context, proxy, label) {
  const start = proxy.observations.length;
  const page = await context.newPage(), marker = `${label}-${start}`;
  const target = `http://192.0.2.1/owned-migration-proxy-${marker}`;
  try {
    const response = await page.goto(target, {waitUntil: 'domcontentloaded', timeout: 15000});
    assert.equal(response.status(), 403);
    await assert.rejects(page.goto('https://192.0.2.2/owned-migration-proxy', {waitUntil: 'domcontentloaded', timeout: 15000}), /ERR_TUNNEL_CONNECTION_FAILED/);
    const observed = proxy.observations.slice(start);
    assert(observed.some(item => item.method === 'GET' && item.target === target), 'Actual literal-IP HTTP navigation must reach the rejecting proxy');
    assert(observed.some(item => item.method === 'CONNECT' && item.target === '192.0.2.2:443'), 'Actual literal-IP HTTPS navigation must reach the rejecting proxy');
    return {label, passed: true, actualBrowserHTTP403: true, actualBrowserHTTPSRejected: true,
      httpLiteralIPObservedAtProxy: true, httpsLiteralIPConnectObservedAtProxy: true, chromiumSandboxConfigured: true};
  } finally { await page.close(); }
}

async function processRows() {
  const {stdout} = await execute('/bin/ps', ['-ww', '-axo', 'pid=,ppid=,lstart=,comm='], {env: {PATH: '/usr/bin:/bin', LC_ALL: 'C'}});
  return stdout.trim().split('\n').filter(Boolean).map(line => {
    const match = /^\s*(\d+)\s+(\d+)\s+(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$/.exec(line);
    assert(match, 'Unexpected macOS process identity format');
    return {pid: Number(match[1]), parent: Number(match[2]), started: match[3], executable: match[4]};
  });
}

async function ownedProcessTree(context) {
  const session = await context.browser().newBrowserCDPSession();
  try {
    const {processInfo} = await session.send('SystemInfo.getProcessInfo');
    const browser = processInfo.find(row => row.type === 'browser'); assert(browser, 'Browser PID is required for shutdown proof');
    const rows = await processRows(), main = rows.find(row => row.pid === Number(browser.id));
    assert(main && main.parent === process.pid, 'Only this harness direct browser child can own the profile');
    const owned = new Map([[main.pid, main]]); let changed;
    do { changed = false; for (const row of rows) if (!owned.has(row.pid) && owned.has(row.parent)) { owned.set(row.pid, row); changed = true; } } while (changed);
    return [...owned.values()];
  } finally { await session.detach(); }
}

async function closedFully(context, profile) {
  const owned = await ownedProcessTree(context);
  await context.close();
  await eventually(async () => {
    const rows = await processRows();
    return !owned.some(before => rows.some(after => after.pid === before.pid && after.started === before.started && after.executable === before.executable));
  }, 'All observed owned browser/helper processes must stop before profile reuse', 30000);
  await assert.rejects(lstat(path.join(profile, 'SingletonLock')), {code: 'ENOENT'});
  return {observedProcesses: owned.length, allObservedOwnedProcessesStopped: true, profileLockAbsent: true};
}

async function workerFor(context, id) {
  return eventually(() => context.serviceWorkers().find(worker => worker.url().startsWith(`chrome-extension://${id}/`)), `Storage worker ${id} must load`);
}

async function ordinaryWorker(context) {
  return eventually(() => context.serviceWorkers().find(worker => worker.url().startsWith('chrome-extension://') && !worker.url().startsWith(`chrome-extension://${LEGACY_ID}/`)), 'The ordinary extension worker must load');
}

async function localStorage(worker, keys) { return worker.evaluate(keys => chrome.storage.local.get(keys), keys); }

async function storedProfile(profile) { return JSON.parse(await readFile(path.join(profile, 'Default/Preferences'), 'utf8')); }

function assertPersisted(preferences, expected) {
  assert.equal(preferences.kumo?.protection?.legacy_migrated, true);
  assert.equal(preferences.kumo.protection.phishing_enabled, expected.phishing);
  assert.equal(preferences.kumo.protection.malware_enabled, expected.malware);
  assert.deepEqual(preferences.kumo.start_page, expected.preferences);
  assert(!Object.hasOwn(preferences.extensions?.settings || {}, LEGACY_ID), 'Only the old product registration must be retired');
}

async function nativeAssertions(context, expected, ordinaryId, ordinarySeed) {
  const settings = await context.newPage(); await settings.goto('chrome://settings/kumo');
  await settings.locator('settings-kumo-page').waitFor();
  const status = await eventually(async () => {
    const result = await settings.evaluate(async () => (await import('chrome://resources/js/cr.js')).sendWithPromise('kumoGetStatus'));
    return result.protection?.migrationComplete ? result : false;
  }, 'Actual native legacy storage migration must commit', 90000);
  assert.equal(status.protection.migrationError, '');
  assert.equal(status.protection.phishing.desiredEnabled, expected.phishing);
  assert.equal(status.protection.malware.enabled, expected.malware);
  assert.deepEqual(status.preferences, expected.preferences);
  assert.equal(status.agents.enabled, false, 'Legacy agent authority must never be imported');
  const ordinary = await workerFor(context, ordinaryId);
  assert.deepEqual(await localStorage(ordinary, ['migrationQA']), {migrationQA: ordinarySeed});
  const installed = await ordinary.evaluate(() => chrome.management.getAll());
  assert(installed.some(item => item.id === ordinaryId && item.enabled));
  assert(!installed.some(item => item.id === LEGACY_ID), 'The old product extension must not be installed');
  const cdp = await context.browser().newBrowserCDPSession();
  try {
    const {targetInfos} = await cdp.send('Target.getTargets');
    assert(!targetInfos.some(target => target.url.startsWith(`chrome-extension://${LEGACY_ID}/`)), 'No old product page/worker target may execute');
  } finally { await cdp.detach(); }
  assert(!context.serviceWorkers().some(worker => worker.url().startsWith(`chrome-extension://${LEGACY_ID}/`)));
  return {nativeMigrationComplete: true, persistedIntentMatches: true, ordinaryExtensionStorageRetained: true,
    ordinaryExtensionStillEnabled: true, legacyExtensionAbsentFromManagementAndTargets: true, agentsRemainDisabled: true};
}

async function selfTest() {
  for (const item of cases()) assertLegacySeed(item.legacy);
  assert.throws(() => assertLegacySeed({preferences: {}}));
  assert.throws(() => assertOutputOutsideApps('/private/tmp/Kumo.app/evidence', ['/private/tmp/Kumo.app']));
  assertOutputOutsideApps('/private/tmp/evidence', ['/private/tmp/Kumo.app']);
  const temporary = await mkdtemp('/private/tmp/km-self-');
  let proxy;
  try {
    const environment = await nativeQAEnvironment(temporary);
    const homeProof = await foundationProof(temporary, environment.HOME, environment);
    proxy = await rejectingProxy();
    const network = await proxySelfTest(proxy);
    const key = Buffer.from('synthetic public key '.repeat(10)).toString('base64');
    assert.match(extensionId(key), /^[a-p]{32}$/);
    const source = path.join(temporary, 'copy-source'); await mkdir(source); await writeFile(path.join(source, 'manifest.json'), '{}');
    await legacyFixture(source, path.join(temporary, 'copy-target'), {key});
    const manifest = JSON.parse(await readFile(path.join(temporary, 'copy-target/manifest.json'), 'utf8'));
    assert.deepEqual(manifest.permissions, ['storage']); assert.equal(manifest.key, key);
    assert.equal(manifest.content_scripts, undefined); assert.equal(manifest.host_permissions, undefined);
    const parsed = await processRows(); assert(parsed.some(row => row.pid === process.pid));
    console.log(JSON.stringify({passed: true, checks: ['strict known-key fixtures', 'exclusive app/output boundary', 'real Foundation disposable-home lookup',
      'loopback-only rejecting HTTP/CONNECT proxy with no outbound sockets or DIRECT fallback', 'owned minimal legacy manifest preserves public key and has no network/nativeMessaging', 'macOS process identity parser'],
    homeProof, networkProof: network,
    browserLaunched: false, migrationExecuted: false, sealedAppsRead: false}));
  } finally { if (proxy) await proxy.close(); await rm(temporary, {recursive: true, force: true}); }
}

async function run() {
  assert(process.env.KUMO_QA_APP && process.env.KUMO_QA_LEGACY_APP && process.env.KUMO_QA_OUTPUT,
    'Set explicit KUMO_QA_APP, KUMO_QA_LEGACY_APP and a new KUMO_QA_OUTPUT');
  const current = await nativeQAApp(), legacy = await legacyApp();
  assert.notEqual(current.app, legacy.app);
  const currentPlist = await appInfo(current.app); assert.equal(currentPlist.CFBundleShortVersionString, '0.2.0');
  assert.equal(current.info.engineVersion, legacy.info.engineVersion, 'This native-UI migration fixture requires the same Chromium engine version');
  const requested = path.resolve(process.env.KUMO_QA_OUTPUT);
  const output = path.join(await realpath(path.dirname(requested)), path.basename(requested));
  assertOutputOutsideApps(output, [current.app, legacy.app]);
  await mkdir(output, {mode: 0o700});
  const temporary = await mkdtemp('/private/tmp/km-');
  const report = {schemaVersion: 1, startedAt: new Date().toISOString(), passed: false,
    legacyVersion: '0.1.2', legacyBuild: legacy.info.appUpdates.build, nativeVersion: '0.2.0', chromiumVersion: current.info.engineVersion,
    fixture: 'Copied legacy resources; only owned copy uses minimal storage-only worker with original public key/ID',
    legacyKeys: LEGACY_KEYS, cases: [], browserProxyProofs: [], limitations: [
      'Tests real extension LevelDB import and retirement, not the historical background service or real user profile upgrades.',
      'Only valid preference/protection records are migrated. Corrupt/missing storage and managed-policy interactions need separate coverage.',
      'Browser HTTP/HTTPS requests use a fixed rejecting loopback proxy, including literal IPs and implicit localhost bypasses; QUIC is disabled and DNS is sunk. This is not an OS firewall and does not prove helper-wide Internet denial.',
      'Chromium retains its native sandbox. No provider configuration, installer, AV setup/update or updater action is invoked.',
      'The ordinary extension is a synthetic unpacked storage/management fixture; this does not test Chrome Web Store installation.']};
  let context, contextProfile, proxy, shutdownSafe = true;
  try {
    const environment = await nativeQAEnvironment(temporary);
    report.homeProof = await foundationProof(temporary, environment.HOME, environment);
    proxy = await rejectingProxy(); report.networkProof = await proxySelfTest(proxy);
    const copied = path.join(temporary, 'legacy-extension'), ordinary = path.join(temporary, 'ordinary-extension');
    await legacyFixture(legacy.resources, copied, legacy.manifest); await ordinaryFixture(ordinary);
    const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
    const launch = async (profile, old) => {
      contextProfile = profile; shutdownSafe = false;
      context = await chromium.launchPersistentContext(profile, {executablePath: old ? legacy.executable : current.executable,
        headless: true, chromiumSandbox: true, timeout: 90000, ignoreDefaultArgs: ['--disable-extensions'], env: environment,
        args: [`--load-extension=${old ? copied + ',' : ''}${ordinary}`, '--no-first-run', '--no-default-browser-check',
          '--disable-sync', '--use-mock-keychain', '--password-store=basic', ...proxy.browserArgs],
        viewport: {width: 1100, height: 900}});
      context.setDefaultTimeout(20000);
      report.browserProxyProofs.push(await browserProxyProof(context, proxy, `${old ? 'legacy' : 'native'}-${path.basename(profile)}`));
      return context;
    };
    const stop = async () => { const proof = await closedFully(context, contextProfile); context = undefined; shutdownSafe = true; return proof; };
    for (const item of cases()) {
      assertLegacySeed(item.legacy);
      const profile = path.join(temporary, item.name); await mkdir(path.join(profile, 'Default'), {recursive: true, mode: 0o700});
      await writeFile(path.join(profile, 'Default/Preferences'), JSON.stringify({signin: {allowed: false}, credentials_enable_service: false,
        profile: {password_manager_enabled: false}, search: {suggest_enabled: false}}), {mode: 0o600});
      const ordinarySeed = {case: item.name, retained: true};
      await launch(profile, true);
      const oldWorker = await workerFor(context, LEGACY_ID), third = await ordinaryWorker(context);
      const ordinaryId = new URL(third.url()).hostname;
      await oldWorker.evaluate(async seed => { await chrome.storage.local.set(seed); }, item.legacy);
      assert.deepEqual(await localStorage(oldWorker, LEGACY_KEYS), item.legacy);
      await third.evaluate(async seed => { await chrome.storage.local.set({migrationQA: seed}); }, ordinarySeed);
      const proof = {name: item.name, realLegacyLevelDBSeeded: true, shutdowns: [await stop()]};
      const localArea = path.join(profile, 'Default/Local Extension Settings', LEGACY_ID);
      assert((await lstat(localArea)).isDirectory());
      assert((await readdir(localArea)).length > 0);
      if (item.native) {
        const prefs = await storedProfile(profile); prefs.kumo = structuredClone(item.native);
        await writeFile(path.join(profile, 'Default/Preferences'), JSON.stringify(prefs), {mode: 0o600});
      }
      await launch(profile, false);
      proof.migration = await nativeAssertions(context, item.expected, ordinaryId, ordinarySeed);
      proof.shutdowns.push(await stop()); assertPersisted(await storedProfile(profile), item.expected);
      assert((await lstat(localArea)).isDirectory(), 'Legacy LevelDB storage must survive registration retirement');
      // The minimal worker has no initialization writes: this is an actual
      // readback from the retained LevelDB, not a hash-based retention guess.
      await launch(profile, true);
      assert.deepEqual(await localStorage(await workerFor(context, LEGACY_ID), LEGACY_KEYS), item.legacy);
      assert.deepEqual(await localStorage(await workerFor(context, ordinaryId), ['migrationQA']), {migrationQA: ordinarySeed});
      proof.oldStorageReadbackMatches = true; proof.shutdowns.push(await stop());
      // Old-engine readback re-registers its fixed ID. A final native restart
      // must retire that registration again while preserving committed intent.
      await launch(profile, false);
      proof.restart = await nativeAssertions(context, item.expected, ordinaryId, ordinarySeed);
      proof.shutdowns.push(await stop()); assertPersisted(await storedProfile(profile), item.expected);
      proof.persistedNativeIntentAndMigrationMarker = true; report.cases.push(proof);
    }
    report.passed = true;
  } catch (error) { report.error = {message: error.message, stack: error.stack}; }
  finally {
    if (context) {
      try { report.finalShutdown = await closedFully(context, contextProfile); shutdownSafe = true; }
      catch (error) { report.passed = false; report.shutdownError = error.message; }
    }
    if (proxy) await proxy.close();
    for (const [name, app] of [['nativeAppSeal', current], ['legacyAppSeal', legacy]]) {
      try { report[name] = await app.verifyUnchanged(); } catch (error) { report.passed = false; report[name] = {unchanged: false, error: error.message}; }
    }
    if (shutdownSafe) { await rm(temporary, {recursive: true, force: true}); report.disposableProfilesRemoved = true; }
    else { report.disposableProfilesRemoved = false; report.retainedOwnedTemporaryDirectory = temporary; }
    report.finishedAt = new Date().toISOString();
    await writeFile(path.join(output, 'results.json'), JSON.stringify(report, null, 2) + '\n', {mode: 0o600, flag: 'wx'});
    console.log(JSON.stringify({passed: report.passed, evidence: path.join(output, 'results.json'), cases: report.cases.length}));
    if (!report.passed) process.exitCode = 1;
  }
}

if (process.argv.length !== 3 || !['--self-test', '--run'].includes(process.argv[2]))
  throw new Error('Choose --self-test, or --run with explicit KUMO_QA_APP, KUMO_QA_LEGACY_APP and fresh KUMO_QA_OUTPUT');
if (process.argv[2] === '--self-test') await selfTest(); else await run();
