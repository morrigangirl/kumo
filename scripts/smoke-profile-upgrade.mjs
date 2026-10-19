// Retain one explicitly synthetic profile until the source browser is ready.
// No real Google site/account, user profile, password or Keychain is accessed.
import {execFile as execFileCallback} from 'node:child_process';
import {promisify} from 'node:util';
import {lstat, mkdir, readFile, writeFile, rename, rm, realpath} from 'node:fs/promises';
import {createServer} from 'node:http';
import {randomUUID} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const arguments_ = process.argv.slice(2);
if (arguments_.includes('--help')) {
  console.log(`Usage: node scripts/smoke-profile-upgrade.mjs seed|verify|cleanup
seed: current upstream preview stores one synthetic persistent HTTPOnly cookie
and localStorage item using an owned HTTP loopback fixture and mock keychain.
It closes normally and retains only .cache/qa/profile-upgrade-fixture.
verify: requires a locally compiled source app with a different actual engine
version, rebinds the saved loopback port, checks both values, then deletes the
marker-guarded fixture on success. Failure retains it for retry or cleanup.
cleanup: removes only this marked owned fixture, refusing an active operation
or browser. An occupied loopback port fails without touching its owner.
Output contains only boolean evidence and engine versions. This tests synthetic
profile storage compatibility, not real Google authentication, MFA, or Keychain
access/consent. No source-runtime upgrade success is claimed by seed alone.`);
  process.exit(0);
}
const mode = arguments_[0];
const root = await realpath(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'));
const qaRoot = path.join(root, '.cache/qa');
const fixture = path.join(qaRoot, 'profile-upgrade-fixture');
const markerPath = path.join(fixture, 'fixture.json');
const profile = path.join(fixture, 'profile');
const markerKind = 'kumo-owned-synthetic-profile-upgrade';
const execFile = promisify(execFileCallback);
const cookieName = 'kumo_synthetic_upgrade_session';
const storageKey = 'kumo_synthetic_upgrade_state';
let metadata, context, server, committed = false, created = false, cleanupPromise;
let seedEngineVersion, currentEngineVersion;

function requireFixture(condition, flag) {
  if (!condition) { const error = new Error(flag); error.fixtureFailure = flag; throw error; }
}
function numericVersion(value) {
  const match = typeof value === 'string' && value.match(/^(\d+\.\d+\.\d+\.\d+)(?:-.+)?$/);
  requireFixture(match, 'engineVersionMetadataInvalid'); return match[1];
}
function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (error) { return error.code !== 'ESRCH'; }
}
async function readMarker() {
  const directory = await lstat(fixture);
  requireFixture(directory.isDirectory() && !directory.isSymbolicLink(), 'fixtureDirectoryUnsafe');
  const marker = await lstat(markerPath);
  requireFixture(marker.isFile() && !marker.isSymbolicLink() && marker.size < 16384, 'fixtureMarkerInvalid');
  let value;
  try { value = JSON.parse(await readFile(markerPath, 'utf8')); }
  catch { requireFixture(false, 'fixtureMarkerInvalid'); }
  requireFixture(value.kind === markerKind && value.schema === 1 &&
    typeof value.id === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value.id), 'fixtureMarkerInvalid');
  return value;
}
async function saveMarker() {
  const pending = path.join(fixture, `fixture.pending-${process.pid}.json`);
  await writeFile(pending, JSON.stringify(metadata, null, 2), {mode: 0o600});
  await rename(pending, markerPath);
}
async function noOwnedBrowserRunning() {
  const {stdout} = await execFile('ps', ['-axo', 'pid=,command=']);
  requireFixture(!stdout.split('\n').some(line => line.includes(`--user-data-dir=${profile}`)), 'ownedFixtureBrowserStillRunning');
}
async function removeOwnedFixture() {
  const marker = await readMarker();
  requireFixture(!metadata || marker.id === metadata.id, 'fixtureMarkerChanged');
  requireFixture(!marker.activePid || marker.activePid === process.pid || !pidAlive(marker.activePid), 'ownedFixtureOperationStillRunning');
  await noOwnedBrowserRunning();
  await rm(fixture, {recursive: true});
}
function finishRuntime() {
  return cleanupPromise ??= (async () => {
    await context?.close(); context = undefined;
    if (server?.listening) await new Promise(resolve => server.close(resolve));
    if (created && !committed) await removeOwnedFixture();
    else if (metadata?.activePid === process.pid) {
      const marker = await readMarker();
      requireFixture(marker.id === metadata.id, 'fixtureMarkerChanged');
      delete metadata.activePid; await saveMarker();
    }
  })();
}
for (const signal of ['SIGINT', 'SIGTERM'])
  process.once(signal, () => { void finishRuntime().finally(() => process.exit(130)); });

async function run() {
  requireFixture(arguments_.length === 1 && ['seed', 'verify', 'cleanup'].includes(mode), 'invalidMode');
  const qaDirectory = await lstat(qaRoot);
  requireFixture(qaDirectory.isDirectory() && !qaDirectory.isSymbolicLink(), 'qaDirectoryUnsafe');
  if (mode === 'cleanup') {
    try { metadata = await readMarker(); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      try { await lstat(fixture); } catch (missing) {
        if (missing.code !== 'ENOENT') throw missing;
        console.log(JSON.stringify({passed: true, cleanupMode: true, fixtureAlreadyAbsent: true})); return;
      }
      requireFixture(false, 'fixtureMarkerMissing');
    }
    await removeOwnedFixture(); metadata = undefined;
    console.log(JSON.stringify({passed: true, cleanupMode: true, ownedFixtureRemoved: true})); return;
  }
  const app = path.join(root, 'dist/Kumo.app');
  const buildInfo = JSON.parse(await readFile(path.join(app, 'Contents/Resources/KumoExtension/build-info.json'), 'utf8'));
  currentEngineVersion = numericVersion(buildInfo.engineVersion);
  if (mode === 'seed') {
    requireFixture(buildInfo.sourceCompiledLocally === false, 'seedRequiresUpstreamPreview');
    try { await mkdir(fixture, {mode: 0o700}); }
    catch (error) { if (error.code === 'EEXIST') requireFixture(false, 'ownedFixtureAlreadyExists'); throw error; }
    metadata = {kind: markerKind, schema: 1, id: randomUUID(), activePid: process.pid, seeded: false};
    await saveMarker(); created = true;
    await mkdir(path.join(profile, 'Default'), {recursive: true, mode: 0o700});
    await writeFile(path.join(profile, 'Default/Preferences'), JSON.stringify({
      browser: {check_default_browser: false}, signin: {allowed: false},
      search: {suggest_enabled: false}, session: {restore_on_startup: 1},
      credentials_enable_service: false, profile: {password_manager_enabled: false},
    }), {mode: 0o600});
  } else {
    metadata = await readMarker();
    requireFixture(metadata.seeded === true, 'ownedFixtureNotSeeded');
    seedEngineVersion = numericVersion(metadata.seedEngineVersion);
    requireFixture(buildInfo.sourceCompiledLocally === true, 'verifyRequiresLocallyCompiledSource');
    requireFixture(currentEngineVersion !== seedEngineVersion, 'verifyRequiresDifferentEngineVersion');
    requireFixture(Number.isInteger(metadata.port) && metadata.port > 0 && metadata.port < 65536, 'fixtureOriginPortInvalid');
    requireFixture(!metadata.activePid || !pidAlive(metadata.activePid), 'ownedFixtureOperationStillRunning');
    const profileDirectory = await lstat(profile);
    requireFixture(profileDirectory.isDirectory() && !profileDirectory.isSymbolicLink(), 'ownedProfileDirectoryUnsafe');
    await noOwnedBrowserRunning();
    metadata.activePid = process.pid; await saveMarker();
  }
  const token = `kumo_fixture_${metadata.id.replaceAll('-', '')}`;
  let cookieReachedServer = false, storageReachedServer = false;
  server = createServer((request, response) => {
    if (['/check', '/verify'].includes(request.url))
      cookieReachedServer ||= (request.headers.cookie || '').split(';').some(part => part.trim() === `${cookieName}=${token}`);
    if (request.method === 'POST' && request.url === '/storage-check') {
      let body = '';
      request.on('data', chunk => { if (body.length <= 256) body += chunk.toString('utf8'); });
      request.once('end', () => {
        storageReachedServer ||= body === token;
        response.writeHead(storageReachedServer ? 204 : 400); response.end();
      });
      return;
    }
    response.setHeader('Content-Type', 'text/html; charset=utf-8');
    response.setHeader('Content-Security-Policy', "default-src 'none'; connect-src 'self'; base-uri 'none'; form-action 'none'");
    if (mode === 'seed' && request.url === '/seed')
      response.setHeader('Set-Cookie', `${cookieName}=${token}; Max-Age=31536000; Path=/; HttpOnly; SameSite=Lax`);
    response.end('<!doctype html><title>Synthetic Kumo profile-upgrade fixture</title>');
  });
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(mode === 'seed' ? 0 : metadata.port, '127.0.0.1', resolve); });
  } catch (error) {
    if (error.code === 'EADDRINUSE') requireFixture(false, 'savedLoopbackPortAlreadyInUse');
    throw error;
  }
  metadata.port = server.address().port; await saveMarker();
  const origin = `http://127.0.0.1:${metadata.port}`;
  const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
  context = await chromium.launchPersistentContext(profile, {
    executablePath: path.join(app, 'Contents/MacOS/Chromium'), headless: true,
    chromiumSandbox: true, timeout: 90000,
    args: ['--no-first-run', '--no-default-browser-check', '--disable-sync', '--use-mock-keychain', '--password-store=basic'],
  });
  const page = context.pages()[0] ?? await context.newPage();
  const diagnostics = await context.newCDPSession(page);
  const actual = (await diagnostics.send('Browser.getVersion')).product.match(/\d+\.\d+\.\d+\.\d+/)?.[0];
  await diagnostics.detach();
  requireFixture(actual === currentEngineVersion, 'actualEngineVersionDoesNotMatchPackage');
  currentEngineVersion = actual;
  if (mode === 'seed') {
    seedEngineVersion = actual;
    await page.goto(`${origin}/seed`);
    await page.evaluate(({key, value}) => localStorage.setItem(key, value), {key: storageKey, value: token});
    await page.goto(`${origin}/check`);
  } else {
    requireFixture(actual !== seedEngineVersion, 'verifyRequiresDifferentActualEngineVersion');
    await page.goto(`${origin}/verify`);
  }
  const storage = await page.evaluate(key => ({value: localStorage.getItem(key), documentCookie: document.cookie}), storageKey);
  requireFixture(storage.value === token, 'syntheticLocalStorageDidNotPersist');
  requireFixture(!storage.documentCookie.includes(cookieName), 'syntheticCookieIsNotHTTPOnly');
  const cookie = (await context.cookies(origin)).find(item => item.name === cookieName);
  requireFixture(cookie?.value === token && cookie.httpOnly && cookie.expires > Date.now() / 1000 + 86400, 'syntheticPersistentCookieDidNotPersist');
  requireFixture(cookieReachedServer, 'syntheticCookieDidNotReachOwnedServer');
  const storageSent = await page.evaluate(async key => (await fetch('/storage-check', {
    method: 'POST', body: localStorage.getItem(key), credentials: 'same-origin',
  })).ok, storageKey);
  requireFixture(storageSent && storageReachedServer, 'syntheticLocalStorageDidNotReachOwnedServer');
  // This is Playwright's owned persistent context: close() exits its browser,
  // rather than merely disconnecting a raw CDP attachment.
  await context.close(); context = undefined;
  await new Promise(resolve => server.close(resolve));
  await noOwnedBrowserRunning();
  if (mode === 'seed') {
    metadata.seeded = true; metadata.seedEngineVersion = seedEngineVersion;
    delete metadata.activePid; await saveMarker(); committed = true;
  } else { await removeOwnedFixture(); metadata = undefined; }
  console.log(JSON.stringify({passed: true, seedMode: mode === 'seed', verifyMode: mode === 'verify',
    seedEngineVersion, currentEngineVersion, syntheticHTTPOnlyPersistentCookieChecked: true,
    syntheticCookieReachedOwnedServer: true, syntheticLocalStorageChecked: true,
    syntheticLocalStorageReachedOwnedServer: true,
    browserClosedNormally: true, mockKeychainUsed: true, realAccountOrKeychainAccess: false,
    sourceUpgradeVerified: mode === 'verify', ownedFixtureRetained: mode === 'seed',
    ownedFixtureRemoved: mode === 'verify'}));
}

try { await run(); }
catch (error) {
  console.log(JSON.stringify({passed: false, [error.fixtureFailure || 'unexpectedFixtureFailure']: true,
    ...(seedEngineVersion ? {seedEngineVersion} : {}),
    ...(currentEngineVersion ? {currentEngineVersion} : {}), sourceUpgradeVerified: false}));
  process.exitCode = 1;
} finally {
  await finishRuntime();
}
