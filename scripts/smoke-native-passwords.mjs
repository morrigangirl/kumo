// Interactive native-browser QA. CUA operates only this disposable app's native
// controls; Playwright owns the synthetic page. Never open the Passwords picker.
import assert from 'node:assert/strict';
import {execFile as execFileCallback, spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp, mkdir, open, readFile, writeFile, readdir, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {createInterface} from 'node:readline';

const execFile = promisify(execFileCallback);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const arguments_ = process.argv.slice(2);
if (arguments_.includes('--help')) {
  console.log(`Usage: node scripts/smoke-native-passwords.mjs [--app /path/to/Kumo.app] [--prepare-only]
Requires a locally compiled source build and .cache/qa/node_modules/playwright-core.
Creates a separately signed QA app, unique bundle ID, and disposable profile.
CUA must target the printed QA app path, never the original app or raw engine.
No credential picker, personal password, browser import, or certificate bypass.
--prepare-only accepts the preview for setup evidence only: clone, compile the
QA launcher, preserve corresponding original signing policies/entitlements,
verify same-team and unchanged nested signatures, then clean up. It never
launches Chromium, opens a picker, or contacts the network. Actual browser QA
always requires a locally compiled source app.

For every scenario: reset, then use CUA to right-click the target field and
choose “Fill with Apple Passwords…”. Enter the exact synthetic token from
qa-state.json DIRECTLY into the native panel; native AX setValue is permitted.
Do not normalize or substitute characters; never choose AutoFill → Passwords.
This QA app uses an ephemeral loopback CDP connection with Playwright default
focus emulation disabled, so the real tab-hide visibility assertion is valid.

Exact field: open panel; enter token; send focus-decoy; CUA clicks Fill and
verifies panel closed; send check-fill closed.
Cancel: reset; open panel; enter token; CUA clicks Cancel and verifies closure;
send check-cancel closed.
Navigation: reset; open panel; enter token; send navigate; CUA verifies closure;
send check-navigation closed.
Tab hiding: reset; open panel; enter token; send hide; CUA verifies closure;
send show, then check-hide closed.

Commands: reset, focus-decoy, navigate, hide, show, status,
check-fill closed, check-cancel closed, check-navigation closed,
check-hide closed, finish, close.
“closed” is the operator's explicit CUA observation, not an automated UI claim.
finish requires all four checks; close aborts without claiming success.`);
  process.exit(0);
}
const prepareOnly = arguments_.includes('--prepare-only');
assert(arguments_.filter(argument => argument === '--prepare-only').length <= 1, 'Pass --prepare-only only once.');
const appArguments = arguments_.filter(argument => argument !== '--prepare-only');
assert(appArguments.length === 0 || (appArguments.length === 2 && appArguments[0] === '--app'),
  'Use --help for supported arguments.');
assert(process.platform === 'darwin' && process.arch === 'arm64', 'This QA target requires Apple Silicon macOS.');
const original = path.resolve(appArguments[1] ?? path.join(root, 'dist/Kumo.app'));
const buildInfo = JSON.parse(await readFile(path.join(original, 'Contents/Resources/KumoExtension/build-info.json'), 'utf8'));
assert(prepareOnly || buildInfo.sourceCompiledLocally === true,
  'Native QA refuses the upstream preview: package a locally compiled Chromium.app first.');
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const runtime = await mkdtemp(path.join(tmpdir(), 'kumo-native-browser-qa-'));
const suffix = randomUUID().replaceAll('-', '');
const app = path.join(runtime, `Kumo Native QA ${suffix.slice(0, 8)}.app`);
const bundleId = `app.kumo.nativeqa.${suffix}`;
const profile = path.join(runtime, 'profile');
const engine = path.join(app, 'Contents/MacOS/Chromium');
const launcher = path.join(app, 'Contents/MacOS/KumoNativeQA');
const dummy = 'KUMO_SYNTHETIC_ONLY_café_雲_🔐';
const statePath = path.join(runtime, 'qa-state.json');
let browser, browserControl, child, childExit, childLaunchFailed = false;
let context, fixture, hiddenTab, input, cleanupPromise;
let focusedDecoy = false, navigated = false, hidden = false, shownAgain = false;
let finished = false;
const passed = new Set();

async function signingPolicy(target) {
  const result = await execFile('codesign', ['-d', '--verbose=4', target]);
  const details = result.stdout + result.stderr;
  const flags = details.match(/\bflags=(0x[\da-f]+)/i);
  const identifier = details.match(/^Identifier=(.+)$/m);
  const team = details.match(/^TeamIdentifier=([A-Z0-9]{10})$/m);
  const cdhash = details.match(/^CDHash=(.+)$/m);
  assert(flags && identifier && team && cdhash, 'The verified QA source must expose signing flags, identifier, Team ID and code hash.');
  return {options: (Number.parseInt(flags[1], 16) & ~0x20002) >>> 0,
    identifier: identifier[1], team: team[1], cdhash: cdhash[1]};
}

async function nestedSignatures(base, expectedTeam) {
  const result = new Map();
  const machoMagic = new Set([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe,
    0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca]);
  async function visit(directory) {
    for (const entry of await readdir(directory, {withFileTypes: true})) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) { await visit(file); continue; }
      if (!entry.isFile()) continue;
      const handle = await open(file, 'r');
      let magic;
      try {
        const buffer = Buffer.alloc(4);
        const {bytesRead} = await handle.read(buffer, 0, 4, 0);
        if (bytesRead === 4) magic = buffer.readUInt32BE();
      } finally { await handle.close(); }
      if (!machoMagic.has(magic)) continue;
      const policy = await signingPolicy(file);
      assert.equal(policy.team, expectedTeam, 'All retained nested code must belong to the configured development team.');
      result.set(path.relative(base, file), policy);
    }
  }
  await visit(path.join(base, 'Contents/Frameworks'));
  assert(result.size > 0, 'The QA source must include signed nested browser code.');
  return result;
}

async function stopOwnedProcesses() {
  // Match executable prefixes inside this generated app, never a browser name,
  // bundle ID shared by the user, profile substring, or broad process pattern.
  const owned = async () => {
    const {stdout} = await execFile('ps', ['-axo', 'pid=,command=']);
    return stdout.split('\n').flatMap(line => {
      const match = line.trim().match(/^(\d+)\s+(.+)$/);
      return match && match[2].startsWith(`${app}/Contents/`) ? [Number(match[1])] : [];
    });
  };
  for (const pid of await owned()) { try { process.kill(pid, 'SIGTERM'); } catch {} }
  for (let attempt = 0; attempt < 12; attempt++) {
    if ((await owned()).length === 0) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  for (const pid of await owned()) { try { process.kill(pid, 'SIGKILL'); } catch {} }
}
async function bounded(promise, milliseconds) {
  let timer;
  try {
    return await Promise.race([promise, new Promise(resolve => {
      timer = setTimeout(resolve, milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

function parseOwnedDevToolsEndpoint(text) {
  // This file belongs to the freshly created, private QA profile. Do not accept
  // an arbitrary URL, hostname, path, extra record, or preselected debug port.
  const match = text.match(/^([1-9][0-9]{0,4})\r?\n(\/devtools\/browser\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\r?\n?$/);
  assert(match && match[0] === text, 'The owned QA DevTools endpoint file is malformed.');
  const port = Number(match[1]);
  assert(port <= 65535, 'The owned QA DevTools port is invalid.');
  return {port, endpoint: `ws://127.0.0.1:${port}${match[2]}`};
}

async function ownedDevToolsEndpoint() {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    assert(!childLaunchFailed && child.exitCode === null && child.signalCode === null,
      'The owned QA browser exited before its debugging endpoint was ready.');
    let text;
    try { text = await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8'); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await new Promise(resolve => setTimeout(resolve, 100));
      continue;
    }
    // Chromium creates this file during startup; allow its write to complete.
    if (!text.endsWith('\n') && text.split('\n').length < 2) {
      await new Promise(resolve => setTimeout(resolve, 100));
      continue;
    }
    const endpoint = parseOwnedDevToolsEndpoint(text);
    const {stdout} = await execFile('/usr/sbin/lsof', ['-nP', '-a', '-p', String(child.pid),
      `-iTCP:${endpoint.port}`, '-sTCP:LISTEN', '-Fpn']);
    const records = stdout.trim().split('\n');
    assert.deepEqual(records.filter(record => record.startsWith('p')), [`p${child.pid}`],
      'The QA debugging listener must belong to the directly spawned browser.');
    assert.deepEqual(records.filter(record => record.startsWith('n')), [`n127.0.0.1:${endpoint.port}`],
      'The QA debugging listener must bind only the IPv4 loopback address.');
    return endpoint.endpoint;
  }
  throw new Error('The owned QA browser did not publish its debugging endpoint.');
}

function cleanup() {
  return cleanupPromise ??= (async () => {
    input?.close();
    // A CDP attachment's browser.close() can just disconnect. Ask only this
    // verified owned browser to exit, then wait before the scoped fallback.
    if (browserControl) await bounded(browserControl.send('Browser.close').catch(() => {}), 5000);
    if (childExit) await bounded(childExit, 5000);
    await browser?.close().catch(() => {});
    await stopOwnedProcesses();
    await rm(runtime, {recursive: true, force: true});
  })();
}
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => { void cleanup().finally(() => process.exit(130)); });
}

const form = `<!doctype html><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'none'">
<title>Kumo native QA — synthetic fields only</title>
<style>body{font:18px system-ui;padding:40px}label,input{display:block;margin:14px 0}input{width:480px;padding:14px}</style>
<h1>Kumo native QA</h1><p>Synthetic inputs only. No submission or network scripts.</p>
<label for="target">Target password field</label><input id="target" type="password" autocomplete="off">
<label for="decoy">Decoy password field</label><input id="decoy" type="password" autocomplete="off">`;

async function resetFixture() {
  await hiddenTab?.close(); hiddenTab = undefined;
  fixture ??= await context.newPage();
  await fixture.bringToFront();
  // Real HTTPS navigation establishes Chromium's normal certificate status.
  // Do not use ignoreHTTPSErrors, certificate switches, localhost TLS, or a data URL.
  await fixture.goto('https://example.com/', {waitUntil: 'load', timeout: 30000});
  assert.equal(new URL(fixture.url()).origin, 'https://example.com');
  await fixture.setContent(form, {waitUntil: 'domcontentloaded'});
  await fixture.locator('#target').focus();
  focusedDecoy = false; navigated = false; hidden = false; shownAgain = false;
  console.log(JSON.stringify({ready: true, fixtureOriginTrusted: true, target: 'Target password field'}));
}
async function fixtureStatus() {
  assert(fixture && new URL(fixture.url()).origin === 'https://example.com', 'Reset the owned fixture first.');
  return fixture.evaluate(expected => {
    const target = document.querySelector('#target');
    const decoy = document.querySelector('#decoy');
    if (!(target instanceof HTMLInputElement) || !(decoy instanceof HTMLInputElement))
      throw new Error('Synthetic fixture fields are missing.');
    return {targetEmpty: target.value === '', targetMatchesDummy: target.value === expected,
      decoyEmpty: decoy.value === '', decoyFocused: document.activeElement === decoy};
  }, dummy);
}
async function check(name, confirmed) {
  assert.equal(confirmed, 'closed', 'Use CUA to observe native-panel closure, then append closed.');
  const status = await fixtureStatus();
  if (name === 'fill') {
    assert(focusedDecoy && status.targetMatchesDummy && status.decoyEmpty,
      'Exact-target fill failed, or focus-decoy was not exercised.');
  } else {
    if (name === 'navigation') assert(navigated, 'Run navigate while the native panel is open.');
    if (name === 'hide') assert(hidden && shownAgain, 'Run hide while the panel is open, then show.');
    assert(status.targetEmpty && status.decoyEmpty, 'Cancellation changed a synthetic fixture field.');
  }
  passed.add(name);
  console.log(JSON.stringify({check: name, pass: true, nativePanelClosureConfirmedByOperator: true}));
}

try {
  const signingConfig = JSON.parse(await readFile(path.join(root, 'config/apple-signing.json'), 'utf8'));
  const selectedIdentity = await execFile('python3', ['-c',
    "import json,runpy,sys; print(json.dumps(runpy.run_path(sys.argv[1])['development_identity']()))",
    path.join(root, 'scripts/package.py')]);
  const [identity, team] = JSON.parse(selectedIdentity.stdout);
  assert.equal(team, signingConfig.teamId, 'QA must use the configured development team.');
  assert.match(identity, /^[A-F0-9]{40}$/, 'The selected development certificate identity is missing.');
  await execFile('codesign', ['--verify', '--deep', '--strict', original]);
  const originalPolicy = await signingPolicy(original);
  const originalEnginePolicy = await signingPolicy(path.join(original, 'Contents/MacOS/Chromium'));
  for (const policy of [originalPolicy, originalEnginePolicy]) {
    assert.equal(policy.team, team, 'The original app and engine must use the configured development team.');
    assert(policy.options & 0x10000, 'Native QA requires the shipping hardened-runtime policy.');
  }
  const originalNested = await nestedSignatures(original, team);
  const sourceExecutable = (await execFile('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleExecutable',
    path.join(original, 'Contents/Info.plist')])).stdout.trim();
  assert(sourceExecutable && path.basename(sourceExecutable) === sourceExecutable && !['.', '..'].includes(sourceExecutable),
    'The original app must declare a local executable basename.');
  await execFile('ditto', ['--norsrc', '--noextattr', original, app]);
  const plist = path.join(app, 'Contents/Info.plist');
  // Only generated QA artifacts are changed. Original app and launcher stay intact.
  await execFile('/usr/libexec/PlistBuddy', ['-c', 'Set :CFBundleExecutable KumoNativeQA', plist]);
  await execFile('/usr/libexec/PlistBuddy', ['-c', `Set :CFBundleIdentifier ${bundleId}`, plist]);
  await execFile('/usr/libexec/PlistBuddy', ['-c', `Set :CFBundleName Kumo Native QA ${suffix.slice(0, 8)}`, plist]);
  await execFile('/usr/libexec/PlistBuddy', ['-c', `Set :CFBundleDisplayName Kumo Native QA ${suffix.slice(0, 8)}`, plist]);
  // The unused copied wrapper is signed against the original Info.plist.
  // Remove only that superseded launcher in this disposable copy; always keep
  // the actual Chromium engine and sign the generated QA launcher below.
  const supersededLauncherRemoved = !['Chromium', 'KumoNativeQA'].includes(sourceExecutable);
  if (supersededLauncherRemoved) await rm(path.join(app, 'Contents/MacOS', sourceExecutable));
  const swift = path.join(runtime, 'launcher.swift');
  const literal = value => `String(data: Data(base64Encoded: "${Buffer.from(value).toString('base64')}")!, encoding: .utf8)!`;
  await writeFile(swift, `import Darwin\nimport Foundation
let engine = ${literal(engine)}
let profile = ${literal(profile)}
var forwarded: [String] = []
var skip = false
for argument in CommandLine.arguments.dropFirst() {
    if skip { skip = false; continue }
    if argument == "--" { break }
    if argument == "--user-data-dir" || argument == "--profile-directory" { skip = true; continue }
    if argument.hasPrefix("--user-data-dir=") || argument.hasPrefix("--profile-directory=") || argument.hasPrefix("-psn_") { continue }
    forwarded.append(argument)
}
let forced = ["--user-data-dir=\\(profile)", "--profile-directory=Default", "--no-first-run", "--no-default-browser-check", "--disable-sync", "--password-store=basic", "--use-mock-keychain", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0", "--window-size=1100,800"]
let args = [engine] + forwarded + forced
let pointers = args.map { strdup($0) } + [nil]
let result = pointers.withUnsafeBufferPointer { execv(engine, $0.baseAddress!) }
fputs("QA browser launch failed.\\n", stderr)
exit(result == -1 ? 1 : result)
`, {mode: 0o600});
  await execFile('swiftc', ['-O', '-target', 'arm64-apple-macos13.0', swift, '-o', launcher, '-framework', 'AppKit']);
  const entitlements = path.join(runtime, 'entitlements.plist');
  const engineEntitlements = path.join(runtime, 'engine-entitlements.plist');
  const originalEntitlements = await execFile('codesign', ['-d', '--entitlements', ':-', original]);
  const originalEngineEntitlements = await execFile('codesign', ['-d', '--entitlements', ':-', path.join(original, 'Contents/MacOS/Chromium')]);
  await writeFile(entitlements, originalEntitlements.stdout, {mode: 0o600});
  await writeFile(engineEntitlements, originalEngineEntitlements.stdout, {mode: 0o600});
  for (const [target, policy, originalEntitlementsFile] of [[engine, originalEnginePolicy, engineEntitlements], [launcher, originalPolicy, entitlements], [app, originalPolicy, entitlements]]) {
    await execFile('codesign', ['--force', '--sign', identity, '--timestamp=none', '--identifier', bundleId,
      '--options', String(policy.options), '--entitlements', originalEntitlementsFile, target]);
    const signed = await signingPolicy(target);
    assert.equal(signed.options, policy.options, 'The disposable QA app must retain the corresponding shipping signing policy.');
    assert.equal(signed.identifier, bundleId, 'Both QA main executables and the app must use the unique QA identifier.');
    assert.equal(signed.team, team, 'QA must retain the selected Apple team.');
    const actualEntitlements = await execFile('codesign', ['-d', '--entitlements', ':-', target]);
    const actualFile = path.join(runtime, 'verified-entitlements.plist');
    await writeFile(actualFile, actualEntitlements.stdout, {mode: 0o600});
    const toJSON = async file => JSON.parse((await execFile('plutil', ['-convert', 'json', '-o', '-', file])).stdout);
    assert.deepEqual(await toJSON(actualFile), await toJSON(originalEntitlementsFile), 'QA signing must preserve the corresponding original entitlements.');
  }
  await execFile('codesign', ['--verify', '--deep', '--strict', app]);
  const copiedNested = await nestedSignatures(app, team);
  assert.deepEqual(copiedNested, originalNested, 'QA must retain the original nested code signatures and policies.');
  const codeSigningPolicy = {teamId: team, outerOptions: originalPolicy.options,
    engineOptions: originalEnginePolicy.options, allResignedIdentifiers: bundleId,
    entitlementsPreserved: true, retainedNestedSignatures: copiedNested.size,
    supersededLauncherRemoved};
  await mkdir(path.join(profile, 'Default'), {recursive: true, mode: 0o700});
  await writeFile(path.join(profile, 'Default/Preferences'), JSON.stringify({
    signin: {allowed: false}, credentials_enable_service: false,
    profile: {password_manager_enabled: false}, browser: {check_default_browser: false}
  }), {mode: 0o600});
  await writeFile(statePath, JSON.stringify({app, bundleId, profile, codeSigningPolicy,
    syntheticInput: dummy, fixtureOrigin: 'https://example.com',
    warning: 'CUA must use this app path. Enter syntheticInput exactly in the native field; AX setValue is permitted. Never open AutoFill → Passwords.'}, null, 2), {mode: 0o600});
  if (prepareOnly) {
    console.log(JSON.stringify({setupVerified: true, browserLaunched: false,
      sourceCompiledLocally: buildInfo.sourceCompiledLocally, codeSigningPolicy,
      passwordPickerOpened: false, nativePasswordBehaviorVerified: false}));
  } else {
  // Launch the same signed, sandboxed QA engine directly. launchPersistentContext
  // enables focus emulation, whose visible capture keeps renderer visibility
  // "visible" even when Chromium's actual native tab has become hidden.
  child = spawn(launcher, ['about:blank'], {stdio: 'ignore'});
  childExit = new Promise(resolve => {
    child.once('exit', (code, signal) => resolve({code, signal}));
    child.once('error', () => { childLaunchFailed = true; resolve({launchFailed: true}); });
  });
  const endpoint = await ownedDevToolsEndpoint();
  browser = await chromium.connectOverCDP(endpoint, {timeout: 15000, noDefaults: true, isLocal: true});
  browserControl = await browser.newBrowserCDPSession();
  const contexts = browser.contexts();
  assert.equal(contexts.length, 1, 'The owned QA browser must expose only its default context.');
  context = contexts[0];
  context.setDefaultTimeout(10000);
  await resetFixture();
  console.log(JSON.stringify({handoff: 'CUA native panels', app, bundleId, statePath,
    focusEmulationDisabled: true, verifiedLoopbackCDP: true,
    instructions: 'Read --help for the four scenarios. Enter the exact native value; AX setValue is permitted. Never open a password picker or use personal credentials.'}));
  input = createInterface({input: process.stdin, crlfDelay: Infinity});
  for await (const line of input) {
    const [command, confirmation] = line.trim().split(/\s+/);
    try {
      if (!command) continue;
      if (command === 'reset') await resetFixture();
      else if (command === 'focus-decoy') {
        await fixture.locator('#decoy').focus(); focusedDecoy = true;
        assert((await fixtureStatus()).decoyFocused, 'Decoy focus did not change.');
        console.log(JSON.stringify({decoyFocusChanged: true}));
      } else if (command === 'navigate') {
        await fixture.goto('about:blank');
        await resetFixture(); navigated = true;
        console.log(JSON.stringify({documentReplaced: true}));
      } else if (command === 'hide') {
        hiddenTab = await context.newPage(); await hiddenTab.goto('about:blank');
        await hiddenTab.bringToFront();
        await fixture.waitForFunction(() => document.visibilityState === 'hidden', null, {timeout: 10000, polling: 100});
        hidden = true; console.log(JSON.stringify({fixtureTabHidden: true}));
      } else if (command === 'show') {
        assert(hidden, 'Run hide first.'); await fixture.bringToFront();
        await fixture.waitForFunction(() => document.visibilityState === 'visible', null, {timeout: 10000, polling: 100});
        shownAgain = true;
        console.log(JSON.stringify({fixtureTabShownAgain: true}));
      } else if (command === 'status') console.log(JSON.stringify(await fixtureStatus()));
      else if (command.startsWith('check-') && ['fill', 'cancel', 'navigation', 'hide'].includes(command.slice(6)))
        await check(command.slice(6), confirmation);
      else if (command === 'finish') {
        assert(['fill', 'cancel', 'navigation', 'hide'].every(name => passed.has(name)), 'Complete all four scenarios before finish.');
        finished = true;
        console.log(JSON.stringify({pass: true, checks: [...passed], syntheticValuesOnly: true})); break;
      } else if (command === 'close') break;
      else throw new Error('Unknown command; read --help.');
    } catch (error) {
      // Assertion messages are fixed descriptions, never observed field values.
      console.error(`QA command failed: ${error.message}`);
    }
  }
  if (!finished) {
    process.exitCode = 1;
    console.log(JSON.stringify({pass: false, aborted: true, completedChecks: [...passed]}));
  }
  }
} finally {
  await cleanup();
}
