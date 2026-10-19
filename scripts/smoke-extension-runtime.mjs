// Reproduce Chromium's actual DNR cache writes without letting an unpacked
// extension modify the sealed app. Every profile is disposable and explicit.
import assert from 'node:assert/strict';
import {execFile as execFileCallback} from 'node:child_process';
import {promisify} from 'node:util';
import {chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

if (process.argv.includes('--help')) {
  console.log(`Usage: node scripts/smoke-extension-runtime.mjs
Validates a signed Kumo.app using the exact production Swift extension-runtime
functions, an explicit disposable profile, and two sandboxed Chromium launches.
Verifies the full static DNR ruleset, actual generated cache permissions, reuse,
unchanged sealed resources and an unchanged deep strict app signature.
KUMO_QA_APP selects the app; KUMO_EXTENSION_RUNTIME_ARTIFACTS selects evidence.
No normal profile, keychain, account, public website or remote feed is used.`);
  process.exit(0);
}
assert.equal(process.argv.length, 2, 'Use --help for supported options.');
assert.equal(process.platform, 'darwin', 'This test requires native macOS.');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = path.resolve(process.env.KUMO_QA_APP || path.join(root, 'dist/Kumo.app'));
const source = path.join(app, 'Contents/Resources/KumoExtension');
const engine = path.join(app, 'Contents/MacOS/Chromium');
const artifacts = path.resolve(process.env.KUMO_EXTENSION_RUNTIME_ARTIFACTS ||
  path.join(root, '.cache/qa/malware-protection-2026-10-19/runtime-extension-final-001'));
const execFile = promisify(execFileCallback);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha256 = value => createHash('sha256').update(value).digest('hex');
const mode = state => (state.mode & 0o777).toString(8).padStart(4, '0');
await mkdir(artifacts, {recursive: true, mode: 0o700});
await chmod(artifacts, 0o700);
const temporary = await mkdtemp('/private/tmp/kumo-extension-runtime-qa-');
const profile = path.join(temporary, 'profile');
const helperSource = path.join(artifacts, 'runtime-helper.swift');
const helper = path.join(artifacts, 'runtime-helper');
const checks = [], launches = [], cacheStates = [], runtimeReuse = [], requestAttempts = [];
let context, failure, result, extension, sourceBefore, signatureBefore;

async function eventually(operation, description, timeout = 20000) {
  let lastError;
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try { const value = await operation(); if (value) return value; } catch (error) { lastError = error; }
    await delay(100);
  }
  throw new Error(`${description}: ${lastError?.message || 'condition did not become true'}`);
}

async function sourceSnapshot(directory, relative = '') {
  const entries = [];
  for (const name of (await readdir(directory)).sort()) {
    const next = path.join(directory, name), local = relative ? `${relative}/${name}` : name;
    const state = await lstat(next);
    assert(!state.isSymbolicLink(), 'The sealed source must not contain symlinks.');
    if (state.isDirectory()) {
      entries.push({path: local, type: 'directory'});
      entries.push(...await sourceSnapshot(next, local));
    } else {
      assert(state.isFile(), 'The sealed source must contain only files and directories.');
      entries.push({path: local, type: 'file', bytes: state.size, sha256: sha256(await readFile(next))});
    }
  }
  return entries;
}

async function signature() {
  await execFile('/usr/bin/codesign', ['--verify', '--deep', '--strict', '--verbose=2', app], {timeout: 120000});
  const {stderr} = await execFile('/usr/bin/codesign', ['--display', '--verbose=4', app]);
  const value = {
    cdHash: stderr.match(/^CDHash=(\S+)$/m)?.[1], teamID: stderr.match(/^TeamIdentifier=(\S+)$/m)?.[1],
    flags: stderr.match(/^CodeDirectory .* flags=(\S+)/m)?.[1],
    codeResourcesSHA256: sha256(await readFile(path.join(app, 'Contents/_CodeSignature/CodeResources'))),
  };
  assert.match(value.cdHash || '', /^[a-f0-9]{40}$/);
  assert.equal(value.teamID, 'PV65ZWXCWX');
  return value;
}

async function prepare() {
  const value = (await execFile(helper, [source, profile], {timeout: 30000})).stdout.trim();
  assert.equal(path.dirname(value), path.join(profile, 'ExtensionRuntime'));
  assert.match(path.basename(value), /^[a-f0-9]{64}$/);
  return value;
}

async function runtimeCodeState() {
  const value = [];
  for (const entry of sourceBefore.filter(entry => entry.type === 'file')) {
    const file = path.join(extension, entry.path), state = await lstat(file);
    assert(state.isFile() && !state.isSymbolicLink());
    assert.equal(mode(state), '0600');
    assert.equal(state.nlink, 1);
    assert.equal(state.uid, process.getuid());
    assert.equal(sha256(await readFile(file)), entry.sha256);
    value.push({path: entry.path, sha256: entry.sha256, bytes: state.size, mtimeMs: state.mtimeMs});
  }
  assert.equal(mode(await lstat(extension)), '0700');
  return value;
}

async function cacheState() {
  const files = ['_metadata', '_metadata/generated_indexed_rulesets', '_metadata/generated_indexed_rulesets/_ruleset1'];
  const value = [];
  for (const name of files) {
    const state = await lstat(path.join(extension, name));
    assert(!state.isSymbolicLink() && state.uid === process.getuid());
    assert.equal(state.mode & 0o022, 0, 'Generated cache must not be group/other writable.');
    assert(name.endsWith('_ruleset1') ? state.isFile() && state.size > 0 : state.isDirectory());
    value.push({path: name, mode: mode(state), bytes: state.size});
  }
  return value;
}

const processRows = async () => (await execFile('/bin/ps', ['-axo', 'pid=,ppid=,command='])).stdout.split('\n').flatMap(line => {
  const match = line.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/);
  return match ? [{pid: +match[1], ppid: +match[2], command: match[3]}] : [];
});
const isOwned = row => row.command.startsWith(`${app}/Contents/`) && row.command.includes(`--user-data-dir=${profile}`);

try {
  sourceBefore = await sourceSnapshot(source);
  assert(!sourceBefore.some(entry => entry.path === '_metadata' || entry.path.startsWith('_metadata/')),
    'A fresh signed app must contain no Chromium-generated DNR cache.');
  signatureBefore = await signature();
  const swift = await readFile(path.join(root, 'native/launcher/main.swift'), 'utf8');
  const marker = '// Fixed setup actions run relative to this app.';
  assert.equal(swift.split(marker).length, 2, 'The production runtime helper boundary must remain unambiguous.');
  const prefix = swift.split(marker)[0];
  await writeFile(helperSource, `${prefix}
do {
    guard CommandLine.arguments.count == 3 else { exit(2) }
    let source = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    let profile = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
    print(try prepareExtensionRuntime(source: source, profile: profile).path)
} catch { fputs("runtime-helper: \\(error.localizedDescription)\\n", stderr); exit(1) }
`, {mode: 0o600});
  const compilation = await execFile('/usr/bin/swiftc', ['-O', '-module-cache-path', path.join(artifacts, 'modules'),
    helperSource, '-o', helper, '-framework', 'AppKit'], {timeout: 120000});
  await writeFile(path.join(artifacts, 'swift-compile.log'), compilation.stdout + compilation.stderr, {mode: 0o600});
  await chmod(helper, 0o700);
  extension = await prepare();
  const originalCode = await runtimeCodeState();
  checks.push('Exact production Swift runtime functions compile and create a private complete extension copy from signed resources.');
  const eid = (await readFile(path.join(root, 'config/extension-id.txt'), 'utf8')).trim();
  assert.match(eid, /^[a-p]{32}$/);
  const manifest = JSON.parse(await readFile(path.join(source, 'manifest.json'), 'utf8'));
  const ruleResource = manifest.declarative_net_request.rule_resources.find(rule => rule.id === 'kumo_malware');
  assert.equal(ruleResource.enabled, true);
  const rules = JSON.parse(await readFile(path.join(source, ruleResource.path), 'utf8'));
  const metadata = JSON.parse(await readFile(path.join(source, 'malware/metadata.json'), 'utf8'));
  const owners = new Map(rules.flatMap(rule => rule.condition.requestDomains.map(domain => [domain, rule.id])));
  const representatives = rules.map(rule => ({ruleId: rule.id, domain: rule.condition.requestDomains.find(domain => {
    let ancestor = domain;
    while (ancestor.includes('.')) {
      ancestor = ancestor.slice(ancestor.indexOf('.') + 1);
      if (owners.has(ancestor) && owners.get(ancestor) !== rule.id) return false;
    }
    return true;
  })}));
  assert(representatives.every(rule => rule.domain), 'Every grouped rule must have an unambiguous representative.');
  const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
  for (let launch = 1; launch <= 2; launch++) {
    context = await chromium.launchPersistentContext(profile, {
      executablePath: engine, headless: true, chromiumSandbox: true, timeout: 90000,
      ignoreDefaultArgs: ['--disable-extensions'], viewport: {width: 1200, height: 850},
      args: [`--load-extension=${extension}`, '--no-first-run', '--no-default-browser-check', '--disable-sync',
        '--use-mock-keychain', '--password-store=basic', '--no-proxy-server', '--host-resolver-rules=MAP * ~NOTFOUND'],
      env: {...process.env, KUMO_AGENT_DIR: path.join(temporary, 'agents')},
    });
    await context.route(/^https?:\/\//, route => { requestAttempts.push(route.request().url()); return route.abort(); });
    const page = await context.newPage();
    await page.goto(`chrome-extension://${eid}/newtab.html`);
    const status = await eventually(async () => {
      const value = await page.evaluate(() => chrome.runtime.sendMessage({type: 'malware.status'}));
      return value?.ok && value.available ? value : false;
    }, 'The unchanged packaged extension must initialize malware protection');
    assert.equal(status.enabled, true);
    assert.equal(status.domainCount, metadata.domainCount);
    const native = await page.evaluate(async ({rulesetId, representatives}) => {
      const dnr = chrome.declarativeNetRequest, matches = [];
      for (const rule of representatives) {
        const outcome = await dnr.testMatchOutcome({url: `https://${rule.domain}/kumo-runtime-cache-qa`, type: 'main_frame'});
        matches.push({ruleId: rule.ruleId, matched: outcome.matchedRules.some(item => item.rulesetId === rulesetId && item.ruleId === rule.ruleId)});
      }
      return {enabledRulesets: await dnr.getEnabledRulesets(), disabledRuleIds: await dnr.getDisabledRuleIds({rulesetId}), matches};
    }, {rulesetId: ruleResource.id, representatives});
    assert(native.enabledRulesets.includes(ruleResource.id));
    assert.deepEqual(native.disabledRuleIds, []);
    assert.equal(native.matches.length, rules.length);
    assert(native.matches.every(rule => rule.matched), 'Every packaged static rule must match in native Chromium after each launch.');
    const agents = await page.evaluate(() => chrome.runtime.sendMessage({type: 'agent.status'}));
    assert.equal(agents.enabled, false); assert.deepEqual(agents.grants, []);
    launches.push({launch, status, native, agentsEnabled: agents.enabled, grants: agents.grants});
    await context.close(); context = undefined;
    cacheStates.push({launch, entries: await cacheState()});
    const before = await runtimeCodeState();
    assert.deepEqual(before, originalCode, 'Chromium must not modify runtime source files.');
    assert.equal(await prepare(), extension, 'Production helper must verify and reuse the real Chromium-populated runtime.');
    const after = await runtimeCodeState();
    assert.deepEqual(after, before, 'Reusing a cache-populated runtime must not rewrite source assets.');
    runtimeReuse.push({launch, sameDirectory: true, codeBytesAndMtimesUnchanged: true});
    assert.deepEqual(await sourceSnapshot(source), sourceBefore, 'The sealed source files must remain exactly unchanged.');
    assert.deepEqual(await signature(), signatureBefore, 'Strict signed app identity must remain unchanged after a real extension load.');
    checks.push(`Browser launch ${launch}: every static DNR rule active; actual cache remains outside the seal; production verification/reuse and deep strict signature pass.`);
  }
  result = {passed: true, checks, productionPrefixSHA256: sha256(prefix), helperSHA256: sha256(await readFile(helper)),
    signatureBefore, signatureAfter: await signature(), sourceFiles: sourceBefore, sourceUnchanged: true,
    runtimeDirectoryMode: mode(await lstat(extension)), cacheStates, runtimeReuse, launches,
    productionRuleCount: rules.length, productionDomainCount: metadata.domainCount, requestAttempts,
    browserLaunches: launches.length, sandbox: true, mockKeychain: true, agentsOff: true,
    publicNetworkRequired: false, networkPolicy: 'All DNS denied; no proxy; HTTP(S) page requests aborted; native hypothetical DNR matching sends no requests.',
    personalProfileAccessed: false, accountAccessed: false, limits: ['Validates signed app/runtime/DNR integration; no feed update or antivirus detection coverage.']};
} catch (error) {
  failure = error;
  result = {passed: false, checks, error: {name: error.name, message: error.message, stack: error.stack},
    launches, cacheStates, runtimeReuse, requestAttempts, signatureBefore};
} finally {
  try { await context?.close(); } catch (error) { failure ||= error; }
  const recoveredPids = [];
  for (const signal of ['SIGTERM', 'SIGKILL']) {
    for (const row of (await processRows()).filter(isOwned)) {
      const current = (await processRows()).find(item => item.pid === row.pid);
      if (!current || !isOwned(current)) continue;
      try { process.kill(row.pid, signal); recoveredPids.push({pid: row.pid, signal}); }
      catch (error) { if (error.code !== 'ESRCH') failure ||= error; }
    }
    await delay(300);
  }
  const remaining = await eventually(async () => {
    const rows = (await processRows()).filter(row => row.command.includes(temporary));
    return rows.length === 0 ? [] : false;
  }, 'Owned disposable Chromium must exit before profile removal', 10000).catch(async error => {
    failure ||= error; return (await processRows()).filter(row => row.command.includes(temporary)).map(({pid, ppid}) => ({pid, ppid}));
  });
  if (!remaining.length) await rm(temporary, {recursive: true, force: true});
  const cleanup = {temporaryRemoved: remaining.length === 0, ownedRemaining: remaining, recoveredPids};
  result ||= {passed: false, checks};
  result.cleanup = cleanup;
  if (failure) result.passed = false;
  await writeFile(path.join(artifacts, 'cleanup.json'), JSON.stringify(cleanup, null, 2) + '\n', {mode: 0o600});
  await writeFile(path.join(artifacts, 'results.json'), JSON.stringify(result, null, 2) + '\n', {mode: 0o600});
  console.log(JSON.stringify({passed: result.passed, checks, browserLaunches: launches.length, cleanup, artifacts}, null, 2));
}
if (failure) throw failure;
