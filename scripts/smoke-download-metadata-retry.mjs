// Fault injection around the unchanged full download-malware harness.
// Only one owned synthetic download receives a private QA xattr; file bytes,
// quarantine, browser flags, production code and original assertions stay intact.
import assert from 'node:assert/strict';
import {createHash, randomUUID} from 'node:crypto';
import {spawn, execFile as execFileCallback} from 'node:child_process';
import {constants, openSync, writeSync, closeSync} from 'node:fs';
import {readFile, writeFile, mkdir, open, lstat, readdir, realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
if (process.argv.includes('--help')) {
  console.log(`Usage: node scripts/smoke-download-metadata-retry.mjs
Runs the existing full download-malware harness twice in fresh disposable profiles.
One QA xattr change during the first benign scan must trigger one complete rescan;
changes during both attempts must fail closed with no third scan or completion.
KUMO_QA_APP selects the source-built app (default dist/Kumo.app).
KUMO_DOWNLOAD_MALWARE_QA_MODE must be cdp (the default); native is tested separately.
KUMO_DOWNLOAD_MALWARE_QA_ARTIFACTS selects a fresh wrapper evidence directory.
Only owned synthetic temporary-download metadata is changed. No accounts, app,
definitions, quarantine or global configuration are changed.`);
  process.exit(0);
}
assert.equal(process.argv.length, 2, 'Only --help is supported.');
const mode = process.env.KUMO_DOWNLOAD_MALWARE_QA_MODE || 'cdp';
assert.equal(mode, 'cdp', 'This metadata fault-injection wrapper currently requires CDP mode.');
const app = path.resolve(process.env.KUMO_QA_APP || path.join(root, 'dist/Kumo.app'));
const helper = path.join(app, 'Contents/Helpers/KumoMalware.app/Contents/MacOS/KumoMalwareHost');
const harness = path.join(root, 'scripts/smoke-download-malware.mjs');
const artifacts = path.resolve(process.env.KUMO_DOWNLOAD_MALWARE_QA_ARTIFACTS ||
  path.join(root, '.cache/qa', `download-metadata-retry-${Date.now()}`));
assert(!artifacts.startsWith(app + path.sep), 'Evidence must stay outside the application.');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const harnessSHA256 = hash(await readFile(harness));
const benign = Buffer.from('Kumo inert antivirus browser QA fixture.\n');
assert.equal(benign.length, 41);
const execFile = promisify(execFileCallback);
const tick = ms => new Promise(resolve => setTimeout(resolve, ms));
await mkdir(artifacts, {mode: 0o700}); // Exclusive: preserve any prior evidence.

const fields = ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'birthtimeNs'];
const metadata = value => Object.fromEntries([...fields, 'ctimeNs'].map(key => [key, value[key].toString()]));
const sameIdentity = (a, b) => fields.every(key => a[key] === b[key]);
const missing = async filename => {
  try { await lstat(filename); return false; } catch (error) { if (error.code === 'ENOENT') return true; throw error; }
};
async function processRows() {
  const {stdout} = await execFile('/bin/ps', ['-axo', 'pid=,ppid=,pgid=,command='], {timeout: 3000, maxBuffer: 4 * 1024 * 1024});
  return stdout.split('\n').map(line => {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/);
    return match ? {pid: +match[1], ppid: +match[2], pgid: +match[3], command: match[4]} : null;
  }).filter(Boolean);
}

// fsetxattr binds the single metadata write to the already-validated read-only
// descriptor. No pathname can redirect the write through a symlink or rename.
const setOwnedXattr = `import ctypes, json, os, stat, sys
fd = 3
expected = json.loads(sys.argv[1]); filename = sys.argv[2]
s = os.fstat(fd); named = os.lstat(filename)
assert stat.S_ISREG(s.st_mode) and stat.S_ISREG(named.st_mode)
assert s.st_uid == os.getuid() and s.st_nlink == 1 and s.st_size == 41
assert s.st_dev == named.st_dev and s.st_ino == named.st_ino
assert str(s.st_dev) == expected['dev'] and str(s.st_ino) == expected['ino']
assert str(s.st_mtime_ns) == expected['mtimeNs'] and str(s.st_size) == expected['size']
name = b'org.kumo.qa.metadata'; value = sys.argv[3].encode('ascii')
libc = ctypes.CDLL(None, use_errno=True)
call = libc.fsetxattr
call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
call.restype = ctypes.c_int
if call(fd, name, value, len(value), 0, 0) != 0:
    raise OSError(ctypes.get_errno(), 'owned QA fsetxattr failed')
print(json.dumps({'attribute': name.decode(), 'bytes': len(value)}))
`;
async function inject(file, scanner, scenario, count) {
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = metadata(await fd.stat({bigint: true}));
    assert.equal(before.uid, String(process.getuid())); assert.equal(before.nlink, '1'); assert.equal(before.size, '41');
    assert.deepEqual(await fd.readFile(), benign, 'Only the exact owned first benign fixture may be tagged.');
    const named = await lstat(file, {bigint: true});
    assert(named.isFile() && !named.isSymbolicLink()); assert(sameIdentity(before, metadata(named)));
    const value = `${scenario}-${count}-${randomUUID()}`;
    await new Promise((resolve, reject) => {
      const child = spawn('/usr/bin/python3', ['-c', setOwnedXattr, JSON.stringify(before), file, value],
        {stdio: ['ignore', 'pipe', 'pipe', fd.fd]});
      let output = ''; const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
      child.stdout.on('data', bytes => { output += bytes; if (output.length > 2048) child.kill('SIGKILL'); });
      child.stderr.on('data', bytes => { output += bytes; if (output.length > 2048) child.kill('SIGKILL'); });
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('close', code => { clearTimeout(timer); code === 0 ? resolve() : reject(new Error(`Owned xattr writer exited ${code}: ${output.slice(0, 2048)}`)); });
    });
    const after = metadata(await fd.stat({bigint: true}));
    assert(sameIdentity(before, after), 'The injection must preserve content metadata and identity.');
    assert.notEqual(before.ctimeNs, after.ctimeNs, 'The injection must actually change ctime.');
    const checkedBytes = Buffer.alloc(benign.length);
    const checked = await fd.read(checkedBytes, 0, checkedBytes.length, 0);
    assert.equal(checked.bytesRead, benign.length);
    assert.deepEqual(checkedBytes, benign, 'The injection must leave every content byte unchanged.');
    assert(sameIdentity(after, metadata(await lstat(file, {bigint: true}))), 'The target must remain bound to the tagged descriptor.');
    return {at: Date.now(), scanner, file, attribute: 'org.kumo.qa.metadata', value, before, after,
      sha256: hash(benign), descriptorBoundWrite: true};
  } finally { await fd.close(); }
}

async function firstDownload(directory, port) {
  const file = path.join(directory, 'cdp-protocol.log');
  if (await missing(file)) return null;
  const stream = await open(file, 'r');
  try {
    const bytes = Buffer.alloc(2 * 1024 * 1024); const {bytesRead} = await stream.read(bytes, 0, bytes.length, 0);
    for (const line of bytes.subarray(0, bytesRead).toString().split('\n')) {
      const marker = line.indexOf('◀ RECV '); if (marker < 0 || !line.includes('downloadWillBegin')) continue;
      let event; try { event = JSON.parse(line.slice(marker + '◀ RECV '.length)); } catch { continue; }
      if (!['Browser.downloadWillBegin', 'Page.downloadWillBegin'].includes(event.method)) continue;
      if (event.params?.url !== `http://127.0.0.1:${port}/fixtures/benign`) continue;
      assert.equal(event.params.suggestedFilename, 'kumo-benign.txt');
      assert.match(event.params.guid, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      return {guid: event.params.guid, at: Date.now()};
    }
    return null;
  } finally { await stream.close(); }
}

async function scenario(name, maximumInjections) {
  assert.equal(hash(await readFile(harness)), harnessSHA256, 'The original harness changed.');
  const directory = path.join(artifacts, name);
  const logFD = openSync(path.join(artifacts, `${name}.log`), 'wx', 0o600);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('KUMO_')));
  Object.assign(env, {KUMO_QA_APP: app, KUMO_DOWNLOAD_MALWARE_QA_MODE: mode, KUMO_DOWNLOAD_MALWARE_QA_ARTIFACTS: directory});
  const child = spawn(process.execPath, [harness], {cwd: root, env, stdio: ['ignore', 'pipe', 'pipe']});
  let closed = false, qa, stdoutLine = '', logBytes = 0, logTruncated = false, observationError;
  const injections = [], scanners = new Map(), observations = [];
  let first, target, targetGone, removedBeforeCleanup = false;
  const close = new Promise((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => { closed = true; resolve({code, signal}); });
  });
  const log = bytes => {
    if (logBytes + bytes.length <= 2 * 1024 * 1024) { writeSync(logFD, bytes); logBytes += bytes.length; }
    else logTruncated = true;
  };
  child.stderr.on('data', log);
  child.stdout.on('data', bytes => {
    log(bytes); stdoutLine += bytes.toString();
    let newline;
    while ((newline = stdoutLine.indexOf('\n')) !== -1) {
      const line = stdoutLine.slice(0, newline); stdoutLine = stdoutLine.slice(newline + 1);
      if (line.startsWith('{"qaPaths":')) {
        try { qa = JSON.parse(line); } catch (error) { observationError ||= error; }
      }
    }
    if (stdoutLine.length > 65536) { observationError ||= new Error('Unexpected oversized harness output line.'); stdoutLine = ''; }
  });
  const observedAt = Date.now();
  // The unchanged harness bounds each scan and owns teardown. The observer never
  // signals its processes; its own first-download sampling stops after210s.
  const observe = (async () => {
    try {
      while (!qa && !closed && Date.now() - observedAt < 60000) await tick(50);
      assert(qa, 'The original harness must emit its owned QA paths.');
      assert.equal(qa.app, app); assert.equal(qa.mode, mode); assert.equal(qa.qaPaths.artifacts, directory);
      const temporary = path.resolve(qa.qaPaths.temporary), systemTemporary = await realpath(tmpdir());
      assert.equal(path.dirname(await realpath(temporary)), systemTemporary);
      assert(path.basename(temporary).startsWith('kumo-download-malware-qa-'));
      const temporaryState = await lstat(temporary);
      assert(temporaryState.isDirectory() && !temporaryState.isSymbolicLink());
      assert.equal(temporaryState.uid, process.getuid()); assert.equal(temporaryState.mode & 0o777, 0o700);
      assert.equal(qa.qaPaths.profile, path.join(temporary, 'profile'));
      assert.equal(qa.qaPaths.downloads, path.join(temporary, 'downloads'));
      while (!closed && Date.now() - observedAt < 210000 && !observationError) {
        first ||= await firstDownload(directory, qa.port);
        if (!first) { await tick(50); continue; }
        const downloads = qa.qaPaths.downloads;
        if (target && await missing(target)) {
          targetGone = Date.now();
          if (!await missing(downloads)) {
            const names = await readdir(downloads);
            removedBeforeCleanup = !names.some(value => value === path.basename(target) ||
              value === first.guid || value === 'kumo-benign.txt');
          }
          break; // Never write or count another fixture's scanner after this path disappears.
        }
        const rows = await processRows();
        const browser = rows.find(row => row.ppid === child.pid && row.command.startsWith(`${app}/Contents/MacOS/Chromium `) &&
          row.command.includes(`--user-data-dir=${qa.qaPaths.profile}`) && !row.command.includes('--type='));
        if (!browser) { await tick(50); continue; }
        const helpers = rows.filter(row => row.ppid === browser.pid && row.command.trim() === helper);
        const active = rows.filter(row => row.command.startsWith('/usr/local/clamav/bin/clamscan ') && helpers.some(item => item.pid === row.ppid));
        if (!target && active.length) {
          const names = (await readdir(downloads)).filter(value => value.endsWith('.crdownload'));
          const eligible = [];
          for (const value of names) {
            const file = path.join(downloads, value), state = await lstat(file, {bigint: true});
            if (state.isFile() && state.size === 41n && state.nlink === 1n && state.uid === BigInt(process.getuid()) &&
                value === `${first.guid}.crdownload` && (await readFile(file)).equals(benign)) eligible.push(file);
          }
          assert(eligible.length <= 1, 'The first owned synthetic target must be unambiguous.');
          target = eligible[0];
        }
        // Recheck after the process snapshot: a later fixture's scanner cannot
        // be counted as this GUID's retry once its intermediate path is gone.
        if (target && await missing(target)) continue;
        if (target) for (const scanner of active) {
          const parent = helpers.find(item => item.pid === scanner.ppid);
          assert.equal(scanner.pgid, parent.pgid);
          if (!scanners.has(scanner.pid)) {
            scanners.set(scanner.pid, {pid: scanner.pid, ppid: scanner.ppid, pgid: scanner.pgid, browserPid: browser.pid, at: Date.now()});
            assert(scanners.size <= 2, 'The first download must never receive a third scanner attempt.');
            if (injections.length < maximumInjections && !await missing(target))
              injections.push(await inject(target, scanners.get(scanner.pid), name, injections.length + 1));
          }
          if (observations.length < 5000) observations.push({at: Date.now(), scannerPid: scanner.pid, file: target});
        }
        await tick(50);
      }
      if (!closed && !targetGone) assert.fail('The bounded first-download observer did not observe its target disappear.');
    } catch (error) { observationError ||= error; }
  })();
  let exit;
  try { [exit] = await Promise.all([close, observe]); } finally { closeSync(logFD); }
  const evidence = {scenario: name, app, mode, harnessSHA256, harnessExit: exit, firstDownload: first,
    target, targetGone, removedBeforeCleanup, injections, scanners: [...scanners.values()], observations,
    logTruncated, observationError: observationError ? {name: observationError.name, message: observationError.message} : null};
  await writeFile(path.join(artifacts, `${name}-observer.json`), JSON.stringify(evidence, null, 2), {flag: 'wx'});
  assert(!observationError, observationError?.message); assert.equal(logTruncated, false);
  assert.equal(injections.length, maximumInjections); assert.equal(scanners.size, 2);
  const result = JSON.parse(await readFile(path.join(directory, 'results.json'), 'utf8'));
  assert.equal(result.cleanup?.passed, true); assert.equal(result.cleanup.temporaryRemoved, true);
  assert.deepEqual(result.cleanup.remainingNative, []);
  assert(await missing(qa.qaPaths.temporary), 'The original harness must remove its disposable profile and downloads.');
  assert.equal(hash(await readFile(harness)), harnessSHA256, 'The original harness changed during the run.');
  if (name === 'once') {
    assert.equal(exit.code, 0); assert.equal(result.passed, true); assert.equal(result.cases.length, 6);
    const firstCase = result.cases.find(item => item.id === 'benign');
    assert(firstCase); assert.equal(firstCase.nativeTerminal.state, 2); assert(firstCase.quarantine);
    assert.equal(firstCase.guid, first.guid);
    assert.equal(firstCase.cdpTerminal.guid, first.guid);
    assert.equal(firstCase.cdpTerminal.state, 'completed');
    assert(scanners.values().next().value.at < targetGone);
    assert([...scanners.values()][1].at < firstCase.cdpTerminal.at,
      'The second scanner must be observed before this download completes.');
  } else {
    assert.equal(exit.code, 1); assert.equal(result.passed, false); assert.equal(result.cases.length, 0);
    assert.equal(removedBeforeCleanup, true, 'Blocked intermediate/final paths must disappear before QA cleanup.');
    const progress = result.nativeEvents.filter(event => event.type === 'progress' && event.guid === first.guid);
    assert(progress.length); assert(!progress.some(event => event.state === 'completed' || event.state === 2));
    assert.equal(progress.at(-1).state, 'canceled');
    assert.deepEqual(result.unexpectedRequests, []); assert.deepEqual(result.pageErrors, []);
  }
  return {scenario: name, passed: true, injections: injections.length, scannerAttempts: scanners.size,
    originalHarnessExitCode: exit.code, originalHarnessCasesPassed: result.cases.length,
    observer: path.join(artifacts, `${name}-observer.json`), results: path.join(directory, 'results.json')};
}

const results = [];
let failure;
try {
  results.push(await scenario('once', 1));
  results.push(await scenario('repeated', 2));
} catch (error) { failure = {name: error.name, message: error.message, stack: error.stack}; }
const result = {passed: !failure, app, mode, harnessSHA256, results, failure,
  limitations: ['Synthetic metadata fault injection only; existing full native/CDP matrices remain required.',
    'The repeated-change child harness intentionally fails its original benign-completion assertion; this wrapper additionally requires fail-closed evidence.']};
await writeFile(path.join(artifacts, 'results.json'), JSON.stringify(result, null, 2), {flag: 'wx'});
console.log(JSON.stringify(result, null, 2));
if (failure) process.exitCode = 1;
