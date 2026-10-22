// Shared isolation for native-browser QA. Never defaults to a personal app.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdir, readFile, realpath} from 'node:fs/promises';
import path from 'node:path';
import {promisify} from 'node:util';

async function nativeQASeal(app) {
  await promisify(execFile)('/usr/bin/codesign', ['--verify', '--deep', '--strict', '-R', '=anchor apple generic and identifier "app.kumo.browser" and certificate leaf[subject.OU] = "PV65ZWXCWX"', app]);
  const details = await promisify(execFile)('/usr/bin/codesign', ['-dvvv', app]);
  const hash = /^CDHash=([a-f0-9]{40})$/m.exec(details.stdout + details.stderr)?.[1];
  assert(hash, 'The selected QA app must have an inspectable code signature.');
  const seal = await readFile(path.join(app, 'Contents/_CodeSignature/CodeResources'));
  return {codeDirectoryHash: hash, resourceSealSHA256: createHash('sha256').update(seal).digest('hex')};
}

export async function nativeQAApp() {
  assert(process.env.KUMO_QA_APP, 'Set KUMO_QA_APP to a freshly packaged native Kumo.app.');
  const app = await realpath(process.env.KUMO_QA_APP);
  assert(app.endsWith('/Kumo.app') && !app.split(path.sep).includes('Applications'), 'Use a separate QA app outside system and user Applications folders.');
  const info = JSON.parse(await readFile(path.join(app, 'Contents/Resources/kumo-build-info.json'), 'utf8'));
  assert.equal(info.sourceCompiledLocally, true);
  assert.equal(info.nativeIntegration?.included, true);
  assert.equal(info.nativeIntegration?.extensionRequired, false);
  const signatureBefore = await nativeQASeal(app);
  const verifyUnchanged = async () => {
    const signatureAfter = await nativeQASeal(app);
    assert.deepEqual(signatureAfter, signatureBefore, 'The browser app signature or sealed resources changed during QA.');
    return {before: signatureBefore, after: signatureAfter, unchanged: true};
  };
  return {app, info, executable: path.join(app, 'Contents/MacOS/Chromium'), verifyUnchanged};
}

export async function nativeQAEnvironment(temporary) {
  const home = path.join(temporary, 'home'), tmp = path.join(temporary, 'tmp');
  await mkdir(home, {mode: 0o700});
  await mkdir(tmp, {mode: 0o700});
  // base::GetHomeDir() uses NSHomeDirectory() on macOS; HOME alone is not
  // sufficient. The native suite separately proves this Foundation isolation.
  return {PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: home,
    CFFIXED_USER_HOME: home, TMPDIR: tmp, LANG: 'en_US.UTF-8',
    XDG_CONFIG_HOME: path.join(home, '.config'), XDG_CACHE_HOME: path.join(home, '.cache'),
    CODEX_HOME: path.join(home, '.codex')};
}
