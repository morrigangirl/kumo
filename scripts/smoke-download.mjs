// Source-build QA: verify the original downloaded file, before any save/copy
// could discard its quarantine metadata. A local inert text fixture is used.
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {execFile as execFileCallback} from 'node:child_process';
import {promisify} from 'node:util';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {nativeQAApp, nativeQAEnvironment} from './native-browser-qa.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const {executable, verifyUnchanged} = await nativeQAApp();
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const execFile = promisify(execFileCallback);
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-download-qa-'));
const environment = await nativeQAEnvironment(temporary);
const payload = 'Kumo inert download-quarantine QA fixture.\n';
const server = createServer((request, response) => {
  if (request.url === '/fixture.txt') {
    response.writeHead(200, {'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename="kumo-qa-fixture.txt"'});
    response.end(payload);
  } else {
    response.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
    response.end('<!doctype html><title>Kumo download QA</title><a href="/fixture.txt">Download inert fixture</a>');
  }
});
let context;
try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  context = await chromium.launchPersistentContext(path.join(temporary, 'profile'), {
    executablePath: executable, env: environment, headless: true,
    chromiumSandbox: true, acceptDownloads: true, downloadsPath: path.join(temporary, 'downloads'),
    args: ['--no-first-run', '--no-default-browser-check', '--disable-sync', '--use-mock-keychain'],
  });
  const page = await context.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', {name: 'Download inert fixture'}).click()]);
  const original = await download.path();
  assert.equal(await download.failure(), null);
  assert.equal(download.suggestedFilename(), 'kumo-qa-fixture.txt');
  assert.equal(await readFile(original, 'utf8'), payload);
  const {stdout} = await execFile('xattr', ['-p', 'com.apple.quarantine', original]);
  assert.match(stdout.trim(), /^[0-9a-f]+;[0-9a-f]+;[^;]+;/i, 'macOS quarantine metadata must exist on the original download');
  console.log(JSON.stringify({passed: true, quarantinePresent: true, originalDownloadChecked: true, inertLocalFixture: true}));
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
