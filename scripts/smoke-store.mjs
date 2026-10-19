// Interactive native Store QA; no automatic confirmation or account access.
// Run after packaging: node scripts/smoke-store.mjs
// Use cua_repl or the GUI to click “Install in Kumo”, then “Add theme”.
// Send “status” over stdin to inspect only the installed fixture manifest;
// send “close” (or Ctrl-C) to stop Chromium and remove its disposable profile.
import {access, cp, mkdtemp, mkdir, writeFile, readFile, rm, readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createInterface} from 'node:readline';
import {spawn} from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const executable = path.join(root, 'dist/Kumo.app/Contents/MacOS/Chromium');
const extensionSource = process.env.KUMO_QA_EXTENSION_SOURCE || path.join(root, 'dist/Kumo.app/Contents/Resources/KumoExtension');
const themeId = 'aghfnjkcakhmadgdomlmlhhaocbkloab';
const storeURL = `https://chromewebstore.google.com/detail/just-black/${themeId}`;
await Promise.all([access(executable), access(path.join(extensionSource, 'manifest.json'))]);
const temporary = await mkdtemp(path.join(tmpdir(), 'kumo-store-qa-'));
const extension = path.join(temporary, 'kumo-extension');
let browser;
let input;
let stopped = false;
const stop = () => { stopped = true; input?.close(); };
process.once('SIGINT', stop);
process.once('SIGTERM', stop);

async function installedThemes() {
  const base = path.join(temporary, 'Default/Extensions', themeId);
  let versions;
  try { versions = await readdir(base); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  return Promise.all(versions.sort().map(async directory => {
    const manifest = JSON.parse(await readFile(path.join(base, directory, 'manifest.json'), 'utf8'));
    return {
      id: themeId, directory, name: manifest.name, version: manifest.version,
      manifestVersion: manifest.manifest_version, theme: !!manifest.theme,
      permissions: manifest.permissions || [],
    };
  }));
}

try {
  await cp(extensionSource, extension, {recursive: true});
  await mkdir(path.join(temporary, 'Default'), {recursive: true});
  await writeFile(path.join(temporary, 'Default/Preferences'), JSON.stringify({
    download: {default_directory: path.join(temporary, 'downloads'), prompt_for_download: false},
    signin: {allowed: false},
  }));
  // Keep the native CRX installation flow. Browser automation download
  // interception can alter this flow, so this check deliberately uses no CDP.
  browser = spawn(executable, [
    `--user-data-dir=${temporary}`, `--load-extension=${extension}`,
    '--extension-mime-request-handling=always-prompt-for-install',
    '--no-first-run', '--no-default-browser-check', '--disable-sync',
    '--use-mock-keychain', storeURL,
  ], {stdio: 'ignore'});
  browser.once('exit', stop);
  await new Promise((resolve, reject) => {
    browser.once('spawn', resolve);
    browser.once('error', reject);
  });
  console.log(JSON.stringify({
    ready: true, pid: browser.pid, profile: temporary, storeURL, themeId,
    instructions: 'In this disposable Kumo window, click Install in Kumo, then approve the native Add theme dialog. Confirm the Installed theme infobar. Send status to inspect the installed manifest; send close to clean up.',
  }));
  if (!stopped) {
    input = createInterface({input: process.stdin});
    for await (const line of input) {
      if (line.trim() === 'close') break;
      if (line.trim() === 'status') {
        console.log(JSON.stringify({installedThemes: await installedThemes()}, null, 2));
      }
    }
  }
} finally {
  input?.close();
  if (browser?.pid && browser.exitCode === null && browser.signalCode === null) {
    await new Promise(resolve => {
      const force = setTimeout(() => browser.kill('SIGKILL'), 5000);
      browser.once('exit', () => { clearTimeout(force); resolve(); });
      browser.kill('SIGTERM');
    });
  }
  await rm(temporary, {recursive: true, force: true});
  process.removeListener('SIGINT', stop);
  process.removeListener('SIGTERM', stop);
  console.log(JSON.stringify({closed: true, profileRemoved: true}));
}
