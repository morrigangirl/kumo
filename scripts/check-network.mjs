// Optional live checks of the packaged runtime. No account sign-in is involved.
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
const temp = await mkdtemp(path.join(tmpdir(), 'kumo-tls-'));
let context;
try {
  context = await chromium.launchPersistentContext(temp, {
    executablePath: path.join(root, 'dist/Kumo.app/Contents/MacOS/Chromium'),
    headless: true, chromiumSandbox: true, args: ['--no-first-run', '--disable-sync', ...(process.argv.includes('--tcp') ? ['--disable-quic'] : [])]
  });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('Network.enable');
  let details;
  cdp.on('Network.responseReceived', event => {
    if (event.response.url === 'https://www.cloudflare.com/cdn-cgi/trace') details = event.response.securityDetails;
  });
  await page.goto('https://www.cloudflare.com/cdn-cgi/trace', {waitUntil: 'domcontentloaded', timeout: 30000});
  if (!details) throw new Error('TLS security details were not returned.');
  const result = {protocol: details.protocol, cipher: details.cipher, keyExchangeGroup: details.keyExchangeGroup, invalidCertificateRejected: false};
  try { await page.goto('https://expired.badssl.com/', {waitUntil: 'domcontentloaded', timeout: 20000}); }
  catch (error) {
    const code = error.message.match(/ERR_CERT_[A-Z_]+/)?.[0];
    if (code) { result.invalidCertificateRejected = true; result.certificateRejection = code; }
    else throw error;
  }
  if (!result.invalidCertificateRejected) throw new Error('Expired certificate was not rejected.');
  await writeFile(path.join(root, 'dist/network-check.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result, null, 2));
} finally { await context?.close(); await rm(temp, {recursive: true, force: true}); }
