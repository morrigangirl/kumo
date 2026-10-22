// Native Chromium integration QA. Run only an explicit freshly packaged app.
// Codex/AV/updater mutations are excluded. The one Claude setup case requires
// an independently proven disposable home and never launches a desktop client.
// The actual signed app is never copied or modified.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFile, spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {createConnection} from 'node:net';
import {mkdtemp, mkdir, readFile, writeFile, realpath, lstat, readdir, rm} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';

const execute = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const legacyId = 'eldkgppmnhligdekahicdcdndcoongio';
const blockedHost = 'blocked.kumo-qa.invalid';
const fixtureResolverRules = `MAP ${blockedHost} 127.0.0.1, MAP * ^NOTFOUND, EXCLUDE 127.0.0.1`;
const sha = text => createHash('sha256').update(text).digest('hex');
const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const listen = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
const closeServer = server => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); });
async function bounded(operation, label, milliseconds = 5000) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(operation), new Promise((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`QA operation timed out: ${label}`)), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}
function navigationReleasedPause(error) {
  const response = 'Can only perform operation while paused.';
  return [response, `Protocol error (Debugger.resume): ${response}`,
    `cdpSession.send: Protocol error (Debugger.resume): ${response}`].includes(error?.message);
}
function ownedCDPEndpoint(text) {
  const [port, target] = text.trim().split('\n');
  assert(/^\d{1,5}$/.test(port) && +port > 0 && +port < 65536);
  assert(/^\/devtools\/browser\/[a-zA-Z0-9-]+$/.test(target));
  return `ws://127.0.0.1:${port}${target}`;
}
async function processIdentity(pid) {
  try {
    const {stdout} = await execute('/bin/ps', ['-ww', '-p', String(pid), '-o', 'pid=,ppid=,lstart=,comm='], {env:{PATH:'/usr/bin:/bin',LC_ALL:'C',LANG:'C'}});
    return stdout.trim().replace(/\s+/g, ' ');
  } catch (error) { if (error.code === 1) return ''; throw error; }
}
function sameProcessIdentity(current, original) {
  return !!current && current.replace(/^(\d+) \d+ /, '$1 ') === original.replace(/^(\d+) \d+ /, '$1 ');
}
function allowedOwnedPage(value, origins, extensionId) {
  if (value === 'about:blank') return true;
  try {
    const url = new URL(value);
    if (url.username || url.password) return false;
    if (url.protocol === 'chrome:') return !url.search && !url.hash &&
      (url.host === 'settings' && url.pathname === '/kumo' ||
       ['newtab','new-tab-page','kumo-new-tab'].includes(url.host) && url.pathname === '/');
    if (url.protocol === 'chrome-extension:') return extensionId && url.host === extensionId && url.pathname === '/qa.html';
    return origins.includes(url.origin);
  } catch { return false; }
}
const blockedErrorDocument = 'chrome-error://chromewebdata/';
function expectedBlockedNavigationCandidate(page, value, scope, now = Date.now()) {
  if (!scope || scope.page !== page || now > scope.expiresAt) return false;
  try {
    const target = new URL(scope.target);
    if (target.protocol !== 'http:' || target.hostname !== blockedHost || !target.port ||
        target.pathname !== '/main' || target.search || target.hash || target.username || target.password) return false;
    return value === scope.target || value === blockedErrorDocument;
  } catch { return false; }
}
function expectedBlockedFrameMatches(frame, scope, now = Date.now()) {
  return frame?.id === scope.frameId && frame.unreachableUrl === scope.target &&
    expectedBlockedNavigationCandidate(scope.page, frame.url, scope, now);
}
async function ownedBrowserChildren(browserPid, app) {
  const {stdout} = await execute('/bin/ps', ['-ww','-axo','pid=,ppid=,lstart=,comm='], {env:{PATH:'/usr/bin:/bin',LC_ALL:'C',LANG:'C'}});
  return stdout.split('\n').map(line => line.trim().replace(/\s+/g, ' ')).filter(line => {
    const [pid, parent] = line.split(' '); return /^\d+$/.test(pid) && +parent === browserPid && line.includes(`${app}/Contents/`);
  }).map(identity => ({pid:+identity.split(' ')[0], identity}));
}
async function cleanupDebugger(session, breakpointId, {remove = true, resume = true} = {}, milliseconds = 5000) {
  const failures = [];
  // Each operation has its own budget. A stalled removal must never prevent
  // the independent resume and detach attempts that release the owned renderer.
  const operations = [
    ...(remove ? [['Debugger.removeBreakpoint', () => session.send('Debugger.removeBreakpoint', {breakpointId})]] : []),
    ...(resume ? [['Debugger.resume', () => session.send('Debugger.resume')]] : []),
    ['CDPSession.detach', () => session.detach()],
  ];
  for (const [label, operation] of operations) {
    try { await bounded(operation, label, milliseconds); }
    catch (error) { failures.push({operation: label, message: error.message}); }
  }
  return failures;
}
async function eventually(operation, description, milliseconds = 30000) {
  const end = Date.now() + milliseconds; let last;
  while (Date.now() < end) {
    try { const value = await operation(); if (value) return value; } catch (error) { last = error; }
    await pause(75);
  }
  throw new Error(`${description}: ${last?.message || 'condition did not become true'}`);
}
function snapshot(domains, modifiedEpoch = Math.floor(Date.now() / 1000)) {
  const sorted = [...new Set(domains)].sort();
  assert(sorted.length && sorted.every(domain => /^[a-z0-9.-]+$/.test(domain)));
  const version = 'kumo-local-qa-1';
  return {schemaVersion: 1, version, modifiedEpoch,
    sha256: sha(`${version}\n${modifiedEpoch}\n${sorted.map(domain => `${domain}\n`).join('')}`), domains: sorted};
}
function isolatedEnvironment(home, output) {
  // C++ base::GetHomeDir() is NSHomeDirectory() on Apple. The independent
  // Foundation probe below must confirm CFFIXED_USER_HOME before browser start.
  const env = {...process.env, HOME: home, CFFIXED_USER_HOME: home,
    TMPDIR: path.join(output, 'tmp'), XDG_CONFIG_HOME: path.join(home, '.config'),
    XDG_CACHE_HOME: path.join(home, '.cache'), CODEX_HOME: path.join(home, '.codex')};
  for (const name of ['NODE_OPTIONS', 'NODE_PATH', 'KUMO_AGENT_DIR', 'CLAUDE_CONFIG_DIR', 'CHROME_USER_DATA_DIR']) delete env[name];
  return env;
}
function provenClaudeFixture(home, proof) {
  assert(proof?.passed===true && proof.foundationHomeIsDisposable===true,
    'Claude setup requires the independent disposable Foundation-home proof');
  assert(path.isAbsolute(home));
  return path.join(home,'Library/Application Support/Claude/claude_desktop_config.json');
}
async function verifyFoundationHome(directory, home, environment) {
  const source = path.join(directory, 'home-probe.m'), executable = path.join(directory, 'home-probe');
  await writeFile(source, '#import <Foundation/Foundation.h>\nint main(){@autoreleasepool{NSData*d=[NSJSONSerialization dataWithJSONObject:@{@"home":NSHomeDirectory(),@"support":[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject.path} options:0 error:nil];fwrite(d.bytes,1,d.length,stdout);}}\n');
  await execute('/usr/bin/clang', ['-fobjc-arc', '-framework', 'Foundation', source, '-o', executable]);
  const result = JSON.parse((await execute(executable, [], {env: environment})).stdout);
  assert.equal(await realpath(result.home), await realpath(home), 'Foundation must resolve the disposable home');
  const expected = path.join(home, 'Library/Application Support'); await mkdir(expected, {recursive: true, mode: 0o700});
  assert.equal(await realpath(result.support), await realpath(expected), 'Foundation Application Support must be disposable');
  return {passed: true, baseGetHomeDir: 'NSHomeDirectory', foundationHomeIsDisposable: true};
}
async function seal(app) {
  const args = ['--verify', '--deep', '--strict', '--verbose=2', app];
  await execute('/usr/bin/codesign', args, {maxBuffer: 1024 * 1024});
  const details = await execute('/usr/bin/codesign', ['-dvvv', app]);
  const text = details.stdout + details.stderr;
  assert.match(text, /Identifier=app\.kumo\.browser(?:\n|$)/);
  assert.match(text, /TeamIdentifier=PV65ZWXCWX(?:\n|$)/);
  const resources = await readFile(path.join(app, 'Contents/_CodeSignature/CodeResources'));
  return {cdHash: /CDHash=(\w+)/.exec(text)?.[1], codeResourcesSha256: sha(resources), strictSignatureValid: true};
}
async function writeSyntheticExtension(directory) {
  await mkdir(directory, {mode: 0o700});
  await writeFile(path.join(directory, 'manifest.json'), JSON.stringify({manifest_version: 3,
    name: 'Kumo disposable third-party API fixture', version: '1.0', permissions: ['storage', 'management'],
    background: {service_worker: 'background.js'}}));
  await writeFile(path.join(directory, 'background.js'), "chrome.runtime.onMessage.addListener((m,s,reply)=>{if(m?.qa==='ping')reply({qa:'pong',id:chrome.runtime.id});});chrome.runtime.onInstalled.addListener(()=>chrome.storage.local.set({qaInstalled:true}));\n");
  await writeFile(path.join(directory, 'qa.html'), '<!doctype html><title>Third-party extension fixture</title><h1>Third-party extension fixture</h1>');
}
async function rejectedSocketRole(socketPath, token, role) {
  return new Promise((resolve,reject) => {
    const peer=createConnection(socketPath); let text='';
    const timer=setTimeout(()=>{peer.destroy();reject(new Error('Browser-role socket rejection timed out'))},5000);
    peer.setEncoding('utf8');
    peer.once('connect',()=>peer.write(JSON.stringify({type:'hello',role,token})+'\n'));
    peer.on('data',chunk=>{text+=chunk;if(text.length>4096)peer.destroy(new Error('Oversized socket rejection'))});
    peer.once('error',error=>{clearTimeout(timer);reject(error)});
    peer.once('end',()=>{clearTimeout(timer);peer.destroy();try{resolve(JSON.parse(text.trim()))}catch(error){reject(error)}});
  });
}
function fixtureHTML(title = 'Native agent owned fixture') {
  return `<!doctype html><title>${title}</title><h1>Public owned heading</h1><p id="result">Public visible text</p>
    <button id="click" onclick="document.querySelector('#result').textContent='Clicked'">Click fixture</button>
    <input id="normal" value="NORMAL_SECRET_QA" aria-label="Public field"><textarea id="draft">DRAFT_SECRET_QA</textarea>
    <input id="password" type="password" value="PASSWORD_SECRET_QA" aria-label="PASSWORD_METADATA_SECRET_QA">
    <input id="otp" autocomplete="section-login ONE-TIME-CODE" value="OTP_SECRET_QA" aria-label="OTP_METADATA_SECRET_QA">
    <input id="card" autocomplete="SECTION-CHECKOUT BILLING CC-NUMBER" value="CARD_SECRET_QA">
    <input id="hidden" type="hidden" value="HIDDEN_SECRET_QA"><div hidden>HIDDEN_TEXT_SECRET_QA</div>
    <div contenteditable="true">EDITABLE_SECRET_QA<a id="private-draft-link" href="/private-draft">EDITABLE_LINK_SECRET_QA</a><button id="private-draft-button">EDITABLE_BUTTON_SECRET_QA</button></div>
    <a id="public-aggregate-link" href="/public?token=URL_SECRET_QA#private">Public link<span contenteditable="true">NESTED_LINK_SECRET_QA</span><span hidden>HIDDEN_LINK_SECRET_QA</span></a>
    <button id="public-aggregate-button">Public button<span contenteditable="true">NESTED_BUTTON_SECRET_QA</span><textarea>NESTED_FORM_SECRET_QA</textarea></button>
    <select id="private-options"><option>SELECT_SECRET_QA</option></select>`;
}
async function selfTest() {
  const value = snapshot(['b.invalid', 'a.invalid', 'a.invalid'], 1792610000);
  assert.deepEqual(value.domains, ['a.invalid', 'b.invalid']);
  assert.equal(value.sha256, sha('kumo-local-qa-1\n1792610000\na.invalid\nb.invalid\n'));
  const env = isolatedEnvironment('/private/tmp/fake-home', '/private/tmp/fake-output');
  assert.equal(env.HOME, env.CFFIXED_USER_HOME); assert.equal(env.NODE_OPTIONS, undefined);
  assert(!['protection.setup', 'definitions.update', 'agents.connectCodex', 'agents.connectClaude'].some(verb => SAFE_ACTIONS.has(verb)));
  assert.throws(()=>provenClaudeFixture('/private/tmp/unproven-home',null),/Foundation-home proof/);
  assert.match(fixtureHTML(), /section-login ONE-TIME-CODE/);
  await assert.rejects(bounded(() => new Promise(() => {}), 'synthetic stalled CDP', 5), /QA operation timed out: synthetic stalled CDP/);
  const cleanupCalls = [];
  const cleanup = await cleanupDebugger({
    send(method) { cleanupCalls.push(method); return method === 'Debugger.removeBreakpoint' ? new Promise(() => {}) : Promise.resolve(); },
    detach() { cleanupCalls.push('detach'); return Promise.resolve(); },
  }, 'synthetic-breakpoint', {}, 5);
  assert.deepEqual(cleanupCalls, ['Debugger.removeBreakpoint', 'Debugger.resume', 'detach']);
  assert.equal(cleanup.length, 1); assert.equal(cleanup[0].operation, 'Debugger.removeBreakpoint');
  assert(navigationReleasedPause(new Error('cdpSession.send: Protocol error (Debugger.resume): Can only perform operation while paused.')));
  assert(!navigationReleasedPause(new Error('Target closed')));
  assert(!navigationReleasedPause(new Error('QA operation timed out: agent resume controlled pause')));
  assert.equal(ownedCDPEndpoint('54321\n/devtools/browser/owned-fixture\n'), 'ws://127.0.0.1:54321/devtools/browser/owned-fixture');
  assert.match(fixtureResolverRules, /MAP \* \^NOTFOUND, EXCLUDE 127\.0\.0\.1$/);
  for (const invalid of ['0\n/devtools/browser/owned', '65536\n/devtools/browser/owned', '9222\nws://remote.invalid/target', '9222\n/devtools/page/not-browser']) assert.throws(() => ownedCDPEndpoint(invalid));
  assert(allowedOwnedPage('chrome://kumo-new-tab/', ['http://127.0.0.1:1234'], 'fixture'));
  for (const value of ['https://example.com/', 'chrome://settings/passwords', 'chrome://kumo-new-tab.evil/', 'http://user:secret@127.0.0.1:1234/']) assert(!allowedOwnedPage(value, ['http://127.0.0.1:1234'], 'fixture'));
  const probesPage = {}, otherPage = {};
  const blockedScope = {page:probesPage,target:`http://${blockedHost}:1234/main`,frameId:'owned-main-frame',expiresAt:1000};
  for (const value of [blockedScope.target,blockedErrorDocument]) assert(expectedBlockedNavigationCandidate(probesPage,value,blockedScope,500));
  assert(!expectedBlockedNavigationCandidate(otherPage,blockedErrorDocument,blockedScope,500));
  assert(!expectedBlockedNavigationCandidate(probesPage,blockedErrorDocument,undefined,500));
  assert(!expectedBlockedNavigationCandidate(probesPage,blockedErrorDocument,blockedScope,1001));
  for (const value of [`http://${blockedHost}:1234/other`,`http://${blockedHost}:5678/main`,'chrome-error://other/','https://example.com/']) assert(!expectedBlockedNavigationCandidate(probesPage,value,blockedScope,500));
  assert(!expectedBlockedNavigationCandidate(probesPage,blockedErrorDocument,{...blockedScope,target:'https://example.com/main'},500));
  const failedFrame = {id:blockedScope.frameId,url:blockedErrorDocument,unreachableUrl:blockedScope.target};
  assert(expectedBlockedFrameMatches(failedFrame,blockedScope,500));
  for (const frame of [{...failedFrame,id:'other-frame'},{...failedFrame,unreachableUrl:`http://${blockedHost}:5678/main`},{...failedFrame,unreachableUrl:undefined},{...failedFrame,url:'https://example.com/'}]) assert(!expectedBlockedFrameMatches(frame,blockedScope,500));
  assert(!expectedBlockedFrameMatches(failedFrame,blockedScope,1001));
  assert(sameProcessIdentity('42 1 Wed Oct 21 21:00:00 2026 owned-helper', '42 2 Wed Oct 21 21:00:00 2026 owned-helper'));
  assert(!sameProcessIdentity('42 1 Wed Oct 21 21:00:01 2026 owned-helper', '42 2 Wed Oct 21 21:00:00 2026 owned-helper'));
  const directory = await mkdtemp('/private/tmp/kns-');
  try {
    const home = path.join(directory, 'h'); await mkdir(home, {mode: 0o700}); await mkdir(path.join(directory, 'tmp'));
    const homeProof=await verifyFoundationHome(directory, home, isolatedEnvironment(home, directory));
    const fixture=provenClaudeFixture(await realpath(home),homeProof);
    await assert.rejects(lstat(fixture),{code:'ENOENT'});
    const extension = path.join(directory, 'extension'); await writeSyntheticExtension(extension);
    assert.equal(JSON.parse(await readFile(path.join(extension, 'manifest.json'), 'utf8')).manifest_version, 3);
  } finally { await rm(directory, {recursive: true, force: true}); }
  console.log(JSON.stringify({passed: true, checks: ['canonical local domain snapshot', 'restricted action allowlist', 'sensitive fixture semantics', 'real Foundation disposable-home lookup', 'Claude exception requires proven owned home', 'ordinary MV3 fixture manifest', 'expected blocked navigation permit is page/target/frame scoped, expiring and requires exact unreachableUrl'], browserLaunched: false, providerSetupPerformed:false}));
}
const SAFE_ACTIONS = new Set(['preferences.set', 'preferences.import', 'preferences.export', 'phishing.setEnabled', 'malware.setEnabled', 'agents.grant', 'agents.revoke', 'agents.refresh']);

async function run() {
  assert(process.env.KUMO_QA_APP, 'Set KUMO_QA_APP to the explicitly approved fresh native app');
  assert(process.env.KUMO_QA_OUTPUT, 'Set KUMO_QA_OUTPUT to a new evidence directory');
  const app = await realpath(process.env.KUMO_QA_APP), output = path.resolve(process.env.KUMO_QA_OUTPUT);
  const headed = process.env.KUMO_QA_HEADFUL === '1';
  assert(app.endsWith('/Kumo.app')); assert(!app.split(path.sep).includes('Applications'), 'Use a separate QA app outside system and user Applications folders');
  await mkdir(output, {recursive: false, mode: 0o700});
  const report = {schemaVersion: 1, app, output, startedAt: new Date().toISOString(), passed: false, checks: [],
    mode: headed ? 'headed' : 'headless', phases: [],
    interactiveChecks: {hiddenCompletion: headed ? {required: true, status: 'pending'} :
      {required: false, status: 'not-run', reason: 'Real hidden-document completion requires an unlocked headed desktop session.'}},
    limits: ['Codex setup, AV setup/update and updater launching are forbidden. Claude setup is exercised only through its actual button after Foundation proves the disposable home; it writes that owned client fixture and managed runtime without launching a client.',
      'Settings updater controls/status are checked; native menu inspection remains a separate manual gate. No update helper window or external update check is opened.',
      'Swift scanner status may inspect its canonical KumoSecurity state read-only; no credential, provider-account or installer action is authorized.']};
  const short = await mkdtemp('/private/tmp/kn-'), home = path.join(short, 'h'), profile = path.join(short, 'p');
  await mkdir(home, {mode: 0o700}); await mkdir(profile, {mode: 0o700}); await mkdir(path.join(output, 'tmp'), {mode: 0o700});
  const environment = isolatedEnvironment(home, output); let context, browser, browserProcess, browserIdentity, connection, before, runtimeSocketPath;
  const browserErrors = [];
  let preserve = false, fixtureExtensionId;
  const expectedBlockedNavigations = new WeakMap();
  const errors = [], blockedHits = [], external = [], sockets = new Set();
  let originA, originB;
  const phase = name => { if (preserve && name !== 'owned-cleanup') throw new Error('Unexpected navigation; owned user session preserved'); report.phases.push({name, at: new Date().toISOString()}); console.log(JSON.stringify({nativeBrowserPhase: name, mode: report.mode})); };
  const serverB = createServer((_request, response) => { response.setHeader('Content-Type', 'text/html'); response.end(fixtureHTML('Other owned origin')); });
  const serverA = createServer((request, response) => {
    if (request.headers.host?.startsWith(blockedHost)) blockedHits.push(request.url);
    response.setHeader('Access-Control-Allow-Origin', '*');
    if (request.url === '/redirect-blocked') { response.writeHead(302, {Location: `http://${blockedHost}:${serverA.address().port}/redirect-target`}); response.end(); return; }
    if (request.url === '/redirect-other') { response.writeHead(302, {Location: `${originB}/destination`}); response.end(); return; }
    if (request.url === '/worker.js') { response.setHeader('Content-Type', 'application/javascript'); response.end(`onmessage=async e=>{try{await fetch(e.data);postMessage('reached')}catch{postMessage('blocked')}}`); return; }
    response.setHeader('Content-Type', 'text/html'); response.end(fixtureHTML());
  });
  serverA.on('upgrade', (request, socket) => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); if (request.headers.host?.startsWith(blockedHost)) blockedHits.push('WEBSOCKET:'+request.url); socket.destroy(); });
  try {
    phase('verify-app-and-disposable-home');
    report.homeProof = await verifyFoundationHome(short, home, environment);
    before = await seal(app); report.signatureBefore = before;
    await assert.rejects(lstat(path.join(app, 'Contents/Resources/KumoExtension')), {code: 'ENOENT'});
    const engine = path.join(app, 'Contents/MacOS/Chromium'); assert((await lstat(engine)).isFile());
    const extension = path.join(short, 'extension'); await writeSyntheticExtension(extension);
    await mkdir(path.join(profile, 'Default'), {mode: 0o700});
    const seeded = snapshot([blockedHost]);
    await writeFile(path.join(profile, 'Default/Preferences'), JSON.stringify({kumo: {protection: {domain_snapshot: seeded}}}), {mode: 0o600});
    report.domainFixture = {domains: seeded.domains, sha256: seeded.sha256, syntheticOnly: true};
    await Promise.all([listen(serverA), listen(serverB)]);
    originA = `http://127.0.0.1:${serverA.address().port}`; originB = `http://127.0.0.1:${serverB.address().port}`;
    const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
    phase('launch-isolated-browser');
    // Use the same public noDefaults connection as native download QA. The
    // normal Playwright launch enables a session-scoped focus/visibility
    // override on every page, which would invalidate the real hidden-tab test.
    const sdkSource = await readFile(path.join(root, '.cache/qa/node_modules/playwright-core/lib/coreBundle.js'), 'utf8');
    assert(sdkSource.includes('const skipDefaultOverrides = browserOptions.noDefaults && this._crPage._browserContext === this._crPage._browserContext._browser._defaultContext;'));
    assert(sdkSource.includes('if (this._isMainFrame() && !skipDefaultOverrides)'));
    const launchArgs = [`--user-data-dir=${profile}`, ...(!headed ? ['--headless=new'] : []),
      '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', `--load-extension=${extension}`,
      '--no-first-run', '--no-default-browser-check', '--disable-sync', '--use-mock-keychain', '--password-store=basic',
      '--no-proxy-server', '--lang=en-US', '--window-size=1280,1000',
      `--host-resolver-rules=${fixtureResolverRules}`, 'about:blank'];
    assert(!launchArgs.some(argument => argument === '--no-sandbox' || argument === '--disable-web-security'));
    browserProcess = spawn(engine, launchArgs, {env: environment, stdio: ['ignore','ignore','pipe']});
    browserProcess.stderr.on('data', bytes => { if (browserErrors.join('').length < 131072) browserErrors.push(String(bytes)); });
    browserProcess.on('error', error => browserErrors.push(error.message));
    browserIdentity = await processIdentity(browserProcess.pid);
    assert(browserIdentity.startsWith(`${browserProcess.pid} ${process.pid} `) && browserIdentity.endsWith(engine), 'Spawned browser identity must match the owned PID, parent and exact executable');
    const endpoint = await eventually(async () => ownedCDPEndpoint(await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')), 'Owned browser loopback CDP endpoint', 60000);
    browser = await chromium.connectOverCDP(endpoint, {noDefaults:true, timeout:30000});
    context = browser.contexts()[0]; assert(context, 'Owned default browser context is required');
    report.launch = {pid:browserProcess.pid, identity:browserIdentity, noDefaults:true, sdkSourceSha256:sha(sdkSource), sandbox:true, loopbackCDP:true, mockKeychain:true};
    context.setDefaultTimeout(20000);
    const watchPage = page => page.on('framenavigated', frame => {
      if (frame !== page.mainFrame() || allowedOwnedPage(frame.url(), [originA,originB], fixtureExtensionId)) return;
      const scope = expectedBlockedNavigations.get(page);
      if (expectedBlockedNavigationCandidate(page,frame.url(),scope)) { scope.candidates.add(frame.url()); return; }
      preserve=true; report.unexpectedNavigation=true;
    });
    context.pages().forEach(watchPage); context.on('page', watchPage);
    context.on('page', page => page.on('pageerror', error => errors.push(error.message)));
    context.on('request', request => { try { const url = new URL(request.url()); if (['http:', 'https:'].includes(url.protocol) && !['127.0.0.1', blockedHost].includes(url.hostname)) external.push(url.origin); } catch {} });
    await context.route(/^https?:\/\//, route => {
      const host = new URL(route.request().url()).hostname;
      return ['127.0.0.1', blockedHost].includes(host) ? route.continue() : route.abort();
    });
    const settings = await context.newPage(); await settings.goto('chrome://settings/kumo');
    await settings.locator('settings-kumo-page').waitFor();
    const status = async () => {
      assert(!preserve, 'Unexpected navigation; owned user session preserved');
      await settings.bringToFront();
      await settings.waitForFunction(() => document.visibilityState === 'visible', null, {timeout: 5000});
      return settings.evaluate(async () => {
        let timer;
        try {
          const {sendWithPromise} = await import('chrome://resources/js/cr.js');
          return await Promise.race([sendWithPromise('kumoGetStatus'), new Promise((_resolve, reject) => {
            timer = setTimeout(() => reject(new Error('Native status reply timed out; check that the Mac is unlocked and Settings is visible.')), 5000);
          })]);
        } finally { clearTimeout(timer); }
      });
    };
    phase('native-defaults-and-model-health');
    const initial = await eventually(async () => { const s = await status(); return s.protection?.migrationComplete && s.agents?.bridgeConnected ? s : false; }, 'Native migration and private browser channel must become ready', 90000);
    assert.equal(initial.schemaVersion, 1); assert.equal(initial.agents.enabled, false);
    assert.equal(initial.protection.phishing.enabled, true); assert.equal(initial.protection.phishing.desiredEnabled, true);
    const ready = await eventually(async () => { const s = await status(); return s.protection?.phishing?.health === 'ready' ? s : false; }, 'Actual bundled PhishLang model must be healthy', 180000);
    assert.equal(ready.protection.phishing.available, true); assert.equal(ready.protection.phishing.localOnly, true);
    assert.equal(ready.protection.malware.health, 'ready'); assert.equal(ready.protection.malware.domainCount, 1);
    report.protection = ready.protection; report.checks.push('Native Settings, default-on PhishLang desired/actual ready, and synthetic local domain list');
    const clients = await eventually(async()=>{const s=await status();return s.clients?.codex?.provider && s.clients?.claude?.provider ? s.clients : false},'Read-only disposable client configuration status',90000);
    assert.equal(clients.codex.configured,false); assert.equal(clients.claude.configured,false); report.initialClients=clients;
    await settings.getByRole('button', {name: 'Check for updates', exact: true}).waitFor();
    assert.equal(await settings.getByRole('button', {name: 'Connect Codex Desktop', exact: true}).count(), 1);
    assert.equal(await settings.getByRole('button', {name: 'Connect Claude Desktop', exact: true}).count(), 1);
    report.updateStatus = ready.updates || null; report.checks.push('Native update status and Settings controls visible; Codex, antivirus setup and updater launching remain uninvoked');
    // Narrow setup exception: Foundation independently proved this exact home
    // before browser start; native RunVerifiedHelper forwards that resolved
    // home to Node. Claude configuration writes only this owned path/runtime
    // and never discovers or launches a desktop client. No Codex setup occurs.
    assert.equal(report.homeProof.foundationHomeIsDisposable,true);
    const canonicalHome=await realpath(home);
    const claudeFile=provenClaudeFixture(canonicalHome,report.homeProof);
    await assert.rejects(lstat(claudeFile),{code:'ENOENT'});
    phase('native-claude-setup-admission');
    let hiddenControl;
    if (headed) {
      hiddenControl=await context.newPage();await hiddenControl.goto('about:blank');
    }
    await settings.bringToFront();
    const claudeButton=settings.getByRole('button',{name:'Connect Claude Desktop',exact:true});
    await claudeButton.click();
    await eventually(async()=>{const s=await status();return s.operation?.busy===true && s.operation?.name==='agents.connectClaude'},'Native Claude setup operation must be admitted asynchronously');
    assert.equal(await claudeButton.isEnabled(),false);
    if (headed) {
      phase('actual-hidden-document-completion');
      report.interactiveChecks.hiddenCompletion.status='running';
      await hiddenControl.bringToFront();
      await eventually(()=>settings.evaluate(()=>document.visibilityState==='hidden'),'Settings document must actually become hidden');
      await eventually(()=>claudeButton.isEnabled(),'Completed native callback must clear the hidden Settings action state',120000);
      assert.equal(await settings.evaluate(()=>document.visibilityState),'hidden');
      report.interactiveChecks.hiddenCompletion.status='passed';
    } else {
      await eventually(()=>claudeButton.isEnabled(),'Completed native callback must clear the visible Settings action state',120000);
      report.limits.push('Headless mode did not exercise native hidden-document completion. An unlocked headed run is a separate release qualification gate.');
    }
    const claudeState=await lstat(claudeFile);
    assert(claudeState.isFile()&&!claudeState.isSymbolicLink());assert.equal(claudeState.nlink,1);assert.equal(claudeState.mode&0o077,0);
    const originalClaude=await readFile(claudeFile);
    const profileIds=(await readdir(path.join(canonicalHome,'.kumo/agents/profiles'))).filter(value=>/^[a-f0-9]{32}$/.test(value));assert.equal(profileIds.length,1);
    const {desktopMcp}=await import(path.join(app,'Contents/Resources/agent-bridge/desktop.mjs'));
    assert.deepEqual(JSON.parse(originalClaude).mcpServers.kumo,desktopMcp(profileIds[0]));
    const configured=await eventually(async()=>{const s=await status();return s.clients?.claude?.configured===true?s:false},'Native status must show the disposable Claude transport configured',120000);
    assert.equal(configured.clients.claude.connected,false);
    assert.equal(typeof configured.helperStatus?.ageSeconds,'number');assert.equal(typeof configured.helperStatus?.stale,'boolean');assert.equal(typeof configured.helperStatus?.refreshing,'boolean');
    let refreshed;
    phase('native-status-ttl-refresh');
    try{
      await writeFile(claudeFile,'{malformed owned QA configuration\n',{mode:0o600});
      refreshed=await eventually(async()=>{const s=await status();return s.clients?.claude?.configured===false&&s.clients?.claude?.status==='needs-attention'?s:false},'Read-only status polling must observe malformed owned Claude data through automatic helper TTL refresh',120000);
      assert.equal(refreshed.helperStatus.stale,false);
    }finally{await writeFile(claudeFile,originalClaude,{mode:0o600});}
    assert.deepEqual(await readFile(claudeFile),originalClaude);
    await hiddenControl?.close();
    report.claudeConfigurationQA={disposableHomeProven:true,fileInitiallyAbsent:true,nativeAsyncOperationObserved:true,completedWhileSettingsHidden:report.interactiveChecks.hiddenCompletion.status==='passed',transportBoundToNativeProfile:true,desktopClientLaunched:false,automaticTtlObservedMalformedConfig:true,fixtureRestored:true,helperStatus:refreshed.helperStatus};
    report.checks.push('Actual Claude setup stays in proven disposable home; native completion and automatic helper TTL notice malformed owned client data without manual refresh');
    await settings.evaluate(async () => {
      const {sendWithPromise} = await import('chrome://resources/js/cr.js');
      const button = document.createElement('button'); button.id = 'kumo-qa-native-action'; button.textContent = 'Owned native QA action'; document.body.prepend(button);
      button.addEventListener('click', event => { const request = globalThis.__kumoQARequest; globalThis.__kumoQAReply = null; globalThis.__kumoQATrusted = event.isTrusted; sendWithPromise('kumoPerformAction', request.verb, request.params).then(reply => { globalThis.__kumoQAReply = reply; }); });
    });
    const action = async (verb, params = {}) => {
      assert(SAFE_ACTIONS.has(verb), `Harness refuses mutating helper/provider action ${verb}`); await settings.bringToFront();
      await settings.evaluate(request => { globalThis.__kumoQARequest = request; globalThis.__kumoQAReply = null; }, {verb, params});
      await settings.locator('#kumo-qa-native-action').click();
      const reply = await eventually(() => settings.evaluate(() => globalThis.__kumoQAReply), `Native action ${verb}`);
      assert.equal(await settings.evaluate(() => globalThis.__kumoQATrusted), true); return reply;
    };
    phase('native-preferences-and-new-tab');
    await settings.locator('settings-kumo-page #greeting').fill('Owned native runtime QA');
    await settings.locator('settings-kumo-page #theme').selectOption('forest');
    await settings.getByRole('button',{name:'Save appearance',exact:true}).click();
    await eventually(async()=>{const s=await status();return s.preferences.greeting==='Owned native runtime QA' && s.preferences.theme==='forest'},'Actual Save appearance button persists native preferences');
    const stable = (await status()).preferences;
    for (const bad of [{greeting:'Must not partially save',unexpected:true}, {shortcuts:[{name:'Unsafe',url:'javascript:alert(1)'}]}, {engine:'custom',engines:[{id:'custom',name:'Unsafe',url:'https://user:secret@example.invalid/?q={searchTerms}'}]}]) {
      assert.equal((await action('preferences.set', bad)).ok, false); assert.deepEqual((await status()).preferences, stable);
    }
    report.checks.push('Trusted UI activation saves preferences; native unknown-key, unsafe URL and credential-bearing URL rejection preserves prior state');
    const ntp = await context.newPage(); await ntp.goto('chrome://newtab/');
    await ntp.locator('#greeting').waitFor(); assert.equal(await ntp.locator('#greeting').textContent(), 'Owned native runtime QA');
    assert.equal(new URL(ntp.url()).protocol, 'chrome:'); assert.equal(await ntp.locator('a[href="chrome://settings/kumo"]').count(), 3);
    report.checks.push('Native new tab uses saved native preferences and chrome://settings/kumo links');
    phase('ordinary-extension-apis');
    const worker = await eventually(async () => context.serviceWorkers().find(w => w.url().startsWith('chrome-extension://')), 'Ordinary third-party MV3 extension service worker');
    const extensionId = new URL(worker.url()).host; assert.notEqual(extensionId, legacyId);
    fixtureExtensionId = extensionId;
    const extensionPage = await context.newPage(); await extensionPage.goto(`chrome-extension://${extensionId}/qa.html`);
    const extensionResult = await extensionPage.evaluate(async () => ({id:chrome.runtime.id, echo:await chrome.runtime.sendMessage({qa:'ping'}), installed:await chrome.management.getAll(), storage:await chrome.storage.local.get('qaInstalled')}));
    assert.equal(extensionResult.echo.qa, 'pong'); assert(!extensionResult.installed.some(value => value.id === legacyId));
    assert.equal(extensionResult.storage.qaInstalled, true);
    const extensionSession = await context.newCDPSession(extensionPage);
    let targets;
    try { targets = await bounded(() => extensionSession.send('Target.getTargets'), 'ordinary extension targets'); }
    finally { await bounded(() => extensionSession.detach(), 'ordinary extension CDP detach'); }
    assert(!targets.targetInfos.some(target => target.url.includes(`chrome-extension://${legacyId}/`)));
    report.checks.push('Ordinary extension runtime messaging and management APIs work; retired product ID is absent from installed extensions and all targets');
    // These fixtures deliberately contain login/payment controls. The separate
    // native phishing suite qualifies their actual warning flow; isolate agent
    // DOM/authority assertions using only the real user-facing native toggle.
    phase('isolate-agent-fixtures-through-native-phishing-toggle');
    const phishingToggle=settings.getByRole('checkbox',{name:'Local PhishLang phishing warnings',exact:true});
    await settings.bringToFront();await phishingToggle.setChecked(false);
    await eventually(async()=>{const p=(await status()).protection.phishing;return p.enabled===false&&p.available===false&&p.health==='off'},'Actual native toggle must isolate agent fixtures');
    report.agentFixturePhishingIsolation={actualNativeToggle:true,initiallyDefaultOn:true,disabledForAgentFixtures:true,restoredOn:false};
    phase('native-agent-authority-and-private-dom');
    const target = await context.newPage(); await target.goto(originA);
    await eventually(async () => (await status()).tabs.some(t => t.origin === originA), 'Owned fixture in native tab list');
    await settings.getByRole('button', {name:'Refresh connections and tabs', exact:true}).click();
    const choice = settings.locator('settings-kumo-page label').filter({hasText: 'Native agent owned fixture'});
    await choice.locator('input[type=checkbox]').check();
    await settings.getByRole('button', {name:'Allow selected tabs', exact:true}).click();
    await eventually(async () => (await status()).agents.grants.length === 1, 'Actual native grant button');
    const runtimeBase = path.join(home, '.kumo/agents/profiles');
    const runtimeIds = (await readdir(runtimeBase)).filter(value => /^[a-f0-9]{32}$/.test(value)); assert.equal(runtimeIds.length, 1);
    const runtimeDir = path.join(runtimeBase, runtimeIds[0]); assert.equal((await lstat(runtimeDir)).mode & 0o077, 0);
    const socketPath = path.join(runtimeDir, 'bridge.sock'), token = (await readFile(path.join(runtimeDir, 'pairing-token'), 'utf8')).trim(); runtimeSocketPath=socketPath;
    const {connectBroker, requestBrowser} = await import(path.join(app, 'Contents/Resources/agent-bridge/lib/broker.mjs'));
    for (const role of ['browser','extension']) {
      const rejected=await rejectedSocketRole(socketPath,token,role);
      assert.equal(rejected.type,'error'); assert.match(rejected.error.message,/agent authentication/);
    }
    connection = await connectBroker({socketPath, token});
    const tabs = await eventually(async () => { const rows = await requestBrowser(connection, 'tabs.list', {}); return rows.length === 1 ? rows : false; }, 'Native authoritative grant reaches agent-only socket');
    const tabId = tabs[0].tabId; assert.equal(tabs[0].url, originA+'/');
    phase('native-agent-snapshot-and-private-dom');
    const sampled = await requestBrowser(connection, 'tab.snapshot', {tabId});
    assert.match(sampled.text, /Public owned heading/); assert.doesNotMatch(JSON.stringify(sampled), /SECRET_QA/);
    for (const id of ['password','otp','card','hidden']) assert(!sampled.controls.some(control => control.id === id));
    assert(!sampled.controls.some(control => control.id === 'private-draft-button'));
    assert.equal(sampled.controls.find(control => control.id === 'draft').label, '');
    assert.equal(sampled.controls.find(control => control.id === 'private-options').label, '');
    assert.equal(sampled.controls.find(control => control.id === 'public-aggregate-button').label, 'Public button');
    assert.deepEqual(sampled.links, [{text:'Public link',href:originA+'/public'}]);
    await requestBrowser(connection, 'tab.click', {tabId,selector:'#click'}); assert.equal(await target.locator('#result').textContent(), 'Clicked');
    await requestBrowser(connection, 'tab.type', {tabId,selector:'#normal',text:'Public QA entry'}); assert.equal(await target.locator('#normal').inputValue(), 'Public QA entry');
    for (const id of ['password','otp','card']) await assert.rejects(requestBrowser(connection, 'tab.type', {tabId,selector:'#'+id,text:'Rejected'}), /password|payment|verification/);
    // Pause renderer script execution, leave a real native DOM call pending,
    // then initiate a native same-origin navigation. Its epoch changes before
    // any old document result can return, while the origin grant stays valid.
    // This exercises native document/epoch rejection rather than relying on
    // broker revocation alone to discard a stale result.
    phase('native-agent-controlled-document-epoch-race');
    const debuggerSession = await context.newCDPSession(target);
    let breakpointId, pendingSnapshot, removed = false, resumed = false, debuggerFailure;
    try {
      await bounded(() => debuggerSession.send('Debugger.enable'), 'agent Debugger.enable');
      ({breakpointId} = await bounded(() => debuggerSession.send('Debugger.setInstrumentationBreakpoint', {instrumentation:'beforeScriptExecution'}), 'agent instrumentation breakpoint'));
      const paused = new Promise((resolve,reject) => {
        const timer=setTimeout(()=>reject(new Error('Native DOM script did not reach the controlled renderer pause')),15000);
        debuggerSession.once('Debugger.paused', event=>{clearTimeout(timer);resolve(event)});
      });
      pendingSnapshot = requestBrowser(connection, 'tab.snapshot', {tabId}).then(value=>({value}),error=>({error:error.message}));
      await paused;
      phase('native-agent-paused-navigation');
      assert.equal((await requestBrowser(connection, 'tab.navigate', {tabId,url:originA+'/same-origin-navigation-race'})).navigating,true);
      phase('native-agent-remove-breakpoint-and-resume');
      await bounded(() => debuggerSession.send('Debugger.removeBreakpoint', {breakpointId}), 'agent remove instrumentation breakpoint'); removed = true;
      try { await bounded(() => debuggerSession.send('Debugger.resume'), 'agent resume controlled pause'); }
      catch (error) {
        // The real pause, native navigation acknowledgement and successful
        // removal above are mandatory. Navigation may release the old context.
        if (!navigationReleasedPause(error)) throw error;
        report.debuggerResume = 'Native navigation released the previously observed controlled pause';
      }
      resumed = true;
      const stale = await pendingSnapshot;
      assert(stale.error, 'A DOM result started before native navigation must be discarded');
      assert.doesNotMatch(stale.error, /timed?\s*out|timeout/i, 'The race requires an actual native stale rejection, not a bridge timeout');
      assert.match(stale.error,/document|chang|revok|grant|result|origin/);
      await target.waitForURL(originA+'/same-origin-navigation-race');
    } catch (error) {
      debuggerFailure = error; throw error;
    } finally {
      const failures = await cleanupDebugger(debuggerSession, breakpointId, {remove: !!breakpointId && !removed, resume: !resumed});
      if (failures.length) {
        report.debuggerCleanupFailures = failures;
        if (!debuggerFailure) throw new Error(`Owned debugger cleanup failed: ${failures.map(item => item.operation).join(', ')}`);
      }
    }
    report.checks.push('Controlled in-flight native DOM result is discarded after native navigation changes the document epoch');
    await target.goto(originA+'/redirect-other');
    await eventually(async () => (await status()).agents.grants.length === 0, 'Cross-origin redirect revokes native grant');
    await assert.rejects(requestBrowser(connection, 'tab.snapshot', {tabId}), /grant|revok|origin/);
    assert.equal((await action('agents.grant', {grants:[{tabId,origin:originA}],allowNewTabs:false})).ok, false, 'Stale origin cannot be regranted');
    assert.equal((await action('agents.revoke')).ok, true);
    await assert.rejects(requestBrowser(connection, 'tabs.list', {}), /disabled|revok/);
    report.checks.push('Actual native grant/revoke UI, private browser pipes, agent-only socket, two-origin redirect/stale-grant rejection and password/OTP/payment exclusions');
    phase('native-domain-network-admission');
    const probes = await context.newPage(); await probes.goto(originA);
    const blocked = `http://${blockedHost}:${serverA.address().port}`;
    const networkResults = await probes.evaluate(async blocked => {
      const fetchBlocked = async url => { try { await fetch(url); return false; } catch { return true; } };
      const subresource = await fetchBlocked(blocked+'/fetch');
      const redirect = await fetchBlocked('/redirect-blocked');
      const worker = await new Promise(resolve => { const w=new Worker('/worker.js');const timer=setTimeout(()=>{w.terminate();resolve('timeout')},10000);w.onmessage=e=>{clearTimeout(timer);w.terminate();resolve(e.data)};w.postMessage(blocked+'/worker-fetch'); });
      const websocket = await new Promise(resolve => { const ws=new WebSocket(blocked.replace('http:','ws:')+'/socket');const timer=setTimeout(()=>{ws.close();resolve('timeout')},10000);ws.onopen=()=>{clearTimeout(timer);ws.close();resolve('opened')};ws.onerror=()=>{clearTimeout(timer);resolve('error')}; });
      return {subresource,redirect,worker,websocket};
    }, blocked);
    report.domainResults = networkResults; report.listedServerHits = [...blockedHits];
    await writeFile(path.join(output,'domain-network-results.json'),JSON.stringify({networkResults,listedServerHits:blockedHits,protection:(await status()).protection},null,2)+'\n',{mode:0o600});
    assert.equal(networkResults.subresource,true,'A listed-host subresource fetch must reject'); assert.equal(networkResults.redirect,true,'A listed redirect destination must reject'); assert.equal(networkResults.worker,'blocked'); assert.equal(networkResults.websocket,'error');
    const blockedTarget = blocked+'/main';
    const blockedSession = await context.newCDPSession(probes);
    const beforeBlocked = (await bounded(()=>blockedSession.send('Page.getFrameTree'),'Owned probes main-frame metadata',2000)).frameTree.frame;
    assert(!preserve, 'Unexpected navigation; owned user session preserved');
    const blockedScope = {page:probes,target:blockedTarget,frameId:beforeBlocked.id,expiresAt:Date.now()+15000,candidates:new Set()};
    expectedBlockedNavigations.set(probes,blockedScope);
    try {
      await assert.rejects(bounded(()=>probes.goto(blockedTarget),'Expected listed main-navigation rejection',5000), /ERR_BLOCKED_BY_CLIENT/);
      const failedFrame = (await bounded(()=>blockedSession.send('Page.getFrameTree'),'Expected blocked main-frame metadata',2000)).frameTree.frame;
      assert(expectedBlockedFrameMatches(failedFrame,blockedScope),'Blocked error document must identify the exact expected unreachable URL and main frame');
      assert(!preserve, 'Unexpected navigation; owned user session preserved');
      await pause(200); assert.deepEqual(blockedHits, [], 'No listed destination may reach the local HTTP or WebSocket server');
      await bounded(()=>probes.goto(originA),'Restore owned probes origin after expected blocked navigation',5000);
      const restoredFrame = (await bounded(()=>blockedSession.send('Page.getFrameTree'),'Restored owned main-frame metadata',2000)).frameTree.frame;
      assert.equal(restoredFrame.id,blockedScope.frameId);
      assert.equal(new URL(restoredFrame.url).origin,originA);
      assert(!restoredFrame.unreachableUrl);
      assert(!preserve, 'Unexpected navigation; owned user session preserved');
      report.expectedBlockedNavigation = {pageScoped:true,operationBudgetMilliseconds:15000,error:'ERR_BLOCKED_BY_CLIENT',target:blockedTarget,errorDocumentURL:failedFrame.url,unreachableUrl:failedFrame.unreachableUrl,sameMainFrame:true,observedCandidates:[...blockedScope.candidates],listedServerHits:[],restoredToOwnedOrigin:originA};
    } catch(error) {
      preserve=true;
      report.expectedBlockedNavigationValidationFailed=true;
      throw error;
    } finally {
      expectedBlockedNavigations.delete(probes);
      await bounded(()=>blockedSession.detach(),'Expected blocked-navigation CDP detach',2000);
    }
    report.domainResults = networkResults; report.checks.push('Native domain blocking stops main navigation, subresources, redirect destinations, worker fetch and WebSocket before server contact');
    assert.equal((await action('agents.revoke')).ok, true);
    phase('restore-native-phishing-enabled');
    await settings.bringToFront();await phishingToggle.setChecked(true);
    await eventually(async()=>{const p=(await status()).protection.phishing;return p.enabled===true&&p.available===true&&p.health==='ready'},'Native phishing must be restored ready',180000);
    report.agentFixturePhishingIsolation.restoredOn=true;
    await settings.screenshot({path:path.join(output,'native-settings.png'),fullPage:true});
    report.browserErrors = errors; report.externalPageRequestsAborted = [...new Set(external)];
    assert.deepEqual(errors, []); report.passed = true;
  } catch (error) {
    if (report.interactiveChecks.hiddenCompletion.status==='running') report.interactiveChecks.hiddenCompletion.status='failed';
    report.error = {message:String(error.message).replaceAll(/\b[A-Z_]+SECRET_QA\b/g,'[synthetic sensitive fixture]'), stack:error.stack};
    throw error;
  } finally {
    phase('owned-cleanup');
    connection?.close(); let closed=!preserve;
    const observedChildren = browserProcess && !preserve ? await ownedBrowserChildren(browserProcess.pid, app).catch(()=>[]) : [];
    if ((browser || context) && !preserve) {
      try { await bounded(() => browser ? browser.close() : context.close(), 'Owned browser close; runtime preserved on timeout', 20000); }
      catch(error) { closed=false;report.passed=false;report.cleanupError=error.message; }
    }
    if (browserProcess && !preserve) {
      try {
        if (browserProcess.exitCode===null && browserProcess.signalCode===null && await processIdentity(browserProcess.pid)===browserIdentity) browserProcess.kill('SIGTERM');
        await eventually(async()=>!await processIdentity(browserProcess.pid),'Owned spawned browser must exit',15000);
        await eventually(async()=>(await Promise.all(observedChildren.map(async child=>sameProcessIdentity(await processIdentity(child.pid),child.identity)))).every(present=>!present),'Observed owned browser children must exit',15000);
        report.browserProcessStopped=true;
        report.observedOwnedChildrenStopped=observedChildren.map(child=>child.pid);
      } catch(error) { closed=false;report.passed=false;report.browserShutdownError=error.message; }
    }
    if (runtimeSocketPath && closed) {
      try {
        await eventually(async()=>{try{await lstat(runtimeSocketPath);return false}catch(error){if(error.code==='ENOENT')return true;throw error}},'Browser-owned agent socket must disappear after browser shutdown',10000);
        report.agentChildStoppedWithBrowser=true;
      } catch(error) { closed=false;report.passed=false;report.agentShutdownError=error.message; }
    }
    for (const socket of sockets) socket.destroy();
    await Promise.all([closeServer(serverA),closeServer(serverB)]);
    if (before) { try { report.signatureAfter = await seal(app); assert.deepEqual(report.signatureAfter,before); } catch(error) {report.passed=false;report.signatureError=error.message;} }
    report.finishedAt = new Date().toISOString(); report.disposableProfileRemoved = closed;
    await writeFile(path.join(output,'browser-stderr.log'),browserErrors.join(''),{mode:0o600});
    if (closed) await rm(short, {recursive:true,force:true});
    else report.preservedRuntime={temporary:short,profile,home,reason:preserve?'Unexpected navigation; user session retained without closing it':'Owned shutdown incomplete; retained for diagnosis'};
    await writeFile(path.join(output,'results.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
    console.log(JSON.stringify({passed:report.passed,evidence:path.join(output,'results.json'),checks:report.checks.length}));
    if (!report.passed) process.exitCode=1;
  }
}
const mode = process.argv[2];
if (process.argv.length !== 3 || !['--self-test','--run'].includes(mode)) throw new Error('Choose --self-test, or --run with explicit KUMO_QA_APP and new KUMO_QA_OUTPUT');
if (mode === '--self-test') await selfTest(); else await run();
