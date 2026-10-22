// Real native Chromium -> isolated sampler -> private model pipe -> warning UI.
// Explicit signed app, synthetic loopback pages, no extension or payload tracing.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {createServer} from 'node:http';
import {lstat, mkdtemp, mkdir, realpath, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import {nativeQAApp, nativeQAEnvironment} from './native-browser-qa.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const execute = promisify(execFile);
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const warningURL = value => {
  try { const url = new URL(value); return url.protocol === 'chrome:' && url.hostname === 'kumo-phishing-warning' && url.pathname === '/'; }
  catch { return false; }
};
const fixtures = {
  '/benign': '<!doctype html><title>Public library hours</title><h1>Public library</h1><p>Our library opens Monday at nine. Read books and attend community events.</p>',
  '/suspicious': '<!doctype html><title>Account suspended</title><p>Urgent verify your account immediately to avoid closure.</p><a href="/verify">verify</a>',
  '/privacy': `<!doctype html><title>Example account sign in</title><h1>Example account sign in</h1>
    <form name="PRIVATE_FORM_NAME" action="/?token=PRIVATE_FORM_ACTION"><p>PRIVATE_FORM_TEXT</p>
    <input type="email" name="PRIVATE_EMAIL_NAME" placeholder="PRIVATE_EMAIL_PLACEHOLDER" value="PRIVATE_EMAIL_VALUE">
    <input type="password" value="PRIVATE_PASSWORD_VALUE"><input autocomplete="section-login ONE-TIME-CODE" value="PRIVATE_OTP_VALUE">
    <input type="checkbox" checked value="PRIVATE_CHECKBOX_VALUE"><button>PRIVATE_FORM_BUTTON</button></form>
    <textarea>PRIVATE_TEXTAREA_VALUE</textarea><select><option>PRIVATE_SELECT_VALUE</option></select>
    <p>Public page text <span contenteditable="true">PRIVATE_EDITABLE_VALUE</span><span hidden>PRIVATE_HIDDEN_VALUE</span></p>
    <script>const fixtureOnly='PRIVATE_SCRIPT_VALUE';</script>
    <a href="/account/PRIVATE_PATH_VALUE?token=PRIVATE_LINK_QUERY#PRIVATE_LINK_FRAGMENT">Account</a>`,
};
function allowedPage(value, origin) {
  if (value === 'about:blank' || warningURL(value)) return true;
  try {
    const url = new URL(value);
    if (url.protocol === 'chrome:') return ['newtab', 'new-tab-page'].includes(url.hostname) ||
      url.hostname === 'kumo-new-tab' && url.pathname === '/' && !url.search && !url.hash ||
      url.hostname === 'settings' && url.pathname === '/kumo';
    return url.origin === origin && Object.hasOwn(fixtures, url.pathname) && !url.username && !url.password;
  } catch { return false; }
}
async function eventually(operation, description, timeout = 30000) {
  const deadline = Date.now() + timeout; let last;
  while (Date.now() < deadline) {
    try { const value = await operation(); if (value) return value; }
    catch (error) { if (error.code === 'KUMO_QA_UNEXPECTED_NAVIGATION') throw error; last = error; }
    await pause(100);
  }
  throw new Error(`${description}: ${last?.message || 'condition did not become true'}`);
}
async function foundationProof(directory, environment) {
  const source = path.join(directory, 'home-probe.m'), executable = path.join(directory, 'home-probe');
  await writeFile(source, '#import <Foundation/Foundation.h>\nint main(){@autoreleasepool{NSData*d=[NSJSONSerialization dataWithJSONObject:@{@"home":NSHomeDirectory(),@"support":[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject.path} options:0 error:nil];fwrite(d.bytes,1,d.length,stdout);}}\n');
  await execute('/usr/bin/clang', ['-fobjc-arc', '-framework', 'Foundation', source, '-o', executable], {timeout: 60000});
  const native = JSON.parse((await execute(executable, [], {env: environment, timeout: 10000})).stdout);
  assert.equal(await realpath(native.home), await realpath(environment.HOME));
  const support = path.join(environment.HOME, 'Library/Application Support'); await mkdir(support, {recursive: true, mode: 0o700});
  assert.equal(await realpath(native.support), await realpath(support));
  return {foundationHomeIsDisposable: true, foundationApplicationSupportIsDisposable: true};
}
async function ownedModel(context, executable, helper) {
  const cdp = await context.browser().newBrowserCDPSession();
  let browserPid;
  try { browserPid = (await cdp.send('SystemInfo.getProcessInfo')).processInfo.find(row => row.type === 'browser')?.id; }
  finally { await cdp.detach(); }
  assert(Number.isInteger(browserPid) && browserPid > 1, 'Identify only the launched browser before reading its child names.');
  const command = (await execute('/bin/ps', ['-p', String(browserPid), '-o', 'comm='])).stdout.trim();
  assert.equal(command, executable);
  const ids = (await execute('/usr/bin/pgrep', ['-P', String(browserPid)])).stdout.trim().split(/\s+/);
  assert(ids.length && ids.every(id => /^\d+$/.test(id)));
  // comm contains executable paths only; never collect full process arguments.
  const rows = (await execute('/bin/ps', ['-p', ids.join(','), '-o', 'pid=,ppid=,lstart=,comm='])).stdout;
  const model = rows.split('\n').map(row => /^\s*(\d+)\s+(\d+)\s+(.{24})\s+(.*)$/.exec(row))
      .find(row => row && Number(row[2]) === browserPid && row[4] === helper);
  assert(model, 'The actual packaged PhishLang host must be a direct child of this owned browser.');
  return {browserPid, modelPid: Number(model[1]), modelStarted: model[3], modelExecutable: helper, modelHostIsDirectChild: true};
}
async function sameModelStillPresent(model) {
  if (!model) return false;
  try {
    const row = (await execute('/bin/ps', ['-p', String(model.modelPid), '-o', 'lstart=,comm='])).stdout.trim();
    return row === `${model.modelStarted} ${model.modelExecutable}`;
  } catch (error) { if (error.code === 1) return false; throw error; }
}

async function selfTest() {
  assert(warningURL('chrome://kumo-phishing-warning/?ticket=synthetic'));
  assert(!warningURL('https://kumo-phishing-warning/'));
  assert(!warningURL('chrome://kumo-phishing-warning.evil/'));
  const origin = 'http://127.0.0.1:12345';
  for (const route of Object.keys(fixtures)) assert(allowedPage(origin + route, origin));
  assert(allowedPage('chrome://kumo-new-tab/', origin));
  for (const value of ['https://example.com/', origin + '/unexpected', 'chrome://settings/passwords', 'chrome://kumo-new-tab.evil/', 'chrome://kumo-new-tab/private', 'chrome://kumo-new-tab/?unexpected=1', 'https://user:pass@127.0.0.1:12345/privacy']) assert(!allowedPage(value, origin));
  assert.match(fixtures['/privacy'], /section-login ONE-TIME-CODE/);
  assert.match(fixtures['/privacy'], /PRIVATE_(?:PASSWORD|TEXTAREA|EDITABLE|SCRIPT)_VALUE/);
  assert.doesNotMatch(fixtures['/suspicious'], /<script|http/i);
  const temporary = await mkdtemp('/private/tmp/knp-self-');
  try { await foundationProof(temporary, await nativeQAEnvironment(temporary)); }
  finally { await rm(temporary, {recursive: true, force: true}); }
  console.log(JSON.stringify({passed: true, checks: ['fixed synthetic fixtures', 'warning URL and unexpected-navigation guards', 'actual disposable Foundation home'], browserLaunched: false, modelLaunched: false}));
}

async function run() {
  assert(process.env.KUMO_QA_OUTPUT && path.isAbsolute(process.env.KUMO_QA_OUTPUT), 'Set KUMO_QA_OUTPUT to a new absolute evidence directory.');
  const output = process.env.KUMO_QA_OUTPUT; await mkdir(output, {recursive: false, mode: 0o700});
  const temporary = await mkdtemp('/private/tmp/knp-'), profile = path.join(temporary, 'profile');
  await mkdir(profile, {mode: 0o700});
  const environment = await nativeQAEnvironment(temporary);
  const report = {schemaVersion: 1, startedAt: new Date().toISOString(), passed: false, phases: [], checks: [], errors: [], externalPageOrigins: [],
    limits: ['Synthetic fixtures establish native integration, not model accuracy, calibration or general phishing coverage.',
      'No sampler or helper instrumentation is installed; model payloads, probabilities and per-tab benign classification results are not observed.',
      'A benign/disabled/continued fixture remaining unwarned is a bounded observation, not a proof of safety or absence of inference.',
      'Native status may read the canonical antivirus database read-only; no installer, updater or provider-setup action is invoked.']};
  let app, context, origin, preserve = false, model, primary;
  const serverSockets = new Set();
  const fixture = createServer((request, response) => {
    const route = new URL(request.url, 'http://owned.invalid').pathname;
    response.setHeader('Content-Type', 'text/html; charset=utf-8'); response.setHeader('Cache-Control', 'no-store');
    if (!Object.hasOwn(fixtures, route)) { response.writeHead(404); response.end('Owned fixture not found'); return; }
    response.end(fixtures[route]);
  });
  fixture.on('connection', socket => { serverSockets.add(socket); socket.once('close', () => serverSockets.delete(socket)); });
  const phase = name => { report.phases.push({name, at: new Date().toISOString()}); console.log(JSON.stringify({nativePhishingPhase: name})); };
  const assertOwned = () => {
    if (preserve) { const error = new Error('Unexpected navigation: stop and preserve this profile for the user.'); error.code = 'KUMO_QA_UNEXPECTED_NAVIGATION'; throw error; }
  };
  try {
    phase('verify-signed-app-and-disposable-home'); app = await nativeQAApp();
    report.engineVersion = app.info.engineVersion;
    report.homeProof = await foundationProof(temporary, environment);
    await assert.rejects(lstat(path.join(app.app, 'Contents/Resources/KumoExtension')), {code: 'ENOENT'});
    await new Promise((resolve, reject) => { fixture.once('error', reject); fixture.listen(0, '127.0.0.1', resolve); });
    origin = `http://127.0.0.1:${fixture.address().port}`; report.fixtureOrigin = origin;
    const {chromium} = await import(path.join(root, '.cache/qa/node_modules/playwright-core/index.mjs'));
    phase('launch-isolated-native-browser');
    context = await chromium.launchPersistentContext(profile, {executablePath: app.executable, headless: process.env.KUMO_QA_HEADFUL !== '1', chromiumSandbox: true, timeout: 90000, ignoreDefaultArgs: ['--disable-extensions'],
      env: environment, viewport: {width: 1280, height: 900}, args: ['--no-first-run', '--no-default-browser-check', '--disable-sync', '--use-mock-keychain', '--password-store=basic', '--no-proxy-server', '--host-resolver-rules=MAP * ^NOTFOUND, EXCLUDE 127.0.0.1']});
    context.setDefaultTimeout(20000);
    const watch = page => {
      page.on('pageerror', error => report.errors.push(error.message.slice(0, 2000)));
      page.on('framenavigated', frame => { if (frame === page.mainFrame() && !allowedPage(frame.url(), origin)) { preserve = true; report.unexpectedNavigation = true; } });
    };
    context.pages().forEach(watch); context.on('page', watch);
    await context.route(/^https?:\/\//, route => {
      const url = new URL(route.request().url());
      if (url.origin === origin) return route.continue();
      report.externalPageOrigins.push(url.origin); return route.abort();
    });
    const controls = await context.newPage(); await controls.goto('chrome://settings/kumo');
    await controls.locator('settings-kumo-page').waitFor();
    const status = async () => {
      assertOwned(); await controls.bringToFront();
      await controls.waitForFunction(() => document.visibilityState === 'visible', null, {timeout: 5000});
      return controls.evaluate(async () => {
        let timer;
        try {
          const {sendWithPromise} = await import('chrome://resources/js/cr.js');
          return await Promise.race([sendWithPromise('kumoGetStatus'), new Promise((_resolve, reject) => {
            timer = setTimeout(() => reject(new Error('Native status reply timed out; check Settings visibility.')), 5000);
          })]);
        } finally { clearTimeout(timer); }
      });
    };
    const ready = await eventually(async () => {
      const s = await status();
      return s.protection?.migrationComplete && s.protection.phishing.health === 'ready' ? s : false;
    }, 'Fresh profile native default-on model must become ready', 180000);
    assert.equal(ready.protection.phishing.enabled, true); assert.equal(ready.protection.phishing.available, true);
    assert.equal(ready.protection.phishing.localOnly, true); assert.match(ready.protection.phishing.modelVersion, /^[a-f0-9]{40}$/);
    assert.equal(ready.agents.enabled, false); assert.deepEqual(ready.agents.grants, []);
    report.version = ready.version; report.build = ready.build;
    report.initialProtection = ready.protection.phishing;
    model = await ownedModel(context, app.executable, path.join(app.app, 'Contents/Helpers/KumoPhishing.app/Contents/MacOS/KumoPhishingHost'));
    report.modelProcess = model;
    const toggle = controls.getByRole('checkbox', {name: 'Local PhishLang phishing warnings', exact: true});
    assert.equal(await toggle.isChecked(), true);
    report.checks.push('Fresh profile native model is default-on and ready; actual packaged host is an owned browser child; agent access stays off');
    const target = await context.newPage();
    const visit = async (url, mayWarn = false, reload = false) => {
      assertOwned(); await target.bringToFront();
      try { if (reload) await target.reload({waitUntil: 'domcontentloaded'}); else await target.goto(url, {waitUntil: 'domcontentloaded'}); }
      catch (error) {
        if (!mayWarn) throw error;
        if (!warningURL(target.url()) && !/ERR_ABORTED|interrupted by another navigation/.test(error.message)) throw error;
        await eventually(() => warningURL(target.url()), 'Classifier navigation must explain the interrupted fixture load', 10000);
      }
      assertOwned();
    };
    const hold = async (url, milliseconds = 5000) => {
      const deadline = Date.now() + milliseconds;
      while (Date.now() < deadline) { assertOwned(); assert.equal(target.url(), url); await pause(100); }
    };
    const warning = async name => {
      await target.bringToFront();
      await eventually(async () => { assertOwned(); return warningURL(target.url()); }, 'Actual native model must navigate to its warning', 60000);
      await target.getByRole('heading', {name: 'This page may be trying to deceive you.', exact: true}).waitFor();
      await eventually(async () => !await target.locator('#continue').isDisabled(), 'Native warning ticket must be valid for this document');
      assert.equal(new URL((await target.locator('#origin').textContent()).trim()).origin, origin);
      assert.doesNotMatch(await target.locator('main').innerText(), /PRIVATE_|DOCUMENT_QUERY|DOCUMENT_FRAGMENT/);
      await target.screenshot({path: path.join(output, `${name}.png`)});
      report.phases.push({name, nativeWarning: true, at: new Date().toISOString()});
    };
    const leave = async () => { assertOwned(); assert(warningURL(target.url())); await target.getByRole('button', {name: 'Leave this site', exact: true}).click(); await eventually(() => target.url() === 'about:blank', 'Leave must reach a blank page'); };
    phase('benign-bounded-observation'); await visit(origin + '/benign'); await hold(origin + '/benign');
    report.checks.push('Synthetic library fixture remains unwarned during a five-second observation; no per-tab classification or safety claim');
    phase('privacy-login-native-warning-and-leave');
    await visit(origin + '/privacy?token=PRIVATE_DOCUMENT_QUERY#PRIVATE_DOCUMENT_FRAGMENT', true);
    await warning('privacy-login-warning'); await leave();
    report.checks.push('Real native login-structure warning renders only fixture origin; actual Leave button exits');
    phase('suspicious-native-warning-and-continue');
    const suspicious = origin + '/suspicious'; await visit(suspicious, true); await warning('urgent-page-warning');
    assertOwned(); await target.getByRole('button', {name: 'Continue anyway', exact: true}).click();
    await eventually(() => target.url() === suspicious, 'Continue must return to the requested document'); await hold(suspicious);
    await visit(suspicious, true, true); await warning('reload-warning'); await leave();
    report.checks.push('Actual Continue returns to one document; it remains unwarned for five seconds, then an ordinary reload warns again');
    phase('disable-through-native-settings');
    await controls.bringToFront(); assertOwned(); await toggle.setChecked(false);
    await eventually(async () => { const p = (await status()).protection.phishing; return !p.enabled && !p.available && p.health === 'off'; }, 'Native off state must settle');
    await eventually(async () => !await sameModelStillPresent(model), 'Disabling must stop the previous owned model host', 15000);
    await visit(suspicious); await hold(suspicious);
    report.checks.push('Actual native Settings checkbox turns protection off and the suspicious fixture remains unwarned for five seconds');
    phase('reenable-already-open-owned-page');
    await controls.bringToFront(); assertOwned(); await toggle.setChecked(true);
    await eventually(async () => (await status()).protection.phishing.health === 'ready', 'Native model must become ready after re-enable', 180000);
    model = await ownedModel(context, app.executable, path.join(app.app, 'Contents/Helpers/KumoPhishing.app/Contents/MacOS/KumoPhishingHost'));
    report.reenabledModelProcess = model;
    await warning('reenabled-existing-page-warning'); await leave();
    const final = await status(); assert.equal(final.protection.phishing.enabled, true); assert.equal(final.agents.enabled, false); assert.deepEqual(final.agents.grants, []);
    report.finalProtection = final.protection.phishing;
    report.checks.push('Re-enabling through the real Settings checkbox warns on an already-open synthetic page; final enabled state restored');
    assert.deepEqual(report.errors, []); assert.deepEqual(report.externalPageOrigins, []);
    report.passed = true;
  } catch (error) {
    primary = error; report.primaryError = {message: error.message, stack: error.stack}; report.passed = false;
  } finally {
    phase('owned-cleanup');
    if (context && !preserve) {
      let timer;
      try { await Promise.race([context.close(), new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Owned browser close timed out')), 20000); })]); }
      catch (error) { report.cleanupError = error.message; report.passed = false; preserve = true; }
      finally { clearTimeout(timer); }
    }
    if (!preserve && model) {
      try { await eventually(async () => !await sameModelStillPresent(model), 'Owned model child must exit after browser close', 15000); }
      catch (error) { report.cleanupError = error.message; report.passed = false; preserve = true; }
    }
    for (const socket of serverSockets) socket.destroy();
    if (fixture.listening) await new Promise(resolve => fixture.close(resolve));
    if (app) {
      try { report.signature = await app.verifyUnchanged(); }
      catch (error) { report.signatureError = error.message; report.passed = false; }
    }
    if (preserve) { report.preservedRuntime = {temporary, profile, reason: report.unexpectedNavigation ? 'Unexpected navigation; user session preserved without closing it' : 'Owned cleanup incomplete; preserved for diagnosis'}; report.passed = false; }
    else { await rm(temporary, {recursive: true, force: true}); report.disposableRuntimeRemoved = true; }
    report.finishedAt = new Date().toISOString();
    await writeFile(path.join(output, 'results.json'), JSON.stringify(report, null, 2) + '\n', {mode: 0o600});
    console.log(JSON.stringify({passed: report.passed, evidence: path.join(output, 'results.json'), checks: report.checks.length, ...(primary ? {error: primary.message} : {})}));
    if (!report.passed) process.exitCode = 1;
  }
}

const mode = process.argv[2];
assert(process.argv.length === 3 && ['--self-test', '--run'].includes(mode), 'Choose --self-test, or --run with explicit KUMO_QA_APP and new KUMO_QA_OUTPUT.');
if (mode === '--self-test') await selfTest(); else await run();
