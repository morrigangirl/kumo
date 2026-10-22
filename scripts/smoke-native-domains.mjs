// Real native domain policy across browser, renderer, workers and extension
// redirects. Explicit fresh app + digest only; all destinations are loopback.
import assert from 'node:assert/strict';
import {execFile, spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createServer} from 'node:http';
import {appendFile, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import {Script} from 'node:vm';
import {nativeQAApp, nativeQAEnvironment} from './native-browser-qa.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const execute = promisify(execFile);
const listedHost = 'blocked.kumo-qa.invalid', allowedHost = 'unlisted.kumo-qa.invalid';
const legacyId = 'eldkgppmnhligdekahicdcdndcoongio';
const resolverRules = `MAP ${listedHost} 127.0.0.1, MAP ${allowedHost} 127.0.0.1, MAP * ^NOTFOUND, EXCLUDE 127.0.0.1`;
const pixel = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII=', 'base64');
const hash = value => createHash('sha256').update(value).digest('hex');
const escaped = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const tick = ms => new Promise(resolve => setTimeout(resolve, ms));
async function bounded(operation, label, ms = 7000) {
  let timer;
  try { return await Promise.race([Promise.resolve().then(operation), new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`QA timeout: ${label}`)), ms);
  })]); } finally { clearTimeout(timer); }
}
async function eventually(operation, label, ms = 30000) {
  const end = Date.now() + ms; let last;
  while (Date.now() < end) {
    try { const result = await operation(); if (result) return result; }
    catch (error) { last = error; }
    await tick(80);
  }
  throw new Error(`${label}: ${last?.message || 'condition absent'}`);
}
function domainSnapshot() {
  const version = 'kumo-local-qa-1', modifiedEpoch = Math.floor(Date.now() / 1000);
  return {schemaVersion: 1, version, modifiedEpoch, domains: [listedHost],
    sha256: hash(`${version}\n${modifiedEpoch}\n${listedHost}\n`)};
}
function endpoint(text) {
  const [port, target] = text.trim().split('\n');
  assert(/^\d+$/.test(port) && +port > 0 && +port < 65536);
  assert(/^\/devtools\/browser\/[\w-]+$/.test(target));
  return `ws://127.0.0.1:${port}${target}`;
}
function allowedPage(value, origins, extensionId) {
  if (value === 'about:blank' || value === 'chrome-error://chromewebdata/') return true;
  try {
    const url = new URL(value);
    if (url.username || url.password) return false;
    if (url.protocol === 'chrome:') return !url.search && !url.hash &&
      (url.host === 'settings' && url.pathname === '/kumo' ||
       ['newtab', 'new-tab-page', 'kumo-new-tab'].includes(url.host) && url.pathname === '/');
    if (url.protocol === 'chrome-extension:') return extensionId && url.host === extensionId && url.pathname === '/qa.html';
    return origins.includes(url.origin);
  } catch { return false; }
}
function completed(result) {
  return result?.outcome === 'completed' && !result.timedOut &&
    (result.status === 200 || result.loaded === true && result.marker === true || result.opened === true);
}
function blocked(result) {
  return result?.outcome === 'rejected' && !result.timedOut &&
    ['TypeError', 'NetworkError', 'NativeBlocked'].includes(result.errorName);
}
async function processRows() {
  const {stdout} = await execute('/bin/ps', ['-ww', '-axo', 'pid=,ppid=,lstart=,comm='],
    {env: {PATH: '/usr/bin:/bin', LC_ALL: 'C', LANG: 'C'}});
  return stdout.split('\n').map(line => {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\S+\s+\S+\s+\d+\s+\d\d:\d\d:\d\d\s+\d{4})\s+(.*)$/);
    return match ? {pid: +match[1], ppid: +match[2], started: match[3].replace(/\s+/g, ' '), executable: match[4]} : null;
  }).filter(Boolean);
}
const sameProcess = (current, original) => !!current && !!original && current.pid === original.pid &&
  current.started === original.started && current.executable === original.executable;
function verifiedOwnedIdentity(child, identity, executable, parentPid = process.pid) {
  return Number.isInteger(child?.pid) && child.pid > 0 && identity?.pid === child.pid &&
    identity.ppid === parentPid && typeof identity.started === 'string' && identity.started.length > 0 &&
    typeof executable === 'string' && identity.executable === executable;
}
async function foundationProof(temporary, environment) {
  const source = path.join(temporary, 'home-probe.m'), executable = path.join(temporary, 'home-probe');
  await writeFile(source, '#import <Foundation/Foundation.h>\nint main(){@autoreleasepool{NSData*d=[NSJSONSerialization dataWithJSONObject:@{@"home":NSHomeDirectory(),@"support":[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject.path} options:0 error:nil];fwrite(d.bytes,1,d.length,stdout);}}\n');
  await execute('/usr/bin/clang', ['-fobjc-arc', '-framework', 'Foundation', source, '-o', executable]);
  const value = JSON.parse((await execute(executable, [], {env: environment})).stdout);
  assert.equal(await realpath(value.home), await realpath(environment.HOME));
  await mkdir(path.join(environment.HOME, 'Library/Application Support'), {recursive: true, mode: 0o700});
  assert.equal(await realpath(value.support), await realpath(path.join(environment.HOME, 'Library/Application Support')));
  return {passed: true, foundationHomeIsDisposable: true, applicationSupportIsDisposable: true};
}
function workerSource(kind, serviceImports = {}) {
  const operation = `async function operate(request) {
    try {
      if (request.action === 'import') {
        importScripts(request.url);
        return {outcome:'completed',loaded:true,marker:globalThis.__qaImports?.includes(request.caseId)===true};
      }
      const response=await fetch(request.url,{signal:AbortSignal.timeout(2500)});
      const body=await response.text();
      return {outcome:'completed',status:response.status,bodyBytes:body.length,timedOut:false};
    } catch(error) { return {outcome:'rejected',errorName:error.name,timedOut:['TimeoutError','AbortError'].includes(error.name)}; }
  }`;
  if (kind === 'service') return `${operation}
    const imported={};
    for(const [caseId,url] of Object.entries(${JSON.stringify(serviceImports)})) {
      try { importScripts(url);imported[caseId]={outcome:'completed',loaded:true,marker:globalThis.__qaImports?.includes(caseId)===true}; }
      catch(error) { imported[caseId]={outcome:'rejected',errorName:error.name,timedOut:false}; }
    }
    self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
    self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
    self.addEventListener('message',event=>{event.waitUntil((async()=>{event.ports[0].postMessage(event.data.action==='initial-import'?imported[event.data.caseId]:await operate(event.data));})());});`;
  if (kind === 'shared') return `${operation}\nonconnect=event=>{const port=event.ports[0];port.onmessage=async event=>port.postMessage(await operate(event.data));port.start();};`;
  return `${operation}\nonmessage=async event=>postMessage(await operate(event.data));`;
}
function extensionFixture(unlistedOrigin, listedOrigin) {
  const rules = ['control', 'listed'].map((destination, index) => ({id: index + 1, priority: 1,
    action: {type: 'redirect', redirect: {url: `${destination === 'listed' ? listedOrigin : unlistedOrigin}/resource?case=dnr-${destination}`}},
    condition: {urlFilter: `|${unlistedOrigin}/dnr/source?case=dnr-${destination}|`, resourceTypes: ['xmlhttprequest']}}));
  return {manifest: {manifest_version: 3, name: 'Kumo owned DNR redirect fixture', version: '1.0',
    permissions: ['declarativeNetRequest'], host_permissions: ['http://127.0.0.1/*', `http://${allowedHost}/*`, `http://${listedHost}/*`],
    background: {service_worker: 'background.js'},
    declarative_net_request: {rule_resources: [{id: 'qa_redirect', enabled: true, path: 'rules.json'}]}}, rules};
}
async function selfTest() {
  assert.match(resolverRules, /MAP \* \^NOTFOUND, EXCLUDE 127\.0\.0\.1$/);
  assert.equal(domainSnapshot().domains[0], listedHost);
  assert.equal(endpoint('12345\n/devtools/browser/fixture\n'), 'ws://127.0.0.1:12345/devtools/browser/fixture');
  assert.throws(() => endpoint('12345\nws://elsewhere.invalid/devtools/browser/fixture'));
  const ownedIdentity={pid:42,ppid:7,started:'Wed Oct 21 21:00:00 2026',executable:'/owned/Chromium'};
  assert(verifiedOwnedIdentity({pid:42},ownedIdentity,'/owned/Chromium',7));
  for(const identity of [undefined,{...ownedIdentity,pid:43},{...ownedIdentity,ppid:8},{...ownedIdentity,started:''},{...ownedIdentity,executable:'/unverified/Chromium'}])
    assert(!verifiedOwnedIdentity({pid:42},identity,'/owned/Chromium',7));
  assert(!verifiedOwnedIdentity({},ownedIdentity,'/owned/Chromium',7));
  assert(completed({outcome: 'completed', status: 200}));
  assert(!completed({outcome: 'completed', status: 200, timedOut: true}));
  assert(blocked({outcome: 'rejected', errorName: 'NetworkError'}));
  for (const value of [{outcome:'timeout'}, {outcome:'rejected',errorName:'TimeoutError',timedOut:true}, {outcome:'rejected',errorName:'SecurityError'}]) assert(!blocked(value));
  for (const kind of ['dedicated','shared','service']) new Script(workerSource(kind, {'service-import-control':'http://127.0.0.1:12345/import.js?case=service-import-control'}));
  const fixture = extensionFixture('http://unlisted.kumo-qa.invalid:12345', 'http://blocked.kumo-qa.invalid:12345');
  assert.deepEqual(fixture.manifest.host_permissions, ['http://127.0.0.1/*', `http://${allowedHost}/*`, `http://${listedHost}/*`], 'DNR redirect needs both the exact synthetic initiator and request hosts');
  assert.equal(fixture.rules.length, 2); assert.equal(fixture.rules[1].action.redirect.url, 'http://blocked.kumo-qa.invalid:12345/resource?case=dnr-listed');
  const rewritePattern=new RegExp(`^${escaped('http://127.0.0.1:12345')}/cdp-rewrite\\?case=(cdp-rewrite-control|cdp-rewrite-listed)$`);
  assert(rewritePattern.test('http://127.0.0.1:12345/cdp-rewrite?case=cdp-rewrite-control'));
  for(const value of ['http://127.0.0.1:12345/resource?case=cdp-rewrite-control','http://127.0.0.1:12345/cdp-rewrite?case=other','http://127x0x0x1:12345/cdp-rewrite?case=cdp-rewrite-listed'])assert(!rewritePattern.test(value));
  assert(allowedPage('chrome://kumo-new-tab/', [], 'owned'));
  for (const value of ['https://example.com/', 'chrome://settings/passwords', 'chrome://kumo-new-tab.evil/', 'http://user:secret@127.0.0.1:12345/']) assert(!allowedPage(value, ['http://127.0.0.1:12345'], 'owned'));
  const temporary = await mkdtemp('/private/tmp/knds-');
  try { await foundationProof(temporary, await nativeQAEnvironment(temporary)); }
  finally { await rm(temporary, {recursive:true,force:true}); }
  console.log(JSON.stringify({passed:true,browserLaunched:false,checks:['source-pin/endpoint boundaries','explicit timeouts never count as blocking','worker fixture syntax','ordinary MV3 DNR fixture','unexpected-navigation preservation','independent Foundation home']}));
}
async function run() {
  assert(process.env.KUMO_QA_OUTPUT, 'Set KUMO_QA_OUTPUT to a fresh evidence directory');
  assert(path.isAbsolute(process.env.KUMO_QA_OUTPUT), 'KUMO_QA_OUTPUT must be an explicit absolute path');
  const expectedSource = process.env.KUMO_QA_EXPECTED_SOURCE_INPUTS;
  assert(/^[a-f0-9]{64}$/.test(expectedSource || ''), 'Set the exact expected KUMO_QA_EXPECTED_SOURCE_INPUTS digest');
  const output = path.resolve(process.env.KUMO_QA_OUTPUT); await mkdir(output, {recursive:false,mode:0o700});
  const report = {schemaVersion:1,startedAt:new Date().toISOString(),passed:false,cases:[],expectedSource,
    routeInterception:{baseline:false,trustedCDPRewriteOnly:true},headless:true,sandbox:true,mockKeychain:true,accountsAccessed:false,
    trustedCDPRewrite:{routeInterception:true,cases:[],rewrites:[]},
    providerSetupPerformed:false,antivirusChanged:false,realMalwareContacted:false,
    limits:['Only synthetic loopback hosts are classified by the native domain list. This is policy wiring qualification, not malware detection coverage.',
      'WebTransport has source and native admission-unit coverage only; no real HTTP3/TLS server is provided and generic handshake rejection is not counted as runtime protection.',
      'No helper setup/update or desktop client configuration is invoked. PhishLang is explicitly off in this disposable domain fixture; separate native phishing QA covers its default-on behavior.',
      'Worker classic importScripts is covered; ES module dynamic import and worker shutdown keepalive are not claimed.']};
  let app, temporary, environment, profile, browser, context, child, identity, origin, unlisted, listed, extensionId, preserve=false;
  const serverHits=[], sockets=new Set(), browserStderr=[], children=new Map(); let hitWrites=Promise.resolve();
  const recordHit = value => {serverHits.push(value);hitWrites=hitWrites.then(()=>appendFile(path.join(output,'server-hits.ndjson'),JSON.stringify(value)+'\n',{mode:0o600}));};
  const server=createServer((request,response)=>{
    const url=new URL(request.url,'http://fixture.invalid'), hostname=(request.headers.host||'').split(':')[0];
    recordHit({caseId:url.searchParams.get('case'),path:url.pathname,method:request.method,
      host:hostname===listedHost?'listed':hostname===allowedHost?'unlisted':'loopback'});
    response.setHeader('Cache-Control','no-store');response.setHeader('Access-Control-Allow-Origin','*');
    response.setHeader('Access-Control-Allow-Private-Network','true');response.setHeader('Access-Control-Allow-Methods','GET,OPTIONS');response.setHeader('Access-Control-Allow-Headers','*');
    if(request.method==='OPTIONS'){response.writeHead(204);response.end();return;}
    if(url.pathname==='/redirect'){
      const status=Number(url.searchParams.get('status')), destination=url.searchParams.get('to');
      if(![302,307].includes(status)||!['listed','unlisted'].includes(destination)){response.writeHead(400);response.end();return;}
      response.writeHead(status,{Location:`${destination==='listed'?listed:unlisted}/resource?case=${encodeURIComponent(url.searchParams.get('case')||'')}`});response.end();return;
    }
    if(url.pathname==='/pixel'){response.setHeader('Content-Type','image/png');response.end(pixel);return;}
    if(url.pathname==='/import.js'){
      response.setHeader('Content-Type','application/javascript');
      response.end(`globalThis.__qaImports=(globalThis.__qaImports||[]).concat(${JSON.stringify(url.searchParams.get('case'))});`);return;
    }
    if(url.pathname.startsWith('/workers/')){
      response.setHeader('Content-Type','application/javascript');response.setHeader('Service-Worker-Allowed','/');
      const kind=url.pathname.split('/').pop().replace('.js','');
      response.end(workerSource(kind,{'service-import-control':`${unlisted}/import.js?case=service-import-control`,'service-import-listed':`${listed}/import.js?case=service-import-listed`}));return;
    }
    if(url.pathname==='/resource'){response.setHeader('Content-Type','text/plain');response.end('Owned public resource');return;}
    response.setHeader('Content-Type','text/html');response.end('<!doctype html><title>Owned native domain fixture</title><h1>Public owned domain fixture</h1>');
  });
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
  server.on('upgrade',(request,socket)=>{
    const url=new URL(request.url,'http://fixture.invalid'),hostname=(request.headers.host||'').split(':')[0];
    recordHit({caseId:url.searchParams.get('case'),path:url.pathname,method:'UPGRADE',host:hostname===listedHost?'listed':hostname===allowedHost?'unlisted':'loopback'});
    const key=request.headers['sec-websocket-key'];
    if(typeof key!=='string'){socket.destroy();return;}
    const accept=createHash('sha1').update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    setTimeout(()=>socket.end(Buffer.from([0x88,0x00])),100);
  });
  const phase=async name=>{assert(!preserve,'Unexpected navigation; user session preserved');report.phase=name;console.log(JSON.stringify({nativeDomainPhase:name}));await writeFile(path.join(output,'progress.json'),JSON.stringify({at:new Date().toISOString(),phase:name,cases:report.cases.length},null,2)+'\n');};
  const capture=async(name,api,expectation,operation,control,collection=report.cases)=>{
    await phase(name);let result;
    try{result=await bounded(operation,name,10000);}catch(error){result={outcome:'qa-error',message:error.message};}
    await hitWrites;
    const hits=serverHits.filter(hit=>hit.caseId===name), validControl=!control||collection.find(row=>row.name===control)?.passed===true;
    const passed=validControl&&(expectation==='blocked'?blocked(result)&&!hits.some(hit=>hit.host==='listed'):completed(result));
    const row={name,api,expectation,control:control||null,controlPassed:validControl,result,serverHits:hits,passed};collection.push(row);
    await writeFile(path.join(output,collection===report.cases?'cases.json':'trusted-cdp-cases.json'),JSON.stringify(collection,null,2)+'\n',{mode:0o600});return row;
  };
  try{
    await phase('verify-app-and-owned-home');app=await nativeQAApp();
    assert.equal(app.info.sourceBuildReceipt?.sourceInputsSha256,expectedSource,'The fresh app must match the exact approved source fingerprint');
    report.app=app.app;report.sourceBuildReceipt=app.info.sourceBuildReceipt;
    await assert.rejects(lstat(path.join(app.app,'Contents/Resources/KumoExtension')),{code:'ENOENT'});
    temporary=await mkdtemp('/private/tmp/knd-');environment=await nativeQAEnvironment(temporary);profile=path.join(temporary,'profile');
    report.homeProof=await foundationProof(temporary,environment);
    await mkdir(path.join(profile,'Default'),{recursive:true,mode:0o700});
    report.domainSnapshot=domainSnapshot();
    await writeFile(path.join(profile,'Default/Preferences'),JSON.stringify({kumo:{protection:{phishing_enabled:false,domain_snapshot:report.domainSnapshot}}}),{mode:0o600});
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
    origin=`http://127.0.0.1:${server.address().port}`;unlisted=`http://${allowedHost}:${server.address().port}`;listed=`http://${listedHost}:${server.address().port}`;
    const extension=path.join(temporary,'extension');await mkdir(extension,{mode:0o700});const fixture=extensionFixture(unlisted,listed);
    await writeFile(path.join(extension,'manifest.json'),JSON.stringify(fixture.manifest));await writeFile(path.join(extension,'rules.json'),JSON.stringify(fixture.rules));
    await writeFile(path.join(extension,'background.js'),'chrome.runtime.onInstalled.addListener(()=>{});\n');await writeFile(path.join(extension,'qa.html'),'<!doctype html><title>Owned DNR fixture</title>');
    const args=[`--user-data-dir=${profile}`,'--headless=new','--remote-debugging-port=0','--remote-debugging-address=127.0.0.1',`--load-extension=${extension}`,
      '--no-first-run','--no-default-browser-check','--disable-sync','--use-mock-keychain','--password-store=basic','--no-proxy-server',`--host-resolver-rules=${resolverRules}`,'about:blank'];
    assert(!args.some(value=>value==='--no-sandbox'||value==='--disable-web-security'));
    await phase('launch-native-without-network-interception');child=spawn(app.executable,args,{env:environment,stdio:['ignore','ignore','pipe']});
    child.stderr.on('data',bytes=>{if(browserStderr.join('').length<131072)browserStderr.push(String(bytes));});child.on('error',error=>browserStderr.push(error.message));
    identity=(await processRows()).find(row=>row.pid===child.pid);assert(verifiedOwnedIdentity(child,identity,app.executable));report.browserIdentity=identity;
    const cdp=await eventually(async()=>endpoint(await readFile(path.join(profile,'DevToolsActivePort'),'utf8')),'Owned loopback CDP endpoint',60000);
    const {chromium}=await import(path.join(root,'.cache/qa/node_modules/playwright-core/index.mjs'));
    browser=await chromium.connectOverCDP(cdp,{noDefaults:true,timeout:30000});context=browser.contexts()[0];assert(context);context.setDefaultTimeout(15000);
    const watch=page=>page.on('framenavigated',frame=>{if(frame===page.mainFrame()&&!allowedPage(frame.url(),[origin,unlisted,listed],extensionId)){preserve=true;report.unexpectedNavigation=true;}});
    context.pages().forEach(watch);context.on('page',watch);
    const settings=await context.newPage();await settings.goto('chrome://settings/kumo');await settings.locator('settings-kumo-page').waitFor();
    const status=async()=>{assert(!preserve);await settings.bringToFront();return bounded(()=>settings.evaluate(async()=>{const {sendWithPromise}=await import('chrome://resources/js/cr.js');return sendWithPromise('kumoGetStatus');}),'native status');};
    const ready=await eventually(async()=>{const value=await status(),p=value.protection;return p.migrationComplete&&p.malware.enabled&&p.malware.health==='ready'&&p.malware.domainCount===1?value:false;},'Native list must be ready');
    assert.equal(ready.protection.phishing.enabled,false);assert.equal(ready.agents.enabled,false);assert.deepEqual(ready.agents.grants,[]);report.initialProtection=ready.protection;
    const page=await context.newPage();await page.goto(origin+'/scope/page');await page.bringToFront();
    const fetchRequest=(url,keepalive=false)=>page.evaluate(async({url,keepalive})=>{try{const response=await fetch(url,{keepalive,signal:AbortSignal.timeout(3000)});const body=await response.text();return{outcome:'completed',status:response.status,bodyBytes:body.length,timedOut:false};}catch(error){return{outcome:'rejected',errorName:error.name,timedOut:['TimeoutError','AbortError'].includes(error.name)};}},{url,keepalive});
    const urlFor=(base,resource,name)=>`${base}/${resource}?case=${name}`;
    await capture('fetch-control','fetch','allowed',()=>fetchRequest(urlFor(unlisted,'resource','fetch-control')));
    await capture('fetch-listed','fetch','blocked',()=>fetchRequest(urlFor(listed,'resource','fetch-listed')), 'fetch-control');
    const xhrRequest=url=>page.evaluate(url=>new Promise(resolve=>{const xhr=new XMLHttpRequest();xhr.open('GET',url);xhr.timeout=3000;xhr.onload=()=>resolve({outcome:'completed',status:xhr.status});xhr.onerror=()=>resolve({outcome:'rejected',errorName:'NetworkError',timedOut:false});xhr.ontimeout=()=>resolve({outcome:'timeout',timedOut:true});xhr.send();}),url);
    await capture('xhr-control','XMLHttpRequest','allowed',()=>xhrRequest(urlFor(unlisted,'resource','xhr-control')));
    await capture('xhr-listed','XMLHttpRequest','blocked',()=>xhrRequest(urlFor(listed,'resource','xhr-listed')),'xhr-control');
    const imageRequest=url=>page.evaluate(url=>new Promise(resolve=>{const image=new Image();const timer=setTimeout(()=>{image.src='';resolve({outcome:'timeout',timedOut:true});},3000);image.onload=()=>{clearTimeout(timer);resolve({outcome:'completed',loaded:true,marker:image.naturalWidth===1});};image.onerror=()=>{clearTimeout(timer);resolve({outcome:'rejected',errorName:'NetworkError',timedOut:false});};image.src=url;}),url);
    await capture('image-control','image','allowed',()=>imageRequest(urlFor(unlisted,'pixel','image-control')));
    await capture('image-listed','image','blocked',()=>imageRequest(urlFor(listed,'pixel','image-listed')),'image-control');
    for(const statusCode of [302,307]){
      const control=`redirect-${statusCode}-control`,name=`redirect-${statusCode}-listed`;
      await capture(control,'fetch redirect','allowed',()=>fetchRequest(`${unlisted}/redirect?case=${control}&status=${statusCode}&to=unlisted`));
      await capture(name,'fetch redirect','blocked',()=>fetchRequest(`${unlisted}/redirect?case=${name}&status=${statusCode}&to=listed`),control);
    }
    for(const redirect of [false,true]){
      const control=`keepalive${redirect?'-redirect':''}-control`,name=`keepalive${redirect?'-redirect':''}-listed`;
      await capture(control,'keepalive fetch','allowed',()=>fetchRequest(redirect?`${unlisted}/redirect?case=${control}&status=307&to=unlisted`:urlFor(unlisted,'resource',control),true));
      await capture(name,'keepalive fetch','blocked',()=>fetchRequest(redirect?`${unlisted}/redirect?case=${name}&status=307&to=listed`:urlFor(listed,'resource',name),true),control);
    }
    const workerRequest=(kind,request)=>page.evaluate(async({kind,request})=>new Promise(resolve=>{
      let worker,port;const timer=setTimeout(()=>{worker?.terminate?.();port?.close?.();resolve({outcome:'timeout',timedOut:true});},5000);
      const finish=result=>{clearTimeout(timer);worker?.terminate?.();port?.close?.();resolve(result);};
      if(kind==='shared'){worker=new SharedWorker(`/workers/shared.js?case=${request.caseId}-bootstrap`,request.caseId);port=worker.port;port.onmessage=event=>finish(event.data);port.start();worker.onerror=()=>finish({outcome:'worker-error'});port.postMessage(request);}
      else{worker=new Worker(`/workers/dedicated.js?case=${request.caseId}-bootstrap`);worker.onmessage=event=>finish(event.data);worker.onerror=()=>finish({outcome:'worker-error'});worker.postMessage(request);}
    }),{kind,request});
    for(const kind of ['dedicated','shared'])for(const action of ['fetch','import']){
      const control=`${kind}-${action}-control`,name=`${kind}-${action}-listed`,resource=action==='import'?'import.js':'resource';
      await capture(control,`${kind} worker ${action}`,'allowed',()=>workerRequest(kind,{action,caseId:control,url:urlFor(unlisted,resource,control)}));
      await capture(name,`${kind} worker ${action}`,'blocked',()=>workerRequest(kind,{action,caseId:name,url:urlFor(listed,resource,name)}),control);
    }
    await phase('service-worker-registration-and-imports');
    await bounded(()=>page.evaluate(async()=>{await navigator.serviceWorker.register('/workers/service.js',{scope:'/scope/',updateViaCache:'none'});await navigator.serviceWorker.ready;}),'Service worker activation',15000);
    const serviceRequest=request=>page.evaluate(async request=>{
      const registration=await navigator.serviceWorker.ready;
      return new Promise(resolve=>{
        const channel=new MessageChannel();const timer=setTimeout(()=>{channel.port1.close();resolve({outcome:'timeout',timedOut:true});},5000);
        channel.port1.onmessage=event=>{clearTimeout(timer);channel.port1.close();resolve(event.data);};registration.active.postMessage(request,[channel.port2]);
      });
    },request);
    await capture('service-import-control','service worker importScripts','allowed',()=>serviceRequest({action:'initial-import',caseId:'service-import-control'}));
    await capture('service-import-listed','service worker importScripts','blocked',()=>serviceRequest({action:'initial-import',caseId:'service-import-listed'}),'service-import-control');
    await capture('service-fetch-control','service worker fetch','allowed',()=>serviceRequest({action:'fetch',caseId:'service-fetch-control',url:urlFor(unlisted,'resource','service-fetch-control')}));
    await capture('service-fetch-listed','service worker fetch','blocked',()=>serviceRequest({action:'fetch',caseId:'service-fetch-listed',url:urlFor(listed,'resource','service-fetch-listed')}),'service-fetch-control');
    await phase('ordinary-extension-DNR-post-rewrite');
    const worker=await eventually(async()=>{
      for(const value of context.serviceWorkers().filter(value=>value.url().startsWith('chrome-extension://')))
        if(await bounded(()=>value.evaluate(()=>chrome.runtime.getManifest().name),'owned extension manifest')===fixture.manifest.name)return value;
      return false;
    },'Owned ordinary MV3 worker');extensionId=new URL(worker.url()).host;assert.notEqual(extensionId,legacyId);
    const extensionPage=await context.newPage();await extensionPage.goto(`chrome-extension://${extensionId}/qa.html`);
    report.extension={id:extensionId,enabledRulesets:await extensionPage.evaluate(()=>chrome.declarativeNetRequest.getEnabledRulesets()),fixtureSha256:hash(JSON.stringify(fixture))};assert.deepEqual(report.extension.enabledRulesets,['qa_redirect']);
    const dnrControl=await capture('dnr-control','ordinary extension DNR redirect','allowed',()=>fetchRequest(`${unlisted}/dnr/source?case=dnr-control`));
    dnrControl.passed&&=dnrControl.serverHits.some(hit=>hit.path==='/resource'&&hit.host==='unlisted')&&!dnrControl.serverHits.some(hit=>hit.path==='/dnr/source');
    await capture('dnr-listed','ordinary extension DNR redirect','blocked',()=>fetchRequest(`${unlisted}/dnr/source?case=dnr-listed`),'dnr-control');
    const websocket=url=>page.evaluate(url=>new Promise(resolve=>{const socket=new WebSocket(url);const timer=setTimeout(()=>{socket.close();resolve({outcome:'timeout',timedOut:true});},3000);socket.onopen=()=>{clearTimeout(timer);socket.close();resolve({outcome:'completed',opened:true});};socket.onerror=()=>{clearTimeout(timer);resolve({outcome:'rejected',errorName:'NetworkError',timedOut:false});};}),url);
    await capture('websocket-control','WebSocket handshake','allowed',()=>websocket(urlFor(unlisted.replace('http:','ws:'),'socket','websocket-control')));
    await capture('websocket-listed','WebSocket handshake','blocked',()=>websocket(urlFor(listed.replace('http:','ws:'),'socket','websocket-listed')),'websocket-control');
    const navigation=async(url)=>{const target=await context.newPage();try{const response=await target.goto(url,{timeout:5000});return{outcome:'completed',status:response?.status()};}catch(error){return{outcome:'rejected',errorName:/ERR_BLOCKED_BY_CLIENT/.test(error.message)?'NativeBlocked':'NavigationError',timedOut:/Timeout/.test(error.message),message:error.message.split('\n')[0]};}finally{if(!preserve)await bounded(()=>target.close(),'owned navigation tab close');}};
    await capture('navigation-control','main navigation','allowed',()=>navigation(urlFor(unlisted,'resource','navigation-control')));
    await capture('navigation-listed','main navigation','blocked',()=>navigation(urlFor(listed,'resource','navigation-listed')),'navigation-control');
    for(const statusCode of [302,307]){
      const control=`navigation-${statusCode}-control`,name=`navigation-${statusCode}-listed`;
      await capture(control,'main navigation redirect','allowed',()=>navigation(`${unlisted}/redirect?case=${control}&status=${statusCode}&to=unlisted`));
      await capture(name,'main navigation redirect','blocked',()=>navigation(`${unlisted}/redirect?case=${name}&status=${statusCode}&to=listed`),control);
    }
    await phase('native-domain-toggle-off-and-on');
    const toggle=settings.getByRole('checkbox',{name:'Block known dangerous domains',exact:true});await settings.bringToFront();await toggle.setChecked(false);
    await eventually(async()=>!(await status()).protection.malware.enabled,'Actual native domain toggle off');
    await capture('disabled-listed-control','native policy toggle','allowed',()=>fetchRequest(urlFor(listed,'resource','disabled-listed-control')));
    await settings.bringToFront();await toggle.setChecked(true);await eventually(async()=>{const p=(await status()).protection;return p.malware.enabled&&p.malware.health==='ready';},'Actual native domain toggle restored');
    await capture('reenabled-listed','native policy toggle','blocked',()=>fetchRequest(urlFor(listed,'resource','reenabled-listed')),'disabled-listed-control');
    report.finalProtection=(await status()).protection;assert.equal(report.finalProtection.malware.enabled,true);
    assert.equal(report.cases.length,38,'All baseline cases run without request interception');
    await phase('trusted-CDP-rewrite-separate-scope');
    const rewritePattern=new RegExp(`^${escaped(origin)}/cdp-rewrite\\?case=(cdp-rewrite-control|cdp-rewrite-listed)$`);
    const rewriteHandler=route=>{
      const caseId=new URL(route.request().url()).searchParams.get('case');
      const destination=caseId==='cdp-rewrite-listed'?listed:unlisted;
      report.trustedCDPRewrite.rewrites.push({caseId,target:destination===listed?'listed':'unlisted'});
      return route.continue({url:urlFor(destination,'resource',caseId)});
    };
    await bounded(()=>context.route(rewritePattern,rewriteHandler),'install owned CDP rewrite route');
    try{
      const collection=report.trustedCDPRewrite.cases;
      const control=await capture('cdp-rewrite-control','trusted CDP URL rewrite','allowed',()=>fetchRequest(`${origin}/cdp-rewrite?case=cdp-rewrite-control`),undefined,collection);
      control.passed&&=report.trustedCDPRewrite.rewrites.filter(row=>row.caseId===control.name).length===1&&
        control.serverHits.some(hit=>hit.path==='/resource'&&hit.host==='unlisted')&&!control.serverHits.some(hit=>hit.path==='/cdp-rewrite');
      const negative=await capture('cdp-rewrite-listed','trusted CDP URL rewrite','blocked',()=>fetchRequest(`${origin}/cdp-rewrite?case=cdp-rewrite-listed`),'cdp-rewrite-control',collection);
      negative.passed&&=report.trustedCDPRewrite.rewrites.filter(row=>row.caseId===negative.name).length===1;
    }finally{await bounded(()=>context.unroute(rewritePattern,rewriteHandler),'remove owned CDP rewrite route');}
    await hitWrites;await writeFile(path.join(output,'cases.json'),JSON.stringify(report.cases,null,2)+'\n',{mode:0o600});
    report.passed=[...report.cases,...report.trustedCDPRewrite.cases].every(value=>value.passed);report.completed=true;
  }catch(error){report.primaryError={message:error.message,stack:error.stack};report.passed=false;}
  finally{
    report.cleanup={passed:false,preserved:preserve};
    if(child&&!verifiedOwnedIdentity(child,identity,app?.executable)){
      preserve=true;report.passed=false;
      report.cleanup={passed:false,preserved:true,error:'Spawn identity was not verified; no signal, exit claim or profile deletion is authorized'};
    }
    if(child&&!preserve){
      let disconnectError;
      try{
        for(const row of await processRows())if(row.ppid===child.pid&&row.executable.startsWith(`${app.app}/Contents/`))children.set(row.pid,row);
      }catch(error){report.childInventoryError=error.message;report.passed=false;preserve=true;}
      // A stalled CDP disconnect must not prevent the independent, identity-
      // checked graceful shutdown of the ChildProcess owned by this fixture.
      try{if(browser)await bounded(()=>browser.close(),'owned browser disconnect',10000);}
      catch(error){disconnectError=error.message;report.passed=false;}
      try{
        const current=(await processRows()).find(row=>row.pid===child.pid);
        if(sameProcess(current,identity)&&current.ppid===process.pid&&child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');
        await eventually(async()=>!(await processRows()).some(row=>sameProcess(row,identity)||sameProcess(row,children.get(row.pid))),'Owned browser and recorded children exit',15000);
        report.cleanup={passed:!disconnectError&&!report.childInventoryError,observedOwnedChildPids:[...children.keys()],preserved:preserve,
          ...(disconnectError?{disconnectError}:{})};
      }catch(error){report.cleanup.error=error.message;preserve=true;report.passed=false;}
    }
    for(const socket of sockets)socket.destroy();if(server.listening)await new Promise(resolve=>server.close(resolve));await hitWrites;
    report.serverHits=serverHits;
    // Reconcile after browser exit too: a late transport contact must never
    // inherit an earlier successful rejection result.
    for(const row of [...report.cases,...report.trustedCDPRewrite.cases]){
      row.serverHits=serverHits.filter(hit=>hit.caseId===row.name);
      if(row.expectation==='blocked'&&row.serverHits.some(hit=>hit.host==='listed'))row.passed=false;
    }
    report.passed&&=[...report.cases,...report.trustedCDPRewrite.cases].every(row=>row.passed);
    await writeFile(path.join(output,'cases.json'),JSON.stringify(report.cases,null,2)+'\n',{mode:0o600});
    await writeFile(path.join(output,'trusted-cdp-cases.json'),JSON.stringify(report.trustedCDPRewrite.cases,null,2)+'\n',{mode:0o600});
    if(app)try{report.signature=await app.verifyUnchanged();}catch(error){report.signatureError=error.message;report.passed=false;preserve=true;}
    if(temporary&&!preserve){await rm(temporary,{recursive:true,force:true});report.disposableRuntimeRemoved=true;}
    else if(temporary){report.preservedRuntime={temporary,profile,reason:report.unexpectedNavigation?'Unexpected navigation; user session retained without closing':'Owned shutdown or signature incomplete'};report.passed=false;}
    await writeFile(path.join(output,'browser-stderr.log'),browserStderr.join(''),{mode:0o600});report.finishedAt=new Date().toISOString();
    await writeFile(path.join(output,'results.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
    console.log(JSON.stringify({passed:report.passed,baselineCases:report.cases.length,trustedCDPRewriteCases:report.trustedCDPRewrite.cases.length,
      failed:[...report.cases,...report.trustedCDPRewrite.cases].filter(value=>!value.passed).map(value=>value.name),evidence:path.join(output,'results.json')}));
    if(!report.passed)process.exitCode=1;
  }
}
if(process.argv.length!==3||!['--self-test','--run'].includes(process.argv[2]))throw new Error('Choose --self-test or --run with explicit app, expected source digest and new output');
if(process.argv[2]==='--self-test')await selfTest();else await run();
