import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startBroker, connectBroker, requestBrowser } from '../lib/broker.mjs';
import { privateRuntime } from '../lib/runtime.mjs';

async function setup(t, requestTimeoutMs = 500) {
  const directory = await mkdtemp(path.join(tmpdir(), 'kumo-'));
  const runtime = await privateRuntime(directory);
  const broker = await startBroker({ ...runtime, requestTimeoutMs });
  t.after(async () => { await broker.close(); await rm(directory, { recursive: true, force: true }); });
  return {...runtime, broker};
}

function privateBrowser(broker) {
  const listeners = new Set();
  const channel = broker.attachBrowser(message => { for (const listener of listeners) listener(message); });
  return {send: message => channel.receive(message), onMessage: callback => { listeners.add(callback); return () => listeners.delete(callback); }, close: () => channel.close()};
}

test('local sockets and pairing token are private and unauthenticated clients fail', async t => {
  const runtime = await setup(t);
  assert.equal((await stat(runtime.runtimeDir)).mode & 0o777, 0o700);
  assert.equal((await stat(path.join(runtime.runtimeDir, 'pairing-token'))).mode & 0o777, 0o600);
  assert.equal((await stat(runtime.socketPath)).mode & 0o777, 0o600);
  await assert.rejects(connectBroker({ ...runtime, token: '0'.repeat(64) }), /authentication/);
  const agent = await connectBroker(runtime);
  t.after(() => agent.close());
  await assert.rejects(requestBrowser(agent, 'tabs.list', {}), /not connected/);
});

test('broker gates actions, filters tab discovery, and revokes in-flight results', async t => {
  const runtime = await setup(t);
  const browser = privateBrowser(runtime.broker);
  const agent = await connectBroker(runtime);
  t.after(() => { browser.close(); agent.close(); });
  await assert.rejects(requestBrowser(agent, 'tabs.list', {}), /disabled/);
  browser.send({ type: 'state', enabled: true, allowNewTabs: false, grants: [{ tabId: 4, origin: 'https://example.com' }] });
  const commands = [];
  const remove = browser.onMessage(command => {
    if (command.type !== 'command') return;
    commands.push(command);
    if (command.action === 'tabs.list') browser.send({ type: 'result', id: command.id, result: [
      { tabId: 4, title: 'Allowed', url: 'https://example.com/page' },
      { tabId: 5, title: 'Private', url: 'https://other.example/' },
      { tabId: 4, title: 'Wrong origin', url: 'https://other.example/' },
    ] });
    if (command.action === 'tab.snapshot') {
      browser.send({ type: 'state', enabled: false, allowNewTabs: false, grants: [] });
      browser.send({ type: 'result', id: command.id, result: 'Must never reach the agent' });
    }
  });
  assert.deepEqual(await requestBrowser(agent, 'tabs.list', {}), [{ tabId: 4, title: 'Allowed', url: 'https://example.com/page' }]);
  await assert.rejects(requestBrowser(agent, 'tab.snapshot', { tabId: 5 }), /not been granted/);
  await assert.rejects(requestBrowser(agent, 'tab.navigate', { tabId: 4, url: 'https://other.example/' }), /granted origin/);
  await assert.rejects(requestBrowser(agent, 'tab.open', { url: 'https://example.com' }), /not been allowed/);
  assert.equal(commands.length, 1);
  await assert.rejects(requestBrowser(agent, 'tab.snapshot', { tabId: 4 }), /revoked/);
  remove();
});

test('closing a granted tab permits its grant to disappear before the acknowledgement', async t => {
  const runtime = await setup(t);
  const browser = privateBrowser(runtime.broker);
  const agent = await connectBroker(runtime);
  t.after(() => { browser.close(); agent.close(); });
  browser.send({ type: 'state', enabled: true, allowNewTabs: true, grants: [{ tabId: 4, origin: 'https://example.com' }] });
  browser.onMessage(command => {
    if (command.type !== 'command') return;
    browser.send({ type: 'state', enabled: true, allowNewTabs: true, grants: [] });
    browser.send({ type: 'result', id: command.id, result: 'Ignored arbitrary browser data' });
  });
  assert.deepEqual(await requestBrowser(agent, 'tab.close', { tabId: 4 }), { closeRequested: 4 });
  await assert.rejects(requestBrowser(agent, 'tab.snapshot', { tabId: 4 }), /not been granted/);
});

test('disconnect resets permission and pending commands expire without retrying', async t => {
  const runtime = await setup(t, 30);
  const browser = privateBrowser(runtime.broker);
  const agent = await connectBroker(runtime);
  t.after(() => { browser.close(); agent.close(); });
  browser.send({ type: 'state', enabled: true, allowNewTabs: false, grants: [{ tabId: 4, origin: 'https://example.com' }] });
  await assert.rejects(requestBrowser(agent, 'tab.click', { tabId: 4, selector: 'button' }), /timed out/);
  browser.close();
  await new Promise(resolve => setImmediate(resolve));
  const nextBrowser = privateBrowser(runtime.broker);
  t.after(() => nextBrowser.close());
  await assert.rejects(requestBrowser(agent, 'tabs.list', {}), /disabled/);
});

test('agent token cannot authenticate a browser role or publish browser state', async t => {
  const runtime = await setup(t);
  for (const role of ['extension', 'browser']) await assert.rejects(connectBroker({...runtime, role}), /agents only/);
  const agent = await connectBroker(runtime); t.after(() => agent.close());
  const closed = new Promise(resolve => agent.onClose(resolve));
  agent.send({type: 'state', enabled: true, allowNewTabs: true, grants: []});
  await closed;
});

test('revoking Mission Memory discards an in-flight read without granting tabs', async t => {
  const runtime = await setup(t);
  const browser = privateBrowser(runtime.broker), agent = await connectBroker(runtime);
  t.after(()=>{browser.close();agent.close();});
  const missionId='38c119bd-24a8-4ad6-9680-930f857e09d1';
  browser.send({type:'state',enabled:false,allowNewTabs:false,grants:[],missions:[missionId]});
  browser.onMessage(command=>{
    if(command.type!=='command')return;
    browser.send({type:'state',enabled:false,allowNewTabs:false,grants:[],missions:[]});
    browser.send({type:'result',id:command.id,result:{notes:'Must never reach the client'}});
  });
  await assert.rejects(requestBrowser(agent,'missions.read',{missionId}),/revoked/);
  await assert.rejects(requestBrowser(agent,'missions.list',{}),/not been granted/);
});

test('partial revocation removes unshared missions from delayed search results', async t => {
  const runtime=await setup(t), browser=privateBrowser(runtime.broker), agent=await connectBroker(runtime);
  t.after(()=>{browser.close();agent.close();});
  const a='38c119bd-24a8-4ad6-9680-930f857e09d1', b='48c119bd-24a8-4ad6-9680-930f857e09d1';
  browser.send({type:'state',enabled:false,allowNewTabs:false,grants:[],missions:[a,b]});
  browser.onMessage(command=>{
    if(command.type!=='command')return;
    browser.send({type:'state',enabled:false,allowNewTabs:false,grants:[],missions:[a]});
    browser.send({type:'result',id:command.id,result:{missions:[{id:a,name:'Allowed',notes:'not metadata'},{id:b,name:'Revoked'}]}});
  });
  const result=await requestBrowser(agent,'missions.search',{query:''});
  assert.deepEqual(result.missions,[{id:a,name:'Allowed'}]);
});
