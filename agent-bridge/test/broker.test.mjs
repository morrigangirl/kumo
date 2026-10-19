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
  return runtime;
}

test('local sockets and pairing token are private and unauthenticated clients fail', async t => {
  const runtime = await setup(t);
  assert.equal((await stat(runtime.runtimeDir)).mode & 0o777, 0o700);
  assert.equal((await stat(path.join(runtime.runtimeDir, 'pairing-token'))).mode & 0o777, 0o600);
  assert.equal((await stat(runtime.socketPath)).mode & 0o777, 0o600);
  await assert.rejects(connectBroker({ ...runtime, token: '0'.repeat(64) }), /pairing token/);
  const agent = await connectBroker(runtime);
  t.after(() => agent.close());
  await assert.rejects(requestBrowser(agent, 'tabs.list', {}), /not connected/);
});

test('broker gates actions, filters tab discovery, and revokes in-flight results', async t => {
  const runtime = await setup(t);
  const extension = await connectBroker({ ...runtime, role: 'extension' });
  const agent = await connectBroker(runtime);
  t.after(() => { extension.close(); agent.close(); });
  await assert.rejects(requestBrowser(agent, 'tabs.list', {}), /disabled/);
  extension.send({ type: 'state', enabled: true, allowNewTabs: false, grants: [{ tabId: 4, origin: 'https://example.com' }] });
  const commands = [];
  const remove = extension.onMessage(command => {
    if (command.type !== 'command') return;
    commands.push(command);
    if (command.action === 'tabs.list') extension.send({ type: 'result', id: command.id, result: [
      { tabId: 4, title: 'Allowed', url: 'https://example.com/page' },
      { tabId: 5, title: 'Private', url: 'https://other.example/' },
      { tabId: 4, title: 'Wrong origin', url: 'https://other.example/' },
    ] });
    if (command.action === 'tab.snapshot') {
      extension.send({ type: 'state', enabled: false, allowNewTabs: false, grants: [] });
      extension.send({ type: 'result', id: command.id, result: 'Must never reach the agent' });
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
  const extension = await connectBroker({ ...runtime, role: 'extension' });
  const agent = await connectBroker(runtime);
  t.after(() => { extension.close(); agent.close(); });
  extension.send({ type: 'state', enabled: true, allowNewTabs: true, grants: [{ tabId: 4, origin: 'https://example.com' }] });
  extension.onMessage(command => {
    if (command.type !== 'command') return;
    extension.send({ type: 'state', enabled: true, allowNewTabs: true, grants: [] });
    extension.send({ type: 'result', id: command.id, result: 'Ignored arbitrary extension data' });
  });
  assert.deepEqual(await requestBrowser(agent, 'tab.close', { tabId: 4 }), { closed: 4 });
  await assert.rejects(requestBrowser(agent, 'tab.snapshot', { tabId: 4 }), /not been granted/);
});

test('disconnect resets permission and pending commands expire without retrying', async t => {
  const runtime = await setup(t, 30);
  const extension = await connectBroker({ ...runtime, role: 'extension' });
  const agent = await connectBroker(runtime);
  t.after(() => { extension.close(); agent.close(); });
  extension.send({ type: 'state', enabled: true, allowNewTabs: false, grants: [{ tabId: 4, origin: 'https://example.com' }] });
  await assert.rejects(requestBrowser(agent, 'tab.click', { tabId: 4, selector: 'button' }), /timed out/);
  extension.close();
  await new Promise(resolve => setImmediate(resolve));
  const nextExtension = await connectBroker({ ...runtime, role: 'extension' });
  t.after(() => nextExtension.close());
  await assert.rejects(requestBrowser(agent, 'tabs.list', {}), /disabled/);
});
