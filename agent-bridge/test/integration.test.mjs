import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startBroker } from '../lib/broker.mjs';
import { privateRuntime, CLI_PATH } from '../lib/runtime.mjs';
import { LineDecoder, NativeDecoder, nativeMessage } from '../lib/protocol.mjs';

const exec = promisify(execFile);

function inbox(stream, decoder) {
  const queue = [];
  const waiting = [];
  stream.on('data', chunk => {
    for (const value of decoder.push(chunk)) {
      if (waiting.length) waiting.shift()(value);
      else queue.push(value);
    }
  });
  return () => queue.length ? Promise.resolve(queue.shift()) : new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Child protocol reply timed out')), 3000);
    waiting.push(value => { clearTimeout(timer); resolve(value); });
  });
}

test('installer, actual Native Messaging host and stdio MCP work together without modifying account configs', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'kumo-'));
  const runtime = await privateRuntime(directory);
  const profile = path.join(directory, 'test profile');
  const env = { ...process.env, KUMO_AGENT_DIR: directory };
  const { stdout } = await exec(process.execPath, [CLI_PATH, 'install', '--extension-id', 'a'.repeat(32), '--browser-profile', profile], { env });
  const installed = JSON.parse(stdout);
  const manifest = JSON.parse(await readFile(installed.manifestPath, 'utf8'));
  assert.equal(manifest.name, 'com.kumo.agent_bridge');
  assert.deepEqual(manifest.allowed_origins, [`chrome-extension://${'a'.repeat(32)}/`]);
  assert.match(await readFile(installed.codexConfig, 'utf8'), /mcp_servers.kumo/);
  assert.equal(JSON.parse(await readFile(installed.claudeConfig, 'utf8')).mcpServers.kumo.type, 'stdio');

  const broker = await startBroker(runtime);
  const children = [];
  t.after(async () => {
    for (const child of children) child.kill('SIGTERM');
    await broker.close();
    await rm(directory, { recursive: true, force: true });
  });
  const host = spawn(manifest.path, [manifest.allowed_origins[0]], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  children.push(host);
  const nextNative = inbox(host.stdout, new NativeDecoder());
  assert.equal((await nextNative()).type, 'ready');
  host.stdin.write(nativeMessage({ type: 'state', enabled: true, allowNewTabs: false, grants: [{ tabId: 12, origin: 'https://example.com' }] }));
  assert.equal((await nextNative()).type, 'stateApplied');
  const mcp = spawn(process.execPath, [CLI_PATH, 'mcp'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  children.push(mcp);
  mcp.stdout.setEncoding('utf8');
  const nextMcp = inbox(mcp.stdout, new LineDecoder());
  const sendMcp = message => mcp.stdin.write(JSON.stringify(message) + '\n');
  sendMcp({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'integration-test', version: '1' } } });
  assert.equal((await nextMcp()).result.serverInfo.name, 'kumo-browser');
  sendMcp({ jsonrpc: '2.0', method: 'notifications/initialized' });
  sendMcp({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.equal((await nextMcp()).result.tools.length, 8);
  sendMcp({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'browser_snapshot', arguments: { tabId: 12 } } });
  const command = await nextNative();
  assert.equal(command.action, 'tab.snapshot');
  assert.deepEqual(command.params, { tabId: 12 });
  host.stdin.write(nativeMessage({ type: 'result', id: command.id, result: { title: 'Example', text: 'Visible content' } }));
  const reply = await nextMcp();
  assert.equal(reply.id, 3);
  assert.deepEqual(JSON.parse(reply.result.content[0].text), { title: 'Example', text: 'Visible content' });
  sendMcp({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'browser_snapshot', arguments: { tabId: 99 } } });
  assert.equal((await nextMcp()).result.isError, true);
});

test('native host rejects a caller outside the installed extension allowlist', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'kumo-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const env = { ...process.env, KUMO_AGENT_DIR: directory };
  await exec(process.execPath, [CLI_PATH, 'install', '--extension-id', 'a'.repeat(32), '--browser-profile', path.join(directory, 'profile')], { env });
  await assert.rejects(exec(process.execPath, [CLI_PATH, 'native', `chrome-extension://${'b'.repeat(32)}/`], { env }), error => {
    assert.match(error.stderr, /unregistered extension origin/);
    assert.equal(error.stdout, '');
    return true;
  });
});
