import test from 'node:test';
import assert from 'node:assert/strict';
import { NativeDecoder, nativeMessage, LineDecoder, authorize, validateState, validateCommand } from '../lib/protocol.mjs';
import { createMcpHandler, TOOLS } from '../lib/mcp.mjs';

test('Private browser pipes decode split frames, multiple frames and UTF-8', () => {
  const decoder = new NativeDecoder();
  const value = { text: 'Kumo 雲 ☁️' };
  const bytes = nativeMessage(value);
  assert.deepEqual(decoder.push(bytes.subarray(0, 2)), []);
  assert.deepEqual(decoder.push(bytes.subarray(2, 7)), []);
  assert.deepEqual(decoder.push(Buffer.concat([bytes.subarray(7), nativeMessage({ second: true })])), [value, { second: true }]);
  assert.throws(() => new NativeDecoder().push(Buffer.from([255, 255, 255, 255])), /length/);
  assert.throws(() => new NativeDecoder().push(Buffer.from([0, 0, 0, 0])), /length/);
});

test('JSON lines reject malformed and oversized messages', () => {
  const decoder = new LineDecoder();
  assert.deepEqual(decoder.push('{"a":'), []);
  assert.deepEqual(decoder.push('1}\n\n{"b":2}\n'), [{ a: 1 }, { b: 2 }]);
  assert.throws(() => new LineDecoder().push('invalid\n'), SyntaxError);
  assert.throws(() => new LineDecoder().push('x'.repeat(1048577)), /exceeds/);
});

test('authorization requires explicit, origin-bound grants and opt-in opening', () => {
  const state = validateState({ enabled: true, allowNewTabs: false, grants: [{ tabId: 4, origin: 'https://example.com' }] });
  assert.doesNotThrow(() => authorize(state, 'tab.snapshot', { tabId: 4 }));
  assert.doesNotThrow(() => authorize(state, 'tab.navigate', { tabId: 4, url: 'https://example.com/path' }));
  assert.throws(() => authorize(state, 'tab.snapshot', { tabId: 5 }), /not been granted/);
  assert.throws(() => authorize(state, 'tab.open', { url: 'https://example.com' }), /not been allowed/);
  assert.throws(() => authorize(state, 'tab.navigate', { tabId: 4, url: 'https://other.example/' }), /granted origin/);
  assert.throws(() => authorize({ ...state, enabled: false }, 'tabs.list', {}), /disabled/);
  for (const url of ['file:///etc/passwd', 'javascript:alert(1)', 'chrome://settings', 'https://name:secret@example.com']) {
    assert.throws(() => validateCommand('tab.open', { url }));
  }
  assert.throws(() => validateCommand('tab.snapshot', { tabId: 4, script: 'alert()' }), /Unexpected/);
  assert.throws(() => validateCommand('tab.type', { tabId: 4, selector: 'input', text: 'x'.repeat(20001) }));
  assert.throws(() => validateState({ enabled: true, allowNewTabs: true, grants: [{ tabId: 4, origin: 'https://example.com/path' }] }));
});

test('MCP negotiates tools, validates arguments and reports authorization failures', async () => {
  const calls = [];
  const handler = createMcpHandler(async (action, params) => { calls.push({ action, params }); throw new Error('Control disabled'); });
  const initialized = await handler({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } });
  assert.equal(initialized.result.protocolVersion, '2025-06-18');
  const tools = await handler({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.equal(tools.result.tools.length, 8);
  assert.equal(TOOLS.find(tool => tool.name === 'browser_snapshot').annotations.readOnlyHint, true);
  const failed = await handler({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'browser_snapshot', arguments: { tabId: 4 } } });
  assert.equal(failed.result.isError, true);
  assert.match(failed.result.content[0].text, /disabled/);
  const invalid = await handler({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'browser_snapshot', arguments: { tabId: -1 } } });
  assert.equal(invalid.result.isError, true);
  assert.equal(calls.length, 1);
  assert.equal(await handler({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
  assert.equal((await handler({ jsonrpc: '2.0', id: 5, method: 'executeJavaScript' })).error.code, -32601);
});

test('duplicate browser grants and setup verbs cannot enter the agent protocol', () => {
  assert.throws(() => validateState({enabled: true, allowNewTabs: false, grants: [{tabId: 1, origin: 'https://example.com'}, {tabId: 1, origin: 'https://evil.example'}]}), /Duplicate/);
  for (const action of ['provider-configure', 'agents.connectCodex', 'executeJavaScript', 'state']) assert.throws(() => validateCommand(action, {}), /Unknown/);
  assert.ok(TOOLS.every(tool => !/setup|configure|provider/.test(tool.name)));
});
