import { Buffer } from 'node:buffer';

export const MAX_MESSAGE_BYTES = 1024 * 1024;

// The browser-owned private pipe uses a 32-bit little-endian length. MCP uses JSON lines.
export function nativeMessage(value) {
  const body = Buffer.from(JSON.stringify(value));
  if (body.length > MAX_MESSAGE_BYTES) throw new Error('Message exceeds 1 MiB');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length);
  return Buffer.concat([header, body]);
}

export class NativeDecoder {
  #buffer = Buffer.alloc(0);
  push(chunk) {
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    const messages = [];
    while (this.#buffer.length >= 4) {
      const length = this.#buffer.readUInt32LE(0);
      if (!length || length > MAX_MESSAGE_BYTES) throw new Error('Invalid native message length');
      if (this.#buffer.length < length + 4) break;
      messages.push(JSON.parse(this.#buffer.subarray(4, length + 4).toString('utf8')));
      this.#buffer = this.#buffer.subarray(length + 4);
    }
    return messages;
  }
}

export class LineDecoder {
  #buffer = '';
  push(chunk) {
    this.#buffer += chunk;
    const messages = [];
    while (true) {
      const index = this.#buffer.indexOf('\n');
      if (index < 0) break;
      const line = this.#buffer.slice(0, index);
      this.#buffer = this.#buffer.slice(index + 1);
      if (Buffer.byteLength(line) > MAX_MESSAGE_BYTES) throw new Error('Message exceeds 1 MiB');
      if (line.trim()) messages.push(JSON.parse(line));
    }
    if (Buffer.byteLength(this.#buffer) > MAX_MESSAGE_BYTES) throw new Error('Message exceeds 1 MiB');
    return messages;
  }
}

export function sendLine(stream, value) {
  const body = JSON.stringify(value);
  if (Buffer.byteLength(body) > MAX_MESSAGE_BYTES) throw new Error('Message exceeds 1 MiB');
  stream.write(body + '\n');
}

export function httpOrigin(url) {
  if (typeof url !== 'string' || url.length > 8192) throw new Error('A valid HTTP(S) URL is required');
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error('Only HTTP(S) URLs without embedded credentials are permitted');
  }
  return parsed.origin;
}

const actionFields = {
  'tabs.list': [],
  'tab.open': ['url'],
  'tab.navigate': ['tabId', 'url'],
  'tab.snapshot': ['tabId'],
  'tab.click': ['tabId', 'selector'],
  'tab.type': ['tabId', 'selector', 'text'],
  'tab.scroll': ['tabId', 'x', 'y'],
  'tab.close': ['tabId'],
};

export function validateCommand(action, params = {}) {
  if (!Object.hasOwn(actionFields, action)) throw new Error('Unknown browser action');
  if (!params || typeof params !== 'object' || Array.isArray(params)) throw new Error('Invalid parameters');
  const fields = actionFields[action];
  if (Object.keys(params).some(key => !fields.includes(key)) || fields.some(key => !Object.hasOwn(params, key))) {
    throw new Error('Unexpected or missing parameters');
  }
  if (fields.includes('tabId') && (!Number.isSafeInteger(params.tabId) || params.tabId < 0)) throw new Error('Invalid tab ID');
  if (fields.includes('url')) httpOrigin(params.url);
  if (fields.includes('selector') && (typeof params.selector !== 'string' || !params.selector || params.selector.length > 512)) {
    throw new Error('Selector must be between 1 and 512 characters');
  }
  if (fields.includes('text') && (typeof params.text !== 'string' || params.text.length > 20000)) throw new Error('Text must not exceed 20000 characters');
  for (const key of ['x', 'y']) {
    if (fields.includes(key) && (!Number.isFinite(params[key]) || Math.abs(params[key]) > 100000)) throw new Error('Invalid scroll offset');
  }
  return params;
}

export function validateState(state) {
  if (!state || typeof state.enabled !== 'boolean' || typeof state.allowNewTabs !== 'boolean' || !Array.isArray(state.grants) || state.grants.length > 1000) {
    throw new Error('Invalid browser permission state');
  }
  const grants = new Map();
  for (const grant of state.grants) {
    if (!Number.isSafeInteger(grant.tabId) || grant.tabId < 0 || httpOrigin(grant.origin) !== grant.origin) throw new Error('Invalid tab grant');
    if (grants.has(grant.tabId)) throw new Error('Duplicate tab grant');
    grants.set(grant.tabId, grant.origin);
  }
  return { enabled: state.enabled, allowNewTabs: state.allowNewTabs, grants };
}

export function authorize(state, action, params) {
  validateCommand(action, params);
  if (!state.enabled) throw new Error('Browser control is disabled. Enable it in Kumo settings.');
  if (action === 'tabs.list') return;
  if (action === 'tab.open') {
    if (!state.allowNewTabs) throw new Error('Opening new tabs has not been allowed in Kumo.');
    return;
  }
  const origin = state.grants.get(params.tabId);
  if (!origin) throw new Error('This tab has not been granted to the agent. Grant it in Kumo.');
  if (action === 'tab.navigate' && httpOrigin(params.url) !== origin) {
    throw new Error('Navigation would leave the granted origin. Open the destination yourself and grant that tab.');
  }
}
