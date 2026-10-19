import net from 'node:net';
import { chmod, lstat, unlink } from 'node:fs/promises';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { LineDecoder, authorize, httpOrigin, sendLine, validateState } from './protocol.mjs';

const disabled = () => ({ enabled: false, allowNewTabs: false, grants: new Map() });
const tokenMatches = (a, b) => typeof a === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

export async function startBroker({ socketPath, token, requestTimeoutMs = 20000 }) {
  let extension = null;
  let state = disabled();
  const peers = new Set();
  const pending = new Map();

  const failPending = (message, onlyRevoked = false) => {
    for (const [id, item] of pending) {
      if (onlyRevoked) {
        // A successful close naturally removes its own grant; its reply contains no page data.
        if (item.action === 'tab.close') continue;
        try { authorize(state, item.action, item.params); continue; } catch {}
      }
      clearTimeout(item.timer);
      sendLine(item.peer, { type: 'result', id: item.clientId, error: { message } });
      pending.delete(id);
    }
  };

  const server = net.createServer(peer => {
    peers.add(peer);
    let role = null;
    const decoder = new LineDecoder();
    const helloTimeout = setTimeout(() => peer.destroy(), 3000);
    const fail = message => {
      try { sendLine(peer, { type: 'error', error: { message } }); } catch {}
      peer.end();
    };
    peer.setEncoding('utf8');
    peer.on('data', chunk => {
      try {
        for (const message of decoder.push(chunk)) {
          if (!message || typeof message !== 'object' || Array.isArray(message)) throw new Error('Invalid message');
          if (!role) {
            if (message.type !== 'hello' || !['agent', 'extension'].includes(message.role) || !tokenMatches(message.token, token)) {
              throw new Error('Invalid local pairing token');
            }
            if (message.role === 'extension' && extension) throw new Error('Another browser profile is already connected');
            role = message.role;
            clearTimeout(helloTimeout);
            if (role === 'extension') { extension = peer; state = disabled(); }
            sendLine(peer, { type: 'ready' });
            continue;
          }
          if (role === 'extension') {
            if (message.type === 'state') {
              state = validateState(message);
              failPending('Permission was revoked before the command completed.', true);
              sendLine(peer, { type: 'stateApplied', enabled: state.enabled, grantCount: state.grants.size });
            } else if (message.type === 'result') {
              const item = pending.get(message.id);
              if (!item) continue;
              pending.delete(message.id);
              clearTimeout(item.timer);
              let response = message;
              try {
                if (item.action !== 'tab.close') authorize(state, item.action, item.params);
                if (message.error) {
                  response = { error: { message: String(message.error.message || 'Browser command failed').slice(0, 2000) } };
                } else if (item.action === 'tabs.list') {
                  // Validate each row as well: extension tab data must still match the grant.
                  const rows = Array.isArray(message.result) ? message.result : [];
                  response = { result: rows.filter(tab => {
                    try { return state.grants.get(tab.tabId) === httpOrigin(tab.url); } catch { return false; }
                  }).map(({ tabId, url, title }) => ({ tabId, url, title })) };
                } else if (item.action === 'tab.close') {
                  response = { result: { closed: item.params.tabId } };
                } else {
                  response = { result: message.result ?? null };
                }
              } catch (error) { response = { error: { message: error.message } }; }
              sendLine(item.peer, { type: 'result', id: item.clientId, ...response });
            } else throw new Error('Unexpected extension message');
            continue;
          }
          if (message.type !== 'request' || typeof message.id !== 'string' || message.id.length > 100) throw new Error('Invalid agent request');
          try {
            if (!extension) throw new Error('Kumo is not connected. Open Kumo and enable agent control.');
            authorize(state, message.action, message.params);
            if (pending.size >= 32) throw new Error('Too many pending browser requests');
            const id = randomUUID();
            const item = { peer, clientId: message.id, action: message.action, params: message.params };
            item.timer = setTimeout(() => {
              pending.delete(id);
              sendLine(peer, { type: 'result', id: message.id, error: { message: 'Browser command timed out. Check the tab before retrying an action.' } });
            }, requestTimeoutMs);
            pending.set(id, item);
            sendLine(extension, { type: 'command', id, action: message.action, params: message.params });
          } catch (error) {
            sendLine(peer, { type: 'result', id: message.id, error: { message: error.message } });
          }
        }
      } catch (error) { fail(error.message); }
    });
    peer.on('error', () => {});
    peer.on('close', () => {
      peers.delete(peer);
      clearTimeout(helloTimeout);
      if (extension === peer) {
        extension = null;
        state = disabled();
        failPending('Browser disconnected; all permissions were revoked.');
      }
      for (const [id, item] of pending) {
        if (item.peer === peer) { clearTimeout(item.timer); pending.delete(id); }
      }
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, resolve);
  });
  await chmod(socketPath, 0o600);
  return {
    socketPath,
    async close() {
      for (const item of pending.values()) clearTimeout(item.timer);
      pending.clear();
      for (const peer of peers) peer.destroy();
      await new Promise(resolve => server.close(resolve));
      // The Unix socket is normally removed by net.Server, but never delete a replacement.
      try { if ((await lstat(socketPath)).isSocket()) await unlink(socketPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    },
  };
}

export function connectBroker({ socketPath, token, role = 'agent' }) {
  return new Promise((resolve, reject) => {
    const peer = net.createConnection(socketPath);
    const decoder = new LineDecoder();
    const listeners = new Set();
    let ready = false;
    const timer = setTimeout(() => peer.destroy(new Error('Broker authentication timed out')), 3000);
    peer.setEncoding('utf8');
    peer.on('connect', () => sendLine(peer, { type: 'hello', role, token }));
    peer.on('data', chunk => {
      try {
        for (const message of decoder.push(chunk)) {
          if (!ready) {
            if (message.type !== 'ready') throw new Error(message.error?.message || 'Broker authentication failed');
            ready = true;
            clearTimeout(timer);
            resolve({
              send: message => sendLine(peer, message),
              onMessage: callback => { listeners.add(callback); return () => listeners.delete(callback); },
              onClose: callback => { peer.once('close', callback); return () => peer.off('close', callback); },
              close: () => peer.destroy(),
            });
          } else for (const listener of listeners) listener(message);
        }
      } catch (error) { peer.destroy(error); }
    });
    peer.on('error', error => { clearTimeout(timer); if (!ready) reject(error); });
    peer.on('close', () => { clearTimeout(timer); if (!ready) reject(new Error('Broker closed before authentication')); });
  });
}

export async function requestBrowser(connection, action, params) {
  const id = randomUUID();
  return new Promise((resolve, reject) => {
    const cleanup = () => { clearTimeout(timer); remove(); removeClose(); };
    const timer = setTimeout(() => { cleanup(); reject(new Error('Local browser bridge timed out')); }, 25000);
    const removeClose = connection.onClose(() => { cleanup(); reject(new Error('Local browser bridge disconnected')); });
    const remove = connection.onMessage(message => {
      if (message.type !== 'result' || message.id !== id) return;
      cleanup();
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result);
    });
    connection.send({ type: 'request', id, action, params });
  });
}
