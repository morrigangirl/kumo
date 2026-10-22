import net from 'node:net';
import {chmod, lstat, unlink} from 'node:fs/promises';
import {randomUUID, timingSafeEqual} from 'node:crypto';
import {LineDecoder, authorize, httpOrigin, sendLine, validateState} from './protocol.mjs';

const disabled = () => ({enabled: false, allowNewTabs: false, grants: new Map()});
const tokenMatches = (a, b) => typeof a === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

// The listening socket accepts agents ONLY. Browser authority is an in-process
// capability attached by the browser-owned child to its inherited private pipes.
// Knowing the agent token never permits a socket peer to publish grants/results.
export async function startBroker({socketPath, token, requestTimeoutMs = 20000}) {
  let browser = null, state = disabled();
  const peers = new Set(), pending = new Map();
  const failPending = (message, onlyRevoked = false) => {
    for (const [id, item] of pending) {
      if (onlyRevoked) {
        if (item.action === 'tab.close') continue;
        try { authorize(state, item.action, item.params); continue; } catch {}
      }
      clearTimeout(item.timer);
      sendLine(item.peer, {type: 'result', id: item.clientId, error: {message}});
      pending.delete(id);
    }
  };
  const server = net.createServer(peer => {
    peers.add(peer);
    let authenticated = false;
    const decoder = new LineDecoder();
    const helloTimeout = setTimeout(() => peer.destroy(), 3000);
    peer.setEncoding('utf8');
    peer.on('data', chunk => {
      try {
        for (const message of decoder.push(chunk)) {
          if (!message || typeof message !== 'object' || Array.isArray(message)) throw new Error('Invalid message');
          if (!authenticated) {
            if (message.type !== 'hello' || message.role !== 'agent' || !tokenMatches(message.token, token)) throw new Error('Invalid agent authentication');
            authenticated = true; clearTimeout(helloTimeout); sendLine(peer, {type: 'ready'}); continue;
          }
          if (message.type !== 'request' || typeof message.id !== 'string' || !message.id || message.id.length > 100) throw new Error('Invalid agent request');
          try {
            if (!browser) throw new Error('Kumo is not connected. Open Kumo and enable agent control.');
            authorize(state, message.action, message.params);
            if (pending.size >= 32) throw new Error('Too many pending browser requests');
            const id = randomUUID(), item = {peer, clientId: message.id, action: message.action, params: message.params};
            item.timer = setTimeout(() => {
              pending.delete(id);
              sendLine(peer, {type: 'result', id: message.id, error: {message: 'Browser command timed out. Check the tab before retrying an action.'}});
            }, requestTimeoutMs);
            pending.set(id, item);
            browser.send({type: 'command', id, action: message.action, params: message.params});
          } catch (error) { sendLine(peer, {type: 'result', id: message.id, error: {message: error.message}}); }
        }
      } catch (error) {
        try { sendLine(peer, {type: 'error', error: {message: error.message}}); } catch {}
        peer.end();
      }
    });
    peer.on('error', () => {});
    peer.on('close', () => {
      peers.delete(peer); clearTimeout(helloTimeout);
      for (const [id, item] of pending) if (item.peer === peer) { clearTimeout(item.timer); pending.delete(id); }
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve); });
  await chmod(socketPath, 0o600);
  return {
    socketPath,
    attachBrowser(send) {
      if (browser) throw new Error('A browser channel is already attached');
      if (typeof send !== 'function') throw new Error('A private browser writer is required');
      const channel = {send}; browser = channel; state = disabled();
      return {
        receive(message) {
          if (browser !== channel) throw new Error('Browser channel has closed');
          if (message?.type === 'state') {
            state = validateState(message); failPending('Permission was revoked before the command completed.', true);
            send({type: 'stateApplied', enabled: state.enabled, grantCount: state.grants.size});
          } else if (message?.type === 'result') {
            const item = pending.get(message.id); if (!item) return;
            pending.delete(message.id); clearTimeout(item.timer);
            let response;
            try {
              if (item.action !== 'tab.close') authorize(state, item.action, item.params);
              if (message.error) response = {error: {message: String(message.error.message || 'Browser command failed').slice(0, 2000)}};
              else if (item.action === 'tabs.list') response = {result: (Array.isArray(message.result) ? message.result : []).filter(tab => {
                try { return state.grants.get(tab.tabId) === httpOrigin(tab.url); } catch { return false; }
              }).map(({tabId, url, title}) => ({tabId, url, title}))};
              else if (item.action === 'tab.close') response = {result: {closeRequested: item.params.tabId}};
              else response = {result: message.result ?? null};
            } catch (error) { response = {error: {message: error.message}}; }
            sendLine(item.peer, {type: 'result', id: item.clientId, ...response});
          } else throw new Error('Unexpected private browser message');
        },
        close() {
          if (browser !== channel) return;
          browser = null; state = disabled(); failPending('Browser disconnected; all permissions were revoked.');
        },
      };
    },
    async close() {
      browser = null; state = disabled(); failPending('Browser disconnected; all permissions were revoked.');
      for (const peer of peers) peer.destroy();
      await new Promise(resolve => server.close(resolve));
      try { if ((await lstat(socketPath)).isSocket()) await unlink(socketPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    },
  };
}

export function connectBroker({socketPath, token, role = 'agent'}) {
  if (role !== 'agent') return Promise.reject(new Error('The local socket accepts agents only'));
  return new Promise((resolve, reject) => {
    const peer = net.createConnection(socketPath), decoder = new LineDecoder(), listeners = new Set();
    let ready = false;
    const timer = setTimeout(() => peer.destroy(new Error('Broker authentication timed out')), 3000);
    peer.setEncoding('utf8');
    peer.on('connect', () => sendLine(peer, {type: 'hello', role, token}));
    peer.on('data', chunk => {
      try {
        for (const message of decoder.push(chunk)) {
          if (!ready) {
            if (message.type !== 'ready') throw new Error(message.error?.message || 'Broker authentication failed');
            ready = true; clearTimeout(timer);
            resolve({send: message => sendLine(peer, message), onMessage: callback => { listeners.add(callback); return () => listeners.delete(callback); },
              onClose: callback => { peer.once('close', callback); return () => peer.off('close', callback); }, close: () => peer.destroy()});
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
    const remove = connection.onMessage(message => {
      if (message.type !== 'result' || message.id !== id) return;
      cleanup(); message.error ? reject(new Error(message.error.message)) : resolve(message.result);
    });
    const removeClose = connection.onClose(() => { cleanup(); reject(new Error('Browser bridge disconnected')); });
    connection.send({type: 'request', id, action, params});
  });
}
