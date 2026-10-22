#!/usr/bin/env node
import path from 'node:path';
import {homedir} from 'node:os';
import {lstat, unlink} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {startBroker} from './lib/broker.mjs';
import {privateRuntime} from './lib/runtime.mjs';
import {NativeDecoder, nativeMessage} from './lib/protocol.mjs';
import {serveMcp} from './lib/mcp.mjs';
import {installPortableRuntime, configureDesktopProviders, desktopProviderStatus} from './desktop.mjs';

export function profileRuntime(profile, home = homedir()) {
  if (typeof profile !== 'string' || !/^[a-f0-9]{32}$/.test(profile)) throw new Error('A native browser profile identifier is required');
  return path.join(home, '.kumo', 'agents', 'profiles', profile);
}

async function browserChannel(runtime) {
  // This mode is launched only as Kumo's fixed child with inherited anonymous
  // pipes. There is no extension origin, network browser role or setup verb.
  if (process.stdin.isTTY || process.stdout.isTTY) throw new Error('A private browser pipe channel is required');
  try {
    const state = await lstat(runtime.socketPath);
    if (!state.isSocket() || state.uid !== process.getuid()) throw new Error('Unsafe browser socket');
    // Do not unlink an active broker. A short connection distinguishes a stale
    // socket; the new server also refuses competing live owners.
    const net = await import('node:net');
    const alive = await new Promise(resolve => {
      const peer = net.createConnection(runtime.socketPath);
      peer.once('connect', () => { peer.destroy(); resolve(true); });
      peer.once('error', () => resolve(false));
      peer.setTimeout(250, () => { peer.destroy(); resolve(true); });
    });
    if (alive) throw new Error('This profile already has an active browser channel');
    await unlink(runtime.socketPath);
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const broker = await startBroker(runtime), decoder = new NativeDecoder();
  const browser = broker.attachBrowser(message => process.stdout.write(nativeMessage(message)));
  let closing = false;
  const close = async () => { if (closing) return; closing = true; browser.close(); process.stdin.destroy(); await broker.close(); };
  process.stdout.write(nativeMessage({type: 'ready'}));
  process.stdin.on('data', chunk => {
    try { for (const message of decoder.push(chunk)) browser.receive(message); }
    catch { close().then(() => { process.exitCode = 1; }); }
  });
  process.stdin.once('end', close); process.stdin.once('error', close);
  process.once('SIGTERM', close); process.once('SIGINT', close);
}

export async function main(args = process.argv.slice(2)) {
  const [mode, flag, profile, ...remaining] = args;
  if (!['browser-channel', 'mcp', 'provider-status', 'provider-configure', 'install-runtime'].includes(mode) || flag !== '--profile') throw new Error('Use a fixed native agent action with --profile PROFILE_ID');
  const runtimeDir = profileRuntime(profile);
  if (mode === 'provider-status' || mode === 'provider-configure') {
    if (remaining.length !== 2 || remaining[0] !== '--provider' || !['codex-desktop', 'claude-desktop'].includes(remaining[1])) throw new Error('Choose one desktop provider');
    const provider = remaining[1];
    if (mode === 'provider-status') return console.log(JSON.stringify({ok: true, ...await desktopProviderStatus(provider, {profile})}));
    await installPortableRuntime();
    const [result] = await configureDesktopProviders(provider, {profile});
    console.log(JSON.stringify({ok: true, provider, configured: result.configured, restartRequired: true, connected: false}));
    return;
  }
  if (remaining.length) throw new Error('Unexpected native agent arguments');
  if (mode === 'install-runtime') { const value = await installPortableRuntime(); console.log(JSON.stringify({ok: true, installed: true, version: value.version})); return; }
  const runtime = await privateRuntime(runtimeDir);
  if (mode === 'browser-channel') return browserChannel(runtime);
  // An MCP client never starts a broker or receives browser authority. Tool
  // discovery works while the browser is closed; actual calls fail closed.
  const server = serveMcp(runtime);
  const stop = () => { server.close(); process.stdin.destroy(); };
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => { console.error(`Kumo bridge: ${error.message}`); process.exitCode = 1; });
