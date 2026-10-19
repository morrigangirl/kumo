#!/usr/bin/env node
import path from 'node:path';
import { homedir } from 'node:os';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { startBroker, connectBroker } from './lib/broker.mjs';
import { privateRuntime, ensureBroker, CLI_PATH } from './lib/runtime.mjs';
import { NativeDecoder, nativeMessage } from './lib/protocol.mjs';
import { serveMcp } from './lib/mcp.mjs';
import {installPortableRuntime, configureDesktopProviders, atomicPrivateWrite, readPrivateFile, temporaryInstallAnchor, DESKTOP_MCP} from './desktop.mjs';

export const HOST_NAME = 'com.kumo.agent_bridge';
const shellQuote = value => "'" + value.replaceAll("'", "'\\''") + "'";

async function install(args, runtime) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    if (!['--extension-id', '--browser-profile', '--manifest-path', '--provider'].includes(key) || !args[index + 1] || Object.hasOwn(options, key)) throw new Error('Invalid install option');
    options[key] = args[index + 1];
  }
  const provider = options['--provider'];
  if (provider && !['codex-desktop', 'claude-desktop', 'all'].includes(provider)) throw new Error('Choose codex-desktop, claude-desktop, or all.');
  const extensionId = options['--extension-id'] || (provider ? 'eldkgppmnhligdekahicdcdndcoongio' : null);
  if (!/^[a-p]{32}$/.test(extensionId || '')) throw new Error('Pass --extension-id with the 32-letter ID shown in chrome://extensions');
  if (options['--browser-profile'] && options['--manifest-path']) throw new Error('Choose --browser-profile or --manifest-path');
  const profile = options['--browser-profile'] || path.join(homedir(), 'Library', 'Application Support', 'Kumo');
  const manifestPath = options['--manifest-path'] || path.join(profile, 'NativeMessagingHosts', HOST_NAME + '.json');
  if (!path.isAbsolute(manifestPath) || !path.isAbsolute(profile)) throw new Error('Installation paths must be absolute');
  const home = homedir(), canonicalRuntime = path.join(home, '.kumo', 'agents');
  if (provider && runtime.runtimeDir !== canonicalRuntime) throw new Error('Desktop setup requires the standard ~/.kumo/agents directory. Unset KUMO_AGENT_DIR and retry.');
  await installPortableRuntime({home, runtimeDir: runtime.runtimeDir});
  const anchorFor = file => file.startsWith(home + path.sep) ? home : file.startsWith(runtime.runtimeDir + path.sep) ? runtime.runtimeDir : null;
  const write = async (file, data, options = {}) => {
    const anchor = anchorFor(file) || await temporaryInstallAnchor(file);
    return atomicPrivateWrite(file, data, {anchor, ...options});
  };
  const origin = `chrome-extension://${extensionId}/`;
  const originsPath = path.join(runtime.runtimeDir, 'allowed-origins.json');
  let origins = [];
  const originData = await readPrivateFile(originsPath, {maximum: 8192});
  if (originData) origins = JSON.parse(originData.toString('utf8'));
  if (!Array.isArray(origins) || origins.some(value => !/^chrome-extension:\/\/[a-p]{32}\/$/.test(value))) throw new Error('Invalid installed extension origins');
  origins = [...new Set([...origins, origin])];
  await write(originsPath, JSON.stringify(origins, null, 2) + '\n');
  const launcherPath = path.join(runtime.runtimeDir, 'native-host.sh');
  await write(launcherPath, '#!/bin/sh\nset -eu\nKUMO_AGENT_DIR=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)\nexport KUMO_AGENT_DIR\nexec "$KUMO_AGENT_DIR/server/run" native "$@"\n', {mode: 0o700});
  await write(manifestPath, JSON.stringify({ name: HOST_NAME, description: 'Kumo opt-in agent bridge', path: launcherPath, type: 'stdio', allowed_origins: [origin] }, null, 2) + '\n', {backup: true});
  const codexConfig = path.join(runtime.runtimeDir, 'codex-config.toml');
  const claudeConfig = path.join(runtime.runtimeDir, 'claude-mcp.json');
  const snippet = runtime.runtimeDir === canonicalRuntime ? DESKTOP_MCP : {command: '/bin/sh', args: ['-c', `exec ${shellQuote(path.join(runtime.runtimeDir, 'server/run'))} mcp`]};
  await write(codexConfig, `[mcp_servers.kumo]\ncommand = ${JSON.stringify(snippet.command)}\nargs = ${JSON.stringify(snippet.args)}\n`);
  await write(claudeConfig, JSON.stringify({mcpServers: {kumo: {type: 'stdio', command: snippet.command, args: [...snippet.args]}}}, null, 2) + '\n');
  const providers = provider ? await configureDesktopProviders(provider, {home}) : [];
  console.log(JSON.stringify({installed: true, manifestPath, codexConfig, claudeConfig, serverPath: path.join(runtime.runtimeDir, 'server'), providers,
    note: provider ? 'Restart the configured desktop clients when convenient to load Kumo. No client was restarted.' : 'Portable bridge and configuration snippets installed. Desktop client settings were not changed.'}, null, 2));
}

async function native(runtime, args) {
  const origin = args.find(value => /^chrome-extension:\/\//.test(value));
  const origins = JSON.parse(await readFile(path.join(runtime.runtimeDir, 'allowed-origins.json'), 'utf8'));
  if (!origin || !Array.isArray(origins) || !origins.includes(origin)) throw new Error('Native host rejected an unregistered extension origin');
  await ensureBroker(runtime);
  const connection = await connectBroker({ ...runtime, role: 'extension' });
  const decoder = new NativeDecoder();
  connection.onMessage(message => process.stdout.write(nativeMessage(message)));
  connection.onClose(() => { process.stdin.destroy(); });
  process.stdout.write(nativeMessage({ type: 'ready' }));
  process.stdin.on('data', chunk => {
    try {
      for (const message of decoder.push(chunk)) {
        if (!['state', 'result'].includes(message?.type)) throw new Error('Unexpected native extension message');
        connection.send(message);
      }
    } catch (error) { console.error(error.message); connection.close(); process.stdin.destroy(); }
  });
  process.stdin.on('end', () => connection.close());
  process.stdin.on('error', () => connection.close());
  const close = () => { connection.close(); process.stdin.destroy(); };
  process.on('SIGTERM', close);
  process.on('SIGINT', close);
}

async function main() {
  const [mode, ...args] = process.argv.slice(2);
  if (!['install', 'broker', 'native', 'mcp'].includes(mode)) {
    console.log('Kumo agent bridge (Node 22+)\n\n  agent-bridge/run install --provider codex-desktop|claude-desktop|all\n  agent-bridge/run install --extension-id ID [--browser-profile /absolute/path | --manifest-path /absolute/file.json]\n  agent-bridge/run mcp\n\nProvider setup configures the desktop clients and preserves existing settings. It never logs in, starts a task, or restarts a client.');
    return;
  }
  const runtime = await privateRuntime();
  if (mode === 'install') return install(args, runtime);
  if (mode === 'native') return native(runtime, args);
  if (args.length) throw new Error('Unexpected command arguments');
  if (mode === 'broker') {
    const broker = await startBroker(runtime);
    const stop = () => broker.close().then(() => process.exit(0));
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
    return;
  }
  await ensureBroker(runtime);
  const server = serveMcp(runtime);
  const stop = () => { server.close(); process.stdin.destroy(); };
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(`Kumo bridge: ${error.message}`); process.exitCode = 1; });
}
