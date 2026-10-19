#!/usr/bin/env node
import path from 'node:path';
import { homedir } from 'node:os';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { startBroker, connectBroker } from './lib/broker.mjs';
import { privateRuntime, ensureBroker, CLI_PATH } from './lib/runtime.mjs';
import { NativeDecoder, nativeMessage } from './lib/protocol.mjs';
import { serveMcp } from './lib/mcp.mjs';

export const HOST_NAME = 'com.kumo.agent_bridge';
const shellQuote = value => "'" + value.replaceAll("'", "'\\''") + "'";

async function install(args, runtime) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    if (!['--extension-id', '--browser-profile', '--manifest-path'].includes(key) || !args[index + 1]) throw new Error('Invalid install option');
    options[key] = args[index + 1];
  }
  const extensionId = options['--extension-id'];
  if (!/^[a-p]{32}$/.test(extensionId || '')) throw new Error('Pass --extension-id with the 32-letter ID shown in chrome://extensions');
  if (options['--browser-profile'] && options['--manifest-path']) throw new Error('Choose --browser-profile or --manifest-path');
  const profile = options['--browser-profile'] || path.join(homedir(), 'Library', 'Application Support', 'Kumo');
  const manifestPath = options['--manifest-path'] || path.join(profile, 'NativeMessagingHosts', HOST_NAME + '.json');
  if (!path.isAbsolute(manifestPath) || !path.isAbsolute(profile)) throw new Error('Installation paths must be absolute');
  const origin = `chrome-extension://${extensionId}/`;
  const originsPath = path.join(runtime.runtimeDir, 'allowed-origins.json');
  let origins = [];
  try { origins = JSON.parse(await readFile(originsPath, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!Array.isArray(origins) || origins.some(value => !/^chrome-extension:\/\/[a-p]{32}\/$/.test(value))) throw new Error('Invalid installed extension origins');
  origins = [...new Set([...origins, origin])];
  await writeFile(originsPath, JSON.stringify(origins, null, 2) + '\n', { mode: 0o600 });
  const launcherPath = path.join(runtime.runtimeDir, 'native-host.sh');
  await writeFile(launcherPath, `#!/bin/sh\nexport KUMO_AGENT_DIR=${shellQuote(runtime.runtimeDir)}\nexec ${shellQuote(process.execPath)} ${shellQuote(CLI_PATH)} native "$@"\n`, { mode: 0o700 });
  await mkdir(path.dirname(manifestPath), { recursive: true, mode: 0o700 });
  await writeFile(manifestPath, JSON.stringify({ name: HOST_NAME, description: 'Kumo opt-in agent bridge', path: launcherPath, type: 'stdio', allowed_origins: [origin] }, null, 2) + '\n', { mode: 0o600 });
  const codexConfig = path.join(runtime.runtimeDir, 'codex-config.toml');
  const claudeConfig = path.join(runtime.runtimeDir, 'claude-mcp.json');
  const command = process.execPath;
  const env = { KUMO_AGENT_DIR: runtime.runtimeDir };
  await writeFile(codexConfig, `[mcp_servers.kumo]\ncommand = ${JSON.stringify(command)}\nargs = [${JSON.stringify(CLI_PATH)}, "mcp"]\n\n[mcp_servers.kumo.env]\nKUMO_AGENT_DIR = ${JSON.stringify(runtime.runtimeDir)}\n`, { mode: 0o600 });
  await writeFile(claudeConfig, JSON.stringify({ mcpServers: { kumo: { type: 'stdio', command, args: [CLI_PATH, 'mcp'], env } } }, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify({ installed: true, manifestPath, codexConfig, claudeConfig, note: 'Kumo configuration files generated. Existing Codex and Claude settings were not changed.' }, null, 2));
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
    console.log('Kumo agent bridge (Node 22+)\n\n  node agent-bridge/cli.mjs install --extension-id ID [--browser-profile /absolute/path | --manifest-path /absolute/file.json]\n  node agent-bridge/cli.mjs mcp\n\nThe install command generates local Codex and Claude configuration snippets. It never logs in or starts an agent task.');
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
