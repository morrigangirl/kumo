import path from 'node:path';
import {homedir, tmpdir} from 'node:os';
import {constants} from 'node:fs';
import {access, chmod, lstat, mkdir, open, readFile, readdir, realpath, rename, rm, symlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {randomUUID, createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

export const DESKTOP_MCP_COMMAND = 'exec "$HOME/.kumo/agents/server/run" mcp';
export const DESKTOP_MCP = Object.freeze({command: '/bin/sh', args: ['-c', DESKTOP_MCP_COMMAND]});
export function desktopMcp(profile) {
  if (!/^[a-f0-9]{32}$/.test(profile || '')) throw new Error('A native browser profile identifier is required');
  return {command: '/bin/sh', args: ['-c', DESKTOP_MCP_COMMAND + ' --profile ' + profile]};
}
export const PORTABLE_FILES = Object.freeze(['cli.mjs', 'desktop.mjs', 'run', 'package.json',
  'lib/broker.mjs', 'lib/runtime.mjs', 'lib/protocol.mjs', 'lib/mcp.mjs',
  'bin/node', 'LICENSE.node', 'runtime.json']);
const SOURCE = path.dirname(fileURLToPath(import.meta.url));
const MAX_CONFIG = 2 * 1024 * 1024;
const uid = process.getuid?.();
const contained = (directory, base) => directory === base || directory.startsWith(base + path.sep);
const sha = data => createHash('sha256').update(data).digest('hex');

export async function temporaryInstallAnchor(file) {
  for (const candidate of [tmpdir(), '/private/tmp', '/tmp']) {
    const temporary = path.resolve(candidate);
    if (!contained(path.resolve(file), temporary)) continue;
    const canonicalTemporary = await realpath(temporary);
    let parent = path.dirname(file);
    while (parent !== temporary && contained(parent, temporary)) {
      try {
        const state = await lstat(parent);
        if (!state.isDirectory() || state.isSymbolicLink() || uid !== undefined && state.uid !== uid || state.mode & 0o022 ||
            await realpath(parent) !== path.join(canonicalTemporary, path.relative(temporary, parent))) throw new Error('Unsafe temporary installation directory.');
        return parent;
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
      parent = path.dirname(parent);
    }
  }
  throw new Error('Explicit profile must be inside your home or an owned private temporary directory.');
}

// Walk only the explicitly supplied user-owned boundary. System ancestors such
// as macOS's /var symlink are outside it; symlinks inside it are never followed.
export async function privateDirectory(directory, {anchor = homedir(), privateMode = true} = {}) {
  directory = path.resolve(directory); anchor = path.resolve(anchor);
  if (!contained(directory, anchor)) throw new Error('Installation path is outside its private directory.');
  const root = await lstat(anchor);
  if (!root.isDirectory() || root.isSymbolicLink() || uid !== undefined && root.uid !== uid || root.mode & 0o022) throw new Error('Unsafe installation directory.');
  let current = anchor;
  for (const component of path.relative(anchor, directory).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    try { await mkdir(current, {mode: 0o700}); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const state = await lstat(current);
    if (!state.isDirectory() || state.isSymbolicLink() || uid !== undefined && state.uid !== uid || state.mode & 0o022) throw new Error('Unsafe installation directory.');
  }
  if (privateMode && directory !== anchor) await chmod(directory, 0o700);
  return directory;
}

export async function readPrivateFile(file, {maximum = MAX_CONFIG, missing = true, allowRoot = false} = {}) {
  let descriptor;
  try { descriptor = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW); }
  catch (error) { if (missing && error.code === 'ENOENT') return null; throw new Error('Configuration must be a user-owned regular file without symlinks.'); }
  try {
    const state = await descriptor.stat();
    if (!state.isFile() || state.nlink !== 1 || uid !== undefined && state.uid !== uid && !(allowRoot && state.uid === 0) || state.size > maximum) throw new Error('Unsafe or oversized configuration file.');
    const data = await descriptor.readFile();
    if (data.length > maximum) throw new Error('Configuration file is oversized.');
    return data;
  } finally { await descriptor.close(); }
}

export async function atomicPrivateWrite(file, data, {anchor = homedir(), mode = 0o600, backup = false, expected} = {}) {
  await privateDirectory(path.dirname(file), {anchor});
  const original = await readPrivateFile(file);
  if (expected !== undefined && (original === null ? null : sha(original)) !== expected) throw new Error('Configuration changed during setup; retry.');
  const temporary = path.join(path.dirname(file), `.kumo-write-${randomUUID()}`);
  const descriptor = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  let backupPath = null;
  try {
    await descriptor.writeFile(data); await descriptor.sync(); await descriptor.chmod(mode); await descriptor.close();
    if (backup && original !== null) {
      backupPath = file + `.kumo-backup-${Date.now()}-${randomUUID()}`;
      const copy = await open(backupPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { await copy.writeFile(original); await copy.sync(); } finally { await copy.close(); }
    }
    const current = await readPrivateFile(file);
    if ((current === null ? null : sha(current)) !== (original === null ? null : sha(original))) throw new Error('Configuration changed during setup; retry.');
    await rename(temporary, file);
    return backupPath;
  } finally { await descriptor.close().catch(() => {}); await rm(temporary, {force: true}); }
}

const payloadLimit = name => name === 'bin/node' ? 256 * 1024 * 1024 : 2 * 1024 * 1024;
async function payload(directory, {allowRoot = false, legacy = false} = {}) {
  const names = legacy ? PORTABLE_FILES.filter(name => !['bin/node', 'LICENSE.node', 'runtime.json'].includes(name)) : PORTABLE_FILES;
  const allowed = new Set(names), values = new Map();
  for (const parent of ['', 'lib', ...(legacy ? [] : ['bin'])]) {
    const folder = path.join(directory, parent), state = await lstat(folder);
    if (!state.isDirectory() || state.isSymbolicLink() || uid !== undefined && state.uid !== uid && !(allowRoot && state.uid === 0) || state.mode & 0o022) throw new Error('Unsafe bridge payload directory.');
    for (const entry of await readdir(folder, {withFileTypes: true})) {
      const relative = parent ? `${parent}/${entry.name}` : entry.name;
      if (['lib', 'bin'].includes(relative) && entry.isDirectory() && !entry.isSymbolicLink()) continue;
      if (!allowed.has(relative) || !entry.isFile() || entry.isSymbolicLink()) throw new Error('Unexpected bridge payload file.');
    }
  }
  for (const name of names) values.set(name, await readPrivateFile(path.join(directory, name), {maximum: payloadLimit(name), missing: false, allowRoot}));
  return values;
}

export async function installPortableRuntime({home = homedir(), runtimeDir = path.join(home, '.kumo', 'agents'), sourceDir = SOURCE} = {}) {
  await privateDirectory(runtimeDir, {anchor: home});
  const values = await payload(sourceDir, {allowRoot: true});
  const hash = createHash('sha256');
  for (const [name, data] of values) { hash.update(name); hash.update('\0'); hash.update(data); }
  const version = hash.digest('hex'), versions = path.join(runtimeDir, 'versions');
  await privateDirectory(versions, {anchor: home});
  const target = path.join(versions, version), staging = path.join(versions, `.install-${randomUUID()}`);
  try {
    try {
      const existing = await payload(target);
      for (const [name, data] of values) if (!existing.get(name).equals(data)) throw new Error('Managed runtime version changed.');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await mkdir(staging, {mode: 0o700});
      for (const name of ['lib', 'bin']) await mkdir(path.join(staging, name), {mode: 0o700});
      for (const [name, data] of values) await atomicPrivateWrite(path.join(staging, name), data, {anchor: runtimeDir, mode: ['run', 'bin/node'].includes(name) ? 0o700 : 0o600});
      await rename(staging, target);
    }
    const server = path.join(runtimeDir, 'server'), link = path.join(runtimeDir, `.active-${randomUUID()}`);
    let previous = null;
    try {
      const state = await lstat(server);
      if (state.isSymbolicLink()) {
        const resolved = await realpath(server);
        if (path.dirname(resolved) !== versions || !/^[a-f0-9]{64}$/.test(path.basename(resolved))) throw new Error('Unsafe active bridge runtime.');
        await payload(resolved);
      } else {
        await payload(server, {legacy: true});
        previous = path.join(runtimeDir, `.legacy-${randomUUID()}`); await rename(server, previous);
      }
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    try { await symlink(path.join('versions', version), link); await rename(link, server); }
    catch (error) { if (previous) await rename(previous, server); throw error; }
    finally { await rm(link, {force: true}); }
    if (previous) await rm(previous, {recursive: true});
    return {runtimeDir, server, run: path.join(server, 'run'), version};
  } finally { await rm(staging, {recursive: true, force: true}); }
}

export async function discoverCodex({environment = process.env, home = homedir(), applicationDirectories = ['/Applications', path.join(home, 'Applications')]} = {}) {
  const candidates = (environment.PATH || '').split(path.delimiter).filter(value => path.isAbsolute(value)).map(value => path.join(value, 'codex'));
  for (const directory of applicationDirectories) for (const app of ['Codex.app', 'ChatGPT.app']) {
    candidates.push(path.join(directory, app, 'Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex'));
    candidates.push(path.join(directory, app, 'Contents/Resources/codex'));
  }
  for (const candidate of candidates) {
    try {
      await access(candidate, constants.X_OK);
      const resolved = await realpath(candidate), state = await lstat(resolved);
      if (state.isFile() && (uid === undefined || state.uid === uid || state.uid === 0) && !(state.mode & 0o022)) return resolved;
    } catch {}
  }
  throw new Error('Codex Desktop or the Codex CLI is not installed. Install it, then run Kumo setup again.');
}

async function runCodex(command, args, {home, environment}) {
  return new Promise((resolve, reject) => {
    // The official CLI edits its own TOML. Never expose arbitrary existing
    // configuration or provider credentials in setup output.
    const child = spawn(command, args, {cwd: home, env: environment, stdio: ['ignore', 'pipe', 'pipe']});
    let stdout = '', bytes = 0, failed = false;
    const timer = setTimeout(() => { failed = true; child.kill('SIGKILL'); }, 15000); timer.unref?.();
    const collect = chunk => { bytes += chunk.length; if (bytes > 131072) { failed = true; child.kill('SIGKILL'); } };
    child.stdout.on('data', chunk => { collect(chunk); if (bytes <= 131072) stdout += chunk.toString('utf8'); });
    child.stderr.on('data', collect);
    child.once('error', () => { clearTimeout(timer); reject(new Error('Could not start the official Codex configuration command.')); });
    child.once('close', code => { clearTimeout(timer); code === 0 && !failed ? resolve(stdout) : reject(new Error('The official Codex configuration command failed. Existing settings were backed up.')); });
  });
}

export async function configureCodexDesktop({home = homedir(), environment = process.env, applicationDirectories, profile} = {}) {
  const mcp = desktopMcp(profile);
  const configuredHome = environment.CODEX_HOME;
  if (configuredHome && (!path.isAbsolute(configuredHome) || configuredHome.includes('\0'))) throw new Error('CODEX_HOME must be an absolute, safe user-owned directory.');
  const directory = configuredHome ? path.resolve(configuredHome) : path.join(home, '.codex');
  if (contained(directory, home)) await privateDirectory(directory, {anchor: home});
  else {
    // An explicitly configured home outside the normal home must already be a
    // real user-owned directory. Never invent or follow its parent paths.
    let canonical;
    try { canonical = await realpath(directory); } catch { throw new Error('Custom CODEX_HOME must already be a safe user-owned directory.'); }
    if (canonical !== directory) throw new Error('Custom CODEX_HOME cannot contain symlinks.');
    await privateDirectory(directory, {anchor: directory}); await chmod(directory, 0o700);
  }
  const configPath = path.join(directory, 'config.toml'), original = await readPrivateFile(configPath);
  const executable = await discoverCodex({home, environment, applicationDirectories});
  let backupPath = null;
  if (original !== null) {
    backupPath = configPath + `.kumo-backup-${Date.now()}-${randomUUID()}`;
    await atomicPrivateWrite(backupPath, original, {anchor: directory});
    await chmod(configPath, 0o600);
  }
  await runCodex(executable, ['mcp', 'add', 'kumo', '--', mcp.command, ...mcp.args], {home, environment});
  const configured = await readPrivateFile(configPath, {missing: false});
  if (!configured.length) throw new Error('Codex did not create its MCP configuration.');
  await chmod(configPath, 0o600);
  const status = JSON.parse(await runCodex(executable, ['mcp', 'get', 'kumo', '--json'], {home, environment}));
  if (status.enabled === false || status.transport?.type !== 'stdio' || status.transport.command !== mcp.command ||
      JSON.stringify(status.transport.args) !== JSON.stringify(mcp.args)) throw new Error('Codex did not retain the expected Kumo MCP command.');
  return {provider: 'codex-desktop', configured: true, configPath, backupPath, restartRequired: true};
}

export async function configureClaudeDesktop({home = homedir(), profile} = {}) {
  const mcp = desktopMcp(profile);
  const directory = path.join(home, 'Library', 'Application Support', 'Claude'); await privateDirectory(directory, {anchor: home});
  const configPath = path.join(directory, 'claude_desktop_config.json'), original = await readPrivateFile(configPath);
  let config = {};
  if (original !== null) {
    try { config = JSON.parse(original.toString('utf8')); } catch { throw new Error('Claude Desktop configuration is malformed; it was not changed.'); }
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Claude Desktop configuration must be an object.');
  }
  if (config.mcpServers !== undefined && (!config.mcpServers || typeof config.mcpServers !== 'object' || Array.isArray(config.mcpServers))) throw new Error('Claude Desktop mcpServers configuration must be an object.');
  config.mcpServers = {...config.mcpServers, kumo: {command: mcp.command, args: [...mcp.args]}};
  const backupPath = await atomicPrivateWrite(configPath, JSON.stringify(config, null, 2) + '\n', {anchor: home, backup: original !== null, expected: original === null ? null : sha(original)});
  return {provider: 'claude-desktop', configured: true, configPath, backupPath, restartRequired: true};
}

export async function configureDesktopProviders(provider, options = {}) {
  if (!['codex-desktop', 'claude-desktop', 'all'].includes(provider)) throw new Error('Choose codex-desktop, claude-desktop, or all.');
  const results = [];
  if (provider !== 'claude-desktop') results.push(await configureCodexDesktop(options));
  if (provider !== 'codex-desktop') results.push(await configureClaudeDesktop(options));
  return results;
}

// Status inspects only the Kumo transport and never returns client settings,
// account credentials, paths, tokens, CLI stdout or config contents to the UI.
export async function desktopProviderStatus(provider, {home = homedir(), profile, environment = process.env, applicationDirectories} = {}) {
  const expected = desktopMcp(profile);
  if (!['codex-desktop', 'claude-desktop'].includes(provider)) throw new Error('Choose one desktop provider');
  try {
    let actual;
    if (provider === 'codex-desktop') {
      const executable = await discoverCodex({home, environment, applicationDirectories});
      const result = JSON.parse(await runCodex(executable, ['mcp', 'get', 'kumo', '--json'], {home, environment}));
      actual = result.enabled === false ? null : result.transport;
    } else {
      const file = path.join(home, 'Library/Application Support/Claude/claude_desktop_config.json');
      const data = await readPrivateFile(file);
      if (!data) return {provider, configured: false, connected: false, status: 'not-configured'};
      const config = JSON.parse(data.toString('utf8'));
      if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Invalid settings');
      actual = config.mcpServers?.kumo;
    }
    const configured = actual?.command === expected.command && JSON.stringify(actual?.args) === JSON.stringify(expected.args);
    return {provider, configured, connected: false, status: configured ? 'configured' : 'not-configured'};
  } catch { return {provider, configured: false, connected: false, status: 'needs-attention'}; }
}
