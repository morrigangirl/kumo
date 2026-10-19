import path from 'node:path';
import {homedir, tmpdir} from 'node:os';
import {constants} from 'node:fs';
import {access, chmod, lstat, mkdir, open, readFile, readdir, realpath, rename, rm} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {randomUUID, createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

export const DESKTOP_MCP_COMMAND = 'exec "$HOME/.kumo/agents/server/run" mcp';
export const DESKTOP_MCP = Object.freeze({command: '/bin/sh', args: ['-c', DESKTOP_MCP_COMMAND]});
export const PORTABLE_FILES = Object.freeze(['cli.mjs', 'desktop.mjs', 'run', 'package.json',
  'lib/broker.mjs', 'lib/runtime.mjs', 'lib/protocol.mjs', 'lib/mcp.mjs']);
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

async function verifyPayload(directory) {
  const allowed = new Set(PORTABLE_FILES);
  for (const parent of ['', 'lib']) {
    const folder = path.join(directory, parent), state = await lstat(folder);
    if (!state.isDirectory() || state.isSymbolicLink() || uid !== undefined && state.uid !== uid) throw new Error('Unsafe bridge payload directory.');
    for (const entry of await readdir(folder, {withFileTypes: true})) {
      const relative = parent ? `${parent}/${entry.name}` : entry.name;
      if (relative === 'lib' && entry.isDirectory()) continue;
      if (!allowed.has(relative) || !entry.isFile() || entry.isSymbolicLink()) throw new Error('Unexpected bridge payload file.');
      await readPrivateFile(path.join(directory, relative), {maximum: 1024 * 1024, missing: false});
    }
  }
  for (const name of PORTABLE_FILES) await readPrivateFile(path.join(directory, name), {maximum: 1024 * 1024, missing: false});
}

export async function installPortableRuntime({home = homedir(), runtimeDir = path.join(home, '.kumo', 'agents'), sourceDir = SOURCE} = {}) {
  const anchor = contained(runtimeDir, home) ? home : runtimeDir;
  await privateDirectory(runtimeDir, {anchor});
  if (contained(runtimeDir, home)) await privateDirectory(path.join(home, '.kumo'), {anchor: home});
  const server = path.join(runtimeDir, 'server'), staging = path.join(runtimeDir, `.server-install-${randomUUID()}`);
  const previous = path.join(runtimeDir, `.server-previous-${randomUUID()}`);
  await mkdir(staging, {mode: 0o700}); await mkdir(path.join(staging, 'lib'), {mode: 0o700});
  let hadPrevious = false, published = false;
  try {
    const sourceState = await lstat(sourceDir), libraryState = await lstat(path.join(sourceDir, 'lib'));
    if (!sourceState.isDirectory() || sourceState.isSymbolicLink() || !libraryState.isDirectory() || libraryState.isSymbolicLink()) throw new Error('Unsafe bridge source payload.');
    for (const name of PORTABLE_FILES) {
      const data = await readPrivateFile(path.join(sourceDir, name), {maximum: 1024 * 1024, missing: false, allowRoot: true});
      await atomicPrivateWrite(path.join(staging, name), data, {anchor: runtimeDir, mode: name === 'run' ? 0o700 : 0o600});
    }
    try { await lstat(server); await verifyPayload(server); await rename(server, previous); hadPrevious = true; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    try { await rename(staging, server); published = true; }
    catch (error) { if (hadPrevious) await rename(previous, server); throw error; }
    if (hadPrevious) await rm(previous, {recursive: true});
    return {runtimeDir, server, run: path.join(server, 'run')};
  } finally { if (!published) await rm(staging, {recursive: true, force: true}); }
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

export async function configureCodexDesktop({home = homedir(), environment = process.env, applicationDirectories} = {}) {
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
  await runCodex(executable, ['mcp', 'add', 'kumo', '--', '/bin/sh', '-c', DESKTOP_MCP_COMMAND], {home, environment});
  const configured = await readPrivateFile(configPath, {missing: false});
  if (!configured.length) throw new Error('Codex did not create its MCP configuration.');
  await chmod(configPath, 0o600);
  const status = JSON.parse(await runCodex(executable, ['mcp', 'get', 'kumo', '--json'], {home, environment}));
  if (status.enabled === false || status.transport?.type !== 'stdio' || status.transport.command !== DESKTOP_MCP.command ||
      JSON.stringify(status.transport.args) !== JSON.stringify(DESKTOP_MCP.args)) throw new Error('Codex did not retain the expected Kumo MCP command.');
  return {provider: 'codex-desktop', configured: true, configPath, backupPath, restartRequired: true};
}

export async function configureClaudeDesktop({home = homedir()} = {}) {
  const directory = path.join(home, 'Library', 'Application Support', 'Claude'); await privateDirectory(directory, {anchor: home});
  const configPath = path.join(directory, 'claude_desktop_config.json'), original = await readPrivateFile(configPath);
  let config = {};
  if (original !== null) {
    try { config = JSON.parse(original.toString('utf8')); } catch { throw new Error('Claude Desktop configuration is malformed; it was not changed.'); }
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Claude Desktop configuration must be an object.');
  }
  if (config.mcpServers !== undefined && (!config.mcpServers || typeof config.mcpServers !== 'object' || Array.isArray(config.mcpServers))) throw new Error('Claude Desktop mcpServers configuration must be an object.');
  config.mcpServers = {...config.mcpServers, kumo: {command: DESKTOP_MCP.command, args: [...DESKTOP_MCP.args]}};
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
