import { homedir } from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { chmod, lstat, mkdir, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const CLI_PATH = fileURLToPath(new URL('../cli.mjs', import.meta.url));
export const DEFAULT_RUNTIME_DIR = path.join(homedir(), '.kumo', 'agents');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function privateRuntime(runtimeDir = process.env.KUMO_AGENT_DIR || DEFAULT_RUNTIME_DIR) {
  if (!path.isAbsolute(runtimeDir)) throw new Error('KUMO_AGENT_DIR must be an absolute path');
  await mkdir(runtimeDir, { recursive: true, mode: 0o700 });
  const stat = await lstat(runtimeDir);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (process.getuid && stat.uid !== process.getuid())) throw new Error('Unsafe bridge runtime directory');
  await chmod(runtimeDir, 0o700);
  const tokenPath = path.join(runtimeDir, 'pairing-token');
  try { await writeFile(tokenPath, randomBytes(32).toString('hex'), { flag: 'wx', mode: 0o600 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const tokenStat = await lstat(tokenPath);
  if (!tokenStat.isFile() || tokenStat.isSymbolicLink() || (process.getuid && tokenStat.uid !== process.getuid()) || (tokenStat.mode & 0o077)) {
    throw new Error('Pairing token must be a private, user-owned regular file');
  }
  const token = (await readFile(tokenPath, 'utf8')).trim();
  if (!/^[a-f0-9]{64}$/.test(token)) throw new Error('Invalid local pairing token');
  const socketPath = path.join(runtimeDir, 'bridge.sock');
  if (Buffer.byteLength(socketPath) > 100) throw new Error('KUMO_AGENT_DIR path is too long for a Unix socket (choose a shorter directory)');
  return { runtimeDir, token, socketPath };
}

function listening(socketPath) {
  return new Promise(resolve => {
    const socket = net.createConnection(socketPath);
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => resolve(false));
    socket.setTimeout(250, () => { socket.destroy(); resolve(false); });
  });
}

export async function ensureBroker(runtime) {
  if (await listening(runtime.socketPath)) return;
  const lockPath = path.join(runtime.runtimeDir, 'start.lock');
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      await mkdir(lockPath, { mode: 0o700 });
      try {
        await writeFile(path.join(lockPath, 'pid'), String(process.pid), { mode: 0o600 });
        if (await listening(runtime.socketPath)) return;
        try {
          const stat = await lstat(runtime.socketPath);
          if (!stat.isSocket() || (process.getuid && stat.uid !== process.getuid())) throw new Error('Unsafe bridge socket path');
          await unlink(runtime.socketPath);
        } catch (error) { if (error.code !== 'ENOENT') throw error; }
        const child = spawn(process.execPath, [CLI_PATH, 'broker'], {
          detached: true,
          stdio: 'ignore',
          env: { ...process.env, KUMO_AGENT_DIR: runtime.runtimeDir },
        });
        let spawnError;
        child.once('error', error => { spawnError = error; });
        child.unref();
        for (let check = 0; check < 60; check++) {
          if (spawnError) throw spawnError;
          if (await listening(runtime.socketPath)) return;
          await pause(50);
        }
        throw new Error('Could not start the local browser bridge');
      } finally { await rm(lockPath, { recursive: true, force: true }); }
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      if (await listening(runtime.socketPath)) return;
      // Recover a lock left by a killed starter. Never remove an active starter's lock.
      try {
        const pid = Number(await readFile(path.join(lockPath, 'pid'), 'utf8'));
        if (Number.isSafeInteger(pid) && pid > 0) {
          try { process.kill(pid, 0); } catch (probe) { if (probe.code === 'ESRCH') await rm(lockPath, { recursive: true, force: true }); }
        }
      } catch (readError) {
        if (readError.code === 'ENOENT') {
          try {
            if (Date.now() - (await lstat(lockPath)).mtimeMs > 10000) await rm(lockPath, { recursive: true, force: true });
          } catch (lockError) { if (lockError.code !== 'ENOENT') throw lockError; }
        } else throw readError;
      }
      await pause(50);
    }
  }
  throw new Error('Timed out waiting for the bridge startup lock');
}
