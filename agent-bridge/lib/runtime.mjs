import { homedir } from 'node:os';
import path from 'node:path';
import { chmod, lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { privateDirectory } from '../desktop.mjs';

export const CLI_PATH = fileURLToPath(new URL('../cli.mjs', import.meta.url));
export const DEFAULT_RUNTIME_DIR = path.join(homedir(), '.kumo', 'agents');

export async function privateRuntime(runtimeDir = DEFAULT_RUNTIME_DIR) {
  if (!path.isAbsolute(runtimeDir)) throw new Error('KUMO_AGENT_DIR must be an absolute path');
  const userHome = homedir();
  if (runtimeDir.startsWith(userHome + path.sep)) await privateDirectory(runtimeDir, {anchor: userHome});
  else await mkdir(runtimeDir, { recursive: true, mode: 0o700 });
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
