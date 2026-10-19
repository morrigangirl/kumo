import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {spawn, execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {chmod, cp, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {installPortableRuntime, configureClaudeDesktop, configureCodexDesktop, discoverCodex, PORTABLE_FILES, DESKTOP_MCP, DESKTOP_MCP_COMMAND} from '../desktop.mjs';
import {privateRuntime, CLI_PATH} from '../lib/runtime.mjs';
import {startBroker} from '../lib/broker.mjs';

const exec = promisify(execFile);
const source = path.dirname(fileURLToPath(new URL('../cli.mjs', import.meta.url)));
async function fixture(t) {
  const home = await mkdtemp('/private/tmp/kumo-desktop-');
  t.after(() => rm(home, {recursive: true, force: true}));
  const bin = path.join(home, 'bin'); await mkdir(bin, {mode: 0o700}); await symlink(process.execPath, path.join(bin, 'node'));
  const environment = {...process.env, HOME: home, CODEX_HOME: path.join(home, '.codex'), PATH: bin + ':/usr/bin:/bin'};
  delete environment.KUMO_AGENT_DIR;
  return {home, bin, environment, runtimeDir: path.join(home, '.kumo', 'agents')};
}
async function fakeCodex(file) {
  await mkdir(path.dirname(file), {recursive: true, mode: 0o700});
  await writeFile(file, `#!${process.execPath}
import fs from 'node:fs'; import path from 'node:path';
const dir=process.env.CODEX_HOME, config=path.join(dir,'config.toml'), args=process.argv.slice(2);
fs.mkdirSync(dir,{recursive:true,mode:0o700});
const before=fs.existsSync(config)?fs.readFileSync(config,'utf8'):'';
if(before.includes('BROKEN_TOML')) { process.stderr.write('private failure detail must not be forwarded'); process.exit(2); }
if(args[0]!=='mcp'||args[2]!=='kumo')process.exit(3);
if(args[1]==='add') {
 if(JSON.stringify(args.slice(3,7))!==JSON.stringify(['--','/bin/sh','-c',${JSON.stringify(DESKTOP_MCP_COMMAND)}])) process.exit(4);
 const remaining=before.replace(/\\[mcp_servers\\.kumo\\][\\s\\S]*?(?=\\n\\[|$)/g,'');
 fs.writeFileSync(config,remaining+'\\n[mcp_servers.kumo]\\ncommand = "/bin/sh"\\nargs = '+JSON.stringify(['-c',args[6]])+'\\n',{mode:0o600});
 fs.writeFileSync(path.join(dir,'fake-kumo-transport.json'),JSON.stringify({type:'stdio',command:'/bin/sh',args:['-c',args[6]]}),{mode:0o600});
 process.stdout.write('Added global MCP server kumo.\\n');
} else if(args[1]==='get'&&args[3]==='--json') {
 process.stdout.write(JSON.stringify({name:'kumo',enabled:true,transport:JSON.parse(fs.readFileSync(path.join(dir,'fake-kumo-transport.json'),'utf8'))}));
} else process.exit(5);
`, {mode: 0o700});
}

test('portable installation copies only approved runtime files, uses private modes and contains no checkout or pinned Node path', async t => {
  const f = await fixture(t), checkout = path.join(f.home, 'checkout with spaces');
  await cp(source, checkout, {recursive: true}); await writeFile(path.join(checkout, 'secret-provider-token'), 'not payload');
  await mkdir(path.join(checkout, 'node_modules')); await writeFile(path.join(checkout, 'node_modules', 'secret'), 'not payload');
  const installed = await installPortableRuntime({...f, sourceDir: checkout});
  assert.deepEqual((await readdir(installed.server)).sort(), ['cli.mjs', 'desktop.mjs', 'lib', 'package.json', 'run']);
  assert.deepEqual((await readdir(path.join(installed.server, 'lib'))).sort(), ['broker.mjs', 'mcp.mjs', 'protocol.mjs', 'runtime.mjs']);
  for (const name of PORTABLE_FILES) {
    assert.equal((await lstat(path.join(installed.server, name))).mode & 0o777, name === 'run' ? 0o700 : 0o600);
  }
  for (const name of ['.kumo', '.kumo/agents', '.kumo/agents/server', '.kumo/agents/server/lib']) assert.equal((await lstat(path.join(f.home, name))).mode & 0o777, 0o700);
  assert.doesNotMatch(await readFile(installed.run, 'utf8'), /\/Volumes\/|\/Users\/|Cellar/);
  await rm(checkout, {recursive: true});
  const result = await exec('/bin/sh', [installed.run], {env: f.environment, cwd: '/private/tmp'});
  assert.match(result.stdout, /Kumo agent bridge/); assert.equal(result.stderr, '');
});

test('CLI provider all installs stable payload and updates actual desktop configs while preserving other settings', async t => {
  const f = await fixture(t); await fakeCodex(path.join(f.bin, 'codex'));
  const codex = path.join(f.home, '.codex', 'config.toml'); await mkdir(path.dirname(codex), {mode: 0o700});
  const originalToml = 'model = "fixture-model"\n[mcp_servers.other]\ncommand = "unchanged"\n'; await writeFile(codex, originalToml);
  const claude = path.join(f.home, 'Library/Application Support/Claude/claude_desktop_config.json'); await mkdir(path.dirname(claude), {recursive: true, mode: 0o700});
  const originalClaude = {preferences: {theme: 'dark'}, mcpServers: {other: {command: 'unchanged'}, kumo: {command: '/old/checkout/node'}}};
  await writeFile(claude, JSON.stringify(originalClaude));
  const {stdout, stderr} = await exec(process.execPath, [CLI_PATH, 'install', '--provider', 'all'], {env: f.environment});
  assert.equal(stderr, ''); const installed = JSON.parse(stdout); assert.equal(installed.providers.length, 2);
  const output = JSON.parse(await readFile(claude, 'utf8'));
  assert.deepEqual(output.preferences, originalClaude.preferences); assert.deepEqual(output.mcpServers.other, originalClaude.mcpServers.other);
  assert.deepEqual(output.mcpServers.kumo, DESKTOP_MCP);
  assert.match(await readFile(codex, 'utf8'), /fixture-model/); assert.match(await readFile(codex, 'utf8'), /mcp_servers.other/);
  for (const result of installed.providers) {
    assert.equal(result.configured, true); assert.equal(result.restartRequired, true); assert.equal((await lstat(result.configPath)).mode & 0o777, 0o600);
    assert.equal((await lstat(result.backupPath)).mode & 0o777, 0o600);
  }
  assert.equal(await readFile(installed.providers[0].backupPath, 'utf8'), originalToml);
  assert.deepEqual(JSON.parse(await readFile(installed.providers[1].backupPath, 'utf8')), originalClaude);
  for (const file of [codex, claude, installed.codexConfig, installed.claudeConfig, path.join(f.runtimeDir, 'native-host.sh')]) assert.doesNotMatch(await readFile(file, 'utf8'), /\/Volumes\/Creative|\/Users\/aoibhwood|Cellar/);
  const manifest = JSON.parse(await readFile(installed.manifestPath, 'utf8'));
  assert.equal(manifest.path, path.join(f.runtimeDir, 'native-host.sh'));
  assert.deepEqual(manifest.allowed_origins, ['chrome-extension://eldkgppmnhligdekahicdcdndcoongio/']);
});

test('Codex discovery finds app-bundled CLI without a PATH installation', async t => {
  const f = await fixture(t), applications = path.join(f.home, 'Applications');
  const executable = path.join(applications, 'ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex');
  await fakeCodex(executable);
  assert.equal(await discoverCodex({...f, environment: {...f.environment, PATH: '/usr/bin:/bin'}, applicationDirectories: [applications]}), executable);
  const result = await configureCodexDesktop({...f, environment: {...f.environment, PATH: '/usr/bin:/bin'}, applicationDirectories: [applications]});
  assert.equal(result.configured, true);
});

test('Claude setup creates missing config and rejects malformed or non-object settings without changing them', async t => {
  const f = await fixture(t); const result = await configureClaudeDesktop(f);
  assert.equal(result.backupPath, null); assert.deepEqual(JSON.parse(await readFile(result.configPath, 'utf8')).mcpServers.kumo, DESKTOP_MCP);
  for (const contents of ['{invalid', '[]', 'null', '{"mcpServers":[]}']) {
    await writeFile(result.configPath, contents);
    await assert.rejects(configureClaudeDesktop(f), /malformed|object/);
    assert.equal(await readFile(result.configPath, 'utf8'), contents);
  }
});

test('Codex malformed TOML failure preserves original and never forwards CLI output', async t => {
  const f = await fixture(t); await fakeCodex(path.join(f.bin, 'codex'));
  const file = path.join(f.home, '.codex/config.toml'); await mkdir(path.dirname(file), {mode: 0o700}); await writeFile(file, 'BROKEN_TOML');
  await assert.rejects(configureCodexDesktop(f), error => { assert.match(error.message, /official Codex configuration command failed/); assert.doesNotMatch(error.message, /private failure/); return true; });
  assert.equal(await readFile(file, 'utf8'), 'BROKEN_TOML');
  const backups = (await readdir(path.dirname(file))).filter(value => value.startsWith('config.toml.kumo-backup-'));
  assert.equal(backups.length, 1); assert.equal((await lstat(path.join(path.dirname(file), backups[0]))).mode & 0o777, 0o600);
});

test('symlinked client config and parent directories are rejected without modifying external targets', async t => {
  const f = await fixture(t), target = path.join(f.home, 'external.json'); await writeFile(target, '{"untouched":true}');
  const directory = path.join(f.home, 'Library/Application Support/Claude'); await mkdir(directory, {recursive: true, mode: 0o700});
  const config = path.join(directory, 'claude_desktop_config.json'); await symlink(target, config);
  await assert.rejects(configureClaudeDesktop(f), /symlink|regular/); assert.equal(await readFile(target, 'utf8'), '{"untouched":true}');
  await rm(config); await rm(directory, {recursive: true}); await symlink(path.dirname(target), directory);
  await assert.rejects(configureClaudeDesktop(f), /Unsafe installation/); assert.equal(await readFile(target, 'utf8'), '{"untouched":true}');
});

test('symlinked private runtime and unexpected old payload are rejected without deleting user data', async t => {
  const f = await fixture(t), external = path.join(f.home, 'outside'); await mkdir(external, {mode: 0o700});
  await symlink(external, path.join(f.home, '.kumo'));
  await assert.rejects(installPortableRuntime(f), /Unsafe installation/); assert.deepEqual(await readdir(external), []);
  await rm(path.join(f.home, '.kumo')); const installed = await installPortableRuntime(f);
  await writeFile(path.join(installed.server, 'do-not-delete'), 'owned data');
  await assert.rejects(installPortableRuntime(f), /Unexpected bridge payload/);
  assert.equal(await readFile(path.join(installed.server, 'do-not-delete'), 'utf8'), 'owned data');
});

test('installation updates an existing approved payload without copying private runtime state', async t => {
  const f = await fixture(t); const installed = await installPortableRuntime(f);
  await writeFile(path.join(f.runtimeDir, 'pairing-token'), 'private-token', {mode: 0o600});
  await installPortableRuntime({...f, sourceDir: installed.server});
  assert.equal(await readFile(path.join(f.runtimeDir, 'pairing-token'), 'utf8'), 'private-token');
  assert.equal((await readdir(f.runtimeDir)).some(name => name.startsWith('.server-')), false);
});

test('installed relocated launcher produces pure MCP stdout after original checkout is removed', async t => {
  const f = await fixture(t), checkout = path.join(f.home, 'temporary checkout'); await cp(source, checkout, {recursive: true});
  const installed = await installPortableRuntime({...f, sourceDir: checkout}); await rm(checkout, {recursive: true});
  const runtime = await privateRuntime(f.runtimeDir), broker = await startBroker(runtime); t.after(() => broker.close());
  const stale = path.join(f.home, 'obsolete-checkout-runtime');
  const child = spawn('/bin/sh', DESKTOP_MCP.args, {env: {...f.environment, KUMO_AGENT_DIR: stale}, cwd: '/private/tmp', stdio: ['pipe', 'pipe', 'pipe']});
  t.after(() => child.kill('SIGTERM'));
  let stdout = '', stderr = ''; child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
  const exited = new Promise(resolve => child.once('exit', code => resolve(code)));
  child.stdin.end(JSON.stringify({jsonrpc: '2.0', id: 1, method: 'initialize', params: {}}) + '\n');
  assert.equal(await exited, 0); assert.equal(stderr, '');
  const lines = stdout.trim().split('\n'); assert.equal(lines.length, 1);
  const reply = JSON.parse(lines[0]); assert.equal(reply.id, 1); assert.equal(reply.result.serverInfo.name, 'kumo-browser');
  assert.equal(installed.run, path.join(f.runtimeDir, 'server/run'));
  await assert.rejects(lstat(stale), error => error.code === 'ENOENT');
});

test('Codex setup preserves a custom caller CODEX_HOME instead of redirecting it', async t => {
  const f = await fixture(t); await fakeCodex(path.join(f.bin, 'codex'));
  const custom = path.join(f.home, 'custom-codex'); await mkdir(custom, {mode: 0o700});
  const environment = {...f.environment, CODEX_HOME: custom};
  const result = await configureCodexDesktop({...f, environment});
  assert.equal(result.configPath, path.join(custom, 'config.toml')); assert.match(await readFile(result.configPath, 'utf8'), /mcp_servers.kumo/);
  await assert.rejects(lstat(path.join(f.home, '.codex')), error => error.code === 'ENOENT');
  await assert.rejects(configureCodexDesktop({...f, environment: {...environment, CODEX_HOME: 'relative'}}), /absolute/);
  const link = path.join(f.home, 'linked-codex'); await symlink(custom, link);
  await assert.rejects(configureCodexDesktop({...f, environment: {...environment, CODEX_HOME: link}}), /Unsafe/);
});

test('Codex setup backs up and preserves an existing config in a private CODEX_HOME outside the user home', async t => {
  const f = await fixture(t); await fakeCodex(path.join(f.bin, 'codex'));
  const custom = await mkdtemp('/private/tmp/kumo-external-codex-');
  t.after(() => rm(custom, {recursive: true, force: true}));
  const config = path.join(custom, 'config.toml');
  const original = 'model = "external-fixture"\n[mcp_servers.other]\ncommand = "untouched"\n';
  await writeFile(config, original, {mode: 0o600});
  const result = await configureCodexDesktop({...f, environment: {...f.environment, CODEX_HOME: custom}});
  assert.equal(result.configPath, config);
  assert.equal(path.dirname(result.backupPath), custom);
  assert.equal(await readFile(result.backupPath, 'utf8'), original);
  assert.equal((await lstat(result.backupPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(config)).mode & 0o777, 0o600);
  assert.equal((await lstat(custom)).mode & 0o777, 0o700);
  const configured = await readFile(config, 'utf8');
  assert.match(configured, /external-fixture/); assert.match(configured, /mcp_servers.other/);
  assert.match(configured, /mcp_servers.kumo/);
  await assert.rejects(lstat(path.join(f.home, '.codex')), error => error.code === 'ENOENT');
});

test('provider installation rejects custom runtime and unknown/duplicate options', async t => {
  const f = await fixture(t), custom = path.join(f.home, 'custom-runtime');
  await assert.rejects(exec(process.execPath, [CLI_PATH, 'install', '--provider', 'claude-desktop'], {env: {...f.environment, KUMO_AGENT_DIR: custom}}), error => /standard ~\/.kumo\/agents/.test(error.stderr));
  for (const args of [['--provider', 'unknown'], ['--provider', 'all', '--provider', 'all'], ['--bad', 'value']]) {
    await assert.rejects(exec(process.execPath, [CLI_PATH, 'install', ...args], {env: f.environment}), error => /Choose|Invalid/.test(error.stderr));
  }
});

test('legacy install accepts a separately owned temporary profile and its generated custom-runtime command is portable', async t => {
  const f = await fixture(t), separate = await mkdtemp('/private/tmp/kumo-profile-'); t.after(() => rm(separate, {recursive: true, force: true}));
  const runtimeDir = path.join(f.home, 'custom-runtime');
  const {stdout} = await exec(process.execPath, [CLI_PATH, 'install', '--extension-id', 'a'.repeat(32), '--browser-profile', path.join(separate, 'profile')],
    {env: {...f.environment, KUMO_AGENT_DIR: runtimeDir}});
  const installed = JSON.parse(stdout); assert.equal(installed.manifestPath, path.join(separate, 'profile/NativeMessagingHosts/com.kumo.agent_bridge.json'));
  const snippet = JSON.parse(await readFile(installed.claudeConfig, 'utf8')).mcpServers.kumo;
  assert.equal(snippet.command, '/bin/sh'); assert.equal(snippet.args[1], `exec '${runtimeDir}/server/run' mcp`);
  assert.doesNotMatch(snippet.args[1], /\/Volumes\/|Cellar/);
});
