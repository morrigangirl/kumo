import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {installPortableRuntime, configureClaudeDesktop, configureCodexDesktop, desktopProviderStatus, desktopMcp, discoverCodex, PORTABLE_FILES} from '../desktop.mjs';
const profile='b'.repeat(32), source=path.dirname(fileURLToPath(new URL('../cli.mjs',import.meta.url)));
async function fixture(t,{realNode=false}={}) {
 const home=await mkdtemp('/private/tmp/kumo-desktop-');t.after(()=>rm(home,{recursive:true,force:true}));
 const sourceDir=path.join(home,'source');await mkdir(sourceDir,{mode:0o700});
 for(const folder of ['lib','bin'])await mkdir(path.join(sourceDir,folder),{mode:0o700});
 for(const name of PORTABLE_FILES.filter(x=>!['bin/node','LICENSE.node','runtime.json'].includes(x)))await copyFile(path.join(source,name),path.join(sourceDir,name));
 if(realNode)await copyFile(fileURLToPath(new URL('../../build/agent-runtime/bin/node',import.meta.url)),path.join(sourceDir,'bin/node'));else await writeFile(path.join(sourceDir,'bin/node'),'synthetic runtime');
 await (await import('node:fs/promises')).chmod(path.join(sourceDir,'bin/node'),0o700);
 await writeFile(path.join(sourceDir,'LICENSE.node'),'Synthetic license fixture.');await writeFile(path.join(sourceDir,'runtime.json'),'{}');
 const bin=path.join(home,'bin');await mkdir(bin,{mode:0o700});const environment={...process.env,HOME:home,CODEX_HOME:path.join(home,'.codex'),PATH:bin+':/usr/bin:/bin'};
 return {home,sourceDir,bin,environment,profile,runtimeDir:path.join(home,'.kumo/agents')};
}
async function fakeCodex(file) {
 await mkdir(path.dirname(file),{recursive:true,mode:0o700});
 await writeFile(file,`#!${process.execPath}
const fs=require('node:fs'),p=require('node:path'),a=process.argv.slice(2),d=process.env.CODEX_HOME,c=p.join(d,'config.toml');fs.mkdirSync(d,{recursive:true,mode:448});const before=fs.existsSync(c)?fs.readFileSync(c,'utf8'):'';
if(before.includes('BROKEN')){process.stderr.write('PRIVATE DATA');process.exit(2);}
if(a[0]!=='mcp'||a[2]!=='kumo')process.exit(3);
const entry=p.join(d,'transport.json');if(a[1]==='add'){fs.writeFileSync(c,before+'\\n[mcp_servers.kumo]\\ncommand="/bin/sh"\\n');fs.writeFileSync(entry,JSON.stringify({type:'stdio',command:a[4],args:a.slice(5)}));}else if(a[1]==='get'){process.stdout.write(JSON.stringify({enabled:true,transport:JSON.parse(fs.readFileSync(entry,'utf8'))}));}else process.exit(4);
`,{mode:0o700});
}

test('versioned managed payload activation preserves private state and uses only bundled files',async t=>{
 const f=await fixture(t),first=await installPortableRuntime(f);assert.match(first.version,/^[a-f0-9]{64}$/);assert.equal((await lstat(first.server)).isSymbolicLink(),true);assert.equal(await realpath(first.server),path.join(f.runtimeDir,'versions',first.version));
 for(const name of PORTABLE_FILES)assert.equal((await lstat(path.join(first.server,name))).mode&0o777,['run','bin/node'].includes(name)?0o700:0o600);
 await writeFile(path.join(f.runtimeDir,'pairing-token'),'PRESERVE');await writeFile(path.join(f.sourceDir,'LICENSE.node'),'Updated fixture license');const next=await installPortableRuntime(f);assert.notEqual(first.version,next.version);assert.equal(await readFile(path.join(f.runtimeDir,'pairing-token'),'utf8'),'PRESERVE');
 assert.doesNotMatch(await readFile(next.run,'utf8'),/\/Volumes\/|Cellar|command -v node/);assert.match(await readFile(next.run,'utf8'),/--jitless --no-expose-wasm/);
});

test('unexpected source or managed payload contents and unsafe runtime links are rejected',async t=>{
 const f=await fixture(t);await writeFile(path.join(f.sourceDir,'secret'),'DO NOT COPY');await assert.rejects(installPortableRuntime(f),/Unexpected/);await rm(path.join(f.sourceDir,'secret'));
 const installed=await installPortableRuntime(f);await writeFile(path.join(installed.server,'keep-me'),'PRESERVE');await assert.rejects(installPortableRuntime(f),/Unexpected/);assert.equal(await readFile(path.join(installed.server,'keep-me'),'utf8'),'PRESERVE');
});

test('Claude registration preserves unrelated configuration and backs it up privately',async t=>{
 const f=await fixture(t),dir=path.join(f.home,'Library/Application Support/Claude');await mkdir(dir,{recursive:true,mode:0o700});const file=path.join(dir,'claude_desktop_config.json'),original={preferences:{theme:'dark'},mcpServers:{other:{command:'unchanged'}}};await writeFile(file,JSON.stringify(original));
 const configured=await configureClaudeDesktop(f),value=JSON.parse(await readFile(file));assert.deepEqual(value.preferences,original.preferences);assert.deepEqual(value.mcpServers.other,original.mcpServers.other);assert.deepEqual(value.mcpServers.kumo,desktopMcp(profile));assert.deepEqual(JSON.parse(await readFile(configured.backupPath)),original);assert.equal((await lstat(configured.backupPath)).mode&0o777,0o600);
 assert.deepEqual(await desktopProviderStatus('claude-desktop',f),{provider:'claude-desktop',configured:true,connected:false,status:'configured'});
 assert.equal((await desktopProviderStatus('claude-desktop',{...f,profile:'c'.repeat(32)})).configured,false);
});

test('malformed or symlinked Claude settings remain unchanged and status reveals no contents',async t=>{
 const f=await fixture(t),r=await configureClaudeDesktop(f);for(const bad of ['null','[]','{invalid','{"mcpServers":[]}']){await writeFile(r.configPath,bad);await assert.rejects(configureClaudeDesktop(f));assert.equal(await readFile(r.configPath,'utf8'),bad);}
 const target=path.join(f.home,'private.json');await writeFile(target,'{"account":"SECRET"}');await rm(r.configPath);await symlink(target,r.configPath);await assert.rejects(configureClaudeDesktop(f));assert.equal(await readFile(target,'utf8'),'{"account":"SECRET"}');assert.doesNotMatch(JSON.stringify(await desktopProviderStatus('claude-desktop',f)),/SECRET|private.json/);
});

test('Codex official CLI preserves settings, status verifies exact profile binding and masks failures',async t=>{
 const f=await fixture(t);await fakeCodex(path.join(f.bin,'codex'));await mkdir(f.environment.CODEX_HOME,{mode:0o700});const config=path.join(f.environment.CODEX_HOME,'config.toml');await writeFile(config,'model="fixture"\n[mcp_servers.other]\ncommand="keep"');const result=await configureCodexDesktop(f);assert.equal(result.configured,true);assert.match(await readFile(config,'utf8'),/mcp_servers.other/);assert.equal((await desktopProviderStatus('codex-desktop',f)).configured,true);
 await writeFile(config,'BROKEN SECRET');await assert.rejects(configureCodexDesktop(f),error=>!/PRIVATE|SECRET/.test(error.message));assert.equal(await readFile(config,'utf8'),'BROKEN SECRET');
});

test('Codex discovery supports app-bundled CLI and a private explicit CODEX_HOME',async t=>{
 const f=await fixture(t),apps=path.join(f.home,'Applications'),file=path.join(apps,'Codex.app/Contents/Resources/codex');await fakeCodex(file);assert.equal(await discoverCodex({...f,environment:{...f.environment,PATH:'/usr/bin:/bin'},applicationDirectories:[apps]}),file);
 const custom=path.join(f.home,'custom');await mkdir(custom,{mode:0o700});await configureCodexDesktop({...f,environment:{...f.environment,CODEX_HOME:custom,PATH:'/usr/bin:/bin'},applicationDirectories:[apps]});assert.ok((await readdir(custom)).includes('config.toml'));
});

test('relocated copied runtime initializes MCP without PATH node or original checkout',async t=>{
 const f=await fixture(t,{realNode:true}),installed=await installPortableRuntime(f);await rm(f.sourceDir,{recursive:true});const mcp=desktopMcp(profile);
 const child=spawn(mcp.command,mcp.args,{env:{HOME:f.home,PATH:'/usr/bin:/bin',NODE_OPTIONS:'--invalid-secret-option',NODE_PATH:'/invalid'},stdio:['pipe','pipe','pipe']});t.after(()=>child.kill('SIGTERM'));let stdout='',stderr='';child.stdout.on('data',x=>stdout+=x);child.stderr.on('data',x=>stderr+=x);const exit=new Promise(resolve=>child.once('exit',resolve));child.stdin.end(JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{}})+'\n');assert.equal(await exit,0,stderr);assert.equal(stderr,'');assert.equal(JSON.parse(stdout).result.serverInfo.name,'kumo-browser');assert.equal(installed.run,path.join(f.runtimeDir,'server/run'));
});
