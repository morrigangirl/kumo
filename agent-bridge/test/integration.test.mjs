import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn, execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp, lstat, rm} from 'node:fs/promises';
import path from 'node:path';
import {CLI_PATH} from '../lib/runtime.mjs';
import {profileRuntime} from '../cli.mjs';
import {LineDecoder, NativeDecoder, nativeMessage} from '../lib/protocol.mjs';
const profile = 'a'.repeat(32), exec = promisify(execFile);
function inbox(stream, decoder) {
  const queue=[], waiting=[];
  stream.on('data', chunk => { for(const value of decoder.push(chunk)) waiting.length ? waiting.shift()(value) : queue.push(value); });
  return () => queue.length ? Promise.resolve(queue.shift()) : new Promise((resolve,reject)=>{ const timer=setTimeout(()=>reject(new Error('Child reply timed out')),3000);waiting.push(value=>{clearTimeout(timer);resolve(value);}); });
}
async function fixture(t) {
  const home=await mkdtemp('/private/tmp/ka-'), env={...process.env, HOME:home}; delete env.KUMO_AGENT_DIR;
  const children=[];t.after(async()=>{for(const child of children)child.kill('SIGTERM');await new Promise(r=>setTimeout(r,50));await rm(home,{recursive:true,force:true});});
  const child=mode=>{const c=spawn(process.execPath,[CLI_PATH,mode,'--profile',profile],{env,stdio:['pipe','pipe','pipe']});children.push(c);return c;};
  return {home,env,child};
}

test('private browser pipes and stdio MCP exchange eight tools with live revocation',async t=>{
  const f=await fixture(t), browser=f.child('browser-channel'), read=inbox(browser.stdout,new NativeDecoder());
  assert.equal((await read()).type,'ready');
  browser.stdin.write(nativeMessage({type:'state',enabled:true,allowNewTabs:false,grants:[{tabId:12,origin:'https://example.com'}]}));assert.equal((await read()).type,'stateApplied');
  const mcp=f.child('mcp');mcp.stdout.setEncoding('utf8');const next=inbox(mcp.stdout,new LineDecoder());
  const send=message=>mcp.stdin.write(JSON.stringify(message)+'\n');
  send({jsonrpc:'2.0',id:1,method:'initialize',params:{}});assert.equal((await next()).result.serverInfo.name,'kumo-browser');
  send({jsonrpc:'2.0',id:2,method:'tools/list'});assert.equal((await next()).result.tools.length,8);
  send({jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'browser_snapshot',arguments:{tabId:12}}});
  const command=await read();assert.equal(command.action,'tab.snapshot');
  browser.stdin.write(nativeMessage({type:'result',id:command.id,result:{text:'Visible fixture'}}));assert.deepEqual(JSON.parse((await next()).result.content[0].text),{text:'Visible fixture'});
  send({jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'browser_snapshot',arguments:{tabId:12}}});const pending=await read();
  browser.stdin.write(nativeMessage({type:'state',enabled:false,allowNewTabs:false,grants:[]}));await read();
  browser.stdin.write(nativeMessage({type:'result',id:pending.id,result:'SECRET MUST NOT ARRIVE'}));const denied=await next();assert.equal(denied.result.isError,true);assert.doesNotMatch(denied.result.content[0].text,/SECRET/);
});

test('MCP discovery cannot start a browser broker, and obsolete extension modes fail',async t=>{
  const f=await fixture(t), mcp=f.child('mcp');mcp.stdout.setEncoding('utf8');const next=inbox(mcp.stdout,new LineDecoder());
  mcp.stdin.write(JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})+'\n');assert.equal((await next()).result.tools.length,8);
  await assert.rejects(lstat(path.join(profileRuntime(profile,f.home),'bridge.sock')),e=>e.code==='ENOENT');
  for(const mode of ['native','install','broker']) await assert.rejects(exec(process.execPath,[CLI_PATH,mode,'--profile',profile],{env:f.env}));
});

test('browser pipe closure revokes authority and removes the listening socket',async t=>{
  const f=await fixture(t), browser=f.child('browser-channel'), next=inbox(browser.stdout,new NativeDecoder());await next();
  const ended=new Promise(resolve=>browser.once('exit',resolve));browser.stdin.end();assert.equal(await ended,0);
  await assert.rejects(lstat(path.join(profileRuntime(profile,f.home),'bridge.sock')),e=>e.code==='ENOENT');
});
