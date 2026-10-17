import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { mkdtemp, chmod, writeFile, readFile, rm, readdir, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inventoryPeer, REPO, TOKEN } from './github-pull-inventory-fixture.mjs';
import { main } from '../../scripts/discover_github_pulls.mjs';
import { parseGithubPullCapture } from '../../scripts/lib/github-pull-source.mjs';

const script=fileURLToPath(new URL('../../scripts/discover_github_pulls.mjs',import.meta.url));
async function files(t) {
  const root=await mkdtemp(join(tmpdir(),'fg-pr-inventory-'));await chmod(root,0o700);t.after(()=>rm(root,{recursive:true,force:true}));
  const token=join(root,'token'),shim=join(root,'peer.mjs');await writeFile(token,TOKEN,{mode:0o600});
  await writeFile(shim,`const request=globalThis.fetch;globalThis.fetch=async(input,options)=>{const u=new URL(input);if(u.origin!=='https://api.github.com')throw Error('foreign source');const r=await request(process.env.FG_TEST_SOURCE+u.pathname+u.search,options);return new Response(r.body,{status:r.status,headers:r.headers});};`,{mode:0o600});
  return {root,token,shim,inventory:join(root,'inventory.json'),capture:join(root,'capture.json')};
}
function start(t,f,peer,args) {
  const child=spawn(process.execPath,['--import',f.shim,script,...args],{env:{...process.env,FG_TEST_SOURCE:peer.origin},stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='';
  const finished=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('CLI test deadline'));},8000);
    child.stdout.on('data',b=>{stdout+=b;if(stdout.length>2**20)child.kill('SIGKILL');});child.stderr.on('data',b=>stderr+=b);
    child.on('error',e=>{clearTimeout(timer);reject(e);});child.on('close',(code,signal)=>{clearTimeout(timer);resolve({code,signal,stdout,stderr});});
  });
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});return {child,finished};
}
const run=(t,f,p,args)=>start(t,f,p,args).finished;
function value(r,code=0){assert.equal(r.code,code,r.stderr);assert.equal(r.signal,null);assert.equal(r.stderr,'');return JSON.parse(r.stdout);}
const discover=f=>['discover','--repository',REPO,'--out',f.inventory,'--token-file',f.token,'--batch-size','1'];
const captured=(f,pin)=>['capture-batch','--inventory',f.inventory,'--confirm',pin,'--batch','2','--out',f.capture,'--token-file',f.token];

test('real CLI discovers, inspects a pin and writes an ordinary migration capture',async t=>{
  const f=await files(t),p=await inventoryPeer(t,{records:1}),d=value(await run(t,f,p,discover(f)));
  assert.equal(d.pulls,2);assert.equal(d.total_batches,2);assert.equal(d.mutation_submitted,false);
  const i=value(await run(t,f,p,['inspect','--inventory',f.inventory,'--confirm',d.inventory_sha256,'--batch','2']));
  assert.equal(i.network_accessed,false);assert.deepEqual(i.selection.numbers,[17]);
  const c=value(await run(t,f,p,captured(f,d.inventory_sha256)));assert.equal(c.pulls,1);assert.equal(c.first_index,1);assert.equal(c.next_batch,null);
  const parsed=parseGithubPullCapture(await readFile(f.capture));assert.equal(parsed.pulls[0].pull.number,17);assert.equal(parsed.pulls[0].inline.length,1);
  await p.close();await unlink(f.token);assert.equal(value(await run(t,f,p,['inspect','--inventory',f.inventory,'--confirm',d.inventory_sha256])).pulls,2);
});
test('CLI refuses bad pin, duplicate flags, unsupported source override and decimal aliases before HTTP',async t=>{
  const f=await files(t),p=await inventoryPeer(t),d=value(await run(t,f,p,discover(f))),count=p.calls.length;
  for(const args of [
    ['inspect','--inventory',f.inventory,'--confirm','0'.repeat(64)],
    [...captured(f,d.inventory_sha256),'--batch','1'],[...captured(f,d.inventory_sha256),'--endpoint','https://evil.test'],
    [...discover(f),'--max-requests','1e2'],[...discover(f),'--batch-size','01'],
    ['capture-batch','--inventory',f.inventory,'--confirm',d.inventory_sha256,'--batch','0','--out',f.capture],['__proto__'],
  ]){const r=await run(t,f,p,args);assert.equal(r.code,2);assert.equal(r.stdout,'');assert.equal(JSON.parse(r.stderr).mutation_submitted,false);}
  assert.equal(p.calls.length,count);
});
test('CLI refuses an occupied destination before source reads and never changes it',async t=>{
  const f=await files(t),p=await inventoryPeer(t);await writeFile(f.inventory,'retained',{mode:0o600});
  const r=await run(t,f,p,discover(f));assert.equal(r.code,2);assert.equal(p.calls.length,0);assert.equal(await readFile(f.inventory,'utf8'),'retained');
});
test('CLI source rejection retains no successful inventory',async t=>{
  const f=await files(t),p=await inventoryPeer(t,{alter:s=>{if(s.kind==='listing'){s.res.writeHead(403);s.res.end('denied');return false;}}});
  const r=await run(t,f,p,discover(f));assert.equal(r.code,2);assert(!(await readdir(f.root)).includes('inventory.json'));assert.equal(p.calls.length,2);
});
for(const signal of ['SIGTERM','SIGINT','SIGKILL'])test(`actual ${signal} during source listing never publishes a complete inventory`,async t=>{
  const f=await files(t);let child,sent=false;
  const p=await inventoryPeer(t,{alter:s=>{if(s.kind==='listing'){s.res.writeHead(200,{'content-type':'application/json'});s.res.write('[');sent=child.kill(signal);return false;}}});
  const pending=start(t,f,p,discover(f));child=pending.child;const r=await pending.finished;assert.equal(sent,true);assert.equal(r.stdout,'');
  if(signal==='SIGKILL')assert.equal(r.signal,signal);else{assert.equal(r.code,2);assert.equal(r.signal,null);}
  assert(!(await readdir(f.root)).includes('inventory.json'));
});
test('broken output retains the completed inventory and does not repeat requests',async t=>{
  const f=await files(t),p=await inventoryPeer(t);let stderr='';const original=globalThis.fetch;globalThis.fetch=p.fetchImpl;
  try {
    const stdout=new Writable({write(_b,_e,cb){cb(Error('broken pipe'));}}),errors=new Writable({write(b,_e,cb){stderr+=b;cb();}});
    assert.equal(await main(discover(f),{stdout,stderr:errors}),4);const r=JSON.parse(stderr).retained_result;assert(r.inventory_sha256);
    assert.equal(p.calls.length,6);assert.equal(value(await run(t,f,p,['inspect','--inventory',f.inventory,'--confirm',r.inventory_sha256])).pulls,2);
  } finally {globalThis.fetch=original;}
});
test('help documents the separate membership and capture meanings',async t=>{
  const f=await files(t),p=await inventoryPeer(t),r=value(await run(t,f,p,['--help']));assert.match(r.usage,/NOT|not an atomic/);assert.match(r.usage,/capture-batch/);assert.equal(p.calls.length,0);
});
