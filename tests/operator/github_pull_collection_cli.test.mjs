import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { writeFile, readFile, unlink, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { main } from '../../scripts/collect_github_pulls.mjs';
import { inspectGithubPullCollection } from '../../scripts/lib/github-pull-collection.mjs';
import { parseGithubPullCapture } from '../../scripts/lib/github-pull-source.mjs';
import { collectionFixture } from './github-pull-collection-fixture.mjs';

const script=fileURLToPath(new URL('../../scripts/collect_github_pulls.mjs',import.meta.url));
async function fixture(t,source={}) {
  const f=await collectionFixture(t,source),shim=join(f.root,'peer.mjs');
  // Only the test harness maps the fixed GitHub origin to a local schema peer.
  // The product accepts neither this module path nor an alternate source URL.
  await writeFile(shim,`const request=globalThis.fetch;globalThis.fetch=async(input,options)=>{const u=new URL(input);if(u.origin!=='https://api.github.com')throw Error('foreign source');const r=await request(process.env.FG_TEST_SOURCE+u.pathname+u.search,options);return new Response(r.body,{status:r.status,headers:r.headers});};`,{mode:0o600});
  return {...f,shim};
}
function start(t,f,args) {
  const child=spawn(process.execPath,['--import',f.shim,script,...args],{env:{...process.env,FG_TEST_SOURCE:f.origin},stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='';
  const finished=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('CLI test deadline'));},10000);
    child.stdout.on('data',b=>{stdout+=b;if(stdout.length>2**20)child.kill('SIGKILL');});
    child.stderr.on('data',b=>{stderr+=b;if(stderr.length>2**20)child.kill('SIGKILL');});
    child.once('error',e=>{clearTimeout(timer);reject(e);});
    child.once('close',(code,signal)=>{clearTimeout(timer);resolve({code,signal,stdout,stderr});});
  });
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
  return {child,finished};
}
const run=(t,f,args)=>start(t,f,args).finished;
const args=(f,operation='run')=>[operation,'--workdir',f.workdir,'--confirm',f.prepared.plan_sha256];
const collect=f=>[...args(f),'--token-file',f.tokenFile];
function result(raw,code=0) {
  assert.equal(raw.code,code,raw.stderr);assert.equal(raw.signal,null);assert.equal(raw.stderr,'');
  assert.equal(raw.stdout.trim().split('\n').length,1);return JSON.parse(raw.stdout);
}

test('actual CLI prepares, pauses, completes and selects a pinned native-compatible batch',async t=>{
  const f=await fixture(t,{records:1}),newJob=join(f.root,'cli-job');
  const p=result(await run(t,f,['prepare','--inventory',f.inventoryFile,'--inventory-confirm',f.inventory.sha256,'--workdir',newJob]));
  assert.equal(p.network_accessed,false);assert.equal(p.complete,false);assert.equal(p.plan_sha256,f.prepared.plan_sha256);
  f.workdir=newJob;f.prepared=p;
  const paused=result(await run(t,f,[...collect(f),'--max-batches','1']),3);
  assert.equal(paused.complete,false);assert.equal(paused.checkpointed_batches,1);assert.equal(paused.next_batch,2);
  const done=result(await run(t,f,collect(f)));assert.equal(done.complete,true);assert.equal(done.new_batches,1);
  assert.equal(f.calls.filter(c=>c.kind==='pull'&&c.n===9).length,4);
  const selected=result(await run(t,f,[...args(f,'batch'),'--complete-confirm',done.complete_sha256,'--batch','2','--number-start','18446744073709551614']));
  assert.equal(selected.destination_number_start,'18446744073709551615');assert.deepEqual(selected.numbers,[17]);
  const capture=parseGithubPullCapture(await readFile(selected.capture_file));assert.equal(capture.pulls[0].pull.number,17);assert.equal(capture.pulls[0].inline.length,1);
  await unlink(f.tokenFile);await unlink(f.inventoryFile);await f.close();
  const inspected=result(await run(t,f,[...args(f,'status'),'--complete-confirm',done.complete_sha256]));assert.equal(inspected.network_accessed,false);
  const repeated=result(await run(t,f,args(f)));assert.equal(repeated.network_accessed,false);assert.equal(repeated.new_batches,0);assert.equal(repeated.complete_sha256,done.complete_sha256);
});
for(const signal of ['SIGTERM','SIGINT','SIGKILL'])test(`fresh process resumes after actual ${signal} without recapturing an earlier batch`,async t=>{
  let child,block=false,sent=false;
  const f=await fixture(t,{records:1,alter:s=>{if(block&&s.n===17&&s.kind==='reviews'){
    s.res.writeHead(200,{'content-type':'application/json'});s.res.write('[');sent=child.kill(signal);return false;
  }}});
  block=true;const pending=start(t,f,collect(f));child=pending.child;const stopped=await pending.finished;
  assert.equal(sent,true);assert.equal(stopped.stdout,'');
  if(signal==='SIGKILL'){assert.equal(stopped.signal,signal);assert.equal(stopped.code,null);}
  else {assert.equal(stopped.signal,null);assert.equal(stopped.code,4);assert.equal(JSON.parse(stopped.stderr).collection_progress.plan_verified,true);}
  block=false;const status=result(await run(t,f,args(f,'status')));assert.equal(status.checkpointed_batches,1);assert.equal(status.complete,false);
  const bytes=await readFile(join(f.workdir,'captures','batch-000001.json'));
  const done=result(await run(t,f,collect(f)));assert.equal(done.complete,true);assert.equal(done.new_batches,1);
  assert.equal(f.calls.filter(c=>c.kind==='pull'&&c.n===9).length,4);
  assert((await readFile(join(f.workdir,'captures','batch-000001.json'))).equals(bytes));
});
test('CLI deadline leaves the preceding checkpoint and no false completion',async t=>{
  let block=false;const f=await fixture(t,{alter:s=>{if(block&&s.kind==='reviews'){s.res.writeHead(200,{'content-type':'application/json'});s.res.write('[');return false;}}});
  result(await run(t,f,[...collect(f),'--max-batches','1']),3);block=true;
  const stopped=await run(t,f,[...collect(f),'--timeout-ms','100']);assert.equal(stopped.code,4);assert.equal(stopped.stdout,'');
  const s=result(await run(t,f,args(f,'status')));assert.equal(s.checkpointed_batches,1);assert.equal(s.complete,false);
  assert(!(await readdir(f.workdir)).includes('complete.json'));
});
test('an existing collection cannot be overwritten by CLI preparation',async t=>{
  const f=await fixture(t),before=await readFile(join(f.workdir,'plan.json')),count=f.calls.length;
  const rejected=await run(t,f,['prepare','--inventory',f.inventoryFile,'--inventory-confirm',f.inventory.sha256,'--workdir',f.workdir]);
  assert.equal(rejected.code,2);assert.equal(rejected.stdout,'');assert.equal(f.calls.length,count);assert((await readFile(join(f.workdir,'plan.json'))).equals(before));
});
test('closed CLI arguments and bad pins refuse before source reads',async t=>{
  const f=await fixture(t),count=f.calls.length;
  for(const argv of [
    ['run','--workdir',f.workdir,'--confirm','0'.repeat(64)],
    [...collect(f),'--max-batches','01'],[...collect(f),'--max-batches','1e2'],[...collect(f),'--max-batches','0'],
    [...collect(f),'--max-capture-bytes','1'],[...collect(f),'--endpoint','https://evil.test'],[...collect(f),'--confirm',f.prepared.plan_sha256],
    [...args(f,'batch'),'--batch','1'],['__proto__'],
  ]){const rejected=await run(t,f,argv);assert.equal(rejected.code,2);assert.equal(rejected.stdout,'');assert.equal(JSON.parse(rejected.stderr).mutation_submitted,false);}
  assert.equal(f.calls.length,count);
});
test('output failure preserves the final content pin without additional source requests',async t=>{
  const f=await fixture(t),source=globalThis.fetch;let stderr='';globalThis.fetch=f.fetchImpl;
  try {
    const stdout=new Writable({write(_b,_e,callback){callback(Error('broken pipe'));}});
    const errors=new Writable({write(b,_e,callback){stderr+=b;callback();}});
    assert.equal(await main(collect(f),{stdout,stderr:errors}),4);
    const retained=JSON.parse(stderr).retained_result;assert.equal(retained.complete,true);assert(retained.complete_sha256);
    const count=f.calls.length,s=await inspectGithubPullCollection({...f.status,completeConfirm:retained.complete_sha256});
    assert.equal(s.complete,true);assert.equal(f.calls.length,count);assert.equal(f.calls.filter(c=>c.kind==='pull').length,8);
  } finally {globalThis.fetch=source;}
});
test('help distinguishes source collection, pauses and completion pin',async t=>{
  const f=await fixture(t),count=f.calls.length,r=result(await run(t,f,['--help']));
  assert.match(r.usage,/COMPLETE_SHA256/);assert.match(r.usage,/3: run paused/);assert.match(r.usage,/No native writes/);assert.equal(f.calls.length,count);
});
