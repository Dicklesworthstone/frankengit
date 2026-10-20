import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { readFile,writeFile,rm,unlink,stat } from 'node:fs/promises';
import { main } from '../../scripts/migrate_github_pull_collection.mjs';
import { executeGithubPullMigration } from '../../scripts/lib/github-pull-migration.mjs';
import { wholeMigrationFixture,childPath } from './github-pull-migration-fixture.mjs';
const script=fileURLToPath(new URL('../../scripts/migrate_github_pull_collection.mjs',import.meta.url));
function start(t,args) {
  const child=spawn(process.execPath,[script,...args],{stdio:['ignore','pipe','pipe']});let stdout='',stderr='';
  const exited=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('CLI test deadline'));},30000);
    child.stdout.on('data',s=>{stdout+=s;if(stdout.length>8*1024*1024)child.kill('SIGKILL');});
    child.stderr.on('data',s=>{stderr+=s;if(stderr.length>8*1024*1024)child.kill('SIGKILL');});
    child.once('error',e=>{clearTimeout(timer);reject(e);});
    child.once('close',(code,signal)=>{clearTimeout(timer);resolve({code,signal,stdout,stderr});});
  });
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});return {child,exited};
}
const run=(t,args)=>start(t,args).exited;
function value(r,code=0){assert.equal(r.code,code,r.stderr);assert.equal(r.signal,null);assert.equal(r.stderr,'');return JSON.parse(r.stdout);}
const args=(f,op='run')=>[op,'--workdir',f.workdir,'--confirm',f.prepared.plan_sha256];
const send=f=>[...args(f),'--token-file',f.tokenFile];
async function preparation(f) {
  const selected=join(f.root,'destination.json');await writeFile(selected,JSON.stringify(f.input.selection),{mode:0o600});
  return ['prepare','--collection-dir',f.collectionDir,'--collection-confirm',f.input.collectionConfirm,
    '--complete-confirm',f.input.completeConfirm,'--selection',selected,'--workdir',f.workdir,'--token-file',f.tokenFile];
}

test('actual CLI prepares a whole plan, derives requirements, pauses across batches and finishes',async t=>{
  const f=await wholeMigrationFixture(t,{prepare:false});f.prepared=value(await run(t,await preparation(f)));
  assert.equal(f.prepared.steps,15);assert.equal(f.peer.calls.length,0);
  const inspected=value(await run(t,args(f,'inspect')));assert.equal(inspected.current.batch,1);assert.equal(inspected.local_read_only,true);
  const batch=value(await run(t,[...args(f,'batch'),'--batch','2']));assert.equal(batch.destination_number_start,'101');
  const out=join(f.root,'branches.json'),r=value(await run(t,[...args(f,'requirements'),'--batch','2','--principal','77'.repeat(16),'--out',out]));
  assert.equal(r.selection.scope.principal_id,'77'.repeat(16));assert.equal(r.selection.refs.length,2);
  assert.deepEqual(JSON.parse(await readFile(out,'utf8')),r.selection);
  await rm(f.collectionDir,{recursive:true});
  const paused=value(await run(t,[...send(f),'--max-operations','6']),3);assert.equal(paused.committed_steps,6);assert.equal(paused.current.batch,2);
  const done=value(await run(t,send(f)));assert.equal(done.complete,true);assert.equal(f.peer.mutations.length,15);
  await f.peer.close();await unlink(f.tokenFile);
  assert.equal(value(await run(t,args(f))).complete,true);assert.equal(value(await run(t,args(f,'status'))).network_accessed,false);
});
for(const signal of ['SIGTERM','SIGINT','SIGKILL'])test(`actual ${signal} in a later batch recovers original key with no duplicate mutation`,async t=>{
  let child,block=true,killed=false;
  const f=await wholeMigrationFixture(t,{destination:{alter:c=>{
    if(block&&!c.recovery&&c.number==='101'&&c.action==='open') {
      c.res.writeHead(200,{'content-type':'application/json'});c.res.write('{');
      setImmediate(()=>{killed=child.kill(signal);});return false;
    }
  }}});
  const first=await readFile(join(childPath(f,0),'requests','step-000001','intent.json'));
  const pending=start(t,send(f));child=pending.child;const stopped=await pending.exited;block=false;
  assert(killed);assert.equal(stopped.stdout,'');
  if(signal==='SIGKILL'){assert.equal(stopped.signal,'SIGKILL');assert.equal(stopped.code,null);}
  else {assert.equal(stopped.code,4);assert.equal(stopped.signal,null);assert.equal(JSON.parse(stopped.stderr).outcome_unknown,true);}
  const status=value(await run(t,args(f,'status')));assert.equal(status.committed_batches,1);assert.equal(status.current.batch,2);assert.equal(status.state,'pending');
  assert.equal(f.peer.mutations.length,6);const key=status.current.key;
  const recovered=value(await run(t,[...args(f,'recover'),'--token-file',f.tokenFile]),3);
  assert.equal(recovered.committed_steps,6);assert.equal(f.peer.mutations.length,6);
  const done=value(await run(t,send(f)));assert.equal(done.complete,true);assert.equal(f.peer.mutations.length,15);
  assert.equal(f.peer.calls.filter(c=>!c.recovery&&c.key===key).length,1);
  assert((await readFile(join(childPath(f,0),'requests','step-000001','intent.json'))).equals(first));
});
test('actual CLI returns native refusal separately from unresolved execution',async t=>{
  const f=await wholeMigrationFixture(t,{destination:{alter:c=>{
    if(!c.recovery&&c.number==='101')Object.assign(c.value,{outcome:'refused',repository_commit_id:null,
      refusal_record_id:'refused',refusal_code:'RefMismatch',refusal_code_point:1});
  }}});
  const r=value(await run(t,send(f)),1);assert.equal(r.state,'refused');assert.equal(r.committed_batches,1);assert.equal(f.peer.mutations.length,6);
});
test('broken prepare output retains the complete outer plan and never creates replacement keys',async t=>{
  const f=await wholeMigrationFixture(t,{prepare:false});let diagnostic='';
  const stdout=new Writable({write(_c,_e,cb){cb(new Error('broken pipe'));}}),stderr=new Writable({write(c,_e,cb){diagnostic+=c;cb();}});
  assert.equal(await main(await preparation(f),{stdout,stderr}),4);assert.equal(f.peer.calls.length,0);
  f.prepared=JSON.parse(diagnostic).retained_result;assert(f.prepared.plan_sha256);
  const done=value(await run(t,send(f)));assert.equal(done.complete,true);assert.equal(f.peer.mutations.length,15);
});
test('broken execution output retains committed results and replay performs no new POST',async t=>{
  const f=await wholeMigrationFixture(t);let diagnostic='';
  const stdout=new Writable({write(_c,_e,cb){cb(new Error('broken pipe'));}}),stderr=new Writable({write(c,_e,cb){diagnostic+=c;cb();}});
  assert.equal(await main(send(f),{stdout,stderr}),4);assert.equal(JSON.parse(diagnostic).retained_result.complete,true);
  assert.equal(f.peer.mutations.length,15);assert.equal(value(await run(t,send(f))).complete,true);assert.equal(f.peer.mutations.length,15);
});
test('argument grammar rejects overrides and noncanonical budgets before HTTP',async t=>{
  const f=await wholeMigrationFixture(t);
  for(const extra of [['--force','true'],['--max-operations','0'],['--max-operations','01'],['--max-operations','1e2'],
    ['--max-operations','8193'],['--timeout-ms','NaN'],['--confirm',f.prepared.plan_sha256]]) {
    const refused=await run(t,[...send(f),...extra]);assert.equal(refused.code,2);assert.equal(refused.stdout,'');
  }
  for(const command of ['__proto__','constructor','unknown'])assert.equal((await run(t,[command])).code,2);
  assert.equal(f.peer.calls.length,0);
});
test('requirements output is create-only and needs an independent valid branch principal',async t=>{
  const f=await wholeMigrationFixture(t),out=join(f.root,'occupied.json');await writeFile(out,'original',{mode:0o600});
  const command=[...args(f,'requirements'),'--batch','1','--principal','77'.repeat(16),'--out',out];
  assert.equal((await run(t,command)).code,2);assert.equal(await readFile(out,'utf8'),'original');
  assert.equal((await run(t,[...args(f,'requirements'),'--batch','1','--principal','bad','--out',join(f.root,'new.json')])).code,2);
  assert.equal(f.peer.calls.length,0);
});
test('status emits no unescaped terminal controls and never reads a token',async t=>{
  const f=await wholeMigrationFixture(t);await unlink(f.tokenFile);const before=f.peer.calls.length;
  const r=await run(t,args(f,'status'));assert.equal(value(r).network_accessed,false);assert(!/[\x00-\x08\x1b\x7f-\x9f]/.test(r.stdout));
  assert.equal(f.peer.calls.length,before);
});
test('help distinguishes source completion and destination plan pins',async t=>{
  const r=value(await run(t,['--help']));assert.match(r.usage,/COLLECTION_COMPLETE_SHA256/);assert.match(r.usage,/MIGRATION_SHA256/);
});

test('actual SIGTERM during preparation retains partial child keys but no executable outer root',async t=>{
  const f=await wholeMigrationFixture(t,{prepare:false,pulls:[1,2,3,4,5,6,7,8]}),command=await preparation(f);
  const processRun=start(t,command),first=join(childPath(f,0),'manifest.json'),until=Date.now()+10000;
  for(;;){
    const found=await stat(first).then(()=>true,e=>{if(e.code==='ENOENT')return false;throw e;});
    if(found)break;
    if(Date.now()>=until)assert.fail('first child did not publish');
    await new Promise(r=>setTimeout(r,2));
  }
  assert(processRun.child.kill('SIGTERM'));const stopped=await processRun.exited;
  assert.equal(stopped.code,4,stopped.stderr);assert.equal(stopped.stdout,'');
  await assert.rejects(stat(join(f.workdir,'manifest.json')),{code:'ENOENT'});
  const intent=join(childPath(f,0),'requests','step-000001','intent.json'),before=await readFile(intent);
  const refused=await run(t,command);assert.equal(refused.code,2);assert((await readFile(intent)).equals(before));
  assert.equal(f.peer.calls.length,0);
});
