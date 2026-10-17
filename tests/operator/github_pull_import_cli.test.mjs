import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile,writeFile,unlink,readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { main } from '../../scripts/migrate_github_pulls.mjs';
import { migrationFixture,ROTATED } from './github-pull-import-fixture.mjs';
import { parseGithubPullCapture } from '../../scripts/lib/github-pull-source.mjs';
import { pullHash } from '../../scripts/operator/pull_command.mjs';
const script=new URL('../../scripts/migrate_github_pulls.mjs',import.meta.url).pathname;
function start(t,args){const child=spawn(process.execPath,[script,...args]);let stdout='',stderr='';
 const done=new Promise((resolve,reject)=>{const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('CLI test deadline'));},10000);
  child.stdout.on('data',b=>{stdout+=b;if(stdout.length>1024*1024)child.kill('SIGKILL');});child.stderr.on('data',b=>stderr+=b);
  child.once('error',e=>{clearTimeout(timer);reject(e);});child.once('close',(code,signal)=>{clearTimeout(timer);resolve({code,signal,stdout,stderr});});});
 t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});return {child,done};}
const run=(t,args)=>start(t,args).done;
function value(r,code=0){assert.equal(r.code,code,r.stderr);assert.equal(r.signal,null);assert.equal(r.stderr,'');return JSON.parse(r.stdout);}
const args=(f,verb)=>[verb,'--workdir',f.workdir,'--confirm',f.prepared.plan_sha256];
const sendArgs=(f,verb='run')=>[...args(f,verb),'--token-file',f.tokenFile];

test('CLI prepares and executes capture as original native PRs with offline branch requirements',async t=>{
 const f=await migrationFixture(t,{prepare:false}),selection=join(f.root,'selection.json');await writeFile(selection,JSON.stringify(f.input.selection),{mode:0o600});
 f.prepared=value(await run(t,['prepare','--workdir',f.workdir,'--capture',f.captureFile,'--capture-confirm',f.captured.sha256,'--selection',selection,'--token-file',f.tokenFile]));
 assert.equal(f.peer.calls.length,0);assert.equal(f.prepared.steps,5);
 const branch=join(f.root,'branches.json'),requirements=value(await run(t,[...args(f,'requirements'),'--principal','77'.repeat(16),'--out',branch]));
 const branchBytes=await readFile(branch),selected=JSON.parse(branchBytes);assert.equal(pullHash(branchBytes),requirements.requirements_sha256);
 assert.equal(selected.scope.principal_id,'77'.repeat(16));assert.equal(selected.namespace,f.input.selection.namespace);assert.equal(selected.refs.length,2);
 assert.equal(value(await run(t,args(f,'inspect'))).capture_sha256,f.captured.sha256);
 const paused=value(await run(t,[...sendArgs(f),'--max-operations','1']),3);assert.equal(paused.committed_steps,1);
 const done=value(await run(t,sendArgs(f)));assert.equal(done.complete,true);assert.equal(f.peer.mutations.length,5);
 await unlink(f.captureFile);await unlink(f.tokenFile);await f.peer.close();
 assert.equal(value(await run(t,args(f,'status'))).complete,true);assert.equal(value(await run(t,args(f,'run'))).complete,true);
});
for(const signal of ['SIGTERM','SIGINT','SIGKILL'])test(`fresh CLI recovers after actual ${signal} during a committed reply without duplicate POST`,async t=>{
 let child,stalled=true;const f=await migrationFixture(t,{destination:{alter:c=>{if(!c.recovery&&stalled){
   c.res.writeHead(200,{'content-type':'application/json'});c.res.write('{');setTimeout(()=>child.kill(signal),10);return false;}}}});
 const before=await readFile(join(f.workdir,'requests','step-000001','intent.json'));const pending=start(t,sendArgs(f));child=pending.child;
 const r=await pending.done;assert.equal(f.peer.mutations.length,1);assert.equal(r.stdout,'');
 if(signal==='SIGKILL')assert.equal(r.signal,'SIGKILL');else {assert.equal(r.code,4);const e=JSON.parse(r.stderr);assert.equal(e.mutation_submitted,null);assert.equal(e.retained_result.current.key,f.peer.mutations[0].key);}
 stalled=false;const status=value(await run(t,args(f,'status')));assert.equal(status.state,'pending');
 const recovered=value(await run(t,sendArgs(f,'recover')),3);assert.equal(recovered.committed_steps,1);assert.equal(f.peer.mutations.length,1);
 const completed=value(await run(t,sendArgs(f)));assert.equal(completed.complete,true);assert.equal(f.peer.mutations.length,5);
 assert((await readFile(join(f.workdir,'requests','step-000001','intent.json'))).equals(before));
});
test('native refusal has explicit exit code and retained current key',async t=>{
 const f=await migrationFixture(t,{destination:{alter:c=>{if(!c.recovery)Object.assign(c.value,{outcome:'refused',repository_commit_id:null,refusal_record_id:'no',refusal_code:'RefMismatch',refusal_code_point:1});}}});
 const r=value(await run(t,sendArgs(f)),1);assert.equal(r.state,'refused');assert.equal(r.complete,false);assert.equal(f.peer.mutations.length,1);
});
test('broken output retains the completed migration rather than resending',async t=>{
 const f=await migrationFixture(t);let err='';const output=new Writable({write(_b,_e,cb){cb(new Error('test broken pipe'));}}),errors=new Writable({write(b,_e,cb){err+=b;cb();}});
 const code=await main(sendArgs(f),{stdout:output,stderr:errors});assert.equal(code,4);const e=JSON.parse(err);assert.equal(e.retained_result.complete,true);
 const count=f.peer.calls.length;assert.equal(value(await run(t,sendArgs(f))).complete,true);assert.equal(f.peer.calls.length,count);
});
test('no dynamic loader, field refresh, inline credential or implicit conversion option',async t=>{
 const f=await migrationFixture(t);for(const extra of [['--loader','evil'],['--force','true'],['--token','secret'],['--max-operations','1e2'],['--principal','alice']]){
  const r=await run(t,[...sendArgs(f),...extra]);assert.equal(r.code,2);assert.equal(r.stdout,'');
 }assert.equal(f.peer.calls.length,0);
});
test('prepare source tamper and invalid native metadata do not create a job',async t=>{
 const f=await migrationFixture(t,{prepare:false}),selection=join(f.root,'selection.json');await writeFile(selection,JSON.stringify(f.input.selection),{mode:0o600});
 await writeFile(f.captureFile,'{}\n');const r=await run(t,['prepare','--workdir',f.workdir,'--capture',f.captureFile,'--capture-confirm',f.captured.sha256,'--selection',selection,'--token-file',f.tokenFile]);
 assert.equal(r.code,2);assert.equal(f.peer.calls.length,0);await assert.rejects(readdir(f.workdir));
});
