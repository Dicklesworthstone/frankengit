import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile,writeFile,unlink,readdir,mkdir,symlink,access } from 'node:fs/promises';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { main } from '../../scripts/migrate_github_pulls.mjs';
import { migrationFixture,ROTATED } from './github-pull-import-fixture.mjs';
import { parseGithubPullCapture } from '../../scripts/lib/github-pull-source.mjs';
import { pullHash } from '../../scripts/operator/pull_command.mjs';
const script=new URL('../../scripts/migrate_github_pulls.mjs',import.meta.url).pathname;
function start(t,args,preload){const child=spawn(process.execPath,[...(preload?['--import',preload]:[]),script,...args]);let stdout='',stderr='';
 const done=new Promise((resolve,reject)=>{const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('CLI test deadline'));},10000);
  child.stdout.on('data',b=>{stdout+=b;if(stdout.length>1024*1024)child.kill('SIGKILL');});child.stderr.on('data',b=>stderr+=b);
  child.once('error',e=>{clearTimeout(timer);reject(e);});child.once('close',(code,signal)=>{clearTimeout(timer);resolve({code,signal,stdout,stderr});});});
 t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});return {child,done};}
const run=(t,args,preload)=>start(t,args,preload).done;
function value(r,code=0){assert.equal(r.code,code,r.stderr);assert.equal(r.signal,null);assert.equal(r.stderr,'');return JSON.parse(r.stdout);}
const args=(f,verb)=>[verb,'--workdir',f.workdir,'--confirm',f.prepared.plan_sha256];
const sendArgs=(f,verb='run')=>[...args(f,verb),'--token-file',f.tokenFile];

for(const field of ['selection','requirements'])test(`worktree parent aliases cannot hide migration ${field} paths`,async t=>{
 const f=await migrationFixture(t,{prepare:field==='requirements'}),repo=join(f.root,'worktree'),privateDir=join(repo,'private'),alias=join(f.root,'alias');
 await mkdir(repo,{mode:0o700});await mkdir(join(repo,'.git'));await mkdir(privateDir,{mode:0o700});await symlink(privateDir,alias);
 let command;
 if(field==='selection'){
  await writeFile(join(privateDir,'selection.json'),JSON.stringify(f.input.selection),{mode:0o600});
  command=['prepare','--workdir',f.workdir,'--capture',f.captureFile,'--capture-confirm',f.captured.sha256,
   '--selection',join(alias,'selection.json'),'--token-file',f.tokenFile];
 }else command=[...args(f,'requirements'),'--principal','77'.repeat(16),'--out',join(alias,'branches.json')];
 const r=await run(t,command);assert.equal(r.code,2);assert.equal(r.stdout,'');
 assert.equal(JSON.parse(r.stderr).code,'github_pull_worktree');assert.equal(f.peer.calls.length,0);
 await assert.rejects(access(field==='selection'?f.workdir:join(privateDir,'branches.json')),{code:'ENOENT'});
});

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

async function preparationArgs(f) {
 const selection=join(f.root,'selection.json');await writeFile(selection,JSON.stringify(f.input.selection),{mode:0o600});
 return ['prepare-begin','--workdir',f.workdir,'--capture',f.captureFile,'--capture-confirm',f.captured.sha256,
  '--selection',selection,'--token-file',f.tokenFile];
}
const draftArgs=(f,verb,pin)=>[verb,'--workdir',f.workdir,'--confirm',pin];

test('restartable CLI preserves its bounded prefix without source, credential or destination access',async t=>{
 const f=await migrationFixture(t,{prepare:false}),beginArgs=await preparationArgs(f);
 const begun=value(await run(t,beginArgs));
 assert.equal(begun.preparation_complete,false);assert.equal(begun.execution_complete,false);
 assert.equal(begun.network_accessed,false);assert.equal(begun.mutation_submitted,false);
 const pin=begun.preparation_sha256,header=await readFile(join(f.workdir,'preparation.json'));
 const duplicate=await run(t,beginArgs);assert.equal(duplicate.code,2);
 assert.equal(JSON.parse(duplicate.stderr).code,'github_pull_preparation_exists');
 assert((await readFile(join(f.workdir,'preparation.json'))).equals(header));
 const prefix=value(await run(t,[...draftArgs(f,'prepare-resume',pin),'--max-requests','1']),3);
 assert.equal(prefix.prepared_steps,1);assert.equal(prefix.new_steps,1);assert.equal(prefix.preparation_complete,false);
 assert.equal(prefix.mutation_submitted,false);assert.equal(prefix.execution_complete,false);
 const request=join(f.workdir,'import/requests/step-000001/intent.json'),original=await readFile(request);
 await assert.rejects(readFile(join(f.workdir,'import/manifest.json')),{code:'ENOENT'});
 await unlink(f.captureFile);await unlink(f.tokenFile);assert.equal(f.peer.calls.length,0);await f.peer.close();
 for(const verb of ['prepare-status','prepare-resume']){
  const refused=await run(t,draftArgs(f,verb,'0'.repeat(64)));assert.equal(refused.code,2);
  assert.equal(JSON.parse(refused.stderr).code,'github_pull_preparation_pin_mismatch');
  assert((await readFile(request)).equals(original));
 }
 const status=value(await run(t,draftArgs(f,'prepare-status',pin)));
 assert.equal(status.prepared_steps,1);assert.equal(status.local_read_only,true);assert.equal(status.preparation_complete,false);
 const complete=value(await run(t,draftArgs(f,'prepare-resume',pin)));
 assert.equal(complete.preparation_complete,true);assert.equal(complete.plan_sha256,begun.plan_sha256);
 assert.equal(complete.new_steps,complete.steps-1);assert.equal(complete.network_accessed,false);
 assert((await readFile(request)).equals(original));
 const inspected=value(await run(t,['inspect','--workdir',complete.import_workdir,'--confirm',complete.plan_sha256]));
 assert.equal(inspected.capture_sha256,f.captured.sha256);
 const repeated=value(await run(t,draftArgs(f,'prepare-resume',pin)));
 assert.equal(repeated.new_steps,0);assert.equal(repeated.plan_sha256,complete.plan_sha256);
 assert((await readFile(request)).equals(original));assert((await readFile(join(f.workdir,'preparation.json'))).equals(header));
});

test('restartable CLI produces an ordinary job for the existing sender and remains inspectable after execution',async t=>{
 const f=await migrationFixture(t,{prepare:false}),begun=value(await run(t,await preparationArgs(f)));
 const ready=value(await run(t,draftArgs(f,'prepare-resume',begun.preparation_sha256)));
 const original=await readFile(join(ready.import_workdir,'requests/step-000001/intent.json'));
 const common=['--workdir',ready.import_workdir,'--confirm',ready.plan_sha256];
 const done=value(await run(t,['run',...common,'--token-file',f.tokenFile]));
 assert.equal(done.complete,true);assert.equal(f.peer.mutations.length,ready.steps);
 await unlink(f.tokenFile);await f.peer.close();
 for(const verb of ['prepare-status','prepare-resume']){
  const status=value(await run(t,draftArgs(f,verb,begun.preparation_sha256)));
  assert.equal(status.preparation_complete,true);assert.equal(status.execution_complete,false);
  assert.equal(status.mutation_submitted,false);assert.equal(status.network_accessed,false);
 }
 assert((await readFile(join(ready.import_workdir,'requests/step-000001/intent.json'))).equals(original));
 assert.equal(value(await run(t,['run',...common])).complete,true);
});

test('restartable CLI keeps request-budget grammar closed and refuses wrong options before preparing slots',async t=>{
 const f=await migrationFixture(t,{prepare:false}),begun=value(await run(t,await preparationArgs(f)));
 for(const extra of [['--max-requests','0'],['--max-requests','8193'],['--max-requests','1.5'],['--max-requests','1e2'],
  ['--max-requests','1','--max-requests','2'],['--token-file',f.tokenFile],['--max-operations','1'],['--retry-key','invented']]){
  const r=await run(t,[...draftArgs(f,'prepare-resume',begun.preparation_sha256),...extra]);
  assert.equal(r.code,2);assert.equal(r.stdout,'');
 }
 for(const extra of [['--max-requests','1'],['--token-file',f.tokenFile],['--capture',f.captureFile]]){
  const r=await run(t,[...draftArgs(f,'prepare-status',begun.preparation_sha256),...extra]);assert.equal(r.code,2);
 }
 assert.deepEqual(await readdir(join(f.workdir,'import/requests')),[]);assert.equal(f.peer.calls.length,0);
 assert.equal(value(await run(t,draftArgs(f,'prepare-resume',begun.preparation_sha256))).preparation_complete,true);
});

test('restartable CLI preserves the preparation pin when output fails after beginning',async t=>{
 const f=await migrationFixture(t,{prepare:false});let text='';
 const output=new Writable({write(_b,_e,cb){cb(new Error('broken preparation output'));}});
 const errors=new Writable({write(b,_e,cb){text+=b;cb();}});
 const code=await main(await preparationArgs(f),{stdout:output,stderr:errors});assert.equal(code,4);
 const report=JSON.parse(text);assert.equal(report.retained_result.preparation_complete,false);
 assert.equal(report.mutation_submitted,false);assert.equal(report.outcome_unknown,false);
 const pin=report.retained_result.preparation_sha256;
 assert.equal(value(await run(t,draftArgs(f,'prepare-resume',pin))).preparation_complete,true);
 assert.equal(f.peer.calls.length,0);
});

test('restartable CLI exposes all offline phases in installed help',async t=>{
 const result=value(await run(t,['--help']));
 for(const command of ['prepare-begin','prepare-resume','prepare-status'])assert.ok(result.usage.includes(command));
});

test('restartable CLI retains verified preparation custody after a filesystem write fault',async t=>{
 const f=await migrationFixture(t,{prepare:false}),begun=value(await run(t,await preparationArgs(f)));
 const pending=join(f.workdir,'pending/request'),header=await readFile(join(f.workdir,'preparation.json'));
 // A test-only syscall fault is portable to privileged test runners, where a
 // chmod-based write refusal would not be reliable. No native reply is replaced.
 const preload=join(f.root,'write-fault.mjs');
 await writeFile(preload,`import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
const mkdir=fs.promises.mkdir;
fs.promises.mkdir=async function(path,...args){
 if(path===${JSON.stringify(pending)}){const e=new Error('controlled preparation write fault');e.code='EIO';throw e;}
 return mkdir.call(this,path,...args);
};
syncBuiltinESMExports();\n`,{mode:0o600});
 const r=await run(t,draftArgs(f,'prepare-resume',begun.preparation_sha256),preload);assert.equal(r.code,4);
 const report=JSON.parse(r.stderr);assert.equal(report.code,'EIO');
 assert.equal(report.preparation_progress.preparation_sha256,begun.preparation_sha256);
 assert.equal(report.preparation_progress.preparation_verified,true);assert.equal(report.preparation_progress.new_steps,0);
 assert.equal(report.mutation_submitted,false);assert.equal(report.outcome_unknown,false);
 assert((await readFile(join(f.workdir,'preparation.json'))).equals(header));
 assert.equal(value(await run(t,draftArgs(f,'prepare-resume',begun.preparation_sha256))).preparation_complete,true);
 assert.equal(f.peer.calls.length,0);
});

test('restartable CLI cancellation before begin creates no custody and a later permitted begin succeeds',async t=>{
 const f=await migrationFixture(t,{prepare:false}),beginArgs=await preparationArgs(f);let text='';
 const output=new Writable({write(_b,_e,cb){cb();}}),errors=new Writable({write(b,_e,cb){text+=b;cb();}});
 const code=await main(beginArgs,{stdout:output,stderr:errors,signal:AbortSignal.abort()});
 assert.equal(code,2);assert.equal(JSON.parse(text).mutation_submitted,false);
 await assert.rejects(readdir(f.workdir),{code:'ENOENT'});assert.equal(f.peer.calls.length,0);
 assert.equal(value(await run(t,beginArgs)).preparation_complete,false);
});

test('one-shot CLI encoded capacity preflight creates no custody and the exact byte limit remains usable',async t=>{
 const f=await migrationFixture(t),workdir=join(f.root,'exact-capacity'),selection=join(f.root,'capacity-selection.json');
 const original=await readFile(join(f.workdir,'requests/step-000001/intent.json'));
 const selected={...f.input.selection,max_request_bytes:f.prepared.request_bytes-1};
 await writeFile(selection,JSON.stringify(selected),{mode:0o600});
 const command=['prepare','--workdir',workdir,'--capture',f.captureFile,'--capture-confirm',f.captured.sha256,
  '--selection',selection,'--token-file',f.tokenFile];
 const refused=await run(t,command);assert.equal(refused.code,2);
 const report=JSON.parse(refused.stderr);assert.equal(report.code,'github_pull_import_request_limit');
 assert.equal(report.import_progress.directory_created,false);assert.equal(report.mutation_submitted,false);
 await assert.rejects(readdir(workdir),{code:'ENOENT'});assert.equal(f.peer.calls.length,0);
 assert((await readFile(join(f.workdir,'requests/step-000001/intent.json'))).equals(original));
 selected.max_request_bytes=f.prepared.request_bytes;await writeFile(selection,JSON.stringify(selected));
 const accepted=value(await run(t,command));assert.equal(accepted.request_bytes,f.prepared.request_bytes);
 const done=value(await run(t,['run','--workdir',workdir,'--confirm',accepted.plan_sha256,'--token-file',f.tokenFile]));
 assert.equal(done.complete,true);assert.equal(f.peer.mutations.length,accepted.steps);
});
