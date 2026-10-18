import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile,writeFile,unlink,mkdir,symlink,link,readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { prepareGithubPullImport,inspectGithubPullImport,executeGithubPullImport,githubPullBranchRequirements }
 from '../../scripts/lib/github-pull-import.mjs';
import { loadPullIntent } from '../../scripts/operator/pull_files.mjs';
import { migrationFixture,ROTATED,SCOPE,wire } from './github-pull-import-fixture.mjs';
const status=f=>executeGithubPullImport({workdir:f.workdir,confirm:f.prepared.plan_sha256,operation:'status'});
const intentPath=f=>join(f.workdir,'requests','step-000001','intent.json');

test('complete capture-to-plan-to-HTTP execution uses only the original native requests',async t=>{
 const f=await migrationFixture(t),before=await readFile(intentPath(f));assert.equal(f.peer.calls.length,0);assert.equal(f.prepared.steps,5);
 const i=await inspectGithubPullImport({workdir:f.workdir,confirm:f.prepared.plan_sha256});assert.equal(i.required_refs.length,2);assert.equal(i.network_accessed,false);
 await unlink(f.captureFile);const r=await executeGithubPullImport(f.run);assert.equal(r.type,'github_pull_import_progress');assert.equal(r.capture_sha256,f.captured.sha256);
 assert(!Object.hasOwn(r,'archive_sha256'));assert.equal(r.complete,true);assert.equal(r.committed_steps,5);assert.equal(f.peer.mutations.length,5);
 assert.deepEqual(f.peer.mutations.map(x=>x.action),['open','comment','comment','comment','comment']);
 assert.equal(f.peer.mutations[0].fields.body,f.captured.capture.pulls[0].pull.body);assert((await readFile(intentPath(f))).equals(before));
 await f.peer.close();await unlink(f.tokenFile);assert.equal((await executeGithubPullImport({...f.run,tokenFile:undefined})).complete,true);
 assert.equal((await status(f)).local_read_only,true);
});
test('same capture survives source/token removal and cannot be mistaken for native archive',async t=>{
 const f=await migrationFixture(t);await unlink(f.captureFile);await unlink(f.tokenFile);await f.peer.close();
 const r=await inspectGithubPullImport({workdir:f.workdir,confirm:f.prepared.plan_sha256});assert.equal(r.capture_sha256,f.captured.sha256);assert.equal(r.approvals_imported,false);
 const m=JSON.parse(await readFile(join(f.workdir,'manifest.json')));assert.equal(m.schema,'frankengit-github-pull-import-v1');assert(!Object.hasOwn(m,'archive_sha256'));
 assert.equal((await status(f)).state,'ready');
});
test('bounded batches retain the original keys and full destination u64',async t=>{
 const f=await migrationFixture(t,{select:{number_start:'18446744073709551615'}}),first=await loadPullIntent(join(f.workdir,'requests','step-000001'));
 for(let i=1;i<=5;i++){const r=await executeGithubPullImport({...f.run,maxOperations:1});assert.equal(r.committed_steps,i);assert.equal(r.complete,i===5);}
 assert.equal(f.peer.mutations[0].key,first.key);assert(f.peer.mutations.every(c=>c.number==='18446744073709551615'));assert.equal(f.peer.mutations.length,5);
});
test('lost committed reply recovers original key before moving to the next operation',async t=>{
 let lost=false;const f=await migrationFixture(t,{destination:{alter:c=>{if(!c.recovery&&!lost){lost=true;c.res.destroy();return false;}}}});
 const r=await executeGithubPullImport(f.run);assert.equal(r.state,'pending');assert.equal(f.peer.mutations.length,1);const key=r.current.key;
 const recovered=await executeGithubPullImport({...f.run,operation:'recover'});assert.equal(recovered.committed_steps,1);assert.equal(f.peer.mutations.length,1);
 assert.equal(f.peer.calls.at(-1).key,key);assert.equal(f.peer.calls.at(-1).recovery,true);
 assert.equal((await executeGithubPullImport(f.run)).complete,true);assert.equal(f.peer.mutations.filter(c=>c.key===key).length,1);
});
test('unobserved request stays fenced until exact-key retry is explicitly selected',async t=>{
 let drop=true;const f=await migrationFixture(t,{destination:{alter:c=>{if(!c.recovery&&drop){c.res.destroy();return 'not-committed';}}}});
 const r=await executeGithubPullImport(f.run),key=r.current.key;assert.equal(r.state,'pending');assert.equal(f.peer.mutations.length,0);
 drop=false;const recovered=await executeGithubPullImport(f.run);assert.equal(recovered.state,'pending');assert.equal(f.peer.mutations.length,0);
 await assert.rejects(executeGithubPullImport({...f.run,retryKey:'different'}));
 const done=await executeGithubPullImport({...f.run,retryKey:key});assert.equal(done.complete,true);assert.equal(f.peer.mutations[0].key,key);
 const attempts=f.peer.calls.filter(c=>!c.recovery&&c.key===key);assert.equal(attempts.length,2);assert.equal(attempts[0].body,attempts[1].body);
});
test('canonical refusal stops successor steps, not renumbering or refreshing',async t=>{
 const f=await migrationFixture(t,{destination:{alter:c=>{if(!c.recovery){Object.assign(c.value,{outcome:'refused',repository_commit_id:null,refusal_record_id:'refused',refusal_code:'RefMismatch',refusal_code_point:1});}}}});
 const r=await executeGithubPullImport(f.run);assert.equal(r.state,'refused');assert.equal(r.complete,false);assert.equal(f.peer.mutations.length,1);
 const n=f.peer.calls.length;assert.equal((await executeGithubPullImport(f.run)).state,'refused');assert.equal(f.peer.calls.length,n);
});
test('rotated credential only recovers original principal, never sends a successor',async t=>{
 let dropped=false;const f=await migrationFixture(t,{destination:{alter:c=>{if(!c.recovery&&!dropped){dropped=true;c.res.destroy();return false;}}}});
 await executeGithubPullImport(f.run);await writeFile(f.tokenFile,ROTATED);const n=f.peer.mutations.length;
 assert.equal((await executeGithubPullImport({...f.run,operation:'recover'})).committed_steps,1);assert.equal(f.peer.mutations.length,n);
 await assert.rejects(executeGithubPullImport(f.run),/original_credential/);assert.equal(f.peer.mutations.length,n);
});
test('rotated recovery principal mismatch remains unresolved',async t=>{
 let wrong=false;const f=await migrationFixture(t,{destination:{alter:c=>{if(!c.recovery){c.res.destroy();return false;}if(wrong)c.value.principal_id='ff'.repeat(16);}}});
 await executeGithubPullImport(f.run);wrong=true;await writeFile(f.tokenFile,ROTATED);
 const r=await executeGithubPullImport({...f.run,operation:'recover'});assert.equal(r.state,'pending');assert.equal(f.peer.mutations.length,1);
});
test('received publication survives failed confirmation and forbids explicit re-upload',async t=>{
 let fail=true;const f=await migrationFixture(t,{destination:{alter:c=>{if(c.recovery&&c.value.terminal&&fail){c.res.destroy();return false;}}}});
 const r=await executeGithubPullImport(f.run);assert.equal(r.current.publication,'committed');assert.equal(f.peer.mutations.length,1);
 fail=false;const done=await executeGithubPullImport({...f.run,retryKey:r.current.key});assert.equal(done.complete,true);assert.equal(f.peer.mutations.filter(c=>c.key===r.current.key).length,1);
});
for(const [name,mutate] of [
 ['capture tamper',f=>writeFile(join(f.workdir,'capture.json'),'{}\n')],
 ['manifest tamper',f=>writeFile(join(f.workdir,'manifest.json'),'{}\n')],
 ['request tamper',f=>writeFile(intentPath(f),'{}\n')],
 ['missing request',f=>unlink(intentPath(f))],
 ['unknown root file',f=>writeFile(join(f.workdir,'unknown'),'x')],
 ['unknown request file',f=>writeFile(join(f.workdir,'requests','step-000001','unknown'),'x')],
 ['journal gap',f=>mkdir(join(f.workdir,'journal','attempt-000002'),{mode:0o700})],
 ['empty reservation',f=>mkdir(join(f.workdir,'journal','attempt-000001'),{mode:0o700})],
 ['hard linked source',f=>link(join(f.workdir,'capture.json'),join(f.root,'alias'))],
 ['symlinked source',async f=>{await unlink(join(f.workdir,'capture.json'));await symlink(f.captureFile,join(f.workdir,'capture.json'));}],
])test(`preflight refuses ${name} without HTTP`,async t=>{
 const f=await migrationFixture(t);await mutate(f);await assert.rejects(executeGithubPullImport(f.run));assert.equal(f.peer.calls.length,0);
});
test('preparation validates all native size/step limits before creating a job',async t=>{
 const f=await migrationFixture(t,{prepare:false,select:{max_steps:1}});await assert.rejects(prepareGithubPullImport(f.input),/step_limit/);await assert.rejects(readFile(join(f.workdir,'manifest.json')));
 assert.equal(f.peer.calls.length,0);
 const g=await migrationFixture(t,{prepare:false,select:{max_request_bytes:10}});await assert.rejects(prepareGithubPullImport(g.input),/request_limit/);assert.equal(g.peer.calls.length,0);
});
test('existing prepared job and pins are not overwritten',async t=>{
 const f=await migrationFixture(t),bytes=await readFile(join(f.workdir,'manifest.json'));
 await assert.rejects(prepareGithubPullImport(f.input),/workdir_exists/);assert((await readFile(join(f.workdir,'manifest.json'))).equals(bytes));
 await assert.rejects(executeGithubPullImport({...f.run,confirm:'0'.repeat(64)}));assert.equal(f.peer.calls.length,0);
});
test('branch requirements select independent principal and preserve exact original PR requests',async t=>{
 const f=await migrationFixture(t),bytes=await readFile(intentPath(f));
 const r=await githubPullBranchRequirements({workdir:f.workdir,confirm:f.prepared.plan_sha256,principal:'77'.repeat(16)});
 assert.equal(r.selection.scope.principal_id,'77'.repeat(16));assert.equal(r.selection.endpoint,f.peer.endpoint);assert.equal(r.selection.refs.length,2);
 assert.equal(r.selection.refs[0].new_commit,'b'.repeat(40));assert.equal(r.selection.refs[1].new_commit,'a'.repeat(40));assert.equal(r.plan_sha256,f.prepared.plan_sha256);
 assert((await readFile(intentPath(f))).equals(bytes));assert.equal(f.peer.calls.length,0);
 await assert.rejects(githubPullBranchRequirements({workdir:f.workdir,confirm:f.prepared.plan_sha256,principal:'alice'}));
});
test('unattempted recovery is read-only and requires no credentials',async t=>{
 const f=await migrationFixture(t);await unlink(f.tokenFile);const r=await executeGithubPullImport({...f.run,operation:'recover'});
 assert.equal(r.state,'ready');assert.equal(r.new_operations,0);assert.equal(f.peer.calls.length,0);
});
test('cancellation preserves committed operation for later recovery',async t=>{
 const stop=new AbortController();let stalled=true;
 const f=await migrationFixture(t,{destination:{alter:c=>{if(!c.recovery&&stalled){c.res.writeHead(200,{'content-type':'application/json'});c.res.write('{');setTimeout(()=>stop.abort(),20);return false;}}}});
 const r=await executeGithubPullImport({...f.run,signal:stop.signal});assert.equal(r.state,'pending');assert.equal(f.peer.mutations.length,1);
 stalled=false;assert.equal((await executeGithubPullImport(f.run)).complete,true);assert.equal(f.peer.mutations.length,5);
});
test('raw fields cannot select a loader, sender, current tip or replacement principal',async t=>{
 const f=await migrationFixture(t);for(const delta of [{loader:'evil'},{sourceKind:'native'},{endpoint:'https://evil.test'},{force:true},{principal:'alice'}])
 await assert.rejects(executeGithubPullImport({...f.run,...delta}));assert.equal(f.peer.calls.length,0);
});
