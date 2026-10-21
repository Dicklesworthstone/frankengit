import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile,writeFile,rm,unlink,readdir,mkdir,symlink,link,stat } from 'node:fs/promises';
import { join } from 'node:path';
import { prepareGithubPullMigration,executeGithubPullMigration,githubPullMigrationBatch } from '../../scripts/lib/github-pull-migration.mjs';
import { executeGithubPullImport,inspectGithubPullImport } from '../../scripts/lib/github-pull-import.mjs';
import { compileGithubPullImport } from '../../scripts/lib/github-pull-import-plan.mjs';
import { encode,digest } from '../../scripts/lib/forge-pull-archive-store.mjs';
import { wholeMigrationFixture,childPath,readJson,ROTATED,NATIVE_TOKEN } from './github-pull-migration-fixture.mjs';
const status=f=>executeGithubPullMigration({workdir:f.workdir,confirm:f.prepared.plan_sha256,operation:'status'});
const childManifest=(f,i)=>readJson(join(childPath(f,i),'manifest.json'));

test('whole preparation creates ordinary independent jobs with exact u64 windows',async t=>{
  const f=await wholeMigrationFixture(t,{batchSize:2,select:{number_start:'9007199254740993'}});
  assert.equal(f.prepared.total_batches,2);assert.equal(f.prepared.steps,15);assert.equal(f.peer.calls.length,0);
  const root=await readJson(join(f.workdir,'manifest.json'));assert.equal(root.pulls,3);
  const numbers=[];
  for(let i=0;i<2;i++) {
    const m=await childManifest(f,i);assert.equal(m.selection.number_start,String(9007199254740993n+BigInt(i*2)));
    const inspected=await inspectGithubPullImport({workdir:childPath(f,i),confirm:root.batches[i].plan_sha256});
    numbers.push(...inspected.mapping.map(r=>r.destination));
    const captured=await readJson(join(childPath(f,i),'capture.json'));
    assert.equal(compileGithubPullImport(captured,m.selection).stepsSha256,m.steps_sha256);
  }
  assert.deepEqual(numbers,['9007199254740993','9007199254740994','9007199254740995']);
  assert.equal((await status(f)).committed_steps,0);
});
test('one operation allowance spans batch boundaries and original keys survive resume',async t=>{
  const f=await wholeMigrationFixture(t);const intents=await Promise.all([0,1,2].map(i=>readFile(join(childPath(f,i),'requests','step-000001','intent.json'))));
  const paused=await executeGithubPullMigration({...f.run,maxOperations:6});
  assert.equal(paused.new_operations,6);assert.equal(paused.committed_batches,1);assert.equal(paused.committed_steps,6);
  assert.equal(paused.current.batch,2);assert.equal(paused.complete,false);assert.equal(f.peer.mutations.length,6);
  const done=await executeGithubPullMigration(f.run);assert.equal(done.complete,true);assert.equal(done.new_operations,9);
  assert.equal(f.peer.mutations.length,15);assert.equal(new Set(f.peer.mutations.map(m=>m.key)).size,15);
  for(let i=0;i<3;i++)assert((await readFile(join(childPath(f,i),'requests','step-000001','intent.json'))).equals(intents[i]));
});
test('source removal does not affect execution; completed state needs no credential or network',async t=>{
  const f=await wholeMigrationFixture(t);await rm(f.collectionDir,{recursive:true});
  const done=await executeGithubPullMigration(f.run);assert.equal(done.complete,true);
  await unlink(f.tokenFile);await f.peer.close();
  const cached=await executeGithubPullMigration({workdir:f.workdir,confirm:f.prepared.plan_sha256,operation:'run'});
  assert.equal(cached.complete,true);assert.equal(cached.network_accessed,false);assert.equal((await status(f)).complete,true);
});
test('empty completed source creates an offline no-op migration',async t=>{
  const f=await wholeMigrationFixture(t,{pulls:[]});assert.equal(f.prepared.complete,true);assert.equal(f.prepared.steps,0);
  const done=await executeGithubPullMigration({...f.run,tokenFile:undefined});assert.equal(done.complete,true);assert.equal(f.peer.calls.length,0);
});
for(const [label,source,select,limits,error] of [
  ['late draft',{alter:s=>{if(s.kind==='pull'&&s.n===23)s.value.draft=true;}},{},{},/draft_requires_consent/],
  ['late oversized title',{alter:s=>{if(s.kind==='pull'&&s.n===23)s.value.title='x'.repeat(257);}},{},{},/invalid_pull_text/],
  ['whole number overflow',{}, {number_start:'18446744073709551614'},{},/u64/],
  ['global step ceiling',{},{},{maxSteps:14},/plan_capacity/],
  ['global byte ceiling',{},{},{maxRequestBytes:1},/plan_capacity/],
  ['native hash translation',{}, {scope:{tenant_id:'11'.repeat(16),repository_id:'22'.repeat(16),repository_incarnation:'33'.repeat(16),principal_id:'44'.repeat(16),object_format:'sha256'}},{},/destination_hash_domain/],
])test(`whole preflight refuses ${label} before creating requests`,async t=>{
  const f=await wholeMigrationFixture(t,{source,select,limits,prepare:false});
  await assert.rejects(prepareGithubPullMigration(f.input),error);
  await assert.rejects(stat(f.workdir),{code:'ENOENT'});assert.equal(f.peer.calls.length,0);
});
test('explicit draft and merged consent is retained across the complete plan',async t=>{
  const f=await wholeMigrationFixture(t,{select:{merged:'as-closed',drafts:'as-ordinary'},source:{alter:s=>{
    if(s.kind==='pull'&&s.n===17)s.value.draft=true;
    if(s.kind==='pull'&&s.n===23)Object.assign(s.value,{state:'closed',merged:true,closed_at:s.value.updated_at,merged_at:s.value.updated_at,merge_commit_sha:'d'.repeat(40)});
  }}});
  const done=await executeGithubPullMigration(f.run);assert.equal(done.complete,true);assert.equal(f.peer.mutations.at(-1).action,'close');
  assert(f.peer.mutations.every(m=>['open','comment','close'].includes(m.action)));
});
for(const [name,change] of [
  ['wrong completion pin',async f=>{f.input.completeConfirm='0'.repeat(64);}],
  ['missing completion root',async f=>unlink(join(f.collectionDir,'complete.json'))],
  ['corrupt final capture',async f=>writeFile(join(f.collectionDir,'captures','batch-000003.json'),'{}\n')],
])test(`preparation requires the complete source: ${name}`,async t=>{
  const f=await wholeMigrationFixture(t,{prepare:false});await change(f);
  await assert.rejects(prepareGithubPullMigration(f.input));await assert.rejects(stat(f.workdir),{code:'ENOENT'});assert.equal(f.peer.calls.length,0);
});
for(const [name,change] of [
  ['later intent',async f=>{const p=join(childPath(f,2),'requests','step-000001','intent.json');await writeFile(p,(await readFile(p,'utf8')).replace('Change 23','Changed23'));}],
  ['later capture',async f=>writeFile(join(childPath(f,2),'capture.json'),'{}\n')],
  ['later torn reservation',async f=>{const p=join(childPath(f,2),'journal','attempt-000001');await mkdir(p,{mode:0o700});}],
  ['extra child',async f=>mkdir(join(f.workdir,'batches','batch-000004'),{mode:0o700})],
  ['missing child',async f=>rm(childPath(f,2),{recursive:true})],
  ['hard link',async f=>link(join(childPath(f,2),'manifest.json'),join(f.root,'alias'))],
  ['symlink',async f=>{const p=join(childPath(f,2),'capture.json'),b=await readFile(p);await writeFile(join(f.root,'alias'),b,{mode:0o600});await unlink(p);await symlink(join(f.root,'alias'),p);}],
])test(`validates every child before first network request: ${name}`,async t=>{
  const f=await wholeMigrationFixture(t);await change(f);
  await assert.rejects(executeGithubPullMigration(f.run));assert.equal(f.peer.calls.length,0);
});
test('original child outcomes govern collection order; manual successor send is refused',async t=>{
  const f=await wholeMigrationFixture(t),root=await readJson(join(f.workdir,'manifest.json'));
  await executeGithubPullImport({workdir:childPath(f,1),confirm:root.batches[1].plan_sha256,tokenFile:f.tokenFile,operation:'run',maxOperations:1});
  const n=f.peer.calls.length;await assert.rejects(executeGithubPullMigration(f.run),/crossed_unresolved_batch/);assert.equal(f.peer.calls.length,n);
});
test('lost last reply in a batch is recovered without sending its successor',async t=>{
  let lost=false;const f=await wholeMigrationFixture(t,{destination:{alter:c=>{
    if(!c.recovery&&c.number==='100'&&c.action==='comment'&&c.fields.expected_version==='3'&&!lost){lost=true;c.res.destroy();return false;}
  }}});
  const pending=await executeGithubPullMigration(f.run);assert.equal(pending.current.batch,1);assert.equal(pending.state,'pending');assert.equal(f.peer.mutations.length,5);
  const recovered=await executeGithubPullMigration({...f.run,operation:'recover'});
  assert.equal(recovered.committed_batches,1);assert.equal(recovered.new_operations,1);assert.equal(recovered.current.batch,2);
  assert.equal(f.peer.mutations.length,5);assert.equal((await executeGithubPullMigration(f.run)).complete,true);assert.equal(f.peer.mutations.length,15);
});
test('explicit retry applies only to the original pending key and unchanged bytes',async t=>{
  let blocked=false;const f=await wholeMigrationFixture(t,{destination:{alter:c=>{
    if(!c.recovery&&!blocked){blocked=true;c.res.destroy();return 'not-committed';}
  }}});
  const pending=await executeGithubPullMigration(f.run),key=pending.current.key,original=f.peer.calls.find(c=>!c.recovery).body;
  const check=await executeGithubPullMigration(f.run);assert.equal(check.state,'pending');assert.equal(f.peer.mutations.length,0);
  await assert.rejects(executeGithubPullMigration({...f.run,retryKey:'fgp1-'+'0'.repeat(32)+'-'+'0'.repeat(64)}),/retry_original_pending_key/);
  const done=await executeGithubPullMigration({...f.run,retryKey:key});assert.equal(done.complete,true);
  const sends=f.peer.calls.filter(c=>!c.recovery&&c.key===key);assert.equal(sends.length,2);assert(sends.every(c=>c.body===original));
});
test('native refusal in second batch preserves first and never starts third',async t=>{
  const f=await wholeMigrationFixture(t,{destination:{alter:c=>{
    if(!c.recovery&&c.number==='101'&&c.action==='open')Object.assign(c.value,{outcome:'refused',repository_commit_id:null,refusal_record_id:'refusal-1',refusal_code:'RefMismatch',refusal_code_point:1});
  }}});
  const r=await executeGithubPullMigration(f.run);assert.equal(r.state,'refused');assert.equal(r.committed_batches,1);assert.equal(r.current.batch,2);
  assert.equal(f.peer.mutations.length,6);const n=f.peer.calls.length;
  assert.equal((await executeGithubPullMigration(f.run)).state,'refused');assert.equal(f.peer.calls.length,n);
});
test('rotated token recovers a pending original principal but cannot submit the next step',async t=>{
  let lost=false;const f=await wholeMigrationFixture(t,{destination:{alter:c=>{if(!c.recovery&&!lost){lost=true;c.res.destroy();return false;}}}});
  await executeGithubPullMigration(f.run);await writeFile(f.tokenFile,ROTATED);
  const recovered=await executeGithubPullMigration({...f.run,operation:'recover'});assert.equal(recovered.committed_steps,1);assert.equal(f.peer.mutations.length,1);
  await assert.rejects(executeGithubPullMigration(f.run),/original_credential/);assert.equal(f.peer.mutations.length,1);
});
test('concurrent wrappers arbitrate existing original request slots without duplicate sends',{timeout:30000},async t=>{
  let arrived,release,held=false;
  const arrival=new Promise(resolve=>{arrived=resolve;}),gate=new Promise(resolve=>{release=resolve;});
  const f=await wholeMigrationFixture(t,{destination:{alter:async c=>{
    // Both invocations must observe the SAME original slot. Without this
    // barrier the first may finish before the second loads the journal, in
    // which case two distinct operations are permitted by the public API.
    if(!c.recovery&&!held){held=true;arrived();await gate;}
  }}});
  const first=executeGithubPullMigration({...f.run,maxOperations:1});
  try {
    await Promise.race([arrival,first.then(()=>{throw new Error('sender ended before the held request');})]);
    const other=await Promise.allSettled([executeGithubPullMigration({...f.run,maxOperations:1})]);
    release();const results=[...await Promise.allSettled([first]),...other];
    assert(results.some(r=>r.status==='fulfilled'));assert.equal(f.peer.mutations.length,1);
    assert.equal(f.peer.calls.filter(c=>!c.recovery).length,1);
    assert.equal((await status(f)).committed_steps,1);
  } finally {release();await Promise.allSettled([first]);}
});
test('sequential one-operation invocations may advance two distinct original slots',{timeout:30000},async t=>{
  const f=await wholeMigrationFixture(t);
  for(let i=0;i<2;i++)await executeGithubPullMigration({...f.run,maxOperations:1});
  assert.equal(f.peer.mutations.length,2);assert.equal(new Set(f.peer.mutations.map(c=>c.key)).size,2);
  assert.equal((await status(f)).committed_steps,2);
});
test('batch handoff uses original child pin, exact number window and independent branch principal',async t=>{
  const f=await wholeMigrationFixture(t,{batchSize:2}),principal='77'.repeat(16);
  const r=await githubPullMigrationBatch({workdir:f.workdir,confirm:f.prepared.plan_sha256,batch:2,principal});
  assert.equal(r.destination_number_start,'102');assert.equal(r.workdir,childPath(f,1));assert.equal(r.selection.scope.principal_id,principal);
  assert.equal(r.selection.refs.length,2);assert.equal(r.migration_sha256,f.prepared.plan_sha256);assert.equal(digest(encode(r.selection)),r.requirements_sha256);
  assert.equal(f.peer.calls.length,0);
});
test('existing migration is not re-prepared, overwritten or assigned replacement keys',async t=>{
  const f=await wholeMigrationFixture(t),before=await readFile(join(f.workdir,'manifest.json'));
  await assert.rejects(prepareGithubPullMigration(f.input),/workdir_exists/);assert((await readFile(join(f.workdir,'manifest.json'))).equals(before));
});
test('invalid options and wrong root pins refuse without contacting destination',async t=>{
  const f=await wholeMigrationFixture(t);
  for(const extra of [{confirm:'0'.repeat(64)},{maxOperations:0},{maxOperations:8193},{force:true},{selection:{}},{operation:'recover',retryKey:'x'}])await assert.rejects(executeGithubPullMigration({...f.run,...extra}));
  assert.equal(f.peer.calls.length,0);
});
