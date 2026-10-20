import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile,writeFile,stat } from 'node:fs/promises';
import { join } from 'node:path';
import { encode,digest } from '../../scripts/lib/forge-pull-archive-store.mjs';
import { wholeMigrationFixture,childPath,readJson } from './github-pull-migration-fixture.mjs';
import { prepareGithubPullMigration,executeGithubPullMigration } from '../../scripts/lib/github-pull-migration.mjs';

test('101 PRs in five original batches execute under one shared default 100-operation allowance',async t=>{
  const f=await wholeMigrationFixture(t,{pulls:Array.from({length:101},(_,i)=>i+1),batchSize:25,
    source:{discussions:0,reviews:0,inlines:0}});
  assert.equal(f.prepared.total_batches,5);assert.equal(f.prepared.steps,202);
  const first=await executeGithubPullMigration(f.run);assert.equal(first.new_operations,100);assert.equal(first.committed_batches,2);
  assert.equal(first.current.batch,3);assert.equal(f.peer.mutations.length,100);
  const second=await executeGithubPullMigration(f.run);assert.equal(second.new_operations,100);assert.equal(second.committed_batches,4);
  const third=await executeGithubPullMigration(f.run);assert.equal(third.new_operations,2);assert.equal(third.complete,true);
  assert.equal(f.peer.mutations.length,202);assert.equal(new Set(f.peer.mutations.map(m=>m.key)).size,202);
  assert.deepEqual(f.peer.mutations.filter(m=>m.action==='open').map(m=>m.number),Array.from({length:101},(_,i)=>String(100+i)));
});
test('aggregate intent size refuses even when body preflight fits, leaving no executable outer root',async t=>{
  const f=await wholeMigrationFixture(t),limit=f.prepared.request_bytes-1,second=join(f.root,'too-small');
  await assert.rejects(prepareGithubPullMigration({...f.input,workdir:second,maxRequestBytes:limit}),/plan_capacity/);
  await assert.rejects(stat(join(second,'manifest.json')),{code:'ENOENT'});assert.equal(f.peer.calls.length,0);
  await assert.rejects(prepareGithubPullMigration({...f.input,workdir:second,maxRequestBytes:limit}),/workdir_exists/);
});
test('pre-aborted execution cannot reserve an attempt or submit',async t=>{
  const f=await wholeMigrationFixture(t),stop=new AbortController();stop.abort();
  await assert.rejects(executeGithubPullMigration({...f.run,signal:stop.signal}));assert.equal(f.peer.calls.length,0);
  const s=await executeGithubPullMigration({workdir:f.workdir,confirm:f.prepared.plan_sha256,operation:'status'});assert.equal(s.attempts,0);
});
test('the whole deadline bounds a stalled later-batch response and retained keys remain recoverable',async t=>{
  let block=true;const f=await wholeMigrationFixture(t,{destination:{alter:c=>{
    if(block&&!c.recovery&&c.number==='101') {c.res.writeHead(200,{'content-type':'application/json'});c.res.write('{');return false;}
  }}});
  // First batch is committed before starting the invocation under test.
  const first=await executeGithubPullMigration({...f.run,maxOperations:5});assert.equal(first.committed_batches,1);
  const before=await readFile(join(childPath(f,1),'requests','step-000001','intent.json'));
  let result,error;try{result=await executeGithubPullMigration({...f.run,timeoutMs:500});}catch(e){error=e;}
  assert(result?.state==='pending'||error?.migration_progress?.outcome_unknown);
  block=false;const done=await executeGithubPullMigration(f.run);assert.equal(done.complete,true);
  assert.equal(f.peer.mutations.length,15);assert((await readFile(join(childPath(f,1),'requests','step-000001','intent.json'))).equals(before));
});

for(const [name,change] of [
  ['renumbered batch',m=>{m.batches[1].first_index=0;}],
  ['changed destination',m=>{m.selection.scope.principal_id='99'.repeat(16);}],
  ['changed credential',m=>{m.credential_fingerprint='0'.repeat(64);}],
  ['altered totals',m=>{m.steps--;}],
])test(`semantic plan verification rejects ${name} even under a recalculated outer pin`,async t=>{
  const f=await wholeMigrationFixture(t),path=join(f.workdir,'manifest.json'),m=await readJson(path);change(m);
  const bytes=encode(m);await writeFile(path,bytes);
  await assert.rejects(executeGithubPullMigration({...f.run,confirm:digest(bytes)}));assert.equal(f.peer.calls.length,0);
});
test('the final native u64 destination number survives every batch and the actual HTTP sender',async t=>{
  const f=await wholeMigrationFixture(t,{select:{number_start:'18446744073709551613'}});
  assert.equal((await executeGithubPullMigration(f.run)).complete,true);
  assert.deepEqual(f.peer.mutations.filter(m=>m.action==='open').map(m=>m.number),['18446744073709551613','18446744073709551614','18446744073709551615']);
});
