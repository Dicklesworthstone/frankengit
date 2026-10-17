import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, unlink, readdir, link, symlink, chmod, rename, mkdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { prepareGithubPullCollection, inspectGithubPullCollection, collectGithubPulls, selectGithubPullCollectionBatch } from '../../scripts/lib/github-pull-collection.mjs';
import { batchName, COLLECTION_LIMITS as L } from '../../scripts/lib/github-pull-collection-store.mjs';
import { captureGithubPullBatch } from '../../scripts/lib/github-pull-inventory.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { collectionFixture } from './github-pull-collection-fixture.mjs';

const status=f=>inspectGithubPullCollection(f.status), data=(f,i=0)=>join(f.workdir,'captures',batchName(i)),record=(f,i=0)=>join(f.workdir,'journal',batchName(i));
test('collection resumes batch boundaries without recapturing verified data',async t=>{
  const f=await collectionFixture(t,{pulls:[9,17,23],records:1});const initial=f.calls.length;
  assert.equal(f.prepared.complete,false);assert.equal(f.prepared.total_batches,3);assert.equal(f.prepared.network_accessed,false);
  const first=await collectGithubPulls({...f.run,maxBatches:1}),bytes=await readFile(data(f));
  assert.equal(first.complete,false);assert.equal(first.next_batch,2);assert.equal(first.statistics.requests,14);
  const final=await collectGithubPulls({...f.run,maxBatches:2});assert.equal(final.complete,true);assert.equal(final.new_batches,2);assert.equal(final.statistics.requests,28);
  assert.equal(f.calls.length-initial,42);assert.equal(final.captured_pulls,3);assert.equal(final.records,9);assert.equal(final.uncheckpointed_batch,null);
  assert((await readFile(data(f))).equals(bytes));assert.equal((await status(f)).complete_sha256,final.complete_sha256);
  const golden=await captureGithubPullBatch({inventory:f.inventory.inventory,confirm:f.inventory.sha256,batch:1,fetchImpl:f.fetchImpl});assert(bytes.equals(golden.bytes));
});
test('101 PRs traverse independent bounded captures and one shared per-run owner',async t=>{
  const f=await collectionFixture(t,{pulls:Array.from({length:101},(_,i)=>i+1),records:1},{batchSize:25});
  const first=await collectGithubPulls({...f.run,maxBatches:2});assert.equal(first.captured_batches,2);assert.equal(first.captured_pulls,50);assert.equal(first.statistics.requests,508);
  const done=await collectGithubPulls(f.run);assert.equal(done.complete,true);assert.equal(done.captured_pulls,101);assert.equal(done.captured_batches,5);
  assert.equal(done.statistics.requests,522);assert.equal(done.records,303);
  assert.equal(f.calls.filter(c=>c.kind==='pull'&&c.n===1).length,4);
});
test('empty inventory finalizes offline without an invalid empty capture',async t=>{
  const f=await collectionFixture(t,{pulls:[]});await f.close();await unlink(f.tokenFile);await unlink(f.inventoryFile);
  const r=await collectGithubPulls(f.status);assert.equal(r.complete,true);assert.equal(r.captured_pulls,0);assert.equal(r.network_accessed,false);assert.equal(r.statistics.requests,0);
  assert.deepEqual(await readdir(join(f.workdir,'captures')),[]);
});
test('completed collection and independent final pin work after source and token removal',async t=>{
  const f=await collectionFixture(t),done=await collectGithubPulls(f.run);await unlink(f.inventoryFile);await unlink(f.tokenFile);await f.close();
  const original=globalThis.fetch;globalThis.fetch=()=>{throw Error('offline work contacted source');};
  try {
    const read=await inspectGithubPullCollection({...f.status,completeConfirm:done.complete_sha256});assert.equal(read.complete,true);assert.equal(read.local_read_only,true);
    const replay=await collectGithubPulls(f.status);assert.equal(replay.new_batches,0);assert.equal(replay.network_accessed,false);assert.equal(replay.complete_sha256,done.complete_sha256);
  }finally{globalThis.fetch=original;}
});
test('finalization after a lost final root requires no recapture',async t=>{
  const f=await collectionFixture(t),done=await collectGithubPulls(f.run);await unlink(join(f.workdir,'complete.json'));await unlink(f.tokenFile);await f.close();
  assert.equal((await status(f)).ready_to_seal,true);const r=await collectGithubPulls(f.status);assert.equal(r.complete_sha256,done.complete_sha256);assert.equal(r.network_accessed,false);
});
test('same observations produce the same root regardless of invocation partition',async t=>{
  const f=await collectionFixture(t),a=await collectGithubPulls(f.run),other=join(f.root,'second');
  const prepared=await prepareGithubPullCollection({workdir:other,inventoryFile:f.inventoryFile,inventoryConfirm:f.inventory.sha256});
  assert.equal(prepared.plan_sha256,f.prepared.plan_sha256);
  const opts={...f.run,workdir:other};await collectGithubPulls({...opts,maxBatches:1});const b=await collectGithubPulls(opts);assert.equal(a.complete_sha256,b.complete_sha256);
});
test('uncheckpointed valid body is recaptured identically and never overwritten',async t=>{
  const f=await collectionFixture(t);await collectGithubPulls({...f.run,maxBatches:1});const bytes=await readFile(data(f));await unlink(record(f));
  assert.equal((await status(f)).uncheckpointed_batch,1);const before=f.calls.length,r=await collectGithubPulls({...f.run,maxBatches:1});
  assert.equal(r.checkpointed_batches,1);assert.equal(r.new_batches,1);assert.equal(r.next_batch,2);assert.equal(f.calls.length-before,14);assert((await readFile(data(f))).equals(bytes));
});
test('changed uncheckpointed observation refuses instead of substituting newer bytes',async t=>{
  let changed=false;const f=await collectionFixture(t,{alter:s=>{if(changed&&s.kind==='pull')s.value.body='new content';}});
  await collectGithubPulls({...f.run,maxBatches:1});const bytes=await readFile(data(f));await unlink(record(f));changed=true;
  await assert.rejects(collectGithubPulls(f.run),/uncheckpointed_changed/);assert((await readFile(data(f))).equals(bytes));assert.equal((await status(f)).uncheckpointed_batch,1);
});
for(const [name,damage] of [
  ['inventory edit',async f=>{const p=join(f.workdir,'inventory.json'),v=JSON.parse(await readFile(p));v.batch_size=2;await writeFile(p,JSON.stringify(v)+'\n');}],
  ['plan edit',async f=>{const p=join(f.workdir,'plan.json'),v=JSON.parse(await readFile(p));v.max_capture_bytes--;await writeFile(p,JSON.stringify(v)+'\n');}],
  ['capture edit',async f=>{const p=data(f),v=JSON.parse(await readFile(p));v.pulls[0].pull.body='edited';await writeFile(p,JSON.stringify(v)+'\n');}],
  ['truncated capture',async f=>writeFile(data(f),'{')],
  ['truncated checkpoint',async f=>writeFile(record(f),'{')],
  ['missing capture',async f=>unlink(data(f))],
  ['checkpoint gap',async f=>{await unlink(record(f));await writeFile(record(f,1),'{}\n',{mode:0o600});}],
  ['foreign root file',async f=>writeFile(join(f.workdir,'unexpected'),'x',{mode:0o600})],
  ['foreign capture file',async f=>writeFile(join(f.workdir,'captures','other'),'x',{mode:0o600})],
  ['hard-linked capture',async f=>link(data(f),join(f.root,'alias'))],
  ['symlinked capture',async f=>{const b=await readFile(data(f));await writeFile(join(f.root,'external'),b,{mode:0o600});await unlink(data(f));await symlink(join(f.root,'external'),data(f));}],
  ['public capture permissions',async f=>chmod(data(f),0o644)],
])test(`full preflight refuses ${name} before reading a credential or networking`,async t=>{
  const f=await collectionFixture(t);await collectGithubPulls({...f.run,maxBatches:1});await damage(f);await unlink(f.tokenFile);const before=f.calls.length;
  await assert.rejects(status(f));await assert.rejects(collectGithubPulls(f.run));assert.equal(f.calls.length,before);
});
test('final root cannot assert completion over an incomplete prefix',async t=>{
  const f=await collectionFixture(t);await collectGithubPulls({...f.run,maxBatches:1});await writeFile(join(f.workdir,'complete.json'),'{}\n',{mode:0o600});
  const n=f.calls.length;await assert.rejects(collectGithubPulls(f.run),/incomplete/);assert.equal(f.calls.length,n);
});
test('independent completion pin detects a locally recomputed changed root',async t=>{
  const f=await collectionFixture(t),done=await collectGithubPulls(f.run);
  const p=join(f.workdir,'complete.json'),bytes=await readFile(p);assert.equal(recordDigest(bytes),done.complete_sha256);
  const first=JSON.parse(await readFile(data(f)));first.pulls[0].pull.body='changed but locally valid';
  await writeFile(data(f),JSON.stringify(first)+'\n');
  let previous=f.prepared.plan_sha256,total=0;
  for(let i=0;i<done.total_batches;i++) {
    const body=await readFile(data(f,i)),checkpoint=JSON.parse(await readFile(record(f,i)));
    checkpoint.previous_sha256=previous;checkpoint.capture_sha256=recordDigest(body);checkpoint.bytes=body.length;
    const encoded=Buffer.from(JSON.stringify(checkpoint)+'\n');await writeFile(record(f,i),encoded);previous=recordDigest(encoded);total+=body.length;
  }
  const complete=JSON.parse(bytes);complete.checkpoint_sha256=previous;complete.capture_bytes=total;
  await writeFile(p,JSON.stringify(complete)+'\n');
  const unpinned=await status(f);assert.equal(unpinned.complete,true);assert.notEqual(unpinned.complete_sha256,done.complete_sha256);
  await assert.rejects(inspectGithubPullCollection({...f.status,completeConfirm:done.complete_sha256}),/complete_pin/);
});
test('cumulative normalized byte ceiling includes completed earlier invocations',async t=>{
  const f=await collectionFixture(t);await collectGithubPulls({...f.run,maxBatches:1});const firstBytes=(await readFile(data(f))).length,workdir=join(f.root,'limited');
  const p=await prepareGithubPullCollection({workdir,inventoryFile:f.inventoryFile,inventoryConfirm:f.inventory.sha256,maxCaptureBytes:firstBytes});
  const opts={...f.run,workdir,confirm:p.plan_sha256};const first=await collectGithubPulls({...opts,maxBatches:1});assert.equal(first.capture_bytes,firstBytes);
  await assert.rejects(collectGithubPulls(opts),/capacity/);assert.equal((await inspectGithubPullCollection({workdir,confirm:p.plan_sha256})).captured_batches,1);
});
test('cumulative record ceiling includes previous batches without resetting',async t=>{
  const f=await collectionFixture(t,{records:1},{maxRecords:3});await collectGithubPulls({...f.run,maxBatches:1});
  await assert.rejects(collectGithubPulls(f.run),/capacity/);assert.equal((await status(f)).records,3);
});
test('one capture-owner HTTP allowance covers all batches in an invocation',async t=>{
  const f=await collectionFixture(t),before=f.calls.length;
  await assert.rejects(collectGithubPulls({...f.run,maxRequests:20}),/request_limit/);assert.equal(f.calls.length-before,20);assert.equal((await status(f)).checkpointed_batches,1);
  const r=await collectGithubPulls(f.run);assert.equal(r.complete,true);assert.equal(r.statistics.requests,14);
});
test('repository replacement after one completed batch cannot fill the next batch',async t=>{
  let change=false;const f=await collectionFixture(t,{alter:s=>{if(change&&s.kind==='repository')s.value.id++;}});
  await collectGithubPulls({...f.run,maxBatches:1});change=true;const before=f.calls.length;
  await assert.rejects(collectGithubPulls(f.run),/inventory_repository_changed/);assert.equal(f.calls.length-before,1);assert.equal((await status(f)).checkpointed_batches,1);
});
test('cross-batch review IDs cannot be reused under another PR',async t=>{
  const f=await collectionFixture(t,{records:1,alter:s=>{if(s.kind==='reviews')s.value[0].id=201;}});
  await collectGithubPulls({...f.run,maxBatches:1});await assert.rejects(collectGithubPulls(f.run),/duplicate_record/);assert.equal((await status(f)).captured_batches,1);
});
test('concurrent collectors cannot overwrite the same immutable batch slot',async t=>{
  let racing=false,arrivals=0,release;const barrier=new Promise(r=>release=r);
  const f=await collectionFixture(t,{pulls:[9],alter:async s=>{if(racing&&s.kind==='repository'&&arrivals<2){if(++arrivals===2)release();await barrier;}}});racing=true;
  const results=await Promise.allSettled([collectGithubPulls(f.run),collectGithubPulls(f.run)]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(results.filter(r=>r.status==='rejected').length,1);assert.equal((await status(f)).complete,true);
});
test('directory replacement during collection refuses before publishing into the new directory',async t=>{
  let active=false,f;
  f=await collectionFixture(t,{alter:async s=>{if(active&&s.kind==='pull'){active=false;await rename(join(f.workdir,'captures'),join(f.root,'old-captures'));await mkdir(join(f.workdir,'captures'),{mode:0o700});}}});
  active=true;await assert.rejects(collectGithubPulls(f.run),/collection_directory/);assert.deepEqual(await readdir(join(f.workdir,'captures')),[]);
});
test('invalid run options do not contact the source or mutate the plan',async t=>{
  const f=await collectionFixture(t),n=f.calls.length,b=await readFile(join(f.workdir,'plan.json'));
  for(const extra of [{maxBatches:0},{maxRequests:0},{maxCaptureBytes:L.bytes},{repository:'elsewhere/repo'},{confirm:'0'.repeat(64)}])await assert.rejects(collectGithubPulls({...f.run,...extra}));
  assert.equal(f.calls.length,n);assert((await readFile(join(f.workdir,'plan.json'))).equals(b));
});
test('offline batch selection binds complete content and computes disjoint exact u64 destinations',async t=>{
  const f=await collectionFixture(t),done=await collectGithubPulls(f.run);
  const common={...f.status,completeConfirm:done.complete_sha256,numberStart:'18446744073709551614'};
  const first=await selectGithubPullCollectionBatch({...common,batch:1}),last=await selectGithubPullCollectionBatch({...common,batch:2});
  assert.equal(first.destination_number_start,'18446744073709551614');assert.equal(last.destination_number_start,'18446744073709551615');
  assert.equal(recordDigest(await readFile(last.capture_file)),last.capture_sha256);assert.deepEqual(last.numbers,[17]);
  for(const extra of [{numberStart:'18446744073709551615'},{numberStart:'1e2'},{batch:3},{completeConfirm:'0'.repeat(64)}])
    await assert.rejects(selectGithubPullCollectionBatch({...common,batch:1,...extra}));
});
test('pending collection cannot be selected as a complete migration source',async t=>{
  const f=await collectionFixture(t);await collectGithubPulls({...f.run,maxBatches:1});
  await assert.rejects(selectGithubPullCollectionBatch({...f.status,completeConfirm:'0'.repeat(64),batch:1}),/complete_pin/);
});
test('status does not explicitly change custody timestamps',async t=>{
  const f=await collectionFixture(t);await collectGithubPulls({...f.run,maxBatches:1});const paths=[join(f.workdir,'plan.json'),data(f),record(f)];
  const before=await Promise.all(paths.map(p=>stat(p,{bigint:true})));await status(f);const after=await Promise.all(paths.map(p=>stat(p,{bigint:true})));
  for(let i=0;i<paths.length;i++)for(const key of ['ino','size','mtimeNs','ctimeNs'])assert.equal(before[i][key],after[i][key]);
});
