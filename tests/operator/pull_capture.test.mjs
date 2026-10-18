import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, unlink, readdir, stat, link, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { preparePullCapture, resumePullCapture, inspectPullCapture } from '../../scripts/lib/forge-pull-capture.mjs';
import { exportPullArchive, inspectPullArchive } from '../../scripts/lib/forge-pull-archive.mjs';
import { fixture, encode, hash, HEAD, TOKEN } from './pull-archive-fixture.mjs';

async function capture(t, settings = {}, options = {}) {
  const f = await fixture(t,settings), root = join(f.root,'capture');
  const prepared = await preparePullCapture({...f.options,...options,workdir:root});
  return {...f,job:root,prepared,resume:{workdir:root,confirm:prepared.selection_sha256,tokenFile:f.token}};
}
const status = f => inspectPullCapture({workdir:f.job,confirm:f.prepared.selection_sha256});
const page = (f,n,part='archive') => join(f.job,part,`page-${String(n).padStart(6,'0')}.json`);

for (const format of ['sha1','sha256']) test(`checkpointed capture equals one-shot archive: ${format}`, async t => {
  const f = await capture(t,{format}); assert.equal(f.requests.length,1);
  let result = f.prepared, prior = 1;
  while (!result.complete) {
    result = await resumePullCapture({...f.resume,pageBudget:3});
    assert(result.new_requests <= 3); assert(result.pages >= prior); prior = result.pages;
    assert.equal(result.checkpointed_pages,result.pages);
    assert.equal((await status(f)).checkpoint_sha256,result.checkpoint_sha256);
  }
  assert.equal(f.requests.length,14); assert.equal(result.pages,14);
  assert.equal(result.pulls,2); assert.equal(result.reviews,4); assert.equal(result.comments,6);
  assert(f.requests.slice(1).every(r => r.head === HEAD));
  const direct = await exportPullArchive(f.options);
  assert.equal(result.archive_sha256,direct.archive_sha256);
  await f.close(); await unlink(f.token);
  assert.equal((await inspectPullArchive({workdir:result.archive_workdir,confirm:result.archive_sha256})).complete,true);
  const cached = await resumePullCapture({workdir:f.job,confirm:f.prepared.selection_sha256});
  assert.equal(cached.complete,true); assert.equal(cached.network_accessed,false); assert.equal(cached.new_requests,0);
});

test('every page boundary survives another invocation without redownload', async t => {
  const f = await capture(t); let result = f.prepared;
  while (!result.complete) {
    const before = await status(f), bytes = await readFile(page(f,before.pages));
    result = await resumePullCapture({...f.resume,pageBudget:1});
    assert.equal(result.pages,before.pages+1); assert.equal(result.new_requests,1);
    assert((await readFile(page(f,before.pages))).equals(bytes));
  }
  assert.equal(f.requests.length,14);
});
test('empty capture can finalize without credential or network', async t => {
  const f = await capture(t,{pulls:0}); assert.equal(f.prepared.ready_to_seal,true); assert.equal(f.prepared.complete,false);
  await f.close(); await unlink(f.token);
  const r = await resumePullCapture({workdir:f.job,confirm:f.prepared.selection_sha256});
  assert.equal(r.complete,true); assert.equal(r.new_requests,0); assert.equal(r.pulls,0);
});
test('status reads no credentials, constructs no transport and changes no custody', async t => {
  const f = await capture(t), files = [join(f.job,'selection.json'),page(f,1),page(f,1,'journal')];
  const before = await Promise.all(files.map(p => stat(p,{bigint:true}))); await unlink(f.token); await f.close();
  const fetch = globalThis.fetch; globalThis.fetch = () => { throw new Error('offline status used network'); };
  try { const s = await status(f); assert.equal(s.complete,false); assert.equal(s.local_read_only,true); assert.equal(s.network_accessed,false); }
  finally { globalThis.fetch = fetch; }
  const after = await Promise.all(files.map(p => stat(p,{bigint:true})));
  for (let i=0;i<files.length;i++) for (const key of ['ino','size','mtimeNs','ctimeNs']) assert.equal(after[i][key],before[i][key]);
});
test('source identity and initial page are pinned before any continuation', async t => {
  const f = await capture(t), s = JSON.parse(await readFile(join(f.job,'selection.json'),'utf8'));
  assert.equal(s.snapshot_token,HEAD); assert.equal(s.first_page_sha256,hash(await readFile(page(f,1))));
  assert.equal(s.credential_sha256,hash(Buffer.from(TOKEN)));
  const contents = await readFile(join(f.job,'selection.json'),'utf8'); assert(!contents.includes(TOKEN)); assert(!contents.includes(f.token));
});
test('original credential is required before any continuation HTTP', async t => {
  const f = await capture(t); await writeFile(f.token,'bb'.repeat(32),{mode:0o600}); const n = f.requests.length;
  await assert.rejects(resumePullCapture(f.resume),/credential_changed/); assert.equal(f.requests.length,n);
});
test('changed snapshot refuses without refreshing or publishing', async t => {
  let change = false; const f = await capture(t,{alter:({reply}) => { if (change) reply.snapshot_token='alg:2:'+'99'.repeat(32); }});
  change = true; const before = await status(f);
  await assert.rejects(resumePullCapture(f.resume));
  assert.equal(f.requests.length,2); assert.equal(f.requests.at(-1).head,HEAD);
  assert.equal((await status(f)).checkpoint_sha256,before.checkpoint_sha256);
});
test('expired snapshot performs one failing pinned request, never an unpinned retry', async t => {
  let expired = false; const f = await capture(t,{alter:({res}) => { if (expired) { res.writeHead(409,{'content-type':'application/json'}); res.end('{}'); return false; } }});
  expired = true; await assert.rejects(resumePullCapture(f.resume),/snapshot changed/i);
  assert.equal(f.requests.length,2); assert.equal(f.requests.at(-1).head,HEAD); assert.equal((await status(f)).complete,false);
});
for (const [name,alter] of [
  ['selection pin',async f => { const p=join(f.job,'selection.json'),v=JSON.parse(await readFile(p));v.max_pages--;await writeFile(p,encode(v)); }],
  ['page checksum',async f => { const p=page(f,1),v=JSON.parse(await readFile(p));v.pull_requests[0].data.body+='!';await writeFile(p,encode(v)); }],
  ['checkpoint chain',async f => { const p=page(f,1,'journal'),v=JSON.parse(await readFile(p));v.previous_sha256='0'.repeat(64);await writeFile(p,encode(v)); }],
  ['partial checkpoint',async f => writeFile(page(f,1,'journal'),'{')],
  ['missing data',async f => unlink(page(f,1))],
  ['unknown job file',async f => writeFile(join(f.job,'unknown'),'x',{mode:0o600})],
  ['noncontiguous page',async f => writeFile(page(f,3),await readFile(page(f,1)),{mode:0o600})],
  ['hard-linked page',async f => link(page(f,1),join(f.root,'alias'))],
  ['symlinked page',async f => { const p=page(f,1),target=join(f.root,'external');await writeFile(target,await readFile(p),{mode:0o600});await unlink(p);await symlink(target,p); }],
]) test(`preflight refuses ${name} before network`, async t => {
  const f = await capture(t); await alter(f); const count = f.requests.length;
  await assert.rejects(resumePullCapture(f.resume)); await assert.rejects(status(f)); assert.equal(f.requests.length,count);
});
test('page persisted before checkpoint is re-fetched exactly once, not overwritten', async t => {
  const f = await capture(t); await resumePullCapture({...f.resume,pageBudget:1});
  const retained = await readFile(page(f,2)); await unlink(page(f,2,'journal'));
  const s = await status(f); assert.equal(s.uncommitted_tail,true); assert.equal(s.checkpointed_pages,1);
  const r = await resumePullCapture({...f.resume,pageBudget:1});
  assert.equal(r.pages,2); assert.equal(r.checkpointed_pages,2); assert.equal(r.uncommitted_tail,false); assert.equal(r.new_requests,1);
  assert((await readFile(page(f,2))).equals(retained)); assert.equal(f.requests.at(-1).kind,'show'); assert.equal(f.requests.at(-1).head,HEAD);
});
test('uncommitted page contradiction is not adopted or repaired', async t => {
  let changed = false; const f = await capture(t,{alter:({kind,reply}) => { if(changed&&kind==='show')reply.pull_request.data.title='different'; }});
  await resumePullCapture({...f.resume,pageBudget:1}); await unlink(page(f,2,'journal'));
  const bytes = await readFile(page(f,2)); changed = true;
  await assert.rejects(resumePullCapture(f.resume),/uncommitted_page_changed/);
  assert((await readFile(page(f,2))).equals(bytes)); assert.equal((await status(f)).uncommitted_tail,true);
});
test('partial uncommitted file refuses rather than treating damage as absence', async t => {
  const f = await capture(t); await writeFile(page(f,2),'{',{mode:0o600}); const n = f.requests.length;
  await assert.rejects(resumePullCapture(f.resume)); assert.equal(f.requests.length,n); assert.equal(await readFile(page(f,2),'utf8'),'{');
});
test('source selection survives preparation interrupted before first page', async t => {
  const f = await capture(t); await unlink(page(f,1,'journal')); await unlink(page(f,1));
  const r = await resumePullCapture({...f.resume,pageBudget:1}); assert.equal(r.pages,1);
  assert.equal(f.requests.at(-1).kind,'list'); assert.equal(f.requests.at(-1).head,HEAD);
  assert.equal(r.snapshot_token,f.prepared.snapshot_token);
});
test('stored page ceiling does not reset across resumptions', async t => {
  const f = await capture(t,{}, {maxPages:2}); await resumePullCapture({...f.resume,pageBudget:1});
  const count = f.requests.length, before = await status(f);
  await assert.rejects(resumePullCapture(f.resume),/page_limit/); await assert.rejects(resumePullCapture(f.resume),/page_limit/);
  assert.equal(f.requests.length,count); assert.equal((await status(f)).checkpoint_sha256,before.checkpoint_sha256);
});
test('stored byte ceiling includes earlier invocations', async t => {
  const f = await capture(t), root = join(f.root,'small');
  const p = await preparePullCapture({...f.options,workdir:root,maxArchiveBytes:f.prepared.data_bytes+50});
  const opts={workdir:root,confirm:p.selection_sha256,tokenFile:f.token};
  await assert.rejects(resumePullCapture(opts),/archive_limit/); await assert.rejects(resumePullCapture(opts),/archive_limit/);
  assert.equal((await inspectPullCapture({workdir:root,confirm:p.selection_sha256})).pages,1);
});
test('concurrent collectors arbitrate one immutable next-page slot', async t => {
  let arrivals=0, release; const barrier=new Promise(resolve => { release=resolve; });
  const f = await capture(t,{alter:async({kind}) => { if(kind==='show'){if(++arrivals===2)release();await barrier;} }});
  const results = await Promise.allSettled([resumePullCapture({...f.resume,pageBudget:1}),resumePullCapture({...f.resume,pageBudget:1})]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1); assert.equal(results.filter(r=>r.status==='rejected').length,1);
  const s=await status(f); assert.equal(s.pages,2); assert.equal(s.checkpointed_pages,2); assert.equal(s.uncommitted_tail,false);
});
test('invalid resume options do not contact the source', async t => {
  const f=await capture(t), count=f.requests.length;
  for(const extra of [{pageBudget:0},{pageBudget:1.5},{head:HEAD},{maxPages:999},{href:f.href}]) await assert.rejects(resumePullCapture({...f.resume,...extra}));
  assert.equal(f.requests.length,count);
});
test('cancellation of a stalled continuation preserves the last checkpoint', async t => {
  let block=false; const stop=new AbortController();
  const f=await capture(t,{alter:({res})=>{if(block){res.writeHead(200,{'content-type':'application/json'});res.write('{');setTimeout(()=>stop.abort(),20);return false;}}});
  block=true; const before=await status(f);
  await assert.rejects(resumePullCapture({...f.resume,signal:stop.signal,timeoutMs:2000}));
  const after=await status(f); assert.equal(after.checkpoint_sha256,before.checkpoint_sha256); assert.equal(after.pages,1);
  block=false; const r=await resumePullCapture({...f.resume,pageBudget:1}); assert.equal(r.pages,2);
});
test('completed root is bound to selection and journal, not merely present', async t => {
  const f=await capture(t); const r=await resumePullCapture(f.resume); assert.equal(r.complete,true);
  const p=join(f.job,'archive','archive.json'),m=JSON.parse(await readFile(p));m.href='https://other.test/repo/ui/pulls/';await writeFile(p,encode(m));
  const count=f.requests.length; await assert.rejects(resumePullCapture(f.resume),/root_mismatch/);assert.equal(f.requests.length,count);
});

for(const [key,error] of [['maxReviews',/review_limit/],['maxComments',/comment_limit/]])test(`${key} stays cumulative across page-sized invocations`,async t=>{
  const f=await capture(t,{}, {[key]:1});let refused=false;
  for(let i=0;i<12;i++){
    try {await resumePullCapture({...f.resume,pageBudget:1});}
    catch(e){assert.match(e.message,error);refused=true;break;}
  }
  assert.equal(refused,true);const before=await status(f);assert.equal(before.complete,false);
  await assert.rejects(resumePullCapture(f.resume),error);assert.equal((await status(f)).checkpoint_sha256,before.checkpoint_sha256);
});
test('all checkpointed pages finalize offline after loss of only the final root',async t=>{
  const f=await capture(t),r=await resumePullCapture(f.resume);assert.equal(r.complete,true);
  await unlink(join(f.job,'archive','archive.json'));await unlink(f.token);await f.close();
  const s=await status(f);assert.equal(s.complete,false);assert.equal(s.ready_to_seal,true);
  const finished=await resumePullCapture({workdir:f.job,confirm:f.prepared.selection_sha256});
  assert.equal(finished.complete,true);assert.equal(finished.new_requests,0);assert.equal(finished.archive_sha256,r.archive_sha256);
});
