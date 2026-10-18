import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir, unlink, stat, symlink, link } from 'node:fs/promises';
import { join } from 'node:path';
import { exportPullArchive, inspectPullArchive, PULL_ARCHIVE_LIMITS as L } from '../../scripts/lib/forge-pull-archive.mjs';
import { fixture, rewriteArchive, HEAD, TEN } from './pull-archive-fixture.mjs';

for(const format of ['sha1','sha256'])test(`complete production HTTP traversal and credential-free readback: ${format}`,async t=>{
  const f=await fixture(t,{format});const result=await exportPullArchive(f.options);
  assert.equal(result.pulls,2);assert.equal(result.reviews,4);assert.equal(result.comments,6);assert.equal(result.complete,true);
  assert(f.requests.slice(1).every(r=>r.head===HEAD));assert.equal(f.requests.length,result.pages);
  await f.close();await unlink(f.token);
  const fetch=globalThis.fetch;globalThis.fetch=()=>{throw new Error('offline inspection used fetch');};
  try{const read=await inspectPullArchive({workdir:f.out,confirm:result.archive_sha256});assert.equal(read.complete,true);assert.equal(read.network_accessed,false);assert.equal(read.merge_authority,false);}
  finally{globalThis.fetch=fetch;}
});
for(const [name,options,expected] of [['empty',{pulls:0},[0,0,0]],['empty conversations',{reviews:0,comments:0},[2,0,0]],
  ['byte-only refs',{changeRow:r=>{r.data.source_ref=null;r.data.source_ref_hex=Buffer.from('refs/heads/').toString('hex')+'ff';}},[2,4,6]],
  ['closed pulls',{changeRow:r=>{r.state='closed';}},[2,4,6]]])test(name,async t=>{
    const f=await fixture(t,options),result=await exportPullArchive(f.options);assert.deepEqual([result.pulls,result.reviews,result.comments],expected);
    assert.equal((await inspectPullArchive({workdir:f.out,confirm:result.archive_sha256})).complete,true);
  });
const attacks=[
  ['missing review stream',p=>p.filter(v=>!(v.desc.kind==='reviews'&&v.desc.number===1))],
  ['missing discussion stream',p=>p.filter(v=>!(v.desc.kind==='comments'&&v.desc.number===1))],
  ['missing first review page',p=>p.filter(v=>!(v.desc.kind==='reviews'&&v.desc.number===1&&v.desc.cursor===null))],
  ['missing first comment page',p=>p.filter(v=>!(v.desc.kind==='comments'&&v.desc.number===1&&v.desc.cursor===0))],
  ['missing final comment page',p=>p.slice(0,-1)],
  ['unfollowed list continuation',p=>p.slice(0,p.findIndex((v,i)=>i>0&&v.desc.kind==='list'))],
  ['duplicate comment page',p=>{const i=p.findIndex(v=>v.desc.kind==='comments');p.splice(i,0,structuredClone(p[i]));}],
  ['orphan review stream',p=>{const v=p.find(v=>v.desc.kind==='reviews');v.desc.number=88;v.reply.number=88;for(const r of v.reply.reviews)r.subject.number=88;}],
  ['changed show metadata',p=>{p.find(v=>v.desc.kind==='show').reply.pull_request.data.body='different';}],
  ['changed show actor',p=>{p.find(v=>v.desc.kind==='show').reply.pull_request.opened_by='77'.repeat(16);}],
  ['wrong manifest tenant',(p,m)=>{m.tenant_id='88'.repeat(16);}],
  ['wrong manifest repository',(p,m)=>{m.repository_id='88'.repeat(16);}],
  ['wrong manifest incarnation',(p,m)=>{m.repository_incarnation='88'.repeat(16);}],
  ['wrong manifest hash domain',(p,m)=>{m.object_format='sha256';}],
  ['changed source head',p=>{p.at(-1).reply.source_head='different';}],
  ['changed snapshot',p=>{p.at(-1).reply.snapshot_token='alg:2:'+'99'.repeat(32);}],
  ['review metadata version',p=>{const v=p.find(v=>v.desc.kind==='reviews');v.reply.pull_request_version=2;v.reply.reviews[0].subject.pull_request_version=2;}],
  ['review policy epoch drift',p=>{const v=p.find(v=>v.desc.kind==='reviews'&&v.desc.cursor!==null);v.reply.policy_epoch=2;v.reply.reviews[0].subject.policy_epoch=2;}],
  ['discussion high water drift',p=>{const v=p.find(v=>v.desc.kind==='comments'&&v.desc.cursor===1);v.reply.discussion_version=4;}],
  ['unavailable reviews',p=>{const v=p.find(v=>v.desc.kind==='reviews');Object.assign(v.reply,{found:false,reviews:[],next_after:null,source_head:null,snapshot_token:null,pull_request_version:null,policy_epoch:null});}],
  ['nonzero show cursor',p=>{p.find(v=>v.desc.kind==='show').desc.cursor=1;}],
  ['reordered streams',p=>{[p[1],p[2]]=[p[2],p[1]];}],
];
for(const [name,alter] of attacks)test(`complete readback refuses ${name} even with recalculated hashes`,async t=>{
  const f=await fixture(t),result=await exportPullArchive(f.options);await inspectPullArchive({workdir:f.out,confirm:result.archive_sha256});
  const confirm=await rewriteArchive(f.out,alter);await assert.rejects(inspectPullArchive({workdir:f.out,confirm}));
});
test('online metadata mismatch never publishes the root',async t=>{
  const f=await fixture(t,{alter:({kind,reply})=>{if(kind==='show')reply.pull_request.data.title='changed';}});
  await assert.rejects(exportPullArchive(f.options),/metadata_changed/);assert(!(await readdir(f.out)).includes('archive.json'));
});
test('scope mismatch refuses at first response',async t=>{
  const f=await fixture(t);await assert.rejects(exportPullArchive({...f.options,tenant:'ff'.repeat(16)}),/repository_mismatch/);assert.equal(f.requests.length,1);
});
test('global page budget refuses before an extra request',async t=>{
  const f=await fixture(t);await assert.rejects(exportPullArchive({...f.options,maxPages:2}),/page_limit/);assert.equal(f.requests.length,2);
});
test('abort of a real stalled HTTP body settles without a root',async t=>{
  const stop=new AbortController();const f=await fixture(t,{alter:({kind,res})=>{if(kind==='reviews'){res.writeHead(200,{'content-type':'application/json'});res.write('{');setTimeout(()=>stop.abort(),25);return false;}}});
  await assert.rejects(exportPullArchive({...f.options,signal:stop.signal,timeoutMs:2000}));assert(!(await readdir(f.out)).includes('archive.json'));
});
test('whole-operation deadline stops stalled capture',async t=>{
  const f=await fixture(t,{alter:({res})=>{res.writeHead(200,{'content-type':'application/json'});res.write('{');return false;}});
  await assert.rejects(exportPullArchive({...f.options,timeoutMs:75}));assert(!(await readdir(f.out)).includes('archive.json'));
});
test('response allocation is bounded by the archive page envelope',async t=>{
  const f=await fixture(t,{alter:({reply})=>{reply.padding='x'.repeat(L.pageBytes+1);}});
  await assert.rejects(exportPullArchive(f.options),/Response exceeds/);assert.equal(f.requests.length,1);
});
test('non-ASCII token bytes cannot be folded into a valid credential',async t=>{
  const f=await fixture(t);await writeFile(f.token,Buffer.alloc(64,0xe1));await assert.rejects(exportPullArchive(f.options),/pull_archive_token/);assert.equal(f.requests.length,0);
});
for(const field of ['username','password'])test(`credential-bearing endpoint refuses before capture: ${field}`,async t=>{
  const f=await fixture(t),url=new URL(f.href);url[field]='secret';await assert.rejects(exportPullArchive({...f.options,href:url.href}));assert.equal(f.requests.length,0);
});
test('existing archive is never overwritten and bad pin fails',async t=>{
  const f=await fixture(t),r=await exportPullArchive(f.options);const before=await readFile(join(f.out,'archive.json'));
  await assert.rejects(exportPullArchive(f.options),/record_exists/);await assert.rejects(inspectPullArchive({workdir:f.out,confirm:'0'.repeat(64)}),/pin_mismatch/);
  assert((await readFile(join(f.out,'archive.json'))).equals(before));assert.equal((await inspectPullArchive({workdir:f.out,confirm:r.archive_sha256})).complete,true);
});
test('all archive custody files are private regular single links',async t=>{
  const f=await fixture(t),r=await exportPullArchive(f.options);for(const name of await readdir(f.out)){const s=await stat(join(f.out,name));assert.equal(s.mode&0o777,0o600);assert.equal(s.nlink,1);}
  const page=join(f.out,'page-000001.json');await link(page,join(f.root,'extra-link'));
  await assert.rejects(inspectPullArchive({workdir:f.out,confirm:r.archive_sha256}),/private_file/);
});
test('inspector refuses unexpected files and symlinked custody',async t=>{
  const f=await fixture(t),r=await exportPullArchive(f.options);await writeFile(join(f.out,'unknown'),'x',{mode:0o600});
  await assert.rejects(inspectPullArchive({workdir:f.out,confirm:r.archive_sha256}),/unexpected_file/);await unlink(join(f.out,'unknown'));
  const alias=join(f.root,'alias');await symlink(f.out,alias);await assert.rejects(inspectPullArchive({workdir:alias,confirm:r.archive_sha256}),/directory_changed_or_unsafe/);
});
