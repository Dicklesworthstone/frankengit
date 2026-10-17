import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverGithubPulls, parseGithubPullInventory, githubPullInventoryBytes, selectGithubPullBatch,
  captureGithubPullBatch, GITHUB_PULL_INVENTORY_LIMITS as L } from '../../scripts/lib/github-pull-inventory.mjs';
import { createGithubPullCaptureSession, captureGithubPulls, parseGithubPullCapture } from '../../scripts/lib/github-pull-source.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { inventoryPeer, REPO, TOKEN } from './github-pull-inventory-fixture.mjs';

const population=n=>Array.from({length:n},(_,i)=>i+1);
const link=(page=2,path=`/repos/${REPO}/pulls`,extra='')=>`<https://api.github.com${path}?state=all&sort=created&direction=asc&per_page=100&page=${page}${extra}>; rel="next"`;
for(const count of [0,1,100,101,203])test(`discovers all ${count} PR aliases without treating a full page as EOF`,async t=>{
  const f=await inventoryPeer(t,{pulls:population(count)}),r=await discoverGithubPulls({...f.options,batchSize:25});
  assert.equal(r.inventory.pulls.length,count);assert.equal(r.total_batches,Math.ceil(count/25));
  assert.equal(r.statistics.requests,f.calls.length);assert.equal(f.calls.filter(c=>c.kind==='listing').length,2*(Math.floor(count/100)+1));
  assert.equal(r.atomic_snapshot,false);assert.equal(r.mutation_submitted,false);
  assert(f.calls.every(c=>c.authorization===`Bearer ${TOKEN}`));await f.close();
  assert.deepEqual(parseGithubPullInventory(r.bytes),r.inventory);assert.equal(recordDigest(r.bytes),r.sha256);
  if(!count)assert.throws(()=>selectGithubPullBatch(r.inventory,r.sha256,1));
});
test('actual 10000-row HTTP membership inventory stays within the advertised bound',async t=>{
  const f=await inventoryPeer(t,{pulls:population(L.pulls)}),r=await discoverGithubPulls(f.options);
  assert.equal(r.inventory.pulls.length,L.pulls);assert.equal(r.statistics.requests,206);assert(r.bytes.length<=L.bytes);
  const last=selectGithubPullBatch(r.inventory,r.sha256,r.total_batches);assert.equal(last.numbers.at(-1),L.pulls);assert.equal(last.next_batch,null);
});
test('created-time ties do not invent a numeric pagination order',async t=>{
  const f=await inventoryPeer(t,{pulls:[44,9,17]}),r=await discoverGithubPulls(f.options);
  assert.deepEqual(r.inventory.pulls.map(r=>r.number),[9,17,44]);
});
test('closed and draft listing entries remain members rather than being filtered out',async t=>{
  const f=await inventoryPeer(t,{alter:s=>{if(s.kind==='listing'){s.value[0].state='closed';s.value[1].draft=true;}}});
  assert.equal((await discoverGithubPulls(f.options)).inventory.pulls.length,2);
});
for(const [name,alter] of [
  ['repository identity drift',s=>{if(s.kind==='repository'&&s.count>1)s.value.id++;}],
  ['repository name substitution',s=>{if(s.kind==='repository')s.value.full_name='other/project';}],
  ['PR identity drift between passes',s=>{if(s.kind==='listing'&&s.count>3)s.value[0].id++;}],
  ['membership growth',s=>{if(s.kind==='listing'&&s.count===2)s.value.pop();}],
  ['duplicate PR ID',s=>{if(s.kind==='listing')s.value[1].id=s.value[0].id;}],
  ['duplicate number',s=>{if(s.kind==='listing')s.value.push(s.value[0]);}],
  ['foreign PR URL',s=>{if(s.kind==='listing')s.value[0].url='https://api.github.com/repos/other/repo/pulls/9';}],
  ['foreign base ID',s=>{if(s.kind==='listing')s.value[0].base.repo.id++;}],
  ['foreign html URL',s=>{if(s.kind==='listing')s.value[0].html_url='https://evil.test/pull/9';}],
  ['wrong listing type',s=>{if(s.kind==='listing')s.value={items:s.value};}],
])test(`refuses ${name} instead of a successful partial inventory`,async t=>{
  const f=await inventoryPeer(t,{alter});await assert.rejects(discoverGithubPulls(f.options));
});
for(const invalid of [link(1),link(3),link(2,'/repos/other/repo/pulls'),link(2,`/repos/${REPO}/issues`),
  link(2,`/repos/${REPO}/pulls`,'&state=open'),link().replace('state=all','state=open'),
  link().replace('https://api.github.com','https://evil.test'),`${link()}, ${link()}`,link().replace('rel="next"','rel="unknown"')])
  test('refuses changed pagination scope or sequence: '+invalid,async t=>{
    const f=await inventoryPeer(t,{pulls:population(101),alter:s=>{if(s.kind==='listing')s.link=invalid;}});
    await assert.rejects(discoverGithubPulls(f.options),/pagination/);assert.equal(f.calls.length,2);
  });
test('numeric repository alias is checked but the next request is locally constructed',async t=>{
  const f=await inventoryPeer(t,{pulls:population(101),alter:s=>{if(s.kind==='listing'&&s.page===1)s.link=link(2,'/repositories/123/pulls');}});
  assert.equal((await discoverGithubPulls(f.options)).inventory.pulls.length,101);assert(f.calls.every(c=>c.path.startsWith('/repos/')));
});
test('a short page cannot advertise an unobserved continuation',async t=>{
  const f=await inventoryPeer(t,{alter:s=>{if(s.kind==='listing')s.link=link();}});
  await assert.rejects(discoverGithubPulls(f.options),/incomplete_page/);assert.equal(f.calls.length,2);
});
test('cumulative request and population limits refuse before extra reads',async t=>{
  const f=await inventoryPeer(t);await assert.rejects(discoverGithubPulls({...f.options,maxRequests:3}),/request_limit/);assert.equal(f.calls.length,3);
  const g=await inventoryPeer(t,{pulls:population(101)});await assert.rejects(discoverGithubPulls({...g.options,maxPulls:100}),/pull_limit/);
  assert.equal(g.calls.filter(c=>c.kind==='listing').length,2);
});
test('discovery validates limits and selectors before any source work',async t=>{
  const f=await inventoryPeer(t);
  for(const extra of [{maxPulls:10001},{batchSize:0},{maxRequests:0},{maxReadBytes:0},{repository:'../repo'},{endpoint:'https://evil.test'}])
    await assert.rejects(discoverGithubPulls({...f.options,...extra}));
  assert.equal(f.calls.length,0);
});
test('discovery read bytes and deadline cancel without a result',async t=>{
  const f=await inventoryPeer(t);await assert.rejects(discoverGithubPulls({...f.options,maxReadBytes:1}),/read_bytes/);
  const g=await inventoryPeer(t,{alter:s=>{if(s.kind==='listing'){s.res.writeHead(200,{'content-type':'application/json'});s.res.write('[');return false;}}});
  await assert.rejects(discoverGithubPulls({...g.options,timeoutMs:75}));assert.equal(g.calls.length,2);
});
test('inventory partition is pinned and each capture retains exact membership',async t=>{
  const f=await inventoryPeer(t,{pulls:[9,17,23],records:1}),r=await discoverGithubPulls({...f.options,batchSize:2});
  const first=selectGithubPullBatch(r.inventory,r.sha256,1);assert.deepEqual(first.numbers,[9,17]);assert.equal(first.next_batch,2);
  const captured=await captureGithubPullBatch({inventory:r.inventory,confirm:r.sha256,batch:2,fetchImpl:f.fetchImpl,token:TOKEN});
  assert.deepEqual(captured.capture.pulls.map(e=>e.pull.number),[23]);assert.equal(captured.first_index,2);assert.equal(captured.next_batch,null);
  assert.deepEqual(parseGithubPullCapture(captured.bytes),captured.capture);assert.equal(captured.capture.pulls[0].inline.length,1);
  const n=f.calls.length;await assert.rejects(captureGithubPullBatch({inventory:r.inventory,confirm:'0'.repeat(64),batch:1,fetchImpl:f.fetchImpl}));
  r.inventory.batch_size=1;assert.throws(()=>selectGithubPullBatch(r.inventory,r.sha256,1));assert.equal(f.calls.length,n);
});
for(const field of ['repository','pull'])test(`a replaced ${field} after discovery refuses before discussion reads`,async t=>{
  let changed=false;
  const f=await inventoryPeer(t,{alter:s=>{if(changed&&s.kind===field)s.value.id++;}}),r=await discoverGithubPulls(f.options);
  changed=true;const count=f.calls.length;
  await assert.rejects(captureGithubPullBatch({inventory:r.inventory,confirm:r.sha256,batch:1,fetchImpl:f.fetchImpl}),/inventory_.*changed/);
  assert.equal(f.calls.length-count,field==='repository'?1:2);
});
test('offline inventory rejects duplicate keys, unknown fields, ordering and bad pins',async t=>{
  const f=await inventoryPeer(t),r=await discoverGithubPulls(f.options);
  for(const mutate of [v=>v.extra=true,v=>v.pulls.reverse(),v=>v.pulls[1].id=v.pulls[0].id,v=>v.complete=false]) {
    const v=structuredClone(r.inventory);mutate(v);assert.throws(()=>githubPullInventoryBytes(v));
  }
  assert.throws(()=>parseGithubPullInventory(Buffer.concat([Buffer.from('\ufeff'),r.bytes])));
  assert.throws(()=>parseGithubPullInventory(Buffer.from(r.bytes.toString().replace('"schema":','"schema":"other","schema":'))));
  const v=structuredClone(r.inventory);v.pulls[0].id='18446744073709551615';assert.equal(parseGithubPullInventory(githubPullInventoryBytes(v)).pulls[0].id,v.pulls[0].id);
  assert.throws(()=>selectGithubPullBatch(r.inventory,'f'.repeat(64),1));
});
test('capture session never renews its request budget between batches',async t=>{
  const f=await inventoryPeer(t),owner=createGithubPullCaptureSession({...f.options,maxRequests:20});t.after(owner.close);
  assert.equal((await owner.capture([9])).statistics.requests,14);
  await assert.rejects(owner.capture([17]),/request_limit/);assert.equal(f.calls.length,20);
  await assert.rejects(owner.capture([9]),/session_closed/);assert.equal(f.calls.length,20);
});
test('shared owner preserves old single-capture bytes and cumulative statistics',async t=>{
  const f=await inventoryPeer(t),single=await captureGithubPulls({...f.options,numbers:[9]}),owner=createGithubPullCaptureSession(f.options);t.after(owner.close);
  assert((await owner.capture([9])).bytes.equals(single.bytes));assert.equal((await owner.capture([17])).statistics.requests,28);
});
test('overlapping batch capture refuses rather than mixing observations',async t=>{
  let arrived,release;const seen=new Promise(r=>arrived=r),barrier=new Promise(r=>release=r);
  const f=await inventoryPeer(t,{alter:async s=>{if(s.count===1){arrived();await barrier;}}}),owner=createGithubPullCaptureSession(f.options);t.after(owner.close);
  const first=owner.capture([9]);await seen;await assert.rejects(owner.capture([17]),/session_busy/);release();assert.equal((await first).capture.pulls.length,1);
});
test('caller edits cannot alter an in-flight expected inventory selection',async t=>{
  const expected={source:{id:'123',full_name:REPO},pulls:[{number:9,id:'909'}]};
  const f=await inventoryPeer(t,{alter:s=>{if(s.count===1){expected.source.id='999';expected.pulls[0].id='1';}}});
  const r=await captureGithubPulls({...f.options,numbers:[9],expectedSelection:expected});assert.equal(r.capture.pulls[0].pull.id,'909');
});
