import test from 'node:test';
import assert from 'node:assert/strict';
import { captureGithubPulls,parseGithubPullCapture,githubPullCaptureBytes,encodeGithubPulls,GITHUB_PULL_LIMITS as L } from '../../scripts/lib/github-pull-source.mjs';
import { githubPeer,REPO,TOKEN,AT } from './github-pull-fixture.mjs';

test('captures all three discussion/review streams through actual bounded source transport',async t=>{
  const f=await githubPeer(t),r=await captureGithubPulls(f.options),e=r.capture.pulls[0];
  assert.equal(e.pull.head.repo.full_name,'alice/project');assert.equal(e.pull.base.repo.full_name,REPO);
  assert.equal(e.pull.body,'\ufeffexact body\r\nwith 雪\n');assert.equal(e.inline[0].diff_hunk,'@@ -1 +1 @@\n-old\n+new\n');
  assert.equal(e.reviews[0].state,'APPROVED');assert.equal(e.inline[0].original_commit_id,'c'.repeat(40));
  assert.equal(r.capture.consistency,'two-equal-observations-not-atomic');assert.equal(r.atomic_snapshot,false);assert.equal(r.mutation_submitted,false);
  assert.equal(r.statistics.requests,14);assert.equal(f.calls.length,14);assert(f.calls.every(c=>c.authorization===`Bearer ${TOKEN}`&&c.version==='2026-03-10'));
  await f.close();assert.deepEqual(parseGithubPullCapture(r.bytes),r.capture);assert.equal(r.sha256.length,64);
});
test('walks every page independently for discussion, reviews and inline comments',async t=>{
  const f=await githubPeer(t,{discussions:101,reviews:101,inlines:101}),r=await captureGithubPulls(f.options);
  for(const k of ['discussion','reviews','inline']){assert.equal(r.capture.pulls[0][k].length,101);assert.equal(f.calls.filter(c=>c.kind===k&&c.page===2).length,2);}
  assert.equal(f.calls.length,20);
});
for(const [name,alter] of [
  ['fork deleted',s=>{if(s.kind==='pull')s.value.head.repo=null;}],
  ['draft',s=>{if(s.kind==='pull')s.value.draft=true;}],
  ['merged',s=>{if(s.kind==='pull')Object.assign(s.value,{state:'closed',closed_at:AT,merged:true,merged_at:AT,merge_commit_sha:'d'.repeat(40)});} ],
  ['ghost reviewer',s=>{if(s.kind==='reviews')s.value[0].user=null;}],
  ['outdated inline location',s=>{if(s.kind==='inline'){s.value[0].position=null;s.value[0].line=null;}}],
])test(`retains ${name} without inventing native authority`,async t=>{
  const f=await githubPeer(t,{alter}),r=await captureGithubPulls(f.options);assert.deepEqual(parseGithubPullCapture(r.bytes),r.capture);
});
for(const [name,alter] of [
  ['wrong repository',s=>{if(s.kind==='repository')s.value.full_name='other/repo';}],
  ['wrong PR',s=>{if(s.kind==='pull')s.value.number++;}],
  ['wrong base repository',s=>{if(s.kind==='pull')s.value.base.repo.id++;}],
  ['wrong discussion scope',s=>{if(s.kind==='discussion')s.value[0].issue_url='https://api.github.com/repos/other/repo/issues/9';}],
  ['wrong review scope',s=>{if(s.kind==='reviews')s.value[0].pull_request_url='https://api.github.com/repos/other/repo/pulls/9';}],
  ['wrong inline scope',s=>{if(s.kind==='inline')s.value[0].html_url='https://evil.test/data#x';}],
  ['pending review',s=>{if(s.kind==='reviews')s.value[0].state='PENDING';}],
  ['unknown review state',s=>{if(s.kind==='reviews')s.value[0].state='TRUSTED';}],
  ['wrong Git domain',s=>{if(s.kind==='pull')s.value.head.sha='a'.repeat(64);}],
  ['unknown review side',s=>{if(s.kind==='inline')s.value[0].side='MIDDLE';}],
  ['omitted comments',s=>{if(s.kind==='discussion')s.value=[];}],
  ['duplicate reviews',s=>{if(s.kind==='reviews')s.value.push(s.value[0]);}],
  ['duplicate inline comments',s=>{if(s.kind==='inline')s.value.push(s.value[0]);}],
  ['repository identity changes',s=>{if(s.kind==='repository'&&s.count>1)s.value.id++;}],
  ['head changes within bracket',s=>{if(s.kind==='pull'&&s.count>2)s.value.head.sha='e'.repeat(40);}],
  ['review body changes only in second observation',s=>{if(s.kind==='reviews'&&s.count>7)s.value[0].body+='edited';}],
  ['inline location changes only in second observation',s=>{if(s.kind==='inline'&&s.count>7)s.value[0].line++;}],
])test(`refuses ${name} instead of claiming a complete capture`,async t=>{
  const f=await githubPeer(t,{alter});await assert.rejects(captureGithubPulls(f.options));
});
for(const link of [
  '<https://evil.test/steal>; rel="next"',
  `<https://api.github.com/repos/${REPO}/pulls/10/reviews?per_page=100&page=2>; rel="next"`,
  `<https://api.github.com/repos/${REPO}/pulls/9/reviews?per_page=100&page=1>; rel="next"`,
  `<https://api.github.com/repos/${REPO}/pulls/9/reviews?per_page=100&page=2&token=oops>; rel="next"`,
])test('untrusted pagination never becomes a credential-bearing request: '+link,async t=>{
  const f=await githubPeer(t,{reviews:101,alter:s=>{if(s.kind==='reviews')s.link=link;}});
  await assert.rejects(captureGithubPulls(f.options),/pagination/);assert.equal(f.calls.filter(c=>c.kind==='reviews').length,1);
});
test('numeric repository Link aliases are accepted but never followed as supplied',async t=>{
  const f=await githubPeer(t,{reviews:101,alter:s=>{if(s.kind==='reviews'&&s.page===1)s.link='<https://api.github.com/repositories/123/pulls/9/reviews?per_page=100&page=2>; rel="next"';}});
  assert.equal((await captureGithubPulls(f.options)).capture.pulls[0].reviews.length,101);
});
test('selection and request budgets fail without an additional fetch',async t=>{
  const f=await githubPeer(t);for(const n of [[],[9,9],[0],Array.from({length:101},(_,i)=>i+1)])await assert.rejects(captureGithubPulls({...f.options,numbers:n}));
  assert.equal(f.calls.length,0);await assert.rejects(captureGithubPulls({...f.options,maxRequests:3}),/request_limit/);assert.equal(f.calls.length,3);
});
test('read-byte, record and retained-package budgets are hard bounds',async t=>{
  const f=await githubPeer(t);await assert.rejects(captureGithubPulls({...f.options,maxReadBytes:1}),/read_bytes/);
  const g=await githubPeer(t,{reviews:2001});await assert.rejects(captureGithubPulls(g.options),/record_limit/);
  const h=await githubPeer(t,{reviews:20,alter:s=>{if(s.kind==='reviews')for(const row of s.value)row.body='x'.repeat(65536);}});
  await assert.rejects(captureGithubPulls(h.options),/capture_bytes/);
});
test('cancellation drains a real stalled response',async t=>{
  const stop=new AbortController(),f=await githubPeer(t,{alter:s=>{if(s.kind==='reviews'){s.res.writeHead(200,{'content-type':'application/json'});s.res.write('[');setTimeout(()=>stop.abort(),20);return false;}}});
  await assert.rejects(captureGithubPulls({...f.options,signal:stop.signal,timeoutMs:2000}));assert.equal(f.calls.length,4);
});
test('offline package rejects unknown fields, edits, BOM and duplicate-key encodings',async t=>{
  const f=await githubPeer(t),r=await captureGithubPulls(f.options);for(const change of [v=>v.extra=true,v=>v.pulls[0].inline[0].extra=true,v=>v.pulls[0].pull.comments=99]){
    const v=structuredClone(r.capture);change(v);assert.throws(()=>parseGithubPullCapture(encodeGithubPulls(v)));
  }
  assert.throws(()=>parseGithubPullCapture(Buffer.concat([Buffer.from('\ufeff'),r.bytes])));
  const duplicate=r.bytes.toString().replace('"schema":','"schema":"ignored","schema":');assert.throws(()=>parseGithubPullCapture(Buffer.from(duplicate)));
  assert.throws(()=>parseGithubPullCapture(Buffer.alloc(L.bytes+1)));
  assert(githubPullCaptureBytes(r.capture).equals(r.bytes));
});
