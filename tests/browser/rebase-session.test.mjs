// Actual browser client with explicit HTTP doubles; not native Rust execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { RebaseClient } from '../../crates/fgit-node/src/smart_http/server/browser/rebase.mjs';
import { objectHash, MAX_COMMITS } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-data.mjs';
import { utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fixture, token, href, crypto } from './rebase-session-fixtures.mjs';
async function setup(format='sha1') {
  const f=await fixture(format), client=new RebaseClient({href,cryptoImpl:crypto,fetchImpl:f.fetchImpl});
  await client.connect(token);await client.select(f.command.source_ref,f.command.onto_ref,format);
  return {f,client};
}
async function completeEmpty(f, policy) {
  // The SECOND change becomes empty; a kept commit hashes its actual empty tree.
  const clean=structuredClone(f.clean), inspected=structuredClone(f.inspected);
  const first=f.commits[0], original=f.original[1];
  let last=first;
  if(policy==='keep') {
    const body=utf8.encode(`tree ${first.tree}\nparent ${first.commit}\nauthor Original <o@example.invalid> 2 +0130\ncommitter ${f.input.committer} ${f.input.timestamp} +0000\n\nOriginal message 1\n`);
    const id=await objectHash('commit',body,f.algorithm,crypto);
    last={index:1,commit:id,parent:first.commit,tree:first.tree,body_hex:hex(body)};
  }
  clean.empty=policy;clean.candidate_commit=last.commit;clean.root_tree=last.tree;
  clean.steps[1]={original,rewritten:last.commit,tree:last.tree,kind:policy==='drop'?'dropped_empty':'preserved_empty'};
  inspected.candidate_commit=last.commit;
  inspected.net_change=f.diff(f.command.expected_source,last.commit,f.sourceTree,last.tree);
  inspected.commits=policy==='drop'?[inspected.commits[0]]:[inspected.commits[0],{...last,diff:f.diff(first.commit,last.commit,first.tree,last.tree)}];
  inspected.commit_count=inspected.commits.length;
  f.config.inspect=r=>Object.assign(r,structuredClone(inspected));
  return clean;
}
for(const format of ['sha1','sha256']) for(const policy of ['drop','keep']) {
  test(`${format} ${policy}: an empty stop continues the exact series and inspects its final bundle`,async()=>{
    const {f,client}=await setup(format), final=await completeEmpty(f,policy);
    f.config.sequence=[f.stopped(1,'became_empty'),final];await client.prepare(f.input);
    const before=client.state;assert.equal(before.candidate,null);
    await client.continueEmpty(policy);
    assert.deepEqual(client.selection,before.selection);
    assert.deepEqual(client.state.command,{...before.command,empty:policy});
    assert.equal(client.candidate.inspection.commit_count,policy==='drop'?1:2);
    assert.equal(f.calls.filter(c=>c.endpoint==='source/tree').length,2);
    assert.equal(f.calls.at(-1).endpoint,'source/rebase/inspect');
    assert(!f.calls.some(c=>c.endpoint.endsWith('/apply')));
    await client.stage();assert(client.pending);assert.equal(client.pending.sent,false);
  });
  test(`${format} ${policy}: earlier byte resolutions survive an empty stop unchanged`,async()=>{
    const {f,client}=await setup(format), final=await completeEmpty(f,policy);
    f.config.sequence=[f.stopped(0),f.stopped(1,'became_empty'),final];
    await client.prepare(f.input);
    const bytes=new Uint8Array([0,255,10,13]);
    await client.resolve([{path_hex:f.conflict(0).path_hex,choice:'file',mode:0o100755,bytes}]);
    bytes.fill(42);const before=client.state;
    await client.continueEmpty(policy);
    const calls=f.calls.filter(c=>c.endpoint==='source/rebase/resolve');assert.equal(calls.length,2);
    assert.deepEqual(calls[0].files.get('file_0'),calls[1].files.get('file_0'));
    assert.deepEqual(calls[1].files.get('file_0'),new Uint8Array([0,255,10,13]));
    assert.deepEqual(calls[0].command.getAll('resolution'),calls[1].command.getAll('resolution'));
    assert.equal(client.state.resolutionPaths,1);assert.equal(client.state.resolutionBytes,before.resolutionBytes);
    assert.equal(client.candidate.metadata.resolution_consumed_commits,1);
  });
}
test('session observations are detached and never expose recipe bytes or credentials',async()=>{
 const {f,client}=await setup();f.config.sequence=[f.stopped(0),f.stopped(1,'became_empty')];await client.prepare(f.input);
 await client.resolve([{path_hex:f.conflict(0).path_hex,choice:'file',mode:0o100644,bytes:new Uint8Array([0,255])}]);
 const state=client.state;assert.equal(state.resolutionBytes,f.conflict(0).path_hex.length/2+2);
 state.command.expected_source=f.onto;state.selection.onto.commit=f.original[0];state.report.state='clean';state.resolutionCommits.length=0;
 assert.equal(client.state.report.state,'became_empty');assert.equal(client.state.command.expected_source,f.command.expected_source);
 assert.deepEqual(client.state.resolutionCommits,[f.original[0]]);assert(!JSON.stringify(client.state).includes(token));
 assert(!('recipes' in client.state));assert(!('bundle' in client.state));
});
test('invalid empty policies and continuation without a stop send no requests',async()=>{
 const {f,client}=await setup();const n=f.calls.length;
 for(const policy of ['drop','keep','stop','',null,{},'force'])await assert.rejects(client.continueEmpty(policy));
 assert.equal(f.calls.length,n);f.config.sequence=[f.stopped(1,'became_empty')];await client.prepare(f.input);
 const before=client.state,count=f.calls.length;
 for(const policy of ['stop','',null,{},'force'])await assert.rejects(client.continueEmpty(policy));
 assert.equal(f.calls.length,count);assert.deepEqual(client.state,before);
});
test('failed continuation retains its previous stop and exact recipes for another explicit attempt',async()=>{
 const {f,client}=await setup();f.config.sequence=[f.stopped(0),f.stopped(1,'became_empty')];await client.prepare(f.input);
 await client.resolve([{path_hex:f.conflict(0).path_hex,choice:'ours'}]);const before=client.state;
 f.config.prepare=r=>{r.expected_source=f.id(77);};await assert.rejects(client.continueEmpty('keep'));
 assert.deepEqual(client.state,before);assert.equal(client.candidate,null);
 f.config.prepare=null;f.config.sequence=[await completeEmpty(f,'keep')];await client.continueEmpty('keep');
 assert(client.candidate);assert.equal(client.state.resolutionPaths,1);
});
test('uninspected or corrupted complete series cannot replace a stopped candidate',async()=>{
 const {f,client}=await setup();f.config.sequence=[f.stopped(1,'became_empty')];await client.prepare(f.input);
 f.config.sequence=[await completeEmpty(f,'keep')];f.config.inspect=r=>{r.complete=false;};
 await assert.rejects(client.continueEmpty('keep'));assert.equal(client.candidate,null);
 assert.equal(client.report.state,'became_empty');await assert.rejects(client.stage());
});
for(const method of ['cancel','disconnect']) test(`${method} during continuation cannot resurrect an inspected candidate`,async()=>{
 const {f,client}=await setup();f.config.sequence=[f.stopped(1,'became_empty'),await completeEmpty(f,'keep')];await client.prepare(f.input);
 let release;f.config.wait=e=>e==='source/rebase/inspect'?new Promise(r=>release=r):null;
 const operation=client.continueEmpty('keep');while(!release)await new Promise(r=>setImmediate(r));
 client[method]();release();await assert.rejects(operation);assert.equal(client.candidate,null);assert.equal(client.pending,null);
 assert(!f.calls.some(c=>c.endpoint.endsWith('/apply')));
});
test('an in-flight continuation cannot be replaced by a second policy',async()=>{
 const {f,client}=await setup();f.config.sequence=[f.stopped(1,'became_empty'),await completeEmpty(f,'keep')];await client.prepare(f.input);
 let release;f.config.wait=e=>e==='source/rebase/prepare'?new Promise(r=>release=r):null;
 const running=client.continueEmpty('keep');while(!release)await new Promise(r=>setImmediate(r));
 const n=f.calls.length;await assert.rejects(client.continueEmpty('drop'),/already running/);assert.equal(f.calls.length,n);
 release();await running;assert.equal(client.state.command.empty,'keep');
});
test('narrowed commit limits are enforced on replies and never widened by continuation',async()=>{
 const {f,client}=await setup();await assert.rejects(client.prepare({...f.input,max_commits:1}),/step list/);
 const n=f.calls.length;for(const max_commits of [0,MAX_COMMITS+1,1.5,'1',NaN])await assert.rejects(client.prepare({...f.input,max_commits}));
 assert.equal(f.calls.length,n);f.config.sequence=[f.stopped(1,'became_empty'),await completeEmpty(f,'drop')];
 await client.prepare({...f.input,max_commits:2});await client.continueEmpty('drop');assert.equal(client.state.command.max_commits,2);
});
test('the whole read timeout retains a safe stop and prevents publication',async()=>{
 const f=await fixture(),client=new RebaseClient({href,cryptoImpl:crypto,fetchImpl:f.fetchImpl,operationTimeoutMs:50});
 await client.connect(token);await client.select(f.command.source_ref,f.command.onto_ref,'sha1');f.config.sequence=[f.stopped(1,'became_empty')];await client.prepare(f.input);
 f.config.sequence=[await completeEmpty(f,'keep')];f.config.wait=()=>new Promise(r=>setTimeout(r,100));
 await assert.rejects(client.continueEmpty('keep'));assert.equal(client.candidate,null);assert.equal(client.report.state,'became_empty');
});
test('pending publication blocks policy changes and retries preserve exact bytes',async()=>{
 const {f,client}=await setup();f.config.sequence=[f.stopped(1,'became_empty'),await completeEmpty(f,'keep')];await client.prepare(f.input);await client.continueEmpty('keep');await client.stage();
 const p=client.pending,n=f.calls.length;await assert.rejects(client.continueEmpty('drop'));assert.equal(f.calls.length,n);assert.deepEqual(client.pending,p);
 f.config.lose=true;await assert.rejects(client.send());const sent=f.calls.at(-1);const receipt=client.exportReceipt();assert(!receipt.includes(token));
 const restored=new RebaseClient({href,cryptoImpl:crypto,fetchImpl:f.fetchImpl});await restored.connect(token);const reads=f.calls.length;
 await restored.restoreReceipt(receipt);assert.equal(f.calls.length,reads);assert.equal(restored.pending.key,p.key);
 await assert.rejects(restored.send());assert.deepEqual(f.calls.at(-1).options.body,sent.options.body);
});
