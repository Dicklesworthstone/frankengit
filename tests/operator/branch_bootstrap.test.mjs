import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir, unlink, lstat, link, symlink, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { prepareBootstrap, bootstrapStatus, runBootstrap } from '../../scripts/lib/branch-bootstrap.mjs';
import { BOOTSTRAP_LIMITS as L, selection, createRequest, checkedRequest, canonical, encode, hash, parse, publication, operateBranch }
  from '../../scripts/lib/branch-bootstrap-protocol.mjs';
import { fixture, TOKEN, ROTATED, absent, wire } from './branch-bootstrap-fixture.mjs';

async function prepared(t,options){const f=await fixture(t,options),p=await prepareBootstrap(f.prepare);return {...f,p,run:{workdir:p.workdir,confirm:p.plan_sha256,tokenFile:f.tokenFile}};}
const status=f=>bootstrapStatus({workdir:f.p.workdir,confirm:f.p.plan_sha256});
const requestFile=(f,n=1)=>join(f.p.workdir,'requests',`request-${String(n).padStart(6,'0')}.json`);
const request=async(f,n=1)=>canonical(await readFile(requestFile(f,n)));
const attemptFile=(f,n,file)=>join(f.p.workdir,'journal',`attempt-${String(n).padStart(6,'0')}`,file);

test('canonical fixture roots do not authorize an explicitly aliased custody parent',async t=>{
  const f=await fixture(t),alias=join(f.root,'alias');await symlink(f.root,alias);
  await assert.rejects(prepareBootstrap({...f.prepare,workdir:join(alias,'job')}),
    error=>error.code==='branch_bootstrap_directory_changed_or_unsafe');
  assert.equal(f.requests.length,0);
  await assert.rejects(lstat(join(f.root,'job')),error=>error.code==='ENOENT');
});

for(const format of ['sha1','sha256'])test(`prepare and execute actual native-schema HTTP batch in ${format}`,async t=>{
  const f=await prepared(t,{format});assert.equal(f.requests.length,0);assert.equal(f.p.mutation_submitted,false);
  const r=await runBootstrap(f.run);assert.equal(r.complete,true);assert.equal(r.committed,3);assert.equal(r.operations,3);assert.equal(f.posts(),3);
  assert.equal(f.requests.length,9);assert.equal(r.current_ref_state_verified,false);assert.equal(r.atomic_batch,false);
  const raw=canonical(await readFile(attemptFile(f,1,'result.json')));
  assert.equal(raw.observation.outcome.decision.decision_sequence,'9007199254740992');
  assert.equal(raw.observation.publication.decision_sequence,'9007199254740992');
  await f.close();await unlink(f.tokenFile);
  const completed=await runBootstrap({workdir:f.p.workdir,confirm:f.p.plan_sha256});assert.equal(completed.complete,true);assert.equal(completed.network_accessed,false);
  assert.equal((await status(f)).complete,true);
});
test('each bounded invocation preserves original keys and resumes without resending',async t=>{
  const f=await prepared(t);const keys=[];for(let i=1;i<=3;i++)keys.push((await request(f,i)).key);
  for(let i=0;i<3;i++){const r=await runBootstrap({...f.run,maxOperations:1});assert.equal(r.committed,i+1);assert.equal(r.complete,i===2);}
  assert.deepEqual(f.requests.filter(r=>r.path.endsWith('/create')).map(r=>r.key),keys);
  assert.equal((await status(f)).unsettled_attempts,0);
});
test('recover never starts an unattempted branch',async t=>{
  const f=await prepared(t);const r=await runBootstrap({...f.run,operation:'recover'});assert.equal(r.state,'ready');assert.equal(r.operations,0);assert.equal(f.requests.length,0);
});
test('lost committed response recovers original key and continues without another create',async t=>{
  let lost=false;const f=await prepared(t,{behavior:{send:({res})=>{if(!lost){lost=true;res.destroy();return false;}}}});
  const r=await runBootstrap(f.run);assert.equal(r.state,'unresolved');assert.equal(f.posts(),1);assert.equal(r.current.key,(await request(f)).key);
  const recovered=await runBootstrap({...f.run,operation:'recover'});assert.equal(recovered.committed,1);assert.equal(recovered.state,'ready');assert.equal(f.posts(),1);
  const done=await runBootstrap(f.run);assert.equal(done.complete,true);assert.equal(f.posts(),3);
});
test('unknown outcome remains fenced until exact-key retry, preserving bytes',async t=>{
  let drop=true;const f=await prepared(t,{behavior:{beforeSend:({res})=>{if(drop){res.destroy();return false;}}}});
  const before=await request(f);await runBootstrap(f.run);assert.equal(f.posts(),1);
  let r=await runBootstrap(f.run);assert.equal(r.state,'unresolved');assert.equal(f.posts(),1);
  await assert.rejects(runBootstrap({...f.run,retryKey:(await request(f,2)).key}),/retry_not_pending/);assert.equal(f.posts(),1);
  drop=false;r=await runBootstrap({...f.run,retryKey:before.key});assert.equal(r.complete,true);assert.equal(f.posts(),4);
  const copies=f.requests.filter(r=>r.path.endsWith('/create')&&r.key===before.key);assert.equal(copies.length,2);assert.equal(copies[0].body,copies[1].body);
});
test('native refusal never overwrites an occupied branch or creates later branches',async t=>{
  const existing=[['refs/heads/import/0002','9'.repeat(40)]];const f=await prepared(t,{existing});
  const r=await runBootstrap(f.run);assert.equal(r.state,'refused');assert.equal(r.committed,1);assert.equal(f.posts(),2);
  assert.equal(f.refs.get('refs/heads/import/0002'),'9'.repeat(40));assert(!f.refs.has('refs/heads/import/0003'));
  const n=f.requests.length;await runBootstrap(f.run);assert.equal(f.requests.length,n);
});
test('an occupied equal tip is still a native create refusal, not a fabricated successful creation',async t=>{
  const f=await prepared(t,{branches:1,existing:[['refs/heads/import/0001','1'.repeat(40)]]});const r=await runBootstrap(f.run);
  assert.equal(r.state,'refused');assert.equal(r.complete,false);assert.equal(f.posts(),1);
});
test('previously observed commit does not resurrect a subsequently deleted branch',async t=>{
  const f=await prepared(t,{branches:1});await runBootstrap(f.run);f.refs.clear();const n=f.requests.length;
  assert.equal((await runBootstrap(f.run)).complete,true);assert.equal(f.requests.length,n);assert.equal(f.refs.size,0);
});
test('rotation may recover but cannot send any new request',async t=>{
  const f=await prepared(t,{behavior:{send:({res})=>{res.destroy();return false;}}});await runBootstrap(f.run);
  await writeFile(f.tokenFile,ROTATED,{mode:0o600});let r=await runBootstrap({...f.run,operation:'recover'});
  assert.equal(r.committed,1);assert.equal(f.posts(),1);await assert.rejects(runBootstrap(f.run),/original_credential/);assert.equal(f.posts(),1);
});
test('rotated credential naming another principal is not original-key evidence',async t=>{
  const f=await prepared(t,{behavior:{send:({res})=>{res.destroy();return false;},outcome:({result,req})=>{
    if(req.headers.authorization===`Bearer ${ROTATED}`)result.principal_id='ff'.repeat(16);return result;
  }}});await runBootstrap(f.run);await writeFile(f.tokenFile,ROTATED);
  const r=await runBootstrap({...f.run,operation:'recover'});assert.equal(r.state,'unresolved');assert.equal(f.posts(),1);
});
test('retained publication prevents resending after failed confirmation',async t=>{
  let failConfirmation=true;const f=await prepared(t,{branches:1,behavior:{outcome:({result,res})=>{
    if(failConfirmation&&result.terminal){res.writeHead(503);res.end();return false;}
  }}});let r=await runBootstrap(f.run);assert.equal(r.state,'unresolved');assert(r.current.publication);assert.equal(f.posts(),1);
  r=await runBootstrap({...f.run,retryKey:r.current.key});assert.equal(r.state,'unresolved');assert.equal(f.posts(),1);
  failConfirmation=false;r=await runBootstrap(f.run);assert.equal(r.complete,true);assert.equal(f.posts(),1);
});
test('mismatched publication leaves an unknown result recoverable through native outcome',async t=>{
  const f=await prepared(t,{branches:1,behavior:{send:({pub})=>{pub.updates[0].force=true;return pub;}}});
  let r=await runBootstrap(f.run);assert.equal(r.state,'unresolved');assert.equal(r.current.publication,null);
  r=await runBootstrap(f.run);assert.equal(r.complete,true);assert.equal(f.posts(),1);
});
test('whole invocation cancellation retains prior confirmed operations',async t=>{
  const stop=new AbortController();let posts=0;
  const f=await prepared(t,{behavior:{send:({res})=>{if(++posts===2){res.writeHead(200,{'content-type':'application/json'});res.write('{');setTimeout(()=>stop.abort(),20);return false;}}}});
  await assert.rejects(runBootstrap({...f.run,signal:stop.signal}));const s=await status(f);assert.equal(s.committed,1);assert.equal(s.current.attempts,1);
  const done=await runBootstrap(f.run);assert.equal(done.complete,true);assert.equal(f.posts(),3);
});
test('missing result after process loss is recovered without resending',async t=>{
  const f=await prepared(t,{branches:1});await runBootstrap(f.run);await unlink(attemptFile(f,1,'result.json'));
  const s=await status(f);assert.equal(s.state,'unresolved');assert.equal(s.unsettled_attempts,1);
  const r=await runBootstrap(f.run);assert.equal(r.complete,true);assert.equal(r.unsettled_attempts,1);assert.equal(f.posts(),1);
});
test('concurrent collectors arbitrate exclusive attempt slots and preserve one native create',async t=>{
  const f=await prepared(t,{branches:1});const results=await Promise.allSettled([runBootstrap(f.run),runBootstrap(f.run)]);
  assert(results.some(r=>r.status==='fulfilled'));assert.equal(f.posts(),1);
  const r=await runBootstrap(f.run);assert.equal(r.complete,true);
});
test('status is credential-free, network-free and does not rewrite custody',async t=>{
  const f=await prepared(t);await runBootstrap({...f.run,maxOperations:1});await unlink(f.tokenFile);await f.close();
  const p=attemptFile(f,1,'result.json'), before=await lstat(p,{bigint:true});
  const s=await status(f);const after=await lstat(p,{bigint:true});assert.equal(s.committed,1);assert.equal(s.local_read_only,true);
  for(const k of ['ino','size','mtimeNs','ctimeNs'])assert.equal(before[k],after[k]);
});
for(const [name,change] of [
  ['unknown field',s=>{s.force=true;}],['hash domain',s=>{s.scope.object_format='sha512';}],
  ['zero oid',s=>{s.refs[0].new_commit='0'.repeat(40);}],['wrong oid domain',s=>{s.refs[0].new_commit='1'.repeat(64);}],
  ['outside namespace',s=>{s.refs[0].ref='refs/heads/main';}],['ambiguous namespace',s=>{s.namespace='refs/heads/import';}],
  ['duplicate branch',s=>{s.refs.push({...s.refs[0]});}],['force hint',s=>{s.refs[0].force=true;}],
  ['noncanonical endpoint',s=>{s.endpoint+='/';}],['endpoint credentials',s=>{s.endpoint=s.endpoint.replace('http://','http://secret@');}],
  ['nonloopback cleartext',s=>{s.endpoint='http://forge.test/repo';}],['hidden component',s=>{s.refs[0].ref='refs/heads/import/.hidden';}],
  ['invalid ref sequence',s=>{s.refs[0].ref='refs/heads/import/a..b';}],['lone surrogate',s=>{s.refs[0].ref='refs/heads/import/\ud800';}],
])test(`preparation rejects ${name} before creating custody or network access`,async t=>{
  const f=await fixture(t);change(f.selection);await assert.rejects(prepareBootstrap(f.prepare));assert.equal(f.requests.length,0);
  await assert.rejects(lstat(f.prepare.workdir),e=>e.code==='ENOENT');
});
for(const [name,mutate] of [
  ['request body',async f=>{const p=requestFile(f),v=canonical(await readFile(p));v.body+='&force=true';await writeFile(p,encode(v));}],
  ['manifest',async f=>{const p=join(f.p.workdir,'manifest.json'),v=canonical(await readFile(p));v.request_bytes++;await writeFile(p,encode(v));}],
  ['selection',async f=>{const p=join(f.p.workdir,'selection.json'),v=canonical(await readFile(p));v.refs[0].new_commit='9'.repeat(40);await writeFile(p,encode(v));}],
  ['extra file',async f=>writeFile(join(f.p.workdir,'junk'),'x',{mode:0o600})],
  ['hard link',async f=>link(requestFile(f),join(f.root,'extra'))],
  ['symlink',async f=>{const bytes=await readFile(requestFile(f)),p=join(f.root,'outside');await writeFile(p,bytes,{mode:0o600});await unlink(requestFile(f));await symlink(p,requestFile(f));}],
  ['torn reservation',async f=>{const p=join(f.p.workdir,'journal','attempt-000001');await mkdir(p,{mode:0o700});await writeFile(join(p,'started.json'),'{',{mode:0o600});}],
  ['empty attempt',async f=>mkdir(join(f.p.workdir,'journal','attempt-000001'),{mode:0o700})],
  ['journal gap',async f=>mkdir(join(f.p.workdir,'journal','attempt-000002'),{mode:0o700})],
])test(`full preflight refuses ${name} before a native call`,async t=>{
  const f=await prepared(t);await mutate(f);await assert.rejects(runBootstrap(f.run));await assert.rejects(status(f));assert.equal(f.requests.length,0);
});
test('request reconstruction rejects recalculated outer hashes over altered semantics',async t=>{
  const f=await prepared(t),p=requestFile(f),v=canonical(await readFile(p));v.new_commit='9'.repeat(40);v.body=new URLSearchParams({object_format:'sha1',ref:v.ref,new_commit:v.new_commit}).toString();
  const bytes=encode(v);await writeFile(p,bytes);const mp=join(f.p.workdir,'manifest.json'),m=canonical(await readFile(mp));
  m.request_bytes+=bytes.length-m.requests[0].bytes;m.requests[0]={sha256:hash(bytes),bytes:bytes.length};const updated=encode(m);await writeFile(mp,updated);
  await assert.rejects(runBootstrap({...f.run,confirm:hash(updated)}),/request_changed/);assert.equal(f.requests.length,0);
});
test('bounded branch compilation covers 8192 requirements and rejects one more',async t=>{
  const f=await fixture(t,{branches:L.branches}),s=selection(f.selection);assert.equal(s.refs.length,L.branches);
  let total=0;for(const ref of s.refs){const r=createRequest(s,ref,hash(Buffer.from(TOKEN)));checkedRequest(r);total+=encode(r).length;}
  assert(total<L.requestBytes);f.selection.refs.push({ref:'refs/heads/import/extra',new_commit:'9'.repeat(40)});assert.throws(()=>selection(f.selection),/limit/);
});
test('duplicate keys, precision loss, deep records and malformed UTF-8 refuse',()=>{
  for(const text of ['{"a":1,"a":2}','{"a":1,"\\u0061":2}','{"a":9007199254740993}','{"a":1e2}','['.repeat(17)+']'.repeat(17)])assert.throws(()=>parse(Buffer.from(text)));
  assert.throws(()=>parse(Buffer.from([0xff])));
  assert.equal(parse(Buffer.from('{"decision_sequence":18446744073709551615}'),true).decision_sequence,'18446744073709551615');
});
for(const name of ['scope','operation','old','new','force','extra','status','sequence'])test(`native publication checks ${name}`,async t=>{
  const f=await prepared(t,{branches:1});await runBootstrap(f.run);const r=await request(f),p=structuredClone(f.publications.get(r.key));let code=200;
  if(name==='scope')p.principal_id='ff'.repeat(16);if(name==='operation')p.operation='update';if(name==='old')p.updates[0].expected_commit='sha1:'+'1'.repeat(40);
  if(name==='new')p.updates[0].new_commit='sha1:'+'9'.repeat(40);if(name==='force')p.updates[0].force=true;if(name==='extra')p.updates.push(p.updates[0]);
  if(name==='status')code=409;if(name==='sequence')p.decision_sequence='18446744073709551616';
  assert.throws(()=>publication(p,r,code));
});
test('token and arbitrary response prose never enter retained result diagnostics',async t=>{
  const f=await prepared(t,{branches:1,behavior:{send:({res})=>{res.writeHead(503);res.end(`secret ${TOKEN}`);return false;}}});await runBootstrap(f.run);
  const text=await readFile(attemptFile(f,1,'result.json'),'utf8');assert(!text.includes(TOKEN));assert(!text.includes('secret'));
});
test('input snapshots cannot be changed during asynchronous preparation',async t=>{
  const f=await fixture(t,{branches:1}),raw={...f.prepare};const pending=prepareBootstrap(raw);raw.tokenFile='/not/a/credential';f.selection.refs[0].new_commit='9'.repeat(40);
  const p=await pending;const r=canonical(await readFile(join(p.workdir,'requests','request-000001.json')));assert.equal(r.new_commit,'1'.repeat(40));
});
test('cumulative per-branch retry allowance cannot reset between invocations',async t=>{
  const f=await prepared(t,{branches:1,behavior:{beforeSend:({res})=>{res.destroy();return false;}}});
  await runBootstrap(f.run);for(let i=1;i<L.perBranch;i++)await runBootstrap(f.run);
  const before=f.requests.length;await assert.rejects(runBootstrap(f.run),/attempt_limit/);assert.equal(f.requests.length,before);assert.equal((await status(f)).attempts,L.perBranch);
});
