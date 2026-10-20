import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir, unlink, rename, mkdir, link, symlink, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { createHmac } from 'node:crypto';
import { beginGithubPullPreparation, resumeGithubPullPreparation, inspectGithubPullPreparation }
  from '../../scripts/lib/github-pull-preparation.mjs';
import { preparePullWithIdentity, pullCanonical, pullHash, validatePullIntent } from '../../scripts/operator/pull_command.mjs';
import { compileGithubPullImport } from '../../scripts/lib/github-pull-import-plan.mjs';
import { savePullIntent, loadPullIntent } from '../../scripts/operator/pull_files.mjs';
import { preparationFixture } from './github-pull-preparation-fixture.mjs';
const name = i => `step-${String(i).padStart(6,'0')}`;
const request = (f, i) => join(f.workdir, 'import/requests', name(i), 'intent.json');
const inspect = f => inspectGithubPullPreparation(f.options);
async function expected(f, i) {
  const plan = JSON.parse(await readFile(join(f.workdir, 'preparation.json')));
  const compiled = compileGithubPullImport(f.capture.capture, plan.manifest.selection);
  const nonce = createHmac('sha256', Buffer.from(plan.nonce_seed,'hex'))
    .update('frankengit/github-pull-preparation/nonce/v1\0').update(compiled.captureSha256)
    .update('\0').update(String(i)).digest('hex').slice(0,32);
  const { number, action, fields } = compiled.steps[i];
  return preparePullWithIdentity({ endpoint: compiled.selection.endpoint, scope: compiled.selection.scope, number, action, fields },
    { nonce, credential_fingerprint: plan.manifest.credential_fingerprint });
}
test('bounded preparation preserves every selected key and publishes an ordinary v1 root last', async t => {
  const f = await preparationFixture(t); assert.equal(f.prepared.prepared_steps, 0); assert.equal(f.prepared.steps, 5);
  assert.equal(f.prepared.preparation_complete, false); const plan = f.prepared.plan_sha256;
  let result = f.prepared;
  for (let i=1; i<=5; i++) {
    result = await resumeGithubPullPreparation({ ...f.options, maxRequests: 1 });
    assert.equal(result.prepared_steps, i); assert.equal(result.new_steps, 1); assert.equal(result.plan_sha256, plan);
    const raw = await readFile(request(f,i)), intent = await loadPullIntent(join(f.workdir,'import/requests',name(i)));
    assert.equal(pullCanonical(intent), pullCanonical(await expected(f,i-1))); assert(raw.equals(Buffer.from(pullCanonical(intent))));
    assert.equal((await readdir(join(f.workdir,'import'))).includes('manifest.json'), i===5);
  }
  assert.equal(result.preparation_complete,true);assert.equal(result.network_accessed,false);assert.equal(result.mutation_submitted,false);
  const manifestBytes=await readFile(join(f.workdir,'import/manifest.json')),m=JSON.parse(manifestBytes);
  assert.equal(m.schema,'frankengit-github-pull-import-v1');assert.equal(pullHash(manifestBytes),plan);
  assert.equal(m.request_bytes,(await Promise.all(Array.from({length:5},(_,i)=>readFile(request(f,i+1))))).reduce((n,b)=>n+b.length,0));
});
test('resume needs neither source path nor credential and never accesses the network',async t=>{
 const f=await preparationFixture(t);await unlink(f.captureFile);await unlink(f.tokenFile);
 const fetch=globalThis.fetch;globalThis.fetch=()=>assert.fail('offline preparation connected');
 try {const r=await resumeGithubPullPreparation(f.options);assert.equal(r.preparation_complete,true);assert.equal((await inspect(f)).local_read_only,true);}
 finally {globalThis.fetch=fetch;}
});
test('status preserves file identities and completed resume creates no requests',async t=>{
 const f=await preparationFixture(t);await resumeGithubPullPreparation(f.options);
 const paths=[join(f.workdir,'preparation.json'),request(f,1),join(f.workdir,'import/manifest.json')];
 const before=await Promise.all(paths.map(p=>stat(p,{bigint:true})));await inspect(f);
 assert.equal((await resumeGithubPullPreparation(f.options)).new_steps,0);
 const after=await Promise.all(paths.map(p=>stat(p,{bigint:true})));
 for(let i=0;i<paths.length;i++)for(const k of ['ino','size','mtimeNs','ctimeNs'])assert.equal(after[i][k],before[i][k]);
});
test('complete request staged before termination is adopted with its original bytes',async t=>{
 const f=await preparationFixture(t),intent=await expected(f,0),pending=join(f.workdir,'pending/request');await savePullIntent(pending,intent);
 assert.equal((await inspect(f)).pending_step,1);
 const before=await stat(join(pending,'intent.json'),{bigint:true});const r=await resumeGithubPullPreparation({...f.options,maxRequests:1});
 assert.equal(r.prepared_steps,1);assert.equal((await stat(request(f,1),{bigint:true})).ino,before.ino);
 assert.equal((await loadPullIntent(join(f.workdir,'import/requests',name(1)))).key,intent.key);
});
for(const [title,change] of [
 ['plan pin',async f=>{const p=join(f.workdir,'preparation.json'),v=JSON.parse(await readFile(p));v.nonce_seed='b'.repeat(64);await writeFile(p,JSON.stringify(v)+'\n');}],
 ['source content',async f=>{const p=join(f.workdir,'import/capture.json'),v=JSON.parse(await readFile(p));v.pulls[0].pull.title='changed';await writeFile(p,JSON.stringify(v)+'\n');}],
 ['request key',async f=>{await resumeGithubPullPreparation({...f.options,maxRequests:1});const p=request(f,1),v=JSON.parse(await readFile(p));v.nonce='1'.repeat(32);await writeFile(p,pullCanonical(v));}],
 ['request gap',async f=>{await resumeGithubPullPreparation({...f.options,maxRequests:1});await rename(join(f.workdir,'import/requests',name(1)),join(f.workdir,'import/requests',name(2)));}],
 ['uninitialized staging slot',async f=>mkdir(join(f.workdir,'pending/request'),{mode:0o700})],
 ['torn staged intent',async f=>{await mkdir(join(f.workdir,'pending/request'),{mode:0o700});await writeFile(join(f.workdir,'pending/request/intent.json'),'{',{mode:0o600});}],
 ['unknown file',async f=>writeFile(join(f.workdir,'unknown'),'x',{mode:0o600})],
 ['premature journal',async f=>mkdir(join(f.workdir,'import/journal/attempt-000001'),{mode:0o700})],
 ['hard-linked source',async f=>link(join(f.workdir,'import/capture.json'),join(f.root,'alias'))],
 ['symlinked source',async f=>{await unlink(join(f.workdir,'import/capture.json'));await symlink(f.captureFile,join(f.workdir,'import/capture.json'));}],
 ['unexpected request content',async f=>{await resumeGithubPullPreparation({...f.options,maxRequests:1});await writeFile(join(f.workdir,'import/requests',name(1),'extra'),'x',{mode:0o600});}],
])test(`refuses ${title} without silently replacing a request`,async t=>{
 const f=await preparationFixture(t);await change(f);await assert.rejects(resumeGithubPullPreparation(f.options));await assert.rejects(inspect(f));
});
test('changed pending identity is never adopted even when locally valid',async t=>{
 const f=await preparationFixture(t),intent=await expected(f,0);
 const changed=preparePullWithIdentity({endpoint:intent.endpoint,scope:intent.scope,number:intent.number,action:intent.action,fields:intent.fields},
  {nonce:'1'.repeat(32),credential_fingerprint:intent.credential_fingerprint});
 await savePullIntent(join(f.workdir,'pending/request'),changed);await assert.rejects(resumeGithubPullPreparation(f.options),/request_changed/);
 assert.equal((await readdir(join(f.workdir,'import/requests'))).length,0);
});
test('validly altered source plus recomputed local hashes still requires the independent preparation pin',async t=>{
 const f=await preparationFixture(t),p=join(f.workdir,'preparation.json'),v=JSON.parse(await readFile(p));v.manifest.selection.number_start='999';
 await writeFile(p,JSON.stringify(v)+'\n');await assert.rejects(resumeGithubPullPreparation(f.options),/pin_mismatch/);
});
test('full encoded intent overhead refuses before creating a draft',async t=>{
 const f=await preparationFixture(t,{begin:false});const compiled=compileGithubPullImport(f.capture.capture,f.input.selection);
 await assert.rejects(beginGithubPullPreparation({...f.input,selection:{...f.input.selection,max_request_bytes:compiled.encodedBytes}}),/request_capacity/);
 await assert.rejects(stat(f.workdir),{code:'ENOENT'});
});
test('original input files and existing output never overwritten',async t=>{
 const f=await preparationFixture(t),before=await readFile(join(f.workdir,'preparation.json'));
 await assert.rejects(beginGithubPullPreparation(f.input),/exists/);assert((await readFile(join(f.workdir,'preparation.json'))).equals(before));
});
test('two independently selected drafts have different keys but identical native commands',async t=>{
 const f=await preparationFixture(t),other=join(f.root,'other'),p=await beginGithubPullPreparation({...f.input,workdir:other});
 await resumeGithubPullPreparation({...f.options,maxRequests:1});await resumeGithubPullPreparation({workdir:other,confirm:p.preparation_sha256,maxRequests:1});
 const a=JSON.parse(await readFile(request(f,1))),b=JSON.parse(await readFile(join(other,'import/requests/step-000001/intent.json')));
 assert.notEqual(a.key,b.key);assert.equal(a.body,b.body);assert.notEqual(p.plan_sha256,f.prepared.plan_sha256);
});
test('whole u64 destination range and invalid later PR preflight',async t=>{
 const f=await preparationFixture(t,{source:{pulls:[9,17]},select:{number_start:'18446744073709551614'}});
 const r=await resumeGithubPullPreparation(f.options);assert.equal(r.steps,10);
 assert.equal(JSON.parse(await readFile(request(f,6))).number,'18446744073709551615');
 const g=await preparationFixture(t,{begin:false,source:{pulls:[9,17]},select:{number_start:'18446744073709551615'}});
 await assert.rejects(beginGithubPullPreparation(g.input),/u64/);await assert.rejects(stat(g.workdir),{code:'ENOENT'});
});
test('invocation controls cannot alter selected scope, source or nonce',async t=>{
 const f=await preparationFixture(t);
 for(const extra of [{maxRequests:0},{maxRequests:8193},{nonce_seed:'0'.repeat(64)},{selection:f.input.selection},{tokenFile:f.tokenFile}])
  await assert.rejects(resumeGithubPullPreparation({...f.options,...extra}));
 assert.equal((await inspect(f)).prepared_steps,0);
});
test('aborted preparation writes nothing and aborted resume retains selected keys',async t=>{
 const f=await preparationFixture(t,{begin:false}),s=AbortSignal.abort();await assert.rejects(beginGithubPullPreparation({...f.input,signal:s}));
 await assert.rejects(stat(f.workdir),{code:'ENOENT'});const p=await beginGithubPullPreparation(f.input);
 await assert.rejects(resumeGithubPullPreparation({workdir:f.workdir,confirm:p.preparation_sha256,signal:s}));
 assert.equal((await resumeGithubPullPreparation({workdir:f.workdir,confirm:p.preparation_sha256})).plan_sha256,p.plan_sha256);
});
test('concurrent preparers never publish competing identities',async t=>{
 const f=await preparationFixture(t);
 const results=await Promise.allSettled([resumeGithubPullPreparation({...f.options,maxRequests:1}),resumeGithubPullPreparation({...f.options,maxRequests:1})]);
 assert(results.some(r=>r.status==='fulfilled'));
 const s=await inspect(f);assert(s.prepared_steps>=1);assert(s.prepared_steps<=2);
 for(let i=1;i<=s.prepared_steps;i++)assert.equal(validatePullIntent(JSON.parse(await readFile(request(f,i)))).key,(await expected(f,i-1)).key);
 assert.equal((await resumeGithubPullPreparation(f.options)).preparation_complete,true);
});
test('copied preparation has byte-identical final plans regardless of invocation budget',async t=>{
 const f=await preparationFixture(t),{cp}=await import('node:fs/promises'),other=join(f.root,'copy');await cp(f.workdir,other,{recursive:true});
 const all=await resumeGithubPullPreparation(f.options);let one;
 do{one=await resumeGithubPullPreparation({workdir:other,confirm:f.options.confirm,maxRequests:1});}while(!one.preparation_complete);
 assert.equal(one.plan_sha256,all.plan_sha256);
 for(let i=1;i<=all.steps;i++)assert((await readFile(request(f,i))).equals(await readFile(join(other,'import/requests',name(i),'intent.json'))));
});
