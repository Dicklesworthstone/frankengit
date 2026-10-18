import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile, rm, lstat, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { migrationFixture, fileHashes } from './branch-bootstrap-pulls-fixture.mjs';
import { pullBootstrapRequirements, preparePullBootstrap } from '../../scripts/lib/branch-bootstrap-pulls.mjs';
import { inspectBootstrap, runBootstrap } from '../../scripts/lib/branch-bootstrap.mjs';
import { canonical, encode, hash } from '../../scripts/lib/branch-bootstrap-protocol.mjs';
import { loadPullImport, inspectPullImport } from '../../scripts/lib/native-pull-import.mjs';
import { lifetime } from '../../scripts/lib/forge-pull-archive-store.mjs';
import { compilePullImport } from '../../scripts/lib/native-pull-import-plan.mjs';
import { readPullImportSource } from '../../scripts/lib/native-pull-import-source.mjs';
import { preparePull, pullCanonical, pullHash } from '../../scripts/operator/pull_command.mjs';
import { savePullIntent } from '../../scripts/operator/pull_files.mjs';
import { ROTATED } from './branch-bootstrap-fixture.mjs';

for(const format of ['sha1','sha256'])test(`verified PR requirements -> create-only branch execution (${format})`,async t=>{
  const f=await migrationFixture(t,{format}),before=await fileHashes(f.migration.workdir);
  const derived=await pullBootstrapRequirements(f.bridge),again=await pullBootstrapRequirements(f.bridge);
  assert.deepEqual(derived,again);assert.equal(derived.required_branches,3);assert.equal(derived.pull_requests,2);
  assert.equal(derived.selection.scope.principal_id,f.selection.scope.principal_id);
  assert.notEqual(derived.selection.scope.principal_id,f.prepareMigration.selection.scope.principal_id);
  assert.equal(derived.selection.origin.plan_sha256,f.migration.plan_sha256);assert.equal(derived.network_accessed,false);
  const p=await preparePullBootstrap(f.prepareBranches);assert.equal(p.requirements_sha256,derived.requirements_sha256);
  const inspected=await inspectBootstrap({workdir:p.workdir,confirm:p.plan_sha256});assert.deepEqual(inspected.selection,derived.selection);
  assert.deepEqual(await fileHashes(f.migration.workdir),before);assert.equal(f.requests.length,0);
  const result=await runBootstrap({workdir:p.workdir,confirm:p.plan_sha256,tokenFile:f.tokenFile});assert.equal(result.complete,true);
  assert.equal(f.posts(),3);for(const r of derived.selection.refs)assert.equal(f.refs.get(r.ref),r.new_commit);
  assert(f.requests.every(r=>!r.path.includes('/pulls/')));assert.deepEqual(await fileHashes(f.migration.workdir),before);
});
test('per-PR mappings preserve different historical target tips without moving a shared base',async t=>{
  const f=await migrationFixture(t,{sharedBase:false,modifyRow:row=>{row.data.target_tip=`sha1:${String(row.number+4).repeat(40)}`;}});
  const r=await pullBootstrapRequirements(f.bridge);assert.equal(r.required_branches,4);
  assert.equal(r.selection.refs.find(x=>x.ref.endsWith('pr-2/base')).new_commit,'6'.repeat(40));
});
test('byte-only original refs use only previously reviewed destination mappings',async t=>{
  const f=await migrationFixture(t,{byteOnly:true});const r=await pullBootstrapRequirements(f.bridge);
  assert.equal(r.required_branches,3);assert(r.selection.refs.every(x=>x.ref.startsWith(f.bridge.namespace)));
});
test('standalone branch job survives removal of PR plan, source archive and PR credential',async t=>{
  const f=await migrationFixture(t),p=await preparePullBootstrap(f.prepareBranches);
  await rm(f.migration.workdir,{recursive:true});await rm(f.archive,{recursive:true});await rm(f.prToken);
  const r=await runBootstrap({workdir:p.workdir,confirm:p.plan_sha256,tokenFile:f.tokenFile});assert.equal(r.complete,true);
  assert.equal((await inspectBootstrap({workdir:p.workdir,confirm:p.plan_sha256})).selection.origin.plan_sha256,f.migration.plan_sha256);
});
for(const [name,change]of [
  ['missing independently selected principal',v=>{delete v.principal;}],['invalid principal',v=>{v.principal='author@example.com';}],
  ['narrow namespace omission',v=>{v.namespace='refs/heads/import/project/pr-1/';}],['bare branch root',v=>{v.namespace='refs/heads/';}],
  ['replacement endpoint',v=>{v.endpoint='https://other.example/repo';}],['replacement OID',v=>{v.new_commit='f'.repeat(40);}],
  ['wrong PR plan pin',v=>{v.migrationConfirm='0'.repeat(64);}],['relative source path',v=>{v.migrationDir='relative';}],
])test(`requirements refuse ${name} without publishing or contacting destination`,async t=>{
  const f=await migrationFixture(t),v={...f.prepareBranches};change(v);
  await assert.rejects(preparePullBootstrap(v));assert.equal(f.requests.length,0);
  await assert.rejects(lstat(f.prepareBranches.workdir),e=>e.code==='ENOENT');
});
for(const target of ['archive','request','manifest'])test(`complete PR preflight rejects changed ${target}`,async t=>{
  const f=await migrationFixture(t),p=join(f.migration.workdir,target==='archive'?'archive/page-000002.json':
    target==='request'?'requests/step-000001/intent.json':'manifest.json');
  await writeFile(p,'{}\n');await assert.rejects(preparePullBootstrap(f.prepareBranches));assert.equal(f.requests.length,0);
  await assert.rejects(lstat(f.prepareBranches.workdir),e=>e.code==='ENOENT');
});
test('preparation cannot overwrite the original PR migration or any existing output',async t=>{
  const f=await migrationFixture(t),before=await fileHashes(f.migration.workdir);
  await assert.rejects(preparePullBootstrap({...f.prepareBranches,workdir:f.migration.workdir}));
  assert.deepEqual(await fileHashes(f.migration.workdir),before);assert.equal(f.requests.length,0);
});
test('cancellation refuses before deriving keys or creating branch output',async t=>{
  const f=await migrationFixture(t),stop=new AbortController();stop.abort();
  await assert.rejects(preparePullBootstrap({...f.prepareBranches,signal:stop.signal}));assert.equal(f.requests.length,0);
  await assert.rejects(lstat(f.prepareBranches.workdir),e=>e.code==='ENOENT');
});
test('empty PR migration is an explicit no-branch-profile refusal',async t=>{
  const f=await migrationFixture(t,{pulls:0});await assert.rejects(pullBootstrapRequirements(f.bridge),/limit/);assert.equal(f.requests.length,0);
});
test('mutable caller options cannot substitute a different source or principal after validation begins',async t=>{
  const f=await migrationFixture(t),raw={...f.bridge},pending=pullBootstrapRequirements(raw);
  raw.principal='ff'.repeat(16);raw.migrationConfirm='0'.repeat(64);raw.migrationDir='/not/source';
  const r=await pending;assert.equal(r.selection.scope.principal_id,f.bridge.principal);assert.equal(r.migration_plan_sha256,f.bridge.migrationConfirm);
});
test('already sealed v1 requests remain readable while conflicting historical branch bases refuse bootstrap',async t=>{
  const f=await migrationFixture(t),root=join(f.root,'legacy');await mkdir(root,{mode:0o700});
  // Construct an old-format plan using the unchanged compiler's legacy default,
  // not a replacement production loader. New PR preparation disallows this basis.
  const source=await readPullImportSource({workdir:f.archive,confirm:f.prepareMigration.archiveConfirm});
  source.entries[1].row.data.target_tip='sha1:'+'c'.repeat(40);
  // Rebuild a self-consistent pinned archive fixture and retain exact source pages.
  const m=structuredClone(source.manifest);m.pages=[];m.data_bytes=0;
  await mkdir(join(root,'archive'),{mode:0o700});await mkdir(join(root,'requests'),{mode:0o700});await mkdir(join(root,'journal'),{mode:0o700});
  for(const [i,raw]of source.pages.entries()){
    const r=canonical(raw);
    if(r.type==='pull_request_page')r.pull_requests[1].data.target_tip=source.entries[1].row.data.target_tip;
    if(r.type==='pull_request'&&r.number===2)r.pull_request.data.target_tip=source.entries[1].row.data.target_tip;
    const bytes=encode(r),d=source.manifest.pages[i];m.pages.push({...d,sha256:hash(bytes),bytes:bytes.length});m.data_bytes+=bytes.length;
    await writeFile(join(root,'archive',`page-${String(i+1).padStart(6,'0')}.json`),bytes,{mode:0o600});
  }
  const archiveBytes=encode(m);await writeFile(join(root,'archive','archive.json'),archiveBytes,{mode:0o600});
  const saved=await readPullImportSource({workdir:join(root,'archive'),confirm:hash(archiveBytes)});
  const compiled=compilePullImport(saved,f.prepareMigration.selection);
  const intents=compiled.steps.map(({number,action,fields})=>preparePull({endpoint:compiled.selection.endpoint,scope:compiled.selection.scope,number,action,fields},ROTATED));
  for(const [i,intent]of intents.entries())await savePullIntent(join(root,'requests',`step-${String(i+1).padStart(6,'0')}`),intent);
  const manifest={schema:'frankengit-native-pull-import-v1',selection:compiled.selection,archive_sha256:saved.archiveSha256,
    credential_fingerprint:hash(Buffer.from(ROTATED)),step_count:intents.length,steps_sha256:hash(encode(compiled.steps)),
    request_sha256:intents.map(i=>pullHash(pullCanonical(i))),request_bytes:intents.reduce((n,i)=>n+Buffer.byteLength(pullCanonical(i)),0)};
  const bytes=encode(manifest),confirm=hash(bytes);await writeFile(join(root,'manifest.json'),bytes,{mode:0o600});
  await inspectPullImport({workdir:root,confirm});const before=await fileHashes(root);
  await assert.rejects(pullBootstrapRequirements({...f.bridge,migrationDir:root,migrationConfirm:confirm}),/migration_ref_tip_conflict/);
  assert.deepEqual(await fileHashes(root),before);assert.equal(f.requests.length,0);
});
