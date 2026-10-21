// Complete durable owner and executable, private files and real HTTP sockets.
// Fixture responses are NOT native Rust authorization/admission evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, access, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { canonical, hash } from '../../scripts/operator/source_edit_candidate.mjs';
import { saveVerifiedSourceEdit, saveSourceEdit, loadSourceEdit, stageSourceApply, dispatchSourceApply,
  recoverSourceApply, inspectSourceApply } from '../../scripts/operator/source_edit_publish.mjs';
import { saveSourceEditResultPlan } from '../../scripts/operator/source_edit_result_plan.mjs';
import { main } from '../../scripts/fg_source_edit.mjs';
import { resultFixture, resultPeer, hex, TOKEN, PRINCIPAL } from './source_edit_result_fixture.mjs';
const CLI=resolve('scripts/fg_source_edit.mjs'), sequence='18446744073709551615';
function expected(f) {
  // Ground truth from the fixture's independent Git objects, not production
  // plan generation or any peer's preparation/inspection field.
  return { schema:'frankengit-source-edit-result-selection-v1', source:f.evidence.expected.source??f.evidence.expected,
    create_paths_hex:f.capture.request.paths_hex.filter(p=>!f.before.has(p)),
    after:f.capture.request.paths_hex.map(pathHex=>{const file=f.after.get(pathHex);return {pathHex,
      blob:file?.oid??null,kind:file?file.mode===0o100755?'executable':'file':null};}) };
}
async function setup(t,format='sha1',changes) {
  const f=await resultPeer(t,resultFixture(format,changes)), dir=await mkdtemp(join(tmpdir(),'fg-result-custody-'));
  t.after(()=>rm(dir,{recursive:true,force:true}));
  const candidate=join(dir,'candidate'),journal=join(dir,'journal');
  const evidence={package_bytes:f.evidence.package_bytes,expected:expected(f)};
  const inputs={source:join(dir,'source.json'),files:join(dir,'files.json'),expected:join(dir,'expected.json'),
    selection:join(dir,'selection.json'),pkg:join(dir,'package.json'),patch:join(dir,'change.patch'),token:join(dir,'token')};
  const files=[];
  for(const [i,path] of f.capture.request.paths_hex.entries()) {
    const file=f.after.get(path), body=file?join(dir,`body${i}`):null;
    if(file)await writeFile(body,file.data,{mode:0o600});
    files.push({path_hex:path,kind:file?file.mode===0o100755?'executable':'file':null,body_file:body});
  }
  for(const [path,bytes] of [[inputs.source,canonical(evidence.expected.source)],[inputs.files,canonical({files})],
    [inputs.selection,canonical(f.capture.request)],[inputs.pkg,evidence.package_bytes],[inputs.patch,f.patch],[inputs.token,Buffer.from(TOKEN)]]) {
    await writeFile(path,bytes,{mode:0o600});
  }
  const publication={type:'source_publication',schema_version:1,...f.capture.request.scope,principal_id:PRINCIPAL,
    ref:f.capture.request.ref,ref_hex:hex(f.capture.request.ref),expected_commit:f.base,candidate_commit:f.candidate,
    tx_id:'result-tx',outcome:'committed',decision_sequence:sequence,decision_record:'result-rcr',refusal_code:null,delivery_acknowledged:null};
  const outcome={type:'transaction_outcome',schema_version:1,tenant_id:f.capture.request.scope.tenant_id,
    repository_id:f.capture.request.scope.repository_id,repository_incarnation:f.capture.request.scope.repository_incarnation,principal_id:PRINCIPAL,
    selector:'transaction',command_index:null,state:'committed',terminal:true,
    transaction:{tx_id:'result-tx',seal_id:'result-seal',request_schema:'result-schema',canonical_request_digest:{algorithm:2,hex:'7'.repeat(64)}},
    decision:{kind:'committed',decision_sequence:sequence,repository_commit_id:'result-rcr'},read_only:true,request_reexecuted:false,
    absence_proves_non_commit:false,session_completeness_established:false};
  const send=(res,value)=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(value).replace(/"decision_sequence":"([0-9]+)"/g,'"decision_sequence":$1'));};
  return {...f,dir,candidate,journal,evidence,inputs,files,publication,outcome,send};
}
function command(args) {
  const child=spawn(process.execPath,[CLI,...args],{stdio:['ignore','pipe','pipe']});
  const a=[],b=[];child.stdout.on('data',v=>a.push(v));child.stderr.on('data',v=>b.push(v));
  const result=new Promise((ok,no)=>{child.once('error',no);child.once('close',(code,signal)=>ok({code,signal,
    out:Buffer.concat(a).toString(),err:Buffer.concat(b).toString()}));});
  return {child,result};
}
async function run(args) {return command(args).result;}
function planArgs(f) {return ['plan-results','--source-expected',f.inputs.source,'--files',f.inputs.files,'--output',f.inputs.expected];}
function prepareArgs(f) {return ['prepare-verified','--selection',f.inputs.selection,'--package',f.inputs.pkg,
  '--expect',f.inputs.expected,'--patch-file',f.inputs.patch,'--token-file',f.inputs.token,'--output',f.candidate];}
const json=r=>JSON.parse(r.out.trim());
const noFile=async path=>assert.rejects(access(path),e=>e.code==='ENOENT');
for(const format of ['sha1','sha256']) {
  test(`${format}: executable plans desired files offline and prepares/inspects v4`,async t=>{
    const f=await setup(t,format), p=await run(planArgs(f));assert.equal(p.code,0,p.err);
    const plan=json(p);assert.equal(plan.network_requests,0);assert.equal(plan.source_membership_verified,false);
    const raw=await readFile(f.inputs.expected);assert.equal(hash(raw),plan.expected_sha256);
    assert.deepEqual(JSON.parse(raw),f.evidence.expected);assert.equal(f.calls.length,0);
    const prepared=await run(prepareArgs(f));assert.equal(prepared.code,0,prepared.err);
    const saved=json(prepared);assert.equal(saved.source_verification.requested_result_verified,true);
    assert.equal(JSON.parse(await readFile(join(f.candidate,'manifest.json'))).schema,'frankengit-source-edit-files-v4');
    const inspect=await run(['inspect','--candidate',f.candidate,'--sha256',saved.manifest_sha256]);assert.equal(inspect.code,0,inspect.err);
    assert.equal(json(inspect).source_verification.intended_tree,f.nextTree.oid);
    assert.deepEqual(f.calls.map(c=>c.operation),['prepare','inspect']);
  });
  test(`${format}: staged original key retains result commitments through lost apply reply and recovery`,async t=>{
    const f=await setup(t,format);
    const saved=await saveVerifiedSourceEdit(f.candidate,f.capture,f.bundle,f.evidence);
    const staged=await stageSourceApply(f.journal,f.candidate,saved.manifest_sha256,PRINCIPAL);
    await rm(f.candidate,{recursive:true});await rm(f.inputs.pkg);await rm(f.inputs.source);
    f.control.handler=(_req,res,call)=>call.operation==='apply'?res.destroy():f.send(res,f.outcome);
    await assert.rejects(dispatchSourceApply(f.journal,staged.request_sha256,TOKEN),e=>!!e.retained_request);
    const pending=await inspectSourceApply(f.journal,staged.request_sha256);
    assert.equal(pending.state,'outcome_unknown');assert.equal(pending.source_verification.requested_result_verified,true);
    await assert.rejects(dispatchSourceApply(f.journal,staged.request_sha256,TOKEN),/already_dispatched/);
    const done=await recoverSourceApply(f.journal,staged.request_sha256,TOKEN);
    assert.equal(done.decision.decision_sequence,sequence);assert.equal(done.source_verification.intended_tree,f.nextTree.oid);
    assert.deepEqual(f.calls.map(c=>c.operation),['apply','outcomes']);
    assert.equal(f.calls[1].body.length,0);assert.equal(f.calls[1].headers['idempotency-key'],staged.key);
    await dispatchSourceApply(f.journal,staged.request_sha256,TOKEN);assert.equal(f.calls.length,2);
  });
}
test('binary result commitment remains separate from omitted native after bytes',async t=>{
  const f=await setup(t,'sha1',[{path:'src/anchor.rs',data:Buffer.from([0,255,10])}]);
  const saved=await saveVerifiedSourceEdit(f.candidate,f.capture,f.bundle,f.evidence);
  const loaded=await loadSourceEdit(f.candidate,saved.manifest_sha256);
  assert.equal(loaded.source_verification.requested_result_verified,true);
  assert.deepEqual(loaded.source_verification.unverified_after_paths_hex,[hex('src/anchor.rs')]);
});
test('rehashing a substituted expected result cannot fool semantic offline verification',async t=>{
  const f=await setup(t), saved=await saveVerifiedSourceEdit(f.candidate,f.capture,f.bundle,f.evidence);
  const e=structuredClone(f.evidence.expected);e.after[0].blob='f'.repeat(40);
  const b=canonical(e),root=JSON.parse(await readFile(join(f.candidate,'manifest.json')));
  root.source_evidence.expected_sha256=hash(b);root.source_evidence.expected_bytes=b.length;
  await writeFile(join(f.candidate,'source-expected.json'),b);await writeFile(join(f.candidate,'manifest.json'),canonical(root));
  await assert.rejects(loadSourceEdit(f.candidate,saved.manifest_sha256),/manifest_changed/);
  await assert.rejects(loadSourceEdit(f.candidate,hash(canonical(root))),/requested_result/);
});
for(const version of [2,3]) test(`v4 result evidence cannot be relabeled v${version}`,async t=>{
  const f=await setup(t);await saveVerifiedSourceEdit(f.candidate,f.capture,f.bundle,f.evidence);
  const root=JSON.parse(await readFile(join(f.candidate,'manifest.json')));root.schema=`frankengit-source-edit-files-v${version}`;
  root.source_evidence.profile=`frankengit-source-edit-evidence-v${version-1}`;
  await writeFile(join(f.candidate,'manifest.json'),canonical(root));
  await assert.rejects(loadSourceEdit(f.candidate,hash(canonical(root))),/evidence_profile/);
});
test('damaged result plan blocks dispatch and cannot erase prior mutation responsibility',async t=>{
  const f=await setup(t),saved=await saveVerifiedSourceEdit(f.candidate,f.capture,f.bundle,f.evidence);
  const staged=await stageSourceApply(f.journal,f.candidate,saved.manifest_sha256,PRINCIPAL);
  const path=join(f.journal,'candidate','source-expected.json'),original=await readFile(path);
  await writeFile(path,Buffer.from('bad'));
  await assert.rejects(dispatchSourceApply(f.journal,staged.request_sha256,TOKEN));assert.equal(f.calls.length,0);
  await noFile(join(f.journal,'dispatch'));
  await writeFile(path,original);
  f.control.handler=(_req,res)=>res.destroy();
  await assert.rejects(dispatchSourceApply(f.journal,staged.request_sha256,TOKEN));assert.equal(f.calls.length,1);
  await writeFile(path,Buffer.from('bad'));
  await assert.rejects(recoverSourceApply(f.journal,staged.request_sha256,TOKEN));
  await access(join(f.journal,'dispatch','started.json'));assert.equal(f.calls.length,1);
  await writeFile(path,original);
  await assert.rejects(dispatchSourceApply(f.journal,staged.request_sha256,TOKEN),/already_dispatched/);
});
test('ordinary and legacy evidence exports keep their v1/v2/v3 shapes',async t=>{
  const f=await setup(t,'sha1',[{path:'src/anchor.rs',data:Buffer.from('other\n')}]);
  const a=await saveSourceEdit(join(f.dir,'ordinary'),f.capture,f.bundle);
  const b=await saveVerifiedSourceEdit(join(f.dir,'positive'),f.capture,f.bundle,f.evidence.expected.source?{
    package_bytes:f.evidence.package_bytes,expected:f.evidence.expected.source}:f.evidence);
  const g=await setup(t);
  const c=await saveVerifiedSourceEdit(join(g.dir,'creation'),g.capture,g.bundle,g.evidence.expected.source?{
    package_bytes:g.evidence.package_bytes,expected:g.evidence.expected.source&&{
      schema:'frankengit-source-edit-create-selection-v1',source:g.evidence.expected.source,
      create_paths_hex:g.evidence.expected.create_paths_hex}}:g.evidence);
  for(const [path,pin,version] of [[join(f.dir,'ordinary'),a.manifest_sha256,1],[join(f.dir,'positive'),b.manifest_sha256,2],
    [join(g.dir,'creation'),c.manifest_sha256,3]]) {
    assert.equal(JSON.parse(await readFile(join(path,'manifest.json'))).schema,`frankengit-source-edit-files-v${version}`);
    assert.equal((await loadSourceEdit(path,pin)).source_verification?.requested_result_verified,undefined);
  }
});
test('concurrent candidate saves publish one complete v4 with no overwrite',async t=>{
  const f=await setup(t);const results=await Promise.allSettled([0,1].map(()=>saveVerifiedSourceEdit(f.candidate,f.capture,f.bundle,f.evidence)));
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  const winner=results.find(r=>r.status==='fulfilled').value;
  assert.equal((await loadSourceEdit(f.candidate,winner.manifest_sha256)).source_verification.requested_result_verified,true);
});
test('competing executable plan writers cannot overwrite the winning expectation',async t=>{
  const f=await setup(t);const [a,b]=await Promise.all([run(planArgs(f)),run(planArgs(f))]);
  assert.equal([a,b].filter(r=>r.code===0).length,1);
  const winning=json(a.code===0?a:b),raw=await readFile(f.inputs.expected);
  assert.equal(hash(raw),winning.expected_sha256);assert.equal(f.calls.length,0);
  const repeat=await run(planArgs(f));assert.notEqual(repeat.code,0);assert.deepEqual(await readFile(f.inputs.expected),raw);
});
for(const hazard of ['public','symlink','oversize']) test(`offline plan rejects ${hazard} body inputs without publication`,async t=>{
  const f=await setup(t),body=f.files[0].body_file;
  if(hazard==='public')await chmod(body,0o644);
  else if(hazard==='symlink'){await rm(body);await symlink(f.inputs.source,body);}
  else await writeFile(body,Buffer.alloc(1048577));
  const r=await run(planArgs(f));assert.equal(r.code,2,r.err);await noFile(f.inputs.expected);assert.equal(f.calls.length,0);
});
test('offline plan refuses credentials, arbitrary fields and ambiguous deletion inputs',async t=>{
  const f=await setup(t);
  const r=await run([...planArgs(f),'--token-file',f.inputs.token]);assert.equal(r.code,2);assert.equal(f.calls.length,0);
  for(const spec of [{files:[{...f.files[0],approved:true}]},{files:[{...f.files[0],body_file:null}]},
    {files:[],source_commit:f.base}]) {
    await writeFile(f.inputs.files,canonical(spec));const bad=await run(planArgs(f));assert.equal(bad.code,2);await noFile(f.inputs.expected);
  }
});
test('private result bodies and caller buffers are owned before asynchronous plan reads',async t=>{
  const f=await setup(t),a=await readFile(f.inputs.source),b=await readFile(f.inputs.files);
  const task=saveSourceEditResultPlan(f.inputs.expected,a,b);a.fill(0);b.fill(0);
  const receipt=await task;assert.deepEqual(JSON.parse(await readFile(f.inputs.expected)),f.evidence.expected);
  assert.equal(receipt.network_requests,0);
});
test('cancelled plan writes nothing; lost stdout retains an already-published plan receipt',async t=>{
  const f=await setup(t),a=await readFile(f.inputs.source),b=await readFile(f.inputs.files);
  await assert.rejects(saveSourceEditResultPlan(f.inputs.expected,a,b,{signal:AbortSignal.abort()}),/cancelled/);await noFile(f.inputs.expected);
  const errors=[],broken=new Writable({write(_b,_e,cb){cb(Object.assign(Error('closed'),{code:'EPIPE'}));}});
  const stderr=new Writable({write(b,_e,cb){errors.push(Buffer.from(b));cb();}});
  const code=await main(planArgs(f),{stdout:broken,stderr});assert.equal(code,4);
  const r=JSON.parse(Buffer.concat(errors).toString()).retained_result;
  assert.equal(r.type,'source_edit_result_plan');assert.equal(hash(await readFile(f.inputs.expected)),r.expected_sha256);
});
test('SIGKILL after apply retains exact desired results and recovers only the original key',async t=>{
  const f=await setup(t),saved=await saveVerifiedSourceEdit(f.candidate,f.capture,f.bundle,f.evidence);
  const staged=await stageSourceApply(f.journal,f.candidate,saved.manifest_sha256,PRINCIPAL);
  let observed;const arrived=new Promise(r=>{observed=r;});
  f.control.handler=(_req,_res,call)=>{if(call.operation==='apply')observed();};
  const active=command(['apply','--journal',f.journal,'--request-sha256',staged.request_sha256,'--token-file',f.inputs.token]);
  t.after(()=>{if(active.child.exitCode===null&&active.child.signalCode===null)active.child.kill('SIGKILL');});
  await Promise.race([arrived,new Promise((_,reject)=>setTimeout(()=>reject(Error('apply was not observed')),10000).unref())]);
  active.child.kill('SIGKILL');assert.equal((await active.result).signal,'SIGKILL');
  const before=await inspectSourceApply(f.journal,staged.request_sha256);assert.equal(before.state,'outcome_unknown');
  assert.equal(before.source_verification.intended_tree,f.nextTree.oid);
  f.control.handler=(_req,res,call)=>{assert.equal(call.operation,'outcomes');assert.equal(call.body.length,0);
    assert.equal(call.headers['idempotency-key'],staged.key);f.send(res,f.outcome);};
  const recovered=await run(['recover','--journal',f.journal,'--request-sha256',staged.request_sha256,'--token-file',f.inputs.token]);
  assert.equal(recovered.code,0,recovered.err);assert.equal(json(recovered).source_verification.requested_result_verified,true);
  assert.equal(json(recovered).decision.decision_sequence,sequence);
  assert.deepEqual(f.calls.map(c=>c.operation),['apply','outcomes']);
});
