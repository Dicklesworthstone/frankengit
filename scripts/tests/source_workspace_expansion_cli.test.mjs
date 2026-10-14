// Real CLI, private files and sockets. Native-shaped peers are not Rust fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, unlink, lstat, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { main } from '../fg_source_workspace.mjs';
import { localPath, loadSourceWorkspace } from '../operator/source_workspace.mjs';
import { canonical } from '../operator/source_changes.mjs';
import { changeFixture, hexPath } from './source_changes_fixture.mjs';
import { selectSource, withParent } from './source_replay_fixture.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
const CLI = new URL('../fg_source_workspace.mjs',import.meta.url).pathname;
const CHANGES = new URL('../fg_source_changes.mjs',import.meta.url).pathname;
const EDIT = new URL('../fg_source_edit.mjs',import.meta.url).pathname;
const absent = p => assert.rejects(lstat(p),{code:'ENOENT'});
function cli(args, executable = CLI) {
  return new Promise((resolve,reject)=>{
    const child = spawn(process.execPath,[executable,...args],{stdio:['ignore','pipe','pipe']}), out=[],err=[];
    let failure=null,size=0;
    const timer=setTimeout(()=>{failure=Error('CLI did not settle');child.kill('SIGKILL');},20000);
    child.once('error',e=>{clearTimeout(timer);reject(e);});
    for(const [stream,parts] of [[child.stdout,out],[child.stderr,err]]) stream.on('data',b=>{
      size+=b.length; if(size>262144){failure=Error('CLI output limit');child.kill('SIGKILL');} else parts.push(b);
    });
    child.once('close',(code,signal)=>{clearTimeout(timer);if(failure)reject(failure);else resolve({code,signal,out:Buffer.concat(out).toString(),err:Buffer.concat(err).toString()});});
  });
}
const success = r => {assert.equal(r.code,0,r.err);assert.equal(r.signal,null);return JSON.parse(r.out);};
async function setup(t, full = changeFixture('sha1'), original = ['empty.txt','src/main.rs'], added = ['run.sh']) {
  const root = await mkdtemp(join(tmpdir(),'fg-expand-cli-')); t.after(()=>rm(root,{recursive:true,force:true}));
  const left=selectSource(full,original), right=selectSource(full,added), workspace=join(root,'original'), output=join(root,'expanded');
  const source=join(root,'source.json'), expected=join(root,'expected.json'), more=join(root,'more.json'), moreExpected=join(root,'more-expected.json');
  for(const [path,bytes] of [[source,left.bytes],[expected,canonical(left.expected)],[more,right.bytes],[moreExpected,canonical(right.expected)]]) await writeFile(path,bytes,{mode:0o600});
  const created=success(await cli(['create','--package',source,'--expect',expected,'--output',workspace]));
  const expand=['expand','--workspace',workspace,'--sha256',created.workspace_sha256,'--package',more,'--expect',moreExpected,'--output',output];
  return {root,full,left,right,workspace,output,created,expand,source,expected,more,moreExpected};
}
for(const format of ['sha1','sha256']) {
  test(`${format}: expand and capture edited old/new files through packed candidate and one-shot recovery`,async t=>{
    const peer=await nativePeer(format,{tls:true,nativePatchBundle:true,files:[
      {path:'src/main.rs',bytes:'line\n'.repeat(1000)}, {path:'empty.txt',bytes:''},
      {path:'run.sh',bytes:'echo initial\n',mode:0o100755}, {path:'hidden/untouched',bytes:'not selected\n'}]});
    t.after(()=>peer.close());
    const s=await setup(t,peer.fixture), oldFile=localPath(s.workspace,hexPath('src/main.rs'));
    const edited=Buffer.from(Array.from({length:1000},(_,i)=>i===5||i===990?`binary\0edit${i}\n`:'line\n').join(''));
    await writeFile(oldFile,edited); await unlink(localPath(s.workspace,hexPath('empty.txt')));
    const paths=join(s.root,'paths.json'), oldCapture=join(s.root,'old-capture');
    const profile={byte_profile:'binary-safe-v1',patch_profile:'bounded-line-hunks-v1'};
    await writeFile(paths,canonical({paths_hex:s.left.expected.files.map(f=>f.pathHex),...profile}),{mode:0o600});
    const old=success(await cli(['capture','--workspace',s.workspace,'--sha256',s.created.workspace_sha256,'--paths',paths,'--output',oldCapture]));
    const expanded=success(await cli(s.expand));
    assert.deepEqual(await readFile(localPath(s.output,hexPath('src/main.rs'))),edited);
    await absent(localPath(s.output,hexPath('hidden')));
    await writeFile(localPath(s.output,hexPath('run.sh')),'echo newly selected and edited\n');
    await chmod(localPath(s.output,hexPath('run.sh')),0o600);
    await writeFile(paths,canonical({paths_hex:['empty.txt','run.sh','src/main.rs'].map(hexPath),...profile}));
    const capture=join(s.root,'capture'), captured=success(await cli(['capture','--workspace',s.output,'--sha256',expanded.workspace_sha256,'--paths',paths,'--output',capture]));
    const inspected=success(await cli(['inspect-capture','--capture',capture,'--sha256',captured.capture_sha256]));
    assert.equal(inspected.offline_recomputed,true); assert.equal(captured.changed_path_count,3);
    const draft=JSON.parse(await readFile(join(capture,'draft.json'),'utf8'));
    assert.equal(draft.effects.find(f=>f.path_hex===hexPath('src/main.rs')).hunks,2);
    const selection=join(s.root,'target.json'), token=join(s.root,'token'), ca=join(s.root,'ca.pem');
    await writeFile(selection,canonical(peer.selection(draft.effects.map(f=>f.path_hex))),{mode:0o600});
    await writeFile(token,TOKEN,{mode:0o600});await writeFile(ca,peer.ca,{mode:0o600});
    const candidate=join(s.root,'candidate'), journal=join(s.root,'journal');
    const common=['--package',join(capture,'source.json'),'--expect',join(capture,'expected.json'),'--changes',join(capture,'changes.json'),'--confirm-draft-sha256',captured.draft_sha256];
    const prepare=['prepare-packed',...common,'--selection',selection,'--token-file',token,'--ca-file',ca,'--output',candidate];
    const wrong=prepare.slice();wrong[wrong.indexOf('--confirm-draft-sha256')+1]=old.draft_sha256;
    assert.equal((await cli(wrong,CHANGES)).code,2);assert.equal(peer.requests.length,0);await absent(candidate);
    const saved=success(await cli(prepare,CHANGES));assert.equal(saved.pack_verification.exact_object_inventory_verified,true);
    success(await cli(['inspect-packed',...common,'--candidate',candidate,'--sha256',saved.manifest_sha256],CHANGES));
    const staged=success(await cli(['stage-packed',...common,'--selection',selection,'--candidate',candidate,'--sha256',saved.manifest_sha256,
      '--principal',PRINCIPAL,'--confirm-candidate',saved.candidate_commit,'--journal',journal],CHANGES));
    assert.equal(staged.pack_verification.packed_objects_independently_verified,true);assert.equal(peer.applies,0);
    for(const p of [s.workspace,s.output,oldCapture,capture,candidate])await rm(p,{recursive:true});
    for(const p of [s.source,s.expected,s.more,s.moreExpected,selection,paths])await rm(p);
    peer.lostApply=true;
    const args=['--journal',journal,'--request-sha256',staged.request_sha256,'--token-file',token,'--ca-file',ca];
    const lost=await cli(['apply',...args],EDIT);assert.equal(lost.code,3,lost.err);
    assert.equal(JSON.parse(lost.err).retained_request.key,staged.key);
    await writeFile(token,ROTATED_TOKEN);
    const recovered=success(await cli(['recover',...args],EDIT));
    assert.equal(recovered.key,staged.key);assert.equal(recovered.decision.decision_sequence,'18446744073709551615');
    assert.equal(recovered.decision.outcome,'committed');assert.equal(peer.applies,1);assert.deepEqual(peer.failures,[]);
  });
}
test('CLI expansion produces independently reopenable baseline and refuses original root pin',async t=>{
  const s=await setup(t), expanded=success(await cli(s.expand));
  await rm(s.workspace,{recursive:true});await rm(s.more);await rm(s.moreExpected);
  const status=success(await cli(['status','--workspace',s.output,'--sha256',expanded.workspace_sha256]));assert.equal(status.entries.length,3);
  assert.equal((await cli(['status','--workspace',s.output,'--sha256',s.created.workspace_sha256])).code,2);
});
test('CLI refuses public or symlinked supplemental inputs without claiming output',async t=>{
  const s=await setup(t);await chmod(s.more,0o644);assert.equal((await cli(s.expand)).code,2);await absent(s.output);
  await chmod(s.more,0o600);const alias=join(s.root,'alias');await symlink(s.more,alias);
  const args=s.expand.slice();args[args.indexOf('--package')+1]=alias;assert.equal((await cli(args)).code,2);await absent(s.output);
});
test('CLI rejects credentials, network, force, missing and duplicate selectors',async t=>{
  const s=await setup(t);
  for(const args of [...['--token-file','--endpoint','--force','--sha256'].map(k=>[...s.expand,k,s.more]),s.expand.slice(0,-2)]) {
    const r=await cli(args);assert.equal(r.code,2);assert.equal(r.out,'');assert.equal(JSON.parse(r.err).network_attempted,false);
  }
  await absent(s.output);
});
test('CLI prevents occupied added paths and existing output replacement',async t=>{
  const s=await setup(t), p=localPath(s.workspace,hexPath('run.sh'));
  await writeFile(p,'untracked',{mode:0o600});assert.equal((await cli(s.expand)).code,2);await absent(s.output);
  await unlink(p);const result=success(await cli(s.expand));const original=await readFile(join(s.output,'manifest.json'));
  assert.equal((await cli(s.expand)).code,2);assert.deepEqual(await readFile(join(s.output,'manifest.json')),original);
  await loadSourceWorkspace(s.output,result.workspace_sha256);
});
test('two independent CLI processes cannot replace the same expanded workspace',async t=>{
  const s=await setup(t), results=await Promise.all([cli(s.expand),cli(s.expand)]);
  assert.deepEqual(results.map(r=>r.code).sort(),[0,2]);const saved=success(results.find(r=>r.code===0));
  await loadSourceWorkspace(s.output,saved.workspace_sha256);
});
test('failed result delivery retains a completed expanded workspace and its new pin',async t=>{
  const s=await setup(t), errors=[];
  const stdout=new Writable({write(_b,_e,cb){cb(Error('lost stdout'));}});
  const stderr=new Writable({write(b,_e,cb){errors.push(Buffer.from(b));cb();}});
  const code=await main(s.expand,{stdout,stderr});assert.equal(code,4);
  const report=JSON.parse(Buffer.concat(errors));assert.equal(report.retained_result.type,'source_workspace_expanded');
  await loadSourceWorkspace(s.output,report.retained_result.workspace_sha256);
  await loadSourceWorkspace(s.workspace,s.created.workspace_sha256);
});
test('new generation is refused by CLI instead of refreshing source beneath local edits',async t=>{
  const s=await setup(t), next=selectSource(withParent(s.full,s.full.commit),['run.sh']);
  await writeFile(s.more,next.bytes);await writeFile(s.moreExpected,canonical(next.expected));
  const r=await cli(s.expand);assert.equal(r.code,2);await absent(s.output);assert.equal(r.err.includes('source_union_basis'),true);
});
test('explicit further expansion preserves work after removing earlier workspace generations',async t=>{
  const full=changeFixture('sha1',[{path:'a',bytes:'a'},{path:'b',bytes:'b'},{path:'c',bytes:'c'}]);
  const s=await setup(t,full,['a'],['b']);await writeFile(localPath(s.workspace,hexPath('a')),'edited a');
  const second=success(await cli(s.expand));await rm(s.workspace,{recursive:true});
  await writeFile(localPath(s.output,hexPath('b')),'edited b');const extra=selectSource(full,['c']);
  await writeFile(s.more,extra.bytes);await writeFile(s.moreExpected,canonical(extra.expected));
  const output=join(s.root,'third'), third=success(await cli(['expand','--workspace',s.output,'--sha256',second.workspace_sha256,
    '--package',s.more,'--expect',s.moreExpected,'--output',output]));
  await rm(s.output,{recursive:true});assert.equal(third.files,3);
  assert.equal((await readFile(localPath(output,hexPath('a')))).toString(),'edited a');
  assert.equal((await readFile(localPath(output,hexPath('b')))).toString(),'edited b');
  assert.equal((await readFile(localPath(output,hexPath('c')))).toString(),'c');
  success(await cli(['status','--workspace',output,'--sha256',third.workspace_sha256]));
});
test('help describes the explicit expansion and unchanged source generation',async()=>{
  const text=success(await cli(['--help'])).usage;assert.match(text,/expand --workspace/);assert.match(text,/SAME commit/);
});
test('expanding only read context changes review consent even when patch and resulting tree are identical',async t=>{
  const s=await setup(t);await writeFile(localPath(s.workspace,hexPath('src/main.rs')),'local edit\n');
  const paths=join(s.root,'paths.json');await writeFile(paths,canonical({paths_hex:[hexPath('src/main.rs')]}),{mode:0o600});
  const oldPath=join(s.root,'before-capture');
  const before=success(await cli(['capture','--workspace',s.workspace,'--sha256',s.created.workspace_sha256,'--paths',paths,'--output',oldPath]));
  const expanded=success(await cli(s.expand)), nextPath=join(s.root,'after-capture');
  const after=success(await cli(['capture','--workspace',s.output,'--sha256',expanded.workspace_sha256,'--paths',paths,'--output',nextPath]));
  assert.deepEqual(await readFile(join(oldPath,'patch.diff')),await readFile(join(nextPath,'patch.diff')));
  assert.equal(before.expected_tree,after.expected_tree);assert.notEqual(before.draft_sha256,after.draft_sha256);
  const expected=JSON.parse(await readFile(join(nextPath,'expected.json'),'utf8'));
  assert.equal(expected.files.length,3);
});
