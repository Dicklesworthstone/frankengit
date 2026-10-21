// Actual local edits through the complete source-authoring/candidate/recovery
// modules. Native-schema HTTP peers are not a Rust server or authority proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, realpath, rm, writeFile, readFile, chmod, unlink, mkdir, symlink, lstat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { createSourceWorkspace, loadSourceWorkspace, localPath } from '../operator/source_workspace.mjs';
import { collectWorkspaceChanges, captureWorkspaceChanges, inspectWorkspaceChangeCapture } from '../operator/source_workspace_changes.mjs';
import { canonical, sha256, buildSourceChanges } from '../operator/source_changes.mjs';
import { prepareSourceChanges, stageVerifiedSourceChanges } from '../operator/source_changes_prepare.mjs';
import { saveSourceEdit, dispatchSourceApply, recoverSourceApply, inspectSourceApply } from '../operator/source_edit_publish.mjs';
import { changeFixture, hexPath, intent } from './source_changes_fixture.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
import { main } from '../fg_source_workspace.mjs';
const CLI = new URL('../fg_source_workspace.mjs', import.meta.url).pathname;
const AUTHOR = new URL('../fg_source_changes.mjs', import.meta.url).pathname;
const missing = p => assert.rejects(lstat(p), {code:'ENOENT'});
async function setup(t, format='sha1', files) {
  const f=changeFixture(format,files), root=await realpath(await mkdtemp(join(tmpdir(),'fg-workspace-changes-'))), path=join(root,'workspace');
  t.after(()=>rm(root,{recursive:true,force:true}));
  const saved=await createSourceWorkspace(path,f.bytes,f.expected), hash=saved.workspace_sha256;
  return {f,root,path,hash, output:join(root,'capture'),
    collect: (paths,options)=>collectWorkspaceChanges(path,hash,{paths_hex:paths.map(hexPath)},options),
    capture: (paths,options)=>captureWorkspaceChanges(path,hash,{paths_hex:paths.map(hexPath)},join(root,'capture'),options)};
}
function cli(script,args) {
  return new Promise((resolve,reject)=>{
    const p=spawn(process.execPath,[script,...args],{stdio:['ignore','pipe','pipe']}), out=[],err=[];
    const timer=setTimeout(()=>{p.kill('SIGKILL');reject(Error('CLI deadline'));},20000);
    p.stdout.on('data',b=>out.push(b));p.stderr.on('data',b=>err.push(b));
    p.on('error',e=>{clearTimeout(timer);reject(e);});p.on('close',code=>{clearTimeout(timer);resolve({code,out:Buffer.concat(out).toString(),err:Buffer.concat(err).toString()});});
  });
}
for(const format of ['sha1','sha256']) {
  test(`${format}: explicit file selection yields exact changed/new/deleted/mode effects`,async t=>{
    const s=await setup(t,format);
    await writeFile(localPath(s.path,hexPath('src/main.rs')),'fn main() { updated(); }\r\n');
    await unlink(localPath(s.path,hexPath('empty.txt')));await chmod(localPath(s.path,hexPath('run.sh')),0o600);
    await mkdir(localPath(s.path,hexPath('new')),{mode:0o700}); await writeFile(localPath(s.path,hexPath('new/file')),Buffer.from([0xff,13,10]),{mode:0o700});
    const r=await s.collect(['run.sh','new/file','empty.txt','src/main.rs']);
    assert.equal(r.manifest.changed_path_count,4);assert.equal(r.manifest.unchanged_path_count,0);
    assert.deepEqual(r.changes.changes.map(c=>c.operation),['delete','create','replace','replace']);
    const expected=await buildSourceChanges(s.f.bytes,s.f.expected,r.changes);
    assert.deepEqual(r.draft.bytes,expected.bytes);assert.deepEqual(r.draft.tree,expected.tree);
    assert.equal(r.draft.tree.beforeTree,s.f.tree);assert.equal(r.manifest.repository_changed,false);
  });
  test(`${format}: capture survives workspace removal and replays into the existing authoring CLI`,async t=>{
    const s=await setup(t,format);await writeFile(localPath(s.path,hexPath('src/main.rs')),'fn main() {}\n');
    const r=await s.capture(['src/main.rs','run.sh']);assert.equal(r.unchanged_path_count,1);
    assert.equal((await lstat(join(s.output,'changes.json'))).mode&0o777,0o600);
    await rm(s.path,{recursive:true});
    const inspected=await inspectWorkspaceChangeCapture(s.output,r.capture_sha256);assert.equal(inspected.offline_recomputed,true);
    const out=await cli(AUTHOR,['draft','--package',join(s.output,'source.json'),'--expect',join(s.output,'expected.json'),
      '--changes',join(s.output,'changes.json'),'--output',join(s.root,'redraft')]);assert.equal(out.code,0,out.err);
    assert.equal(JSON.parse(out.out).manifest_sha256,r.draft_sha256);
    assert.deepEqual(await readFile(join(s.output,'patch.diff')),await readFile(join(s.root,'redraft','patch.diff')));
  });
  test(`${format}: captured workspace -> native candidate -> stage -> lost-reply recovery`,async t=>{
    const peer=await nativePeer(format,{tls:format==='sha256'});t.after(()=>peer.close());
    const root=await realpath(await mkdtemp(join(tmpdir(),'fg-workspace-pipeline-')));t.after(()=>rm(root,{recursive:true,force:true}));
    const path=join(root,'workspace'),f=peer.fixture,saved=await createSourceWorkspace(path,f.bytes,f.expected);
    await writeFile(localPath(path,hexPath('src/main.rs')),'fn main() { captured(); }\n');
    await mkdir(localPath(path,hexPath('generated')),{mode:0o700});await writeFile(localPath(path,hexPath('generated/new.rs')),'// new\n',{mode:0o600});
    const output=join(root,'capture'),r=await captureWorkspaceChanges(path,saved.workspace_sha256,{paths_hex:[hexPath('src/main.rs'),hexPath('generated/new.rs')]},output);
    const source=await readFile(join(output,'source.json')), expected=JSON.parse(await readFile(join(output,'expected.json'))), changes=JSON.parse(await readFile(join(output,'changes.json')));
    const draft=JSON.parse(await readFile(join(output,'draft.json'))),selection=peer.selection(draft.effects.map(e=>e.path_hex));
    const candidate=await prepareSourceChanges(source,expected,changes,selection,TOKEN,{confirmDraftSha256:r.draft_sha256,ca:peer.ca});
    assert.equal(candidate.draft.tree.afterTree,r.expected_tree);
    const candidatePath=join(root,'candidate'),keep=await saveSourceEdit(candidatePath,candidate.capture,candidate.bundle);
    const staged=await stageVerifiedSourceChanges(join(root,'journal'),candidatePath,keep.manifest_sha256,source,expected,changes,selection,
      {confirmDraftSha256:r.draft_sha256,confirmCandidate:candidate.candidate_commit,principal:PRINCIPAL});
    assert.equal(staged.binding.expected_tree,r.expected_tree);assert.equal(peer.applies,0);
    await rm(path,{recursive:true});await rm(output,{recursive:true});await rm(candidatePath,{recursive:true});
    peer.lostApply=true;await assert.rejects(dispatchSourceApply(staged.journal,staged.request_sha256,TOKEN,{ca:peer.ca}));
    const recovered=await recoverSourceApply(staged.journal,staged.request_sha256,ROTATED_TOKEN,{ca:peer.ca});
    assert.equal(recovered.key,staged.key);assert.equal(recovered.decision.outcome,'committed');
    assert.equal(recovered.decision.decision_sequence,'18446744073709551615');assert.equal(peer.applies,1);
    const count=peer.requests.length;await dispatchSourceApply(staged.journal,staged.request_sha256,TOKEN,{ca:peer.ca});
    assert.equal(peer.requests.length,count);assert.deepEqual(peer.failures,[]);
  });
  test(`${format}: ignored files and changed paths outside the explicit selection stay out`,async t=>{
    const s=await setup(t,format);await writeFile(localPath(s.path,hexPath('src/main.rs')),'wanted\n');
    await writeFile(localPath(s.path,hexPath('run.sh')),'NOT SELECTED SECRET');
    await symlink('/etc/passwd',localPath(s.path,hexPath('unselected-symlink')));
    const r=await s.collect(['src/main.rs']);assert.equal(r.draft.manifest.effects.length,1);
    assert.ok(!r.draft.bytes.includes(Buffer.from('NOT SELECTED SECRET')));assert.equal(r.manifest.unselected_paths_examined,false);
  });
  for (const [names, raw] of [['UTF-8', Buffer.from('🌱/file\n')], ['raw-byte', Buffer.from([0xff,47,0xfe,10])]]) {
    const unsupported = names === 'raw-byte' && process.platform === 'darwin';
    test(`${format}: ${names} capture ${unsupported ? 'refuses unrepresentable host paths before publication' : 'preserves exact path and content bytes'}`,async t=>{
      if (unsupported) {
        // A root-level new path has a complete committed-absence proof. The
        // refusal must be the host boundary, not missing context or local ENOENT.
        const s=await setup(t,format,[{path:'plain',bytes:'old\r\n'}]);
        await assert.rejects(s.capture([Buffer.from([0xff])]), {code:'source_workspace_host_path_unrepresentable'});
        await missing(s.output);
        await loadSourceWorkspace(s.path,s.hash);
        t.diagnostic('raw-name capture unsupported on macOS; mandatory Linux capture and UTF-8 twin retained');
        return;
      }
      const s=await setup(t,format,[{path:raw,bytes:'old\r\n'}]);
      await writeFile(localPath(s.path,raw.toString('hex')),Buffer.from([255,10,65]));
      const r=await collectWorkspaceChanges(s.path,s.hash,{paths_hex:[raw.toString('hex')]});
      assert.equal(r.changes.changes[0].path_hex,raw.toString('hex'));assert.equal(r.changes.changes[0].content_hex,'ff0a41');
    });
  }
}
test('no-change and missing new-file selections refuse without a capture directory',async t=>{
  const s=await setup(t);await assert.rejects(s.capture(['run.sh']),/no_changes/);await missing(s.output);
  await assert.rejects(s.capture(['new-file']),/new_file_missing/);await missing(s.output);
});
test('unselected original file and unknown parent are not mistaken for new-file absence',async t=>{
  const s=await setup(t),p=s.f.value;
  p.membership.files=p.membership.files.filter(f=>f.pathHex===hexPath('run.sh'));
  p.membership.trees=p.membership.trees.filter(f=>f.pathHex===null);p.blobs=p.blobs.filter(b=>b.oid===p.membership.files[0].blob);
  const expected={...s.f.expected,files:s.f.expected.files.filter(f=>f.pathHex===hexPath('run.sh'))};
  const path=join(s.root,'sparse'),r=await createSourceWorkspace(path,canonical(p),expected);
  // No local file exists: the rejection must originate from committed absence,
  // not from opening/reading a body or mistaking its absence for authorization.
  for(const name of ['empty.txt','src/new-file']) await assert.rejects(collectWorkspaceChanges(path,r.workspace_sha256,{paths_hex:[hexPath(name)]}),/Context membership/);
  await writeFile(localPath(path,hexPath('new-file')),'yes',{mode:0o600});
  assert.equal((await collectWorkspaceChanges(path,r.workspace_sha256,{paths_hex:[hexPath('new-file')]})).changes.changes[0].operation,'create');
});
test('binary materialization is readable but changed binary authoring refuses',async t=>{
  const s=await setup(t,'sha1',[{path:'binary',bytes:Buffer.from([0,1])},{path:'text',bytes:'old'}]);
  await writeFile(localPath(s.path,hexPath('text')),'new');
  assert.equal((await s.collect(['binary','text'])).changes.changes.length,1);
  await writeFile(localPath(s.path,hexPath('binary')),Buffer.from([0,2]));await assert.rejects(s.capture(['binary','text']),/binary_unsupported/);await missing(s.output);
});
test('new path with empty executable data produces one exact creation',async t=>{
  const s=await setup(t);await writeFile(localPath(s.path,hexPath('new')),'',{mode:0o700});
  const r=await s.collect(['new']);assert.equal(r.draft.manifest.effects[0].old_blob,null);
  assert.equal(r.draft.manifest.effects[0].new_mode,0o100755);assert.equal(r.draft.manifest.creation_preconditions.paths.length,1);
});
test('selection is owned before the first await',async t=>{
  const s=await setup(t);await writeFile(localPath(s.path,hexPath('src/main.rs')),'new');
  const chosen={paths_hex:[hexPath('src/main.rs')]},pending=collectWorkspaceChanges(s.path,s.hash,chosen);chosen.paths_hex.length=0;
  assert.equal((await pending).manifest.selected_path_count,1);
});
test('ordinary edits during final verification abort the actual capture',async t=>{
  const s=await setup(t);await writeFile(localPath(s.path,hexPath('src/main.rs')),'new');
  // Count the permitted twin's host checkpoints, then change an actual file
  // near the end of hashing/revalidation. No production filesystem is replaced.
  let count=0;await s.collect(['src/main.rs'],{check:()=>{count++;}});assert.ok(count>30);
  const {writeFileSync}=await import('node:fs');let at=0,changed=false;
  await assert.rejects(s.collect(['src/main.rs'],{check:()=>{
    if(++at===count-10){writeFileSync(localPath(s.path,hexPath('src/main.rs')),'raced');changed=true;}
  }}),/source_workspace_changed/);
  assert.equal(changed,true);await missing(s.output);
});
for(const name of ['source.json','expected.json','paths.json','changes.json','patch.diff','draft.json','manifest.json']) {
  test(`capture detects changed ${name} without reopening the workspace`,async t=>{
    const s=await setup(t);await writeFile(localPath(s.path,hexPath('src/main.rs')),'new');const r=await s.capture(['src/main.rs']);
    await inspectWorkspaceChangeCapture(s.output,r.capture_sha256);await rm(s.path,{recursive:true});await writeFile(join(s.output,name),'{}\n');
    await assert.rejects(inspectWorkspaceChangeCapture(s.output,r.capture_sha256));
  });
}
test('rehashing a inconsistent patch cannot replace offline regeneration',async t=>{
  const s=await setup(t);await writeFile(localPath(s.path,hexPath('src/main.rs')),'new');await s.capture(['src/main.rs']);
  const root=JSON.parse(await readFile(join(s.output,'manifest.json'))),bad=Buffer.from('not the generated patch\n');
  await writeFile(join(s.output,'patch.diff'),bad);const entry=root.payloads.find(f=>f.name==='patch.diff');entry.sha256=sha256(bad);entry.bytes=bad.length;
  const bytes=canonical(root);await writeFile(join(s.output,'manifest.json'),bytes);
  await assert.rejects(inspectWorkspaceChangeCapture(s.output,sha256(bytes)),/capture_changed/);
});
test('self-consistent capture cannot substitute the workspace baseline root',async t=>{
  const s=await setup(t);await writeFile(localPath(s.path,hexPath('src/main.rs')),'new');await s.capture(['src/main.rs']);
  const root=JSON.parse(await readFile(join(s.output,'manifest.json')));root.workspace_sha256='0'.repeat(64);const bytes=canonical(root);
  await writeFile(join(s.output,'manifest.json'),bytes);await assert.rejects(inspectWorkspaceChangeCapture(s.output,sha256(bytes)),/baseline_changed/);
});
test('output cannot overlap the workspace and competing captures do not overwrite',async t=>{
  const s=await setup(t);await writeFile(localPath(s.path,hexPath('src/main.rs')),'new');
  for(const p of [s.path,s.root,join(s.path,'files','output')]) await assert.rejects(captureWorkspaceChanges(s.path,s.hash,{paths_hex:[hexPath('src/main.rs')]},p),/overlapping_output/);
  const replies=await Promise.allSettled([s.capture(['src/main.rs']),s.capture(['src/main.rs'])]);assert.equal(replies.filter(r=>r.status==='fulfilled').length,1);
  const r=replies.find(r=>r.status==='fulfilled').value;await inspectWorkspaceChangeCapture(s.output,r.capture_sha256);
});
test('interrupted capture leaves a retained slot, not a false complete manifest',async t=>{
  const s=await setup(t);await writeFile(localPath(s.path,hexPath('src/main.rs')),'new');let error;
  try{await s.capture(['src/main.rs'],{check:()=>{if(existsSync(join(s.output,'source.json')))throw Error('stop');}});}catch(e){error=e;}
  assert.ok(error?.publication_unconfirmed?.capture_sha256);await missing(join(s.output,'manifest.json'));
  await assert.rejects(s.capture(['src/main.rs']),/output_exists/);
});
test('aborted capture does not own an output',async t=>{
  const s=await setup(t),controller=new AbortController();controller.abort();
  await assert.rejects(s.capture(['src/main.rs'],{signal:controller.signal}));await missing(s.output);
});
test('capture CLI and offline inspector consume private explicit path selections',async t=>{
  const s=await setup(t);await writeFile(localPath(s.path,hexPath('src/main.rs')),'new\n');
  const paths=join(s.root,'paths.json');await writeFile(paths,canonical({paths_hex:[hexPath('src/main.rs')]}),{mode:0o600});
  const args=['capture','--workspace',s.path,'--sha256',s.hash,'--paths',paths,'--output',s.output];
  const out=await cli(CLI,args);assert.equal(out.code,0,out.err);const r=JSON.parse(out.out);
  await rm(s.path,{recursive:true});const checked=await cli(CLI,['inspect-capture','--capture',s.output,'--sha256',r.capture_sha256]);
  assert.equal(checked.code,0,checked.err);assert.equal(JSON.parse(checked.out).draft_sha256,r.draft_sha256);
});
test('lost capture stdout retains its independently usable root',async t=>{
  const s=await setup(t);await writeFile(localPath(s.path,hexPath('src/main.rs')),'new\n');
  const paths=join(s.root,'paths.json');await writeFile(paths,canonical({paths_hex:[hexPath('src/main.rs')]}),{mode:0o600});
  const diagnostics=[],stdout=new Writable({write(_b,_e,cb){cb(Error('lost output'));}}),stderr=new Writable({write(b,_e,cb){diagnostics.push(b);cb();}});
  const code=await main(['capture','--workspace',s.path,'--sha256',s.hash,'--paths',paths,'--output',s.output],{stdout,stderr});assert.equal(code,4);
  const r=JSON.parse(Buffer.concat(diagnostics));await inspectWorkspaceChangeCapture(s.output,r.retained_result.capture_sha256);
});
for(const format of ['sha1','sha256']) test(`${format}: a physical move captures both explicit paths without rename inference`,async t=>{
  const s=await setup(t,format),{rename}=await import('node:fs/promises');
  await mkdir(localPath(s.path,hexPath('lib')),{mode:0o700});await rename(localPath(s.path,hexPath('src/main.rs')),localPath(s.path,hexPath('lib/main.rs')));
  const r=await s.collect(['src/main.rs','lib/main.rs']);
  assert.deepEqual(r.changes.changes.map(c=>c.operation),['create','delete']);assert.equal(r.draft.manifest.relocations,undefined);
  const [add,remove]=r.draft.manifest.effects;assert.equal(add.new_blob,remove.old_blob);
});
test('end-to-end CLI capture/prepare/stage uses the frozen capture, not later editor changes',async t=>{
  const peer=await nativePeer();t.after(()=>peer.close());const root=await realpath(await mkdtemp(join(tmpdir(),'fg-workspace-cli-pipeline-')));
  t.after(()=>rm(root,{recursive:true,force:true}));const path=join(root,'workspace'),f=peer.fixture;
  const saved=await createSourceWorkspace(path,f.bytes,f.expected);await writeFile(localPath(path,hexPath('src/main.rs')),'captured\n');
  const selected=join(root,'paths.json');await writeFile(selected,canonical({paths_hex:[hexPath('src/main.rs')]}),{mode:0o600});
  const output=join(root,'capture'),captured=await cli(CLI,['capture','--workspace',path,'--sha256',saved.workspace_sha256,'--paths',selected,'--output',output]);
  assert.equal(captured.code,0,captured.err);const r=JSON.parse(captured.out);
  await writeFile(localPath(path,hexPath('src/main.rs')),'later unreviewed editor change\n');
  const selection=join(root,'target.json'),token=join(root,'token');
  await writeFile(selection,canonical(peer.selection([hexPath('src/main.rs')])),{mode:0o600});await writeFile(token,TOKEN,{mode:0o600});
  const common=['--package',join(output,'source.json'),'--expect',join(output,'expected.json'),'--changes',join(output,'changes.json')];
  const candidate=join(root,'candidate'),prepared=await cli(AUTHOR,['prepare',...common,'--selection',selection,'--token-file',token,
    '--confirm-draft-sha256',r.draft_sha256,'--output',candidate]);assert.equal(prepared.code,0,prepared.err);
  const p=JSON.parse(prepared.out);assert.ok(peer.candidate.patch.includes(Buffer.from('captured')));
  assert.ok(!peer.candidate.patch.includes(Buffer.from('later unreviewed')));
  const staged=await cli(AUTHOR,['stage',...common,'--selection',selection,'--candidate',candidate,'--sha256',p.manifest_sha256,
    '--confirm-draft-sha256',r.draft_sha256,'--confirm-candidate',p.candidate_commit,'--principal',PRINCIPAL,'--journal',join(root,'journal')]);
  assert.equal(staged.code,0,staged.err);const j=JSON.parse(staged.out);assert.equal((await inspectSourceApply(j.journal,j.request_sha256)).state,'not_dispatched');
  assert.equal(peer.applies,0);assert.deepEqual(peer.failures,[]);
});
test('self-consistent hidden candidate changes are still refused for captured workspace edits',async t=>{
  const peer=await nativePeer();t.after(()=>peer.close());const root=await realpath(await mkdtemp(join(tmpdir(),'fg-workspace-hidden-')));t.after(()=>rm(root,{recursive:true,force:true}));
  const path=join(root,'workspace'),f=peer.fixture,saved=await createSourceWorkspace(path,f.bytes,f.expected);
  await writeFile(localPath(path,hexPath('src/main.rs')),'captured\n');const r=await collectWorkspaceChanges(path,saved.workspace_sha256,{paths_hex:[hexPath('src/main.rs')]});
  const selection=peer.selection(r.draft.manifest.effects.map(e=>e.path_hex));peer.fault='unreported-addition';
  await assert.rejects(prepareSourceChanges(r.baseline.packageBytes,r.baseline.expected,r.changes,selection,TOKEN,
    {confirmDraftSha256:r.manifest.draft_sha256}),/source_changes_candidate_tree/);
  peer.fault=null;assert.ok((await prepareSourceChanges(r.baseline.packageBytes,r.baseline.expected,r.changes,selection,TOKEN,
    {confirmDraftSha256:r.manifest.draft_sha256})).candidate_commit);assert.equal(peer.applies,0);assert.deepEqual(peer.failures,[]);
});
