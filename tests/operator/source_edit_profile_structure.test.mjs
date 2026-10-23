// Installed Git constructs independent tree/commit/bundle fixture bytes.
// The inspection receipts here are adversarial schema fixtures, NOT native fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync,readFileSync,rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { peer,digest } from './source_edit_fixture.mjs';
import { validateSourceEdit, EDIT_PROFILE_CAPTURE } from '../../scripts/operator/source_edit_candidate.mjs';
const hex = value => Buffer.from(value).toString('hex');
const opaque = () => ({type:'object_only',content_read:false});
async function fixture(t,format) {
  const f=await peer(t,format),dir=mkdtempSync(join(tmpdir(),'fg-profile-tree-'));
  try {
    const git=(args,input)=>execFileSync('git',['-C',dir,...args],{input,env:{...process.env,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null'}}).toString().trim();
    git(['init','--quiet',`--object-format=${format}`]);
    const object=(kind,bytes)=>git(['hash-object','-w','-t',kind,'--stdin'],bytes);
    const tree=rows=>git(['mktree','-z'],Buffer.concat(rows.map(([mode,name,id])=>Buffer.concat([
      Buffer.from(`${mode} ${mode==='40000'?'tree':'blob'} ${id}\t`),Buffer.from(name),Buffer.from([0])]))));
    const a=object('blob',Buffer.from('before\0x')),b=object('blob',Buffer.from('after\0y'));
    const sibling=object('blob',Buffer.from('untouched'));
    const leftSub=tree([['100644','x',a]]),rightSub=tree([['100755','x',b]]);
    const raw=Buffer.from([0x61,0xff]);
    const old=tree([['40000','sub',leftSub],['100644','sub.',a],['100644',raw,a]]);
    const lib=tree([['100755',raw,b],['100644','sub.',b],['40000','sub',rightSub]]);
    const beforeTree=tree([['40000','old',old],['100644','keep',sibling]]);
    const afterTree=tree([['40000','lib',lib],['100644','keep',sibling]]);
    const metadata=f.request.metadata;
    const body=(root,parent,timestamp,message)=>Buffer.from(`tree ${root}\n${parent?`parent ${parent}\n`:''}author ${metadata.author} ${timestamp} +0000\ncommitter ${metadata.committer} ${timestamp} +0000\n\n${message}`);
    const base=object('commit',body(beforeTree,null,1,'base\n'));
    const commit=body(afterTree,base,2,metadata.message),candidate=object('commit',commit);
    git(['update-ref','refs/heads/main',candidate]);git(['bundle','create',join(dir,'candidate.bundle'),'refs/heads/main',`^${base}`]);
    const bundle=readFileSync(join(dir,'candidate.bundle'));
    const fileRows=[],directoryRows=[];
    for(const [prefix,side,id,sub,blob]of[['old','before',old,leftSub,a],['lib','after',lib,rightSub,b]]) {
      const row=(path,mode,identity,structural)=>({path_hex:hex(path),kind:side==='before'?'deleted':'added',
        before:side==='before'?{mode,oid:identity}:null,after:side==='after'?{mode,oid:identity}:null,
        content:structural?opaque():{type:'binary',before_bytes:side==='before'?8:0,after_bytes:side==='after'?7:0,body_included:false}});
      directoryRows.push(row(prefix,0o40000,id,true),row(prefix+'/sub',0o40000,sub,true));
      for(const [name,mode]of[[Buffer.concat([Buffer.from(prefix+'/'),raw]),side==='after'?0o100755:0o100644],[prefix+'/sub.',0o100644],[prefix+'/sub/x',side==='after'?0o100755:0o100644]]) fileRows.push(row(name,mode,blob,false));
    }
    const sort=rows=>rows.sort((a,b)=>a.path_hex<b.path_hex?-1:1);
    const leaves=sort(fileRows),entries=sort([...leaves,...directoryRows]);
    const request={...structuredClone(f.request),expected_commit:base,expected_result_tree:afterTree,patch_profile:'exact-tree-binary-v1',paths_hex:leaves.map(r=>r.path_hex)};
    const preparation={...structuredClone(f.preparation),source_commit:base,candidate_commit:candidate,root_tree:afterTree,patch_profile:request.patch_profile,expected_result_tree:afterTree,
      bundle:{bytes:bundle.length,sha256:digest(bundle)},paths:leaves.map(r=>({path_hex:r.path_hex,old_blob:r.before?.oid??null,new_blob:r.after?.oid??null,new_mode:r.after?.mode??null,hunks:0}))};
    const inspection={...structuredClone(f.inspection),expected_commit:base,candidate_commit:candidate,parents:[base],bundle_bytes:bundle.length,bundle_sha256:digest(bundle),candidate_commit_body_hex:commit.toString('hex'),
      comparison:{mode:'direct',before_tree:beforeTree,after_tree:afterTree,entry_count:entries.length,entries}};
    return {capture:{schema:EDIT_PROFILE_CAPTURE,request,patch_sha256:preparation.patch_sha256,patch_bytes:f.patch.length,preparation,inspection},bundle};
  }finally{rmSync(dir,{recursive:true,force:true});}
}
for(const format of ['sha1','sha256']) {
  test(`${format}: complete raw-byte nested added/deleted trees match independent Git identities`,async t=>{
    const f=await fixture(t,format),result=validateSourceEdit(f.capture,f.bundle);
    assert.deepEqual(result.capture,f.capture);assert.equal(result.bundle_objects_independently_verified,false);
    assert.equal(result.capture.inspection.comparison.entries.length,10);
    assert.equal(result.capture.preparation.paths.length,6);
    for(const schema of ['frankengit-source-edit-capture-v1','frankengit-source-edit-capture-v2']) {
      const changed=structuredClone(f.capture);changed.schema=schema;delete changed.request.patch_profile;delete changed.preparation.patch_profile;
      if(schema.endsWith('v1')){delete changed.request.expected_result_tree;delete changed.preparation.expected_result_tree;}
      assert.throws(()=>validateSourceEdit(changed,f.bundle));
    }
  });
  const mutations={
    'wrong directory identity':rows=>{rows.find(r=>r.path_hex===hex('lib')).after.oid='e'.repeat(format==='sha1'?40:64);},
    'missing nested structural row':rows=>rows.splice(rows.findIndex(r=>r.path_hex===hex('lib/sub')),1),
    'missing nested file':rows=>rows.splice(rows.findIndex(r=>r.path_hex===hex('lib/sub/x')),1),
    'extra empty directory':rows=>rows.push({path_hex:hex('zzz'),kind:'added',before:null,after:{mode:0o40000,oid:'e'.repeat(format==='sha1'?40:64)},content:opaque()}),
    'directory kind reversal':rows=>{rows.find(r=>r.path_hex===hex('lib')).kind='deleted';},
    'both directory sides present':rows=>{const r=rows.find(r=>r.path_hex===hex('lib'));r.before={...r.after};r.kind='modified';},
    'directory content falsely read':rows=>{rows.find(r=>r.path_hex===hex('lib')).content.content_read=true;},
    'directory content arbitrary':rows=>{rows.find(r=>r.path_hex===hex('lib')).content.type='identical';},
    'mixed direction child':rows=>{const r=rows.find(r=>r.path_hex===hex('lib/sub'));r.before=r.after;r.after=null;r.kind='deleted';},
    'non-null opposite file side':rows=>{const r=rows.find(r=>r.path_hex===hex('lib/sub/x'));r.before={...r.after};r.kind='modified';},
    'directory mode disguised as symlink':rows=>{rows.find(r=>r.path_hex===hex('lib')).after.mode=0o120000;},
    'duplicate row':rows=>rows.splice(1,0,structuredClone(rows[0])),
    'out of order':rows=>rows.reverse(),
    'unknown row field':rows=>{rows[0].trusted=true;},
    'wrong immediate-child executable mode':rows=>{rows.find(r=>r.path_hex===hex('lib/sub/x')).after.mode=0o100644;},
    'misleading directory prefix':rows=>{rows.find(r=>r.path_hex===hex('lib')).path_hex=hex('lib-');},
  };
  for(const [name,mutate]of Object.entries(mutations))test(`${format}: ${name} refuses without accepting a filtered view`,async t=>{
    const f=await fixture(t,format);validateSourceEdit(f.capture,f.bundle);
    const altered=structuredClone(f.capture);mutate(altered.inspection.comparison.entries);
    altered.inspection.comparison.entry_count=altered.inspection.comparison.entries.length;
    assert.throws(()=>validateSourceEdit(altered,f.bundle));
    validateSourceEdit(f.capture,f.bundle);
  });
}
