// Actual private-file executable, including async encoding and lost output.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, stat, realpath, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { Writable } from 'node:stream';
import { main } from '../../scripts/fg_source_patch.mjs';
import { compileCompactSourceSplices, SPLICE_PATCH_PROFILES } from '../../scripts/operator/source_edit_compact_splices.mjs';
import { compileSourceSplices, SPLICE_PROFILE } from '../../scripts/operator/source_edit_splices.mjs';
const hex=b=>Buffer.from(b).toString('hex');
const hash=b=>createHash('sha256').update(b).digest('hex');
async function fixture(t,format='sha1') {
  const dir=await mkdtemp(join(await realpath(tmpdir()),'fg-compact-splice-cli-'));t.after(()=>rm(dir,{recursive:true,force:true}));
  const old=Buffer.from('abcdefghijklmno\n'.repeat(51200)),source=join(dir,'old'),input=join(dir,'plan.json'),output=join(dir,'change.patch');
  await writeFile(source,old,{mode:0o600});
  const original={file:source,mode:0o100644,blob:createHash(format).update(`blob ${old.length}\0`).update(old).digest('hex')};
  const plan={schema:SPLICE_PROFILE,object_format:format,files:[{path_hex:hex('src/file'),before:original,after_mode:0o100755,
    edits:[{byte_start:400000,before_hex:'61',after_hex:'5a'}]}]};
  const save=()=>writeFile(input,JSON.stringify(plan),{mode:0o600});await save();
  const args=['splice','--splices-file',input,'--output',output];
  const files=[{...plan.files[0],before:{bytes:old,blob:original.blob,mode:original.mode},edits:[{byte_start:400000,before:Buffer.from('a'),after:Buffer.from('Z')}]}];
  return {dir,old,source,input,output,plan,save,args,files,format};
}
function run(args) {
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['scripts/fg_source_patch.mjs',...args],{stdio:['ignore','pipe','pipe']});
    const out=[],err=[];child.stdout.on('data',b=>out.push(b));child.stderr.on('data',b=>err.push(b));
    child.on('error',reject);child.on('close',(code,signal)=>resolve({code,signal,out:Buffer.concat(out).toString(),err:Buffer.concat(err).toString()}));
  });
}
for(const format of ['sha1','sha256']) for(const profile of SPLICE_PATCH_PROFILES) test(`${format} ${profile}: actual CLI emits compact checked bytes where full replacement cannot fit`,async t=>{
  const f=await fixture(t,format);assert.throws(()=>compileSourceSplices(format,f.files),/patch_limit/);
  const r=await run([...f.args,'--patch-profile',profile]);assert.equal(r.code,0,r.err);
  const receipt=JSON.parse(r.out),patch=await readFile(f.output),expected=await compileCompactSourceSplices(format,f.files,{patchProfile:profile});
  assert.deepEqual(patch,expected.patch);assert.equal(receipt.patch_sha256,hash(patch));
  assert.equal(receipt.patch_profile,profile);assert.equal(receipt.splice_profile,SPLICE_PROFILE);
  assert.equal(receipt.splice_count,1);assert.equal(receipt.hunks,1);assert.equal(receipt.expected_bytes,1);assert.equal(receipt.inserted_bytes,1);
  assert.equal(receipt.preimages_verified,true);assert.equal(receipt.source_membership_verified,false);assert.equal(receipt.publication_attempted,false);
  assert.equal(receipt.source_bytes,f.old.length);assert.equal(receipt.result_bytes,f.old.length);assert.ok(patch.length<1024);
  assert.equal((await stat(f.output)).mode&0o777,0o600);assert.deepEqual(await readFile(f.source),f.old);
});
for(const [label,tail] of [
  ['unknown profile',['--patch-profile','unknown']],['duplicate profile',['--patch-profile',SPLICE_PATCH_PROFILES[0],'--patch-profile',SPLICE_PATCH_PROFILES[1]]],
  ['binary literal conflict',['--patch-profile',SPLICE_PATCH_PROFILES[0],'--binary','literal']],
  ['binary delta conflict',['--patch-profile',SPLICE_PATCH_PROFILES[1],'--binary','delta']],
  ['too-small output',['--patch-profile',SPLICE_PATCH_PROFILES[0],'--max-patch-bytes','1']],
]) test(`CLI ${label} refuses without final output`,async t=>{
  const f=await fixture(t),r=await run([...f.args,...tail]);assert.equal(r.code,2,r.out);
  await assert.rejects(readFile(f.output),{code:'ENOENT'});
});
test('the replacement-only command and untrusted JSON cannot silently enable compact splices',async t=>{
  const f=await fixture(t);
  let r=await run(['compile','--changes-file',f.input,'--output',f.output,'--patch-profile',SPLICE_PATCH_PROFILES[0]]);
  assert.equal(r.code,2);f.plan.patch_profile=SPLICE_PATCH_PROFILES[0];await f.save();
  r=await run(f.args);assert.equal(r.code,2);await assert.rejects(readFile(f.output),{code:'ENOENT'});
});
test('stale selected bytes and binary bytes are refused before output, not normalized into a compact result',async t=>{
  for(const mutate of [f=>{f.plan.files[0].edits[0].before_hex='7a';},f=>{f.plan.files[0].edits[0].after_hex='00';}]){
    const f=await fixture(t);mutate(f);await f.save();
    assert.equal((await run([...f.args,'--patch-profile',SPLICE_PATCH_PROFILES[1]])).code,2);
    await assert.rejects(readFile(f.output),{code:'ENOENT'});
  }
});
test('competing compact exporters retain one private patch and never overwrite its receipt',async t=>{
  const f=await fixture(t),args=[...f.args,'--patch-profile',SPLICE_PATCH_PROFILES[1]];
  const results=await Promise.all([run(args),run(args)]);assert.deepEqual(results.map(r=>r.code).sort(),[0,2]);
  const winner=JSON.parse(results.find(r=>r.code===0).out),before=await readFile(f.output);
  assert.equal(winner.patch_sha256,hash(before));assert.equal((await run(args)).code,2);assert.deepEqual(await readFile(f.output),before);
});
test('async encoding cancellation publishes nothing; a lost stdout after publication preserves the exact receipt',async t=>{
  const f=await fixture(t),args=[...f.args,'--patch-profile',SPLICE_PATCH_PROFILES[1]],stop=new AbortController();
  const quiet=()=>new Writable({write(_b,_e,cb){cb();}});
  const pending=main(args,{signal:stop.signal,stdout:quiet(),stderr:quiet()});setTimeout(()=>stop.abort(),0);
  assert.equal(await pending,2);await assert.rejects(readFile(f.output),{code:'ENOENT'});
  const errors=[],broken=new Writable({write(_b,_e,cb){cb(new Error('closed'));}}),stderr=new Writable({write(b,_e,cb){errors.push(b);cb();}});
  assert.equal(await main(args,{stdout:broken,stderr}),4);
  const receipt=JSON.parse(Buffer.concat(errors)).retained_result;
  assert.equal(receipt.patch_sha256,hash(await readFile(f.output)));assert.equal(receipt.patch_profile,SPLICE_PATCH_PROFILES[1]);
  assert.ok(!(await readdir(f.dir)).some(n=>n.includes('.writing-')));
});
