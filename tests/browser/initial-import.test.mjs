// Browser contracts against actual byte encoders/WebCrypto, not native admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto as crypto } from 'node:crypto';
import { initialPlan, initialFilePatch, initialImportDescriptors, importInitialFiles, verifyInitial } from '../../crates/fgit-node/src/smart_http/server/browser/initial-plan.mjs';
import { fullFilePatch, FILE_LIMIT, PATCH_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
import { utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
const meta = {author:'Author <a@example.invalid>',committer:'Committer <c@example.invalid>',timestamp:1,message:'Initial binary project\n'};
const file = (path='a.bin',bytes=new Uint8Array([0,255,13,10]),mode=0o100644) => ({path_hex:hex(utf8.encode(path)),bytes,mode});
const hash = (kind, bytes, algorithm) => createHash(algorithm).update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
function selected(name,bytes=new Uint8Array([0,255]),relative='') {
  return {name,webkitRelativePath:relative,size:bytes.length,reads:0,async arrayBuffer(){this.reads++;return bytes.slice().buffer;}};
}
const input = f => ({path_hex:hex(utf8.encode(f.name)),mode:0o100644,file:f});
function envelope(plan,algorithm,change=()=>{}) {
  const bundle=utf8.encode('Explicit transport double, NOT a native pack\n');
  const fields={ref:'refs/heads/main',object_format:algorithm,expected_absent:true};
  const reply={schema_version:1,tenant_id:'1'.repeat(32),repository_id:'2'.repeat(32),repository_incarnation:'3'.repeat(32),object_format:algorithm,
    source_head:'source-head-double',snapshot_token:`alg:2:${'4'.repeat(64)}`,type:'initial_source_preparation',ref:fields.ref,ref_hex:hex(utf8.encode(fields.ref)),
    read_only:true,objects_staged:false,transaction_created:false,published:false,publication_authorized:false,expected_absent:true,default_branch_changed:false,
    parents:[],prerequisites:[],patch_sha256:plan.patchSha256,candidate_commit:plan.commit,root_tree:plan.tree,object_count:plan.objectCount,
    candidate_commit_body_hex:hex(plan.commitBody),files:structuredClone(plan.files),bundle:{bytes:bundle.length,sha256:createHash('sha256').update(bundle).digest('hex')}};
  change(reply);
  const b=`fg-initial-${'a'.repeat(48)}-0`;
  const bytes=Buffer.concat([Buffer.from(`--${b}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n${JSON.stringify(reply)}\r\n--${b}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="initial.bundle"\r\n\r\n`),bundle,Buffer.from(`\r\n--${b}--\r\n`)]);
  return {fields,response:{status:200,type:`multipart/mixed; boundary=${b}`,value:new Uint8Array(bytes)}};
}
for(const algorithm of ['sha1','sha256']) {
  test(`${algorithm}: mixed binary, text and empty executable initial files preserve native identities`,async()=>{
    const files=[file('assets/all.bin',Uint8Array.from({length:256},(_,i)=>i)),file('empty',new Uint8Array(),0o100755),file('README',utf8.encode('a\r\nb'))];
    const plan=await initialPlan(files,meta,algorithm,crypto);
    assert.equal(plan.files.length,3);assert(!Buffer.from(plan.commitBody).includes(Buffer.from('\nparent ')));
    assert.equal(plan.commit,hash('commit',plan.commitBody,algorithm));
    for(const f of files) {const actual=plan.files.find(p=>p.path_hex===f.path_hex);assert.equal(actual.blob,hash('blob',f.bytes,algorithm));assert.equal(actual.bytes,f.bytes.length);assert.equal(actual.mode,f.mode);}
    const {response,fields}=envelope(plan,algorithm);const result=await verifyInitial(response,fields,plan,null,crypto);assert.equal(result.fields.candidate_commit,plan.commit);
  });
  test(`${algorithm}: queue permutations yield byte-identical full patches and root commits`,async()=>{
    const files=[file('a.b'),file('a/z'),file('a0'),{...file(),path_hex:'ff2f62'}];
    const a=await initialPlan(files,meta,algorithm,crypto),b=await initialPlan([...files].reverse(),meta,algorithm,crypto);
    assert.deepEqual(a,b);
  });
  for(const [name,mutate] of [
    ['missing file',r=>r.files.pop()],['extra file',r=>r.files.push(r.files[0])],['changed blob',r=>r.files[0].blob='a'.repeat(algorithm==='sha1'?40:64)],
    ['changed mode',r=>r.files[0].mode=0o100755],['changed length',r=>r.files[0].bytes++],['changed tree',r=>r.root_tree='b'.repeat(algorithm==='sha1'?40:64)],
    ['invented parent',r=>r.parents=['parent']],['default branch mutation',r=>r.default_branch_changed=true],['missing object',r=>r.object_count--]]) {
    test(`${algorithm}: binary preparation rejects ${name}`,async()=>{
      const p=await initialPlan([file()],meta,algorithm,crypto),e=envelope(p,algorithm,mutate);
      await assert.rejects(verifyInitial(e.response,e.fields,p,null,crypto));
    });
  }
}
test('initial binary opt-in does not widen the shared text encoder',()=>{
 const files=[file()];assert(initialFilePatch(files).bytes.includes(0));
 assert.throws(()=>fullFilePatch(files.map(f=>({path_hex:f.path_hex,before:null,after:{bytes:f.bytes,mode:f.mode}}))),/NUL/);
});
test('file bytes and commit metadata are copied before the first asynchronous digest',async()=>{
 const bytes=new Uint8Array([0,1,255]),files=[file('a',bytes)],metadata={...meta};let entered;
 const first=new Promise(r=>entered=r);let release;const hold=new Promise(r=>release=r);let waited=false;
 const slow={subtle:{async digest(...args){if(!waited){waited=true;entered();await hold;}return crypto.subtle.digest(...args);}}};
 const pending=initialPlan(files,metadata,'sha1',slow);await first;bytes.fill(9);files[0].mode=0o100755;metadata.message='changed';release();
 const p=await pending;assert.equal(p.files[0].blob,hash('blob',new Uint8Array([0,1,255]),'sha1'));assert.equal(p.files[0].mode,0o100644);assert.equal(p.metadata.message,meta.message);
});
for(const [name,files] of [
 ['empty queue',[]],['too many files',Array.from({length:65},(_,i)=>file(String(i)))],['large file',[file('a',new Uint8Array(FILE_LIMIT+1))]],
 ['symlink',[file('a',new Uint8Array(),0o120000)]],['gitlink',[file('a',new Uint8Array(),0o160000)]],['duplicate',[file('a'),file('a')]],
 ['overlap',[file('a'),file('a/b')]],['git metadata',[file('x/.GiT/config')]],['dot dot',[file('../a')]],
 ['raw budget',Array.from({length:5},(_,i)=>file(String(i),new Uint8Array(FILE_LIMIT)))]])
 test(`initial queue refuses ${name}`,()=>assert.throws(()=>initialFilePatch(files)));
test('selected directory retains nested paths and strips only the validated common root',()=>{
 const f=[selected('a.bin',undefined,'project/assets/a.bin'),selected('résumé',undefined,'project/résumé')];
 const rows=initialImportDescriptors(f,{directory:true,prefix:'vendor',mode:0o100755});
 assert.deepEqual(rows.map(r=>Buffer.from(r.path_hex,'hex').toString()),['vendor/assets/a.bin','vendor/résumé']);assert(rows.every(r=>r.mode===0o100755));assert.equal(f[0].reads,0);
});
for(const [name,files,options] of [
 ['mixed directory roots',[selected('a',undefined,'one/a'),selected('b',undefined,'two/b')],{directory:true}],
 ['directory/file mismatch',[selected('a',undefined,'one/b')],{directory:true}],
 ['hidden git directory',[selected('config',undefined,'project/.git/config')],{directory:true}],
 ['unsafe stripped root',[selected('a',undefined,'../a')],{directory:true}],
 ['missing relative path',[selected('a')],{directory:true}],['duplicate names',[selected('a'),selected('a')],{}],
 ['traversal prefix',[selected('a')],{prefix:'../bad'}],['trailing slash prefix',[selected('a')],{prefix:'bad/'}],
 ['unknown option',[selected('a')],{strip:true}],['surrogate name',[selected('\ud800')],{}],
 ['file name with slash',[selected('a/b')],{}]])
 test(`directory descriptor refuses ${name} before file reads`,()=>{assert.throws(()=>initialImportDescriptors(files,options));assert(files.every(f=>f.reads===0));});
test('real File objects preserve all byte values and empty files with correct read receiver',async()=>{
 const files=[new File([Uint8Array.from({length:256},(_,i)=>i)],'binary'),new File([],'empty')];
 const result=await importInitialFiles([],initialImportDescriptors(files));
 assert.deepEqual(result[0].bytes,Uint8Array.from({length:256},(_,i)=>i));assert.equal(result[1].bytes.length,0);
});
for(const failure of ['oversize','duplicate','overlap','count','aggregate','invalid-mode'])
 test(`batch preflights ${failure} before any upload read`,async()=>{
  const a=selected('a'),b=selected('b');let retained=[],rows=[input(a),input(b)];
  if(failure==='oversize')b.size=FILE_LIMIT+1;
  if(failure==='duplicate')rows[1].path_hex=rows[0].path_hex;
  if(failure==='overlap')rows[1].path_hex=hex(utf8.encode('a/child'));
  if(failure==='count')retained=Array.from({length:63},(_,i)=>file(`old${i}`,new Uint8Array()));
  if(failure==='aggregate'){retained=Array.from({length:4},(_,i)=>file(`old${i}`,new Uint8Array(FILE_LIMIT-1024)));b.size=8192;}
  if(failure==='invalid-mode')rows[1].mode=0o120000;
  await assert.rejects(importInitialFiles(retained,rows));assert.equal(a.reads+b.reads,0);
 });
test('late file failure leaves the caller queue untouched',async()=>{
 const retained=[file('old')],before=structuredClone(retained),a=selected('a'),b=selected('b');b.arrayBuffer=async()=>{throw Error('disk read refused');};
 await assert.rejects(importInitialFiles(retained,[input(a),input(b)]),/disk/);assert.deepEqual(retained,before);assert.equal(a.reads,1);
});
test('batch captures descriptors and retained bytes before the first read',async()=>{
 const retained=[file('old')],a=selected('a'),b=selected('b');const rows=[input(a),input(b)];
 a.arrayBuffer=async()=>{rows[1].path_hex='ff';rows[1].mode=0o100755;b.arrayBuffer=()=>{throw Error('new reader');};retained[0].bytes.fill(7);return new Uint8Array([0,255]).buffer;};
 const result=await importInitialFiles(retained,rows);assert.equal(result[1].path_hex,hex(utf8.encode('b')));assert.equal(result[1].mode,0o100644);assert.deepEqual(result[2].bytes,new Uint8Array([0,255,13,10]));
});
test('cancel after one read prevents the next and cannot return a partial queue',async()=>{
 let live=true;const a=selected('a'),b=selected('b');a.arrayBuffer=async()=>{live=false;return new Uint8Array([0,255]).buffer;};
 await assert.rejects(importInitialFiles([],[input(a),input(b)],()=>{if(!live)throw Error('cancelled');}),/cancelled/);assert.equal(b.reads,0);
});
test('truncated uploads refuse even when the received prefix fits its byte budget',async()=>{
 const a=selected('a');a.size++;await assert.rejects(importInitialFiles([],[input(a)]),/length changed/);
});
test('encoded patch overflow after complete reads leaves the retained queue unchanged',async()=>{
 const selectedFiles=Array.from({length:4},(_,i)=>selected(String(i),new Uint8Array(FILE_LIMIT-1)));
 await assert.rejects(importInitialFiles([],selectedFiles.map(input)),/Encoded patch/);assert(selectedFiles.every(f=>f.reads===1));
});
test('incoming size and read method getters are captured once before asynchronous work',async()=>{
 let sizes=0,methods=0;
 const f={get size(){assert.equal(++sizes,1);return 2;},get arrayBuffer(){assert.equal(++methods,1);return async()=>new Uint8Array([0,255]).buffer;}};
 const result=await importInitialFiles([],[{path_hex:'61',mode:0o100644,file:f}]);
 assert.deepEqual(result[0].bytes,new Uint8Array([0,255]));assert.equal(sizes,1);assert.equal(methods,1);
});
