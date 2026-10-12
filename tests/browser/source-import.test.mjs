import test from 'node:test';
import assert from 'node:assert/strict';
import { SourceEditClient, captureSourceImport, IMPORT_PAGE } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit.mjs';
import { FILE_LIMIT, PATCH_LIMIT, fullFilePatch } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
import { setup, entry, upload, pathHex, bytes, hex, token, href, crypto } from './source-import-fixtures.mjs';
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: overlay creates, updates and skips unchanged without deleting siblings`, async () => {
    const original = [entry('dir/a', new Uint8Array([0,255,10]), 0o100755), entry('dir/unchanged', ''), entry('untouched', 'keep')];
    const { f, c } = await setup(original, algorithm);
    const files = [upload('a', new Uint8Array([0,1,255]), 'project/dir/a'), upload('unchanged', '', 'project/dir/unchanged'), upload('new', 'new', 'project/fresh/new')];
    const result = await c.importFiles(files, { directory: true });
    assert.equal(result.created, 1); assert.equal(result.updated, 1); assert.deepEqual(result.unchanged, [pathHex('dir/unchanged')]);
    assert.equal(result.edits.length, 2); assert.equal(result.edits[0].before.mode, 0o100755); assert.equal(result.edits[0].after.mode, 0o100755);
    assert.deepEqual(result.edits[0].after.bytes, new Uint8Array([0,1,255]));
    assert(!result.edits.some(e => e.path_hex === pathHex('untouched') || e.after === null));
    assert(files.every(f => f.reads === 1)); assert.equal(c.candidate, null); assert.equal(c.pending, null);
    for (const call of f.calls) { assert(['source/tree', 'source/blob'].includes(call.endpoint)); assert.equal(call.command.get('expected_head'), f.common.snapshot_token); assert.equal(call.command.get('expected_commit'), f.commit); }
    assert.equal(f.calls.filter(x => x.endpoint === 'source/tree').length, 2);
  });
  test(`${algorithm}: mode policy preserves old modes but applies explicit replacements`, async () => {
    const { c } = await setup([entry('x', '', 0o100755)], algorithm);
    const same = await c.importFiles([upload('x', '')]); assert.equal(same.edits.length, 0); assert.equal(same.unchanged.length, 1);
    const mode = await c.importFiles([upload('x', '')], { mode: '100644' }); assert.equal(mode.updated, 1); assert.equal(mode.edits[0].after.mode, 0o100644);
    const fresh = await c.importFiles([upload('y', '')], { mode: '100755' }); assert.equal(fresh.created, 1); assert.equal(fresh.edits[0].after.mode, 0o100755);
  });
  test(`${algorithm}: paginate and verify virtual-slash ordering before absent creation`, async () => {
    const originals = Array.from({length: IMPORT_PAGE}, (_, i) => entry(`a${String(i).padStart(3,'0')}`, ''));
    originals.push(entry('dir/x'), entry('dir.c'), entry('dir0'), { ...entry(), path_hex: 'ff', bytes: bytes('raw') });
    const { f, c } = await setup(originals, algorithm);
    const r = await c.importFiles([upload('missing', '')]); assert.equal(r.created, 1); assert.equal(r.scannedPages, 2);
    assert.equal(f.calls[1].command.get('after_hex'), f.calls[0] ? pathHex('a063') : '');
    assert.equal(f.calls.filter(c => c.endpoint === 'source/blob').length, 0);
  });
  test(`${algorithm}: a fully populated page needs its empty terminal page`, async () => {
    const {f,c} = await setup(Array.from({length: IMPORT_PAGE}, (_, i) => entry(`x${i.toString().padStart(3,'0')}`, '')), algorithm);
    const r = await c.importFiles([upload('new', '')]); assert.equal(r.scannedPages, 2); assert.equal(r.created, 1);
  });
}
for (const [name, selected, options, retained] of [
  ['empty selection', [], {}, []], ['too many files', {length:65}, {}, []],
  ['oversize', [{...upload('x'),size:FILE_LIMIT+1}], {}, []],
  ['duplicate', [upload('x'),upload('x')], {}, []],
  ['traversal', [upload('x','', 'p/../x')], {directory:true}, []],
  ['git metadata', [upload('config','', 'p/.GiT/config')], {directory:true}, []],
  ['different roots', [upload('a','', 'p/a'),upload('b','', 'q/b')], {directory:true}, []],
  ['mismatched basename', [upload('x','', 'p/y')], {directory:true}, []],
  ['file overlap', [upload('a','', 'p/a'),upload('b','', 'p/a/b')], {directory:true}, []],
  ['invalid prefix', [upload('x')], {prefixHex:pathHex('../x')}, []],
  ['invalid mode', [upload('x')], {mode:'120000'}, []],
  ['unknown option', [upload('x')], {force:true}, []],
  ['queued collision', [upload('x')], {}, [{path_hex:pathHex('x'),before:null,after:{bytes:bytes('old'),mode:0o100644}}]],
]) test(`${name}: preflight refuses without reading network or local bytes`, async () => {
  const {f,c} = await setup(); await assert.rejects(c.importFiles(selected,options,retained));
  assert.equal(f.calls.length,0); if(Array.isArray(selected)) assert(selected.every(f=>f.reads===0)); assert.equal(c.pending,null);
});
for (const mode of [0o120000,0o160000]) test(`refuse existing special mode ${mode.toString(8)} and its descendants`, async()=>{
  const {f,c} = await setup([entry('link','target',mode)]);
  for(const [file,options] of [[upload('link'),{}],[upload('child','', 'p/link/child'),{directory:true}]]) {
    await assert.rejects(c.importFiles([file],options),/directory|symlink|gitlink/);assert.equal(file.reads,0);
  }
  assert(!f.calls.some(x=>x.endpoint==='source/blob'));
});
test('an existing directory cannot be overwritten by a local regular file',async()=>{
 const {c}=await setup([entry('dir/a')]), file=upload('dir');await assert.rejects(c.importFiles([file]),/directory/);assert.equal(file.reads,0);
});
for(const [name, corrupt] of [
 ['omission',r=>{r.entries=[];r.next_after_hex=null;}],['substitution',r=>{r.entries[0].object_id='a'.repeat(40);} ],
 ['mode replacement',r=>{r.entries[0].kind='executable';}],['invented extra file',r=>{r.entries.push({...r.entries[0],name_hex:pathHex('z')});}],
 ['wrong tree',r=>{r.object_id='a'.repeat(40);}],['wrong scope',r=>{r.repository_incarnation='other';}],
 ['snapshot mismatch',r=>{r.snapshot_token=`alg:2:${'a'.repeat(64)}`;}],['history mismatch',r=>{r.source_rcr='different';}],
 ['cursor mismatch',r=>{r.after_hex='ff';}],['malformed continuation',r=>{r.next_after_hex='ff';}],
 ['wrong path',r=>{r.path_hex='ff';}],['unsorted children',r=>{r.entries.reverse();}],
 ['write claim',r=>{r.published=true;}],['noncanonical name',r=>{r.entries[0].name_hex='FF';}],
])test(`${name}: directory evidence cannot silently become absence`,async()=>{
 const {f,c}=await setup([entry('a'),entry('b')]);f.config.tree=corrupt;const file=upload('new');
 await assert.rejects(c.importFiles([file]));assert.equal(file.reads,0);assert.equal(c.candidate,null);assert.equal(c.pending,null);
});
for(const status of [401,403,404,409,500])test(`HTTP ${status} never means create an absent file`,async()=>{
 const {f,c}=await setup();f.config.status=status;const file=upload('file.txt');await assert.rejects(c.importFiles([file]));assert.equal(file.reads,0);
});
for(const [name,corrupt]of[
 ['wrong blob',r=>{r.object_id='a'.repeat(40);}],['changed bytes',r=>{r.content_hex='000000';r.returned_bytes=3;r.total_bytes=3;}],
 ['truncated blob',r=>{r.next_offset=1;}],['wrong mode',r=>{r.kind='executable';}],['wrong rcr',r=>{r.source_rcr='other';}],
])test(`${name}: reject an inconsistent existing file before local file reads`,async()=>{
 const {f,c}=await setup();f.config.blob=corrupt;const file=upload('file.txt');await assert.rejects(c.importFiles([file]));assert.equal(file.reads,0);
});
test('old and new bytes share one budget before local file reads',async()=>{
 const originals=Array.from({length:3},(_,i)=>entry(`x${i}`,new Uint8Array(FILE_LIMIT))),{c}=await setup(originals);
 const files=originals.map((_,i)=>upload(`x${i}`,new Uint8Array(FILE_LIMIT)));
 await assert.rejects(c.importFiles(files),/combined.*budget/);assert(files.every(f=>f.reads===0));
});
test('all local descriptors captured and retained bytes copied before awaits',async()=>{
 const {f,c}=await setup([entry('keep')]), files=[upload('x','original')], retained=[{path_hex:pathHex('queued'),before:null,after:{mode:0o100644,bytes:bytes('retained')}}];
 let release,entered;const ready=new Promise(r=>entered=r);f.config.wait=()=>new Promise(r=>{release=r;entered();});
 const work=c.importFiles(files,{},retained);await ready;files[0]=upload('other','changed');retained[0].after.bytes.fill(0);f.config.wait=null;release();
 const result=await work;assert.deepEqual(result.edits.find(x=>x.path_hex===pathHex('x')).after.bytes,bytes('original'));
 assert.deepEqual(result.edits.find(x=>x.path_hex===pathHex('queued')).after.bytes,bytes('retained'));
});
for(const action of ['disconnect','invalidateCandidate'])test(`cancellation by ${action} drains late file reads without partial result`,async()=>{
 const {c}=await setup([]),a=upload('a','first'),b=upload('b','next');let release,entered;const ready=new Promise(r=>entered=r);
 a.arrayBuffer=()=>new Promise(r=>{release=r;entered();});const work=c.importFiles([a,b]);await ready;c[action]();release(bytes('first').buffer);
 await assert.rejects(work,/cancelled/);assert.equal(b.reads,0);assert.equal(c.candidate,null);assert.equal(c.pending,null);
});
test('whole import deadline covers local file reads and prevents subsequent reads',async()=>{
 const {c}=await setup([], 'sha1',{importTimeoutMs:10}),a=upload('a',''),b=upload('b','');
 a.arrayBuffer=async()=>{await new Promise(r=>setTimeout(r,30));return new ArrayBuffer(0);};
 await assert.rejects(c.importFiles([a,b]),/deadline/);assert.equal(b.reads,0);assert.equal(c.busy,false);
});
for(const failure of ['throws','short','oversize'])test(`a later file ${failure} cannot return a successful prefix`,async()=>{
 const {c}=await setup([]),a=upload('a','a'),b=upload('b','b');b.arrayBuffer=async()=>{
  if(failure==='throws')throw new Error('local failure');return new ArrayBuffer(failure==='short'?0:2);
 };await assert.rejects(c.importFiles([a,b]));assert.equal(c.candidate,null);assert.equal(c.pending,null);
});
test('encoded patch budget applies after file reads without publishing a prefix',async()=>{
 const {c}=await setup([]); // Each file is bounded, but the combined line count is not.
 const files=[upload('a',new Uint8Array(200_000).fill(10)),upload('b',new Uint8Array(200_000).fill(10))];
 await assert.rejects(c.importFiles(files),/line budget/);assert.equal(c.pending,null);
});
test('batch is deterministic under local file reordering and a raw-byte prefix',async()=>{
 const {c}=await setup([]),files=[upload('b','B'),upload('a','A')];
 const a=await c.importFiles(files,{prefixHex:'ff'}),b=await c.importFiles([...files].reverse(),{prefixHex:'ff'});
 assert.deepEqual(a.edits,b.edits);assert.deepEqual(fullFilePatch(a.edits,{allowBinary:true}).bytes,fullFilePatch(b.edits,{allowBinary:true}).bytes);
});
test('bounded directory pagination cannot become a partial absence result',async()=>{
 const {f,c}=await setup(Array.from({length:IMPORT_PAGE*129},(_,i)=>entry(`x${i.toString().padStart(5,'0')}`,''))),file=upload('new');
 await assert.rejects(c.importFiles([file]),/page budget/);assert.equal(file.reads,0);assert.equal(f.calls.length,128);
});
test('directory inventory byte ceiling refuses before local reads',async()=>{
 const originals=Array.from({length:520},(_,i)=>entry(`${i.toString().padStart(4,'0')}${'x'.repeat(4000)}`,''));
 const {c}=await setup(originals),file=upload('new');await assert.rejects(c.importFiles([file]),/inventory.*byte budget/);assert.equal(file.reads,0);
});
test('cancelled inventory cannot continue into blob or local reads',async()=>{
 const {f,c}=await setup(),file=upload('file.txt');let release,entered;const ready=new Promise(r=>entered=r);
 f.config.wait=()=>new Promise(r=>{release=r;entered();});const work=c.importFiles([file]);await ready;c.invalidateCandidate();release();
 await assert.rejects(work,e=>e.name==='AbortError');assert.equal(file.reads,0);assert.equal(f.calls.length,1);
});
test('returned data cannot alter the selected branch snapshot or a later import',async()=>{
 const {f,c}=await setup(),file=upload('new');const r=await c.importFiles([file]);r.selection.fields.expected_commit='a'.repeat(40);r.edits[0].after.bytes.fill(0);
 assert.equal(c.selection.fields.expected_commit,f.commit);const again=await c.importFiles([file]);assert.deepEqual(again.edits[0].after.bytes,bytes('new\n'));
});
test('a pending original publication blocks import without replacing its key',async()=>{
 const {fixture,metadata}=await import('./source-edit-fixtures.mjs');const f=await fixture();
 const c=new SourceEditClient({href,cryptoImpl:crypto,fetchImpl:f.fetchImpl});await c.connect(token);await c.select(f.fields.ref,'sha1');
 await c.prepareEdits(f.patch.edits,metadata);await c.stageApply();const key=c.pending.key,calls=f.calls.length,file=upload('x');
 await assert.rejects(c.importFiles([file]),/saved publication/);assert.equal(c.pending.key,key);assert.equal(file.reads,0);assert.equal(f.calls.length,calls);
});
