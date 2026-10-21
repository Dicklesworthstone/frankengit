import test from 'node:test';
import assert from 'node:assert/strict';
import { compileCompactSourceSplices, captureCompactSourceSplices, COMPACT_SPLICE_PROFILE, SPLICE_PATCH_PROFILES }
  from '../../scripts/operator/source_edit_compact_splices.mjs';
import { compileSourceSplices } from '../../scripts/operator/source_edit_splices.mjs';
import { buildPatch } from '../../crates/fgit-node/src/smart_http/server/browser/source-patch.mjs';
import { file, edit, oracle, acquisition, bytes, TOKEN, digest } from './source_edit_compact_splices_fixture.mjs';
const trim = { patchProfile: 'trim-common-lines-v1' }, multi = { patchProfile: 'bounded-line-hunks-v1' };

for (const format of ['sha1', 'sha256']) {
  for (const profile of SPLICE_PATCH_PROFILES) {
    test(`${format} ${profile}: exact byte edits retain newline, raw-path and mode semantics in both directions`, async () => {
      await oracle(format, [file('a\r\nb\r\nlast', [edit(3, 'b', 'BB'), edit(6, 'last', 'tail')], format, Buffer.from([255, 34, 92, 10]), 0o100644, 0o100755),
        file('', [edit(0, '', 'new\n')], format, 'empty'), file('abc', [edit(0, 'abc', '')], format, 'emptied'),
        file('same\n', [], format, 'mode', 0o100644, 0o100755),
        file(Buffer.from([255, 195, 169, 10]), [edit(1, [195, 169], [254])], format, 'raw')],
      ['a\r\nBB\r\ntail', 'new\n', '', 'same\n', Buffer.from([255, 254, 10])], { patchProfile: profile });
    });
    test(`${format} ${profile}: every unequal pair of six small line sequences applies and reverses`, async () => {
      const values = ['', 'a', 'a\n', '\n', 'b\r\n', 'a\nb'], files = [], wanted = [];
      for (const old of values) for (const next of values) if (old !== next) {
        files.push(file(old, [edit(0, old, next)], format, `f${files.length}`)); wanted.push(next);
      }
      await oracle(format, files, wanted, { patchProfile: profile });
    });
    test(`${format} ${profile}: a small edit to an 800 KiB file fits without a raised patch ceiling`, async () => {
      const old = bytes('abcdefghijklmno\n'.repeat(51200)), next = Buffer.from(old);
      next[400000] = 90;
      const files = [file(old, [edit(400000, [old[400000]], [90])], format)];
      assert.throws(() => compileSourceSplices(format, files), /patch_limit/);
      const result = await oracle(format, files, [next], { patchProfile: profile });
      assert.equal(result.profile, COMPACT_SPLICE_PROFILE); assert.equal(result.patch_profile, profile);
      assert.equal(result.hunks, 1); assert.ok(result.patch.length < 1024);
      assert.equal(result.source_bytes, old.length); assert.equal(result.result_bytes, next.length);
    });
  }
  test(`${format}: separated length-changing edits preserve two compact hunks and exact original coordinates`, async () => {
    const old = bytes(Array.from({ length: 50000 }, (_, i) => `line-${String(i).padStart(5,'0')}\n`).join(''));
    const a = 110, b = 440000, first = bytes('insert\nextra\n');
    const desired = Buffer.concat([old.subarray(0,a), first, old.subarray(a+11,b), bytes('tail\n'), old.subarray(b+11)]);
    const result = await oracle(format, [file(old, [edit(b, old.subarray(b,b+11), 'tail\n'), edit(a, old.subarray(a,a+11), first)], format)], [desired], multi);
    assert.equal(result.hunks, 2); assert.ok(result.patch.length < 1024);
  });
  test(`${format}: native prepare/inspect receipts preserve independent root and compiled compact bytes`, async t => {
    const f = await acquisition(t, format);
    const result = await captureCompactSourceSplices(f.selection, f.files, TOKEN, multi);
    assert.equal(result.candidate_commit, f.candidate); assert.deepEqual(result.bundle, f.bundle);
    assert.equal(result.capture.patch_sha256, digest(f.compiled.patch)); assert.equal(result.patch_profile, multi.patchProfile);
    assert.equal(result.splice_count, 1); assert.equal(result.publication_authorized, false);
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
    assert.ok(f.calls[0].body.includes(f.compiled.patch));
    assert.ok(f.calls.every(c => c.headers['idempotency-key'] === undefined));
  });
}

test('uses the exact shared production hunk encoder, not a substitute or different diff implementation', async () => {
  const old = bytes('a\nb\nc\nd\ne\nf\ng\nh\ni\n'), next = bytes('a\nX\nc\nd\ne\nf\ng\nY\ni\n');
  const files = [file(old, [edit(2, 'b', 'X'), edit(14, 'h', 'Y')])];
  const compiled = await compileCompactSourceSplices('sha1', files, multi);
  const direct = await buildPatch([{ path_hex: files[0].path_hex, before: { mode: 0o100644, bytes: old }, after: { mode: 0o100644, bytes: next } }], 'sha1', multi);
  assert.deepEqual(compiled.patch, Buffer.from(direct.bytes));
});
for (const options of [trim, multi]) test(`${options.patchProfile}: exact patch/record allowances succeed and one less refuses`, async () => {
  const files = [file('first\nold\nlast', [edit(6, 'old', 'new')])];
  const r = await compileCompactSourceSplices('sha1', files, options);
  assert.deepEqual((await compileCompactSourceSplices('sha1', files, { ...options, maxPatchBytes: r.patch.length, maxRecords: r.records })).patch,r.patch);
  await assert.rejects(compileCompactSourceSplices('sha1', files,{...options, maxPatchBytes:r.patch.length-1}),/patch_limit/);
  await assert.rejects(compileCompactSourceSplices('sha1', files,{...options, maxRecords:r.records-1}),/patch_limit/);
});
test('profile and limit grammar cannot opt out, widen, or choose binary alongside line encoding', async () => {
  const f=[file('old',[edit(0,'old','new')])];
  for (const options of [undefined, {}, {patchProfile:null},{patchProfile:'unknown'}, {...multi,binary:'literal'}, {...multi,binary:'delta'},
    {...multi,maxPatchBytes:1048577},{...multi,maxPatchBytes:null},{...multi,maxRecords:0},{...multi,maxSplices:0},{...multi,force:true}]) {
    await assert.rejects(compileCompactSourceSplices('sha1',f,options));
  }
  assert.ok((await compileCompactSourceSplices('sha1',f,multi)).patch.length);
});
test('text profile refuses NUL on either side while existing explicit binary compiler stays available', async () => {
  for (const f of [file('a\0b',[edit(0,'a','x')]),file('abc',[edit(0,'a',[0])])]) {
    await assert.rejects(compileCompactSourceSplices('sha1',[f],multi), /compact_binary/);
    assert.ok(compileSourceSplices('sha1',[f],{binary:'literal'}).patch.includes(bytes('GIT binary patch')));
  }
});
test('spans and full preimages must match even if the shared diff could construct a valid patch', async () => {
  const f=file('abc',[edit(1,'b','x')]);
  for (const mutate of [r=>r.before.bytes.fill(97),r=>r.edits[0].before.fill(97),r=>r.edits[0].byte_start=0,r=>r.edits.push(edit(1,'b','z'))]) {
    const broken=structuredClone(f);mutate(broken);await assert.rejects(compileCompactSourceSplices('sha1',[broken],multi));
  }
});
test('shared four-MiB source/result ceiling applies across files even when output would be tiny', async () => {
  const original=bytes('abcdefghijklmno\n'.repeat(65536));
  const a=file(original,[edit(128,[97],[90])],'sha1','a'),b={...a,path_hex:'62'},c={...a,path_hex:'63'};
  assert.ok((await compileCompactSourceSplices('sha1',[a,b],multi)).patch.length<2048);
  await assert.rejects(compileCompactSourceSplices('sha1',[a,b,c],multi),/compact_input_limit/);
});
test('bounded-line search exhaustion refuses rather than silently selecting a different representation', async () => {
  const before=bytes(Array.from({length:129},(_,i)=>`a${i}\n`).join('')), after=bytes(Array.from({length:129},(_,i)=>`b${i}\n`).join(''));
  const f=[file(before,[edit(0,before,after)])];
  await assert.rejects(compileCompactSourceSplices('sha1',f,multi),/distance_limit/);
  assert.ok((await compileCompactSourceSplices('sha1',f,trim)).patch.length>0);
});
test('original, ranges, modes and selected profile are owned before the first digest await', async () => {
  const f=[file('old\nkeep\n',[edit(0,'old','new')])],options={...multi};
  const wanted=await compileCompactSourceSplices('sha1',f,options), pending=compileCompactSourceSplices('sha1',f,options);
  f[0].before.bytes.fill(0);f[0].edits[0].after.fill(0);f[0].after_mode=0o120000;options.patchProfile='invalid';
  assert.deepEqual(await pending,wanted);
});
test('cancellation is observed during a real async line-encoder yield', async () => {
  const b=bytes('abcdefghijklmno\n'.repeat(51200)),f=[file(b,[edit(16000,[97],[90])])];
  const stop=new AbortController();
  const pending=compileCompactSourceSplices('sha1',f,multi,()=>stop.signal.throwIfAborted());
  setTimeout(()=>stop.abort(),0);
  await assert.rejects(pending,{name:'AbortError'});
  assert.ok((await compileCompactSourceSplices('sha1',f,multi)).patch.length<1024);
});
test('compile cancellation and invalid path/root/scope never open native requests', async t => {
  const f=await acquisition(t,'sha1');
  const stop=new AbortController();stop.abort();
  const missing={...f.selection};delete missing.expected_result_tree;
  for(const [selection,files,options] of [[missing,f.files,multi], [f.selection,f.files,{...multi,signal:stop.signal}],
    [{...f.selection,paths_hex:['7a']},f.files,multi],[f.selection,f.files,{...multi,binary:'delta'}]]) {
    await assert.rejects(captureCompactSourceSplices(selection,files,TOKEN,options));
  }
  assert.equal(f.calls.length,0);
});
test('one aggregate response allowance and wrong-root refusal cannot trigger retry or alternate encoding', async t => {
  const f=await acquisition(t,'sha1');
  const r=await captureCompactSourceSplices(f.selection,f.files,TOKEN,multi);
  await captureCompactSourceSplices(f.selection,f.files,TOKEN,{...multi,maxWireBytes:r.metrics.response_bytes});
  await assert.rejects(captureCompactSourceSplices(f.selection,f.files,TOKEN,{...multi,maxWireBytes:r.metrics.response_bytes-1}));
  assert.equal(f.calls.length,6);
  f.control.mutate=reply=>{reply.root_tree='f'.repeat(40);};
  await assert.rejects(captureCompactSourceSplices(f.selection,f.files,TOKEN,multi),/result_tree_mismatch/);
  assert.equal(f.calls.length,7);assert.equal(f.calls.at(-1).operation,'prepare');
});
test('compact acquisition retains caller source and options across hashing and transport awaits', async t => {
  const f=await acquisition(t,'sha256'),selection=structuredClone(f.selection),files=structuredClone(f.files),options={...multi};
  const p=captureCompactSourceSplices(selection,files,TOKEN,options);
  selection.expected_result_tree='f'.repeat(64);files[0].edits[0].after.fill(0);options.patchProfile='bad';
  assert.equal((await p).candidate_commit,f.candidate);
});
for (const format of ['sha1', 'sha256']) test(`${format}: structurally valid review cannot substitute the original executable mode`, async t => {
  const f=await acquisition(t,format);
  f.control.mutate=(reply,call)=>{if(call.operation==='inspect') {
    const row=reply.comparison.entries[0];row.before.mode=0o100755;row.kind='mode_changed';
  }};
  await assert.rejects(captureCompactSourceSplices(f.selection,f.files,TOKEN,multi),/effect_mismatch/);
  assert.deepEqual(f.calls.map(c=>c.operation),['prepare','inspect']);
});
test('compilation consumes the same operation deadline before native preparation', async t => {
  const f=await acquisition(t,'sha1');
  const old=bytes('abcdefghijklmno\n'.repeat(51200)),files=[file(old,[edit(400000,[97],[90])])];
  await assert.rejects(captureCompactSourceSplices(f.selection,files,TOKEN,{...multi,timeoutMs:1}),/timeout/);
  assert.equal(f.calls.length,0);
});
