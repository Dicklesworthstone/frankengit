import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { compileSourceRefactoring as compile, compileSourceReplacements, REFACTOR_PROFILE,
  BINARY_REFACTOR_PROFILE } from '../../scripts/operator/source_edit_replacements.mjs';
const hex = s => Buffer.from(s).toString('hex');
const oid = (fmt,b) => createHash(fmt).update(`blob ${b.length}\0`).update(b).digest('hex');
const row = (fmt, old, next, path='old', destination='new') => ({path_hex:hex(path),destination_hex:hex(destination),
  before:{mode:0o100644,blob:oid(fmt,old),bytes:old},after:{mode:0o100755,bytes:next}});
for (const format of ['sha1','sha256']) {
  test(`${format}: binary relocation requires both explicit native and encoding profiles`, () => {
    const r=row(format,Buffer.from('old\0'),Buffer.from('new\0'));
    for(const options of [{},{binary:'literal'},{nativeProfile:'exact-tree-binary-v1'},{nativeProfile:'exact-tree-v1',binary:'delta'}])
      assert.throws(()=>compile(format,[r],options),{code:'source_refactor_binary_move_edit'});
    for(const binary of ['literal','delta','delta-runs']) {
      const c=compile(format,[r],{nativeProfile:'exact-tree-binary-v1',binary});
      assert.equal(c.profile,BINARY_REFACTOR_PROFILE);assert.equal(c.native_patch_profile,'exact-tree-binary-v1');
      assert.equal(c.move_count,1);assert.equal(c.file_sections,1);assert.equal(c.changes.length,2);
      assert.equal(c.binary_files,1);assert.match(c.patch.toString(),/rename from "old"\nrename to "new"\n/);
      assert.equal(c.publication_authorized,false);assert.equal(c.source_membership_verified,false);
      assert.equal(c.destinations_absent_verified,false);
    }
    assert.throws(()=>compile(format,[r],{nativeProfile:'unknown',binary:'delta'}),{code:'source_refactor_native_profile'});
    assert.throws(()=>compile(format,[r],{nativeProfile:null,binary:'delta'}),{code:'source_refactor_native_profile'});
    assert.throws(()=>compileSourceReplacements(format,[r],{nativeProfile:'exact-tree-binary-v1'}));
  });
  test(`${format}: old text and unchanged binary move bytes are unchanged`, () => {
    for(const r of [row(format,Buffer.from('old\n'),Buffer.from('new\n')),row(format,Buffer.from('same\0'),Buffer.from('same\0'))]) {
      const old=compile(format,[r]);assert.equal(old.profile,REFACTOR_PROFILE);
      assert.deepEqual(compile(format,[r],{nativeProfile:'exact-tree-v1'}),old);
      assert.deepEqual(compile(format,[r],{nativeProfile:'exact-tree-binary-v1'}).patch,old.patch);
    }
  });
  test(`${format}: a one MiB edited move uses both bounded delta directions`, () => {
    const old=Buffer.alloc(1048576,65);old[0]=0;const next=Buffer.from(old);next[500000]=66;
    const r=row(format,old,next), options={nativeProfile:'exact-tree-binary-v1',binary:'delta'};
    const c=compile(format,[r],options);assert.equal(c.delta_members,2);assert.equal(c.literal_members,0);
    assert.ok(c.patch.length<512);assert.equal(c.source_bytes,old.length);assert.equal(c.result_bytes,next.length);
    assert.deepEqual(compile(format,[r],{...options,maxPatchBytes:c.patch.length}).patch,c.patch);
    assert.throws(()=>compile(format,[r],{...options,maxPatchBytes:c.patch.length-1}),{code:'source_replacement_patch_limit'});
    assert.throws(()=>compile(format,[r],{...options,binary:'literal'}),{code:'source_replacement_patch_limit'});
  });
  test(`${format}: full preimages, original endpoints, cancellation and no-op rules remain`, () => {
    const r=row(format,Buffer.from('old\0'),Buffer.from('new\0')), options={nativeProfile:'exact-tree-binary-v1',binary:'delta'};
    assert.throws(()=>compile(format,[{...r,before:{...r.before,blob:'f'.repeat(format==='sha1'?40:64)}}],options),{code:'source_replacement_preimage'});
    for(const destination of ['old','old/child'])assert.throws(()=>compile(format,[{...r,destination_hex:hex(destination)}],options));
    assert.throws(()=>compile(format,[r,row(format,Buffer.from('a\0'),Buffer.from('b\0'),'new','third')],options),{code:'source_refactor_collision'});
    let checkpoints=0;assert.throws(()=>compile(format,[r],options,()=>{if(++checkpoints===6)throw new Error('cancelled')}),/cancelled/);
    const c=compile(format,[r],options);assert.ok(c.patch.length);
    const ordinary={...r};delete ordinary.destination_hex;ordinary.after={mode:r.before.mode,bytes:r.before.bytes};
    assert.throws(()=>compile(format,[ordinary],options),{code:'source_replacement_no_effect'});
  });
}
