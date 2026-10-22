import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { compileSourceRefactoring as compile, compileSourceReplacements, REFACTOR_PROFILE, REPLACEMENT_LIMITS }
  from '../../scripts/operator/source_edit_replacements.mjs';

const bytes = value => typeof value === 'string' ? Buffer.from(value) : Buffer.from(value);
const hex = name => bytes(name).toString('hex');
const oid = (format, value) => createHash(format).update(`blob ${value.length}\0`).update(value).digest('hex');
function change(format, from, before, to, after = before, oldMode = 0o100644, newMode = oldMode) {
  return { path_hex: hex(from), ...(to === undefined ? {} : { destination_hex: hex(to) }),
    before: before === null ? null : { bytes: bytes(before), blob: oid(format, bytes(before)), mode: oldMode },
    after: after === null ? null : { bytes: bytes(after), mode: newMode } };
}
const refuses = (fn, code) => assert.throws(fn, error => error.code === code);
for (const format of ['sha1', 'sha256']) {
  test(`${format}: explicit unchanged move emits full identities and two independently sorted effects`, () => {
    const row = change(format, 'z/from', 'exact\n', 'a/to');
    const result = compile(format, [row]);
    assert.equal(result.profile, REFACTOR_PROFILE);
    assert.equal(result.native_patch_profile, 'exact-tree-v1');
    assert.equal(result.move_count, 1); assert.equal(result.file_sections, 1);
    assert.equal(result.source_membership_verified, false); assert.equal(result.destinations_absent_verified, false);
    assert.equal(result.publication_authorized, false);
    assert.equal(result.patch.toString(), `diff --git "a/z/from" "b/a/to"\nsimilarity index 100%\nrename from "z/from"\nrename to "a/to"\nindex ${row.before.blob}..${row.before.blob} 100644\n`);
    assert.deepEqual(result.changes, [
      { path_hex: hex('a/to'), before_blob: null, after_blob: row.before.blob, before_mode: null, after_mode: 0o100644 },
      { path_hex: hex('z/from'), before_blob: row.before.blob, after_blob: null, before_mode: 0o100644, after_mode: null },
    ]);
    assert.equal(result.records, 5);
  });
  test(`${format}: edited text moves retain executable modes, CRLF and missing terminal newline`, () => {
    const row = change(format, 'old', 'old\r\nlast', 'new', 'new\r\nlast!', 0o100644, 0o100755);
    const r = compile(format, [row]);
    assert.match(r.patch.toString(), /old mode 100644\nnew mode 100755\nrename from "old"\nrename to "new"\n/);
    assert.match(r.patch.toString(), /--- "a\/old"\n\+\+\+ "b\/new"\n@@ -1,2 \+1,2 @@\n/);
    assert.equal(r.patch.toString().split('\\ No newline at end of file\n').length, 3);
    assert.equal(r.source_bytes, row.before.bytes.length); assert.equal(r.result_bytes, row.after.bytes.length);
    assert.equal(r.changes.find(x => x.path_hex === hex('new')).after_blob, oid(format, row.after.bytes));
  });
  test(`${format}: pure NUL-containing moves need no compressed binary grammar`, () => {
    const row = change(format, 'old', Buffer.from([0, 255, 10, 13]), 'new', Buffer.from([0, 255, 10, 13]), 0o100644, 0o100755);
    const r = compile(format, [row]);
    assert.ok(!r.patch.includes(Buffer.from('GIT binary patch')));
    assert.ok(!r.patch.includes(Buffer.from('@@')));
    assert.equal(r.patch.toString().match(/rename /g).length, 2);
    for (const binary of ['literal', 'delta', 'delta-runs']) assert.equal(compile(format, [row], { binary }).binary_files, 0);
  });
  test(`${format}: edited binary moves refuse even with explicit binary options`, () => {
    const row = change(format, 'old', Buffer.from([0, 1]), 'new', Buffer.from([0, 2]));
    for (const options of [{}, { binary: 'literal' }, { binary: 'delta' }, { binary: 'delta-runs' }]) {
      refuses(() => compile(format, [row], options), 'source_refactor_binary_move_edit');
    }
    refuses(() => compile(format, [change(format, 'old', 'text', 'new', Buffer.from([0]))]), 'source_refactor_binary_move_edit');
  });
  test(`${format}: mixed moves, updates, additions and deletions share deterministic whole-batch bounds`, () => {
    const rows = [change(format, 'move', 'before\n', 'moved', 'after\n'),
      change(format, 'update', 'old\n', undefined, 'new\n'), change(format, 'add', null, undefined, 'create\n'),
      change(format, 'delete', 'remove\n', undefined, null)];
    const r = compile(format, rows);
    assert.deepEqual(compile(format, rows.slice().reverse()), r);
    assert.equal(r.changes.length, 5); assert.equal(r.file_sections, 4);
    assert.equal(r.source_bytes, Buffer.byteLength('before\nold\nremove\n'));
    assert.equal(r.result_bytes, Buffer.byteLength('after\nnew\ncreate\n'));
    for (const [key, exact] of [['maxPatchBytes', r.patch.length], ['maxRecords', r.records], ['maxSourceBytes', r.source_bytes], ['maxResultBytes', r.result_bytes]]) {
      assert.deepEqual(compile(format, rows, { [key]: exact }), r);
      assert.throws(() => compile(format, rows, { [key]: exact - 1 }));
    }
  });
  test(`${format}: both move endpoints reject duplicates, chains, swaps and original-coordinate overlaps`, () => {
    const a = change(format, 'a', 'x', 'b');
    for (const other of [change(format, 'b', 'x', 'c'), change(format, 'b', 'x', 'a'),
      change(format, 'c', 'x', 'b'), change(format, 'a', 'x', 'c'),
      change(format, 'b/child', 'x', undefined, 'y'), change(format, 'b', 'x', undefined, null),
      change(format, 'a/child', null, undefined, 'x')]) {
      refuses(() => compile(format, [a, other]), 'source_refactor_collision');
      refuses(() => compile(format, [other, a]), 'source_refactor_collision');
    }
    for (const [from, to] of [['a', 'a/child'], ['a/child', 'a']]) {
      refuses(() => compile(format, [change(format, from, 'x', to)]), 'source_refactor_collision');
    }
    assert.equal(compile(format, [a, change(format, 'aa', 'x', 'bb')]).move_count, 2);
  });
  test(`${format}: late invalid preimages, unknown fields and impossible moves produce no partial result`, () => {
    const a = change(format, 'a', 'x', 'b'), bad = change(format, 'c', 'x', 'd');
    bad.before.blob = '1'.repeat(format === 'sha1' ? 40 : 64);
    refuses(() => compile(format, [a, bad]), 'source_replacement_preimage');
    refuses(() => compile(format, [{ ...a, surprise: true }]), 'source_edit_fields');
    for (const bad of [change(format, 'a', 'x', 'a'), change(format, 'a', null, 'b', 'x'), change(format, 'a', 'x', 'b', null)]) {
      refuses(() => compile(format, [bad]), 'source_refactor_move');
    }
    refuses(() => compileSourceReplacements(format, [a]), 'source_edit_fields');
  });
  test(`${format}: raw filename bytes round-trip through explicit octal quotes`, () => {
    const from = Buffer.from([0xff, 32, 34, 92, 10, 13]), to = Buffer.from([0xfe, 9]);
    const r = compile(format, [change(format, from, 'x', to)]);
    assert.ok(r.patch.includes(Buffer.from('rename from "\\377\\040\\042\\134\\012\\015"\n')));
    assert.ok(r.patch.includes(Buffer.from('rename to "\\376\\011"\n')));
    assert.equal(r.changes.find(x => x.before_blob !== null).path_hex, from.toString('hex'));
  });
  test(`${format}: names, regular-file modes and exact hash domains fail closed`, () => {
    for (const name of ['', '/root', 'a//b', 'a/../b', '.git/config', 'a/.GIT/x', 'a\0b']) {
      refuses(() => compile(format, [change(format, 'old', 'x', name)]), 'source_replacement_path');
    }
    const bad = change(format, 'a', 'x', 'b'); bad.before.blob = oid(format === 'sha1' ? 'sha256' : 'sha1', bad.before.bytes);
    refuses(() => compile(format, [bad]), 'source_replacement_preimage');
    for (const mode of [0, 0o120000, 0o160000, '100644']) {
      const row = change(format, 'a', 'x', 'b'); row.after.mode = mode;
      refuses(() => compile(format, [row]), 'source_replacement_file');
    }
  });
  test(`${format}: empty files still move; unchanged same-path requests remain no-ops`, () => {
    const r = compile(format, [change(format, 'a', '', 'b')]);
    assert.equal(r.changes.length, 2); assert.ok(!r.patch.includes(Buffer.from('@@')));
    refuses(() => compile(format, [change(format, 'a', '', undefined)]), 'source_replacement_no_effect');
  });
  test(`${format}: shared binary allowance applies to ordinary edits beside a pure move`, () => {
    const before = Buffer.alloc(16384, 1); before[0] = 0;
    const after = Buffer.from(before); after[8192] = 2;
    const rows = [change(format, 'm', before, 'n'), change(format, 'binary', before, undefined, after)];
    refuses(() => compile(format, rows), 'source_replacement_binary');
    for (const binary of ['literal', 'delta', 'delta-runs']) {
      const r = compile(format, rows, { binary });
      assert.equal(r.binary_files, 1); assert.equal(r.move_count, 1);
      assert.equal(r.binary_profile, binary);
      if (binary !== 'literal') assert.equal(r.delta_members + r.literal_members, 2);
    }
  });
}
test('cancellation checkpoints stop before returning any compiled result', () => {
  const rows = [change('sha256', 'a', 'x\n'.repeat(10000), 'b', 'y\n'.repeat(10000))];
  for (const stop of [1, 2, 3, 10, 100]) {
    let calls = 0; const sentinel = new Error('stop');
    assert.throws(() => compile('sha256', rows, {}, () => { if (++calls >= stop) throw sentinel; }), e => e === sentinel);
    assert.equal(calls, stop);
  }
});
test('file, section, path-byte and aggregate ceilings stay bounded', () => {
  const row = change('sha256', 'a', Buffer.alloc(1048576), 'b');
  assert.equal(compile('sha256', [row]).source_bytes, 1048576);
  const large = change('sha256', 'a', Buffer.alloc(1048577), 'b');
  refuses(() => compile('sha256', [large]), 'source_replacement_file');
  const batch = Array.from({ length: 32 }, (_, i) => change('sha256', `a${i}`, '', `b${i}`));
  assert.equal(compile('sha256', batch).changes.length, 64);
  refuses(() => compile('sha256', [...batch, change('sha256', 'z', '', 'zz')]), 'source_replacement_changes');
  const many = Array.from({ length: 9 }, (_, i) => change('sha256', `a${i}`, row.before.bytes, `b${i}`));
  refuses(() => compile('sha256', many), 'source_replacement_bytes');
  const paths = Array.from({ length: 5 }, (_, i) => change('sha256', `${i}`.repeat(4096), '', `${i+5}`.repeat(4096)));
  refuses(() => compile('sha256', paths), 'source_replacement_paths');
  for (const key of Object.keys(REPLACEMENT_LIMITS)) assert.throws(() => compile('sha256', [row], { [key]: REPLACEMENT_LIMITS[key] + 1 }));
});
