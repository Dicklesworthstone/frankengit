import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, stat, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { buildSourceChanges, CHANGE_LIMITS, CHANGES_SCHEMA, sha256 } from '../operator/source_changes.mjs';
import { changeFixture, intent, replace, hexPath, objectId } from './source_changes_fixture.mjs';
const clone = structuredClone;
const draft = (f, changes, options) => buildSourceChanges(f.bytes, f.expected, intent(changes), options);
const code = expected => error => error.code === expected;
const once = (path, before, after) => ({ path_hex: hexPath(path), operation: 'replace-once', before_utf8: before, after_utf8: after });

for (const format of ['sha1', 'sha256']) {
  test(`${format}: replacement, mode, deletion and explicit no-op have exact effects`, async () => {
    const f = changeFixture(format), changes = [replace('src/main.rs', 'fn main() { new(); }\n'),
      { path_hex: hexPath('run.sh'), operation: 'mode', executable: false }, replace('empty.txt', '')];
    const result = await draft(f, changes), m = result.manifest;
    assert.equal(m.source_commit, f.commit); assert.equal(m.root_tree, f.tree);
    assert.equal(m.patch_sha256, sha256(result.bytes)); assert.equal(m.patch_bytes, result.bytes.length);
    assert.deepEqual(m.no_op_paths_hex, [hexPath('empty.txt')]);
    assert.deepEqual(m.effects.map(e => [e.path_hex, e.old_mode, e.new_mode, e.hunks]),
      [[hexPath('run.sh'), 0o100755, 0o100644, 0], [hexPath('src/main.rs'), 0o100644, 0o100644, 1]]);
    assert.equal(m.effects[1].new_blob, objectId('blob', Buffer.from('fn main() { new(); }\n'), format));
    assert.equal(m.authority_verified, false); assert.equal(m.native_patch_applied, false);
    assert.equal(m.publication_authorized, false); assert.equal(m.source_material_untrusted, true);
    const deleted = await draft(f, [{ path_hex: hexPath('empty.txt'), operation: 'delete' }]);
    assert.equal(deleted.manifest.effects[0].new_blob, null); assert.equal(deleted.manifest.effects[0].new_mode, null);
  });
  test(`${format}: disjoint splices use original byte offsets and preserve CRLF / missing LF`, async () => {
    const f = changeFixture(format, [{ path: 'a', bytes: 'abc\r\nxyz' }]);
    const result = await draft(f, [{ path_hex: '61', operation: 'splice', splices: [
      { byte_offset: 0, before_utf8: 'a', after_utf8: 'START' },
      { byte_offset: 5, before_hex: '78797a', after_utf8: 'END' },
      { byte_offset: 8, before_utf8: '', after_utf8: '!' },
    ] }]);
    assert.equal(result.manifest.effects[0].new_blob, objectId('blob', Buffer.from('STARTbc\r\nEND!'), format));
    assert.match(result.bytes.toString(), /\\ No newline at end of file/);
  });
  test(`${format}: replace-once is exact, UTF-8 byte based and not a regexp`, async () => {
    const f = changeFixture(format, [{ path: 'a', bytes: '\uFEFFα[old].*\r\nrest' }]);
    const result = await draft(f, [once('a', '[old].*', 'β')]);
    assert.equal(result.manifest.effects[0].new_blob, objectId('blob', Buffer.from('\uFEFFαβ\r\nrest'), format));
  });
  test(`${format}: complete unchanged package dependencies reject corrupt objects and forged modes`, async () => {
    const f = changeFixture(format);
    for (const mutate of [v => { v.membership.commit.bodyHex += '00'; }, v => { v.membership.trees[0].bodyHex += '00'; },
      v => { v.blobs[0].bytesHex += 'ff'; }, v => { v.membership.files[0].kind = 'executable'; },
      v => { v.blobs.pop(); }, v => { v.membership.files.pop(); }]) {
      const value = clone(f.value); mutate(value);
      await assert.rejects(buildSourceChanges(Buffer.from(JSON.stringify(value)), f.expected, intent([replace('run.sh', 'x')])));
    }
    assert.ok((await draft(f, [replace('run.sh', 'x')])).bytes.length > 0);
  });
  test(`${format}: independent expectations cannot be replaced by package assertions`, async () => {
    const f = changeFixture(format);
    for (const mutate of [e => { e.commit = 'f'.repeat(format === 'sha1' ? 40 : 64); },
      e => { e.files[0].blob = 'e'.repeat(format === 'sha1' ? 40 : 64); }, e => { e.files.pop(); }]) {
      const expected = clone(f.expected); mutate(expected);
      await assert.rejects(buildSourceChanges(f.bytes, expected, intent([replace('run.sh', 'x')])));
    }
    assert.ok((await draft(f, [replace('run.sh', 'x')])).manifest.before_bytes_verified);
  });
  test(`${format}: request permutation and equivalent UTF-8/hex spellings produce identical draft bytes`, async () => {
    const f = changeFixture(format), a = [replace('run.sh', 'changed\n'), replace('empty.txt', 'one')];
    const first = await draft(f, a), b = [...a].reverse().map(row => {
      const { content_utf8, ...rest } = row; return { ...rest, content_hex: Buffer.from(content_utf8).toString('hex') };
    });
    assert.deepEqual(await draft(f, b), first); assert.deepEqual(await draft(f, a), first);
  });
  test(`${format}: caller mutation after invocation cannot change verified bytes, pins or edits`, async () => {
    const f = changeFixture(format), input = intent([once('src/main.rs', 'old', 'new')]);
    const expected = clone(f.expected), bytes = Buffer.from(f.bytes), pending = buildSourceChanges(bytes, expected, input);
    bytes.fill(0); expected.commit = 'f'.repeat(40); expected.files.length = 0; input.changes[0].after_utf8 = 'evil';
    const result = await pending;
    assert.equal(result.manifest.package_sha256, sha256(f.bytes));
    assert.equal(result.manifest.effects[0].new_blob, objectId('blob', Buffer.from('fn main() { new(); }\n'), format));
  });
  test(`${format}: generated patches apply with installed Git to the exact independently expected whole tree`, async () => {
    // Installed Git is a non-production oracle, not the pinned conformance lane.
    const raw = Buffer.from([0x7a, 0xff, 0x22, 0x5c, 0x0a]);
    const input = [{ path: 'a', bytes: 'one\r\ntwo', mode: 0o100644 }, { path: raw, bytes: Buffer.from([255, 10, 128]), mode: 0o100644 },
      { path: 'dir/script', bytes: '#!/bin/sh\nold\n', mode: 0o100755 }, { path: 'empty', bytes: '', mode: 0o100644 },
      { path: 'unchanged', bytes: 'preserve me\n', mode: 0o100644 }];
    const f = changeFixture(format, input), output = await draft(f, [once('a', 'two', 'THREE'),
      { path_hex: raw.toString('hex'), operation: 'replace', content_hex: 'fe0a81' },
      { path_hex: hexPath('dir/script'), operation: 'mode', executable: false }, { path_hex: hexPath('empty'), operation: 'delete' }]);
    const root = await mkdtemp(join(tmpdir(), 'fg-changes-oracle-'));
    const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_COUNT: '0', LC_ALL: 'C', GIT_OPTIONAL_LOCKS: '0' };
    const git = (...args) => execFileSync('git', ['-C', root, ...args], { env, timeout: 15000 });
    try {
      git('init', '--quiet', `--object-format=${format}`);
      for (const file of f.files) {
        const full = Buffer.concat([Buffer.from(root + '/'), file.path]), slash = full.lastIndexOf(47);
        await mkdir(full.subarray(0, slash), { recursive: true }); await writeFile(full, file.bytes); await chmod(full, file.mode & 0o777);
      }
      git('add', '--all'); assert.equal(git('write-tree').toString().trim(), f.tree);
      execFileSync('git', ['-C', root, 'apply', '--index', '--whitespace=nowarn', '-'], { env, input: output.bytes, timeout: 15000 });
      const final = changeFixture(format, [
        { ...input[0], bytes: 'one\r\nTHREE' }, { ...input[1], bytes: Buffer.from([254, 10, 129]) },
        { ...input[2], mode: 0o100644 }, input[4],
      ]);
      assert.equal(git('write-tree').toString().trim(), final.tree);
      for (const file of final.files) {
        const full = Buffer.concat([Buffer.from(root + '/'), file.path]); assert.deepEqual(await readFile(full), file.bytes);
        assert.equal((await stat(full)).mode & 0o111, file.mode & 0o111);
      }
      await assert.rejects(stat(join(root, 'empty')), { code: 'ENOENT' });
    } finally { await rm(root, { recursive: true, force: true }); }
  });
}

test('ambiguous including overlapping matches and missing matches are refused beside a permitted twin', async () => {
  for (const [bytes, before, error] of [['aaa', 'aa', 'source_changes_match_ambiguous'], ['xx xx', 'xx', 'source_changes_match_ambiguous'],
    ['abc', 'xyz', 'source_changes_match_missing'], ['abc', '', 'source_changes_empty_match']]) {
    const f = changeFixture('sha1', [{ path: 'a', bytes }]);
    await assert.rejects(draft(f, [once('a', before, 'new')]), code(error));
    assert.ok((await draft(f, [once('a', bytes, 'new')])).bytes.length);
  }
});
test('no new paths, duplicate changes, unsafe paths or silent all-no-op results', async () => {
  const f = changeFixture();
  await assert.rejects(draft(f, [replace('missing', 'x')]), code('source_changes_unselected_path'));
  await assert.rejects(draft(f, [replace('run.sh', 'x'), replace('run.sh', 'y')]), code('source_changes_paths'));
  for (const path of ['../a', '/a', '.git/config', 'a//b', 'a/..', 'a\0']) await assert.rejects(draft(f, [replace(path, 'x')]));
  await assert.rejects(draft(f, [replace('empty.txt', '')]), code('source_changes_no_effect'));
  assert.ok((await draft(f, [replace('empty.txt', 'x')])).bytes.length);
});
test('original-byte preconditions, extent and overlap checks fail closed', async () => {
  const f = changeFixture('sha1', [{ path: 'a', bytes: 'abcdef' }]);
  const splice = splices => [{ path_hex: '61', operation: 'splice', splices }];
  const row = (byte_offset, before_utf8, after_utf8 = 'X') => ({ byte_offset, before_utf8, after_utf8 });
  for (const [parts, error] of [[[row(0, 'z')], 'source_changes_preimage'], [[row(6, 'a')], 'source_changes_extent'],
    [[row(7, '')], 'source_changes_extent'], [[row(0, 'ab'), row(1, 'b')], 'source_changes_overlap'],
    [[row(1, ''), row(1, '')], 'source_changes_overlap'], [[row(2, 'c'), row(0, 'a')], 'source_changes_overlap']]) {
    await assert.rejects(draft(f, splice(parts)), code(error));
  }
  assert.ok((await draft(f, splice([row(0, 'a'), row(1, 'b')]))).bytes.length);
});
test('closed change schema, encoding and modes refuse ambiguous or unsupported input', async () => {
  const f = changeFixture(), good = replace('run.sh', 'x');
  for (const row of [{ ...good, content_hex: '78' }, { ...good, force: true }, { ...good, executable: 1 },
    { ...good, content_utf8: '\ud800' }, { ...good, operation: 'rename' }, { path_hex: '61', operation: 'mode' },
    { path_hex: '61', operation: 'delete', executable: false }, { path_hex: '61', operation: 'replace', content_hex: '0' }]) {
    await assert.rejects(draft(f, [row]));
  }
  await assert.rejects(buildSourceChanges(f.bytes, f.expected, { schema: CHANGES_SCHEMA, changes: [good], extra: true }));
  assert.ok((await draft(f, [good])).bytes.length);
});
test('NUL-containing before and after images refuse without changing the shared encoder', async () => {
  const binary = changeFixture('sha1', [{ path: 'a', bytes: Buffer.from([0, 1]) }]), plain = changeFixture('sha1', [{ path: 'a', bytes: 'ok' }]);
  await assert.rejects(draft(binary, [replace('a', 'ok')]), code('source_changes_binary_unsupported'));
  await assert.rejects(draft(plain, [{ path_hex: '61', operation: 'replace', content_hex: '00' }]), code('source_changes_binary_unsupported'));
  assert.ok((await draft(plain, [replace('a', 'new')])).bytes.length);
});
test('exact and one-under file, retained-byte and patch-byte budgets', async () => {
  const f = changeFixture('sha1', [{ path: 'a', bytes: 'old' }]), edit = [replace('a', 'new')], full = await draft(f, edit);
  await draft(f, edit, { limits: { fileBytes: 3, totalBytes: 6, patchBytes: full.bytes.length } });
  await assert.rejects(draft(f, edit, { limits: { fileBytes: 2 } }));
  await assert.rejects(draft(f, edit, { limits: { totalBytes: 5 } }), code('source_changes_retained_budget'));
  await assert.rejects(draft(f, edit, { limits: { patchBytes: full.bytes.length - 1 } }), code('source_changes_patch_budget'));
  await assert.rejects(draft(f, edit, { limits: { patchBytes: CHANGE_LIMITS.patchBytes + 1 } }), code('source_changes_limit'));
});
test('file and splice inventories have aggregate rather than per-row allowances', async () => {
  const f = changeFixture(), rows = [replace('run.sh', 'new'), replace('empty.txt', 'new')];
  await draft(f, rows, { limits: { files: 2 } });
  await assert.rejects(draft(f, rows, { limits: { files: 1 } }), code('source_changes_inventory'));
  const changes = ['run.sh', 'empty.txt'].map(path => ({ path_hex: hexPath(path), operation: 'splice', splices: [{ byte_offset: 0, before_utf8: '', after_utf8: 'new' }] }));
  await draft(f, changes, { limits: { splices: 2 } });
  await assert.rejects(draft(f, changes, { limits: { splices: 1 } }), code('source_changes_splice_limit'));
});
test('a patch over the actual native 1 MiB input ceiling is refused locally', async () => {
  const f = changeFixture('sha1', [{ path: 'a', bytes: 'x'.repeat(600000) }]);
  await assert.rejects(draft(f, [replace('a', 'y'.repeat(600000))]), code('source_changes_patch_budget'));
  assert.ok((await draft(changeFixture('sha1', [{ path: 'a', bytes: 'x'.repeat(400000) }]), [replace('a', 'y'.repeat(400000))])).bytes.length < 1048576);
});
test('cancellation and deadline checks cover verification and patch generation with no partial result', async () => {
  const f = changeFixture(), c = new AbortController(); c.abort();
  await assert.rejects(draft(f, [replace('run.sh', 'x')], { signal: c.signal }));
  let checks = 0; await assert.rejects(draft(f, [replace('run.sh', 'x')], { check() { if (++checks === 10) throw new Error('deadline'); } }), /deadline/);
  const active = new AbortController(); checks = 0;
  await assert.rejects(draft(f, [replace('run.sh', 'x')], { signal: active.signal, check() { if (++checks === 10) active.abort(); } }));
  assert.ok((await draft(f, [replace('run.sh', 'x')])).bytes.length);
});
test('shared source memory, unknown limits and invalid lifecycle hosts refuse', async () => {
  const f = changeFixture(), shared = new Uint8Array(new SharedArrayBuffer(f.bytes.length)); shared.set(f.bytes);
  await assert.rejects(buildSourceChanges(shared, f.expected, intent([replace('run.sh', 'x')])), code('source_changes_package'));
  for (const options of [{ signal: {} }, { check: false }, { limits: { ignored: 1 } }, { limits: { files: 0 } }, { retry: true }]) {
    await assert.rejects(draft(f, [replace('run.sh', 'x')], options));
  }
});
