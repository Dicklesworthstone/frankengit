// Binary-safe source authoring uses the existing exact-hunk encoder and native
// object commitments. Installed Git is a test-only oracle, not a production
// dependency or evidence that a Rust fg server ran these requests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { buildSourceChanges, ownSourceChangeInputs, BINARY_CHANGE_PROFILE, canonical, sha256 } from '../operator/source_changes.mjs';
import { buildPatch, exactText, textBytes } from '../../crates/fgit-node/src/smart_http/server/browser/source-patch.mjs';
import { changeFixture, intent, hexPath, objectId } from './source_changes_fixture.mjs';

const binary = changes => ({ ...intent(changes), byte_profile: BINARY_CHANGE_PROFILE });
const code = value => error => error.code === value;
const replace = (path, bytes) => ({ path_hex: hexPath(path), operation: 'replace', content_hex: Buffer.from(bytes).toString('hex') });
const run = (f, changes, options) => buildSourceChanges(f.bytes, f.expected, binary(changes), options);

// Build the starting index from independently framed blobs, apply the ENTIRE
// patch with Git, then compare both native tree identity and every output byte.
async function gitOracle(fixture, draft, expectedFiles) {
  const root = await mkdtemp(join(tmpdir(), 'fg-binary-oracle-'));
  const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_COUNT: '0', LC_ALL: 'C', GIT_OPTIONAL_LOCKS: '0' };
  const git = (args, input) => execFileSync('git', ['-C', root, ...args], { env, input, timeout: 15000, maxBuffer: 8 * 1024 * 1024 });
  try {
    git(['init', '--quiet', `--object-format=${fixture.expected.format}`]);
    for (const file of fixture.files) {
      const blob = git(['hash-object', '-w', '--stdin'], file.bytes).toString().trim();
      assert.equal(blob, file.id);
      git(['update-index', '-z', '--index-info'], Buffer.concat([Buffer.from(`${file.mode.toString(8)} ${blob}\t`), file.path, Buffer.from([0])]));
    }
    assert.equal(git(['write-tree']).toString().trim(), fixture.tree);
    git(['apply', '--cached', '--binary', '--whitespace=nowarn', '-'], draft.bytes);
    const expected = changeFixture(fixture.expected.format, expectedFiles);
    assert.equal(git(['write-tree']).toString().trim(), expected.tree);
    assert.equal(draft.tree.afterTree, expected.tree);
    for (const file of expected.files) assert.deepEqual(git(['cat-file', 'blob', file.id]), file.bytes);
    return expected;
  } finally { await rm(root, { recursive: true, force: true }); }
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: binary replacements preserve all byte values, patch-looking content, CRLF and missing LF`, async () => {
    const rawPath = Buffer.from([0x62, 0xff, 0x22, 0x5c, 10]);
    const before = Buffer.concat([Buffer.from(Array.from({ length: 256 }, (_, i) => i)),
      Buffer.from('\n@@ -1,2 +1,2 @@\n--- a/f\n+++ b/f\ndiff --git a/x b/x\n\\ No newline at end of file\nlast\0')]);
    const after = Buffer.concat([Buffer.from('new\0\r\n'), Buffer.from(Array.from({ length: 256 }, (_, i) => 255 - i)), Buffer.from('tail\0')]);
    const f = changeFixture(format, [{ path: rawPath, bytes: before }, { path: 'untouched', bytes: 'keep' }]);
    const result = await run(f, [replace(rawPath, after)]);
    assert.equal(result.manifest.byte_profile, BINARY_CHANGE_PROFILE);
    assert.equal(result.manifest.effects[0].new_blob, objectId('blob', after, format));
    assert.equal(result.manifest.patch_sha256, sha256(result.bytes));
    assert.equal(result.manifest.native_patch_applied, false);
    assert.equal(result.manifest.publication_authorized, false);
    assert.ok(result.bytes.includes(0));
    await gitOracle(f, result, [{ path: rawPath, bytes: after }, { path: 'untouched', bytes: 'keep' }]);
    await assert.rejects(buildSourceChanges(f.bytes, f.expected, intent([replace(rawPath, after)])), code('source_changes_binary_unsupported'));
  });
  test(`${format}: binary creation, deletion, mode-only, copy and rename share one exact candidate tree`, async () => {
    const rows = [{ path: 'gone', bytes: Buffer.from([0, 255]) }, { path: 'move', bytes: Buffer.from([0, 10, 13, 255]), mode: 0o100755 },
      { path: 'copy', bytes: Buffer.from([1, 0, 2]) }, { path: 'mode', bytes: Buffer.from([0, 0]) }, { path: 'keep', bytes: 'unchanged' }];
    const f = changeFixture(format, rows), result = await run(f, [
      { path_hex: hexPath('new/empty'), operation: 'create', content_hex: '', executable: false },
      { path_hex: hexPath('new/bin'), operation: 'create', content_hex: '00ff', executable: true },
      { path_hex: hexPath('gone'), operation: 'delete' },
      { path_hex: hexPath('renamed/file'), from_path_hex: hexPath('move'), operation: 'rename' },
      { path_hex: hexPath('copied'), from_path_hex: hexPath('copy'), operation: 'copy', executable: true },
      { path_hex: hexPath('mode'), operation: 'mode', executable: true },
    ]);
    assert.equal(result.manifest.effects.length, 7);
    await gitOracle(f, result, [rows[2], rows[4], { ...rows[1], path: 'renamed/file' },
      { ...rows[2], path: 'copied', mode: 0o100755 }, { ...rows[3], mode: 0o100755 },
      { path: 'new/empty', bytes: '' }, { path: 'new/bin', bytes: Buffer.from([0, 255]), mode: 0o100755 }]);
    // Binary-safe is not an overwrite permission or an escape from membership.
    await assert.rejects(run(f, [{ path_hex: hexPath('keep'), operation: 'create', content_hex: '00', executable: false }]));
    await assert.rejects(run(f, [{ path_hex: hexPath('new'), from_path_hex: hexPath('missing'), operation: 'copy' }]), code('source_changes_unselected_path'));
  });
  test(`${format}: binary to empty, empty to binary, and deletion to empty root agree with Git`, async () => {
    for (const [before, after] of [[Buffer.from([0, 255]), Buffer.alloc(0)], [Buffer.alloc(0), Buffer.from([0])]]) {
      const f = changeFixture(format, [{ path: 'a', bytes: before }]), result = await run(f, [replace('a', after)]);
      await gitOracle(f, result, [{ path: 'a', bytes: after }]);
    }
    const f = changeFixture(format, [{ path: 'only/deep/file', bytes: Buffer.from([0]) }]);
    const result = await run(f, [{ path_hex: hexPath('only/deep/file'), operation: 'delete' }]);
    await gitOracle(f, result, []);
  });
  test(`${format}: binary splices address original bytes and replace-once counts overlapping NUL matches`, async () => {
    const f = changeFixture(format, [{ path: 'a', bytes: Buffer.from([0, 1, 2, 0, 3, 4, 255]) }]);
    const result = await run(f, [{ path_hex: '61', operation: 'splice', splices: [
      { byte_offset: 0, before_hex: '0001', after_hex: 'ff0000' },
      { byte_offset: 4, before_hex: '03', after_hex: '' },
      { byte_offset: 7, before_hex: '', after_hex: '00' },
    ] }]);
    await gitOracle(f, result, [{ path: 'a', bytes: Buffer.from([255, 0, 0, 2, 0, 4, 255, 0]) }]);
    const once = await run(f, [{ path_hex: '61', operation: 'replace-once', before_hex: '020003', after_hex: 'ff00' }]);
    await gitOracle(f, once, [{ path: 'a', bytes: Buffer.from([0, 1, 255, 0, 4, 255]) }]);
    const ambiguous = changeFixture(format, [{ path: 'a', bytes: Buffer.from([0, 0, 0]) }]);
    await assert.rejects(run(ambiguous, [{ path_hex: '61', operation: 'replace-once', before_hex: '0000', after_hex: 'ff' }]), code('source_changes_match_ambiguous'));
    await assert.rejects(run(f, [{ path_hex: '61', operation: 'splice', splices: [{ byte_offset: 0, before_hex: 'ff', after_hex: '00' }] }]), code('source_changes_preimage'));
  });
  test(`${format}: profile changes require new review even when the exact patch is NUL-free`, async () => {
    const f = changeFixture(format, [{ path: 'a', bytes: 'before' }]), rows = [replace('a', 'after')];
    const ordinary = await buildSourceChanges(f.bytes, f.expected, intent(rows)), opted = await run(f, rows);
    assert.deepEqual(ordinary.bytes, opted.bytes); assert.deepEqual(ordinary.tree, opted.tree);
    assert.equal(Object.hasOwn(ordinary.manifest, 'byte_profile'), false);
    assert.notEqual(sha256(canonical(ordinary.manifest)), sha256(canonical(opted.manifest)));
    const { byte_profile, changes_sha256, ...remaining } = opted.manifest;
    const { changes_sha256: oldChanges, ...old } = ordinary.manifest;
    assert.deepEqual(remaining, old); assert.notEqual(changes_sha256, oldChanges);
    assert.deepEqual(await run(f, rows), opted);
  });
  test(`${format}: exact byte budgets, full source checks and caller ownership still apply`, async () => {
    const f = changeFixture(format, [{ path: 'a', bytes: Buffer.from([0, 255]) }]), rows = [replace('a', Buffer.from([0, 1, 2]))];
    const result = await run(f, rows, { limits: { fileBytes: 3, totalBytes: 5 } });
    await assert.rejects(run(f, rows, { limits: { totalBytes: 4 } }), code('source_changes_retained_budget'));
    await assert.rejects(run(f, rows, { limits: { fileBytes: 2 } }), code('source_changes_bytes'));
    assert.deepEqual(await run(f, rows, { limits: { patchBytes: result.bytes.length } }), result);
    await assert.rejects(run(f, rows, { limits: { patchBytes: result.bytes.length - 1 } }), code('source_changes_patch_budget'));
    const bytes = Buffer.from(f.bytes), expected = structuredClone(f.expected), input = binary(rows);
    const pending = buildSourceChanges(bytes, expected, input);
    bytes.fill(0); expected.files.length = 0; input.byte_profile = 'invalid'; input.changes[0].content_hex = 'ff';
    assert.deepEqual(await pending, result);
    const bad = structuredClone(f.value); bad.blobs[0].bytesHex = 'ffff';
    await assert.rejects(buildSourceChanges(Buffer.from(JSON.stringify(bad)), f.expected, binary(rows)));
  });
}

test('only the explicit known byte profile is accepted, before copying or hashing source', async () => {
  const f = changeFixture(), rows = [{ path_hex: hexPath('empty.txt'), operation: 'replace', content_hex: '00' }];
  for (const profile of [null, undefined, true, false, 1, 'binary', 'text', {}, ['binary-safe-v1']]) {
    await assert.rejects(buildSourceChanges(f.bytes, f.expected, { ...intent(rows), byte_profile: profile }), code('source_changes_byte_profile'));
  }
  const normalized = ownSourceChangeInputs(f.bytes, f.expected, binary(rows));
  assert.equal(normalized.changes.byte_profile, BINARY_CHANGE_PROFILE);
  await assert.rejects(buildSourceChanges(f.bytes, f.expected, intent(rows)), code('source_changes_binary_unsupported'));
  assert.ok((await run(f, rows)).bytes.includes(0));
});
test('shared encoder is binary-safe only by explicit boolean; text helpers remain text-only', async () => {
  const edits = [{ path_hex: '61', before: { mode: 0o100644, bytes: Uint8Array.of(0, 255) }, after: { mode: 0o100644, bytes: Uint8Array.of(0, 1) } }];
  await assert.rejects(buildPatch(edits, 'sha1', { crypto: webcrypto }));
  for (const allowBinary of [1, 'true', null, {}]) await assert.rejects(buildPatch(edits, 'sha1', { crypto: webcrypto, allowBinary }));
  assert.ok((await buildPatch(edits, 'sha1', { crypto: webcrypto, allowBinary: true })).bytes.includes(0));
  assert.throws(() => exactText(Uint8Array.of(0))); assert.throws(() => textBytes('a\0b'));
});
test('binary no-op, work interruption and line-budget refusal do not yield partial drafts', async () => {
  const f = changeFixture('sha1', [{ path: 'a', bytes: Buffer.from([0, 1]) }]);
  await assert.rejects(run(f, [replace('a', Buffer.from([0, 1]))]), code('source_changes_no_effect'));
  const controller = new AbortController(); controller.abort();
  await assert.rejects(run(f, [replace('a', Buffer.from([0, 2]))], { signal: controller.signal }));
  let count = 0;
  await assert.rejects(run(f, [replace('a', Buffer.from([0, 2]))], { check: () => { if (++count === 15) throw new Error('checkpoint stop'); } }), /checkpoint stop/);
  const lines = Buffer.concat([Buffer.from([0]), Buffer.alloc(160001, 10)]);
  await assert.rejects(run(f, [replace('a', lines)]), /line budget/);
});
test('seeded arbitrary-byte patches match independently built trees in both hash domains', async () => {
  let seed = 0x41fb901;
  const random = () => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return seed >>> 0; };
  for (const format of ['sha1', 'sha256']) for (let trial = 0; trial < 8; trial++) {
    const before = Buffer.from(Array.from({ length: 1 + random() % 512 }, () => random() & 255)); before[0] = 0;
    const after = Buffer.from(Array.from({ length: 1 + random() % 512 }, () => random() & 255)); after[0] = 0;
    const f = changeFixture(format, [{ path: 'data.bin', bytes: before }]);
    await gitOracle(f, await run(f, [replace('data.bin', after)]), [{ path: 'data.bin', bytes: after }]);
  }
});

test('shared encoder owns Buffer-backed binary sides before the first asynchronous hash', async () => {
  const before = Buffer.from([0, 1]), after = Buffer.from([0, 2]);
  const edits = [{ path_hex: '61', before: { mode: 0o100644, bytes: before }, after: { mode: 0o100755, bytes: after } }];
  const pending = buildPatch(edits, 'sha1', { crypto: webcrypto, allowBinary: true });
  before.fill(255); after.fill(254); edits[0].after.mode = 0o100644;
  const result = await pending;
  assert.equal(result.paths[0].old_blob, objectId('blob', Buffer.from([0, 1]), 'sha1'));
  assert.equal(result.paths[0].new_blob, objectId('blob', Buffer.from([0, 2]), 'sha1'));
  assert.equal(result.paths[0].new_mode, 0o100755);
  assert.ok(Buffer.from(result.bytes).includes(Buffer.from([45, 0, 1])));
  assert.ok(Buffer.from(result.bytes).includes(Buffer.from([43, 0, 2])));
});
