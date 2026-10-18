// Exact source relocation through complete existing package/patch/candidate
// modules. Git in nativePeer is a test oracle, not a production dependency.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { prepareSourceChanges, verifySourceChangeCandidate } from '../operator/source_changes_prepare.mjs';
import { changeFixture, hexPath, intent, replace } from './source_changes_fixture.mjs';
import { nativePeer, TOKEN } from './source_changes_native_fixture.mjs';
const move = (from, to, extra = {}) => ({ operation: 'rename', from_path_hex: hexPath(from), path_hex: hexPath(to), ...extra });
const copy = (from, to, extra = {}) => ({ ...move(from, to, extra), operation: 'copy' });
const draft = (f, rows, options) => buildSourceChanges(f.bytes, f.expected, intent(rows), options);
function sparse(format) {
  const f = changeFixture(format, [{ path: 'src/chosen', bytes: 'selected\r\nlast', mode: 0o100755 },
    { path: 'src/hidden', bytes: 'hidden' }, { path: 'opaque/file', bytes: 'unread' },
    { path: 'link', bytes: 'src', mode: 0o120000 }]);
  const chosen = hexPath('src/chosen');
  f.expected.files = f.expected.files.filter(r => r.pathHex === chosen);
  f.value.membership.files = f.value.membership.files.filter(r => r.pathHex === chosen);
  f.value.membership.trees = f.value.membership.trees.filter(r => [null, hexPath('src')].includes(r.pathHex));
  f.value.blobs = f.value.blobs.filter(r => r.oid === f.expected.files[0].blob);
  f.bytes = Buffer.from(JSON.stringify(f.value)); return f;
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: rename creates two exact effects and prunes the emptied source directory`, async () => {
    const f = changeFixture(format, [{ path: 'old/deep/file', bytes: 'data\r\nlast', mode: 0o100755 }]);
    const result = await draft(f, [move('old/deep/file', 'new/deep/file')]);
    const expected = changeFixture(format, [{ path: 'new/deep/file', bytes: 'data\r\nlast', mode: 0o100755 }]);
    assert.equal(result.tree.afterTree, expected.tree);
    assert.equal(result.manifest.effects.length, 2);
    const [added, removed] = result.manifest.effects;
    assert.equal(added.old_blob, null); assert.equal(added.new_blob, f.files[0].id);
    assert.equal(removed.old_blob, f.files[0].id); assert.equal(removed.new_blob, null);
    assert.equal(added.new_mode, 0o100755); assert.equal(removed.old_mode, 0o100755);
    assert.equal(result.manifest.retained_file_bytes, 2 * f.files[0].bytes.length);
    assert.equal(result.manifest.creation_preconditions.paths[0].pathHex, hexPath('new/deep/file'));
    assert.deepEqual(result.manifest.relocations, [{ operation: 'rename', from_path_hex: hexPath('old/deep/file'),
      path_hex: hexPath('new/deep/file'), source_blob: f.files[0].id, source_mode: 0o100755, destination_mode: 0o100755 }]);
    assert.equal(result.manifest.publication_authorized, false);
  });
  test(`${format}: multiple copies share a verified source but charge each complete before/after pair`, async () => {
    const f = changeFixture(format, [{ path: 'source', bytes: 'exact', mode: 0o100755 }]);
    const result = await draft(f, [copy('source', 'a'), copy('source', 'b', { executable: false })]);
    assert.equal(result.tree.afterTree, changeFixture(format, [
      { path: 'source', bytes: 'exact', mode: 0o100755 }, { path: 'a', bytes: 'exact', mode: 0o100755 }, { path: 'b', bytes: 'exact' }]).tree);
    assert.equal(result.manifest.retained_file_bytes, 20); assert.equal(result.manifest.effects.length, 2);
    assert.ok(result.manifest.effects.every(e => e.old_blob === null && e.new_blob === f.files[0].id));
    assert.equal(result.manifest.relocations.length, 2);
    assert.deepEqual(await draft(f, [copy('source', 'b', { executable: false }), copy('source', 'a')]), result);
  });
  test(`${format}: empty content, non-UTF8 bytes, quoted paths and destination modes are exact`, async () => {
    const from = Buffer.from([0xff, 34, 92, 10]), to = Buffer.from([0xfe, 47, 0xfd]);
    const f = changeFixture(format, [{ path: from, bytes: Buffer.from([0xff, 13, 10, 0xfe]), mode: 0o100644 }, { path: 'empty', bytes: '' }]);
    const result = await draft(f, [move(from, to, { executable: true }), copy('empty', 'empty-copy')]);
    assert.equal(result.tree.afterTree, changeFixture(format, [
      { path: to, bytes: Buffer.from([0xff, 13, 10, 0xfe]), mode: 0o100755 }, { path: 'empty', bytes: '' }, { path: 'empty-copy', bytes: '' }]).tree);
    assert.match(result.bytes.toString('latin1'), /\\377/);
    assert.equal(result.manifest.effects.find(e => e.path_hex === hexPath('empty-copy')).hunks, 0);
  });
  test(`${format}: hidden targets, unproved ancestors and unselected sources cannot be relocated`, async () => {
    const f = sparse(format);
    for (const op of [copy, move]) {
      for (const dest of ['src/hidden', 'opaque', 'link']) await assert.rejects(draft(f, [op('src/chosen', dest)]), /already exists/);
      await assert.rejects(draft(f, [op('src/chosen', 'src')]), /source_changes_paths/);
      await assert.rejects(draft(f, [op('src/chosen', 'opaque/new')]), /not proved/);
      await assert.rejects(draft(f, [op('src/chosen', 'link/new')]), /not a directory/);
      for (const source of ['src/hidden', 'opaque/file', 'link']) await assert.rejects(draft(f, [op(source, 'fresh')]), /unselected/);
      assert.ok((await draft(f, [op('src/chosen', 'src/fresh')])).tree.afterTree);
    }
  });
  test(`${format}: renames, copies and unrelated edits form one deterministic net effect`, async () => {
    const f = changeFixture(format), rows = [move('src/main.rs', 'lib/main.rs'), copy('run.sh', 'bin/run.sh'), replace('empty.txt', 'filled')];
    const result = await draft(f, rows);
    assert.equal(result.tree.afterTree, changeFixture(format, [
      { path: 'lib/main.rs', bytes: f.files.find(r => r.path.toString() === 'src/main.rs').bytes },
      { path: 'run.sh', bytes: '#!/bin/sh\necho old\n', mode: 0o100755 },
      { path: 'bin/run.sh', bytes: '#!/bin/sh\necho old\n', mode: 0o100755 }, { path: 'empty.txt', bytes: 'filled' }]).tree);
    assert.deepEqual(await draft(f, [...rows].reverse()), result);
    assert.notEqual(sha256(canonical(result.manifest)), sha256(canonical((await draft(f, [copy('src/main.rs', 'lib/main.rs'), ...rows.slice(1)])).manifest)));
  });
  test(`${format}: generated mixed relocation patches reach native-schema preparation and offline replay`, async t => {
    const peer = await nativePeer(format); t.after(() => peer.close());
    const changes = intent([move('src/main.rs', 'lib/main.rs'), copy('run.sh', 'bin/run.sh', { executable: false })]);
    const d = await buildSourceChanges(peer.fixture.bytes, peer.fixture.expected, changes);
    const options = { confirmDraftSha256: sha256(canonical(d.manifest)) };
    const selected = peer.selection(d.manifest.effects.map(e => e.path_hex));
    const candidate = await prepareSourceChanges(peer.fixture.bytes, peer.fixture.expected, changes, selected, TOKEN, options);
    assert.equal(peer.candidate.tree, d.tree.afterTree); assert.equal(candidate.binding.effect_count, 3);
    assert.equal(candidate.binding.candidate_root_matches_exact_effects, true);
    const replay = await verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, changes, candidate.capture, candidate.bundle, options);
    assert.deepEqual(replay.binding, candidate.binding); assert.equal(peer.requests.length, 2); assert.equal(peer.applies, 0);
    assert.deepEqual(peer.failures, []);
  });
  test(`${format}: candidate omissions and wrong destination content are still refused`, async t => {
    const peer = await nativePeer(format); t.after(() => peer.close());
    const changes = intent([move('run.sh', 'bin/run.sh'), replace('src/main.rs', 'intended\n')]);
    const d = await buildSourceChanges(peer.fixture.bytes, peer.fixture.expected, changes);
    const selected = peer.selection(d.manifest.effects.map(e => e.path_hex)), options = { confirmDraftSha256: sha256(canonical(d.manifest)) };
    for (const fault of ['unreported-addition', 'wrong-after']) {
      peer.fault = fault;
      await assert.rejects(prepareSourceChanges(peer.fixture.bytes, peer.fixture.expected, changes, selected, TOKEN, options), /candidate_(tree|effects)/);
    }
    peer.fault = null; assert.ok((await prepareSourceChanges(peer.fixture.bytes, peer.fixture.expected, changes, selected, TOKEN, options)).binding);
    assert.equal(peer.applies, 0); assert.deepEqual(peer.failures, []);
  });
}
test('conflicting source/destination graphs are refused without selecting an execution order', async () => {
  const f = changeFixture();
  for (const rows of [[move('run.sh', 'new'), copy('run.sh', 'other')], [move('run.sh', 'new'), move('run.sh', 'other')],
    [copy('run.sh', 'new'), replace('run.sh', 'changed')], [copy('run.sh', 'new'), { path_hex: hexPath('run.sh'), operation: 'delete' }],
    [move('run.sh', 'new'), copy('new', 'next')], [move('run.sh', 'src/main.rs'), move('src/main.rs', 'run.sh')]]) {
    await assert.rejects(draft(f, rows), /source_changes_source_conflict/);
  }
  for (const rows of [[copy('run.sh', 'run.sh')], [copy('run.sh', 'new'), copy('empty.txt', 'new')],
    [copy('run.sh', 'fresh'), copy('empty.txt', 'fresh/child')], [move('run.sh', 'run.sh/child')]]) await assert.rejects(draft(f, rows), /source_changes_paths/);
  assert.ok((await draft(f, [copy('run.sh', 'one'), copy('run.sh', 'two')])).manifest);
});
test('closed operation grammar never converts a malformed relocation into a replace', async () => {
  const f = changeFixture(), good = copy('run.sh', 'new');
  for (const row of [{ ...good, content_utf8: 'different' }, { ...good, splices: [] }, { ...good, executable: 1 },
    { ...good, from_path_hex: undefined }, { ...good, from_path_hex: hexPath('../escape') },
    { ...good, from_path_hex: hexPath('.git/config') }, { ...good, from_path_hex: hexPath('run.sh') + 'f' },
    { path_hex: good.path_hex, operation: 'copy' }, { ...good, operation: 'move' }]) await assert.rejects(draft(f, [row]));
  assert.ok((await draft(f, [good])).tree.afterTree);
});
test('effect, logical byte and patch bounds apply after relocation expansion', async () => {
  const f = changeFixture('sha1', [{ path: 'src', bytes: '12345' }]);
  const full = await draft(f, [move('src', 'dest')]);
  assert.deepEqual(await draft(f, [move('src', 'dest')], { limits: { files: 2, fileBytes: 5, totalBytes: 10, patchBytes: full.bytes.length } }), full);
  for (const limits of [{ files: 1 }, { fileBytes: 4 }, { totalBytes: 9 }, { patchBytes: full.bytes.length - 1 }]) await assert.rejects(draft(f, [move('src', 'dest')], { limits }));
  const many = changeFixture('sha256', Array.from({ length: 17 }, (_, n) => ({ path: `src${n}`, bytes: '' })));
  const rows = Array.from({ length: 17 }, (_, n) => move(`src${n}`, `dest${n}`));
  assert.equal((await draft(many, rows.slice(0, 16))).manifest.effects.length, 32);
  await assert.rejects(draft(many, rows), /inventory/);
  assert.equal((await draft(f, Array.from({ length: 32 }, (_, n) => copy('src', `dest${n}`)))).manifest.effects.length, 32);
});
test('original NUL-bearing sources remain explicitly unsupported', async () => {
  const f = changeFixture('sha1', [{ path: 'source', bytes: Buffer.from([1, 0, 2]) }]);
  for (const op of [copy, move]) await assert.rejects(draft(f, [op('source', 'dest')]), /binary_unsupported/);
});
test('caller mutations cannot redirect a relocation after verification starts', async () => {
  const f = changeFixture(), untouched = changeFixture(), rows = [move('run.sh', 'bin/run.sh')];
  const pending = draft(f, rows);
  rows[0].path_hex = hexPath('stolen'); rows[0].from_path_hex = hexPath('empty.txt');
  f.bytes.fill(0); f.expected.files.length = 0;
  assert.deepEqual(await pending, await draft(untouched, [move('run.sh', 'bin/run.sh')]));
});
test('cancellation at early, middle and final checkpoints returns no partial relocation', async () => {
  const f = changeFixture(), rows = [move('run.sh', 'bin/run.sh'), copy('src/main.rs', 'lib/main.rs')];
  let count = 0; const good = await draft(f, rows, { check() { count++; } });
  for (const stop of [1, Math.floor(count / 2), count - 1, count]) {
    let n = 0; await assert.rejects(draft(f, rows, { check() { if (++n === stop) throw new Error('stop relocation'); } }), /stop relocation/);
  }
  assert.deepEqual(await draft(f, rows), good);
});
