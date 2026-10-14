import test from 'node:test';
import assert from 'node:assert/strict';
import { buildSourceChanges, ownSourceChangeInputs, canonical, sha256, SOURCE_PACKAGE_BYTES } from '../operator/source_changes.mjs';
import { replaySourceChanges } from '../operator/source_replay.mjs';
import { changeFixture, hexPath, intent, replace } from './source_changes_fixture.mjs';
import { replayPair, selectSource, withParent } from './source_replay_fixture.mjs';
const edits = () => intent([{ path_hex: hexPath('src/file'), operation: 'replace-once', before_utf8: 'beta', after_utf8: 'reviewed' }]);
async function setup(format = 'sha1', changes = edits(), selected) {
  const pair = replayPair(format, selected), draft = await buildSourceChanges(pair.old.bytes, pair.old.expected, changes);
  const pin = sha256(canonical(draft.manifest));
  return { ...pair, changes, draft, pin,
    run: (next = pair.next, options = {}) => replaySourceChanges(pair.old.bytes, pair.old.expected, changes,
      next.bytes, next.expected, { confirmDraftSha256: pin, ...options }) };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: replay preserves the exact reviewed effect while retaining independent concurrent changes`, async () => {
    const s = await setup(format), replay = await s.run();
    assert.deepEqual(replay.draft.bytes, s.draft.bytes); assert.deepEqual(replay.draft.manifest.effects, s.draft.manifest.effects);
    assert.notEqual(replay.receipt.draft_sha256, s.pin); assert.equal(replay.receipt.selected_commit, s.next.commit);
    const after = s.after.map(row => row.path === 'src/file' ? { ...row, bytes: 'alpha\nreviewed\n' } : row);
    assert.equal(replay.draft.tree.afterTree, changeFixture(format, after).tree);
    assert.notEqual(replay.draft.tree.afterTree, s.draft.tree.afterTree);
    assert.equal(replay.receipt.selected_file_count, 3); assert.equal(replay.receipt.exact_patch_preserved, true);
    for (const name of ['ancestry_verified', 'semantic_compatibility_verified', 'authority_verified', 'freshness_verified', 'publication_authorized', 'repository_changed']) assert.equal(replay.receipt[name], false);
    assert.equal(replay.receipt.new_review_required, true);
    assert.deepEqual(await s.run(), replay);
  });
  test(`${format}: changed preimages cannot be reinterpreted even when replace-once still finds a unique match`, async () => {
    const s = await setup(format), rows = s.after.map(row => row.path === 'src/file' ? { ...row, bytes: 'concurrent\nbeta\n' } : row);
    const changed = selectSource(withParent(changeFixture(format, rows), s.old.commit), s.selected);
    // Control: naive replay succeeds against the changed file. The original
    // read witness, not an ordinary patch-parser refusal, must prevent it.
    assert.ok((await buildSourceChanges(changed.bytes, changed.expected, s.changes)).bytes.length);
    await assert.rejects(s.run(changed), /source_replay_read_set_changed/);
    assert.ok((await s.run()).draft.bytes.length);
  });
  test(`${format}: unused context, no-op intents and copy sources are part of the original selected read set`, async () => {
    for (const changes of [edits(), intent([...edits().changes, replace('empty', '')]),
      intent([{ operation: 'copy', from_path_hex: hexPath('run.sh'), path_hex: hexPath('copy.sh') }])]) {
      const s = await setup(format, changes), rows = s.after.map(row => row.path === 'empty' ? { ...row, bytes: 'was unused but changed' } : row);
      const next = selectSource(changeFixture(format, rows), s.selected);
      await assert.rejects(s.run(next), /source_replay_read_set_changed/);
      assert.ok((await s.run()).receipt.selected_read_set_preserved);
    }
  });
  test(`${format}: a selected mode change is a conflict even for an unedited context file`, async () => {
    const s = await setup(format), rows = s.after.map(row => row.path === 'run.sh' ? { ...row, mode: 0o100644 } : row);
    const next = selectSource(changeFixture(format, rows), s.selected);
    assert.deepEqual(next.expected.files, s.old.expected.files);
    assert.ok((await buildSourceChanges(next.bytes, next.expected, s.changes)).bytes.equals(s.draft.bytes));
    await assert.rejects(s.run(next), /source_replay_read_set_changed/);
  });
  test(`${format}: omission, replacement and widening of the selected source set are refused`, async () => {
    const s = await setup(format);
    for (const paths of [['src/file'], ['src/file', 'run.sh', 'README'], [...s.selected, 'README']]) {
      await assert.rejects(s.run(selectSource(withParent(changeFixture(format, s.after), s.old.commit), paths)), /source_replay_read_set_changed/);
    }
    assert.equal((await s.run()).receipt.effect_count, 1);
  });
  test(`${format}: creations, relocations, exact splices, mode changes, deletes and no-ops keep identical patches`, async () => {
    const cases = [intent([{ operation: 'create', path_hex: hexPath('src/new'), content_utf8: '', executable: true }]),
      intent([{ operation: 'rename', from_path_hex: hexPath('src/file'), path_hex: hexPath('new/nested/file') }]),
      intent([{ operation: 'copy', from_path_hex: hexPath('run.sh'), path_hex: hexPath('copy.sh'), executable: false }]),
      intent([{ operation: 'splice', path_hex: hexPath('src/file'), splices: [{ byte_offset: 0, before_utf8: 'alpha', after_utf8: 'gamma' }] }]),
      intent([{ operation: 'mode', path_hex: hexPath('run.sh'), executable: false }]),
      intent([{ operation: 'delete', path_hex: hexPath('empty') }]),
      intent([...edits().changes, replace('empty', '')])];
    for (const changes of cases) {
      const s = await setup(format, changes), r = await s.run();
      assert.deepEqual(r.draft.bytes, s.draft.bytes); assert.deepEqual(r.draft.manifest.effects, s.draft.manifest.effects);
      assert.deepEqual(r.draft.manifest.no_op_paths_hex, s.draft.manifest.no_op_paths_hex);
    }
  });
  test(`${format}: an occupied creation destination or newly opaque ancestor never becomes overwrite consent`, async () => {
    for (const path of ['new', 'new/child']) {
      const s = await setup(format, intent([{ operation: 'create', path_hex: hexPath(path), content_utf8: 'intended', executable: false }]));
      const rows = [...s.after, { path: 'new', bytes: 'another writer' }];
      await assert.rejects(s.run(selectSource(changeFixture(format, rows), s.selected)));
      const opaque = selectSource(changeFixture(format, [...s.after, { path: 'new/other', bytes: 'another writer' }]), s.selected);
      await assert.rejects(s.run(opaque));
      assert.ok((await s.run()).draft.tree.afterTree);
    }
  });
  test(`${format}: no implicit already-applied success or disappearance of reviewed effects`, async () => {
    const s = await setup(format), rows = s.after.map(row => row.path === 'src/file' ? { ...row, bytes: 'alpha\nreviewed\n' } : row);
    await assert.rejects(s.run(selectSource(changeFixture(format, rows), s.selected)), /source_replay_read_set_changed/);
  });
  test(`${format}: independent commit and full original review hash must match`, async () => {
    const s = await setup(format);
    await assert.rejects(s.run(s.next, { confirmDraftSha256: 'f'.repeat(64) }), /source_replay_confirmation/);
    await assert.rejects(s.run(s.next, { confirmDraftSha256: undefined }), /source_replay_confirmation/);
    await assert.rejects(s.run(s.old), /source_replay_same_commit/);
    const wrong = structuredClone(s.next); wrong.expected.commit = 'e'.repeat(format === 'sha1' ? 40 : 64);
    await assert.rejects(s.run(wrong)); assert.ok((await s.run()).receipt.draft_sha256);
  });
  test(`${format}: reordered JSON and qualified independent IDs normalize without changing logical input`, async () => {
    const s = await setup(format), next = structuredClone(s.next);
    next.bytes = Buffer.from(JSON.stringify(next.value, null, 2));
    next.expected.commit = `${format}:${next.expected.commit}`;
    next.expected.files = next.expected.files.map(row => ({ blob: `${format}:${row.blob}`, pathHex: row.pathHex }));
    const r = await s.run(next); assert.deepEqual(r.draft.bytes, s.draft.bytes);
    assert.equal(r.receipt.expected_sha256, sha256(canonical(s.next.expected)));
  });
  test(`${format}: full source bytes and modes are checked, not imported success flags or self-consistent declarations`, async () => {
    const s = await setup(format);
    for (const mutate of [v => { v.blobs[0].bytesHex += '00'; }, v => { v.membership.trees[0].bodyHex += '00'; },
      v => { v.membership.files[0].kind = v.membership.files[0].kind === 'file' ? 'executable' : 'file'; },
      v => { v.authority_verified = true; }, v => { v.membership.commit.bodyHex += '00'; }]) {
      const next = structuredClone(s.next); mutate(next.value); next.bytes = Buffer.from(JSON.stringify(next.value));
      await assert.rejects(s.run(next));
    }
  });
}
test('complete two-base input ownership precedes the first asynchronous digest', async () => {
  const s = await setup(), old = Buffer.from(s.old.bytes), next = Buffer.from(s.next.bytes), a = structuredClone(s.old.expected), b = structuredClone(s.next.expected), changes = structuredClone(s.changes);
  const pending = replaySourceChanges(old, a, changes, next, b, { confirmDraftSha256: s.pin });
  old.fill(0); next.fill(0); a.files.length = 0; b.files.length = 0; changes.changes[0].after_utf8 = 'mutated';
  assert.deepEqual(await pending, await s.run());
});
test('all replay checkpoints cancel without returning a partial new review', async () => {
  const s = await setup(); const controller = new AbortController(); controller.abort();
  await assert.rejects(s.run(s.next, { signal: controller.signal }));
  // Count injected clock reads without weakening the production lifetime guard.
  const original = performance.now.bind(performance); let calls = 0;
  Object.defineProperty(performance, 'now', { configurable: true, value: () => { calls++; return original(); } });
  try {
    await s.run(); const count = calls;
    for (const at of [2, 15, Math.floor(count / 2), count - 1]) {
      calls = 0; const c = new AbortController();
      Object.defineProperty(performance, 'now', { configurable: true, value: () => { if (++calls === at) c.abort(); return original(); } });
      await assert.rejects(s.run(s.next, { signal: c.signal }));
    }
  } finally { Object.defineProperty(performance, 'now', { configurable: true, value: original }); }
  assert.ok((await s.run()).receipt.new_review_required);
});
test('exact edit bounds, shared-buffer refusals and closed options remain enforced', async () => {
  const s = await setup(), m = s.draft.manifest;
  assert.ok((await s.run(s.next, { limits: { patchBytes: m.patch_bytes, totalBytes: m.retained_file_bytes, files: m.effects.length } })).draft);
  for (const limits of [{ patchBytes: m.patch_bytes - 1 }, { totalBytes: m.retained_file_bytes - 1 }, { files: 0 }, { files: 33 }]) await assert.rejects(s.run(s.next, { limits }));
  for (const extra of [{ timeoutMs: 0 }, { timeoutMs: 300001 }, { ca: Buffer.from('x') }, { key: 'old-key' }, { journal: '/old' }, { signal: {} }]) await assert.rejects(s.run(s.next, extra));
  await assert.rejects(replaySourceChanges(s.old.bytes, s.old.expected, s.changes,
    new Uint8Array(new SharedArrayBuffer(1)), s.next.expected, { confirmDraftSha256: s.pin }));
  assert.throws(() => ownSourceChangeInputs(Buffer.alloc(SOURCE_PACKAGE_BYTES + 1), s.old.expected, s.changes));
});
test('a total deadline spans both verifications rather than resetting at the next base', async () => {
  const s = await setup(), original = performance.now.bind(performance); let now = 0;
  Object.defineProperty(performance, 'now', { configurable: true, value: () => now++ });
  try { await assert.rejects(s.run(s.next, { timeoutMs: 10 }), /source_edit_timeout/); }
  finally { Object.defineProperty(performance, 'now', { configurable: true, value: original }); }
});
test('unrelated independently selected commits never acquire an ancestry claim', async () => {
  const s = await setup(), unrelated = selectSource(withParent(changeFixture('sha1', s.after), null), s.selected);
  const r = await s.run(unrelated); assert.equal(r.receipt.ancestry_verified, false); assert.equal(r.receipt.semantic_compatibility_verified, false);
  assert.notEqual(r.receipt.draft_sha256, s.pin);
});
test('native hash domains cannot be crossed by explicit replay', async () => {
  const s = await setup(), other = replayPair('sha256');
  await assert.rejects(s.run(other.next), /source_replay_format_changed/);
});
