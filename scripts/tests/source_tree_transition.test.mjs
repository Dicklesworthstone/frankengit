// Native commitment derivation, not authorization or pack-closure verification.
// Test framing is independent of the production decoder/encoder; Git fixtures
// in the pipeline independently apply the actual patches and check the result.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import * as membership from '../../crates/fgit-node/src/smart_http/server/browser/search-context-membership.mjs';
import { changeFixture, hexPath, objectId } from './source_changes_fixture.mjs';
const pair = (blob, mode = 0o100644) => ({ blob, kind: mode === 0o100755 ? 'executable' : 'file' });
function effect(f, path, bytes, mode = 0o100644) {
  const key = hexPath(path), file = f.files.find(row => row.path.toString('hex') === key);
  return { pathHex: key, before: file ? pair(file.id, file.mode) : null,
    after: bytes === null ? null : pair(objectId('blob', Buffer.from(bytes), f.format), mode) };
}
const ordered = effects => [...effects].sort((a, b) => a.pathHex < b.pathHex ? -1 : 1);
const derive = (f, effects, input = {}, check = () => {}) => membership.deriveEditedTree(f.value.membership, f.expected,
  ordered(effects), webcrypto, check, input);
function sparse(format, rows, anchors) {
  const f = changeFixture(format, rows), selected = new Set(anchors.map(hexPath)), dirs = new Set([null]);
  for (const path of anchors) {
    const parts = Buffer.from(path).toString('latin1').split('/');
    for (let i = 1; i < parts.length; i++) dirs.add(Buffer.from(parts.slice(0, i).join('/'), 'latin1').toString('hex'));
  }
  f.expected.files = f.expected.files.filter(row => selected.has(row.pathHex));
  f.value.membership.files = f.value.membership.files.filter(row => selected.has(row.pathHex));
  f.value.membership.trees = f.value.membership.trees.filter(row => dirs.has(row.pathHex));
  return f;
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: sparse changed parents preserve unrelated files, subtrees and external entries`, async () => {
    const rows = [{ path: 'a/leaf', bytes: 'before\n' }, { path: 'a/hidden', bytes: 'untouched\n' },
      { path: 'elsewhere/deep/leaf', bytes: 'unread subtree\n' }, { path: 'link', bytes: 'a', mode: 0o120000 },
      { path: 'module', bytes: 'unread target', mode: 0o160000 }, { path: 'root', bytes: 'keep' }];
    const f = sparse(format, rows, ['a/leaf', 'root']);
    const edits = [effect(f, 'a/leaf', 'after\n', 0o100755), effect(f, 'a/new', ''), effect(f, 'fresh/sub/file', 'new\r\n')];
    const expected = changeFixture(format, [
      ...rows.map(row => row.path === 'a/leaf' ? { ...row, bytes: 'after\n', mode: 0o100755 } : row),
      { path: 'a/new', bytes: '' }, { path: 'fresh/sub/file', bytes: 'new\r\n' }]);
    const result = await derive(f, edits);
    assert.equal(result.afterTree, expected.tree); assert.equal(result.beforeTree, f.tree); assert.equal(result.commit, f.commit);
    assert.equal(result.exactFileEffectsBound, true); assert.equal(result.unrelatedEntriesPreserved, true);
    assert.equal(result.objectClosureVerified, false); assert.equal(result.authorityVerified, false); assert.equal(result.publicationAuthorized, false);
    assert.deepEqual(result.rewrittenTrees.map(row => row.pathHex), ['fresh/sub', 'a', 'fresh', null].map(p => p === null ? null : hexPath(p)));
    assert.ok(!result.rewrittenTrees.some(row => row.pathHex === hexPath('elsewhere')));
    const reordered = structuredClone(f); reordered.value.membership.trees.reverse();
    assert.deepEqual(await derive(reordered, edits), result);
  });
  test(`${format}: deleting the last descendant prunes every touched empty directory but retains an empty root`, async () => {
    const f = changeFixture(format, [{ path: 'deep/nested/file', bytes: 'remove' }]);
    const result = await derive(f, [effect(f, 'deep/nested/file', null)]);
    assert.equal(result.afterTree, objectId('tree', Buffer.alloc(0), format));
    assert.deepEqual(result.rewrittenTrees.map(row => [row.pathHex, row.afterTree]), [
      [hexPath('deep/nested'), null], [hexPath('deep'), null], [null, result.afterTree] ]);
    assert.equal(result.treeBytes, 0); assert.equal(result.entryCount, 0);
  });
  test(`${format}: equal-hash subtrees have independent path overlays`, async () => {
    const rows = [{ path: 'a/file', bytes: 'same' }, { path: 'b/file', bytes: 'same' }];
    const f = sparse(format, rows, ['a/file']);
    assert.equal(f.value.membership.trees.length, 2);
    const result = await derive(f, [effect(f, 'a/file', 'changed')]);
    const expected = changeFixture(format, [{ path: 'a/file', bytes: 'changed' }, rows[1]]);
    assert.equal(result.afterTree, expected.tree);
    assert.equal(result.rewrittenTrees.length, 2);
    assert.equal(result.rewrittenTrees[0].pathHex, hexPath('a'));
  });
  test(`${format}: native directory ordering and raw byte paths survive combined replacement and insertion`, async () => {
    const raw = Buffer.from([0xff, 47, 0xfe, 34, 92, 10]);
    const f = changeFixture(format, [{ path: 'a.c', bytes: 'first' }, { path: 'a/file', bytes: 'second' }, { path: raw, bytes: 'third' }]);
    const edits = [effect(f, 'a.c', 'replacement'), effect(f, 'a/file', null), effect(f, 'a/z', 'new'), effect(f, raw, 'raw', 0o100755), effect(f, 'a0', 'last')];
    const expected = changeFixture(format, [{ path: 'a.c', bytes: 'replacement' }, { path: 'a/z', bytes: 'new' },
      { path: raw, bytes: 'raw', mode: 0o100755 }, { path: 'a0', bytes: 'last' }]);
    assert.equal((await derive(f, edits)).afterTree, expected.tree);
  });
  test(`${format}: original selected before-images and actual absence are mandatory`, async () => {
    const f = sparse(format, [{ path: 'src/file', bytes: 'a' }, { path: 'src/hidden', bytes: 'b' },
      { path: 'opaque/file', bytes: 'c' }, { path: 'link', bytes: 'src', mode: 0o120000 }], ['src/file']);
    const good = effect(f, 'src/file', 'new');
    for (const altered of [{ ...good, before: null }, { ...good, before: pair('e'.repeat(format === 'sha1' ? 40 : 64)) },
      { ...good, before: { ...good.before, kind: 'executable' } }, effect(f, 'src/hidden', 'overwrite')]) await assert.rejects(derive(f, [altered]));
    const hiddenCreate = effect(f, 'src/hidden', 'x'); hiddenCreate.before = null;
    await assert.rejects(derive(f, [hiddenCreate]), /already exists/);
    await assert.rejects(derive(f, [effect(f, 'opaque/new', 'x')]), /not proved/);
    await assert.rejects(derive(f, [effect(f, 'link/new', 'x')]), /not a directory/);
    assert.equal((await derive(f, [effect(f, 'src/new', 'x')])).treeCount, 2);
  });
  test(`${format}: malformed or substituted basis cannot produce a plausible candidate commitment`, async () => {
    const f = changeFixture(format), edits = [effect(f, 'src/main.rs', 'new')];
    for (const mutate of [v => { v.value.membership.trees[0].bodyHex += '00'; }, v => { v.value.membership.trees.pop(); },
      v => { v.expected.commit = 'f'.repeat(format === 'sha1' ? 40 : 64); }, v => { v.value.membership.commit.bodyHex += '00'; }]) {
      const bad = structuredClone(f); mutate(bad); await assert.rejects(derive(bad, edits));
    }
    assert.ok((await derive(f, edits)).afterTree);
  });
  test(`${format}: inputs are snapshotted before asynchronous digests`, async () => {
    const f = changeFixture(format), original = structuredClone(f), edits = [effect(f, 'src/main.rs', 'intended')], originalEdits = structuredClone(edits);
    const pending = derive(f, edits);
    f.value.membership.trees.length = 0; f.expected.files.length = 0; edits[0].after.blob = 'f'.repeat(40); edits[0].pathHex = hexPath('elsewhere');
    assert.deepEqual(await pending, await derive(original, originalEdits));
  });
}
test('effect schemas, ordering, overlaps, unsupported modes and no-ops are refused', async () => {
  const f = changeFixture(), good = effect(f, 'src/main.rs', 'new');
  for (const edits of [[], [good, good], [{ ...good, unexpected: true }], [{ ...good, after: null, before: null }],
    [{ ...good, after: good.before }], [{ ...good, after: { ...good.after, kind: 'symlink' } }],
    [{ ...good, after: { ...good.after, blob: '0'.repeat(40) } }],
    [effect(f, 'fresh', 'a'), effect(f, 'fresh/sub', 'b')]]) await assert.rejects(derive(f, edits));
  await assert.rejects(membership.deriveEditedTree(f.value.membership, f.expected,
    [good, effect(f, 'empty.txt', 'filled')], webcrypto), /order/);
  await assert.rejects(derive(f, [effect(f, '../escape', 'x')]));
  await assert.rejects(derive(f, [good], { output: { maxTrees: 0 } }));
  await assert.rejects(derive(f, [good], { output: { maxTrees: 2049 } }));
  assert.ok((await derive(f, [good])).afterTree);
});
test('output work has exact finite bounds without narrowing the supported creation depth', async () => {
  const f = changeFixture('sha256', [{ path: 'anchor', bytes: 'a' }]);
  const edits = Array.from({ length: 32 }, (_, i) => effect(f, [`n${String(i).padStart(2, '0')}`, ...Array(62).fill('d'), 'file'].join('/'), 'x'));
  const full = await derive(f, edits);
  assert.equal(full.treeCount, 2017); assert.equal(full.rewrittenTrees.at(-1).pathHex, null);
  assert.deepEqual(await derive(f, edits, { output: { maxTrees: full.treeCount, maxEntries: full.entryCount, maxTreeBytes: full.treeBytes } }), full);
  for (const output of [{ maxTrees: full.treeCount - 1 }, { maxEntries: full.entryCount - 1 }, { maxTreeBytes: full.treeBytes - 1 }]) {
    await assert.rejects(derive(f, edits, { output }), /budget/);
  }
  await assert.rejects(derive(f, [...edits, effect(f, 'another', 'x')]));
});
test('every declared cancellation checkpoint settles without exposing a partial tree', async () => {
  const f = changeFixture(), edits = [effect(f, 'fresh/deep/file', 'x'), effect(f, 'src/main.rs', 'new')];
  let count = 0; const expected = await derive(f, edits, {}, () => { count++; });
  for (const target of [1, 8, Math.floor(count / 2), count - 1, count]) {
    let seen = 0;
    await assert.rejects(derive(f, edits, {}, () => { if (++seen === target) throw new Error('cancel transition'); }), /cancel transition/);
  }
  assert.deepEqual(await derive(f, edits), expected);
});
test('seeded independent tree reconstructions agree across both hash domains', async () => {
  for (const format of ['sha1', 'sha256']) for (let seed = 0; seed < 32; seed++) {
    const rows = Array.from({ length: 8 }, (_, i) => ({ path: `d${i % 3}/file${i}`, bytes: `seed${seed}:file${i}\n`, mode: i % 2 ? 0o100755 : 0o100644 }));
    const f = changeFixture(format, rows), after = [], effects = [];
    for (let i = 0; i < rows.length; i++) {
      const op = (seed + i) % 4;
      if (op === 0) { effects.push(effect(f, rows[i].path, null)); continue; }
      const row = op === 1 ? { ...rows[i], bytes: `changed:${seed}:${i}\n` } : op === 2 ? { ...rows[i], mode: rows[i].mode === 0o100644 ? 0o100755 : 0o100644 } : rows[i];
      after.push(row); if (op !== 3) effects.push(effect(f, row.path, row.bytes, row.mode));
    }
    const added = { path: `new-${seed}/nested/file`, bytes: `new:${seed}\n` }; after.push(added); effects.push(effect(f, added.path, added.bytes));
    assert.equal((await derive(f, effects)).afterTree, changeFixture(format, after).tree, `${format} seed ${seed}`);
  }
});
for (const format of ['sha1', 'sha256']) test(`${format}: untouched explicit empty subtrees are preserved rather than mistaken for pruned parents`, async () => {
  const f = changeFixture(format, [{ path: 'anchor', bytes: 'before' }]), root = f.value.membership.trees.find(t => t.pathHex === null);
  const empty = objectId('tree', Buffer.alloc(0), format);
  const emptyEntry = Buffer.concat([Buffer.from('40000 empty\0'), Buffer.from(empty, 'hex')]);
  root.bodyHex = Buffer.concat([Buffer.from(root.bodyHex, 'hex'), emptyEntry]).toString('hex');
  const newRoot = objectId('tree', Buffer.from(root.bodyHex, 'hex'), format);
  const commit = Buffer.from(f.value.membership.commit.bodyHex, 'hex').toString().replace(`tree ${f.tree}\n`, `tree ${newRoot}\n`);
  root.oid = newRoot; f.tree = newRoot; f.commit = objectId('commit', Buffer.from(commit), format);
  f.expected.commit = f.commit; f.value.membership.commit = { oid: f.commit, bodyHex: Buffer.from(commit).toString('hex') };
  const retained = await derive(f, [effect(f, 'anchor', null)]);
  assert.equal(retained.afterTree, objectId('tree', emptyEntry, format));
  assert.notEqual(retained.afterTree, empty); assert.equal(retained.rewrittenTrees.length, 1);
  assert.equal(retained.rewrittenTrees[0].entries, 1);
});
test('basis proof budgets remain independent of output budgets and cannot be widened', async () => {
  const f = changeFixture(), edits = [effect(f, 'src/main.rs', 'new')];
  const proof = await membership.verifyMembershipProof(f.value.membership, f.expected, webcrypto);
  assert.ok((await derive(f, edits, { membership: { maxTrees: proof.trees, maxEntries: proof.entries, maxTreeBytes: proof.treeBytes } })).afterTree);
  for (const membership of [{ maxTrees: proof.trees - 1 }, { maxEntries: proof.entries - 1 }, { maxTreeBytes: proof.treeBytes - 1 }]) {
    await assert.rejects(derive(f, edits, { membership }));
  }
  await assert.rejects(derive(f, edits, { output: { ignored: 1 } }));
  await assert.rejects(derive(f, edits, { unexpected: 1 }));
});
