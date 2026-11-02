// Independent Git framing for local proof contracts; no server or authority mock.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { ownParentTreeBasis, parentTreeFileRows, PARENT_TREE_PROFILE } from '../../scripts/operator/source_edit_parent_trees.mjs';
import { editInput, validateSourceEdit, EDIT_PARENT_CAPTURE } from '../../scripts/operator/source_edit_candidate.mjs';
import { sourceChangeRequest } from '../../scripts/operator/source_changes_prepare.mjs';

const hex = value => Buffer.from(value).toString('hex');
const hash = (format, kind, bytes) => createHash(format).update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
function fixture(format = 'sha1', extras = 0, removeNested = false) {
  const width = format === 'sha1' ? 40 : 64;
  const entry = (mode, bytes) => ({ mode, oid: hash(format, 'blob', Buffer.from(bytes)) });
  const before = new Map(Object.entries({
    'dir/change': entry(0o100644, 'before\n'), 'dir/delete': entry(0o100644, 'remove\n'),
    'dir/tool': entry(0o100644, '#!/bin/false\n'), 'dir/kept': entry(0o100755, 'keep\0\xff'),
    'dir/nested/change': entry(0o100644, 'old nested\n'), 'dir/nested/kept': entry(0o100644, 'keep nested\n'),
    'dir/opaque/unread': entry(0o100644, 'do not fetch'), 'dir/link': entry(0o120000, '../../outside'),
    'dir/submodule': { mode: 0o160000, oid: 'e'.repeat(width) }, 'outside/keep': entry(0o100644, 'not selected'),
  }).map(([name, value]) => [hex(name), value]));
  before.set(Buffer.from('dir/raw\xff', 'latin1').toString('hex'), entry(0o100644, 'raw sibling'));
  before.set(hex('dir/new.'), entry(0o100644, 'directory ordering sibling'));
  before.set(Buffer.from([100, 105, 114, 47, 242, 241]).toString('hex'), entry(0o100644, 'unaligned hex slash sibling'));
  for (let i = 0; i < extras; i++) before.set(hex(`dir/extra-${String(i).padStart(5, '0')}`), entry(0o100644, 'bounded sibling'));
  const after = new Map(before);
  after.set(hex('dir/change'), entry(0o100755, '\0after\xff'));
  after.delete(hex('dir/delete'));
  after.set(hex('dir/tool'), { ...before.get(hex('dir/tool')), mode: 0o100755 });
  after.set(hex('dir/nested/change'), entry(0o100644, 'new nested\n'));
  after.set(hex('dir/new/data'), entry(0o100644, 'new\0file'));
  if (removeNested) { after.delete(hex('dir/nested/change')); after.delete(hex('dir/nested/kept')); }
  function trees(files) {
    const result = new Map();
    function directory(prefix) {
      const rows = new Map();
      for (const [path, value] of files) {
        const raw = Buffer.from(path, 'hex');
        if (!raw.subarray(0, prefix.length).equals(prefix)) continue;
        const suffix = raw.subarray(prefix.length), slash = suffix.indexOf(47);
        const name = slash < 0 ? suffix : suffix.subarray(0, slash), key = name.toString('hex');
        if (rows.has(key)) continue;
        rows.set(key, slash < 0 ? { name, ...value } : { name, mode: 0o40000,
          oid: directory(Buffer.concat([prefix, name, Buffer.from('/')])) });
      }
      const ordered = [...rows.values()].sort((a, b) => Buffer.compare(
        Buffer.concat([a.name, Buffer.from(a.mode === 0o40000 ? '/' : '\0')]),
        Buffer.concat([b.name, Buffer.from(b.mode === 0o40000 ? '/' : '\0')])));
      const bytes = Buffer.concat(ordered.map(r => Buffer.concat([Buffer.from(`${r.mode.toString(8)} `), r.name, Buffer.from([0]), Buffer.from(r.oid, 'hex')])));
      const oid = hash(format, 'tree', bytes);
      result.set(prefix.subarray(0, Math.max(0, prefix.length - 1)).toString('hex'), { oid, bodyHex: bytes.toString('hex') });
      return oid;
    }
    directory(Buffer.alloc(0)); return result;
  }
  const old = trees(before), next = trees(after);
  const body = Buffer.from(`tree ${old.get('').oid}\nauthor Proof <proof@example.invalid> 1 +0000\ncommitter Proof <proof@example.invalid> 1 +0000\n\nbase\n`);
  const commit = hash(format, 'commit', body), paths = [...new Set([...before.keys(), ...after.keys()])]
    .filter(p => JSON.stringify(before.get(p)) !== JSON.stringify(after.get(p))).sort();
  const basis = { commit: { oid: commit, bodyHex: body.toString('hex') }, trees: [...old]
    .filter(([p]) => p === '' || paths.some(path => path.startsWith(p + '2f')))
    .map(([p, row]) => ({ pathHex: p || null, ...row })) };
  const leaf = paths.map(p => ({ path_hex: p, kind: !before.has(p) ? 'added' : !after.has(p) ? 'deleted'
    : before.get(p).mode !== after.get(p).mode ? 'mode_changed' : 'modified', before: before.get(p) ?? null,
    after: after.get(p) ?? null, content: { type: 'binary', before_bytes: 0, after_bytes: 0, body_included: false } }));
  const directories = [...new Set([...old.keys(), ...next.keys()])].filter(p => p !== '' && old.get(p)?.oid !== next.get(p)?.oid)
    .map(p => ({ path_hex: p, kind: !old.has(p) ? 'added' : !next.has(p) ? 'deleted' : 'modified',
      before: old.has(p) ? { mode: 0o40000, oid: old.get(p).oid } : null,
      after: next.has(p) ? { mode: 0o40000, oid: next.get(p).oid } : null, content: { type: 'object_only', content_read: false } }));
  const rows = [...leaf, ...directories].sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
  const check = (r = rows, b = basis, target = next.get('').oid) => parentTreeFileRows(r, format, commit, paths, b, old.get('').oid, target);
  const selection = { endpoint: 'http://127.0.0.1:1/repository.git', scope: { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
    repository_incarnation: '3'.repeat(32), object_format: format }, ref: 'refs/heads/main', expected_commit: commit,
    metadata: { author: 'Proof <proof@example.invalid>', committer: 'Proof <proof@example.invalid>', timestamp: 2, message: 'edit\n' },
    paths_hex: paths, expected_result_tree: next.get('').oid, patch_profile: 'exact-tree-binary-v1', parent_tree_profile: PARENT_TREE_PROFILE };
  return { format, commit, basis, rows, leaf, check, old, next, paths, selection };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: partial trees preserve unselected regular, executable, raw, symlink, gitlink and opaque-subtree siblings`, () => {
    const f = fixture(format), copy = structuredClone(f.basis), result = f.check();
    assert.deepEqual(result, f.leaf); assert.deepEqual(f.basis, copy);
    assert.equal(f.basis.trees.length, 3); assert.equal(result.length, 5);
    assert.equal(f.basis.trees.some(t => t.pathHex === hex('dir/opaque')), false);
  });
  for (const [name, mutate] of [
    ['changed commit bytes', f => f.basis.commit.bodyHex += '00'],
    ['wrong commit', f => f.basis.commit.oid = 'd'.repeat(format === 'sha1' ? 40 : 64)],
    ['changed tree bytes', f => f.basis.trees[0].bodyHex += '00'],
    ['missing root', f => f.basis.trees = f.basis.trees.filter(t => t.pathHex !== null)],
    ['missing intermediate tree', f => f.basis.trees = f.basis.trees.filter(t => t.pathHex !== hex('dir'))],
    ['duplicate tree', f => f.basis.trees.push(structuredClone(f.basis.trees[0]))],
    ['unrelated tree', f => f.basis.trees.push({ pathHex: hex('outside'), ...f.old.get(hex('outside')) })],
    ['wrong old blob', f => f.rows.find(r => r.path_hex === hex('dir/change')).before.oid = 'f'.repeat(format === 'sha1' ? 40 : 64)],
    ['missing deletion', f => f.rows = f.rows.filter(r => r.path_hex !== hex('dir/delete'))],
    ['missing modified parent', f => f.rows = f.rows.filter(r => r.path_hex !== hex('dir/nested'))],
    ['wrong after directory', f => f.rows.find(r => r.path_hex === hex('dir')).after.oid = 'f'.repeat(format === 'sha1' ? 40 : 64)],
    ['unknown row field', f => f.rows[0].trusted = true],
    ['extra changed sibling', f => f.rows.push({ ...structuredClone(f.leaf[0]), path_hex: hex('zzz') })],
  ]) test(`${format}: ${name} refuses beside the unchanged permitted twin`, () => {
    const valid = fixture(format); valid.check();
    const f = fixture(format); mutate(f);
    assert.throws(() => parentTreeFileRows(f.rows, format, f.commit, f.paths, f.basis, f.old.get('').oid, f.next.get('').oid));
    assert.deepEqual(valid.check(), valid.leaf);
  });
  test(`${format}: complete resulting root and original hash domain remain mandatory`, () => {
    const f = fixture(format); assert.throws(() => f.check(f.rows, f.basis, 'f'.repeat(format === 'sha1' ? 40 : 64)));
    assert.throws(() => ownParentTreeBasis(f.basis, format === 'sha1' ? 'sha256' : 'sha1', f.commit, f.paths));
  });
  test(`${format}: proof order is canonicalized and caller-owned bytes cannot change the normalized request`, () => {
    const f = fixture(format), selection = { ...f.selection, parent_tree_basis: f.basis }, owned = editInput(selection);
    f.basis.trees.reverse(); f.basis.commit.bodyHex += '00';
    assert.notEqual(owned.parent_tree_basis.commit.bodyHex, f.basis.commit.bodyHex);
    assert.equal(owned.parent_tree_basis.trees[0].pathHex, null);
    assert.equal(editInput(owned).parent_tree_profile, PARENT_TREE_PROFILE);
  });
  test(`${format}: authoring binds package parent bytes only with explicit profile consent`, () => {
    const f = fixture(format), pkg = Buffer.from(JSON.stringify({ membership: { ...f.basis,
      trees: [...f.basis.trees, { pathHex: hex('outside'), ...f.old.get(hex('outside')) }] } }));
    const request = sourceChangeRequest(f.selection, pkg);
    assert.deepEqual(request.parent_tree_basis, ownParentTreeBasis(f.basis, format, f.commit, f.paths));
    const old = structuredClone(f.selection); delete old.parent_tree_profile;
    assert.equal(Object.hasOwn(sourceChangeRequest(old, pkg), 'parent_tree_basis'), false);
    const invalid = structuredClone(f.selection); invalid.parent_tree_profile = 'implicit';
    assert.throws(() => editInput(invalid));
  });
  test(`${format}: directory removal accounts for every original child`, () => {
    const f = fixture(format, 0, true);
    assert.deepEqual(f.check(), f.leaf);
    assert.equal(f.rows.find(row => row.path_hex === hex('dir/nested')).kind, 'deleted');
    const missing = f.rows.filter(row => row.path_hex !== hex('dir/nested/kept'));
    assert.throws(() => f.check(missing), /unreported_deletion/);
  });
  test(`${format}: deleting the final file verifies the native empty-root commitment`, () => {
    const blob = hash(format, 'blob', Buffer.from('last file'));
    const tree = Buffer.concat([Buffer.from('100644 last\0'), Buffer.from(blob, 'hex')]);
    const root = hash(format, 'tree', tree), empty = hash(format, 'tree', Buffer.alloc(0));
    const body = Buffer.from(`tree ${root}\nauthor T <t@example.invalid> 1 +0000\ncommitter T <t@example.invalid> 1 +0000\n\nbase\n`);
    const commit = hash(format, 'commit', body), path = hex('last');
    const basis = { commit: { oid: commit, bodyHex: body.toString('hex') }, trees: [{ pathHex: null, oid: root, bodyHex: tree.toString('hex') }] };
    const rows = [{ path_hex: path, kind: 'deleted', before: { mode: 0o100644, oid: blob }, after: null, content: { type: 'binary' } }];
    assert.deepEqual(parentTreeFileRows(rows, format, commit, [path], basis, root, empty), rows);
  });
}

test('tree inventory and byte ceilings apply before proof traversal', () => {
  const f = fixture();
  assert.throws(() => ownParentTreeBasis({ ...f.basis, trees: Array(129).fill(f.basis.trees[0]) }, f.format, f.commit, f.paths), /tree_limit/);
  const altered = structuredClone(f.basis); altered.trees[0].bodyHex = '00'.repeat(4 * 1024 * 1024 + 1);
  assert.throws(() => ownParentTreeBasis(altered, f.format, f.commit, f.paths), /parent_bytes/);
});

test('the parent entry ceiling has an exact permitted twin', () => {
  const count = basis => basis.trees.reduce((total, tree) => {
    const bytes = Buffer.from(tree.bodyHex, 'hex');
    for (let at = 0; at < bytes.length; total++) at = bytes.indexOf(0, at) + 21;
    return total;
  }, 0);
  const base = fixture(), permitted = fixture('sha1', 16384 - count(base.basis));
  assert.equal(count(permitted.basis), 16384);
  assert.equal(ownParentTreeBasis(permitted.basis, 'sha1', permitted.commit, permitted.paths).trees.length, 3);
  assert.deepEqual(permitted.check(), permitted.leaf);
  const refused = fixture('sha1', 16385 - count(base.basis));
  assert.throws(() => ownParentTreeBasis(refused.basis, 'sha1', refused.commit, refused.paths), /entry_limit/);
});
