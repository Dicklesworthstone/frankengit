// Exact sparse-absence and creation tests. Installed Git is an independent,
// nonproduction patch/tree oracle; no live Rust server result is implied.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import * as membership from '../../crates/fgit-node/src/smart_http/server/browser/search-context-membership.mjs';
import { readSourcePackage } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { changeFixture, hexPath, intent, replace, objectId } from './source_changes_fixture.mjs';
const creation = (path, text = 'new source\n', executable = false) => ({ path_hex: hexPath(path), operation: 'create', content_utf8: text, executable });
const draft = (f, rows, options) => buildSourceChanges(f.bytes, f.expected, intent(rows), options);
function sparse(format = 'sha1') {
  const f = changeFixture(format, [
    { path: 'anchor', bytes: 'root\n' }, { path: 'src/old', bytes: 'old\n' },
    { path: 'src/hidden', bytes: 'not selected\n' }, { path: 'opaque/existing', bytes: 'unproved subtree\n' },
    { path: 'link', bytes: 'src', mode: 0o120000 }, { path: 'module', bytes: '', mode: 0o160000 },
  ]);
  const chosen = new Set(['anchor', 'src/old'].map(hexPath)), parents = new Set([null, hexPath('src')]);
  f.expected.files = f.expected.files.filter(file => chosen.has(file.pathHex));
  f.value.membership.files = f.value.membership.files.filter(file => chosen.has(file.pathHex));
  f.value.membership.trees = f.value.membership.trees.filter(tree => parents.has(tree.pathHex));
  const ids = new Set(f.expected.files.map(file => file.blob));
  f.value.blobs = f.value.blobs.filter(blob => ids.has(blob.oid));
  f.bytes = Buffer.from(JSON.stringify(f.value));
  return f;
}
const prove = (f, paths, check = () => {}, limits = {}) => membership.verifyPathAbsence(
  f.value.membership, f.expected, paths.map(hexPath).sort(), webcrypto, check, limits);
for (const format of ['sha1', 'sha256']) {
  test(`${format}: complete parent trees prove absent siblings and new directory chains`, async () => {
    const f = sparse(format);
    assert.equal((await readSourcePackage(f.bytes, f.expected, webcrypto)).verified.files.length, 2);
    const result = await prove(f, ['newdir/deep/new.rs', 'src/new.rs', 'new']);
    assert.equal(result.commit, f.commit); assert.equal(result.rootTree, f.tree);
    assert.equal(result.pathAbsenceVerified, true); assert.equal(result.authorityVerified, false);
    assert.equal(result.freshnessVerified, false); assert.equal(result.publicationAuthorized, false);
    assert.deepEqual(result.paths.map(p => [p.pathHex, p.absentPrefixHex, p.parentPathHex]), [
      [hexPath('new'), hexPath('new'), null], [hexPath('newdir/deep/new.rs'), hexPath('newdir'), null],
      [hexPath('src/new.rs'), hexPath('src/new.rs'), hexPath('src')],
    ]);
    assert.equal(result.paths[0].parentTree, f.tree);
    assert.deepEqual(await prove(f, ['new', 'src/new.rs', 'newdir/deep/new.rs']), result);
  });
  test(`${format}: absence of a file body or parent subtree is not an absence proof`, async () => {
    const f = sparse(format);
    for (const name of ['anchor', 'src/hidden', 'src', 'opaque', 'link', 'module']) {
      await assert.rejects(prove(f, [name]), /already exists/);
    }
    await assert.rejects(prove(f, ['opaque/new.rs']), /parent tree is not proved/);
    for (const name of ['anchor/child', 'link/child', 'module/child']) await assert.rejects(prove(f, [name]), /ancestor is not a directory/);
    assert.equal((await prove(f, ['src/new.rs'])).paths.length, 1);
    await assert.rejects(prove(f, ['new.rs', 'src/hidden']), /already exists/); // no successful prefix
  });
  test(`${format}: corrupt, truncated or substituted proof cannot establish absence`, async () => {
    const f = sparse(format);
    for (const mutate of [v => { v.membership.trees.pop(); }, v => { v.membership.trees[0].bodyHex += '00'; },
      v => { v.membership.commit.bodyHex += '00'; }, v => { v.membership.trees[0].oid = 'e'.repeat(format === 'sha1' ? 40 : 64); }]) {
      const value = structuredClone(f.value); mutate(value);
      await assert.rejects(membership.verifyPathAbsence(value.membership, f.expected, [hexPath('new')], webcrypto));
    }
    const changed = sparse(format), expected = structuredClone(f.expected); expected.commit = 'f'.repeat(format === 'sha1' ? 40 : 64);
    await assert.rejects(membership.verifyPathAbsence(changed.value.membership, expected, [hexPath('new')], webcrypto));
    assert.equal((await prove(f, ['new'])).pathAbsenceVerified, true);
  });
  test(`${format}: new file before-images are null and creation intent is hash-bound`, async () => {
    const f = sparse(format), rows = [creation('newdir/a.rs', 'fn a() {}\r\n', true), creation('src/new.rs', ''), replace('src/old', 'updated\n')];
    const result = await draft(f, rows);
    assert.equal(result.manifest.creation_preconditions.profile, 'frankengit-context-path-absence-v1');
    assert.equal(result.manifest.creation_preconditions.paths.length, 2);
    const effects = new Map(result.manifest.effects.map(e => [e.path_hex, e]));
    for (const name of ['newdir/a.rs', 'src/new.rs']) { assert.equal(effects.get(hexPath(name)).old_blob, null); assert.equal(effects.get(hexPath(name)).old_mode, null); }
    assert.equal(effects.get(hexPath('newdir/a.rs')).new_mode, 0o100755);
    assert.equal(effects.get(hexPath('src/new.rs')).new_blob, objectId('blob', Buffer.alloc(0), format));
    assert.match(result.bytes.toString(), /new file mode 100755/);
    assert.deepEqual(await draft(f, [...rows].reverse()), result);
    assert.notEqual(sha256(canonical((await draft(f, [creation('newdir/b.rs')])).manifest)), sha256(canonical(result.manifest)));
  });
  test(`${format}: create never silently replaces a selected, hidden or nonregular entry`, async () => {
    const f = sparse(format);
    for (const path of ['anchor', 'src/hidden', 'src', 'link', 'module', 'opaque']) await assert.rejects(draft(f, [creation(path)]), /already exists/);
    await assert.rejects(draft(f, [creation('opaque/new')]), /parent tree is not proved/);
    for (const path of ['anchor/child', 'link/child', 'module/child']) await assert.rejects(draft(f, [creation(path)]), /ancestor is not a directory/);
    await assert.rejects(draft(f, [replace('missing', 'x')]), { code: 'source_changes_unselected_path' });
    assert.ok((await draft(f, [creation('missing')])).bytes.length > 0);
  });
  test(`${format}: caller mutation cannot replace the independent basis or creation after-image`, async () => {
    const f = sparse(format), bytes = Buffer.from(f.bytes), expected = structuredClone(f.expected), changes = intent([creation('new')]);
    const pending = buildSourceChanges(bytes, expected, changes);
    bytes.fill(0); expected.commit = 'e'.repeat(40); expected.files.length = 0;
    changes.changes[0].path_hex = hexPath('anchor'); changes.changes[0].content_utf8 = 'wrong';
    const actual = await pending;
    assert.equal(actual.manifest.source_commit, f.commit); assert.equal(actual.manifest.effects[0].path_hex, hexPath('new'));
    assert.equal(actual.manifest.effects[0].new_blob, objectId('blob', Buffer.from('new source\n'), format));
    const proof = structuredClone(f.value.membership), pins = structuredClone(f.expected), paths = [hexPath('new')];
    const verifying = membership.verifyPathAbsence(proof, pins, paths, webcrypto);
    proof.trees.length = 0; pins.files.length = 0; paths[0] = hexPath('anchor');
    assert.equal((await verifying).paths[0].pathHex, hexPath('new'));
  });
  test(`${format}: the complete mixed-create patch agrees with an independent installed-Git tree`, async () => {
    const f = changeFixture(format, [{ path: 'anchor', bytes: 'root\n' }, { path: 'src/old', bytes: 'old\n' }, { path: 'remove', bytes: 'gone\n' }]);
    const raw = Buffer.from([0x73, 0x72, 0x63, 47, 255, 34, 92, 10]);
    const result = await draft(f, [creation(raw, 'no final newline', true), creation('new/sub/file', '\uFEFFα\r\n'), creation('empty', ''),
      replace('src/old', 'updated\n'), { path_hex: hexPath('remove'), operation: 'delete' }]);
    const final = changeFixture(format, [{ path: 'anchor', bytes: 'root\n' }, { path: 'src/old', bytes: 'updated\n' },
      { path: raw, bytes: 'no final newline', mode: 0o100755 }, { path: 'new/sub/file', bytes: '\uFEFFα\r\n' }, { path: 'empty', bytes: '' }]);
    const root = await mkdtemp(join(tmpdir(), 'fg-create-oracle-'));
    const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_COUNT: '0', LC_ALL: 'C' };
    const git = (args, input) => execFileSync('git', ['-C', root, ...args], { env, input, timeout: 15000 });
    try {
      git(['init', '--quiet', `--object-format=${format}`]);
      for (const file of f.files) { const path = Buffer.concat([Buffer.from(root + '/'), file.path]); await mkdir(path.subarray(0, path.lastIndexOf(47)), { recursive: true }); await writeFile(path, file.bytes); }
      git(['add', '--all']); assert.equal(git(['write-tree']).toString().trim(), f.tree);
      git(['apply', '--cached', '--whitespace=nowarn', '-'], result.bytes);
      assert.equal(git(['write-tree']).toString().trim(), final.tree);
      for (const effect of result.manifest.effects.filter(e => e.old_blob === null)) assert.equal(effect.new_blob, final.files.find(f => f.path.toString('hex') === effect.path_hex).id);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
}
test('creation requires explicit mode and rejects aliases, duplicate and ancestor/descendant changes', async () => {
  const f = sparse();
  for (const row of [{ path_hex: hexPath('new'), operation: 'create', content_utf8: 'x' }, { ...creation('new'), executable: 1 },
    { ...creation('new'), before_utf8: 'old' }, { ...creation('new'), content_hex: '78' }]) await assert.rejects(draft(f, [row]));
  for (const path of ['.git/config', 'src/.GiT/a', '../escape', '/absolute', 'a//b', 'a/..', 'a\0']) await assert.rejects(draft(f, [creation(path)]));
  for (const rows of [[creation('a'), creation('a')], [creation('a'), creation('a/b')], [creation('a/b'), creation('a')],
    [{ path_hex: hexPath('anchor'), operation: 'delete' }, creation('anchor/child')]]) await assert.rejects(draft(f, rows));
  assert.ok((await draft(f, [creation('a/b'), creation('a/c')])).bytes.length);
});
test('absence path inventory and work bounds have exact permitted edges', async () => {
  const f = sparse(), paths = Array.from({ length: 32 }, (_, i) => `new${String(i).padStart(2, '0')}`);
  assert.equal((await prove(f, paths)).paths.length, 32);
  await assert.rejects(prove(f, [...paths, 'new32'])); await assert.rejects(prove(f, []));
  await assert.rejects(prove(f, ['x', 'x'])); await assert.rejects(prove(f, ['x', 'x/y']));
  await assert.rejects(membership.verifyPathAbsence(f.value.membership, f.expected, ['62', '61'], webcrypto));
  assert.equal((await prove(f, [Array(64).fill('n').join('/')])).paths.length, 1);
  await assert.rejects(prove(f, [Array(65).fill('n').join('/')]));
  const metadata = await membership.verifyMembershipProof(f.value.membership, f.expected, webcrypto);
  assert.equal((await prove(f, ['new'], () => {}, { maxEntries: metadata.entries, maxTreeBytes: metadata.treeBytes })).paths.length, 1);
  await assert.rejects(prove(f, ['new'], () => {}, { maxEntries: metadata.entries - 1 }));
  await assert.rejects(prove(f, ['new'], () => {}, { maxTreeBytes: metadata.treeBytes - 1 }));
});
test('creation charges retained bytes and exact patch limits before returning a draft', async () => {
  const f = sparse(); const full = await draft(f, [creation('new', '12345')]);
  assert.equal(full.manifest.retained_file_bytes, 5);
  assert.deepEqual(await draft(f, [creation('new', '12345')], { limits: { fileBytes: 5, totalBytes: 5, patchBytes: full.bytes.length } }), full);
  for (const limits of [{ fileBytes: 4 }, { totalBytes: 4 }, { patchBytes: full.bytes.length - 1 }]) await assert.rejects(draft(f, [creation('new', '12345')], { limits }));
  await assert.rejects(draft(f, [creation('new', '\0')]), { code: 'source_changes_binary_unsupported' });
  assert.ok((await draft(f, [creation('empty', '')])).bytes.length);
});
test('cancellation before and during proof verification never returns a partial creation', async () => {
  const f = sparse(), controller = new AbortController(); controller.abort();
  await assert.rejects(draft(f, [creation('new')], { signal: controller.signal }));
  let calls = 0; await prove(f, ['new'], () => { calls++; });
  for (const target of [1, Math.floor(calls / 2), calls]) {
    let at = 0; await assert.rejects(prove(f, ['new'], () => { if (++at === target) throw new Error('canceled proof'); }), /canceled proof/);
  }
  const mid = new AbortController(), promise = draft(f, [creation('new')], { signal: mid.signal });
  mid.abort(); await assert.rejects(promise);
  assert.equal((await draft(f, [creation('new')])).manifest.effects.length, 1);
});
test('existing-file draft bytes and review hashes remain compatible with d565b3bc', async () => {
  // Captured from the unchanged encoder/package/core at the recovered checkpoint.
  const pins = { sha1: ['36db8069c5c7d78f228abf8d7fb0570a04a0af9329f1492057ddef21265caf7e', '28e7702354712e693406d45f322aed70ae5873bb750a93dbde49a79d505422e5'],
    sha256: ['264ba9613ac1c68c765e4f5687d47ef62f623575122675e056ec4a210dc166d7', 'f44e022a8fff020b844adc6a739fc0aa7552505a07e7a89cdcaa6a2c41b6a9fc'] };
  for (const format of ['sha1', 'sha256']) {
    const f = changeFixture(format), result = await draft(f, [replace('src/main.rs', 'fn main() { new(); }\n'), replace('empty.txt', '')]);
    assert.deepEqual([sha256(canonical(result.manifest)), sha256(result.bytes)], pins[format]);
    assert.equal(Object.hasOwn(result.manifest, 'creation_preconditions'), false);
  }
});
