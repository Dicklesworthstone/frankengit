import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyGitBundle, verifyGitBundleObjects, BundleVerificationError } from '../../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs';
import { bytes, objectId, bundle, webcrypto } from './bundle-verify-fixtures.mjs';
const options = { cryptoImpl: webcrypto };
const identity = 'Test <test@example.invalid> 1700000000 +0000';
const commit = (tree, parents = [], extra = '', message = bytes('message\n')) => Buffer.concat([
  bytes(`tree ${tree}\n${parents.map(id => `parent ${id}\n`).join('')}author ${identity}\ncommitter ${identity}\n${extra}\n`), message,
]);
const tree = entries => Buffer.concat(entries.map(({ name, id, mode = '100644' }) => Buffer.concat([bytes(`${mode} `), bytes(name), bytes([0]), Buffer.from(id, 'hex')])));
const tag = (id, kind = 'commit', extra = '') => bytes(`object ${id}\ntype ${kind}\ntag v1\n${extra}\nmessage\n`);
function rootBundle(kind, body, records = [], format = 'sha1') {
  const id = objectId(kind, body, format);
  return bundle([{ kind, body }, ...records], format, { refs: [{ name: kind === 'commit' ? 'refs/heads/main' : 'refs/tags/root', id }] });
}
function graph(format = 'sha1') {
  const records = {}, ids = {};
  const add = (name, kind, body) => { records[name] = { kind, body }; ids[name] = objectId(kind, body, format); return ids[name]; };
  add('blob', 'blob', bytes('file\0bytes\r\n')); add('link', 'blob', bytes('../never-follow-this'));
  add('nested', 'tree', tree([{ name: bytes([255, 10]), id: ids.link, mode: '120000' }]));
  add('tree', 'tree', tree([{ name: 'dir', id: ids.nested, mode: '40000' }, { name: 'exec', id: ids.blob, mode: '100755' },
    { name: 'file', id: ids.blob }, { name: 'module', id: '9'.repeat(format === 'sha1' ? 40 : 64), mode: '160000' }]));
  add('parent', 'commit', commit(ids.tree));
  add('commit', 'commit', commit(ids.tree, [ids.parent], `gpgsig opaque signature\n parent ${'e'.repeat(format === 'sha1' ? 40 : 64)}\n tree misleading continuation\n`, bytes([0xff, 0, 13, 10])));
  add('tag', 'tag', tag(ids.commit, 'commit', `tagger ${identity}\n`)); add('outer', 'tag', tag(ids.tag, 'tag'));
  const refs = [{ name: 'refs/heads/main', id: ids.commit }, { name: 'refs/tags/release', id: ids.outer }];
  return { records, ids, refs, input: bundle(Object.values(records), format, { refs }), format };
}
const fail = (input, code, limits = {}) => assert.rejects(verifyGitBundle(input, { ...options, limits }), e => e instanceof BundleVerificationError && e.code === code);
for (const format of ['sha1', 'sha256']) {
  test(`${format}: full typed closure covers history, nested/raw-name trees, symlinks, executables and nested tags`, async () => {
    const g = graph(format), result = await verifyGitBundle(g.input, options);
    assert.equal(result.object_closure_verified, true); assert.equal(result.closure_scope, 'advertised-direct-refs');
    assert.equal(result.reachable_objects, 8); assert.equal(result.unreachable_objects, 0);
    assert.deepEqual(result.object_kinds, { blob: 2, tree: 2, commit: 2, tag: 2 });
    assert.equal(result.gitlink_entries, 1); assert.equal(result.reachable_gitlink_entries, 1);
    for (const key of ['gitlink_targets_verified', 'forge_state_verified', 'independently_authenticated', 'signatures_verified', 'author_identity_verified', 'fsck_equivalent']) assert.equal(result[key], false);
  });
  for (const missing of ['link', 'nested', 'tree', 'parent', 'tag']) test(`${format}: matching pack/object checksums cannot hide a missing ${missing}`, async () => {
    const g = graph(format), records = Object.entries(g.records).filter(([key]) => key !== missing).map(([, value]) => value);
    const input = bundle(records, format, { refs: g.refs });
    assert.equal((await verifyGitBundleObjects(input, options)).objects_verified, true, 'checksum/object-only checking demonstrably misses this failure');
    await assert.rejects(verifyGitBundle(input, options), error => {
      assert.equal(error.code, 'missing_reachable_object'); assert.equal(error.details.target_object, g.ids[missing]); return true;
    });
  });
  test(`${format}: object kind is checked even for an already visited shared target`, async () => {
    const blob = bytes('target'), id = objectId('blob', blob, format), body = tree([
      { name: 'a', id }, { name: 'z', id, mode: '40000' },
    ]);
    await fail(rootBundle('tree', body, [{ kind: 'blob', body: blob }], format), 'reachable_object_type_mismatch');
  });
  test(`${format}: tag declared type and commit tree/parent types cannot substitute`, async () => {
    const blob = bytes('target'), id = objectId('blob', blob, format), records = [{ kind: 'blob', body: blob }];
    await fail(rootBundle('tag', tag(id, 'tree'), records, format), 'reachable_object_type_mismatch');
    await fail(rootBundle('commit', commit(id), records, format), 'reachable_object_type_mismatch');
    const empty = bytes(''), treeId = objectId('tree', empty, format);
    await fail(rootBundle('commit', commit(treeId, [id]), [...records, { kind: 'tree', body: empty }], format), 'reachable_object_type_mismatch');
  });
}
test('native directory-slash order differs from simple byte-name order', async () => {
  const blob = bytes('x'), blobId = objectId('blob', blob), empty = bytes(''), treeId = objectId('tree', empty);
  const entries = [{ name: 'a.c', id: blobId }, { name: 'a', id: treeId, mode: '40000' }, { name: 'a0', id: blobId }];
  const records = [{ kind: 'blob', body: blob }, { kind: 'tree', body: empty }];
  assert.equal((await verifyGitBundle(rootBundle('tree', tree(entries), records), options)).reachable_objects, 3);
  await fail(rootBundle('tree', tree([entries[1], entries[0], entries[2]]), records), 'noncanonical_tree_order');
});
test('leading-zero legacy mode bytes remain hashed verbatim, not silently normalized', async () => {
  const empty = bytes(''), id = objectId('tree', empty), body = tree([{ name: 'dir', id, mode: '040000' }]);
  const result = await verifyGitBundle(rootBundle('tree', body, [{ kind: 'tree', body: empty }]), options);
  assert.equal(result.refs[0].object_id, objectId('tree', body)); assert.equal(result.reachable_objects, 2);
});
for (const name of ['', '.', '..', '.git', '.GiT', 'a/b']) test(`unsafe tree name ${JSON.stringify(name)} refuses`, async () => {
  const blob = bytes('x'), body = tree([{ name, id: objectId('blob', blob) }]);
  await fail(rootBundle('tree', body, [{ kind: 'blob', body: blob }]), name ? 'unsafe_tree_name' : 'invalid_tree_entry');
});
test('duplicate tree names cannot hide behind different modes', async () => {
  const blob = bytes('x'), id = objectId('blob', blob), empty = bytes(''), treeId = objectId('tree', empty);
  await fail(rootBundle('tree', tree([{ name: 'same', id }, { name: 'same', id: treeId, mode: '40000' }]),
    [{ kind: 'blob', body: blob }, { kind: 'tree', body: empty }]), 'duplicate_tree_name');
});
for (const mode of ['100600', '100664', '777777', '100648', '0000000']) test(`unimplemented or malformed native tree mode ${mode} refuses`, async () => {
  const blob = bytes('x'), body = tree([{ name: 'file', id: objectId('blob', blob), mode }]);
  await fail(rootBundle('tree', body, [{ kind: 'blob', body: blob }]), ['100648', '0000000'].includes(mode) ? 'invalid_tree_mode' : 'unsupported_tree_mode');
});
test('tree entry truncation and zero targets cannot become empty-directory success', async () => {
  await fail(rootBundle('tree', bytes('100644 file\0short')), 'invalid_tree_entry');
  await fail(rootBundle('tree', tree([{ name: 'file', id: '0'.repeat(40) }])), 'zero_tree_target');
});
test('only actual reference headers create dependencies; signatures and binary messages do not', async () => {
  const empty = bytes(''), id = objectId('tree', empty), body = commit(id, [], 'encoding ISO-8859-1\ngpgsig x\n parent not-an-edge\n tree not-an-edge\nmergetag embedded\n object not-an-edge\n', bytes('parent in message\0\xff'));
  assert.equal((await verifyGitBundle(rootBundle('commit', body, [{ kind: 'tree', body: empty }]), options)).reachable_objects, 2);
});
test('ambiguous, continued, misplaced and incomplete commit reference headers fail closed', async () => {
  const empty = bytes(''), id = objectId('tree', empty), base = commit(id).toString(), records = [{ kind: 'tree', body: empty }];
  for (const [body, code] of [
    [base.replace(`tree ${id}\n`, `tree ${id}\n continued\n`), 'continued_reference_or_identity_header'],
    [base.replace('\n\nmessage', `\ntree ${id}\n\nmessage`), 'ambiguous_commit_tree'],
    [base.replace('\n\nmessage', `\nparent ${id}\n\nmessage`), 'misplaced_commit_parent'],
    [base.replace(`author ${identity}\n`, ''), 'invalid_commit_committer_header'],
    [base.replace(`committer ${identity}\n`, ''), 'incomplete_commit_headers'],
    [base.replace(`author ${identity}`, `author ${identity}\0`), 'invalid_object_header'],
    [base.replace('\n\n', '\n').replace(/\n$/, ''), 'unterminated_object_header'],
  ]) await fail(rootBundle('commit', bytes(body), records), code);
});
test('tag target metadata must be complete and unambiguous', async () => {
  const blob = bytes('x'), id = objectId('blob', blob), records = [{ kind: 'blob', body: blob }], good = tag(id, 'blob');
  assert.equal((await verifyGitBundle(rootBundle('tag', good, records), options)).reachable_objects, 2);
  for (const [body, code] of [
    [good.toString().replace('type blob', 'type planet'), 'invalid_tag_target_type'],
    [good.toString().replace('tag v1\n', ''), 'incomplete_tag_headers'],
    [good.toString().replace('type blob\n', 'type blob\n continued\n'), 'continued_reference_or_identity_header'],
    [good.toString().replace('\n\nmessage', `\nobject ${id}\n\nmessage`), 'ambiguous_tag_target'],
  ]) await fail(rootBundle('tag', bytes(body), records), code);
});
test('transport-only objects are reported, not silently included in advertised closure', async () => {
  const g = graph(), extra = { kind: 'commit', body: commit(g.ids.tree, ['e'.repeat(40)], '', bytes('unreachable delta base')) };
  const input = bundle([...Object.values(g.records), extra], 'sha1', { refs: g.refs });
  const result = await verifyGitBundle(input, options);
  assert.equal(result.reachable_objects, 8); assert.equal(result.unreachable_objects, 1); assert.equal(result.object_closure_verified, true);
  // Advertising that same extra object turns its absent parent into a real
  // closure failure, without changing any packed bytes or object identities.
  const exposed = bundle([...Object.values(g.records), extra], 'sha1', { refs: [...g.refs, { name: 'refs/heads/extra', id: objectId('commit', extra.body) }] });
  await fail(exposed, 'missing_reachable_object');
});
test('metadata and link budgets have exact permitted and refused twins', async () => {
  const input = graph().input, result = await verifyGitBundle(input, options);
  assert.equal((await verifyGitBundle(input, { ...options, limits: { maxMetadataBytes: result.metadata_bytes, maxLinks: result.parsed_links, maxWork: result.work } })).object_closure_verified, true);
  await fail(input, 'metadata_byte_limit', { maxMetadataBytes: result.metadata_bytes - 1 });
  await fail(input, 'object_link_limit', { maxLinks: result.parsed_links - 1 });
  await fail(input, 'work_limit', { maxWork: result.work - 1 });
});
test('iterative closure walks deep history without recursive stack overflow', async () => {
  const empty = bytes(''), treeId = objectId('tree', empty), records = [{ kind: 'tree', body: empty }]; let parent = null;
  for (let n = 0; n < 1500; n++) { const body = commit(treeId, parent ? [parent] : [], '', bytes(String(n))); parent = objectId('commit', body); records.push({ kind: 'commit', body }); }
  const input = bundle(records, 'sha1', { refs: [{ name: 'refs/heads/main', id: parent }] });
  const result = await verifyGitBundle(input, options); assert.equal(result.reachable_objects, 1501); assert.equal(result.reachable_links, 2999);
});
test('defensive cycle refusal uses a controlled digest seam, not a claimed Git collision fixture', async () => {
  const empty = bytes(''), treeId = objectId('tree', empty), a = 'a'.repeat(40), b = 'b'.repeat(40);
  const bodyA = commit(treeId, [b], '', bytes('A')), bodyB = commit(treeId, [a], '', bytes('B'));
  const input = bundle([{ kind: 'tree', body: empty }, { kind: 'commit', body: bodyA }, { kind: 'commit', body: bodyB }], 'sha1',
    { refs: [{ name: 'refs/heads/main', id: a }] });
  const cryptoImpl = { subtle: { async digest(algorithm, data) {
    const value = Buffer.from(data);
    if (algorithm === 'SHA-1' && value.subarray(0, 7).toString() === 'commit ') return Buffer.from(value.at(-1) === 65 ? a : b, 'hex');
    return webcrypto.subtle.digest(algorithm, data);
  } } };
  await assert.rejects(verifyGitBundle(input, { cryptoImpl }), error => error.code === 'cyclic_object_graph');
});
test('interruption at each closure checkpoint never returns a partial proof', async () => {
  const input = graph().input; let objectChecks = 0, allChecks = 0;
  await verifyGitBundleObjects(input, { ...options, checkpoint() { objectChecks++; } });
  await verifyGitBundle(input, { ...options, checkpoint() { allChecks++; } });
  assert.ok(allChecks > objectChecks);
  for (let interrupt = objectChecks + 1; interrupt <= allChecks; interrupt++) {
    let checks = 0;
    await assert.rejects(verifyGitBundle(input, { ...options, checkpoint() { if (++checks === interrupt) throw new Error('interrupted closure'); } }), /interrupted closure/);
  }
  assert.deepEqual(await verifyGitBundle(input, options), await verifyGitBundle(input, options));
});
