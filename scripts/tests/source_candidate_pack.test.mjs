// Real Git-generated native-shaped packs. HTTP reports remain explicit fixtures,
// not a running Rust node or independent evidence of repository authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { prepareSourceChanges, verifySourceChangeCandidate } from '../operator/source_changes_prepare.mjs';
import { verifySourceCandidatePack } from '../operator/source_candidate_pack.mjs';
import { verifyGitBundleObjects } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';
import { nativePeer, TOKEN } from './source_changes_native_fixture.mjs';
import { intent, replace, hexPath } from './source_changes_fixture.mjs';
import { selectSource } from './source_replay_fixture.mjs';

async function setup(t, format = 'sha1', rows = null, files = undefined) {
  const peer = await nativePeer(format, { nativePatchBundle: true, files }); t.after(() => peer.close());
  const f = peer.fixture, changes = intent(rows ?? [replace('src/main.rs', 'fn main() { changed(); }\n')]);
  const draft = await buildSourceChanges(f.bytes, f.expected, changes), confirmDraftSha256 = sha256(canonical(draft.manifest));
  const c = await prepareSourceChanges(f.bytes, f.expected, changes, peer.selection(draft.manifest.effects.map(e => e.path_hex)), TOKEN, { confirmDraftSha256 });
  assert.deepEqual(peer.failures, []);
  const verify = (capture = c.capture, bundle = c.bundle, extra = {}) => verifySourceCandidatePack(f.bytes, f.expected, changes, capture, bundle, { confirmDraftSha256, ...extra });
  return { peer, f, changes, draft, c, confirmDraftSha256, verify };
}
function withBundle(s, bytes) {
  const capture = structuredClone(s.c.capture), bundle = Buffer.from(bytes);
  capture.preparation.bundle = { bytes: bundle.length, sha256: sha256(bundle) };
  capture.inspection.bundle_bytes = bundle.length; capture.inspection.bundle_sha256 = sha256(bundle);
  return { capture, bundle };
}
async function oldAccepts(s, modified) {
  const result = await verifySourceChangeCandidate(s.f.bytes, s.f.expected, s.changes, modified.capture, modified.bundle,
    { confirmDraftSha256: s.confirmDraftSha256 });
  assert.equal(result.binding.candidate_root_matches_exact_effects, true);
  assert.equal(result.binding.bundle_objects_independently_verified, false);
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: verify actual native-shaped packed objects without claiming absent base closure`, async t => {
    const s = await setup(t, format), input = Buffer.from(s.c.bundle), result = await s.verify();
    assert.deepEqual(result.bundle, input);
    assert.equal(result.verification.bundle_sha256, sha256(input));
    assert.equal(result.verification.expected_object_count, s.peer.packedIds.length);
    assert.equal(result.verification.exact_object_inventory_verified, true);
    assert.equal(result.verification.packed_objects_independently_verified, true);
    for (const key of ['base_closure_verified', 'complete_repository', 'authority_verified', 'publication_authorized', 'pack_bytes_rewritten']) assert.equal(result.verification[key], false);
    // The public self-contained entrypoint must STILL refuse this original
    // incremental artifact. Verification never weakens that existing contract.
    await assert.rejects(verifyGitBundleObjects(input), /prerequisites_not_self_contained/);
  });
  test(`${format}: old report checks accept rehashed corrupt pack; independent decoder refuses it`, async t => {
    const s = await setup(t, format), corrupt = Buffer.from(s.c.bundle); corrupt[corrupt.length - 1] ^= 1;
    const altered = withBundle(s, corrupt); await oldAccepts(s, altered);
    await assert.rejects(s.verify(altered.capture, altered.bundle), /pack_checksum_mismatch/);
  });
  test(`${format}: missing changed blob and missing rewritten tree are not satisfied by original source`, async t => {
    const s = await setup(t, format);
    for (const kind of ['blob', 'tree', 'commit']) {
      const omitted = s.peer.packedIds.find(id => s.peer.objectKind(id) === kind); assert.ok(omitted);
      const altered = withBundle(s, Buffer.concat([s.peer.packHeader, s.peer.packObjects(s.peer.packedIds.filter(id => id !== omitted))]));
      await oldAccepts(s, altered);
      await assert.rejects(s.verify(altered.capture, altered.bundle), /advertised_object_missing/);
    }
  });
  test(`${format}: extra object and same-count substitution cannot launder incomplete materialization`, async t => {
    const s = await setup(t, format), extra = s.f.files.find(f => f.path.toString() === 'empty.txt').id;
    assert.ok(!s.peer.packedIds.includes(extra));
    for (const ids of [[...s.peer.packedIds, extra], [...s.peer.packedIds.filter(id => s.peer.objectKind(id) !== 'blob'), extra]]) {
      const altered = withBundle(s, Buffer.concat([s.peer.packHeader, s.peer.packObjects(ids)])); await oldAccepts(s, altered);
      await assert.rejects(s.verify(altered.capture, altered.bundle), /object_count_limit|advertised_object_missing/);
    }
  });
  test(`${format}: precise original base, ref and candidate envelope is mandatory`, async t => {
    const s = await setup(t, format), header = s.peer.packHeader.toString(), pack = s.c.bundle.subarray(s.peer.packHeader.length);
    const changed = [header.replace(s.f.commit, 'e'.repeat(s.f.commit.length)), header.replace('refs/heads/main', 'refs/heads/other'),
      header.replace(' patch base', ' arbitrary label'), header.replace(`-${s.f.commit} patch base\n`, ''),
      header.replace('\n\n', `\n${s.c.candidate_commit} refs/heads/extra\n\n`), header.replace(s.c.candidate_commit, s.f.commit)];
    for (const next of changed) {
      const altered = withBundle(s, Buffer.concat([Buffer.from(next), pack])); await oldAccepts(s, altered);
      await assert.rejects(s.verify(altered.capture, altered.bundle), /source_pack_envelope/);
    }
  });
  test(`${format}: mixed create/delete/mode/copy preserves exact deduplicated object inventory`, async t => {
    const files = [{ path: 'dir/a', bytes: 'identical\n' }, { path: 'dir/b', bytes: 'delete me\n' }, { path: 'empty', bytes: '' }];
    const s = await setup(t, format, [
      { operation: 'mode', path_hex: hexPath('dir/a'), executable: true },
      { operation: 'copy', from_path_hex: hexPath('empty'), path_hex: hexPath('new/deep/empty') },
      { operation: 'delete', path_hex: hexPath('dir/b') },
      { operation: 'create', path_hex: hexPath('same'), content_utf8: 'identical\n', executable: false },
    ], files);
    const r = await s.verify(); assert.equal(r.verification.expected_object_count, s.peer.packedIds.length);
    assert.ok(r.verification.expected_object_count < s.draft.tree.rewrittenTrees.length + s.draft.manifest.effects.length + 1);
  });
  test(`${format}: deleting the only file verifies the empty root but no obsolete blob`, async t => {
    const s = await setup(t, format, [{ operation: 'delete', path_hex: hexPath('dir/only') }], [{ path: 'dir/only', bytes: 'old\n' }]);
    const r = await s.verify(); assert.equal(r.verification.expected_object_count, 2);
    assert.equal(s.draft.tree.rewrittenTrees.find(t => t.pathHex === hexPath('dir')).afterTree, null);
  });
}

test('checks reported count, exact decoder limits and malformed options', async t => {
  const s = await setup(t), r = await s.verify(), count = r.verification.expected_object_count;
  const c = structuredClone(s.c.capture); c.preparation.object_count++;
  await assert.rejects(s.verify(c), /source_pack_reported_count/);
  await s.verify(s.c.capture, s.c.bundle, { limits: { maxObjects: count, maxRefs: count, maxExpandedBytes: r.verification.expanded_bytes, maxWork: r.verification.decoder_work } });
  for (const limits of [{ maxObjects: count - 1 }, { maxRefs: count - 1 }, { maxExpandedBytes: r.verification.expanded_bytes - 1 },
    { maxWork: r.verification.decoder_work - 1 }, { maxHeaderBytes: 1 }, { maxInputBytes: 1 }, { maxObjects: 0 }, { maxObjects: 32769 }, { unexpected: 2 }]) {
    await assert.rejects(s.verify(s.c.capture, s.c.bundle, { limits }));
  }
  await assert.rejects(s.verify(s.c.capture, s.c.bundle, { ca: Buffer.from('not an offline option') }), /source_edit_fields/);
  await assert.rejects(s.verify(s.c.capture, s.c.bundle, { confirmDraftSha256: 'e'.repeat(64) }), /source_changes_confirmation/);
});
test('owns capture and buffer inputs before asynchronous source verification', async t => {
  const s = await setup(t), bundle = Buffer.from(s.c.bundle), capture = structuredClone(s.c.capture);
  const task = s.verify(capture, bundle); bundle.fill(0); capture.request.ref = 'refs/heads/other';
  const r = await task; assert.equal(r.verification.bundle_sha256, sha256(s.c.bundle)); assert.deepEqual(r.bundle, s.c.bundle);
});
test('cancellation produces no verified subset, deadline covers source and pack', async t => {
  const s = await setup(t); const stop = new AbortController(); stop.abort();
  await assert.rejects(s.verify(s.c.capture, s.c.bundle, { signal: stop.signal }), /cancelled/);
  const during = new AbortController(), task = s.verify(s.c.capture, s.c.bundle, { signal: during.signal }); during.abort();
  await assert.rejects(task, /cancelled|Abort/);
  await assert.rejects(s.verify(s.c.capture, s.c.bundle, { timeoutMs: 1 }));
});
test('valid checksum cannot hide a damaged zlib stream or extra bytes after declared pack objects', async t => {
  const s = await setup(t), format = s.f.format, raw = s.c.bundle.subarray(s.peer.packHeader.length), width = 20;
  const trailer = bytes => Buffer.concat([bytes, createHash(format).update(bytes).digest()]);
  // Git pack record at 12: skip the bounded object-size varint to its zlib CMF.
  let at = 12; while (raw[at++] & 128) {}
  const damaged = Buffer.from(raw.subarray(0, -width)); damaged[at] = 0;
  const trailing = Buffer.concat([raw.subarray(0, -width), Buffer.from([42])]);
  for (const body of [damaged, trailing]) {
    const altered = withBundle(s, Buffer.concat([s.peer.packHeader, trailer(body)])); await oldAccepts(s, altered);
    await assert.rejects(s.verify(altered.capture, altered.bundle), /invalid_zlib_header|pack_count_or_trailing_bytes/);
  }
});
test('sparse original proof does not require fetching untouched subtree bodies', async t => {
  const s = await setup(t), sparse = selectSource(s.f, ['src/main.rs']);
  const draft = await buildSourceChanges(sparse.bytes, sparse.expected, s.changes), hash = sha256(canonical(draft.manifest));
  // Package identity changes the draft, but not the patch, tree or candidate.
  const r = await verifySourceCandidatePack(sparse.bytes, sparse.expected, s.changes, s.c.capture, s.c.bundle, { confirmDraftSha256: hash });
  assert.equal(r.verification.expected_tree, s.draft.tree.afterTree); assert.equal(r.verification.base_closure_verified, false);
});
for (const format of ['sha1', 'sha256']) {
  test(`${format}: verify binary and compact after-images with deduplicated copied blobs`, async t => {
    const body = Buffer.concat([Buffer.from(Array.from({ length: 256 }, (_, i) => i)), Buffer.from('\n')]);
    const peer = await nativePeer(format, { nativePatchBundle: true, files: [{ path: 'binary', bytes: body }] }); t.after(() => peer.close());
    const f = peer.fixture, changes = { ...intent([
      { operation: 'copy', from_path_hex: hexPath('binary'), path_hex: hexPath('a/new'), executable: true },
      { operation: 'copy', from_path_hex: hexPath('binary'), path_hex: hexPath('b/new'), executable: true },
    ]), byte_profile: 'binary-safe-v1', patch_profile: 'trim-common-lines-v1' };
    const draft = await buildSourceChanges(f.bytes, f.expected, changes), confirmDraftSha256 = sha256(canonical(draft.manifest));
    const c = await prepareSourceChanges(f.bytes, f.expected, changes, peer.selection(draft.manifest.effects.map(e => e.path_hex)), TOKEN, { confirmDraftSha256 });
    const r = await verifySourceCandidatePack(f.bytes, f.expected, changes, c.capture, c.bundle, { confirmDraftSha256 });
    // Two new directories have identical bytes/IDs: the native pack deduplicates
    // both the copied blob and those trees while keeping two path memberships.
    assert.equal(r.verification.expected_object_count, 4);
    assert.deepEqual(peer.failures, []);
  });
  test(`${format}: mode-only output still requires its emitted original blob`, async t => {
    const s = await setup(t, format, [{ operation: 'mode', path_hex: hexPath('run.sh'), executable: false }]);
    const r = await s.verify(); assert.equal(r.verification.expected_object_count, 3);
    const old = s.f.files.find(f => f.path.toString() === 'run.sh').id;
    assert.ok(s.peer.packedIds.includes(old));
    const altered = withBundle(s, Buffer.concat([s.peer.packHeader, s.peer.packObjects(s.peer.packedIds.filter(id => id !== old))]));
    await assert.rejects(s.verify(altered.capture, altered.bundle), /advertised_object_missing/);
  });
}
test('near-limit source with compact patch verifies the actual expanded candidate bytes', async t => {
  const old = Buffer.from('a sufficiently long unchanged line\n'.repeat(28000));
  const peer = await nativePeer('sha1', { nativePatchBundle: true, files: [{ path: 'large', bytes: old }] }); t.after(() => peer.close());
  const f = peer.fixture, changes = { ...intent([{ path_hex: hexPath('large'), operation: 'splice',
    splices: [{ byte_offset: old.length - 35, before_hex: old.subarray(old.length - 35, old.length - 34).toString('hex'), after_utf8: 'Z' }] }]),
    patch_profile: 'trim-common-lines-v1' };
  const draft = await buildSourceChanges(f.bytes, f.expected, changes), confirmDraftSha256 = sha256(canonical(draft.manifest));
  assert.ok(draft.bytes.length < 1024);
  const c = await prepareSourceChanges(f.bytes, f.expected, changes, peer.selection([hexPath('large')]), TOKEN, { confirmDraftSha256 });
  const r = await verifySourceCandidatePack(f.bytes, f.expected, changes, c.capture, c.bundle, { confirmDraftSha256 });
  assert.ok(r.verification.expanded_bytes >= old.length);
  assert.ok(r.verification.bundle_bytes < old.length / 10);
});
