// Real Git-produced packs, HTTP/TLS peers and private files. Peers model native
// source schemas; these are not Rust admission/authority or full-repository tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, lstat, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { prepareSourceChanges, verifySourceChangeCandidate } from '../operator/source_changes_prepare.mjs';
import { preparePackedSourceChanges, inspectPackedSourceChanges, stagePackedSourceChanges } from '../operator/source_candidate_pack_flow.mjs';
import { saveSourceEdit, inspectSourceApply, dispatchSourceApply, recoverSourceApply } from '../operator/source_edit_publish.mjs';
import { BUNDLE_VERIFY_LIMITS } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
import { hexPath, intent } from './source_changes_fixture.mjs';
const absent = async path => assert.rejects(lstat(path), { code: 'ENOENT' });
async function setup(t, format = 'sha1', extra = {}) {
  const peer = await nativePeer(format, { nativePatchBundle: true, ...extra });
  const root = await mkdtemp(join(tmpdir(), 'fg-packed-flow-'));
  t.after(async () => { await peer.close(); await rm(root, { recursive: true, force: true }); });
  const f = peer.fixture, changes = intent([{ operation: 'replace-once', path_hex: hexPath('src/main.rs'),
    before_utf8: 'old', after_utf8: 'verified' }]);
  const draft = await buildSourceChanges(f.bytes, f.expected, changes), pin = sha256(canonical(draft.manifest));
  const selection = peer.selection(draft.manifest.effects.map(e => e.path_hex));
  const options = { confirmDraftSha256: pin };
  const prepare = (opts = {}) => preparePackedSourceChanges(f.bytes, f.expected, changes, selection, TOKEN,
    { ...options, ...(peer.ca ? { ca: peer.ca } : {}), ...opts });
  const candidate = await prepareSourceChanges(f.bytes, f.expected, changes, selection, TOKEN,
    { ...options, ...(peer.ca ? { ca: peer.ca } : {}) });
  const candidatePath = join(root, 'candidate'), saved = await saveSourceEdit(candidatePath, candidate.capture, candidate.bundle);
  const inspect = (opts = {}, path = candidatePath, hash = saved.manifest_sha256) =>
    inspectPackedSourceChanges(path, hash, f.bytes, f.expected, changes, { ...options, ...opts });
  const stageOptions = { ...options, principal: PRINCIPAL, confirmCandidate: candidate.candidate_commit };
  const stage = (opts = {}, request = selection, path = candidatePath, hash = saved.manifest_sha256, journal = join(root, 'journal')) =>
    stagePackedSourceChanges(journal, path, hash, f.bytes, f.expected, changes, request, { ...stageOptions, ...opts });
  return { peer, root, f, changes, draft, pin, selection, options, prepare, candidate, candidatePath, saved, inspect, stage, stageOptions };
}
function replaceBundle(s, bytes) {
  const capture = structuredClone(s.candidate.capture);
  capture.preparation.bundle = { bytes: bytes.length, sha256: sha256(bytes) };
  capture.inspection.bundle_bytes = bytes.length; capture.inspection.bundle_sha256 = sha256(bytes);
  return { capture, bundle: bytes };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: strict preparation/inspection/staging retain original bytes and report separate pack evidence`, async t => {
    const s = await setup(t, format, { tls: true }), prepared = await s.prepare();
    assert.ok(prepared.bundle.equals(s.candidate.bundle));
    assert.equal(prepared.bundle_objects_independently_verified, true);
    assert.equal(prepared.binding.bundle_objects_independently_verified, true);
    assert.equal(prepared.pack_verification.base_closure_verified, false);
    assert.equal(prepared.pack_verification.packed_candidate_matches_reviewed_effects, true);
    assert.equal(prepared.pack_verification.publication_authorized, false);
    assert.equal(prepared.metrics.requests, 2); assert.equal(s.peer.requests.length, 4);
    const checked = await s.inspect(), staged = await s.stage();
    assert.ok(checked.bundle.equals(prepared.bundle));
    assert.equal(staged.pack_verification.bundle_sha256, sha256(prepared.bundle));
    assert.equal(staged.pack_verification.candidate_manifest_sha256, s.saved.manifest_sha256);
    assert.equal(staged.binding.target_selection_matched, true);
    assert.equal(staged.binding.bundle_objects_independently_verified, true);
    assert.equal((await inspectSourceApply(staged.journal, staged.request_sha256)).state, 'not_dispatched');
    assert.ok((await readFile(join(staged.journal, 'candidate/candidate.bundle'))).equals(prepared.bundle));
    assert.equal(s.peer.requests.length, 4); assert.equal(s.peer.applies, 0); assert.deepEqual(s.peer.failures, []);
  });
  for (const fault of ['checksum', 'missing', 'extra', 'substituted']) {
    test(`${format}: ${fault} pack with consistent report hashes cannot create a strict journal`, async t => {
      const s = await setup(t, format); let bundle;
      if (fault === 'checksum') { bundle = Buffer.from(s.candidate.bundle); bundle[bundle.length - 1] ^= 1; }
      else {
        const ids = [...s.peer.packedIds], blob = s.draft.manifest.effects[0].new_blob;
        const selected = fault === 'extra' ? [...ids, s.f.commit] : ids.filter(id => id !== blob);
        if (fault === 'substituted') selected.push(s.draft.manifest.effects[0].old_blob);
        bundle = Buffer.concat([s.peer.packHeader, s.peer.packObjects(selected)]);
      }
      const bad = replaceBundle(s, bundle);
      // The unchanged report/tree validator accepts this transport. This is the
      // concrete regression: native identities in JSON do not verify pack bytes.
      await verifySourceChangeCandidate(s.f.bytes, s.f.expected, s.changes, bad.capture, bad.bundle, s.options);
      const path = join(s.root, 'bad'), saved = await saveSourceEdit(path, bad.capture, bad.bundle);
      await assert.rejects(s.inspect({}, path, saved.manifest_sha256));
      await assert.rejects(s.stage({}, s.selection, path, saved.manifest_sha256));
      await absent(join(s.root, 'journal')); assert.equal(s.peer.requests.length, 2); assert.equal(s.peer.applies, 0);
      assert.ok((await s.stage()).key); // Near-identical valid candidate succeeds.
    });
  }
  test(`${format}: corrupt remotely prepared pack refuses instead of downgrading to report-only verification`, async t => {
    const s = await setup(t, format);
    s.peer.transformPack = bytes => { const bad = Buffer.from(bytes); bad[bad.length - 1] ^= 1; return bad; };
    await assert.rejects(s.prepare(), /pack_checksum_mismatch/);
    assert.equal(s.peer.requests.length, 4); assert.equal(s.peer.applies, 0); assert.deepEqual(s.peer.failures, []);
    delete s.peer.transformPack;
    assert.equal((await s.prepare()).pack_verification.pack_checksum_verified, true);
  });
  test(`${format}: strict staging still requires independent target, original review and candidate consent`, async t => {
    const s = await setup(t, format);
    const changes = [r => { r.endpoint = 'https://elsewhere.invalid/repo'; }, r => { r.ref = 'refs/heads/wrong'; },
      r => { r.scope.repository_id = '9'.repeat(32); }, r => { r.metadata.message = 'not reviewed'; }];
    for (const mutate of changes) {
      const selection = structuredClone(s.selection); mutate(selection);
      await assert.rejects(s.stage({}, selection), /source_changes_target_selection/); await absent(join(s.root, 'journal'));
    }
    for (const options of [{ confirmDraftSha256: '0'.repeat(64) }, { confirmCandidate: 'f'.repeat(format === 'sha1' ? 40 : 64) },
      { principal: 'invalid' }, { token: TOKEN }, { ca: Buffer.from('not offline') }]) {
      await assert.rejects(s.stage(options)); await absent(join(s.root, 'journal'));
    }
    assert.equal(s.peer.requests.length, 2); assert.ok((await s.stage()).key);
  });
  test(`${format}: strict journal recovers original key after lost response and removal of external candidate`, async t => {
    const s = await setup(t, format), staged = await s.stage();
    await rm(s.candidatePath, { recursive: true }); s.f.bytes.fill(0); s.changes.changes.length = 0;
    s.peer.lostApply = true;
    await assert.rejects(dispatchSourceApply(staged.journal, staged.request_sha256, TOKEN), e => {
      assert.equal(e.retained_request.key, staged.key); return true;
    });
    const recovered = await recoverSourceApply(staged.journal, staged.request_sha256, ROTATED_TOKEN);
    assert.equal(recovered.decision.decision_sequence, '18446744073709551615');
    assert.equal(recovered.decision.outcome, 'committed'); assert.equal(recovered.key, staged.key);
    assert.equal(recovered.submission_retried, false); assert.equal(s.peer.applies, 1);
    const requests = s.peer.requests.length;
    assert.deepEqual(await dispatchSourceApply(staged.journal, staged.request_sha256, TOKEN), recovered);
    assert.equal(s.peer.requests.length, requests); assert.deepEqual(s.peer.failures, []);
  });
}
test('pack budgets are copied and only narrowed; invalid profiles refuse before network or journal work', async t => {
  const s = await setup(t);
  for (const packLimits of [{ maxWork: 0 }, { maxObjects: BUNDLE_VERIFY_LIMITS.maxObjects + 1 }, { unknown: 1 }, []]) {
    await assert.rejects(s.prepare({ packLimits })); await assert.rejects(s.stage({ packLimits }));
  }
  assert.equal(s.peer.requests.length, 2); await absent(join(s.root, 'journal'));
  await assert.rejects(s.inspect({ packLimits: { maxWork: 1 } }), /work_limit/);
  await assert.rejects(s.stage({ packLimits: { maxWork: 1 } }), /work_limit/);
  await absent(join(s.root, 'journal')); assert.ok((await s.stage()).key);
});
test('prepare and offline stage freeze caller inputs and limit selections before asynchronous work', async t => {
  const s = await setup(t), f = s.f;
  const source = Buffer.from(f.bytes), expected = structuredClone(f.expected), changes = structuredClone(s.changes), target = structuredClone(s.selection);
  const opts = { ...s.options, packLimits: { maxObjects: 20 } };
  const pending = preparePackedSourceChanges(source, expected, changes, target, TOKEN, opts);
  source.fill(0); expected.files.length = 0; changes.changes.length = 0; target.metadata.message = 'mutated'; opts.packLimits.maxObjects = 1;
  const prepared = await pending; assert.ok(prepared.bundle.equals(s.candidate.bundle));
  const original = Buffer.from(f.bytes), ex = structuredClone(f.expected), ch = structuredClone(s.changes), selection = structuredClone(s.selection);
  const consent = { ...s.stageOptions, packLimits: { maxObjects: 20 } };
  const staging = stagePackedSourceChanges(join(s.root, 'journal'), s.candidatePath, s.saved.manifest_sha256, original, ex, ch, selection, consent);
  original.fill(0); ex.files.length = 0; ch.changes.length = 0; selection.ref = 'refs/heads/mutated'; consent.principal = '9'.repeat(32); consent.packLimits.maxObjects = 1;
  const result = await staging; assert.equal(result.principal_id, PRINCIPAL);
  assert.equal(result.pack_verification.candidate_commit, s.candidate.candidate_commit);
});
test('cancelled and in-flight stopped operations cannot stage partial pack verification', async t => {
  const s = await setup(t), before = new AbortController(); before.abort();
  await assert.rejects(s.prepare({ signal: before.signal })); await assert.rejects(s.stage({ signal: before.signal }));
  await absent(join(s.root, 'journal')); assert.equal(s.peer.requests.length, 2);
  const during = new AbortController(); s.peer.held = true;
  s.peer.onRequest = () => during.abort();
  await assert.rejects(s.prepare({ signal: during.signal }), /source_edit_cancelled/);
  assert.equal(s.peer.requests.length, 3); assert.equal(s.peer.applies, 0);
  s.peer.held = false; delete s.peer.onRequest;
  const local = new AbortController(), pending = s.stage({ signal: local.signal }); queueMicrotask(() => local.abort());
  await assert.rejects(pending); await absent(join(s.root, 'journal'));
  assert.ok((await s.stage()).key);
});
test('offline inspection rejects network options and self-consistent replacement candidate manifests', async t => {
  const s = await setup(t);
  for (const options of [{ ca: Buffer.from('x') }, { token: TOKEN }, { maxWireBytes: 10 }]) await assert.rejects(s.inspect(options));
  const old = await readFile(join(s.candidatePath, 'manifest.json'));
  await writeFile(join(s.candidatePath, 'manifest.json'), Buffer.from(old.toString().replace(s.saved.bundle_sha256, 'a'.repeat(64))));
  await assert.rejects(s.inspect()); await assert.rejects(s.stage()); await absent(join(s.root, 'journal'));
  await writeFile(join(s.candidatePath, 'manifest.json'), old);
  assert.equal((await s.inspect()).pack_verification.exact_object_inventory_verified, true);
});
