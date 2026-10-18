import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { prepareSourceChanges, verifySourceChangeCandidate } from '../operator/source_changes_prepare.mjs';
import { captureSourceEdit, validateSourceEdit } from '../operator/source_edit_candidate.mjs';
import { saveSourceEdit, loadSourceEdit, stageSourceApply, dispatchSourceApply, recoverSourceApply, inspectSourceApply } from '../operator/source_edit_publish.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
import { intent, replace, hexPath } from './source_changes_fixture.mjs';
const edit = () => intent([replace('src/main.rs', 'fn main() { new(); }\n')]);
const code = value => error => error.code === value;
async function basis(peer, changes = edit()) {
  const f = peer.fixture, draft = await buildSourceChanges(f.bytes, f.expected, changes);
  return { changes, draft, request: peer.selection(draft.manifest.effects.map(row => row.path_hex)),
    options: { confirmDraftSha256: sha256(canonical(draft.manifest)) } };
}
const prepare = (peer, b, options = {}) => prepareSourceChanges(peer.fixture.bytes, peer.fixture.expected, b.changes, b.request, TOKEN, { ...b.options, ...options });

for (const format of ['sha1', 'sha256']) {
  test(`${format}: complete verifier/encoder/transport/native-capture integration preserves exact effects`, async () => {
    const peer = await nativePeer(format);
    try {
      const b = await basis(peer, intent([replace('src/main.rs', 'fn main() { new(); }\n'),
        { path_hex: hexPath('run.sh'), operation: 'mode', executable: false }, { path_hex: hexPath('empty.txt'), operation: 'delete' }]));
      const result = await prepare(peer, b);
      assert.deepEqual(result.draft, b.draft); assert.deepEqual(result.capture.request, b.request);
      assert.equal(result.binding.effect_count, 3); assert.equal(result.binding.intended_effect_reports_matched, true);
      assert.equal(result.binding.candidate_tree_independently_verified, false); assert.equal(result.binding.publication_authorized, false);
      assert.equal(result.candidate_commit, peer.candidate.commit);
      assert.ok(peer.candidate.patch.equals(b.draft.bytes));
      assert.deepEqual(peer.requests.map(r => r.route), ['source/prepare', 'source/inspect']); assert.deepEqual(peer.failures, []);
      const replay = await verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, b.changes, result.capture, result.bundle, b.options);
      assert.deepEqual(replay.binding, result.binding); assert.equal(peer.requests.length, 2);
    } finally { await peer.close(); }
  });
  test(`${format}: self-consistent wrong native after-image passes old capture validation but fails exact intent binding`, async () => {
    const peer = await nativePeer(format);
    try {
      const b = await basis(peer); peer.fault = 'wrong-after';
      const internallyValid = await captureSourceEdit(b.request, b.draft.bytes, TOKEN);
      assert.equal(validateSourceEdit(internallyValid.capture, internallyValid.bundle).candidate_commit, peer.candidate.commit);
      await assert.rejects(verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, b.changes,
        internallyValid.capture, internallyValid.bundle, b.options), code('source_changes_candidate_effects'));
      await assert.rejects(prepare(peer, b), code('source_changes_candidate_effects'));
      peer.fault = null; assert.equal((await prepare(peer, b)).binding.intended_effect_reports_matched, true);
      assert.deepEqual(peer.failures, []);
    } finally { await peer.close(); }
  });
  test(`${format}: standard candidate handoff retains one-shot lost-reply recovery and full-width decision sequence`, async () => {
    const peer = await nativePeer(format), root = await mkdtemp(join(tmpdir(), 'fg-authored-handoff-'));
    try {
      const b = await basis(peer), result = await prepare(peer, b), candidate = join(root, 'candidate'), journal = join(root, 'journal');
      const saved = await saveSourceEdit(candidate, result.capture, result.bundle);
      const loaded = await loadSourceEdit(candidate, saved.manifest_sha256);
      const checked = await verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, b.changes, loaded.capture, loaded.bundle, b.options);
      assert.equal(checked.binding.draft_sha256, b.options.confirmDraftSha256);
      const staged = await stageSourceApply(journal, candidate, saved.manifest_sha256, PRINCIPAL);
      peer.lostApply = true;
      await assert.rejects(dispatchSourceApply(journal, staged.request_sha256, TOKEN), e => e.retained_request?.key === staged.key);
      assert.equal((await inspectSourceApply(journal, staged.request_sha256)).state, 'outcome_unknown');
      await assert.rejects(dispatchSourceApply(journal, staged.request_sha256, TOKEN), code('source_edit_already_dispatched'));
      const recovered = await recoverSourceApply(journal, staged.request_sha256, ROTATED_TOKEN);
      assert.equal(recovered.decision.outcome, 'committed'); assert.equal(recovered.decision.decision_sequence, '18446744073709551615');
      assert.equal(recovered.key, staged.key); assert.equal(peer.applies, 1);
      const count = peer.requests.length;
      assert.deepEqual(await recoverSourceApply(journal, staged.request_sha256, ROTATED_TOKEN), recovered);
      assert.deepEqual(await dispatchSourceApply(journal, staged.request_sha256, TOKEN), recovered);
      assert.equal(peer.requests.length, count); assert.equal(peer.requests.at(-1).route, 'outcomes');
      assert.equal(peer.requests.at(-1).bytes.length, 0); assert.deepEqual(peer.failures, []);
    } finally { await peer.close(); await rm(root, { recursive: true, force: true }); }
  });
}
for (const fault of ['wrong-before-tree', 'wrong-old-blob', 'wrong-old-mode', 'wrong-new-mode']) {
  test(`exact intended basis/effects refuse ${fault} beside the valid native-schema twin`, async () => {
    const peer = await nativePeer();
    try {
      const b = await basis(peer); peer.fault = fault;
      const internallyValid = await captureSourceEdit(b.request, b.draft.bytes, TOKEN);
      assert.ok(validateSourceEdit(internallyValid.capture, internallyValid.bundle));
      await assert.rejects(verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, b.changes,
        internallyValid.capture, internallyValid.bundle, b.options), code(fault === 'wrong-before-tree' ? 'source_changes_candidate_basis' : 'source_changes_candidate_effects'));
      peer.fault = null; assert.ok((await prepare(peer, b)).binding.intended_effect_reports_matched); assert.deepEqual(peer.failures, []);
    } finally { await peer.close(); }
  });
}
test('preparation requires a reviewed manifest pin and exact native base/hash/path selection before any I/O', async () => {
  const peer = await nativePeer();
  try {
    const b = await basis(peer);
    await assert.rejects(prepare(peer, b, { confirmDraftSha256: 'f'.repeat(64) }), code('source_changes_confirmation'));
    await assert.rejects(prepare(peer, b, { confirmDraftSha256: undefined }), code('source_changes_confirmation'));
    await assert.rejects(prepare(peer, { ...b, changes: intent([replace('src/main.rs', 'different\n')]) }), code('source_changes_confirmation'));
    for (const update of [r => { r.expected_commit = 'f'.repeat(40); }, r => { r.paths_hex = [hexPath('run.sh')]; },
      r => { r.paths_hex.push(hexPath('run.sh')); }, r => { r.scope.object_format = 'sha256'; r.expected_commit = 'f'.repeat(64); }]) {
      const request = structuredClone(b.request); update(request);
      await assert.rejects(prepare(peer, { ...b, request }), code('source_changes_selection_mismatch'));
    }
    assert.equal(peer.requests.length, 0); assert.ok((await prepare(peer, b)).candidate_commit);
  } finally { await peer.close(); }
});
test('explicit no-op changes are not sent as native effect paths', async () => {
  const peer = await nativePeer();
  try {
    const b = await basis(peer, intent([replace('src/main.rs', 'new\n'), replace('empty.txt', '')]));
    assert.equal(b.draft.manifest.no_op_paths_hex.length, 1);
    assert.equal((await prepare(peer, b)).binding.no_op_count, 1);
    assert.deepEqual(b.request.paths_hex, [hexPath('src/main.rs')]);
  } finally { await peer.close(); }
});
test('selection, before package, expected pins, changes and confirmation are owned across async verification', async () => {
  const peer = await nativePeer();
  try {
    const b = await basis(peer), originalRequest = structuredClone(b.request), bytes = Buffer.from(peer.fixture.bytes), expected = structuredClone(peer.fixture.expected);
    const pending = prepareSourceChanges(bytes, expected, b.changes, b.request, TOKEN, b.options);
    bytes.fill(0); expected.files.length = 0; b.changes.changes[0].content_utf8 = 'not the edit';
    b.request.metadata.message = 'not the message'; b.request.scope.repository_id = 'f'.repeat(32); b.request.paths_hex.length = 0;
    b.options.confirmDraftSha256 = 'f'.repeat(64);
    const result = await pending;
    assert.deepEqual(result.capture.request, originalRequest); assert.equal(result.draft.manifest.patch_sha256, b.draft.manifest.patch_sha256);
  } finally { await peer.close(); }
});
test('offline candidate validation snapshots supplied capture and bundle before hashing the original source', async () => {
  const peer = await nativePeer();
  try {
    const b = await basis(peer), result = await prepare(peer, b), capture = structuredClone(result.capture), bundle = Buffer.from(result.bundle);
    const pending = verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, b.changes, capture, bundle, b.options);
    capture.inspection.comparison.entries.length = 0; bundle.fill(0);
    assert.equal((await pending).binding.candidate_commit, result.candidate_commit);
    const bad = structuredClone(result.capture); bad.patch_sha256 = 'f'.repeat(64);
    await assert.rejects(verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, b.changes, bad, result.bundle, b.options));
    assert.equal(peer.requests.length, 2);
  } finally { await peer.close(); }
});
test('pre-cancellation and in-flight cancellation never select a partial candidate or retry', async () => {
  const peer = await nativePeer();
  try {
    const b = await basis(peer), stopped = new AbortController(); stopped.abort();
    await assert.rejects(prepare(peer, b, { signal: stopped.signal })); assert.equal(peer.requests.length, 0);
    const active = new AbortController(); peer.held = true; peer.onRequest = () => active.abort();
    await assert.rejects(prepare(peer, b, { signal: active.signal }), code('source_edit_cancelled'));
    assert.deepEqual(peer.requests.map(r => r.route), ['source/prepare']);
    peer.held = false; peer.onRequest = null; assert.ok((await prepare(peer, b)).candidate_commit);
  } finally { await peer.close(); }
});
test('one shared operation deadline terminates a stalled preparation socket', async () => {
  const peer = await nativePeer();
  try {
    const b = await basis(peer); peer.held = true;
    const start = performance.now(); await assert.rejects(prepare(peer, b, { timeoutMs: 150 }), code('source_edit_timeout'));
    assert.ok(performance.now() - start < 3000); assert.equal(peer.requests.length, 1);
    peer.held = false; assert.ok((await prepare(peer, b)).candidate_commit);
  } finally { await peer.close(); }
});
test('HTTP refusal, wire budget and untrusted TLS are not converted into successful candidates', async () => {
  const peer = await nativePeer();
  try {
    const b = await basis(peer); peer.httpStatus = 403;
    await assert.rejects(prepare(peer, b), code('source_edit_http')); assert.equal(peer.requests.length, 1);
    peer.httpStatus = null;
    await assert.rejects(prepare(peer, b, { maxWireBytes: 1 }));
    assert.ok((await prepare(peer, b)).candidate_commit);
  } finally { await peer.close(); }
  const secure = await nativePeer('sha256', { tls: true });
  try {
    const b = await basis(secure);
    await assert.rejects(prepare(secure, b), code('source_edit_transport')); assert.equal(secure.requests.length, 0);
    assert.ok((await prepare(secure, b, { ca: secure.ca })).binding.intended_effect_reports_matched);
    assert.equal(secure.requests.length, 2); assert.deepEqual(secure.failures, []);
  } finally { await secure.close(); }
});
