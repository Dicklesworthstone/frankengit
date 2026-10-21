// Complete production composition with independently Git-built native objects.
// HTTP peers are native response fixtures, not a live Rust preparation service.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { planVerifiedSourceSplices, captureVerifiedSourceSplices, VERIFIED_SPLICE_PLAN }
  from '../../scripts/operator/source_edit_verified_splices.mjs';
import { validateSourceEditEvidence } from '../../scripts/operator/source_edit_from_package.mjs';
import { resultFixture, resultPeer, TOKEN, hex } from './source_edit_result_fixture.mjs';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const edit = (at, before, after) => ({ byte_start: at, before_hex: hex(before), after_hex: hex(after) });
function fixture(format = 'sha1', before = Buffer.from('start old\r\nlast'), after = Buffer.from('start NEW VALUE\r\nlast'), options = {}) {
  const path = options.path ?? 'src/selected';
  const f = resultFixture(format, [{ path, data: after, mode: options.afterMode ?? 0o100644 }], {
    before: [{ path, data: before, mode: options.beforeMode ?? 0o100644 }, { path: 'untouched', data: Buffer.from('sibling\n') }],
    selected: options.selected ?? [path], ...(options.hidden ? { hidden: options.hidden } : {}),
  });
  const edits = options.edits ?? [edit(6, 'old', 'NEW VALUE')];
  const plan = { schema: VERIFIED_SPLICE_PLAN, files: [{ path_hex: hex(path), after_mode: options.afterMode ?? 0o100644, edits }] };
  return { ...f, plan };
}
const compile = (f, options = {}, check) => planVerifiedSourceSplices(f.capture.request, f.plan, f.evidence, options, check);
async function peer(t, f, options = {}) {
  const p = await resultPeer(t, f), planned = await compile(f, options);
  p.control.mutate = (reply, call) => { if (call.operation === 'prepare') reply.patch_sha256 = digest(planned.patch); };
  return { ...p, planned, options };
}
const acquire = f => captureVerifiedSourceSplices(f.capture.request, f.plan, TOKEN, f.evidence, f.options ?? {});

for (const format of ['sha1', 'sha256']) {
  test(`${format}: verified originals produce the independently computed tree and retained result intent`, async () => {
    const f = fixture(format), snapshot = { package_bytes: Buffer.from(f.evidence.package_bytes),
      expected: structuredClone(f.evidence.expected) }, r = await compile(f);
    assert.equal(r.request.expected_result_tree, f.nextTree.oid);
    assert.equal(r.request.expected_commit, f.base);
    assert.equal(Object.hasOwn(f.capture.request, 'expected_result_tree'), false);
    assert.equal(r.source_evidence.expected.schema, 'frankengit-source-edit-result-selection-v1');
    assert.equal(r.source_evidence.expected.after[0].blob, f.after.get(f.plan.files[0].path_hex).oid);
    assert.equal(r.receipt.source_membership_verified, true);
    assert.equal(r.receipt.candidate_result_verified, false);
    assert.equal(r.receipt.publication_authorized, false);
    assert.equal(r.receipt.patch_sha256, digest(r.patch));
    assert.deepEqual(f.evidence, snapshot);
    assert.deepEqual(r.source_evidence.package_bytes, f.evidence.package_bytes);
  });
  test(`${format}: ordinary acquisition and offline replay retain the same independent source/result evidence`, async t => {
    const f = await peer(t, fixture(format)), r = await acquire(f);
    assert.equal(r.candidate_commit, f.candidate);
    assert.equal(r.capture.request.expected_result_tree, f.nextTree.oid);
    assert.equal(r.capture.schema, 'frankengit-source-edit-capture-v2');
    assert.equal(r.source_verification.requested_result_verified, true);
    assert.equal(r.source_verification.exact_tree_effects_verified, true);
    assert.equal(r.source_verification.bundle_objects_independently_verified, false);
    assert.equal(r.splice_plan.candidate_result_verified, false); // preflight receipt is not promoted
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
    assert.ok(f.calls[0].body.includes(f.planned.patch));
    assert.ok(f.calls.every(c => c.headers['idempotency-key'] === undefined));
    assert.ok(!f.calls[0].body.includes(Buffer.from('expected_result_tree=')));
    const replay = await validateSourceEditEvidence(r.capture, r.bundle, r.source_evidence);
    assert.deepEqual(replay.source_verification, r.source_verification);
    const changed = structuredClone(r.source_evidence); changed.expected.after[0].blob = 'f'.repeat(format === 'sha1' ? 40 : 64);
    await assert.rejects(validateSourceEditEvidence(r.capture, r.bundle, changed));
  });
  test(`${format}: valid unwanted same-path candidate fails before inspection`, async t => {
    const f = await peer(t, fixture(format, Buffer.from('start old\r\nlast'), Buffer.from('start WRONG\r\nlast')));
    assert.notEqual(f.planned.request.expected_result_tree, f.nextTree.oid);
    await assert.rejects(acquire(f), /result_tree_mismatch/);
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare']);
  });
  test(`${format}: real candidate with a hidden sibling change fails before inspection`, async t => {
    const f = await peer(t, fixture(format, undefined, undefined, { hidden: [{ path: 'untouched', data: Buffer.from('hidden\n') }] }));
    await assert.rejects(acquire(f), /result_tree_mismatch/);
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare']);
  });
  for (const patchProfile of ['trim-common-lines-v1', 'bounded-line-hunks-v1']) {
    test(`${format}/${patchProfile}: compact representation preserves verified result intent`, async t => {
      const f = await peer(t, fixture(format), { patchProfile }), r = await acquire(f);
      assert.equal(r.candidate_commit, f.candidate);
      assert.equal(r.splice_plan.patch_profile, patchProfile);
      assert.equal(r.capture.request.expected_result_tree, f.nextTree.oid);
      assert.equal(r.source_verification.requested_result_verified, true);
    });
  }
  for (const binary of ['literal', 'delta']) {
    test(`${format}/${binary}: exact binary after commitments remain distinct from omitted review bodies`, async t => {
      const before = Buffer.alloc(512, 0), after = Buffer.from(before); after[200] = 255;
      const f = await peer(t, fixture(format, before, after, { edits: [edit(200, [0], [255])] }), { binary });
      const r = await acquire(f);
      assert.equal(r.capture.request.expected_result_tree, f.nextTree.oid);
      assert.equal(r.source_verification.requested_result_verified, true);
      assert.deepEqual(r.source_verification.unverified_after_paths_hex, [hex('src/selected')]);
      assert.equal(r.source_verification.patch_application_verified, false);
    });
  }
  test(`${format}: full removal leaves a committed empty regular file`, async t => {
    const f = await peer(t, fixture(format, Buffer.from('old\n'), Buffer.alloc(0), { edits: [edit(0, 'old\n', '')] }));
    const r = await acquire(f);
    assert.equal(r.capture.inspection.comparison.entries[0].kind, 'modified');
    assert.notEqual(r.source_evidence.expected.after[0].blob, null);
    assert.equal(r.capture.request.expected_result_tree, f.nextTree.oid);
  });
  test(`${format}: mode-only changes use package modes and preserve source bytes`, async t => {
    const f = await peer(t, fixture(format, Buffer.from('same\n'), Buffer.from('same\n'), { edits: [], afterMode: 0o100755 }));
    const r = await acquire(f);
    assert.equal(r.source_evidence.expected.after[0].kind, 'executable');
    assert.equal(r.splice_plan.splice_count, 0);
    assert.equal(r.capture.inspection.comparison.entries[0].kind, 'mode_changed');
  });
  test(`${format}: raw paths and bytes do not require a host filesystem name`, async t => {
    const raw = Buffer.from([255, 47, 254, 32, 34, 92]);
    const f = await peer(t, fixture(format, Buffer.from([255, 13, 10, 254]), Buffer.from([253, 13, 10, 254]),
      { path: raw, edits: [edit(0, [255], [253])] }));
    const r = await acquire(f);
    assert.equal(r.source_evidence.expected.after[0].pathHex, hex(raw));
    assert.equal(r.capture.request.expected_result_tree, f.nextTree.oid);
  });
  test(`${format}: matching extra root is retained; conflicting root refuses before any request`, async t => {
    const f = await peer(t, fixture(format)); f.capture.request.expected_result_tree = f.nextTree.oid;
    assert.equal((await acquire(f)).candidate_commit, f.candidate);
    f.calls.length = 0; f.capture.request.expected_result_tree = 'f'.repeat(format === 'sha1' ? 40 : 64);
    await assert.rejects(acquire(f), /result_tree_mismatch/); assert.equal(f.calls.length, 0);
  });
}

for (const [name, mutate] of [
  ['stale original range', f => { f.plan.files[0].edits[0].before_hex = hex('bad'); }],
  ['wrong offset', f => { f.plan.files[0].edits[0].byte_start = 7; }],
  ['overlap', f => { f.plan.files[0].edits.push(edit(7, 'l', 'Q')); }],
  ['duplicate starts', f => { f.plan.files[0].edits.push(edit(6, '', 'Q')); }],
  ['unselected path', f => { f.capture.request.paths_hex = [hex('untouched')]; f.plan.files[0].path_hex = hex('untouched'); }],
  ['changed commit', f => { f.evidence.expected.commit = 'f'.repeat(40); }],
  ['changed independent blob', f => { f.evidence.expected.files[0].blob = 'f'.repeat(40); }],
  ['corrupt source body', f => { const p = JSON.parse(f.evidence.package_bytes); p.blobs[0].bytesHex = '00'; f.evidence.package_bytes = Buffer.from(JSON.stringify(p)); }],
  ['endpoint in plan', f => { f.plan.endpoint = 'http://127.0.0.1:1/other'; }],
  ['original supplied in instruction', f => { f.plan.files[0].before = { bytes_hex: hex('old') }; }],
  ['unrelated result constraints', f => { f.evidence.expected = { schema: 'frankengit-source-edit-result-selection-v1', source: f.evidence.expected, create_paths_hex: [], after: [] }; }],
  ['symlink mode', f => { f.plan.files[0].after_mode = 0o120000; }],
  ['zero effect', f => { f.plan.files[0].edits[0].after_hex = f.plan.files[0].edits[0].before_hex; }],
]) test(`before network: ${name}`, async t => {
  const f = await peer(t, fixture()); mutate(f);
  await assert.rejects(acquire(f)); assert.equal(f.calls.length, 0);
});

test('copy inputs and options before asynchronous verification', async () => {
  const f = fixture(), expectedTree = f.nextTree.oid, options = { patchProfile: 'bounded-line-hunks-v1' };
  const pending = compile(f, options);
  f.plan.files[0].edits[0].after_hex = hex('malicious'); f.evidence.package_bytes.fill(0);
  f.evidence.expected.files.length = 0; f.capture.request.expected_commit = 'f'.repeat(40);
  options.patchProfile = 'unknown';
  const r = await pending; assert.equal(r.request.expected_result_tree, expectedTree);
  assert.equal(r.receipt.patch_profile, 'bounded-line-hunks-v1');
});
test('all offsets retain original coordinates after a length-changing earlier edit', async () => {
  const f = fixture('sha256', Buffer.from('abcdef'), Buffer.from('aLONGcdQ'), { edits: [edit(4, 'ef', 'Q'), edit(1, 'b', 'LONG')] });
  assert.equal((await compile(f)).request.expected_result_tree, f.nextTree.oid);
});
test('proof may include unchanged files but only explicit paths become effects', async () => {
  const f = fixture('sha1', undefined, undefined, { selected: ['src/selected', 'untouched'] });
  const r = await compile(f);
  assert.equal(r.source_evidence.expected.source.files.length, 2);
  assert.equal(r.source_evidence.expected.after.length, 1);
  assert.equal(r.request.expected_result_tree, f.nextTree.oid);
});
test('shared output and edit limits have exact permitted twins', async () => {
  const f = fixture(), r = await compile(f);
  const allowed = { maxPatchBytes: r.patch.length, maxExpectedBytes: 3, maxInsertedBytes: 9,
    maxSplices: 1, maxSourceBytes: f.before.get(hex('src/selected')).data.length,
    maxResultBytes: f.after.get(hex('src/selected')).data.length };
  assert.equal((await compile(f, allowed)).request.expected_result_tree, f.nextTree.oid);
  for (const key of ['maxPatchBytes', 'maxExpectedBytes', 'maxInsertedBytes', 'maxSourceBytes', 'maxResultBytes']) {
    await assert.rejects(compile(f, { ...allowed, [key]: allowed[key] - 1 }));
  }
  for (const options of [{ maxSplices: 0 }, { maxPatchBytes: 1048577 }, { binary: null }, { patchProfile: 'bad' },
    { binary: 'literal', patchProfile: 'bounded-line-hunks-v1' }, { force: true }]) await assert.rejects(compile(f, options));
});
test('one response allowance is not renewed by package verification', async t => {
  const f = await peer(t, fixture()), r = await acquire(f);
  // captureVerifiedSourceEdit returns checked evidence rather than network metrics.
  const b = `fg-source-${digest(f.bundle).slice(0, 48)}-0`, preparation = structuredClone(f.capture.preparation);
  preparation.patch_sha256 = digest(f.planned.patch);
  const first = Buffer.byteLength(`--${b}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n${JSON.stringify(preparation)}\r\n--${b}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="candidate.bundle"\r\n\r\n`) + f.bundle.length + Buffer.byteLength(`\r\n--${b}--\r\n`);
  const allowance = first + Buffer.byteLength(JSON.stringify(f.capture.inspection));
  assert.equal((await captureVerifiedSourceSplices(f.capture.request, f.plan, TOKEN, f.evidence, { maxWireBytes: allowance })).candidate_commit, r.candidate_commit);
  await assert.rejects(captureVerifiedSourceSplices(f.capture.request, f.plan, TOKEN, f.evidence, { maxWireBytes: allowance - 1 }));
  assert.equal(f.calls.length, 6);
});
test('pre-cancellation and cancellation during proof hashing never open transport', async t => {
  const f = await peer(t, fixture()), stop = new AbortController(); stop.abort();
  await assert.rejects(captureVerifiedSourceSplices(f.capture.request, f.plan, TOKEN, f.evidence, { signal: stop.signal }), /cancelled/);
  const other = new AbortController(), pending = captureVerifiedSourceSplices(f.capture.request, f.plan, TOKEN, f.evidence, { signal: other.signal });
  other.abort(); await assert.rejects(pending, /cancelled/); assert.equal(f.calls.length, 0);
});
test('later damaged review cannot yield a successful prepared-only prefix', async t => {
  const f = await peer(t, fixture()), normal = f.control.mutate;
  f.control.mutate = (reply, call) => { normal(reply, call); if (call.operation === 'inspect') reply.comparison.entries[0].content.hunks[0].before_hex = hex('tampered'); };
  await assert.rejects(acquire(f)); assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
});


for (const format of ['sha1', 'sha256']) test(`${format}: verified delta-runs preserves source evidence and derived result root`, async () => {
  const before = Buffer.alloc(800000, 97); before[0] = 0;
  const after = Buffer.from(before); after[64] = 98; after[after.length - 100] = 99;
  const f = fixture(format, before, after, {
    edits: [edit(64, [97], [98]), edit(before.length - 100, [97], [99])],
  });
  await assert.rejects(compile(f, { binary: 'delta' }), /patch_limit/);
  const result = await compile(f, { binary: 'delta-runs' });
  assert.equal(result.request.expected_result_tree, f.nextTree.oid);
  assert.equal(result.receipt.source_membership_verified, true);
  assert.equal(result.receipt.candidate_result_verified, false);
  assert.equal(result.receipt.encoding_profile, 'frankengit-source-replacements-delta-runs-v1');
  assert.ok(result.receipt.aligned_copy_regions >= 4);
  assert.ok(result.patch.length < 1024);
});
