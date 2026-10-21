// Production verifier with independent Git-built objects and actual HTTP peers.
// These peers are native-schema fixtures, not Rust patch or admission execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { validateSourceEdit } from '../../scripts/operator/source_edit_candidate.mjs';
import { sourceEditResultSelection, bindVerifiedEditSource, validateSourceEditEvidence,
  captureVerifiedSourceEdit, SOURCE_RESULT_SELECTION, SOURCE_RESULT_EVIDENCE_PROFILE } from '../../scripts/operator/source_edit_from_package.mjs';
import { resultFixture, resultPeer, hex, TOKEN } from './source_edit_result_fixture.mjs';
const copy = value => structuredClone(value);
const source = f => f.evidence.expected.source ?? f.evidence.expected;
export function intended(f) {
  // These are the fixture's independently supplied desired file bytes, not a
  // server's preparation/diff fields or a root copied from its response.
  const changes = f.capture.request.paths_hex.map(pathHex => {
    const file = f.after.get(pathHex);
    return { pathHex, bytes: file?.data ?? null, kind: file ? file.mode === 0o100755 ? 'executable' : 'file' : null };
  });
  return sourceEditResultSelection(source(f), changes);
}
const evidence = (f, expected = intended(f)) => ({ package_bytes: Buffer.from(f.evidence.package_bytes), expected });
const verify = (f, e = evidence(f), check) => validateSourceEditEvidence(f.capture, f.bundle, e, check);
const scenarios = {
  creation: [{ path: 'src/new.rs', data: Buffer.from('new\r\nlast') }],
  text: [{ path: 'src/anchor.rs', data: Buffer.from('changed\n') }],
  binary: [{ path: 'src/anchor.rs', data: Buffer.from([0,255,1,10]) }],
  executable: [{ path: 'src/anchor.rs', data: Buffer.from('pub fn anchor() {}\n'), mode: 0o100755 }],
  delete: [{ path: 'src/anchor.rs', data: null }],
  empty: [{ path: 'src/empty', data: Buffer.alloc(0) }],
  raw: [{ path: Buffer.from([255,47,254]), data: Buffer.from([13,10,255]), mode: 0o100755 }],
  mixed: [{ path: 'src/anchor.rs', data: null }, { path: 'new/deep/file', data: Buffer.from('new\n') }],
};
for (const format of ['sha1','sha256']) {
  for (const [name, changes] of Object.entries(scenarios)) test(`${format}/${name}: exact requested result and native candidate agree`, async () => {
    const f = resultFixture(format, changes), selected = intended(f), before = copy(selected);
    const preflight = await bindVerifiedEditSource(f.evidence.package_bytes, selected, f.capture.request);
    assert.equal(preflight.intended_tree, f.nextTree.oid);
    assert.equal(preflight.candidate_result_verified, false);
    const result = await verify(f, evidence(f, selected)), r = result.source_verification;
    assert.equal(r.profile, SOURCE_RESULT_EVIDENCE_PROFILE);
    assert.equal(r.requested_result_verified, true);
    assert.equal(r.intended_tree, f.nextTree.oid);
    assert.equal(r.result_commitments_from, 'independent-expected-selection');
    assert.equal(r.exact_tree_effects_verified, true);
    assert.equal(r.authority_verified, false);
    assert.equal(r.patch_application_verified, false);
    assert.equal(r.bundle_objects_independently_verified, false);
    assert.deepEqual(r.unverified_after_paths_hex, name === 'binary' ? [hex('src/anchor.rs')] : []);
    assert.deepEqual(selected, before);
    assert.deepEqual((await validateSourceEditEvidence(result.capture, result.bundle, result.source_evidence)).source_verification, r);
  });
  for (const name of ['text','binary','executable','delete']) test(`${format}: internally valid but unintended ${name} candidate is refused`, async () => {
    const actual = resultFixture(format, scenarios[name]);
    const wanted = resultFixture(format, [{ path: 'src/anchor.rs', data: Buffer.from('independently desired\n') }]);
    assert.equal(actual.base, wanted.base);
    // The old source proof and native receipts accept this genuine alternate
    // Git candidate; only the independently selected result distinguishes it.
    assert.doesNotThrow(() => validateSourceEdit(actual.capture, actual.bundle));
    await validateSourceEditEvidence(actual.capture, actual.bundle, actual.evidence);
    await assert.rejects(verify(actual, evidence(actual, intended(wanted))), /source_edit_requested_result/);
  });
  test(`${format}: acquisition refuses a dishonest same-path result despite an echoed patch hash`, async t => {
    const f = await resultPeer(t, resultFixture(format, scenarios.text));
    const wanted = resultFixture(format, [{ path: 'src/anchor.rs', data: Buffer.from('desired\n') }]);
    const desiredHash = createHash('sha256').update(wanted.patch).digest('hex');
    f.control.mutate = (reply, call) => { if (call.operation === 'prepare') reply.patch_sha256 = desiredHash; };
    await assert.rejects(captureVerifiedSourceEdit(f.capture.request, wanted.patch, TOKEN, evidence(f, intended(wanted))), /source_edit_requested_result/);
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare','inspect']);
    assert.ok(f.calls[0].body.includes(wanted.patch));
    assert.ok(f.calls.every(c => c.headers['idempotency-key'] === undefined));
  });
  test(`${format}: matching acquisition retains independent result instead of a server-selected expectation`, async t => {
    const f = await resultPeer(t, resultFixture(format, scenarios.mixed));
    const e = evidence(f), result = await captureVerifiedSourceEdit(f.capture.request, f.patch, TOKEN, e);
    assert.equal(result.source_verification.requested_result_verified, true);
    assert.equal(result.candidate_commit, f.capture.preparation.candidate_commit.split(':').at(-1));
    assert.deepEqual(result.source_evidence.expected, e.expected);
    assert.equal(result.metrics.requests, 2);
  });
}
test('constructor hashes exact desired binary/CRLF/empty bytes and sorts only owned paths', () => {
  const f = resultFixture(), values = [Buffer.from('a\r\nb'),Buffer.from([0,255]),Buffer.alloc(0)];
  const changes = values.map((bytes,i) => ({ pathHex:hex(`src/new${2-i}`), bytes, kind: 'file' }));
  const expected = sourceEditResultSelection(source(f), changes);
  assert.deepEqual(changes.map(c => c.pathHex), [hex('src/new2'),hex('src/new1'),hex('src/new0')]);
  for (const row of expected.after) {
    const b = changes.find(c => c.pathHex === row.pathHex).bytes;
    assert.equal(row.blob, createHash('sha1').update(`blob ${b.length}\0`).update(b).digest('hex'));
  }
  assert.equal(expected.schema, SOURCE_RESULT_SELECTION);
});
const malformed = {
  'missing result': e => { delete e.after; },
  'extra flag': e => { e.approved = true; },
  'wrong kind': e => { e.after[0].kind = 'symlink'; },
  'duplicate target': e => { e.after.push(copy(e.after[0])); },
  'unknown target': e => { e.after[0].pathHex = hex('unproved/path'); },
  'inexact deletion': e => { e.after[0].blob = null; },
  'foreign hash domain': e => { e.after[0].blob = 'f'.repeat(64); },
  'zero blob': e => { e.after[0].blob = '0'.repeat(40); },
  'path traversal': e => { e.after[0].pathHex = hex('../path'); },
  'git metadata path': e => { e.after[0].pathHex = hex('.GiT/config'); },
  'null creation': e => { e.after[0].blob = null; e.after[0].kind = null; },
};
for (const [name, alter] of Object.entries(malformed)) test(`invalid ${name} fails before native requests`, async t => {
  const f = await resultPeer(t, resultFixture()), e = evidence(f); alter(e.expected);
  await assert.rejects(captureVerifiedSourceEdit(f.capture.request, f.patch, TOKEN, e));
  assert.equal(f.calls.length, 0);
});
test('same existing blob and mode is an explicit no-op refusal before any HTTP request', async t => {
  const f = await resultPeer(t, resultFixture('sha1', scenarios.text));
  const old = f.before.get(hex('src/anchor.rs'));
  const expected = sourceEditResultSelection(source(f), [{ pathHex:hex('src/anchor.rs'), bytes:old.data, kind:'file' }]);
  await assert.rejects(captureVerifiedSourceEdit(f.capture.request, f.patch, TOKEN, evidence(f,expected)), /tree effect has no change/);
  assert.equal(f.calls.length,0);
});
test('desired paths must equal the actual request, never a selectable subset', async t => {
  const f = await resultPeer(t, resultFixture()), expected = intended(f);
  const request = copy(f.capture.request); request.paths_hex.push(hex('src/anchor.rs'));
  await assert.rejects(captureVerifiedSourceEdit(request, f.patch, TOKEN, evidence(f,expected)), /source_edit_result_paths/);
  assert.equal(f.calls.length,0);
});
test('result selection cannot disguise an occupied path as a creation or bypass missing parent proof', async t => {
  for (const path of ['root-anchor','unproved/missing','top-link/child','submodule/child']) {
    const f = await resultPeer(t, resultFixture()), request = copy(f.capture.request);
    request.paths_hex=[hex(path)];
    const expected=sourceEditResultSelection(source(f),[{pathHex:hex(path),bytes:Buffer.from('new\n'),kind:'file'}]);
    await assert.rejects(captureVerifiedSourceEdit(request, f.patch, TOKEN, evidence(f,expected)));
    assert.equal(f.calls.length,0);
  }
});
test('bounded desired bytes distinguish empty files from deletions and reject oversized plans', () => {
  const f=resultFixture(), base=source(f), row={pathHex:hex('new'),bytes:Buffer.alloc(0),kind:'file'};
  assert.ok(sourceEditResultSelection(base,[row]).after[0].blob);
  assert.throws(()=>sourceEditResultSelection(base,[{...row,bytes:null,kind:null}]),/unselected_deletion/);
  assert.throws(()=>sourceEditResultSelection(base,[{...row,bytes:Buffer.alloc(1048577)}]),/result_bytes/);
  const big=Array.from({length:9},(_,i)=>({...row,pathHex:hex(`n${i}`),bytes:Buffer.alloc(1048576)}));
  assert.throws(()=>sourceEditResultSelection(base,big),/result_bytes/);
  assert.throws(()=>sourceEditResultSelection(base,Array.from({length:33},(_,i)=>({...row,pathHex:hex(`n${i}`)}))),/result_selection/);
  assert.throws(()=>sourceEditResultSelection(base,[row,{...row,pathHex:hex('new/child')}]));
});
test('owned result commitments survive mutation during asynchronous verification', async () => {
  const f=resultFixture(), e=evidence(f), original=copy(e.expected);
  const task=verify(f,e);
  e.expected.after[0].blob='f'.repeat(40);e.expected.create_paths_hex.length=0;e.package_bytes.fill(0);
  f.capture.inspection.comparison.after_tree='f'.repeat(40);f.bundle.fill(0);
  const r=await task;assert.deepEqual(r.source_evidence.expected,original);
  assert.equal(r.source_verification.requested_result_verified,true);
});
test('cancelled result acquisition does not open a socket or change to ordinary mode', async t => {
  const f=await resultPeer(t,resultFixture()), signal=AbortSignal.abort();
  await assert.rejects(captureVerifiedSourceEdit(f.capture.request,f.patch,TOKEN,evidence(f),{signal}),/cancelled/);
  assert.equal(f.calls.length,0);
  let checks=0; await assert.rejects(verify(f,evidence(f),()=>{if(++checks===20)throw Error('stop-check');}),/stop-check/);
});
test('legacy positive and creation evidence retain their exact profiles without invented result claims', async () => {
  for(const changes of [scenarios.text,scenarios.creation]) {
    const f=resultFixture('sha1',changes), r=(await validateSourceEditEvidence(f.capture,f.bundle,f.evidence)).source_verification;
    assert.equal(r.profile,changes===scenarios.text?'frankengit-source-edit-evidence-v1':'frankengit-source-edit-evidence-v2');
    assert.equal(Object.hasOwn(r,'requested_result_verified'),false);
  }
});
