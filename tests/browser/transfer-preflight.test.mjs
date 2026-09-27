// Actual transfer client with real native object bytes and injected HTTP replies.
// No claim about native node admission or a real browser rendering engine.
import test from 'node:test';
import assert from 'node:assert/strict';
import { TransferClient } from '../../crates/fgit-node/src/smart_http/server/browser/transfers.mjs';
import { intakeExpectations } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-view.mjs';
import { completeBundle } from './transfer-closure-fixtures.mjs';
import { fixture, bundleBytes, token, crypto, href, sha, hex, deferred, decodeUpload } from './transfers-fixtures.mjs';
async function selected(format = 'sha1', input = completeBundle(format, { refCount: 2 }).bytes, cryptoImpl = crypto) {
  const f = fixture(format, input), client = new TransferClient({ href, cryptoImpl, fetchImpl: f.fetchImpl });
  await client.connect(token); await client.select(format); return { f, client, input };
}
const requirements = f => ({ sha256: sha(f.bytes), object_format: f.format, refs: f.rows.map(({ ref_hex, object_id }) => ({ ref_hex, object_id })), exact_refs: true });
for (const format of ['sha1', 'sha256']) {
  for (const operation of ['import', 'fetch']) test(`${format}: verified ${operation} preflight has no upload or authority side effect`, async () => {
    const graph = completeBundle(format, { refCount: 2, delta: operation === 'fetch' ? 6 : 7 }), { client, f } = await selected(format, graph.bytes);
    const summary = await client.load(graph.bytes, { verifyClosure: true, expectations: requirements(graph) });
    assert.equal(client.bundleVerification.object_closure_verified, true); assert.equal(client.bundleVerification.caller_expectations_matched, true);
    assert.equal(summary.objects_verified, false, 'legacy transport summary is not relabeled');
    assert.equal(f.calls.length, 1); assert.equal(client.pending, null);
    const mappings = operation === 'fetch' ? [{ source_hex: graph.rows[0].ref_hex, destination_hex: hex('refs/remotes/recovered/main'), expected_old: null }] : [];
    await client.stage(operation, mappings, { requireVerified: true }); const pending = client.pending;
    assert.equal(f.calls.length, 1); assert.equal(pending.sent, false);
    const receipt = client.exportReceipt(); assert.equal(receipt.includes(token), false);
    f.config.lose = true; await assert.rejects(client.send()); const sent = f.calls.at(-1);
    assert.deepEqual(decodeUpload(sent).payload, graph.bytes); assert.equal(client.pending.key, pending.key);
    const second = new TransferClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl });
    await second.connect(token); await second.restoreReceipt(receipt);
    assert.equal(second.bundleVerification, null, 'restoring request bytes does not manufacture a new proof');
    f.config.lose = false; const terminal = await second.send();
    assert.equal(terminal.outcome, 'committed'); assert.equal(second.pending, null);
    assert.deepEqual(f.calls.at(-1).body, sent.body); assert.equal(f.calls.at(-1).headers['idempotency-key'], pending.key);
  });
  test(`${format}: incomplete bundles never become new verified publications even with a matching artifact pin`, async () => {
    const graph = completeBundle(format, { omit: 'blob' }), { client, f } = await selected(format, graph.bytes);
    await assert.rejects(client.load(graph.bytes, { verifyClosure: true, expectations: requirements(graph) }), error => error.code === 'missing_reachable_object');
    assert.equal(client.bundle, null); assert.equal(client.bundleVerification, null); assert.equal(client.pending, null);
    await assert.rejects(client.stage('import', [], { requireVerified: true })); assert.equal(f.calls.length, 1);
    const good = completeBundle(format); await client.load(good.bytes, { verifyClosure: true });
    await client.stage('import', [], { requireVerified: true }); assert.equal(client.pending.count, 1);
  });
  test(`${format}: internally valid wrong artifacts, tips and exact ref sets refuse without upload`, async () => {
    const graph = completeBundle(format), other = completeBundle(format, { file: Buffer.from('other history') });
    const { client, f } = await selected(format, graph.bytes);
    await assert.rejects(client.load(other.bytes, { verifyClosure: true, expectations: { sha256: sha(graph.bytes) } }), error => error.code === 'expected_artifact_mismatch');
    await assert.rejects(client.load(other.bytes, { verifyClosure: true, expectations: { object_format: format, refs: requirements(graph).refs } }), error => error.code === 'expected_ref_mismatch');
    const extra = completeBundle(format, { refCount: 2 });
    await assert.rejects(client.load(extra.bytes, { verifyClosure: true, expectations: requirements(graph) }), error => error.code === 'expected_ref_set_mismatch');
    assert.equal(client.bundleVerification, null); assert.equal(f.calls.length, 1);
    await client.load(extra.bytes, { verifyClosure: true, expectations: { object_format: format, refs: requirements(graph).refs } });
    assert.equal(client.bundleVerification.expectations.ref_set, 'contains'); assert.equal(client.bundleVerification.refs.length, 2);
  });
}
test('new verified preparation cannot silently accept a legacy checksum-only selection', async () => {
  const { client, f, input } = await selected(); await client.load(input);
  assert.equal(client.bundleVerification, null); await assert.rejects(client.stage('import', [], { requireVerified: true }), /Verify the complete/);
  assert.equal(client.pending, null); assert.equal(f.calls.length, 1);
  await client.load(input, { verifyClosure: true }); await client.stage('import', [], { requireVerified: true });
  assert.equal(client.pending.count, 2);
});
test('historical incomplete request receipts stay recoverable without fresh preflight or listing', async () => {
  const input = bundleBytes(), { client, f } = await selected('sha1', input);
  await client.load(input); await client.stage('import'); const receipt = client.exportReceipt(), key = client.pending.key;
  const next = new TransferClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl }); await next.connect(token);
  const before = f.calls.length; await next.restoreReceipt(receipt);
  assert.equal(f.calls.length, before); assert.equal(next.pending.key, key); assert.equal(next.bundleVerification, null);
  await assert.rejects(next.load(completeBundle().bytes, { verifyClosure: true }), /Resolve the original/);
  assert.equal(next.pending.key, key); f.config.outcome = 'refused';
  const result = await next.recover(); assert.equal(result.outcome, 'refused'); assert.equal(next.pending, null);
  assert.equal(f.calls.at(-1).path, 'outcomes'); assert.equal(f.calls.at(-1).headers['idempotency-key'], key);
});
test('preflight requirements do not alter canonical multipart bytes, request keys or receipt schema', async () => {
  const graph = completeBundle('sha1', { refCount: 2 });
  const deterministic = { getRandomValues(array) { array.fill(41); return array; }, subtle: crypto.subtle };
  const legacy = await selected('sha1', graph.bytes, deterministic), full = await selected('sha1', graph.bytes, deterministic);
  await legacy.client.load(graph.bytes); await legacy.client.stage('import');
  await full.client.load(graph.bytes, { verifyClosure: true, expectations: requirements(graph) });
  await full.client.stage('import', [], { requireVerified: true });
  assert.deepEqual(full.client.pending, legacy.client.pending); assert.equal(full.client.exportReceipt(), legacy.client.exportReceipt());
});
for (const action of ['cancel', 'disconnect', 'invalidateBundle']) test(`${action} interrupts local preflight and cannot revive its selected bytes`, async () => {
  const graph = completeBundle(), gate = deferred(), entered = deferred(); let stop = false;
  const controlled = { getRandomValues: a => crypto.getRandomValues(a), subtle: { async digest(...args) {
    if (stop) { entered.resolve(); await gate.promise; } return crypto.subtle.digest(...args);
  } } };
  const { client, f } = await selected('sha1', graph.bytes, controlled); stop = true;
  const work = client.load(graph.bytes, { verifyClosure: true, expectations: requirements(graph) }); await entered.promise;
  client[action](); gate.resolve(); await assert.rejects(work);
  assert.equal(client.bundle, null); assert.equal(client.bundleVerification, null); assert.equal(client.pending, null); assert.equal(f.calls.length, 1);
});
test('an expectation mutation during hashing cannot select new pins or corrupt retained bytes', async () => {
  const graph = completeBundle(), expected = requirements(graph); let mutate = false;
  const controlled = { getRandomValues: a => crypto.getRandomValues(a), subtle: { async digest(...args) {
    if (mutate) { mutate = false; expected.sha256 = 'f'.repeat(64); expected.refs.length = 0; graph.bytes.fill(0); }
    return crypto.subtle.digest(...args);
  } } };
  const original = graph.bytes.slice(), { client } = await selected('sha1', graph.bytes, controlled); mutate = true;
  await client.load(graph.bytes, { verifyClosure: true, expectations: expected });
  assert.equal(client.bundleVerification.sha256, sha(original)); assert.equal(client.bundleVerification.expectations.refs.length, 1);
  const view = client.bundleVerification; view.refs[0].object_id = 'a'.repeat(40);
  assert.equal(client.bundleVerification.refs[0].object_id, graph.tip);
});
test('invalid options and incompatible pin hash domains fail without upload and clear prior proof', async () => {
  const graph = completeBundle(), { client, f } = await selected();
  for (const opts of [{ verifyClosure: 'true' }, { expectations: requirements(graph) }, { verifyClosure: true, unexpected: true }]) {
    await client.load(graph.bytes, { verifyClosure: true }); await assert.rejects(client.load(graph.bytes, opts));
    assert.equal(client.bundleVerification, null); assert.equal(client.pending, null);
  }
  await assert.rejects(client.load(graph.bytes, { verifyClosure: true, expectations: { object_format: 'sha256', sha256: sha(graph.bytes) } }), error => error.code === 'expected_object_format_mismatch');
  assert.equal(f.calls.length, 1);
});
test('pin controls preserve exact names, binary names, full IDs and deliberate exactness', () => {
  const graph = completeBundle('sha256'), typed = `sha256:${graph.tip.toUpperCase()}`;
  const parsed = intakeExpectations('sha256', sha(graph.bytes), `refs/heads/a=b=${typed}\r\n`, 'text', true);
  assert.equal(parsed.refs[0].ref_hex, hex('refs/heads/a=b')); assert.equal(parsed.exact_refs, true);
  const byteRef = hex('refs/tags/') + 'ff';
  assert.equal(intakeExpectations('sha256', '', `${byteRef}=${typed}`, 'hex', false).refs[0].ref_hex, byteRef);
  assert.equal(intakeExpectations('sha1', '', '', 'text', false), null);
  assert.throws(() => intakeExpectations('sha1', '', '', 'text', true));
  assert.throws(() => intakeExpectations('sha1', '', `refs/heads/main=${typed}`, 'text', false));
  assert.throws(() => intakeExpectations('sha1', '', 'x'.repeat(65537), 'text', false));
  assert.throws(() => intakeExpectations('sha1', '', Array(65).fill('refs/heads/main=' + 'a'.repeat(40)).join('\n'), 'text', false));
  for (const line of ['refs/heads/main', 'refs/heads/main=', '../main=' + 'a'.repeat(40), 'refs/heads/a=' + 'a'.repeat(39)]) {
    assert.throws(() => intakeExpectations('sha1', '', line, 'text', false));
  }
});
test('local preflight deadline includes asynchronous hashing and cannot leave a late proof', async t => {
  let now = 0, slow = false; t.mock.method(performance, 'now', () => now);
  const controlled = { getRandomValues: a => crypto.getRandomValues(a), subtle: { async digest(...args) {
    const result = await crypto.subtle.digest(...args); if (slow) now += 15000; return result;
  } } };
  const graph = completeBundle(), { client } = await selected('sha1', graph.bytes, controlled); slow = true;
  await assert.rejects(client.load(graph.bytes, { verifyClosure: true }), error => error.code === 'deadline');
  assert.equal(client.bundle, null); assert.equal(client.bundleVerification, null);
  slow = false; await client.load(graph.bytes, { verifyClosure: true }); assert.equal(client.bundleVerification.object_closure_verified, true);
});
