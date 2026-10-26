// Real native object graphs through the served verifier and transfer client.
// HTTP replies are doubles; native publication has separate Rust coverage.
import test from 'node:test';
import assert from 'node:assert/strict';
import { TransferClient } from '../../crates/fgit-node/src/smart_http/server/browser/transfers.mjs';
import { intakeExpectations } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-view.mjs';
import { FORM_LIMIT, form } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import {
  REF_LIMIT, MAPPING_LIMIT, HEADER_LIMIT, BUNDLE_VERIFY_LIMITS, inspectBundle,
  inspectVerifiedBundle, transferCommand, normalizeBundleExpectation, verifyGitBundle,
} from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';
import { bundle as encodeBundle } from './bundle-verify-fixtures.mjs';
import { completeBundle, connectedTransfer } from './transfer-closure-fixtures.mjs';
import { fixture, crypto, href, token, hex, decodeUpload } from './transfers-fixtures.mjs';

function shortBundle(format, count, { head = false } = {}) {
  const graph = completeBundle(format);
  const rows = Array.from({ length: count }, (_, n) => {
    const ref = n === 0 ? (head ? 'refs/heads/main' : 'refs/a') : 'refs/r' + String(n).padStart(4, '0');
    return { ref, ref_hex: hex(ref), object_id: graph.tip };
  });
  const refs = rows.map(row => ({ name: row.ref, id: row.object_id }));
  if (head) refs.push({ name: 'HEAD', id: graph.tip });
  return { ...graph, rows, bytes: new Uint8Array(encodeBundle(graph.records, format, { refs })) };
}
function mappings(source, count, old = null) {
  return Array.from({ length: count }, (_, n) => ({
    source_hex: source,
    destination_hex: hex('refs/d' + String(n).padStart(4, '0')),
    expected_old: n === 0 ? old : null,
  }));
}
const verify = input => verifyGitBundle(input, { cryptoImpl: crypto });

for (const format of ['sha1', 'sha256']) {
  for (const count of [65, 1024, 1025]) {
    test(format + ': complete imports cross the old ceilings at ' + count + ' refs', async () => {
      const graph = shortBundle(format, count);
      const checked = await inspectVerifiedBundle(graph.bytes, crypto);
      assert.equal(checked.verification.object_closure_verified, true);
      assert.equal(checked.verification.reachable_objects, 3);
      assert.equal(checked.summary.refs.length, count);
      assert(checked.summary.header_bytes < HEADER_LIMIT);
      const command = transferCommand('import', checked.summary);
      assert.equal(command.count, count);
      assert(command.updates.every(row => row.expected_old === null));
      assert.equal(command.fields.mapping, undefined);
      assert.equal((await inspectBundle(graph.bytes, crypto)).summary.refs.length, count);
    });
  }

  test(format + ': 4096 short fetch mappings retain exact leases and independent form bytes', async () => {
    const graph = shortBundle(format, 1), { summary } = await inspectVerifiedBundle(graph.bytes, crypto);
    const old = 'b'.repeat(format === 'sha1' ? 40 : 64);
    for (const count of [65, 1024, 4096]) {
      const input = mappings(graph.rows[0].ref_hex, count, old).reverse();
      const command = transferCommand('fetch', summary, input);
      assert.equal(command.count, count);
      assert(form(command.fields).length < FORM_LIMIT);
      assert.equal(command.updates[0].expected_old, old);
      assert(command.updates.slice(1).every(row => row.expected_old === null));
      assert.equal(command.updates[0].destination_hex, hex('refs/d0000'));
      assert.equal(new URLSearchParams(form(command.fields)).getAll('mapping').length, count);
    }
    assert.throws(() => transferCommand('fetch', summary, mappings(graph.rows[0].ref_hex, 4097)), /4096 explicit fetch mappings/);
    const longLeases = mappings(graph.rows[0].ref_hex, 4096, old).map(row => ({ ...row, expected_old: old }));
    assert.throws(() => transferCommand('fetch', summary, longLeases), /Encoded command exceeds 256 KiB/);
  });

  test(format + ': a lost 4096-command reply replays the exact bundle, leases and original key', async () => {
    const graph = shortBundle(format, 1), f = fixture(format, graph.bytes);
    const client = new TransferClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl });
    await client.connect(token); await client.select(format); await client.load(graph.bytes, { verifyClosure: true });
    const old = 'b'.repeat(format === 'sha1' ? 40 : 64);
    const input = mappings(graph.rows[0].ref_hex, 4096, old);
    await client.stage('fetch', input, { requireVerified: true });
    assert.equal(client.pending.count, 4096); assert.equal(client.pending.sent, false);
    input[0].expected_old = null; input.pop();
    const key = client.pending.key, receipt = client.exportReceipt();
    assert(!receipt.includes(token)); assert.equal(f.calls.length, 1);
    f.config.lose = true; await assert.rejects(client.send(), error => error.outcomeUnknown);
    const sent = f.calls.at(-1), upload = decodeUpload(sent);
    assert.deepEqual(upload.payload, graph.bytes);
    assert.equal(upload.fields.getAll('mapping').length, 4096);
    assert(upload.fields.getAll('mapping')[0].endsWith(':' + old));
    const retry = new TransferClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl });
    await retry.connect(token); const before = f.calls.length;
    await retry.restoreReceipt(receipt); assert.equal(f.calls.length, before);
    assert.equal(retry.pending.count, 4096); assert.equal(retry.pending.key, key);
    f.config.lose = false;
    assert.equal((await retry.send()).outcome, 'committed');
    assert.equal(retry.pending, null);
    assert.deepEqual(f.calls.at(-1).body, sent.body);
    assert.equal(f.calls.at(-1).headers['idempotency-key'], key);
  });

  test(format + ': more than 64 trusted pins fit while the 64 KiB text budget remains', () => {
    const graph = shortBundle(format, 65);
    const pins = graph.rows.map(row => row.ref + '=' + row.object_id).join('\n');
    assert.equal(intakeExpectations(format, '', pins, 'text', true).refs.length, 65);
    assert.throws(() => intakeExpectations(format, '', 'x'.repeat(65537), 'text', false), /trusted reference pins/);
  });
}

test('4096 SHA-1 advertised records import and verify without widening other resource ceilings', async () => {
  const graph = shortBundle('sha1', 4096);
  const checked = await inspectVerifiedBundle(graph.bytes, crypto);
  assert.equal(checked.verification.refs.length, 4096);
  assert.equal(checked.verification.reachable_objects, 3);
  assert(checked.summary.header_bytes < HEADER_LIMIT);
  assert.equal(transferCommand('import', checked.summary).count, 4096);
  assert.equal((await inspectBundle(graph.bytes, crypto)).summary.refs.length, 4096);
  assert.equal(normalizeBundleExpectation({
    object_format: 'sha1', exact_refs: true,
    refs: graph.rows.map(({ ref_hex, object_id }) => ({ ref_hex, object_id })),
  }).refs.length, 4096);
  assert.equal(REF_LIMIT, 4096); assert.equal(MAPPING_LIMIT, 4096);
  assert.equal(BUNDLE_VERIFY_LIMITS.maxRefs, 4096);
  assert.equal(BUNDLE_VERIFY_LIMITS.maxHeaderBytes, 256 * 1024);
  assert.equal(BUNDLE_VERIFY_LIMITS.maxInputBytes, 16 * 1024 * 1024);
  assert.equal(FORM_LIMIT, 256 * 1024);
  await assert.rejects(verifyGitBundle(graph.bytes, { cryptoImpl: crypto, limits: { maxRefs: 4095 } }),
    error => error.code === 'reference_limit');
});

test('4097 SHA-1 records refuse by count before any larger header budget is needed', async () => {
  const graph = shortBundle('sha1', 4097);
  assert(graph.bytes.length < HEADER_LIMIT);
  await assert.rejects(inspectBundle(graph.bytes, crypto), /4096 advertised reference records/);
  await assert.rejects(verify(graph.bytes), error => error.code === 'reference_limit');
  assert.throws(() => normalizeBundleExpectation({
    object_format: 'sha1', refs: graph.rows.map(({ ref_hex, object_id }) => ({ ref_hex, object_id })),
  }), error => error.code === 'expectation_reference_limit');
  assert.throws(() => transferCommand('import', {
    object_format: 'sha1', sha256: 'a'.repeat(64), refs: graph.rows,
  }), /4096 direct refs/);
});

test('optional HEAD consumes one advertised record, preserving the native envelope accounting', async () => {
  const atLimit = shortBundle('sha1', 4095, { head: true });
  assert.equal((await verify(atLimit.bytes)).refs.length, 4095);
  assert.equal((await inspectBundle(atLimit.bytes, crypto)).summary.advertised_head, atLimit.tip);
  const above = shortBundle('sha1', 4096, { head: true });
  await assert.rejects(verify(above.bytes), error => error.code === 'reference_limit');
  await assert.rejects(inspectBundle(above.bytes, crypto), /4096 advertised reference records/);
});

test('SHA-256 headers retain the independent 256 KiB limit below the 4096-record ceiling', async () => {
  const fits = shortBundle('sha256', 3000);
  const checked = await inspectVerifiedBundle(fits.bytes, crypto);
  assert.equal(checked.summary.refs.length, 3000); assert(checked.summary.header_bytes < HEADER_LIMIT);
  assert.equal(transferCommand('import', checked.summary).count, 3000);
  const oversized = shortBundle('sha256', 4096);
  await assert.rejects(inspectBundle(oversized.bytes, crypto), /Bundle header exceeds 256 KiB/);
  await assert.rejects(verify(oversized.bytes), error => error.code === 'bundle_header_limit_or_truncation');
});

test('full export inventory crosses 1024 refs and verifies all 4096 against the same snapshot', async () => {
  const graph = shortBundle('sha1', 4096), { client, calls } = await connectedTransfer(graph);
  await client.exportBundle({ verifyInventory: true, verifyClosure: true });
  assert.equal(client.exported.refs.length, 4096);
  assert.equal(client.exportVerification.refs.length, 4096);
  assert.equal(client.exportVerification.caller_expectations_matched, true);
  const pages = calls.filter(call => call.path === 'source/refs' && new URLSearchParams(call.body).get('limit') === '100');
  assert.equal(pages.length, 41);
  assert(pages.every(call => new URLSearchParams(call.body).get('expected_head') === client.selection.head));
  assert.equal(client.pending, null);
  const saved = JSON.parse(client.exportManifest());
  assert.equal(saved.bundle.refs.length, 4096);
});

test('an over-count inventory cannot download a bundle or claim a complete export', async () => {
  const { client, calls } = await connectedTransfer(shortBundle('sha1', 4097));
  await assert.rejects(client.exportBundle({ verifyInventory: true, verifyClosure: true }), /export inventory/);
  assert.equal(client.exported, null);
  assert.equal(client.pending, null);
  assert(!calls.some(call => call.path === 'source/bundle/export'));
});
