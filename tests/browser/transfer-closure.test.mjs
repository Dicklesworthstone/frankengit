import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { inspectBundle, inspectVerifiedBundle, verifyExportManifest } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';
import * as served from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';
import * as offline from '../../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs';
import { crypto, deferred, binary, token } from './export-integrity-fixtures.mjs';
import { completeBundle, connectedTransfer } from './transfer-closure-fixtures.mjs';
for (const format of ['sha1', 'sha256']) {
  for (const delta of [null, 6, 7]) test(`${format}, delta=${delta}: audited exports verify real objects and closure while keeping exact v1 manifests`, async () => {
    const f = completeBundle(format, { delta }), { client, calls } = await connectedTransfer(f);
    const summary = await client.exportBundle({ verifyInventory: true, verifyClosure: true });
    assert.equal(summary.snapshot_refs_checked, true); assert.equal(client.exportVerification.object_closure_verified, true);
    assert.equal(client.exportVerification.reachable_objects, 3); assert.equal(client.exportVerification.delta_objects, delta ? 1 : 0);
    assert.equal(client.exportVerification.independently_authenticated, false);
    assert.deepEqual(client.exportBytes(), f.bytes); assert.equal(client.pending, null);
    const manifest = client.exportManifest(); assert.equal(JSON.parse(manifest).bundle.objects_verified, false, 'v1 remains transport-only evidence');
    const checked = await verifyExportManifest(f.bytes, manifest, crypto, () => {}, { verifyClosure: true });
    assert.equal(checked.object_closure_verified, true); assert.equal(checked.objects_verified, true);
    const legacy = await verifyExportManifest(f.bytes, manifest, crypto);
    assert.equal(legacy.objects_verified, false); assert.equal(legacy.verification, undefined);
    assert(calls.every(call => call.method === 'POST' && !call.headers['Idempotency-Key']));
    assert(!manifest.includes(token));
  });
  for (const omit of ['blob', 'tree']) test(`${format}: checksum-valid export missing ${omit} cannot become a verified download`, async () => {
    const f = completeBundle(format, { omit }), { client } = await connectedTransfer(f);
    await client.exportBundle({ verifyInventory: true }); const legacy = client.exportManifest();
    assert.equal(client.exportVerification, null);
    await assert.rejects(client.exportBundle({ verifyInventory: true, verifyClosure: true }), error => error.code === 'missing_reachable_object');
    assert.equal(client.exported, null); assert.equal(client.exportVerification, null);
    assert.throws(() => client.exportBytes()); assert.throws(() => client.exportManifest());
    assert.equal((await verifyExportManifest(f.bytes, legacy, crypto)).objects_verified, false);
    await assert.rejects(verifyExportManifest(f.bytes, legacy, crypto, () => {}, { verifyClosure: true }), error => error.code === 'missing_reachable_object');
  });
}
test('multiple complete inventory pages are all bound to the verified export', async () => {
  const f = completeBundle('sha1', { refCount: 202 }), { client, calls } = await connectedTransfer(f);
  await client.exportBundle({ verifyInventory: true, verifyClosure: true });
  assert.equal(client.exportVerification.refs.length, 202); assert.equal(calls.length, 5);
  assert(calls.slice(1).every(call => new URLSearchParams(call.body).get('expected_head') === client.selection.head));
});
test('server artifact substitution is refused before object hashing and leaves no export', async () => {
  const f = completeBundle(), { client } = await connectedTransfer(f, { customize: path => path === 'source/bundle/export'
    ? binary(f.bytes, f.format, { 'x-fgit-artifact-sha256': 'f'.repeat(64) }) : null });
  await assert.rejects(client.exportBundle({ verifyInventory: true, verifyClosure: true }), error => error.code === 'expected_artifact_mismatch');
  assert.equal(client.exported, null);
});
test('complete but different ref sets do not substitute for a pinned inventory', async () => {
  const f = completeBundle(), other = completeBundle('sha1', { refCount: 2 });
  const { client } = await connectedTransfer(f, { customize: path => path === 'source/bundle/export' ? binary(other.bytes) : null });
  await assert.rejects(client.exportBundle({ verifyInventory: true, verifyClosure: true }), error => error.code === 'expected_ref_set_mismatch');
  assert.equal(client.exported, null);
});
for (const action of ['cancel', 'disconnect', 'invalidateBundle']) test(`${action} during verification cannot retain private proof or export bytes`, async () => {
  const gate = deferred(), entered = deferred(); let blocking = false;
  const controlled = { getRandomValues: a => crypto.getRandomValues(a), subtle: { async digest(...args) {
    if (blocking) { entered.resolve(); await gate.promise; } return crypto.subtle.digest(...args);
  } } };
  const { client } = await connectedTransfer(completeBundle(), { cryptoImpl: controlled }); blocking = true;
  const pending = client.exportBundle({ verifyInventory: true, verifyClosure: true }); await entered.promise;
  client[action](); gate.resolve(); await assert.rejects(pending);
  assert.equal(client.exported, null); assert.equal(client.exportVerification, null); assert.equal(client.busy, false);
});
test('a failure after an earlier verified export clears both its proof and downloads', async () => {
  let refuse = false; const { client } = await connectedTransfer(completeBundle(), { customize: path => refuse && path === 'source/bundle/export' ? new Response('', { status: 403 }) : null });
  await client.exportBundle({ verifyClosure: true }); assert(client.exportVerification);
  refuse = true; await assert.rejects(client.exportBundle({ verifyClosure: true }));
  assert.equal(client.exported, null); assert.equal(client.exportVerification, null);
});
test('full proof cannot mutate the retained transfer summary or bytes', async () => {
  const f = completeBundle(), { client } = await connectedTransfer(f); await client.exportBundle({ verifyInventory: true, verifyClosure: true });
  const proof = client.exportVerification; proof.refs[0].object_id = 'a'.repeat(40); proof.object_closure_verified = false;
  const bytes = client.exportBytes(); bytes.fill(0);
  assert.equal(client.exportVerification.refs[0].object_id, f.tip); assert.deepEqual(client.exportBytes(), f.bytes);
});
test('checksum and full-check paths own Buffer inputs before yielding', async () => {
  for (const inspect of [inspectBundle, inspectVerifiedBundle]) {
    const f = completeBundle(), input = Buffer.from(f.bytes); let changed = false;
    const controlled = { subtle: { digest(...args) { if (!changed) { changed = true; input.fill(0); } return crypto.subtle.digest(...args); } } };
    const result = await inspect(input, controlled); assert.deepEqual(result.bytes, f.bytes);
  }
});
test('legacy and full checks share the original deterministic object verifier', async () => {
  for (const name of Object.keys(offline)) assert.equal(offline[name], served[name]);
  const source = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs', import.meta.url), 'utf8');
  let moved = source.slice(source.indexOf('// Independent, read-only verification'), source.indexOf('\nreturn { BUNDLE_VERIFY_LIMITS'));
  for (const name of Object.keys(offline)) moved = moved.replace(new RegExp(`^(const|class|async function|function) ${name}\\b`, 'm'), 'export $&');
  const raw = Buffer.from(moved);
  assert.equal(createHash('sha1').update(`blob ${raw.length}\0`).update(raw).digest('hex'),
    '74561a4e58e2aa970094e4cbb5dc6feefdf27101', 'the original verifier body moved unchanged');
});
test('unsupported verification choices fail locally without creating a request', async () => {
  const { client, calls } = await connectedTransfer(); const count = calls.length;
  await assert.rejects(client.exportBundle({ verifyClosure: 'true' })); assert.equal(calls.length, count);
  assert.equal(client.exported, null); assert.equal(client.pending, null);
});
