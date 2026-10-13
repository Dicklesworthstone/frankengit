import test from 'node:test';
import assert from 'node:assert/strict';
import { captureSourceEdit, validateSourceEdit, editInput } from '../../scripts/operator/source_edit_candidate.mjs';
import { parse, upload, exchange, clock } from '../../scripts/operator/source_edit_wire.mjs';
import { peer, TOKEN, digest } from './source_edit_fixture.mjs';
for (const format of ['sha1', 'sha256']) test(`${format}: real Git bundle crosses native-schema prepare and inspect unchanged`, async t => {
  const f = await peer(t, format), result = await captureSourceEdit(f.request, f.patch, TOKEN);
  assert.deepEqual(result.bundle, f.bundle); assert.equal(result.candidate_commit, f.candidate);
  assert.equal(result.native_bundle_validation_observed, true); assert.equal(result.bundle_objects_independently_verified, false);
  assert.equal(result.publication_authorized, false); assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
  assert.ok(f.calls[0].body.includes(f.patch)); assert.ok(f.calls[1].body.includes(f.bundle));
  for (const c of f.calls) { assert.equal(c.method, 'POST'); assert.equal(c.headers['idempotency-key'], undefined); assert.equal(c.headers.cookie, undefined); }
  const offline = validateSourceEdit(result.capture, result.bundle); assert.deepEqual(offline.capture, result.capture);
  offline.bundle[0] ^= 1; assert.deepEqual(result.bundle, f.bundle);
});
for (const [name, alter] of [
  ['tenant', r => r.tenant_id = '7'.repeat(32)], ['incarnation', r => r.repository_incarnation = '7'.repeat(32)],
  ['branch', r => r.ref = 'refs/heads/other'], ['patch', r => r.patch_sha256 = '0'.repeat(64)],
  ['unexpected path', r => r.paths[0].path_hex = '6576696c'], ['bundle hash', r => r.bundle.sha256 = '0'.repeat(64)],
  ['staged claim', r => r.objects_staged = true], ['parent', r => r.source_commit = 'e'.repeat(40)],
  ['symlink edit', r => r.paths[0].new_mode = 0o120000],
]) test(`preparation refuses changed ${name} before inspection`, async t => {
  const f = await peer(t); f.control.mutate = r => alter(r);
  await assert.rejects(captureSourceEdit(f.request, f.patch, TOKEN)); assert.equal(f.calls.length, 1);
});
for (const [name, alter] of [
  ['commit bytes', r => r.candidate_commit_body_hex += '00'], ['another parent', r => r.parents.push(r.parents[0])],
  ['tree', r => r.comparison.after_tree = 'f'.repeat(40)], ['path omission', r => r.comparison.entries = []],
  ['entry count', r => r.comparison.entry_count++], ['wrong file', r => r.comparison.entries[0].after.oid = 'f'.repeat(40)],
  ['span bounds', r => r.comparison.entries[0].content.hunks[0].new.byte_end++],
  ['line count', r => r.comparison.entries[0].content.hunks[0].new.line_count++],
  ['effect claim', r => r.published = true], ['bad snapshot', r => r.snapshot_token = 'latest'],
]) test(`inspection refuses changed ${name} without a partial capture`, async t => {
  const f = await peer(t); f.control.mutate = (r, c) => { if (c.operation === 'inspect') alter(r); };
  await assert.rejects(captureSourceEdit(f.request, f.patch, TOKEN)); assert.equal(f.calls.length, 2);
});
test('metadata, controls and exact allowed path set are checked before any connection', async t => {
  const f = await peer(t);
  for (const change of [q => q.ref = 'HEAD', q => q.expected_commit = '0'.repeat(40), q => q.paths_hex.push('66696c65'),
    q => q.paths_hex = ['2e2e2f66696c65'], q => q.metadata.author += '\nforged', q => q.force = true,
    q => q.endpoint = 'http://example.invalid/repo.git', q => q.metadata.timestamp = 0]) {
    const q = structuredClone(f.request); change(q); assert.throws(() => editInput(q));
  }
  await assert.rejects(captureSourceEdit(f.request, Buffer.alloc(1048577), TOKEN));
  await assert.rejects(captureSourceEdit(f.request, f.patch, 'bad')); assert.equal(f.calls.length, 0);
});
test('native original commit metadata is compared with explicit author, time and message', async t => {
  const f = await peer(t);
  for (const change of [q => q.metadata.message = 'another message', q => q.metadata.timestamp++, q => q.metadata.author = 'Other <o@example.invalid>']) {
    const q = structuredClone(f.request); change(q); await assert.rejects(captureSourceEdit(q, f.patch, TOKEN), /commit_body/);
  }
});
test('shared wire allowance has an exact permitted twin', async t => {
  const f = await peer(t), first = await captureSourceEdit(f.request, f.patch, TOKEN), maxWireBytes = first.metrics.response_bytes;
  await captureSourceEdit(f.request, f.patch, TOKEN, { maxWireBytes });
  await assert.rejects(captureSourceEdit(f.request, f.patch, TOKEN, { maxWireBytes: maxWireBytes - 1 }));
});
test('caller edits during the first await do not change the retained request or patch', async t => {
  const f = await peer(t), input = structuredClone(f.request), patch = Buffer.from(f.patch);
  f.control.mutate = (_r, c) => { if (c.operation === 'prepare') { input.ref = 'refs/heads/other'; input.paths_hex.length = 0; patch.fill(0); } };
  const value = await captureSourceEdit(input, patch, TOKEN);
  assert.equal(value.capture.request.ref, f.request.ref); assert.equal(value.capture.patch_sha256, digest(f.patch));
});
for (const status of [301, 401, 403, 409, 429, 503]) test(`HTTP ${status} does not refresh, redirect or retry`, async t => {
  const f = await peer(t); f.control.status = status;
  await assert.rejects(captureSourceEdit(f.request, f.patch, TOKEN), e => e.status === status); assert.equal(f.calls.length, 1);
});
test('one deadline covers both phases and cancellation drains the client request', async t => {
  const f = await peer(t), stop = new AbortController(); stop.abort();
  await assert.rejects(captureSourceEdit(f.request, f.patch, TOKEN, { signal: stop.signal })); assert.equal(f.calls.length, 0);
  f.control.mutate = () => new Promise(resolve => setTimeout(resolve, 45));
  await assert.rejects(captureSourceEdit(f.request, f.patch, TOKEN, { timeoutMs: 70 }), /timeout/); assert.ok(f.calls.length <= 2);
});
test('duplicate keys, noncanonical counters, excessive depth and invalid UTF-8 cannot alter receipts', () => {
  for (const value of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a":1e0}', '{"a":-0}', '{"a":1.0}', '['.repeat(34) + '0' + ']'.repeat(34)])
    assert.throws(() => parse(Buffer.from(value), 4096));
  assert.throws(() => parse(Buffer.from([255]), 4096));
  assert.equal(parse(Buffer.from('{"decision_sequence":18446744073709551615}'), 4096).decision_sequence, '18446744073709551615');
});
test('closed wire profile rejects a mutation without its original key', async () => {
  await assert.rejects(exchange('http://127.0.0.1:1/repo.git', TOKEN, 'apply', upload({}, Buffer.from('x'), 'bundle'), clock(), 1024));
});
