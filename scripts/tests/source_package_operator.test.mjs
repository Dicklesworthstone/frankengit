import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { captureSourcePackage, inspectSourcePackage, packageAcquisitionLimits, packageAcquisitionSelection } from '../operator/source_package.mjs';
import { readSourcePackage } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';
import { fixture, peer, TOKEN, sha256 } from './source_package_fixture.mjs';
const capture = (p, options = {}) => captureSourcePackage(p.context, p.contextHash, p.selected, p.expected, TOKEN, options);
const inspect = (p, result, options = {}) => inspectSourcePackage(result.bytes, result.receipt.package_sha256, p.context, p.contextHash, p.selected, p.expected, options);
const updateContext = (p, change) => { const value = JSON.parse(p.context); change(value.native_response); p.context = Buffer.from(JSON.stringify(value)); p.contextHash = sha256(p.context); };

for (const format of ['sha1', 'sha256']) test(`${format}: native paginated capture, independent offline replay and deterministic package`, async t => {
  const p = await peer(t, fixture(format, { paged: true }));
  const result = await capture(p), value = JSON.parse(result.bytes), expectedPaths = p.expected.files.map(row => row.pathHex);
  assert.equal(result.metrics.metadataRequests, 4); assert.equal(result.metrics.blobRequests, 6);
  assert.equal(result.metrics.sourceBytesRead, p.f.rows.reduce((n, row) => n + row.bytes.length, 0));
  assert.equal(value.blobs.length, 3); // Two selected paths share a body but both incur reads.
  assert.deepEqual(value.membership.files.map(row => row.pathHex), expectedPaths);
  const receipt = await inspect(p, result);
  assert.deepEqual(receipt, result.receipt);
  assert.equal(receipt.context_excerpt_bytes_verified, true); assert.equal(receipt.excerpt_count, 4);
  assert.equal(receipt.verified.commitMembershipVerified, true); assert.equal(receipt.verified.blobBytesVerified, true);
  for (const field of ['authorityVerified', 'freshnessVerified', 'signatureVerified', 'searchCoverageVerified', 'completeRepository']) assert.equal(receipt.verified[field], false);
  const replay = await readSourcePackage(result.bytes, p.expected, webcrypto);
  assert.deepEqual(replay.verified, receipt.verified);
  assert.ok(result.bytes.equals((await capture(p)).bytes));
  for (const forbidden of [TOKEN, p.selected.endpoint, 'untrusted_query', 'generation', 'excerpts', 'verified']) assert.equal(result.bytes.toString().includes(forbidden), false);
});

test('bare native context is accepted; full-width unrelated generations are not rounded into pins', async t => {
  const p = await peer(t);
  p.context = Buffer.from(JSON.stringify(p.f.context).replace('"18446744073709551615"', '18446744073709551615'));
  p.contextHash = sha256(p.context);
  assert.equal((await capture(p)).receipt.verified.commit, p.f.commitId);
});

test('exact source, request, tree, entry and tree-byte budgets succeed', async t => {
  const p = await peer(t), maxSourceBytes = p.f.rows.reduce((n, row) => n + row.bytes.length, 0);
  const trees = [...p.f.trees.values()];
  const result = await capture(p, { limits: { package: { maxSourceBytes, maxBlobRequests: 6,
    membership: { maxRequests: 3, maxTrees: 2, maxEntries: trees.reduce((n, row) => n + row.entries.length, 0),
      maxTreeBytes: trees.reduce((n, row) => n + row.bytes.length, 0) } } } });
  assert.equal(result.receipt.verified.logicalSourceBytes, maxSourceBytes);
});
for (const name of ['source', 'blob requests', 'metadata requests', 'parent trees']) test(`one-under ${name} preflight refuses before network`, async t => {
  const p = await peer(t), total = p.f.rows.reduce((n, row) => n + row.bytes.length, 0);
  const limits = { source: { maxSourceBytes: total - 1 }, 'blob requests': { maxBlobRequests: 5 },
    'metadata requests': { membership: { maxRequests: 2 } }, 'parent trees': { membership: { maxTrees: 1 } } }[name];
  await assert.rejects(capture(p, { limits: { package: limits } })); assert.equal(p.requests.length, 0);
});
for (const name of ['entries', 'tree bytes']) test(`one-under ${name} refuses while verifying metadata, before blob disclosure`, async t => {
  const p = await peer(t), trees = [...p.f.trees.values()];
  const membership = name === 'entries' ? { maxEntries: trees.reduce((n, row) => n + row.entries.length, 0) - 1 }
    : { maxTreeBytes: trees.reduce((n, row) => n + row.bytes.length, 0) - 1 };
  await assert.rejects(capture(p, { limits: { package: { membership } } }));
  assert.equal(p.requests.some(call => call.path.endsWith('/blob')), false);
});

const invalidContexts = {
  'different tenant': c => { c.retrieval.tenant_id = '4'.repeat(32); },
  'different incarnation': c => { c.retrieval.repository_incarnation = '4'.repeat(32); },
  'different commit': c => { c.retrieval.source_commit = 'c'.repeat(40); },
  'different snapshot': c => { c.retrieval.snapshot_token = 'alg:1:bb'; },
  'wrong ref bytes': c => { c.retrieval.ref_hex = Buffer.from('refs/heads/other').toString('hex'); },
  'non-read retrieval': c => { c.retrieval.transaction_created = true; },
  'empty context': c => { c.files = []; c.returned_files = 0; },
  'duplicate path': c => { c.files[1] = c.files[0]; },
  'wrong count': c => { c.returned_files++; },
  'unsafe full file size': c => { c.files[1].source_bytes = 2 ** 53; },
  'out-of-range excerpt': c => { c.files[0].excerpts[0].untrusted_bytes_hex = '00'; },
  'duplicate empty excerpts': c => { c.files[0].excerpts.push({ ...c.files[0].excerpts[0] }); },
  'unknown excerpt field': c => { c.files[0].excerpts[0].authority_verified = true; },
};
for (const [name, change] of Object.entries(invalidContexts)) test(`saved context refuses ${name} before I/O`, async t => {
  const p = await peer(t); updateContext(p, change); await assert.rejects(capture(p)); assert.equal(p.requests.length, 0);
});
for (const name of ['root', 'file', 'extra file', 'unknown field']) test(`independent expected ${name} cannot be replaced from capture`, async t => {
  const p = await peer(t);
  if (name === 'root') p.expected = { ...p.expected, commit: 'c'.repeat(40) };
  if (name === 'file') p.expected.files[0].blob = 'c'.repeat(40);
  if (name === 'extra file') p.expected.files.push({ pathHex: '78', blob: 'c'.repeat(40) });
  if (name === 'unknown field') p.expected.authority_verified = true;
  await assert.rejects(capture(p)); assert.equal(p.requests.length, 0);
});

test('retained context hash and endpoint are mandatory independent bindings', async t => {
  const p = await peer(t); p.contextHash = '0'.repeat(64); await assert.rejects(capture(p));
  p.contextHash = sha256(p.context); p.selected = { ...p.selected, endpoint: p.selected.endpoint.replace('/repo', '/other') };
  await assert.rejects(capture(p)); assert.equal(p.requests.length, 0);
});

test('altered saved excerpt cannot become verified merely because its blob ID is correct', async t => {
  const p = await peer(t); updateContext(p, c => { c.files[1].excerpts[0].untrusted_bytes_hex = 'ff'.repeat(8); });
  await assert.rejects(capture(p), /excerpt differs/);
  assert.equal(p.requests.filter(call => call.path.endsWith('/blob')).length, 6);
});

for (const [name, change] of Object.entries({
  'commit body': value => { value.commits[0].body_hex += '00'; },
  'tree entry': value => { value.entries[0].object_id = 'c'.repeat(40); },
  'blob body': value => { if (value.content_hex) value.content_hex = 'ff' + value.content_hex.slice(2); },
  'blob mode': value => { value.kind = 'symlink'; },
  'snapshot': value => { value.snapshot_token = 'alg:1:bb'; },
  'incarnation': value => { value.repository_incarnation = '4'.repeat(32); },
})) test(`native ${name} tampering has no partial success or retry`, async t => {
  const target = name.startsWith('commit') ? 'source_log' : name.startsWith('tree') ? 'source_tree' : 'source_blob';
  let altered = false;
  const p = await peer(t, fixture(), value => { if (!altered && value.type === target && (name !== 'blob body' || value.content_hex)) { altered = true; change(value); } });
  await assert.rejects(capture(p)); assert.equal(altered, true);
  assert.equal(p.requests.filter(call => call.path.endsWith('/log')).length, 1);
});

test('authentication revocation aborts without retry or content leakage', async t => {
  const p = await peer(t, fixture(), (_value, call) => { call.res.writeHead(401); call.res.end('private rejected token'); return false; });
  await assert.rejects(capture(p), error => error.status === 401 && !error.message.includes('private'));
  assert.equal(p.requests.length, 1);
});

test('caller mutations during network I/O cannot alter the retained source selection', async t => {
  let p;
  p = await peer(t, fixture(), (_value, _call, calls) => {
    if (calls.length === 1) { p.context.fill(0); p.expected.commit = 'c'.repeat(40); p.expected.files.length = 0; p.selected.endpoint = 'http://127.0.0.1:1/evil'; }
  });
  const result = await capture(p); assert.equal(result.receipt.verified.commit, p.f.commitId); assert.equal(result.receipt.verified.files.length, 4);
});

test('pre-cancellation does no I/O; in-flight cancellation drains the real HTTP request', async t => {
  const controller = new AbortController(); controller.abort(new Error('selected stop'));
  const p = await peer(t); await assert.rejects(capture(p, { signal: controller.signal }), /selected stop/); assert.equal(p.requests.length, 0);
  const next = new AbortController(), stalled = await peer(t, fixture(), () => { next.abort(new Error('stop read')); return false; });
  await assert.rejects(capture(stalled, { signal: next.signal })); assert.equal(stalled.requests.length, 1);
});

test('one operation deadline bounds a stalled body', async t => {
  const p = await peer(t, fixture(), (_value, call) => { call.res.writeHead(200, { 'Content-Type': 'application/json' }); call.res.write('{'); return false; });
  const start = performance.now(); await assert.rejects(capture(p, { limits: { timeoutMs: 100 } }));
  assert.ok(performance.now() - start < 3000); assert.equal(p.requests.length, 1);
});

test('offline replay rejects changed package hash, bodies, saved excerpts and selection', async t => {
  const p = await peer(t), result = await capture(p), network = p.requests.length;
  await assert.rejects(inspectSourcePackage(result.bytes, '0'.repeat(64), p.context, p.contextHash, p.selected, p.expected));
  const value = JSON.parse(result.bytes); value.blobs.find(row => row.bytesHex).bytesHex += '00';
  const altered = Buffer.from(JSON.stringify(value));
  await assert.rejects(inspectSourcePackage(altered, sha256(altered), p.context, p.contextHash, p.selected, p.expected));
  updateContext(p, c => { c.files[1].excerpts[0].untrusted_bytes_hex = 'ff'.repeat(8); });
  await assert.rejects(inspect(p, result), /excerpt differs/); assert.equal(p.requests.length, network);
});

test('invalid limits and noncanonical or unsafe endpoints are typed refusals', () => {
  for (const value of [{ timeoutMs: 0 }, { timeoutMs: 300001 }, { package: { maxSourceBytes: 0 } }, { retries: 2 }]) assert.throws(() => packageAcquisitionLimits(value));
  const f = fixture(), selected = { endpoint: 'https://example.invalid/repo', tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: f.format, ref: 'refs/heads/main', expected_commit: f.commitId };
  assert.equal(packageAcquisitionSelection(selected).expected_commit, f.commitId);
  for (const endpoint of ['http://example.invalid/repo', 'http://localhost/repo', 'https://example.invalid/a/../repo', 'https://example.invalid/repo/', 'https://user:secret@example.invalid/repo', 'https://example.invalid/repo?x', 'https://example.invalid/%72epo']) assert.throws(() => packageAcquisitionSelection({ ...selected, endpoint }));
});

// The operator must not silently inherit Node's process-wide insecure TLS mode.
test('disabled TLS verification refuses before credential use or network', async t => {
  const p = await peer(t), before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  try { await assert.rejects(capture(p), /TLS verification/); assert.equal(p.requests.length, 0); }
  finally { if (before === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = before; }
});
