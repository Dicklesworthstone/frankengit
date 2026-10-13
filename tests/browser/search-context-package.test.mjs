// Complete package/membership/source validators + actual shared Transport and
// real Fetch/WebCrypto/HTTP sockets. The peer is a native-schema fixture, not fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { acquireContextPackage, contextPackageCost, verifySourcePackage, encodeSourcePackage,
  readSourcePackage, SOURCE_PACKAGE_BYTES, sourcePackageLimits } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';
import { repository, definitions, basis, expectedFor, packageFor, online, hex, webcrypto, token } from './search-context-package-fixture.mjs';
const clone = value => structuredClone(value);
const decoded = text => new TextEncoder().encode(text);
for (const format of ['sha1', 'sha256']) {
  test(`portable source verifies all bytes and membership offline (${format})`, async () => {
    const repo = repository(format, definitions), value = packageFor(repo), expected = expectedFor(repo);
    const result = await verifySourcePackage(value, expected, webcrypto);
    assert.equal(result.commit, repo.commit); assert.equal(result.rootTree, repo.root.id);
    assert.equal(result.commitMembershipVerified, true); assert.equal(result.blobBytesVerified, true);
    for (const field of ['authorityVerified', 'freshnessVerified', 'signatureVerified', 'searchCoverageVerified', 'declarationSemanticsVerified', 'completeRepository']) assert.equal(result[field], false);
    assert.equal(result.files.length, 2); assert.equal(result.files[1].kind, 'executable');
    const encoded = await encodeSourcePackage(value, expected, webcrypto);
    const replayed = await readSourcePackage(decoded(encoded.serialized), expected, webcrypto);
    assert.deepEqual(replayed.package, value); assert.deepEqual(replayed.verified, result);
    assert.equal(encoded.serialized.includes(token), false);
    assert.deepEqual(value, packageFor(repo), 'caller evidence was not changed');
  });
  test(`acquisition uses fresh pinned metadata and only selected bodies (${format})`, async t => {
    const f = await online(t, { format });
    const answer = await acquireContextPackage(f.result, f.selection.ref, f.repo.commit, f.request, webcrypto);
    assert.deepEqual(answer.package, packageFor(f.repo));
    assert.deepEqual(answer.metrics, { metadataRequests: 3, blobRequests: 2,
      sourceBytesRead: definitions[0].data.length + definitions[1].data.length });
    assert.deepEqual(f.calls.map(c => c.operation), ['log', 'tree', 'tree', 'blob', 'blob']);
    for (const c of f.calls) {
      assert.equal(c.method, 'POST'); assert.equal(c.form.get('expected_head'), f.repo.snapshot);
      assert.equal(c.form.get('expected_commit'), f.repo.commit); assert.equal(c.headers['idempotency-key'], undefined);
      assert.equal(c.form.get('object_format'), format); assert.equal(c.form.get('ref'), f.selection.ref);
      assert.notEqual(c.form.get('path_hex'), hex('unused')); assert.notEqual(c.form.get('path_hex'), hex('unused/secret'));
    }
    const count = f.calls.length;
    await readSourcePackage(decoded(answer.serialized), f.expected, webcrypto);
    assert.equal(f.calls.length, count, 'offline replay never contacts the peer');
  });
  test(`empty, byte-only, shared and multi-page blobs (${format})`, async t => {
    const data = Buffer.alloc(65537, 255), raw = Buffer.from([255, 46, 114, 115]);
    const defs = [{ path: 'empty', data: Buffer.alloc(0) }, { path: raw, data }, { path: 'same', data }];
    const paths = defs.map(d => hex(d.path)); const f = await online(t, { format, definitions: defs, paths });
    const result = await acquireContextPackage(f.result, f.selection.ref, f.repo.commit, f.request, webcrypto);
    assert.equal(result.package.blobs.length, 2); assert.equal(result.verified.files.length, 3);
    assert.equal(result.metrics.blobRequests, 5); assert.equal(result.metrics.sourceBytesRead, data.length * 2);
    assert.equal(result.verified.logicalSourceBytes, data.length * 2); assert.equal(result.verified.uniqueSourceBytes, data.length);
    const loaded = await readSourcePackage(decoded(result.serialized), f.expected, webcrypto);
    assert.deepEqual(loaded.verified, result.verified);
    assert.equal(f.calls.filter(c => c.operation === 'blob' && c.form.get('path_hex') === hex('empty')).length, 1);
  });
  test(`source and page bounds preflight the whole selection (${format})`, async t => {
    const f = await online(t, { format }), cost = contextPackageCost(f.result, f.repo.commit);
    for (const limits of [{ maxSourceBytes: cost.sourceBytes - 1 }, { maxBlobRequests: cost.blobRequests - 1 },
      { membership: { maxRequests: 2 } }]) {
      await assert.rejects(acquireContextPackage(f.result, f.selection.ref, f.repo.commit, f.request, webcrypto, () => {}, limits));
      assert.equal(f.calls.length, 0);
    }
    const exact = { maxSourceBytes: cost.sourceBytes, maxBlobRequests: cost.blobRequests,
      membership: { maxTrees: 2, maxRequests: 3, maxEntries: 4, maxTreeBytes: f.repo.root.body.length + f.repo.dirs.get(hex('src')).body.length } };
    const answer = await acquireContextPackage(f.result, f.selection.ref, f.repo.commit, f.request, webcrypto, () => {}, exact);
    assert.equal(answer.verified.logicalSourceBytes, cost.sourceBytes);
    assert.deepEqual(answer.limits, sourcePackageLimits(exact));
  });
  test(`wrong independent root refuses before any I/O (${format})`, async t => {
    const f = await online(t, { format });
    await assert.rejects(acquireContextPackage(f.result, f.selection.ref, 'f'.repeat(format === 'sha1' ? 40 : 64), f.request, webcrypto));
    assert.equal(f.calls.length, 0);
  });
  test(`a complete valid source is not a valid package for another selection (${format})`, async () => {
    const repo = repository(format, definitions), value = packageFor(repo), expected = expectedFor(repo);
    expected.files[0].pathHex = hex('other');
    await assert.rejects(verifySourcePackage(value, expected, webcrypto));
    await assert.rejects(verifySourcePackage(value, { ...expectedFor(repo), commit: 'f'.repeat(format === 'sha1' ? 40 : 64) }, webcrypto));
  });
}
const corruptions = {
  'blob changed': p => { p.blobs[0].bytesHex = '00' + p.blobs[0].bytesHex.slice(2); },
  'blob shortened': p => { p.blobs[0].bytesHex = p.blobs[0].bytesHex.slice(2); },
  'blob missing': p => p.blobs.pop(),
  'blob duplicated': p => p.blobs.push(clone(p.blobs[0])),
  'blob unordered': p => p.blobs.reverse(),
  'unselected blob': p => p.blobs.push({ oid: 'f'.repeat(40), bytesHex: 'ff' }),
  'qualified package identity': p => { p.blobs[0].oid = 'sha1:' + p.blobs[0].oid; },
  'wrong hash domain': p => { p.membership.objectFormat = 'sha256'; },
  'odd body encoding': p => { p.blobs[0].bytesHex += '1'; },
  'uppercase encoding': p => { p.blobs[0].bytesHex = 'FF' + p.blobs[0].bytesHex.slice(2); },
  'unknown package field': p => { p.authorityVerified = true; },
  'unknown blob field': p => { p.blobs[0].trusted = true; },
  'foreign schema': p => { p.schema += '-other'; },
  'changed original commit': p => { p.membership.commit.bodyHex += '00'; },
  'changed original tree': p => { p.membership.trees[0].bodyHex += '00'; },
  'missing parent': p => p.membership.trees.pop(),
  'extra parent': p => p.membership.trees.push(clone(p.membership.trees[0])),
  'unrelated parent': p => { p.membership.trees[1].pathHex = hex('unused'); },
  'changed file mode': p => { p.membership.files[0].kind = 'executable'; },
  'selected symlink': p => { p.membership.files[0].kind = 'symlink'; },
  'changed file identity': p => { p.membership.files[0].blob = 'f'.repeat(40); },
  'unknown proof fields': p => { p.membership.verified = true; },
};
for (const [name, corrupt] of Object.entries(corruptions)) test(`offline package rejects ${name}`, async () => {
  const repo = repository('sha1', definitions), p = packageFor(repo); corrupt(p);
  await assert.rejects(verifySourcePackage(p, expectedFor(repo), webcrypto));
  await assert.rejects(readSourcePackage(decoded(JSON.stringify(p)), expectedFor(repo), webcrypto));
});
for (const [name, change] of Object.entries({
  snapshot: v => { v.snapshot_token = `alg:2:${'f'.repeat(64)}`; },
  incarnation: v => { v.repository_incarnation = 'f'.repeat(32); },
  kind: v => { v.kind = v.kind === 'file' ? 'executable' : 'file'; },
  identity: v => { v.object_id = 'f'.repeat(40); },
  bytes: v => { v.content_hex = '00' + v.content_hex.slice(2); },
  range: v => { v.offset = 1; },
  continuation: v => { v.next_offset = 1; },
})) test(`acquisition rejects changed ${name} without returning a prefix`, async t => {
  const f = await online(t);
  f.control.mutate = (value, call) => { if (call.operation === 'blob' && call.form.get('path_hex') === hex('src/main.rs')) change(value); };
  await assert.rejects(acquireContextPackage(f.result, f.selection.ref, f.repo.commit, f.request, webcrypto));
  assert.equal(f.calls.filter(c => c.operation === 'blob').length, 2);
});
test('all needed metadata must verify before any source body is read', async t => {
  const f = await online(t);
  f.control.mutate = (v, call) => { if (call.operation === 'tree') v.entries.pop(); };
  await assert.rejects(acquireContextPackage(f.result, f.selection.ref, f.repo.commit, f.request, webcrypto));
  assert.equal(f.calls.some(c => c.operation === 'blob'), false);
});
test('deduplicated bodies still spend a logical-byte allowance per selected path', async () => {
  const repo = repository('sha1', [{ path: 'a', data: Buffer.from('abcd') }, { path: 'b', data: Buffer.from('abcd') }]);
  const paths = ['a', 'b'].map(hex), p = packageFor(repo, paths), expected = expectedFor(repo, paths);
  await assert.rejects(verifySourcePackage(p, expected, webcrypto, () => {}, { maxSourceBytes: 7 }));
  const result = await verifySourcePackage(p, expected, webcrypto, () => {}, { maxSourceBytes: 8 });
  assert.equal(result.logicalSourceBytes, 8); assert.equal(result.uniqueSourceBytes, 4);
});
test('untrusted package bytes are bounded and strict UTF-8', async () => {
  const repo = repository('sha1', definitions), expected = expectedFor(repo);
  for (const value of [new Uint8Array(), new Uint8Array(SOURCE_PACKAGE_BYTES + 1), new Uint8Array([255]), decoded('\ufeff{}'), decoded('{')]) {
    await assert.rejects(readSourcePackage(value, expected, webcrypto));
  }
});
test('oversized inventories and byte bodies refuse before crypto', async () => {
  const repo = repository('sha1', definitions), expected = expectedFor(repo); let digests = 0;
  const crypto = { subtle: { digest() { digests++; throw new Error('unexpected crypto'); } } };
  for (const change of [p => { p.blobs = Array(33).fill(p.blobs[0]); }, p => { p.blobs[0].bytesHex = 'ff'.repeat(9 * 1024 * 1024); },
    p => { p.membership.trees = Array(129).fill(p.membership.trees[0]); }]) {
    const p = packageFor(repo); change(p); await assert.rejects(verifySourcePackage(p, expected, crypto));
  }
  assert.equal(digests, 0);
});
test('offline hashing owns proof bytes, file bodies and expected pins before yielding', async () => {
  const repo = repository('sha1', definitions), original = packageFor(repo), p = clone(original), expected = expectedFor(repo);
  let release; const gate = new Promise(resolve => { release = resolve; }); let first = true;
  const crypto = { subtle: { async digest(...args) { if (first) { first = false; await gate; } return webcrypto.subtle.digest(...args); } } };
  const pending = encodeSourcePackage(p, expected, crypto);
  p.membership.commit.bodyHex = '00'; p.blobs[0].bytesHex = 'ff'; expected.commit = 'f'.repeat(40); expected.files.length = 0;
  release(); const checked = await pending;
  assert.deepEqual(JSON.parse(checked.serialized), original);
  assert.equal(checked.verified.commit, repo.commit);
});
test('cancellation during crypto refuses without a result', async () => {
  const repo = repository('sha1', definitions), controller = new AbortController();
  const crypto = { subtle: { async digest(...args) { const answer = await webcrypto.subtle.digest(...args); controller.abort(); return answer; } } };
  await assert.rejects(verifySourcePackage(packageFor(repo), expectedFor(repo), crypto, () => controller.signal.throwIfAborted()));
});
test('disconnect cancels the real response stream without retry', async t => {
  const f = await online(t); let reached;
  const arrived = new Promise(resolve => { reached = resolve; });
  f.control.respond = (req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); reached(); };
  const pending = acquireContextPackage(f.result, f.selection.ref, f.repo.commit, f.request, webcrypto);
  const refused = assert.rejects(pending); await arrived; f.transport.disconnect(); await refused;
  assert.equal(f.calls.length, 1);
});
test('real transport deadline bounds a stalled acquisition', async t => {
  const f = await online(t, { timeoutMs: 50 });
  f.control.respond = (req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); };
  await assert.rejects(acquireContextPackage(f.result, f.selection.ref, f.repo.commit, f.request, webcrypto));
  assert.equal(f.calls.length, 1);
});
