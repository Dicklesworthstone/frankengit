import test from 'node:test';
import assert from 'node:assert/strict';
import { ArtifactClient } from '../../crates/fgit-node/src/smart_http/server/browser/artifacts.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { ARTIFACT_BYTES, artifactLocation, artifactMetadata, payloadPins, preview } from '../../crates/fgit-node/src/smart_http/server/browser/artifacts-protocol.mjs';
import { bindMetadata, crypto, deferred, digest, fixture, href, incarnation, token, unhex, vectors } from './artifacts-fixtures.mjs';

async function harness(index = 1, options = {}) {
  const f = fixture(index), client = new ArtifactClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl, ...options });
  await client.connect(token, incarnation);
  return { ...f, client, id: f.config.metadata.artifact_id,
    async inspect(pins) { return client.inspect(f.config.metadata.artifact_id, pins); },
    async verify() { await this.inspect(); return client.verifyDownload(); } };
}
for (const [index, vector] of vectors.entries()) {
  test(`native identity and namespace vectors: ${vector.name}`, async () => {
    const selected = await artifactMetadata(vector.metadata, { id: vector.metadata.artifact_id, incarnation }, crypto);
    assert.equal(selected.artifactIdentityVerified, true); assert.equal(selected.scopeCommitmentVerified, true);
    assert.deepEqual(bindMetadata(vector.metadata), vector.metadata);
    assert.equal(digest(unhex(vector.payload_hex)), vector.metadata.payload_sha256);
    const h = await harness(index); await h.verify();
    const file = h.client.download(); assert.equal(file.blob.type, 'application/octet-stream');
    assert.equal(file.filename, `artifact-${vector.metadata.artifact_id}`);
    assert.deepEqual(new Uint8Array(await file.blob.arrayBuffer()), h.original);
    h.client.disconnect(); assert.equal(h.client.state.artifact, null); assert.equal(h.client.preview, null);
    assert.throws(() => h.client.download(), /No complete verified/);
  });
}
test('inspect and verify use only exact bodyless GETs, no automatic fetch on connect, and token-free pinned links', async () => {
  const h = await harness(); assert.equal(h.calls.length, 0); assert.throws(() => h.client.download());
  await h.inspect({ payloadSha256: h.config.metadata.payload_sha256, payloadBytes: h.original.length });
  assert.equal(h.client.state.receiptPinsMatched, true); assert.equal(h.client.state.payloadVerified, false);
  assert.throws(() => h.client.download()); await h.client.verifyDownload();
  assert.deepEqual(h.calls.map(c => c.path), [`artifacts/${h.id}`, `artifacts/${h.id}`, `artifacts/${h.id}/content`, `artifacts/${h.id}`]);
  for (const { options, headers, url } of h.calls) {
    assert.equal(options.method, 'GET'); assert.equal(options.body, undefined); assert.equal(headers.authorization, `Bearer ${token}`);
    assert.equal(headers['content-type'], undefined); assert.equal(headers['idempotency-key'], undefined);
    for (const [key, value] of Object.entries({ redirect: 'error', mode: 'same-origin', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' })) assert.equal(options[key], value);
    assert.ok(!url.includes(token));
  }
  assert.equal(h.calls.find(call => call.path.endsWith('/content')).headers.accept, 'application/octet-stream');
  assert.equal(h.client.link(), `${href}#artifact=${h.id}&incarnation=${incarnation}`);
  assert.ok(!JSON.stringify(h.client.state).includes(token));
  const state = h.client.state; state.artifact.payload_sha256 = 'f'.repeat(64);
  assert.equal(h.client.state.artifact.payload_sha256, h.config.metadata.payload_sha256);
});
test('exact incarnation is mandatory and a pinned link cannot silently select its replacement', async () => {
  const f = fixture(), link = `${href}#artifact=${f.config.metadata.artifact_id}&incarnation=${incarnation}`;
  const client = new ArtifactClient({ href: link, cryptoImpl: crypto, fetchImpl: f.fetchImpl });
  assert.deepEqual(client.initialSelection, { id: f.config.metadata.artifact_id, incarnation });
  await assert.rejects(client.connect(token, '')); await assert.rejects(client.connect(token, 'ff'.repeat(16)), /pinned link/);
  assert.equal(f.calls.length, 0); await client.connect(token, incarnation);
  f.config.metadata = bindMetadata({ ...f.config.metadata, repository_incarnation_id: 'aa'.repeat(16) });
  await assert.rejects(client.inspect(f.config.metadata.artifact_id), /incarnation changed/);
  assert.equal(client.state.artifact, null);
});
test('page and fragment grammar exclude token/query, remote HTTP, alternate roots and ambiguous pin fragments', () => {
  for (const url of [href + '?token=x', href + '#token=x', href + '#artifact=' + 'a'.repeat(64),
    href.replace('https:', 'http:'), href.replace('/artifacts/', '/pulls/'),
    `${href}#artifact=${'a'.repeat(64)}&incarnation=${incarnation}&token=x`,
    `${href}#incarnation=${incarnation}&artifact=${'a'.repeat(64)}`]) assert.throws(() => artifactLocation(url));
  assert.equal(artifactLocation('http://127.0.0.1/repo.git/ui/artifacts/').root.route, '/repo.git');
});
test('artifact transport forbids every other API lane, mutation envelope and recovery mode before sending', async () => {
  const f = fixture(), id = f.config.metadata.artifact_id;
  const transport = new Transport({ href, pageSuffix: '/ui/artifacts/', cryptoImpl: crypto, fetchImpl: f.fetchImpl });
  await transport.connect(token);
  const opts = { maximum: 16 * 1024 };
  for (const path of ['artifacts', 'artifacts/' + id + '?root=anything', 'artifacts/' + id + '/content?x=1', 'outcomes', 'source/tree', 'pulls/1', 'artifacts/../' + id,
    'https://elsewhere.example/artifacts/' + id, 'artifacts/' + id.toUpperCase(), 'artifacts/' + id + '/delete']) {
    await assert.rejects(transport.request(path, opts));
  }
  for (const invalid of [{ method: 'POST' }, { body: '' }, { key: 'key' }, { read: false }, { statuses: [200, 404] }, { statuses: null },
    { binary: true }, { maximum: 16385 }, { contentType: 'text/plain' }]) await assert.rejects(transport.request(`artifacts/${id}`, { ...opts, ...invalid }));
  for (const invalid of [{ binary: false }, { maximum: ARTIFACT_BYTES + 1 }, { maximum: -1 }, { maximum: 1.1 }]) {
    await assert.rejects(transport.request(`artifacts/${id}/content`, { binary: true, maximum: ARTIFACT_BYTES, ...invalid }));
  }
  assert.throws(() => transport.restrictToRecovery({ key: 'key', principal: '12'.repeat(16) }));
  await assert.rejects(transport.connect(token, null, { key: 'key', principal: '12'.repeat(16) }));
  await assert.rejects(transport.connect('fgagent_' + token)); assert.equal(f.calls.length, 0);
});
test('other browser profiles gain no artifact-read route', async () => {
  for (const suffix of ['pulls','source','initial','branches','search','transfers','tags','replay','rebase','queues']) {
    const f = fixture(), transport = new Transport({ href: href.replace('/artifacts/', `/${suffix}/`), pageSuffix: `/ui/${suffix}/`, cryptoImpl: crypto, fetchImpl: f.fetchImpl });
    await transport.connect(token); await assert.rejects(transport.request(`artifacts/${f.config.metadata.artifact_id}`, { maximum: 16384 }));
    assert.equal(f.calls.length, 0);
  }
});
test('metadata must reproduce every artifact identity and namespace field, not just echo the requested ID', async () => {
  const changes = [ { artifact_id: 'f'.repeat(64) }, { scope_sha256: 'f'.repeat(64) }, { payload_sha256: 'f'.repeat(64) },
    { tenant_id: 'ab'.repeat(16) }, { repository_id: 'ab'.repeat(16) }, { payload_bytes: 1 }, { kind: 'sbom' },
    { media_type: 'image/svg+xml' }, { build_capsule_sha256: 'f'.repeat(64) }, { check_receipt_sha256: null },
    { source_rcr_sha256: null }, { retention_canonical_hex: '03' }, { provenance_authenticated: true },
    { canonical_repository_published: true }, { retention_enforced: true }, { payload_verified: false }, { read_only: false },
    { trust_domain: 'another-domain' }, { schema_version: 2 }, { unexpected: true } ];
  for (const change of changes) {
    const h = await harness(); h.config.metadata = { ...h.config.metadata, ...change };
    await assert.rejects(h.client.inspect(h.id), undefined, JSON.stringify(change));
    assert.equal(h.client.state.artifact, null); assert.throws(() => h.client.download());
  }
  const h = await harness(); delete h.config.metadata.source_rcr_sha256; await assert.rejects(h.inspect(), /Incomplete/);
});
test('retention parsing refuses noncanonical/truncated/unknown/oversized encodings even with matching IDs', async () => {
  for (const retention of ['', '00', '0300', '0101', '02000000', '04000000000000000100000001ff',
    '04000000000000000100000401' + '61'.repeat(1025)]) {
    const h = await harness(); h.config.metadata = bindMetadata({ ...h.config.metadata, retention_canonical_hex: retention });
    await assert.rejects(h.inspect(), /retention|hold|hex/); assert.equal(h.client.state.artifact, null);
  }
});
test('custody namespace remains pinned across exact-ID inspections within one connection', async () => {
  const h = await harness(); await h.inspect();
  h.config.metadata = bindMetadata({ ...h.config.metadata, tenant_id: '55'.repeat(16) });
  await assert.rejects(h.inspect(), /namespace changed/); assert.equal(h.client.state.artifact, null);
  await h.client.connect(token, incarnation); await h.inspect(); assert.equal(h.client.state.scope.tenant, '55'.repeat(16));
});
test('optional receipt pins are exact and paired, and mismatches cannot leave a previous download selected', async () => {
  for (const pins of [{ payloadSha256: 'a'.repeat(64) }, { payloadBytes: 1 }, { payloadSha256: 'a'.repeat(64), payloadBytes: -1 },
    { payloadSha256: 'A'.repeat(64), payloadBytes: 1 }, { payloadSha256: null, payloadBytes: null, other: true }]) assert.throws(() => payloadPins(pins));
  for (const pins of [{ payloadSha256: 'f'.repeat(64), payloadBytes: 25 }, { payloadSha256: vectors[1].metadata.payload_sha256, payloadBytes: 0 }]) {
    const h = await harness(); await h.verify(); await assert.rejects(h.inspect(pins), /receipt pins/);
    assert.equal(h.client.state.artifact, null); assert.equal(h.client.preview, null); assert.throws(() => h.client.download());
  }
});
test('metadata above the browser cap remains inspectable but no content request is sent', async () => {
  const h = await harness(); h.config.metadata = bindMetadata({ ...h.config.metadata, payload_bytes: ARTIFACT_BYTES + 1 });
  await h.inspect(); assert.equal(h.client.state.artifact.payload_bytes, ARTIFACT_BYTES + 1);
  await assert.rejects(h.client.verifyDownload(), /browser limit/); assert.equal(h.calls.length, 1);
});
test('verification rechecks the incarnation before any content disclosure', async () => {
  const h = await harness(); await h.inspect(); h.config.metadata = bindMetadata({ ...h.config.metadata, repository_incarnation_id: 'aa'.repeat(16) });
  await assert.rejects(h.client.verifyDownload(), /incarnation changed/);
  assert.equal(h.calls.filter(call => call.path.endsWith('/content')).length, 0); assert.equal(h.client.preview, null);
});
test('replacement during content transfer is refused by the final incarnation observation', async () => {
  const h = await harness(); await h.inspect();
  h.config.before = call => { if (call.path.endsWith('/content')) h.config.metadata = bindMetadata({ ...h.config.metadata, repository_incarnation_id: 'aa'.repeat(16) }); };
  await assert.rejects(h.client.verifyDownload(), /incarnation changed/);
  assert.equal(h.client.preview, null); assert.throws(() => h.client.download()); assert.equal(h.calls.length, 4);
});
test('revocation during content transfer prevents exposing even digest-correct bytes', async () => {
  const h = await harness(); await h.inspect();
  h.config.before = call => { if (call.path.endsWith('/content')) h.config.metadataStatus = 403; };
  await assert.rejects(h.client.verifyDownload(), error => error.status === 403);
  assert.equal(h.client.connected, false); assert.equal(h.client.preview, null); assert.equal(h.client.state.scope, null);
});
for (const status of [401,403,404,408,413,429,503]) test(`HTTP ${status} refuses without exposing an error body or stale bytes`, async () => {
  const h = await harness(); await h.verify(); h.config.metadataStatus = status;
  await assert.rejects(h.inspect(), error => error.status === status && !error.message.includes('private server error'));
  assert.equal(h.client.state.artifact, null); assert.equal(h.client.preview, null); assert.throws(() => h.client.download());
  if (status === 401 || status === 403) { assert.equal(h.client.connected, false); assert.equal(h.client.state.scope, null); }
});
test('whole-payload digest and length verification reject corrupted, short and oversized content', async () => {
  for (const change of [bytes => { bytes[0] ^= 1; return bytes; }, bytes => bytes.slice(1), bytes => Uint8Array.from([...bytes, 0])]) {
    const h = await harness(); await h.inspect(); h.config.content = change(h.config.content);
    await assert.rejects(h.client.verifyDownload(), /SHA-256|length|byte limit/);
    assert.equal(h.client.state.artifact, null); assert.equal(h.client.preview, null); assert.throws(() => h.client.download());
  }
});
test('content must use exact inert download framing and nosniff, never its declared payload MIME', async () => {
  for (const headers of [{ 'Content-Type': 'text/html' }, { 'Content-Disposition': 'inline' },
    { 'Content-Disposition': 'attachment; filename="private.html"' }, { 'X-Content-Type-Options': 'sniff' }, { 'Content-Length': '1' }]) {
    const h = await harness(3); await h.inspect(); h.config.contentHeaders = headers;
    await assert.rejects(h.client.verifyDownload(), /headers|length/); assert.equal(h.client.preview, null);
  }
});
test('decoded bytes are bounded and hashed even when a proxy encodes the wire representation', async () => {
  const h = await harness(); h.config.contentHeaders = { 'Content-Encoding': 'gzip', 'Content-Length': '500' };
  await h.verify(); assert.deepEqual(new Uint8Array(await h.client.download().blob.arrayBuffer()), h.original);
});
test('streaming overflow cancels the reader and never offers a verified prefix', async () => {
  const h = await harness(); await h.inspect(); let cancelled = 0;
  h.config.response = call => call.path.endsWith('/content') ? new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(h.original.length)); controller.enqueue(Uint8Array.of(0)); },
    cancel() { cancelled++; return new Promise(() => {}); }
  }), { headers: { 'Content-Type': 'application/octet-stream', 'X-Content-Type-Options': 'nosniff',
    'Content-Disposition': `attachment; filename="artifact-${h.id}"` } }) : new Response(JSON.stringify(h.config.metadata), {
    headers: { 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff' } });
  await assert.rejects(h.client.verifyDownload(), /byte limit/); assert.equal(cancelled, 1); assert.equal(h.client.preview, null);
});
test('disconnect and selection cancellation reject promptly and cannot be revived by a late response', async () => {
  for (const action of ['disconnect','cancelReads']) {
    const h = await harness(), gate = deferred(), started = deferred();
    h.config.before = async () => { started.resolve(); await gate.promise; };
    const work = h.inspect(), rejected = assert.rejects(work, /cancelled/); await started.promise; h.client[action](); await rejected;
    assert.equal(h.client.state.artifact, null); assert.equal(h.calls[0].options.signal.aborted, true);
    gate.resolve(); await new Promise(resolve => setImmediate(resolve)); assert.equal(h.client.state.artifact, null);
  }
});
test('an obsolete forbidden response cannot disconnect a newly connected credential', async () => {
  const h = await harness(), gate = deferred(), started = deferred();
  h.config.response = async () => { started.resolve(); await gate.promise; return new Response('', { status: 403 }); };
  const old = h.inspect(), rejected = assert.rejects(old, /cancelled/); await started.promise;
  await h.client.connect('cd'.repeat(32), incarnation); await rejected;
  h.config.response = null; await h.inspect(); gate.resolve(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(h.client.connected, true); assert.equal(h.client.state.artifact.artifact_id, h.id);
});
test('one operation deadline includes asynchronous metadata hashing and prevents late state installation', async () => {
  const gate = deferred(), started = deferred(); let calls = 0;
  const cryptoImpl = { subtle: { digest(...args) { if (++calls === 2) { started.resolve(); return gate.promise; } return crypto.subtle.digest(...args); } } };
  const h = await harness(1, { cryptoImpl, timeoutMs: 25 }); const work = h.inspect(); await started.promise;
  await assert.rejects(work, /deadline/); assert.equal(h.client.state.artifact, null);
  gate.resolve(new ArrayBuffer(32)); await new Promise(resolve => setImmediate(resolve)); assert.equal(h.client.state.artifact, null);
});
test('a connection hashing timeout cannot later install its credential', async () => {
  const gate = deferred(), f = fixture(), client = new ArtifactClient({ href, fetchImpl: f.fetchImpl, timeoutMs: 15,
    cryptoImpl: { subtle: { digest() { return gate.promise; } } } });
  await assert.rejects(client.connect(token, incarnation), /deadline/); gate.resolve(new ArrayBuffer(32));
  await new Promise(resolve => setImmediate(resolve)); assert.equal(client.connected, false); assert.equal(f.calls.length, 0);
});
test('disconnect zeroes a held payload during asynchronous hashing and a late digest cannot offer it', async () => {
  const gate = deferred(), started = deferred(); let held = null;
  const cryptoImpl = { subtle: { digest(algorithm, bytes) {
    if (digest(bytes) === vectors[1].metadata.payload_sha256) { held = bytes; started.resolve(); return gate.promise; }
    return crypto.subtle.digest(algorithm, bytes);
  } } };
  const h = await harness(1, { cryptoImpl }); await h.inspect();
  const work = h.client.verifyDownload(), rejected = assert.rejects(work, /cancelled/); await started.promise;
  assert.deepEqual(held, h.original); h.client.disconnect(); await rejected;
  assert.ok(held.every(byte => byte === 0));
  gate.resolve(await crypto.subtle.digest('SHA-256', h.original)); await new Promise(resolve => setImmediate(resolve));
  assert.equal(h.client.preview, null); assert.throws(() => h.client.download());
});
test('a malformed cryptographic result cannot be treated as an identity check', async () => {
  let calls = 0;
  const cryptoImpl = { subtle: { digest(...args) { return ++calls === 2 ? Promise.resolve(new ArrayBuffer(31)) : crypto.subtle.digest(...args); } } };
  const h = await harness(1, { cryptoImpl }); await assert.rejects(h.inspect(), /SHA-256 verification is unavailable/);
  assert.equal(h.client.state.artifact, null);
});
test('preview is bounded and HTML/control/binary content stays escaped inert text', () => {
  const html = preview(unhex(vectors[3].payload_hex)); assert.equal(html.text, '<script>alert("inert")</script>\n');
  assert.equal(preview(Uint8Array.of(0,255,10,9,65)).text, '\\x00\\xff\n\tA');
  const text = preview(new TextEncoder().encode('X\u202eY\u001bZ')); assert.equal(text.text, 'X\\u{202e}Y\\u{1b}Z');
  const large = preview(new Uint8Array(5000).fill(65)); assert.equal(large.shownBytes, 4096); assert.equal(large.clipped, true);
});
