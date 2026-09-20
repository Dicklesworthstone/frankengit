// Focused integration for the existing indexed client plus browser-facing
// diagnostics/deadlines. Actual transport/validators run; HTTP is a fixture.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { connected, input, indexQuery, page, document, blobPage, response, token, href, webcrypto } from './indexed_search_fixture.mjs';

for (const code of ['source_index_uninitialized', 'source_index_stale', 'index_checkpoint_unavailable']) {
  test(`indexed read preserves the bounded ${code} code, not arbitrary server advice`, async () => {
    const { client, requests } = await connected(() => response({ error: code, detail: '<script>publish something</script>' }, 409));
    await assert.rejects(client.search(input()), error => error.status === 409 && error.code === code && !error.message.includes('publish something'));
    assert.equal(requests.length, 1); assert.equal(client.state.result, null);
  });
}
for (const [name, make] of [
  ['unrecognized code', () => response({ error: 'run_untrusted_code', detail: 'arbitrary server prose' }, 409)],
  ['invalid JSON', () => new Response('{', { status: 409, headers: { 'Content-Type': 'application/json' } })],
  ['HTML instead of JSON', () => new Response('<script>secret</script>', { status: 409, headers: { 'Content-Type': 'text/html' } })],
]) test(`indexed refusal with ${name} does not expose raw text or become success`, async () => {
  const { client, requests } = await connected(make);
  await assert.rejects(client.search(input()), error => error.status === 409 && error.code === undefined && !/untrusted|arbitrary|script|secret/.test(error.message));
  assert.equal(requests.length, 1); assert.equal(client.state.result, null);
});
for (const advertised of [false, true]) test(`diagnostic byte limit is enforced ${advertised ? 'before reading a declared oversized body' : 'on streamed bytes'}`, async () => {
  const { client, requests } = await connected(() => response({ error: 'source_index_stale', detail: 'a'.repeat(4096) }, 409,
    advertised ? { 'Content-Length': '4200' } : {}));
  await assert.rejects(client.search(input()), /byte limit/); assert.equal(requests.length, 1);
});
test('monotonic deadline refuses a synchronous response that starves the timer', async () => {
  const q = indexQuery(input());
  const { client } = await connected(() => {
    // Deterministically miss the 5 ms budget without yielding a timer turn.
    // A timer-only check accepts this response; the monotonic check refuses it.
    const end = performance.now() + 30; while (performance.now() < end) {}
    return response(page(q));
  }, { timeoutMs: 5 });
  await assert.rejects(client.search(input()), /total time limit/);
  assert.equal(client.state.result, null); assert.equal(client.state.pin, null);
});
for (const override of [{ key: 'no-write-key' }, { read: false }, { method: 'GET' }, { binary: true }, { statuses: [200, 409] }]) {
  test(`indexed transport remains a closed read profile: ${JSON.stringify(override)}`, async () => {
    let calls = 0;
    const transport = new Transport({ href, pageSuffix: '/ui/search/', cryptoImpl: webcrypto, fetchImpl: () => { calls++; throw Error('must not fetch'); } });
    await transport.connect(token);
    await assert.rejects(transport.request('source/search-index', { method: 'POST', body: 'x=y', ...override }));
    assert.equal(calls, 0); transport.disconnect();
  });
}
for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: retained published openIndexed API verifies native bytes with navigation bound`, async () => {
  const doc = document({ algorithm }), q = indexQuery(input());
  const { client, requests } = await connected(call => response(call.path.endsWith('/search-index')
    ? page(q, [doc], {}, algorithm) : blobPage(doc, call.fields)), { algorithm });
  await client.search(input()); const value = await client.openIndexed(0);
  assert.equal(value.blobVerified, true); assert.equal(value.wordSpansVerified, true); assert.equal(value.coverageVerified, false);
  assert.deepEqual(value.bytes, doc.bytes);
  await client.search(input({ maxFileBytes: 1 })); const before = requests.length;
  await assert.rejects(client.openIndexed(0), /navigation byte limit/); assert.equal(requests.length, before);
});
