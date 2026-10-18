// HTTP transport integration tests, not an fg-binary or forge-admission E2E.
// Real Fetch decodes content codings but retains the encoded Content-Length.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib';
import { readBytes, Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

const token = 'ab'.repeat(32);
const payload = Buffer.from(JSON.stringify({ title: 'A real response', body: 'repository data\n'.repeat(1024) }));
const codings = [
  ['identity', bytes => bytes],
  ['gzip', gzipSync],
  ['deflate', deflateSync],
  ['br', brotliCompressSync],
  ['gzip, br', bytes => brotliCompressSync(gzipSync(bytes))],
];
async function fixture(t, handler) {
  const requests = [];
  const server = createServer((request, response) => {
    requests.push({ path: request.url, method: request.method, headers: request.headers });
    handler(request, response);
  });
  server.on('clientError', (_error, socket) => socket.destroy());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, requests };
}
function send(response, bytes, encoding, fixed = true, status = 200, type = 'application/json') {
  response.writeHead(status, { 'Content-Type': type, 'Content-Encoding': encoding,
    ...(fixed ? { 'Content-Length': String(bytes.length) } : { 'Transfer-Encoding': 'chunked' }) });
  response.end(bytes);
}
async function transport(origin, options = {}) {
  const client = new Transport({ href: `${origin}/repo/ui/pulls/`, timeoutMs: 2000, ...options });
  await client.connect(token);
  return client;
}

for (const [encoding, encode] of codings) for (const fixed of [true, false]) {
  test(`${encoding}: ${fixed ? 'fixed-length' : 'chunked'} reply is bounded in decoded bytes`, { timeout: 5000 }, async t => {
    const wire = encode(payload);
    const { origin } = await fixture(t, (_request, response) => send(response, wire, encoding, fixed));
    const response = await fetch(`${origin}/`);
    assert.equal(response.headers.get('Content-Length'), fixed ? String(wire.length) : null);
    const bytes = await readBytes(response, new AbortController().signal, payload.length);
    assert.deepEqual(Buffer.from(bytes), payload);
    assert.equal(response.body.locked, false);
  });
  test(`${encoding}: ${fixed ? 'fixed-length' : 'chunked'} decoded overflow is refused`, { timeout: 5000 }, async t => {
    const { origin } = await fixture(t, (_request, response) => send(response, encode(payload), encoding, fixed));
    const response = await fetch(`${origin}/`);
    await assert.rejects(readBytes(response, new AbortController().signal, payload.length - 1), /byte limit/);
    assert.equal(response.body.locked, false);
  });
}

for (const [encoding, encode] of codings.slice(1)) {
  test(`${encoding}: coding overhead does not consume the decoded budget`, { timeout: 5000 }, async t => {
    const body = Buffer.from('{}'), wire = encode(body);
    assert.ok(wire.length > body.length);
    const { origin } = await fixture(t, (_request, response) => send(response, wire, encoding));
    const client = await transport(origin);
    assert.deepEqual((await client.request('pulls', { maximum: body.length })).value, {});
  });
  test(`${encoding}: binary replies preserve every byte, including NUL`, { timeout: 5000 }, async t => {
    const body = Buffer.from(Array.from({ length: 4096 }, (_, i) => i % 256));
    const { origin } = await fixture(t, (_request, response) => send(response, encode(body), encoding, true, 200, 'multipart/mixed; boundary=example'));
    const client = await transport(origin);
    const reply = await client.request('pulls/1/prepare', { method: 'POST', body: '', binary: true, maximum: body.length });
    assert.deepEqual(Buffer.from(reply.value), body);
  });
}

test('an empty compressed binary response fits a zero decoded-byte budget', { timeout: 5000 }, async t => {
  const { origin } = await fixture(t, (_request, response) => send(response, gzipSync(Buffer.alloc(0)), 'gzip'));
  const response = await fetch(`${origin}/`);
  assert.equal((await readBytes(response, new AbortController().signal, 0)).length, 0);
});

for (const declared of ['1', '3', '01', '-1', '2.0', '2, 2']) {
  test(`identity replies still refuse inconsistent or malformed Content-Length ${declared}`, async () => {
    const response = new Response('{}', { headers: { 'Content-Length': declared } });
    await assert.rejects(readBytes(response, new AbortController().signal, 10), /length|byte limit/);
    assert.equal(response.body.locked, false);
  });
}
for (const declared of ['01', '-1', '2.0', '2, 2']) {
  test(`compression does not excuse malformed Content-Length ${declared}`, async () => {
    const response = new Response('{}', { headers: { 'Content-Length': declared, 'Content-Encoding': 'gzip' } });
    await assert.rejects(readBytes(response, new AbortController().signal, 10), /byte limit/);
  });
}
for (const encoding of [null, 'identity', ' IDENTITY ', 'identity, identity']) {
  test(`uncoded framing remains checked for ${JSON.stringify(encoding)}`, async () => {
    const headers = { 'Content-Length': '3', ...(encoding === null ? {} : { 'Content-Encoding': encoding }) };
    await assert.rejects(readBytes(new Response('{}', { headers }), new AbortController().signal, 10), /length/);
    headers['Content-Length'] = '2';
    assert.deepEqual(Buffer.from(await readBytes(new Response('{}', { headers }), new AbortController().signal, 2)), Buffer.from('{}'));
  });
}
for (const maximum of [NaN, Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
  test(`compressed reads require an exact finite byte budget: ${maximum}`, async () => {
    await assert.rejects(readBytes(new Response('{}', { headers: { 'Content-Encoding': 'gzip' } }), new AbortController().signal, maximum), /response byte limit/);
  });
}
for (const defect of ['truncated', 'checksum']) {
  test(`Fetch decoding failure (${defect}) is not accepted as complete JSON`, { timeout: 5000 }, async t => {
    const encoded = gzipSync(payload);
    const wire = defect === 'truncated' ? encoded.subarray(0, Math.floor(encoded.length / 2)) : Buffer.from(encoded);
    if (defect === 'checksum') wire[wire.length - 8] ^= 1;
    const { origin } = await fixture(t, (_request, response) => send(response, wire, 'gzip'));
    const client = await transport(origin);
    await assert.rejects(client.request('pulls'));
  });
}

test('compressed search refusal preserves the closed diagnostic code and HTTP error', { timeout: 5000 }, async t => {
  const body = Buffer.from(JSON.stringify({ error: 'source_index_stale', detail: 'do not display this prose' }));
  const { origin } = await fixture(t, (_request, response) => send(response, gzipSync(body), 'gzip', true, 409));
  const client = await transport(origin, { href: `${origin}/repo/ui/search/`, pageSuffix: '/ui/search/' });
  await assert.rejects(client.request('source/search-index', { method: 'POST', body: '' }), error => {
    assert.equal(error.status, 409);
    assert.equal(error.code, 'source_index_stale');
    assert.ok(!error.message.includes('do not display'));
    return true;
  });
});

test('compressed publication reply retains the original request key without replay', { timeout: 5000 }, async t => {
  const body = Buffer.from('{"published":true}');
  const { origin, requests } = await fixture(t, (_request, response) => send(response, gzipSync(body), 'gzip'));
  const client = await transport(origin);
  const result = await client.request('pulls/1/close', { method: 'POST', body: 'expected_version=1', key: 'sealed-request', read: false });
  assert.deepEqual(result.value, { published: true });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].headers['idempotency-key'], 'sealed-request');
  assert.equal(requests[0].headers.authorization, `Bearer ${token}`);
});

test('a broken encoded publication reply does not trigger an automatic resend', { timeout: 5000 }, async t => {
  const { origin, requests } = await fixture(t, (_request, response) => send(response, Buffer.from('not gzip'), 'gzip'));
  const client = await transport(origin);
  await assert.rejects(client.request('pulls/1/close', { method: 'POST', body: '', key: 'sealed-request', read: false }));
  assert.equal(requests.length, 1);
});

test('cancelling a compressed read does not cancel a concurrent publication', { timeout: 5000 }, async t => {
  const readStarted = Promise.withResolvers(), writeStarted = Promise.withResolvers();
  const { origin } = await fixture(t, (request, response) => {
    if (request.method === 'GET') {
      response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', 'Transfer-Encoding': 'chunked' });
      response.flushHeaders();
      readStarted.resolve();
    } else writeStarted.resolve(response);
  });
  const client = await transport(origin);
  const read = assert.rejects(client.request('pulls'), error => error.name === 'AbortError');
  const write = client.request('pulls/1/close', { method: 'POST', body: '', key: 'sealed-request', read: false });
  await readStarted.promise;
  const response = await writeStarted.promise;
  client.cancelReads();
  send(response, gzipSync(Buffer.from('{"published":true}')), 'gzip');
  await read;
  assert.deepEqual((await write).value, { published: true });
  assert.equal(client.connected, true);
});

test('a stalled compressed stream still expires under the transport deadline', { timeout: 5000 }, async t => {
  const { origin } = await fixture(t, (_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', 'Transfer-Encoding': 'chunked' });
    response.flushHeaders();
  });
  const client = await transport(origin, { timeoutMs: 100 });
  await assert.rejects(client.request('pulls'), error => error.name === 'AbortError');
});
