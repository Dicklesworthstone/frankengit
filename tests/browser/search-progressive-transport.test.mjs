// Real shared Transport, Fetch/HTTP sockets and WHATWG streams/TextDecoder.
// The records below are deliberately schema-opaque fixtures: this suite proves
// transport framing and lifecycle, not native source-generation correctness.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { webcrypto } from 'node:crypto';
import { once } from 'node:events';
import { gzipSync } from 'node:zlib';
import { Transport, FORM_LIMIT, REPLY_LIMIT, form, readJsonRecords } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

const TOKEN = '7'.repeat(64), ROUTE = 'source/search-progressive';
const BODY = form({ reference: 'refs/heads/main', object_format: 'sha256', text_hex: '636174' });
const INITIAL = { fixture: 'initial', text: 'caf\u00e9 \ud83c\udf32', inert: '<script>do not execute</script>' };
const TERMINAL = { fixture: 'refined', rows: [1, 2] };
const line = value => Buffer.from(JSON.stringify(value) + '\n');
const WIRE = Buffer.concat([line(INITIAL), line(TERMINAL)]);
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
};
const options = onRecord => ({ method: 'POST', body: BODY, onRecord });

async function peer(t, answer, overrides = {}) {
  const requests = [], errors = [];
  const server = createServer(async (request, response) => {
    try {
      let bytes = '';
      for await (const chunk of request) bytes += chunk;
      requests.push({ path: request.url, method: request.method, headers: request.headers, body: bytes });
      await answer(request, response, requests.at(-1));
    } catch (error) { errors.push(error); response.destroy(error); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const href = 'http://127.0.0.1:' + server.address().port + '/r.git/ui/search/';
  const client = new Transport({ href, cryptoImpl: webcrypto, pageSuffix: '/ui/search/', ...overrides });
  t.after(async () => {
    client.disconnect(); server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    assert.deepEqual(errors, []);
  });
  await client.connect(TOKEN);
  return { client, requests, href };
}
function ndjson(response, bytes = WIRE, extra = {}) {
  response.writeHead(200, { 'Content-Type': 'application/x-ndjson', ...extra });
  response.end(bytes);
}
function json(response, status, value) {
  response.writeHead(status, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(value));
}
// Actual WHATWG streams, including explicit source cleanup observation. Unlike
// Fetch, Response constructed here lets a test supply inconsistent length bytes.
function framed(chunks, { headers = {}, open = false, cancelResult } = {}) {
  let controller, cancellations = 0;
  const stream = new ReadableStream({
    start(value) {
      controller = value;
      for (const chunk of chunks) value.enqueue(chunk);
      if (!open) value.close();
    },
    cancel() { cancellations += 1; return cancelResult; },
  });
  return {
    response: new Response(stream, { headers: { 'Content-Type': 'application/x-ndjson', ...headers } }),
    get cancellations() { return cancellations; },
    close() { controller.close(); },
    enqueue(bytes) { controller.enqueue(bytes); },
  };
}
async function records(chunks, settings = {}) {
  const input = framed(chunks, settings), seen = [];
  await readJsonRecords(input.response, new AbortController().signal, settings.maximum ?? REPLY_LIMIT,
    (row, index) => { seen.push({ row, index }); });
  return seen;
}

test('Initial reaches the consumer before the peer sends its terminal record', { timeout: 8000 }, async t => {
  const first = deferred(), reply = deferred(), fetched = [];
  const { client, requests } = await peer(t, (_, response) => {
    response.writeHead(200, { 'Content-Type': 'application/x-ndjson' });
    response.write(line(INITIAL)); reply.resolve(response);
  }, { fetchImpl: (url, init) => { fetched.push(init); return fetch(url, init); } });
  const seen = [];
  let settled = false;
  const pending = client.request(ROUTE, options((row, index) => {
    seen.push({ row, index }); if (index === 0) first.resolve();
  }));
  const completion = pending.then(value => { settled = true; return value; }, error => { settled = true; throw error; });
  // Observe any rejection immediately, including before the peer accepts.
  const observed = completion.then(value => ({ value }), error => ({ error }));
  await Promise.race([first.promise, completion]);
  assert.deepEqual(seen, [{ row: INITIAL, index: 0 }]);
  assert.equal(settled, false);
  (await reply.promise).end(line(TERMINAL));
  const result = await observed; if (result.error) throw result.error;
  assert.equal(result.value.status, 200); assert.equal(result.value.value, null);
  assert.deepEqual(seen, [{ row: INITIAL, index: 0 }, { row: TERMINAL, index: 1 }]);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].path, '/r.git/api/v1/source/search-progressive');
  assert.equal(requests[0].method, 'POST'); assert.equal(requests[0].body, BODY);
  assert.equal(requests[0].headers.authorization, 'Bearer ' + TOKEN);
  assert.equal(requests[0].headers.accept, 'application/x-ndjson');
  assert.equal(requests[0].headers['content-type'], 'application/x-www-form-urlencoded');
  assert.equal(requests[0].headers['idempotency-key'], undefined);
  assert.equal(requests[0].headers.cookie, undefined);
  assert.equal(fetched[0].credentials, 'omit'); assert.equal(fetched[0].redirect, 'error');
  assert.equal(fetched[0].mode, 'same-origin'); assert.equal(fetched[0].cache, 'no-store');
  assert.equal(fetched[0].referrerPolicy, 'no-referrer');
});

test('terminal delivery remains provisional until an exact EOF', { timeout: 3000 }, async () => {
  const terminal = deferred(), input = framed([WIRE], { open: true });
  let settled = false;
  const seen = [];
  const pending = readJsonRecords(input.response, new AbortController().signal, WIRE.length, (row, index) => {
    seen.push({ row, index }); if (index === 1) terminal.resolve();
  });
  const observed = pending.then(() => { settled = true; }, error => { settled = true; throw error; });
  await terminal.promise; await Promise.resolve();
  assert.equal(settled, false); assert.equal(seen.length, 2);
  input.close(); await observed; assert.equal(settled, true);
});

test('UTF-8 code points and record delimiters survive arbitrary network chunk boundaries', async () => {
  const expected = [{ row: INITIAL, index: 0 }, { row: TERMINAL, index: 1 }];
  assert.deepEqual(await records([WIRE]), expected);
  assert.deepEqual(await records(Array.from(WIRE, byte => Uint8Array.of(byte))), expected);
  const crlf = Buffer.from(WIRE.toString('utf8').replaceAll('\n', '\r\n'));
  assert.deepEqual(await records([crlf.subarray(0, 1), new Uint8Array(), crlf.subarray(1)]), expected);
});

test('a line beyond the initial buffer capacity stays within the exact total byte budget', async () => {
  const initial = { text: 'x'.repeat(70 * 1024) };
  const bytes = Buffer.concat([line(initial), line(TERMINAL)]);
  const chunks = [];
  for (let offset = 0; offset < bytes.length; offset += 257) chunks.push(bytes.subarray(offset, offset + 257));
  assert.deepEqual(await records(chunks, { maximum: bytes.length }),
    [{ row: initial, index: 0 }, { row: TERMINAL, index: 1 }]);
  await assert.rejects(records(chunks, { maximum: bytes.length - 1 }), /byte limit/);
});

for (const [name, bytes, count] of [
  ['empty', Buffer.alloc(0), 0],
  ['only Initial', line(INITIAL), 1],
  ['unterminated terminal', WIRE.subarray(0, WIRE.length - 1), 1],
  ['two JSON objects on one line', Buffer.from('{}{}\n{}\n'), 0],
  ['array envelope', Buffer.from('[{},{}]\n{}\n'), 0],
  ['null record', Buffer.from('null\n{}\n'), 0],
  ['scalar record', Buffer.from('"fixture"\n{}\n'), 0],
  ['blank first record', Buffer.from('\n{}\n'), 0],
  ['blank terminal record', Buffer.concat([line(INITIAL), Buffer.from('\n')]), 1],
  ['invalid terminal JSON', Buffer.concat([line(INITIAL), Buffer.from('{\n')]), 1],
  ['extra record', Buffer.concat([WIRE, Buffer.from('{}\n')]), 2],
  ['blank trailing record', Buffer.concat([WIRE, Buffer.from('\n')]), 2],
  ['non-newline trailing bytes', Buffer.concat([WIRE, Buffer.from('junk')]), 2],
  ['UTF-8 BOM before JSON', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), WIRE]), 0],
  ['invalid UTF-8 terminal', Buffer.concat([line(INITIAL), Buffer.from('{"text":"'), Buffer.from([0xc3, 0x28]), Buffer.from('"}\n')]), 1],
]) {
  test('progressive framing refuses ' + name + ' without inventing another callback', async () => {
    const seen = [], input = framed([bytes]);
    await assert.rejects(readJsonRecords(input.response, new AbortController().signal, REPLY_LIMIT,
      (row, index) => { seen.push({ row, index }); }));
    assert.equal(seen.length, count);
    if (count >= 1) assert.deepEqual(seen[0], { row: INITIAL, index: 0 });
  });
}

test('identity Content-Length binds the full decoded representation exactly', async () => {
  assert.equal((await records([WIRE], { headers: { 'Content-Length': String(WIRE.length) } })).length, 2);
  for (const declared of [String(WIRE.length - 1), String(WIRE.length + 1), '0', '-1', '01', '1.0', '1, 1', 'invalid']) {
    await assert.rejects(records([WIRE], { headers: { 'Content-Length': declared } }), 'length ' + declared);
  }
});

test('declared oversize responses cancel their body before any record is delivered', async () => {
  const input = framed([WIRE], { open: true, headers: { 'Content-Length': String(WIRE.length + 1) } });
  let calls = 0;
  await assert.rejects(readJsonRecords(input.response, new AbortController().signal, WIRE.length, () => { calls += 1; }), /byte limit/);
  assert.equal(calls, 0); assert.equal(input.cancellations, 1);
});

test('streamed byte accounting includes line delimiters and all records', async () => {
  const seen = [], input = framed([line(INITIAL), line(TERMINAL)], { open: true });
  await assert.rejects(readJsonRecords(input.response, new AbortController().signal, WIRE.length - 1,
    (row, index) => { seen.push({ row, index }); }), /byte limit/);
  assert.deepEqual(seen, [{ row: INITIAL, index: 0 }]); assert.equal(input.cancellations, 1);
});

test('compressed HTTP reads measure decoded bytes while Fetch owns compressed wire framing', { timeout: 8000 }, async t => {
  const compressed = gzipSync(WIRE);
  const { client, requests } = await peer(t, (_, response) =>
    ndjson(response, compressed, { 'Content-Encoding': 'gzip', 'Content-Length': String(compressed.length) }));
  const seen = [];
  await client.request(ROUTE, { ...options((row, index) => { seen.push({ row, index }); }), maximum: WIRE.length });
  assert.deepEqual(seen, [{ row: INITIAL, index: 0 }, { row: TERMINAL, index: 1 }]);
  await assert.rejects(client.request(ROUTE, { ...options(() => {}), maximum: WIRE.length - 1 }), /byte limit/);
  assert.equal(requests.length, 2);
});

test('encoded length overhead does not replace the decoded allocation bound', async () => {
  assert.equal((await records([WIRE], { maximum: WIRE.length,
    headers: { 'Content-Encoding': 'gzip', 'Content-Length': String(WIRE.length + 100) } })).length, 2);
  await assert.rejects(records([WIRE], { maximum: WIRE.length - 1,
    headers: { 'Content-Encoding': 'gzip', 'Content-Length': '1' } }), /byte limit/);
  await assert.rejects(records([WIRE], { maximum: WIRE.length,
    headers: { 'Content-Encoding': 'identity', 'Content-Length': String(WIRE.length + 100) } }), /byte limit/);
});

test('progressive callbacks cannot acquire another route, method, write or recovery envelope', async t => {
  const { client, requests } = await peer(t, (_, response) => ndjson(response));
  for (const change of [{ method: 'GET' }, { method: 'PUT' }, { body: undefined }, { body: new Uint8Array() },
    { key: 'original-key' }, { key: '' }, { read: false }, { binary: true }, { contentType: 'application/json' },
    { statuses: [200, 409] }, { statuses: [] }, { maximum: 0 }, { maximum: REPLY_LIMIT + 1 },
    { body: 'x'.repeat(FORM_LIMIT + 1) }, { body: '\u00e9'.repeat(FORM_LIMIT / 2 + 1) },
    { onRecord: null }, { onRecord: false }, { onRecord: {} }]) {
    await assert.rejects(client.request(ROUTE, { ...options(() => {}), ...change }));
  }
  for (const path of ['source/search', 'source/search-initial', 'source/context-initial', 'source/apply', 'outcomes',
    ROUTE + '?x=1', ROUTE + '/', 'source/%73earch-progressive', '../' + ROUTE, '/' + ROUTE,
    'https://example.invalid/r.git/api/v1/' + ROUTE]) {
    await assert.rejects(client.request(path, options(() => {})));
  }
  assert.equal(requests.length, 0);
  await client.request(ROUTE, { ...options(() => {}), body: 'x'.repeat(FORM_LIMIT) });
  assert.equal(requests.length, 1);
});

test('streaming is confined to the explicit search browser profile', async t => {
  const { href, requests } = await peer(t, (_, response) => ndjson(response));
  for (const suffix of ['pulls', 'source', 'initial', 'branches', 'default-branch', 'transfers', 'tags', 'replay', 'rebase', 'queues', 'artifacts']) {
    const client = new Transport({ href: href.replace('/ui/search/', '/ui/' + suffix + '/'),
      pageSuffix: '/ui/' + suffix + '/', cryptoImpl: webcrypto });
    try { await client.connect(TOKEN); await assert.rejects(client.request(ROUTE, options(() => {}))); }
    finally { client.disconnect(); }
  }
  assert.equal(requests.length, 0);
});

for (const code of ['source_index_uninitialized', 'source_index_stale', 'symbol_index_uninitialized',
  'symbol_index_stale', 'index_checkpoint_unavailable', 'source_snapshot_mismatch', 'index_generation_mismatch']) {
  test('progressive HTTP 409 preserves only the registered diagnostic ' + code, async t => {
    const { client, requests } = await peer(t, (_, response) => json(response, 409, { error: code, message: 'untrusted prose' }));
    let calls = 0;
    await assert.rejects(client.request(ROUTE, options(() => { calls += 1; })), error => {
      assert.equal(error.status, 409); assert.equal(error.code, code);
      assert.equal(error.message.includes('untrusted prose'), false); return true;
    });
    assert.equal(requests.length, 1); assert.equal(calls, 0); assert.equal(client.connected, true);
  });
}
for (const detail of [{ error: '<img src=x onerror=alert(1)>' }, { error: ['source_index_stale'] }, { message: 'source_index_stale' }]) {
  test('progressive unregistered diagnostic remains a plain HTTP refusal ' + JSON.stringify(detail), async t => {
    const { client, requests } = await peer(t, (_, response) => json(response, 409, detail));
    await assert.rejects(client.request(ROUTE, options(() => assert.fail('error is not a record'))),
      error => error.status === 409 && error.code === undefined);
    assert.equal(requests.length, 1);
  });
}
for (const status of [401, 403, 404, 429, 503]) {
  test('HTTP ' + status + ' cannot become a progressive record or trigger a retry', async t => {
    const { client, requests } = await peer(t, (_, response) => json(response, status, { fixture: 'not progress' }));
    await assert.rejects(client.request(ROUTE, options(() => assert.fail('error is not progress'))), error => error.status === status);
    assert.equal(requests.length, 1); assert.equal(client.connected, status !== 401);
  });
}

test('redirects are refused without another credential-bearing request', async t => {
  const { client, requests } = await peer(t, (_, response) => {
    response.writeHead(302, { Location: '/other.git/api/v1/' + ROUTE }); response.end();
  });
  await assert.rejects(client.request(ROUTE, options(() => assert.fail('redirect is not progress'))));
  assert.equal(requests.length, 1);
});

for (const type of ['application/json', 'text/html', 'application/x-ndjson-extra']) {
  test('progressive transport refuses the wrong media type ' + type, async t => {
    const { client, requests } = await peer(t, (_, response) => {
      response.writeHead(200, { 'Content-Type': type }); response.end(WIRE);
    });
    await assert.rejects(client.request(ROUTE, options(() => assert.fail('wrong media is not progress'))));
    assert.equal(requests.length, 1);
  });
}

for (const refusal of ['media', 'redirected', 'foreign-url', 'status']) {
  test('early ' + refusal + ' refusal cancels an unread real stream', async t => {
    const input = framed([], { open: true });
    const response = refusal === 'status'
      ? new Response(input.response.body, { status: 503, headers: input.response.headers })
      : input.response;
    if (refusal === 'media') response.headers.set('Content-Type', 'text/html');
    if (refusal === 'redirected') Object.defineProperty(response, 'redirected', { value: true });
    if (refusal === 'foreign-url') Object.defineProperty(response, 'url', { value: 'https://example.invalid/r.git/api/v1/' + ROUTE });
    const client = new Transport({ href: 'http://127.0.0.1/r.git/ui/search/', pageSuffix: '/ui/search/',
      cryptoImpl: webcrypto, fetchImpl: async () => response });
    t.after(() => client.disconnect()); await client.connect(TOKEN);
    await assert.rejects(client.request(ROUTE, options(() => assert.fail('unread body must not publish'))));
    assert.equal(input.cancellations, 1);
  });
}

for (const stop of ['cancelReads', 'disconnect', 'deadline']) {
  test('a progressive read settles on ' + stop + ' after preserving its delivered Initial', { timeout: 8000 }, async t => {
    const first = deferred(), seen = [];
    const { client, requests } = await peer(t, (_, response) => {
      response.writeHead(200, { 'Content-Type': 'application/x-ndjson' }); response.write(line(INITIAL));
    }, { timeoutMs: stop === 'deadline' ? 1000 : 3000 });
    const pending = client.request(ROUTE, options((row, index) => { seen.push({ row, index }); first.resolve(); }));
    const refused = assert.rejects(pending);
    await Promise.race([first.promise, pending]); if (stop !== 'deadline') client[stop]();
    await refused;
    assert.deepEqual(seen, [{ row: INITIAL, index: 0 }]);
    assert.equal(requests.length, 1); assert.equal(client.connected, stop !== 'disconnect');
  });
}

for (const stop of ['cancelReads', 'disconnect', 'deadline']) {
  test('an async record consumer settles on ' + stop + ' before its late rejection', { timeout: 5000 }, async t => {
    const entered = deferred(), consumer = deferred(), seen = [];
    const { client } = await peer(t, (_, response) => ndjson(response), { timeoutMs: stop === 'deadline' ? 1000 : 3000 });
    const pending = client.request(ROUTE, options((row, index) => {
      seen.push({ row, index }); entered.resolve(); return consumer.promise;
    }));
    const refused = assert.rejects(pending);
    t.after(() => consumer.resolve());
    await Promise.race([entered.promise, pending]); if (stop !== 'deadline') client[stop](); await refused;
    assert.deepEqual(seen, [{ row: INITIAL, index: 0 }]);
    // node:test observes an unhandled rejection if the cancelled callback promise
    // is abandoned without a rejection handler.
    consumer.reject(new Error('late consumer failure'));
    await new Promise(resolve => setImmediate(resolve));
  assert.equal(client.connected, stop !== 'disconnect');
  });
}

test('callback cancellation stops another record in the very same chunk', async () => {
  const controller = new AbortController(), seen = [], input = framed([WIRE], { open: true });
  await assert.rejects(readJsonRecords(input.response, controller.signal, REPLY_LIMIT, (row, index) => {
    seen.push({ row, index }); controller.abort();
  }));
  assert.deepEqual(seen, [{ row: INITIAL, index: 0 }]); assert.equal(input.cancellations, 1);
});

test('source cleanup that never settles cannot prevent cancellation from settling', { timeout: 3000 }, async () => {
  const controller = new AbortController(), input = framed([line(INITIAL)], { open: true, cancelResult: new Promise(() => {}) });
  await assert.rejects(readJsonRecords(input.response, controller.signal, REPLY_LIMIT, () => controller.abort()));
  assert.equal(input.cancellations, 1); assert.equal(input.response.body.locked, false);
});

test('callback refusal cancels the source and never calls the terminal consumer', async () => {
  const input = framed([WIRE], { open: true }), seen = [];
  await assert.rejects(readJsonRecords(input.response, new AbortController().signal, REPLY_LIMIT, (row, index) => {
    seen.push({ row, index }); throw new Error('consumer rejected the record');
  }), /consumer rejected/);
  assert.deepEqual(seen, [{ row: INITIAL, index: 0 }]); assert.equal(input.cancellations, 1);
});

test('reconnecting invalidates a pending progressive read without disconnecting its replacement', { timeout: 8000 }, async t => {
  const first = deferred(), oldResponse = deferred(), seen = [];
  const { client, requests } = await peer(t, (_, response, request) => {
    if (request.headers.authorization === 'Bearer ' + TOKEN) {
      response.writeHead(200, { 'Content-Type': 'application/x-ndjson' });
      response.write(line(INITIAL)); oldResponse.resolve(response);
    } else ndjson(response);
  });
  const pending = client.request(ROUTE, options((row, index) => { seen.push({ row, index }); first.resolve(); }));
  const refused = assert.rejects(pending);
  await Promise.race([first.promise, pending]); await client.connect('8'.repeat(64)); await refused;
  (await oldResponse.promise).end(line(TERMINAL));
  const replacement = [];
  await client.request(ROUTE, options((row, index) => { replacement.push({ row, index }); }));
  assert.deepEqual(seen, [{ row: INITIAL, index: 0 }]);
  assert.deepEqual(replacement, [{ row: INITIAL, index: 0 }, { row: TERMINAL, index: 1 }]);
  assert.equal(requests.length, 2); assert.equal(client.connected, true);
});

test('missing bodies, non-byte chunks and pre-aborted reads never deliver a record', async () => {
  const signal = new AbortController();
  await assert.rejects(readJsonRecords(new Response(null), signal.signal, REPLY_LIMIT,
    () => assert.fail('missing body has no record')), /Missing response body/);
  const invalid = framed(['not a byte chunk'], { open: true });
  await assert.rejects(readJsonRecords(invalid.response, signal.signal, REPLY_LIMIT,
    () => assert.fail('non-bytes have no record')), /Invalid progressive response bytes/);
  assert.equal(invalid.cancellations, 1);
  signal.abort();
  const input = framed([WIRE], { open: true });
  await assert.rejects(readJsonRecords(input.response, signal.signal, REPLY_LIMIT,
    () => assert.fail('aborted read has no record')));
  assert.equal(input.cancellations, 1);
});
