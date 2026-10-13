// Real shared Transport, WebCrypto, Fetch and HTTP sockets. The peer checks the
// wire envelope; its JSON is not a Rust node or a source-context schema oracle.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { webcrypto } from 'node:crypto';
import { once } from 'node:events';
import { Transport, FORM_LIMIT, REPLY_LIMIT, form } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

const TOKEN = '7'.repeat(64), ROUTE = 'source/context-initial';
const body = form({ reference: 'refs/heads/main', object_format: 'sha256', text_hex: '636174', context_max_files: 2 });
async function peer(t, answer, options = {}) {
  const requests = [];
  const server = createServer(async (request, response) => {
    let bytes = '';
    for await (const chunk of request) bytes += chunk;
    requests.push({ path: request.url, method: request.method, headers: request.headers, body: bytes });
    answer(request, response, requests.at(-1));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const href = `http://127.0.0.1:${server.address().port}/r.git/ui/search/`;
  const client = new Transport({ href, cryptoImpl: webcrypto, pageSuffix: '/ui/search/', ...options });
  t.after(async () => { client.disconnect(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  await client.connect(TOKEN);
  return { client, requests, href };
}
function json(response, status, value) {
  response.writeHead(status, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value));
}
for (const algorithm of ['sha1', 'sha256']) for (const selection of ['raw-path-prefix', 'context-weighted-rrf-q16-v1']) {
  test(`context read reaches the real peer once (${algorithm}, ${selection})`, async t => {
    const reply = { untrusted: '<script>do not execute</script>', bytes: '00ff' };
    const { client, requests } = await peer(t, (_, response) => json(response, 200, reply));
    const exactBody = form({ object_format: algorithm, reference_hex: '726566732f68656164732f6d61696e',
      text_hex: '636174', context_selection: selection, context_max_files: 2, context_radius_bytes: 0 });
    const result = await client.request(ROUTE, { method: 'POST', body: exactBody });
    assert.deepEqual(result.value, reply);
    assert.equal(requests.length, 1); const received = requests[0];
    assert.equal(received.path, '/r.git/api/v1/source/context-initial');
    assert.equal(received.method, 'POST'); assert.equal(received.body, exactBody);
    assert.equal(received.headers.authorization, `Bearer ${TOKEN}`);
    assert.equal(received.headers['content-type'], 'application/x-www-form-urlencoded');
    assert.equal(received.headers.accept, 'application/json');
    assert.equal(received.headers['idempotency-key'], undefined); assert.equal(received.headers.cookie, undefined);
    assert.equal(client.connected, true);
  });
}

test('existing search routes retain their closed read envelope', async t => {
  const { client, requests } = await peer(t, (_, response) => json(response, 200, { received: true }));
  for (const path of ['search', 'search-batch', 'search-regex', 'search-index', 'search-symbols-index', 'search-initial', 'blob']) {
    assert.deepEqual((await client.request(`source/${path}`, { method: 'POST', body })).value, { received: true });
  }
  assert.equal(requests.length, 7);
});

test('context does not acquire another method, mutation, recovery, route or representation', async t => {
  const { client, requests } = await peer(t, (_, response) => json(response, 200, {}));
  for (const change of [{ method: 'GET' }, { method: 'PUT' }, { body: undefined }, { body: new Uint8Array() },
    { key: 'original-key' }, { key: '' }, { read: false }, { binary: true }, { contentType: 'application/json' },
    { statuses: [200, 409] }, { statuses: [] }, { maximum: 0 }, { maximum: REPLY_LIMIT + 1 },
    { body: 'x'.repeat(FORM_LIMIT + 1) }]) {
    await assert.rejects(client.request(ROUTE, { method: 'POST', body, ...change }));
  }
  for (const path of [`${ROUTE}?x=1`, `${ROUTE}/`, `${ROUTE}x`, 'source/%63ontext-initial',
    '../source/context-initial', '/r.git/api/v1/source/context-initial', 'source/apply', 'outcomes', 'pulls/1/open',
    'https://example.invalid/r.git/api/v1/source/context-initial']) {
    await assert.rejects(client.request(path, { method: 'POST', body }));
  }
  assert.equal(requests.length, 0);
});

test('enabling context in search does not enable it in any other browser profile', async t => {
  const { href, requests } = await peer(t, (_, response) => json(response, 200, {}));
  for (const suffix of ['pulls', 'source', 'initial', 'branches', 'transfers', 'tags', 'replay', 'rebase']) {
    const client = new Transport({ href: href.replace('/ui/search/', `/ui/${suffix}/`), pageSuffix: `/ui/${suffix}/`, cryptoImpl: webcrypto });
    try { await client.connect(TOKEN); await assert.rejects(client.request(ROUTE, { method: 'POST', body })); }
    finally { client.disconnect(); }
  }
  assert.equal(requests.length, 0);
});

for (const code of ['source_index_uninitialized', 'source_index_stale', 'symbol_index_uninitialized',
  'symbol_index_stale', 'index_checkpoint_unavailable', 'source_snapshot_mismatch', 'index_generation_mismatch']) {
  test(`context retains the native read refusal ${code} without retrying`, async t => {
    const { client, requests } = await peer(t, (_, response) => json(response, 409, { error: code, message: 'untrusted prose' }));
    await assert.rejects(client.request(ROUTE, { method: 'POST', body }), error => {
      assert.equal(error.status, 409); assert.equal(error.code, code);
      assert.equal(error.message.includes('untrusted prose'), false); return true;
    });
    assert.equal(requests.length, 1); assert.equal(client.connected, true);
  });
}
for (const detail of [{ error: '<img src=x onerror=alert(1)>' }, { error: ['source_index_stale'] }, { message: 'source_index_stale' }]) {
  test(`unknown diagnostic remains a plain refusal: ${JSON.stringify(detail)}`, async t => {
    const { client, requests } = await peer(t, (_, response) => json(response, 409, detail));
    await assert.rejects(client.request(ROUTE, { method: 'POST', body }), error => error.status === 409 && error.code === undefined);
    assert.equal(requests.length, 1);
  });
}
for (const status of [401, 403, 404, 429, 503]) {
  test(`HTTP ${status} never becomes context or triggers a retry`, async t => {
    const { client, requests } = await peer(t, (_, response) => json(response, status, { error: 'source_index_stale' }));
    await assert.rejects(client.request(ROUTE, { method: 'POST', body }), error => error.status === status && error.code === undefined);
    assert.equal(requests.length, 1); assert.equal(client.connected, status !== 401);
  });
}

test('context refuses redirect without following it or sending credentials again', async t => {
  const { client, requests } = await peer(t, (_, response) => {
    response.writeHead(302, { Location: '/other.git/api/v1/source/context-initial' }); response.end();
  });
  await assert.rejects(client.request(ROUTE, { method: 'POST', body })); assert.equal(requests.length, 1);
});
for (const kind of ['length', 'stream', 'media', 'json', 'diagnostic']) {
  test(`context enforces ${kind} response refusal`, async t => {
    const { client, requests } = await peer(t, (_, response) => {
      if (kind === 'length') { response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 17 }); response.end(' '.repeat(17)); }
      else if (kind === 'stream') { response.writeHead(200, { 'Content-Type': 'application/json' }); response.write(' '.repeat(16)); response.end('x'); }
      else if (kind === 'media') { response.writeHead(200, { 'Content-Type': 'text/html' }); response.end('{}'); }
      else if (kind === 'json') { response.writeHead(200, { 'Content-Type': 'application/json' }); response.end('{'); }
      else json(response, 409, { error: 'source_index_stale', extra: 'x'.repeat(4096) });
    });
    await assert.rejects(client.request(ROUTE, { method: 'POST', body, maximum: 16 })); assert.equal(requests.length, 1);
  });
}
for (const stop of ['cancelReads', 'disconnect', 'deadline']) {
  test(`context stream settles on ${stop} and cannot return a late result`, async t => {
    let arrived; const started = new Promise(resolve => { arrived = resolve; });
    const { client, requests } = await peer(t, (_, response) => {
      response.writeHead(200, { 'Content-Type': 'application/json' }); response.write('{'); arrived();
    }, { timeoutMs: stop === 'deadline' ? 100 : 3000 });
    const pending = client.request(ROUTE, { method: 'POST', body });
    // Attach rejection observation immediately, including before peer arrival.
    const refused = assert.rejects(pending);
    await Promise.race([started, pending]); if (stop !== 'deadline') client[stop]();
    await refused; assert.equal(requests.length, 1); assert.equal(client.connected, stop !== 'disconnect');
  });
}
