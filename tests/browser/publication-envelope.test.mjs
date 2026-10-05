import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

const response = () => new Response('{}', { headers: { 'Content-Type': 'application/json' } });
const envelope = () => ({ method: 'POST', body: 'exact=command', key: 'original-key', read: false });
async function client(profile, fetchImpl) {
  const transport = new Transport({
    href: `http://127.0.0.1/repo/ui/${profile}/`, pageSuffix: `/ui/${profile}/`,
    cryptoImpl: webcrypto, fetchImpl,
  });
  await transport.connect('a'.repeat(64));
  return transport;
}

// Include every publication route, including paths shared by multiple pages.
// The server owns authorization and command validation; these tests exercise
// the actual shared transport, not a duplicate route/envelope implementation.
const publications = [
  ...['open', 'update', 'close', 'reopen', 'merge'].map(action => ['pulls', `pulls/1/${action}`]),
  ...['approve', 'request-changes', 'withdraw'].map(action => ['pulls', `pulls/1/reviews/${action}`]),
  ['source', 'source/apply'], ['initial', 'source/initial/apply'],
  ['replay', 'source/apply'], ['rebase', 'source/rebase/apply'],
  ...['create', 'update', 'delete', 'rename'].map(action => ['branches', `source/branches/${action}`]),
  ...['import', 'fetch'].map(action => ['transfers', `source/bundle/${action}`]),
  ...['lightweight', 'annotated', 'delete'].map(action => ['tags', `source/tags/${action}`]),
];
for (const [profile, path] of publications) {
  test(`${profile}: ${path} requires a keyed non-read publication before network I/O`, async () => {
    const sent = [];
    const transport = await client(profile, async (url, options) => {
      sent.push({ url, options }); return response();
    });
    for (const changes of [
      { key: undefined }, { key: '' }, { key: 1 },
      { read: undefined }, { read: true }, { read: null }, { read: 0 },
      { method: 'GET' }, { method: 'PUT' }, { body: undefined },
    ]) {
      await assert.rejects(transport.request(path, { ...envelope(), ...changes }), Error,
        `must reject ${JSON.stringify(changes)}`);
      assert.equal(sent.length, 0, 'invalid publication must not transmit');
    }
    const original = envelope();
    const result = await transport.request(path, original);
    assert.equal(result.status, 200);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].url.pathname, `/repo/api/v1/${path}`);
    assert.equal(sent[0].options.method, 'POST');
    assert.equal(sent[0].options.headers['Idempotency-Key'], original.key);
    assert.equal(sent[0].options.body, original.body);
    transport.disconnect();
  });
}

for (const profile of ['pulls', 'source', 'initial', 'branches', 'transfers', 'tags', 'replay', 'rebase']) {
  test(`${profile}: outcome lookup retains the key but cannot resubmit a command`, async () => {
    const sent = [];
    const transport = await client(profile, async (_url, options) => { sent.push(options); return response(); });
    const lookup = { method: 'POST', key: 'original-key', read: false };
    for (const changes of [{ key: undefined }, { key: '' }, { read: true }, { method: 'GET' }, { body: 'resubmit=command' }]) {
      await assert.rejects(transport.request('outcomes', { ...lookup, ...changes }), Error);
      assert.equal(sent.length, 0);
    }
    await transport.request('outcomes', lookup);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].body, undefined);
    assert.equal(sent[0].headers['Content-Type'], undefined);
    assert.equal(sent[0].headers['Idempotency-Key'], lookup.key);
    transport.disconnect();
  });
}

test('query strings cannot disguise terminal PR or review writes', async () => {
  let calls = 0;
  const transport = await client('pulls', async () => { calls++; return response(); });
  for (const [, path] of publications.filter(([profile]) => profile === 'pulls')) {
    await assert.rejects(transport.request(`${path}?after=0`, envelope()), Error);
  }
  assert.equal(calls, 0);
  transport.disconnect();
});

test('existing read and preparation routes do not require publication envelopes', async () => {
  const reads = [
    ['pulls', 'pulls?after=0', {}],
    ['pulls', 'pulls/1/reviews', {}],
    ['pulls', 'pulls/1/checks', { statuses: [200, 404] }],
    ...['diff', 'prepare', 'resolve', 'inspect'].map(action => ['pulls', `pulls/1/${action}`, { method: 'POST', body: 'pin=exact' }]),
    ['source', 'source/tree', { method: 'POST', body: 'pin=exact' }],
    ['initial', 'source/initial/prepare', { method: 'POST', body: 'pin=exact' }],
    ['branches', 'source/refs', { method: 'POST', body: 'pin=exact' }],
    ['transfers', 'source/bundle/export', { method: 'POST', body: 'pin=exact' }],
    ['tags', 'source/tags/inspect', { method: 'POST', body: 'pin=exact' }],
    ['replay', 'source/cherry-pick/prepare', { method: 'POST', body: 'pin=exact' }],
    ['rebase', 'source/rebase/prepare', { method: 'POST', body: 'pin=exact' }],
    ['search', 'source/search', { method: 'POST', body: 'pin=exact' }],
  ];
  for (const [profile, path, options] of reads) {
    let calls = 0;
    const transport = await client(profile, async (_url, request) => {
      calls++; assert.equal(request.headers['Idempotency-Key'], undefined); return response();
    });
    await transport.request(path, options);
    assert.equal(calls, 1, `${profile} ${path}`);
    transport.disconnect();
  }
});

test('binary publication bodies and explicit media types retain exact identity', async () => {
  const bytes = new Uint8Array([0, 255, 13, 10]);
  let observed;
  const transport = await client('source', async (_url, options) => { observed = options; return response(); });
  await transport.request('source/apply', { ...envelope(), body: bytes, contentType: 'multipart/mixed; boundary=exact' });
  assert.equal(observed.body, bytes);
  assert.equal(observed.headers['Content-Type'], 'multipart/mixed; boundary=exact');
  transport.disconnect();
});

function heldFetch() {
  const sent = [];
  return {
    sent,
    fetch: (_url, options) => new Promise((resolve, reject) => {
      const abort = () => reject(options.signal.reason);
      options.signal.addEventListener('abort', abort, { once: true });
      sent.push({ options, finish: () => {
        options.signal.removeEventListener('abort', abort); resolve(response());
      } });
      if (options.signal.aborted) abort();
    }),
  };
}

test('view cancellation aborts reads but neither publication nor outcome recovery', async () => {
  const held = heldFetch();
  const transport = await client('pulls', held.fetch);
  const read = transport.request('pulls');
  const rejectedRead = assert.rejects(read, { name: 'AbortError' });
  const write = transport.request('pulls/1/merge', envelope());
  const recovery = transport.request('outcomes', { method: 'POST', key: 'another-original-key', read: false });
  assert.equal(held.sent.length, 3);
  transport.cancelReads();
  await rejectedRead;
  assert.equal(held.sent[0].options.signal.aborted, true);
  assert.equal(held.sent[1].options.signal.aborted, false);
  assert.equal(held.sent[2].options.signal.aborted, false);
  held.sent[1].finish(); held.sent[2].finish();
  await Promise.all([write, recovery]);
  assert.equal(held.sent.length, 3, 'no automatic retransmission');
  transport.disconnect();
});

test('disconnect still cancels both lifecycles without retransmitting a mutation', async () => {
  const held = heldFetch();
  const transport = await client('pulls', held.fetch);
  const read = assert.rejects(transport.request('pulls'), { name: 'AbortError' });
  const write = assert.rejects(transport.request('pulls/1/merge', envelope()), { name: 'AbortError' });
  transport.disconnect();
  await Promise.all([read, write]);
  assert.equal(held.sent.length, 2);
  assert.ok(held.sent.every(({ options }) => options.signal.aborted));
  assert.equal(transport.connected, false);
});

test('a failed transmission does not invent another recovery key or retry', async () => {
  const sent = [], failure = new TypeError('connection lost after transmission');
  const transport = await client('pulls', async (_url, options) => { sent.push(options); throw failure; });
  await assert.rejects(transport.request('pulls/1/merge', envelope()), error => error === failure);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].headers['Idempotency-Key'], 'original-key');
  transport.disconnect();
});

test('a valid publication envelope does not expand the page route allowlist', async () => {
  let calls = 0;
  const transport = await client('search', async () => { calls++; return response(); });
  await assert.rejects(transport.request('source/apply', envelope()), Error);
  await assert.rejects(transport.request('outcomes', { method: 'POST', key: 'key', read: false }), Error);
  assert.equal(calls, 0);
  transport.disconnect();
});
