import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { readBytes, Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

// Real WHATWG streams: cancellation closes the reader immediately, but the
// underlying source's cleanup may settle later (or reject). No fake DOM/server.
function pendingCleanup(bytes = new Uint8Array([1, 2, 3])) {
  let release, calls = 0;
  const cleanup = new Promise(resolve => { release = resolve; });
  const body = new ReadableStream({
    start(controller) { if (bytes) controller.enqueue(bytes); },
    cancel() { calls += 1; return cleanup; },
  });
  return { body, release, get calls() { return calls; } };
}

async function beforeCleanupSettles(operation, source, check) {
  let outcome;
  const settled = operation.then(value => ({ value }), error => ({ error }));
  void settled.then(value => { outcome = value; });
  try {
    await nextTurn();
    assert.ok(outcome, 'request must settle without waiting for underlying cancellation cleanup');
    check(outcome);
    assert.equal(source.calls, 1, 'the underlying source is cancelled exactly once');
    assert.equal(source.body.locked, false, 'the local reader is released');
  } finally {
    source.release();
    await settled;
  }
}

const signal = () => new AbortController().signal;
const token = 'a'.repeat(64);
async function transport(fetchImpl) {
  const client = new Transport({ href: 'http://127.0.0.1/repo/ui/pulls/', fetchImpl, cryptoImpl: webcrypto });
  await client.connect(token);
  return client;
}

test('oversized declared response refuses before slow body cancellation settles', async () => {
  const source = pendingCleanup();
  const response = new Response(source.body, { headers: { 'Content-Length': '3' } });
  await beforeCleanupSettles(readBytes(response, signal(), 2), source, ({ error }) => {
    assert.match(error.message, /byte limit/);
  });
});

test('decoded stream overflow releases its reader without awaiting cleanup', async () => {
  const source = pendingCleanup();
  await beforeCleanupSettles(readBytes(new Response(source.body), signal(), 2), source, ({ error }) => {
    assert.match(error.message, /byte limit/);
  });
});

test('cleanup rejection cannot replace a framing refusal', async () => {
  const response = new Response(new ReadableStream({
    cancel() { return Promise.reject(new Error('cleanup failed')); },
  }), { headers: { 'Content-Length': 'invalid' } });
  await assert.rejects(readBytes(response, signal(), 2), /byte limit/);
  await nextTurn(); // Any unhandled cancellation rejection fails node:test.
});

test('HTTP status refusal is not held hostage by unread body cleanup', async () => {
  const source = pendingCleanup();
  const client = await transport(async () => new Response(source.body, { status: 503 }));
  await beforeCleanupSettles(client.request('pulls'), source, ({ error }) => {
    assert.equal(error.status, 503);
    assert.equal(client.connected, true);
  });
  client.disconnect();
});

test('credential rejection disconnects and returns while cleanup is pending', async () => {
  const source = pendingCleanup();
  const client = await transport(async () => new Response(source.body, { status: 401 }));
  await beforeCleanupSettles(client.request('pulls'), source, ({ error }) => {
    assert.equal(error.status, 401);
    assert.equal(client.connected, false);
    assert.equal(client.fingerprint, '');
  });
});

test('wrong content type refuses without waiting for the response source', async () => {
  const source = pendingCleanup();
  const client = await transport(async () => new Response(source.body, { headers: { 'Content-Type': 'text/html' } }));
  await beforeCleanupSettles(client.request('pulls'), source, ({ error }) => {
    assert.match(error.message, /JSON API response/);
  });
  client.disconnect();
});

test('view cancellation does not cancel a submitted mutation or replay its body', async () => {
  const source = pendingCleanup(null), calls = [];
  const client = await transport(async (url, options) => {
    calls.push({ url, options });
    return new Response(source.body, { headers: { 'Content-Type': 'application/json' } });
  });
  const operation = client.request('pulls/1/close', { method: 'POST', body: 'expected_version=1', key: 'original-key', read: false });
  await nextTurn();
  client.cancelReads();
  assert.equal(calls[0].options.signal.aborted, false);
  client.disconnect();
  await beforeCleanupSettles(operation, source, ({ error }) => {
    assert.equal(error.name, 'AbortError');
    assert.equal(calls.length, 1, 'disconnect must not resubmit a mutation');
    assert.equal(calls[0].options.headers['Idempotency-Key'], 'original-key');
  });
});

test('successful identity and decoded compressed replies retain byte framing checks', async () => {
  assert.deepEqual(await readBytes(new Response('ok', { headers: { 'Content-Length': '2' } }), signal(), 2), new Uint8Array([111, 107]));
  assert.deepEqual(await readBytes(new Response('ok', { headers: { 'Content-Encoding': 'gzip', 'Content-Length': '22' } }), signal(), 2), new Uint8Array([111, 107]));
  await assert.rejects(readBytes(new Response('ok', { headers: { 'Content-Length': '3' } }), signal(), 3), /inconsistent HTTP response length/);
});
