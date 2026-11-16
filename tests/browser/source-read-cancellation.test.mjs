// A stream's cancellation closes local reads before its source cleanup settles.
// Refusals must retain their original error and release UI/reader ownership even
// when that cleanup is stalled or rejects. These use real WHATWG streams.
import test from 'node:test';
import assert from 'node:assert/strict';
import { boundedJson, mount } from '../../crates/fgit-node/src/smart_http/server/browser/browser.mjs';
import { collectSourceArchive } from '../../crates/fgit-node/src/smart_http/server/browser/source-archive.mjs';
import { dom, location } from './source-browser-fixtures.mjs';

function heldBody(bytes = null) {
  let release, reject, cancellations = 0, reads = 0;
  const cleanup = new Promise((yes, no) => { release = yes; reject = no; });
  const body = new ReadableStream({
    pull(controller) { reads++; if (bytes) controller.enqueue(bytes); },
    cancel() { cancellations++; return cleanup; },
  }, { highWaterMark: 0 });
  return { body, release, reject, get cancellations() { return cancellations; }, get reads() { return reads; } };
}
const turn = () => new Promise(resolve => setImmediate(resolve));

async function rejectsBeforeCleanup(operation, held, expected, lateFailure = false) {
  let settled = false, error;
  const observed = operation.then(() => { settled = true; }, failure => { settled = true; error = failure; });
  try {
    await turn();
    assert.equal(settled, true, 'the refusal must not wait for underlying source cleanup');
    assert.ok(error, 'no partial source result may escape');
    if (expected instanceof RegExp) assert.match(error.message, expected);
    else assert.equal(error, expected);
    assert.equal(held.body.locked, false, 'reader lock is released before cleanup completes');
    assert.equal(held.cancellations, 1);
  } finally {
    if (lateFailure) held.reject(new Error('late source cleanup failure'));
    else held.release();
    await observed;
    await turn(); // A late rejection must already have an observer.
  }
}

function archive(archiveFormat) {
  const zip = archiveFormat === 'zip', length = zip ? 112 : 1536;
  const expected = { archiveFormat, format: 'sha256', head: 'alg:2:' + 'a'.repeat(64),
    commit: 'b'.repeat(64), rootTree: 'c'.repeat(64), selectedTree: 'c'.repeat(64) };
  const headers = { 'Content-Length': String(length), 'Cache-Control': 'no-store',
    'Content-Type': zip ? 'application/zip' : 'application/x-tar',
    'Content-Disposition': `attachment; filename="source.${archiveFormat}"`,
    'X-FrankenGit-Archive-Profile': zip ? 'zip-store-source-v1' : 'ustar-source-v1',
    'X-FrankenGit-Archive-Entries': '1', 'X-FrankenGit-Archive-Gitlinks': '0',
    'X-FrankenGit-Snapshot-Token': expected.head, 'X-FrankenGit-Source-Commit': expected.commit,
    'X-FrankenGit-Root-Tree': expected.rootTree, 'X-FrankenGit-Selected-Tree': expected.selectedTree };
  return { length, headers, expected };
}

for (const format of ['tar', 'zip']) {
  test(`${format}: invalid headers retain their refusal before stalled cleanup`, async () => {
    const f = archive(format), held = heldBody();
    f.headers['Content-Type'] = 'text/html';
    await rejectsBeforeCleanup(collectSourceArchive(new Response(held.body, { headers: f.headers }), f.expected),
      held, /headers or profile/, true);
    assert.equal(held.reads, 0);
  });
  test(`${format}: overlong chunks release their reader without waiting for cleanup`, async () => {
    const f = archive(format), held = heldBody(new Uint8Array(f.length + 1));
    await rejectsBeforeCleanup(collectSourceArchive(new Response(held.body, { headers: f.headers }), f.expected),
      held, /exceeded its declared/);
    assert.equal(held.reads, 1);
  });
  test(`${format}: a checkpoint expiry is not extended by source cleanup`, async () => {
    const f = archive(format), held = heldBody(new Uint8Array(16)), expired = new DOMException('deadline', 'TimeoutError');
    let checks = 0;
    await rejectsBeforeCleanup(collectSourceArchive(new Response(held.body, { headers: f.headers }), f.expected,
      { checkpoint() { if (++checks === 3) throw expired; } }), held, expired);
  });
  test(`${format}: already cancelled reads reject without acquiring a reader`, async () => {
    const f = archive(format), held = heldBody(), controller = new AbortController();
    const reason = new DOMException('cancelled', 'AbortError'); controller.abort(reason);
    await rejectsBeforeCleanup(collectSourceArchive(new Response(held.body, { headers: f.headers }), f.expected,
      { signal: controller.signal }), held, reason);
    assert.equal(held.reads, 0);
  });
}

test('source JSON refuses excessive declared lengths before stalled or rejecting cleanup', async () => {
  for (const reject of [false, true]) {
    const held = heldBody();
    await rejectsBeforeCleanup(boundedJson(new Response(held.body, { headers: { 'Content-Length': '3' } }), 2),
      held, /response length/, reject);
    assert.equal(held.reads, 0);
  }
});
test('source JSON releases an oversized response reader before cleanup settles', async () => {
  const held = heldBody(new Uint8Array(3));
  await rejectsBeforeCleanup(boundedJson(new Response(held.body), 2), held, /byte limit/);
});
test('source JSON preserves an already cancelled request and releases its reader', async () => {
  const held = heldBody(), controller = new AbortController(), reason = new DOMException('cancelled', 'AbortError');
  controller.abort(reason);
  await rejectsBeforeCleanup(boundedJson(new Response(held.body), 2, controller.signal), held, reason);
  assert.equal(held.reads, 0);
});

for (const [name, response, message] of [
  ['revoked token', { status: 401 }, /Token rejected or revoked/],
  ['forbidden', { status: 403 }, /lacks read scope/],
  ['redirect', { status: 200, redirected: true }, /redirect refused/],
  ['wrong media', { status: 200, headers: { 'Content-Type': 'text/html' } }, /Unexpected API content type/],
]) {
  for (const rejecting of [false, true]) {
    test(`${name}: browser clears read ownership before ${rejecting ? 'rejecting' : 'stalled'} cleanup`, async () => {
      const d = dom(), held = heldBody();
      const received = new Response(held.body, response);
      if (response.redirected) Object.defineProperty(received, 'redirected', { value: true });
      const client = mount(d.document, location, async () => received, { timeoutMs: 30_000 });
      try {
        d.get('token').value = 'a'.repeat(64); d.get('connection').emit('submit');
        await turn();
        assert.match(d.get('status').textContent, message);
        assert.equal(d.get('cancel-read').disabled, true);
        assert.equal(d.get('snapshot').textContent, '');
        assert.equal(d.get('content').textContent, '');
        assert.equal(held.cancellations, 1); assert.equal(held.reads, 0);
      } finally {
        if (rejecting) held.reject(new Error('cleanup must not replace the HTTP error'));
        else held.release();
        await turn(); client.disconnect();
      }
    });
  }
}
