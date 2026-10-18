import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverGithubIssues, parseIssueInventory, issueInventoryBytes, selectIssueInventoryBatch } from '../../scripts/lib/github-issue-inventory.mjs';
import { captureGithubIssueBatch } from '../../scripts/lib/github-issue-inventory-command.mjs';
import { captureGithubIssues, parseCapture, issueImportSteps } from '../../scripts/lib/github-issue-source.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { makePeer, repository } from './github-inventory-fixture.mjs';
async function discover(options = {}) {
  const peer = makePeer(options);
  return discoverGithubIssues({ repository, batchSize: 100, fetchImpl: peer.fetchImpl });
}
function capture(discovered, batch = 1, options = {}, peer = makePeer()) {
  return captureGithubIssueBatch({ inventory: discovered.inventory, expectedSha256: discovered.sha256,
    batch, fetchImpl: peer.fetchImpl, ...options });
}

test('repository discovery composes through every batch into the unchanged native issue command proposal', async () => {
  const discovered = await discover(); assert.equal(discovered.total_batches, 3);
  const numbers = [], allIds = [];
  for (let batch = 1; batch <= discovered.total_batches; batch++) {
    const peer = makePeer(), result = await capture(discovered, batch, {}, peer);
    assert.deepEqual(parseCapture(result.bytes), result.capture);
    const selected = selectIssueInventoryBatch(discovered.inventory, discovered.sha256, batch);
    const direct = await captureGithubIssues({ repository, numbers: selected.numbers, fetchImpl: makePeer().fetchImpl });
    assert.deepEqual(result.bytes, direct.bytes); assert.equal(result.sha256, direct.sha256);
    assert.equal(result.requests, direct.requests);
    assert.deepEqual(result.selection, selected);
    numbers.push(...result.capture.issues.map(r => r.number)); allIds.push(...result.capture.issues.map(r => r.id));
    const steps = issueImportSteps(result.capture, 1000);
    for (const source of result.capture.issues) {
      const own = steps.filter(s => s.number === source.number + 1000);
      assert.deepEqual(own.map(s => s.action), source.state === 'closed' ? ['open', 'comment', 'comment', 'close'] : ['open', 'comment', 'comment']);
      assert.deepEqual(own.map(s => s.expected_version), own.map((_, i) => i));
      assert.match(own[0].fields.body, /attribution only/);
      assert.ok(own[0].fields.body.includes(`"source_issue_id":"${source.id}"`));
      assert.equal(own.some(s => Object.hasOwn(s.fields, 'principal')), false);
    }
    assert.ok(peer.calls.every(c => !c.url.pathname.endsWith('/issues')), 'no rediscovery during capture');
    assert.ok(peer.calls.filter(c => /issues\/\d/.test(c.url.pathname)).every(c => !/issues\/(7|14|21)(\/|$)/.test(c.url.pathname)));
  }
  assert.deepEqual(numbers, discovered.inventory.issues.map(r => r.number));
  assert.deepEqual(allIds, discovered.inventory.issues.map(r => r.id));
  assert.equal(new Set(numbers).size, 216);
});

for (const pass of [1, 2]) {
  test(`repository alias substitution on pass ${pass} refuses before issue reads`, async () => {
    const d = await discover({ count: 1 }), peer = makePeer({ count: 1, modify(r) {
      if (r.kind === 'repository' && r.repoReads === pass) r.value.id = '43';
    } });
    await assert.rejects(capture(d, 1, {}, peer), /selection_repository_changed/);
    assert.equal(peer.calls.length, pass === 1 ? 1 : 4);
  });
  test(`issue alias substitution on pass ${pass} refuses before comment reads`, async () => {
    const d = await discover({ count: 1 }), peer = makePeer({ count: 1, modify(r) {
      if (r.kind === 'issue' && r.repoReads === pass) r.value.id = '999';
    } });
    await assert.rejects(capture(d, 1, {}, peer), /selection_issue_changed/);
    assert.equal(peer.calls.filter(c => c.url.pathname.endsWith('/comments')).length, pass - 1);
  });
}
test('inventory pin, batch range and changed partition refuse without network access', async () => {
  const d = await discover({ count: 1 }); let requests = 0;
  const fetchImpl = () => { requests++; throw Error('must not fetch'); };
  for (const options of [{ expectedSha256: '00'.repeat(32) }, { batch: 0 }, { batch: 2 }, { batch: '1' },
    { inventory: { ...d.inventory, batch_size: 1 } }]) {
    await assert.rejects(capture(d, 1, { fetchImpl, ...options }), /pin|batch/);
  }
  assert.equal(requests, 0);
});
const expectedFrom = d => ({ source: structuredClone(d.inventory.source), issues: structuredClone(d.inventory.issues) });
for (const [name, mutate] of [
  ['extra field', v => { v.approved = true; }], ['extra source field', v => { v.source.token = 'secret'; }],
  ['foreign source', v => { v.source.repository = 'other/project'; }], ['numeric repo alias', v => { v.source.repository_id = 42; }],
  ['missing issue', v => { v.issues.pop(); }], ['extra issue', v => { v.issues.push({ number: 3, id: '4' }); }],
  ['reordered issues', v => { v.issues.reverse(); }], ['duplicate alias', v => { v.issues[1].id = v.issues[0].id; }],
  ['numeric issue alias', v => { v.issues[0].id = 100001; }], ['alias with leading zero', v => { v.issues[0].id = '01'; }],
  ['missing source', v => { delete v.source; }], ['hidden issue field', v => { v.issues[0].title = 'silently ignored'; }],
]) test(`expected selection refuses ${name} before network`, async () => {
  const d = await discover({ count: 2 }), selected = expectedFrom(d); mutate(selected); let calls = 0;
  await assert.rejects(captureGithubIssues({ repository, numbers: [1, 2], expectedSelection: selected,
    fetchImpl() { calls++; throw Error('must not fetch'); } }));
  assert.equal(calls, 0);
});

test('capture owns independent inventory and source identities before asynchronous callbacks can mutate them', async () => {
  const d = await discover({ count: 2 }), peer = makePeer({ count: 2, onRequest() {
    d.inventory.source.repository_id = 'changed'; d.inventory.issues[0].id = 'changed';
  } });
  const result = await capture(d, 1, {}, peer);
  assert.equal(result.selection.source.repository_id, '42'); assert.equal(result.selection.issues[0].id, '100001');
  const fresh = parseIssueInventory(d.bytes), expected = expectedFrom({ inventory: fresh });
  const later = makePeer({ count: 2, onRequest() { expected.issues[0].id = 'changed'; expected.source.repository_id = 'changed'; } });
  assert.equal((await captureGithubIssues({ repository, numbers: [1, 2], expectedSelection: expected, fetchImpl: later.fetchImpl })).capture.issues[0].id, '100001');
});

test('full-width repository and issue aliases remain exact through batch capture', async () => {
  const repositoryId = '18446744073709551615';
  const options = { count: 1, repositoryId, modify(r) {
    if (r.kind === 'inventory') r.value[0].id = '18446744073709551614';
    if (r.kind === 'issue') r.value.id = '18446744073709551614';
  } };
  const d = await discover(options), result = await capture(d, 1, {}, makePeer(options));
  assert.equal(result.capture.source.repository_id, repositoryId);
  assert.equal(result.capture.issues[0].id, '18446744073709551614');
});
test('current bodies may differ from discovery, but both body/comment capture observations must match', async () => {
  const d = await discover({ count: 1 });
  const r = await capture(d, 1, {}, makePeer({ count: 1, modify(r) { if (r.kind === 'issue') r.value.body = 'Updated after discovery'; } }));
  assert.equal(r.capture.issues[0].body, 'Updated after discovery');
  await assert.rejects(capture(d, 1, {}, makePeer({ count: 1, modify(r) {
    if (r.kind === 'comments' && r.repoReads === 2) r.value[0].body = 'Changed in capture';
  } })), /source_changed/);
});
test('large selected comment sets remain bounded and are never silently split or discarded', async () => {
  const d = await discover({ count: 1 });
  await assert.rejects(capture(d, 1, {}, makePeer({ count: 1, commentCount: 2001 })), /comment count/);
  await assert.rejects(capture(d, 1, {}, makePeer({ count: 1, modify(r) { if (r.kind === 'issue') r.value.body = 'x'.repeat(65536); } })), /body|form/);
  assert.equal(recordDigest(issueInventoryBytes(d.inventory)), d.sha256);
});
test('batch capture retains the existing complete comment pagination', async () => {
  const d = await discover({ count: 1 }), peer = makePeer({ count: 1, commentCount: 101 });
  const r = await capture(d, 1, {}, peer); assert.equal(r.capture.issues[0].comments.length, 101);
  assert.equal(peer.calls.filter(c => c.url.searchParams.get('page') === '2').length, 2);
});
test('batch capture uses one aggregate byte budget and one optional source retry allowance', async () => {
  const d = await discover({ count: 1 }), a = await capture(d, 1, {}, makePeer({ count: 1 }));
  assert.deepEqual((await capture(d, 1, { maxReadBytes: a.read_bytes }, makePeer({ count: 1 }))).bytes, a.bytes);
  await assert.rejects(capture(d, 1, { maxReadBytes: a.read_bytes - 1 }, makePeer({ count: 1 })), /read_bytes/);
  const peer = makePeer({ count: 1 }); let calls = 0;
  const r = await capture(d, 1, { maxSourceRetries: 1, fetchImpl: (...args) => ++calls === 1
    ? new Response('', { status: 503, headers: { 'Retry-After': '0' } }) : peer.fetchImpl(...args) });
  assert.deepEqual(r.bytes, a.bytes); assert.equal(r.source_retries, 1);
});
test('pre-cancelled batch does not fetch, and a delayed body is cancelled before any capture result', async () => {
  const d = await discover({ count: 1 }), stop = new AbortController(), peer = makePeer(); stop.abort();
  await assert.rejects(capture(d, 1, { signal: stop.signal }, peer)); assert.equal(peer.calls.length, 0);
  let cancelled = 0;
  await assert.rejects(capture(d, 1, { timeoutMs: 20, fetchImpl: async () => new Response(new ReadableStream({
    start(c) { c.enqueue(Buffer.from('{')); }, cancel() { cancelled++; },
  }), { headers: { 'Content-Type': 'application/json' } }) }));
  assert.equal(cancelled, 1);
});
test('resumed later batch reads only its original population even if new issues appeared', async () => {
  const d = await discover(), r = await capture(d, 3, {}, makePeer({ count: 500 }));
  assert.equal(r.selection.next_batch, null);
  assert.deepEqual(r.capture.issues.map(r => r.number), d.inventory.issues.slice(200).map(r => r.number));
});
