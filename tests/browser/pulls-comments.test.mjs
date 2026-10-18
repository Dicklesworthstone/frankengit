// Production browser client and WebCrypto with controlled HTTP responses.
// These are protocol/recovery tests, not evidence of native CAS execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { commentsReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-comments.mjs';
import { commentCommand, requestBody, publication } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { token, actor, ids, scope, head, page, json, options, deferred } from './pulls-fixtures.mjs';
import { fixture as candidateFixture } from './pulls-candidate-fixtures.mjs';

function comment(version, extra = {}) { return { version, actor, body: `Comment ${version}`, ...extra }; }
function conversation(extra = {}) {
  return { ...ids, type: 'pull_request_comments', number: 1, found: true, source_head: 'head-id', snapshot_token: head,
    discussion_version: 2, after: 0, limit: 20, next_after: null, complete: true,
    merge_permission: null, transaction_created: false, comments: [comment(1), comment(2)], ...extra };
}
function terminal(pending, extra = {}) {
  return { ...ids, type: 'pull_request_comment_publication', number: pending.number, action: 'comment',
    expected_version: pending.fields.expected_version, comment_version: pending.fields.expected_version + 1,
    principal_id: actor, tx_id: 'native-comment-tx', decision_sequence: 7, outcome: 'committed',
    repository_commit_id: 'native-rcr', refusal_record_id: null, refusal_code: null, refusal_code_point: null,
    refs_changed: false, delivery_acknowledged: null, ...extra };
}
async function setup(handler = () => json(conversation())) {
  const calls = []; let client;
  client = new PullClient(options((url, init) => {
    calls.push({ url: String(url), ...init });
    if (new URL(url).pathname.endsWith('/pulls')) return json(page());
    return handler(url, init, client);
  }));
  await client.connect(token); await client.list(); return { client, calls };
}

test('comment pages have their own high water and require exact contiguous positions', () => {
  assert.equal(commentsReply(conversation(), 1).reply.discussion_version, 2);
  assert.equal(commentsReply(conversation({ limit: 1, next_after: 1, complete: false, comments: [comment(1)] }), 1, { limit: 1 }).head, head);
  for (const extra of [
    { comments: [comment(2), comment(1)] }, { comments: [comment(1)] }, { discussion_version: 3 },
    { next_after: 2 }, { complete: false }, { number: 2 }, { transaction_created: true },
    { merge_permission: true }, { comments: [comment(1, { actor: 'forged' }), comment(2)] },
    { comments: [comment(1, { body: '' }), comment(2)] }, { discussion_version: Number.MAX_SAFE_INTEGER + 1 },
  ]) assert.throws(() => commentsReply(conversation(extra), 1), JSON.stringify(extra));
  assert.throws(() => commentsReply(conversation(), 1, { head: `alg:1:${'a'.repeat(64)}` }));
});

test('unavailable conversations disclose no counts, actors, bodies or snapshot', () => {
  const absent = conversation({ found: false, source_head: null, snapshot_token: null,
    discussion_version: null, comments: [] });
  assert.equal(commentsReply(absent, 1).head, null);
  for (const extra of [{ discussion_version: 0 }, { source_head: 'leak' }, { comments: [comment(1)] }]) {
    assert.throws(() => commentsReply({ ...absent, ...extra }, 1));
  }
  const empty = commentsReply(conversation({ discussion_version: 0, comments: [] }), 1);
  assert.equal(empty.reply.found, true); assert.equal(empty.reply.discussion_version, 0);
});

test('conversation reads carry explicit pins on continuation and never send keys or bodies', async () => {
  const { client, calls } = await setup((_url, init) => {
    assert.equal(init.method, 'GET'); assert.equal(init.body, undefined);
    return json(conversation({ after: 1, limit: 1, comments: [comment(2)] }));
  });
  await assert.rejects(client.comments(1, { after: 1, limit: 1 }));
  assert.equal(calls.length, 1);
  const result = await client.comments(1, { after: 1, limit: 1, head, render: true });
  assert.equal(result.reply.discussion_version, 2);
  const call = calls.at(-1), query = new URL(call.url).searchParams;
  assert.equal(query.get('expected_head'), head); assert.equal(query.get('render'), 'html_safe');
  assert.equal(call.headers['Idempotency-Key'], undefined);
});

test('conversation transport keeps reads and publications in their exact lifecycle envelopes', async () => {
  let calls = 0;
  const transport = new Transport(options(() => { calls += 1; return json({}); }));
  await transport.connect(token);
  const reading = { statuses: [200, 404] };
  const writing = { method: 'POST', body: 'expected_version=0&body=comment', key: 'original-key', read: false, statuses: [200, 409] };
  for (const override of [{ body: 'hidden-write' }, { key: 'hidden-key' }, { read: false }, { binary: true }, { statuses: [200] }]) {
    await assert.rejects(transport.request('pulls/1/comments', { ...reading, ...override }));
  }
  for (const override of [{ method: 'PUT' }, { body: undefined }, { key: undefined }, { read: true }, { binary: true },
    { statuses: [200, 404] }, { contentType: 'application/octet-stream' }]) {
    await assert.rejects(transport.request('pulls/1/comments', { ...writing, ...override }));
  }
  await assert.rejects(transport.request('pulls/1/comments?expected_version=0', writing));
  assert.equal(calls, 0);
  await transport.request('pulls/1/comments?after=0&limit=1', reading);
  await transport.request('pulls/1/comments', writing);
  assert.equal(calls, 2);
});

test('other browser profiles cannot use conversation routes', async () => {
  for (const pageSuffix of ['/ui/source/', '/ui/initial/', '/ui/branches/', '/ui/search/', '/ui/transfers/', '/ui/tags/', '/ui/replay/', '/ui/rebase/']) {
    let calls = 0;
    const transport = new Transport({ ...options(() => { calls += 1; throw new Error('Unexpected request'); }),
      href: `https://forge.example/team/repo.git${pageSuffix}`, pageSuffix });
    await transport.connect(token);
    await assert.rejects(transport.request('pulls/1/comments', { statuses: [200, 404] }));
    await assert.rejects(transport.request('pulls/1/comments', { method: 'POST', body: 'body=comment', key: 'key', read: false, statuses: [200, 409] }));
    assert.equal(calls, 0, pageSuffix);
  }
});

test('comment form retains exact text and rejects metadata, authority and invented line anchors', () => {
  const fields = { object_format: 'sha256', expected_version: 0, body: ' é\r\n<script>literal</script> ' };
  const encoded = requestBody('comment', fields, null, 'a'.repeat(32));
  assert.deepEqual([...new URLSearchParams(new TextDecoder().decode(encoded.bytes)).keys()], ['expected_version', 'body']);
  assert.equal(new URLSearchParams(new TextDecoder().decode(encoded.bytes)).get('body'), fields.body);
  assert.equal(encoded.fields.object_format, 'sha256');
  for (const extra of [{ principal: actor }, { pull_request_version: 4 }, { source_tip: 'a'.repeat(40) },
    { line: 7 }, { force: true }, { expected_version: -1 }, { expected_version: Number.MAX_SAFE_INTEGER },
    { body: ' \n' }, { body: 'a\0b' }, { body: 'é'.repeat(32769) }]) assert.throws(() => commentCommand({ ...fields, ...extra }));
  assert.throws(() => requestBody('comment', fields, new Uint8Array([1]), 'a'.repeat(32)));
});

test('staging is local and a lost comment response retries the identical body and key', async () => {
  let sends = 0;
  const { client, calls } = await setup((_url, _init, owner) => {
    if (++sends === 1) throw new Error('lost response after possible publication');
    return json(terminal(owner.pending));
  });
  await client.stageComment(1, 2, 'Literal\r\nbody');
  const saved = client.pending; assert.equal(calls.length, 1);
  const copy = client.pending; copy.fields.body = 'editor changed';
  assert.equal(client.pending.fields.body, 'Literal\r\nbody');
  await assert.rejects(client.send(), error => error.outcomeUnknown);
  assert.equal(client.pending.key, saved.key); assert.throws(() => client.discardUnsent());
  await assert.rejects(client.stageComment(1, 3, 'retry with wrong version'));
  assert.equal((await client.send()).outcome, 'committed'); assert.equal(client.pending, null);
  const writes = calls.slice(1);
  assert.ok(writes.every(call => call.url.endsWith('/pulls/1/comments')));
  assert.equal(writes[0].headers['Idempotency-Key'], writes[1].headers['Idempotency-Key']);
  assert.equal(await writes[0].body.text(), await writes[1].body.text());
});

test('comment receipts survive export/reconnect and detect changed text, version, PR or credential', async () => {
  const { client } = await setup(); await client.stageComment(1, 2, 'Saved private comment');
  const saved = client.exportReceipt(); assert.equal(saved.includes(token), false);
  const { client: restored, calls } = await setup((_url, _init, owner) => json(terminal(owner.pending)));
  await restored.restoreReceipt(saved); assert.equal(calls.length, 1); assert.equal(restored.pending.sent, true);
  await restored.send(); assert.equal(restored.pending, null);
  for (const alter of [r => { r.request.fields.body = 'Changed'; }, r => { r.request.fields.expected_version = 3; },
    r => { r.request.number = 2; }, r => { r.request.scope.incarnation = 'other'; }]) {
    const receipt = JSON.parse(saved); alter(receipt);
    const { client: other } = await setup(); await assert.rejects(other.restoreReceipt(JSON.stringify(receipt)));
  }
  const other = new PullClient(options(() => { throw new Error('No request'); }));
  await other.connect('d'.repeat(64)); await assert.rejects(other.restoreReceipt(saved));
});

test('canonical refusals settle while mismatched response coordinates preserve uncertainty', async () => {
  const { client } = await setup(); await client.stageComment(1, 2, 'Comment'); const pending = client.pending;
  const refused = terminal(pending, { outcome: 'refused', comment_version: null,
    repository_commit_id: null, refusal_record_id: 'refusal', refusal_code: 'EvidenceStale', refusal_code_point: 1 });
  assert.equal(publication(refused, pending, 409).outcome, 'refused');
  for (const extra of [{ expected_version: 1 }, { comment_version: 4 }, { number: 2 },
    { type: 'pull_request_publication' }, { refs_changed: true }, { action: 'approve' }]) {
    assert.throws(() => publication(terminal(pending, extra), pending, 200));
  }
});

test('comment publication does not discard an independently inspected candidate', async () => {
  const f = candidateFixture();
  const { client } = await setup((url, _init, owner) => new URL(url).pathname.endsWith('/inspect') ? json(f.inspection) : json(terminal(owner.pending)));
  await client.inspect(1, f.fields, f.bundle); const candidate = client.candidate;
  await client.stageComment(1, 2, 'Discussion alongside review');
  const receipt = await client.send(); assert.equal(receipt.action, 'comment');
  assert.deepEqual(client.candidate, candidate);
});

test('disconnect rejects delayed conversation responses and does not restore a private binding', async () => {
  const pending = deferred(), { client, calls } = await setup(() => pending.promise);
  const result = client.comments(1); client.disconnect(); pending.resolve(json(conversation()));
  await assert.rejects(result); assert.equal(client.binding, null); assert.equal(calls.at(-1).signal.aborted, true);
});
