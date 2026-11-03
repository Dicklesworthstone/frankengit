// Protocol doubles test browser custody and validation, not native authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { IssueClient } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { DiscussionClient, discussionAction, discussionMutationRequest, discussionState, discussionPage, discussionHistory }
  from '../../crates/fgit-node/src/smart_http/server/browser/discussions.mjs';

const href = 'https://forge.example/repo.git/ui/discussions/', token = 'c'.repeat(64), actor = '3'.repeat(32);
const head = `alg:1:${'b'.repeat(64)}`;
const ids = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32) };
const binding = { tenant: ids.tenant_id, repository: ids.repository_id };
const row = { number: 7, version: 1, title: 'Design 雪', body: '<script>inert</script> & text',
  state: 'open', opened_by: actor, last_actor: actor, comments: 0, locked: false };
const page = { ...ids, type: 'discussion_page', scope: 'repository_discussions', snapshot_token: head,
  after: 0, limit: 20, next_after: null, discussions: [row] };
const history = { ...ids, type: 'discussion_history', scope: 'repository_discussions', snapshot_token: head,
  found: true, discussion: row, after_version: 0, limit: 20, next_after_version: null,
  events: [{ version: 1, actor, action: { name: 'open', title: row.title, body: row.body } }] };
const terminal = { ...ids, type: 'discussion_publication', number: 7, expected_version: 1, action: 'comment',
  principal_id: actor, tx_id: 'original-tx', outcome: 'committed', decision_sequence: 2,
  repository_commit_id: 'original-rcr', refusal_record_id: null, refusal_code: null, delivery_acknowledged: null };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const fresh = fetchImpl => new DiscussionClient({ href, fetchImpl, cryptoImpl: webcrypto });

test('discussion actions preserve literal bytes and enforce bounded exact commands', () => {
  const request = discussionMutationRequest(7, 1, 'comment', { body: '\n<svg onload=alert(1)> & 雪\n' });
  assert.equal(new URLSearchParams(request.body).get('body'), request.fields.body);
  assert.equal(request.expected_version, 1);
  for (const [name, fields] of [['comment', { body: ' \n' }], ['comment', { body: 'x', title: 'wrong' }],
      ['edit', {}], ['open', { title: 'x' }], ['lock', { body: 'x' }], ['edit', { body: '\0' }],
      ['open', { title: '\ud800', body: '' }], ['comment', { body: '雪'.repeat(21846) }]]) assert.throws(() => discussionAction(name, fields));
  for (const args of [[7, 0, 'comment', { body: 'x' }], [7, 1, 'open', { title: 'x', body: '' }],
      [Number.MAX_SAFE_INTEGER + 1, 0, 'open', { title: 'x', body: '' }]]) assert.throws(() => discussionMutationRequest(...args));
  assert.deepEqual(discussionAction('edit', { body: '' }), { body: '' });
  assert.deepEqual(discussionAction('unlock', {}), {});
});
test('discussion reads require exact scope, repository, ordering and continuation', () => {
  assert.equal(discussionPage(page).head, head);
  assert.equal(discussionHistory(history, 7).reply.found, true);
  for (const changed of [{ ...page, scope: 'repository_issues' }, { ...page, discussions: [row, row] },
      { ...page, next_after: 7 }, { ...page, discussions: [{ ...row, comments: 1 }] }]) assert.throws(() => discussionPage(changed));
  assert.throws(() => discussionPage(page, { binding: { ...binding, repository: '4'.repeat(32) } }));
  assert.throws(() => discussionPage(page, { head: `alg:1:${'a'.repeat(64)}` }));
  assert.throws(() => discussionState({ ...row, locked: undefined }));
  assert.throws(() => discussionHistory({ ...history, events: [] }, 7));
  assert.throws(() => discussionHistory({ ...history, discussion: { ...row, title: 'changed' } }, 7));
  assert.throws(() => discussionHistory({ ...history, discussion: { ...row, opened_by: 'other' } }, 7));
});
test('history accepts closed unlocked replies and refuses lock violations or hidden transitions', () => {
  const events = [...history.events, { version: 2, actor, action: { name: 'close' } },
    { version: 3, actor, action: { name: 'comment', body: 'Still useful' } }, { version: 4, actor, action: { name: 'lock' } }];
  const checked = { ...history, discussion: { ...row, version: 4, state: 'closed', comments: 1, locked: true }, events };
  assert.equal(discussionHistory(checked, 7).reply.discussion.comments, 1);
  for (const changes of [
    { discussion: { ...checked.discussion, comments: 0 } },
    { discussion: { ...checked.discussion, locked: false } },
    { events: events.map(e => e.version === 2 ? { ...e, action: { name: 'lock' } } : e) },
    { events: events.map(e => e.version === 3 ? { ...e, version: 9 } : e) },
  ]) assert.throws(() => discussionHistory({ ...checked, ...changes }, 7));
  const continuation = { ...checked, after_version: 2, events: events.slice(2) };
  assert.equal(discussionHistory(continuation, 7, { after: 2, head }).head, head);
});
test('native discussion client uses separate routes, no ambient credentials and pinned reads', async () => {
  const calls = [], client = fresh(async (url, init) => { calls.push({ url: String(url), ...init }); return json(calls.length === 1 ? page : history); });
  await client.connect(token); await client.read(); await client.read(7, { head, render: true });
  assert.ok(calls[0].url.includes('/api/v1/discussions?'));
  assert.equal(new URL(calls[1].url).searchParams.get('expected_head'), head);
  assert.equal(new URL(calls[1].url).searchParams.get('render'), 'html_safe');
  for (const call of calls) { assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error'); assert.equal(call.headers['Idempotency-Key'], undefined); }
  await assert.rejects(client.read(7, { after: 1 }), /original snapshot/);
  await assert.rejects(client.search({}), /not supported/); client.disconnect();
  assert.throws(() => new DiscussionClient({ href: href.replace('https:', 'http:') }), /HTTPS/);
});
test('discussion retry identities are independent from issues even for identical edits and nonce', async () => {
  const cryptoImpl = { subtle: webcrypto.subtle, getRandomValues(value) { value.fill(5); return value; } };
  const issue = new IssueClient({ href: href.replace('discussions/', 'issues/'), cryptoImpl });
  const discussion = new DiscussionClient({ href, cryptoImpl });
  await issue.connect(token); await discussion.connect(token);
  await issue.stage(7, 1, 'edit', { body: 'same' }, binding); await discussion.stage(7, 1, 'edit', { body: 'same' }, binding);
  const i = JSON.parse(issue.exportReceipt()), d = JSON.parse(discussion.exportReceipt());
  assert.equal(i.request.body, d.request.body); assert.match(d.request.key, /^fgdi-/);
  assert.notEqual(i.request.key.slice(38), d.request.key.slice(38));
  assert.equal(d.schema, 'frankengit-discussion-retry-v1'); assert.equal(JSON.stringify(d).includes(token), false);
  const other = new DiscussionClient({ href, cryptoImpl }); await other.connect(token);
  await assert.rejects(other.restoreReceipt(JSON.stringify(i)), /does not belong/);
  const forged = structuredClone(i); forged.schema = d.schema; forged.request.key = forged.request.key.replace(/^fgui/, 'fgdi');
  await assert.rejects(other.restoreReceipt(JSON.stringify(forged)), /does not commit/);
  other.disconnect(); issue.disconnect(); discussion.disconnect();
});
test('a lost discussion reply retains the immutable request and rejects another family terminal', async () => {
  const calls = [], client = fresh(async (url, init) => { calls.push({ url: String(url), ...init }); throw new Error('lost reply'); });
  await client.connect(token); await client.stage(7, 1, 'comment', { body: 'Original & 雪' }, binding);
  await assert.rejects(client.send(), error => error.outcomeUnknown === true);
  const receipt = client.exportReceipt(); client.disconnect();
  let correct = false;
  const restored = fresh(async (url, init) => { calls.push({ url: String(url), ...init }); return json({ ...terminal, type: correct ? 'discussion_publication' : 'issue_publication' }); });
  await restored.connect(token); await restored.restoreReceipt(receipt);
  await assert.rejects(restored.send(), /terminal issue reply/); assert.ok(restored.pending);
  correct = true; assert.equal((await restored.send()).outcome, 'committed'); assert.equal(restored.pending, null);
  for (const call of calls) {
    assert.equal(call.body, calls[0].body); assert.equal(call.url, calls[0].url);
    assert.equal(call.headers['Idempotency-Key'], calls[0].headers['Idempotency-Key']);
  }
  assert.ok(calls[0].url.endsWith('/discussions/7/comment')); restored.disconnect();
});
test('outcome recovery does not replay a discussion and absence never clears custody', async () => {
  let decided = false;
  const calls = [], client = fresh(async (url, init) => {
    calls.push({ url: String(url), ...init });
    return json({ ...ids, type: 'transaction_outcome', selector: 'transaction', command_index: null,
      read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
      repository_incarnation: '4'.repeat(32), principal_id: actor, state: decided ? 'committed' : 'key_not_observed', terminal: decided,
      transaction: decided ? { tx_id: 'original-tx' } : null,
      decision: decided ? { kind: 'committed', decision_sequence: 2, repository_commit_id: 'original-rcr' } : null });
  });
  await client.connect(token); await client.stage(7, 1, 'comment', { body: 'Original' }, binding);
  client.exportReceipt(); assert.equal((await client.recover()).terminal, false); assert.ok(client.pending);
  assert.throws(() => client.discardUnsent()); decided = true;
  assert.equal((await client.recover()).tx, 'original-tx'); assert.equal(client.pending, null);
  assert.ok(calls.every(call => call.url.endsWith('/outcomes'))); client.disconnect();
});
