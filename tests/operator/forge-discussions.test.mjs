import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir, lstat, chmod, symlink, link } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { discussionOperatorOptions, runDiscussionOperation } from '../../scripts/lib/forge-discussion-operator.mjs';
import { runIssueOperation } from '../../scripts/lib/forge-issue-operator.mjs';
import { discussionPeer, mutations, token, discussionCommand } from './discussion-operator-fixture.mjs';

test('discussion mutation saves the exact independent request before HTTP and recovers without republishing', async t => {
  const f = await discussionPeer(t), o = f.operation();
  f.onMutation = ({ key, body }) => {
    const bytes = readFileSync(o.record), saved = JSON.parse(bytes);
    assert.equal(saved.schema, 'frankengit-discussion-operator-v1');
    assert.equal(saved.receipt.schema, 'frankengit-discussion-retry-v1');
    assert.equal(saved.receipt.request.key, key); assert.match(key, /^fgdi-/);
    assert.equal(saved.receipt.request.body, body); assert.equal(bytes.includes(token), false);
  };
  const result = await runDiscussionOperation(o), original = await readFile(o.record);
  assert.equal(result.type, 'forge_discussion_operator_result'); assert.equal(result.result.outcome, 'committed');
  assert.equal((await lstat(o.record)).mode & 0o777, 0o600);
  for (const operation of ['status', 'retry']) {
    const recovered = await runDiscussionOperation(f.operation(operation));
    assert.equal(recovered.result.tx, result.result.tx); assert.equal(recovered.mutation_submitted, false);
  }
  assert.equal(mutations(f).length, 1); assert.deepEqual(await readFile(o.record), original);
  assert.ok(f.calls.every(call => call.userAgent === 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)'));
});

test('complete discussion lifecycle preserves comments, author, literal text and independent locks', async t => {
  const f = await discussionPeer(t); await runDiscussionOperation(f.operation());
  const apply = async (operation, fields = {}) => runDiscussionOperation({ ...f.operation(operation, join(f.root, `request-${f.sequence + 1}.json`)),
    number: 1, expectedVersion: f.rows.get(1).version, fields });
  assert.equal((await apply('comment', { body: 'Comment & 雪\n<script>inert</script>' })).result.outcome, 'committed');
  assert.equal((await apply('edit', { title: 'New title', body: '' })).result.outcome, 'committed');
  assert.equal((await apply('lock')).result.outcome, 'committed');
  assert.equal((await apply('close')).result.outcome, 'committed');
  assert.equal(f.rows.get(1).locked, true); assert.equal(f.rows.get(1).state, 'closed');
  const refused = await apply('comment', { body: 'Blocked while locked' });
  assert.equal(refused.result.outcome, 'refused'); assert.equal(refused.result.refusal, 'ProtectedRefTransitionDenied');
  assert.equal((await apply('unlock')).result.outcome, 'committed');
  assert.equal((await apply('comment', { body: 'Closed but unlocked permits comments' })).result.outcome, 'committed');
  assert.equal((await apply('reopen')).result.outcome, 'committed');
  assert.equal(f.rows.get(1).comments, 2); assert.equal(f.rows.get(1).title, 'New title'); assert.equal(f.rows.get(1).body, '');
  assert.equal(f.histories.get(1)[0].action.body, 'Literal <script> & text');
  assert.equal(f.histories.get(1)[1].action.body, 'Comment & 雪\n<script>inert</script>');
});

test('append replans through a concurrent edit while strict comment retains its exact predecessor', async t => {
  const f = await discussionPeer(t); f.seed();
  const race = () => { f.onMutation = null; f.apply(1, 'edit', { title: 'Concurrent title' }); };
  f.onMutation = race;
  const append = await runDiscussionOperation({ ...f.operation('append-comment'), number: 1, fields: { body: 'Append once' } });
  assert.equal(append.result.outcome, 'committed'); assert.equal(f.rows.get(1).version, 3);
  assert.equal(f.rows.get(1).title, 'Concurrent title');
  const first = mutations(f)[0], request = JSON.parse(await readFile(f.operation().record)).receipt.request;
  assert.equal(request.expected_version, null); assert.equal(new URLSearchParams(first.body).has('expected_version'), false);
  const originalVersion = f.rows.get(1).version; f.onMutation = race;
  const strict = await runDiscussionOperation({ ...f.operation('comment', join(f.root, 'strict.json')),
    number: 1, expectedVersion: originalVersion, fields: { body: 'Strict predecessor' } });
  assert.equal(strict.result.outcome, 'refused'); assert.equal(strict.result.refusal, 'EvidenceStale');
  assert.equal(f.rows.get(1).comments, 1);
  assert.equal(new URLSearchParams(mutations(f)[1].body).get('expected_version'), String(originalVersion));
});

test('append checks existence and native lock policy; two original keys with the same body remain distinct', async t => {
  const f = await discussionPeer(t), input = { number: 1, fields: { body: 'Same literal body' } };
  await assert.rejects(runDiscussionOperation({ ...f.operation('append-comment'), ...input }),
    error => error.code === 'discussion_operator_version_moved');
  assert.equal(mutations(f).length, 0); assert.deepEqual(await readdir(f.root), ['token']);
  f.seed(); f.apply(1, 'lock');
  const locked = await runDiscussionOperation({ ...f.operation('append-comment'), ...input });
  assert.equal(locked.result.outcome, 'refused'); f.apply(1, 'unlock');
  for (let i = 0; i < 2; i++) assert.equal((await runDiscussionOperation({
    ...f.operation('append-comment', join(f.root, `append-${i}.json`)), ...input })).result.outcome, 'committed');
  assert.equal(f.rows.get(1).comments, 2); assert.notEqual(mutations(f)[1].key, mutations(f)[2].key);
});

test('response loss and later lifecycle changes recover the original decision in a fresh client', async t => {
  const f = await discussionPeer(t); f.mode = 'lost-reply';
  await assert.rejects(runDiscussionOperation(f.operation()), error => error.operator_state === 'submitted_unknown');
  const bytes = await readFile(f.operation().record); f.mode = null; f.apply(1, 'close'); f.apply(1, 'lock');
  const result = await runDiscussionOperation(f.operation('retry'));
  assert.equal(result.result.outcome, 'committed'); assert.equal(result.mutation_submitted, false);
  assert.equal(mutations(f).length, 1); assert.deepEqual(await readFile(f.operation().record), bytes);
  assert.equal(f.rows.get(1).state, 'closed'); assert.equal(f.rows.get(1).locked, true);
});

test('interruption after custody leaves an exact resumable request; status never sends', async t => {
  const f = await discussionPeer(t);
  await assert.rejects(runDiscussionOperation({ ...f.operation(), onProgress: ({ phase }) => {
    if (phase === 'receipt_saved') throw Error('interrupt after sync');
  } }), error => error.operator_state === 'recorded_unknown');
  const bytes = await readFile(f.operation().record), original = JSON.parse(bytes).receipt.request;
  assert.equal((await runDiscussionOperation(f.operation('status'))).state, 'unresolved');
  assert.equal(mutations(f).length, 0);
  assert.equal((await runDiscussionOperation(f.operation('retry'))).result.outcome, 'committed');
  assert.equal(mutations(f)[0].key, original.key); assert.equal(mutations(f)[0].body, original.body);
  assert.deepEqual(await readFile(f.operation().record), bytes);
});

test('original discussion custody refuses replacement, corruption and issue-family substitution before network', async t => {
  const f = await discussionPeer(t); await runDiscussionOperation(f.operation());
  const bytes = await readFile(f.operation().record), calls = f.calls.length;
  await assert.rejects(runDiscussionOperation(f.operation()), error => error.code === 'operator_record_exists');
  await assert.rejects(runIssueOperation({ ...f.operation('retry'), href: f.href.replace('/discussions/', '/issues/') }));
  for (const change of [value => { value.schema = 'frankengit-issue-operator-v1'; },
      value => { value.receipt.request.fields.body = 'Substitution'; },
      value => { value.receipt.request.action = 'append-comment'; value.receipt.request.expected_version = null; }]) {
    const forged = JSON.parse(bytes); change(forged);
    await writeFile(f.operation().record, JSON.stringify(forged) + '\n');
    await assert.rejects(runDiscussionOperation(f.operation('retry')));
  }
  await writeFile(f.operation().record, Buffer.from([0xff]));
  await assert.rejects(runDiscussionOperation(f.operation('status')), error => error.code === 'discussion_operator_invalid_record');
  assert.equal(f.calls.length, calls); await writeFile(f.operation().record, bytes);
  assert.equal((await runDiscussionOperation(f.operation('status'))).result.outcome, 'committed');
});

test('grant refusal, malformed terminal and revoked credential retain uncertainty without extra writes', async t => {
  const f = await discussionPeer(t); f.allowRead = false;
  await assert.rejects(runDiscussionOperation(f.operation()), error => error.status === 403 && error.operator_state === 'not_submitted');
  assert.deepEqual(await readdir(f.root), ['token']); f.allowRead = true; f.allowWrite = false;
  await assert.rejects(runDiscussionOperation(f.operation()), error => error.status === 403 && error.operator_state === 'submitted_unknown');
  f.allowWrite = true; f.mode = 'wrong-publication';
  await assert.rejects(runDiscussionOperation(f.operation('retry')), error => error.operator_state === 'submitted_unknown');
  f.mode = 'unauthorized'; await assert.rejects(runDiscussionOperation(f.operation('status')), error => error.status === 401);
  f.mode = null; f.allowOutcome = false; await assert.rejects(runDiscussionOperation(f.operation('status')), error => error.status === 403);
  const count = mutations(f).length; f.allowOutcome = true;
  assert.equal((await runDiscussionOperation(f.operation('retry'))).result.outcome, 'committed');
  assert.equal(mutations(f).length, count); assert.equal(f.rows.get(1).version, 1);
});

test('rotated credentials and changed expected identity cannot reinterpret existing discussion custody', async t => {
  const f = await discussionPeer(t); await runDiscussionOperation(f.operation());
  const calls = f.calls.length;
  await writeFile(f.tokenFile, 'cd'.repeat(32)); await assert.rejects(runDiscussionOperation(f.operation('retry')));
  await writeFile(f.tokenFile, token);
  await assert.rejects(runDiscussionOperation({ ...f.operation('status'), repository: '55'.repeat(16) }));
  assert.equal(f.calls.length, calls);
  assert.equal((await runDiscussionOperation(f.operation('status'))).result.outcome, 'committed');
});

test('unsafe token files and non-private request destinations refuse beside owned permitted twins', async t => {
  const f = await discussionPeer(t);
  await chmod(f.tokenFile, 0o644);
  await assert.rejects(runDiscussionOperation(f.operation()), error => error.code === 'operator_private_owner_required');
  await chmod(f.tokenFile, 0o600);
  const linked = join(f.root, 'linked-token'); await symlink(f.tokenFile, linked);
  await assert.rejects(runDiscussionOperation({ ...f.operation(), tokenFile: linked }));
  const hard = join(f.root, 'hard-token'); await link(f.tokenFile, hard);
  await assert.rejects(runDiscussionOperation(f.operation()), error => error.code === 'operator_file_type_or_size');
  const privateToken = join(f.root, 'private-token'); await writeFile(privateToken, token, { mode: 0o600 });
  await chmod(f.root, 0o755);
  await assert.rejects(runDiscussionOperation({ ...f.operation(), tokenFile: privateToken }), error => error.code === 'operator_private_owner_required');
  await chmod(f.root, 0o700); assert.equal(f.calls.length, 0);
  assert.equal((await runDiscussionOperation({ ...f.operation(), tokenFile: privateToken })).result.outcome, 'committed');
});

test('deadline cancels a submitted socket while preserving original-key recovery', async t => {
  const f = await discussionPeer(t); f.mode = 'wait';
  await assert.rejects(runDiscussionOperation({ ...f.operation(), timeoutMs: 1000 }), error => error.operator_state === 'submitted_unknown');
  assert.equal(f.rows.get(1).version, 1); f.mode = null;
  assert.equal((await runDiscussionOperation(f.operation('status'))).result.outcome, 'committed');
  assert.equal(mutations(f).length, 1);
});

test('fresh-process CLI append uses original recovery records and separates terminal refusals', async t => {
  const f = await discussionPeer(t); f.seed(); const record = join(f.root, 'append.json');
  const body = join(f.root, 'comment.txt'); await writeFile(body, 'Private\n🦀 & literal text', { mode: 0o600 });
  f.mode = 'lost-reply';
  const lost = await discussionCommand([...f.flags('append-comment', record), '--number', '1', '--body-file', body]).done;
  assert.equal(lost.code, 2); assert.equal(lost.stdout, '');
  assert.equal(JSON.parse(lost.stderr).state, 'submitted_unknown'); assert.ok(!lost.stderr.includes('literal text'));
  f.mode = null;
  const recovered = await discussionCommand(f.flags('retry', record)).done;
  assert.equal(recovered.code, 0, recovered.stderr); assert.equal(JSON.parse(recovered.stdout).mutation_submitted, false);
  assert.equal(mutations(f).length, 1); assert.equal(f.histories.get(1)[1].action.body, 'Private\n🦀 & literal text');
  f.apply(1, 'lock');
  const refused = await discussionCommand([...f.flags('append-comment', join(f.root, 'blocked.json')), '--number', '1', '--body', 'blocked']).done;
  assert.equal(refused.code, 3, refused.stderr); assert.equal(JSON.parse(refused.stdout).result.refusal, 'ProtectedRefTransitionDenied');
});

test('discussion operator closed grammar refuses unsupported scope and implicit predecessor substitutions', async t => {
  const f = await discussionPeer(t), append = { ...f.operation('append-comment'), number: 1, fields: { body: 'Comment' } };
  assert.equal(discussionOperatorOptions(append).expectedVersion, null);
  for (const raw of [{ ...append, expectedVersion: 1 }, { ...append, fields: { body: 'x', title: 'unexpected' } },
      { ...append, operation: 'assign', fields: { assignees: ['11'.repeat(16)] } },
      { ...append, operation: 'comment', expectedVersion: null }, { ...append, principal: '11'.repeat(16) },
      { ...append, href: f.href.replace('/discussions/', '/issues/') },
      { ...f.operation('retry'), number: 1 }, { ...f.operation('status'), fields: {} }]) assert.throws(() => discussionOperatorOptions(raw));
  assert.equal(f.calls.length, 0);
});
