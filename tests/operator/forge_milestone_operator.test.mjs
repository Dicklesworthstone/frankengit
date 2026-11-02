// Production native metadata operator against a response-schema HTTP peer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runMilestoneOperation, milestoneOperatorOptions } from '../../scripts/lib/forge-milestone-operator.mjs';
import { createMetadataOperator, runIssueOperation } from '../../scripts/lib/forge-issue-operator.mjs';
import { milestonePeer, milestoneSnapshot, tenant, repository } from './native_milestone_transfer_helper.mjs';

const mutations = peer => peer.calls.filter(call => call.method === 'POST' && !call.path.endsWith('/outcomes'));
async function fixture(t, peerOptions) {
  const root = await mkdtemp(join(tmpdir(), 'fg-milestone-operator-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const dest = await milestonePeer(peerOptions); t.after(() => dest.close());
  const tokenFile = join(root, 'token'); await writeFile(tokenFile, dest.token, { mode: 0o600 });
  const options = { href: dest.href, tenant, repository, tokenFile, record: join(root, 'request.json') };
  return { root, dest, options };
}
const opening = options => ({ ...options, operation: 'open', number: 7, expectedVersion: 0,
  fields: { title: 'Mapped release', body: 'Literal & <script> 雪', due_at: 0 } });

test('native milestone operator creates, edits, closes and reopens with ordinary exact-version commands', async t => {
  const f = await fixture(t);
  const first = await runMilestoneOperation(opening(f.options));
  assert.equal(first.type, 'forge_milestone_operator_result'); assert.equal(first.state, 'terminal_observed');
  assert.equal(first.result.outcome, 'committed'); assert.equal(first.mutation_submitted, true);
  const bytes = await readFile(f.options.record), value = JSON.parse(bytes);
  assert.equal(value.schema, 'frankengit-milestone-operator-v1');
  assert.equal(value.receipt.schema, 'frankengit-milestone-retry-v1'); assert.match(value.receipt.request.key, /^fgmi-/);
  assert.equal(bytes.includes(f.dest.token), false);
  const edits = [['edit', { due_at: null }, 1], ['close', {}, 2], ['reopen', {}, 3]];
  for (const [operation, fields, expectedVersion] of edits) {
    const result = await runMilestoneOperation({ ...f.options, record: join(f.root, `${operation}.json`),
      operation, number: 7, expectedVersion, fields });
    assert.equal(result.result.outcome, 'committed');
  }
  const current = milestoneSnapshot(f.dest.milestoneSource.get(7));
  assert.equal(current.state, 'open'); assert.equal(current.version, 4); assert.equal(current.due_at, null);
  assert.equal(f.dest.source.size, 0);
  assert.ok(mutations(f.dest).every(call => call.path.includes('/api/v1/milestones/7/')));
  const observed = await runMilestoneOperation({ ...f.options, operation: 'status' });
  assert.equal(observed.result.tx, first.result.tx); assert.equal(observed.mutation_submitted, false);
  assert.equal(mutations(f.dest).length, 4); assert.deepEqual(await readFile(f.options.record), bytes);
});
test('lost terminal response leaves original private custody and status settles without resubmission', async t => {
  let lose = true;
  const f = await fixture(t, { afterMutation({ res }) { if (lose) { lose = false; res.destroy(); return true; } } });
  await assert.rejects(runMilestoneOperation(opening(f.options)), error => {
    assert.equal(error.operator_state, 'submitted_unknown'); assert.equal(typeof error.record_sha256, 'string'); return true;
  });
  const bytes = await readFile(f.options.record), original = JSON.parse(bytes).receipt.request;
  assert.equal(f.dest.decisions.size, 1);
  for (const operation of ['status', 'retry']) {
    const result = await runMilestoneOperation({ ...f.options, operation });
    assert.equal(result.state, 'terminal_observed'); assert.equal(result.mutation_submitted, false);
    assert.equal(result.result.tx, f.dest.decisions.get(original.key).tx_id);
  }
  assert.equal(mutations(f.dest).length, 1); assert.deepEqual(await readFile(f.options.record), bytes);
});
test('an unknown milestone request requires explicit retry and uses the same key and form', async t => {
  let interrupt = true;
  const f = await fixture(t, { fault({ res, call }) {
    if (interrupt && call.path.endsWith('/milestones/7/open')) { res.destroy(); return true; }
  } });
  await assert.rejects(runMilestoneOperation(opening(f.options)));
  const bytes = await readFile(f.options.record), original = JSON.parse(bytes).receipt.request;
  const status = await runMilestoneOperation({ ...f.options, operation: 'status' });
  assert.equal(status.state, 'unresolved'); assert.equal(status.absence_proves_non_commit, false);
  assert.equal(f.dest.decisions.size, 0); assert.equal(mutations(f.dest).length, 1);
  interrupt = false;
  const result = await runMilestoneOperation({ ...f.options, operation: 'retry' });
  assert.equal(result.state, 'terminal_observed'); assert.equal(result.mutation_submitted, true);
  assert.equal(mutations(f.dest).length, 2);
  assert.ok(mutations(f.dest).every(call => call.key === original.key && call.body === original.body));
  assert.deepEqual(await readFile(f.options.record), bytes);
});
test('issue and milestone operator records cannot be reinterpreted across families', async t => {
  const f = await fixture(t); await runMilestoneOperation(opening(f.options));
  const count = f.dest.calls.length;
  await assert.rejects(runIssueOperation({ ...f.options, operation: 'status' }), /issue_operator_record_mismatch/);
  assert.equal(f.dest.calls.length, count);
  await assert.rejects(runMilestoneOperation({ ...f.options, operation: 'retry', fields: {} }), /milestone_operator_recovery_is_exact/);
  assert.equal(f.dest.calls.length, count);
  assert.throws(() => createMetadataOperator('arbitrary-route'), /issue_operator_profile/);
  for (const operation of ['comment', 'set-milestone', 'assign', 'lock']) {
    assert.throws(() => milestoneOperatorOptions({ ...f.options, operation, number: 7, expectedVersion: 1 }), /milestone_operator_operation/);
  }
});
test('current version or destination mismatch cannot be converted to a new milestone intent', async t => {
  const f = await fixture(t); await runMilestoneOperation(opening(f.options));
  const record = join(f.root, 'stale.json'), before = mutations(f.dest).length;
  await assert.rejects(runMilestoneOperation({ ...f.options, record, operation: 'close', number: 7, expectedVersion: 2 }), /milestone_operator_version_moved/);
  assert.equal(mutations(f.dest).length, before); assert.equal((await readdir(f.root)).includes('stale.json'), false);
  const count = f.dest.calls.length;
  await assert.rejects(runMilestoneOperation({ ...f.options, operation: 'status', repository: 'f'.repeat(32) }), /record_mismatch/);
  assert.equal(f.dest.calls.length, count);
});
test('credential replacement cannot query or resend the original milestone request', async t => {
  const f = await fixture(t); await runMilestoneOperation(opening(f.options));
  const token = await readFile(f.options.tokenFile), before = f.dest.calls.length;
  await writeFile(f.options.tokenFile, '0'.repeat(64));
  await assert.rejects(runMilestoneOperation({ ...f.options, operation: 'retry' }), /does not belong/);
  assert.equal(f.dest.calls.length, before);
  await writeFile(f.options.tokenFile, token);
  assert.equal((await runMilestoneOperation({ ...f.options, operation: 'status' })).state, 'terminal_observed');
  assert.equal(mutations(f.dest).length, 1);
});
