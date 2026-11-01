// Production archive/migration/import/custody over an explicit HTTP schema peer.
// This exercises real sockets and private files, not a Rust fg authority node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readFile, writeFile, rm } from 'node:fs/promises';
import { prepareNativeIssueMigration, inspectNativeIssueMigration, runNativeIssueMigration }
  from '../../scripts/lib/native-issue-migration.mjs';
import { parseNativeIssueCapture, nativeIssueImportSteps, NATIVE_CAPTURE_SCHEMA_V2 }
  from '../../scripts/lib/native-issue-source.mjs';
import { setup, peer, snapshot, actor, destinationTenant as tenant, destinationRepository as repository, encode }
  from './native_issue_transfer_helper.mjs';

function issue(number, { closed = false, locked = false } = {}) {
  const actions = [
    { name: 'open', title: `Source ${number}`, body: 'Original source body', labels: ['discussion'] },
    { name: 'comment', body: `First comment ${number}: literal <script> & Unicode 雪.\r\n` },
    { name: 'lock' },
    { name: 'edit', title: `Edited source ${number}`, body: 'Edited while locked' },
    { name: 'unlock' },
    { name: 'comment', body: `Second comment ${number}, after unlock: %2F+&=\n` },
    ...(closed ? [{ name: 'close' }] : []),
    ...(locked ? [{ name: 'lock' }] : []),
  ];
  return { number, events: actions.map((action, index) => ({ version: index + 1,
    actor: index % 2 ? '7'.repeat(32) : actor, action })) };
}
async function migration(t, rows, destinationOptions = {}) {
  const f = await setup(t, rows, { pageSize: 100 });
  const dest = await peer({ tenantId: tenant, repositoryId: repository, ...destinationOptions });
  t.after(() => dest.close());
  const tokenFile = join(f.root, 'destination-token');
  await writeFile(tokenFile, dest.token, { mode: 0o600 });
  const options = { workdir: join(f.root, 'migration'), href: dest.href, tenant, repository, tokenFile };
  const plan = await prepareNativeIssueMigration({ ...options, archiveDir: f.archiveDir,
    archiveSha256: f.archive.archive_sha256, offset: 1000 });
  return { ...f, dest, plan, options: { ...options, confirm: plan.plan_sha256 } };
}

test('native v2 migration preserves open/closed and locked/unlocked independently after all comments', async t => {
  const cases = [{ closed: false, locked: false }, { closed: false, locked: true },
    { closed: true, locked: false }, { closed: true, locked: true }];
  const rows = cases.map((state, index) => issue(index + 1, state));
  const f = await migration(t, rows);
  assert.equal(f.plan.batches, 1); assert.equal(f.plan.steps, 16);
  assert.equal(f.plan.comments, 8); assert.equal(f.dest.calls.length, 0);
  const capture = parseNativeIssueCapture(await readFile(join(f.options.workdir, 'capture-000001.json')));
  assert.equal(capture.schema, NATIVE_CAPTURE_SCHEMA_V2);
  assert.deepEqual(capture.issues.map(row => row.snapshot.locked), [false, true, false, true]);
  const steps = nativeIssueImportSteps(capture, 1000);
  for (const [index, state] of cases.entries()) {
    const commands = steps.filter(step => step.number === 1001 + index);
    assert.deepEqual(commands.map(step => step.action),
      ['open', 'comment', 'comment', ...(state.closed ? ['close'] : []), ...(state.locked ? ['lock'] : [])]);
    assert.deepEqual(commands.map(step => step.expected_version), commands.map((_, i) => i));
  }
  assert.equal((await inspectNativeIssueMigration(f.options)).steps, 16);
  assert.equal(f.dest.calls.length, 0, 'complete preparation and inspection must be offline');
  const result = await runNativeIssueMigration({ ...f.options, operation: 'run' });
  assert.equal(result.complete, true); assert.equal(result.committed_observed, 16);
  assert.equal(result.mutation_calls, 16);
  for (const [index, state] of cases.entries()) {
    const source = snapshot(rows[index]), target = f.dest.source.get(1001 + index), current = snapshot(target);
    assert.equal(current.state, state.closed ? 'closed' : 'open'); assert.equal(current.locked, state.locked);
    assert.equal(current.title, source.title); assert.ok(current.body.endsWith(source.body));
    assert.deepEqual(current.labels, source.labels); assert.equal(current.comments, 2);
    assert.deepEqual(current.assignees, []);
    const commands = steps.filter(step => step.number === target.number);
    assert.deepEqual(target.events.map(event => event.action.name), commands.map(step => step.action));
    const original = rows[index].events.filter(event => event.action.name === 'comment');
    const copied = target.events.filter(event => event.action.name === 'comment');
    for (const [i, comment] of copied.entries()) {
      assert.ok(comment.action.body.endsWith(original[i].action.body));
      assert.ok(comment.action.body.includes(`"comment_version":${original[i].version}`));
      assert.ok(comment.action.body.includes(`"source_actor":"${original[i].actor}"`));
      assert.equal(comment.actor, actor, 'source attribution must not impersonate a destination principal');
    }
    if (state.locked) assert.deepEqual(target.events.at(-1).action, { name: 'lock' });
  }
});

test('a budget stop before the final lock resumes the saved command and preserves imported discussion', async t => {
  const f = await migration(t, [issue(1, { closed: true, locked: true })]);
  const path = join(f.options.workdir, 'batch-000001', 'step-000004.request.json');
  const before = await readFile(path), request = JSON.parse(before).receipt.request;
  const partial = await runNativeIssueMigration({ ...f.options, operation: 'run', maxMutations: 4 });
  assert.equal(partial.complete, false); assert.equal(partial.stop_reason, 'mutation_limit');
  assert.equal(partial.committed_observed, 4); assert.equal(partial.mutation_calls, 4);
  const current = snapshot(f.dest.source.get(1001));
  assert.equal(current.state, 'closed'); assert.equal(current.locked, false); assert.equal(current.comments, 2);
  assert.equal(f.dest.calls.filter(call => call.path.endsWith('/lock')).length, 0);
  const resumed = await runNativeIssueMigration({ ...f.options, operation: 'run', maxMutations: 1 });
  assert.equal(resumed.complete, true); assert.equal(resumed.mutation_calls, 1);
  assert.equal(snapshot(f.dest.source.get(1001)).locked, true);
  const lock = f.dest.calls.filter(call => call.path.endsWith('/lock'));
  assert.equal(lock.length, 1); assert.equal(lock[0].key, request.key); assert.equal(lock[0].body, request.body);
  assert.deepEqual(await readFile(path), before);
});

test('a lost final-lock reply resumes the original key without another mutation or source archive', async t => {
  let lost = false;
  const f = await migration(t, [issue(1, { closed: true, locked: true })], {
    afterMutation({ res, call, decision }) {
      if (!lost && call.path.endsWith('/lock') && decision.outcome === 'committed') {
        lost = true; res.destroy(); return true;
      }
      return false;
    },
  });
  assert.equal(f.plan.steps, 5);
  const path = join(f.options.workdir, 'batch-000001', 'step-000004.request.json');
  const before = await readFile(path), request = JSON.parse(before).receipt.request;
  assert.equal(request.action, 'lock'); assert.deepEqual(request.fields, {});
  assert.equal(request.body, 'expected_version=4');
  await assert.rejects(runNativeIssueMigration({ ...f.options, operation: 'run' }), error => {
    assert.equal(error.migration_progress.committed_observed, 4);
    assert.equal(error.migration_progress.mutation_calls, 5);
    assert.equal(error.migration_progress.complete, false); return true;
  });
  assert.equal(lost, true); assert.equal(f.dest.decisions.size, 5);
  assert.equal(snapshot(f.dest.source.get(1001)).locked, true);
  const lock = f.dest.calls.filter(call => call.path.endsWith('/lock'));
  assert.equal(lock.length, 1); assert.equal(lock[0].key, request.key); assert.equal(lock[0].body, request.body);
  await rm(f.archiveDir, { recursive: true });
  const resumedAt = f.dest.calls.length;
  const result = await runNativeIssueMigration({ ...f.options, operation: 'run' });
  assert.equal(result.complete, true); assert.equal(result.committed_observed, 5);
  assert.equal(result.mutation_calls, 0); assert.deepEqual(await readFile(path), before);
  const recovered = f.dest.calls.slice(resumedAt);
  assert.ok(recovered.length > 0 && recovered.every(call => call.path.endsWith('/outcomes')));
  assert.ok(recovered.some(call => call.key === request.key));
  assert.equal(f.dest.calls.filter(call => call.path.endsWith('/lock')).length, 1);
  assert.deepEqual(f.dest.source.get(1001).events.map(event => event.action.name),
    ['open', 'comment', 'comment', 'close', 'lock']);
});

test('a tampered final lock in a later batch refuses before any destination I/O', async t => {
  const rows = Array.from({ length: 101 }, (_, i) => ({ number: i + 1, events: [
    { version: 1, actor, action: { name: 'open', title: `Issue ${i + 1}`, body: '', labels: [] } },
  ] }));
  rows.at(-1).events.push({ version: 2, actor, action: { name: 'lock' } });
  const f = await migration(t, rows);
  assert.equal(f.plan.batches, 2); assert.equal(f.plan.steps, 102); assert.equal(f.dest.calls.length, 0);
  const path = join(f.options.workdir, 'batch-000002', 'step-000001.request.json');
  const original = await readFile(path), changed = JSON.parse(original);
  assert.equal(changed.receipt.request.action, 'lock');
  changed.receipt.request.action = 'unlock';
  await writeFile(path, encode(changed));
  await assert.rejects(inspectNativeIssueMigration(f.options), /request_plan_mismatch/);
  await assert.rejects(runNativeIssueMigration({ ...f.options, operation: 'run' }), /request_plan_mismatch/);
  assert.equal(f.dest.calls.length, 0); assert.equal(f.dest.source.size, 0);
  await writeFile(path, original);
  const valid = await inspectNativeIssueMigration(f.options);
  assert.equal(valid.steps, 102); assert.equal(valid.batches.length, 2); assert.equal(f.dest.calls.length, 0);
});

