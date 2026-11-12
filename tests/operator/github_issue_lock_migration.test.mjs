// Production GitHub compiler, full migration preflight and original-key sender.
// The destination is an explicit HTTP schema peer, not a Rust authority node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, rm, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { fixture, tenant, repository, requestFile, encode } from './github-migration-fixture.mjs';
import { peer, snapshot, actor } from './native_issue_transfer_helper.mjs';
import { captureBytes, issueImportSteps, parseCapture, CAPTURE_SCHEMA, CAPTURE_SCHEMA_V2 }
  from '../../scripts/lib/github-issue-source.mjs';
import { runGithubIssueMigration } from '../../scripts/lib/github-issue-migration-execute.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';

async function migration(t, { states = [true], schema = CAPTURE_SCHEMA_V2, prepare = true, destination = {} } = {}) {
  const dest = await peer({ tenantId: tenant, repositoryId: repository, ...destination });
  t.after(() => dest.close());
  const f = await fixture(t, { batches: states.length, batchSize: 1, comments: 2, href: dest.href });
  await writeFile(f.tokenFile, dest.token, { mode: 0o600 });
  const captures = [];
  for (const [index, row] of f.captures.entries()) {
    const source = JSON.parse(await readFile(row.path));
    source.schema = schema; source.issues[0].locked = states[index];
    const bytes = captureBytes(source); await writeFile(row.path, bytes);
    row.sha256 = recordDigest(bytes); captures.push(source);
  }
  const plan = prepare ? await f.prepare() : null;
  const options = { ...f.common, confirm: plan?.plan_sha256, operation: 'run' };
  const sourceFiles = [f.options.inventoryFile, ...f.captures.map(row => row.path)];
  return { ...f, dest, captures, plan, options, sourceFiles, run: extra => runGithubIssueMigration({ ...options, ...extra }) };
}

test('new GitHub captures import every open/closed and locked/unlocked combination after their comments', async t => {
  // The fixture's odd issues are closed; even issues are open.
  const f = await migration(t, { states: [false, true, true, false] });
  assert.equal(f.plan.steps, 16); assert.equal(f.plan.batches, 4); assert.equal(f.dest.calls.length, 0);
  const inspected = await f.inspect(f.plan.plan_sha256);
  assert.equal(inspected.steps, 16); assert.equal(f.dest.calls.length, 0);
  const completed = await f.run(); assert.equal(completed.complete, true);
  assert.equal(completed.committed_observed, 16); assert.equal(completed.mutation_calls, 16);
  for (const [index, capture] of f.captures.entries()) {
    const source = capture.issues[0], row = f.dest.source.get(index + 101), current = snapshot(row);
    const commands = issueImportSteps(capture, 100);
    assert.deepEqual(commands.map(step => step.action), ['open', 'comment', 'comment',
      ...(source.state === 'closed' ? ['close'] : []), ...(source.locked ? ['lock'] : [])]);
    assert.deepEqual(commands.map(step => step.expected_version), commands.map((_, i) => i));
    assert.deepEqual(row.events.map(event => event.action.name), commands.map(step => step.action));
    assert.equal(current.state, source.state); assert.equal(current.locked, source.locked);
    assert.equal(current.comments, 2); assert.equal(current.title, source.title);
    assert.ok(current.body.endsWith(source.body)); assert.deepEqual(current.assignees, []);
    assert.equal(current.opened_by, actor, 'source attribution grants no destination identity');
    const comments = row.events.filter(event => event.action.name === 'comment');
    for (const [i, event] of comments.entries()) {
      assert.ok(event.action.body.endsWith(source.comments[i].body));
      assert.match(event.action.body, /source-author/); assert.equal(event.actor, actor);
    }
  }
});

test('a stopped migration resumes its already prepared final lock with the same exact key and bytes', async t => {
  const f = await migration(t), file = requestFile(f.workdir, 1, 4);
  const original = await readFile(file), request = JSON.parse(original).receipt.request;
  assert.equal(request.action, 'lock'); assert.equal(request.body, 'expected_version=4');
  const stopped = await f.run({ maxMutations: 4 });
  assert.equal(stopped.complete, false); assert.equal(stopped.stop_reason, 'mutation_limit');
  assert.equal(stopped.committed_observed, 4); assert.equal(stopped.mutation_calls, 4);
  const before = snapshot(f.dest.source.get(101));
  assert.equal(before.state, 'closed'); assert.equal(before.locked, false); assert.equal(before.comments, 2);
  const resumed = await f.run({ maxMutations: 1 }); assert.equal(resumed.complete, true);
  assert.equal(resumed.mutation_calls, 1); assert.equal(snapshot(f.dest.source.get(101)).locked, true);
  const locks = f.dest.calls.filter(call => call.path.endsWith('/lock'));
  assert.equal(locks.length, 1); assert.equal(locks[0].key, request.key); assert.equal(locks[0].body, request.body);
  assert.deepEqual(await readFile(file), original);
});

test('a lost final-lock response recovers after source deletion without another lock mutation', async t => {
  let lost = false;
  const f = await migration(t, { destination: { afterMutation({ res, call, decision }) {
    if (!lost && call.path.endsWith('/lock') && decision.outcome === 'committed') {
      lost = true; res.destroy(); return true;
    }
    return false;
  } } });
  const file = requestFile(f.workdir, 1, 4), original = await readFile(file);
  const request = JSON.parse(original).receipt.request;
  await assert.rejects(f.run(), error => {
    assert.equal(error.migration_progress.committed_observed, 4);
    assert.equal(error.migration_progress.mutation_calls, 5); return true;
  });
  assert.equal(lost, true); assert.equal(snapshot(f.dest.source.get(101)).locked, true);
  // Only retained custody is required on resume; remove the original source files.
  for (const path of f.sourceFiles) await rm(path);
  const calls = f.dest.calls.length, result = await f.run();
  assert.equal(result.complete, true); assert.equal(result.committed_observed, 5); assert.equal(result.mutation_calls, 0);
  const recovery = f.dest.calls.slice(calls);
  assert.ok(recovery.length > 0 && recovery.every(call => call.path.endsWith('/outcomes')));
  assert.ok(recovery.some(call => call.key === request.key));
  assert.equal(f.dest.calls.filter(call => call.path.endsWith('/lock')).length, 1);
  assert.deepEqual(await readFile(file), original);
});

test('a missing original lock outcome requires explicit retry with unchanged custody', async t => {
  let dropped = false;
  const f = await migration(t, { destination: { fault({ res, call }) {
    if (!dropped && call.path.endsWith('/lock')) { dropped = true; res.destroy(); return true; }
    return false;
  } } });
  const file = requestFile(f.workdir, 1, 4), original = await readFile(file), request = JSON.parse(original).receipt.request;
  await assert.rejects(f.run());
  const unresolved = await f.run(); assert.equal(unresolved.complete, false);
  assert.equal(unresolved.stop_reason, 'unresolved_original_request');
  assert.equal(snapshot(f.dest.source.get(101)).locked, false);
  const retry = await f.run({ retryUnresolved: true }); assert.equal(retry.complete, true);
  const locks = f.dest.calls.filter(call => call.path.endsWith('/lock'));
  assert.equal(locks.length, 2); assert.ok(locks.every(call => call.key === request.key && call.body === request.body));
  assert.equal(snapshot(f.dest.source.get(101)).locked, true); assert.deepEqual(await readFile(file), original);
});

test('a changed final lock in a later batch refuses the entire migration before destination access', async t => {
  const f = await migration(t, { states: [false, true] }), file = requestFile(f.workdir, 2, 3);
  const original = await readFile(file), changed = JSON.parse(original);
  assert.equal(changed.receipt.request.action, 'lock'); changed.receipt.request.action = 'unlock';
  await writeFile(file, encode(changed));
  await assert.rejects(f.inspect(f.plan.plan_sha256), /request_plan_mismatch/);
  await assert.rejects(f.run(), /request_plan_mismatch/); assert.equal(f.dest.calls.length, 0);
  await writeFile(file, original);
  assert.equal((await f.inspect(f.plan.plan_sha256)).steps, 8); assert.equal(f.dest.calls.length, 0);
});

test('whole migration capacity includes final locks before any native request key is prepared', async t => {
  const f = await migration(t, { states: [true, true], prepare: false });
  await assert.rejects(f.prepare({ maxSteps: 8 }), /step_budget/);
  await assert.rejects(lstat(f.workdir), { code: 'ENOENT' }); assert.equal(f.dest.calls.length, 0);
  const allowed = await f.prepare({ maxSteps: 9 });
  assert.equal(allowed.steps, 9); assert.equal((await f.inspect(allowed.plan_sha256)).steps, 9);
  assert.equal(f.dest.calls.length, 0);
});

test('legacy V1 source locks remain attribution across prepared migration and sender restart', async t => {
  const f = await migration(t, { schema: CAPTURE_SCHEMA, states: [true, true] });
  assert.equal(f.plan.steps, 7);
  await f.run({ maxMutations: 2 }); const resumed = await f.run(); assert.equal(resumed.complete, true);
  assert.equal(f.dest.calls.some(call => call.path.endsWith('/lock')), false);
  for (const number of [101, 102]) {
    const current = snapshot(f.dest.source.get(number)); assert.equal(current.locked, false);
    assert.match(current.body, /"locked":true/);
  }
  const copied = parseCapture(await readFile(join(f.workdir, 'capture-000001.json')));
  assert.equal(copied.schema, CAPTURE_SCHEMA);
});
