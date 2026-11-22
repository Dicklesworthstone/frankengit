// Production capture compiler, complete migration preflight and original-key
// sender. The destination is an HTTP schema peer, NOT Rust fg or authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { lstat, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fixture, tenant, repository, requestFile, batchDir, encode } from './github-migration-fixture.mjs';
import { peer, snapshot, actor } from './native_issue_transfer_helper.mjs';
import { captureBytes, issueImportSteps, mapGithubIssueAssignees, parseCapture,
  CAPTURE_SCHEMA_V2, CAPTURE_SCHEMA_V3, ASSIGNEE_MAP_SCHEMA,
} from '../../scripts/lib/github-issue-source.mjs';
import { prepareGithubIssueImport, inspectPreparedGithubIssueImport, runGithubIssueImport } from '../../scripts/lib/github-issue-import.mjs';
import { runGithubIssueMigration } from '../../scripts/lib/github-issue-migration-execute.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';

const sourceId = index => index === 0 ? '11' : index === 1 ? '18446744073709551614' : String(1000 + index);
const destinationId = index => (16 + index).toString(16).padStart(32, '0');
const sourceAssignees = count => Array.from({ length: count }, (_, index) => ({
  id: sourceId(index), login: index === 0 ? 'source-author' : 'source-assignee-' + index,
})).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
const mutations = dest => dest.calls.filter(call => /\/(?:open|assign|comment|close|lock)$/.test(call.path));
const assignments = dest => dest.calls.filter(call => call.path.endsWith('/assign'));

async function migration(t, { counts = [2], locks = counts.map(() => true), comments = 2,
  prepare = true, destination = {} } = {}) {
  const dest = await peer({ tenantId: tenant, repositoryId: repository, ...destination,
    async afterMutation(context) {
      const { call, decision } = context;
      if (call.path.endsWith('/assign') && decision.outcome === 'committed') {
        // Extend only this peer's action-body decoding. Production requests,
        // custody, execution, outcome parsing and recovery remain unchanged.
        const event = dest.source.get(decision.number).events.at(-1);
        assert.equal(event.action.name, 'assign');
        event.action.assignees = new URLSearchParams(call.body).getAll('assignee');
      }
      return destination.afterMutation ? destination.afterMutation(context) : false;
    } });
  t.after(() => dest.close());
  const f = await fixture(t, { batches: counts.length, batchSize: 1, comments, href: dest.href });
  await writeFile(f.tokenFile, dest.token, { mode: 0o600 });
  const captures = [], originals = [], sourceFiles = [f.options.inventoryFile, ...f.captures.map(row => row.path)];
  for (const [index, row] of f.captures.entries()) {
    const original = JSON.parse(await readFile(row.path));
    original.schema = CAPTURE_SCHEMA_V2;
    original.issues[0].locked = locks[index];
    original.issues[0].assignees = sourceAssignees(counts[index]);
    const sourceBytes = captureBytes(original);
    const mappings = Array.from({ length: counts[index] }, (_, i) => ({
      source_user_id: sourceId(i), destination_principal_id: destinationId(i),
    })).reverse();
    const mapBytes = encode({ schema: ASSIGNEE_MAP_SCHEMA, capture_sha256: recordDigest(sourceBytes), mappings });
    const mapped = mapGithubIssueAssignees(sourceBytes, mapBytes);
    assert.equal(mapped.capture.schema, CAPTURE_SCHEMA_V3);
    assert.equal(mapped.assignmentCommands, counts[index] ? 1 : 0);
    const originalPath = join(f.dir, 'original-' + index + '.json'), mappingPath = join(f.dir, 'mapping-' + index + '.json');
    await writeFile(originalPath, sourceBytes, { mode: 0o600 });
    await writeFile(mappingPath, mapBytes, { mode: 0o600 });
    sourceFiles.push(originalPath, mappingPath);
    await writeFile(row.path, mapped.bytes);
    row.sha256 = recordDigest(mapped.bytes);
    captures.push(mapped.capture); originals.push(original);
  }
  const plan = prepare ? await f.prepare() : null;
  const options = { ...f.common, confirm: plan?.plan_sha256, operation: 'run' };
  return { ...f, dest, captureFiles: f.captures, captures, originals, counts, plan, options, sourceFiles,
    run: extra => runGithubIssueMigration({ ...options, ...extra }) };
}

test('mapped GitHub assignees reach native issue metadata while source attribution and moderation survive', async t => {
  const f = await migration(t, { counts: [2, 0, 16, 1], locks: [false, true, true, false] });
  assert.equal(f.plan.steps, 19); assert.equal(f.plan.batches, 4);
  assert.equal((await f.inspect(f.plan.plan_sha256)).steps, 19);
  assert.equal(f.dest.calls.length, 0, 'preparation and complete inspection are offline');
  const result = await f.run();
  assert.equal(result.complete, true); assert.equal(result.committed_observed, 19); assert.equal(result.mutation_calls, 19);
  assert.equal(assignments(f.dest).length, 3);
  for (const [index, capture] of f.captures.entries()) {
    const source = capture.issues[0], row = f.dest.source.get(source.number + 100), current = snapshot(row);
    const steps = issueImportSteps(capture, 100), original = issueImportSteps(f.originals[index], 100);
    assert.deepEqual(row.events.map(event => event.action.name), ['open', ...(f.counts[index] ? ['assign'] : []),
      'comment', 'comment', ...(source.state === 'closed' ? ['close'] : []), ...(source.locked ? ['lock'] : [])]);
    assert.deepEqual(steps.map(step => step.expected_version), steps.map((_, i) => i));
    assert.deepEqual(row.events.map(event => event.version), steps.map((_, i) => i + 1));
    assert.deepEqual(current.assignees, Array.from({ length: f.counts[index] }, (_, i) => destinationId(i)).sort());
    assert.equal(current.opened_by, actor); assert.equal(current.last_actor, actor);
    assert.equal(current.state, source.state); assert.equal(current.locked, source.locked); assert.equal(current.comments, 2);
    assert.equal(current.body, original[0].fields.body, 'mapping must not rewrite original attribution');
    assert.ok(current.body.includes(JSON.stringify(source.assignees)));
    const oldComments = original.filter(step => step.action === 'comment');
    assert.deepEqual(row.events.filter(event => event.action.name === 'comment').map(event => event.action.body),
      oldComments.map(step => step.fields.body));
    assert.ok(row.events.every(event => event.actor === actor), 'mapping does not impersonate source authors');
  }
  const count = mutations(f.dest).length;
  assert.equal((await f.run({ operation: 'status' })).complete, true);
  assert.equal((await f.run()).mutation_calls, 0);
  assert.equal(mutations(f.dest).length, count);
});

test('the ordinary single-capture importer prepares and executes one maximum-size assignment', async t => {
  const f = await migration(t, { counts: [16], locks: [false], comments: 0, prepare: false });
  const plan = await prepareGithubIssueImport({ ...f.common, captureFile: f.captureFiles[0].path, offset: 100 });
  const options = { ...f.common, confirm: plan.plan_sha256 };
  assert.equal(plan.steps, 3);
  assert.equal((await inspectPreparedGithubIssueImport(options)).steps, 3);
  assert.equal(f.dest.calls.length, 0);
  assert.equal((await runGithubIssueImport({ ...options, operation: 'run' })).complete, true);
  const assigned = assignments(f.dest);
  assert.equal(assigned.length, 1);
  assert.equal(new URLSearchParams(assigned[0].body).getAll('assignee').length, 16);
  assert.equal(snapshot(f.dest.source.get(101)).assignees.length, 16);
});

test('a mutation limit before assignment resumes the same prepared key, fields and predecessor', async t => {
  const f = await migration(t), file = requestFile(f.workdir, 1, 1);
  const original = await readFile(file), request = JSON.parse(original).receipt.request;
  assert.equal(request.action, 'assign'); assert.equal(request.expected_version, 1);
  assert.deepEqual(request.fields.assignees, [destinationId(0), destinationId(1)]);
  const first = await f.run({ maxMutations: 1 });
  assert.equal(first.stop_reason, 'mutation_limit'); assert.equal(first.committed_observed, 1); assert.equal(first.mutation_calls, 1);
  assert.deepEqual(snapshot(f.dest.source.get(101)).assignees, []); assert.equal(assignments(f.dest).length, 0);
  const second = await f.run({ maxMutations: 1 });
  assert.equal(second.stop_reason, 'mutation_limit'); assert.equal(second.committed_observed, 2); assert.equal(second.mutation_calls, 1);
  assert.deepEqual(snapshot(f.dest.source.get(101)).assignees, request.fields.assignees);
  const completed = await f.run();
  assert.equal(completed.complete, true); assert.equal(completed.mutation_calls, f.plan.steps - 2);
  const assigned = assignments(f.dest);
  assert.equal(assigned.length, 1); assert.equal(assigned[0].key, request.key); assert.equal(assigned[0].body, request.body);
  assert.deepEqual(await readFile(file), original);
});

test('a lost committed assignment response recovers with original sources removed and no assignment resend', async t => {
  let lost = false;
  const f = await migration(t, { destination: { afterMutation({ res, call, decision }) {
    if (!lost && call.path.endsWith('/assign') && decision.outcome === 'committed') {
      lost = true; res.destroy(); return true;
    }
    return false;
  } } });
  const file = requestFile(f.workdir, 1, 1), original = await readFile(file), request = JSON.parse(original).receipt.request;
  await assert.rejects(f.run(), error => {
    assert.equal(error.migration_progress.committed_observed, 1);
    assert.equal(error.migration_progress.mutation_calls, 2); return true;
  });
  assert.equal(lost, true); assert.deepEqual(snapshot(f.dest.source.get(101)).assignees, request.fields.assignees);
  for (const path of f.sourceFiles) await rm(path);
  const previous = f.dest.calls.length;
  const status = await f.run({ operation: 'status' });
  assert.equal(status.committed_observed, 2); assert.equal(status.mutation_calls, 0); assert.equal(status.complete, false);
  const recovery = f.dest.calls.slice(previous);
  assert.ok(recovery.length && recovery.every(call => call.path.endsWith('/outcomes')));
  assert.ok(recovery.some(call => call.key === request.key));
  const completed = await f.run();
  assert.equal(completed.complete, true); assert.equal(completed.mutation_calls, f.plan.steps - 2);
  assert.equal(assignments(f.dest).length, 1);
  assert.equal(assignments(f.dest)[0].key, request.key); assert.equal(assignments(f.dest)[0].body, request.body);
  assert.deepEqual(await readFile(file), original);
  assert.equal(parseCapture(await readFile(join(batchDir(f.workdir, 1), 'capture.json'))).schema, CAPTURE_SCHEMA_V3);
});

test('an assignment with no observed outcome requires explicit identical-key retry', async t => {
  let dropped = false;
  const f = await migration(t, { destination: { fault({ res, call }) {
    if (!dropped && call.path.endsWith('/assign')) { dropped = true; res.destroy(); return true; }
    return false;
  } } });
  const file = requestFile(f.workdir, 1, 1), original = await readFile(file), request = JSON.parse(original).receipt.request;
  await assert.rejects(f.run());
  const unresolved = await f.run();
  assert.equal(unresolved.stop_reason, 'unresolved_original_request'); assert.equal(unresolved.complete, false);
  assert.equal(unresolved.mutation_calls, 0); assert.deepEqual(snapshot(f.dest.source.get(101)).assignees, []);
  assert.equal(assignments(f.dest).length, 1);
  assert.equal((await f.run({ retryUnresolved: true })).complete, true);
  assert.equal(assignments(f.dest).length, 2);
  assert.ok(assignments(f.dest).every(call => call.key === request.key && call.body === request.body));
  assert.deepEqual(await readFile(file), original);
});

test('altered retained assignment in a later batch blocks every destination contact', async t => {
  const f = await migration(t, { counts: [1, 2] }), file = requestFile(f.workdir, 2, 1);
  const original = await readFile(file), changed = JSON.parse(original);
  assert.equal(changed.receipt.request.action, 'assign');
  changed.receipt.request.fields.assignees[0] = 'f'.repeat(32);
  await writeFile(file, encode(changed));
  await assert.rejects(f.inspect(f.plan.plan_sha256), /request_plan_mismatch/);
  await assert.rejects(f.run(), /request_plan_mismatch/);
  assert.equal(f.dest.calls.length, 0);
  await writeFile(file, original);
  assert.equal((await f.inspect(f.plan.plan_sha256)).steps, 11);
  assert.equal(f.dest.calls.length, 0);
});

test('whole-migration step and mutation budgets include each separately recorded assignment', async t => {
  const f = await migration(t, { counts: [1, 1], locks: [false, false], comments: 0, prepare: false });
  // Legacy commands would total three. Two explicitly mapped assignments add
  // one exact-version event to each child and must count before custody begins.
  await assert.rejects(f.prepare({ maxSteps: 4 }), /step_budget/);
  await assert.rejects(lstat(f.workdir), { code: 'ENOENT' });
  assert.equal(f.dest.calls.length, 0);
  const plan = await f.prepare({ maxSteps: 5 });
  const options = { ...f.common, confirm: plan.plan_sha256, operation: 'run' };
  const inspected = await f.inspect(plan.plan_sha256);
  assert.equal(plan.steps, 5); assert.deepEqual(inspected.batches.map(row => row.steps), [3, 2]);
  const file = requestFile(f.workdir, 2, 1), original = await readFile(file), request = JSON.parse(original).receipt.request;
  const first = await runGithubIssueMigration({ ...options, maxMutations: 3 });
  assert.equal(first.mutation_calls, 3); assert.equal(first.committed_observed, 3); assert.equal(first.stop_reason, 'mutation_limit');
  assert(!f.dest.source.has(102));
  const second = await runGithubIssueMigration({ ...options, maxMutations: 1 });
  assert.equal(second.mutation_calls, 1); assert.equal(second.committed_observed, 4); assert.equal(second.stop_reason, 'mutation_limit');
  assert.deepEqual(snapshot(f.dest.source.get(102)).assignees, []);
  const completed = await runGithubIssueMigration({ ...options, maxMutations: 1 });
  assert.equal(completed.complete, true); assert.equal(completed.mutation_calls, 1);
  assert.equal(completed.committed_observed, 5);
  assert.equal(assignments(f.dest).length, 2);
  assert.equal(assignments(f.dest).at(-1).key, request.key);
  assert.equal(assignments(f.dest).at(-1).body, request.body);
  assert.deepEqual(await readFile(file), original);
});
