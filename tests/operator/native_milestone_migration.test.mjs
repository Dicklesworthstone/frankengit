// Real production clients, private custody and HTTP sockets against a response-
// schema peer. Canonical Rust authority is exercised by the separate fg campaign.
import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { prepareNativeIssueMigration, inspectNativeIssueMigration, runNativeIssueMigration }
  from '../../scripts/lib/native-issue-migration.mjs';
import { inspectPreparedNativeIssueImport } from '../../scripts/lib/native-issue-import.mjs';
import { inspectPreparedNativeMilestoneImport } from '../../scripts/lib/native-milestone-import.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { setupMilestones, milestonePeer, milestoneSnapshot, issueSnapshot,
  fixtureMilestoneIssues, actor, encode } from './native_milestone_transfer_helper.mjs';

const tenant = '4'.repeat(32), repository = '5'.repeat(32);
const mapping = [{ source: 1, destination: 201 }, { source: 2, destination: 102 }, { source: 3, destination: 303 }];
const mutations = peer => peer.calls.filter(call => call.method === 'POST' && !call.path.endsWith('/outcomes'));
async function fixture(t, { sourceOptions = {}, destinationOptions = {}, mappings = mapping } = {}) {
  const f = await setupMilestones(t, sourceOptions);
  const dest = await milestonePeer({ tenantId: tenant, repositoryId: repository, ...destinationOptions }); t.after(() => dest.close());
  const tokenFile = join(f.root, 'destination-token'), mapFile = join(f.root, 'map.json');
  await writeFile(tokenFile, dest.token, { mode: 0o600 });
  await writeFile(mapFile, encode({ schema: 'frankengit-native-milestone-map-v1', mappings }), { mode: 0o600 });
  const options = { workdir: join(f.root, 'migration'), href: dest.href, tenant, repository, tokenFile };
  const input = { ...options, archiveDir: f.archiveDir, archiveSha256: f.archive.archive_sha256,
    milestoneMapFile: mapFile, offset: 1000 };
  return { ...f, dest, options, input, mapFile, mappings };
}
async function prepared(t, options) {
  const f = await fixture(t, options), plan = await prepareNativeIssueMigration(f.input);
  return { ...f, plan, run: { ...f.options, confirm: plan.plan_sha256 } };
}
async function originalRequests(root) {
  const result = {};
  for (const entry of await readdir(root, { withFileTypes: true })) if (entry.isDirectory()) {
    for (const name of await readdir(join(root, entry.name))) if (name.endsWith('.request.json')) {
      result[`${entry.name}/${name}`] = recordDigest(await readFile(join(root, entry.name, name)));
    }
  }
  return result;
}
async function replaceRoot(f, mutate) {
  const path = join(f.options.workdir, 'migration.json'), value = JSON.parse(await readFile(path));
  await mutate(value); const bytes = encode(value); await writeFile(path, bytes);
  return { ...f.run, confirm: recordDigest(bytes) };
}

test('mapped migration binds all three phases, then resumes original custody after source removal', async t => {
  const f = await prepared(t), before = await originalRequests(f.options.workdir);
  assert.equal(f.plan.schema_version, 2); assert.equal(f.plan.milestones, 3); assert.equal(f.plan.steps, 14);
  assert.deepEqual(f.plan.milestone_map, mapping); assert.equal(f.dest.calls.length, 0);
  const info = await inspectNativeIssueMigration(f.run);
  assert.deepEqual(info.batches.map(row => [row.kind, row.phase, row.steps]),
    [['milestone', 'open', 3], ['issue', 'issues', 10], ['milestone', 'close', 1]]);
  const childSchemas = await Promise.all([1, 2, 3].map(async n => JSON.parse(await readFile(join(f.options.workdir,
    `batch-${String(n).padStart(6, '0')}`, 'manifest.json'))).schema));
  assert.deepEqual(childSchemas, ['frankengit-native-milestone-import-v1', 'frankengit-native-issue-import-v2', 'frankengit-native-milestone-import-v1']);
  await rm(f.archiveDir, { recursive: true }); await rm(f.mapFile); await f.src.close();
  const first = await runNativeIssueMigration({ ...f.run, operation: 'run', maxMutations: 4 });
  assert.equal(first.schema_version, 2); assert.equal(first.mutation_calls, 4); assert.equal(first.stop_reason, 'mutation_limit');
  assert.equal(f.dest.milestoneSource.size, 3); assert.equal(f.dest.source.size, 1);
  assert.ok([...f.dest.milestoneSource.values()].every(row => milestoneSnapshot(row).state === 'open'));
  assert.deepEqual(first.batches.map(row => [row.kind, row.phase, row.mutation_calls]), [['milestone', 'open', 3], ['issue', 'issues', 1]]);
  const rest = await runNativeIssueMigration({ ...f.run, operation: 'run', maxMutations: 10000 });
  assert.equal(rest.complete, true); assert.equal(rest.mutation_calls, 10); assert.equal(rest.committed_observed, 14);
  assert.deepEqual(await originalRequests(f.options.workdir), before);
  const closed = milestoneSnapshot(f.dest.milestoneSource.get(201), f.dest.source.values());
  assert.equal(closed.state, 'closed'); assert.equal(closed.due_at, 253402300799); assert.equal(closed.closed_issues, 1);
  assert.ok(closed.body.endsWith('Edited release <script> & text.\r\n'));
  assert.ok(closed.body.includes(f.archive.archive_sha256));
  assert.equal(milestoneSnapshot(f.dest.milestoneSource.get(102), f.dest.source.values()).open_issues, 1);
  assert.equal(issueSnapshot(f.dest.source.get(1001)).milestone, 201);
  assert.equal(issueSnapshot(f.dest.source.get(1001)).locked, true);
  assert.equal(issueSnapshot(f.dest.source.get(1002)).milestone, null);
  assert.equal(issueSnapshot(f.dest.source.get(1003)).milestone, 102);
  assert.ok(mutations(f.dest).slice(0, 3).every(call => /milestones\/\d+\/open$/.test(call.path)));
  assert.ok(mutations(f.dest).at(-1).path.endsWith('/milestones/201/close'));
  const status = await runNativeIssueMigration({ ...f.run, operation: 'status' });
  assert.equal(status.complete, true); assert.equal(status.mutation_calls, 0); assert.equal(mutations(f.dest).length, 14);
});
test('status visits every phase without sending, including an unresolved original milestone key', async t => {
  const f = await prepared(t), info = await inspectNativeIssueMigration(f.run), first = info.batches[0];
  await writeFile(join(f.options.workdir, 'batch-000001', 'step-000000.started.json'), encode({
    schema: 'frankengit-native-milestone-import-v1/started', plan_sha256: first.plan_sha256, index: 0 }), { mode: 0o600 });
  const blocked = await runNativeIssueMigration({ ...f.run, operation: 'run' });
  assert.equal(blocked.stop_reason, 'unresolved_original_request'); assert.equal(blocked.mutation_calls, 0);
  assert.equal(blocked.batches.length, 1); assert.equal(mutations(f.dest).length, 0);
  const status = await runNativeIssueMigration({ ...f.run, operation: 'status' });
  assert.equal(status.batches.length, 3); assert.equal(status.mutation_calls, 0); assert.equal(mutations(f.dest).length, 0);
  assert.ok(f.dest.calls.every(call => call.path.endsWith('/outcomes')));
  assert.equal((await runNativeIssueMigration({ ...f.run, operation: 'run', retryUnresolved: true })).complete, true);
});
test('lost milestone terminal reply recovers before any downstream batch without replacing its request', async t => {
  let lose = true;
  const f = await prepared(t, { destinationOptions: { afterMutation({ res }) {
    if (lose) { lose = false; res.destroy(); return true; }
  } } });
  const before = await originalRequests(f.options.workdir);
  await assert.rejects(runNativeIssueMigration({ ...f.run, operation: 'run' }), error => {
    assert.equal(error.migration_progress.mutation_calls, 1);
    assert.equal(error.migration_progress.batches[0].kind, 'milestone'); return true;
  });
  assert.equal(f.dest.decisions.size, 1); assert.equal(f.dest.source.size, 0);
  const originalKey = mutations(f.dest)[0].key;
  const rest = await runNativeIssueMigration({ ...f.run, operation: 'run' });
  assert.equal(rest.complete, true); assert.equal(rest.mutation_calls, 13);
  assert.equal(mutations(f.dest).filter(call => call.key === originalKey).length, 1);
  assert.deepEqual(await originalRequests(f.options.workdir), before);
});
test('lost membership reply uses mapped issue import-v2 terminal custody on recovery', async t => {
  let lost = false;
  const f = await prepared(t, { destinationOptions: { afterMutation({ res, call }) {
    if (!lost && call.path.endsWith('/set-milestone')) { lost = true; res.destroy(); return true; }
  } } });
  await assert.rejects(runNativeIssueMigration({ ...f.run, operation: 'run' }), error => {
    assert.equal(error.migration_progress.mutation_calls, 6); return true;
  });
  assert.equal(issueSnapshot(f.dest.source.get(1001)).milestone, 201);
  assert.equal(milestoneSnapshot(f.dest.milestoneSource.get(201)).state, 'open');
  assert.equal((await runNativeIssueMigration({ ...f.run, operation: 'run' })).complete, true);
  assert.equal(mutations(f.dest).filter(call => call.path.endsWith('/issues/1001/set-milestone')).length, 1);
  const terminal = JSON.parse(await readFile(join(f.options.workdir, 'batch-000002', 'step-000002.terminal.json')));
  assert.equal(terminal.schema, 'frankengit-native-issue-import-v2/terminal');
});
test('all late-phase request custody must validate before first milestone network work', async t => {
  const f = await prepared(t);
  await writeFile(join(f.options.workdir, 'batch-000003', 'step-000000.request.json'), '{}\n');
  await assert.rejects(runNativeIssueMigration({ ...f.run, operation: 'run' }), /request_plan_mismatch/);
  assert.equal(f.dest.calls.length, 0);
});
test('explicitly repinned map or phase changes do not reinterpret existing prepared requests', async t => {
  const f = await prepared(t);
  const altered = await replaceRoot(f, value => { value.milestone_map[0].destination = 401; });
  await assert.rejects(runNativeIssueMigration({ ...altered, operation: 'run' }), /population_mismatch|milestone_phase_coverage/);
  assert.equal(f.dest.calls.length, 0);
  const g = await prepared(t);
  const reversed = await replaceRoot(g, value => { value.batches[0].phase = 'close'; });
  await assert.rejects(runNativeIssueMigration({ ...reversed, operation: 'run' }), /population_mismatch/);
  assert.equal(g.dest.calls.length, 0);
});
test('omitting the final source-closed milestone phase refuses complete-plan inspection', async t => {
  const f = await prepared(t);
  const raw = await readFile(join(f.options.workdir, 'capture-000003.json'));
  const altered = await replaceRoot(f, async value => {
    const last = value.batches.pop(); value.step_count -= last.steps;
    value.request_bytes -= last.request_bytes; value.capture_bytes -= raw.length;
    await rm(join(f.options.workdir, 'capture-000003.json'));
    await rm(join(f.options.workdir, 'batch-000003'), { recursive: true });
  });
  await assert.rejects(runNativeIssueMigration({ ...altered, operation: 'run' }), /milestone_phase_coverage/);
  assert.equal(f.dest.calls.length, 0);
});
test('legacy import manifest cannot reinterpret a mapped v3 issue capture', async t => {
  const f = await prepared(t), info = await inspectNativeIssueMigration(f.run), row = info.batches[1];
  const root = join(f.options.workdir, 'batch-000002'), path = join(root, 'manifest.json');
  const value = JSON.parse(await readFile(path)); value.schema = 'frankengit-native-issue-import-v1';
  const bytes = encode(value); await writeFile(path, bytes);
  await assert.rejects(inspectPreparedNativeIssueImport({ ...f.options, workdir: root, confirm: recordDigest(bytes) }), /capture_profile_mismatch/);
  await assert.rejects(inspectPreparedNativeMilestoneImport({ ...f.options, workdir: root, confirm: row.plan_sha256 }), /plan_mismatch/);
  assert.equal(f.dest.calls.length, 0);
});
test('live milestone version movement refuses membership and never repairs or closes it implicitly', async t => {
  const f = await prepared(t);
  const first = await runNativeIssueMigration({ ...f.run, operation: 'run', maxMutations: 3 });
  assert.equal(first.mutation_calls, 3); assert.equal(f.dest.source.size, 0);
  // Peer-only concurrent canonical-write simulation; no authority is inferred
  // from this map in production, whose normal expected-version command decides.
  f.dest.milestoneSource.get(201).events.push({ version: 2, actor, action: { name: 'edit', title: 'Changed independently' } });
  const stopped = await runNativeIssueMigration({ ...f.run, operation: 'run' });
  assert.equal(stopped.stop_reason, 'terminal_refusal'); assert.equal(stopped.batches.at(-1).kind, 'issue');
  assert.equal(stopped.batches.at(-1).refusal.refusal, 'EvidenceStale');
  assert.equal(f.dest.source.size, 1); assert.equal(issueSnapshot(f.dest.source.get(1001)).milestone, null);
  assert.equal(milestoneSnapshot(f.dest.milestoneSource.get(201)).state, 'open');
  assert.equal(mutations(f.dest).some(call => /milestones\/\d+\/close$/.test(call.path)), false);
  assert.equal((await runNativeIssueMigration({ ...f.run, operation: 'run', retryUnresolved: true })).mutation_calls, 0);
});
test('milestone-only migration and empty explicit map each complete their valid population', async t => {
  const f = await prepared(t, { sourceOptions: { rows: [] } });
  assert.equal(f.plan.issues, 0); assert.equal(f.plan.milestones, 3); assert.equal(f.plan.steps, 4);
  const completed = await runNativeIssueMigration({ ...f.run, operation: 'run' });
  assert.equal(completed.complete, true); assert.equal(f.dest.source.size, 0);
  assert.deepEqual(completed.batches.map(row => row.phase), ['open', 'close']);
  const plain = fixtureMilestoneIssues().filter(row => row.number === 4);
  const g = await prepared(t, { sourceOptions: { rows: plain, milestones: [] }, mappings: [] });
  assert.equal(g.plan.milestones, 0); assert.deepEqual(g.plan.milestone_map, []);
  assert.equal((await runNativeIssueMigration({ ...g.run, operation: 'run' })).complete, true);
  assert.equal(g.dest.milestoneSource.size, 0); assert.equal(g.dest.source.size, 1);
});
test('invalid mapping and source budgets refuse before creating any key custody', async t => {
  const f = await fixture(t);
  const { milestoneMapFile: _, ...withoutMap } = f.input;
  await assert.rejects(prepareNativeIssueMigration(withoutMap), /milestone_map_required/);
  await assert.rejects(prepareNativeIssueMigration({ ...f.input, maxSteps: 13 }), /source_budget/);
  await writeFile(f.mapFile, encode({ schema: 'frankengit-native-milestone-map-v1', mappings: mapping.slice(0, 2) }));
  await assert.rejects(prepareNativeIssueMigration(f.input), /map_coverage/);
  await assert.rejects(readdir(f.options.workdir), { code: 'ENOENT' }); assert.equal(f.dest.calls.length, 0);
});
test('cancellation after a known milestone terminal preserves it and stops all later admissions', async t => {
  const f = await prepared(t), stop = new AbortController();
  await assert.rejects(runNativeIssueMigration({ ...f.run, operation: 'run', signal: stop.signal,
    onProgress(event) { if (event.phase === 'step_committed') stop.abort(); } }), error => {
    assert.equal(error.migration_progress.committed_observed, 1); assert.equal(error.migration_progress.mutation_calls, 1); return true;
  });
  assert.equal(f.dest.decisions.size, 1); assert.equal(f.dest.source.size, 0);
  const terminal = JSON.parse(await readFile(join(f.options.workdir, 'batch-000001', 'step-000000.terminal.json')));
  assert.equal(terminal.schema, 'frankengit-native-milestone-import-v1/terminal'); assert.equal(terminal.result.outcome, 'committed');
  assert.equal((await runNativeIssueMigration({ ...f.run, operation: 'run' })).complete, true);
});
