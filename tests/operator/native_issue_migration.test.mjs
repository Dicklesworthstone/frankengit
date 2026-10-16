import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { writeFile, readFile, readdir, rm, mkdir, rename, symlink } from 'node:fs/promises';
import { prepareNativeIssueMigration, inspectNativeIssueMigration, runNativeIssueMigration } from '../../scripts/lib/native-issue-migration.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { setup, peer, fixtureIssues, destinationTenant as tenant, destinationRepository as repository, encode } from './native_issue_transfer_helper.mjs';
async function migration(t, count = 101, destinationOptions = {}) {
  const f = await setup(t, fixtureIssues(count), { pageSize: 100 });
  const dest = await peer({ tenantId: tenant, repositoryId: repository, ...destinationOptions }); t.after(() => dest.close());
  const tokenFile = join(f.root, 'destination-token'); await writeFile(tokenFile, dest.token, { mode: 0o600 });
  const options = { workdir: join(f.root, 'migration'), href: dest.href, tenant, repository, tokenFile };
  const input = { ...options, archiveDir: f.archiveDir, archiveSha256: f.archive.archive_sha256, offset: 1000 };
  return { ...f, dest, options, input };
}
test('complete multi-batch native migration uses production inspector and shared sender', async t => {
  const f = await migration(t), plan = await prepareNativeIssueMigration(f.input), o = { ...f.options, confirm: plan.plan_sha256 };
  assert.equal(plan.batches, 2); assert.equal(plan.issues, 101); assert.equal(f.dest.calls.length, 0);
  const info = await inspectNativeIssueMigration(o);
  assert.equal(info.batches.length, 2); assert.equal(info.steps, plan.steps);
  const first = await runNativeIssueMigration({ ...o, operation: 'run', maxMutations: 2 });
  assert.equal(first.mutation_calls, 2); assert.equal(first.complete, false);
  const keys = await readFile(join(o.workdir, 'batch-000001', 'step-000000.request.json'));
  await rm(f.archiveDir, { recursive: true }); await f.src.close();
  const rest = await runNativeIssueMigration({ ...o, operation: 'run', maxMutations: 10000 });
  assert.equal(rest.complete, true); assert.equal(rest.committed_observed, plan.steps); assert.equal(rest.mutation_calls, plan.steps - 2);
  assert.deepEqual([...f.dest.source.keys()], Array.from({ length: 101 }, (_, i) => 1001 + i));
  assert.deepEqual(await readFile(join(o.workdir, 'batch-000001', 'step-000000.request.json')), keys);
  const status = await runNativeIssueMigration({ ...o, operation: 'status' });
  assert.equal(status.complete, true); assert.equal(status.mutation_calls, 0); assert.equal(status.remote_read_only, true);
});
test('full-plan corruption refuses before any first-batch network operation', async t => {
  const f = await migration(t), p = await prepareNativeIssueMigration(f.input);
  await writeFile(join(f.options.workdir, 'batch-000002', 'step-000000.request.json'), '{}\n');
  await assert.rejects(runNativeIssueMigration({ ...f.options, confirm: p.plan_sha256, operation: 'run' }), /request_plan_mismatch/);
  assert.equal(f.dest.calls.length, 0);
});
test('status inspects every batch even when the first has not started', async t => {
  const f = await migration(t), p = await prepareNativeIssueMigration(f.input);
  const result = await runNativeIssueMigration({ ...f.options, confirm: p.plan_sha256, operation: 'status' });
  assert.equal(result.batches.length, 2); assert.equal(result.mutation_calls, 0); assert.equal(result.complete, false);
  assert.ok(f.dest.calls.every(c => c.path.endsWith('/outcomes')));
});
test('parent owner serializes migration runs while status remains usable', async t => {
  const f = await migration(t, 1), p = await prepareNativeIssueMigration(f.input), o = { ...f.options, confirm: p.plan_sha256 };
  await writeFile(join(o.workdir, 'migration.sender.lock'), '{}\n', { mode: 0o600 });
  await assert.rejects(runNativeIssueMigration({ ...o, operation: 'run' }), /sender_lock_retained/);
  assert.equal((await runNativeIssueMigration({ ...o, operation: 'status' })).owner_present, true);
  assert.ok((await readdir(o.workdir)).includes('migration.sender.lock'));
});
test('source envelope refusal occurs before creating native request custody', async t => {
  const f = await migration(t, 3);
  await assert.rejects(prepareNativeIssueMigration({ ...f.input, maxSteps: 1 }), /source_budget/);
  assert.equal((await readdir(f.root)).includes('migration'), false); assert.equal(f.dest.calls.length, 0);
  await assert.rejects(prepareNativeIssueMigration({ ...f.input, maxCaptureBytes: 1 }), /source_budget/);
  assert.equal((await readdir(f.root)).includes('migration'), false);
});
test('request byte exhaustion retains an incomplete root and never makes a runnable migration', async t => {
  const f = await migration(t, 3);
  await assert.rejects(prepareNativeIssueMigration({ ...f.input, maxRequestBytes: 1 }), error => {
    assert.equal(error.migration_preparation.directory_created, true); return /request_byte_limit/.test(error.message);
  });
  assert.equal((await readdir(f.options.workdir)).includes('migration.json'), false); assert.equal(f.dest.calls.length, 0);
  await assert.rejects(prepareNativeIssueMigration(f.input), /operator_record_exists/);
});
test('unknown root files and symlinked children are refused before sending', async t => {
  const f = await migration(t, 3), p = await prepareNativeIssueMigration(f.input), o = { ...f.options, confirm: p.plan_sha256 };
  await writeFile(join(o.workdir, 'unaccounted.json'), '{}\n', { mode: 0o600 });
  await assert.rejects(runNativeIssueMigration({ ...o, operation: 'run' }), /unexpected_file/);
  await rm(join(o.workdir, 'unaccounted.json'));
  await rename(join(o.workdir, 'batch-000001'), join(f.root, 'other'));
  await symlink(join(f.root, 'other'), join(o.workdir, 'batch-000001'));
  await assert.rejects(runNativeIssueMigration({ ...o, operation: 'run' }), /directory_changed_or_unsafe/);
  assert.equal(f.dest.calls.length, 0);
});
test('complete migration pin binds destination and independent source archive', async t => {
  const f = await migration(t, 3), p = await prepareNativeIssueMigration(f.input), o = { ...f.options, confirm: p.plan_sha256 };
  await assert.rejects(inspectNativeIssueMigration({ ...o, confirm: 'f'.repeat(64) }), /pin_mismatch/);
  await assert.rejects(inspectNativeIssueMigration({ ...o, tenant: 'f'.repeat(32) }), /root_mismatch/);
  const path = join(o.workdir, 'migration.json'), m = JSON.parse(await readFile(path));
  m.source.archive_sha256 = 'b'.repeat(64); const bytes = encode(m); await writeFile(path, bytes);
  await assert.rejects(inspectNativeIssueMigration({ ...o, confirm: recordDigest(bytes) }), /population_mismatch/);
});
test('whole-migration cancellation preserves terminal progress and original keys', async t => {
  const f = await migration(t, 3), p = await prepareNativeIssueMigration(f.input), o = { ...f.options, confirm: p.plan_sha256 };
  const stop = new AbortController();
  await assert.rejects(runNativeIssueMigration({ ...o, operation: 'run', signal: stop.signal,
    onProgress(event) { if (event.phase === 'step_committed') stop.abort(); } }), error => {
    assert.equal(error.migration_progress.committed_observed, 1); return true;
  });
  assert.equal(f.dest.decisions.size, 1);
  assert.equal((await runNativeIssueMigration({ ...o, operation: 'run' })).complete, true);
});
test('unsafe replacement during preparation stops root publication and preserves both directories', async t => {
  const f = await migration(t, 3);
  // Synchronous callback replacement models an operator changing its own tree.
  const { renameSync, mkdirSync } = await import('node:fs');
  await assert.rejects(prepareNativeIssueMigration({ ...f.input, onProgress() {
    renameSync(f.options.workdir, join(f.root, 'original')); mkdirSync(f.options.workdir, { mode: 0o700 });
  } }), /directory_changed_or_unsafe/);
  assert.ok((await readdir(f.root)).includes('original'));
  assert.deepEqual(await readdir(f.options.workdir), []); assert.equal(f.dest.calls.length, 0);
});
test('async progress cannot detach execution behind failed output', async t => {
  const f = await migration(t, 3);
  await assert.rejects(prepareNativeIssueMigration({ ...f.input, async onProgress() { throw new Error('consumer failed'); } }), /progress_must_be_synchronous/);
  assert.equal((await readdir(f.options.workdir)).includes('migration.json'), false);
});
test('a changed root capture cannot produce a successful complete preparation', async t => {
  const f = await migration(t, 3), { writeFileSync } = await import('node:fs');
  await assert.rejects(prepareNativeIssueMigration({ ...f.input, onProgress() {
    writeFileSync(join(f.options.workdir, 'capture-000001.json'), '{}\n');
  } }), /capture_mismatch/);
  assert.equal((await readdir(f.options.workdir)).includes('migration.json'), false);
  assert.equal(f.dest.calls.length, 0);
});
