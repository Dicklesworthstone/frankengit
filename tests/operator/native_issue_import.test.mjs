import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { readIssueArchive, inspectIssueArchive } from '../../scripts/lib/forge-issue-archive.mjs';
import { partitionNativeIssueArchive, parseNativeIssueCapture, nativeIssueImportSteps, nativeCaptureBytes }
  from '../../scripts/lib/native-issue-source.mjs';
import { prepareNativeIssueImport, inspectPreparedNativeIssueImport, runNativeIssueImport }
  from '../../scripts/lib/native-issue-import.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { setup, peer, fixtureIssues, destinationTenant as tenant, destinationRepository as repository, encode } from './native_issue_transfer_helper.mjs';
async function prepared(t, rows, destinationOptions = {}) {
  const f = await setup(t, rows), view = await readIssueArchive({ workdir: f.archiveDir, confirm: f.archive.archive_sha256 });
  const batches = partitionNativeIssueArchive(view, 100);
  const dest = await peer({ tenantId: tenant, repositoryId: repository, ...destinationOptions }); t.after(() => dest.close());
  const tokenFile = join(f.root, 'destination-token'); await writeFile(tokenFile, dest.token, { mode: 0o600 });
  const captureFile = join(f.root, 'source.json'); await writeFile(captureFile, batches[0].bytes, { mode: 0o600 });
  const options = { workdir: join(f.root, 'prepared'), href: dest.href, tenant, repository, tokenFile };
  const plan = await prepareNativeIssueImport({ ...options, captureFile, offset: 100 });
  return { ...f, view, batches, dest, captureFile, options: { ...options, confirm: plan.plan_sha256 }, plan };
}
test('read returns complete owned current state and discussion; inspector result unchanged', async t => {
  const f = await setup(t), options = { workdir: f.archiveDir, confirm: f.archive.archive_sha256 };
  const view = await readIssueArchive(options);
  assert.deepEqual(view.archive, await inspectIssueArchive(options));
  assert.equal(view.records.length, 3); assert.equal(view.records[0].snapshot.title, 'Edited title');
  assert.equal(view.records[0].comments[0].version, 2);
  view.records[0].snapshot.title = 'mutated caller';
  assert.equal((await readIssueArchive(options)).records[0].snapshot.title, 'Edited title');
});
test('native batch prepare/run/recovery use actual shipped client and loopback API', async t => {
  const f = await prepared(t);
  assert.equal(f.dest.calls.length, 0, 'offline preparation must not contact destination');
  const before = await readdir(f.options.workdir), hashes = await Promise.all(before.map(async n => [n, recordDigest(await readFile(join(f.options.workdir, n)))]));
  const inspected = await inspectPreparedNativeIssueImport(f.options);
  assert.equal(inspected.steps, 5); assert.equal(inspected.network_accessed, false);
  const result = await runNativeIssueImport({ ...f.options, operation: 'run' });
  assert.equal(result.complete, true); assert.equal(result.committed_observed, 5);
  assert.deepEqual([...f.dest.source.keys()], [101, 102, 103]);
  assert.deepEqual(f.dest.source.get(101).events.map(e => e.action.name), ['open', 'comment', 'close']);
  const action = f.dest.source.get(101).events[0].action;
  assert.equal(action.title, 'Edited title'); assert.deepEqual(action.labels, ['done']);
  assert.ok(action.body.endsWith('Current body')); assert.ok(action.body.includes('source_assignees'));
  assert.equal(f.dest.calls.some(c => /\/assign$/.test(c.path)), false);
  const posts = f.dest.calls.filter(c => /\/(open|comment|close)$/.test(c.path)).length;
  assert.equal((await runNativeIssueImport({ ...f.options, operation: 'run' })).mutation_calls, 0);
  assert.equal(f.dest.calls.filter(c => /\/(open|comment|close)$/.test(c.path)).length, posts);
  for (const [name, sha] of hashes) assert.equal(recordDigest(await readFile(join(f.options.workdir, name))), sha);
  await rm(f.archiveDir, { recursive: true }); await rm(f.captureFile);
  assert.equal((await runNativeIssueImport({ ...f.options, operation: 'status' })).complete, true);
});
test('budget stops resume same keys without spending another call for committed work', async t => {
  const f = await prepared(t);
  const first = await runNativeIssueImport({ ...f.options, operation: 'run', maxMutations: 1 });
  assert.equal(first.committed_observed, 1); assert.equal(first.stop_reason, 'mutation_limit');
  const second = await runNativeIssueImport({ ...f.options, operation: 'run' });
  assert.equal(second.complete, true); assert.equal(second.mutation_calls, 4);
  assert.equal(new Set(f.dest.calls.filter(c => /\/(open|comment|close)$/.test(c.path)).map(c => c.key)).size, 5);
});
test('wrong source pin and later corruption expose no partial records', async t => {
  const f = await setup(t);
  await assert.rejects(readIssueArchive({ workdir: f.archiveDir, confirm: 'f'.repeat(64) }), /pin_mismatch/);
  await writeFile(join(f.archiveDir, 'page-000003.json'), '{}\n', { mode: 0o600 });
  await assert.rejects(readIssueArchive({ workdir: f.archiveDir, confirm: f.archive.archive_sha256 }), /page_commitment/);
});
test('source dialect mismatch cannot resume a native plan as GitHub', async t => {
  const f = await prepared(t), path = join(f.options.workdir, 'manifest.json');
  const m = JSON.parse(await readFile(path)); m.schema = 'frankengit-github-issue-import-v1';
  const bytes = encode(m); await writeFile(path, bytes);
  await assert.rejects(inspectPreparedNativeIssueImport({ ...f.options, confirm: recordDigest(bytes) }), /plan_mismatch/);
  assert.equal(f.dest.calls.length, 0);
});
test('canonical source parser rejects duplicate keys and altered metadata', async t => {
  const f = await prepared(t), value = parseNativeIssueCapture(f.batches[0].bytes);
  const repeated = f.batches[0].bytes.toString().replace('"schema":', '"schema":"bad","schema":');
  assert.throws(() => parseNativeIssueCapture(Buffer.from(repeated)), /encoding/);
  value.issues[0].id = 'another issue'; assert.throws(() => nativeCaptureBytes(value), /issue_identity/);
});
test('100 issue boundary partitions exactly and preserves sorted source membership', async t => {
  const f = await setup(t, fixtureIssues(101), { pageSize: 100 });
  const view = await readIssueArchive({ workdir: f.archiveDir, confirm: f.archive.archive_sha256 });
  const result = partitionNativeIssueArchive(view);
  assert.deepEqual(result.map(r => r.issues.length), [100, 1]);
  assert.deepEqual(result.flatMap(r => r.issues.map(x => x.number)), Array.from({ length: 101 }, (_, i) => i + 1));
});
test('provenance form overflow refuses instead of truncating a source body', async t => {
  const rows = fixtureIssues(1); rows[0].events = [{ version: 1, actor: '3'.repeat(32), action: { name: 'open', title: 'Large', body: 'x'.repeat(65536), labels: [] } }];
  const f = await setup(t, rows);
  const view = await readIssueArchive({ workdir: f.archiveDir, confirm: f.archive.archive_sha256 });
  assert.throws(() => partitionNativeIssueArchive(view), /oversized body/);
});
test('empty archive has no transfer batch, and unsafe number offsets refuse', async t => {
  const f = await setup(t, []), view = await readIssueArchive({ workdir: f.archiveDir, confirm: f.archive.archive_sha256 });
  assert.throws(() => partitionNativeIssueArchive(view), /source issue count/);
  const g = await prepared(t);
  assert.throws(() => partitionNativeIssueArchive(g.view, Number.MAX_SAFE_INTEGER), /target issue number/);
});
test('cancelled archive collection cannot produce a source package', async t => {
  const f = await setup(t), stop = new AbortController(); stop.abort();
  await assert.rejects(readIssueArchive({ workdir: f.archiveDir, confirm: f.archive.archive_sha256, signal: stop.signal }));
});
test('credential changes refuse before destination query; original credential remains usable', async t => {
  const f = await prepared(t), original = await readFile(f.options.tokenFile);
  await writeFile(f.options.tokenFile, '0'.repeat(64));
  await assert.rejects(runNativeIssueImport({ ...f.options, operation: 'run' }), /original_native_credential_required/);
  assert.equal(f.dest.calls.length, 0);
  await writeFile(f.options.tokenFile, original);
  assert.equal((await runNativeIssueImport({ ...f.options, operation: 'run' })).complete, true);
});
test('request corruption in a later step refuses all destination work', async t => {
  const f = await prepared(t);
  await writeFile(join(f.options.workdir, 'step-000004.request.json'), '{}\n');
  await assert.rejects(runNativeIssueImport({ ...f.options, operation: 'run' }), /request_plan_mismatch/);
  assert.equal(f.dest.calls.length, 0);
});
test('lost terminal reply recovers the original committed key without another mutation', async t => {
  let lose = true;
  const f = await prepared(t, undefined, { afterMutation({ res }) { if (lose) { lose = false; res.destroy(); return true; } } });
  await assert.rejects(runNativeIssueImport({ ...f.options, operation: 'run' }), error => {
    assert.equal(error.import_progress.mutation_calls, 1); assert.equal(error.import_progress.committed_observed, 0); return true;
  });
  assert.equal(f.dest.decisions.size, 1);
  const firstKey = JSON.parse(await readFile(join(f.options.workdir, 'step-000000.request.json'))).receipt.request.key;
  const recovered = await runNativeIssueImport({ ...f.options, operation: 'run' });
  assert.equal(recovered.complete, true); assert.equal(recovered.mutation_calls, 4);
  assert.equal(f.dest.calls.filter(c => c.key === firstKey && /\/open$/.test(c.path)).length, 1);
});
test('a started undecided original key requires explicit retry and cannot re-key', async t => {
  const f = await prepared(t);
  const request = await readFile(join(f.options.workdir, 'step-000000.request.json'));
  await writeFile(join(f.options.workdir, 'step-000000.started.json'), encode({ schema: 'frankengit-native-issue-import-v1/started', plan_sha256: f.plan.plan_sha256, index: 0 }), { mode: 0o600 });
  const blocked = await runNativeIssueImport({ ...f.options, operation: 'run' });
  assert.equal(blocked.stop_reason, 'unresolved_original_request'); assert.equal(blocked.mutation_calls, 0);
  assert.equal(f.dest.decisions.size, 0);
  const resumed = await runNativeIssueImport({ ...f.options, operation: 'run', retryUnresolved: true });
  assert.equal(resumed.complete, true);
  assert.deepEqual(await readFile(join(f.options.workdir, 'step-000000.request.json')), request);
});
test('a conflicting destination issue yields terminal refusal and stops later issues', async t => {
  const conflict = fixtureIssues(1); conflict[0].number = 101;
  const f = await prepared(t, undefined, { rows: conflict });
  const result = await runNativeIssueImport({ ...f.options, operation: 'run' });
  assert.equal(result.stop_reason, 'terminal_refusal'); assert.equal(result.committed_observed, 0);
  assert.equal(result.refusal.outcome, 'refused'); assert.equal(f.dest.source.has(102), false);
  assert.equal((await runNativeIssueImport({ ...f.options, operation: 'run', retryUnresolved: true })).mutation_calls, 0);
});
test('late cancellation retains the known terminal and stops new mutations', async t => {
  const f = await prepared(t), stop = new AbortController();
  await assert.rejects(runNativeIssueImport({ ...f.options, operation: 'run', signal: stop.signal,
    onProgress() { stop.abort(); } }), error => {
    assert.equal(error.import_progress.committed_observed, 1); return true;
  });
  assert.equal(f.dest.decisions.size, 1);
  assert.equal(JSON.parse(await readFile(join(f.options.workdir, 'step-000000.terminal.json'))).result.outcome, 'committed');
  assert.equal((await runNativeIssueImport({ ...f.options, operation: 'run' })).complete, true);
});
test('a changed terminal observation cannot regress committed custody to absence', async t => {
  let regress = false;
  const f = await prepared(t, undefined, { fault({ call, decisions }) {
    if (regress && call.path.endsWith('/outcomes')) decisions.delete(call.key);
  } });
  await runNativeIssueImport({ ...f.options, operation: 'run' }); regress = true;
  await assert.rejects(runNativeIssueImport({ ...f.options, operation: 'run', retryUnresolved: true }), /terminal_observation_regressed/);
  assert.equal(f.dest.calls.filter(c => /\/(open|comment|close)$/.test(c.path)).length, 5);
});
test('body size partition uses exact provenance and JSON bytes, not raw text alone', async t => {
  const rows = fixtureIssues(24).map(row => ({ number: row.number, events: [{ version: 1, actor: '3'.repeat(32),
    action: { name: 'open', title: 'Large discussion', body: 'x'.repeat(48000), labels: [] } }] }));
  const f = await setup(t, rows, { pageSize: 10 });
  const view = await readIssueArchive({ workdir: f.archiveDir, confirm: f.archive.archive_sha256 });
  const batches = partitionNativeIssueArchive(view);
  assert.equal(batches.length, 2); assert.equal(batches.flatMap(b => b.issues).length, 24);
  for (const batch of batches) {
    assert.ok(batch.bytes.length <= 1024 * 1024);
    assert.ok(encode(nativeIssueImportSteps(parseNativeIssueCapture(batch.bytes))).length <= 1024 * 1024);
  }
});
test('native source principals and metadata never enter mutation identity fields', async t => {
  const f = await prepared(t), source = parseNativeIssueCapture(f.batches[0].bytes);
  const steps = nativeIssueImportSteps(source, 200);
  for (const step of steps) {
    assert.ok(['open', 'comment', 'close'].includes(step.action));
    assert.deepEqual(Object.keys(step).sort(), ['action', 'expected_version', 'fields', 'number', 'source']);
    assert.ok(!('assignees' in step.fields)); assert.ok(!('actor' in step.fields));
  }
  assert.equal(steps[0].number, 201);
});
