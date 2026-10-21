// Real filesystem/Ed25519 recovery jobs; no native engine or archive test double.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFile, writeFile, readdir, lstat, unlink, mkdir, symlink, link, chmod, rename } from 'node:fs/promises';
import { join, dirname, basename } from 'node:path';
import { sealRepositoryBackupJob, runRepositoryBackupJob } from '../lib/repository-backup-job.mjs';
import { jobFixture, DATA, digest, rewriteIntent, replaceDirectory } from './repository-backup-job-fixture.mjs';

const code = wanted => error => { assert.equal(error.code, wanted); return true; };
async function emptyTargets(f) { for (const path of f.destinations) assert.deepEqual(await readdir(path), []); }
async function outputs(report, data = DATA) {
  assert.equal(report.state, 'complete'); assert.equal(report.result.all_destinations_verified, true);
  for (const row of report.result.completed_replicas) assert.deepEqual(await readFile(row.receipt.candidate.input), data);
}

for (const format of ['sha1', 'sha256']) test(`${format}: sealed intent is canonical, immutable and executable`, async t => {
  const f = await jobFixture(t, format), job = await f.seal(); await emptyTargets(f);
  assert.equal(job.state, 'sealed'); assert.equal(job.checkpoint.approval_sha256, digest(await readFile(f.source.approval)));
  assert.equal(job.job_id, digest(await readFile(job.intent))); assert(Object.isFrozen(job.destinations));
  const intent = JSON.parse(await readFile(job.intent)); assert.equal(intent.policy.object_format, format);
  assert.equal(intent.sources[0], f.source.input); assert.equal(intent.destinations.length, 2);
  assert.equal((await lstat(job.intent)).mode & 0o777, 0o600);
  const run = await f.run(job.intent); await outputs(run); assert.equal(run.job.job_id, job.job_id);
  assert.equal(run.job.native_content_verified, false); assert.equal(run.job.newest_checkpoint_verified, false);
  assert.equal(run.result.final_scrub.authentication.statement.head_generation, '9007199254740993');
});

test('restart finds completed output after every original source/control was removed', async t => {
  const f = await jobFixture(t), job = await f.seal(); let partial;
  await assert.rejects(f.run(job.intent, { onProgress(event) {
    if (event.phase === 'replica_complete') { const e = new Error('stop after first copy'); e.code = 'stopped'; throw e; }
  } }), error => { partial = error; return error.code === 'stopped'; });
  const first = partial.replenishment.completed_replicas[0].receipt.candidate;
  const before = await lstat(first.input, { bigint: true });
  await unlink(f.source.input); await unlink(f.source.approval);
  const run = await f.run(job.intent); await outputs(run);
  assert.equal(run.result.source_selection.selected.input, first.input);
  assert.equal((await lstat(first.input, { bigint: true })).ino, before.ino);
  assert.deepEqual(run.job.checkpoint, job.checkpoint);
});

test('in-progress job retires original source/control after a verified handoff', async t => {
  const f = await jobFixture(t, 'sha256', 3), job = await f.seal();
  const run = await f.run(job.intent, { async onProgress(event) {
    if (event.phase === 'replica_complete' && event.completed_destinations === 1) { await unlink(f.source.input); await unlink(f.source.approval); }
  } });
  await outputs(run); assert.equal(run.result.completed_replicas.length, 3);
});

test('preserved approval also allows recovery before any target completed', async t => {
  const f = await jobFixture(t), job = await f.seal(); await unlink(f.source.approval);
  await outputs(await f.run(job.intent));
});

test('all original bytes lost with no surviving output refuses without target publication', async t => {
  const f = await jobFixture(t), job = await f.seal(); await unlink(f.source.input); await unlink(f.source.approval);
  await assert.rejects(f.run(job.intent), code('ENOENT')); await emptyTargets(f);
});

test('a saved checkpoint never adopts newer valid bytes at an original path', async t => {
  const f = await jobFixture(t), job = await f.seal();
  const next = await f.sign('next', Buffer.alloc(DATA.length, 0x62), '9007199254740994');
  await writeFile(f.source.input, await readFile(next.input)); await writeFile(f.source.approval, await readFile(next.approval));
  await assert.rejects(f.run(job.intent), error => error.replica_attempts.some(row => row.code === 'backup_artifact_mismatch')); await emptyTargets(f);
});

test('job seals only highest signed source paths, excluding lower checkpoint payloads', async t => {
  const f = await jobFixture(t), old = await f.sign('old', DATA, '3'); await unlink(old.input);
  const job = await f.seal({ candidates: [old, f.source] });
  assert.deepEqual(JSON.parse(await readFile(job.intent)).sources, [f.source.input]);
  await outputs(await f.run(job.intent));
});

test('exact seal retry reuses both control files and target order does not change the job', async t => {
  const f = await jobFixture(t), a = await f.seal(), before = await lstat(a.intent, { bigint: true });
  const b = await f.seal({ destinations: f.destinations.slice().reverse() });
  assert.equal(a.intent, b.intent); assert.equal((await lstat(b.intent, { bigint: true })).ino, before.ino);
  assert.equal((await readdir(f.jobDirectory)).length, 2); await emptyTargets(f);
});

test('complete retry never rewrites matching target files', async t => {
  const f = await jobFixture(t), job = await f.seal(), first = await f.run(job.intent);
  const ids = await Promise.all(first.result.completed_replicas.map(row => lstat(row.receipt.candidate.input, { bigint: true })));
  await unlink(f.source.input); const second = await f.run(job.intent); await outputs(second);
  for (const [i, row] of second.result.completed_replicas.entries()) {
    assert.equal(row.receipt.disposition.archive, 'reused'); assert.equal((await lstat(row.receipt.candidate.input, { bigint: true })).ino, ids[i].ino);
  }
});

test('changed intent bytes under original content address refuse', async t => {
  const f = await jobFixture(t), job = await f.seal();
  await writeFile(job.intent, Buffer.concat([await readFile(job.intent), Buffer.from(' ')]));
  await assert.rejects(f.run(job.intent), code('backup_job_identity_mismatch')); await emptyTargets(f);
});

test('missing intent is not recreated and adjacent jobs are not discovered', async t => {
  const f = await jobFixture(t), job = await f.seal(); await rename(job.intent, `${job.intent}.saved`);
  await assert.rejects(f.run(job.intent), code('ENOENT')); await emptyTargets(f);
});

test('changed saved original approval refuses even when replacement has a valid signature', async t => {
  const f = await jobFixture(t), job = await f.seal(), newer = await f.sign('newer', DATA, '9007199254740994');
  const stored = join(f.jobDirectory, `checkpoint-sha256-${job.checkpoint.approval_sha256}.approval.json`);
  await writeFile(stored, await readFile(newer.approval));
  await assert.rejects(f.run(job.intent), code('backup_job_approval_changed')); await emptyTargets(f);
});

test('reformatted original approval cannot silently change the exact job pin', async t => {
  const f = await jobFixture(t), job = await f.seal();
  const stored = join(f.jobDirectory, `checkpoint-sha256-${job.checkpoint.approval_sha256}.approval.json`);
  await writeFile(stored, Buffer.concat([await readFile(stored), Buffer.from('\n')]));
  await assert.rejects(f.run(job.intent), code('backup_job_approval_changed'));
});

for (const field of ['tenant_id', 'repository_id', 'incarnation_id', 'object_format']) test(`independent ${field} mismatch refuses`, async t => {
  const f = await jobFixture(t), job = await f.seal();
  const value = field === 'object_format' ? 'sha1' : '4'.repeat(32);
  await assert.rejects(f.run(job.intent, { policy: { ...f.policy, [field]: value } }), code('backup_job_policy_mismatch')); await emptyTargets(f);
});

test('sealed minimum generation cannot be weakened while a stricter one is enforced', async t => {
  const f = await jobFixture(t), job = await f.seal();
  await assert.rejects(f.run(job.intent, { policy: { ...f.policy, minimum_head_generation: '1' } }), code('backup_job_floor_regression'));
  await assert.rejects(f.run(job.intent, { policy: { ...f.policy, minimum_head_generation: '9007199254740994' } }), code('backup_approval_below_floor'));
  await emptyTargets(f);
});

test('independently supplied wrong signing key refuses before publication', async t => {
  const f = await jobFixture(t), job = await f.seal(), other = generateKeyPairSync('ed25519');
  await writeFile(f.trustKey, other.publicKey.export({ type: 'spki', format: 'pem' }));
  await assert.rejects(f.run(job.intent), code('backup_untrusted_signer')); await emptyTargets(f);
});

test('expired original approval is not made usable by a saved job', async t => {
  const f = await jobFixture(t), job = await f.seal();
  await assert.rejects(f.run(job.intent, { now: f.now + 86401000 }), code('backup_approval_expired')); await emptyTargets(f);
});

test('changed destination inode never retargets the frozen job', async t => {
  const f = await jobFixture(t), job = await f.seal(); await replaceDirectory(f.destinations[1]);
  await assert.rejects(f.run(job.intent), code('backup_job_destination_changed')); await emptyTargets(f);
});

test('a symlink destination replacement is refused', async t => {
  const f = await jobFixture(t), job = await f.seal(); await rename(f.destinations[1], `${f.destinations[1]}-old`);
  await symlink(`${f.destinations[1]}-old`, f.destinations[1]);
  await assert.rejects(f.run(job.intent), error => /backup_job_(private_owner_required|directory_required)/.test(error.code));
});

test('a changed job directory during a progress callback aborts with completed copy evidence', async t => {
  const f = await jobFixture(t), job = await f.seal();
  await assert.rejects(f.run(job.intent, { async onProgress(event) {
    if (event.phase === 'replica_complete') await rename(f.jobDirectory, `${f.jobDirectory}-moved`);
  } }), error => error.code === 'ENOENT' && error.replenishment.completed_replicas.length === 1);
});

for (const which of ['intent', 'approval']) test(`non-private ${which} refuses`, async t => {
  const f = await jobFixture(t), job = await f.seal();
  const path = which === 'intent' ? job.intent : join(f.jobDirectory, `checkpoint-sha256-${job.checkpoint.approval_sha256}.approval.json`);
  await chmod(path, 0o644); await assert.rejects(f.run(job.intent), code('backup_private_owner_required')); await emptyTargets(f);
});

test('hard-linked and symlinked intent files refuse', async t => {
  const f = await jobFixture(t), job = await f.seal();
  const extra = `${job.intent}.link`; await link(job.intent, extra);
  await assert.rejects(f.run(job.intent), code('backup_private_key_links')); await unlink(extra);
  await rename(job.intent, `${job.intent}.real`); await symlink(`${job.intent}.real`, job.intent);
  await assert.rejects(f.run(job.intent), code('ELOOP')); await emptyTargets(f);
});

test('a changed target approval after the first completion is not bypassed by handoff', async t => {
  const f = await jobFixture(t), job = await f.seal();
  await assert.rejects(f.run(job.intent, { async onProgress(event) {
    if (event.phase === 'replica_complete') await writeFile(event.candidate.approval, 'bad');
  } }), code('backup_invalid_envelope'));
  assert.deepEqual(await readdir(f.destinations[1]), []);
});

test('corrupt existing content-addressed output is never overwritten', async t => {
  const f = await jobFixture(t), job = await f.seal();
  const path = join(f.destinations[0], `archive-sha256-${digest(DATA)}.fgbackup`); await writeFile(path, Buffer.alloc(DATA.length, 0x62), { mode: 0o600 });
  await assert.rejects(f.run(job.intent), code('backup_replenishment_read_budget'));
  assert.deepEqual(await readFile(path), Buffer.alloc(DATA.length, 0x62));
  await assert.rejects(f.run(job.intent, { maximumTotalBytes: DATA.length * 12 }), code('backup_replica_digest_mismatch'));
});

test('exact whole-attempt budget and one-byte-short refusal', async t => {
  const f = await jobFixture(t), job = await f.seal();
  await assert.rejects(f.run(job.intent, { maximumTotalBytes: DATA.length * 9 - 1 }), code('backup_replenishment_read_budget')); await emptyTargets(f);
  const done = await f.run(job.intent, { maximumTotalBytes: DATA.length * 9 }); await outputs(done);
  assert.equal(done.result.streaming.total_payload_bytes_read, String(DATA.length * 9));
});

test('higher total allowance never raises archive-size limit', async t => {
  const f = await jobFixture(t), job = await f.seal();
  await assert.rejects(f.run(job.intent, { maximumBytes: DATA.length - 1, maximumTotalBytes: DATA.length * 10 }), code('backup_selected_archive_limit')); await emptyTargets(f);
});

test('cancellation after first receipt preserves the job and resumes exact output', async t => {
  const f = await jobFixture(t), job = await f.seal(), stop = new AbortController();
  await assert.rejects(f.run(job.intent, { signal: stop.signal, onProgress(event) { if (event.phase === 'replica_complete') stop.abort(); } }),
    error => error.code === 'backup_cancelled' && error.replenishment.completed_replicas.length === 1);
  await unlink(f.source.input); await outputs(await f.run(job.intent));
});

test('pre-cancelled job operation creates no state', async t => {
  const f = await jobFixture(t), stop = new AbortController(); stop.abort();
  await assert.rejects(f.seal({ signal: stop.signal }), code('backup_cancelled')); assert.deepEqual(await readdir(f.jobDirectory), []); await emptyTargets(f);
});

test('throwing after sealed publication preserves the exact usable intent receipt', async t => {
  const f = await jobFixture(t); let completed;
  await assert.rejects(f.seal({ onProgress(event) { if (event.phase === 'job_sealed') throw new Error('lost receipt'); } }), error => {
    completed = error.completed_result; return completed?.state === 'sealed';
  });
  await outputs(await f.run(completed.intent));
});

test('job folder overlapping destination or trust key is refused', async t => {
  const f = await jobFixture(t);
  await assert.rejects(f.seal({ jobDirectory: f.destinations[0] }), code('backup_job_separate_path_required'));
  const keyInside = join(f.jobDirectory, 'trust.pem'); await writeFile(keyInside, await readFile(f.trustKey), { mode: 0o600 });
  await assert.rejects(f.seal({ trustKey: keyInside }), code('backup_job_separate_path_required')); await emptyTargets(f);
});

test('alias of job folder cannot become a destination', async t => {
  const f = await jobFixture(t), alias = join(f.root, 'alias'); await symlink(f.root, alias);
  await assert.rejects(f.seal({ destinations: [join(alias, 'jobs')] }), code('backup_job_separate_path_required')); await emptyTargets(f);
});

test('seal refuses a candidate approval whose parent alias resolves inside a destination', async t => {
  const f = await jobFixture(t), alias = join(f.root, 'approval-alias');
  const nested = join(f.destinations[0], 'source.approval');
  await writeFile(nested, await readFile(f.source.approval), { mode: 0o600 });
  await symlink(f.destinations[0], alias);
  const before = await Promise.all([f.jobDirectory, ...f.destinations].map(path => readdir(path)));
  const inode = (await lstat(nested, {bigint: true})).ino;
  await assert.rejects(f.seal({ candidates: [{ input: f.source.input, approval: join(alias, 'source.approval') }] }),
    code('backup_job_separate_path_required'));
  assert.deepEqual(await readFile(nested), await readFile(f.source.approval));
  assert.equal((await lstat(nested, {bigint: true})).ino, inode);
  assert.deepEqual(await Promise.all([f.jobDirectory, ...f.destinations].map(path => readdir(path))), before);
});

test('selected approval is rechecked after an observer retargets its parent alias', async t => {
  const f = await jobFixture(t), external = join(f.root, 'approval-external'), alias = join(f.root, 'approval-alias');
  await mkdir(external, { mode: 0o700 });
  await writeFile(join(external, 'source.approval'), await readFile(f.source.approval), { mode: 0o600 });
  await writeFile(join(f.destinations[0], 'source.approval'), await readFile(f.source.approval), { mode: 0o600 });
  await symlink(external, alias); let moved = false;
  const before = await Promise.all([f.jobDirectory, ...f.destinations].map(path => readdir(path)));
  const inode = (await lstat(join(f.destinations[0], 'source.approval'), {bigint: true})).ino;
  await assert.rejects(f.seal({
    candidates: [{ input: f.source.input, approval: join(alias, 'source.approval') }],
    async onProgress(event) {
      if (!moved && event.phase === 'approval_inspected') {
        moved = true; await unlink(alias); await symlink(f.destinations[0], alias);
      }
    },
  }), code('backup_job_separate_path_required'));
  assert(moved);
  assert.deepEqual(await readFile(join(f.destinations[0], 'source.approval')), await readFile(f.source.approval));
  assert.equal((await lstat(join(f.destinations[0], 'source.approval'), {bigint: true})).ino, inode);
  assert.deepEqual(await Promise.all([f.jobDirectory, ...f.destinations].map(path => readdir(path))), before);
});

test('seal refuses a source whose parent alias resolves inside a destination', async t => {
  const f = await jobFixture(t), alias = join(f.root, 'source-alias');
  const nested = join(f.destinations[0], 'source');
  await writeFile(nested, DATA, { mode: 0o600 }); await symlink(f.destinations[0], alias);
  await assert.rejects(f.seal({ candidates: [{ input: join(alias, 'source'), approval: f.source.approval }] }),
    code('backup_job_separate_path_required'));
  assert.deepEqual(await readFile(nested), DATA);
});

test('run rechecks physical source separation after a parent alias is retargeted', async t => {
  const f = await jobFixture(t), external = join(f.root, 'external'), alias = join(f.root, 'source-alias');
  await mkdir(external, { mode: 0o700 }); await writeFile(join(external, 'source'), DATA, { mode: 0o600 });
  await symlink(external, alias);
  const job = await f.seal({ candidates: [{ input: join(alias, 'source'), approval: f.source.approval }] });
  await unlink(alias); await symlink(f.destinations[0], alias);
  await writeFile(join(f.destinations[0], 'source'), DATA, { mode: 0o600 });
  await assert.rejects(f.run(job.intent), code('backup_job_separate_path_required'));
  assert.deepEqual(await readdir(f.destinations[1]), []);
});

test('manifest path substitutions are rejected before writes', async t => {
  const f = await jobFixture(t), job = await f.seal();
  const modified = await rewriteIntent(job.intent, value => { value.destinations[0].path += '/..'; });
  await assert.rejects(f.run(modified), code('backup_job_invalid_intent')); await emptyTargets(f);
});

for (const mutation of [value => value.extra = true, value => value.checkpoint = null,
  value => value.sources.reverse().push(value.sources[0]), value => value.destinations = [],
  value => value.destinations[0].inode = '-1', value => value.witness_directory = '../outside']) {
  test('self-consistent hash does not bypass strict intent schema', async t => {
    const f = await jobFixture(t), job = await f.seal(), modified = await rewriteIntent(job.intent, mutation);
    await assert.rejects(f.run(modified)); await emptyTargets(f);
  });
}

test('changing the stored statement commitment cannot bypass signed verification', async t => {
  const f = await jobFixture(t), job = await f.seal(), modified = await rewriteIntent(job.intent, value => { value.statement_sha256 = '0'.repeat(64); });
  await assert.rejects(f.run(modified), code('backup_job_checkpoint_mismatch')); await emptyTargets(f);
});

test('unknown run destination overrides and work limits refuse before reading', async () => {
  const base = { intent: '/absent/intent', trustKey: '/absent/key', policy: { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32), object_format: 'sha256', minimum_head_generation: '1' } };
  await assert.rejects(runRepositoryBackupJob({ ...base, destinations: ['/arbitrary'] }), code('backup_invalid_job_options'));
  for (const maximumTotalBytes of [0, -1, 1.2, Number.MAX_SAFE_INTEGER]) await assert.rejects(runRepositoryBackupJob({ ...base, maximumTotalBytes }), code('backup_replenishment_read_limit'));
});
