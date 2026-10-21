import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, unlink, symlink, link, chmod, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { signRepositoryBackupFile } from '../../scripts/lib/repository-backup-approval.mjs';
import { initializeRepositoryBackupWitness, withRepositoryBackupWitness } from '../../scripts/lib/repository-backup-witness.mjs';
import { selectRepositoryBackup } from '../../scripts/lib/repository-backup-selection.mjs';

// Real filesystem, signatures and persistence, over opaque data, not fg archives.
const NOW = Date.parse('2026-10-08T12:00:00Z');
const POLICY = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16),
  object_format: 'sha256', minimum_head_generation: '1' };
const keys = generateKeyPairSync('ed25519');
const SECRET = Buffer.from(keys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
const PUBLIC = Buffer.from(keys.publicKey.export({ type: 'spki', format: 'pem' }));
const code = expected => error => error.code === expected;
async function fixture(t, policy = POLICY) {
  const root = await mkdtemp(join(tmpdir(), 'fg-witness-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const key = join(root, 'key'), directory = join(root, 'witness'); await writeFile(key, PUBLIC);
  const create = () => initializeRepositoryBackupWitness(directory, key, policy, { now: NOW });
  const withWitness = (action, changes = {}, options = {}) => withRepositoryBackupWitness(directory, key, { ...policy, ...changes }, { now: NOW, ...options }, action);
  const select = (rows, options = {}) => withWitness(witness => selectRepositoryBackup(rows, key, policy, { now: NOW, ...options }, witness), {}, options);
  async function candidate(name, generation, changes = {}) {
    const input = join(root, name), approval = input + '.approval'; await writeFile(input, changes.bytes ?? 'opaque ' + generation);
    const declarations = { ...policy, head_generation: generation, issued_at: '2026-10-08T11:00:00Z', ...changes.declarations };
    delete declarations.minimum_head_generation;
    const signed = await signRepositoryBackupFile(input, SECRET, declarations, { now: changes.now ?? NOW });
    await writeFile(approval, signed.envelope); return { input, approval };
  }
  return { root, key, directory, create, withWitness, select, candidate, state: () => readFile(join(directory, 'witness.json')) };
}
for (const object_format of ['sha1', 'sha256']) test(`${object_format}: restart refuses omitted newer evidence and accepts the retained checkpoint`, async t => {
  const f = await fixture(t, { ...POLICY, object_format }), old = await f.candidate('old', '9007199254740992'), high = await f.candidate('high', '9007199254740993');
  await f.create(); const selected = await f.select([old, high]);
  assert.equal(selected.report.selected.input, high.input); assert.equal(selected.report.read_only, false);
  assert.equal(selected.report.recovery_witness.highest_observed_generation, '9007199254740993');
  assert.equal(selected.report.newest_checkpoint_verified, false);
  const before = await f.state(); await assert.rejects(f.select([old]), code('backup_below_witness')); assert.deepEqual(await f.state(), before);
  assert.equal((await f.select([high])).report.selected.input, high.input);
});
for (const defect of ['missing', 'corrupt', 'expired', 'future', 'oversized']) test(`${defect} newer signed checkpoint remains remembered after failure`, async t => {
  const f = await fixture(t), low = await f.candidate('a-low', '1'); await f.create();
  const changes = defect === 'expired' ? { declarations: { expires_at: '2026-10-08T11:30:00Z' }, now: NOW - 3600000 }
    : defect === 'future' ? { declarations: { issued_at: '2026-10-08T13:00:00Z' }, now: NOW + 3600000 }
    : defect === 'oversized' ? { bytes: Buffer.alloc(1024) } : {};
  const high = await f.candidate('z-high', '2', changes);
  if (defect === 'missing') await unlink(high.input);
  if (defect === 'corrupt') await writeFile(high.input, 'changed');
  await assert.rejects(f.select([high, low], { maximumBytes: 100 }));
  assert.equal((await f.withWitness(w => w.snapshot())).highest_observed_generation, '2');
  await assert.rejects(f.select([low]), code('backup_below_witness'));
  const newer = await f.candidate('newer', '3'); assert.equal((await f.select([newer])).report.selected.input, newer.input);
});
test('maximum-generation conflicts survive restart even when one candidate is omitted', async t => {
  const f = await fixture(t); await f.create();
  const a = await f.candidate('a', '2'), b = await f.candidate('b', '2', { bytes: 'different' });
  await assert.rejects(f.select([a, b]), code('backup_checkpoint_ambiguous'));
  for (const row of [a, b]) await assert.rejects(f.select([row]), code('backup_witness_checkpoint_ambiguous'));
  const c = await f.candidate('c', '3'); assert.equal((await f.select([c])).report.recovery_witness.conflicting_statements, false);
});
test('identical signed replicas do not create conflict or rewrite the witness', async t => {
  const f = await fixture(t); await f.create(); const a = await f.candidate('a', '2'), b = await f.candidate('b', '2');
  await f.select([a]); const before = await f.state(); await f.select([b, a]); assert.deepEqual(await f.state(), before);
});
test('u64 maximum, stronger retained floor and lower independent floors remain lossless', async t => {
  const f = await fixture(t); await f.create();
  const high = await f.candidate('high', '18446744073709551615'); await f.select([high]);
  await f.withWitness(w => assert.equal(w.snapshot().minimum_head_generation, '18446744073709551615'), { minimum_head_generation: '18446744073709551615' });
  await assert.rejects(f.withWitness(() => {}), code('backup_witness_floor_regression'));
});
test('missing or corrupt retained state is never silently initialized', async t => {
  const f = await fixture(t); await assert.rejects(f.withWitness(() => {})); await f.create();
  const bytes = await f.state(); await unlink(join(f.directory, 'witness.json'));
  await assert.rejects(f.withWitness(() => {})); await assert.rejects(f.create());
  await writeFile(join(f.directory, 'witness.json'), bytes, { mode: 0o600 });
  assert.equal((await f.withWitness(w => w.snapshot())).highest_observed_generation, null);
  await writeFile(join(f.directory, 'witness.json'), '{}'); await assert.rejects(f.withWitness(() => {}), code('backup_witness_invalid_state'));
});
test('a tampered retained signature cannot become empty or lower state', async t => {
  const f = await fixture(t); await f.create(); const a = await f.candidate('a', '2'); await f.select([a]);
  const original = await f.state(), state = JSON.parse(original), envelope = JSON.parse(Buffer.from(state.observations[0], 'base64'));
  envelope.signatures[0].sig = Buffer.alloc(64).toString('base64'); state.observations[0] = Buffer.from(JSON.stringify(envelope)).toString('base64');
  await writeFile(join(f.directory, 'witness.json'), JSON.stringify(state) + '\n');
  await assert.rejects(f.select([a]), code('backup_invalid_signature'));
  await writeFile(join(f.directory, 'witness.json'), original); assert.equal((await f.select([a])).report.selected.input, a.input);
});
test('namespace/key substitution and duplicate JSON fields refuse', async t => {
  const f = await fixture(t); await f.create();
  await assert.rejects(f.withWitness(() => {}, { incarnation_id: '44'.repeat(16) }), code('backup_witness_trust_mismatch'));
  const other = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }); await writeFile(f.key, other);
  await assert.rejects(f.withWitness(() => {}), code('backup_witness_trust_mismatch')); await writeFile(f.key, PUBLIC);
  const bytes = await f.state(); await writeFile(join(f.directory, 'witness.json'), bytes.toString().replace('{', '{"type":"repository_backup_witness_v1",'));
  await assert.rejects(f.withWitness(() => {}), code('backup_witness_noncanonical_state'));
});
test('invalid newly supplied approvals do not ratchet the retained generation', async t => {
  const f = await fixture(t); await f.create(); const a = await f.candidate('a', '2'); await f.select([a]);
  const before = await f.state(), b = await f.candidate('b', '3'); const envelope = JSON.parse(await readFile(b.approval));
  envelope.signatures[0].sig = Buffer.alloc(64).toString('base64'); await writeFile(b.approval, JSON.stringify(envelope));
  await assert.rejects(f.select([b])); assert.deepEqual(await f.state(), before); await f.select([a]);
});
test('a later bad candidate or cancelled observer cannot forget an earlier persisted observation', async t => {
  const f = await fixture(t); await f.create(); const a = await f.candidate('a', '5'), b = await f.candidate('b', '6');
  await writeFile(b.approval, '{}'); await assert.rejects(f.select([a, b]));
  assert.equal((await f.withWitness(w => w.snapshot())).highest_observed_generation, '5');
  const c = await f.candidate('c', '7'), controller = new AbortController();
  await assert.rejects(f.select([c], { signal: controller.signal, onProgress(e) { if (e.phase === 'approval_inspected') controller.abort(); } }), code('backup_cancelled'));
  await assert.rejects(f.select([a]), code('backup_below_witness'));
});
test('exclusive ownership spans the entire consumer, not only selection', async t => {
  const f = await fixture(t); await f.create(); const a = await f.candidate('a', '2');
  let entered, release; const started = new Promise(r => entered = r), held = new Promise(r => release = r);
  const active = f.withWitness(async witness => { await witness.observe(await readFile(a.approval)); entered(); await held; return { state: 'complete' }; });
  await started;
  await assert.rejects(f.withWitness(() => assert.fail('concurrent consumer entered')), code('backup_witness_locked'));
  release(); assert.equal((await active).state, 'complete'); await f.select([a]);
});
test('failed native containment retains lock but closes file descriptors', async t => {
  const f = await fixture(t); await f.create(); const descriptorDirectory = process.platform === 'darwin' ? '/dev/fd' : '/proc/self/fd';
  const before = (await readdir(descriptorDirectory)).length;
  await assert.rejects(f.withWitness(() => { throw Object.assign(new Error('uncontained child'), { code: 'native_import_containment_failed' }); }), error => {
    assert.equal(error.witness_lock_retained, true); return true;
  });
  assert.equal((await readdir(descriptorDirectory)).length, before);
  await assert.rejects(f.withWitness(() => {}), code('backup_witness_locked'));
});
test('callback exceptions release ordinary leases, and confirmed completion survives late cancellation', async t => {
  const f = await fixture(t); await f.create();
  await assert.rejects(f.withWitness(() => { throw Error('consumer failed'); }), /consumer failed/);
  const controller = new AbortController();
  assert.deepEqual(await f.withWitness(() => { controller.abort(); return { state: 'complete' }; }, {}, { signal: controller.signal }), { state: 'complete' });
  await f.withWitness(() => {});
});
test('symlinks, hard-linked state, public permissions and oversized files refuse with valid twins', async t => {
  const f = await fixture(t); await f.create(); const state = join(f.directory, 'witness.json'), bytes = await f.state();
  const alias = join(f.root, 'alias'); await symlink(f.directory, alias);
  await assert.rejects(withRepositoryBackupWitness(alias, f.key, POLICY, {}, () => {}));
  await link(state, join(f.root, 'hardlink')); await assert.rejects(f.withWitness(() => {}), code('backup_witness_invalid_file'));
  await unlink(join(f.root, 'hardlink')); await f.withWitness(() => {});
  await chmod(state, 0o644); await assert.rejects(f.withWitness(() => {}), code('backup_witness_private_owner_required')); await chmod(state, 0o600);
  await writeFile(state, Buffer.alloc(65537)); await assert.rejects(f.withWitness(() => {}), code('backup_witness_invalid_file'));
  await writeFile(state, bytes); await f.withWitness(() => {});
});
test('witness capabilities expire with their owner and reject parallel observations', async t => {
  const f = await fixture(t); await f.create(); const a = await f.candidate('a', '2'), encoded = await readFile(a.approval); let retired;
  await f.withWitness(async w => { retired = w; const pending = w.observe(encoded); await assert.rejects(w.observe(encoded), code('backup_witness_concurrent_observation')); await pending; });
  await assert.rejects(retired.observe(encoded), code('backup_witness_not_live'));
});

test('actual CLI processes initialize, select and reject rollback across process restarts', async t => {
  const { spawnSync } = await import('node:child_process');
  const { resolve } = await import('node:path');
  const f = await fixture(t), declarations = { issued_at: '2026-10-08T11:00:00Z' };
  const a = await f.candidate('a', '2', { declarations }), b = await f.candidate('b', '3', { declarations });
  const common = [f.directory, '--trust-key', f.key, ...Object.entries(POLICY).flatMap(([k, v]) => ['--' + k.replaceAll('_', '-'), v])];
  const run = (operation, rest = []) => spawnSync(process.execPath, [resolve('scripts/repository_backup_witness.mjs'), operation, ...common, ...rest], { encoding: 'utf8', timeout: 5000 });
  assert.equal(run('init').status, 0);
  const first = run('select', ['--candidate', a.input, a.approval, '--candidate', b.input, b.approval]);
  assert.equal(first.status, 0, first.stderr); assert.equal(JSON.parse(first.stdout).selected.head_generation, '3');
  const regression = run('select', ['--candidate', a.input, a.approval]);
  assert.equal(regression.status, 1); assert.equal(JSON.parse(regression.stderr).code, 'backup_below_witness');
  assert.equal(JSON.parse(run('inspect').stdout).witness.highest_observed_generation, '3');
  assert.notEqual(run('init').status, 0);
});
test('a real killed witness owner leaves a blocking lease, never an automatically broken stale lock', async t => {
  const { spawn } = await import('node:child_process');
  const { resolve } = await import('node:path');
  const { pathToFileURL } = await import('node:url');
  const f = await fixture(t); await f.create();
  const module = pathToFileURL(resolve('scripts/lib/repository-backup-witness.mjs')).href;
  const child = spawn(process.execPath, ['--input-type=module', '--eval', `import { withRepositoryBackupWitness as hold } from ${JSON.stringify(module)};
    await hold(${JSON.stringify(f.directory)}, ${JSON.stringify(f.key)}, ${JSON.stringify(POLICY)}, {}, async () => {
      process.stdout.write('locked\\n'); await new Promise(() => setInterval(() => {}, 1000));
    });`], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => child.kill('SIGKILL'));
  const closed = new Promise(resolve => child.once('close', resolve));
  await new Promise((resolve, reject) => { child.stdout.once('data', resolve); child.once('error', reject); child.once('exit', () => reject(Error('child exited before lease'))); });
  child.kill('SIGKILL'); await closed;
  await assert.rejects(f.withWitness(() => {}), code('backup_witness_locked'));
  const retained = JSON.parse(await f.state()); assert.equal(retained.type, 'repository_backup_witness_v1');
});

// c69db34c: an owned observation drains into durable state before the lease is
// released (docs/RECOVERY_WITNESS_PERSISTENCE_FAILURES.md); new work is refused.
test('an unawaited observation is drained before the cross-process lease is released', async t => {
  const f = await fixture(t); await f.create(); const row = await f.candidate('row', '2'), encoded = await readFile(row.approval);
  let pending, witness;
  const result = await f.withWitness(w => { witness = w; pending = w.observe(encoded); pending.catch(() => {}); return { state: 'complete' }; });
  assert.deepEqual(result, { state: 'complete' });
  assert.equal((await pending).highest_observed_generation, '2');
  await assert.rejects(witness.observe(encoded), code('backup_witness_not_live'));
  assert.equal((await f.withWitness(w => w.snapshot())).highest_observed_generation, '2');
  await f.select([row]);
});
