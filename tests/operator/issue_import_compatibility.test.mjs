// GitHub's byte contract is frozen from original blob 5772c2dfce213bb1e91d2e2278c70d38381a77d3.
// Fixed RNG is TEST ONLY; production still uses platform cryptographic randomness.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { mkdtemp, writeFile, readFile, readdir, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { prepareGithubIssueImport, inspectPreparedGithubIssueImport, runGithubIssueImport } from '../../scripts/lib/github-issue-import.mjs';
import { createGithubIssueMigrationExecutor } from '../../scripts/lib/github-issue-migration-execute.mjs';
import { createIssueImportEngine } from '../../scripts/lib/issue-import-engine.mjs';
import { createIssueMigrationExecutor } from '../../scripts/lib/issue-migration-execute.mjs';
import { inspectPreparedNativeIssueImport } from '../../scripts/lib/native-issue-import.mjs';
import { captureBytes, issueImportSteps } from '../../scripts/lib/github-issue-source.mjs';
import { issueConnectionOptions } from '../../scripts/lib/forge-issue-operator.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { peer, encode } from './native_issue_transfer_helper.mjs';
const golden = JSON.parse(await readFile(new URL('../fixtures/issue-import/github-pre-extraction.json', import.meta.url)));
async function fixture(t, href = 'https://fixture.invalid/repository/ui/issues/', token) {
  const root = await mkdtemp(join(tmpdir(), 'fg-import-compat-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const tokenFile = join(root, 'token'), captureFile = join(root, 'capture');
  const credential = token ?? createHash('sha256').update('FrankenGit public regression token, never a real credential').digest('hex');
  await writeFile(tokenFile, credential, { mode: 0o600 });
  await writeFile(captureFile, captureBytes(golden.capture), { mode: 0o600 });
  return { root, captureFile, options: { workdir: join(root, 'plan'), href, tenant: '1'.repeat(32), repository: '2'.repeat(32), tokenFile } };
}
test('shared GitHub engine reproduces original capture, manifests, request bodies and keys byte for byte', async t => {
  const f = await fixture(t), descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto'); let nonce = 0, plan;
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { subtle: webcrypto.subtle, getRandomValues(value) { value.fill(++nonce); return value; } } });
  try { plan = await prepareGithubIssueImport({ ...f.options, captureFile: f.captureFile, offset: 40 }); }
  finally { Object.defineProperty(globalThis, 'crypto', descriptor); }
  assert.equal(plan.type, 'github_issue_import_prepared'); assert.equal(plan.plan_sha256, golden.plan_sha256);
  const hashes = {};
  for (const name of await readdir(f.options.workdir)) hashes[name] = recordDigest(await readFile(join(f.options.workdir, name)));
  assert.deepEqual(hashes, golden.hashes);
  const observed = await inspectPreparedGithubIssueImport({ ...f.options, confirm: golden.plan_sha256 });
  assert.equal(observed.type, 'github_issue_import_verified'); assert.equal(observed.steps, 3);
});
test('shared GitHub wrapper submits and recovers the unchanged exact source commands through real HTTP', async t => {
  const dest = await peer(); t.after(() => dest.close());
  const f = await fixture(t, dest.href, dest.token);
  const p = await prepareGithubIssueImport({ ...f.options, captureFile: f.captureFile, offset: 40 }), o = { ...f.options, confirm: p.plan_sha256 };
  assert.equal(dest.calls.length, 0);
  const before = await readFile(join(o.workdir, 'step-000000.request.json'));
  const first = await runGithubIssueImport({ ...o, operation: 'run', maxMutations: 1 });
  assert.equal(first.type, 'github_issue_import_progress'); assert.equal(first.stop_reason, 'mutation_limit');
  const rest = await runGithubIssueImport({ ...o, operation: 'run' });
  assert.equal(rest.complete, true); assert.equal(rest.mutation_calls, 2);
  assert.deepEqual(dest.source.get(41).events.map(e => e.action), issueImportSteps(golden.capture, 40).map(s => ({ name: s.action, ...s.fields })));
  assert.equal((await runGithubIssueImport({ ...o, operation: 'status' })).mutation_calls, 0);
  assert.deepEqual(await readFile(join(o.workdir, 'step-000000.request.json')), before);
});
test('native and GitHub source profiles do not reinterpret each other on resume', async t => {
  const f = await fixture(t), p = await prepareGithubIssueImport({ ...f.options, captureFile: f.captureFile });
  await assert.rejects(inspectPreparedNativeIssueImport({ ...f.options, confirm: p.plan_sha256 }), /native_import_plan_mismatch/);
  await assert.rejects(inspectPreparedGithubIssueImport({ ...f.options, confirm: '0'.repeat(64) }), /github_import_plan_mismatch/);
});
test('shared coordinator preserves GitHub output and lock schemas, original pins and one global allowance', async t => {
  const f = await fixture(t), root = join(f.root, 'migration'); await mkdir(root, { mode: 0o700 });
  const bytes = encode({ fixture: 'inspector boundary only; not a native migration' }), confirm = recordDigest(bytes);
  await writeFile(join(root, 'migration.json'), bytes, { mode: 0o600 });
  for (const n of [1, 2]) await mkdir(join(root, `batch-00000${n}`), { mode: 0o700 });
  const rows = [1, 2].map(n => ({ batch: n, plan_sha256: String(n).repeat(64), capture_sha256: 'a'.repeat(64), steps: 1, request_bytes: 123 }));
  const calls = [];
  const run = createGithubIssueMigrationExecutor({ connectionOptions: issueConnectionOptions,
    async inspect() {
      const lock = JSON.parse(await readFile(join(root, 'migration.sender.lock')));
      assert.deepEqual(lock, { schema: 'frankengit-github-issue-migration-sender-v1', plan_sha256: confirm });
      return { type: 'github_issue_migration_verified', plan_sha256: confirm, network_accessed: false,
        mutation_submitted: false, atomic_migration: false, steps: 2, request_bytes: 246, batches: rows };
    },
    async runBatch(o) {
      calls.push(o);
      return { type: 'github_issue_import_progress', plan_sha256: o.confirm, operation: o.operation,
        atomic_batch: false, absence_proves_non_commit: false, total_steps: 1, committed_observed: 1,
        mutation_calls: o.operation === 'run' ? 1 : 0, next_step: 1, complete: true, stop_reason: 'all_committed' };
    }
  });
  const result = await run({ ...f.options, workdir: root, confirm, operation: 'run', maxMutations: 1 });
  assert.equal(result.type, 'github_issue_migration_progress'); assert.equal(result.complete, true);
  assert.equal(result.mutation_calls, 1);
  assert.deepEqual(calls.map(c => [c.operation, c.confirm]), [['run', rows[0].plan_sha256], ['status', rows[1].plan_sha256]]);
  assert.equal(calls[1].maxMutations, undefined); assert.equal(calls[0].signal, calls[1].signal);
  assert.ok(calls[1].timeoutMs <= calls[0].timeoutMs);
  assert.ok(!(await readdir(root)).includes('migration.sender.lock'));
});
test('unknown import source adapters cannot acquire a lifecycle or authority', () => {
  assert.throws(() => createIssueImportEngine({ kind: 'other' }), /issue_import_adapter/);
  assert.throws(() => createIssueMigrationExecutor({}, 'other'), /issue_migration_adapter/);
});
