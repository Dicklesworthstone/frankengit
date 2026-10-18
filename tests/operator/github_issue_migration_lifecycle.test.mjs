// Production CLI source selection and routing; only the existing migration
// preparer/inspector imports are replaced with an explicit module-boundary fixture.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { mkdtemp, chmod, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { Writable } from 'node:stream';
import { main } from '../../scripts/migrate_github_issues.mjs';

const cli = new URL('../../scripts/migrate_github_issues.mjs', import.meta.url).href;
const fixtureURL = 'data:text/javascript,' + encodeURIComponent(`
  export async function prepareGithubIssueMigration(value) { return globalThis.__fgMigrationLifecycle.prepare(value); }
  export async function inspectGithubIssueMigration(value) { return globalThis.__fgMigrationLifecycle.inspect(value); }
`);
const hooks = registerHooks({ resolve(specifier, context, next) {
  if (context.parentURL === cli && specifier === './lib/github-issue-migration.mjs') return { url: fixtureURL, shortCircuit: true };
  return next(specifier, context);
} });
after(() => { hooks.deregister(); delete globalThis.__fgMigrationLifecycle; });
function output() {
  let text = '';
  return { stream: new Writable({ write(bytes, _encoding, done) { text += bytes; done(); } }), json: () => JSON.parse(text) };
}
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-migration-lifecycle-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const sources = { schema: 'frankengit-github-issue-migration-sources-v1',
    inventory: { path: '/captures/inventory.json', sha256: '1'.repeat(64) },
    captures: [{ batch: 1, path: '/captures/one.json', sha256: '2'.repeat(64) }], offset: 1000, maxSteps: 10 };
  const bytes = Buffer.from(JSON.stringify(sources, null, 2) + '\n'), sourcePath = join(root, 'sources.json');
  await writeFile(sourcePath, bytes, { mode: 0o600 });
  const common = ['--workdir', join(root, 'prepared'), '--url', 'https://forge.example/repository/',
    '--tenant', '1'.repeat(32), '--repository', '2'.repeat(32), '--token-file', '/operator/original-token'];
  const args = ['prepare', ...common, '--sources', sourcePath, '--sources-sha256', createHash('sha256').update(bytes).digest('hex')];
  const calls = [];
  const prepared = { type: 'github_issue_migration_prepared', plan_sha256: '3'.repeat(64), mutation_submitted: false, atomic_migration: false };
  const backend = { prepare: async o => { calls.push(o); return prepared; }, inspect: async o => {
    calls.push(o); return { type: 'github_issue_migration_verified', plan_sha256: o.confirm, network_accessed: false, mutation_submitted: false };
  } };
  globalThis.__fgMigrationLifecycle = backend;
  const invoke = async (selected = args, stream) => {
    const out = output(), err = output();
    const code = await main(selected, { stdout: stream ?? out.stream, stderr: err.stream,
      execute: async () => { assert.fail('preparation/inspection must never execute a migration'); } });
    return { code, out, err };
  };
  return { root, sources, sourcePath, common, args, calls, backend, prepared, invoke };
}

test('prepare reads the pinned private selection and calls the existing preparer with its exact grammar', async t => {
  const f = await fixture(t), value = await f.invoke([...f.args, '--timeout-ms', '300000']);
  assert.equal(value.code, 0); assert.deepEqual(value.out.json(), f.prepared); assert.equal(f.calls.length, 1);
  const received = f.calls[0];
  assert.equal(received.inventoryFile, f.sources.inventory.path); assert.equal(received.inventorySha256, f.sources.inventory.sha256);
  assert.deepEqual(received.captures, f.sources.captures); assert.equal(received.offset, 1000); assert.equal(received.maxSteps, 10);
  assert.equal(received.sources, undefined); assert.equal(received.sourcesSha256, undefined); assert.equal(received.operation, undefined);
  assert.equal(received.tokenFile, '/operator/original-token'); assert.ok(received.timeoutMs > 0 && received.timeoutMs <= 300000);
});

test('inspect reuses the original migration pin and connection without preparation or execution', async t => {
  const f = await fixture(t); f.backend.prepare = () => assert.fail('unexpected preparation');
  const value = await f.invoke(['inspect', ...f.common, '--confirm', '4'.repeat(64)]);
  assert.equal(value.code, 0); assert.equal(value.out.json().network_accessed, false);
  assert.equal(f.calls.length, 1); assert.equal(f.calls[0].confirm, '4'.repeat(64)); assert.equal(f.calls[0].operation, undefined);
});

test('changed descriptor is refused before creating a child plan', async t => {
  const f = await fixture(t); await writeFile(f.sourcePath, JSON.stringify({ ...f.sources, offset: 2000 }) + '\n');
  const value = await f.invoke(); assert.equal(value.code, 2); assert.equal(f.calls.length, 0);
  assert.match(value.err.json().message, /pin_mismatch/);
});

for (const label of ['missing source pin', 'confirm on prepare', 'mutations on prepare', 'retry on prepare',
  'sources on inspect', 'retry on inspect', 'prepare timeout above bound', 'inspect timeout above bound']) {
  test(`lifecycle rejects ${label} before touching the migration`, async t => {
    const f = await fixture(t); let args = [...f.args];
    if (label === 'missing source pin') args = args.slice(0, -2);
    if (label === 'confirm on prepare') args.push('--confirm', '4'.repeat(64));
    if (label === 'mutations on prepare') args.push('--max-mutations', '1');
    if (label === 'retry on prepare') args.push('--retry-unresolved');
    if (label === 'sources on inspect') args = ['inspect', ...f.common, '--confirm', '4'.repeat(64), '--sources', f.sourcePath];
    if (label === 'retry on inspect') args = ['inspect', ...f.common, '--confirm', '4'.repeat(64), '--retry-unresolved'];
    if (label === 'prepare timeout above bound') args.push('--timeout-ms', '300001');
    if (label === 'inspect timeout above bound') args = ['inspect', ...f.common, '--confirm', '4'.repeat(64), '--timeout-ms', '300001'];
    const value = await f.invoke(args); assert.equal(value.code, 2); assert.equal(f.calls.length, 0);
  });
}

test('partial preparation error retains the existing preparer custody diagnostic', async t => {
  const f = await fixture(t), partial = { directory_created: true, prepared_batches: 2, mutation_submitted: false, preserve_custody: true };
  f.backend.prepare = async () => { const error = new Error('third batch preparation failed'); error.migration_preparation = partial; throw error; };
  const value = await f.invoke(); assert.equal(value.code, 2); assert.deepEqual(value.err.json().migration_preparation, partial);
});

test('completed preparation survives broken output without attempting a replacement preparation', async t => {
  const f = await fixture(t);
  const stream = new Writable({ write(_bytes, _encoding, done) { done(new Error('broken output')); } });
  const value = await f.invoke(f.args, stream);
  assert.equal(value.code, 4); assert.equal(f.calls.length, 1);
  assert.equal(value.err.json().migration_progress.plan_sha256, f.prepared.plan_sha256);
});

test('SIGINT and the global preparation deadline reach the original preparer', async t => {
  for (const trigger of ['signal', 'deadline']) {
    const f = await fixture(t);
    f.backend.prepare = async o => {
      if (trigger === 'signal') process.emit('SIGINT');
      if (!o.signal.aborted) await new Promise(resolve => o.signal.addEventListener('abort', resolve, { once: true }));
      o.signal.throwIfAborted();
    };
    const value = await f.invoke([...f.args, '--timeout-ms', '100']);
    assert.equal(value.code, trigger === 'signal' ? 3 : 2);
    assert.equal(value.err.json().absence_proves_non_commit, false);
  }
});
