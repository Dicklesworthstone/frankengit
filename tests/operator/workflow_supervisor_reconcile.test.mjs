// Orchestration tests use an explicit backend fixture. Native fg is tested by
// scripts/e2e/suites/workflow/supervisor_loop.sh, not by these fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createController } from '../../scripts/operator/workflow_supervisor.mjs';
import { argumentsFor, exitCode } from '../../scripts/fg_workflow_supervisor.mjs';
import { reconcile as reconcileWatch } from '../../scripts/operator/workflow_watch.mjs';

const watched = (state = 'observed_succeeded', owner = false) => ({ type: 'workflow_watch_status', schema_version: 1,
  read_only: true, owner_present: owner, records: [{ state }] });
const published = (pending = 0) => ({ type: 'workflow_check_status', schema_version: 1,
  authoritative_check: false, execution_retried: false, owner_present: false,
  runs: [{ jobs: 2, committed: 2 - pending, refused: 0, pending, unknown: pending }] });
async function fixture(t, overrides = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-supervisor-reconcile-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const state = join(root, 'supervisor'); await mkdir(state, { mode: 0o700 });
  const calls = [];
  const backend = {
    configuration: value => value,
    execute: async () => { throw new Error('FORBIDDEN execution during reconciliation'); },
    publish: async () => { throw new Error('FORBIDDEN publication during reconciliation'); },
    watchStatus: async () => watched('execution_unknown'),
    publicationStatus: async value => { calls.push(['publicationStatus', value.state_directory]); return published(); },
    reconcile: async (watch, options) => { calls.push(['reconcile', watch.ref_hex, options.timeoutMs]); return watched(); },
    ...overrides,
  };
  const controller = createController(backend);
  const lanes = ['a', 'b'].map(name => ({ name, publisher: {
    state_directory: join(root, name+'-publication'), principal_id: '5'.repeat(32),
    watch: { schema: 'frankengit-workflow-watch-v1', fg: join(root, 'fg'), storage_root: join(root, 'store'),
      tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32),
      object_format: 'sha1', ref_hex: Buffer.from('refs/heads/'+name).toString('hex'),
      workflow_directory_hex: Buffer.from('.github/workflows').toString('hex'),
      input_prefixes_hex: [Buffer.from('.github').toString('hex')], event: 'push', max_runs: 16,
      trust: 'selected-branch-host-execution', state_directory: join(root, name+'-watch'), run_parent: join(root, name+'-runs') }
  } }));
  const config = controller.configuration({ schema: 'frankengit-workflow-supervisor-v1', state_directory: state, lanes });
  const original = Buffer.from(JSON.stringify(config)+'\n');
  await writeFile(join(state, 'binding.json'), original, { mode: 0o600 });
  return { root, state, config, controller, calls, original, backend };
}

test('reconcile calls only saved watcher reconciliation and publication status across all lanes', async t => {
  const f = await fixture(t), result = await f.controller.reconcile(f.config);
  assert.equal(result.type, 'workflow_supervisor_reconciliation');
  assert.deepEqual(f.calls.map(c => c[0]), ['reconcile', 'publicationStatus', 'reconcile', 'publicationStatus']);
  assert.deepEqual(result.lanes.map(r => r.name), ['a', 'b']);
  assert.ok(f.calls.filter(c => c[0] === 'reconcile').every(c => c[2] > 0 && c[2] <= 30000));
  for (const key of ['failed', 'pending', 'execution_retried', 'publication_submitted', 'locks_removed', 'authoritative_check']) assert.equal(result[key], false);
  assert.equal(exitCode(result), 0);
  assert.deepEqual(await readFile(join(f.state, 'binding.json')), f.original);
});

test('retained supervisor, watcher and publisher owners remain pending and are not removed', async t => {
  const f = await fixture(t, { reconcile: async () => watched('observed_succeeded', true),
    publicationStatus: async () => ({ ...published(1), owner_present: true, recovery_owner_present: true }) });
  const lock = join(f.state, 'owner.lock'); await mkdir(lock, { mode: 0o700 });
  const before = await lstat(lock), result = await f.controller.reconcile(f.config);
  assert.equal(result.owner_present, true); assert.equal(result.pending, true); assert.equal(result.failed, false);
  assert.equal(exitCode(result), 2); assert.equal((await lstat(lock)).ino, before.ino);
  assert.ok(result.lanes.every(r => r.watcher.owner_present && r.publication_owner_present && r.recovery_owner_present));
});

test('one invalid lane does not conceal another valid lane and no source execution is attempted', async t => {
  const f = await fixture(t, { reconcile: async watch => {
    if (watch.state_directory.endsWith('a-watch')) throw new Error('original report corrupt');
    return watched('observed_failed');
  } });
  const result = await f.controller.reconcile(f.config);
  assert.match(result.lanes[0].error.message, /original report corrupt/);
  assert.equal(result.lanes[1].watcher.observed_failed, 1); assert.equal(result.failed, true);
  assert.equal(result.pending, true); assert.equal(exitCode(result), 1);
});

test('deadline is shared across lanes and is not refreshed after an awaited read', async t => {
  let reads = 0, publications = 0;
  const f = await fixture(t, { reconcile: async () => { reads++; await new Promise(r => setTimeout(r, 30)); return watched(); },
    publicationStatus: async () => { publications++; return published(); } });
  const result = await f.controller.reconcile(f.config, { readTimeoutMs: 15 });
  assert.equal(reads, 1); assert.equal(publications, 0);
  assert.ok(result.lanes.every(r => /deadline/.test(r.error.message))); assert.equal(result.pending, true);
});

test('pre-abort and changed or missing bindings never enter a backend', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort(new Error('stop now'));
  await assert.rejects(f.controller.reconcile(f.config, { signal: stop.signal }), /stop now/);
  await assert.rejects(f.controller.reconcile({ ...f.config, lanes: f.config.lanes.slice(1) }), /configuration changed/);
  await rm(join(f.state, 'binding.json'));
  await assert.rejects(f.controller.reconcile(f.config), /original saved supervisor binding/);
  assert.equal(f.calls.length, 0);
});

test('mid-operation cancellation stops new reads but preserves already completed observations', async t => {
  const stop = new AbortController(); let reads = 0;
  const f = await fixture(t, { reconcile: async () => { reads++; stop.abort(new Error('requested stop')); return watched(); } });
  const result = await f.controller.reconcile(f.config, { signal: stop.signal });
  assert.equal(reads, 1); assert.equal(result.lanes[0].watcher.observed_succeeded, 1);
  assert.equal(result.stopped, true); assert.equal(result.pending, true);
});

test('CLI reconciliation requires consent and accepts only its applicable shared read budget', async () => {
  assert.deepEqual(argumentsFor(['reconcile', '--config', '/private/config', '--trusted-local', '--read-timeout-ms', '500']),
    { action: 'reconcile', config: '/private/config', options: { readTimeoutMs: 500 } });
  assert.throws(() => argumentsFor(['reconcile', '--config', '/private/config']), /trusted-local/);
  for (const flag of ['--max-publications', '--dispatch-timeout-ms', '--publication-timeout-ms', '--concurrency', '--max-cycles', '--interval-ms']) {
    assert.throws(() => argumentsFor(['reconcile', '--config', '/private/config', '--trusted-local', flag, '1']), /Invalid budget/);
  }
});

test('watcher reconciliation rejects pre-abort and unsupported budgets before custody I/O', async t => {
  const f = await fixture(t), watch = f.config.lanes[0].publisher.watch;
  const stop = new AbortController(); stop.abort(new Error('no read'));
  await assert.rejects(reconcileWatch(watch, { signal: stop.signal }), /no read/);
  for (const options of [{ timeoutMs: 0 }, { timeoutMs: 660001 }, { signal: {} }, { retry: true }]) {
    await assert.rejects(reconcileWatch(watch, options));
  }
});
