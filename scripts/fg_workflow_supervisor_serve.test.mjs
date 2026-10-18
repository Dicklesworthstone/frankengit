import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createController } from './operator/workflow_supervisor.mjs';
import { argumentsFor, exitCode } from './fg_workflow_supervisor.mjs';

const published = extra => ({ type: 'workflow_check_status', schema_version: 1, authoritative_check: false,
  execution_retried: false, runs: [], ...extra });
const executed = outcome => ({ type: 'workflow_watch_result', schema_version: 1, authoritative_check: false,
  commit: 'a'.repeat(40), outcome: outcome ?? 'observed_succeeded' });
const idle = () => ({ type: 'workflow_watch_idle', schema_version: 1, authoritative_check: false,
  commit: 'a'.repeat(40), outcome: 'observed_succeeded' });
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
async function fixture(t, count = 3) {
  const root = await mkdtemp(join(tmpdir(), 'fg-supervisor-service-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const state = join(root, 'supervisor'); await mkdir(state, { mode: 0o700 });
  const config = { schema: 'frankengit-workflow-supervisor-v1', state_directory: state,
    lanes: Array.from({ length: count }, (_, index) => ({ name: `lane-${index}`, publisher: {
      schema: 'frankengit-workflow-check-publisher-v1', principal_id: '5'.repeat(32),
      state_directory: join(root, `publication-${index}`), watch: {
        schema: 'frankengit-workflow-watch-v1', fg: join(root, 'fg'), storage_root: join(root, `store-${index}`),
        tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32),
        object_format: 'sha1', ref_hex: Buffer.from(`refs/heads/lane-${index}`).toString('hex'),
        workflow_directory_hex: Buffer.from('.github/workflows').toString('hex'),
        input_prefixes_hex: [Buffer.from('.github').toString('hex')], event: 'push',
        state_directory: join(root, `watch-${index}`), run_parent: join(root, `runs-${index}`),
        max_runs: 128, trust: 'selected-branch-host-execution',
      },
    } })) };
  const calls = [], name = watch => Buffer.from(watch.ref_hex, 'hex').toString().split('/').at(-1);
  const backend = {
    configuration: value => structuredClone(value),
    async execute(watch) { calls.push(['execute', name(watch)]); return executed(); },
    async publish(publisher) { calls.push(['publish', name(publisher.watch)]); return published(); },
    async watchStatus() { return { type: 'workflow_watch_status', schema_version: 1, read_only: true, records: [] }; },
    async publicationStatus() { return published(); },
  };
  return { root, state, config, calls, name, backend, controller: createController(backend) };
}

test('independent stores run concurrently, bounded by the selected capacity', async t => {
  const f = await fixture(t, 5); let active = 0, peak = 0;
  f.backend.execute = async () => { active++; peak = Math.max(peak, active); await tick(); active--; return executed(); };
  const result = await f.controller.once(f.config, { concurrency: 2 });
  assert.equal(peak, 2); assert.equal(active, 0); assert.equal(result.failed, false); assert.equal(result.lanes.length, 5);
});

test('one store is reserved across publication and execution even with a larger pool', async t => {
  const f = await fixture(t, 4), busy = new Set(); let peak = 0;
  f.config.lanes[1].publisher.watch.storage_root = f.config.lanes[0].publisher.watch.storage_root;
  f.config.lanes[2].publisher.watch.storage_root = f.config.lanes[0].publisher.watch.storage_root;
  const operation = async watch => {
    assert.equal(busy.has(watch.storage_root), false);
    busy.add(watch.storage_root); peak = Math.max(peak, busy.size); await tick(); busy.delete(watch.storage_root);
  };
  f.backend.execute = async watch => { await operation(watch); return executed(); };
  f.backend.publish = async publisher => { await operation(publisher.watch); return published(); };
  const result = await f.controller.once(f.config, { concurrency: 4 });
  assert.equal(peak, 2); assert.equal(result.failed, false);
});

test('a busy store does not block admission of a later independent store', async t => {
  const f = await fixture(t), otherStarted = deferred(), release = deferred();
  f.config.lanes[1].publisher.watch.storage_root = f.config.lanes[0].publisher.watch.storage_root;
  f.backend.execute = async watch => {
    const name = f.name(watch); f.calls.push(['execute', name]);
    if (name === 'lane-0') await release.promise;
    if (name === 'lane-2') otherStarted.resolve();
    return executed();
  };
  const active = f.controller.once(f.config, { concurrency: 2 });
  await otherStarted.promise; assert.equal(f.calls.some(call => call[1] === 'lane-1'), false);
  release.resolve(); const result = await active;
  assert.equal(result.failed, false); assert.deepEqual(result.lanes.map(row => row.name), ['lane-0', 'lane-1', 'lane-2']);
});

test('unsafe containment stops admission and drains already active execution before returning', async t => {
  const f = await fixture(t, 4), both = deferred(), unsafe = deferred(), release = deferred();
  let entered = 0, drained = false, finished = false;
  f.backend.execute = async watch => {
    f.calls.push(['execute', f.name(watch)]); if (++entered === 2) both.resolve();
    await both.promise;
    if (f.name(watch) === 'lane-0') { unsafe.resolve(); throw Object.assign(new Error('owner forced'), { containment_unknown: true }); }
    await release.promise; drained = true; return executed();
  };
  const active = f.controller.once(f.config, { concurrency: 2 }).then(value => { finished = true; return value; });
  await unsafe.promise; await tick(); assert.equal(finished, false); assert.equal(entered, 2);
  assert.deepEqual(await readdir(f.state), ['binding.json', 'owner.lock']);
  release.resolve(); const result = await active;
  assert.equal(drained, true); assert.equal(result.containment_unknown, true);
  assert.equal(result.lanes[1].after, undefined); // No new publication after another owner becomes unsafe.
  assert.equal(result.lanes[2].skipped, 'containment_unknown'); assert.equal(result.lanes[3].skipped, 'containment_unknown');
  assert.deepEqual(await readdir(f.state), ['binding.json', 'owner.lock']);
});

test('a lane waiting in publication does not begin execution after another owner becomes unsafe', async t => {
  const f = await fixture(t, 2), first = deferred(), release = deferred();
  f.backend.publish = async publisher => {
    if (f.name(publisher.watch) === 'lane-1') { first.resolve(); await release.promise; }
    else { await first.promise; throw Object.assign(new Error('forced'), { containment_unknown: true }); }
    return published();
  };
  const active = f.controller.once(f.config, { concurrency: 2 }); await first.promise; await tick(); release.resolve();
  const result = await active;
  assert.equal(result.containment_unknown, true); assert.equal(f.calls.length, 0);
  assert.equal(result.lanes[1].blocked, true); assert.equal(result.lanes[1].execution, undefined);
});

test('cancellation stops queued lanes and drains all admitted owners', async t => {
  const f = await fixture(t, 4), stop = new AbortController(), both = deferred(), release = deferred(); let entered = 0;
  f.backend.execute = async (_watch, options) => {
    assert.equal(options.signal, stop.signal); if (++entered === 2) both.resolve();
    await release.promise; return executed('observed_stopped');
  };
  const active = f.controller.once(f.config, { concurrency: 2, signal: stop.signal });
  await both.promise; stop.abort(); release.resolve(); const result = await active;
  assert.equal(entered, 2); assert.equal(result.stopped, true); assert.equal(result.lanes[2].skipped, 'stopped');
  assert.ok(result.lanes.slice(0, 2).every(row => row.after === undefined));
  assert.deepEqual(await readdir(f.state), ['binding.json']);
});

test('continuous polling rotates admission order fairly and returns a bounded latest snapshot', async t => {
  const f = await fixture(t), reports = [];
  const result = await f.controller.serve(f.config, { maxCycles: 3, intervalMs: 1, onCycle: row => reports.push(row) });
  assert.deepEqual(f.calls.filter(call => call[0] === 'execute').map(call => call[1]),
    ['lane-0', 'lane-1', 'lane-2', 'lane-1', 'lane-2', 'lane-0', 'lane-2', 'lane-0', 'lane-1']);
  assert.deepEqual(reports.map(row => row.cycle), [1, 2, 3]); assert.equal(result.cycles, 3);
  assert.equal(result.type, 'workflow_supervisor_service'); assert.equal(result.failed, false);
  assert.equal(Object.hasOwn(result, 'history'), false); assert.equal(result.authoritative_check, false);
  assert.deepEqual(await readdir(f.state), ['binding.json']);
});

test('unchanged revisions remain native idle observations, never supervisor-manufactured executions', async t => {
  const f = await fixture(t, 1); let calls = 0;
  f.backend.execute = async () => ++calls === 1 ? executed() : idle();
  const result = await f.controller.serve(f.config, { maxCycles: 2, intervalMs: 1 });
  assert.equal(result.lanes[0].execution.type, 'workflow_watch_idle'); assert.equal(result.execution_retried, false);
});

test('lane exceptions are quarantined while healthy branches continue across cycles', async t => {
  const f = await fixture(t, 2); let brokenAttempts = 0;
  f.backend.execute = async watch => {
    f.calls.push(['execute', f.name(watch)]);
    if (f.name(watch) === 'lane-0') { brokenAttempts++; throw new Error('ambiguous execution needs reconciliation'); }
    return executed();
  };
  const result = await f.controller.serve(f.config, { maxCycles: 4, intervalMs: 1 });
  assert.equal(brokenAttempts, 1); assert.equal(f.calls.filter(call => call[0] === 'execute' && call[1] === 'lane-1').length, 4);
  assert.deepEqual(result.quarantined, ['lane-0']); assert.equal(result.lanes[0].skipped, 'recovery_required');
  assert.equal(result.failed, true); assert.equal(exitCode(result), 1);
});

test('an unknown publication is not implicitly resumed during subsequent polling', async t => {
  const f = await fixture(t, 2); let attempts = 0;
  f.backend.publish = async publisher => {
    if (f.name(publisher.watch) !== 'lane-0') return published();
    attempts++; return published({ runs: [{ jobs: 1, committed: 0, refused: 0, pending: 1, unknown: 1 }] });
  };
  const result = await f.controller.serve(f.config, { maxCycles: 3, intervalMs: 1 });
  assert.equal(attempts, 1); assert.deepEqual(result.quarantined, ['lane-0']); assert.equal(result.pending, true);
  assert.equal(exitCode(result), 2);
});

test('known publication backpressure can clear on a later cycle without quarantine', async t => {
  const f = await fixture(t, 1); let attempts = 0;
  f.backend.publish = async () => published({ limit_reached: ++attempts === 1 });
  const result = await f.controller.serve(f.config, { maxCycles: 2, intervalMs: 1 });
  assert.equal(result.cycles, 2); assert.deepEqual(result.quarantined, []); assert.equal(result.pending, false);
  assert.equal(f.calls.filter(call => call[0] === 'execute').length, 1);
});

test('service exits instead of busy-looping when every lane needs explicit recovery', async t => {
  const f = await fixture(t, 1); f.backend.execute = async () => { throw new Error('reconcile'); };
  const result = await f.controller.serve(f.config, { intervalMs: 1 });
  assert.equal(result.cycles, 1); assert.deepEqual(result.quarantined, ['lane-0']); assert.equal(result.failed, true);
});

test('ordinary workflow failures are observed, published and not quarantined', async t => {
  const f = await fixture(t, 1); f.backend.execute = async () => executed('observed_failed');
  const result = await f.controller.serve(f.config, { intervalMs: 1, maxCycles: 3 });
  assert.equal(result.cycles, 3); assert.equal(result.failed, true); assert.deepEqual(result.quarantined, []);
  assert.equal(f.calls.length, 6);
});

test('service keeps ownership across reporting and waits before admitting another cycle', async t => {
  const f = await fixture(t, 1), reported = deferred(), release = deferred(); let count = 0;
  const active = f.controller.serve(f.config, { intervalMs: 1, maxCycles: 2, onCycle: async () => {
    if (++count === 1) { reported.resolve(); await release.promise; }
  } });
  await reported.promise; await tick(); assert.equal(f.calls.length, 3);
  await assert.rejects(f.controller.once(f.config), { code: 'EEXIST' });
  release.resolve(); await active; assert.equal(f.calls.length, 6);
});

test('reporter mutations cannot forge containment or change service outcomes', async t => {
  const f = await fixture(t, 1);
  f.backend.execute = async () => { throw Object.assign(new Error('forced'), { containment_unknown: true }); };
  const result = await f.controller.serve(f.config, { maxCycles: 2, intervalMs: 1, onCycle: row => {
    row.containment_unknown = false; row.failed = false; row.lanes.length = 0;
  } });
  assert.equal(result.containment_unknown, true); assert.equal(result.failed, true); assert.equal(result.lanes.length, 1);
  assert.deepEqual(await readdir(f.state), ['binding.json', 'owner.lock']);
});

test('reporter failure preserves an already latched unknown containment lock', async t => {
  const f = await fixture(t, 1);
  f.backend.execute = async () => { throw Object.assign(new Error('forced'), { containment_unknown: true }); };
  await assert.rejects(f.controller.serve(f.config, { onCycle() { throw new Error('broken output pipe'); } }), /broken output/);
  assert.deepEqual(await readdir(f.state), ['binding.json', 'owner.lock']);
});

test('reporter failure after contained work stops the service without erasing native history', async t => {
  const f = await fixture(t, 1);
  await assert.rejects(f.controller.serve(f.config, { onCycle() { throw new Error('broken output pipe'); } }), /broken output/);
  assert.equal(f.calls.length, 3); assert.deepEqual(await readdir(f.state), ['binding.json']);
});

test('service cancellation interrupts the polling sleep without a new cycle', async t => {
  const f = await fixture(t, 1), stop = new AbortController();
  const result = await f.controller.serve(f.config, { intervalMs: 3_600_000, signal: stop.signal,
    onCycle() { setImmediate(() => stop.abort()); } });
  assert.equal(result.cycles, 1); assert.equal(result.stopped, true); assert.equal(f.calls.length, 3);
  assert.deepEqual(await readdir(f.state), ['binding.json']);
});

test('pre-cancelled service admits no work and reports zero cycles', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  const result = await f.controller.serve(f.config, { signal: stop.signal });
  assert.equal(result.cycles, 0); assert.equal(result.stopped, true); assert.equal(f.calls.length, 0); assert.equal(exitCode(result), 2);
});

test('service rejects unbounded or malformed scheduling controls before custody changes', async t => {
  const f = await fixture(t, 1);
  for (const options of [{ concurrency: 17 }, { concurrency: 0 }, { concurrency: 1.5 }, { intervalMs: 0 },
    { intervalMs: 3_600_001 }, { maxCycles: -1 }, { maxCycles: 1_000_001 }, { onCycle: true }, { discover: true }]) {
    await assert.rejects(f.controller.serve(f.config, options));
  }
  assert.deepEqual(await readdir(f.state), []); assert.equal(f.calls.length, 0);
});

test('CLI accepts bounded service controls and requires explicit execution trust', () => {
  const selected = argumentsFor(['serve', '--config', '/config', '--trusted-local', '--concurrency', '4',
    '--interval-ms', '100', '--max-cycles', '0']);
  assert.equal(selected.action, 'serve');
  assert.deepEqual(selected.options, { concurrency: 4, intervalMs: 100, maxCycles: 0 });
  assert.throws(() => argumentsFor(['serve', '--config', '/config']), /trusted-local/);
  for (const args of [
    ['serve', '--config', '/config', '--trusted-local', '--concurrency', '17'],
    ['serve', '--config', '/config', '--trusted-local', '--interval-ms', '0'],
    ['serve', '--config', '/config', '--trusted-local', '--max-cycles', '01'],
    ['once', '--config', '/config', '--trusted-local', '--interval-ms', '10'],
    ['status', '--config', '/config', '--concurrency', '1'],
  ]) assert.throws(() => argumentsFor(args));
});

test('containment is fenced in the failing await continuation, before another ready lane can launch', async t => {
  const f = await fixture(t, 2);
  f.backend.publish = async publisher => {
    if (f.name(publisher.watch) === 'lane-0') throw Object.assign(new Error('forced'), { containment_unknown: true });
    return published();
  };
  const result = await f.controller.once(f.config, { concurrency: 2 });
  assert.equal(result.containment_unknown, true); assert.equal(f.calls.length, 0);
  assert.equal(result.lanes[1].execution, undefined);
});
