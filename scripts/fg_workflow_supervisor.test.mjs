import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, chmod, writeFile, readFile, readdir, symlink, link, lstat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createController } from './operator/workflow_supervisor.mjs';
import { argumentsFor, exitCode } from './fg_workflow_supervisor.mjs';

function published(overrides = {}) {
  return { type: 'workflow_check_status', schema_version: 1, authoritative_check: false, execution_retried: false, runs: [], ...overrides };
}
function jobCounts(overrides = {}) {
  return { jobs: 1, committed: 1, refused: 0, pending: 0, unknown: 0, ...overrides };
}
function watched(overrides = {}) {
  return { type: 'workflow_watch_status', schema_version: 1, read_only: true, records: [], owner_present: false, ...overrides };
}
function executed(outcome = 'observed_succeeded') {
  return { type: 'workflow_watch_result', schema_version: 1, authoritative_check: false, commit: 'a'.repeat(40), outcome };
}
async function fixture(t, count = 2, overrides = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-supervisor-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const state = join(root, 'supervisor'); await mkdir(state, { mode: 0o700 });
  const config = { schema: 'frankengit-workflow-supervisor-v1', state_directory: state, lanes: [] };
  for (let index = 0; index < count; index++) {
    const name = `lane-${index}`;
    config.lanes.push({ name, publisher: { schema: 'frankengit-workflow-check-publisher-v1', principal_id: '5'.repeat(32),
      state_directory: join(root, `${name}-publications`), watch: { schema: 'frankengit-workflow-watch-v1',
        fg: join(root, 'fg'), storage_root: join(root, 'store'), tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
        repository_incarnation: '3'.repeat(32), object_format: 'sha1', ref_hex: Buffer.from(`refs/heads/${name}`).toString('hex'),
        workflow_directory_hex: Buffer.from('.github/workflows').toString('hex'), input_prefixes_hex: [Buffer.from('.github').toString('hex')],
        event: 'push', state_directory: join(root, `${name}-watch`), run_parent: join(root, `${name}-runs`), max_runs: 128,
        trust: 'selected-branch-host-execution' } } });
  }
  const calls = [];
  const backend = {
    configuration(value) {
      assert.equal(value.schema, 'frankengit-workflow-check-publisher-v1');
      assert.equal(value.watch.trust, 'selected-branch-host-execution');
      return structuredClone(value);
    },
    async execute(watch, options) { calls.push(['execute', watch.ref_hex, options]); return executed(); },
    async publish(publisher, options) { calls.push(['publish', publisher.watch.ref_hex, options]); return published(); },
    async watchStatus(watch) { calls.push(['watch-status', watch.ref_hex]); return watched(); },
    async publicationStatus(publisher) { calls.push(['publication-status', publisher.watch.ref_hex]); return published(); },
    ...overrides,
  };
  return { root, state, config, calls, backend, controller: createController(backend) };
}

test('executes explicit branches in deterministic publication/execution/publication order', async t => {
  const f = await fixture(t); f.config.lanes.reverse();
  const result = await f.controller.once(f.config);
  assert.deepEqual(f.calls.map(call => call[0]), ['publish', 'execute', 'publish', 'publish', 'execute', 'publish']);
  assert.deepEqual(result.lanes.map(row => row.name), ['lane-0', 'lane-1']);
  assert.equal(result.failed, false); assert.equal(result.pending, false);
  assert.equal(result.authoritative_check, false); assert.equal(result.execution_retried, false);
  assert.deepEqual(await readdir(f.state), ['binding.json']);
  assert.equal((await lstat(join(f.state, 'binding.json'))).mode & 0o777, 0o600);
});

test('forwards exact scope, original principal and per-stage budgets without resume', async t => {
  const f = await fixture(t, 1), signal = new AbortController().signal;
  await f.controller.once(f.config, { signal, maxPublications: 3, timeoutMs: 99, readTimeoutMs: 7, dispatchTimeoutMs: 100 });
  assert.deepEqual(f.calls[0][2], { signal, timeoutMs: 99, maxPublications: 3 });
  assert.deepEqual(f.calls[1][2], { signal, readTimeoutMs: 7, dispatchTimeoutMs: 100 });
  assert.equal(Object.hasOwn(f.calls[0][2], 'resume'), false);
  assert.equal(f.calls[0][1], f.config.lanes[0].publisher.watch.ref_hex);
});

test('pending publication applies branch-local backpressure, not a global outage', async t => {
  const f = await fixture(t), first = f.config.lanes[0].publisher.watch.ref_hex;
  f.backend.publish = async publisher => {
    f.calls.push(['publish', publisher.watch.ref_hex]);
    return publisher.watch.ref_hex === first ? published({ runs: [jobCounts({ committed: 0, pending: 1, unknown: 1 })] }) : published();
  };
  const result = await f.controller.once(f.config);
  assert.equal(result.lanes[0].blocked, true); assert.equal(result.lanes[0].execution, undefined);
  assert.equal(result.lanes[1].execution.outcome, 'observed_succeeded');
  assert.equal(result.pending, true); assert.equal(exitCode(result), 2);
});

test('a safely reported workflow failure is still published and does not skip another branch', async t => {
  const f = await fixture(t);
  f.backend.execute = async watch => { f.calls.push(['execute', watch.ref_hex]); return executed('observed_failed'); };
  const result = await f.controller.once(f.config);
  assert.equal(result.failed, true); assert.equal(result.lanes.length, 2);
  assert.equal(f.calls.filter(call => call[0] === 'publish').length, 4);
  assert.equal(exitCode(result), 1);
});

test('a canonical refusal is not a success or permission to merge', async t => {
  const f = await fixture(t, 1);
  f.backend.publish = async () => published({ runs: [jobCounts({ committed: 0, refused: 1 })] });
  const result = await f.controller.once(f.config);
  assert.equal(result.failed, true); assert.equal(result.authoritative_check, false);
  assert.equal(exitCode(result), 1);
});

test('post-execution publication failure retains work and isolates the failing lane', async t => {
  const f = await fixture(t); let calls = 0;
  f.backend.publish = async () => { if (++calls === 2) throw new Error('lost publication reply'); return published(); };
  const result = await f.controller.once(f.config);
  assert.equal(result.lanes[0].execution.outcome, 'observed_succeeded');
  assert.equal(result.lanes[0].error.stage, 'publication_after_execution');
  assert.equal(result.lanes[1].execution.outcome, 'observed_succeeded');
  assert.equal(result.containment_unknown, false);
  assert.deepEqual(await readdir(f.state), ['binding.json']);
});

test('unknown native containment fences every later lane and retains the owner lock', async t => {
  const f = await fixture(t);
  f.backend.execute = async () => { throw Object.assign(new Error('native descendants not reaped'), { containment_unknown: true }); };
  const result = await f.controller.once(f.config);
  assert.equal(result.containment_unknown, true); assert.equal(result.lanes[1].skipped, 'containment_unknown');
  assert.deepEqual(await readdir(f.state), ['binding.json', 'owner.lock']);
  await assert.rejects(f.controller.once(f.config), { code: 'EEXIST' });
});

test('unknown publisher containment also retains supervisor custody', async t => {
  const f = await fixture(t);
  f.backend.publish = async () => { throw Object.assign(new Error('publication forced'), { containment_unknown: true }); };
  const result = await f.controller.once(f.config);
  assert.equal(result.lanes[0].error.stage, 'publication_before_execution');
  assert.equal(result.lanes[1].skipped, 'containment_unknown');
  assert.equal((await lstat(join(f.state, 'owner.lock'))).isDirectory(), true);
});

test('pre-cancelled cycle starts no native work and reports every skipped lane', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  const result = await f.controller.once(f.config, { signal: stop.signal });
  assert.equal(f.calls.length, 0); assert.equal(result.stopped, true); assert.equal(exitCode(result), 2);
  assert.equal(result.lanes.length, 2); assert.equal(result.pending, true);
});

test('cancellation drains the active execution and never schedules publication or a later lane', async t => {
  const f = await fixture(t), stop = new AbortController(); let drained = false;
  f.backend.execute = async (_watch, options) => {
    assert.equal(options.signal, stop.signal); stop.abort();
    await new Promise(resolve => setImmediate(resolve)); drained = true; return executed('observed_stopped');
  };
  const result = await f.controller.once(f.config, { signal: stop.signal });
  assert.equal(drained, true); assert.equal(f.calls.length, 1);
  assert.equal(result.lanes[0].execution.outcome, 'observed_stopped');
  assert.equal(result.lanes[1].skipped, 'stopped');
  assert.deepEqual(await readdir(f.state), ['binding.json']);
});

test('one supervisor owner spans the full cycle, including native execution', async t => {
  const f = await fixture(t, 1); let entered, release;
  const ready = new Promise(resolve => { entered = resolve; }), wait = new Promise(resolve => { release = resolve; });
  f.backend.execute = async () => { entered(); await wait; return executed(); };
  const active = f.controller.once(f.config); await ready;
  await assert.rejects(f.controller.once(f.config), { code: 'EEXIST' });
  release(); await active;
});

test('configuration is immutable across restart and reordering does not change its binding', async t => {
  const f = await fixture(t); await f.controller.once(f.config);
  f.config.lanes.reverse(); await f.controller.once(f.config);
  const changed = structuredClone(f.config); changed.lanes[0].publisher.principal_id = 'a'.repeat(32);
  f.calls.length = 0;
  await assert.rejects(f.controller.once(changed), /configuration changed/);
  assert.equal(f.calls.length, 0); assert.deepEqual(await readdir(f.state), ['binding.json']);
});

test('read-only status does not bind or start an empty supervisor', async t => {
  const f = await fixture(t), result = await f.controller.status(f.config);
  assert.equal(result.read_only, true); assert.equal(result.bound, false); assert.equal(result.owner_present, false);
  assert.deepEqual(await readdir(f.state), []); assert.equal(f.calls.length, 4);
  assert.ok(f.calls.every(call => call[0].endsWith('status'))); assert.equal(exitCode(result), 0);
});

test('status exposes unresolved native work and publisher locks without changing them', async t => {
  const f = await fixture(t, 1);
  f.backend.watchStatus = async () => watched({ records: [{ state: 'execution_unknown' }], owner_present: true });
  f.backend.publicationStatus = async () => published({ owner_present: true });
  const result = await f.controller.status(f.config);
  assert.equal(exitCode(result), 2); assert.equal(result.lanes[0].publication_owner_present, true);
  assert.deepEqual(await readdir(f.state), []);
});

test('isolates read-only status failures', async t => {
  const f = await fixture(t); let calls = 0;
  f.backend.watchStatus = async () => { if (++calls === 1) throw new Error('corrupt watch custody'); return watched(); };
  const result = await f.controller.status(f.config);
  assert.equal(result.lanes[0].error.stage, 'status'); assert.ok(result.lanes[1].publication); assert.equal(exitCode(result), 1);
});

test('rejects duplicate branches/names and cross-lane custody aliases before work', async t => {
  const f = await fixture(t);
  for (const edit of [
    value => { value.lanes[1].name = value.lanes[0].name; },
    value => { value.lanes[1].publisher.watch.ref_hex = value.lanes[0].publisher.watch.ref_hex; },
    value => { value.lanes[1].publisher.watch.run_parent = value.lanes[0].publisher.watch.state_directory; },
    value => { value.lanes[1].publisher.state_directory = join(value.lanes[0].publisher.watch.run_parent, 'child'); },
    value => { value.state_directory = join(value.lanes[0].publisher.watch.storage_root, 'child'); },
    value => { value.lanes[1].publisher.watch.storage_root = join(value.lanes[0].publisher.watch.storage_root, 'nested'); },
    value => { value.lanes[1].publisher.watch.fg = join(value.lanes[0].publisher.watch.state_directory, 'fg'); },
  ]) {
    const changed = structuredClone(f.config); edit(changed);
    await assert.rejects(f.controller.once(changed), /Duplicate|exactly one|disjoint|Overlapping/);
  }
  assert.equal(f.calls.length, 0); assert.deepEqual(await readdir(f.state), []);
});

test('rejects unknown fields, out-of-range budgets and implicit resume', async t => {
  const f = await fixture(t, 1);
  for (const options of [{ resume: true }, { maxPublications: 129 }, { dispatchTimeoutMs: 0 }, { timeoutMs: Infinity }, { signal: {} }]) {
    await assert.rejects(f.controller.once(f.config, options), /Unsupported|budget|signal/);
  }
  assert.throws(() => f.controller.configuration({ ...f.config, discover_branches: true }), /fields/);
  assert.throws(() => f.controller.configuration({ ...f.config, lanes: [] }), /64/);
  assert.throws(() => f.controller.configuration({ ...f.config, lanes: Array(65).fill(f.config.lanes[0]) }), /64/);
  assert.equal(f.calls.length, 0);
});

test('refuses writable, symlinked, hardlinked and interrupted supervisor custody', async t => {
  const f = await fixture(t, 1);
  await chmod(f.state, 0o755); await assert.rejects(f.controller.once(f.config), /0700/); await chmod(f.state, 0o700);
  const alias = join(f.root, 'alias'); await symlink(f.state, alias);
  await assert.rejects(f.controller.once({ ...f.config, state_directory: alias }), /0700/);
  const stray = join(f.state, 'binding.json.writing-interrupted'); await writeFile(stray, '{}', { mode: 0o600 });
  await assert.rejects(f.controller.once(f.config), /Unrecognized/); assert.equal(await readFile(stray, 'utf8'), '{}');
  await rm(stray); await f.controller.once(f.config);
  await link(join(f.state, 'binding.json'), join(f.root, 'hardlink'));
  await assert.rejects(f.controller.once(f.config), /private regular/);
});

test('rejects forged authoritative outcomes and contradictory publication counters', async t => {
  const f = await fixture(t, 1);
  for (const value of [published({ authoritative_check: true }), published({ execution_retried: true }),
    published({ runs: [jobCounts({ unknown: 1 })] }), published({ runs: [jobCounts({ jobs: 2 })] })]) {
    f.backend.publish = async () => value;
    const result = await f.controller.once(f.config);
    assert.equal(result.failed, true); assert.equal(result.lanes[0].execution, undefined);
  }
  f.backend.publish = async () => published(); f.backend.execute = async () => ({ ...executed(), authoritative_check: true });
  const result = await f.controller.once(f.config); assert.equal(result.lanes[0].error.stage, 'execution');
});

test('loads bounded private JSON and uses the backend publisher validator', async t => {
  const f = await fixture(t, 1), path = join(f.root, 'config.json');
  await writeFile(path, JSON.stringify(f.config), { mode: 0o600 });
  const loaded = await f.controller.loadConfiguration(path);
  assert.equal(loaded.lanes[0].publisher.watch.ref_hex, f.config.lanes[0].publisher.watch.ref_hex);
  await chmod(path, 0o644); await assert.rejects(f.controller.loadConfiguration(path), /private regular/);
});

test('CLI requires explicit trust and rejects duplicate, unknown and misplaced options', () => {
  assert.deepEqual(argumentsFor(['--help']), { help: true });
  assert.throws(() => argumentsFor(['once', '--config', '/a']), /trusted-local/);
  assert.equal(argumentsFor(['once', '--config', '/a', '--trusted-local']).action, 'once');
  assert.equal(argumentsFor(['status', '--config', '/a']).action, 'status');
  for (const args of [
    ['once', '--config', '/a', '--config', '/b', '--trusted-local'],
    ['once', '--config', '/a', '--trusted-local', '--resume'],
    ['once', '--config', '/a', '--trusted-local', '--max-publications', '01'],
    ['status', '--config', '/a', '--dispatch-timeout-ms', '3'],
    ['once', '--config', '--trusted-local'],
  ]) assert.throws(() => argumentsFor(args));
});


test('publication budget exhaustion blocks new execution even before remaining plans are prepared', async t => {
  const f = await fixture(t, 1);
  f.backend.publish = async () => published({ limit_reached: true });
  const result = await f.controller.once(f.config);
  assert.equal(result.lanes[0].execution, undefined); assert.equal(result.pending, true);
});

test('status summarizes thousands of records instead of duplicating native custody', async t => {
  const f = await fixture(t, 1);
  f.backend.watchStatus = async () => watched({ records: Array.from({ length: 4096 }, () => ({ state: 'observed_succeeded' })) });
  const result = await f.controller.status(f.config);
  assert.equal(result.lanes[0].watcher.observed_succeeded, 4096);
  assert.ok(JSON.stringify(result).length < 1500);
});
