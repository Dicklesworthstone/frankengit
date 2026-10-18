// The existing importer/inspector boundary is simulated here; custody, ownership,
// scheduling, cancellation and reporting run through the actual new executor.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, rename, symlink, chmod, link, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { createGithubIssueMigrationExecutor } from '../../scripts/lib/github-issue-migration-execute.mjs';

const hash = data => createHash('sha256').update(data).digest('hex');
const token = 'a'.repeat(64), tenant = '1'.repeat(32), repository = '2'.repeat(32);
async function fixture(t, counts = [2, 3, 1]) {
  const parent = await mkdtemp(join(tmpdir(), 'fg-migration-executor-'));
  await chmod(parent, 0o700); t.after(() => rm(parent, { recursive: true, force: true }));
  const workdir = join(parent, 'migration'); await mkdir(workdir, { mode: 0o700 });
  const bytes = Buffer.from('{"test_boundary":"prepared migration inspector fixture"}\n');
  await writeFile(join(workdir, 'migration.json'), bytes, { mode: 0o600 });
  const rows = [];
  for (const [index, steps] of counts.entries()) {
    await mkdir(join(workdir, `batch-${String(index + 1).padStart(6, '0')}`), { mode: 0o700 });
    rows.push({ batch: index + 1, capture_sha256: hash(`capture-${index}`), plan_sha256: hash(`plan-${index}`), steps, request_bytes: steps * 400 });
  }
  await writeFile(join(parent, 'token'), token, { mode: 0o600 });
  const options = { operation: 'run', workdir, confirm: hash(bytes), href: 'https://forge.example/repo/',
    tenant, repository, tokenFile: join(parent, 'token'), timeoutMs: 30000 };
  const verified = { type: 'github_issue_migration_verified', plan_sha256: options.confirm,
    network_accessed: false, mutation_submitted: false, atomic_migration: false,
    batches: rows, steps: counts.reduce((a, b) => a + b, 0), request_bytes: counts.reduce((a, b) => a + b, 0) * 400 };
  const calls = []; let inspections = 0;
  const backend = {
    connectionOptions: value => ({ ...value, onProgress: value.onProgress ?? (() => {}) }),
    inspect: async value => { inspections++; assert.equal(value.confirm, options.confirm); return structuredClone(verified); },
    runBatch: async value => { calls.push(value); const row = rows.find(row => row.plan_sha256 === value.confirm); return outcome(row, value); }
  };
  return { parent, workdir, rows, options, verified, calls, backend, inspections: () => inspections,
    run: (changes = {}) => createGithubIssueMigrationExecutor(backend)({ ...options, ...changes }) };
}
function outcome(row, options, extra = {}) {
  return { type: 'github_issue_import_progress', plan_sha256: row.plan_sha256, operation: options.operation,
    committed_observed: row.steps, mutation_calls: options.operation === 'status' ? 0 : row.steps,
    next_step: row.steps, total_steps: row.steps, complete: true, stop_reason: 'all_committed',
    atomic_batch: false, absence_proves_non_commit: false, ...extra };
}
function pending(row, options, reason = 'not_started_locally', calls = 0, committed = 0) {
  return outcome(row, options, { complete: false, committed_observed: committed, next_step: committed,
    mutation_calls: calls, stop_reason: reason });
}
async function noOwner(f) { assert.ok(!(await readdir(f.workdir)).includes('migration.sender.lock')); }
function rejectedProgress(error, committed) {
  assert.equal(error.migration_progress.committed_observed, committed);
  assert.equal(error.migration_progress.complete, false); return true;
}

test('complete migration composes original child plans in exact order after one full preflight', async t => {
  const f = await fixture(t), events = [];
  f.backend.runBatch = async o => {
    assert.equal(f.inspections(), 1); f.calls.push(o);
    assert.ok((await readdir(f.workdir)).includes('migration.sender.lock'));
    const row = f.rows.find(row => row.plan_sha256 === o.confirm);
    assert.equal(o.workdir, join(f.workdir, `batch-${String(row.batch).padStart(6, '0')}`));
    assert.equal(o.href, f.options.href); assert.equal(o.tenant, tenant); assert.equal(o.repository, repository);
    assert.equal(o.tokenFile, f.options.tokenFile); assert.equal(o.retryUnresolved, false);
    return outcome(row, o);
  };
  const result = await f.run({ maxMutations: 7, onProgress: event => events.push(event) });
  assert.equal(result.complete, true); assert.equal(result.stop_reason, 'all_committed');
  assert.equal(result.committed_observed, 6); assert.equal(result.mutation_calls, 6);
  assert.deepEqual(f.calls.map(o => o.maxMutations), [7, 5, 2]);
  assert.deepEqual(events.map(e => e.batch), [1, 2, 3]);
  assert.equal(result.atomic_migration, false); assert.equal(result.canonical_snapshot, false);
  await noOwner(f);
});

test('global mutation exhaustion never becomes a fresh per-batch budget', async t => {
  const f = await fixture(t, [2, 2, 1]);
  f.backend.runBatch = async o => {
    f.calls.push(o); const row = f.rows[f.calls.length - 1];
    return o.operation === 'status' ? pending(row, o) : outcome(row, o);
  };
  const result = await f.run({ maxMutations: 2 });
  assert.equal(result.mutation_calls, 2); assert.equal(result.committed_observed, 2);
  assert.equal(result.stop_reason, 'mutation_limit'); assert.equal(result.complete, false);
  assert.deepEqual(f.calls.map(o => o.operation), ['run', 'status']);
  assert.equal(f.calls[1].maxMutations, undefined); assert.equal(f.calls[1].retryUnresolved, undefined);
  await noOwner(f);
});

test('exhausted mutation budget can still recover already committed later batches', async t => {
  const f = await fixture(t, [2, 2, 1]);
  const result = await f.run({ maxMutations: 2 });
  assert.equal(result.complete, true); assert.equal(result.mutation_calls, 2);
  assert.deepEqual(f.calls.map(o => o.operation), ['run', 'status', 'status']);
});

test('previously committed batches spend no new mutation allowance', async t => {
  const f = await fixture(t, [3, 2]);
  f.backend.runBatch = async o => {
    f.calls.push(o); const row = f.rows[f.calls.length - 1];
    return outcome(row, o, { mutation_calls: row.batch === 1 ? 0 : 2 });
  };
  const result = await f.run({ maxMutations: 2 });
  assert.equal(result.complete, true); assert.equal(result.mutation_calls, 2);
  assert.deepEqual(f.calls.map(o => o.maxMutations), [2, 2]);
});

test('uncertain child blocks later batches; explicit restart preserves every original identity', async t => {
  const f = await fixture(t, [2, 1]);
  const seen = [];
  f.backend.runBatch = async o => {
    seen.push({ key: o.confirm, workdir: o.workdir, retry: o.retryUnresolved });
    const row = f.rows.find(row => row.plan_sha256 === o.confirm);
    return row.batch === 1 && !o.retryUnresolved ? pending(row, o, 'unresolved_original_request', 0, 1) : outcome(row, o);
  };
  const first = await f.run();
  assert.equal(first.stop_reason, 'unresolved_original_request'); assert.equal(seen.length, 1);
  const second = await f.run({ retryUnresolved: true });
  assert.equal(second.complete, true);
  assert.deepEqual(seen.slice(0, 2).map(({ key, workdir }) => ({ key, workdir })),
    [1, 2].map(() => ({ key: f.rows[0].plan_sha256, workdir: join(f.workdir, 'batch-000001') })));
  assert.deepEqual(seen.map(row => row.retry), [false, true, true]);
});

test('status observes all batches despite gaps and canonical refusals, even with retained owner', async t => {
  const f = await fixture(t, [2, 2, 1]);
  await writeFile(join(f.workdir, 'migration.sender.lock'), 'crashed owner', { mode: 0o600 });
  f.backend.runBatch = async o => {
    f.calls.push(o); const row = f.rows[f.calls.length - 1];
    assert.equal(o.operation, 'status'); assert.equal(o.retryUnresolved, undefined);
    if (row.batch === 1) return pending(row, o, 'unresolved_original_request');
    if (row.batch === 2) return { ...pending(row, o, 'terminal_refusal', 0, 1),
      refusal: { outcome: 'refused', tx: 'tx-2', rcr: null, refusal: 'policy-denied' } };
    return outcome(row, o);
  };
  const result = await f.run({ operation: 'status' });
  assert.equal(result.owner_present, true); assert.equal(result.remote_read_only, true);
  assert.equal(result.stop_reason, 'terminal_refusal'); assert.equal(result.committed_observed, 2);
  assert.equal(result.mutation_calls, 0); assert.equal(f.calls.length, 3);
  assert.equal(await readFile(join(f.workdir, 'migration.sender.lock'), 'utf8'), 'crashed owner');
});

test('canonical refusal stops sending but does not hide earlier committed steps', async t => {
  const f = await fixture(t, [2, 2, 1]);
  f.backend.runBatch = async o => {
    f.calls.push(o); const row = f.rows[f.calls.length - 1];
    return row.batch === 2 ? { ...pending(row, o, 'terminal_refusal', 1),
      refusal: { outcome: 'refused', tx: 'original-tx', rcr: null, refusal: 'original-record' } } : outcome(row, o);
  };
  const result = await f.run();
  assert.equal(result.stop_reason, 'terminal_refusal'); assert.equal(result.committed_observed, 2);
  assert.equal(result.mutation_calls, 3); assert.equal(f.calls.length, 2);
});

test('full preflight failure reaches no batch and releases only its own sender', async t => {
  const f = await fixture(t);
  f.backend.inspect = async () => { throw new Error('late child request hash changed'); };
  await assert.rejects(f.run(), error => rejectedProgress(error, 0));
  assert.equal(f.calls.length, 0); await noOwner(f);
});

test('missing or symlinked later child refuses before even the first outcome query', async t => {
  for (const redirect of [false, true]) {
    const f = await fixture(t), last = join(f.workdir, 'batch-000003');
    await rm(last, { recursive: true });
    if (redirect) await symlink(join(f.workdir, 'batch-000002'), last);
    await assert.rejects(f.run()); assert.equal(f.calls.length, 0); await noOwner(f);
  }
});

test('root pin mismatch is refused before inspection or sender acquisition', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ confirm: '0'.repeat(64) }), /pin_mismatch/);
  assert.equal(f.inspections(), 0); assert.equal(f.calls.length, 0); await noOwner(f);
});

test('private regular single-link and bounded root files are required', async t => {
  for (const kind of ['public', 'hardlink', 'large', 'symlink']) {
    const f = await fixture(t), file = join(f.workdir, 'migration.json');
    if (kind === 'public') await chmod(file, 0o644);
    if (kind === 'hardlink') await link(file, join(f.parent, 'alias'));
    if (kind === 'large') await writeFile(file, Buffer.alloc(256 * 1024 + 1));
    if (kind === 'symlink') { await rename(file, join(f.parent, 'root')); await symlink(join(f.parent, 'root'), file); }
    await assert.rejects(f.run()); assert.equal(f.calls.length, 0);
  }
});

test('public or aliased migration directories are not accepted', async t => {
  const f = await fixture(t);
  await chmod(f.workdir, 0o755); await assert.rejects(f.run(), /directory_changed_or_unsafe/);
  await chmod(f.workdir, 0o700); const alias = join(f.parent, 'alias'); await symlink(f.workdir, alias);
  await assert.rejects(f.run({ workdir: alias }), /directory_changed_or_unsafe/);
  assert.equal(f.calls.length, 0);
});

test('one sender owns all batches; a competing run cannot enter a child', async t => {
  const f = await fixture(t, [1]); let entered;
  const entering = new Promise(resolve => { entered = resolve; }); let finish;
  const gate = new Promise(resolve => { finish = resolve; });
  f.backend.runBatch = async o => { f.calls.push(o); entered(); await gate; return outcome(f.rows[0], o); };
  const active = f.run(); await entering;
  await assert.rejects(f.run(), /sender_lock_retained/);
  assert.equal(f.calls.length, 1); finish(); assert.equal((await active).complete, true); await noOwner(f);
});

test('root replacement after a committed batch stops admission and preserves the original owner', async t => {
  const g = await fixture(t), retained = join(g.parent, 'original');
  g.backend.runBatch = async o => {
    g.calls.push(o); await rename(g.workdir, retained); await mkdir(g.workdir, { mode: 0o700 });
    await writeFile(join(g.workdir, 'migration.sender.lock'), 'replacement', { mode: 0o600 });
    return outcome(g.rows[0], o);
  };
  await assert.rejects(g.run(), error => {
    assert.equal(error.migration_progress.committed_observed, 2);
    assert.match(error.migration_cleanup_error, /directory_changed_or_unsafe/); return true;
  });
  assert.equal(g.calls.length, 1);
  assert.equal(await readFile(join(g.workdir, 'migration.sender.lock'), 'utf8'), 'replacement');
  assert.ok((await readdir(retained)).includes('migration.sender.lock'));
});

test('changed later directory or migration root is detected before its next batch', async t => {
  for (const kind of ['directory', 'manifest']) {
    const f = await fixture(t);
    f.backend.runBatch = async o => {
      f.calls.push(o);
      if (kind === 'directory') {
        const next = join(f.workdir, 'batch-000002'); await rename(next, join(f.parent, 'old-child'));
        await mkdir(next, { mode: 0o700 });
      } else await writeFile(join(f.workdir, 'migration.json'), '{}\n');
      return outcome(f.rows[0], o);
    };
    await assert.rejects(f.run(), error => rejectedProgress(error, 2)); assert.equal(f.calls.length, 1);
  }
});

test('replaced sender lock is never unlinked as cleanup', async t => {
  const f = await fixture(t, [1]);
  f.backend.runBatch = async o => {
    await rename(join(f.workdir, 'migration.sender.lock'), join(f.parent, 'owner-original'));
    await writeFile(join(f.workdir, 'migration.sender.lock'), 'different owner', { mode: 0o600 });
    return outcome(f.rows[0], o);
  };
  await assert.rejects(f.run(), error => {
    assert.match(error.message, /sender_lock_changed/); assert.equal(error.migration_progress.complete, true); return true;
  });
  assert.equal(await readFile(join(f.workdir, 'migration.sender.lock'), 'utf8'), 'different owner');
});

test('pre-cancellation touches no importer and creates no owner', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  await assert.rejects(f.run({ signal: stop.signal }));
  assert.equal(f.calls.length, 0); assert.equal(f.inspections(), 0); await noOwner(f);
});

test('cancellation after a validated batch retains it and stops the next batch', async t => {
  const f = await fixture(t), stop = new AbortController();
  await assert.rejects(f.run({ signal: stop.signal, onProgress: () => stop.abort() }), error => rejectedProgress(error, 2));
  assert.equal(f.calls.length, 1); await noOwner(f);
});

test('late cancellation cannot erase a completed final batch', async t => {
  const f = await fixture(t, [1]), stop = new AbortController();
  const result = await f.run({ signal: stop.signal, onProgress: () => stop.abort() });
  assert.equal(result.complete, true); assert.equal(result.committed_observed, 1); await noOwner(f);
});

test('one diminishing deadline covers inspection and every child', async t => {
  const f = await fixture(t, [1, 1]); let inspectBudget;
  f.backend.inspect = async o => { inspectBudget = o.timeoutMs; await sleep(25); return f.verified; };
  f.backend.runBatch = async o => { f.calls.push(o); await sleep(25); return outcome(f.rows[f.calls.length - 1], o); };
  assert.equal((await f.run({ timeoutMs: 2000 })).complete, true);
  assert.ok(f.calls[0].timeoutMs < inspectBudget - 15);
  assert.ok(f.calls[1].timeoutMs < f.calls[0].timeoutMs - 15);
  assert.equal(f.calls[0].signal, f.calls[1].signal);
});

test('deadline expiration during a child preserves committed partial progress and blocks later work', async t => {
  const f = await fixture(t, [2, 1]);
  f.backend.runBatch = async o => {
    f.calls.push(o);
    await new Promise(resolve => o.signal.addEventListener('abort', resolve, { once: true }));
    const error = new Error('native deadline after one terminal');
    error.import_progress = pending(f.rows[0], o, null, 1, 1); throw error;
  };
  await assert.rejects(f.run({ timeoutMs: 100 }), error => rejectedProgress(error, 1));
  assert.equal(f.calls.length, 1); await noOwner(f);
});

test('child output/storage failure retains prefix and exact terminal coordinates, without another call', async t => {
  const f = await fixture(t, [2, 2]);
  f.backend.runBatch = async o => {
    f.calls.push(o); const row = f.rows[f.calls.length - 1];
    if (row.batch === 1) return outcome(row, o);
    const error = new Error('child cannot save final terminal');
    error.import_progress = pending(row, o, null, 1, 0);
    error.observed_terminal = { index: 0, outcome: 'committed', tx: 'original', rcr: 'rcr', refusal: null };
    throw error;
  };
  await assert.rejects(f.run(), error => {
    assert.equal(error.migration_progress.committed_observed, 2); assert.equal(error.migration_progress.mutation_calls, 3);
    assert.equal(error.migration_observed_terminal.batch, 2); assert.equal(error.migration_observed_terminal.tx, 'original'); return true;
  });
  assert.equal(f.calls.length, 2);
});

test('final child reporting failure still exposes all committed progress', async t => {
  const f = await fixture(t, [1]);
  f.backend.runBatch = async o => { const error = new Error('reporter failed'); error.import_progress = outcome(f.rows[0], o); throw error; };
  await assert.rejects(f.run(), error => {
    assert.equal(error.migration_progress.complete, true); assert.equal(error.migration_progress.stop_reason, 'all_committed'); return true;
  });
});

test('throwing or asynchronous progress consumers stop subsequent work', async t => {
  for (const onProgress of [() => { throw new Error('output failed'); }, () => Promise.resolve()]) {
    const f = await fixture(t);
    await assert.rejects(f.run({ onProgress }), error => rejectedProgress(error, 2));
    assert.equal(f.calls.length, 1); await noOwner(f);
  }
});

test('caller edits while inspection awaits cannot widen selected scope or mutation budget', async t => {
  const f = await fixture(t, [1, 1]), raw = { ...f.options, maxMutations: 1 };
  f.backend.inspect = async () => { raw.maxMutations = 100; raw.tokenFile = '/tmp/other'; raw.confirm = '0'.repeat(64); return f.verified; };
  const result = await createGithubIssueMigrationExecutor(f.backend)(raw);
  assert.equal(result.complete, true); assert.equal(result.mutation_calls, 1);
  assert.deepEqual(f.calls.map(o => o.operation), ['run', 'status']);
  assert.ok(f.calls.every(o => o.tokenFile === f.options.tokenFile));
});

for (const [name, change] of [
  ['wrong child pin', value => { value.plan_sha256 = '0'.repeat(64); }],
  ['wrong step total', value => { value.total_steps++; }],
  ['invented completion', value => { value.complete = true; value.committed_observed = 0; value.next_step = 0; }],
  ['over-budget submission count', value => { value.mutation_calls = 2201; }],
  ['skipped committed prefix', value => { value.next_step = 0; }],
  ['unknown stop', value => { value.stop_reason = 'assumed_committed'; }],
  ['wrong operation', value => { value.operation = 'retry'; }],
  ['second authority claim', value => { value.atomic_batch = true; }]
]) test(`malformed child result fails closed: ${name}`, async t => {
  const f = await fixture(t);
  f.backend.runBatch = async o => { f.calls.push(o); const value = outcome(f.rows[0], o); change(value); return value; };
  await assert.rejects(f.run()); assert.equal(f.calls.length, 1);
});

for (const [name, change] of [
  ['missing batch', value => { value.batches.pop(); }],
  ['reordered batch', value => { value.batches.reverse(); }],
  ['non-pinned plan', value => { value.plan_sha256 = '0'.repeat(64); }],
  ['unexpected network preflight', value => { value.network_accessed = true; }],
  ['over-limit population', value => { value.steps = 10001; }],
  ['incorrect byte total', value => { value.request_bytes++; }]
]) test(`complete preflight refuses before any child: ${name}`, async t => {
  const f = await fixture(t); change(f.verified);
  await assert.rejects(f.run()); assert.equal(f.calls.length, 0); await noOwner(f);
});

for (const changes of [{ operation: 'retry' }, { maxMutations: 0 }, { maxMutations: 10001 },
  { timeoutMs: 0 }, { timeoutMs: 3600001 }, { retryUnresolved: 1 }, { refreshKeys: true },
  { operation: 'status', retryUnresolved: true }, { operation: 'status', maxMutations: 1 },
  { workdir: './relative' }, { signal: {} }, { confirm: 'f'.repeat(63) }, { onProgress: 7 }]) {
  test(`closed execution grammar ${JSON.stringify(changes)}`, async t => {
    const f = await fixture(t); await assert.rejects(f.run(changes));
    assert.equal(f.calls.length, 0); await noOwner(f);
  });
}
