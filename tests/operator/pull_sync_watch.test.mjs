// Actual sockets, files and child processes; the remote authority is a contract fixture.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, readFile, writeFile, readdir, unlink, rename, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { fixture, TOKEN, ROTATED, row } from './fixtures/pull_sync_native.mjs';
import { configuration, once, serve, status } from '../../scripts/operator/pull_sync_watch.mjs';
import { recover, status as planStatus } from '../../scripts/operator/pull_sync_publish.mjs';
import { loadPlan } from '../../scripts/operator/pull_sync_custody.mjs';
import { encode, discover, freezePlan } from '../../scripts/operator/pull_sync_plan.mjs';
import { main } from '../../scripts/fg_pull_sync_watch.mjs';
const cli = new URL('../../scripts/fg_pull_sync_watch.mjs', import.meta.url).pathname;
const writes = f => f.calls.filter(call => call.path.endsWith('/update'));
const waitFor = async check => { for (let i = 0; i < 500; i++) { if (await check()) return; await new Promise(resolve => setTimeout(resolve, 5)); } throw new Error('fixture wait expired'); };
async function setup(t, format = 'sha1', count = 2, patch = {}) {
  const f = await fixture(t, format, count), root = await mkdtemp(join(tmpdir(), 'fg-sync-watch-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const state_directory = join(root, 'state'); await mkdir(state_directory, { mode: 0o700 });
  const config = configuration({ schema: 'frankengit-pr-sync-watch-v1', destination: f.dest, selected: 'all-open', state_directory,
    max_batches: 16, state_bytes: 64 * 1024 * 1024, policy: 'recorded-tips-only', ...patch });
  const file = join(root, 'config.json'); await writeFile(file, encode(config), { mode: 0o600 });
  const token = join(root, 'token'); await writeFile(token, TOKEN, { mode: 0o600 });
  return { ...f, root, config, file, token, batch: index => join(state_directory, `batch-${String(index).padStart(6, '0')}`) };
}
function child(f, operation, extras = []) {
  const p = spawn(process.execPath, [cli, operation, '--config', f.file,
    ...(operation === 'status' ? [] : ['--token-file', f.token, '--allow-tip-updates']), ...extras], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = ''; p.stdout.on('data', bytes => out += bytes); p.stderr.on('data', bytes => err += bytes);
  const done = new Promise((resolve, reject) => { p.once('error', reject); p.once('close', (code, signal) => resolve({ code, signal, out, err })); });
  return { p, done, get out() { return out; } };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: later pushes automatically refresh PRs without metadata loss or no-op versions`, async t => {
    const f = await setup(t, format), before = structuredClone(f.state.rows); let polls = 0;
    const result = await serve(f.config, TOKEN, { pollMs: 100, maxPolls: 3, onObservation: event => {
      if (event.type === 'pull_sync_watch_sweep' && ++polls === 1) {
        f.state.tips.set('refs/heads/topic-1', 'f'.repeat(format === 'sha1' ? 40 : 64));
        f.state.head = `alg:2:${'a'.repeat(64)}`; f.state.source_head = 'head-after-push';
        f.state.rows[0].version++; f.state.rows[0].data.title = 'new human title';
      }
    } });
    assert.equal(result.updates, 3); assert.equal(result.polls, 3);
    assert.equal(f.state.rows[0].version, 6); assert.equal(f.state.rows[0].data.title, 'new human title');
    assert.equal(f.state.rows[0].data.body, before[0].data.body); assert.equal(f.state.rows[1].version, 4);
    assert.equal((await once(f.config, TOKEN)).updates, 0); assert.equal(writes(f).length, 3);
    assert.equal(new Set(writes(f).map(call => call.headers['idempotency-key'])).size, 3);
    assert.ok(writes(f).every(call => call.form.get('title') && call.form.get('body') === before[0].data.body));
    assert.equal((await status(f.config)).batches.length, 2);
  });
  test(`${format}: uncertain publication blocks discovery/new keys until explicit original-key recovery`, async t => {
    const f = await setup(t, format); f.state.drop = 1;
    await assert.rejects(once(f.config, TOKEN), error => error.publication_unknown);
    const original = await readFile(join(f.batch(1), 'plan.json')), count = f.calls.length;
    await assert.rejects(serve(f.config, TOKEN, { maxPolls: 2, pollMs: 100 }), /unresolved_publication/);
    assert.equal(f.calls.length, count); assert.equal(writes(f).length, 1);
    await recover(f.batch(1), ROTATED, { endpoint: f.dest.endpoint }); f.state.drop = false;
    await once(f.config, TOKEN); assert.equal(writes(f).length, 2);
    assert.deepEqual(await readFile(join(f.batch(1), 'plan.json')), original);
    assert.equal(f.calls.filter(call => call.path.endsWith('/outcomes')).length, 1);
    assert.equal((await status(f.config)).batches[0].committed, 2);
  });
}
test('per-sweep update limit finishes the original batch before reading newly moved refs', async t => {
  const f = await setup(t); const first = await once(f.config, TOKEN, { maxUpdates: 1 });
  assert.equal(first.limit_reached, true); assert.equal(first.batches[0].prepared, 1);
  const count = f.calls.length; f.state.tips.set('refs/heads/topic-1', 'f'.repeat(40));
  await once(f.config, TOKEN); assert.equal(f.calls.length, count + 1); assert.equal(writes(f).at(-1).path.endsWith('/2/update'), true);
  await once(f.config, TOKEN); assert.equal(writes(f).length, 3); assert.equal((await status(f.config)).batches.length, 2);
});
test('canonical refusals are not blindly resubmitted and do not starve other changed PRs', async t => {
  const f = await setup(t, 'sha1', 1); f.state.refuse = true;
  assert.equal((await once(f.config, TOKEN)).refused, 1);
  f.state.head = `alg:2:${'a'.repeat(64)}`; f.state.source_head = 'unrelated-forge-write';
  let next = await once(f.config, TOKEN); assert.equal(next.updates, 0);
  assert.deepEqual(next.suppressed_historical_requests, [{ number: 1, outcome: 'refused' }]);
  assert.deepEqual(next.unchanged, []); assert.equal(writes(f).length, 1);
  f.state.rows.push(row(2)); f.state.tips.set('refs/heads/topic-2', 'f'.repeat(40)); f.state.refuse = false;
  next = await once(f.config, TOKEN); assert.equal(next.updates, 1); assert.equal(writes(f).at(-1).path.endsWith('/2/update'), true);
  assert.deepEqual((await loadPlan(f.batch(2))).discovery.selected, [2]);
  f.state.rows[0].version++; f.state.rows[0].data.title = 'human changed rejected subject';
  assert.equal((await once(f.config, TOKEN)).updates, 1); assert.equal(writes(f).length, 3);
});
test('all-open discovers new PRs but explicit selection never widens', async t => {
  const f = await setup(t, 'sha1', 2, { selected: [1] }); await once(f.config, TOKEN);
  assert.equal(writes(f).length, 1); assert.equal(f.state.rows[1].version, 3);
  f.state.rows.push(row(3)); f.state.tips.set('refs/heads/topic-3', 'f'.repeat(40));
  assert.equal((await once(f.config, TOKEN)).updates, 0);
  await assert.rejects(once({ ...f.config, selected: 'all-open' }, TOKEN), /configuration_changed/);
});
test('no open or changed PRs consumes no batch slots or unnecessary writes', async t => {
  const f = await setup(t, 'sha1', 0);
  const result = await serve(f.config, TOKEN, { maxPolls: 2, pollMs: 100 });
  assert.equal(result.updates, 0); assert.equal(writes(f).length, 0);
  assert.deepEqual(await readdir(f.config.state_directory), ['binding.json']);
});
test('only transient read failures back off; snapshot conflict can be retried without a mutation', async t => {
  const f = await setup(t, 'sha1', 1); let failures = 0;
  f.state.hook = (_call, _req, res) => { if (failures++ === 0) { res.writeHead(409); res.end(); return true; } };
  const result = await serve(f.config, TOKEN, { maxPolls: 2, pollMs: 100 });
  assert.equal(result.read_failures, 1); assert.equal(result.updates, 1); assert.equal(writes(f).length, 1);
});
for (const code of [401, 403]) test(`read HTTP ${code} never becomes an automatic retry or empty success`, async t => {
  const f = await setup(t); f.state.hook = (_call, _req, res) => { res.writeHead(code); res.end(); return true; };
  await assert.rejects(serve(f.config, TOKEN, { maxPolls: 5, pollMs: 100 }), error => error.status === code);
  assert.equal(f.calls.length, 1); assert.equal(writes(f).length, 0);
});
test('persistent transient read failures stop after three attempts', async t => {
  const f = await setup(t); f.state.hook = (_call, _req, res) => { res.writeHead(503); res.end(); return true; };
  await assert.rejects(serve(f.config, TOKEN, { maxPolls: 10, pollMs: 100 }), error => error.status === 503);
  assert.equal(f.calls.length, 3); assert.equal(writes(f).length, 0);
});
test('unrelated malformed source responses and missing branches stop rather than widening selection', async t => {
  const f = await setup(t); f.state.tips.delete('refs/heads/topic-1');
  await assert.rejects(serve(f.config, TOKEN, { maxPolls: 3, pollMs: 100 }), /branch_unavailable/);
  assert.equal(f.calls.length, 2); assert.equal(writes(f).length, 0);
});
test('concurrent supervisors never publish a second batch', async t => {
  const f = await setup(t, 'sha1', 1); f.state.delay = 40;
  const active = once(f.config, TOKEN); await waitFor(() => writes(f).length === 1);
  await assert.rejects(once(f.config, TOKEN), error => error.code === 'EEXIST'); await active;
  assert.equal(writes(f).length, 1);
});
test('stop drains an active socket to its known decision, but does not start another PR', async t => {
  const f = await setup(t); f.state.delay = 50; const stop = new AbortController();
  const active = serve(f.config, TOKEN, { maxPolls: 3, pollMs: 100, signal: stop.signal });
  await waitFor(() => writes(f).length === 1); stop.abort();
  const result = await active; assert.equal(result.stopped, true); assert.equal(result.updates, 1);
  assert.equal(writes(f).length, 1); const saved = await status(f.config);
  assert.equal(saved.batches[0].committed, 1); assert.equal(saved.batches[0].prepared, 1); assert.equal(saved.owner_present, false);
});
test('a retained sender owner blocks new batches even after all remote decisions are recovered', async t => {
  const f = await setup(t, 'sha1', 1); f.state.drop = true; await assert.rejects(once(f.config, TOKEN));
  await mkdir(join(f.batch(1), 'owner.lock'), { mode: 0o700 });
  await recover(f.batch(1), ROTATED, { endpoint: f.dest.endpoint }); const count = f.calls.length;
  await assert.rejects(once(f.config, TOKEN), /sender_owner/); assert.equal(f.calls.length, count);
  assert.equal((await status(f.config)).batches[0].owner_present, true);
});
test('batch count and receipt reservation reject new work before admission', async t => {
  const f = await setup(t, 'sha1', 1, { max_batches: 1 }); await once(f.config, TOKEN);
  f.state.tips.set('refs/heads/topic-1', 'f'.repeat(40)); await assert.rejects(once(f.config, TOKEN), /batch_capacity/);
  assert.equal(writes(f).length, 1); assert.equal((await status(f.config)).batches[0].committed, 1);
  const small = await setup(t, 'sha1', 2, { state_bytes: 65536 });
  await assert.rejects(once(small.config, TOKEN), /receipt_capacity/); assert.equal(writes(small).length, 0);
  assert.deepEqual(await readdir(small.config.state_directory), ['binding.json']);
});
for (const problem of ['empty-batch', 'gap', 'unknown', 'bad-plan', 'alias', 'public']) test(`damaged/private custody stops before network: ${problem}`, async t => {
  const f = await setup(t, 'sha1', 1); await once(f.config, TOKEN); const count = f.calls.length;
  if (problem === 'empty-batch') await mkdir(f.batch(2), { mode: 0o700 });
  if (problem === 'gap') await rename(f.batch(1), f.batch(2));
  if (problem === 'unknown') await writeFile(join(f.config.state_directory, 'unexpected'), 'x', { mode: 0o600 });
  if (problem === 'bad-plan') await writeFile(join(f.batch(1), 'plan.json'), '{}');
  if (problem === 'alias') { await rename(f.batch(1), join(f.root, 'other')); await symlink(join(f.root, 'other'), f.batch(1)); }
  if (problem === 'public') await chmod(f.config.state_directory, 0o755);
  await assert.rejects(once(f.config, TOKEN)); assert.equal(f.calls.length, count);
});
test('output failure is not retried or reclassified as a transient read', async t => {
  const f = await setup(t, 'sha1', 1);
  const error = Object.assign(new Error('output broken'), { watch_phase: 'discovery', code: 'sync_transport_unavailable' });
  await assert.rejects(serve(f.config, TOKEN, { maxPolls: 3, pollMs: 100, onObservation: () => { throw error; } }), e => e.local_output_failed === true && e.retained_terminal?.outcome === 'committed');
  assert.equal(writes(f).length, 1); assert.equal((await status(f.config)).batches[0].committed, 1);
});
test('actual CLI requires opt-in and rejects replay/mutation options outside its closed policy', async t => {
  const f = await setup(t);
  for (const args of [['once', '--config', f.file, '--token-file', f.token],
    ['serve', '--config', f.file, '--token-file', f.token, '--allow-tip-updates', '--retry'],
    ['status', '--config', f.file, '--allow-tip-updates'], ['once', '--config', f.file, '--config', f.file]]) {
    const output = new Writable({ write(_b, _e, done) { done(); } });
    assert.equal(await main(args, { stdout: output, stderr: output }), 2);
  }
  assert.equal(f.calls.length, 0);
  const result = await child(f, 'once').done; assert.equal(result.code, 0, result.err); assert.equal(writes(f).length, 2);
});
test('CLI SIGTERM drains, while SIGKILL keeps ownership and offline status needs no token', async t => {
  const f = await setup(t, 'sha1', 1); f.state.delay = 50;
  const active = child(f, 'serve', ['--poll-millis', '60000']);
  t.after(() => { if (active.p.exitCode === null && active.p.signalCode === null) active.p.kill('SIGKILL'); });
  await waitFor(() => writes(f).length === 1); active.p.kill('SIGTERM');
  const result = await active.done; assert.equal(result.code, 0, result.err); assert.match(result.out, /"stopped":true/);
  const second = child(f, 'serve', ['--poll-millis', '60000']);
  t.after(() => { if (second.p.exitCode === null && second.p.signalCode === null) second.p.kill('SIGKILL'); });
  await waitFor(() => second.out.includes('pull_sync_watch_sweep')); second.p.kill('SIGKILL'); await second.done;
  await unlink(f.token); const count = f.calls.length;
  const inspected = await child(f, 'status').done; assert.equal(inspected.code, 0, inspected.err);
  assert.equal(JSON.parse(inspected.out).owner_present, true); assert.equal(f.calls.length, count);
  await assert.rejects(once(f.config, TOKEN), error => error.code === 'EEXIST');
});
test('CLI reports unknown publication distinctly and does not put tokens or source text in status', async t => {
  const f = await setup(t, 'sha1', 1); f.state.drop = true;
  const result = await child(f, 'once').done; assert.equal(result.code, 3, result.err);
  assert.equal((await planStatus(f.batch(1))).jobs[0].state, 'unknown');
  const inspected = await child(f, 'status').done; assert.equal(inspected.code, 3);
  assert.ok(!inspected.out.includes(TOKEN)); assert.ok(!inspected.out.includes('Résumé'));
});
test('invalid service limits/configuration cannot open a socket or acquire a namespace', async t => {
  const f = await setup(t);
  for (const patch of [{ policy: 'merge' }, { selected: [] }, { max_batches: 129 }, { state_bytes: 0 }, { implicit: true }]) assert.throws(() => configuration({ ...f.config, ...patch }));
  for (const options of [{ retry: true }, { maxUpdates: 0 }, { timeoutMs: 0 }, { ca: 'ambient' }, { signal: {} }]) await assert.rejects(once(f.config, TOKEN, options));
  assert.equal(f.calls.length, 0); assert.deepEqual(await readdir(f.config.state_directory), []);
});
test('a stopped service still reports pending custody before its first sweep', async t => {
  const f = await setup(t); await once(f.config, TOKEN, { maxUpdates: 1 });
  const stop = new AbortController(); stop.abort(); const count = f.calls.length;
  const result = await serve(f.config, TOKEN, { signal: stop.signal });
  assert.equal(result.polls, 0); assert.equal(result.stopped, true); assert.equal(result.last.batches[0].prepared, 1);
  assert.equal(f.calls.length, count); assert.equal((await status(f.config)).owner_present, false);
});
test('credential rotation cannot replace a prepared original request with a fresh key', async t => {
  const f = await setup(t); await once(f.config, TOKEN, { maxUpdates: 1 });
  const original = await readFile(join(f.batch(1), 'plan.json')), count = f.calls.length;
  await assert.rejects(once(f.config, ROTATED), /original_credential/);
  assert.equal(f.calls.length, count); assert.deepEqual(await readFile(join(f.batch(1), 'plan.json')), original);
  assert.equal((await status(f.config)).batches[0].prepared, 1);
  await once(f.config, TOKEN); assert.equal(writes(f).length, 2);
});
test('exact serialized custody capacity succeeds; one byte less refuses before a batch is made', async t => {
  const f = await setup(t);
  const discovery = await discover(f.dest, TOKEN, 'all-open');
  const plan = freezePlan({ ...discovery, selected: [1, 2], unchanged: [] }, TOKEN, '7'.repeat(32));
  const estimate = { ...f.config, state_bytes: 100000 };
  const needed = encode(estimate).length + encode(plan).length + 2 * 3 * 16384;
  assert.equal(String(needed).length, 6);
  const shortPath = join(f.root, 'short'), exactPath = join(f.root, 'exact');
  await mkdir(shortPath, { mode: 0o700 }); await mkdir(exactPath, { mode: 0o700 });
  const short = { ...f.config, state_directory: shortPath, state_bytes: needed - 1 };
  const exact = { ...f.config, state_directory: exactPath, state_bytes: needed };
  await assert.rejects(once(short, TOKEN), /receipt_capacity/); assert.equal(writes(f).length, 0);
  assert.deepEqual(await readdir(shortPath), ['binding.json']);
  const result = await once(exact, TOKEN); assert.equal(result.updates, 2); assert.equal(result.reserved_bytes, needed);
  assert.equal((await status(exact)).reserved_bytes, needed);
});
