// Actual HTTP, filesystem and CLI boundaries; the remote node is a contract fixture.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, readdir, unlink, symlink, rename, link, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { fixture, TOKEN, ROTATED } from './fixtures/pull_sync_native.mjs';
import { discover, freezePlan, encode, hash } from '../../scripts/operator/pull_sync_plan.mjs';
import { savePlan } from '../../scripts/operator/pull_sync_custody.mjs';
import { send, recover, status } from '../../scripts/operator/pull_sync_publish.mjs';
import { main } from '../../scripts/fg_pull_sync.mjs';
const cli = new URL('../../scripts/fg_pull_sync.mjs', import.meta.url).pathname;
async function setup(t, format = 'sha1', count = 2) {
  const f = await fixture(t, format, count), root = await mkdtemp(join(tmpdir(), 'fg-pr-sync-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stateDir = join(root, 'state'); await mkdir(stateDir, { mode: 0o700 });
  await writeFile(join(root, 'token'), TOKEN, { mode: 0o600 });
  const plan = await savePlan(stateDir, freezePlan(await discover(f.dest, TOKEN, 'all-open'), TOKEN));
  return { ...f, root, stateDir, plan, controls: { endpoint: f.dest.endpoint, confirmation: plan.plan_sha256 } };
}
const reads = f => f.calls.filter(c => c.path.endsWith('/outcomes'));
const writes = f => f.calls.filter(c => c.path.endsWith('/update'));
const waitFor = async check => { for (let n = 0; n < 500; n++) { if (await check()) return; await new Promise(r => setTimeout(r, 5)); } throw new Error('fixture wait deadline'); };
function child(f, operation, extra = []) {
  const args = operation === 'status' ? ['status', '--state', f.stateDir] : [operation, '--state', f.stateDir,
    '--endpoint', f.dest.endpoint, '--token-file', join(f.root, 'token'), ...(operation === 'send' ? ['--confirm', f.plan.plan_sha256] : []), ...extra];
  const p = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] }); let out = '', err = '';
  p.stdout.on('data', b => out += b); p.stderr.on('data', b => err += b);
  const done = new Promise((resolve, reject) => { p.once('error', reject); p.once('close', (code, signal) => resolve({ code, signal, out, err })); });
  return { p, done, get out() { return out; } };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: confirmed batch refreshes only tips and records exact full-u64 decisions`, async t => {
    const f = await setup(t, format), before = structuredClone(f.state.rows), events = [];
    const result = await send(f.stateDir, TOKEN, { ...f.controls, onObservation: event => events.push(event) });
    assert.equal(result.updates, 2); assert.ok(result.jobs.every(r => r.state === 'committed'));
    assert.equal(events[0].decision_sequence, '18446744073709551615'); assert.equal(events[0].refs_changed, false);
    for (let index = 0; index < before.length; index++) {
      const old = before[index], now = f.state.rows[index], request = f.plan.requests[index];
      assert.equal(now.data.title, old.data.title); assert.equal(now.data.body, old.data.body); assert.equal(now.version, old.version + 1);
      assert.equal(now.data.source_tip, request.fields.source_tip); assert.equal(now.data.target_tip, request.fields.target_tip);
    }
    assert.equal((await send(f.stateDir, TOKEN, f.controls)).updates, 0); assert.equal(writes(f).length, 2);
    for (const c of writes(f)) assert.equal(c.headers['idempotency-key'], f.plan.requests.find(r => r.number === Number(c.path.split('/').at(-2))).key);
  });
  test(`${format}: partial batch with a lost reply recovers under rotated credentials without resending`, async t => {
    const f = await setup(t, format); f.state.drop = 2;
    await assert.rejects(send(f.stateDir, TOKEN, f.controls), e => e.publication_unknown);
    assert.deepEqual((await status(f.stateDir)).jobs.map(r => r.state), ['committed', 'unknown']);
    const count = f.calls.length;
    await assert.rejects(send(f.stateDir, TOKEN, f.controls), /unresolved/); assert.equal(f.calls.length, count);
    await assert.rejects(send(f.stateDir, ROTATED, { ...f.controls, retry: true }), /original_credential/);
    const result = await recover(f.stateDir, ROTATED, { endpoint: f.dest.endpoint });
    assert.ok(result.jobs.every(r => r.state === 'committed')); assert.equal(writes(f).length, 2);
    assert.equal(reads(f).length, 1); assert.equal(reads(f)[0].body, ''); assert.equal(reads(f)[0].headers.authorization, `Bearer ${ROTATED}`);
    assert.equal((await send(f.stateDir, TOKEN, f.controls)).updates, 0);
  });
  test(`${format}: uncertain request unobserved remotely resends only after explicit retry with identical key/body`, async t => {
    const f = await setup(t, format, 1); let first = true;
    f.state.hook = (call, req) => { if (call.path.endsWith('/update') && first) { first = false; req.socket.destroy(); return true; } };
    await assert.rejects(send(f.stateDir, TOKEN, f.controls)); assert.equal(f.decisions.size, 0);
    assert.equal((await recover(f.stateDir, TOKEN, { endpoint: f.dest.endpoint })).jobs[0].state, 'unknown');
    assert.equal(writes(f).length, 1);
    await send(f.stateDir, TOKEN, { ...f.controls, retry: true });
    assert.equal(writes(f).length, 2); assert.equal(writes(f)[0].body, writes(f)[1].body);
    assert.equal(writes(f)[0].headers['idempotency-key'], writes(f)[1].headers['idempotency-key']); assert.equal(f.decisions.size, 1);
  });
}
for (const movement of ['source', 'target', 'version', 'closed', 'deleted']) test(`post-plan ${movement} change is a native refusal, not refreshed expectations`, async t => {
  const f = await setup(t, 'sha1', 1), original = structuredClone(f.plan.requests[0]);
  if (movement === 'source') f.state.tips.set('refs/heads/topic-1', 'f'.repeat(40));
  if (movement === 'target') f.state.tips.set('refs/heads/main', 'f'.repeat(40));
  if (movement === 'version') { f.state.rows[0].version++; f.state.rows[0].data.title = 'concurrent edit'; }
  if (movement === 'closed') f.state.rows[0].state = 'closed';
  if (movement === 'deleted') f.state.tips.delete('refs/heads/topic-1');
  const result = await send(f.stateDir, TOKEN, f.controls); assert.equal(result.jobs[0].state, 'refused');
  assert.equal(writes(f)[0].form.get('expected_version'), String(original.fields.expected_version));
  assert.equal(writes(f)[0].form.get('source_tip'), original.fields.source_tip);
  assert.equal(writes(f)[0].headers['idempotency-key'], original.key);
});
for (const field of ['principal_id', 'repository_incarnation', 'number', 'expected_version', 'action', 'delivery_acknowledged']) test(`wrong publication ${field} leaves original responsibility unknown`, async t => {
  const f = await setup(t, 'sha1', 1);
  f.state.mutate = (r, c) => { if (c.path.endsWith('/update')) r[field] = ['number', 'expected_version'].includes(field) ? 999 : 'wrong'; };
  await assert.rejects(send(f.stateDir, TOKEN, f.controls)); assert.equal((await status(f.stateDir)).jobs[0].state, 'unknown');
  assert.equal(writes(f).length, 1);
});
test('publication requires independent endpoint equality, exact plan confirmation and original token', async t => {
  const f = await setup(t), count = f.calls.length;
  for (const options of [{ ...f.controls, confirmation: 'f'.repeat(64) }, { ...f.controls, endpoint: f.dest.endpoint + '-other' }, { endpoint: f.dest.endpoint }, { ...f.controls, retry: 'true' }]) await assert.rejects(send(f.stateDir, TOKEN, options));
  assert.equal(f.calls.length, count); assert.ok((await status(f.stateDir)).jobs.every(r => r.state === 'prepared'));
});
test('work bound and cancellation between jobs leave remaining exact requests unstarted', async t => {
  const f = await setup(t), stop = new AbortController();
  const first = await send(f.stateDir, TOKEN, { ...f.controls, onObservation: () => stop.abort(), signal: stop.signal });
  assert.equal(first.stopped, true); assert.deepEqual(first.jobs.map(r => r.state), ['committed', 'prepared']);
  assert.equal((await send(f.stateDir, TOKEN, { ...f.controls, maxRequests: 1 })).jobs[1].state, 'committed');
});
test('pre-aborted publication starts nothing and read-only recovery never starts prepared requests', async t => {
  const f = await setup(t), stop = new AbortController(); stop.abort();
  await send(f.stateDir, TOKEN, { ...f.controls, signal: stop.signal });
  assert.equal(writes(f).length, 0); const count = f.calls.length;
  await recover(f.stateDir, TOKEN, { endpoint: f.dest.endpoint }); assert.equal(f.calls.length, count);
});
test('concurrent senders cannot publish twice; recovery does not steal the sender lock', async t => {
  const f = await setup(t, 'sha1', 1); f.state.delay = 100;
  const sending = send(f.stateDir, TOKEN, f.controls); await waitFor(() => writes(f).length === 1);
  await assert.rejects(send(f.stateDir, TOKEN, f.controls), e => e.code === 'EEXIST');
  const recovering = recover(f.stateDir, ROTATED, { endpoint: f.dest.endpoint });
  await Promise.all([sending, recovering]); assert.equal(writes(f).length, 1);
  assert.equal((await status(f.stateDir)).jobs[0].state, 'committed');
});
test('offline status reports crash-held owners; recovery works with the sender lock retained', async t => {
  const f = await setup(t, 'sha1', 1); f.state.drop = true;
  await assert.rejects(send(f.stateDir, TOKEN, f.controls)); await mkdir(join(f.stateDir, 'owner.lock'), { mode: 0o700 });
  assert.equal((await status(f.stateDir)).owner_present, true);
  await recover(f.stateDir, ROTATED, { endpoint: f.dest.endpoint });
  assert.equal((await status(f.stateDir)).owner_present, true); assert.equal((await status(f.stateDir)).jobs[0].state, 'committed');
  await assert.rejects(send(f.stateDir, TOKEN, f.controls), e => e.code === 'EEXIST');
});
test('wrong recovery principal is never a recovered decision', async t => {
  const f = await setup(t, 'sha1', 1); f.state.drop = true; await assert.rejects(send(f.stateDir, TOKEN, f.controls));
  f.state.mutate = (r, c) => { if (c.path.endsWith('/outcomes')) r.principal_id = 'f'.repeat(32); };
  await assert.rejects(recover(f.stateDir, ROTATED, { endpoint: f.dest.endpoint }));
  assert.equal((await status(f.stateDir)).jobs[0].state, 'unknown');
});
test('retained first transaction refuses later identity regression, no replacement update', async t => {
  const f = await setup(t, 'sha1', 1); f.state.drop = true; await assert.rejects(send(f.stateDir, TOKEN, f.controls));
  f.state.mutate = (r, c) => { if (c.path.endsWith('/outcomes')) { r.state = 'undecided'; r.terminal = false; r.decision = null; } };
  await recover(f.stateDir, ROTATED, { endpoint: f.dest.endpoint });
  f.state.mutate = (r, c) => { if (c.path.endsWith('/outcomes')) r.transaction.seal_id = 'changed-seal'; };
  await assert.rejects(recover(f.stateDir, ROTATED, { endpoint: f.dest.endpoint }), /regressed|conflict/); assert.equal(writes(f).length, 1);
});
test('saved terminal cannot lose its start marker or substitute another request', async t => {
  const f = await setup(t, 'sha1', 1); await send(f.stateDir, TOKEN, f.controls);
  const path = join(f.stateDir, 'terminal-000.json'), bytes = await readFile(path), value = JSON.parse(bytes); value.result.tx_id = 'forged';
  await writeFile(path, encode(value), { mode: 0o600 }); await assert.rejects(status(f.stateDir));
  await writeFile(path, bytes, { mode: 0o600 }); await unlink(join(f.stateDir, 'started-000.json')); await assert.rejects(status(f.stateDir), /lost_start/);
});
test('no new destination, principal or source is discovered during recovery', async t => {
  const f = await setup(t, 'sha1', 1); f.state.drop = true; await assert.rejects(send(f.stateDir, TOKEN, f.controls));
  f.state.rows = []; f.state.tips.clear(); const count = f.calls.length;
  const result = await recover(f.stateDir, ROTATED, { endpoint: f.dest.endpoint }); assert.equal(result.jobs[0].state, 'committed');
  assert.ok(f.calls.slice(count).every(c => c.path.endsWith('/outcomes') && c.body === ''));
});
test('network cancellation leaves unknown request, then original-key recovery settles it', async t => {
  const f = await setup(t, 'sha1', 1), stop = new AbortController(); f.state.delay = 100;
  const task = send(f.stateDir, TOKEN, { ...f.controls, signal: stop.signal });
  await waitFor(() => f.decisions.size === 1); stop.abort(); await assert.rejects(task, e => e.publication_unknown);
  f.state.delay = 0; await recover(f.stateDir, TOKEN, { endpoint: f.dest.endpoint }); assert.equal((await status(f.stateDir)).jobs[0].state, 'committed');
});
test('filesystem failure after a remote decision reports known terminal and preserves outcome recovery', async t => {
  const f = await setup(t, 'sha1', 1);
  f.state.mutate = async (_r, c) => { if (c.path.endsWith('/update')) await mkdir(join(f.stateDir, 'terminal-000.json'), { mode: 0o700 }); };
  await assert.rejects(send(f.stateDir, TOKEN, f.controls));
  // Explicit fixture repair only; production never deletes or repairs custody.
  await rm(join(f.stateDir, 'terminal-000.json'), { recursive: true }); f.state.mutate = null;
  await recover(f.stateDir, TOKEN, { endpoint: f.dest.endpoint }); assert.equal((await status(f.stateDir)).jobs[0].state, 'committed');
});
test('CLI send then status output reflects actual partial and refused decisions', async t => {
  const f = await setup(t); let result = await child(f, 'send', ['--max-requests', '1']).done;
  assert.equal(result.code, 3, result.err); assert.equal(JSON.parse(result.out.trim().split('\n').at(-1)).jobs[1].state, 'prepared');
  f.state.refuse = true; result = await child(f, 'send').done; assert.equal(result.code, 1, result.err);
  const count = f.calls.length; result = await child(f, 'status').done; assert.equal(result.code, 1); assert.equal(f.calls.length, count);
});
test('CLI lost response reports unknown, rotated-token recover sends no update', async t => {
  const f = await setup(t, 'sha1', 1); f.state.drop = true;
  let result = await child(f, 'send').done; assert.equal(result.code, 3, result.err);
  await writeFile(join(f.root, 'token'), ROTATED, { mode: 0o600 });
  result = await child(f, 'recover').done; assert.equal(result.code, 0, result.err); assert.equal(writes(f).length, 1);
});
test('real CLI SIGKILL retains owner and start, then a fresh recovery process settles the decision', async t => {
  const f = await setup(t, 'sha1', 1); f.state.delay = 1000;
  const task = child(f, 'send'); t.after(() => { if (task.p.exitCode === null && task.p.signalCode === null) task.p.kill('SIGKILL'); });
  await waitFor(() => f.decisions.size === 1); task.p.kill('SIGKILL'); await task.done;
  assert.equal((await status(f.stateDir)).owner_present, true); f.state.delay = 0;
  const result = await child(f, 'recover').done; assert.equal(result.code, 0, result.err); assert.equal((await status(f.stateDir)).owner_present, true);
});
test('real CLI SIGTERM stops new publication while keeping unknown original outcome recoverable', async t => {
  const f = await setup(t); f.state.delay = 1000;
  const task = child(f, 'send'); await waitFor(() => f.decisions.size === 1); task.p.kill('SIGTERM');
  const result = await task.done; assert.equal(result.code, 3, result.err); assert.equal(writes(f).length, 1);
  f.state.delay = 0; await recover(f.stateDir, TOKEN, { endpoint: f.dest.endpoint });
  assert.deepEqual((await status(f.stateDir)).jobs.map(r => r.state), ['committed', 'prepared']);
});
test('broken CLI output after commit preserves terminal without claiming rollback or resending', async t => {
  const f = await setup(t, 'sha1', 1); let errors = '';
  const stdout = new Writable({ write(_b, _enc, done) { done(new Error('output broken')); } });
  const stderr = new Writable({ write(b, _enc, done) { errors += b; done(); } });
  const code = await main(['send', '--state', f.stateDir, '--endpoint', f.dest.endpoint, '--token-file', join(f.root, 'token'), '--confirm', f.plan.plan_sha256], { stdout, stderr });
  assert.equal(code, 4); assert.equal(JSON.parse(errors).retained_terminal.outcome, 'committed');
  assert.equal((await send(f.stateDir, TOKEN, f.controls)).updates, 0);
});
test('recovery rejects publication controls before any network and status recognizes orphaned records', async t => {
  const f = await setup(t); const count = f.calls.length;
  await assert.rejects(recover(f.stateDir, TOKEN, { ...f.controls }), /cannot_publish/);
  await assert.rejects(recover(f.stateDir, TOKEN, { endpoint: f.dest.endpoint, retry: true }), /cannot_publish/);
  assert.equal(f.calls.length, count);
  await writeFile(join(f.stateDir, 'terminal-999.json'), '{}', { mode: 0o600 }); await assert.rejects(status(f.stateDir), /orphaned/);
});

test('a terminal retained in the original observation remains known when its duplicate terminal file is lost', async t => {
  const f = await setup(t, 'sha1', 1); f.state.drop = true; await assert.rejects(send(f.stateDir, TOKEN, f.controls));
  await recover(f.stateDir, ROTATED, { endpoint: f.dest.endpoint });
  await unlink(join(f.stateDir, 'terminal-000.json')); // Simulate failure of the later duplicate record.
  const count = f.calls.length;
  assert.equal((await status(f.stateDir)).jobs[0].state, 'committed');
  assert.equal((await send(f.stateDir, TOKEN, f.controls)).updates, 0); assert.equal(f.calls.length, count);
});
test('a late missing-outcome reply cannot erase a concurrently retained terminal or cause an exact resend', async t => {
  const f = await setup(t, 'sha1', 1); f.state.drop = true; await assert.rejects(send(f.stateDir, TOKEN, f.controls));
  // Save a real fixture recovery observation, remove its duplicate, and arrange
  // to expose it concurrently only after the retry's outcome request starts.
  await recover(f.stateDir, TOKEN, { endpoint: f.dest.endpoint });
  const seenPath = join(f.stateDir, 'observed-000.json'), seen = await readFile(seenPath);
  await unlink(seenPath); await unlink(join(f.stateDir, 'terminal-000.json'));
  f.state.mutate = async (r, c) => {
    if (c.path.endsWith('/outcomes')) {
      await writeFile(seenPath, seen, { mode: 0o600 });
      r.state = 'key_not_observed'; r.terminal = false; r.transaction = null; r.decision = null;
    }
  };
  await assert.rejects(send(f.stateDir, TOKEN, { ...f.controls, retry: true }), /regressed|conflict/);
  assert.equal(writes(f).length, 1); assert.equal((await status(f.stateDir)).jobs[0].state, 'committed');
});
test('write failure after a validated receipt is reported as known rather than pre-admission failure', async t => {
  const f = await setup(t, 'sha1', 1);
  f.state.mutate = async (_r, c) => { if (c.path.endsWith('/update')) await mkdir(join(f.stateDir, 'terminal-000.json'), { mode: 0o700 }); };
  await assert.rejects(send(f.stateDir, TOKEN, f.controls), error => error.retained_terminal?.outcome === 'committed');
});

test('CLI cleanup failure after a terminal is exit four and retains its completed operation', async t => {
  const f = await setup(t, 'sha1', 1); let errors = '', first = true;
  const stdout = new Writable({ write(_b, _enc, done) {
    if (!first) { done(); return; } first = false;
    rename(join(f.stateDir, 'owner.lock'), join(f.root, 'original-owner.lock'))
      .then(() => mkdir(join(f.stateDir, 'owner.lock'), { mode: 0o700 })).then(() => done(), done);
  } });
  const stderr = new Writable({ write(b, _enc, done) { errors += b; done(); } });
  const code = await main(['send', '--state', f.stateDir, '--endpoint', f.dest.endpoint, '--token-file', join(f.root, 'token'), '--confirm', f.plan.plan_sha256], { stdout, stderr });
  assert.equal(code, 4); assert.equal(JSON.parse(errors).retained_operation.jobs[0].state, 'committed');
  assert.equal((await status(f.stateDir)).owner_present, true); assert.equal(writes(f).length, 1);
});


// Reproduce the create-only writer's real link -> unlink publication window.
// Even a fully synced body must not be accepted while its private alias exists.
test('status waits for a concurrent receipt link to settle without weakening private-file checks', async t => {
  const f = await setup(t, 'sha1', 1); await send(f.stateDir, TOKEN, f.controls);
  const path = join(f.stateDir, 'terminal-000.json'), temporary = `${path}.writing-${'a'.repeat(32)}`;
  await rename(path, temporary); await link(temporary, path);
  assert.equal((await lstat(path)).nlink, 2);
  const count = f.calls.length;
  const reading = status(f.stateDir);
  const finishWriter = new Promise(resolve => setTimeout(resolve, 30)).then(() => unlink(temporary));
  const [result] = await Promise.all([reading, finishWriter]);
  assert.equal(result.jobs[0].state, 'committed'); assert.equal(f.calls.length, count);
  assert.equal((await lstat(path)).nlink, 1);
});

test('interrupted receipt aliases and persistent hardlinks are never accepted or cleaned automatically', async t => {
  const f = await setup(t, 'sha1', 1); await send(f.stateDir, TOKEN, f.controls);
  const path = join(f.stateDir, 'terminal-000.json'), temporary = `${path}.writing-${'b'.repeat(32)}`;
  await link(path, temporary);
  const count = f.calls.length;
  await assert.rejects(status(f.stateDir), /custody|receipt/);
  assert.equal((await lstat(path)).nlink, 2); assert.equal(f.calls.length, count);
  await unlink(temporary);
  await link(path, join(f.root, 'foreign-alias'));
  await assert.rejects(recover(f.stateDir, ROTATED, { endpoint: f.dest.endpoint }), /custody|receipt/);
  assert.equal((await lstat(path)).nlink, 2); assert.equal(f.calls.length, count);
});
