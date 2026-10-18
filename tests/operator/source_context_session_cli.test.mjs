// Real CLI processes/private files/sockets over explicit native-schema peers.
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile, readdir, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { fixture, input, TOKEN } from './source_context_continue_fixtures.mjs';
import { reserveSessionStep, acquireSessionStep, inspectSession } from '../../scripts/operator/source_context_session.mjs';
import { inspectBundle } from '../../scripts/operator/source_context_export.mjs';
import { main } from '../../scripts/fg_context_session.mjs';
const CLI = new URL('../../scripts/fg_context_session.mjs', import.meta.url).pathname;
const BUDGET = { queries: 2, work: 33554432, payload_bytes: 67108864, source_bytes: 134217728, excerpt_bytes: 2097152 };
function child(args) {
  const p = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  p.stdout.on('data', b => { stdout += b; }); p.stderr.on('data', b => { stderr += b; });
  const done = new Promise((resolve, reject) => { p.once('error', reject); p.once('close', (code, signal) => resolve({ code, signal, stdout, stderr })); });
  return { p, done };
}
async function setup(t, q = input(), settings = {}) {
  const f = await fixture(t, q, settings), session = join(f.root, 'session');
  const limits = join(f.root, 'limits.json'), followup = join(f.root, 'followup.json'), token = join(f.root, 'token');
  await writeFile(limits, JSON.stringify(BUDGET), { mode: 0o600 });
  await writeFile(followup, '{"terms":["recover"]}', { mode: 0o600 });
  await writeFile(token, `${TOKEN}\n`, { mode: 0o600 });
  const init = ['init', '--session', session, '--from-bundle', f.bundle, '--from-sha256', f.receipt.manifest_sha256, '--limits-file', limits];
  const created = await child(init).done; assert.equal(created.code, 0, created.stderr);
  const root = JSON.parse(created.stdout), shared = ['--session', session, '--session-sha256', root.session_sha256];
  return { ...f, session, limits, followup, token, init, created: root, shared,
    step: ['step', ...shared, '--tip-sha256', root.tip_sha256, '--followup-file', followup, '--token-file', token] };
}
const statusArgs = (f, tip = f.created.tip_sha256) => ['status', ...f.shared, '--tip-sha256', tip];

for (const format of ['sha1', 'sha256']) test(`${format}: init, budgeted follow-ups and offline status run through the actual executable`, async t => {
  const f = await setup(t, input(format)), base = f.originalBytes;
  assert.equal(f.p.calls.length, 0);
  const first = await child(f.step).done; assert.equal(first.code, 0, first.stderr);
  const a = JSON.parse(first.stdout); assert.equal(a.reserved.queries, 1);
  await writeFile(f.followup, '{"terms":["untrusted"]}');
  const next = f.step.slice(); next[next.indexOf('--tip-sha256') + 1] = a.tip_sha256;
  const second = await child(next).done; assert.equal(second.code, 0, second.stderr);
  const b = JSON.parse(second.stdout); assert.equal(b.reserved.queries, 2);
  assert.equal(b.remaining.queries, 0); assert.equal(b.history.length, 2); assert.equal(f.p.calls.length, 2);
  await rm(f.token); await rm(f.followup);
  const observed = await child(statusArgs(f, b.tip_sha256)).done;
  assert.equal(observed.code, 0, observed.stderr); assert.equal(JSON.parse(observed.stdout).tip_sha256, b.tip_sha256);
  assert.equal(f.p.calls.length, 2); assert.deepEqual(await f.readParent(), base);
  assert.equal((await inspectBundle(b.latest_bundle, b.latest_manifest_sha256)).complete, true);
  for (const path of [join(f.session, 'session.json'), join(f.session, 'steps/0001/request.json'), join(f.session, 'steps/0001/terminal.json')]) {
    assert.ok(!(await readFile(path, 'utf8')).includes(TOKEN));
  }
});

test('a stale tip cannot create another request or consume more network budget', async t => {
  const f = await setup(t); const first = await child(f.step).done; assert.equal(first.code, 0, first.stderr);
  const stale = await child(f.step).done;
  assert.equal(stale.code, 2); assert.equal(JSON.parse(stale.stderr).code, 'context_session_tip_moved');
  assert.equal(f.p.calls.length, 1); assert.deepEqual(await readdir(join(f.session, 'steps')), ['0001']);
});

test('settled HTTP refusal prints its retained tip and charges the full call', async t => {
  const f = await setup(t); f.state.status = 409;
  const refused = await child(f.step).done; assert.equal(refused.code, 2);
  const result = JSON.parse(refused.stdout); assert.equal(result.type, 'source_context_session_refused'); assert.equal(result.reservation_retained, true);
  const status = await child(statusArgs(f, result.tip_sha256)).done;
  assert.equal(status.code, 0, status.stderr); assert.equal(JSON.parse(status.stdout).reserved.queries, 1);
  assert.equal(f.p.calls.length, 1);
});

test('CLI cannot reset a spent budget, change endpoint or weaken source pins', async t => {
  const f = await setup(t);
  for (const extra of [['--force', 'true'], ['--retry', '1'], ['--endpoint', 'https://other/repo'],
    ['--token', TOKEN], ['--tip-sha256', f.created.tip_sha256], ['--timeout-ms', '0']]) {
    const result = await child([...f.step, ...extra]).done; assert.equal(result.code, 2, result.stderr);
  }
  assert.equal(f.p.calls.length, 0); assert.deepEqual(await readdir(join(f.session, 'steps')), []);
  const existing = await child(f.init).done; assert.equal(existing.code, 2);
  assert.equal((await child(statusArgs(f)).done).code, 0);
});

test('public credentials and malformed input refuse before reservation', async t => {
  const f = await setup(t); await chmod(f.token, 0o644);
  assert.equal((await child(f.step).done).code, 2); await chmod(f.token, 0o600);
  await writeFile(f.followup, '{'); assert.equal((await child(f.step).done).code, 2);
  assert.equal(f.p.calls.length, 0); assert.deepEqual(await readdir(join(f.session, 'steps')), []);
});

test('dispatch resumes only a never-started original reservation and recovery never requeries', async t => {
  const f = await setup(t), r = await reserveSessionStep(f.session, f.created.session_sha256, f.created.tip_sha256, { terms: ['untrusted'] });
  const args = ['dispatch', ...f.shared, '--tip-sha256', f.created.tip_sha256, '--request-sha256', r.request_sha256, '--token-file', f.token];
  const staged = await child(args).done; assert.equal(staged.code, 3, staged.stderr);
  const candidate = JSON.parse(staged.stdout);
  assert.equal(candidate.type, 'source_context_session_staged'); assert.equal(f.p.calls.length, 1);
  assert.equal((await child(args).done).code, 2); assert.equal(f.p.calls.length, 1);
  await rm(f.token);
  const recover = ['recover', ...f.shared, '--tip-sha256', f.created.tip_sha256, '--request-sha256', r.request_sha256];
  assert.equal((await child(recover).done).code, 2);
  const wrong = await child([...recover, '--candidate-sha256', 'f'.repeat(64)]).done; assert.equal(wrong.code, 2);
  const correct = await child([...recover, '--candidate-sha256', candidate.candidate_sha256]).done;
  assert.equal(correct.code, 0, correct.stderr); const result = JSON.parse(correct.stdout);
  assert.equal(result.pending, null); assert.equal(result.reserved.queries, 1); assert.equal(result.acquisition_retried, false);
  const again = await child([...recover, '--candidate-sha256', candidate.candidate_sha256]).done;
  assert.equal(again.code, 0, again.stderr); assert.equal(JSON.parse(again.stdout).tip_sha256, result.tip_sha256); assert.equal(f.p.calls.length, 1);
});

test('two executable instances cannot acquire two budget reservations for one predecessor', async t => {
  const f = await setup(t), results = await Promise.all([child(f.step).done, child(f.step).done]);
  assert.equal(results.filter(r => r.code === 0).length, 1); assert.equal(results.filter(r => r.code === 2).length, 1);
  assert.equal(f.p.calls.length, 1); const s = await child(statusArgs(f)).done; assert.equal(JSON.parse(s.stdout).reserved.queries, 1);
});

test('partial latest query remains explicit even when its durable step is settled', async t => {
  const f = await setup(t, input('sha1', { limits: { context_max_files: 1 } }), { files: [
    { path: Buffer.from('a'), bytes: Buffer.from('recover') }, { path: Buffer.from('b'), bytes: Buffer.from('recover') }] });
  const result = await child(f.step).done; assert.equal(result.code, 3, result.stderr);
  const receipt = JSON.parse(result.stdout); assert.equal(receipt.pending, null); assert.equal(receipt.latest_query_complete, false);
  assert.equal(receipt.aggregate_coverage_claimed, false); assert.equal(receipt.history[0].complete, false);
  const observed = await child(statusArgs(f, receipt.tip_sha256)).done; assert.equal(observed.code, 3);
});

test('SIGTERM drains the actual network read and leaves a durable charged refusal', async t => {
  const f = await setup(t); let ready; const started = new Promise(resolve => { ready = resolve; });
  f.state.hang = true; f.state.started = ready;
  const running = child(f.step); t.after(() => { if (running.p.exitCode === null && running.p.signalCode === null) running.p.kill('SIGKILL'); });
  await started; running.p.kill('SIGTERM'); const result = await running.done;
  assert.equal(result.code, 2, result.stderr); assert.equal(JSON.parse(result.stdout).error_code, 'cancelled');
  const s = await child(statusArgs(f)).done; assert.equal(JSON.parse(s.stdout).reserved.queries, 1); assert.equal(JSON.parse(s.stdout).pending, null);
  assert.equal(f.p.calls.length, 1);
});

test('SIGKILL and restart report unknown read responsibility without another dispatch', async t => {
  const f = await setup(t); let ready; const started = new Promise(resolve => { ready = resolve; });
  f.state.hang = true; f.state.started = ready;
  const running = child(f.step); t.after(() => { if (running.p.exitCode === null && running.p.signalCode === null) running.p.kill('SIGKILL'); });
  await started; running.p.kill('SIGKILL'); assert.equal((await running.done).signal, 'SIGKILL');
  const observed = await child(statusArgs(f)).done; assert.equal(observed.code, 3, observed.stderr);
  const s = JSON.parse(observed.stdout); assert.equal(s.pending.state, 'in_flight_or_interrupted'); assert.equal(s.reserved.queries, 1);
  const recovery = await child(['recover', ...f.shared, '--tip-sha256', s.tip_sha256, '--request-sha256', s.pending.request_sha256]).done;
  assert.equal(recovery.code, 3); assert.equal(JSON.parse(recovery.stdout).acquisition_retried, false);
  assert.equal((await child(f.step).done).code, 2); assert.equal(f.p.calls.length, 1);
});

test('lost stdout after terminal publication retains the tip and independently inspectable result', async t => {
  const f = await setup(t); let errors = '';
  const stdout = new Writable({ write(_bytes, _encoding, done) { done(new Error('closed output')); } });
  const stderr = new Writable({ write(bytes, _encoding, done) { errors += bytes; done(); } });
  const code = await main(f.step, { stdout, stderr }); assert.equal(code, 4);
  const retained = JSON.parse(errors).retained_result;
  const state = await inspectSession(f.session, f.created.session_sha256, retained.tip_sha256);
  assert.equal(state.tip_sha256, retained.tip_sha256); assert.equal(state.pending, null);
  assert.equal((await inspectBundle(state.latest_bundle, state.latest_manifest_sha256)).complete, true); assert.equal(f.p.calls.length, 1);
});

test('offline operations reject credentials, endpoint overrides and nonexistent retained tips', async t => {
  const f = await setup(t);
  for (const extra of [['--token-file', f.token], ['--ca-file', f.token], ['--endpoint', f.p.endpoint]]) {
    assert.equal((await child([...statusArgs(f), ...extra]).done).code, 2);
  }
  assert.equal((await child(statusArgs(f, 'f'.repeat(64))).done).code, 2); assert.equal(f.p.calls.length, 0);
});

test('the one CLI deadline settles a silent server without reissuing the request', async t => {
  const f = await setup(t); f.state.hang = true;
  const value = await child([...f.step, '--timeout-ms', '500']).done;
  assert.equal(value.code, 2, value.stderr);
  assert.equal(JSON.parse(value.stdout).type, 'source_context_session_refused');
  assert.equal(f.p.calls.length, 1);
  const state = await child(statusArgs(f)).done;
  assert.equal(JSON.parse(state.stdout).reserved.queries, 1); assert.equal(JSON.parse(state.stdout).pending, null);
});

test('both synced custody records exist with exact query bytes before the peer sees the read', async t => {
  const { readFileSync } = await import('node:fs');
  const { sha256 } = await import('../../scripts/operator/source_context.mjs');
  const f = await setup(t); let witnessed = false;
  f.state.decorate = value => {
    const dir = join(f.session, 'steps/0001');
    const bytes = readFileSync(join(dir, 'request.json'));
    const request = JSON.parse(bytes), started = JSON.parse(readFileSync(join(dir, 'started.json')));
    assert.equal(request.query_sha256, sha256(f.p.calls[0].body));
    assert.equal(started.request_sha256, sha256(bytes));
    assert.equal(request.reservation.queries, 1); assert.equal(request.previous_tip_sha256, f.created.tip_sha256);
    witnessed = true; return value;
  };
  const result = await child(f.step).done; assert.equal(result.code, 0, result.stderr); assert.equal(witnessed, true);
});
