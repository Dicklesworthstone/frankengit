// Complete production modules, real files/sockets/processes, native-schema peers.
// These tests are not Rust-node, remote-authority or power-loss conformance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile, readdir, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { createSession, inspectSession, reserveSessionStep, acquireSessionStep, recoverSessionStep,
  runSessionStep, sessionLimits, SESSION_PROFILE } from '../../scripts/operator/source_context_session.mjs';
import { loadBundle, inspectBundle, publishBundle, bundleCommitment } from '../../scripts/operator/source_context_export.mjs';
import { fixture, input, TOKEN } from './source_context_continue_fixtures.mjs';
import { hex } from './source_context_fixtures.mjs';
import { symbolInput } from './source_context_symbols_fixtures.mjs';
const BUDGET = { queries: 4, work: 4 * 16777216, payload_bytes: 4 * 33554432, source_bytes: 4 * 67108864, excerpt_bytes: 4 * 1048576 };
async function setup(t, q = input(), budget = BUDGET) {
  const f = await fixture(t, q), root = join(f.root, 'session');
  const created = await createSession(root, f.bundle, f.receipt.manifest_sha256, budget);
  return { ...f, root, created, sessionHash: created.session_sha256, tip: created.tip_sha256 };
}
const inspect = (f, tip = f.tip) => inspectSession(f.root, f.sessionHash, tip);
const reserve = (f, delta = { terms: ['untrusted'] }, tip = f.tip) => reserveSessionStep(f.root, f.sessionHash, tip, delta);
const dispatch = (f, r, options = {}) => acquireSessionStep(f.root, f.sessionHash, r.previous_tip_sha256, r.request_sha256, TOKEN, options);
const recover = async (f, r) => {
  const state = await inspect(f, r.previous_tip_sha256);
  let candidate = state.pending?.candidate_sha256 ?? null;
  if (!state.pending && state.history.some(h => h.request_sha256 === r.request_sha256 && h.state === 'captured')) {
    const { sha256 } = await import('../../scripts/operator/source_context.mjs');
    candidate = sha256(await readFile(join(step(f, r.sequence), 'candidate.json')));
  }
  return recoverSessionStep(f.root, f.sessionHash, r.previous_tip_sha256, r.request_sha256, candidate);
};
const run = (f, delta = { terms: ['untrusted'] }, tip = f.tip, options = {}) => runSessionStep(f.root, f.sessionHash, tip, delta, TOKEN, options);
const step = (f, n = 1) => join(f.root, 'steps', String(n).padStart(4, '0'));

for (const format of ['sha1', 'sha256']) test(`${format}: two durable follow-ups retain cumulative costs, lineage and independent captures`, async t => {
  const f = await setup(t, input(format)), before = f.originalBytes;
  const empty = await inspect(f);
  assert.equal(empty.reserved.queries, 0); assert.equal(empty.history.length, 0); assert.equal(f.p.calls.length, 0);
  const first = await run(f);
  assert.equal(first.pending, null); assert.equal(first.history.length, 1); assert.equal(first.reserved.queries, 1);
  const second = await run(f, { terms: ['recover'], limits: { context_radius_bytes: 0, context_max_files: 2 } }, first.tip_sha256);
  assert.equal(second.history.length, 2); assert.equal(second.reserved.work, 2 * 16777216);
  assert.equal(second.reserved.source_bytes, 2 * 67108864);
  assert.equal(second.reserved.excerpt_bytes, 2 * 262144); assert.equal(second.aggregate_coverage_claimed, false);
  assert.deepEqual((await inspect(f, first.tip_sha256)).history, second.history);
  for (const h of second.history) {
    const loaded = await loadBundle(join(step(f, h.sequence), 'bundle'), h.manifest_sha256);
    assert.equal(loaded.capture.summary.source.source_commit, f.capture.summary.source.source_commit);
    assert.equal(loaded.capture.summary.query.expected_head, f.capture.summary.source.snapshot_token);
    assert.equal((await inspectBundle(loaded.receipt.bundle, h.manifest_sha256)).read_only, true);
  }
  assert.equal(f.p.calls.length, 2);
  for (const call of f.p.calls) {
    const body = new URLSearchParams(call.body);
    assert.equal(body.get('expected_head'), f.capture.summary.source.snapshot_token);
    assert.equal(body.get('minimum_lexical_number'), '7');
    assert.equal(call.headers['idempotency-key'], undefined);
  }
  assert.deepEqual(await f.readParent(), before);
  assert.ok(!(await readFile(join(step(f), 'request.json'), 'utf8')).includes(TOKEN));
});

test('manifest commitment matches the existing export byte-for-byte', async t => {
  const f = await setup(t), expected = bundleCommitment(f.capture);
  assert.equal(expected.manifest_sha256, f.receipt.manifest_sha256);
  assert.equal(expected.capture_sha256, f.receipt.capture_sha256);
  assert.equal(expected.text_sha256, f.receipt.text_sha256);
  assert.equal(f.created.base_manifest_sha256, f.receipt.manifest_sha256);
});

test('session owns a checked copy of its base; removing the external parent does not break replay', async t => {
  const f = await setup(t); await rm(f.bundle, { recursive: true });
  const result = await run(f); assert.equal(result.reserved.queries, 1); assert.equal(f.p.calls.length, 1);
});

for (const name of ['queries', 'work', 'payload_bytes', 'source_bytes', 'excerpt_bytes']) {
  test(`${name}: exact cumulative ceiling succeeds, the next reservation fails before I/O`, async t => {
    const ceiling = { queries: 1, work: 16777216, payload_bytes: 33554432, source_bytes: 67108864, excerpt_bytes: 262144 }[name];
    const f = await setup(t, input(), { ...BUDGET, [name]: ceiling });
    const completed = await run(f);
    assert.equal(completed.reserved[name], ceiling);
    await assert.rejects(run(f, { terms: ['recover'] }, completed.tip_sha256), /budget_exhausted/);
    assert.equal(f.p.calls.length, 1); assert.deepEqual(await readdir(join(f.root, 'steps')), ['0001']);
  });
}

for (const [name, n] of [['work', 16777215], ['payload_bytes', 33554431], ['source_bytes', 67108863], ['excerpt_bytes', 262143]]) {
  test(`${name}: one-under allowance cannot be claimed before dispatch`, async t => {
    const f = await setup(t, input(), { ...BUDGET, [name]: n });
    await assert.rejects(reserve(f), /budget_exhausted/);
    assert.equal(f.p.calls.length, 0); assert.deepEqual(await readdir(join(f.root, 'steps')), []);
  });
}

test('narrowed calls reserve their actual ceilings, not the session maximum or completed-channel counters', async t => {
  const f = await setup(t, input(), { queries: 2, work: 20000, payload_bytes: 20000, source_bytes: 2000, excerpt_bytes: 2000 });
  const delta = { terms: ['recover'], limits: { max_work: 10000, max_payload_bytes: 10000, context_max_source_bytes: 1000, context_max_excerpt_bytes: 1000 } };
  const first = await run(f, delta), second = await run(f, delta, first.tip_sha256);
  assert.equal(second.reserved.work, 20000); assert.equal(second.remaining.work, 0);
  assert.equal(second.reserved.source_bytes, 2000);
  assert.ok((await loadBundle(second.latest_bundle, second.latest_manifest_sha256)).capture.summary.source_bytes_read < 1000);
});

for (const status of [401, 409, 413, 503]) test(`HTTP ${status} settles one refusal but never refunds its reservation`, async t => {
  const f = await setup(t); f.state.status = status;
  const refused = await run(f); assert.equal(refused.type, 'source_context_session_refused'); assert.equal(refused.http_status, status);
  let observed = await inspect(f, refused.tip_sha256);
  assert.equal(observed.pending, null); assert.equal(observed.history[0].state, 'read_refused');
  assert.equal(observed.reserved.work, 16777216); assert.equal(observed.latest_manifest_sha256, f.receipt.manifest_sha256);
  f.state.status = 200;
  const result = await run(f, { terms: ['recover'] }, refused.tip_sha256);
  assert.equal(result.reserved.queries, 2); assert.equal(f.p.calls.length, 2);
});

test('source movement settles a refusal rather than changing the session snapshot', async t => {
  const f = await setup(t); f.state.decorate = r => { r.retrieval.snapshot_token = `alg:2:${'a'.repeat(64)}`; return r; };
  const result = await run(f); assert.equal(result.type, 'source_context_session_refused');
  assert.deepEqual((await inspect(f, result.tip_sha256)).source, f.capture.summary.source);
  assert.equal(f.p.calls.length, 1);
});

test('two concurrent reservations at one predecessor cannot both dispatch', async t => {
  const f = await setup(t);
  const values = await Promise.allSettled([run(f), run(f)]);
  assert.equal(values.filter(v => v.status === 'fulfilled').length, 1);
  assert.equal(f.p.calls.length, 1); assert.equal((await inspect(f)).reserved.queries, 1);
});

test('two dispatchers for the same durable request make exactly one network call', async t => {
  const f = await setup(t), r = await reserve(f);
  const values = await Promise.allSettled([dispatch(f, r), dispatch(f, r)]);
  assert.equal(values.filter(v => v.status === 'fulfilled').length, 1); assert.equal(f.p.calls.length, 1);
  assert.equal((await recover(f, r)).pending, null);
  await assert.rejects(dispatch(f, r)); assert.equal(f.p.calls.length, 1);
});

test('reserved and started-without-result states block new steps, and recovery never retries them', async t => {
  const f = await setup(t), r = await reserve(f);
  assert.equal((await recover(f, r)).pending.state, 'reserved');
  await assert.rejects(run(f), /step_pending/); assert.equal(f.p.calls.length, 0);
  await writeFile(join(step(f), 'started.json'), `${JSON.stringify({ schema: `${SESSION_PROFILE}/started`, request_sha256: r.request_sha256 })}\n`, { mode: 0o600 });
  assert.equal((await recover(f, r)).pending.state, 'in_flight_or_interrupted');
  await assert.rejects(dispatch(f, r), /already_started/);
  assert.equal(f.p.calls.length, 0); assert.equal((await inspect(f)).reserved.queries, 1);
});

test('staged output recovers the exact original candidate without a new acquisition', async t => {
  const f = await setup(t), r = await reserve(f), staged = await dispatch(f, r);
  assert.equal((await inspect(f)).pending.state, 'candidate');
  const first = await recover(f, r), again = await recover(f, r);
  assert.equal(first.latest_manifest_sha256, staged.manifest_sha256);
  assert.equal(again.tip_sha256, first.tip_sha256); assert.equal(f.p.calls.length, 1);
  assert.equal(again.history.length, 1); assert.equal(again.reserved.queries, 1);
});

test('actual child exit after acquisition is recovered from durable files by another process', async t => {
  const f = await setup(t), r = await reserve(f), url = new URL('../../scripts/operator/source_context_session.mjs', import.meta.url).href;
  const child = spawn(process.execPath, ['--input-type=module', '-e',
    `import {acquireSessionStep} from ${JSON.stringify(url)}; const a=JSON.parse(process.env.SESSION_ARGS); await acquireSessionStep(...a); process.exit(0);`],
    { env: { ...process.env, SESSION_ARGS: JSON.stringify([f.root, f.sessionHash, r.previous_tip_sha256, r.request_sha256, TOKEN]) }, stdio: ['ignore', 'pipe', 'pipe'] });
  let errors = ''; child.stderr.on('data', b => { errors += b; });
  assert.equal(await new Promise(resolve => child.once('close', resolve)), 0, errors);
  assert.equal((await inspect(f)).pending.state, 'candidate');
  const after = await recover(f, r); assert.equal(after.pending, null); assert.equal(f.p.calls.length, 1);
});

test('SIGKILL during a real streamed response leaves a charged, non-retryable pending request', async t => {
  const f = await setup(t), r = await reserve(f), url = new URL('../../scripts/operator/source_context_session.mjs', import.meta.url).href;
  let ready; const started = new Promise(resolve => { ready = resolve; }); f.state.hang = true; f.state.started = ready;
  const child = spawn(process.execPath, ['--input-type=module', '-e',
    `import {acquireSessionStep} from ${JSON.stringify(url)}; await acquireSessionStep(...JSON.parse(process.env.SESSION_ARGS));`],
    { env: { ...process.env, SESSION_ARGS: JSON.stringify([f.root, f.sessionHash, r.previous_tip_sha256, r.request_sha256, TOKEN]) }, stdio: 'ignore' });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  const closed = new Promise(resolve => child.once('close', (_code, signal) => resolve(signal)));
  await started; child.kill('SIGKILL'); assert.equal(await closed, 'SIGKILL');
  const after = await recover(f, r); assert.equal(after.pending.state, 'in_flight_or_interrupted');
  assert.equal(after.reserved.queries, 1); await assert.rejects(run(f), /step_pending/); assert.equal(f.p.calls.length, 1);
});

test('live cancellation settles the closed read without dropping reserved cost', async t => {
  const f = await setup(t), stop = new AbortController();
  let ready; const started = new Promise(resolve => { ready = resolve; }); f.state.hang = true; f.state.started = ready;
  const pending = run(f, { terms: ['recover'] }, f.tip, { signal: stop.signal });
  await started; stop.abort();
  const refused = await pending; assert.equal(refused.error_code, 'cancelled');
  assert.equal((await inspect(f, refused.tip_sha256)).pending, null); assert.equal(f.p.calls.length, 1);
});

test('retained terminal checkpoints reject rollback and stale writers', async t => {
  const f = await setup(t), first = await run(f);
  await assert.rejects(run(f), /tip_moved/);
  await assert.rejects(inspect(f, 'f'.repeat(64)), /checkpoint_unavailable/);
  const original = await readFile(join(step(f), 'terminal.json'));
  await rm(join(step(f), 'terminal.json'));
  await assert.rejects(inspect(f, first.tip_sha256), /checkpoint_unavailable/);
  await writeFile(join(step(f), 'terminal.json'), original, { mode: 0o600 });
  assert.equal((await inspect(f, first.tip_sha256)).tip_sha256, first.tip_sha256);
});

for (const name of ['request.json', 'started.json', 'candidate.json', 'terminal.json']) test(`corrupt ${name} never becomes an empty ledger`, async t => {
  const f = await setup(t); const completed = await run(f);
  await writeFile(join(step(f), name), '{}\n', { mode: 0o600 });
  await assert.rejects(inspect(f, completed.tip_sha256)); assert.equal(f.p.calls.length, 1);
});

test('missing or modified source payload prevents recovery; a different capture cannot replace a candidate', async t => {
  const f = await setup(t), r = await reserve(f); await dispatch(f, r);
  const path = join(step(f), 'bundle', 'capture.json'), original = await readFile(path);
  await writeFile(path, '{}', { mode: 0o600 });
  await assert.rejects(recover(f, r)); await assert.rejects(run(f), /step_pending/); assert.equal(f.p.calls.length, 1);
  await writeFile(path, original, { mode: 0o600 }); assert.equal((await recover(f, r)).pending, null);
});

test('history holes, directory aliases, and incomplete reservations fail closed', async t => {
  const f = await setup(t); await mkdir(step(f, 2), { mode: 0o700 });
  await assert.rejects(inspect(f), /history_gap/); await rm(step(f, 2), { recursive: true });
  await mkdir(step(f), { mode: 0o700 }); await assert.rejects(inspect(f), /incomplete_reservation/);
  await rm(step(f), { recursive: true }); await symlink(f.bundle, step(f)); await assert.rejects(inspect(f), /symlink/);
  assert.equal(f.p.calls.length, 0);
});

test('invalid budgets, options, credential and widened followups have no reservation side effects', async t => {
  for (const bad of [{ ...BUDGET, queries: 17 }, { ...BUDGET, work: 0 }, { ...BUDGET, extra: 1 }, { ...BUDGET, source_bytes: 1.5 }]) assert.throws(() => sessionLimits(bad));
  const f = await setup(t, input('sha1', { prefixes_hex: [hex('src')] }));
  for (const delta of [{ terms: ['recover'], prefixes_hex: [] }, { terms: ['recover'], endpoint: 'https://foreign/repo' },
    { terms: ['recover'], limits: { max_work: 16777217 } }]) await assert.rejects(reserve(f, delta));
  await assert.rejects(runSessionStep(f.root, f.sessionHash, f.tip, { terms: ['recover'] }, 'bad'));
  await assert.rejects(run(f, { terms: ['recover'] }, f.tip, { retry: true }));
  assert.deepEqual(await readdir(join(f.root, 'steps')), []); assert.equal(f.p.calls.length, 0);
});

test('required symbol checkpoints survive session replay and changed symbol query names', async t => {
  const f = await setup(t, symbolInput());
  const first = await run(f, { terms: ['recover'], symbols: { name: 'RecoverRaw' } });
  assert.equal(first.history.length, 1);
  const fields = new URLSearchParams(f.p.calls[0].body);
  assert.equal(fields.get('minimum_symbol_number'), '4'); assert.equal(fields.get('symbol_policy'), 'required');
  await assert.rejects(run(f, { terms: ['recover'], symbols: { policy: 'optional' } }, first.tip_sha256), /weakened/);
  assert.equal(f.p.calls.length, 1);
});

test('caller mutation after reservation starts cannot alter saved followup or charge', async t => {
  const f = await setup(t), delta = { terms: ['untrusted'], limits: { context_max_files: 2 } };
  const pending = reserve(f, delta); delta.terms[0] = 'secret'; delta.limits.context_max_files = 32;
  const r = await pending; await dispatch(f, r); const after = await recover(f, r);
  const saved = await loadBundle(after.latest_bundle, after.latest_manifest_sha256);
  assert.deepEqual(saved.capture.summary.query.terms, ['untrusted']); assert.equal(saved.capture.summary.query.limits.context_max_files, 2);
});


test('recover requires the original candidate pin, not just an unchanged request', async t => {
  const f = await setup(t), r = await reserve(f), staged = await dispatch(f, r);
  for (const pin of [null, 'f'.repeat(64)]) {
    await assert.rejects(recoverSessionStep(f.root, f.sessionHash, r.previous_tip_sha256, r.request_sha256, pin), /candidate_pin_changed/);
  }
  const completed = await recoverSessionStep(f.root, f.sessionHash, r.previous_tip_sha256, r.request_sha256, staged.candidate_sha256);
  assert.equal(completed.pending, null); assert.equal(f.p.calls.length, 1);
  await assert.rejects(recoverSessionStep(f.root, f.sessionHash, completed.tip_sha256, r.request_sha256, 'f'.repeat(64)), /candidate_pin_changed/);
});

test('a partial export cannot turn missing backing into a new read or replacement candidate', async t => {
  const f = await setup(t), r = await reserve(f), staged = await dispatch(f, r);
  await rm(join(step(f), 'bundle', 'manifest.json'));
  await assert.rejects(recoverSessionStep(f.root, f.sessionHash, r.previous_tip_sha256, r.request_sha256, staged.candidate_sha256));
  await assert.rejects(dispatch(f, r), /already_started/);
  await assert.rejects(run(f), /step_pending/);
  assert.equal(f.p.calls.length, 1);
});
