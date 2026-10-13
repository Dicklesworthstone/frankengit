import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile, readdir, chmod, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureSourceEdit, canonical, hash } from '../../scripts/operator/source_edit_candidate.mjs';
import { saveSourceEdit, loadSourceEdit, stageSourceApply, dispatchSourceApply, recoverSourceApply, inspectSourceApply } from '../../scripts/operator/source_edit_publish.mjs';
import { peer, TOKEN, PRINCIPAL } from './source_edit_fixture.mjs';
const sequence = '18446744073709551615';
async function fixture(t, format = 'sha1') {
  const p = await peer(t, format), dir = await mkdtemp(join(tmpdir(), 'fg-source-apply-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const value = await captureSourceEdit(p.request, p.patch, TOKEN), candidate = join(dir, 'candidate'), journal = join(dir, 'journal');
  const saved = await saveSourceEdit(candidate, value.capture, value.bundle);
  const staged = await stageSourceApply(journal, candidate, saved.manifest_sha256, PRINCIPAL);
  const publication = { type: 'source_publication', schema_version: 1, ...p.request.scope, principal_id: PRINCIPAL,
    ref: p.request.ref, ref_hex: Buffer.from(p.request.ref).toString('hex'), expected_commit: p.base, candidate_commit: p.candidate,
    tx_id: 'fixture-tx', outcome: 'committed', decision_sequence: sequence, decision_record: 'fixture-rcr', refusal_code: null, delivery_acknowledged: null };
  const outcome = { type: 'transaction_outcome', schema_version: 1,
    tenant_id: p.request.scope.tenant_id, repository_id: p.request.scope.repository_id,
    repository_incarnation: p.request.scope.repository_incarnation, principal_id: PRINCIPAL,
    selector: 'transaction', command_index: null, state: 'committed', terminal: true,
    transaction: { tx_id: 'fixture-tx', seal_id: 'fixture-seal', request_schema: 'fixture-schema', canonical_request_digest: { algorithm: 2, hex: '7'.repeat(64) } },
    decision: { kind: 'committed', decision_sequence: sequence, repository_commit_id: 'fixture-rcr' },
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
  const send = (res, value, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(value).replace(/"decision_sequence":"([0-9]+)"/g, '"decision_sequence":$1')); };
  p.control.handler = (_req, res, call) => send(res, call.operation === 'apply' ? publication : outcome);
  return { ...p, dir, candidate, journal, value, saved, staged, publication, outcome, send };
}
for (const format of ['sha1', 'sha256']) test(`${format}: private staged candidate publishes exactly once and records full u64 decision`, async t => {
  const f = await fixture(t, format);
  await rm(f.candidate, { recursive: true }); // journal owns its copy
  const result = await dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN);
  assert.equal(result.decision.outcome, 'committed'); assert.equal(result.decision.decision_sequence, sequence);
  assert.equal(result.submission_retried, false);
  assert.equal(f.calls.filter(c => c.operation === 'apply').length, 1);
  const sent = f.calls.at(-1); assert.equal(sent.headers['idempotency-key'], f.staged.key);
  assert.ok(sent.body.includes(f.bundle));
  const saved = JSON.parse(await readFile(join(f.journal, 'request.json')));
  assert.equal(saved.upload_sha256, hash(sent.body)); assert.equal(saved.content_type, sent.headers['content-type']);
  assert.ok(!JSON.stringify(saved).includes(TOKEN));
  const priorCalls = f.calls.length;
  const recovered = await recoverSourceApply(f.journal, f.staged.request_sha256, 'b'.repeat(64));
  assert.deepEqual(recovered.decision, result.decision); assert.equal(f.calls.length, priorCalls);
  const again = await dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN);
  assert.deepEqual(again.decision, result.decision); assert.equal(f.calls.length, priorCalls);
});
test('socket loss after mutation remains pending and recovers only the original key without upload', async t => {
  const f = await fixture(t); let read = false;
  f.control.handler = (_req, res, call) => {
    if (call.operation === 'apply') { res.destroy(); return; }
    read = true; assert.equal(call.operation, 'outcomes'); assert.equal(call.body.length, 0);
    assert.equal(call.headers['idempotency-key'], f.staged.key); assert.equal(call.headers.authorization, `Bearer ${'b'.repeat(64)}`);
    f.send(res, f.outcome);
  };
  await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN), e => !!e.retained_request);
  await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN), /already_dispatched/);
  const result = await recoverSourceApply(f.journal, f.staged.request_sha256, 'b'.repeat(64));
  assert.equal(result.decision.outcome, 'committed'); assert.equal(read, true);
  assert.equal(f.calls.filter(c => c.operation === 'apply').length, 1);
});
for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) test(`${state} never permits redispatch or claims rollback`, async t => {
  const f = await fixture(t);
  f.control.handler = (_req, res, call) => {
    if (call.operation === 'apply') { res.destroy(); return; }
    f.send(res, { ...f.outcome, state, terminal: false, decision: null, transaction: state === 'undecided' ? f.outcome.transaction : null });
  };
  await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN));
  const result = await recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN);
  assert.equal(result.state, state); assert.equal(result.absence_proves_non_commit, false);
  await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN), /already_dispatched/);
  assert.equal(f.calls.filter(c => c.operation === 'apply').length, 1);
});
test('an observed transaction cannot disappear or change identity on recovery', async t => {
  const f = await fixture(t); let reply = { ...f.outcome, state: 'undecided', terminal: false, decision: null };
  f.control.handler = (_req, res, call) => call.operation === 'apply' ? res.destroy() : f.send(res, reply);
  await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN));
  await recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN);
  reply = { ...reply, transaction: { ...reply.transaction, tx_id: 'changed' } };
  await assert.rejects(recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN), /regressed_or_conflicted/);
  reply = { ...reply, state: 'key_not_observed', transaction: null };
  await assert.rejects(recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN), /regressed_or_conflicted/);
  reply = f.outcome; assert.equal((await recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN)).decision.outcome, 'committed');
});
test('canonical refusal is terminal while bare HTTP errors are not', async t => {
  const f = await fixture(t);
  f.control.handler = (_req, res) => f.send(res, { ...f.publication, outcome: 'refused', refusal_code: 'Protected', decision_record: 'refusal-record' }, 409);
  const result = await dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN);
  assert.equal(result.decision.outcome, 'refused'); assert.equal(result.decision.refusal_code, 'Protected');
  for (const status of [401, 403, 409, 503]) {
    const g = await fixture(t); g.control.handler = (_req, res) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end('{}'); };
    await assert.rejects(dispatchSourceApply(g.journal, g.staged.request_sha256, TOKEN), e => !!e.retained_request);
    assert.equal((await inspectSourceApply(g.journal, g.staged.request_sha256)).state, 'outcome_unknown');
  }
});
for (const [name, change] of [
  ['principal', r => r.principal_id = '7'.repeat(32)], ['candidate', r => r.candidate_commit = 'f'.repeat(40)],
  ['branch', r => r.ref = 'refs/heads/other'], ['receipt kind', r => r.type = 'transaction_outcome'],
  ['zero sequence', r => r.decision_sequence = '0'], ['acknowledgement', r => r.delivery_acknowledged = true],
]) test(`unexpected ${name} remains unresolved rather than accepting HTTP success`, async t => {
  const f = await fixture(t); change(f.publication);
  await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN), e => !!e.retained_request);
  assert.equal((await inspectSourceApply(f.journal, f.staged.request_sha256)).state, 'outcome_unknown');
});
test('concurrent dispatch has only one wire owner and recovery safely converges', async t => {
  const f = await fixture(t);
  f.control.handler = async (_req, res, call) => { if (call.operation === 'apply') { await new Promise(r => setTimeout(r, 60)); res.destroy(); } else f.send(res, f.outcome); };
  const both = await Promise.allSettled([dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN), dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN)]);
  assert.equal(both.filter(r => r.status === 'rejected').length, 2); assert.equal(f.calls.filter(c => c.operation === 'apply').length, 1);
  const recovered = await Promise.all([recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN), recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN)]);
  assert.deepEqual(recovered[0].decision, recovered[1].decision);
});
test('dispatch marker and exact request are present before the HTTP peer sees a mutation', async t => {
  const f = await fixture(t);
  f.control.handler = async (_req, res) => {
    const started = JSON.parse(await readFile(join(f.journal, 'dispatch', 'started.json')));
    assert.equal(started.request_sha256, f.staged.request_sha256);
    const request = await readFile(join(f.journal, 'request.json')); assert.equal(hash(request), f.staged.request_sha256);
    f.send(res, f.publication);
  };
  await dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN);
});
test('wrong independent pin, corrupt payload, and changed request refuse before mutation', async t => {
  for (const change of [async f => { f.staged.request_sha256 = '0'.repeat(64); },
    async f => writeFile(join(f.journal, 'candidate', 'candidate.bundle'), 'bad'),
    async f => { const path = join(f.journal, 'request.json'), v = JSON.parse(await readFile(path)); v.ref = 'refs/heads/other'; await writeFile(path, canonical(v)); }]) {
    const f = await fixture(t); await change(f);
    await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN));
    assert.equal(f.calls.filter(c => c.operation === 'apply').length, 0);
  }
});
test('offline candidate loader returns verified detached bytes and rejects changed exports', async t => {
  const f = await fixture(t), loaded = await loadSourceEdit(f.candidate, f.saved.manifest_sha256);
  assert.deepEqual(loaded.bundle, f.bundle);
  await assert.rejects(loadSourceEdit(f.candidate, '0'.repeat(64)));
  await chmod(join(f.candidate, 'capture.json'), 0o644); await assert.rejects(loadSourceEdit(f.candidate, f.saved.manifest_sha256));
});
test('exclusive private outputs preserve prior candidates and overlapping paths refuse', async t => {
  const f = await fixture(t), before = await readFile(join(f.candidate, 'manifest.json'));
  await assert.rejects(saveSourceEdit(f.candidate, f.value.capture, f.value.bundle));
  assert.deepEqual(await readFile(join(f.candidate, 'manifest.json')), before);
  await assert.rejects(stageSourceApply(join(f.candidate, 'nested'), f.candidate, f.saved.manifest_sha256, PRINCIPAL));
  const target = join(f.dir, 'competing');
  const writes = await Promise.allSettled([saveSourceEdit(target, f.value.capture, f.value.bundle), saveSourceEdit(target, f.value.capture, f.value.bundle)]);
  assert.equal(writes.filter(r => r.status === 'fulfilled').length, 1);
  await loadSourceEdit(target, f.saved.manifest_sha256);
});
test('undispatched and interrupted marker states never acquire implicitly', async t => {
  const f = await fixture(t), before = f.calls.length;
  assert.equal((await recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN)).state, 'not_dispatched');
  await mkdir(join(f.journal, 'dispatch'), { mode: 0o700 });
  assert.equal((await recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN)).state, 'dispatch_incomplete');
  await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN)); assert.equal(f.calls.length, before);
});
test('pre-cancelled dispatch has no marker while cancellation after transmission preserves responsibility', async t => {
  const f = await fixture(t), pre = new AbortController(); pre.abort();
  await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN, { signal: pre.signal }));
  assert.equal((await readdir(f.journal)).includes('dispatch'), false);
  const stop = new AbortController(); f.control.handler = (_req, _res) => stop.abort();
  await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN, { signal: stop.signal }), e => !!e.retained_request);
  assert.equal((await inspectSourceApply(f.journal, f.staged.request_sha256)).state, 'outcome_unknown');
  await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN));
});
