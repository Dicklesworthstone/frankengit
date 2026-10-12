import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, lstat, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { prepareIntent, publicationReply, outcomeReply, publishIntent, recoverIntent, verifyObservation,
  observation, canonical, parseJson } from '../../scripts/operator/review_protection.mjs';
import { saveIntent, loadIntent } from '../../scripts/operator/protection_files.mjs';
import { sendSavedIntent, recoverSavedIntent } from '../../scripts/operator/protection_journal.mjs';
import { run } from '../../scripts/fg_protection_admin.mjs';
import { TOKEN, ROTATED, ACTOR, REVIEWER, SCOPE, NEXT, state, json, peer, files } from './protection_fixtures.mjs';
const SCRIPT = fileURLToPath(new URL('../../scripts/fg_protection_admin.mjs', import.meta.url));
const make = (address, extra = {}) => prepareIntent({ endpoint: address, token: TOKEN, principal_id: ACTOR,
  expectedScope: SCOPE, snapshot: state(), replacement: NEXT, nonce: 'f'.repeat(32), ...extra });
const publish = (intent, extra = {}) => ({ type: 'review_protection_publication', schema_version: 1, ...intent.scope,
  principal_id: ACTOR, expected_version: intent.source.version, expected_epoch: intent.source.policy_epoch,
  resulting_epoch: (BigInt(intent.source.policy_epoch) + 1n).toString(), tx_id: 'tx-original', outcome: 'committed',
  decision_sequence: '9007199254740993', repository_commit_id: 'rcr-original', refusal_record_id: null,
  refusal_code: null, refusal_code_point: null, delivery_acknowledged: null, ...extra });
const refused = intent => publish(intent, { outcome: 'refused', resulting_epoch: null, repository_commit_id: null,
  refusal_record_id: 'refusal-original', refusal_code: 'EvidenceStale', refusal_code_point: 12 });
const recovered = (intent, status = 'committed', extra = {}) => ({ type: 'transaction_outcome', schema_version: 1,
  tenant_id: intent.scope.tenant_id, repository_id: intent.scope.repository_id, repository_incarnation: intent.scope.repository_incarnation,
  principal_id: ACTOR, selector: 'transaction', command_index: null, state: status,
  terminal: ['committed', 'refused'].includes(status), transaction: ['key_not_observed', 'seal_not_observed'].includes(status) ? null
    : { tx_id: 'tx-original', seal_id: 'seal-original', request_schema: 'native-receive-admission', canonical_request_digest: { algorithm: 2, hex: '5'.repeat(64) } },
  decision: status === 'committed' ? { kind: status, decision_sequence: '9007199254740993', repository_commit_id: 'rcr-original' }
    : status === 'refused' ? { kind: status, decision_sequence: '9007199254740993', code: 'EvidenceStale', code_point: 12, refusal_record_id: 'refusal-original' } : null,
  read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false, ...extra });
const options = intent => ({ expectedEndpoint: intent.endpoint, confirmation: intent.intent_sha256 });
async function prepared(t, handler = (_, response, intent) => json(response, publish(intent)), extra = {}) {
  const f = await files(t); let intent;
  const p = await peer(t, (call, response, request) => handler(call, response, intent, request, f));
  intent = make(p.endpoint, extra); await saveIntent(f.intent, intent);
  return { f, p, intent };
}
function child(args) {
  const process = spawn(globalThis.process.execPath, [SCRIPT, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = ''; process.stdout.on('data', bytes => { stdout += bytes; }); process.stderr.on('data', bytes => { stderr += bytes; });
  const done = new Promise((resolve, reject) => { process.once('error', reject); process.once('close', (code, signal) => resolve({ code, signal, stdout, stderr })); });
  return { process, done };
}
const sendArgs = (f, intent, extra = []) => ['send', '--endpoint', intent.endpoint, '--token-file', f.token, '--intent', f.intent, '--confirm-intent', intent.intent_sha256, ...extra];
const outcomeArgs = (f, intent, tokenFile = f.token) => ['outcome', '--endpoint', intent.endpoint, '--token-file', tokenFile, '--intent', f.intent];

test('native publication validation binds both domains, exact epochs and full-u64 decisions', () => {
  for (const object_format of ['sha1', 'sha256']) {
    const intent = make('https://forge.example/repo.git', { expectedScope: { ...SCOPE, object_format }, snapshot: state({ object_format, policy_epoch: '18446744073709551614' }) });
    const record = publish(intent, { decision_sequence: '18446744073709551615' });
    assert.equal(publicationReply(record, intent, 200).decision_sequence, '18446744073709551615');
    assert.equal(record.resulting_epoch, '18446744073709551615');
    assert.equal(publicationReply(refused(intent), intent, 409).state, 'refused');
  }
});
test('HTTP status alone, changed command coordinates, principals and contradictory receipts refuse', () => {
  const intent = make('https://forge.example/repo.git');
  for (const extra of [{ type: 'issue_publication' }, { schema_version: 2 }, { principal_id: REVIEWER }, { expected_version: '2' },
    { expected_epoch: '3' }, { resulting_epoch: '9' }, { object_format: 'sha256' }, { repository_incarnation: '4'.repeat(32) },
    { delivery_acknowledged: true }, { refusal_code: 'EvidenceStale' }, { refusal_record_id: 'r' }, { decision_sequence: 3 }, { additional: true }]) {
    assert.throws(() => publicationReply(publish(intent, extra), intent, 200));
  }
  assert.throws(() => publicationReply(publish(intent), intent, 409));
  assert.throws(() => publicationReply(refused(intent), intent, 200));
});
test('every native outcome state has precise presence and terminal semantics', () => {
  const intent = make('https://forge.example/repo.git');
  for (const status of ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused']) {
    const selected = outcomeReply(recovered(intent, status), intent);
    assert.equal(selected.state, status); assert.equal(selected.terminal, ['committed', 'refused'].includes(status));
  }
  for (const extra of [{ principal_id: REVIEWER }, { selector: 'receive_command' }, { command_index: 0 },
    { request_reexecuted: true }, { absence_proves_non_commit: true }, { session_completeness_established: true },
    { transaction: null }, { terminal: false }, { decision: null }, { other: false }]) assert.throws(() => outcomeReply(recovered(intent, 'committed', extra), intent));
});
test('send transmits exact original bytes once and persists responsibility before the socket', async t => {
  const { f, p, intent } = await prepared(t, async (call, response, intent, _, f) => {
    const marker = JSON.parse(await readFile(join(f.intent, 'attempt.json'), 'utf8'));
    assert.equal(marker.intent_sha256, intent.intent_sha256);
    assert.equal(call.method, 'POST'); assert.equal(call.body, intent.request.body);
    assert.equal(call.headers['idempotency-key'], intent.request.key); assert.equal(call.headers.authorization, `Bearer ${TOKEN}`);
    assert.equal(call.url.endsWith('/api/v1/protection'), true); json(response, publish(intent));
  });
  const original = await readFile(join(f.intent, 'intent.json'));
  const result = await sendSavedIntent(f.intent, TOKEN, options(intent));
  assert.equal(result.summary.state, 'committed'); assert.equal(result.local_observation_synced, true); assert.equal(result.mutation_request_sent, true);
  assert.equal(p.calls.length, 1); assert.deepEqual(await readFile(join(f.intent, 'intent.json')), original);
  assert.equal((await readdir(f.intent)).includes('.send-lock'), false);
  const saved = verifyObservation(JSON.parse(await readFile(join(f.intent, 'terminal.json'), 'utf8')), intent);
  assert.deepEqual(saved.summary, result.summary);
  const repeated = await sendSavedIntent(f.intent, TOKEN, options(intent));
  assert.equal(repeated.mutation_request_sent, false); assert.equal(p.calls.length, 1);
});
test('durable stale-policy refusal is terminal, not an automatic reprepare or retry', async t => {
  const { f, p, intent } = await prepared(t, (_, response, intent) => json(response, refused(intent), 409));
  const result = await sendSavedIntent(f.intent, TOKEN, options(intent));
  assert.equal(result.summary.state, 'refused'); assert.equal(result.summary.refusal_code, 'EvidenceStale');
  assert.equal(result.summary.refusal_code_point, 12);
  await sendSavedIntent(f.intent, TOKEN, options(intent)); assert.equal(p.calls.length, 1);
  assert.equal((await loadIntent(f.intent)).source.policy_epoch, '2');
});
test('independent endpoint, confirmation and original-token pins refuse before any network call', async t => {
  const { f, p, intent } = await prepared(t);
  for (const opt of [{ ...options(intent), expectedEndpoint: 'https://other.example/repo.git' }, { ...options(intent), confirmation: '0'.repeat(64) }]) {
    await assert.rejects(sendSavedIntent(f.intent, TOKEN, opt));
  }
  await assert.rejects(sendSavedIntent(f.intent, ROTATED, options(intent)), /original_token/);
  assert.equal(p.calls.length, 0); assert.deepEqual(await readdir(f.intent), ['intent.json']);
});
test('lost reply retains original intent and requires explicit identical retry', async t => {
  let sends = 0;
  const { f, p, intent } = await prepared(t, (_, response, intent) => { if (++sends === 1) response.destroy(); else json(response, publish(intent)); });
  const original = await readFile(join(f.intent, 'intent.json'));
  await assert.rejects(sendSavedIntent(f.intent, TOKEN, options(intent)), error => error.outcomeUnknown);
  await assert.rejects(sendSavedIntent(f.intent, TOKEN, options(intent)), /explicit_retry_required/);
  assert.equal(p.calls.length, 1); assert.equal((await readdir(f.intent)).includes('terminal.json'), false);
  await sendSavedIntent(f.intent, TOKEN, { ...options(intent), retry: true });
  assert.equal(p.calls.length, 2); assert.equal(p.calls[0].body, p.calls[1].body);
  assert.equal(p.calls[0].headers['idempotency-key'], p.calls[1].headers['idempotency-key']);
  assert.deepEqual(await readFile(join(f.intent, 'intent.json')), original);
});
test('rotated same-principal outcome lookup is bodyless and never grants resend permission', async t => {
  const { f, p, intent } = await prepared(t, (call, response, intent) => {
    assert.equal(call.url.endsWith('/outcomes'), true); assert.equal(call.body, '');
    assert.equal(call.headers.authorization, `Bearer ${ROTATED}`); assert.equal(call.headers['idempotency-key'], intent.request.key);
    json(response, recovered(intent));
  });
  const original = await readFile(join(f.intent, 'intent.json'));
  const result = await recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint });
  assert.equal(result.summary.state, 'committed'); assert.equal(result.request_reexecuted, false);
  await assert.rejects(sendSavedIntent(f.intent, ROTATED, options(intent)), /original_token/);
  assert.equal(p.calls.length, 1); assert.deepEqual(await readFile(join(f.intent, 'intent.json')), original);
});
test('absent outcomes do not settle, discard or create a transaction observation', async t => {
  for (const status of ['key_not_observed', 'seal_not_observed']) {
    const { f, intent } = await prepared(t, (_, response, intent) => json(response, recovered(intent, status)));
    const result = await recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint });
    assert.equal(result.summary.terminal, false); assert.equal(result.local_observation_synced, false);
    assert.deepEqual(await readdir(f.intent), ['intent.json']);
  }
});
test('retained transaction pins survive process-style reopen and reject disappearance or substitution', async t => {
  let reply;
  const { f, p, intent } = await prepared(t, (_, response, intent) => json(response, reply ?? recovered(intent, 'undecided')));
  await recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint });
  const known = await readFile(join(f.intent, 'known.json'));
  reply = recovered(intent, 'key_not_observed');
  await assert.rejects(recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint }), /regressed/);
  reply = recovered(intent); reply.transaction.tx_id = 'another-tx';
  await assert.rejects(recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint }), /regressed/);
  reply = recovered(intent); reply.transaction.seal_id = 'another-seal';
  await assert.rejects(recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint }), /seal_changed/);
  assert.deepEqual(await readFile(join(f.intent, 'known.json')), known);
  reply = recovered(intent); assert.equal((await recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint })).summary.state, 'committed');
  assert.equal(p.calls.every(call => call.url.endsWith('/outcomes') && call.body === ''), true);
});
test('terminal observations cannot regress to undecided or change refusal codes', async t => {
  let reply;
  const { f, intent } = await prepared(t, (_, response, intent) => json(response, reply ?? recovered(intent, 'refused')));
  await recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint });
  reply = recovered(intent, 'undecided'); await assert.rejects(recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint }), /regressed/);
  reply = recovered(intent, 'refused'); reply.decision.code_point++;
  await assert.rejects(recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint }), /regressed/);
});
test('wrong-principal and malformed mutation receipts remain unknown and do not erase custody', async t => {
  for (const reply of [intent => publish(intent, { principal_id: REVIEWER }), () => ({ error: 'not_a_terminal' })]) {
    const { f, intent } = await prepared(t, (_, response, intent) => json(response, reply(intent)));
    await assert.rejects(sendSavedIntent(f.intent, TOKEN, options(intent)), error => error.outcomeUnknown);
    assert.deepEqual((await readdir(f.intent)).sort(), ['attempt.json', 'intent.json']);
  }
});
test('outcome revocation, wrong principal and response failure retain pending request bytes', async t => {
  for (const handle of [(_, response) => json(response, {}, 401), (_, response, intent) => json(response, recovered(intent, 'committed', { principal_id: REVIEWER })),
    (_, response) => response.destroy()]) {
    const { f, intent } = await prepared(t, handle), original = await readFile(join(f.intent, 'intent.json'));
    await assert.rejects(recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint }), error => error.outcomeUnknown);
    assert.deepEqual(await readFile(join(f.intent, 'intent.json')), original); assert.deepEqual(await readdir(f.intent), ['intent.json']);
  }
});
test('pre-send cancellation and intent substitution stop dispatch without deleting the marker', async t => {
  const { f, p, intent } = await prepared(t), controller = new AbortController();
  await assert.rejects(sendSavedIntent(f.intent, TOKEN, { ...options(intent), signal: controller.signal, observe: async stage => { if (stage === 'before_send') controller.abort(); } }), /cancelled/);
  assert.equal(p.calls.length, 0); assert.equal((await readdir(f.intent)).includes('attempt.json'), true);
  await assert.rejects(sendSavedIntent(f.intent, TOKEN, { ...options(intent), retry: true,
    observe: async () => { await writeFile(join(f.intent, 'intent.json'), '{}'); } }), /invalid_record_fields/);
  assert.equal(p.calls.length, 0);
});
test('a validated terminal wins over late cancellation and is retained before completion', async t => {
  const { f, intent } = await prepared(t), controller = new AbortController();
  const result = await sendSavedIntent(f.intent, TOKEN, { ...options(intent), signal: controller.signal,
    observe: async stage => { if (stage === 'terminal_observed') controller.abort(); } });
  assert.equal(controller.signal.aborted, true); assert.equal(result.summary.state, 'committed');
  assert.equal(JSON.parse(await readFile(join(f.intent, 'terminal.json'), 'utf8')).reply.outcome, 'committed');
});
test('post-terminal filesystem or cleanup failure retains the observed result, never rollback', async t => {
  for (const target of ['terminal.json', '.send-lock/foreign']) {
    const { f, intent } = await prepared(t);
    await assert.rejects(sendSavedIntent(f.intent, TOKEN, { ...options(intent), observe: async stage => {
      if (stage === 'terminal_observed') await mkdir(join(f.intent, target), { mode: 0o700 });
    } }), error => error.outcomeUnknown === false && error.observation?.summary.state === 'committed');
    assert.equal((await loadIntent(f.intent)).intent_sha256, intent.intent_sha256);
    assert.equal((await lstat(join(f.intent, target))).isDirectory(), true);
  }
});
test('concurrent senders never open a second mutation socket', async t => {
  let received, finish; const waiting = new Promise(resolve => { received = resolve; });
  const { f, p, intent } = await prepared(t, (_, response, intent) => { finish = () => json(response, publish(intent)); received(); });
  const first = sendSavedIntent(f.intent, TOKEN, options(intent)); await waiting;
  await assert.rejects(sendSavedIntent(f.intent, TOKEN, { ...options(intent), retry: true }), /lock_held/);
  assert.equal(p.calls.length, 1); finish(); assert.equal((await first).summary.state, 'committed');
});
test('concurrent outcome lookups retain consistent bounded observations', async t => {
  const { f, p, intent } = await prepared(t, (_, response, intent) => json(response, recovered(intent)));
  const results = await Promise.allSettled([1, 2].map(() => recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint })));
  assert.ok(results.some(result => result.status === 'fulfilled'));
  // A racing reader of an incompletely published local record may refuse; it
  // never treats that record as absent, overwrites it, or reexecutes a request.
  const final = await recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint });
  assert.equal(final.summary.state, 'committed'); assert.equal(p.calls.length, 3);
  assert.deepEqual((await readdir(f.intent)).sort(), ['intent.json', 'known.json', 'terminal.json']);
});
test('bodyless outcome response preserves an actual unquoted maximum u64 on the wire', async t => {
  const { f, intent } = await prepared(t, (_, response, intent) => {
    const value = recovered(intent); value.decision.decision_sequence = '18446744073709551615';
    const bytes = Buffer.from(JSON.stringify(value).replace('"decision_sequence":"18446744073709551615"', '"decision_sequence":18446744073709551615'));
    response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': bytes.length }); response.end(bytes);
  });
  const result = await recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint });
  assert.equal(result.summary.decision_sequence, '18446744073709551615');
  assert.equal(JSON.parse(await readFile(join(f.intent, 'terminal.json'), 'utf8')).reply.decision.decision_sequence, '18446744073709551615');
});
test('CLI publication, refusal, unknown and output failures have distinct preserved results', async t => {
  for (const status of ['committed', 'refused', 'undecided']) {
    const { f, intent } = await prepared(t, (call, response, intent) => call.url.endsWith('/outcomes') ? json(response, recovered(intent, status))
      : json(response, status === 'refused' ? refused(intent) : publish(intent), status === 'refused' ? 409 : 200));
    const expected = status === 'committed' ? 0 : status === 'refused' ? 2 : 3;
    let result; const args = status === 'undecided' ? outcomeArgs(f, intent) : sendArgs(f, intent);
    assert.equal(await run(args, { output: async text => { result = JSON.parse(text); } }), expected);
    assert.equal(result.summary.state, status); assert.equal(result.absence_proves_non_commit, false);
    await assert.rejects(run(args, { output: async () => { throw new Error('stdout closed'); } }), error =>
      error.code === 'output_failure_after_observation' && error.observation?.summary.state === status);
  }
});
test('executable CLI uses actual token files and persists publication across process restart', async t => {
  const { f, p, intent } = await prepared(t);
  const first = await child(sendArgs(f, intent)).done;
  assert.equal(first.code, 0, first.stderr); assert.equal(JSON.parse(first.stdout).summary.state, 'committed');
  const second = await child(sendArgs(f, intent)).done;
  assert.equal(second.code, 0, second.stderr); assert.equal(JSON.parse(second.stdout).mutation_request_sent, false);
  assert.equal(p.calls.length, 1); assert.equal(first.stdout.includes(TOKEN), false); assert.equal(first.stderr.includes(TOKEN), false);
});
test('SIGTERM drains an in-flight command and retains unresolved custody', { timeout: 10000 }, async t => {
  let arrived; const wait = new Promise(resolve => { arrived = resolve; });
  const { f, p, intent } = await prepared(t, () => arrived());
  const running = child(sendArgs(f, intent)); t.after(() => { if (running.process.exitCode === null) running.process.kill('SIGKILL'); });
  await wait; running.process.kill('SIGTERM'); const result = await running.done;
  assert.equal(result.code, 3, result.stderr); assert.equal(result.signal, null);
  assert.equal(JSON.parse(result.stderr).outcome_unknown, true); assert.equal(p.calls.length, 1);
  assert.deepEqual((await readdir(f.intent)).sort(), ['attempt.json', 'intent.json']);
});
test('SIGKILL leaves a blocking send lock while a fresh process can recover the original outcome', { timeout: 10000 }, async t => {
  let arrived; const wait = new Promise(resolve => { arrived = resolve; });
  const { f, p, intent } = await prepared(t, (call, response, intent) => {
    if (call.url.endsWith('/outcomes')) json(response, recovered(intent)); else arrived();
  });
  const running = child(sendArgs(f, intent)); t.after(() => { if (running.process.exitCode === null) running.process.kill('SIGKILL'); });
  await wait; running.process.kill('SIGKILL'); const killed = await running.done; assert.equal(killed.signal, 'SIGKILL');
  assert.equal((await lstat(join(f.intent, '.send-lock'))).isDirectory(), true);
  const token = await f.write('rotated', ROTATED), lookup = await child(outcomeArgs(f, intent, token)).done;
  assert.equal(lookup.code, 0, lookup.stderr); assert.equal(JSON.parse(lookup.stdout).summary.state, 'committed');
  const retry = await child(sendArgs(f, intent, ['--retry'])).done;
  assert.equal(retry.code, 3); assert.match(retry.stderr, /lock_held/);
  assert.equal(p.calls.filter(call => call.url.endsWith('/protection')).length, 1);
  assert.equal((await lstat(join(f.intent, '.send-lock'))).isDirectory(), true);
});
test('primitive publication and lookup reject endpoint changes without dispatch', async t => {
  const { p, intent } = await prepared(t);
  await assert.rejects(publishIntent(intent, TOKEN, { ...options(intent), expectedEndpoint: 'https://other.example/repo.git' }), /endpoint/);
  await assert.rejects(recoverIntent(intent, ROTATED, { expectedEndpoint: 'https://other.example/repo.git' }), /endpoint/);
  assert.equal(p.calls.length, 0);
});

test('complete executable prepare, inspect-intent, send and rotated-token outcome workflow', async t => {
  const f = await files(t); let intent;
  const p = await peer(t, (call, response) => {
    if (call.method === 'GET') json(response, state());
    else if (call.url.endsWith('/outcomes')) json(response, recovered(intent));
    else json(response, publish(intent));
  });
  const prep = await child(['prepare', '--endpoint', p.endpoint, '--token-file', f.token, '--scope-file', f.scope,
    '--principal', ACTOR, '--policy-file', f.policy, '--intent', f.intent]).done;
  assert.equal(prep.code, 0, prep.stderr); intent = await loadIntent(f.intent);
  assert.equal(JSON.parse(prep.stdout).intent_sha256, intent.intent_sha256);
  const shown = await child(['show-intent', '--intent', f.intent]).done;
  assert.equal(shown.code, 0); assert.equal(p.calls.length, 1);
  assert.equal((await child(sendArgs(f, intent)).done).code, 0);
  const rotated = await f.write('rotated', ROTATED);
  assert.equal((await child(outcomeArgs(f, intent, rotated)).done).code, 0);
  assert.deepEqual(p.calls.map(call => [call.method, call.url]), [['GET', '/team/repo.git/api/v1/protection'],
    ['POST', '/team/repo.git/api/v1/protection'], ['POST', '/team/repo.git/api/v1/outcomes']]);
});
test('broken executable stdout preserves and reports the confirmed terminal on stderr', { timeout: 10000 }, async t => {
  let arrived, reply; const wait = new Promise(resolve => { arrived = resolve; });
  const { f, intent } = await prepared(t, (_, response, intent) => { reply = () => json(response, publish(intent)); arrived(); });
  const running = child(sendArgs(f, intent)); t.after(() => { if (running.process.exitCode === null) running.process.kill('SIGKILL'); });
  await wait; running.process.stdout.destroy(); reply(); const output = await running.done;
  assert.equal(output.code, 4, output.stderr);
  const error = JSON.parse(output.stderr); assert.equal(error.outcome_unknown, false);
  assert.equal(error.observation.summary.state, 'committed');
  assert.equal(JSON.parse(await readFile(join(f.intent, 'terminal.json'), 'utf8')).reply.outcome, 'committed');
});
