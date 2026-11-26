import test from 'node:test';
import assert from 'node:assert/strict';
import { transactionForm } from '../../crates/fgit-node/src/smart_http/server/browser/branches.mjs';
import { prepareBranchTransaction, validateBranchIntent, publication, branchRecord, validateBranchRecord,
  parse, encode, hash } from '../../scripts/operator/branch_transaction.mjs';
import { sendBranchTransaction, recoverBranchTransaction } from '../../scripts/operator/branch_transaction_transport.mjs';
import { fixture, TOKEN, ROTATED, AGENT, hex } from './fixtures/branch_transaction_peer.mjs';

for (const format of ['sha1', 'sha256']) {
  test(format + ': one exact mixed batch uses canonical native form and confirms its complete effects', async t => {
    const f = await fixture(t, format), intent = prepareBranchTransaction(f.input, TOKEN);
    assert.deepEqual(validateBranchIntent(intent), intent);
    assert.equal(intent.body, transactionForm({ object_format: format, changes: f.input.changes }));
    assert.ok(!encode(intent).includes(Buffer.from(TOKEN)));
    const result = await sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key });
    assert.equal(result.outcome.state, 'committed'); assert.equal(result.publication.decision_sequence, '18446744073709551615');
    assert.deepEqual([...f.state.refs], [[hex('refs/heads/main'), f.oid('4')], [hex('refs/heads/topic'), f.oid('2')], [hex('refs/heads/new'), f.oid('2')]]);
    assert.equal(f.calls.length, 3); assert.equal(f.calls.filter(c => c.path.endsWith('/transaction')).length, 1);
    assert.ok(f.calls.every(c => c.headers['idempotency-key'] === intent.key && c.method === 'POST'));
    assert.ok(f.calls.every(c => c.headers['user-agent'] === 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)'));
    const record = branchRecord(intent, result);
    assert.deepEqual(validateBranchRecord(parse(encode(record), false, 320 * 1024), intent), record);
  });
  test(format + ': atomic raw-byte rename preserves non-UTF-8 references and exact old-tip lease', async t => {
    const f = await fixture(t, format), source = hex(Buffer.concat([Buffer.from('refs/heads/raw-'), Buffer.from([255])]));
    const target = hex(Buffer.concat([Buffer.from('refs/heads/raw-'), Buffer.from([254])]));
    f.state.refs.set(source, f.oid('5'));
    f.input.changes = [{ operation: 'delete', ref_hex: source, expected_commit: f.oid('5') },
      { operation: 'create', ref_hex: target, new_commit: f.oid('5') }];
    const intent = prepareBranchTransaction(f.input, TOKEN), result = await sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key });
    assert.equal(result.publication.updates[0].ref, null); assert.equal(result.publication.updates[1].ref, null);
    assert.equal(f.state.refs.has(source), false); assert.equal(f.state.refs.get(target), f.oid('5'));
    assert.equal(f.decisions.size, 1);
  });
  test(format + ': one stale lease retains the native refusal for the entire batch', async t => {
    const f = await fixture(t, format), before = [...f.state.refs];
    f.input.changes[1].expected_commit = f.oid('f');
    const intent = prepareBranchTransaction(f.input, TOKEN);
    const result = await sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key });
    assert.equal(result.outcome.state, 'refused'); assert.deepEqual([...f.state.refs], before);
    const retry = await sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key, known: result.outcome, publication: result.publication });
    assert.equal(retry.dispatched, false); assert.equal(f.calls.filter(c => c.path.endsWith('/transaction')).length, 1);
  });
  test(format + ': lost publication response recovers the original key after rotation without replaying changed refs', async t => {
    const f = await fixture(t, format), intent = prepareBranchTransaction(f.input, TOKEN); f.state.drop = true;
    let uncertain;
    await assert.rejects(sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key }), error => {
      uncertain = error; return error.dispatched === true && error.outcomeUnknown === true;
    });
    const original = branchRecord(intent, null, uncertain); assert.equal(original.outcome.state, 'key_not_observed');
    f.state.refs.delete(hex('refs/heads/new')); f.state.refs.set(hex('refs/heads/main'), f.oid('6'));
    const result = await recoverBranchTransaction(intent, ROTATED, { known: original.outcome });
    assert.equal(result.outcome.state, 'committed'); assert.equal(result.dispatched, false);
    assert.equal(f.state.refs.has(hex('refs/heads/new')), false); assert.equal(f.state.refs.get(hex('refs/heads/main')), f.oid('6'));
    assert.equal(f.calls.filter(c => c.path.endsWith('/transaction')).length, 1);
    assert.equal(f.calls.at(-1).headers.authorization, 'Bearer ' + ROTATED);
    assert.equal(hash(encode(validateBranchIntent(intent))), hash(encode(intent)));
  });
}
test('intent edits, duplicate destinations, invalid raw refs, hash-domain changes and force all refuse offline', async t => {
  const f = await fixture(t), intent = prepareBranchTransaction(f.input, TOKEN);
  for (const change of [v => v.changes[0].expected_commit = f.oid('a'), v => v.changes.reverse(), v => v.scope.principal_id = '9'.repeat(32),
    v => v.key += 'x', v => v.body += '&force=true', v => v.endpoint += '/other', v => v.credential_sha256 = 'f'.repeat(64)]) {
    const changed = structuredClone(intent); change(changed); assert.throws(() => validateBranchIntent(changed));
  }
  for (const changes of [[], [...f.input.changes, f.input.changes[0]], [{ ...f.input.changes[0], force: true }],
    [{ ...f.input.changes[0], expected_commit: '0'.repeat(40) }], [{ ...f.input.changes[0], new_commit: 'a'.repeat(64) }],
    [{ ...f.input.changes[0], ref_hex: hex('refs/tags/a') }], [{ ...f.input.changes[0], ref_hex: hex('refs/heads/a..b') }],
    Array.from({ length: 33 }, (_, i) => ({ operation: 'create', ref_hex: hex('refs/heads/b' + i), new_commit: f.oid('1') }))]) {
    assert.throws(() => prepareBranchTransaction({ ...f.input, changes }, TOKEN));
  }
  assert.equal(f.calls.length, 0);
});
test('sponsored credentials never acquire atomic receive scope; original-key recovery keeps native principal validation', async t => {
  const f = await fixture(t), intent = prepareBranchTransaction(f.input, TOKEN);
  assert.throws(() => prepareBranchTransaction(f.input, AGENT), /agent_receive_unsupported/);
  await assert.rejects(sendBranchTransaction(intent, AGENT, { confirmKey: intent.key }), /agent_receive_unsupported/);
  await assert.rejects(sendBranchTransaction(intent, ROTATED, { confirmKey: intent.key }), /original_key_and_credential/);
  await assert.rejects(sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key + 'x' }), /original_key_and_credential/);
  assert.equal(f.calls.length, 0);
  const missing = await recoverBranchTransaction(intent, AGENT);
  assert.equal(missing.outcome.state, 'key_not_observed'); assert.equal(missing.outcome.absence_proves_non_commit, false);
  assert.equal(f.calls.length, 1);
});
for (const mutate of [r => r.atomic = false, r => r.updates.pop(), r => r.updates.reverse(), r => r.updates[0].force = true,
  r => r.updates[0].new_commit = 'sha1:' + 'e'.repeat(40), r => r.updates[0].ref = 'refs/heads/other',
  r => r.repository_incarnation = '9'.repeat(32), r => r.operation = 'create', r => r.principal_id = '9'.repeat(32),
  r => r.decision_sequence = '18446744073709551616']) {
  test('malformed or substituted publication never becomes a trusted observation: ' + mutate, async t => {
    const f = await fixture(t), intent = prepareBranchTransaction(f.input, TOKEN);
    f.state.tamper = (r, c) => { if (c.path.endsWith('/transaction')) mutate(r); };
    await assert.rejects(sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key }), e => e.dispatched && e.publication === null);
    assert.equal(f.calls.filter(c => c.path.endsWith('/transaction')).length, 1);
    f.state.tamper = null;
    assert.equal((await recoverBranchTransaction(intent, TOKEN)).outcome.state, 'committed');
  });
}
test('conflicting outcome and publication cannot be combined, including saved records', async t => {
  const f = await fixture(t), intent = prepareBranchTransaction(f.input, TOKEN);
  const result = await sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key });
  const record = branchRecord(intent, result); record.outcome.decision.repository_commit_id = 'other-rcr';
  assert.throws(() => validateBranchRecord(record, intent), /outcome_conflict/);
  const changed = { ...result.publication, decision_sequence: '4' };
  assert.throws(() => branchRecord(intent, { ...result, publication: changed }), /outcome_conflict/);
  assert.throws(() => publication(result.publication, intent, 409));
});
test('confirmation failure retains the complete native publication for read-only recovery', async t => {
  const f = await fixture(t), intent = prepareBranchTransaction(f.input, TOKEN);
  f.state.hook = (call, _req, res) => {
    if (call.path.endsWith('/outcomes') && f.decisions.size) { res.writeHead(503); res.end(); return true; }
    return false;
  };
  let retained;
  await assert.rejects(sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key }), error => {
    retained = branchRecord(intent, null, error); return error.phase === 'confirmation' && error.publication?.outcome === 'committed';
  });
  f.state.hook = null;
  const result = await recoverBranchTransaction(intent, ROTATED, { known: retained.outcome, publication: retained.publication });
  assert.equal(result.outcome.state, 'committed'); assert.equal(result.dispatched, false);
});
test('callers cannot change scope, leases, body or key while preflight is awaiting the server', async t => {
  const f = await fixture(t), intent = prepareBranchTransaction(f.input, TOKEN), original = structuredClone(intent);
  let release, seen;
  const entered = new Promise(resolve => { seen = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  f.state.hook = async call => {
    if (call.path.endsWith('/outcomes') && !f.decisions.size) { seen(); await gate; }
    return false;
  };
  const pending = sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key });
  await entered;
  intent.changes[0].new_commit = f.oid('f'); intent.scope.principal_id = '9'.repeat(32);
  intent.key += 'changed'; intent.body += '&force=true';
  release();
  const result = await pending;
  assert.equal(result.outcome.state, 'committed');
  const sent = f.calls.find(call => call.path.endsWith('/transaction'));
  assert.equal(sent.body, original.body); assert.equal(sent.headers['idempotency-key'], original.key);
  assert.equal(f.state.refs.get(hex('refs/heads/main')), f.oid('4'));
});
test('redirects and request-level errors remain unresolved rather than invented terminal refusals', async t => {
  const f = await fixture(t), intent = prepareBranchTransaction(f.input, TOKEN);
  f.state.hook = (call, _req, res) => {
    if (!call.path.endsWith('/transaction')) return false;
    res.writeHead(307, { Location: f.endpoint + '/elsewhere' }); res.end(); return true;
  };
  await assert.rejects(sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key }), e => e.status === 307 && e.dispatched);
  assert.equal(f.calls.length, 2); assert.equal(f.decisions.size, 0);
  f.state.hook = (call, _req, res) => {
    if (!call.path.endsWith('/transaction')) return false;
    res.writeHead(409, { 'Content-Type': 'application/json' }); res.end('{"type":"source_error","code":"branch_operation_refused"}'); return true;
  };
  await assert.rejects(sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key }), e => e.publication === null && e.dispatched);
});
test('deadline and pre-cancellation stop owned network work without publishing', async t => {
  const f = await fixture(t), intent = prepareBranchTransaction(f.input, TOKEN); f.state.delay = 60;
  await assert.rejects(sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key, timeoutMs: 10 }));
  assert.equal(f.decisions.size, 0);
  const stop = new AbortController(); stop.abort(); const calls = f.calls.length;
  await assert.rejects(sendBranchTransaction(intent, TOKEN, { confirmKey: intent.key, signal: stop.signal }));
  assert.equal(f.calls.length, calls);
});
test('strict JSON rejects duplicated, rounded or noncanonical counters', () => {
  for (const source of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a":9007199254740992}', '{"a":1e2}', '{"a":-0}']) {
    assert.throws(() => parse(Buffer.from(source), true));
  }
  assert.equal(parse(Buffer.from('{"decision_sequence":18446744073709551615}'), true).decision_sequence, '18446744073709551615');
});
