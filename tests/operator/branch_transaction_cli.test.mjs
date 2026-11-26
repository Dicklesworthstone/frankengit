import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, lstat, symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../../scripts/fg_branch_transaction.mjs';
import { loadIntent, loadRecord, tokenFile } from '../../scripts/operator/branch_transaction_files.mjs';
import { fixture, TOKEN, ROTATED, AGENT, hex } from './fixtures/branch_transaction_peer.mjs';

async function local(t, format = 'sha1') {
  const f = await fixture(t, format), root = await mkdtemp(join(tmpdir(), 'fg-branch-transaction-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, 'input.json'), token = join(root, 'token'), rotated = join(root, 'rotated'), job = join(root, 'job');
  await writeFile(input, JSON.stringify(f.input), { mode: 0o600 });
  await writeFile(token, TOKEN + '\n', { mode: 0o600 }); await writeFile(rotated, ROTATED + '\n', { mode: 0o600 });
  const invoke = async (args, options = {}) => {
    const out = [], errors = [];
    const code = await run(args, { output: async text => out.push(text), errorOutput: async text => errors.push(text), ...options });
    return { code, out, errors, value: out.length ? JSON.parse(out.at(-1)) : null, error: errors.length ? JSON.parse(errors.at(-1)) : null };
  };
  const prepare = () => invoke(['prepare', '--input', input, '--token-file', token, '--request-dir', job]);
  return { ...f, root, inputPath: input, token, rotated, job, invoke, prepare };
}
for (const format of ['sha1', 'sha256']) {
  test(format + ': CLI prepares privately, inspects offline, sends once and retains the native result', async t => {
    const f = await local(t, format), prepared = await f.prepare();
    assert.equal(prepared.code, 0); assert.equal(f.calls.length, 0);
    const pin = prepared.value.intent_sha256, record = join(f.root, 'result.json');
    assert.equal((await lstat(f.job)).mode & 0o777, 0o700);
    assert.equal((await lstat(join(f.job, 'intent.json'))).mode & 0o777, 0o600);
    const inspected = await f.invoke(['inspect', '--request-dir', f.job, '--confirm', pin]);
    assert.equal(inspected.code, 0); assert.deepEqual(inspected.value.intent.changes, f.input.changes);
    assert.equal(f.calls.length, 0);
    const sent = await f.invoke(['send', '--request-dir', f.job, '--confirm', pin, '--token-file', f.token, '--record', record]);
    assert.equal(sent.code, 0); assert.equal(sent.value.state, 'committed');
    assert.equal(sent.value.publication.updates.length, 3); assert.equal(sent.value.publication.decision_sequence, '18446744073709551615');
    const intent = await loadIntent(f.job, pin), retained = await loadRecord(record, intent);
    assert.equal(retained.outcome.state, 'committed'); assert.equal(retained.dispatched, true);
    assert.ok(!(await readFile(join(f.job, 'intent.json'))).includes(Buffer.from(TOKEN)));
    assert.ok(!(await readFile(record)).includes(Buffer.from(TOKEN)));
    const retry = await f.invoke(['send', '--request-dir', f.job, '--confirm', pin, '--token-file', f.token,
      '--record', join(f.root, 'retry.json'), '--known', record]);
    assert.equal(retry.code, 0); assert.equal(retry.value.dispatched, false);
    assert.equal(f.calls.filter(c => c.path.endsWith('/transaction')).length, 1);
  });
  test(format + ': lost reply is durably recorded and recovered after token rotation without another send', async t => {
    const f = await local(t, format), prepared = await f.prepare(), pin = prepared.value.intent_sha256;
    const uncertain = join(f.root, 'uncertain.json'); f.state.drop = true;
    const lost = await f.invoke(['send', '--request-dir', f.job, '--confirm', pin, '--token-file', f.token, '--record', uncertain]);
    assert.equal(lost.code, 3); assert.equal(lost.error.record_saved, true); assert.equal(lost.error.retained_result.dispatched, true);
    f.state.refs.delete(hex('refs/heads/new'));
    const recovered = await f.invoke(['recover', '--request-dir', f.job, '--confirm', pin, '--token-file', f.rotated,
      '--known', uncertain, '--record', join(f.root, 'recovered.json')]);
    assert.equal(recovered.code, 0); assert.equal(recovered.value.dispatched, false);
    assert.equal(f.calls.filter(c => c.path.endsWith('/transaction')).length, 1); assert.equal(f.state.refs.has(hex('refs/heads/new')), false);
  });
}
test('CLI native refusal preserves all original refs and has its distinct exit status', async t => {
  const f = await local(t), prepared = await f.prepare(), before = [...f.state.refs]; f.state.refuse = true;
  const result = await f.invoke(['send', '--request-dir', f.job, '--confirm', prepared.value.intent_sha256,
    '--token-file', f.token, '--record', join(f.root, 'refusal.json')]);
  assert.equal(result.code, 1); assert.equal(result.value.state, 'refused'); assert.deepEqual([...f.state.refs], before);
});
test('existing result files, wrong confirmation pins and rotated send credentials refuse before network', async t => {
  const f = await local(t), prepared = await f.prepare(), pin = prepared.value.intent_sha256, record = join(f.root, 'existing.json');
  await writeFile(record, 'keep', { mode: 0o600 });
  const base = ['send', '--request-dir', f.job, '--confirm', pin, '--token-file', f.token, '--record', record];
  assert.equal((await f.invoke(base)).code, 2);
  const badPin = [...base]; badPin[4] = '0'.repeat(64);
  assert.equal((await f.invoke(badPin)).code, 2);
  const rotated = [...base]; rotated[6] = f.rotated; rotated[8] = join(f.root, 'new.json');
  assert.equal((await f.invoke(rotated)).code, 2);
  assert.equal(f.calls.length, 0); assert.equal(await readFile(record, 'utf8'), 'keep');
});
test('a separate outcome credential requires a prepared writer binding before network or result custody', async t => {
  const f = await local(t), prepared = await f.prepare(), record = join(f.root, 'split.json');
  const args = ['--request-dir', f.job, '--confirm', prepared.value.intent_sha256,
    '--token-file', f.token, '--outcome-token-file', f.rotated, '--record', record];
  const sending = await f.invoke(['send', ...args]);
  assert.equal(sending.code, 2);
  assert.equal(sending.error.code, 'branch_transaction_writer_scope_required');
  const recovering = await f.invoke(['recover', ...args]);
  assert.equal(recovering.code, 2);
  assert.equal(recovering.error.code, 'branch_transaction_option');
  assert.equal(f.calls.length, 0);
  await assert.rejects(lstat(record), { code: 'ENOENT' });
});
test('preparation pins the entire writer scope into the exact form and accepts only an explicit true binding', async t => {
  const f = await local(t);
  for (const invalid of [false, null, 'true']) {
    await writeFile(f.inputPath, JSON.stringify({ ...f.input, bind_writer_scope: invalid }));
    assert.equal((await f.prepare()).code, 2);
    await assert.rejects(lstat(f.job), { code: 'ENOENT' });
  }
  await writeFile(f.inputPath, JSON.stringify({ ...f.input, bind_writer_scope: true }));
  const prepared = await f.prepare();
  assert.equal(prepared.code, 0);
  const intent = await loadIntent(f.job, prepared.value.intent_sha256);
  const { tenant_id, repository_id, repository_incarnation, principal_id } = f.input.scope;
  assert.equal(intent.bind_writer_scope, true);
  assert.equal(new URLSearchParams(intent.body).get('expected_scope'),
    [tenant_id, repository_id, repository_incarnation, principal_id].join(':'));
  assert.equal(f.calls.length, 0);
});
test('split credentials send the pinned writer only to publication and the reader to both lookups', async t => {
  const f = await local(t, 'sha256');
  await writeFile(f.inputPath, JSON.stringify({ ...f.input, bind_writer_scope: true }));
  const prepared = await f.prepare(), pin = prepared.value.intent_sha256;
  const intent = await loadIntent(f.job, pin), expected = new URLSearchParams(intent.body).get('expected_scope');
  f.state.hook = (call, _request, response) => {
    const writing = call.path.endsWith('/branches/transaction');
    if (call.headers.authorization !== 'Bearer ' + (writing ? TOKEN : ROTATED) ||
        writing && call.form.get('expected_scope') !== expected) {
      response.writeHead(403); response.end(); return true;
    }
    // The schema peer models ref commands. Its test hook consumes the scope assertion.
    if (writing) call.form.delete('expected_scope');
    return false;
  };
  const record = join(f.root, 'split.json');
  const sent = await f.invoke(['send', '--request-dir', f.job, '--confirm', pin, '--token-file', f.token,
    '--outcome-token-file', f.rotated, '--record', record]);
  assert.equal(sent.code, 0);
  assert.equal(sent.value.outcome.state, 'committed');
  assert.deepEqual(f.calls.map(call => [call.path.split('/').at(-1), call.headers.authorization]), [
    ['outcomes', 'Bearer ' + ROTATED], ['transaction', 'Bearer ' + TOKEN], ['outcomes', 'Bearer ' + ROTATED],
  ]);
  assert.equal(f.calls[1].body, intent.body);
  assert.ok(!(await readFile(record)).includes(Buffer.from(ROTATED)));
});
test('invalid private files, aliases and Git worktree custody are refused', async t => {
  const f = await local(t);
  await chmod(f.token, 0o644); assert.equal((await f.prepare()).code, 2); await chmod(f.token, 0o600);
  const alias = join(f.root, 'alias'); await symlink(f.token, alias);
  assert.equal((await f.invoke(['prepare', '--input', f.inputPath, '--token-file', alias, '--request-dir', f.job])).code, 2);
  await writeFile(join(f.root, '.git'), 'gitdir: elsewhere', { mode: 0o600 });
  assert.equal((await f.prepare()).code, 2); assert.equal(f.calls.length, 0);
});
test('prepare rejects sponsored receive scope without creating request custody', async t => {
  const f = await local(t); await writeFile(f.token, AGENT, { mode: 0o600 });
  const prepared = await f.prepare(); assert.equal(prepared.code, 2);
  assert.match(prepared.error.code, /agent_receive_unsupported/);
  await assert.rejects(lstat(f.job), { code: 'ENOENT' }); assert.equal(f.calls.length, 0);
});
test('credential custody accepts only the exact bearer and at most one LF', async t => {
  const f = await local(t);
  for (const token of [TOKEN, AGENT]) {
    for (const suffix of ['', '\n']) {
      await writeFile(f.token, token + suffix, { mode: 0o600 }); assert.equal(await tokenFile(f.token), token);
    }
    for (const text of [token + '\r\n', token + '\n\n', '\ufeff' + token, token + ' ', token.toUpperCase()]) {
      await writeFile(f.token, text, { mode: 0o600 }); await assert.rejects(tokenFile(f.token));
    }
  }
  assert.equal(f.calls.length, 0);
});
test('request custody cannot be overwritten or accepted after a byte edit', async t => {
  const f = await local(t), prepared = await f.prepare(), pin = prepared.value.intent_sha256;
  assert.equal((await f.prepare()).code, 2);
  const file = join(f.job, 'intent.json'), bytes = await readFile(file);
  await writeFile(file, Buffer.concat([bytes, Buffer.from(' ')]), { mode: 0o600 });
  assert.equal((await f.invoke(['inspect', '--request-dir', f.job, '--confirm', pin])).code, 2);
  assert.equal(f.calls.length, 0);
});
test('output failure retains committed result custody and exposes its path without leaking tokens', async t => {
  const f = await local(t), prepared = await f.prepare(), pin = prepared.value.intent_sha256, record = join(f.root, 'result.json');
  const result = await f.invoke(['send', '--request-dir', f.job, '--confirm', pin, '--token-file', f.token, '--record', record],
    { output: async () => { throw new Error('output closed'); } });
  assert.equal(result.code, 3); assert.equal(result.error.record_saved, true); assert.equal(result.error.record, record);
  assert.equal(result.error.retained_result.publication.outcome, 'committed');
  assert.ok(!result.errors.join('').includes(TOKEN));
  assert.equal((await loadRecord(record, await loadIntent(f.job, pin))).outcome.state, 'committed');
});
test('contradictory confirmation retains the valid publication and compatible prior outcome for recovery', async t => {
  const f = await local(t), prepared = await f.prepare(), pin = prepared.value.intent_sha256, record = join(f.root, 'contradiction.json');
  f.state.tamper = (reply, call) => {
    if (call.path.endsWith('/outcomes') && reply.terminal) reply.transaction.tx_id = 'different-transaction';
  };
  const failed = await f.invoke(['send', '--request-dir', f.job, '--confirm', pin, '--token-file', f.token, '--record', record]);
  assert.equal(failed.code, 3); assert.equal(failed.error.record_saved, true);
  const retained = await loadRecord(record, await loadIntent(f.job, pin));
  assert.equal(retained.publication.outcome, 'committed'); assert.equal(retained.outcome.state, 'key_not_observed');
  assert.equal(retained.error.code, 'branch_transaction_outcome_conflict'); assert.equal(retained.error.phase, 'confirmation');
  f.state.tamper = null;
  const recovered = await f.invoke(['recover', '--request-dir', f.job, '--confirm', pin, '--token-file', f.rotated,
    '--known', record, '--record', join(f.root, 'recovered.json')]);
  assert.equal(recovered.code, 0); assert.equal(recovered.value.dispatched, false);
  assert.equal(recovered.value.publication.tx_id, retained.publication.tx_id);
  assert.equal(f.calls.filter(call => call.path.endsWith('/transaction')).length, 1);
});
test('competing result publication keeps one complete create-only record and one canonical decision', async t => {
  const f = await local(t), prepared = await f.prepare(), pin = prepared.value.intent_sha256, record = join(f.root, 'shared.json');
  f.state.delay = 20;
  const args = ['send', '--request-dir', f.job, '--confirm', pin, '--token-file', f.token, '--record', record];
  const results = await Promise.all([f.invoke(args), f.invoke(args)]);
  assert.equal(results.filter(result => result.code === 0).length, 1);
  assert.ok(results.some(result => [2, 3].includes(result.code)));
  const saved = await loadRecord(record, await loadIntent(f.job, pin));
  assert.equal(saved.outcome.state, 'committed'); assert.equal(f.decisions.size, 1);
  assert.equal((await lstat(record)).nlink, 1);
});
test('known record from another original intent cannot authorize a new transaction', async t => {
  const f = await local(t), prepared = await f.prepare(), pin = prepared.value.intent_sha256, record = join(f.root, 'known.json');
  await f.invoke(['send', '--request-dir', f.job, '--confirm', pin, '--token-file', f.token, '--record', record]);
  const second = join(f.root, 'second');
  const next = await f.invoke(['prepare', '--input', f.inputPath, '--token-file', f.token, '--request-dir', second]);
  const before = f.calls.length;
  const rejected = await f.invoke(['recover', '--request-dir', second, '--confirm', next.value.intent_sha256,
    '--token-file', f.token, '--known', record, '--record', join(f.root, 'other.json')]);
  assert.equal(rejected.code, 2); assert.equal(f.calls.length, before);
});
test('pre-cancelled invocation and unknown or duplicated options do no work', async t => {
  const f = await local(t), stop = new AbortController(); stop.abort();
  assert.equal((await f.invoke(['prepare', '--input', f.inputPath, '--token-file', f.token, '--request-dir', f.job], { signal: stop.signal })).code, 2);
  for (const args of [['send'], ['prepare', '--input', f.inputPath, '--input', f.inputPath], ['force'], ['recover', '--timeout-ms', '0']]) {
    assert.equal((await f.invoke(args)).code, 2);
  }
  assert.equal(f.calls.length, 0);
});
