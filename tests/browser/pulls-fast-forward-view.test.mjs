import test from 'node:test';
import assert from 'node:assert/strict';
import { fastForwardProposal } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { fixture, observation, response, terminal, missingOutcome, token, until } from './helpers/pulls-workflow-fixture.mjs';

for (const format of ['sha1', 'sha256']) {
  test(`${format}: an observed open PR produces exactly the six native fast-forward fields`, () => {
    const observed = observation(format), before = structuredClone(observed);
    const proposal = fastForwardProposal(observed, observed.binding);
    assert.equal(proposal.number, 7);
    assert.deepEqual(Object.keys(proposal.fields).sort(), ['object_format', 'pull_request_version', 'source_ref', 'source_tip', 'target_ref', 'target_tip']);
    assert.equal(proposal.fields.source_ref, 'refs/heads/topic+one');
    assert.equal(proposal.fields.source_tip, 'a'.repeat(format === 'sha1' ? 40 : 64));
    assert.equal(proposal.fields.pull_request_version, 3);
    assert.deepEqual(observed, before, 'constructing a proposal cannot rewrite the observation');
  });
  test(`${format}: actual page staging ignores editable metadata and creates no network effect`, async () => {
    const f = await fixture({ observed: observation(format) });
    f.node('pr-number').value = '999'; f.node('expected-version').value = '90';
    f.node('source-ref').value = 'refs/heads/other'; f.node('source-tip').value = 'c'.repeat(format === 'sha1' ? 40 : 64);
    f.node('required-reviewers').value = '77'.repeat(16); f.node('confirm').checked = true;
    const reads = f.calls.length; await f.stage();
    const pending = f.client.pending;
    assert.equal(pending.action, 'fast-forward'); assert.equal(pending.number, 7); assert.equal(pending.fields.pull_request_version, 3);
    assert.equal(pending.fields.source_ref, 'refs/heads/topic+one'); assert.equal(pending.bundle_bytes, 0);
    assert.equal(pending.sent, false); assert.equal(f.calls.length, reads); assert.equal(f.node('confirm').checked, false);
    assert.equal(f.node('send').disabled, true); assert.equal(f.node('fast-forward-stage').disabled, true);
    assert.equal(f.client.candidate, null); assert.equal(f.node('merge-stage').disabled, true);
    f.click('send'); assert.equal(f.calls.length, reads, 'preparation is not dispatch or implicit confirmation');
    await f.send();
    assert.equal(f.client.pending, null); assert.match(f.node('status').textContent, /Canonical committed/);
    assert.equal(f.node('fast-forward-stage').disabled, true, 'a consumed observation requires explicit reload');
    const write = f.calls.find(call => call.method === 'POST');
    assert.ok(write.url.endsWith('/pulls/7/fast-forward')); assert.match(write.headers['Idempotency-Key'], /^fgpr1-/);
    assert.equal(write.headers['Content-Type'], 'application/x-www-form-urlencoded');
    assert.deepEqual(Object.fromEntries(new URLSearchParams(write.bytes)), Object.fromEntries(Object.entries(pending.fields).map(([key, value]) => [key, String(value)])));
    await f.loadPr(7); assert.equal(f.node('fast-forward-stage').disabled, false, 'fresh permitted twin can be prepared');
    f.disconnect();
  });
}

test('closed, absent, equal-tip, byte-only, corrupt and cross-scope observations fail closed', async () => {
  const cases = [
    value => { value.reply.pull_request.state = 'closed'; },
    value => { value.reply.found = false; value.reply.pull_request = null; },
    value => { value.reply.pull_request.version = Number.MAX_SAFE_INTEGER; },
    value => { value.reply.pull_request.data.source_tip = value.reply.pull_request.data.target_tip; },
    value => { value.reply.pull_request.data.source_ref = null; value.reply.pull_request.data.source_ref_hex = '726566732f68656164732fff'; },
    value => { value.reply.pull_request.data.source_ref_hex = '61'; },
    value => { value.reply.pull_request.data.object_format = 'sha256'; },
    value => { value.reply.repository_incarnation = 'other-incarnation'; },
    value => { value.head = `alg:2:${'8'.repeat(64)}`; },
    value => { value.head = null; },
  ];
  for (const change of cases) {
    const value = observation(); change(value); assert.throws(() => fastForwardProposal(value, observation().binding));
    assert.equal(fastForwardProposal(observation(), observation().binding).number, 7, 'near-identical permitted twin');
  }
  assert.throws(() => fastForwardProposal(observation(), null));
  for (const change of cases.slice(0, 5).filter((_, index) => index !== 1)) {
    const value = observation(); change(value); const f = await fixture({ observed: value });
    assert.equal(f.node('fast-forward-stage').disabled, true);
    f.node('fast-forward-stage').dispatchEvent(new Event('click', { cancelable: true }));
    await until(() => !f.client.busy); assert.equal(f.client.pending, null);
    assert.equal(f.calls.filter(call => call.method === 'POST').length, 0); f.disconnect();
  }
});

test('a canonical policy refusal is terminal and never falls back to force or a candidate merge', async () => {
  const observed = observation();
  const f = await fixture({ observed, dispatch: call => response(terminal(observed, Object.fromEntries(new URLSearchParams(call.bytes)), 'refused'), 409) });
  await f.stage(); await f.send();
  assert.equal(f.client.pending, null); assert.match(f.node('status').textContent, /Canonical refused.*PublicationPolicyRefused/);
  assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
  assert.equal(f.node('fast-forward-stage').disabled, true); f.disconnect();
});

test('lost reply, absent recovery, exported receipt and explicit retry preserve the original bytes and key', async () => {
  const observed = observation(); let writes = 0;
  const dispatch = call => { if (++writes === 1) throw new Error('reply lost after transmission');
    return response(terminal(observed, Object.fromEntries(new URLSearchParams(call.bytes)))); };
  const f = await fixture({ observed, dispatch }); await f.stage(); const original = f.client.pending;
  await f.send(); assert.equal(f.client.pending.key, original.key); assert.equal(f.client.pending.sent, true);
  assert.match(f.node('status').textContent, /Outcome remains unknown/); assert.equal(f.node('discard').disabled, true);
  f.click('receipt-download'); await until(() => f.downloads.length === 1);
  const saved = f.downloads[0].text; assert.equal(saved.includes(token), false); assert.equal(JSON.parse(saved).request.bundle_base64, null);
  f.disconnect();
  const restored = await fixture({ observed, dispatch });
  restored.node('receipt-import-file').files = [new File([saved], 'recovery.json')]; restored.submit('receipt-import');
  await until(() => restored.client.pending && !restored.client.busy);
  assert.equal(restored.client.pending.key, original.key); assert.equal(restored.node('confirm').checked, false);
  assert.equal(writes, 1, 'receipt import must never send');
  restored.click('recover'); await until(() => !restored.client.busy && /Outcome unknown/.test(restored.node('status').textContent));
  assert.equal(restored.client.pending.key, original.key); assert.equal(writes, 1);
  const lookup = restored.calls.find(call => call.url.endsWith('/outcomes'));
  assert.equal(lookup.bytes, null); assert.equal(lookup.headers['Idempotency-Key'], original.key);
  await restored.send(); assert.equal(restored.client.pending, null);
  const first = f.calls.find(call => call.url.endsWith('/fast-forward'));
  const retry = restored.calls.find(call => call.url.endsWith('/fast-forward'));
  assert.equal(first.bytes, retry.bytes); assert.equal(first.headers['Idempotency-Key'], retry.headers['Idempotency-Key']);
  assert.equal(writes, 2); restored.disconnect();
});

test('a second PR selection or input edit cannot replace a saved merge command', async () => {
  const f = await fixture(); await f.stage(); const pending = f.client.pending;
  f.click('new-pr'); f.node('source-tip').value = 'c'.repeat(40);
  f.node('metadata').dispatchEvent(new Event('input'));
  assert.deepEqual(f.client.pending, pending); assert.equal(f.node('metadata-stage').disabled, true);
  await f.loadPr(7); assert.equal(f.node('fast-forward-stage').disabled, true);
  f.node('fast-forward-stage').dispatchEvent(new Event('click', { cancelable: true }));
  await until(() => /existing prepared request/.test(f.node('status').textContent));
  assert.deepEqual(f.client.pending, pending); assert.equal(f.calls.filter(call => call.method === 'POST').length, 0);
  f.disconnect();
});

test('disconnect during dispatch clears views but preserves unresolved responsibility', async () => {
  let sent;
  const f = await fixture({ dispatch: call => new Promise((resolve, reject) => {
    sent = call; call.signal.addEventListener('abort', () => reject(new Error('disconnected after transmission')), { once: true });
  }) });
  await f.stage(); const key = f.client.pending.key;
  f.node('confirm').checked = true; f.node('confirm').dispatchEvent(new Event('change')); f.click('send');
  await until(() => sent); f.disconnect(); await until(() => !f.client.busy);
  assert.equal(sent.signal.aborted, true); assert.equal(f.client.pending.key, key); assert.equal(f.client.pending.sent, true);
  assert.equal(f.node('selected').textContent, ''); assert.equal(f.node('token').value, '');
  assert.match(f.node('status').textContent, /does not prove non-commit/);
});

test('a mismatched receipt remains unknown and a revoked credential never erases its request', async () => {
  for (const revoke of [false, true]) {
    const observed = observation();
    const f = await fixture({ observed, dispatch: call => revoke ? response({}, 401)
      : response({ ...terminal(observed, Object.fromEntries(new URLSearchParams(call.bytes))), target_tip: 'c'.repeat(40) }) });
    await f.stage(); const key = f.client.pending.key; await f.send();
    assert.equal(f.client.pending.key, key); assert.equal(f.client.pending.sent, true);
    assert.equal(f.client.connected, !revoke); assert.match(f.node('status').textContent, /Outcome remains unknown/);
    f.disconnect();
  }
});
