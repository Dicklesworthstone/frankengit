// Real clients and Web Crypto with native-schema peers; enforcement is tested in Rust.
import test from 'node:test';
import assert from 'node:assert/strict';
import { protectionPolicy, protectionChanges } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { editorPolicy } from '../../crates/fgit-node/src/smart_http/server/browser/protection-view.mjs';
import { TOKEN, ADMIN, REVIEWER, hex, policy, snapshot, response, harness, webcrypto } from './protection-fixtures.mjs';

const queueOnly = () => ({ administrators: [ADMIN], branches: [{
  reference_hex: hex('refs/heads/main'), required_reviewers: [], require_merge_queue: true,
}] });

test('omitted and false queue requirements preserve historical receipt bytes and keys', async () => {
  const old = policy(), explicit = policy(); explicit.branches[0].require_merge_queue = false;
  assert.deepEqual(protectionPolicy(explicit), protectionPolicy(old));
  const cryptoImpl = { subtle: webcrypto.subtle, getRandomValues: bytes => bytes.fill(7) };
  const a = harness({ cryptoImpl }), b = harness({ cryptoImpl,
    respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: explicit })) : null });
  await a.ready(); await b.ready();
  const original = await a.client.stage(old), retained = await b.client.stage(explicit);
  assert.deepEqual(retained.intent, original.intent);
  assert.equal(new URLSearchParams(retained.intent.body).has('require_merge_queue'), false);
  assert.equal(b.client.exportReceipt(), a.client.exportReceipt());
});

test('queue-only branches require a strict true boolean and zero approvals', () => {
  const selected = queueOnly();
  assert.deepEqual(protectionPolicy(selected), selected);
  for (const value of [null, 'true', 'false', 1, 0, [], {}]) {
    assert.throws(() => protectionPolicy({ ...selected, branches: [{ ...selected.branches[0], require_merge_queue: value }] }));
  }
  for (const value of [false, undefined]) {
    const branch = { ...selected.branches[0], require_merge_queue: value };
    if (value === undefined) delete branch.require_merge_queue;
    assert.throws(() => protectionPolicy({ ...selected, branches: [branch] }));
  }
  assert.throws(() => protectionPolicy({ ...selected, branches: [{ ...selected.branches[0], required_approvals: 1 }] }));
  assert.deepEqual(protectionPolicy({ ...selected, branches: [{ ...selected.branches[0], required_approvals: 0 }] }), selected);
});

test('standalone edits preserve observed queues and require an explicit boolean to remove them', () => {
  const selected = queueOnly(), branch = selected.branches[0], reference = branch.reference_hex;
  assert.deepEqual(editorPolicy(ADMIN, `${reference} -`, selected.branches), selected);
  assert.deepEqual(editorPolicy(ADMIN, `${reference} - 0 true`, [], null, []), selected);
  assert.deepEqual(editorPolicy(ADMIN, `${reference} ${REVIEWER} all`, selected.branches), {
    administrators: [ADMIN], branches: [{ ...branch, required_reviewers: [REVIEWER] }],
  });
  assert.deepEqual(editorPolicy(ADMIN, `${reference} ${REVIEWER} all false`, selected.branches), policy());
  assert.throws(() => editorPolicy(ADMIN, `${reference} - 0 false`, selected.branches));
  for (const value of ['1', 'yes', 'TRUE', 'null']) {
    assert.throws(() => editorPolicy(ADMIN, `${reference} ${REVIEWER} all ${value}`, selected.branches));
  }
});

test('queue-only changes, additions and removals remain visible in replacement previews', () => {
  const before = policy(), after = policy(); after.branches[0].require_merge_queue = true;
  const change = protectionChanges(before, after).branches[0];
  assert.equal(change.change, 'updated');
  assert.equal(change.require_merge_queue_before, false); assert.equal(change.require_merge_queue_after, true);
  const empty = { administrators: [ADMIN], branches: [] };
  assert.equal(protectionChanges(empty, queueOnly()).branches[0].change, 'added');
  const removed = protectionChanges(queueOnly(), empty).branches[0];
  assert.equal(removed.change, 'removed'); assert.equal(removed.require_merge_queue_after, false);
});

for (const format of ['sha1', 'sha256']) {
  test(`${format}: a lost queue-policy reply retries exact saved bytes and rejects queue-bit tampering`, async () => {
    const selected = queueOnly();
    const h = harness({ format, respond: call => {
      if (call.method === 'POST') throw new Error('connection lost after request');
      return response(snapshot(format, { policy: selected }));
    } });
    await h.ready();
    const pending = await h.client.stage(selected);
    assert.deepEqual(new URLSearchParams(pending.intent.body).getAll('require_merge_queue'), [selected.branches[0].reference_hex]);
    await assert.rejects(h.client.send(), /connection lost/);
    const saved = h.client.exportReceipt();
    const restored = harness({ format }); await restored.client.connect(TOKEN, ADMIN);
    await restored.client.restoreReceipt(saved);
    assert.deepEqual(restored.client.pending.intent, pending.intent);
    await restored.client.send();
    assert.equal(restored.calls.length, 1);
    assert.equal(restored.calls[0].body, pending.intent.body);
    assert.equal(restored.calls[0].headers['Idempotency-Key'], pending.intent.key);
    const tampered = JSON.parse(saved); tampered.intent.replacement.branches[0].require_merge_queue = false;
    const fresh = harness({ format }); await fresh.client.connect(TOKEN, ADMIN);
    await assert.rejects(fresh.client.restoreReceipt(JSON.stringify(tampered)));
    assert.equal(fresh.calls.length, 0); assert.equal(fresh.client.pending, null);
  });
}
