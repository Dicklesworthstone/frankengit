// Real clients and Web Crypto; native candidate proof enforcement is Rust-owned.
import test from 'node:test';
import assert from 'node:assert/strict';
import { protectionPolicy, protectionChanges } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { editorPolicy } from '../../crates/fgit-node/src/smart_http/server/browser/protection-view.mjs';
import { TOKEN, ADMIN, REVIEWER, hex, policy, snapshot, response, harness, webcrypto } from './protection-fixtures.mjs';

const check = (job = 'test:日本語') => ({ publisher: '55'.repeat(16), graph_root: '66'.repeat(32), job });
const selected = () => ({ administrators: [ADMIN], branches: [{
  reference_hex: hex('refs/heads/main'), required_reviewers: [], required_candidate_checks: [check()],
}] });

test('empty candidate selectors preserve historical receipt bytes and keys', async () => {
  const old = policy(), explicit = policy(); explicit.branches[0].required_candidate_checks = [];
  assert.deepEqual(protectionPolicy(explicit), protectionPolicy(old));
  const cryptoImpl = { subtle: webcrypto.subtle, getRandomValues: bytes => bytes.fill(7) };
  const a = harness({ cryptoImpl }), b = harness({ cryptoImpl,
    respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: explicit })) : null });
  await a.ready(); await b.ready();
  assert.deepEqual((await b.client.stage(explicit)).intent, (await a.client.stage(old)).intent);
  assert.equal(a.client.exportReceipt(), b.client.exportReceipt());
  assert.equal(new URLSearchParams(b.client.pending.intent.body).has('required_candidate_check'), false);
});

test('candidate-only rules are closed, normalized and share the 32-check bound', () => {
  const row = selected().branches[0];
  assert.deepEqual(protectionPolicy(selected()), selected());
  for (const required_candidate_checks of [null, {}, '[]', [null], [check('')], [check('bad\njob')],
    [check(), check()], [{ ...check(), source_ref_hex: hex('refs/heads/ci') }], [{ ...check(), actor: ADMIN }]]) {
    assert.throws(() => protectionPolicy({ administrators: [ADMIN], branches: [{ ...row, required_candidate_checks }] }));
  }
  const many = Array.from({ length: 31 }, (_, i) => check('job-' + String(i).padStart(2, '0')));
  const ordinary = { ...check('ordinary'), source_ref_hex: hex('refs/heads/ci') };
  const bounded = { administrators: [ADMIN], branches: [{ ...row, required_checks: [ordinary], required_candidate_checks: many }] };
  assert.equal(protectionPolicy(bounded).branches[0].required_candidate_checks.length, 31);
  bounded.branches[0].required_candidate_checks.push(check('overflow'));
  assert.throws(() => protectionPolicy(bounded));
});

test('standalone reviewer and ordinary-check edits retain exact observed candidate selectors', () => {
  const current = selected(), reference = current.branches[0].reference_hex;
  assert.deepEqual(editorPolicy(ADMIN, reference + ' -', current.branches, null, []), current);
  const edited = editorPolicy(ADMIN, reference + ' ' + REVIEWER + ' all', current.branches, null, []);
  assert.deepEqual(edited.branches[0].required_candidate_checks, current.branches[0].required_candidate_checks);
  assert.deepEqual(edited.branches[0].required_reviewers, [REVIEWER]);
  const removed = protectionChanges(current, { administrators: [ADMIN], branches: [] }).branches[0];
  assert.equal(removed.change, 'removed');
  assert.deepEqual(removed.candidate_checks_removed, [check()]);
  const replaced = structuredClone(current); replaced.branches[0].required_candidate_checks = [check('other')];
  const change = protectionChanges(current, replaced).branches[0];
  assert.deepEqual(change.candidate_checks_added, [check('other')]);
  assert.deepEqual(change.candidate_checks_removed, [check()]);
});

for (const format of ['sha1', 'sha256']) {
  test(format + ': candidate policy receipts retain original bytes/key through lost reply and reject selector tampering', async () => {
    const current = selected();
    const h = harness({ format, respond: call => {
      if (call.method === 'POST') throw new Error('connection lost after request');
      return response(snapshot(format, { policy: current }));
    } });
    await h.ready(); const pending = await h.client.stage(current);
    const encoded = current.branches[0].reference_hex + ':' + check().publisher + ':' + check().graph_root + ':' + hex(check().job);
    assert.deepEqual(new URLSearchParams(pending.intent.body).getAll('required_candidate_check'), [encoded]);
    assert.equal(new URLSearchParams(pending.intent.body).has('required_check'), false);
    await assert.rejects(h.client.send(), /connection lost/);
    const saved = h.client.exportReceipt();
    const restored = harness({ format }); await restored.client.connect(TOKEN, ADMIN);
    await restored.client.restoreReceipt(saved);
    assert.deepEqual(restored.client.pending.intent, pending.intent);
    await restored.client.send();
    assert.equal(restored.calls.length, 1);
    assert.equal(restored.calls[0].body, pending.intent.body);
    assert.equal(restored.calls[0].headers['Idempotency-Key'], pending.intent.key);
    const changed = JSON.parse(saved); changed.intent.replacement.branches[0].required_candidate_checks[0].job = 'untrusted';
    const fresh = harness({ format }); await fresh.client.connect(TOKEN, ADMIN);
    await assert.rejects(fresh.client.restoreReceipt(JSON.stringify(changed)));
    assert.equal(fresh.calls.length, 0);
  });
}
