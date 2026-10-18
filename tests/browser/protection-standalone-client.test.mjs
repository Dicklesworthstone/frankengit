// Uses the production shared ProtectionClient, Response streams and WebCrypto
// with explicit native HTTP fixtures. No Rust-node or real-browser pass implied.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { ProtectionClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { protectionClientHref, editorPolicy, startProtection } from '../../crates/fgit-node/src/smart_http/server/browser/protection-view.mjs';
import { harness, deferred, snapshot, actor, reviewer, token, hex } from './protection-standalone-fixture.mjs';
const href = 'https://forge.example/tenant/repo.git/ui/protection/';
const response = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
function nativeSnapshot() {
  const { scope, head, version, epoch, policy } = snapshot();
  return { type: 'repository_review_protection', schema_version: 1, tenant_id: scope.tenant, repository_id: scope.repository,
    repository_incarnation: scope.incarnation, object_format: scope.format, source_head: head, version, policy_epoch: epoch,
    installed: true, enabled: true, policy, complete: true, transaction_created: false, published: false };
}
function publication(intent, committed = true) {
  return { type: 'review_protection_publication', schema_version: 1, tenant_id: intent.source.scope.tenant,
    repository_id: intent.source.scope.repository, repository_incarnation: intent.source.scope.incarnation, object_format: intent.source.scope.format,
    principal_id: intent.principal, expected_version: intent.source.version, expected_epoch: intent.source.epoch,
    resulting_epoch: committed ? String(BigInt(intent.source.epoch) + 1n) : null, tx_id: 'tx:exact-protection', outcome: committed ? 'committed' : 'refused',
    decision_sequence: '9007199254740997', repository_commit_id: committed ? 'rcr:protection' : null,
    refusal_record_id: committed ? null : 'refusal:protection', refusal_code: committed ? null : 'PolicyDenied',
    refusal_code_point: committed ? null : 1, delivery_acknowledged: null };
}
function outcome(state = 'key_not_observed') {
  const scope = snapshot().scope, present = !['key_not_observed', 'seal_not_observed'].includes(state);
  return { type: 'transaction_outcome', schema_version: 1, tenant_id: scope.tenant, repository_id: scope.repository,
    repository_incarnation: scope.incarnation, principal_id: actor, selector: 'transaction', command_index: null, state,
    terminal: state === 'committed', transaction: present ? { tx_id: 'tx:exact-protection', seal_id: 'seal:exact',
      request_schema: 'schema:protection', canonical_request_digest: { algorithm: 1, hex: 'ab'.repeat(32) } } : null,
    decision: state === 'committed' ? { kind: 'committed', decision_sequence: 7, repository_commit_id: 'rcr:protection' } : null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
function nativeHarness({ read = () => response(nativeSnapshot()), send, recover = () => response(outcome()) } = {}) {
  const requests = [];
  const client = new ProtectionClient({ href: protectionClientHref(href), cryptoImpl: webcrypto,
    fetchImpl: async (url, options) => {
      const request = { url: url.href, ...options }; requests.push(request);
      if (url.pathname.endsWith('/outcomes')) return recover(request);
      if (options.method === 'GET') return read(request);
      return send ? send(request, client.pending.intent) : response(publication(client.pending.intent));
    } });
  return { ...harness({}, client), requests };
}
const confirm = h => { h.get('confirm').checked = true; };

test('actual shared-client load method drives independent inspection (no fabricated inspect API)', async () => {
  const h = nativeHarness(); await h.connect();
  assert.equal(h.requests.length, 1); assert.equal(h.requests[0].method, 'GET');
  assert.equal(h.requests[0].url, 'https://forge.example/tenant/repo.git/api/v1/protection');
  assert.equal(h.requests[0].headers['Idempotency-Key'], undefined);
  assert.ok(h.get('snapshot').textContent.includes(snapshot().version));
  assert.match(h.get('status').textContent, /No transaction/);
});
test('production entrypoint loads the real shared module without starting the PR page', async () => {
  const h = harness(); let requests = 0;
  const mounted = await startProtection(h.doc, { href, cryptoImpl: webcrypto, fetchImpl: async () => { requests++; return response(nativeSnapshot()); } });
  h.get('token').value = token; h.get('actor').value = actor; await h.get('connect').fire('submit');
  assert.equal(requests, 0); await mounted.inspect(); assert.equal(requests, 1);
  assert.match(h.get('status').textContent, /No transaction/);
});
test('full replacement is staged locally and sent only after a fresh explicit confirmation', async () => {
  const h = nativeHarness(); await h.connect();
  h.get('rules').value = `${hex('refs/heads/topic')} ${reviewer}`;
  await h.mounted.prepare(); assert.equal(h.requests.length, 1); assert.ok(h.client.pending);
  await h.mounted.send(); assert.equal(h.requests.length, 1);
  const original = h.client.pending.intent;
  h.get('administrators').value = 'ff'.repeat(16); h.get('rules').value = '';
  confirm(h); await h.mounted.send();
  assert.equal(h.requests.length, 2); assert.equal(h.requests[1].body, original.body);
  assert.equal(h.requests[1].headers['Idempotency-Key'], original.key);
  assert.equal(new URLSearchParams(h.requests[1].body).get('expected_version'), snapshot().version);
  assert.equal(new URLSearchParams(h.requests[1].body).get('expected_epoch'), snapshot().epoch);
  assert.equal(h.client.pending, null); assert.match(h.get('status').textContent, /committed/);
  assert.equal(h.get('confirm').checked, false); assert.equal(h.get('prepare').disabled, true);
});
test('clearing all rules requires its own explicit stage flag', async () => {
  const h = nativeHarness(); await h.connect(); h.get('rules').value = '';
  await h.mounted.prepare(); assert.equal(h.client.pending, null); assert.match(h.get('status').textContent, /explicit clear/);
  await h.mounted.inspect(); h.get('rules').value = ''; h.get('clear').checked = true; await h.mounted.prepare();
  assert.equal(h.client.pending.intent.clear, true); assert.equal(h.requests.length, 2);
  confirm(h); await h.mounted.send(); assert.equal(new URLSearchParams(h.requests.at(-1).body).get('clear'), 'true');
});
test('removing the acting administrator requires a separate ownership acknowledgment', async () => {
  const h = nativeHarness(); await h.connect(); h.get('administrators').value = reviewer; await h.mounted.prepare();
  confirm(h); await h.mounted.send(); assert.equal(h.requests.length, 1); assert.ok(h.client.pending);
  assert.match(h.get('preview').textContent, /removes the submitting principal/);
  h.get('ownership-confirm').checked = true; confirm(h); await h.mounted.send(); assert.equal(h.requests.length, 2);
});
test('failed submission retains exact body and key, forbids replacement, and supports explicit unchanged retry', async () => {
  let attempt = 0;
  const h = nativeHarness({ send: (_request, intent) => { if (++attempt === 1) throw new Error('connection lost'); return response(publication(intent)); } });
  await h.connect(); await h.mounted.prepare(); const original = h.client.pending.intent;
  confirm(h); await h.mounted.send(); assert.equal(h.client.pending.sent, true); assert.match(h.get('status').textContent, /Outcome unknown/);
  await h.mounted.inspect(); assert.equal(h.requests.length, 2); await h.mounted.prepare(); assert.equal(h.client.pending.intent.key, original.key);
  confirm(h); await h.mounted.send(true);
  assert.equal(h.requests[1].body, h.requests[2].body); assert.equal(h.requests[1].headers['Idempotency-Key'], h.requests[2].headers['Idempotency-Key']);
  assert.equal(h.client.pending, null);
});
test('native refusal remains a refusal with no automatic reload or command change', async () => {
  const h = nativeHarness({ send: (_request, intent) => response(publication(intent, false), 409) });
  await h.connect(); await h.mounted.prepare(); confirm(h); await h.mounted.send();
  assert.equal(h.client.pending, null); assert.equal(h.requests.length, 2); assert.match(h.get('status').textContent, /refused/);
  assert.match(h.get('terminal').textContent, /PolicyDenied/);
});
test('a mismatched native principal never becomes a successful replacement in the view', async () => {
  const h = nativeHarness({ send: (_request, intent) => response({ ...publication(intent), principal_id: reviewer }) });
  await h.connect(); await h.mounted.prepare(); confirm(h); await h.mounted.send();
  assert.ok(h.client.pending); assert.equal(h.get('terminal').textContent, ''); assert.match(h.get('status').textContent, /Outcome unknown/);
});
test('original-key absence and undecided outcomes cannot erase the request or imply rollback', async () => {
  let state = 'key_not_observed'; const h = nativeHarness({ recover: () => response(outcome(state)) });
  await h.connect(); await h.mounted.prepare(); const key = h.client.pending.intent.key;
  for (state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
    await h.mounted.recover(); assert.equal(h.client.pending.intent.key, key); assert.match(h.get('status').textContent, /does not prove non-commit/);
    assert.equal(h.requests.at(-1).body, undefined); assert.equal(h.requests.at(-1).headers['Idempotency-Key'], key);
  }
  state = 'committed'; await h.mounted.recover(); assert.equal(h.client.pending, null); assert.match(h.get('status').textContent, /committed/);
});
test('exported receipts are token-free, block discard, and restore without resubmission', async () => {
  const h = nativeHarness(); await h.connect(); await h.mounted.prepare(); h.mounted.exportReceipt();
  const saved = h.get('receipt').value, key = h.client.pending.intent.key;
  assert.equal(saved.includes(token), false); assert.equal(h.client.pending.exported, true);
  await h.get('discard').fire('click'); assert.ok(h.client.pending);
  const other = nativeHarness(); await other.connect(false); other.get('receipt').value = saved; await other.mounted.restore();
  assert.equal(other.requests.length, 0); assert.equal(other.client.pending.intent.key, key); assert.equal(other.client.pending.sent, true);
  assert.equal(other.get('send').disabled, true); confirm(other); await other.mounted.send(true);
  assert.equal(other.requests.length, 1); assert.equal(other.client.pending, null);
});
test('rotated credentials can recover only the original principal and key, never replay', async () => {
  const h = nativeHarness({ recover: () => response(outcome('committed')) }); await h.connect(); await h.mounted.prepare();
  h.mounted.exportReceipt(); const saved = h.get('receipt').value, original = h.client.pending.intent;
  h.mounted.disconnect(); h.get('token').value = 'c2'.repeat(32); h.get('actor').value = actor; h.get('recovery-only').checked = true;
  await h.get('connect').fire('submit'); assert.equal(h.client.recoveryOnly, true);
  confirm(h); await h.mounted.send(true); await h.mounted.inspect(); assert.equal(h.requests.length, 1);
  await h.mounted.recover(); assert.equal(h.requests.length, 2); assert.equal(h.requests[1].headers['Idempotency-Key'], original.key);
  assert.equal(h.requests[1].body, undefined); assert.ok(saved.includes(original.key));
  assert.equal(h.client.pending, null); assert.equal(h.get('reload').disabled, true);
});
test('rotated recovery also restores a receipt after losing the original page', async () => {
  const original = nativeHarness(); await original.connect(); await original.mounted.prepare(); original.mounted.exportReceipt();
  const h = nativeHarness({ recover: () => response(outcome('committed')) });
  h.get('token').value = 'c2'.repeat(32); h.get('actor').value = actor; h.get('recovery-only').checked = true; await h.get('connect').fire('submit');
  h.get('receipt').value = original.get('receipt').value; await h.mounted.restore();
  assert.ok(h.client.pending); assert.equal(h.requests.length, 0); await h.mounted.recover(); assert.equal(h.client.pending, null);
});
test('tampering with an exported replacement cannot create a new recovery command', async () => {
  const original = nativeHarness(); await original.connect(); await original.mounted.prepare(); original.mounted.exportReceipt();
  const receipt = JSON.parse(original.get('receipt').value); receipt.intent.replacement.administrators = [reviewer];
  const h = nativeHarness(); await h.connect(false); h.get('receipt').value = JSON.stringify(receipt); await h.mounted.restore();
  assert.equal(h.client.pending, null); assert.equal(h.requests.length, 0); assert.match(h.get('status').textContent, /exact command/);
});
test('invalid native policy and editor bounds are refused instead of partially rendering or truncating', async () => {
  const h = nativeHarness({ read: () => response({ ...nativeSnapshot(), complete: false }) }); await h.connect();
  assert.equal(h.get('snapshot').textContent, ''); assert.equal(h.get('prepare').disabled, true);
  assert.throws(() => editorPolicy('x'.repeat(2049), ''), /limit/);
  assert.throws(() => editorPolicy(actor, `${hex('refs/heads/main')} ${reviewer}\n`.repeat(65)), /Too many/);
  assert.throws(() => editorPolicy(actor, `${hex('refs/heads/main')} ${Array(33).fill(reviewer).join(',')}`), /32 reviewers/);
});
test('native byte-only branch identities survive load, editor roundtrip and stage', async () => {
  const value = nativeSnapshot(); value.policy.branches[0].reference_hex = hex('refs/heads/') + 'ff';
  const h = nativeHarness({ read: () => response(value) }); await h.connect(); await h.mounted.prepare();
  assert.equal(h.client.pending.intent.replacement.branches[0].reference_hex, value.policy.branches[0].reference_hex);
});
test('disconnect during native transmission fences the reply but retains original responsibility', async () => {
  const deferredReply = deferred(); const h = nativeHarness({ send: () => deferredReply.promise });
  await h.connect(); await h.mounted.prepare(); const intent = h.client.pending.intent; confirm(h); const pending = h.mounted.send();
  h.mounted.disconnect(); deferredReply.resolve(response(publication(intent))); await pending;
  assert.equal(h.client.pending.intent.key, intent.key); assert.equal(h.get('terminal').textContent, ''); assert.equal(h.get('preview').textContent, '');
  assert.match(h.get('status').textContent, /Disconnected/); assert.equal(h.get('export').disabled, false);
});
test('revocation during publication clears credentials but does not erase the original key', async () => {
  const h = nativeHarness({ send: () => response({}, 401) }); await h.connect(); await h.mounted.prepare(); confirm(h); await h.mounted.send();
  assert.equal(h.client.connected, false); assert.ok(h.client.pending); assert.equal(h.get('actor').value, '');
  assert.equal(h.get('preview').textContent, ''); assert.equal(h.get('export').disabled, false);
});
