// Browser protocol tests with real production modules and a controlled HTTP
// transport. These are not evidence that the native node/server has been run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { Transport, hex, utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fastForwardCommand, requestBody, requestPath, requestKey, publication, recovery }
  from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';

const href = 'https://forge.test/repo.git/ui/pulls/';
const token = '12'.repeat(32), nonce = '34'.repeat(16);
const scope = { tenant: 'tenant', repository: 'repository', incarnation: 'incarnation', format: 'sha1' };
const fields = (format = 'sha1') => ({ object_format: format, pull_request_version: 7,
  source_ref: 'refs/heads/topic+&%é', source_tip: 'a'.repeat(format === 'sha1' ? 40 : 64),
  target_ref: 'refs/heads/main', target_tip: 'b'.repeat(format === 'sha1' ? 40 : 64) });
const pending = (format = 'sha1') => ({ scope: { ...scope, format }, number: 2, action: 'fast-forward',
  fields: fields(format), observedTx: null, observedPrincipal: null });
function receipt(p = pending(), outcome = 'committed') {
  const f = p.fields;
  return { schema_version: 1, type: 'fast_forward_merge_publication',
    tenant_id: p.scope.tenant, repository_id: p.scope.repository, repository_incarnation: p.scope.incarnation,
    object_format: p.scope.format, principal_id: 'ab'.repeat(16), action: 'fast-forward', number: p.number,
    pull_request_version: f.pull_request_version, source_ref: f.source_ref, source_ref_hex: hex(utf8.encode(f.source_ref)),
    target_ref: f.target_ref, target_ref_hex: hex(utf8.encode(f.target_ref)),
    source_tip: `${p.scope.format}:${f.source_tip}`, target_tip: `${p.scope.format}:${f.target_tip}`,
    tx_id: 'transaction', outcome, decision_sequence: 9,
    repository_commit_id: outcome === 'committed' ? 'commit-record' : null,
    refusal_record_id: outcome === 'refused' ? 'refusal-record' : null,
    refusal_code: outcome === 'refused' ? 'NonFastForwardRefused' : null,
    refusal_code_point: outcome === 'refused' ? 42 : null, delivery_acknowledged: null };
}
const jsonResponse = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' },
});

for (const format of ['sha1', 'sha256']) test(`fast-forward preserves exact ${format} coordinates and native form bytes`, () => {
  const original = fields(format);
  const normalized = fastForwardCommand({ ...original, source_tip: `${format}:${original.source_tip}` });
  assert.deepEqual(normalized, original);
  const body = requestBody('fast-forward', original, null, nonce);
  assert.equal(body.contentType, 'application/x-www-form-urlencoded');
  assert.deepEqual(Object.fromEntries(new URLSearchParams(new TextDecoder().decode(body.bytes))), {
    ...original, pull_request_version: '7',
  });
  assert.match(new TextDecoder().decode(body.bytes), /topic%2B%26%25%C3%A9/);
  assert.ok(body.bytes.length < 8192);
  assert.equal(requestPath(2, 'fast-forward'), 'pulls/2/fast-forward');
  assert.equal(publication(receipt(pending(format)), pending(format), 200).outcome, 'committed');
});

test('fast-forward rejects missing, unknown and inapplicable authority fields', () => {
  for (const name of Object.keys(fields())) {
    const input = fields(); delete input[name]; assert.throws(() => fastForwardCommand(input), undefined, name);
  }
  for (const name of ['policy_epoch', 'force', 'principal_id', 'required_reviewer', 'merge_base', 'candidate_commit', 'title', 'expected_version']) {
    assert.throws(() => fastForwardCommand({ ...fields(), [name]: 1 }), /Unknown or inapplicable/);
  }
  assert.deepEqual(fastForwardCommand(fields()), fields());
});

test('invalid or oversized coordinates cannot be silently normalized to another command', () => {
  for (const changed of [
    { pull_request_version: 0 }, { pull_request_version: '7' }, { pull_request_version: Number.MAX_SAFE_INTEGER },
    { object_format: 'sha256' }, { source_tip: '0'.repeat(40) }, { source_tip: 'A'.repeat(40) },
    { source_tip: fields().target_tip }, { source_ref: fields().target_ref },
    { source_ref: 'refs/tags/topic' }, { source_ref: 'refs/heads/../topic' },
    { source_ref: 'refs/heads/' + 'x'.repeat(1024) }, { source_ref: null },
  ]) assert.throws(() => fastForwardCommand({ ...fields(), ...changed }));
  assert.throws(() => requestBody('fast-forward', fields(), new Uint8Array([1]), nonce), /must not carry a bundle/);
  assert.throws(() => requestBody('fast-forward', fields(), null, 'invalid'), /nonce/);
  assert.deepEqual(fastForwardCommand(fields()), fields());
});

test('retry keys commit to exact coordinates, method, route, scope and credential', async () => {
  const root = { origin: 'https://forge.test', route: '/repo.git' };
  const body = requestBody('fast-forward', fields(), null, nonce);
  const key = (...args) => requestKey(...args, webcrypto);
  const original = [root, 'credential-fingerprint', scope, 2, 'fast-forward', nonce, body];
  const first = await key(...original);
  assert.match(first, /^fgpr1-[0-9a-f]{32}-[0-9a-f]{64}$/);
  assert.equal(await key(...original), first);
  for (const [index, value] of [
    [0, { ...root, route: '/other.git' }], [1, 'other-credential'], [2, { ...scope, incarnation: 'other' }],
    [3, 3], [4, 'merge'], [5, '56'.repeat(16)],
    [6, requestBody('fast-forward', { ...fields(), pull_request_version: 8 }, null, nonce)],
  ]) {
    const changed = [...original]; changed[index] = value;
    assert.notEqual(await key(...changed), first);
  }
  const reordered = Object.fromEntries(Object.entries(fields()).reverse());
  const same = requestBody('fast-forward', reordered, null, nonce);
  assert.deepEqual(same.bytes, body.bytes);
  assert.equal(await key(...original.slice(0, -1), same), first);
});

test('terminal receipts must match all selected coordinates and native reference bytes', () => {
  const p = pending(), good = receipt(p);
  for (const changed of [
    { type: 'reviewed_merge_publication' }, { number: 3 }, { pull_request_version: 8 },
    { action: 'merge' }, { repository_incarnation: 'other' }, { object_format: 'sha256' },
    { source_tip: 'c'.repeat(40) }, { target_tip: 'c'.repeat(40) },
    { source_ref: 'refs/heads/other' }, { target_ref: null }, { source_ref_hex: 'ff' },
    { target_ref_hex: hex(utf8.encode('refs/heads/other')) }, { delivery_acknowledged: true },
    { decision_sequence: 0 }, { outcome: 'undecided' }, { refusal_code: 'refused' },
  ]) assert.throws(() => publication({ ...good, ...changed }, p, 200));
  assert.throws(() => publication(good, { ...p, observedTx: 'another-transaction' }, 200), /identity changed/);
  assert.throws(() => publication(good, { ...p, observedPrincipal: 'cd'.repeat(16) }, 200), /principal changed/);
  assert.throws(() => publication(good, p, 409), /HTTP status/);
  assert.deepEqual(publication(good, p, 200), { terminal: true, outcome: 'committed', tx: 'transaction',
    principal: 'ab'.repeat(16), rcr: 'commit-record', refusal: null, deliveryAcknowledged: null });
});

test('a canonical refusal is terminal but never a successful or acknowledged merge', () => {
  const p = pending(), refused = receipt(p, 'refused');
  assert.deepEqual(publication(refused, p, 409), { terminal: true, outcome: 'refused', tx: 'transaction',
    principal: 'ab'.repeat(16), rcr: null, refusal: 'NonFastForwardRefused', deliveryAcknowledged: null });
  assert.throws(() => publication(refused, p, 200), /HTTP status/);
  assert.throws(() => publication({ ...refused, repository_commit_id: 'commit' }, p, 409), /Conflicting/);
});

test('transport refuses fast-forward without an explicit keyed publication envelope', async () => {
  let calls = 0;
  const transport = new Transport({ href, cryptoImpl: webcrypto, fetchImpl: async () => { calls++; return jsonResponse({}); } });
  await transport.connect(token);
  const valid = { method: 'POST', body: 'command', key: 'original-key', read: false };
  for (const changed of [{ method: 'GET' }, { key: undefined }, { key: '' }, { body: undefined }, { read: true }]) {
    await assert.rejects(transport.request('pulls/2/fast-forward', { ...valid, ...changed }), /explicit POST/);
  }
  await assert.rejects(transport.request('pulls/2/fast-forward?force=1', valid), /explicit POST/);
  await assert.rejects(transport.request('pulls/2/fast-forward/extra', valid), /Invalid API route/);
  assert.equal(calls, 0);
  await transport.request('pulls/2/fast-forward', valid);
  assert.equal(calls, 1);
  transport.disconnect();
});

test('read cancellation cannot abort an in-flight fast-forward and explicit auth is preserved', async () => {
  let capture, release;
  const transport = new Transport({ href, cryptoImpl: webcrypto,
    fetchImpl: (url, options) => { capture = { url, options }; return new Promise(resolve => { release = resolve; }); } });
  await transport.connect(token);
  const body = requestBody('fast-forward', fields(), null, nonce);
  const task = transport.request(requestPath(2, 'fast-forward'), {
    method: 'POST', body: new Blob([body.bytes]), contentType: body.contentType, key: 'original-key', read: false,
  });
  transport.cancelReads();
  assert.equal(capture.options.signal.aborted, false);
  assert.equal(capture.url.href, 'https://forge.test/repo.git/api/v1/pulls/2/fast-forward');
  assert.equal(capture.options.headers.Authorization, `Bearer ${token}`);
  assert.equal(capture.options.headers['Idempotency-Key'], 'original-key');
  assert.equal(capture.options.credentials, 'omit');
  assert.equal(capture.options.mode, 'same-origin');
  assert.equal(capture.options.redirect, 'error');
  assert.deepEqual(new Uint8Array(await capture.options.body.arrayBuffer()), body.bytes);
  release(jsonResponse(receipt()));
  const response = await task;
  assert.equal(publication(response.value, pending(), response.status).terminal, true);
  transport.disconnect();
});

test('absent recovery evidence does not prove non-commit or replace the original transaction', () => {
  const p = pending();
  const reply = { schema_version: 1, type: 'transaction_outcome', tenant_id: scope.tenant,
    repository_id: scope.repository, repository_incarnation: scope.incarnation, principal_id: 'ab'.repeat(16),
    selector: 'transaction', command_index: null, read_only: true, request_reexecuted: false,
    absence_proves_non_commit: false, session_completeness_established: false,
    state: 'key_not_observed', terminal: false, transaction: null, decision: null };
  assert.deepEqual(recovery(reply, p), { terminal: false, state: 'key_not_observed', tx: null, principal: 'ab'.repeat(16) });
  assert.throws(() => recovery({ ...reply, absence_proves_non_commit: true }, p));
  assert.throws(() => recovery(reply, { ...p, observedTx: 'original-transaction' }), /no longer observes/);
});
