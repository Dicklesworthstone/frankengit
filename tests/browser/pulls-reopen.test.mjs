// Executable browser/transport contracts for the existing native reopen route.
// These tests do not substitute for the native forge lifecycle or a live-node run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { Transport, metadataCommand } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { requestBody, requestPath, publication } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { actor, token, ids, scope, row, show, metadata, json, options, deferred } from './pulls-fixtures.mjs';

const fields = extra => metadata({ expected_version: 2, ...extra });
const closed = extra => show({ pull_request: row(1, { version: 2, state: 'closed' }), ...extra });
const terminal = (extra = {}) => ({ ...ids, type: 'pull_request_publication', number: 1, action: 'reopen',
  expected_version: 2, principal_id: actor, tx_id: 'reopen-tx', decision_sequence: 10,
  outcome: 'committed', repository_commit_id: 'reopen-rcr', refusal_record_id: null,
  refusal_code: null, refusal_code_point: null, delivery_acknowledged: null, ...extra });
const absent = () => ({ ...ids, type: 'transaction_outcome', selector: 'transaction', command_index: null,
  principal_id: actor, read_only: true, request_reexecuted: false, absence_proves_non_commit: false,
  session_completeness_established: false, state: 'key_not_observed', terminal: false, transaction: null, decision: null });
const pending = () => ({ scope, number: 1, action: 'reopen', fields: fields(), observedTx: null, observedPrincipal: null });
async function setup(respond = () => json(terminal())) {
  const calls = [];
  const client = new PullClient(options(async (url, init) => {
    const call = { url: String(url), ...init, bytes: init.body ? Buffer.from(await init.body.arrayBuffer()) : null };
    calls.push(call);
    return calls.length === 1 ? json(closed()) : respond(call, calls.length - 1);
  }));
  await client.connect(token); await client.show(1);
  return { client, calls };
}

for (const algorithm of ['sha1', 'sha256']) test(`reopen preserves complete ${algorithm} metadata without a candidate bundle`, () => {
  const count = algorithm === 'sha1' ? 40 : 64;
  const input = fields({ object_format: algorithm, source_tip: `${algorithm}:${'a'.repeat(count)}`,
    target_tip: `${algorithm}:${'b'.repeat(count)}`, body: 'Keep Unicode 🦀 and literal %26\n&principal=admin' });
  const body = requestBody('reopen', input, null, 'a'.repeat(32));
  assert.equal(requestPath(1, 'reopen'), 'pulls/1/reopen');
  assert.equal(body.contentType, 'application/x-www-form-urlencoded');
  assert.deepEqual(body.fields, { ...input, source_tip: 'a'.repeat(count), target_tip: 'b'.repeat(count) });
  const form = new URLSearchParams(new TextDecoder().decode(body.bytes));
  assert.equal(form.get('body'), input.body); assert.equal(form.get('expected_version'), '2');
  assert.equal(form.has('principal'), false); assert.equal([...form].length, 8);
  assert.throws(() => requestBody('reopen', input, new Uint8Array([1]), 'a'.repeat(32)), /must not carry a bundle/);
});

test('the browser exposes reopening as an explicit metadata proposal, not an automatic send', async () => {
  const html = await readFile(new URL('../../crates/fgit-node/src/smart_http/server/browser/pulls.html', import.meta.url), 'utf8');
  assert.match(html, /<option value="reopen">Reopen closed PR<\/option>/);
  assert.match(html, /positive expected version/); assert.match(html, /not a merged one/);
  const { client, calls } = await setup();
  const proposal = await client.stageMetadata(1, 'reopen', fields());
  assert.equal(calls.length, 1); assert.equal(proposal.sent, false); assert.equal(proposal.bundle_bytes, 0);
  assert.equal(client.candidate, null); assert.equal(proposal.fields.expected_version, 2);
});

test('reopen sends the exact prepared bytes to the native route and validates its terminal receipt', async () => {
  const { client, calls } = await setup(); const input = fields();
  const proposal = await client.stageMetadata(1, 'reopen', input);
  input.title = 'Changed after staging'; input.source_tip = 'd'.repeat(40);
  const result = await client.send();
  assert.equal(calls.length, 2); assert.equal(calls[1].url, 'https://forge.example/team/repo.git/api/v1/pulls/1/reopen');
  assert.equal(calls[1].method, 'POST'); assert.equal(calls[1].headers['Idempotency-Key'], proposal.key);
  assert.equal(calls[1].headers.Authorization, `Bearer ${token}`);
  assert.equal(new URLSearchParams(calls[1].bytes.toString()).get('title'), proposal.fields.title);
  assert.equal(result.outcome, 'committed'); assert.equal(result.rcr, 'reopen-rcr');
  assert.equal(result.deliveryAcknowledged, null); assert.equal(client.pending, null);
});

test('lost reopen response retries the same key and bytes, never an implicit update or new version', async () => {
  const { client, calls } = await setup((_, n) => { if (n === 1) throw new Error('response lost'); return json(terminal()); });
  const proposal = await client.stageMetadata(1, 'reopen', fields());
  await assert.rejects(client.send(), error => error.outcomeUnknown === true);
  assert.equal(client.pending.key, proposal.key); assert.equal(client.pending.sent, true);
  await assert.rejects(client.stageMetadata(1, 'update', fields({ expected_version: 3 })), /existing prepared request/);
  assert.throws(() => client.discardUnsent(), /dispatched or exported/);
  assert.equal((await client.send()).outcome, 'committed');
  assert.equal(calls[1].url, calls[2].url); assert.equal(calls[1].headers['Idempotency-Key'], calls[2].headers['Idempotency-Key']);
  assert.deepEqual(calls[1].bytes, calls[2].bytes); assert.equal(calls.length, 3);
});

test('a canonical reopen refusal is terminal but an ordinary conflict response is not', async () => {
  const refusal = terminal({ outcome: 'refused', repository_commit_id: null, refusal_record_id: 'refusal-id', refusal_code: 'stale_version', refusal_code_point: 10 });
  const first = await setup(() => json(refusal, 409)); await first.client.stageMetadata(1, 'reopen', fields());
  assert.equal((await first.client.send()).outcome, 'refused'); assert.equal(first.client.pending, null);
  const second = await setup(() => json({ error: 'snapshot_moved' }, 409));
  const proposal = await second.client.stageMetadata(1, 'reopen', fields());
  await assert.rejects(second.client.send(), error => error.outcomeUnknown === true);
  assert.equal(second.client.pending.key, proposal.key); assert.equal(second.client.pending.sent, true);
});

test('reopen recovery never turns key absence into non-commit or sends another mutation', async () => {
  const { client, calls } = await setup(() => json(absent()));
  const proposal = await client.stageMetadata(1, 'reopen', fields());
  const result = await client.recover();
  assert.equal(result.terminal, false); assert.equal(client.pending.key, proposal.key);
  assert.equal(calls[1].url.endsWith('/outcomes'), true); assert.equal(calls[1].body, undefined);
  assert.equal(calls[1].headers['Idempotency-Key'], proposal.key); assert.equal(calls.length, 2);
});

test('reopen receipt restores with the original token and preserves command identity across sessions', async () => {
  const first = await setup(); const proposal = await first.client.stageMetadata(1, 'reopen', fields());
  const saved = first.client.exportReceipt(); assert.equal(saved.includes(token), false);
  assert.throws(() => first.client.discardUnsent(), /dispatched or exported/);
  const calls = [], restored = new PullClient(options(async (url, init) => { calls.push({ url: String(url), ...init }); return json(terminal()); }));
  await restored.connect(token); await restored.restoreReceipt(saved);
  assert.equal(calls.length, 0); assert.equal(restored.pending.key, proposal.key); assert.equal(restored.pending.action, 'reopen');
  assert.equal(restored.pending.sent, true); assert.equal(restored.pending.exported, true);
  assert.equal((await restored.send()).outcome, 'committed');
  assert.equal(calls[0].headers['Idempotency-Key'], proposal.key); assert.equal(calls[0].url.endsWith('/pulls/1/reopen'), true);
});

for (const [name, mutate] of [
  ['action', r => { r.request.action = 'update'; }],
  ['version', r => { r.request.fields.expected_version += 1; }],
  ['number', r => { r.request.number = 2; }],
  ['tip', r => { r.request.fields.source_tip = 'd'.repeat(40); }],
  ['principal injection', r => { r.request.fields.principal = actor; }],
]) test(`reopen recovery refuses a changed ${name} without dispatch`, async () => {
  const first = await setup(); await first.client.stageMetadata(1, 'reopen', fields());
  const receipt = JSON.parse(first.client.exportReceipt()); mutate(receipt);
  const restored = new PullClient(options(() => assert.fail('invalid receipt dispatched'))); await restored.connect(token);
  await assert.rejects(restored.restoreReceipt(JSON.stringify(receipt))); assert.equal(restored.pending, null);
});

test('reopen refuses new-stream, unsafe and missing versions or forged authority before transport', () => {
  for (const extra of [{ expected_version: 0 }, { expected_version: -1 }, { expected_version: undefined },
    { expected_version: Number.MAX_SAFE_INTEGER }, { force: true }, { principal: actor }, { policy_epoch: 1 }]) {
    assert.throws(() => metadataCommand('reopen', fields(extra)));
  }
  for (const action of ['Reopen', 'reopen/merge', '../reopen', 'reopen?force=true']) assert.throws(() => requestPath(1, action));
});

test('reopen terminal receipt cannot substitute another command, repository, actor or result', () => {
  assert.equal(publication(terminal(), pending(), 200).outcome, 'committed');
  for (const extra of [{ action: 'update' }, { number: 2 }, { expected_version: 1 }, { type: 'candidate_review_publication' },
    { repository_incarnation: 'other' }, { object_format: 'sha256' }, { delivery_acknowledged: true },
    { refusal_record_id: 'also-refused' }]) assert.throws(() => publication(terminal(extra), pending(), 200));
  assert.throws(() => publication(terminal(), pending(), 409));
  assert.throws(() => publication(terminal(), { ...pending(), observedTx: 'different-tx' }, 200));
  assert.throws(() => publication(terminal(), { ...pending(), observedPrincipal: '4'.repeat(32) }, 200));
});

test('reopening does not broaden any other browser transport profile', async () => {
  for (const pageSuffix of ['/ui/source/', '/ui/initial/', '/ui/branches/', '/ui/search/', '/ui/transfers/', '/ui/tags/', '/ui/replay/', '/ui/rebase/']) {
    const transport = new Transport({ ...options(() => assert.fail('cross-profile request dispatched')),
      href: `https://forge.example/team/repo.git${pageSuffix}`, pageSuffix });
    await transport.connect(token);
    await assert.rejects(transport.request('pulls/1/reopen', { method: 'POST', body: 'x=1', key: 'original', read: false }));
  }
});

test('disconnect during reopen preserves responsibility and rejects a late success response', async () => {
  const wait = deferred(), { client } = await setup(() => wait.promise);
  const proposal = await client.stageMetadata(1, 'reopen', fields());
  const sent = client.send(); client.disconnect(); wait.resolve(json(terminal()));
  await assert.rejects(sent, error => error.outcomeUnknown === true);
  assert.equal(client.pending.key, proposal.key); assert.equal(client.pending.sent, true);
  assert.equal(client.connected, false);
});
