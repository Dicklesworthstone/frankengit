// Adapter contracts; native file-backed tests separately establish admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { metadataCommand, Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { requestBody, requestPath, publication } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { actor, token, ids, scope, row, show, metadata, json, options } from './pulls-fixtures.mjs';

const fields = extra => metadata({ expected_version: 2, target_ref: 'refs/heads/release', ...extra });
const terminal = extra => ({ ...ids, type: 'pull_request_publication', number: 1, action: 'retarget',
  expected_version: 2, principal_id: actor, tx_id: 'retarget-tx', decision_sequence: 10,
  outcome: 'committed', repository_commit_id: 'retarget-rcr', refusal_record_id: null,
  refusal_code: null, refusal_code_point: null, delivery_acknowledged: null, ...extra });
async function setup(respond = () => json(terminal())) {
  const calls = [];
  const client = new PullClient(options(async (url, init) => {
    calls.push({ url: String(url), ...init, bytes: init.body ? Buffer.from(await init.body.arrayBuffer()) : null });
    return calls.length === 1 ? json(show({ pull_request: row(1, { version: 2 }) })) : respond(calls.at(-1), calls.length - 1);
  }));
  await client.connect(token); await client.show(1); return { client, calls };
}

for (const algorithm of ['sha1', 'sha256']) test(`retarget seals complete ${algorithm} metadata under its distinct route`, () => {
  const width = algorithm === 'sha1' ? 40 : 64;
  const input = fields({ object_format: algorithm, source_tip: 'a'.repeat(width), target_tip: 'b'.repeat(width), body: 'Preserved é\r\n&principal=admin' });
  const prepared = requestBody('retarget', input, null, 'a'.repeat(32));
  assert.equal(requestPath(1, 'retarget'), 'pulls/1/retarget');
  const form = new URLSearchParams(new TextDecoder().decode(prepared.bytes));
  assert.equal(form.get('target_ref'), 'refs/heads/release'); assert.equal(form.get('body'), input.body);
  assert.equal(form.has('principal'), false); assert.equal([...form].length, 8);
  assert.throws(() => requestBody('retarget', input, new Uint8Array([1]), 'a'.repeat(32)), /must not carry a bundle/);
});

test('retarget is available as an explicit browser action and prepares without dispatch', async () => {
  const html = await readFile(new URL('../../crates/fgit-node/src/smart_http/server/browser/pulls.html', import.meta.url), 'utf8');
  assert.match(html, /<option value="retarget">Change target branch<\/option>/);
  assert.match(html, /keeping its source branch/); assert.match(html, /earlier reviews become stale/);
  const { client, calls } = await setup();
  const pending = await client.stageMetadata(1, 'retarget', fields());
  assert.equal(calls.length, 1); assert.equal(pending.sent, false); assert.equal(pending.bundle_bytes, 0);
});

test('lost retarget response retries exact key and bytes and cannot alias an ordinary update', async () => {
  const { client, calls } = await setup((_, index) => { if (index === 1) throw Error('response lost'); return json(terminal()); });
  const input = fields(), pending = await client.stageMetadata(1, 'retarget', input);
  input.target_ref = 'refs/heads/changed-after-staging';
  await assert.rejects(client.send(), error => error.outcomeUnknown === true);
  await assert.rejects(client.stageMetadata(1, 'update', fields({ expected_version: 3 })), /existing prepared request/);
  const saved = client.exportReceipt(); assert.equal(saved.includes(token), false);
  const result = await client.send(); assert.equal(result.outcome, 'committed');
  assert.equal(calls[1].url.endsWith('/pulls/1/retarget'), true);
  assert.equal(calls[1].headers['Idempotency-Key'], pending.key);
  assert.deepEqual(calls[1].bytes, calls[2].bytes);
  const restoredCalls = [];
  const restored = new PullClient(options(async (url, init) => { restoredCalls.push({ url: String(url), ...init }); return json(terminal()); }));
  await restored.connect(token); await restored.restoreReceipt(saved);
  assert.equal(restored.pending.action, 'retarget'); assert.equal(restored.pending.key, pending.key);
  assert.equal(restoredCalls.length, 0); await restored.send();
  assert.equal(restoredCalls[0].url.endsWith('/pulls/1/retarget'), true);
  assert.equal(restoredCalls[0].headers['Idempotency-Key'], pending.key);
});

test('retarget refuses invalid authority/version inputs and mismatched action receipts', () => {
  for (const extra of [{ expected_version: 0 }, { expected_version: -1 }, { expected_version: undefined },
    { expected_version: Number.MAX_SAFE_INTEGER }, { force: true }, { principal: actor }]) {
    assert.throws(() => metadataCommand('retarget', fields(extra)));
  }
  const pending = { scope, number: 1, action: 'retarget', fields: fields(), observedTx: null, observedPrincipal: null };
  assert.equal(publication(terminal(), pending, 200).outcome, 'committed');
  for (const extra of [{ action: 'update' }, { action: 'reopen' }, { number: 2 }, { expected_version: 1 }]) {
    assert.throws(() => publication(terminal(extra), pending, 200));
  }
});

test('retarget cannot escape another browser transport profile', async () => {
  const transport = new Transport({ ...options(() => assert.fail('cross-profile request dispatched')),
    href: 'https://forge.example/team/repo.git/ui/source/', pageSuffix: '/ui/source/' });
  await transport.connect(token);
  await assert.rejects(transport.request('pulls/1/retarget', { method: 'POST', body: 'x=1', key: 'original', read: false }));
});
