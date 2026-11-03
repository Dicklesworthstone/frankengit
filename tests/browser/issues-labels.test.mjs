// Contract tests of the actual client. Native union/publication/restart tests
// live in the Rust suites; this peer only exercises request and receipt custody.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { IssueClient, mutationRequest, issueHistory, publication }
  from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';

const token = 'c'.repeat(64), ids = { schema_version: 1, tenant_id: 'tenant', repository_id: 'repo' };
const terminal = { ...ids, type: 'issue_publication', principal_id: 'actor', number: 1,
  expected_version: null, action: 'add-labels', command_profile: 'issue.add-labels.v1',
  tx_id: 'addition-tx', outcome: 'committed', decision_sequence: 2,
  repository_commit_id: 'addition-rcr', refusal_record_id: null, refusal_code: null, delivery_acknowledged: null };
const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' },
});
const fresh = fetchImpl => new IssueClient({ href: 'https://forge.example/repo.git/ui/issues/', fetchImpl, cryptoImpl: webcrypto });

test('add-labels canonicalizes exact UTF-8 sets and forbids predecessors and replacement fields', () => {
  const labels = ['\u{10000}', 'bug', '\ue000', 'é'];
  const request = mutationRequest(1, null, 'add-labels', { labels });
  assert.deepEqual(request.fields.labels, ['bug', 'é', '\ue000', '\u{10000}']);
  assert.deepEqual(new URLSearchParams(request.body).getAll('label'), request.fields.labels);
  assert.equal(new URLSearchParams(request.body).has('expected_version'), false);
  assert.deepEqual(labels, ['\u{10000}', 'bug', '\ue000', 'é']);
  for (const version of [undefined, 0, 1, '1', NaN]) {
    assert.throws(() => mutationRequest(1, version, 'add-labels', { labels: ['bug'] }));
  }
  for (const fields of [{}, { labels: [] }, { labels: ['x', 'x'] }, { labels: [''] },
    { labels: ['\0'] }, { labels: ['a\nb'] }, { labels: ['é'.repeat(33)] }, { labels: ['\ud800'] },
    { labels: ['bug'], expected_version: 1 }, { labels: ['bug'], body: 'changed' },
    { labels: ['bug'], principal: 'actor' }, { labels: ['bug'], clear_labels: true },
    { labels: ['bug'], command_profile: 'issue.add-labels.v1' }]) {
    assert.throws(() => mutationRequest(1, null, 'add-labels', fields));
  }
  const maximum = Array.from({ length: 32 }, (_, i) => `label-${i}`);
  assert.equal(mutationRequest(1, null, 'add-labels', { labels: maximum }).fields.labels.length, 32);
  assert.equal(mutationRequest(1, null, 'add-labels', { labels: ['é'.repeat(32)] }).fields.labels[0].length, 32);
  assert.throws(() => mutationRequest(1, null, 'add-labels', { labels: [...maximum, 'extra'] }));
  assert.throws(() => mutationRequest(1, null, 'edit', { labels: ['bug'] }));
  assert.equal(mutationRequest(1, 7, 'edit', { labels: [] }).body, 'expected_version=7&clear_labels=true');
});

test('history accepts canonical additive deltas but refuses empty, duplicate or reordered labels', () => {
  const history = { ...ids, type: 'issue_history', snapshot_token: `alg:1:${'b'.repeat(64)}`,
    after_version: 1, limit: 20, found: true, next_after_version: null,
    issue: { number: 1, version: 2, title: 'x', body: '', labels: ['bug', 'é'], state: 'open',
      opened_by: 'actor', last_actor: 'actor', comments: 0 },
    events: [{ version: 2, actor: 'actor', action: { name: 'add-labels', labels: ['bug', 'é'] } }] };
  assert.equal(issueHistory(history, 1, { after: 1 }).reply.events[0].action.name, 'add-labels');
  for (const labels of [[], ['é', 'bug'], ['bug', 'bug']]) {
    const forged = structuredClone(history); forged.events[0].action.labels = labels;
    assert.throws(() => issueHistory(forged, 1, { after: 1 }));
  }
});

test('lost response retains the original addition across reload and a later strict replacement', async () => {
  const calls = [], decisions = new Map(); let labels = ['existing'], version = 2, loseReply = true;
  const peer = async (url, options) => {
    const call = { url: String(url), ...options }; calls.push(call);
    const key = options.headers['Idempotency-Key'], prior = decisions.get(key);
    if (prior) { assert.equal(call.url, prior.url); assert.equal(call.body, prior.body); return json(prior.reply); }
    const form = new URLSearchParams(call.body); let reply;
    if (call.url.endsWith('/add-labels')) {
      assert.equal(form.has('expected_version'), false);
      labels = [...new Set([...labels, ...form.getAll('label')])].sort();
      reply = terminal;
    } else {
      assert.ok(call.url.endsWith('/edit')); assert.equal(Number(form.get('expected_version')), version);
      labels = form.getAll('label');
      reply = { ...terminal, action: 'edit', expected_version: version, tx_id: 'edit-tx', repository_commit_id: 'edit-rcr' };
      delete reply.command_profile;
    }
    version += 1; decisions.set(key, { ...call, reply });
    if (loseReply) { loseReply = false; throw new TypeError('lost terminal response'); }
    return json(reply);
  };
  const original = fresh(peer); await original.connect(token);
  const input = { labels: ['urgent', 'bug'] }; await original.stage(1, null, 'add-labels', input);
  input.labels[0] = 'modified'; original.pending.fields.labels[0] = 'modified';
  assert.equal(calls.length, 0);
  await assert.rejects(original.send(), error => error.outcomeUnknown === true);
  assert.deepEqual(labels, ['bug', 'existing', 'urgent']);
  const receipt = original.exportReceipt(), key = original.pending.key;
  assert.equal(receipt.includes(token), false);
  const editor = fresh(peer); await editor.connect(token);
  await editor.stage(1, 3, 'edit', { labels: ['existing'] }); await editor.send();
  const restored = fresh(peer); await restored.connect(token); await restored.restoreReceipt(receipt);
  assert.equal(calls.length, 2); assert.equal(restored.pending.key, key);
  assert.deepEqual(restored.pending.fields.labels, ['bug', 'urgent']);
  assert.equal((await restored.send()).tx, 'addition-tx');
  assert.equal(calls[2].body, calls[0].body); assert.equal(calls[2].headers['Idempotency-Key'], key);
  assert.deepEqual(labels, ['existing']); assert.equal(version, 4); assert.equal(decisions.size, 2);
});

test('terminal receipts require the exact additive profile and retain uncertainty on mismatch', async () => {
  for (const reply of [terminal, { ...terminal, outcome: 'refused', repository_commit_id: null,
    refusal_record_id: 'refusal', refusal_code: 'ResourceBudgetExceeded' }]) {
    const status = reply.outcome === 'committed' ? 200 : 409;
    assert.equal(publication(reply, { number: 1, action: 'add-labels', expected_version: null, binding: null }, status).outcome, reply.outcome);
    for (const change of [r => { delete r.command_profile; }, r => { r.command_profile = 'issue.add-labels.v2'; },
      r => { r.expected_version = 2; }, r => { r.action = 'edit'; }, r => { r.delivery_acknowledged = true; }]) {
      const forged = structuredClone(reply); change(forged);
      const client = fresh(async () => json(forged, status)); await client.connect(token);
      await client.stage(1, null, 'add-labels', { labels: ['bug'] }); const key = client.pending.key;
      await assert.rejects(client.send(), error => error.outcomeUnknown === true);
      assert.equal(client.pending.key, key);
    }
  }
});

test('saved label intents reject changed labels, predecessor, action or encoded body without sending', async () => {
  const client = fresh(() => assert.fail('preparation sends nothing')); await client.connect(token);
  await client.stage(1, null, 'add-labels', { labels: ['urgent', 'bug'] }); const receipt = client.exportReceipt();
  for (const change of [r => { r.expected_version = 1; }, r => { delete r.expected_version; },
    r => { r.fields.labels = ['other']; r.body = 'label=other'; }, r => { r.body = 'label=urgent&label=bug'; },
    r => { r.action = 'edit'; r.expected_version = 2; r.body = `expected_version=2&${r.body}`; }]) {
    const forged = JSON.parse(receipt); change(forged.request);
    const restored = fresh(() => assert.fail('import sends nothing')); await restored.connect(token);
    await assert.rejects(restored.restoreReceipt(JSON.stringify(forged))); assert.equal(restored.pending, null);
  }
});
