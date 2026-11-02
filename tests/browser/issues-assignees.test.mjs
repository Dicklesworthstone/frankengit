// Actual browser client with contract doubles; native admission/restart behavior
// is exercised separately by the Rust and live-node suites.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { IssueClient, mutationRequest, issueHistory, publication }
  from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';

const token = 'c'.repeat(64), a = '11'.repeat(16), b = '22'.repeat(16), c = '33'.repeat(16);
const ids = { schema_version: 1, tenant_id: 'tenant', repository_id: 'repo' };
const committed = { ...ids, type: 'issue_publication', principal_id: 'actor', number: 1,
  expected_version: null, action: 'add-assignees', command_profile: 'issue.add-assignees.v1',
  tx_id: 'addition-tx', outcome: 'committed', decision_sequence: 2,
  repository_commit_id: 'addition-rcr', refusal_record_id: null, refusal_code: null,
  delivery_acknowledged: null };
const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' },
});
const fresh = fetchImpl => new IssueClient({ href: 'https://forge.example/repo.git/ui/issues/',
  fetchImpl, cryptoImpl: webcrypto });

test('additions require null version and canonical bounded IDs without extending history actions', () => {
  const request = mutationRequest(1, null, 'add-assignees', { assignees: [b, a] });
  assert.equal(request.action, 'add-assignees'); assert.equal(request.expected_version, null);
  assert.deepEqual(request.fields, { assignees: [a, b] });
  assert.equal(request.body, `assignee=${a}&assignee=${b}`);
  for (const version of [undefined, 0, 1, '1', NaN, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => mutationRequest(1, version, 'add-assignees', { assignees: [a] }));
  }
  for (const fields of [{}, { assignees: [] }, { assignees: [a, a] }, { assignees: ['AA'.repeat(16)] },
    { assignees: ['admin'] }, { assignees: null }, { assignees: [a], principal: b },
    { assignees: [a], expected_version: 1 }, { assignees: [a], body: 'x' },
    { assignees: [a], command_profile: 'issue.add-assignees.v1' }]) {
    assert.throws(() => mutationRequest(1, null, 'add-assignees', fields));
  }
  const maximum = Array.from({ length: 16 }, (_, i) => i.toString(16).padStart(32, '0'));
  assert.equal(mutationRequest(1, null, 'add-assignees', { assignees: maximum }).fields.assignees.length, 16);
  assert.throws(() => mutationRequest(1, null, 'add-assignees', { assignees: [...maximum, a] }));
  for (const action of ['assign', 'unassign']) {
    assert.throws(() => mutationRequest(1, null, action, { assignees: [a] }));
  }
  const history = { ...ids, type: 'issue_history', snapshot_token: `alg:1:${'b'.repeat(64)}`,
    after_version: 1, limit: 20, found: true, next_after_version: null,
    issue: { number: 1, version: 2, title: 'x', body: '', labels: [], assignees: [a],
      state: 'open', opened_by: 'actor', last_actor: 'actor', comments: 0 },
    events: [{ version: 2, actor: 'actor', action: { name: 'assign', assignees: [a] } }] };
  assert.equal(issueHistory(history, 1, { after: 1 }).reply.events[0].action.name, 'assign');
  assert.throws(() => issueHistory({ ...history,
    events: [{ ...history.events[0], action: { name: 'add-assignees', assignees: [a] } }] }, 1, { after: 1 }));
});

test('lost addition response and later removal retain one exact retry identity across reload', async () => {
  const calls = [], decisions = new Map();
  let version = 2, assignees = [c], loseReply = true;
  // Independent edits are already present before the addition is dispatched.
  // The model returns the original decision for a repeated request identity.
  const fetchImpl = async (url, options) => {
    const call = { url: String(url), ...options }; calls.push(call);
    const key = options.headers['Idempotency-Key'], old = decisions.get(key);
    if (old) {
      assert.equal(call.url, old.url); assert.equal(call.body, old.body);
      return json(old.reply);
    }
    const fields = new URLSearchParams(options.body), delta = fields.getAll('assignee');
    let reply;
    if (call.url.endsWith('/add-assignees')) {
      assert.equal(fields.has('expected_version'), false);
      assignees = [...new Set([...assignees, ...delta])].sort(); version += 1;
      reply = committed;
    } else {
      assert.ok(call.url.endsWith('/unassign')); assert.equal(Number(fields.get('expected_version')), version);
      assignees = assignees.filter(id => !delta.includes(id)); version += 1;
      reply = { ...committed, action: 'unassign', expected_version: version - 1, tx_id: 'removal-tx',
        repository_commit_id: 'removal-rcr', decision_sequence: 3 };
      delete reply.command_profile;
    }
    decisions.set(key, { url: call.url, body: call.body, reply });
    if (loseReply) { loseReply = false; throw new TypeError('terminal response lost'); }
    return json(reply);
  };
  const original = fresh(fetchImpl); await original.connect(token);
  const input = { assignees: [b, a] };
  await original.stage(1, null, 'add-assignees', input); input.assignees[0] = c;
  assert.equal(calls.length, 0); original.pending.fields.assignees[0] = c;
  await assert.rejects(original.send(), error => error.outcomeUnknown === true);
  assert.deepEqual(assignees, [a, b, c]); assert.equal(version, 3);
  const receipt = original.exportReceipt(); assert.equal(receipt.includes(token), false);
  const pending = original.pending;
  const removal = fresh(fetchImpl); await removal.connect(token);
  await removal.stage(1, 3, 'unassign', { assignees: [a] });
  assert.equal((await removal.send()).tx, 'removal-tx');
  assert.deepEqual(assignees, [b, c]); assert.equal(version, 4);
  const restored = fresh(fetchImpl); await restored.connect(token);
  await restored.restoreReceipt(receipt); assert.equal(calls.length, 2);
  assert.equal(restored.pending.key, pending.key); assert.equal(restored.pending.expected_version, null);
  assert.deepEqual(restored.pending.fields, { assignees: [a, b] });
  assert.equal((await restored.send()).tx, 'addition-tx'); assert.equal(restored.pending, null);
  assert.equal(calls[2].body, calls[0].body); assert.equal(calls[2].url, calls[0].url);
  assert.equal(calls[2].headers['Idempotency-Key'], calls[0].headers['Idempotency-Key']);
  assert.equal(decisions.size, 2); assert.deepEqual(assignees, [b, c]); assert.equal(version, 4);
});

test('addition terminal replies require their exact profile and null version for commit and refusal', async () => {
  const refused = { ...committed, outcome: 'refused', repository_commit_id: null,
    refusal_record_id: 'refusal', refusal_code: 'ResourceBudgetExceeded' };
  for (const reply of [committed, refused]) {
    const status = reply.outcome === 'committed' ? 200 : 409;
    const good = fresh(async () => json(reply, status)); await good.connect(token);
    await good.stage(1, null, 'add-assignees', { assignees: [a] });
    assert.equal((await good.send()).outcome, reply.outcome); assert.equal(good.pending, null);
    for (const change of [r => { delete r.command_profile; }, r => { r.command_profile = null; },
      r => { r.command_profile = 'issue.assign.v1'; }, r => { r.command_profile = 'issue.add-assignees.v2'; },
      r => { r.expected_version = 1; }, r => { delete r.expected_version; },
      r => { r.action = 'assign'; }, r => { r.delivery_acknowledged = true; }]) {
      const forged = structuredClone(reply); change(forged);
      const client = fresh(async () => json(forged, status)); await client.connect(token);
      await client.stage(1, null, 'add-assignees', { assignees: [a] });
      const key = client.pending.key;
      await assert.rejects(client.send(), error => error.outcomeUnknown === true);
      assert.equal(client.pending.key, key); assert.equal(client.pending.sent, true);
    }
  }
  assert.throws(() => publication({ ...committed, expected_version: 1 },
    { number: 1, action: 'add-assignees', expected_version: 1, binding: null }));
});

test('saved additions refuse forged versions, changed principal sets and noncanonical bodies without dispatch', async () => {
  const original = fresh(() => assert.fail('preparation dispatched')); await original.connect(token);
  await original.stage(1, null, 'add-assignees', { assignees: [b, a] });
  const receipt = original.exportReceipt();
  for (const change of [r => { r.expected_version = 0; }, r => { r.expected_version = 7; },
    r => { delete r.expected_version; }, r => { r.fields.assignees = [a, c]; r.body = `assignee=${a}&assignee=${c}`; },
    r => { r.body = `assignee=${b}&assignee=${a}`; },
    r => { r.action = 'assign'; r.expected_version = 7; r.body = `expected_version=7&${r.body}`; }]) {
    const forged = JSON.parse(receipt); change(forged.request);
    const client = fresh(() => assert.fail('receipt import dispatched')); await client.connect(token);
    await assert.rejects(client.restoreReceipt(JSON.stringify(forged))); assert.equal(client.pending, null);
  }
});

test('frozen legacy assign and unassign receipts keep their original version, body, route and key', async () => {
  // Golden v1 keys use the pre-additive exact-version grammar and a fixed nonce.
  const digests = { assign: 'af72a57b9532a1c6bd1d9be5f2c24070d37924978d291f88f17e5b825b3f200b',
    unassign: 'b5e7d39fafb8ef238f61c3b77411aa164fc7f3bb5d2166a856490bb626c3fb76' };
  for (const action of ['assign', 'unassign']) {
    const original = { schema: 'frankengit-issue-retry-v1', origin: 'https://forge.example', route: '/repo.git',
      request: { number: 1, expected_version: 7, action, fields: { assignees: [a, b] },
        body: `expected_version=7&assignee=${a}&assignee=${b}`,
        key: `fgui-${'01'.repeat(16)}-${digests[action]}`, binding: { tenant: 'tenant', repository: 'repo' },
        sent: true, exported: true,
        credential_fingerprint: '52b6419d27bd7f547cee3b92f8c17a908b8a49601ecbec161e5030de1dfe9e0a' } };
    const before = JSON.stringify(original), calls = [];
    const reply = { ...committed, action, expected_version: 7 }; delete reply.command_profile;
    const client = fresh(async (url, options) => { calls.push({ url: String(url), ...options }); return json(reply); });
    await client.connect(token); await client.restoreReceipt(before);
    assert.equal(calls.length, 0); assert.equal(client.pending.action, action);
    assert.equal(client.pending.expected_version, 7); assert.equal(client.pending.key, original.request.key);
    assert.deepEqual(JSON.parse(client.exportReceipt()), original);
    assert.equal((await client.send()).outcome, 'committed');
    assert.ok(calls[0].url.endsWith(`/issues/1/${action}`)); assert.equal(calls[0].body, original.request.body);
    assert.equal(calls[0].headers['Idempotency-Key'], original.request.key); assert.equal(JSON.stringify(original), before);
    const migrated = structuredClone(original);
    Object.assign(migrated.request, { action: 'add-assignees', expected_version: null, body: `assignee=${a}&assignee=${b}` });
    const changed = fresh(() => assert.fail('receipt import dispatched')); await changed.connect(token);
    await assert.rejects(changed.restoreReceipt(JSON.stringify(migrated))); assert.equal(changed.pending, null);
  }
});
