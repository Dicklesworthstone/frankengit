// Contract doubles, not live-node interoperability evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { IssueClient, mutationRequest, issuePage, issueHistory, issueLocked, readJson }
  from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
const token = 'c'.repeat(64), head = `alg:1:${'b'.repeat(64)}`;
const ids = { schema_version: 1, tenant_id: 'tenant', repository_id: 'repo' };
const row = { number: 1, version: 1, title: '<script>inert</script>', body: 'body',
  labels: ['bug'], state: 'open', opened_by: 'actor', last_actor: 'actor', comments: 0 };
const page = { ...ids, type: 'issue_page', snapshot_token: head, after: 0, limit: 20, next_after: null, issues: [row] };
const terminal = { ...ids, type: 'issue_publication', principal_id: 'actor', number: 1,
  expected_version: 1, action: 'comment', tx_id: 'tx', outcome: 'committed', decision_sequence: 2,
  repository_commit_id: 'rcr', refusal_record_id: null, refusal_code: null, delivery_acknowledged: null };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const fresh = fetchImpl => new IssueClient({ href: 'https://forge.example/repo.git/ui/issues/', fetchImpl, cryptoImpl: webcrypto });

test('lock controls are payloadless exact-version requests', () => {
  for (const action of ['lock', 'unlock']) {
    const request = mutationRequest(1, 2, action, {});
    assert.equal(request.action, action); assert.deepEqual(request.fields, {});
    assert.equal(request.body, 'expected_version=2');
    for (const version of [null, undefined, 0, -1, 1.5, Number.MAX_SAFE_INTEGER]) {
      assert.throws(() => mutationRequest(1, version, action, {}));
    }
    for (const fields of [{ locked: true }, { body: 'reason' }, { title: 'x' }, { labels: [] }, { assignees: [] }]) {
      assert.throws(() => mutationRequest(1, 2, action, fields));
    }
  }
});
test('old snapshots derive unlocked without rewriting bytes; present lock fields are strict', () => {
  const legacy = structuredClone(page), before = JSON.stringify(legacy);
  assert.equal(issueLocked(issuePage(legacy).reply.issues[0]), false);
  assert.equal(JSON.stringify(legacy), before); assert.equal(Object.hasOwn(legacy.issues[0], 'locked'), false);
  for (const locked of [false, true]) {
    const current = { ...page, issues: [{ ...row, locked }] };
    assert.equal(issueLocked(issuePage(current).reply.issues[0]), locked);
  }
  for (const locked of [null, undefined, 0, 1, 'false', {}, []]) {
    assert.throws(() => issuePage({ ...page, issues: [{ ...row, locked }] }), /lock state/);
  }
});
test('history validates lock transitions, suppressed comments and the final declared lock', () => {
  const opening = { version: 1, actor: 'actor', action: { name: 'open', title: row.title, body: row.body, labels: row.labels } };
  const events = [opening, { version: 2, actor: 'actor', action: { name: 'lock' } },
    { version: 3, actor: 'actor', action: { name: 'close' } }];
  const history = { ...ids, type: 'issue_history', snapshot_token: head, after_version: 0, limit: 20,
    found: true, issue: { ...row, state: 'closed', version: 3, locked: true }, next_after_version: null, events };
  assert.equal(issueHistory(history, 1).reply.issue.locked, true);
  const unlocked = structuredClone(history);
  unlocked.events.push({ version: 4, actor: 'actor', action: { name: 'unlock' } },
    { version: 5, actor: 'actor', action: { name: 'comment', body: 'After unlock' } });
  Object.assign(unlocked.issue, { version: 5, comments: 1, locked: false });
  assert.equal(issueHistory(unlocked, 1).reply.issue.state, 'closed');
  for (const mutate of [
    h => { delete h.issue.locked; }, h => { h.issue.locked = false; },
    h => { h.events[2].action = { name: 'comment', body: 'While locked' }; h.issue.comments = 1; },
    h => { h.events[2].action = { name: 'lock' }; },
    h => { h.events[1].action = { name: 'unlock' }; },
    h => { h.events[1].action = { name: 'lock', locked: true }; },
  ]) {
    const invalid = structuredClone(history); mutate(invalid);
    assert.throws(() => issueHistory(invalid, 1));
  }
  // A continuation can start after the locking event. The shared archive
  // traversal verifies earlier pages; this client must accept its exact page.
  assert.equal(issueHistory({ ...history, after_version: 2, events: [events[2]] }, 1, { after: 2 }).reply.issue.locked, true);
});
test('lock receipts retain the original key and exact request across response loss and reload', async () => {
  for (const action of ['lock', 'unlock']) {
    const calls = [], result = { ...terminal, action, expected_version: 2 };
    const first = fresh(async (url, options) => { calls.push({ url: String(url), ...options }); throw new Error('response lost'); });
    await first.connect(token); await first.stage(1, 2, action, {});
    await assert.rejects(first.send()); const receipt = first.exportReceipt();
    const restored = fresh(async (url, options) => { calls.push({ url: String(url), ...options }); return json(result); });
    await restored.connect(token); await restored.restoreReceipt(receipt);
    assert.equal((await restored.send()).outcome, 'committed'); assert.equal(restored.pending, null);
    assert.equal(calls[0].body, 'expected_version=2'); assert.equal(calls[1].body, calls[0].body);
    assert.equal(calls[1].url, calls[0].url); assert.ok(calls[1].url.endsWith(`/issues/1/${action}`));
    assert.equal(calls[1].headers['Idempotency-Key'], calls[0].headers['Idempotency-Key']);
    assert.equal(receipt.includes(token), false);
  }
});
test('assignment forms sort bounded principal sets and reject authority or malformed IDs', () => {
  const a = '11'.repeat(16), b = '22'.repeat(16);
  for (const action of ['assign', 'unassign']) {
    const request = mutationRequest(1, 2, action, { assignees: [b, a] });
    assert.deepEqual(new URLSearchParams(request.body).getAll('assignee'), [a, b]);
    assert.deepEqual(Object.keys(request.fields), ['assignees']);
    for (const assignees of [[], [a, a], ['admin'], ['AA'.repeat(16)], null, Array(17).fill(a)]) {
      assert.throws(() => mutationRequest(1, 2, action, { assignees }));
    }
    assert.throws(() => mutationRequest(1, 2, action, { assignees: [a], principal: b }));
    assert.throws(() => mutationRequest(1, 0, action, { assignees: [a] }));
    const maximum = Array.from({ length: 16 }, (_, i) => i.toString(16).padStart(2, '0').repeat(16));
    assert.equal(mutationRequest(1, 2, action, { assignees: maximum }).fields.assignees.length, 16);
  }
});
test('assignment reads validate canonical sets and retain original deltas in history', () => {
  const a = '11'.repeat(16), b = '22'.repeat(16);
  assert.equal(issuePage({ ...page, issues: [{ ...row, assignees: [a, b] }] }).reply.issues[0].assignees[0], a);
  for (const assignees of [[b, a], [a, a], ['invalid'], null]) {
    assert.throws(() => issuePage({ ...page, issues: [{ ...row, assignees }] }));
  }
  const reply = { ...ids, type: 'issue_history', snapshot_token: head, after_version: 1, limit: 20,
    found: true, issue: { ...row, version: 3, assignees: [b] }, next_after_version: null,
    events: [{ version: 2, actor: 'actor', action: { name: 'assign', assignees: [a, b] } },
      { version: 3, actor: 'actor', action: { name: 'unassign', assignees: [a] } }] };
  assert.deepEqual(issueHistory(reply, 1, { after: 1, head }).reply.events, reply.events);
  assert.throws(() => issueHistory({ ...reply, events: [{ ...reply.events[0], action: { name: 'assign', assignees: [b, a] } }, reply.events[1]] }, 1, { after: 1, head }));
});
async function staged(fetchImpl) {
  const client = fresh(fetchImpl); await client.connect(token);
  await client.stage(1, 1, 'comment', { body: 'original' }); return client;
}
test('closed forms preserve bytes, replacement and UTF-8 label order', () => {
  const form = new URLSearchParams(mutationRequest(1, 0, 'open', { title: '🦀', body: '&principal=admin', labels: ['😀', '\uE000'] }).body);
  assert.equal(form.get('body'), '&principal=admin'); assert.equal(form.has('principal'), false);
  assert.deepEqual(form.getAll('label'), ['\uE000', '😀']);
  assert.equal(new URLSearchParams(mutationRequest(1, 1, 'edit', { labels: [] }).body).get('clear_labels'), 'true');
  for (const fields of [{ body: 'x', principal: 'admin' }, { body: '\ud800' }, { body: 'x'.repeat(65537) }, { body: '\0' }]) {
    assert.throws(() => mutationRequest(1, 1, 'comment', fields));
  }
  for (const version of [0, -1, Infinity, 0.5, Number.MAX_SAFE_INTEGER]) assert.throws(() => mutationRequest(1, version, 'close', {}));
});
test('page and history refuse mixed snapshots, gaps and inconsistent completion', () => {
  assert.equal(issuePage(page).head, head);
  assert.throws(() => issuePage(page, { head: `alg:1:${'a'.repeat(64)}` }));
  for (const extra of [{ issues: [row, row] }, { next_after: 1 }, { issues: [{ ...row, version: 0 }] }]) assert.throws(() => issuePage({ ...page, ...extra }));
  const history = { ...ids, type: 'issue_history', snapshot_token: head, after_version: 0,
    limit: 20, found: true, issue: row, next_after_version: null,
    events: [{ version: 1, actor: 'actor', action: { name: 'open', title: row.title, body: row.body, labels: row.labels } }] };
  assert.equal(issueHistory(history, 1).reply.found, true);
  assert.throws(() => issueHistory({ ...history, events: [] }, 1));
  assert.throws(() => issueHistory(history, 2));
});
test('preparation never dispatches and lost-response retry is byte identical', async () => {
  const calls = []; const client = await staged(async (url, options) => {
    calls.push({ url: String(url), ...options }); if (calls.length === 1) throw new Error('lost'); return json(terminal);
  });
  assert.equal(calls.length, 0); client.pending.fields.body = 'forged';
  await assert.rejects(client.send()); assert.throws(() => client.discardUnsent());
  await client.send(); assert.equal(client.pending, null);
  assert.equal(calls[0].body, calls[1].body); assert.equal(calls[0].headers['Idempotency-Key'], calls[1].headers['Idempotency-Key']);
  assert.equal(new URLSearchParams(calls[1].body).get('body'), 'original');
  assert.equal(calls[0].credentials, 'omit'); assert.equal(calls[0].redirect, 'error');
});
test('canonical 409 refusal settles but malformed conflict preserves responsibility', async () => {
  const refusal = { ...terminal, outcome: 'refused', repository_commit_id: null, refusal_record_id: 'refusal', refusal_code: 'VersionMismatch' };
  const client = await staged(async () => json(refusal, 409));
  assert.equal((await client.send()).outcome, 'refused'); assert.equal(client.pending, null);
  for (const [body, status] of [[{}, 409], [terminal, 409], [refusal, 200], [{ ...terminal, number: 2 }, 200]]) {
    const invalid = await staged(async () => json(body, status)); await assert.rejects(invalid.send()); assert.ok(invalid.pending);
  }
});
test('receipts survive reload without tokens and bind the exact request', async () => {
  const client = await staged(async () => json(terminal)); const receipt = client.exportReceipt();
  assert.equal(receipt.includes(token), false); assert.throws(() => client.discardUnsent());
  const restored = fresh(async () => json(terminal)); await restored.connect(token); await restored.restoreReceipt(receipt);
  assert.equal(restored.pending.key, client.pending.key); assert.equal(restored.pending.sent, true);
  assert.equal((await restored.send()).outcome, 'committed');
  for (const change of [r => { r.route = '/other'; }, r => { r.request.number = 2; }, r => { r.request.fields.body = 'forged'; }]) {
    const bad = JSON.parse(receipt); change(bad);
    bad.request.body = mutationRequest(bad.request.number, bad.request.expected_version, bad.request.action, bad.request.fields).body;
    const other = fresh(async () => assert.fail('dispatched')); await other.connect(token);
    await assert.rejects(other.restoreReceipt(JSON.stringify(bad))); assert.equal(other.pending, null);
  }
});
test('outcome lookup is bodyless, key-preserving, and absence never means rollback', async () => {
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
    let call;
    const client = await staged(async (url, options) => { call = { url: String(url), ...options };
      return json({ ...ids, type: 'transaction_outcome', repository_incarnation: 'inc', principal_id: 'actor',
        selector: 'transaction', command_index: null, state, terminal: false,
        transaction: state === 'undecided' ? { tx_id: 'tx' } : null, decision: null,
        read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false });
    });
    const key = client.pending.key; assert.equal((await client.recover()).terminal, false);
    assert.equal(client.pending.key, key); assert.equal(call.body, undefined);
    assert.equal(call.headers['Idempotency-Key'], key); assert.match(call.url, /\/outcomes$/);
  }
});
test('disconnect and late unauthorized response cannot erase pending work or new credentials', async () => {
  let resolve;
  const client = await staged(() => new Promise(r => { resolve = r; }));
  const sending = client.send(); client.disconnect(); resolve(json(terminal));
  await assert.rejects(sending); assert.ok(client.pending); assert.equal(client.connected, false);
  await assert.rejects(client.connect('d'.repeat(64))); await client.connect(token);
  const reading = client.read(); await client.connect(token); resolve(json({}, 401));
  await assert.rejects(reading); assert.equal(client.connected, true);
});
test('bounded JSON refuses invalid UTF-8 and cancels oversized streams', async () => {
  await assert.rejects(readJson(new Response(Uint8Array.of(255), { headers: { 'Content-Type': 'application/json' } })));
  let cancelled = false;
  const response = new Response(new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(100)); }, cancel() { cancelled = true; } }),
    { headers: { 'Content-Type': 'application/json' } });
  await assert.rejects(readJson(response, null, 10)); assert.equal(cancelled, true);
});


test('append comments require a null version and never relax canonical history grammar', () => {
  const append = mutationRequest(1, null, 'append-comment', { body: 'A & B 🦀\n%2F' });
  assert.equal(append.expected_version, null); assert.equal(append.action, 'append-comment');
  const form = new URLSearchParams(append.body);
  assert.deepEqual([...form.keys()], ['body']); assert.equal(form.get('body'), 'A & B 🦀\n%2F');
  for (const version of [undefined, 0, 1, '1', NaN]) {
    assert.throws(() => mutationRequest(1, version, 'append-comment', { body: 'x' }));
  }
  for (const fields of [{}, { body: ' \n' }, { body: 'x', expected_version: 1 }, { body: 'x', principal: 'admin' }]) {
    assert.throws(() => mutationRequest(1, null, 'append-comment', fields));
  }
  assert.throws(() => mutationRequest(1, null, 'comment', { body: 'x' }));
  const history = { ...ids, type: 'issue_history', snapshot_token: head, after_version: 1,
    limit: 20, found: true, issue: { ...row, version: 2, comments: 1 }, next_after_version: null,
    events: [{ version: 2, actor: 'actor', action: { name: 'comment', body: 'x' } }] };
  assert.equal(issueHistory(history, 1, { after: 1 }).reply.events[0].action.name, 'comment');
  assert.throws(() => issueHistory({ ...history,
    events: [{ ...history.events[0], action: { name: 'append-comment', body: 'x' } }] }, 1, { after: 1 }));
});
test('append receipt survives response loss and reload with one exact key and body', async () => {
  const calls = [], appendTerminal = { ...terminal, action: 'append-comment', expected_version: null };
  const client = fresh(async (url, options) => {
    calls.push({ url: String(url), ...options }); throw new TypeError('reply lost');
  });
  await client.connect(token); await client.stage(1, null, 'append-comment', { body: 'original' });
  assert.equal(calls.length, 0); await assert.rejects(client.send());
  const receipt = client.exportReceipt();
  const restored = fresh(async (url, options) => {
    calls.push({ url: String(url), ...options }); return json(appendTerminal);
  });
  await restored.connect(token); await restored.restoreReceipt(receipt);
  assert.equal(restored.pending.expected_version, null); assert.equal(restored.pending.sent, true);
  assert.equal((await restored.send()).outcome, 'committed'); assert.equal(restored.pending, null);
  assert.ok(calls.every(call => call.url.endsWith('/issues/1/append-comment')));
  assert.equal(calls[0].body, 'body=original'); assert.equal(calls[1].body, calls[0].body);
  assert.equal(calls[1].headers['Idempotency-Key'], calls[0].headers['Idempotency-Key']);
  const changed = JSON.parse(receipt);
  changed.request.action = 'comment'; changed.request.expected_version = 1;
  changed.request.body = 'expected_version=1&body=original';
  const other = fresh(() => assert.fail('a receipt import dispatched'));
  await other.connect(token); await assert.rejects(other.restoreReceipt(JSON.stringify(changed)));
  assert.equal(other.pending, null);
});
test('the original versioned comment receipt remains byte-identical after append support', async () => {
  // Frozen v1 receipt/key from the original exact-version request grammar.
  const original = {"schema": "frankengit-issue-retry-v1", "origin": "https://forge.example", "route": "/repo.git", "request": {"number": 1, "expected_version": 7, "action": "comment", "fields": {"body": "Legacy\n%2F"}, "body": "expected_version=7&body=Legacy%0A%252F", "key": "fgui-01010101010101010101010101010101-67619d8664aecd901ff4781ade913475b2827eed209f5f997a9723b0903a18f6", "binding": {"tenant": "tenant", "repository": "repo"}, "sent": true, "exported": true, "credential_fingerprint": "52b6419d27bd7f547cee3b92f8c17a908b8a49601ecbec161e5030de1dfe9e0a"}};
  const calls = [], client = fresh(async (url, options) => {
    calls.push({ url: String(url), ...options }); return json({ ...terminal, expected_version: 7 });
  });
  await client.connect(token); await client.restoreReceipt(JSON.stringify(original));
  assert.equal(client.pending.action, 'comment'); assert.equal(client.pending.expected_version, 7);
  assert.equal(client.pending.key, original.request.key);
  assert.equal((await client.send()).outcome, 'committed');
  assert.equal(calls[0].url.endsWith('/issues/1/comment'), true);
  assert.equal(calls[0].body, original.request.body);
  assert.equal(calls[0].headers['Idempotency-Key'], original.request.key);
  original.request.action = 'append-comment'; original.request.expected_version = null;
  original.request.body = 'body=Legacy%0A%252F';
  const changed = fresh(() => assert.fail('dispatched')); await changed.connect(token);
  await assert.rejects(changed.restoreReceipt(JSON.stringify(original)));
});
test('append outcome lookup preserves unknown responsibility and canonical recovery settles it', async () => {
  let settled = false; const calls = [];
  const client = fresh(async (url, options) => {
    calls.push({ url: String(url), ...options });
    return json({ ...ids, type: 'transaction_outcome', repository_incarnation: 'inc', principal_id: 'actor',
      selector: 'transaction', command_index: null, state: settled ? 'committed' : 'key_not_observed', terminal: settled,
      transaction: settled ? { tx_id: 'tx' } : null,
      decision: settled ? { kind: 'committed', decision_sequence: 2, repository_commit_id: 'rcr' } : null,
      read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false });
  });
  await client.connect(token); await client.stage(1, null, 'append-comment', { body: 'recover me' });
  const pending = client.pending;
  assert.equal((await client.recover()).terminal, false); assert.deepEqual(client.pending, pending);
  settled = true; assert.equal((await client.recover()).outcome, 'committed'); assert.equal(client.pending, null);
  for (const call of calls) {
    assert.equal(call.url.endsWith('/outcomes'), true); assert.equal(call.body, undefined);
    assert.equal(call.headers['Idempotency-Key'], pending.key);
  }
});
test('append publication rejects strict-comment and invented-version terminal envelopes', async () => {
  for (const reply of [terminal, { ...terminal, action: 'append-comment' },
    { ...terminal, expected_version: null }]) {
    const client = fresh(async () => json(reply)); await client.connect(token);
    await client.stage(1, null, 'append-comment', { body: 'x' });
    const key = client.pending.key; await assert.rejects(client.send());
    assert.equal(client.pending.key, key); assert.equal(client.pending.sent, true);
  }
});
