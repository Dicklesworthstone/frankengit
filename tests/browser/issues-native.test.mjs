// Contract doubles, not live-node interoperability evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { IssueClient, mutationRequest, issuePage, issueHistory, readJson }
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
