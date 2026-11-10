// Response-schema contract doubles, not Rust authority/interoperability evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { IssueClient } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { NotificationClient } from '../../crates/fgit-node/src/smart_http/server/browser/notifications.mjs';
import { MilestoneClient, milestoneAction, milestoneMutationRequest, milestoneState, milestonePage, milestoneHistory }
  from '../../crates/fgit-node/src/smart_http/server/browser/milestones.mjs';

const href = 'https://forge.example/repo.git/ui/issues/', token = 'c'.repeat(64);
const head = `alg:1:${'b'.repeat(64)}`;
const ids = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32) };
const binding = { tenant: ids.tenant_id, repository: ids.repository_id };
const row = { number: 7, version: 1, title: 'Release 雪', body: '<script>inert</script> & text',
  due_at: 0, state: 'open', opened_by: 'actor', last_actor: 'actor', open_issues: 2, closed_issues: 3 };
const page = { ...ids, type: 'milestone_page', scope: 'repository_milestones', snapshot_token: head,
  after: 0, limit: 20, next_after: null, milestones: [row] };
const history = { ...ids, type: 'milestone_history', scope: 'repository_milestones', snapshot_token: head,
  found: true, milestone: row, after_version: 0, limit: 20, next_after_version: null,
  events: [{ version: 1, actor: 'actor', action: { name: 'open', title: row.title, body: row.body, due_at: row.due_at } }] };
const terminal = { ...ids, type: 'milestone_publication', number: 7, expected_version: 1, action: 'edit',
  principal_id: 'actor', tx_id: 'original-tx', outcome: 'committed', decision_sequence: 2,
  repository_commit_id: 'original-rcr', refusal_record_id: null, refusal_code: null, delivery_acknowledged: null };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const fresh = fetchImpl => new MilestoneClient({ href, fetchImpl, cryptoImpl: webcrypto });
const recovery = terminal => ({ ...ids, type: 'transaction_outcome', selector: 'transaction', command_index: null,
  read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
  repository_incarnation: 'incarnation', principal_id: 'actor', terminal, state: terminal ? 'committed' : 'key_not_observed',
  transaction: terminal ? { tx_id: 'original-tx' } : null,
  decision: terminal ? { kind: 'committed', decision_sequence: 2, repository_commit_id: 'original-rcr' } : null });

test('sponsored issue and milestone clients retain full credential custody through a lost reply', async () => {
  const agent = `fgagent_${token}`, fingerprint = value => createHash('sha256').update(value).digest('hex');
  const cryptoImpl = { subtle: webcrypto.subtle, getRandomValues(value) { value.fill(5); return value; } };
  for (const [Client, family] of [[IssueClient, 'issues'], [MilestoneClient, 'milestones']]) {
    const calls = [];
    const first = new Client({ href, cryptoImpl, fetchImpl: async (url, init) => {
      calls.push({ url: String(url), ...init }); throw new Error('lost reply');
    } });
    await first.connect(agent); await first.stage(7, 1, 'edit', { body: 'sponsored work' }, binding);
    const saved = first.exportReceipt(), request = JSON.parse(saved).request;
    assert.equal(request.credential_fingerprint, fingerprint(agent));
    assert.notEqual(request.credential_fingerprint, fingerprint(token));
    assert.equal(saved.includes(agent), false); assert.equal(saved.includes(token), false);
    assert.equal(calls.length, 0);
    await assert.rejects(first.send(), error => error.outcomeUnknown === true);
    assert.ok(first.pending); first.disconnect();

    const wrong = new Client({ href, cryptoImpl, fetchImpl: () => assert.fail('credential fallback') });
    await wrong.connect(token);
    await assert.rejects(wrong.restoreReceipt(saved), /does not belong/);
    wrong.disconnect();

    const restored = new Client({ href, cryptoImpl, fetchImpl: async (url, init) => {
      calls.push({ url: String(url), ...init }); return json(recovery(true));
    } });
    await restored.connect(agent); await restored.restoreReceipt(saved);
    assert.equal(restored.pending.key, request.key);
    assert.equal((await restored.recover()).tx, 'original-tx');
    assert.equal(restored.pending, null); assert.equal(calls.length, 2);
    assert.ok(calls[0].url.endsWith(`/${family}/7/edit`));
    assert.ok(calls[1].url.endsWith('/outcomes')); assert.equal(calls[1].body, undefined);
    for (const call of calls) {
      assert.equal(call.headers.Authorization, `Bearer ${agent}`);
      assert.equal(call.headers['Idempotency-Key'], request.key);
    }
    restored.disconnect();
  }
});

test('sponsored browser tokens keep closed syntax and cannot bypass server scopes', async () => {
  const agent = `fgagent_${token}`;
  for (const Client of [IssueClient, MilestoneClient]) {
    const calls = [], client = new Client({ href, cryptoImpl: webcrypto, fetchImpl: async (url, init) => {
      calls.push({ url: String(url), ...init }); return json({}, 403);
    } });
    for (const malformed of [null, {}, '', token + '\n', agent + '\n', agent + '\r\n', agent + ' ',
      agent + '\0', agent + 'a', 'fgagent_' + token.slice(1), 'FGAGENT_' + token,
      'fgagent_' + token.toUpperCase(), 'fgagent_' + '雪'.repeat(64)]) {
      await assert.rejects(client.connect(malformed));
    }
    assert.equal(calls.length, 0); assert.equal(client.connected, false);
    await client.connect(agent);
    await assert.rejects(client.read(), error => error.status === 403);
    assert.equal(calls.length, 1); assert.equal(calls[0].headers.Authorization, `Bearer ${agent}`);
    client.disconnect();
  }
  const inbox = new NotificationClient({ href: href.replace('/ui/issues/', '/ui/notifications/'),
    cryptoImpl: webcrypto, fetchImpl: () => assert.fail('unsupported agent route') });
  await assert.rejects(inbox.connect(agent)); assert.equal(inbox.connected, false);
  for (const family of ['issue', 'milestone']) {
    const html = readFileSync(new URL(`../../crates/fgit-node/src/smart_http/server/browser/${family}s.html`, import.meta.url), 'utf8');
    const input = html.match(new RegExp(`<input[^>]*id="${family}-token"[^>]*>`))?.[0];
    assert.ok(input, 'rendered credential input exists');
    assert.equal(Number(input.match(/maxlength="(\d+)"/)?.[1]), agent.length);
    assert.ok(input.includes('type="password"')); assert.ok(input.includes('autocomplete="off"'));
  }
});

test('milestone forms distinguish absent, cleared and epoch dates without accepting authority fields', () => {
  const open = milestoneMutationRequest(7, 0, 'open', { title: row.title, body: row.body });
  assert.equal(open.fields.due_at, null);
  assert.equal(new URLSearchParams(open.body).has('due_at'), false);
  assert.equal(milestoneMutationRequest(7, 1, 'edit', { due_at: null }).body, 'expected_version=1&clear_due_at=true');
  assert.equal(milestoneMutationRequest(7, 1, 'edit', { due_at: 0 }).body, 'expected_version=1&due_at=0');
  assert.equal(milestoneMutationRequest(7, 1, 'edit', { body: '' }).body, 'expected_version=1&body=');
  assert.equal(milestoneMutationRequest(7, 1, 'edit', { due_at: 253402300799 }).fields.due_at, 253402300799);
  for (const due_at of [undefined, '0', -1, 0.5, NaN, 253402300800]) assert.throws(() => milestoneAction('edit', { due_at }));
  for (const fields of [{}, { labels: [] }, { body: 'x', principal: 'admin' }, { clear_due_at: true },
    { body: '\ud800' }, { body: '\0' }, { body: 'x'.repeat(65537) }, { title: ' ' }]) {
    assert.throws(() => milestoneMutationRequest(7, 1, 'edit', fields));
  }
  for (const action of ['close', 'reopen']) {
    assert.equal(milestoneMutationRequest(7, 1, action, {}).body, 'expected_version=1');
    assert.throws(() => milestoneMutationRequest(7, 0, action, {}));
    assert.throws(() => milestoneMutationRequest(7, 1, action, { body: 'reason' }));
  }
  assert.throws(() => milestoneMutationRequest(7, 1, 'open', { title: 'x', body: '' }));
  assert.throws(() => milestoneMutationRequest(7, 1, 'set-milestone', { milestone: 1, expected_milestone_version: 1 }));
});
test('milestone reads require exact counts, identities, snapshot and ordered coverage', () => {
  assert.equal(milestonePage(page, { binding }).head, head);
  assert.equal(milestoneHistory(history, 7, { binding }).reply.milestone, row);
  for (const patch of [{ open_issues: -1 }, { closed_issues: null }, { open_issues: Number.MAX_SAFE_INTEGER },
    { version: 0 }, { due_at: undefined }, { state: 'done' }]) assert.throws(() => milestoneState({ ...row, ...patch }));
  for (const patch of [{ scope: 'repository_issues' }, { type: 'issue_page' }, { milestones: [row, row] },
    { next_after: 7 }, { repository_id: 'other' }]) assert.throws(() => milestonePage({ ...page, ...patch }, { binding }));
  assert.throws(() => milestonePage(page, { head: `alg:1:${'a'.repeat(64)}` }));
  assert.throws(() => milestoneHistory({ ...history, events: [] }, 7));
  assert.throws(() => milestoneHistory(history, 8));
  const missing = { ...history, found: false, milestone: null, events: [] };
  assert.equal(milestoneHistory(missing, 7).reply.found, false);
  assert.throws(() => milestoneHistory({ ...missing, milestone: row }, 7));
});
test('milestone history preserves edits with null dates and rejects invalid state transitions', () => {
  const events = [...history.events, { version: 2, actor: 'editor', action: { name: 'edit', due_at: null } },
    { version: 3, actor: 'closer', action: { name: 'close' } }];
  const reply = { ...history, milestone: { ...row, version: 3, due_at: null, state: 'closed', last_actor: 'closer' }, events };
  assert.equal(milestoneHistory(reply, 7).reply.events[1].action.due_at, null);
  assert.equal(milestoneHistory({ ...reply, after_version: 2, events: [events[2]] }, 7, { after: 2 }).reply.milestone.state, 'closed');
  for (const mutate of [
    v => { v.events[1].action = { name: 'reopen' }; },
    v => { v.events[1].action = { name: 'close' }; },
    v => { v.milestone.state = 'open'; },
    v => { v.events[0].action.name = 'edit'; },
    v => { v.events[1].version = 7; },
  ]) { const invalid = structuredClone(reply); mutate(invalid); assert.throws(() => milestoneHistory(invalid, 7)); }
});
test('milestone client uses native metadata routes and explicit credentials without implicit search', async () => {
  const calls = [], client = fresh(async (url, init) => {
    calls.push({ url: String(url), ...init }); return json(String(url).includes('/milestones/7?') ? history : page);
  });
  await client.connect(token); await client.read(); await client.read(7, { head, render: true });
  assert.ok(calls[0].url.includes('/api/v1/milestones?'));
  assert.equal(new URL(calls[1].url).searchParams.get('expected_head'), head);
  assert.equal(new URL(calls[1].url).searchParams.get('render'), 'html_safe');
  for (const call of calls) {
    assert.equal(call.headers.Authorization, `Bearer ${token}`); assert.equal(call.headers['Idempotency-Key'], undefined);
    assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error');
  }
  await assert.rejects(client.search({}), /not supported/); assert.equal(calls.length, 2);
  client.disconnect();
});
test('issue and milestone receipts have distinct exact keys even for identical action, form and nonce', async () => {
  const cryptoImpl = { subtle: webcrypto.subtle, getRandomValues(value) { value.fill(5); return value; } };
  const issue = new IssueClient({ href, cryptoImpl }), milestone = new MilestoneClient({ href, cryptoImpl });
  await issue.connect(token); await milestone.connect(token);
  await issue.stage(7, 1, 'edit', { body: 'same' }, binding);
  await milestone.stage(7, 1, 'edit', { body: 'same' }, binding);
  const i = JSON.parse(issue.exportReceipt()), m = JSON.parse(milestone.exportReceipt());
  assert.equal(i.request.body, m.request.body);
  assert.match(i.request.key, /^fgui-/); assert.match(m.request.key, /^fgmi-/);
  assert.notEqual(i.request.key.slice(38), m.request.key.slice(38));
  assert.equal(m.schema, 'frankengit-milestone-retry-v1'); assert.equal(JSON.stringify(m).includes(token), false);
  for (const [Client, receipt] of [[IssueClient, m], [MilestoneClient, i]]) {
    const other = new Client({ href, cryptoImpl }); await other.connect(token);
    await assert.rejects(other.restoreReceipt(JSON.stringify(receipt)), /does not belong/); other.disconnect();
  }
  const forged = structuredClone(i); forged.schema = m.schema; forged.request.key = forged.request.key.replace(/^fgui/, 'fgmi');
  const other = new MilestoneClient({ href, cryptoImpl }); await other.connect(token);
  await assert.rejects(other.restoreReceipt(JSON.stringify(forged)), /does not commit/);
  other.disconnect(); issue.disconnect(); milestone.disconnect();
});
test('lost milestone response retains the original key, and recovery never repeats a mutation', async () => {
  const calls = [], first = fresh(async (url, init) => { calls.push({ url: String(url), ...init }); throw new Error('response lost'); });
  await first.connect(token); await first.stage(7, 1, 'edit', { due_at: null }, binding);
  const receipt = first.exportReceipt(); assert.equal(calls.length, 0);
  await assert.rejects(first.send(), error => error.outcomeUnknown === true); assert.ok(first.pending);
  first.disconnect();
  let observed = false;
  const restored = fresh(async (url, init) => { calls.push({ url: String(url), ...init }); return json(recovery(observed)); });
  await restored.connect(token); await restored.restoreReceipt(receipt);
  assert.equal((await restored.recover()).terminal, false); assert.ok(restored.pending);
  assert.throws(() => restored.discardUnsent());
  observed = true;
  assert.equal((await restored.recover()).tx, 'original-tx'); assert.equal(restored.pending, null);
  assert.equal(calls.length, 3); assert.ok(calls[0].url.endsWith('/milestones/7/edit'));
  assert.ok(calls.slice(1).every(call => call.url.endsWith('/outcomes')));
  assert.ok(calls.every(call => call.headers['Idempotency-Key'] === JSON.parse(receipt).request.key));
  assert.equal(calls[0].body, 'expected_version=1&clear_due_at=true');
  restored.disconnect();
});
test('explicit milestone resend is byte identical and only its own terminal family settles', async () => {
  const calls = [], first = fresh(async (url, init) => { calls.push({ url: String(url), ...init }); throw new Error('lost'); });
  await first.connect(token); await first.stage(7, 1, 'edit', { body: 'literal & 雪' }, binding);
  await assert.rejects(first.send()); const receipt = first.exportReceipt(); first.disconnect();
  let correct = false;
  const restored = fresh(async (url, init) => { calls.push({ url: String(url), ...init }); return json({ ...terminal, type: correct ? 'milestone_publication' : 'issue_publication' }); });
  await restored.connect(token); await restored.restoreReceipt(receipt);
  await assert.rejects(restored.send(), /terminal issue reply/); assert.ok(restored.pending);
  correct = true; assert.equal((await restored.send()).outcome, 'committed');
  assert.equal(restored.pending, null);
  for (const call of calls) {
    assert.equal(call.body, calls[0].body); assert.equal(call.url, calls[0].url);
    assert.equal(call.headers['Idempotency-Key'], calls[0].headers['Idempotency-Key']);
  }
  restored.disconnect();
});
test('canonical milestone refusal settles, but status or version mismatch stays unknown', async () => {
  const refusal = { ...terminal, outcome: 'refused', repository_commit_id: null,
    refusal_record_id: 'refusal-record', refusal_code: 'EvidenceStale' };
  for (const [reply, status, settles] of [[refusal, 409, true], [refusal, 200, false],
    [{ ...terminal, expected_version: 2 }, 200, false], [{ ...terminal, repository_id: 'other' }, 200, false]]) {
    const client = fresh(async () => json(reply, status));
    await client.connect(token); await client.stage(7, 1, 'edit', { body: 'x' }, binding);
    if (settles) { assert.equal((await client.send()).refusal, 'EvidenceStale'); assert.equal(client.pending, null); }
    else { await assert.rejects(client.send()); assert.ok(client.pending); }
    client.disconnect();
  }
});
test('milestone 404 is only absence with its exact history envelope', async () => {
  const missing = { ...history, found: false, milestone: null, events: [] };
  const client = fresh(async () => json(missing, 404)); await client.connect(token);
  assert.equal((await client.read(7)).reply.found, false); client.disconnect();
  for (const reply of [history, {}, { ...missing, events: history.events }]) {
    const invalid = fresh(async () => json(reply, 404)); await invalid.connect(token);
    await assert.rejects(invalid.read(7)); invalid.disconnect();
  }
});
