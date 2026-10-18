import test from 'node:test';
import assert from 'node:assert/strict';
import { ProtectionClient, protectionPolicy, protectionBranch, protectionChanges, protectionU64, protectionSnapshot, protectionJson,
  PROTECTION_RECEIPT_LIMIT, requestBody, fastForwardCommand } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { TOKEN, ROTATED, ADMIN, REVIEWER, OTHER, HREF, hex, policy, snapshot, terminal, recovered, response, harness, deferred, webcrypto } from './protection-fixtures.mjs';

for (const format of ['sha1', 'sha256']) {
  test(`${format}: load, edit, stage and publish exact full replacement with full-width counters`, async () => {
    const h = harness({ format }); await h.ready();
    const replacement = policy(); replacement.administrators.push(OTHER); replacement.branches[0].required_reviewers = [OTHER];
    const pending = await h.client.stage(replacement); replacement.administrators.length = 0;
    assert.equal(h.calls.length, 1); assert.equal(h.client.pending.intent.source.version, '9007199254740992');
    const body = new URLSearchParams(pending.intent.body);
    assert.equal(body.get('expected_epoch'), '9007199254740993');
    assert.deepEqual(body.getAll('administrator'), [ADMIN, OTHER]);
    assert.deepEqual(body.getAll('required_reviewer'), [`${hex('refs/heads/main')}:${OTHER}`]);
    assert.equal(body.has('clear'), false); assert.equal(body.has('principal'), false);
    pending.intent.body = 'forged'; assert.notEqual(h.client.pending.intent.body, pending.intent.body);
    const result = await h.client.send(); assert.equal(result.outcome, 'committed');
    assert.equal(result.sequence, '18446744073709551615'); assert.equal(result.deliveryAcknowledged, null);
    assert.equal(h.client.pending, null); assert.equal(h.client.observed, null);
    const send = h.calls[1]; assert.equal(send.url.href, 'https://forge.example/team/repo.git/api/v1/protection');
    assert.equal(send.method, 'POST'); assert.equal(send.headers['Idempotency-Key'].startsWith('fgbp1-'), true);
    assert.equal(send.headers.Authorization, `Bearer ${TOKEN}`); assert.equal(send.credentials, 'omit');
    assert.equal(send.redirect, 'error'); assert.equal(send.mode, 'same-origin'); assert.equal(send.referrerPolicy, 'no-referrer');
    await assert.rejects(h.client.stage(policy()), /Load an installed/);
  });
  test(`${format}: byte-only refs and explicit clearing retain full ownership`, async () => {
    const h = harness({ format }); await h.ready();
    const raw = Buffer.concat([Buffer.from('refs/heads/'), Buffer.from([0xff])]).toString('hex');
    const pending = await h.client.stage({ administrators: [OTHER], branches: [{ reference_hex: raw, required_reviewers: [REVIEWER] }] });
    assert.equal(new URLSearchParams(pending.intent.body).get('required_reviewer'), `${raw}:${REVIEWER}`);
    h.client.discardUnsent();
    await assert.rejects(h.client.stage({ administrators: [ADMIN], branches: [] }), /explicit clear/);
    await assert.rejects(h.client.stage(policy(), true), /clear cannot/);
    const clear = await h.client.stage({ administrators: [ADMIN], branches: [] }, true);
    assert.equal(new URLSearchParams(clear.intent.body).get('clear'), 'true');
    assert.equal((await h.client.send()).outcome, 'committed');
  });
  test(`${format}: an unavailable reply retries only the original bytes and key`, async () => {
    let attempts = 0;
    const h = harness({ format, respond: call => { if (call.method === 'POST' && ++attempts === 1) throw new Error('fixture lost reply'); } });
    await h.ready(); await h.client.stage(policy());
    await assert.rejects(h.client.send(), error => error.outcomeUnknown);
    assert.equal(h.client.pending.sent, true); assert.throws(() => h.client.discardUnsent(), /never-sent/);
    await h.client.send(); assert.equal(h.calls[1].body, h.calls[2].body);
    assert.equal(h.calls[1].headers['Idempotency-Key'], h.calls[2].headers['Idempotency-Key']);
  });
  test(`${format}: original receipt can recover with a rotated credential without resending`, async () => {
    const a = harness({ format }); await a.ready(); await a.client.stage(policy()); const saved = a.client.exportReceipt();
    assert.equal(saved.includes(TOKEN), false); assert.equal(a.client.pending.exported, true);
    assert.throws(() => a.client.discardUnsent(), /never-exported/);
    const b = harness({ format }); await b.client.connect(ROTATED, ADMIN, { recoveryOnly: true });
    await b.client.restoreReceipt(saved); assert.equal(b.calls.length, 0);
    const key = b.client.pending.intent.key; await assert.rejects(b.client.send(), /recovery-only/);
    await assert.rejects(b.client.load(), /recovery-only/); await assert.rejects(b.client.stage(policy()), /recovery-only/);
    const result = await b.client.recover(); assert.equal(result.outcome, 'committed'); assert.equal(b.client.recoveryOnly, true);
    assert.equal(b.calls.length, 1); assert.equal(b.calls[0].body, undefined);
    assert.equal(b.calls[0].headers['Content-Type'], undefined); assert.equal(b.calls[0].headers['Idempotency-Key'], key);
    assert.equal(b.calls[0].headers.Authorization, `Bearer ${ROTATED}`);
    await assert.rejects(b.client.load(), /recovery-only/);
    await b.client.connect(ROTATED, ADMIN); await b.client.load();
  });
  test(`${format}: imported original-token receipts can explicitly retry, never auto-send`, async () => {
    const a = harness({ format }); await a.ready(); await a.client.stage(policy()); const saved = a.client.exportReceipt();
    const b = harness({ format }); await b.client.connect(TOKEN, ADMIN); await b.client.restoreReceipt(saved);
    assert.equal(b.calls.length, 0); const original = a.client.pending.intent;
    await b.client.send(); assert.equal(b.calls[0].body, original.body); assert.equal(b.calls[0].headers['Idempotency-Key'], original.key);
  });
}

test('policy summary enumerates all administrator and reviewer additions/removals', () => {
  const after = { administrators: [OTHER], branches: [{ reference_hex: hex('refs/heads/topic'), required_reviewers: [OTHER] }] };
  assert.deepEqual(protectionChanges(policy(), after), { administrators_added: [OTHER], administrators_removed: [ADMIN], branches: [
    { reference_hex: hex('refs/heads/main'), change: 'removed', added: [], removed: [REVIEWER] },
    { reference_hex: hex('refs/heads/topic'), change: 'added', added: [OTHER], removed: [] }] });
  const reordered = { administrators: [OTHER, ADMIN], branches: [...policy().branches].reverse() };
  assert.deepEqual(protectionPolicy(reordered).administrators, [ADMIN, OTHER]);
});

test('uninstalled and disabled policies are distinguished, and remote bootstrap is never staged', async () => {
  const uninstalled = snapshot('sha1', { version: '0', installed: false, enabled: false, policy: null });
  const h = harness({ respond: () => response(uninstalled) }); await h.ready();
  assert.equal(h.client.observed.policy, null); await assert.rejects(h.client.stage(policy()), /trusted-local/);
  assert.equal(h.calls.length, 1);
  assert.equal(protectionSnapshot(snapshot('sha1', { enabled: false, policy: { administrators: [ADMIN], branches: [] } })).policy.branches.length, 0);
});

for (const value of ['00', '-1', '+1', '1e3', ' 1', '', '18446744073709551616', 1, null]) {
  test(`exact u64 rejects ${JSON.stringify(value)}`, () => assert.throws(() => protectionU64(value)));
}
test('policy epoch and version exhaustion refuse staging before new requests', async () => {
  for (const field of ['version', 'policy_epoch']) {
    const h = harness({ respond: () => response(snapshot('sha1', { [field]: '18446744073709551615' })) });
    await h.ready(); await assert.rejects(h.client.stage(policy()), /counter/); assert.equal(h.calls.length, 1);
  }
});
test('native unquoted outcome sequences preserve all u64 bits; numeric policy versions remain invalid', () => {
  const parsed = protectionJson(Buffer.from('{"decision_sequence":18446744073709551615}'));
  assert.equal(parsed.decision_sequence, '18446744073709551615');
  assert.throws(() => protectionJson(Buffer.from('{"decision_sequence":18446744073709551616}')));
  assert.throws(() => protectionJson(Buffer.from('{"counter":9007199254740992}')));
  assert.throws(() => protectionSnapshot(snapshot('sha1', { version: 1 })));
});
test('native branch byte validation has no text normalization or injection aliases', () => {
  for (const ref of ['refs/heads/', 'refs/tags/v1', '/refs/heads/a', 'refs/heads/a b', 'refs/heads/.a',
    'refs/heads/a..b', 'refs/heads/a.lock', 'refs/heads/a//b', 'refs/heads/a@{b', 'refs/heads/a\nb', 'refs/heads/a\\b']) {
    assert.throws(() => protectionBranch(hex(ref)), ref);
  }
  assert.throws(() => protectionBranch('6A')); assert.throws(() => protectionBranch('0'));
  assert.equal(protectionBranch(hex('refs/heads/a&b=1')), hex('refs/heads/a&b=1'));
});
test('policy bounds, duplicates and unknown fields refuse before publication', () => {
  for (const value of [{ administrators: [], branches: [] }, { administrators: [ADMIN, ADMIN], branches: [] },
    { administrators: Array(33).fill(ADMIN), branches: [] }, { ...policy(), force: true },
    { ...policy(), branches: Array(65).fill(policy().branches[0]) },
    { ...policy(), branches: [policy().branches[0], policy().branches[0]] },
    { ...policy(), branches: [{ reference_hex: hex('refs/heads/main'), required_reviewers: [] }] }]) assert.throws(() => protectionPolicy(value));
});
test('largest structurally valid policy still obeys the encoded command byte ceiling', async () => {
  const h = harness(); await h.ready();
  const people = Array.from({ length: 32 }, (_, i) => (i + 1).toString(16).padStart(32, '0'));
  const branches = Array.from({ length: 64 }, (_, i) => ({ reference_hex: hex(`refs/heads/${String(i).padStart(2, '0')}${'x'.repeat(1000)}`), required_reviewers: people }));
  await assert.rejects(h.client.stage({ administrators: people, branches }), /256 KiB/);
  assert.equal(h.client.pending, null); assert.equal(h.calls.length, 1);
});
for (const patch of [{ complete: false }, { published: true }, { enabled: false }, { installed: false }, { transaction_created: true }, { version: '0' }]) {
  test(`incomplete/inconsistent snapshot cannot authorize editing: ${JSON.stringify(patch)}`, async () => {
    const h = harness({ respond: () => response(snapshot('sha1', patch)) }); await h.client.connect(TOKEN, ADMIN);
    await assert.rejects(h.client.load()); assert.equal(h.client.observed, null);
  });
}
test('failed explicit refresh removes stale editable observation while pending intent stays exact', async () => {
  let reads = 0;
  const h = harness({ respond: call => call.method === 'GET' && ++reads > 1 ? response({}, 409) : null });
  await h.ready(); await h.client.stage(policy()); const saved = h.client.pending;
  await assert.rejects(h.client.load('alg:2:' + 'e'.repeat(64)), error => error.status === 409);
  assert.equal(h.client.observed, null); assert.deepEqual(h.client.pending, saved);
});
test('a changed incarnation is refused, even after reconnect with unresolved intent', async () => {
  let moved = false;
  const h = harness({ respond: call => call.method === 'GET' && moved ? response(snapshot('sha1', { repository_incarnation: 'e'.repeat(32) })) : null });
  await h.ready(); await h.client.stage(policy()); h.client.disconnect(); moved = true;
  await h.client.connect(TOKEN, ADMIN); await assert.rejects(h.client.load(), /incarnation changed/);
});
for (const patch of [{ principal_id: OTHER }, { expected_version: '1' }, { expected_epoch: '1' }, { resulting_epoch: '1' },
  { delivery_acknowledged: true }, { decision_sequence: '0' }, { refusal_record_id: 'contradiction' }]) {
  test(`mismatched publication receipt remains unresolved: ${JSON.stringify(patch)}`, async () => {
    const h = harness({ respond: (call, c) => call.method === 'POST' ? response(terminal(c.pending, 'committed', patch)) : null });
    await h.ready(); await h.client.stage(policy()); await assert.rejects(h.client.send(), error => error.outcomeUnknown);
    assert.equal(h.client.pending.sent, true);
  });
}
test('canonical refusal settles but never silently refreshes or retries a new policy version', async () => {
  const h = harness({ respond: (call, c) => call.method === 'POST' ? response(terminal(c.pending, 'refused'), 409) : null });
  await h.ready(); await h.client.stage(policy()); const result = await h.client.send();
  assert.equal(result.outcome, 'refused'); assert.equal(h.client.pending, null); assert.equal(h.client.observed, null);
  assert.equal(h.calls.length, 2);
});
test('wrong credentials never inherit an unresolved request, but explicit rotation can recover it', async () => {
  const h = harness(); await h.ready(); await h.client.stage(policy()); const key = h.client.pending.intent.key;
  await assert.rejects(h.client.connect(ROTATED, ADMIN), /Original protection credential/); assert.equal(h.client.connected, false);
  await assert.rejects(h.client.connect(TOKEN, OTHER, { recoveryOnly: true }), /another principal/);
  await h.client.connect(ROTATED, ADMIN, { recoveryOnly: true }); assert.equal(h.client.pending.intent.key, key);
});
test('non-observation never clears responsibility or turns recovery-only into write access', async () => {
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
    const h = harness({ respond: (call, c) => call.url.pathname.endsWith('/outcomes') ? response(recovered(c.pending, state)) : null });
    await h.ready(); await h.client.stage(policy()); h.client.exportReceipt();
    await h.client.connect(ROTATED, ADMIN, { recoveryOnly: true });
    assert.equal((await h.client.recover()).state, state); assert.ok(h.client.pending); assert.equal(h.client.recoveryOnly, true);
    await assert.rejects(h.client.send(), /recovery-only/);
  }
});
test('recovered transaction/seal knowledge survives receipt export and refuses regression', async () => {
  let step = 0;
  const h = harness({ respond: (call, c) => call.url.pathname.endsWith('/outcomes') ? response(recovered(c.pending, ++step === 1 ? 'undecided' : 'key_not_observed')) : null });
  await h.ready(); await h.client.stage(policy()); await h.client.recover();
  await assert.rejects(h.client.recover(), /regressed/); assert.equal(h.client.pending.observedTransaction.tx_id, 'fixture-tx');
  const saved = h.client.exportReceipt(); const b = harness({ respond: (call, c) => call.url.pathname.endsWith('/outcomes') ? response(recovered(c.pending, 'committed', {
    transaction: { ...c.pending.observedTransaction, seal_id: 'wrong-seal' } })) : null });
  await b.client.connect(TOKEN, ADMIN); await b.client.restoreReceipt(saved); await assert.rejects(b.client.recover(), /regressed/);
});
test('wrong recovery principal or scope is never accepted even with a valid-looking terminal', async () => {
  for (const patch of [{ principal_id: OTHER }, { repository_id: 'e'.repeat(32) }, { request_reexecuted: true }, { absence_proves_non_commit: true }]) {
    const h = harness({ respond: (call, c) => call.url.pathname.endsWith('/outcomes') ? response(recovered(c.pending, 'committed', patch)) : null });
    await h.ready(); await h.client.stage(policy()); await assert.rejects(h.client.recover()); assert.ok(h.client.pending);
  }
});
test('tampered receipt command, version, principal, endpoint and unknown fields never install', async () => {
  const h = harness(); await h.ready(); await h.client.stage(policy()); const saved = h.client.exportReceipt();
  for (const mutate of [r => r.intent.body += '&clear=true', r => r.intent.source.version = '2', r => r.intent.principal = OTHER,
    r => r.intent.route = '/other.git', r => r.intent.origin = 'https://other.example', r => r.intent.replacement.administrators = [OTHER],
    r => r.intent.key = 'new-key', r => r.extra = true]) {
    const bad = JSON.parse(saved); mutate(bad); const b = harness(); await b.client.connect(TOKEN, ADMIN);
    await assert.rejects(b.client.restoreReceipt(JSON.stringify(bad))); assert.equal(b.client.pending, null); assert.equal(b.calls.length, 0);
  }
  const b = harness(); await b.client.connect(TOKEN, ADMIN);
  await assert.rejects(b.client.restoreReceipt('x'.repeat(PROTECTION_RECEIPT_LIMIT + 1)), /oversized/);
});
test('revocation disconnects without losing the original pending command', async () => {
  const h = harness({ respond: call => call.method === 'POST' ? response({}, 401) : null });
  await h.ready(); await h.client.stage(policy()); const key = h.client.pending.intent.key;
  await assert.rejects(h.client.send(), error => error.status === 401); assert.equal(h.client.connected, false);
  assert.equal(h.client.pending.intent.key, key); assert.ok(h.client.exportReceipt());
});
test('disconnect during hashing fences stale connection and stage results', async () => {
  const gate = deferred(), crypto = { getRandomValues: a => webcrypto.getRandomValues(a), subtle: { digest: () => gate.promise } };
  const h = harness({ cryptoImpl: crypto }); const connecting = h.client.connect(TOKEN, ADMIN);
  h.client.disconnect(); gate.resolve(new Uint8Array(32).buffer); await assert.rejects(connecting, /superseded/); assert.equal(h.client.connected, false);
  const h2 = harness(); await h2.ready(); const staging = h2.client.stage(policy()); h2.client.disconnect();
  await assert.rejects(staging, /superseded/); assert.equal(h2.client.pending, null);
});
test('late publication replies after disconnect cannot clear pending responsibility', async () => {
  const gate = deferred();
  const h = harness({ respond: call => call.method === 'POST' ? gate.promise : null });
  await h.ready(); await h.client.stage(policy()); const original = h.client.pending; const sending = h.client.send();
  await assert.rejects(h.client.send(), /settling/); h.client.disconnect(); gate.resolve(response(terminal(original)));
  await assert.rejects(sending); assert.ok(h.client.pending); assert.equal(h.client.connected, false);
});
test('response framing and bounded stream failures cannot masquerade as publication decisions', async () => {
  for (const reply of [() => new Response('not JSON', { headers: { 'Content-Type': 'text/plain' } }),
    () => new Response('x'.repeat(32769), { headers: { 'Content-Type': 'application/json' } }),
    () => new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': '3' } })]) {
    const h = harness({ respond: call => call.method === 'POST' ? reply() : null });
    await h.ready(); await h.client.stage(policy()); await assert.rejects(h.client.send()); assert.ok(h.client.pending);
  }
});
test('silent response body observes deadline and cancellation without erasing a pending request', async () => {
  let cancelled = false;
  const h = harness({ timeoutMs: 30, respond: call => call.method === 'POST' ? new Response(new ReadableStream({ cancel() { cancelled = true; } }), {
    headers: { 'Content-Type': 'application/json' } }) : null });
  await h.ready(); await h.client.stage(policy()); await assert.rejects(h.client.send()); assert.equal(cancelled, true); assert.ok(h.client.pending);
});
test('existing PR actions keep their original body and no-bundle fast-forward behavior', () => {
  const fields = { object_format: 'sha1', pull_request_version: 7, source_ref: 'refs/heads/topic', target_ref: 'refs/heads/main',
    source_tip: 'a'.repeat(40), target_tip: 'b'.repeat(40) };
  assert.deepEqual(fastForwardCommand(fields), fields);
  const body = requestBody('fast-forward', fields, null, '1'.repeat(32));
  assert.equal(body.contentType, 'application/x-www-form-urlencoded'); assert.equal(new TextDecoder().decode(body.bytes).includes('pull_request_version=7'), true);
  assert.throws(() => requestBody('fast-forward', fields, new Uint8Array([1]), '1'.repeat(32)), /must not carry/);
});
