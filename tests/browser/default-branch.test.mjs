import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { defaultBranchSnapshot, defaultBranchCommand, defaultBranchPublication, DEFAULT_BRANCH_RECEIPT_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/default-branch.mjs';
import { token, actor, href, hex, tip, head, observation, row, page, publication, outcome, json, rig, deferred } from './default-branch-fixtures.mjs';

for (const algorithm of ['sha1', 'sha256']) {
  test(algorithm + ': one pinned observation prepares and publishes only the selected exact default change', async () => {
    const r = rig(); await r.ready(algorithm);
    assert.equal(r.calls.length, 2); assert.equal(r.calls[0].method, 'GET');
    assert.match(r.calls[0].url, /\/api\/v1\/default-branch$/);
    const listing = new URLSearchParams(r.calls[1].body);
    assert.equal(listing.get('expected_head'), head); assert.equal(listing.get('namespace'), 'branches');
    assert.equal(listing.get('object_format'), algorithm); assert.equal(listing.get('cursor_encoding'), 'hex');
    await r.client.prepare(hex('refs/heads/topic')); const p = r.client.pending;
    assert.equal(r.calls.length, 2); assert.equal(p.source.principal, actor);
    assert.deepEqual(p.command, { expected_default_hex: hex('refs/heads/main'), reference_hex: hex('refs/heads/topic'), expected_tip: tip(algorithm, 'b') });
    r.responses.push(json(publication(p))); const result = await r.client.send();
    assert.equal(result.outcome, 'committed'); assert.equal(result.headChanged, true); assert.equal(r.client.pending, null); assert.equal(r.client.observed, null);
    const sent = r.calls[2]; assert.equal(sent.headers['Idempotency-Key'], p.key); assert.equal(sent.method, 'POST');
    assert.deepEqual([...new URLSearchParams(sent.body)], Object.entries({ ...p.command, expected_tip: p.command.expected_tip.split(':')[1] }));
    for (const call of r.calls) {
      assert.equal(call.headers.Authorization, 'Bearer ' + token); assert.equal(call.credentials, 'omit');
      assert.equal(call.mode, 'same-origin'); assert.equal(call.redirect, 'error'); assert.equal(call.cache, 'no-store');
    }
    assert.equal(r.calls[0].headers['Idempotency-Key'], undefined); assert.equal(r.calls[1].headers['Idempotency-Key'], undefined);
  });
  test(algorithm + ': absent, unborn and same-target cases preserve their distinct expectations', async () => {
    for (const reference of [null, hex('refs/heads/main')]) {
      const r = rig(), read = observation(algorithm, { default_reference_hex: reference, tip: null, unborn: reference !== null });
      await r.ready(algorithm, read); await r.client.prepare(hex('refs/heads/topic'));
      const p = r.client.pending;
      assert.equal(p.command.expected_default_hex ?? null, reference); assert.equal(p.command.expect_no_default ?? false, reference === null);
      r.responses.push(json(publication(p))); assert.equal((await r.client.send()).outcome, 'committed');
    }
    const r = rig(); await r.ready(algorithm); await r.client.prepare(hex('refs/heads/main'));
    r.responses.push(json(publication(r.client.pending)));
    assert.equal((await r.client.send()).headChanged, false);
  });
  test(algorithm + ': byte-only names remain exact from listing through command and recovery receipt', async () => {
    const raw = hex('refs/heads/z') + 'ff', r = rig();
    await r.ready(algorithm, observation(algorithm), page(algorithm, { refs: [...page(algorithm).refs, { ref: null, ref_hex: raw, object_id: tip(algorithm, 'd') }] }));
    await r.client.prepare(raw); const p = r.client.pending, receipt = r.client.exportReceipt();
    assert.equal(p.command.reference_hex, raw); assert.equal(p.command.expected_tip, tip(algorithm, 'd'));
    assert.ok(!receipt.includes(token)); assert.throws(() => r.client.discardUnsent());
    const b = rig(); await b.client.connect(token); await b.client.restoreReceipt(receipt);
    assert.equal(b.calls.length, 0); assert.deepEqual(b.client.pending.command, p.command); assert.equal(b.client.pending.key, p.key);
    b.responses.push(json(publication(p))); await b.client.send();
    assert.equal(new URLSearchParams(b.calls[0].body).get('reference_hex'), raw);
  });
}

test('malformed or ambiguous default observations refuse before candidate discovery', async () => {
  for (const changes of [
    { schema_version: 2 }, { type: 'source_refs' }, { read_only: false }, { transaction_created: true }, { published: true },
    { principal_id: 'not-an-actor' }, { snapshot_token: 'alg:1:aa' }, { source_head: '' },
    { default_reference_hex: null, tip: tip(), unborn: false },
    { default_reference_hex: null, tip: null, unborn: true },
    { tip: null, unborn: false }, { tip: tip('sha256') }, { tip: '0'.repeat(40) },
    { default_reference_hex: hex('refs/tags/v1') }, { default_reference_hex: undefined }, { unborn: undefined },
  ]) {
    const r = rig(); await r.client.connect(token); r.responses.push(json(observation('sha1', changes)));
    await assert.rejects(r.client.load()); assert.equal(r.calls.length, 1); assert.equal(r.client.observed, null);
  }
});

test('candidate pages must retain exact repository, snapshot, source head and native bytes', async () => {
  for (const changes of [
    { repository_incarnation: '55'.repeat(16) }, { object_format: 'sha256' }, { snapshot_token: 'alg:1:' + 'f'.repeat(64) },
    { source_head: 'another-head' }, { namespace: 'tags' }, { read_only: false },
    { refs: [{ ...row('refs/heads/main'), ref_hex: hex('refs/heads/other') }] },
  ]) {
    const r = rig(); await r.client.connect(token); r.responses.push(json(observation()), json(page('sha1', changes)));
    await assert.rejects(r.client.load()); assert.equal(r.calls.length, 2); assert.equal(r.client.observed, null); assert.deepEqual(r.client.knownRefs, []);
    await assert.rejects(r.client.prepare(hex('refs/heads/main')));
  }
});

test('pinned pagination preserves initial HEAD and targets while retaining exact byte cursors', async () => {
  const r = rig(), rows = Array.from({ length: 100 }, (_, i) => row('refs/heads/b' + String(i).padStart(3, '0')));
  await r.ready('sha1', observation(), page('sha1', { refs: rows, next_after: rows.at(-1).ref_hex }));
  r.responses.push(json(page('sha1', { after: rows.at(-1).ref_hex, refs: [row('refs/heads/z')] })));
  await r.client.load({ next: true }); assert.equal(r.calls.length, 3);
  const request = new URLSearchParams(r.calls[2].body);
  assert.equal(request.get('after'), rows.at(-1).ref_hex); assert.equal(request.get('expected_head'), head);
  assert.equal(r.client.knownRefs.length, 101); await r.client.prepare(rows[0].ref_hex);
  assert.equal(r.client.pending.command.expected_tip, tip());
});

test('a moved or malformed later page clears candidates instead of mixing snapshots', async () => {
  const r = rig(), rows = Array.from({ length: 100 }, (_, i) => row('refs/heads/b' + String(i).padStart(3, '0')));
  await r.ready('sha1', observation(), page('sha1', { refs: rows, next_after: rows.at(-1).ref_hex }));
  r.responses.push(json(page('sha1', { after: rows.at(-1).ref_hex, snapshot_token: 'alg:2:' + 'f'.repeat(64), refs: [] })));
  await assert.rejects(r.client.load({ next: true })); assert.equal(r.client.observed, null); assert.deepEqual(r.client.knownRefs, []);
});

test('commands reject ambiguous expectations, other namespaces, untyped tips and invented authority fields', async () => {
  const valid = { expected_default_hex: hex('refs/heads/main'), reference_hex: hex('refs/heads/topic'), expected_tip: tip() };
  for (const change of [
    { expect_no_default: true }, { expected_default_hex: undefined }, { expected_default_hex: hex('refs/tags/v1') },
    { reference_hex: hex('refs/heads/') }, { reference_hex: 'FF' }, { expected_tip: 'a'.repeat(40) },
    { expected_tip: tip('sha256') }, { expected_tip: 'sha1:' + '0'.repeat(40) }, { principal_id: actor }, { force: true },
  ]) assert.throws(() => defaultBranchCommand({ ...valid, ...change }, 'sha1'));
  assert.throws(() => defaultBranchCommand({ reference_hex: valid.reference_hex, expected_tip: tip(), expect_no_default: 'true' }, 'sha1'));
  const r = rig(); await r.ready(); await assert.rejects(r.client.prepare(hex('refs/heads/invented'))); assert.equal(r.calls.length, 2);
});

test('caller-owned observation and pending copies cannot change the frozen body or key', async () => {
  const r = rig(); await r.ready();
  const observed = r.client.observed, refs = r.client.knownRefs; observed.referenceHex = null; refs[1].object_id = tip('sha1', 'f');
  await r.client.prepare(hex('refs/heads/topic')); const p = r.client.pending;
  p.command.reference_hex = hex('refs/heads/evil');
  assert.equal(r.client.pending.command.reference_hex, hex('refs/heads/topic'));
  assert.equal(r.client.pending.command.expected_tip, tip('sha1', 'b'));
  r.responses.push(new Error('lost response')); await assert.rejects(r.client.send(), error => error.outcomeUnknown);
  const retained = r.client.pending; r.responses.push(json(publication(retained))); await r.client.send();
  assert.equal(r.calls[2].body, r.calls[3].body); assert.equal(r.calls[2].headers['Idempotency-Key'], r.calls[3].headers['Idempotency-Key']);
  assert.equal(r.calls.length, 4);
});

test('a publication changing any observed coordinate remains unknown and keeps the original request', async () => {
  for (const changes of [
    { principal_id: '99'.repeat(16) }, { repository_incarnation: '88'.repeat(16) }, { authentication: 'operator-assertion' },
    { operation: 'rename' }, { terminal: false }, { expected_default_reference_hex: null },
    { default_reference_hex: hex('refs/heads/main') }, { expected_tip: tip('sha1', 'c') }, { direct_refs_changed: true },
    { head_changed_by_transaction: false }, { decision_sequence: 0 }, { code: 'contradictory-refusal' },
  ]) {
    const r = rig(); await r.ready(); await r.client.prepare(hex('refs/heads/topic')); const p = r.client.pending;
    r.responses.push(json(publication(p, 'committed', changes)));
    await assert.rejects(r.client.send(), error => error.outcomeUnknown); assert.equal(r.client.pending.key, p.key);
  }
});

test('a native refusal is terminal only when its command and false change flags match', async () => {
  const r = rig(); await r.ready(); await r.client.prepare(hex('refs/heads/topic')); const p = r.client.pending;
  r.responses.push(json(publication(p, 'refused'), 409)); const result = await r.client.send();
  assert.equal(result.outcome, 'refused'); assert.equal(result.headChanged, false); assert.equal(r.client.pending, null);
  assert.throws(() => defaultBranchPublication(publication(p, 'refused', { head_changed_by_transaction: true }), p, 409));
  assert.throws(() => defaultBranchPublication(publication(p), p, 409));
});

test('original-key recovery keeps absence unknown and binds every observed seal until terminal', async () => {
  const r = rig(); await r.ready(); await r.client.prepare(hex('refs/heads/topic')); const p = r.client.pending;
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
    r.responses.push(json(outcome(p, state))); const result = await r.client.recover(); assert.equal(result.terminal, false); assert.equal(r.client.pending.key, p.key);
  }
  const changed = outcome(p, 'undecided'); changed.transaction.seal_id = 'another-seal'; r.responses.push(json(changed));
  await assert.rejects(r.client.recover(), /seal changed/);
  r.responses.push(json(outcome(p, 'committed'))); assert.equal((await r.client.recover()).outcome, 'committed'); assert.equal(r.client.pending, null);
  for (const call of r.calls.slice(2)) { assert.match(call.url, /\/outcomes$/); assert.equal(call.body, undefined); assert.equal(call.headers['Idempotency-Key'], p.key); }
});

test('recovery refuses another principal, command schema and regressed observations', async () => {
  for (const mutate of [
    reply => { reply.principal_id = '99'.repeat(16); },
    reply => { reply.transaction.request_schema = 'receive-admission/v1.0'; },
    reply => { reply.repository_incarnation = '99'.repeat(16); },
    reply => { reply.request_reexecuted = true; },
  ]) {
    const r = rig(); await r.ready(); await r.client.prepare(hex('refs/heads/topic')); const p = r.client.pending, reply = outcome(p);
    mutate(reply); r.responses.push(json(reply)); await assert.rejects(r.client.recover()); assert.equal(r.client.pending.key, p.key);
  }
  const r = rig(); await r.ready(); await r.client.prepare(hex('refs/heads/topic')); const p = r.client.pending;
  r.responses.push(json(outcome(p, 'undecided'))); await r.client.recover();
  r.responses.push(json(outcome(p, 'key_not_observed'))); await assert.rejects(r.client.recover()); assert.equal(r.client.pending.observedTx, 'tx-original');
});

test('receipt restoration requires the original credential and never reads or submits implicitly', async () => {
  const a = rig(); await a.ready(); await a.client.prepare(hex('refs/heads/topic')); const original = a.client.pending;
  const encoded = a.client.exportReceipt(); assert.ok(Buffer.byteLength(encoded) < DEFAULT_BRANCH_RECEIPT_LIMIT);
  for (const modify of [
    p => { p.route = '/other.git'; }, p => { p.origin = 'https://elsewhere.invalid'; },
    p => { p.fingerprint = '0'.repeat(64); }, p => { p.command.expected_tip = tip('sha1', 'e'); },
    p => { p.source.referenceHex = null; p.source.tip = null; }, p => { p.key += 'x'; },
    p => { p.principal_id = actor; }, p => { p.observedTx = 'invented'; },
  ]) {
    const r = rig(); await r.client.connect(token); const value = JSON.parse(encoded); modify(value);
    await assert.rejects(r.client.restoreReceipt(JSON.stringify(value))); assert.equal(r.calls.length, 0); assert.equal(r.client.pending, null);
  }
  const b = rig(); await b.client.connect('cd'.repeat(32)); await assert.rejects(b.client.restoreReceipt(encoded));
  const r = rig(); await r.client.connect(token); await r.client.restoreReceipt(encoded);
  assert.equal(r.calls.length, 0); assert.equal(r.client.pending.key, original.key); assert.equal(r.client.pending.exported, true);
  assert.throws(() => r.client.discardUnsent()); await assert.rejects(r.client.load());
  r.client.disconnect(); await assert.rejects(r.client.connect('cd'.repeat(32))); await r.client.connect(token);
  r.responses.push(json(publication(original))); await r.client.send(); assert.equal(r.calls.length, 1);
});

test('cancelled observations and old credentials cannot install late repository data', async () => {
  for (const action of ['cancel', 'disconnect']) {
    const r = rig(); await r.client.connect(token); const gate = deferred(); r.responses.push(() => gate.promise);
    const read = r.client.load(); await Promise.resolve(); r.client[action](); gate.resolve(json(observation()));
    await assert.rejects(read); assert.equal(r.client.observed, null); assert.equal(r.calls.length, 1);
  }
});

test('clearing observations does not abort a dispatched native mutation or replace its responsibility', async () => {
  const r = rig(); await r.ready(); await r.client.prepare(hex('refs/heads/topic')); const p = r.client.pending, gate = deferred();
  r.responses.push(() => gate.promise); const sending = r.client.send(); await Promise.resolve(); r.client.cancel();
  assert.equal(r.calls.at(-1).signal.aborted, false); assert.equal(r.client.pending.key, p.key);
  gate.resolve(json(publication(p))); assert.equal((await sending).outcome, 'committed');
});

test('default-branch transport allows only pinned reads and exact-key native administration', async () => {
  let calls = 0;
  const t = new Transport({ href, pageSuffix: '/ui/default-branch/', cryptoImpl: webcrypto, fetchImpl: async () => { calls += 1; return json({}); } });
  await t.connect(token);
  const body = new URLSearchParams({ expected_default_hex: hex('refs/heads/main'), reference_hex: hex('refs/heads/topic'), expected_tip: tip().split(':')[1] }).toString();
  for (const [path, request] of [
    ['pulls', {}], ['source/branches/delete', { method: 'POST', body, key: 'k', read: false }],
    ['default-branch', { method: 'POST', body, key: 'k' }], ['default-branch', { method: 'POST', body, read: false }],
    ['default-branch', { method: 'GET', key: 'k' }], ['default-branch', { method: 'GET', body: '' }],
    ['default-branch?expected_head=x', {}], ['default-branch?force=true', {}],
    ['default-branch?expected_head=' + head + '&expected_head=' + head, {}],
    ['source/refs', { method: 'POST', body: 'object_format=sha1&namespace=branches&limit=100&cursor_encoding=hex' }],
    ['source/refs', { method: 'POST', body: new URLSearchParams({ object_format: 'sha1', namespace: 'tags', limit: '100', cursor_encoding: 'hex', expected_head: head }).toString() }],
    ['outcomes', { method: 'POST', body, key: 'k', read: false }],
  ]) await assert.rejects(t.request(path, { maximum: 32 * 1024, ...request }));
  assert.equal(calls, 0);
  await t.request('default-branch', { maximum: 16 * 1024 });
  await t.request('default-branch', { method: 'POST', body, key: 'k', read: false, statuses: [200, 409], maximum: 32 * 1024 });
  await t.request('outcomes', { method: 'POST', key: 'k', read: false, maximum: 32 * 1024 }); assert.equal(calls, 3);
  for (const suffix of ['/ui/branches/', '/ui/pulls/', '/ui/source/', '/ui/tags/']) {
    const isolated = new Transport({ href: href.replace('/ui/default-branch/', suffix), pageSuffix: suffix, cryptoImpl: webcrypto,
      fetchImpl: async () => { throw new Error('must not send'); } });
    await isolated.connect(token);
    await assert.rejects(isolated.request('default-branch', { method: 'POST', body, key: 'k', read: false, statuses: [200, 409], maximum: 32 * 1024 }), /Invalid API route/);
  }
});
