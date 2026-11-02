import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { QueueClient, RECEIPT_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/queues.mjs';
import { Transport, rootFor } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { queueCommand, queueMutationRequest, queuePage, queueShow, queuePublication,
  queueReference } from '../../crates/fgit-node/src/smart_http/server/browser/queues-protocol.mjs';

const HREF = 'https://forge.example/team/repo.git/ui/queues/';
const TOKEN = 'c'.repeat(64), ROTATED = 'd'.repeat(64), ACTOR = '3'.repeat(32), OTHER = '4'.repeat(32);
const HEAD = `alg:2:${'b'.repeat(64)}`;
const hex = value => Buffer.from(value).toString('hex');
const ids = (algorithm = 'sha1') => ({ schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
  repository_incarnation: '5'.repeat(32), object_format: algorithm });
const scope = (algorithm = 'sha1') => ({ tenant: ids().tenant_id, repository: ids().repository_id,
  incarnation: ids().repository_incarnation, format: algorithm });
const tip = (which = 'a', algorithm = 'sha1') => which.repeat(algorithm === 'sha1' ? 40 : 64);
const reference = (name, value) => ({ [name]: value, [`${name}_hex`]: hex(value) });
function queued(pull = 7, algorithm = 'sha1') {
  return { pull_request: pull, ...reference('source_ref', `refs/heads/topic${pull}`), head_tip: `${algorithm}:${tip('a', algorithm)}`,
    enqueued_by: ACTOR, priority: pull === 7 ? 10 : 0, enqueued_version: pull === 7 ? 1 : 2 };
}
function row(number = 1, algorithm = 'sha1') {
  return { number, ...reference('target_ref', 'refs/heads/main'), version: 3,
    entries: [queued(7, algorithm), queued(8, algorithm)], order: [7, 8], active_batch: null };
}
const page = (extra = {}, algorithm = 'sha1') => ({ ...ids(algorithm), type: 'merge_queue_page', source_head: 'head/observed',
  snapshot_token: HEAD, after: 0, limit: 20, next_after: null, queues: [row(1, algorithm)], complete: true, ...extra });
const show = (extra = {}, algorithm = 'sha1') => ({ ...ids(algorithm), type: 'merge_queue', source_head: 'head/observed',
  snapshot_token: HEAD, number: 1, found: true, version: 3, queue: row(1, algorithm), complete: true, ...extra });
function pull(number = 7, algorithm = 'sha1') {
  return { ...ids(algorithm), type: 'pull_request', source_head: 'head/observed', snapshot_token: HEAD, number, found: true,
    pull_request: { number, version: 4, state: 'open', merge_only: false, merge: null, opened_by: ACTOR, last_metadata_actor: ACTOR,
      data: { object_format: algorithm, ...reference('source_ref', `refs/heads/topic${number}`), ...reference('target_ref', 'refs/heads/main'),
        source_tip: `${algorithm}:${tip('a', algorithm)}`, target_tip: `${algorithm}:${tip('b', algorithm)}`, title: 'Exact PR', body: '<script>inert</script>' } } };
}
function fields(action = 'enqueue', extra = {}, algorithm = 'sha1') {
  const common = { expected_version: 3, target_ref: 'refs/heads/main' };
  if (action === 'dequeue') return { ...common, pull_request: 7, reason: 'withdrawn', ...extra };
  if (action === 'reorder') return { ...common, entry: [8, 7], ...extra };
  return { ...common, pull_request: 7, expected_pull_request_version: 4, source_ref: 'refs/heads/topic7',
    expected_source_tip: tip('a', algorithm), expected_target_tip: tip('b', algorithm),
    ...(action === 'land' ? { expected_policy_epoch: 1 } : { priority: 10 }), ...extra };
}
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const make = (fetchImpl = async () => json(page()), options = {}) => new QueueClient({ href: HREF, fetchImpl, cryptoImpl: webcrypto, ...options });
const recoveryOptions = () => ({ recoveryOnly: true, originalPrincipal: ACTOR });
function nativeReference(name, bytes) {
  let value;
  try { value = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(bytes, 'hex')); } catch { value = null; }
  return { [name]: value, [`${name}_hex`]: bytes };
}
function publication(pending, committed = true) {
  const f = pending.fields, algorithm = pending.scope.format;
  let proposed;
  if (pending.action === 'enqueue' || pending.action === 'land') proposed = {
    name: pending.action, pull_request: f.pull_request, expected_pull_request_version: f.expected_pull_request_version,
    ...nativeReference('source_ref', f.source_ref_hex), expected_source_tip: `${algorithm}:${f.expected_source_tip}`,
    expected_target_tip: `${algorithm}:${f.expected_target_tip}`,
    ...(pending.action === 'land' ? { method: 'fast-forward-only', expected_policy_epoch: f.expected_policy_epoch } : { priority: f.priority }),
  };
  else if (pending.action === 'dequeue') proposed = { name: 'dequeue', pull_request: f.pull_request, reason: f.reason };
  else proposed = { name: 'reorder', order: [...f.entry] };
  return { ...ids(algorithm), type: 'merge_queue_publication', principal_id: ACTOR, number: pending.number,
    ...nativeReference('target_ref', f.target_ref_hex), expected_version: f.expected_version, proposed_action: proposed,
    tx_id: 'tx/original', decision_sequence: 7, outcome: committed ? 'committed' : 'refused', committed,
    repository_commit_id: committed ? 'rcr/original' : null, refusal_record_id: committed ? null : 'refusal/original',
    refusal_code: committed ? null : 'PolicyDenied', refs_changed: committed && pending.action === 'land',
    delivery_acknowledged: null, historical_outcome: true, complete: true };
}
function outcome(state, extra = {}) {
  const terminal = ['committed', 'refused'].includes(state), { object_format: _, ...identity } = ids();
  return { ...identity, type: 'transaction_outcome', selector: 'transaction', command_index: null, principal_id: ACTOR,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
    state, terminal, transaction: state === 'undecided' || terminal ? { tx_id: 'tx/original', seal_id: 'seal/original',
      request_schema: 'frankengit/request/v1', canonical_request_digest: { algorithm: 2, hex: 'ab'.repeat(32) } } : null,
    decision: !terminal ? null : state === 'committed' ? { kind: state, decision_sequence: 7, repository_commit_id: 'rcr/original' }
      : { kind: state, decision_sequence: 7, refusal_record_id: 'refusal/original', code: 'PolicyDenied', code_point: 3 }, ...extra };
}
async function receipt(action = 'enqueue', algorithm = 'sha1') {
  const client = make(async () => json(page({}, algorithm)));
  await client.connect(TOKEN); await client.list(); await client.stage(1, action, fields(action, {}, algorithm));
  return client.exportReceipt();
}

test('queue commands preserve exact native bytes in both hash domains and reject inapplicable authority fields', () => {
  for (const algorithm of ['sha1', 'sha256']) {
    const input = fields('enqueue', {}, algorithm), encoded = { ...input,
      target_ref_hex: hex(input.target_ref), source_ref_hex: hex(input.source_ref),
      expected_source_tip: `${algorithm}:${input.expected_source_tip}` };
    delete encoded.target_ref; delete encoded.source_ref;
    const request = queueMutationRequest(1, 'enqueue', input, scope(algorithm));
    assert.equal(request.body, queueMutationRequest(1, 'enqueue', encoded, scope(algorithm)).body);
    const form = new URLSearchParams(request.body);
    assert.equal(form.get('expected_incarnation'), ids().repository_incarnation);
    assert.equal(form.get('object_format'), algorithm); assert.equal(form.get('expected_source_tip'), tip('a', algorithm));
    assert.equal(form.has('source_ref'), false); assert.equal(form.get('source_ref_hex'), encoded.source_ref_hex);
    assert.equal(request.path, 'queues/1/enqueue');
    for (const change of [{ actor: ACTOR }, { expected_incarnation: ids().repository_incarnation }, { object_format: algorithm },
      { priority: null }, { priority: -0 }, { priority: 0x100000000 }, { expected_version: -0 }, { expected_version: Number.MAX_SAFE_INTEGER },
      { expected_pull_request_version: 0 }, { pull_request: 0 }, { source_ref_hex: encoded.source_ref_hex },
      { source_ref: input.target_ref }, { expected_source_tip: '0'.repeat(tip('a', algorithm).length) },
      { expected_source_tip: `${algorithm === 'sha1' ? 'sha256' : 'sha1'}:${input.expected_source_tip}` }]) {
      assert.throws(() => queueCommand('enqueue', { ...input, ...change }, scope(algorithm)));
    }
  }
  const f = fields('enqueue'); delete f.priority;
  assert.equal(queueCommand('enqueue', f, scope()).priority, 0);
  for (const value of ['refs/heads/', 'refs/heads/a.lock', 'refs/heads/a..b', 'refs/heads/a b', 'refs/heads/a@{b', 'refs/tags/tag']) {
    assert.throws(() => queueCommand('enqueue', fields('enqueue', { source_ref: value }), scope()));
  }
  for (const entry of [[], [7, 7], [7, 0], Array.from({ length: 1025 }, (_, i) => i + 1)]) {
    assert.throws(() => queueCommand('reorder', fields('reorder', { entry }), scope()));
  }
  assert.throws(() => queueCommand('dequeue', fields('dequeue', { reason: 'quietly-drop' }), scope()));
  assert.throws(() => queueCommand('land', fields('land', { priority: 1 }), scope()));
  assert.throws(() => queueCommand('land', fields('land', { expected_source_tip: tip('b') }), scope()));
  assert.throws(() => queueCommand('land', fields('land', { expected_version: Number.MAX_SAFE_INTEGER - 1 }), scope()));
  assert.throws(() => queueCommand('land', fields('land', { expected_pull_request_version: Number.MAX_SAFE_INTEGER }), scope()));
  assert.throws(() => queueCommand('land-candidate', fields('land'), scope()));
});

test('complete pinned queue reads reject reordered, partial, cross-scope and contradictory observations', () => {
  assert.equal(queuePage(page()).head, HEAD);
  assert.deepEqual(queueShow(show(), 1).reply.queue.order, [7, 8]);
  assert.equal(queueShow(show({ found: false, version: 0, queue: null }), 1).reply.queue, null);
  for (const alter of [p => { p.complete = false; }, p => { delete p.complete; }, p => { p.authoritative = true; },
    p => { p.queues[0].order.reverse(); }, p => { p.queues[0].entries[0].source_ref = 'refs/heads/other'; },
    p => { p.queues[0].entries[1].pull_request = 7; }, p => { p.queues[0].entries[0].enqueued_version = 4; },
    p => { p.queues[0].entries[0].priority = -0; }, p => { p.queues[0].active_batch = 'no'; },
    p => { p.next_after = 1; }, p => { p.queues.unshift(row()); }, p => { p.tenant_id = 'tenant'; },
    p => { p.repository_incarnation = '6'.repeat(32); }, p => { p.snapshot_token = `alg:2:${'c'.repeat(64)}`; }]) {
    const changed = page(); alter(changed);
    assert.throws(() => queuePage(changed, { head: HEAD, scope: scope() }));
  }
  assert.throws(() => queueShow(show({ version: 2 }), 1));
  assert.throws(() => queueShow(show({ found: false }), 1));
  assert.throws(() => queueShow(show({ found: false, queue: null, version: -0 }), 1));
  assert.throws(() => queuePage(page(), { after: 1 }));
  assert.equal(queuePage(page({ limit: 1, next_after: 1 }), { limit: 1 }).reply.next_after, 1);
  const raw = hex('refs/heads/') + 'ff';
  assert.equal(queueReference({ source_ref: null, source_ref_hex: raw }, 'source_ref'), raw);
  const bytes = fields('enqueue'); delete bytes.source_ref; bytes.source_ref_hex = raw;
  assert.equal(queueCommand('enqueue', bytes, scope()).source_ref_hex, raw);
});

test('queue list, exact show and optional PR prefill are pinned private reads', async () => {
  const calls = [];
  const client = make(async (url, init) => {
    calls.push({ url, init });
    if (url.pathname.endsWith('/pulls/7')) return json(pull());
    if (url.pathname.endsWith('/queues/1')) return json(show());
    return json(page());
  });
  await client.connect(TOKEN);
  assert.deepEqual((await client.list()).binding, scope());
  assert.equal((await client.show(1, HEAD)).head, HEAD);
  assert.equal((await client.pull(7, HEAD)).reply.pull_request.version, 4);
  assert.equal(calls.length, 3);
  assert.equal(calls[1].url.searchParams.get('expected_head'), HEAD);
  assert.equal(calls[2].url.searchParams.get('expected_head'), HEAD);
  for (const { url, init } of calls) {
    assert.equal(url.origin, 'https://forge.example'); assert.equal(init.method, 'GET');
    assert.equal(init.headers.Authorization, `Bearer ${TOKEN}`); assert.equal(init.credentials, 'omit');
    assert.equal(init.redirect, 'error'); assert.equal(init.cache, 'no-store'); assert.equal(init.referrerPolicy, 'no-referrer');
    assert.equal(init.body, undefined);
  }
  await assert.rejects(client.list({ after: 1 }), /original snapshot/); assert.equal(calls.length, 3);
});

test('staging has no publication effect, retains immutable coordinates and accepts only matching terminal decisions', async () => {
  for (const algorithm of ['sha1', 'sha256']) for (const action of ['enqueue', 'dequeue', 'reorder', 'land']) {
    const calls = []; let client;
    client = make(async (url, init) => {
      calls.push({ url, init });
      return init.method === 'GET' ? json(page({}, algorithm)) : json(publication(client.pending));
    });
    await client.connect(TOKEN); await client.list();
    const input = fields(action, {}, algorithm), staged = await client.stage(1, action, input);
    input.target_ref = 'refs/heads/changed'; if (input.entry) input.entry.reverse();
    staged.fields.target_ref_hex = hex('refs/heads/changed');
    assert.equal(calls.length, 1); assert.equal(client.pending.state, 'staged');
    assert.equal(client.pending.fields.target_ref_hex, hex('refs/heads/main')); assert.equal('fingerprint' in client.pending, false);
    assert.match(client.pending.key, /^fgq1-[0-9a-f]{32}-[0-9a-f]{64}$/);
    const key = client.pending.key, original = client.pending.body;
    const result = await client.send();
    assert.equal(result.terminal, true); assert.equal(result.outcome, 'committed');
    assert.equal(result.refsChanged, action === 'land'); assert.equal(result.deliveryAcknowledged, null);
    assert.equal(result.tx, 'tx/original'); assert.equal(client.pending, null);
    assert.equal(calls[1].url.pathname, `/team/repo.git/api/v1/queues/1/${action}`);
    assert.equal(calls[1].init.headers['Idempotency-Key'], key); assert.equal(await calls[1].init.body.text(), original);
  }
});

test('reorder preserves full membership and cached head landing cannot silently switch members', async () => {
  const client = make(); await client.connect(TOKEN); await client.list();
  for (const entry of [[7], [7, 9]]) await assert.rejects(client.stage(1, 'reorder', fields('reorder', { entry })), /every current queue member/);
  await assert.rejects(client.stage(1, 'reorder', fields('reorder', { expected_version: 4 })), /exact queue version/);
  await assert.rejects(client.stage(1, 'land', fields('land', { pull_request: 8 })), /selected queue head/);
  await assert.rejects(client.stage(1, 'land', fields('land', { expected_source_tip: tip('c') })), /selected queue head/);
  await client.stage(1, 'reorder', fields('reorder')); client.discardUnsent();
  await client.stage(2, 'enqueue', fields('enqueue', { expected_version: 0 })); client.discardUnsent();
  const active = row(); active.active_batch = 'ab'.repeat(32);
  const blocked = make(async () => json(page({ queues: [active] })));
  await blocked.connect(TOKEN); await blocked.list();
  await assert.rejects(blocked.stage(1, 'dequeue', fields('dequeue')), /active batch/);
});

test('native refusal is terminal while malformed or mismatched receipts retain responsibility', async () => {
  const client = make(); await client.connect(TOKEN); await client.list(); await client.stage(1, 'land', fields('land'));
  const pending = client.pending, correct = publication(pending);
  for (const alter of [p => { p.complete = false; }, p => { p.type = 'merge_queue'; }, p => { p.number = 2; },
    p => { p.expected_version++; }, p => { p.refs_changed = false; }, p => { p.principal_id = 'actor'; },
    p => { p.proposed_action.expected_policy_epoch++; }, p => { p.proposed_action.method = 'merge-commit'; },
    p => { p.proposed_action.expected_target_tip = tip('c'); }, p => { p.proposed_action.source_ref_hex = hex('refs/heads/other'); },
    p => { p.delivery_acknowledged = true; }, p => { p.historical_outcome = false; }, p => { p.refusal_record_id = 'refusal'; },
    p => { delete p.refusal_code; }, p => { p.repository_incarnation = '6'.repeat(32); }]) {
    const changed = structuredClone(correct); alter(changed); assert.throws(() => queuePublication(changed, pending, 200));
  }
  assert.throws(() => queuePublication(correct, pending, 409));
  const refused = make(async (url, init) => init.method === 'GET' ? json(page()) : json(publication(refused.pending, false), 409));
  await refused.connect(TOKEN); await refused.list(); await refused.stage(1, 'land', fields('land'));
  const result = await refused.send(); assert.equal(result.outcome, 'refused'); assert.equal(result.refsChanged, false);
  assert.equal(result.refusal, 'PolicyDenied'); assert.equal(refused.pending, null);
});

test('lost responses and receipt import resend the original exact body and key without credential export', async () => {
  const writes = []; let client;
  client = make(async (url, init) => {
    if (init.method === 'GET') return json(page());
    writes.push({ key: init.headers['Idempotency-Key'], body: await init.body.text() });
    throw new Error('connection lost after dispatch');
  });
  await client.connect(TOKEN); await client.list(); await client.stage(1, 'enqueue', fields());
  await assert.rejects(client.send(), error => error.outcomeUnknown === true);
  assert.equal(client.pending.state, 'unknown');
  const serialized = client.exportReceipt(), retained = client.pending;
  assert.equal(serialized.includes(TOKEN), false); assert.ok(Buffer.byteLength(serialized) < RECEIPT_LIMIT);
  assert.throws(() => client.discardUnsent(), /dispatched or exported/);
  await assert.rejects(client.connect(ROTATED), /another credential/); assert.equal(client.connected, false);
  let restored;
  restored = make(async (url, init) => { writes.push({ key: init.headers['Idempotency-Key'], body: await init.body.text() }); return json(publication(restored.pending)); });
  await restored.connect(TOKEN); await restored.restoreReceipt(serialized);
  assert.equal(restored.pending.key, retained.key); assert.equal(restored.pending.body, retained.body);
  await restored.send(); assert.deepEqual(writes[0], writes[1]); assert.equal(restored.pending, null);
});

test('exported requests are uncertain even before send, and changed recovery commitments fail before network work', async () => {
  const original = JSON.parse(await receipt()); let calls = 0;
  const client = make(async () => { calls++; return json(page()); }); await client.connect(TOKEN);
  for (const alter of [p => { p.request.fields.priority++; }, p => { p.request.fields.expected_version++; },
    p => { p.request.action = 'land'; }, p => { p.request.number++; }, p => { p.request.nonce = '9'.repeat(32); },
    p => { p.request.key = p.request.key.slice(0, -1) + 'z'; }, p => { p.request.fingerprint = 'f'.repeat(64); },
    p => { p.request.scope.incarnation = '6'.repeat(32); }, p => { p.origin = 'https://elsewhere.example'; },
    p => { p.route = '/different.git'; }, p => { p.request.actor = ACTOR; }, p => { delete p.request.observedTx; }]) {
    const changed = structuredClone(original); alter(changed);
    await assert.rejects(client.restoreReceipt(JSON.stringify(changed))); assert.equal(client.pending, null);
  }
  await assert.rejects(client.restoreReceipt('x'.repeat(RECEIPT_LIMIT + 1))); assert.equal(calls, 0);
  await client.restoreReceipt(JSON.stringify(original)); assert.equal(client.pending.state, 'unknown');
  assert.throws(() => client.discardUnsent(), /exported/);
});

test('non-observation never proves non-commit, and recovered transaction and actor observations cannot regress', async () => {
  let reply = outcome('key_not_observed'); const calls = [];
  const client = make(async (url, init) => { calls.push({ url, init }); return json(reply); });
  await client.connect(TOKEN); await client.restoreReceipt(await receipt());
  assert.equal((await client.recover()).terminal, false); assert.equal(client.pending.state, 'unknown');
  assert.throws(() => client.discardUnsent(), /exported/);
  reply = outcome('undecided'); await client.recover(); assert.equal(client.pending.state, 'undecided');
  for (const changed of [outcome('key_not_observed'), outcome('committed', { principal_id: OTHER }),
    outcome('committed', { transaction: { ...reply.transaction, tx_id: 'tx/other' } }),
    outcome('committed', { absence_proves_non_commit: true }), outcome('committed', { request_reexecuted: true }),
    outcome('committed', { repository_incarnation: '6'.repeat(32) })]) {
    reply = changed; await assert.rejects(client.recover()); assert.equal(client.pending.observedTx, 'tx/original');
  }
  reply = outcome('committed'); assert.equal((await client.recover()).outcome, 'committed'); assert.equal(client.pending, null);
  for (const { url, init } of calls) { assert.ok(url.pathname.endsWith('/outcomes')); assert.equal(init.method, 'POST'); assert.equal(init.body, undefined); }
});

test('explicit rotated credential recovery is original-key-only and never enables queue reads or publication', async () => {
  const original = await receipt(); let reply = outcome('committed'), calls = 0;
  const client = make(async (url, init) => {
    calls++; assert.ok(url.pathname.endsWith('/outcomes')); assert.equal(init.headers.Authorization, `Bearer ${ROTATED}`);
    assert.equal(init.headers['Idempotency-Key'], JSON.parse(original).request.key); return json(reply);
  });
  await client.connect(ROTATED, recoveryOptions()); assert.equal(client.recoveryOnly, true);
  for (const operation of [() => client.list(), () => client.show(1), () => client.pull(7), () => client.stage(1, 'enqueue', fields()), () => client.send()]) {
    await assert.rejects(operation(), /Recovery-only/);
  }
  assert.throws(() => client.discardUnsent(), /Recovery-only/); assert.equal(calls, 0);
  await client.restoreReceipt(original);
  reply = outcome('committed', { principal_id: OTHER }); await assert.rejects(client.recover()); assert.ok(client.pending);
  reply = outcome('refused'); assert.equal((await client.recover()).outcome, 'refused'); assert.equal(client.pending, null);
  await assert.rejects(client.list(), /Recovery-only/); await assert.rejects(client.send(), /Recovery-only/);
});

test('recovery-only selection is active during hashing and rejects contradictory original principals', async () => {
  let release; const waiting = new Promise(resolve => { release = resolve; });
  const cryptoImpl = { getRandomValues: webcrypto.getRandomValues.bind(webcrypto), subtle: {
    digest: async (...args) => { await waiting; return webcrypto.subtle.digest(...args); },
  } };
  let calls = 0; const client = make(async () => { calls++; return json(page()); }, { cryptoImpl });
  const selected = recoveryOptions(), connecting = client.connect(ROTATED, selected); selected.originalPrincipal = OTHER; selected.recoveryOnly = false;
  assert.equal(client.recoveryOnly, true); await assert.rejects(client.list(), /Recovery-only/);
  release(); await connecting;
  const original = JSON.parse(await receipt()); original.request.observedPrincipal = OTHER;
  await assert.rejects(client.restoreReceipt(JSON.stringify(original)), /selected original principal/);
  original.request.observedPrincipal = ACTOR; await client.restoreReceipt(JSON.stringify(original));
  await assert.rejects(client.connect(ROTATED, { recoveryOnly: true, originalPrincipal: OTHER }), /retained queue observation/);
  assert.equal(client.connected, false); assert.ok(client.pending); assert.equal(calls, 0);
});

test('cancelReads cancels old observations without canceling a dispatched queue mutation', async () => {
  let readSignal, writeSignal, finishRead, finishWrite, readCount = 0;
  const client = make((url, init) => {
    if (init.method === 'GET') {
      if (++readCount === 1) return Promise.resolve(json(page()));
      readSignal = init.signal; return new Promise(resolve => { finishRead = resolve; });
    }
    writeSignal = init.signal; return new Promise(resolve => { finishWrite = resolve; });
  });
  await client.connect(TOKEN); await client.list(); await client.stage(1, 'enqueue', fields());
  const reading = client.show(1), writing = client.send(), terminal = publication(client.pending);
  client.cancelReads(); assert.equal(readSignal.aborted, true); assert.equal(writeSignal.aborted, false);
  finishRead(json(show())); finishWrite(json(terminal));
  await assert.rejects(reading); assert.equal((await writing).outcome, 'committed'); assert.equal(client.pending, null);
});

test('disconnect, timeout and revocation retain responsibility, and stale hashing cannot install a new request', async () => {
  for (const failure of ['disconnect', 'timeout', 'revoked']) {
    let finish, signal;
    const client = make((url, init) => {
      if (init.method === 'GET') return Promise.resolve(json(page()));
      if (failure === 'revoked') return Promise.resolve(json({}, 401));
      signal = init.signal; return new Promise((resolve, reject) => {
        finish = resolve; init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      });
    }, { timeoutMs: failure === 'timeout' ? 5 : 1000 });
    await client.connect(TOKEN); await client.list(); await client.stage(1, 'enqueue', fields()); const key = client.pending.key;
    const sending = client.send(); if (failure === 'disconnect') client.disconnect();
    await assert.rejects(sending, error => error.outcomeUnknown === true);
    assert.equal(client.pending.key, key); assert.equal(client.pending.state, 'unknown');
    if (failure !== 'timeout') assert.equal(client.connected, false);
    if (signal) { assert.equal(signal.aborted, true); finish(json(publication(client.pending))); }
  }
  let wait = false, release;
  const waiting = new Promise(resolve => { release = resolve; });
  const cryptoImpl = { getRandomValues: webcrypto.getRandomValues.bind(webcrypto), subtle: {
    digest: async (...args) => { if (wait) await waiting; return webcrypto.subtle.digest(...args); },
  } };
  const client = make(undefined, { cryptoImpl }); await client.connect(TOKEN); await client.list(); wait = true;
  const staging = client.stage(1, 'enqueue', fields()); client.disconnect(); release();
  await assert.rejects(staging, /superseded/); assert.equal(client.pending, null); assert.equal(client.busy, false);
});

test('queue Transport is a closed profile and does not widen existing PR routes or authorities', async () => {
  let calls = 0;
  const transport = new Transport({ href: HREF, pageSuffix: '/ui/queues/', cryptoImpl: webcrypto,
    fetchImpl: async () => { calls++; return json(page()); } });
  await transport.connect(TOKEN);
  const write = { method: 'POST', body: 'exact=body', key: 'original', read: false, statuses: [200, 409] };
  for (const [path, options] of [
    ['source/tree', {}], ['pulls', {}], ['pulls/7/update', write], ['queues/1/prepare', write], ['queues/1/land-candidate', write],
    ['queues/1/land?ignored=1', write], ['queues/1', { statuses: [200, 404], method: 'POST' }],
    ['queues?after=1', {}], ['queues?limit=101', {}], ['queues?limit=1&limit=2', {}], ['queues?after=01', {}],
    ['queues/1?after=0', { statuses: [200, 404] }], ['queues?actor=someone', {}], ['queues', { binary: true }],
    ['queues', { key: 'not-a-read' }], ['queues/1/enqueue', {}], ['queues/1/enqueue', { ...write, key: undefined }],
    ['queues/1/enqueue', { ...write, read: true }], ['queues/1/enqueue', { ...write, body: 'x'.repeat(65537) }],
    ['queues/1/enqueue', { ...write, contentType: 'application/json' }], ['outcomes', { ...write, body: undefined }],
    ['https://evil.example/queues', {}], ['../queues', {}],
  ]) await assert.rejects(transport.request(path, options));
  assert.equal(calls, 0);
  const regular = new Transport({ href: HREF.replace('/queues/', '/pulls/'), cryptoImpl: webcrypto,
    fetchImpl: async () => { calls++; return json(page()); } });
  await regular.connect(TOKEN); await assert.rejects(regular.request('queues')); assert.equal(calls, 0);
  assert.equal(rootFor(HREF, '/ui/queues/').route, '/team/repo.git');
});
