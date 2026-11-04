import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { BranchClient, expectedUpdates, transactionCommand, transactionForm, TRANSACTION_LIMIT, RECEIPT_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/branches.mjs';
import { hex, utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

const token = '0123456789abcdef'.repeat(4), href = 'https://example.invalid/repo.git/ui/branches/';
const head = `alg:1:${'1'.repeat(64)}`, actor = '4'.repeat(32);
const identity = algorithm => ({ schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: algorithm });
const oid = (algorithm = 'sha1', byte = 'a') => byte.repeat(algorithm === 'sha1' ? 40 : 64);
const refHex = name => hex(utf8.encode(name));
const main = refHex('refs/heads/main'), topic = refHex('refs/heads/topic');
const row = (name, algorithm = 'sha1', byte = 'a') => ({ ref: name, ref_hex: refHex(name), object_id: `${algorithm}:${oid(algorithm, byte)}` });
const page = (algorithm = 'sha1') => ({ ...identity(algorithm), type: 'source_refs', namespace: 'branches', cursor_encoding: 'hex', source_head: 'head-id', snapshot_token: head,
  after: null, limit: 50, next_after: null, read_only: true, transaction_created: false, published: false, direct_refs_only: true,
  refs: [row('refs/heads/main', algorithm), row('refs/heads/topic', algorithm, 'b')] });
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
function rig(algorithm = 'sha1', cryptoImpl = webcrypto) {
  const calls = [], responses = [];
  const client = new BranchClient({ href, cryptoImpl, fetchImpl: async (url, options) => {
    calls.push({ url: url.href, ...options }); const response = responses.shift();
    if (response instanceof Error) throw response;
    if (typeof response === 'function') return response(url, options);
    return response ?? json(page(algorithm));
  } });
  return { client, calls, responses };
}
async function ready(algorithm = 'sha1') {
  const r = rig(algorithm); await r.client.connect(token); await r.client.list({ objectFormat: algorithm }); return r;
}
function stageMixed(client) {
  client.stage('create', { ref: 'refs/heads/new', sourceRefHex: main });
  client.stage('update', { refHex: topic, sourceRefHex: main });
  client.stage('delete', { refHex: main });
}
async function prepared(algorithm = 'sha1') { const r = await ready(algorithm); stageMixed(r.client); await r.client.prepareTransaction(); return r; }
function publication(p, outcome = 'committed') {
  return { ...identity(p.scope.format), type: 'branch_publication', principal_id: actor, operation: 'transaction',
    atomic: true, terminal: true, forge_transition: false, tx_id: 'batch-tx', decision_sequence: 8, outcome,
    ...(outcome === 'committed' ? { repository_commit_id: 'batch-rcr' } : { refusal_record_id: 'batch-refusal', code: 'TargetRefMoved', code_point: 2 }),
    updates: expectedUpdates('transaction', p.fields).map(update => ({ ...update,
      expected_commit: update.expected_commit === null ? null : `${p.scope.format}:${update.expected_commit}`,
      new_commit: update.new_commit === null ? null : `${p.scope.format}:${update.new_commit}` })),
  };
}
function outcome(p, state = 'committed') {
  const terminal = ['committed', 'refused'].includes(state);
  return { ...identity(p.scope.format), type: 'transaction_outcome', principal_id: actor, selector: 'transaction', command_index: null, state, terminal,
    transaction: ['key_not_observed', 'seal_not_observed'].includes(state) ? null : { tx_id: 'batch-tx', seal_id: 'seal-id', request_schema: 'schema-id', canonical_request_digest: { algorithm: 1, hex: 'a'.repeat(64) } },
    decision: !terminal ? null : state === 'committed' ? { kind: state, decision_sequence: 8, repository_commit_id: 'batch-rcr' } : { kind: state, decision_sequence: 8, code: 'TargetRefMoved', code_point: 2, refusal_record_id: 'batch-refusal' },
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}

for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm} mixed branch batch captures exact tips and publishes once`, async () => {
    const { client, calls, responses } = await prepared(algorithm), saved = client.pending;
    assert.equal(calls.length, 1); assert.equal(saved.operation, 'transaction'); assert.deepEqual(client.stagedChanges, []);
    assert.deepEqual(saved.fields.changes, [
      { operation: 'create', ref_hex: refHex('refs/heads/new'), new_commit: oid(algorithm) },
      { operation: 'update', ref_hex: topic, expected_commit: oid(algorithm, 'b'), new_commit: oid(algorithm) },
      { operation: 'delete', ref_hex: main, expected_commit: oid(algorithm) },
    ]);
    const body = transactionForm(saved.fields); saved.fields.changes[0].new_commit = oid(algorithm, 'f');
    // Independent native-shaped effects, rather than the client's own expected
    // effects helper, establish create/update/delete semantics in both domains.
    responses.push(json({ ...identity(algorithm), type: 'branch_publication', principal_id: actor, operation: 'transaction',
      atomic: true, terminal: true, forge_transition: false, tx_id: 'batch-tx', decision_sequence: 8, outcome: 'committed', repository_commit_id: 'batch-rcr',
      updates: [
        { ref: 'refs/heads/new', ref_hex: refHex('refs/heads/new'), expected_commit: null, new_commit: `${algorithm}:${oid(algorithm)}`, force: false },
        { ref: 'refs/heads/topic', ref_hex: topic, expected_commit: `${algorithm}:${oid(algorithm, 'b')}`, new_commit: `${algorithm}:${oid(algorithm)}`, force: false },
        { ref: 'refs/heads/main', ref_hex: main, expected_commit: `${algorithm}:${oid(algorithm)}`, new_commit: null, force: false },
      ],
    })); assert.equal((await client.send()).outcome, 'committed');
    assert.equal(calls.length, 2); assert.match(calls[1].url, /\/source\/branches\/transaction$/);
    assert.equal(calls[1].body, body); assert.equal(calls[1].headers['Idempotency-Key'], saved.key);
    assert.deepEqual([...new URLSearchParams(body)], [
      ['object_format', algorithm], ['create', `${refHex('refs/heads/new')}:${oid(algorithm)}`],
      ['update', `${topic}:${oid(algorithm, 'b')}:${oid(algorithm)}`], ['delete', `${main}:${oid(algorithm)}`],
    ]);
    assert.equal(client.pending, null); assert.equal(client.page, null); assert.deepEqual(client.stagedChanges, []);
  });
  test(`${algorithm} lost batch reply restores without reads and resends original bytes`, async () => {
    const a = await prepared(algorithm), pending = a.client.pending;
    a.responses.push(new Error('lost response')); await assert.rejects(a.client.send(), error => error.outcomeUnknown);
    const receipt = a.client.exportReceipt(); assert.equal(JSON.parse(receipt).type, 'frankengit-branch-transaction-retry-v1');
    assert.ok(!receipt.includes(token)); assert.ok(utf8.encode(receipt).length <= RECEIPT_LIMIT);
    const b = rig(algorithm); await b.client.connect(token); await b.client.restoreReceipt(receipt);
    assert.equal(b.calls.length, 0); assert.equal(b.client.pending.sent, true); assert.equal(b.client.pending.exported, true);
    assert.throws(() => b.client.discardUnsent());
    b.responses.push(json(publication(pending))); await b.client.send();
    assert.equal(b.calls.length, 1); assert.equal(b.calls[0].body, a.calls[1].body);
    assert.equal(b.calls[0].headers['Idempotency-Key'], a.calls[1].headers['Idempotency-Key']);
  });
  test(`${algorithm} canonical refusal settles the whole batch without partial publication`, async () => {
    const r = await prepared(algorithm); r.responses.push(json(publication(r.client.pending, 'refused'), 409));
    assert.equal((await r.client.send()).outcome, 'refused'); assert.equal(r.client.pending, null); assert.equal(r.client.page, null);
    assert.equal(r.calls.length, 2);
  });
}

test('batch targets and new-tip sources preserve byte-only references exactly', async () => {
  const r = rig(), raw = { ref: null, ref_hex: refHex('refs/heads/x') + 'ff', object_id: `sha1:${oid('sha1', 'c')}` };
  await r.client.connect(token); r.responses.push(json({ ...page(), refs: [...page().refs, raw] })); await r.client.list();
  r.client.stage('create', { ref: 'refs/heads/café', sourceRefHex: raw.ref_hex });
  r.client.stage('update', { refHex: raw.ref_hex, sourceRefHex: main });
  await r.client.prepareTransaction(); const p = r.client.pending;
  const effects = expectedUpdates('transaction', p.fields);
  assert.equal(effects[1].ref, null); assert.equal(effects[1].ref_hex, raw.ref_hex); assert.equal(effects[0].new_commit, oid('sha1', 'c'));
  const restored = rig(); await restored.client.connect(token); await restored.client.restoreReceipt(r.client.exportReceipt());
  restored.responses.push(json(publication(p))); await restored.client.send();
  assert.equal(new URLSearchParams(restored.calls[0].body).get('update'), `${raw.ref_hex}:${oid('sha1', 'c')}:${oid()}`);
});

test('staging is copy-isolated, duplicate targets fail locally, and removing a change permits restaging', async () => {
  const { client, calls } = await ready(); stageMixed(client); const draft = client.stagedChanges;
  draft[0].ref_hex = topic; assert.notEqual(client.stagedChanges[0].ref_hex, topic);
  for (const op of ['update', 'delete']) assert.throws(() => client.stage(op, { refHex: topic, sourceRefHex: main }), /only once/);
  assert.throws(() => client.stage('create', { ref: 'refs/heads/new', sourceRefHex: topic }), /only once/);
  await assert.rejects(client.prepare('delete', { ref: 'refs/heads/topic' }), /staged atomic batch/);
  for (const index of [-1, 3, 0.5]) assert.throws(() => client.removeStaged(index));
  client.removeStaged(1); client.stage('delete', { refHex: topic });
  assert.equal(client.stagedChanges.at(-1).operation, 'delete'); assert.equal(calls.length, 1);
  client.clearStaged(); assert.deepEqual(client.stagedChanges, []);
  await assert.rejects(client.prepareTransaction(), /between 1 and 32/);
});

test('staging accepts only listed branch identities and refuses invalid operations before any write', async () => {
  const { client, calls } = await ready();
  for (const [operation, selection] of [
    ['rename', { refHex: topic }], ['force', { refHex: topic }],
    ['delete', { refHex: refHex('refs/heads/unlisted') }], ['delete', { refHex: refHex('refs/tags/v1') }],
    ['create', { ref: 'refs/heads/main', sourceRefHex: topic }], ['create', { ref: 'refs/heads/new', sourceRefHex: refHex('refs/heads/unlisted') }],
    ['update', { refHex: main, sourceRefHex: main }], ['create', { ref: 'refs/heads/../bad', sourceRefHex: main }],
  ]) assert.throws(() => client.stage(operation, selection));
  assert.equal(calls.length, 1); assert.deepEqual(client.stagedChanges, []); assert.equal(client.pending, null);
});

test('the complete staged profile has closed fields, exact hash domains and finite operation/name bounds', () => {
  const command = { object_format: 'sha1', changes: [{ operation: 'update', ref_hex: topic, expected_commit: oid('sha1', 'b'), new_commit: oid() }] };
  for (const edit of [
    p => { p.force = true; }, p => { p.changes[0].force = false; }, p => { p.changes[0].ref = 'refs/heads/topic'; },
    p => { p.changes[0].operation = 'rename'; }, p => { p.changes[0].expected_commit = '0'.repeat(40); },
    p => { p.changes[0].new_commit = `sha256:${'a'.repeat(64)}`; }, p => { delete p.changes[0].expected_commit; },
    p => { p.changes[0].ref_hex = topic.toUpperCase(); }, p => { p.changes[0].ref_hex = refHex('refs/heads/' + 'x'.repeat(1014)); },
    p => { p.changes.push(p.changes[0]); }, p => { p.changes = Array(1); }, p => { p.changes = []; },
  ]) { const value = structuredClone(command); edit(value); assert.throws(() => transactionCommand(value)); }
  assert.equal(transactionCommand(command).changes[0].expected_commit, oid('sha1', 'b'));
});

test('32 small changes are supported and the 33rd is refused without altering staging', async () => {
  const { client, calls } = await ready();
  for (let index = 0; index < TRANSACTION_LIMIT; index += 1) client.stage('create', { ref: `refs/heads/new-${index}`, sourceRefHex: main });
  assert.throws(() => client.stage('create', { ref: 'refs/heads/too-many', sourceRefHex: main }), /between 1 and 32/);
  assert.equal(client.stagedChanges.length, 32); await client.prepareTransaction();
  assert.equal(client.pending.fields.changes.length, 32); assert.equal(calls.length, 1);
});

test('preparation refuses an unexportable batch before taking pending responsibility', async () => {
  const { client, calls } = await ready();
  for (let index = 0; index < TRANSACTION_LIMIT; index += 1) client.stage('create', { ref: `refs/heads/${String(index).padStart(2, '0')}${'x'.repeat(1011)}`, sourceRefHex: main });
  await assert.rejects(client.prepareTransaction(), /Receipt exceeds/);
  assert.equal(client.pending, null); assert.equal(client.stagedChanges.length, 32); assert.equal(calls.length, 1);
  client.removeStaged(0); assert.equal(client.stagedChanges.length, 31);
});

test('large complete transaction effects have their own bounded reply budget', async () => {
  const { client, calls, responses } = await ready();
  for (let index = 0; index < 24; index += 1) client.stage('create', { ref: `refs/heads/${String(index).padStart(2, '0')}${'x'.repeat(1011)}`, sourceRefHex: main });
  await client.prepareTransaction(); const reply = publication(client.pending);
  assert.ok(utf8.encode(JSON.stringify(reply)).length > 64 * 1024); assert.ok(utf8.encode(client.exportReceipt()).length < RECEIPT_LIMIT);
  responses.push(json(reply)); assert.equal((await client.send()).outcome, 'committed'); assert.equal(calls.length, 2);
});

test('near-limit batches reserve JSON-escaped recovery identities before prepare and restore', async () => {
  const original = await prepared(), base = JSON.parse(original.client.exportReceipt());
  function boundaryReceipt(room) {
    const p = structuredClone(base);
    const names = Array.from({ length: 32 }, (_, index) => `refs/heads/b-${String(index).padStart(2, '0')}`);
    p.fields.changes = names.map(name => ({ operation: 'create', ref_hex: refHex(name), new_commit: oid() }));
    const target = RECEIPT_LIMIT - room;
    let remaining = Math.floor((target - utf8.encode(JSON.stringify(p)).length) / 2);
    for (let index = 0; index < names.length; index += 1) {
      const padding = Math.min(1024 - utf8.encode(names[index]).length, remaining);
      names[index] += 'x'.repeat(padding); remaining -= padding; p.fields.changes[index].ref_hex = refHex(names[index]);
    }
    assert.equal(remaining, 0);
    const body = transactionForm(p.fields);
    const digest = createHash('sha256').update(JSON.stringify([p.origin, p.route, p.fingerprint,
      [p.scope.tenant, p.scope.repository, p.scope.incarnation, p.scope.format], p.operation, p.nonce, body])).digest('hex');
    p.key = `fgbranch1-${p.nonce}-${digest}`;
    assert.ok(RECEIPT_LIMIT - utf8.encode(JSON.stringify(p)).length >= room);
    assert.ok(RECEIPT_LIMIT - utf8.encode(JSON.stringify(p)).length <= room + 1);
    return { encoded: JSON.stringify(p), names };
  }
  // 400 spare bytes fit a 256-byte ASCII observation, but not a valid opaque
  // identity whose 256 quote/backslash bytes expand to 512 bytes in JSON.
  const tooClose = boundaryReceipt(400), r = await ready();
  for (const ref of tooClose.names) r.client.stage('create', { ref, sourceRefHex: main });
  await assert.rejects(r.client.prepareTransaction(), /Receipt exceeds/); assert.equal(r.client.pending, null);
  assert.equal(r.client.stagedChanges.length, 32); assert.equal(r.calls.length, 1);
  const restored = rig(); await restored.client.connect(token);
  await assert.rejects(restored.client.restoreReceipt(tooClose.encoded), /Receipt exceeds/); assert.equal(restored.client.pending, null); assert.equal(restored.calls.length, 0);
  await restored.client.restoreReceipt(boundaryReceipt(550).encoded);
  const pending = restored.client.pending, reply = outcome(pending, 'undecided'); reply.transaction.tx_id = '\\'.repeat(256);
  restored.responses.push(json(reply)); await restored.client.recover();
  const exported = restored.client.exportReceipt(); assert.ok(utf8.encode(exported).length <= RECEIPT_LIMIT);
  assert.equal(JSON.parse(exported).observedTx, '\\'.repeat(256));
});

test('pinned continuation preserves staged tips and a fresh snapshot explicitly drops staging', async () => {
  const r = rig(); await r.client.connect(token);
  r.responses.push(json({ ...page(), refs: [row('refs/heads/main')], limit: 1, next_after: main })); await r.client.list({ limit: 1 });
  r.client.stage('create', { ref: 'refs/heads/new', sourceRefHex: main }); const staged = r.client.stagedChanges;
  r.responses.push(json({ ...page(), refs: [row('refs/heads/topic', 'sha1', 'b')], limit: 1, after: main }));
  await r.client.list({ next: true, objectFormat: 'sha256', namespace: 'tags', limit: 100 });
  assert.deepEqual(r.client.stagedChanges, staged); assert.equal(new URLSearchParams(r.calls[1].body).get('expected_head'), head);
  r.client.stage('delete', { refHex: topic }); await r.client.list(); assert.deepEqual(r.client.stagedChanges, []);
  await assert.rejects(r.client.prepareTransaction());
});

test('a nonfinal byte-only branch boundary continues in exact hex while preserving staged operations', async () => {
  const r = rig(), raw = { ref: null, ref_hex: refHex('refs/heads/main') + 'ff', object_id: `sha1:${oid('sha1', 'c')}` };
  await r.client.connect(token);
  r.responses.push(json({ ...page(), refs: [raw], limit: 1, next_after: raw.ref_hex })); await r.client.list({ limit: 1 });
  assert.equal(new URLSearchParams(r.calls[0].body).get('cursor_encoding'), 'hex');
  assert.equal(new URLSearchParams(r.calls[0].body).has('after'), false);
  r.client.stage('create', { ref: 'refs/heads/new', sourceRefHex: raw.ref_hex }); r.client.stage('delete', { refHex: raw.ref_hex });
  const staged = r.client.stagedChanges;
  r.responses.push(json({ ...page(), refs: [row('refs/heads/topic', 'sha1', 'b')], limit: 1, after: raw.ref_hex }));
  await r.client.list({ next: true, namespace: 'tags', limit: 100 });
  const next = new URLSearchParams(r.calls[1].body);
  assert.equal(next.get('after'), raw.ref_hex); assert.equal(next.get('cursor_encoding'), 'hex'); assert.equal(next.get('expected_head'), head);
  assert.equal(next.get('namespace'), 'branches'); assert.equal(next.get('limit'), '1'); assert.deepEqual(r.client.stagedChanges, staged);
  r.client.stage('update', { refHex: topic, sourceRefHex: raw.ref_hex }); await r.client.prepareTransaction();
  assert.equal(r.client.pending.fields.changes[2].new_commit, oid('sha1', 'c')); assert.equal(r.calls.length, 2);
});

test('cancel and disconnect clear unprepared staging while a frozen batch keeps its original identity', async () => {
  const r = await ready(); stageMixed(r.client); r.client.cancel(); assert.deepEqual(r.client.stagedChanges, []);
  await r.client.list(); stageMixed(r.client); r.client.disconnect(); assert.deepEqual(r.client.stagedChanges, []);
  await r.client.connect(token); await r.client.list(); stageMixed(r.client); await r.client.prepareTransaction();
  const p = r.client.pending; r.client.exportReceipt(); r.client.disconnect(); assert.equal(r.client.pending.key, p.key);
  await assert.rejects(r.client.connect('b'.repeat(64))); await r.client.connect(token);
  assert.throws(() => r.client.stage('delete', { refHex: main })); await assert.rejects(r.client.list());
  assert.throws(() => r.client.clearStaged()); assert.equal(r.client.pending.key, p.key);
});

for (const [name, edit] of [
  ['missing effect', p => p.updates.pop()], ['extra effect', p => p.updates.push(p.updates[0])], ['reordered effects', p => p.updates.reverse()],
  ['duplicate target', p => { p.updates[1] = p.updates[0]; }], ['changed expected tip', p => { p.updates[1].expected_commit = oid(); }],
  ['changed new tip', p => { p.updates[0].new_commit = oid('sha1', 'f'); }], ['invented ref text', p => { p.updates[0].ref = 'refs/heads/evil'; }],
  ['force', p => { p.updates[0].force = true; }], ['partial decision', p => { p.atomic = false; }],
  ['wrong operation', p => { p.operation = 'create'; }], ['wrong scope', p => { p.repository_incarnation = 'f'.repeat(32); }],
]) test(`transaction ${name} cannot erase the original pending request`, async () => {
  const r = await prepared(), saved = r.client.pending, reply = publication(saved); edit(reply); r.responses.push(json(reply));
  await assert.rejects(r.client.send(), error => error.outcomeUnknown); assert.equal(r.client.pending.key, saved.key);
});

for (const state of ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused']) test(`batch original-key recovery preserves ${state}`, async () => {
  const r = await prepared(), pending = r.client.pending; r.responses.push(json(outcome(pending, state)));
  const result = await r.client.recover(); assert.equal(result.terminal, ['committed', 'refused'].includes(state));
  assert.equal(r.client.pending === null, result.terminal); assert.equal(r.calls.at(-1).body, undefined);
  assert.equal(r.calls.at(-1).headers['Idempotency-Key'], pending.key);
});

for (const [name, edit] of [
  ['legacy type', p => { p.type = 'frankengit-branch-retry-v1'; }], ['nontransaction operation', p => { p.operation = 'delete'; }],
  ['changed target', p => { p.fields.changes[0].ref_hex = refHex('refs/heads/different'); }],
  ['changed tip', p => { p.fields.changes[0].new_commit = oid('sha1', 'f'); }], ['reordered changes', p => p.fields.changes.reverse()],
  ['additional field', p => { p.fields.changes[0].force = true; }], ['duplicate target', p => p.fields.changes.push(p.fields.changes[0])],
  ['scope change', p => { p.scope.incarnation = 'f'.repeat(32); }],
]) test(`tampered transaction receipt ${name} fails before network`, async () => {
  const a = await prepared(), encoded = JSON.parse(a.client.exportReceipt()); edit(encoded);
  const b = rig(); await b.client.connect(token); await assert.rejects(b.client.restoreReceipt(JSON.stringify(encoded)));
  assert.equal(b.calls.length, 0); assert.equal(b.client.pending, null);
});

test('historical v1 single-operation receipt and key commitment remain compatible', async () => {
  const fingerprint = createHash('sha256').update(token).digest('hex'), nonce = '0'.repeat(32);
  const scope = { tenant: '1'.repeat(32), repository: '2'.repeat(32), incarnation: '3'.repeat(32), format: 'sha1' };
  const body = `object_format=sha1&ref=refs%2Fheads%2Ftopic&expected_commit=${'b'.repeat(40)}`;
  const digest = createHash('sha256').update(JSON.stringify(['https://example.invalid', '/repo.git', fingerprint,
    [scope.tenant, scope.repository, scope.incarnation, scope.format], 'delete', nonce, body])).digest('hex');
  const original = { type: 'frankengit-branch-retry-v1', origin: 'https://example.invalid', route: '/repo.git', operation: 'delete',
    fields: { object_format: 'sha1', ref: 'refs/heads/topic', expected_commit: 'b'.repeat(40) }, scope, nonce, fingerprint,
    key: `fgbranch1-${nonce}-${digest}`, observedTx: null, observedPrincipal: null };
  const r = rig(); await r.client.connect(token); await r.client.restoreReceipt(JSON.stringify(original));
  assert.equal(r.calls.length, 0); assert.deepEqual(JSON.parse(r.client.exportReceipt()), original);
  r.responses.push(new Error('lost response')); await assert.rejects(r.client.send(), error => error.outcomeUnknown);
  assert.equal(r.calls[0].body, body); assert.match(r.calls[0].url, /\/source\/branches\/delete$/);
  assert.equal(r.calls[0].headers['Idempotency-Key'], original.key);
});

test('cancellation during batch key preparation cannot install a stale pending request', async () => {
  let release, held = false;
  const cryptoImpl = { getRandomValues: bytes => webcrypto.getRandomValues(bytes), subtle: { digest: (...args) => held
    ? new Promise(resolve => { release = async () => resolve(await webcrypto.subtle.digest(...args)); }) : webcrypto.subtle.digest(...args) } };
  const r = rig('sha1', cryptoImpl); await r.client.connect(token); await r.client.list(); stageMixed(r.client); held = true;
  const preparing = r.client.prepareTransaction(); await Promise.resolve(); r.client.cancel(); await release();
  await assert.rejects(preparing, /cancelled/); assert.equal(r.client.pending, null); assert.deepEqual(r.client.stagedChanges, []); assert.equal(r.calls.length, 1);
});

test('cancelling a view never aborts or removes an already submitted atomic batch', async () => {
  const r = await prepared(), pending = r.client.pending; let release;
  r.responses.push(() => new Promise(resolve => { release = resolve; })); const sending = r.client.send();
  await Promise.resolve(); r.client.cancel(); assert.equal(r.calls.at(-1).signal.aborted, false); assert.equal(r.client.pending.key, pending.key);
  release(json(publication(pending))); assert.equal((await sending).outcome, 'committed'); assert.equal(r.client.pending, null);
});
