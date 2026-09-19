import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { BranchClient, refsPage, branchCommand, expectedUpdates, branchPublication, refName, refBytes, RECEIPT_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/branches.mjs';
import { Transport, hex, utf8, form } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
const token = 'a'.repeat(64), href = 'https://example.invalid/repo.git/ui/branches/';
const head = `alg:1:${'1'.repeat(64)}`, actor = '4'.repeat(32);
const scope = algorithm => ({ schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: algorithm });
const oid = (algorithm, byte = 'a') => byte.repeat(algorithm === 'sha1' ? 40 : 64);
const row = (name, algorithm = 'sha1', byte = 'a') => ({ ref: name, ref_hex: hex(utf8.encode(name)), object_id: `${algorithm}:${oid(algorithm, byte)}` });
const query = (algorithm = 'sha1') => ({ object_format: algorithm, namespace: 'branches', limit: 50 });
const page = (algorithm = 'sha1', rows = [row('refs/heads/main', algorithm), row('refs/heads/topic', algorithm, 'b')]) => ({
  ...scope(algorithm), type: 'source_refs', namespace: 'branches', source_head: 'head-id', snapshot_token: head,
  after: null, limit: 50, next_after: null, read_only: true, transaction_created: false, published: false, direct_refs_only: true, refs: rows,
});
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
function rig(algorithm = 'sha1') {
  const calls = [], responses = [];
  const client = new BranchClient({ href, cryptoImpl: webcrypto, fetchImpl: async (url, options) => {
    calls.push({ url: url.href, ...options }); const response = responses.shift();
    if (response instanceof Error) throw response;
    if (typeof response === 'function') return response(url, options);
    return response ?? json(page(algorithm));
  } });
  return { client, calls, responses };
}
function publication(p, outcome = 'committed') {
  const identity = { tenant_id: p.scope.tenant, repository_id: p.scope.repository, repository_incarnation: p.scope.incarnation, object_format: p.scope.format };
  return { schema_version: 1, ...identity, type: 'branch_publication', principal_id: actor, operation: p.operation,
    atomic: true, terminal: true, forge_transition: false, tx_id: 'tx-id', decision_sequence: 8, outcome,
    ...(outcome === 'committed' ? { repository_commit_id: 'rcr-id' } : { refusal_record_id: 'refusal-id', code: 'TargetRefMoved', code_point: 2 }),
    updates: expectedUpdates(p.operation, p.fields).map(update => ({ ...update,
      expected_commit: update.expected_commit === null ? null : `${p.scope.format}:${update.expected_commit}`,
      new_commit: update.new_commit === null ? null : `${p.scope.format}:${update.new_commit}` })),
  };
}
function outcome(p, state = 'committed') {
  const terminal = ['committed', 'refused'].includes(state);
  return { ...scope(p.scope.format), type: 'transaction_outcome', principal_id: actor, selector: 'transaction', command_index: null, state, terminal,
    transaction: ['key_not_observed', 'seal_not_observed'].includes(state) ? null : { tx_id: 'tx-id', seal_id: 'seal-id', request_schema: 'schema-id', canonical_request_digest: { algorithm: 1, hex: 'a'.repeat(64) } },
    decision: !terminal ? null : state === 'committed' ? { kind: state, decision_sequence: 8, repository_commit_id: 'rcr-id' } : { kind: state, decision_sequence: 8, code: 'TargetRefMoved', code_point: 2, refusal_record_id: 'refusal-id' },
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
async function prepared(operation = 'rename', algorithm = 'sha1') {
  const r = rig(algorithm); await r.client.connect(token); await r.client.list({ objectFormat: algorithm });
  const options = operation === 'create' ? { ref: 'refs/heads/new', sourceRef: 'refs/heads/main' } :
    { ref: 'refs/heads/topic', sourceRef: 'refs/heads/main', newRef: 'refs/heads/new' };
  await r.client.prepare(operation, options); return r;
}
for (const algorithm of ['sha1', 'sha256']) {
  for (const operation of ['create', 'update', 'delete', 'rename']) test(`${algorithm} ${operation}: exact native command, no publication until send`, async () => {
    const { client, calls, responses } = await prepared(operation, algorithm); assert.equal(calls.length, 1);
    const saved = client.pending; assert.equal(saved.fields.object_format, algorithm);
    assert.equal(saved.fields.expected_commit ?? null, operation === 'create' ? null : oid(algorithm, 'b'));
    assert.equal(saved.fields.new_commit ?? null, ['create', 'update'].includes(operation) ? oid(algorithm) : null);
    assert.ok(saved.key.length <= 128); saved.fields.ref = 'refs/heads/evil';
    responses.push(json(publication(client.pending))); const result = await client.send();
    assert.equal(result.outcome, 'committed'); assert.equal(client.pending, null); assert.equal(client.page, null);
    assert.match(calls[1].url, new RegExp(`/source/branches/${operation}$`));
    const body = new URLSearchParams(calls[1].body); assert.notEqual(body.get('ref'), saved.fields.ref);
    for (const field of ['force', 'principal', 'expected_head', 'atomic']) assert.equal(body.has(field), false);
    if (operation === 'rename') assert.equal(body.get('new_ref'), 'refs/heads/new');
    assert.equal(calls[1].redirect, 'error'); assert.equal(calls[1].credentials, 'omit');
  });
  test(`${algorithm}: original bytes and key survive lost reply and successful rename retry`, async () => {
    const { client, calls, responses } = await prepared('rename', algorithm);
    responses.push(new Error('lost response')); await assert.rejects(client.send(), error => error.outcomeUnknown);
    const p = client.pending; assert.equal(p.sent, true); assert.throws(() => client.discardUnsent());
    await assert.rejects(client.list()); await assert.rejects(client.prepare('delete', { ref: 'refs/heads/topic' }));
    responses.push(json(publication(p))); await client.send(); assert.equal(calls.length, 3);
    assert.equal(calls[1].body, calls[2].body); assert.equal(calls[1].headers['Idempotency-Key'], calls[2].headers['Idempotency-Key']);
  });
  test(`${algorithm}: one canonical HTTP 409 settles a refused atomic rename`, async () => {
    const { client, responses } = await prepared('rename', algorithm);
    responses.push(json(publication(client.pending, 'refused'), 409)); assert.equal((await client.send()).outcome, 'refused'); assert.equal(client.pending, null);
  });
}
test('continuations retain the selected namespace, cursor and authority head across pages', async () => {
  const { client, responses, calls } = rig(); await client.connect(token);
  responses.push(json({ ...page(), limit: 1, refs: [row('refs/heads/main')], next_after: 'refs/heads/main' }));
  await client.list({ limit: 1 });
  responses.push(json({ ...page(), limit: 1, after: 'refs/heads/main', refs: [row('refs/heads/topic', 'sha1', 'b')] }));
  await client.list({ next: true, namespace: 'tags', objectFormat: 'sha256', limit: 100 });
  assert.equal(calls[1].body, form({ ...query(), limit: 1, after: 'refs/heads/main', expected_head: head }));
  assert.equal(client.knownRefs.length, 2); await client.prepare('create', { ref: 'refs/heads/new', sourceRef: 'refs/heads/main' });
  assert.equal(client.pending.fields.new_commit, oid('sha1')); // selection remains available from the previous pinned page
});
for (const [label, change] of [
  ['scope', p => { p.object_format = 'sha256'; }], ['snapshot', p => { p.snapshot_token = `alg:1:${'2'.repeat(64)}`; }],
  ['namespace', p => { p.namespace = 'tags'; }], ['cursor', p => { p.after = 'refs/heads/wrong'; }],
  ['order', p => p.refs.reverse()], ['duplicate', p => p.refs.push(p.refs[0])], ['extra row', p => { p.limit = 1; }],
  ['false completeness', p => { p.next_after = 'refs/heads/topic'; }], ['null cursor', p => { delete p.next_after; }],
  ['byte identity', p => { p.refs[0].ref_hex += 'ff'; }], ['zero OID', p => { p.refs[0].object_id = '0'.repeat(40); }],
  ['wrong OID domain', p => { p.refs[0].object_id = `sha256:${'a'.repeat(64)}`; }], ['symbolic', p => { p.direct_refs_only = false; }],
  ['publication', p => { p.published = true; }], ['transaction', p => { p.transaction_created = true; }],
]) test(`malformed listing rejects ${label}`, () => {
  const p = page(); change(p); assert.throws(() => refsPage(p, { ...query(), expected_head: head }));
});
test('tags, byte-only refs and unicode names stay lossless and separate from mutation inputs', async () => {
  const raw = { ref: null, ref_hex: hex(utf8.encode('refs/heads/x')) + 'ff', object_id: oid('sha1') };
  assert.doesNotThrow(() => refsPage(page('sha1', [raw]), query()));
  assert.throws(() => refsPage(page('sha1', [{ ...raw, ref: 'refs/heads/x�' }]), query()));
  assert.doesNotThrow(() => refName('refs/heads/café')); assert.doesNotThrow(() => refName('refs/heads/a\u2003b')); // no lossy Unicode whitespace rule
  const p = { ...page('sha1', [row('refs/tags/v1')]), namespace: 'tags' };
  assert.doesNotThrow(() => refsPage(p, { ...query(), namespace: 'tags' })); assert.throws(() => refName('refs/tags/v1'));
  const r = rig(); await r.client.connect(token); r.responses.push(json(p)); await r.client.list({ namespace: 'tags' });
  await assert.rejects(r.client.prepare('create', { ref: 'refs/heads/new', sourceRef: 'refs/tags/v1' }));
});
for (const name of ['main', 'refs/heads/', 'refs/heads/a..b', 'refs/heads/a.lock', 'refs/heads/a b', 'refs/heads/.a', 'refs/heads/a/', 'refs/heads/a\\b', 'refs/heads/a\0b'])
  test(`invalid native branch ${JSON.stringify(name)}`, () => assert.throws(() => refName(name)));
test('native byte path and page bounds are enforced', async () => {
  assert.throws(() => refBytes('aa'.repeat(4097))); assert.throws(() => refName(`refs/heads/${'x'.repeat(4090)}`));
  const { client, calls } = rig(); await client.connect(token);
  for (const limit of [0, 101, NaN, 1.5]) await assert.rejects(client.list({ limit })); assert.equal(calls.length, 0);
});
test('selection, no-op, existing destination and command field errors do not send', async () => {
  const { client, calls } = rig(); await client.connect(token); await client.list();
  for (const [action, options] of [['create', { ref: 'refs/heads/main', sourceRef: 'refs/heads/topic' }],
    ['create', { ref: 'refs/heads/new', sourceRef: 'refs/heads/unknown' }], ['delete', { ref: 'refs/heads/unknown' }],
    ['rename', { ref: 'refs/heads/main', newRef: 'refs/heads/main' }], ['rename', { ref: 'refs/heads/main', newRef: 'refs/heads/topic' }],
    ['update', { ref: 'refs/heads/main', sourceRef: 'refs/heads/main' }]]) await assert.rejects(client.prepare(action, options));
  const fields = { object_format: 'sha1', ref: 'refs/heads/main', expected_commit: oid('sha1') };
  for (const extra of [{ force: true }, { principal: actor }, { new_commit: oid('sha1') }, { expected_head: head }]) assert.throws(() => branchCommand('delete', { ...fields, ...extra }));
  assert.equal(calls.length, 1);
});
for (const [name, change] of [
  ['partial rename', p => p.updates.pop()], ['reordered rename', p => p.updates.reverse()], ['duplicate effect', p => { p.updates[1] = p.updates[0]; }],
  ['old target changed', p => { p.updates[0].expected_commit = oid('sha1', 'c'); }], ['destination not absent', p => { p.updates[1].expected_commit = oid('sha1'); }],
  ['forced', p => { p.updates[0].force = true; }], ['non-atomic', p => { p.atomic = false; }], ['nonterminal', p => { p.terminal = false; }],
  ['forge effect', p => { p.forge_transition = true; }], ['wrong action', p => { p.operation = 'update'; }], ['wrong scope', p => { p.repository_incarnation = '9'.repeat(32); }],
  ['conflicting decisions', p => { p.code = 'refused'; }], ['missing decision', p => { delete p.repository_commit_id; }], ['wrong transaction', p => { p.tx_id = 'wrong-tx'; }],
]) test(`invalid terminal ${name} leaves original responsibility`, async () => {
  const { client, responses } = await prepared(); const saved = client.pending;
  if (name === 'wrong transaction') { responses.push(json(outcome(saved, 'undecided'))); await client.recover(); }
  const p = publication(saved); change(p); responses.push(json(p));
  await assert.rejects(client.send()); assert.equal(client.pending.key, saved.key);
});
test('generic HTTP conflict, outage and malformed JSON are never canonical refusals', async () => {
  const { client, responses } = await prepared(); const key = client.pending.key;
  for (const response of [json({ type: 'source_error', outcome_unknown: false, code: 'idempotency_key_reused' }, 409), json({}, 503), new Response('bad JSON', { headers: { 'Content-Type': 'application/json' } })]) {
    responses.push(response); await assert.rejects(client.send(), e => e.outcomeUnknown); assert.equal(client.pending.key, key);
  }
});
for (const state of ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused']) test(`bodyless recovery preserves ${state} semantics`, async () => {
  const { client, calls, responses } = await prepared(); const p = client.pending;
  responses.push(json(outcome(p, state))); const result = await client.recover();
  assert.equal(result.terminal, ['committed', 'refused'].includes(state)); assert.equal(client.pending === null, result.terminal);
  assert.equal(calls.at(-1).body, undefined); assert.equal(calls.at(-1).headers['Idempotency-Key'], p.key);
});
test('transaction observations cannot disappear or change principal later', async () => {
  const { client, responses } = await prepared(); const p = client.pending;
  responses.push(json(outcome(p, 'undecided'))); await client.recover();
  for (const bad of [outcome(p, 'key_not_observed'), { ...outcome(p), principal_id: '9'.repeat(32) }]) {
    responses.push(json(bad)); await assert.rejects(client.recover()); assert.equal(client.pending.observedTx, 'tx-id');
  }
});
test('saved receipts restore without network or ref-presence read, with the same exact retry', async () => {
  const a = await prepared(); const p = a.client.pending, receipt = a.client.exportReceipt();
  assert.ok(!receipt.includes(token)); assert.throws(() => a.client.discardUnsent());
  const b = rig(); await b.client.connect(token); await b.client.restoreReceipt(receipt); assert.equal(b.calls.length, 0);
  assert.throws(() => b.client.discardUnsent()); b.responses.push(json(publication(p))); await b.client.send();
  assert.equal(b.calls[0].body, form(p.fields)); assert.equal(b.calls[0].headers['Idempotency-Key'], p.key);
});
for (const [label, edit] of [
  ['ref', p => { p.fields.ref = 'refs/heads/other'; }], ['destination', p => { p.fields.new_ref = 'refs/heads/other'; }],
  ['tip', p => { p.fields.expected_commit = oid('sha1'); }], ['operation', p => { p.operation = 'create'; }],
  ['nonce', p => { p.nonce = '0'.repeat(32); }], ['key', p => { p.key += 'a'; }], ['incarnation', p => { p.scope.incarnation = '9'.repeat(32); }],
  ['origin', p => { p.origin = 'https://attacker.invalid'; }], ['route', p => { p.route = '/other.git'; }], ['credential', p => { p.fingerprint = 'b'.repeat(64); }],
  ['extra', p => { p.force = true; }],
]) test(`tampered ${label} receipt cannot reuse identity`, async () => {
  const a = await prepared(); const encoded = JSON.parse(a.client.exportReceipt()); edit(encoded);
  const b = rig(); await b.client.connect(token); await assert.rejects(b.client.restoreReceipt(JSON.stringify(encoded))); assert.equal(b.client.pending, null); assert.equal(b.calls.length, 0);
});
test('receipt bounds and lifecycle cannot silently shed an exported request', async () => {
  const r = await prepared(); r.client.discardUnsent(); assert.equal(r.client.pending, null);
  await assert.rejects(r.client.restoreReceipt(' '.repeat(RECEIPT_LIMIT + 1)));
  await r.client.prepare('delete', { ref: 'refs/heads/topic' }); r.client.exportReceipt(); r.client.disconnect();
  await assert.rejects(r.client.connect('b'.repeat(64))); assert.ok(r.client.pending); await r.client.connect(token); assert.ok(r.client.pending);
});
test('superseded listing does not repopulate disconnected data', async () => {
  const r = rig(); await r.client.connect(token); let release;
  r.responses.push(() => new Promise(resolve => { release = resolve; })); const reading = r.client.list();
  await Promise.resolve(); r.client.disconnect(); release(json(page())); await assert.rejects(reading);
  assert.equal(r.client.page, null); assert.deepEqual(r.client.knownRefs, []);
});
test('cancelling reads does not abort an already dispatched branch mutation', async () => {
  const r = await prepared(); const p = r.client.pending; let release;
  r.responses.push(() => new Promise(resolve => { release = resolve; })); const sending = r.client.send();
  await Promise.resolve(); r.client.cancel(); assert.equal(r.calls.at(-1).signal.aborted, false);
  release(json(publication(p))); assert.equal((await sending).outcome, 'committed');
});
test('branches transport is isolated from source content, initial commits, PRs and issues', async () => {
  let calls = 0; const transport = new Transport({ href, pageSuffix: '/ui/branches/', cryptoImpl: webcrypto, fetchImpl: async () => { calls += 1; return json({}); } });
  await transport.connect(token);
  for (const path of ['pulls', 'source/prepare', 'source/initial/apply', 'source/tree', 'issues', 'source/branches/force', 'source/refs?force=true', 'https://evil.invalid/source/refs']) await assert.rejects(transport.request(path));
  assert.equal(calls, 0);
  for (const path of ['source/refs', 'source/branches/create', 'source/branches/rename', 'outcomes']) await transport.request(path, { method: 'POST' }); assert.equal(calls, 4);
  for (const suffix of ['/ui/pulls/', '/ui/source/', '/ui/initial/']) {
    const other = new Transport({ href: href.replace('/ui/branches/', suffix), pageSuffix: suffix, cryptoImpl: webcrypto, fetchImpl: async () => { throw new Error('unexpected network'); } });
    await other.connect(token); await assert.rejects(other.request('source/branches/create'), /Invalid API route/);
  }
});
