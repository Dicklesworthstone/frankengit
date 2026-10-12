import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { rootFor, utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { digest } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { base64, requestBody, requestKey } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';

const HREF = 'https://forge.example/repo.git/ui/pulls/';
const ORIGINAL = '1'.repeat(64), ROTATED = '2'.repeat(64);
const PRINCIPAL = 'a'.repeat(32), OTHER = 'b'.repeat(32);
const recoveryOptions = () => ({ recoveryOnly: true, originalPrincipal: PRINCIPAL });
const scope = algorithm => ({ tenant: 'tenant', repository: 'repo', incarnation: 'incarnation', format: algorithm });
const identity = algorithm => ({ schema_version: 1, tenant_id: 'tenant', repository_id: 'repo',
  repository_incarnation: 'incarnation', object_format: algorithm });
const response = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' },
});
function page(algorithm = 'sha1') {
  return { ...identity(algorithm), type: 'pull_request_page', source_head: 'rcr/observed',
    snapshot_token: `alg:2:${'d'.repeat(64)}`, after: 0, limit: 20, next_after: null, pull_requests: [] };
}
function metadata(algorithm = 'sha1', version = 0) {
  return { expected_version: version, object_format: algorithm, source_ref: 'refs/heads/topic', target_ref: 'refs/heads/main',
    source_tip: 'a'.repeat(algorithm === 'sha1' ? 40 : 64), target_tip: 'b'.repeat(algorithm === 'sha1' ? 40 : 64),
    title: 'Original request', body: 'Exact original body — including Unicode.' };
}
function outcome(state, algorithm = 'sha1', overrides = {}) {
  const terminal = ['committed', 'refused'].includes(state);
  return { ...identity(algorithm), type: 'transaction_outcome', selector: 'transaction', command_index: null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
    principal_id: PRINCIPAL, state, terminal,
    transaction: state === 'undecided' || terminal ? { tx_id: 'tx/original', seal_id: 'seal/original', request_schema: 'request/v1',
      canonical_request_digest: { algorithm: 2, hex: 'ab'.repeat(32) } } : null,
    decision: !terminal ? null : state === 'committed'
      ? { kind: state, decision_sequence: 4, repository_commit_id: 'rcr/original' }
      : { kind: state, decision_sequence: 4, refusal_record_id: 'refusal/original', code: 'policy_refused', code_point: 7 },
    ...overrides };
}
function makeClient(fetchImpl, extra = {}) {
  return new PullClient({ href: HREF, fetchImpl, cryptoImpl: webcrypto, ...extra });
}
async function receipt(kind = 'open', algorithm = 'sha1') {
  const action = kind === 'squash' ? 'merge' : kind, number = 7, nonce = '3'.repeat(32);
  const original = metadata(algorithm), { object_format, source_ref, target_ref, source_tip, target_tip } = original;
  const selected = { object_format, source_ref, target_ref, source_tip, target_tip, pull_request_version: 3, policy_epoch: 2 };
  let fields, bundle = null;
  if (['open', 'update', 'close', 'reopen'].includes(action)) fields = metadata(algorithm, action === 'open' ? 0 : 3);
  else if (action === 'comment') fields = { object_format: algorithm, expected_version: 2, body: 'Original conversation comment.' };
  else if (action === 'fast-forward') fields = { object_format, source_ref, target_ref, source_tip, target_tip, pull_request_version: 3 };
  else {
    fields = { ...selected, merge_base: 'c'.repeat(source_tip.length), candidate_commit: 'd'.repeat(source_tip.length),
      ...(action === 'merge' ? { required_reviewer: [OTHER], ...(kind === 'squash' ? { method: 'squash' } : {}) }
        : { expected_version: action === 'withdraw' ? 1 : 0, reason: 'Original review reason.' }) };
    // Opaque original upload bytes: these tests never claim native Git validity
    // and must never submit the bundle under the replacement credential.
    if (action !== 'withdraw') bundle = Uint8Array.of(0, 255, 13, 10, 42);
  }
  const fingerprint = await digest(utf8.encode(ORIGINAL), webcrypto), selectedScope = scope(algorithm);
  const body = requestBody(action, fields, bundle, nonce);
  const key = await requestKey(rootFor(HREF), fingerprint, selectedScope, number, action, nonce, body, webcrypto);
  return { schema: 'frankengit-pr-retry-v1', origin: rootFor(HREF).origin, route: rootFor(HREF).route,
    request: { number, action, fields: body.fields, scope: selectedScope, fingerprint, nonce, key,
      bundle_base64: bundle === null ? null : base64(bundle), observedTx: null, observedPrincipal: null } };
}

for (const algorithm of ['sha1', 'sha256']) for (const kind of ['open', 'update', 'close', 'reopen', 'comment',
  'approve', 'request-changes', 'withdraw', 'merge', 'squash', 'fast-forward']) {
  test(`${algorithm} ${kind}: rotated receipt recovery preserves the exact original command and never resends`, async () => {
    const original = await receipt(kind, algorithm), calls = []; let state = 'key_not_observed';
    const client = makeClient(async (url, options) => { calls.push({ url, options }); return response(outcome(state, algorithm)); });
    await client.connect(ROTATED, recoveryOptions());
    assert.equal(client.recoveryOnly, true); assert.equal(client.pending, null);
    await assert.rejects(client.list(), /Recovery-only/);
    await client.restoreReceipt(JSON.stringify(original));
    assert.deepEqual(JSON.parse(client.exportReceipt()), original);
    assert.equal(client.pending.key, original.request.key); assert.equal(client.pending.observedPrincipal, null);
    await assert.rejects(client.send(), /Recovery-only/); assert.equal(calls.length, 0);
    assert.equal((await client.recover()).terminal, false);
    const saved = JSON.parse(client.exportReceipt());
    assert.equal(saved.request.fingerprint, original.request.fingerprint);
    assert.equal(saved.request.key, original.request.key); assert.equal(saved.request.bundle_base64, original.request.bundle_base64);
    assert.equal(saved.request.observedPrincipal, PRINCIPAL);
    assert.deepEqual(saved.request.fields, original.request.fields);
    state = 'undecided'; assert.equal((await client.recover()).tx, 'tx/original');
    assert.equal(client.pending.observedTx, 'tx/original');
    state = 'committed'; const final = await client.recover();
    assert.equal(final.outcome, 'committed'); assert.equal(final.rcr, 'rcr/original');
    assert.equal(client.pending, null); assert.equal(client.recoveryOnly, true);
    await assert.rejects(client.send(), /Recovery-only/); await assert.rejects(client.list(), /Recovery-only/);
    assert.equal(calls.length, 3);
    for (const { url, options } of calls) {
      assert.equal(url.href, 'https://forge.example/repo.git/api/v1/outcomes');
      assert.equal(options.method, 'POST'); assert.equal(options.body, undefined);
      assert.equal(options.headers['Idempotency-Key'], original.request.key);
      assert.equal(options.headers.Authorization, `Bearer ${ROTATED}`);
    }
  });
}

test('lost-response reconnect uses the retained original key without needing a receipt import', async () => {
  const calls = []; let lose = true;
  const client = makeClient(async (url, options) => {
    calls.push({ url, options });
    if (url.pathname.endsWith('/outcomes')) return response(outcome('committed'));
    if (options.method === 'GET') return response(page());
    if (lose) throw new Error('Response lost after dispatch');
    throw new Error('Unexpected replacement publication');
  });
  await client.connect(ORIGINAL); await client.list();
  await client.stageMetadata(7, 'open', metadata());
  await assert.rejects(client.send(), error => error.outcomeUnknown === true);
  const original = JSON.parse(client.exportReceipt());
  await assert.rejects(client.connect(ROTATED), /another credential/);
  assert.equal(client.connected, false); assert.equal(client.pending.key, original.request.key);
  lose = false; await client.connect(ROTATED, recoveryOptions());
  await assert.rejects(client.send(), /Recovery-only/);
  const final = await client.recover(); assert.equal(final.outcome, 'committed');
  assert.equal(calls.filter(call => call.url.pathname.endsWith('/open')).length, 1);
  assert.equal(calls.at(-1).options.headers['Idempotency-Key'], original.request.key);
});

test('ordinary receipt import still requires the original credential', async () => {
  const original = await receipt(), client = makeClient(async () => { throw new Error('No network expected'); });
  await client.connect(ROTATED);
  await assert.rejects(client.restoreReceipt(JSON.stringify(original)), /original credential/);
  assert.equal(client.pending, null);
  await client.connect(ORIGINAL); await client.restoreReceipt(JSON.stringify(original));
  assert.equal(client.recoveryOnly, false); assert.equal(client.pending.key, original.request.key);
});

test('recovery-only connection blocks every normal lane before a receipt is selected', async () => {
  let requests = 0;
  const client = makeClient(async () => { requests++; throw new Error('No request allowed'); });
  await client.connect(ROTATED, recoveryOptions());
  for (const operation of [() => client.list(), () => client.show(7), () => client.reviews(7), () => client.comments(7),
    () => client.checks(7, {}), () => client.diff(7, {}), () => client.stageMetadata(7, 'open', metadata()),
    () => client.stageComment(7, 0, 'Comment'), () => client.prepareAndInspect(7, {}, {}),
    () => client.resolveAndInspect([]), () => client.inspect(7, {}, Uint8Array.of(1)),
    () => client.importCandidate('{}'), () => client.send()]) await assert.rejects(operation(), /Recovery-only/);
  assert.throws(() => client.discardUnsent(), /Recovery-only/);
  await assert.rejects(client.recover(), /retain the original request/);
  assert.equal(requests, 0);
});

test('wrong-principal and invalid native outcome semantics cannot release the retained request', async () => {
  const original = await receipt(); let reply = outcome('committed');
  const client = makeClient(async () => response(reply));
  await client.connect(ROTATED, recoveryOptions()); await client.restoreReceipt(JSON.stringify(original));
  for (const change of [{ principal_id: OTHER }, { repository_incarnation: 'replacement' }, { request_reexecuted: true },
    { absence_proves_non_commit: true }, { session_completeness_established: true }, { transaction: null },
    { decision: { kind: 'refused', decision_sequence: 4 } }]) {
    reply = outcome('committed', 'sha1', change); await assert.rejects(client.recover());
    assert.equal(client.pending.key, original.request.key); assert.equal(client.pending.observedPrincipal, null);
  }
  reply = outcome('committed'); assert.equal((await client.recover()).outcome, 'committed');
});

test('retained principal observations constrain both reconnect and imported receipt selection', async () => {
  const original = await receipt(); original.request.observedPrincipal = OTHER;
  const client = makeClient(async () => response(outcome('key_not_observed', 'sha1', { principal_id: OTHER })));
  await client.connect(ROTATED, recoveryOptions());
  await assert.rejects(client.restoreReceipt(JSON.stringify(original)), /principal conflicts/);
  assert.equal(client.pending, null);
  await client.connect(ORIGINAL); await client.restoreReceipt(JSON.stringify(original));
  await assert.rejects(client.connect(ROTATED, recoveryOptions()), /principal conflicts/);
  assert.equal(client.connected, false); assert.equal(client.pending.observedPrincipal, OTHER);
});

test('altered original key, fingerprint, command, nonce, route and bundle are never silently repaired', async () => {
  const original = await receipt('merge'); let calls = 0;
  for (const alter of [p => { p.request.fields.required_reviewer = [PRINCIPAL]; }, p => { p.request.nonce = '4'.repeat(32); },
    p => { p.request.fingerprint = 'f'.repeat(64); }, p => { p.request.key = p.request.key.slice(0, -1) + 'z'; },
    p => { p.request.bundle_base64 = base64(Uint8Array.of(1, 2)); }, p => { p.route = '/different.git'; },
    p => { p.origin = 'https://other.example'; }, p => { p.request.scope.incarnation = 'different'; }]) {
    const changed = structuredClone(original); alter(changed);
    const client = makeClient(async () => { calls++; return response(outcome('committed')); });
    await client.connect(ROTATED, recoveryOptions());
    await assert.rejects(client.restoreReceipt(JSON.stringify(changed)));
    assert.equal(client.pending, null); assert.equal(client.recoveryOnly, true);
  }
  assert.equal(calls, 0);
});

test('refusal and non-observation never unlock replacement publication', async () => {
  const original = await receipt(); let state = 'seal_not_observed';
  const client = makeClient(async () => response(outcome(state)));
  await client.connect(ROTATED, recoveryOptions()); await client.restoreReceipt(JSON.stringify(original));
  assert.equal((await client.recover()).terminal, false); assert.ok(client.pending);
  state = 'refused'; assert.equal((await client.recover()).refusal, 'policy_refused');
  assert.equal(client.pending, null); await assert.rejects(client.list(), /Recovery-only/);
  await assert.rejects(client.stageMetadata(8, 'open', metadata()), /Recovery-only/);
});

test('previously observed transactions cannot disappear or change during recovery', async () => {
  const original = await receipt(); let reply = outcome('undecided');
  const client = makeClient(async () => response(reply));
  await client.connect(ROTATED, recoveryOptions()); await client.restoreReceipt(JSON.stringify(original));
  await client.recover();
  reply = outcome('key_not_observed'); await assert.rejects(client.recover(), /previously identified/);
  reply = outcome('committed'); reply.transaction.tx_id = 'tx/other';
  await assert.rejects(client.recover(), /transaction changed/);
  assert.equal(client.pending.observedTx, 'tx/original');
});

test('invalid recovery selection disconnects without erasing an unresolved request', async () => {
  const original = await receipt(), client = makeClient(async () => response(page()));
  for (const options of [{ recoveryOnly: 'true' }, { recoveryOnly: null }, { recoveryOnly: true },
    { recoveryOnly: true, originalPrincipal: 'not-a-principal' }, { originalPrincipal: PRINCIPAL },
    { ...recoveryOptions(), permitResend: true }]) {
    await client.connect(ORIGINAL);
    if (!client.pending) await client.restoreReceipt(JSON.stringify(original));
    await assert.rejects(client.connect(ROTATED, options));
    assert.equal(client.connected, false); assert.equal(client.pending.key, original.request.key);
  }
});

test('recovery restriction is visible before credential hashing completes and options cannot race it', async () => {
  let release;
  const wait = new Promise(resolve => { release = resolve; });
  const cryptoImpl = { getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
    subtle: { digest: async (...args) => { await wait; return webcrypto.subtle.digest(...args); } } };
  let calls = 0;
  const client = makeClient(async () => { calls++; return response(page()); }, { cryptoImpl });
  const options = recoveryOptions(), connecting = client.connect(ROTATED, options);
  options.recoveryOnly = false; options.originalPrincipal = OTHER;
  assert.equal(client.recoveryOnly, true); await assert.rejects(client.list(), /Recovery-only/);
  release(); await connecting;
  await client.restoreReceipt(JSON.stringify(await receipt()));
  assert.equal(client.recoveryOnly, true); assert.equal(calls, 0);
});

test('revocation and late disconnected replies preserve the unresolved receipt', async () => {
  const original = await receipt(); let finish, revoked = true;
  const client = makeClient(() => revoked ? response({}, 401) : new Promise(resolve => { finish = resolve; }));
  await client.connect(ROTATED, recoveryOptions()); await client.restoreReceipt(JSON.stringify(original));
  await assert.rejects(client.recover(), error => error.status === 401);
  assert.equal(client.connected, false); assert.equal(client.pending.key, original.request.key);
  revoked = false; await client.connect(ROTATED, recoveryOptions());
  const pending = client.recover(); client.disconnect(); finish(response(outcome('committed')));
  await assert.rejects(pending); assert.equal(client.pending.key, original.request.key);
});

test('ordinary work after terminal recovery requires an explicit new connection', async () => {
  const original = await receipt(); let queries = 0;
  const client = makeClient(async url => {
    if (url.pathname.endsWith('/outcomes')) return response(outcome('committed'));
    queries++; return response(page());
  });
  await client.connect(ROTATED, recoveryOptions()); await client.restoreReceipt(JSON.stringify(original));
  await client.recover(); await assert.rejects(client.list(), /Recovery-only/);
  await client.connect(ROTATED); await client.list();
  assert.equal(client.recoveryOnly, false); assert.equal(queries, 1);
});
