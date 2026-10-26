// Real transfer/transport modules with HTTP doubles. The checksum-only bundle
// fixture is a retained legacy request, not native object-admission evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { TransferClient } from '../../crates/fgit-node/src/smart_http/server/browser/transfers.mjs';
import { fixture, crypto, href, token, actor, hex, json, deferred, decodeUpload } from './transfers-fixtures.mjs';

const ROTATED = '8'.repeat(64), OTHER = 'a'.repeat(32);
const recovering = (originalPrincipal = actor) => ({ recoveryOnly: true, originalPrincipal });
const client = (f, options = {}) => new TransferClient({ href, cryptoImpl: crypto, fetchImpl: (...args) => f.fetchImpl(...args), ...options });
const mappings = algorithm => [{ source_hex: hex('refs/heads/main'), destination_hex: hex('refs/remotes/retained/') + 'ff',
  expected_old: 'b'.repeat(algorithm === 'sha1' ? 40 : 64) }];
async function original(algorithm = 'sha1', operation = 'fetch') {
  const f = fixture(algorithm), c = client(f);
  await c.connect(token); await c.select(algorithm); await c.load(f.input);
  await c.stage(operation, operation === 'fetch' ? mappings(algorithm) : []);
  return { f, c };
}
async function fromReceipt(receipt, f, expected = actor) {
  const c = client(f); await c.connect(ROTATED, recovering(expected)); await c.restoreReceipt(receipt); return c;
}
async function ordinaryLanesRefuse(c, f) {
  const before = f.calls.length, pending = c.pending;
  for (const action of [() => c.select('sha1'), () => c.load(new Uint8Array()), () => c.exportBundle(),
    () => c.exportBundle({ verifyInventory: true, verifyClosure: true }), () => c.exportBytes(), () => c.exportManifest(),
    () => c.stage('import'), () => c.stage('fetch', []), () => c.send(), () => c.discardUnsent()]) {
    await assert.rejects(async () => action(), /Recovery-only/);
    assert.deepEqual(c.pending, pending);
  }
  assert.equal(f.calls.length, before);
}
function onlyOriginalLookup(call, key) {
  assert.equal(call.path, 'outcomes'); assert.equal(call.method, 'POST'); assert.equal(call.body, undefined);
  assert.equal(call.headers.authorization, `Bearer ${ROTATED}`); assert.equal(call.headers['idempotency-key'], key);
  assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error'); assert.equal(call.cache, 'no-store');
}

for (const algorithm of ['sha1', 'sha256']) for (const operation of ['import', 'fetch']) {
  test(`${algorithm} ${operation}: a replacement credential restores and resolves the exact original transfer without resending`, async () => {
    const { f, c: old } = await original(algorithm, operation), receipt = old.exportReceipt(), saved = JSON.parse(receipt);
    const before = f.calls.length, c = await fromReceipt(receipt, f);
    assert.equal(f.calls.length, before); assert.equal(c.recoveryOnly, true); assert.equal(c.recoveryPrincipal, actor);
    assert.equal(c.pending.key, saved.key); assert.equal(c.pending.observedPrincipal, null);
    assert.deepEqual(c.pending.scope, saved.scope); assert.equal(c.pending.operation, operation);
    assert.equal(c.exportReceipt(), receipt); assert(!receipt.includes(token)); assert(!receipt.includes(ROTATED));
    await ordinaryLanesRefuse(c, f);
    f.config.outcome = 'key_not_observed';
    const absent = await c.recover(); assert.equal(absent.terminal, false); assert.equal(absent.state, 'key_not_observed');
    assert.equal(c.pending.observedPrincipal, actor); assert.equal(c.pending.observedTx, null);
    onlyOriginalLookup(f.calls.at(-1), saved.key);
    const afterAbsence = JSON.parse(c.exportReceipt());
    assert.deepEqual({ ...afterAbsence, observedPrincipal: null }, saved);
    f.config.outcome = operation === 'import' ? 'committed' : 'refused';
    const terminal = await c.recover(); assert.equal(terminal.outcome, f.config.outcome); assert.equal(terminal.deliveryAcknowledged, null);
    assert.equal(c.pending, null); assert.equal(c.recoveryOnly, true); assert.equal(c.recoveryPrincipal, actor);
    assert.equal(c.selection, null); assert.equal(c.bundle, null); assert.equal(c.exported, null);
    await ordinaryLanesRefuse(c, f);
    assert.deepEqual(f.calls.slice(before).map(call => call.path), ['outcomes', 'outcomes']);
    for (const call of f.calls.slice(before)) onlyOriginalLookup(call, saved.key);
  });
}

test('lost-response recovery can rotate a retained credential without importing a receipt or refreshing refs', async () => {
  const { f, c } = await original(); f.config.lose = true;
  await assert.rejects(c.send(), error => error.outcomeUnknown === true);
  const originalCall = f.calls.at(-1), retained = c.pending, receipt = c.exportReceipt();
  c.disconnect(); await assert.rejects(c.connect(ROTATED), /another credential/);
  assert.equal(c.connected, false); assert.deepEqual(c.pending, { ...retained, exported: true });
  const before = f.calls.length;
  await c.connect(ROTATED, recovering()); assert.equal(c.exportReceipt(), receipt);
  f.config.outcome = 'undecided'; await c.recover(); onlyOriginalLookup(f.calls.at(-1), retained.key);
  await assert.rejects(c.send(), /Recovery-only/); assert.equal(f.calls.length, before + 1);
  // Explicitly returning to the original credential may retry, and must retain
  // every multipart byte, raw destination name and exact old-tip lease.
  await c.connect(token); f.config.lose = false; await c.send();
  const retried = f.calls.at(-1);
  assert.equal(retried.path, originalCall.path); assert.equal(retried.headers['idempotency-key'], originalCall.headers['idempotency-key']);
  assert.equal(retried.headers['content-type'], originalCall.headers['content-type']); assert.deepEqual(retried.body, originalCall.body);
  assert.deepEqual(decodeUpload(retried).payload, f.input);
});

test('ordinary restore still refuses a replacement credential even when the receipt is valid', async () => {
  const { f, c: old } = await original(), receipt = old.exportReceipt(), c = client(f), before = f.calls.length;
  await c.connect(ROTATED); await assert.rejects(c.restoreReceipt(receipt), /another route or credential/);
  assert.equal(c.pending, null); assert.equal(c.recoveryOnly, false); assert.equal(f.calls.length, before);
});

test('recovery selection blocks every ordinary lane before any receipt has been selected', async () => {
  const f = fixture(), c = client(f);
  await c.connect(ROTATED, recovering()); assert.equal(c.pending, null);
  await ordinaryLanesRefuse(c, f); await assert.rejects(c.recover()); assert.equal(f.calls.length, 0);
});

for (const state of ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused']) {
  test(`wrong-principal ${state} cannot release or modify the original transfer`, async () => {
    const { f, c: old } = await original(), c = await fromReceipt(old.exportReceipt(), f), before = c.pending;
    f.config.outcome = state; f.config.recover = reply => { reply.principal_id = OTHER; };
    await assert.rejects(c.recover(), /selected original principal/);
    assert.deepEqual(c.pending, before); assert.equal(c.recoveryOnly, true); await ordinaryLanesRefuse(c, f);
    f.config.recover = null; const result = await c.recover(); assert.equal(result.state ?? result.outcome, state);
  });
}

test('a missing or malformed authenticated principal cannot be supplied by the receipt or selected identity', async () => {
  const { f, c: old } = await original(), c = await fromReceipt(old.exportReceipt(), f), before = c.pending;
  for (const value of [null, undefined, actor.toUpperCase().replaceAll('9', 'G'), '']) {
    f.config.recover = reply => { reply.principal_id = value; };
    await assert.rejects(c.recover()); assert.deepEqual(c.pending, before);
  }
});

test('retained principal observations constrain both reconnect and receipt restoration', async () => {
  const { f, c } = await original(); await c.recover(); const receipt = c.exportReceipt(), originalPending = c.pending;
  assert.equal(originalPending.observedPrincipal, actor);
  await assert.rejects(c.connect(ROTATED, recovering(OTHER)), /conflicts with the retained observation/);
  assert.equal(c.connected, false); assert.deepEqual(c.pending, originalPending);
  const next = client(f); await next.connect(ROTATED, recovering(OTHER));
  await assert.rejects(next.restoreReceipt(receipt), /Receipt principal conflicts/); assert.equal(next.pending, null);
  await next.connect(ROTATED, recovering()); await next.restoreReceipt(receipt);
  assert.equal(next.exportReceipt(), receipt);
});

test('scope, native semantics and previously observed transaction identity cannot regress', async () => {
  const { f, c: old } = await original(), c = await fromReceipt(old.exportReceipt(), f);
  f.config.outcome = 'undecided'; await c.recover(); const before = c.pending;
  assert.equal(before.observedTx, 'tx-original'); assert.equal(before.sent, true);
  for (const mutate of [r => { r.tenant_id = '4'.repeat(32); }, r => { r.repository_id = '4'.repeat(32); },
    r => { r.repository_incarnation = '4'.repeat(32); }, r => { r.request_reexecuted = true; },
    r => { r.absence_proves_non_commit = true; }, r => { r.transaction.tx_id = 'tx-different'; }]) {
    f.config.recover = mutate; await assert.rejects(c.recover()); assert.deepEqual(c.pending, before);
  }
  f.config.recover = null; f.config.outcome = 'key_not_observed'; await assert.rejects(c.recover(), /previously identified transaction/);
  assert.deepEqual(c.pending, before);
  f.config.outcome = 'committed'; await c.recover(); assert.equal(c.pending, null);
});

test('a transaction observed for a never-exported local preparation prevents later unsent discard', async () => {
  const { f, c } = await original(); assert.equal(c.pending.sent, false); assert.equal(c.pending.exported, false);
  await c.connect(ROTATED, recovering()); f.config.outcome = 'undecided'; await c.recover();
  assert.equal(c.pending.sent, true); assert.equal(c.pending.observedTx, 'tx-original');
  await c.connect(token); assert.throws(() => c.discardUnsent(), /Only an unsent/); assert.ok(c.pending);
});

test('changed receipt identity or command bytes never acquire a repaired key in recovery-only mode', async () => {
  const { f, c: old } = await original(), saved = JSON.parse(old.exportReceipt()), before = f.calls.length;
  const mutations = [r => { r.fingerprint = 'c'.repeat(64); }, r => { r.fingerprint = ''; }, r => { r.key = 'fgbundle1-invalid'; },
    r => { r.key = r.key.slice(0, -1) + (r.key.endsWith('a') ? 'b' : 'a'); }, r => { r.nonce = 'd'.repeat(32); },
    r => { r.origin = 'https://other.example'; }, r => { r.route = '/other.git'; }, r => { r.scope.incarnation = '4'.repeat(32); },
    r => { r.mappings[0].destination_hex = hex('refs/remotes/different'); }, r => { r.mappings[0].expected_old = null; },
    r => { r.operation = 'import'; }, r => { r.bundle_base64 = 'AA=='; }, r => { r.observedTx = ''; }];
  for (const mutate of mutations) {
    const receipt = structuredClone(saved); mutate(receipt);
    const c = client(f); await c.connect(ROTATED, recovering());
    await assert.rejects(c.restoreReceipt(JSON.stringify(receipt))); assert.equal(c.pending, null); assert.equal(c.recoveryOnly, true);
  }
  assert.equal(f.calls.length, before);
});

test('invalid recovery options disconnect without erasing the original pending transfer', async () => {
  const { f, c } = await original(), pending = c.pending, before = f.calls.length;
  for (const options of [null, [], { recoveryOnly: 'true' }, { recoveryOnly: true }, { recoveryOnly: false, originalPrincipal: actor },
    { recoveryOnly: true, originalPrincipal: 'wrong' }, { recoveryOnly: true, originalPrincipal: actor, extra: true }]) {
    await assert.rejects(c.connect(ROTATED, options)); assert.equal(c.connected, false); assert.deepEqual(c.pending, pending);
  }
  assert.equal(f.calls.length, before);
});

test('recovery restriction and principal are captured before asynchronous credential hashing', async () => {
  const { f, c: old } = await original(), receipt = old.exportReceipt(), gate = deferred(), started = deferred();
  const cryptoImpl = { getRandomValues: bytes => crypto.getRandomValues(bytes), subtle: {
    async digest(...args) { started.resolve(); await gate.promise; return crypto.subtle.digest(...args); },
  } };
  const c = client(f, { cryptoImpl }), options = recovering(), connection = c.connect(ROTATED, options);
  await started.promise; assert.equal(c.recoveryOnly, true); assert.equal(c.recoveryPrincipal, actor);
  await ordinaryLanesRefuse(c, f); options.recoveryOnly = false; options.originalPrincipal = OTHER;
  gate.resolve(); await connection; assert.equal(c.recoveryOnly, true); assert.equal(c.recoveryPrincipal, actor);
  await c.restoreReceipt(receipt); f.config.outcome = 'committed'; await c.recover(); assert.equal(c.pending, null);
});

test('revocation and late replies preserve the original receipt across recovery reconnects', async () => {
  const { f, c } = await original(); f.config.lose = true;
  await assert.rejects(c.send(), error => error.outcomeUnknown); const saved = c.exportReceipt(), before = c.pending;
  const request = f.fetchImpl; f.fetchImpl = async () => json({ error: 'rejected' }, 401);
  await assert.rejects(c.recover(), /Credential rejected/); assert.equal(c.connected, false); assert.deepEqual(c.pending, before);
  f.fetchImpl = request; await c.connect(ROTATED, recovering()); assert.equal(c.exportReceipt(), saved);
  const entered = deferred(), gate = deferred(); f.config.outcome = 'committed';
  f.config.recover = async () => { entered.resolve(); await gate.promise; };
  const pending = c.recover(); await entered.promise; c.disconnect(); gate.resolve(); await assert.rejects(pending);
  assert.equal(c.connected, false); assert.deepEqual(c.pending, before);
  f.config.recover = null; await c.connect(ROTATED, recovering()); await c.recover(); assert.equal(c.pending, null);
});

test('an outcome timeout keeps the restricted original request and never triggers a resend', async () => {
  const { f, c: old } = await original(), receipt = old.exportReceipt(), c = client(f, { timeoutMs: 20 });
  await c.connect(ROTATED, recovering()); await c.restoreReceipt(receipt); const before = c.pending, count = f.calls.length;
  f.config.recover = async (_reply, call) => { await new Promise(resolve => {
    if (call.signal.aborted) resolve(); else call.signal.addEventListener('abort', resolve, { once: true });
  }); };
  await assert.rejects(c.recover()); assert.equal(c.recoveryOnly, true); assert.deepEqual(c.pending, before);
  assert.equal(f.calls.length, count + 1); onlyOriginalLookup(f.calls.at(-1), before.key);
});

test('terminal recovery requires an explicit ordinary reconnect before new source selection', async () => {
  const { f, c: old } = await original(), c = await fromReceipt(old.exportReceipt(), f);
  f.config.outcome = 'refused'; await c.recover(); await ordinaryLanesRefuse(c, f);
  const before = f.calls.length; await c.connect(ROTATED); assert.equal(c.recoveryOnly, false); assert.equal(c.recoveryPrincipal, null);
  assert.equal(f.calls.length, before); await c.select('sha1'); assert.equal(f.calls.at(-1).path, 'source/refs');
  assert.equal(f.calls.at(-1).headers.authorization, `Bearer ${ROTATED}`);
});
