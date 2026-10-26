// Actual browser controllers/transport with synthetic native responses. These
// cases establish request custody and principal checks, not Rust admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { SourceEditClient } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit.mjs';
import { InitialSourceClient } from '../../crates/fgit-node/src/smart_http/server/browser/initial.mjs';
import * as source from './source-edit-fixtures.mjs';
import * as initial from './initial-fixtures.mjs';

const ROTATED = '8'.repeat(64), OTHER = '6'.repeat(32);
const selection = () => ({ recoveryOnly: true, originalPrincipal: source.actor });
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
async function setup(kind, algorithm = 'sha1') {
  const lib = kind === 'source' ? source : initial, f = await lib.fixture(algorithm);
  const Client = kind === 'source' ? SourceEditClient : InitialSourceClient;
  const make = (fetchImpl = f.fetchImpl, options = {}) => new Client({ href: lib.href, cryptoImpl: lib.crypto, fetchImpl, ...options });
  const prepare = async client => {
    if (kind === 'source') { await client.select(f.fields.ref, algorithm); await client.prepareEdits(f.edits, lib.metadata); }
    else await client.prepare(f.fields, f.files, lib.metadata);
    await client.stageApply();
  };
  const original = make(); await original.connect(lib.token); await prepare(original);
  const receipt = original.exportReceipt(); f.calls.length = 0;
  return { f, lib, make, original, receipt, prepare };
}
async function assertRestricted(client, kind) {
  const actions = kind === 'source'
    ? [() => client.select('refs/heads/main', 'sha1'), () => client.loadFile('61'), () => client.importFiles([]),
      () => client.prepareEdits([], {}), () => client.preparePatch(new Uint8Array(), {})]
    : [() => client.prepare({}, [], {})];
  actions.push(() => client.stageApply(), () => client.send());
  for (const action of actions) await assert.rejects(action(), /Recovery-only/);
  assert.throws(() => client.discardUnsent(), /Recovery-only/);
}
function alteredOutcome(f, change) {
  return async (url, options) => {
    const reply = await f.fetchImpl(url, options);
    if (!new URL(url).pathname.endsWith('/outcomes')) return reply;
    return json(await change(await reply.json()));
  };
}

for (const kind of ['source', 'initial']) {
  for (const algorithm of ['sha1', 'sha256']) test(`${kind} ${algorithm}: revoked-token receipt recovers only the original outcome`, async () => {
    const s = await setup(kind, algorithm), client = s.make(), saved = JSON.parse(s.receipt);
    await client.connect(ROTATED, selection());
    assert.equal(client.recoveryOnly, true); assert.equal(client.recoveryPrincipal, source.actor);
    await assertRestricted(client, kind);
    await client.restoreReceipt(s.receipt);
    assert.deepEqual(JSON.parse(client.exportReceipt()), saved);
    assert.equal(client.pending.observedPrincipal, null); assert.equal(s.f.calls.length, 0);
    await assertRestricted(client, kind);
    assert.equal((await client.recover()).terminal, false);
    assert.equal(client.pending.observedPrincipal, source.actor);
    s.f.config.outcome = 'undecided'; assert.equal((await client.recover()).tx, 'tx-original');
    assert.equal(client.pending.observedTx, 'tx-original');
    const observed = JSON.parse(client.exportReceipt());
    for (const field of ['fingerprint', 'nonce', 'key', 'bundle_base64', 'fields', 'scope']) assert.deepEqual(observed[field], saved[field]);
    assert.equal(observed.observedPrincipal, source.actor);
    s.f.config.outcome = 'committed'; const result = await client.recover();
    assert.equal(result.outcome, 'committed'); assert.equal(client.pending, null);
    assert.equal(client.recoveryOnly, true); await assertRestricted(client, kind);
    assert.equal(s.f.calls.length, 3);
    for (const call of s.f.calls) {
      assert.equal(call.endpoint, 'outcomes'); assert.equal(call.body, undefined);
      assert.equal(call.headers.authorization, `Bearer ${ROTATED}`);
      assert.equal(call.headers['idempotency-key'], saved.key);
      assert.equal(call.options.method, 'POST');
    }
    await client.connect(ROTATED); assert.equal(client.recoveryOnly, false);
    await s.prepare(client); assert(client.pending);
  });

  test(`${kind}: in-memory lost publication survives token rotation without a resend`, async () => {
    const s = await setup(kind), before = JSON.parse(s.receipt);
    if (kind === 'source') s.f.config.loseApply = true; else s.f.config.lose = true;
    await assert.rejects(s.original.send(), error => error.outcomeUnknown === true);
    assert.equal(s.original.pending.sent, true);
    await assert.rejects(s.original.connect(ROTATED), /another credential/);
    assert.equal(s.original.connected, false); assert.equal(s.original.pending.key, before.key);
    await s.original.connect(ROTATED, selection());
    assert.deepEqual(JSON.parse(s.original.exportReceipt()), before);
    await assertRestricted(s.original, kind);
    s.f.config.outcome = 'refused'; assert.equal((await s.original.recover()).outcome, 'refused');
    assert.equal(s.f.calls.filter(c => c.endpoint.endsWith('/apply')).length, 1);
    assert.equal(s.original.recoveryOnly, true);
  });

  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused']) {
    test(`${kind}: ${state} from another principal never settles or changes the original request`, async () => {
      const s = await setup(kind); s.f.config.outcome = state;
      const client = s.make(alteredOutcome(s.f, value => ({ ...value, principal_id: OTHER })));
      await client.connect(ROTATED, selection()); await client.restoreReceipt(s.receipt);
      await assert.rejects(client.recover(), /principal/);
      assert.deepEqual(JSON.parse(client.exportReceipt()), JSON.parse(s.receipt));
      assert.equal(client.recoveryOnly, true); await assertRestricted(client, kind);
      assert.equal(s.f.calls.length, 1);
    });
  }

  test(`${kind}: an observed original principal cannot be replaced by a new selection`, async () => {
    const s = await setup(kind);
    s.f.config.outcome = 'undecided'; await s.original.recover();
    const before = s.original.exportReceipt(), count = s.f.calls.length;
    await assert.rejects(s.original.connect(ROTATED, { recoveryOnly: true, originalPrincipal: OTHER }), /conflicts/);
    assert.equal(s.original.connected, false); assert.equal(s.original.exportReceipt(), before);
    assert.equal(s.f.calls.length, count);
    const client = s.make(); await client.connect(ROTATED, { recoveryOnly: true, originalPrincipal: OTHER });
    await assert.rejects(client.restoreReceipt(before), /principal conflicts/);
    assert.equal(client.pending, null); assert.equal(s.f.calls.length, count);
  });

  test(`${kind}: the original complete receipt commitment is required under a rotated token`, async () => {
    const s = await setup(kind), original = JSON.parse(s.receipt);
    const mutations = [r => { r.fingerprint = '0'.repeat(64); }, r => { r.fingerprint = null; },
      r => { r.fields.ref = 'refs/heads/other'; }, r => { r.nonce = 'a'.repeat(32); },
      r => { r.bundle_base64 = Buffer.from('different artifact').toString('base64'); },
      r => { r.key += 'x'; }, r => { r.route = '/different.git'; },
      r => { r.scope.incarnation = '4'.repeat(32); }, r => { r.observedPrincipal = OTHER; }];
    for (const change of mutations) {
      const client = s.make(), receipt = structuredClone(original); change(receipt);
      await client.connect(ROTATED, selection());
      await assert.rejects(client.restoreReceipt(JSON.stringify(receipt)));
      assert.equal(client.pending, null); assert.equal(client.recoveryOnly, true);
      await assertRestricted(client, kind);
    }
    assert.equal(s.f.calls.length, 0);
  });

  test(`${kind}: ordinary connection still refuses a receipt bound to another token`, async () => {
    const s = await setup(kind), client = s.make();
    await client.connect(ROTATED); await assert.rejects(client.restoreReceipt(s.receipt), /credential/);
    assert.equal(client.pending, null); assert.equal(s.f.calls.length, 0);
    await client.connect(source.token); await client.restoreReceipt(s.receipt);
    assert.equal(client.recoveryOnly, false); assert.equal(client.pending.key, JSON.parse(s.receipt).key);
  });

  test(`${kind}: invalid recovery options refuse before network and retain responsibility`, async () => {
    const s = await setup(kind);
    for (const options of [{ recoveryOnly: true }, { recoveryOnly: null }, { recoveryOnly: 'yes', originalPrincipal: source.actor },
      { originalPrincipal: source.actor }, { recoveryOnly: true, originalPrincipal: 'F'.repeat(32) },
      { recoveryOnly: true, originalPrincipal: source.actor, force: true }]) {
      await assert.rejects(s.original.connect(ROTATED, options));
      assert.equal(s.original.connected, false); assert.equal(s.original.exportReceipt(), s.receipt);
    }
    assert.equal(s.f.calls.length, 0);
  });

  test(`${kind}: mode and principal are captured before hashing; a superseded connect cannot widen them`, async () => {
    const s = await setup(kind); let release, first = true;
    const pause = new Promise(resolve => { release = resolve; });
    const cryptoImpl = { getRandomValues: source.crypto.getRandomValues.bind(source.crypto), subtle: {
      digest: async (...args) => { if (first) { first = false; await pause; } return source.crypto.subtle.digest(...args); },
    } };
    const client = s.make(s.f.fetchImpl, { cryptoImpl }), options = selection();
    const early = client.connect(ROTATED, options); const failed = assert.rejects(early, /superseded|cancelled|changed/i);
    options.recoveryOnly = false; options.originalPrincipal = OTHER;
    assert.equal(client.recoveryOnly, true); assert.equal(client.recoveryPrincipal, source.actor);
    await assertRestricted(client, kind);
    await client.connect(source.token); release(); await failed;
    assert.equal(client.recoveryOnly, false); assert.equal(client.connected, true);
    await client.restoreReceipt(s.receipt); assert.equal(s.f.calls.length, 0);
    await client.connect(ROTATED, selection()); assert.equal(client.recoveryOnly, true);
    await assertRestricted(client, kind);
  });

  test(`${kind}: malformed, revoked and late disconnected responses preserve the original receipt`, async () => {
    const s = await setup(kind); let mode = 'invalid', finish;
    const client = s.make(async (url, options) => {
      if (mode === 'revoked') return json({}, 401);
      if (mode === 'invalid') return json({ principal_id: source.actor });
      const response = await s.f.fetchImpl(url, options);
      return new Promise(resolve => { finish = () => resolve(response); });
    });
    await client.connect(ROTATED, selection()); await client.restoreReceipt(s.receipt);
    await assert.rejects(client.recover()); assert.equal(client.exportReceipt(), s.receipt);
    mode = 'revoked'; await assert.rejects(client.recover(), error => error.status === 401);
    assert.equal(client.connected, false); assert.equal(client.exportReceipt(), s.receipt);
    mode = 'delayed'; s.f.config.outcome = 'committed'; await client.connect(ROTATED, selection());
    const pending = client.recover(), failed = assert.rejects(pending);
    while (!finish) await new Promise(resolve => setImmediate(resolve));
    client.disconnect(); finish(); await failed;
    assert.equal(client.pending.key, JSON.parse(s.receipt).key); assert.equal(client.exportReceipt(), s.receipt);
  });

  test(`${kind}: completing one recovery does not permit changing its selected key without reconnecting`, async () => {
    const a = await setup(kind), b = await setup(kind), client = a.make();
    await client.connect(ROTATED, selection()); await client.restoreReceipt(a.receipt);
    a.f.config.outcome = 'committed'; await client.recover();
    await assert.rejects(client.restoreReceipt(b.receipt), /Reconnect explicitly/);
    assert.equal(client.pending, null); assert.equal(client.recoveryOnly, true);
    await client.connect(ROTATED, selection()); await client.restoreReceipt(b.receipt);
    assert.equal(client.pending.key, JSON.parse(b.receipt).key);
  });
}
