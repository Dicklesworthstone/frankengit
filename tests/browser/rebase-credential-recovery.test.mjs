// Actual client, native WebCrypto and explicit HTTP doubles. Not native admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { RebaseClient } from '../../crates/fgit-node/src/smart_http/server/browser/rebase.mjs';
import { fixture, token, actor, href, crypto } from './rebase-session-fixtures.mjs';
const replacement = '8'.repeat(64), otherActor = 'a'.repeat(32);
async function setup(algorithm = 'sha1') {
  const f = await fixture(algorithm), control = { response: null, status: null, error: null };
  const fetchImpl = async (url, options) => {
    const response = await f.fetchImpl(url, options);
    if (!String(url).endsWith('/outcomes')) return response;
    if (control.error) throw control.error;
    const value = await response.json(); control.response?.(value);
    return new Response(JSON.stringify(value), { status: control.status ?? 200, headers: { 'Content-Type': 'application/json' } });
  };
  const options = { href, cryptoImpl: crypto, fetchImpl }, client = new RebaseClient(options);
  await client.connect(token); await client.select(f.command.source_ref, f.command.onto_ref, algorithm);
  await client.prepare(f.input); await client.stage();
  return { f, client, control, options };
}
for (const algorithm of ['sha1', 'sha256']) {
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused']) {
    test(`${algorithm}: replacement credential resolves ${state} using only the original key`, async () => {
      const { f, client } = await setup(algorithm), original = client.pending;
      f.config.lose = true; await assert.rejects(client.send(), e => e.outcomeUnknown === true);
      const saved = client.exportReceipt();
      await assert.rejects(client.connect(replacement), /credential/); // unchanged ordinary-mode contract
      await client.connectForRecovery(replacement, actor);
      assert(client.recoveryOnly); assert.equal(client.recoveryPrincipal, actor);
      assert.equal(client.candidate, null); assert.equal(client.selection, null);
      assert.equal(client.exportReceipt(), saved);
      const before = f.calls.length;
      await assert.rejects(client.send(), /Recovery-only/);
      assert.equal(f.calls.length, before);
      f.config.outcome = state; const result = await client.recover();
      const terminal = ['committed', 'refused'].includes(state);
      assert.equal(result.terminal, terminal); assert.equal(client.pending === null, terminal);
      assert.equal(f.calls.length, before + 1);
      const call = f.calls.at(-1);
      assert.equal(call.endpoint, 'outcomes'); assert.equal(call.options.method, 'POST');
      assert.equal(call.options.body, undefined);
      assert.equal(new Headers(call.options.headers).get('Authorization'), `Bearer ${replacement}`);
      assert.equal(new Headers(call.options.headers).get('Idempotency-Key'), original.key);
      assert.equal(new Headers(call.options.headers).has('Content-Type'), false);
      assert.equal(client.recoveryOnly, true); // terminal is not promotion to a writer
      if (!terminal) {
        assert.equal(client.pending.requestSha256, original.requestSha256);
        assert.equal(client.pending.observedPrincipal, actor);
        assert.throws(() => client.discardUnsent(), /Recovery-only/);
      }
    });
  }
  test(`${algorithm}: saved original receipt restores with no original token or repository read`, async () => {
    const { f, client, options } = await setup(algorithm), saved = client.exportReceipt(), original = client.pending;
    const restored = new RebaseClient(options); await restored.connectForRecovery(replacement, actor);
    const before = f.calls.length; await restored.restoreReceipt(saved);
    assert.equal(f.calls.length, before); assert.equal(restored.pending.key, original.key);
    assert.equal(restored.pending.requestSha256, original.requestSha256);
    assert.equal(restored.exportReceipt(), saved);
    assert(!saved.includes(token)); assert(!restored.exportReceipt().includes(replacement));
    f.config.outcome = 'committed'; assert.equal((await restored.recover()).outcome, 'committed');
    assert.equal(f.calls.length, before + 1);
    await assert.rejects(restored.select(f.command.source_ref, f.command.onto_ref, algorithm), /Recovery-only/);
    await restored.connect(replacement); assert.equal(restored.recoveryOnly, false);
    await restored.select(f.command.source_ref, f.command.onto_ref, algorithm);
    assert(restored.selection); // explicit new ordinary connection is allowed after terminal recovery
  });
  for (const state of ['key_not_observed', 'committed']) {
    test(`${algorithm}: another authenticated principal cannot settle or relabel ${state}`, async () => {
      const { f, client, control } = await setup(algorithm);
      await client.connectForRecovery(replacement, actor); const before = client.pending;
      f.config.outcome = state; control.response = value => { value.principal_id = otherActor; };
      await assert.rejects(client.recover(), /original principal/);
      assert.deepEqual(client.pending, before); assert.equal(client.recoveryPrincipal, actor);
      control.response = null; const permitted = await client.recover();
      assert.equal(permitted.terminal, state === 'committed');
    });
  }
}
test('recovery-only mode denies every authoring/draft operation before any fetch', async () => {
  const { f, client } = await setup(); await client.connectForRecovery(replacement, actor);
  const pending = client.pending, before = f.calls.length;
  for (const invoke of [() => client.select('refs/heads/a', 'refs/heads/b', 'sha1'), () => client.prepare({}),
    () => client.resolve([]), () => client.continueEmpty('drop'), () => client.stage(), () => client.send(),
    () => client.restoreDraft('{}'), () => client.resumeDraft(), () => client.exportDraft()]) {
    await assert.rejects(invoke(), /Recovery-only/);
    assert.deepEqual(client.pending, pending);
  }
  assert.throws(() => client.discardUnsent(), /Recovery-only/); assert.equal(f.calls.length, before);
});
test('a previously authenticated principal cannot be replaced by an input or receipt', async () => {
  const { f, client, options } = await setup(); f.config.outcome = 'undecided'; await client.recover();
  const pending = client.pending; await assert.rejects(client.connectForRecovery(replacement, otherActor), /original authenticated/);
  assert.deepEqual(client.pending, pending); assert.equal(client.recoveryOnly, false);
  const restored = new RebaseClient(options); await restored.connectForRecovery(replacement, otherActor);
  await assert.rejects(restored.restoreReceipt(client.exportReceipt()), /Receipt principal/);
  assert.equal(restored.pending, null);
  await restored.connectForRecovery(replacement, actor); await restored.restoreReceipt(client.exportReceipt());
  assert.equal(restored.pending.observedPrincipal, actor);
});
for (const value of [null, undefined, '', '9'.repeat(31), '9'.repeat(33), 'A'.repeat(32), '<script>']) {
  test(`an explicit canonical original principal is mandatory (${String(value)})`, async () => {
    const { f, client } = await setup(), before = f.calls.length, pending = client.pending;
    await assert.rejects(client.connectForRecovery(replacement, value), /principal/);
    assert.equal(f.calls.length, before); assert.deepEqual(client.pending, pending); assert(client.connected);
    assert.equal(client.recoveryOnly, false);
  });
}
for (const [name, mutate] of [
  ['candidate', r => { r.fields.candidate_commit = 'b'.repeat(40); }],
  ['branch', r => { r.fields.ref = 'refs/heads/other'; }],
  ['fingerprint', r => { r.fingerprint = 'a'.repeat(64); }],
  ['missing fingerprint', r => { delete r.fingerprint; }],
  ['malformed fingerprint', r => { r.fingerprint = '<script>'; }],
  ['incarnation', r => { r.scope.incarnation = 'other'; }],
  ['body', r => { r.bundle_base64 = btoa('different native bytes'); }],
  ['key', r => { r.key += 'x'; }], ['origin', r => { r.origin = 'https://example.invalid'; }],
  ['route', r => { r.route = '/other.git'; }], ['extra', r => { r.force = true; }],
]) test(`replacement-token restoration still rejects tampered ${name}`, async () => {
  const { f, client, options } = await setup(), saved = JSON.parse(client.exportReceipt()); mutate(saved);
  const restored = new RebaseClient(options); await restored.connectForRecovery(replacement, actor);
  const before = f.calls.length; await assert.rejects(restored.restoreReceipt(JSON.stringify(saved)));
  assert.equal(restored.pending, null); assert.equal(f.calls.length, before);
});
for (const [name, mutate] of [
  ['scope', r => { r.repository_id = 'b'.repeat(32); }],
  ['incarnation', r => { r.repository_incarnation = 'c'.repeat(32); }],
  ['reexecution', r => { r.request_reexecuted = true; }],
  ['missing decision', r => { r.decision = null; }],
  ['missing transaction', r => { r.transaction = null; }],
  ['inconsistent terminal', r => { r.terminal = false; }],
]) test(`changed ${name} does not erase the outstanding original request`, async () => {
  const { f, client, control } = await setup(); await client.connectForRecovery(replacement, actor);
  f.config.outcome = 'committed'; const pending = client.pending; control.response = mutate;
  await assert.rejects(client.recover()); assert.deepEqual(client.pending, pending);
  control.response = null; assert.equal((await client.recover()).outcome, 'committed');
});
for (const status of [401, 403, 409, 429, 500]) test(`HTTP ${status} retains original responsibility`, async () => {
  const { client, control } = await setup(); await client.connectForRecovery(replacement, actor);
  const pending = client.pending; control.status = status; await assert.rejects(client.recover());
  assert.deepEqual(client.pending, pending); assert.equal(client.connected, status !== 401);
});
test('once observed, transaction identity and principal cannot regress across replacement lookups', async () => {
  const { f, client, control } = await setup(); await client.connectForRecovery(replacement, actor);
  f.config.outcome = 'undecided'; await client.recover(); const pending = client.pending;
  f.config.outcome = 'key_not_observed'; await assert.rejects(client.recover(), /no longer observes/);
  assert.deepEqual(client.pending, pending);
  f.config.outcome = 'committed'; control.response = r => { r.transaction.tx_id = 'other'; };
  await assert.rejects(client.recover(), /transaction changed/); assert.deepEqual(client.pending, pending);
  control.response = null; await client.recover(); assert.equal(client.pending, null);
});
test('ordinary reconnect cannot promote a replacement token into an original-key writer', async () => {
  const { f, client } = await setup(); await client.connectForRecovery(replacement, actor);
  f.config.outcome = 'undecided'; await client.recover(); const pending = client.pending, before = f.calls.length;
  await assert.rejects(client.connect(replacement), /another credential/); assert.equal(client.connected, false);
  await assert.rejects(client.send()); assert.equal(f.calls.length, before); assert.deepEqual(client.pending, pending);
  await client.connect(token); assert.equal(client.recoveryOnly, false);
  await client.send(); assert.equal(f.calls.at(-1).options.headers['Idempotency-Key'], pending.key);
});
test('disconnect during a recovery reply preserves pending bytes without authenticating stale data', async () => {
  const { f, client } = await setup(); await client.connectForRecovery(replacement, actor);
  f.config.outcome = 'committed'; const pending = client.pending; let entered, release;
  const reached = new Promise(resolve => { entered = resolve; });
  f.config.wait = path => path === 'outcomes' ? new Promise(resolve => { release = resolve; entered(); }) : undefined;
  const work = client.recover(); await reached; client.disconnect(); release(); await assert.rejects(work);
  assert.equal(client.connected, false); assert.equal(client.recoveryPrincipal, null); assert.deepEqual(client.pending, pending);
});
test('concurrent credential hashing cannot clear a newer recovery-only restriction', async () => {
  const { client, options } = await setup(); const saved = client.exportReceipt(); let release, calls = 0;
  const heldCrypto = { getRandomValues: values => crypto.getRandomValues(values), subtle: {
    digest: (...args) => ++calls === 1 ? new Promise(resolve => { release = () => resolve(crypto.subtle.digest(...args)); }) : crypto.subtle.digest(...args),
  } };
  const c = new RebaseClient({ ...options, cryptoImpl: heldCrypto });
  const old = c.connectForRecovery(replacement, otherActor);
  const current = c.connectForRecovery('6'.repeat(64), actor); await current; release(); await assert.rejects(old, /superseded/);
  assert(c.connected); assert.equal(c.recoveryPrincipal, actor); await c.restoreReceipt(saved);
  await assert.rejects(c.send(), /Recovery-only/);
});
