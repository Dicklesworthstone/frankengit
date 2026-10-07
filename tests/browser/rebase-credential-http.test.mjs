// Real loopback sockets and default Node Fetch, with an EXPLICIT protocol double.
// The map below models principal-scoped outcomes; it is not native authentication,
// Rust admission, durable storage, or evidence that a ref was really published.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { RebaseClient } from '../../crates/fgit-node/src/smart_http/server/browser/rebase.mjs';
import { fixture, token, actor, crypto } from './rebase-session-fixtures.mjs';
const replacement = '8'.repeat(64), stranger = '6'.repeat(64), noScope = '5'.repeat(64);
async function service(t, algorithm) {
  const f = await fixture(algorithm), received = [], outcomes = new Map(), faults = { loseApply: false, revoked: false, redirect: false, wait: null };
  const grants = new Map([[token, { principal: actor, write: true, outcomes: true }],
    [replacement, { principal: actor, write: false, outcomes: true }],
    [stranger, { principal: 'a'.repeat(32), write: false, outcomes: true }],
    [noScope, { principal: actor, write: false, outcomes: false }]]);
  const send = (res, status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
  const server = createServer((req, res) => { void (async () => {
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > 2 * 1024 * 1024) throw new Error('test request limit'); chunks.push(chunk); }
    const body = Buffer.concat(chunks), endpoint = req.url?.split('/api/v1/')[1], bearer = req.headers.authorization?.slice(7);
    received.push({ endpoint, method: req.method, body, headers: { ...req.headers } });
    const grant = grants.get(bearer);
    if (!grant || (bearer === token && faults.revoked)) return send(res, 401, { error: 'credential' });
    if (req.method !== 'POST' || req.url.includes('?')) return send(res, 400, { error: 'request' });
    if (endpoint === 'outcomes') {
      if (!grant.outcomes) return send(res, 403, { error: 'scope' });
      if (body.length || !req.headers['idempotency-key']) return send(res, 400, { error: 'bodyless key required' });
      if (faults.redirect) { res.writeHead(307, { Location: '/not-an-outcome' }); res.end(); return; }
      if (faults.wait) await faults.wait();
      f.config.outcome = outcomes.get(`${grant.principal}/${req.headers['idempotency-key']}`)?.state ?? 'key_not_observed';
      const reply = await f.fetchImpl(`http://local/repo.git/api/v1/outcomes`, { method: 'POST', headers: {}, body: undefined });
      const value = await reply.json(); value.principal_id = grant.principal;
      return send(res, 200, value);
    }
    if (!grant.write) return send(res, 403, { error: 'no authoring grant in test profile' });
    const reply = await f.fetchImpl(`http://local/repo.git/api/v1/${endpoint}`, {
      method: req.method, headers: req.headers, body: (req.headers['content-type'] ?? '').startsWith('multipart/')
        ? new Uint8Array(body) : body.toString('utf8'),
    });
    if (endpoint === 'source/rebase/apply') {
      assert(req.headers['idempotency-key']);
      outcomes.set(`${grant.principal}/${req.headers['idempotency-key']}`, { state: 'committed', bytes: Buffer.from(body),
        sha256: createHash('sha256').update(body).digest('hex') });
      if (faults.loseApply) { res.destroy(); return; }
    }
    res.writeHead(reply.status, Object.fromEntries(reply.headers)); res.end(Buffer.from(await reply.arrayBuffer()));
  })().catch(error => { t.diagnostic(`Protocol double error: ${error}`); if (!res.destroyed) send(res, 500, { error: String(error) }); }); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { const closed = new Promise(resolve => server.close(resolve)); server.closeAllConnections(); await closed; });
  const href = `http://127.0.0.1:${server.address().port}/repo.git/ui/rebase/`;
  const options = { href, cryptoImpl: crypto, timeoutMs: 3000 }; // no fetchImpl: exercise default Fetch
  const client = new RebaseClient(options);
  await client.connect(token); await client.select(f.command.source_ref, f.command.onto_ref, algorithm);
  await client.prepare(f.input); await client.stage();
  return { f, received, outcomes, faults, client, options };
}
async function lose(s) {
  s.faults.loseApply = true; await assert.rejects(s.client.send(), error => error.outcomeUnknown === true);
  const request = s.received.at(-1), pending = s.client.pending;
  assert.equal(request.endpoint, 'source/rebase/apply');
  assert.equal(createHash('sha256').update(request.body).digest('hex'), pending.requestSha256);
  assert(s.outcomes.has(`${actor}/${pending.key}`));
  s.faults.revoked = true;
  return { request, pending, receipt: s.client.exportReceipt() };
}
function lookupOnly(calls, key) {
  assert(calls.length > 0);
  for (const call of calls) {
    assert.equal(call.endpoint, 'outcomes'); assert.equal(call.method, 'POST');
    assert.equal(call.body.length, 0); assert.equal(call.headers['content-type'], undefined);
    assert.equal(call.headers['idempotency-key'], key);
  }
}
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: lost socket reply and revoked old token recover with the same principal's read-only token`, async t => {
    const s = await service(t, algorithm), original = await lose(s), before = s.received.length;
    await assert.rejects(s.client.recover(), error => error.status === 401); assert(s.client.pending);
    await s.client.connectForRecovery(replacement, actor); assert.equal(s.client.exportReceipt(), original.receipt);
    await assert.rejects(s.client.send(), /Recovery-only/);
    const result = await s.client.recover(); assert.equal(result.outcome, 'committed'); assert.equal(s.client.pending, null);
    lookupOnly(s.received.slice(before), original.pending.key);
    assert.equal(s.received.at(-1).headers.authorization, `Bearer ${replacement}`);
    assert.equal(s.outcomes.size, 1); assert(s.client.recoveryOnly);
    assert.deepEqual(s.outcomes.get(`${actor}/${original.pending.key}`).bytes, original.request.body);
  });
  test(`${algorithm}: receipt reload with replacement token does not rerun rebase or upload candidate bytes`, async t => {
    const s = await service(t, algorithm), original = await lose(s), before = s.received.length;
    const restored = new RebaseClient(s.options); await restored.connectForRecovery(replacement, actor);
    await restored.restoreReceipt(original.receipt); assert.equal(s.received.length, before);
    assert.equal(restored.pending.key, original.pending.key); assert.equal(restored.pending.requestSha256, original.pending.requestSha256);
    assert.equal(restored.exportReceipt(), original.receipt); await restored.recover();
    assert.equal(restored.pending, null); lookupOnly(s.received.slice(before), original.pending.key);
    assert.equal(s.received.length, before + 1);
  });
  test(`${algorithm}: missing scope and another principal have no effect, with a permitted same-principal twin`, async t => {
    const s = await service(t, algorithm), original = await lose(s), before = s.received.length;
    await s.client.connectForRecovery(noScope, actor);
    await assert.rejects(s.client.recover(), error => error.status === 403); assert.equal(s.client.pending.key, original.pending.key);
    await s.client.connectForRecovery(stranger, actor);
    await assert.rejects(s.client.recover(), /original principal/); assert.equal(s.client.pending.observedPrincipal, null);
    assert.equal(s.client.pending.key, original.pending.key); assert.equal(s.outcomes.size, 1);
    await s.client.connectForRecovery(replacement, actor); assert.equal((await s.client.recover()).outcome, 'committed');
    lookupOnly(s.received.slice(before), original.pending.key); assert.equal(s.outcomes.size, 1);
  });
  test(`${algorithm}: absent and undecided observations preserve the exact request until a canonical refusal`, async t => {
    const s = await service(t, algorithm), original = await lose(s), key = `${actor}/${original.pending.key}`, before = s.received.length;
    const retained = s.outcomes.get(key); s.outcomes.delete(key);
    await s.client.connectForRecovery(replacement, actor); assert.equal((await s.client.recover()).state, 'key_not_observed');
    assert.equal(s.client.pending.key, original.pending.key); assert.equal(s.client.pending.requestSha256, original.pending.requestSha256);
    s.outcomes.set(key, { ...retained, state: 'undecided' }); assert.equal((await s.client.recover()).state, 'undecided');
    assert.equal(s.client.pending.observedTx, 'tx-original'); await assert.rejects(s.client.send(), /Recovery-only/);
    s.outcomes.set(key, { ...retained, state: 'refused' }); const result = await s.client.recover();
    assert.equal(result.outcome, 'refused'); assert.equal(result.refusal, 'TargetRefMoved'); assert.equal(s.client.pending, null);
    assert(s.client.recoveryOnly); lookupOnly(s.received.slice(before), original.pending.key);
  });
}
test('a redirected outcome reply never forwards the credential or settles the request', async t => {
  const s = await service(t, 'sha1'), original = await lose(s), before = s.received.length;
  await s.client.connectForRecovery(replacement, actor); s.faults.redirect = true;
  await assert.rejects(s.client.recover()); assert.equal(s.client.pending.key, original.pending.key);
  assert.equal(s.received.length, before + 1); lookupOnly(s.received.slice(before), original.pending.key);
  s.faults.redirect = false; assert.equal((await s.client.recover()).outcome, 'committed');
});
test('disconnect during a real HTTP outcome read keeps the original request recoverable', async t => {
  const s = await service(t, 'sha256'), original = await lose(s); await s.client.connectForRecovery(replacement, actor);
  let release, entered; const reached = new Promise(resolve => { entered = resolve; });
  s.faults.wait = () => new Promise(resolve => { release = resolve; entered(); });
  const work = s.client.recover(); await reached; s.client.disconnect(); release(); await assert.rejects(work);
  assert.equal(s.client.pending.key, original.pending.key); assert.equal(s.client.pending.requestSha256, original.pending.requestSha256);
  s.faults.wait = null; await s.client.connectForRecovery(replacement, actor); await s.client.recover(); assert.equal(s.client.pending, null);
});
