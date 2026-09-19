import test from 'node:test';
import assert from 'node:assert/strict';
import { TagClient } from '../../crates/fgit-node/src/smart_http/server/browser/tags.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { tagPlan, tagFields, tagInspection, refInput, nativeRef, TAG_LIMITS, RETRY_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/tags-protocol.mjs';
import { fixture, crypto, token, href, head, hex, source, existing, destination, annotationInput, objectBody, objectId, deferred, json } from './tags-fixtures.mjs';
async function connected(f, c = crypto) { const client = new TagClient({ href, fetchImpl: f.fetchImpl, cryptoImpl: c }); await client.connect(token); return client; }
async function listed(f, c = crypto) { const client = await connected(f, c); await client.list({ objectFormat: f.algorithm }); return client; }
async function staged(f, operation = 'annotated') { const c = await listed(f); await c.prepare(operation, operation === 'annotated' ? annotationInput() : operation === 'delete' ? { ref_hex: existing } : { ref_hex: destination, source_ref_hex: source }); return c; }
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: preview constructs exact native bytes with raw names, empty and non-UTF8 messages`, async () => {
    const f = fixture(algorithm);
    for (const message_hex of ['', hex('no final newline'), 'ff0d0a78']) {
      const fields = { object_format: algorithm, ref_hex: hex('refs/tags/v') + 'ff', target: f.commit, target_kind: 'commit', tagger: 'Name <email>', timestamp: 0, message_hex };
      const plan = await tagPlan('annotated', fields, crypto), body = objectBody(fields);
      assert.equal(plan.body_hex, hex(body)); assert.equal(plan.new_object, objectId(body, algorithm)); assert.equal(plan.expected_object, null);
    }
  });
  for (const operation of ['annotated', 'lightweight', 'delete']) test(`${algorithm}: ${operation} sends nothing until confirmed, then matches exact ref effects`, async () => {
    const f = fixture(algorithm), c = await staged(f, operation), p = c.pending;
    assert.equal(f.calls.length, 1); assert.equal(p.sent, false);
    const result = await c.send(); assert.equal(result.outcome, 'committed'); assert.equal(c.pending, null);
    const call = f.calls.at(-1); assert.equal(call.path, `source/tags/${operation}`);
    const fields = Object.fromEntries(new URLSearchParams(call.body));
    assert.equal(fields.ref_hex, operation === 'delete' ? existing : destination);
    assert.equal(fields.expected_object, operation === 'delete' ? f.tag : undefined);
    assert.equal(fields.target, operation === 'delete' ? undefined : f.commit);
    assert.equal(fields.force, undefined); assert.equal(fields.expected_head, undefined);
    assert.equal(call.headers['idempotency-key'], p.key); assert.equal(call.redirect, 'error'); assert.equal(call.credentials, 'omit');
  });
  test(`${algorithm}: annotation chain is hashed and inspection pins both direct object and snapshot`, async () => {
    const f = fixture(algorithm), c = await listed(f), r = await c.inspect(existing);
    assert.equal(r.peeled_object, f.commit); assert.equal(r.annotations[0].object_id, f.tag);
    assert.equal(r.signature_verified, false); assert.equal(f.calls.at(-1).headers['idempotency-key'], undefined);
    const form = Object.fromEntries(new URLSearchParams(f.calls.at(-1).body));
    assert.equal(form.expected_head, head); assert.equal(form.expected_object, f.tag); assert.equal(form.max_tags, String(TAG_LIMITS.max_tags));
    c.inspection.annotations[0].body_hex = ''; assert.notEqual(c.inspection.annotations[0].body_hex, '');
  });
  test(`${algorithm}: lost-response receipt restores and retries identical bytes without re-reading deleted refs`, async () => {
    const f = fixture(algorithm), c = await staged(f, 'delete'); f.config.lose = true;
    await assert.rejects(c.send(), e => e.outcomeUnknown); const sent = f.calls.at(-1), receipt = c.exportReceipt();
    assert(!receipt.includes(token)); c.disconnect(); assert(c.pending); const restored = await connected(f), n = f.calls.length;
    await restored.restoreReceipt(receipt); assert.equal(f.calls.length, n); f.refs.length = 0; f.config.lose = false;
    await restored.send(); assert.equal(f.calls.length, n + 1); assert.equal(f.calls.at(-1).body, sent.body); assert.equal(f.calls.at(-1).headers['idempotency-key'], sent.headers['idempotency-key']);
  });
  test(`${algorithm}: canonical 409 is a refusal, not success or an endlessly pending write`, async () => {
    const f = fixture(algorithm), c = await staged(f); f.config.refuse = true;
    assert.equal((await c.send()).outcome, 'refused'); assert.equal(c.pending, null);
  });
}
test('pages retain cursor, limit and snapshot across continuation and own their rows', async () => {
  const f = fixture(), c = await connected(f); await c.list({ limit: 1 }); c.refs[0].object_id = 'b'.repeat(40);
  await c.list({ next: true, objectFormat: 'sha256', limit: 100 });
  assert.equal(c.refs.length, 2); assert.equal(c.refs[0].object_id, f.commit);
  assert.deepEqual(Object.fromEntries(new URLSearchParams(f.calls.at(-1).body)), { object_format: 'sha1', namespace: 'all', limit: '1', after: 'refs/heads/main', expected_head: head });
});
for (const [name, change] of [
  ['head', r => r.snapshot_token = `alg:1:${'8'.repeat(64)}`], ['identity', r => r.repository_incarnation = '8'.repeat(32)],
  ['cursor', r => r.after = null], ['format', r => r.object_format = 'sha256'], ['order', r => r.refs[0] = fixture().refs[0]],
  ['continuation', r => r.next_after = 'refs/tags/not-last'], ['text bytes', r => r.refs[0].ref = 'refs/tags/other'],
]) test(`continuation rejects changed ${name}`, async () => {
  const f = fixture(), c = await connected(f); await c.list({ limit: 1 }); f.config.list = change;
  await assert.rejects(c.list({ next: true })); assert.equal(c.refs.length, 1);
});
for (const [name, change] of [
  ['hash', r => r.annotations[0].body_hex += '78'], ['ref', r => r.ref_hex = destination], ['direct', r => r.object_id = '8'.repeat(40)],
  ['target', r => r.annotations[0].target = '8'.repeat(40)], ['kind', r => r.annotations[0].target_kind = 'blob'],
  ['peeled', r => r.peeled_object = '8'.repeat(40)], ['count', r => r.annotation_count++], ['signature claim', r => r.signature_verified = true],
  ['tagger authority', r => r.tagger_is_authenticated_principal = true], ['annotation signature', r => r.annotations[0].signature_verified = true],
  ['size', r => r.annotations[0].body_bytes++], ['snapshot', r => r.snapshot_token = `alg:1:${'8'.repeat(64)}`],
  ['oversized', r => { r.annotations[0].body_hex = '78'.repeat(TAG_LIMITS.max_object_bytes + 1); }],
]) test(`inspection rejects ${name} and exposes no old report`, async () => {
  const f = fixture(), c = await listed(f); await c.inspect(existing); f.config.inspect = change;
  await assert.rejects(c.inspect(existing)); assert.equal(c.inspection, null);
});
test('nested tag chain verifies every edge; signature text stays opaque and legacy taggers may be absent', async () => {
  const f = fixture(), r = structuredClone(f.inspection), first = r.annotations[0];
  const body = Buffer.from(`object ${first.object_id}\ntype tag\ntag outer\n\n-----BEGIN PGP SIGNATURE-----\nnot a real signature\n`);
  const id = objectId(body, 'sha1'); r.object_id = id; r.annotation_count = 2;
  r.annotations.unshift({ object_id: id, target: first.object_id, target_kind: 'tag', body_hex: hex(body), body_bytes: body.length, signature: 'opaque_unverifiable', signature_verified: false });
  const expected = { scope: { tenant: f.common.tenant_id, repository: f.common.repository_id, incarnation: f.common.repository_incarnation, format: 'sha1' }, head, ref_hex: existing, object_id: id };
  await tagInspection(r, expected, crypto); r.annotations[1].target_kind = 'tag'; await assert.rejects(tagInspection(r, expected, crypto));
});
test('lightweight inspection uses direct target, not a fabricated annotation', async () => {
  const f = fixture(), c = await listed(f); f.config.inspect = r => { r.annotations = []; r.annotation_count = 0; r.peeled_object = f.tag; r.peeled_kind = 'blob'; };
  assert.equal((await c.inspect(existing)).annotation_count, 0);
});
for (const [name, change] of [
  ['new object', r => r.new_object = '8'.repeat(40)], ['old object', r => r.expected_object = '8'.repeat(40)],
  ['operation', r => r.operation = 'delete'], ['ref', r => r.ref_hex = existing], ['force', r => r.force = true],
  ['atomicity', r => r.atomic = false], ['terminal', r => r.terminal = false], ['signature', r => r.signature_verified = true],
  ['tagger', r => r.tagger_is_authenticated_principal = true], ['scope', r => r.repository_incarnation = '8'.repeat(32)],
  ['contradiction', r => r.code = 'Refused'], ['sequence', r => r.decision_sequence = Number.MAX_SAFE_INTEGER + 1],
]) test(`malformed terminal ${name} retains exact request and responsibility`, async () => {
  const f = fixture(), c = await staged(f), key = c.pending.key; f.config.terminal = change;
  await assert.rejects(c.send(), e => e.outcomeUnknown); assert.equal(c.pending.key, key); assert(c.pending.sent); assert.throws(() => c.discardUnsent());
});
test('generic 409 is not a canonical decision', async () => {
  const f = fixture(), normal = f.fetchImpl; f.fetchImpl = (url, opts) => String(url).endsWith('/annotated') ? json({ type: 'source_error', code: 'idempotency_key_reuse' }, 409) : normal(url, opts);
  const c = await staged(f); await assert.rejects(c.send()); assert(c.pending);
});
for (const [name, change] of [
  ['name', r => r.fields.ref_hex = hex('refs/tags/other')], ['message', r => r.fields.message_hex += '78'],
  ['target', r => r.fields.target = '8'.repeat(40)], ['tagger', r => r.fields.tagger = 'Other <a@b>'],
  ['timestamp', r => r.fields.timestamp++], ['kind', r => r.fields.target_kind = 'blob'], ['operation', r => r.operation = 'lightweight'],
  ['scope', r => r.scope.incarnation = '8'.repeat(32)], ['route', r => r.route = '/other.git'], ['origin', r => r.origin = 'https://other.example'],
  ['nonce', r => r.nonce = '8'.repeat(32)], ['extra', r => r.force = true],
]) test(`saved receipt cannot alter ${name} under its original key`, async () => {
  const f = fixture(), c = await staged(f), r = JSON.parse(c.exportReceipt()); change(r);
  const next = await connected(f); await assert.rejects(next.restoreReceipt(JSON.stringify(r))); assert.equal(next.pending, null);
});
test('recovery is bodyless and all nonterminal states preserve the original request', async () => {
  const f = fixture(), c = await staged(f);
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
    f.config.outcome = state; const result = await c.recover(); assert.equal(result.terminal, false); assert(c.pending);
    assert.equal(f.calls.at(-1).body, undefined); assert.equal(f.calls.at(-1).path, 'outcomes');
  }
  f.config.outcome = 'key_not_observed'; await assert.rejects(c.recover()); assert(c.pending);
  f.config.outcome = 'committed'; f.config.recover = r => r.principal_id = '8'.repeat(32); await assert.rejects(c.recover());
  f.config.recover = null; assert.equal((await c.recover()).outcome, 'committed'); assert.equal(c.pending, null);
  assert(!f.calls.some(r => r.path === 'source/tags/annotated'));
});
test('copied user input and returned previews cannot alter prepared publication', async () => {
  const f = fixture(), c = await listed(f), input = annotationInput(), preparing = c.prepare('annotated', input); input.message_hex = '78'; await preparing;
  c.pending.fields.target = '8'.repeat(40); c.pending.new_object = '8'.repeat(40);
  assert.equal((await c.send()).outcome, 'committed'); assert.equal(new URLSearchParams(f.calls.at(-1).body).get('message_hex'), annotationInput().message_hex);
});
test('cancelled HTTP inspection cannot restore cleared views and pending writes survive disconnect', async () => {
  const f = fixture(), c = await listed(f), d = deferred(); f.config.inspect = () => d.promise;
  const p = c.inspect(existing); c.disconnect(); d.resolve(); await assert.rejects(p); assert.equal(c.inspection, null); assert.equal(c.refs.length, 0);
  const other = await staged(f); f.config.lose = true; await assert.rejects(other.send()); const key = other.pending.key;
  other.disconnect(); assert.equal(other.pending.key, key); await assert.rejects(other.connect('8'.repeat(64))); await other.connect(token);
});
test('cancelled asynchronous hash cannot select a prepared request', async () => {
  const f = fixture(), d = deferred(); let block = false;
  const delayed = { getRandomValues: a => crypto.getRandomValues(a), subtle: { digest: async (...args) => { if (block) await d.promise; return crypto.subtle.digest(...args); } } };
  const c = await listed(f, delayed); block = true;
  const preparing = c.prepare('annotated', annotationInput()); c.cancel(); d.resolve(); await assert.rejects(preparing); assert.equal(c.pending, null);
});
test('canceling reads does not abort an in-flight publication', async () => {
  const f = fixture(), c = await staged(f), d = deferred(); f.config.terminal = () => d.promise;
  const sending = c.send(); await new Promise(setImmediate); c.cancel(); assert.equal(f.calls.at(-1).signal.aborted, false);
  d.resolve(); assert.equal((await sending).outcome, 'committed');
});
test('only unsent and unexported requests can be discarded; unknown selected sources are not OID capabilities', async () => {
  const f = fixture(), c = await staged(f); c.discardUnsent(); assert.equal(c.pending, null);
  await assert.rejects(c.prepare('lightweight', { ref_hex: destination, source_ref_hex: hex('refs/heads/missing') }));
  await assert.rejects(c.prepare('lightweight', { ref_hex: destination, source_ref_hex: source, target: f.commit }));
  await c.prepare('annotated', annotationInput()); c.exportReceipt(); assert.throws(() => c.discardUnsent()); await assert.rejects(c.list());
});
test('tag grammar bounds identities, message bytes, raw names and coordinate domains', async () => {
  const f = fixture(), good = { object_format: 'sha1', ref_hex: destination, target: f.commit, target_kind: 'commit', tagger: 'Name <a@b>', timestamp: 1, message_hex: '' };
  for (const tagger of ['missing', ' <a@b>', 'Name <>', 'Name <a<b>>', 'Name <a@b>\ninject']) assert.throws(() => tagFields('annotated', { ...good, tagger }));
  for (const delta of [{ message_hex: '00' }, { message_hex: 'AA' }, { message_hex: '78'.repeat(65537) }, { timestamp: -1 }, { timestamp: Number.MAX_SAFE_INTEGER + 1 }, { target_kind: 'unknown' }, { force: true }, { ref_hex: source }, { target: '0'.repeat(40) }]) assert.throws(() => tagFields('annotated', { ...good, ...delta }));
  for (const name of ['', 'refs/tags/', 'refs/tags/a.lock', 'refs/tags/a..b', 'refs/tags/a\0b', 'refs/tags/.a', 'refs/tags/a b']) assert.throws(() => refInput(name));
  assert.equal(refInput('726566732f746167732f76ff', true), '726566732f746167732f76ff');
  const c = await connected(f); await assert.rejects(c.restoreReceipt('x'.repeat(RETRY_LIMIT + 1))); assert.throws(() => nativeRef('78'.repeat(4097)));
});
test('tag route isolation preserves all other browser profiles and enforces method/read/key boundaries', async () => {
  const f = fixture(), c = new Transport({ href, pageSuffix: '/ui/tags/', cryptoImpl: crypto, fetchImpl: f.fetchImpl }); await c.connect(token);
  for (const path of ['source/apply', 'source/branches/delete', 'source/initial/apply', 'source/bundle/import', 'pulls', 'source/tags/force', 'source/tags/inspect?token=x']) await assert.rejects(c.request(path, { method: 'POST', body: 'x', read: false, key: 'x' }));
  for (const args of [{}, { method: 'GET', body: 'x' }, { method: 'POST', body: 'x', key: 'x' }, { method: 'POST', body: 'x', read: false }, { method: 'POST', body: 'x', binary: true }]) await assert.rejects(c.request('source/tags/inspect', args));
  for (const suffix of ['pulls','source','initial','branches','search','transfers']) {
    const other = new Transport({ href: href.replace('tags/', `${suffix}/`), pageSuffix: `/ui/${suffix}/`, cryptoImpl: crypto, fetchImpl: f.fetchImpl }); await other.connect(token);
    await assert.rejects(other.request('source/tags/delete', { method: 'POST', body: 'x', read: false, key: 'x' }));
  }
  assert.equal(f.calls.length, 0);
});
