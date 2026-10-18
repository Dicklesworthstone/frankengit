import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { submitPull, recoverPull, preparePull, validatePullIntent, parsePullJson } from '../../scripts/operator/remote_pull.mjs';
import { PULL_ACTIONS, PULL_LIMITS, pullCommand, validatePullPublication, pullCanonical } from '../../scripts/operator/pull_command.mjs';
import { TOKEN, ROTATED, input, publication, outcome, wire, peer, respond, consent } from './remote_pull_fixture.mjs';

for (const algorithm of ['sha1', 'sha256']) for (const action of PULL_ACTIONS) for (const state of ['committed', 'refused']) {
  test(`${algorithm} ${action}: native ${state} through preflight, exact publication and confirmation`, async t => {
    const p = await peer(t, { algorithm, action, state }), saved = JSON.stringify(p.intent);
    const result = await submitPull(p.intent, TOKEN, consent(p.intent));
    assert.equal(result.outcome.state, state); assert.equal(result.dispatched, true);
    assert.equal(result.outcome.decision.decision_sequence, '18446744073709551615');
    assert.equal(result.publication.number, '18446744073709551615');
    assert.equal(JSON.stringify(p.intent), saved); assert.equal(p.requests.length, 3);
    const [before, post, after] = p.requests;
    for (const r of p.requests) {
      assert.equal(r.method, 'POST'); assert.equal(r.headers.authorization, `Bearer ${TOKEN}`);
      assert.equal(r.headers['idempotency-key'], p.intent.key); assert.equal(r.headers.cookie, undefined);
      assert.equal(r.headers['accept-encoding'], 'identity');
    }
    assert.equal(before.url, '/repo.git/api/v1/outcomes'); assert.equal(after.url, before.url);
    assert.equal(before.body, ''); assert.equal(after.body, '');
    assert.equal(post.url, `/repo.git/api/v1/pulls/${p.intent.number}/${action === 'comment' ? 'comments' : action}`);
    assert.equal(post.body, p.intent.body);
    const f = new URLSearchParams(post.body);
    assert.equal(f.get('principal'), null); assert.equal(f.get('force'), null);
    assert.equal(f.get('object_format'), action === 'comment' ? null : algorithm);
    const retried = await submitPull(p.intent, TOKEN, consent(p.intent, { known: result.outcome }));
    assert.equal(retried.dispatched, false); assert.equal(p.requests.length, 4);
  });
}
test('all metadata operations require complete coordinates, including close and reopen', () => {
  for (const action of ['open', 'update', 'close', 'reopen']) {
    const value = input('https://forge.test/repo.git', action);
    for (const field of Object.keys(value.fields)) {
      const bad = structuredClone(value); delete bad.fields[field];
      assert.throws(() => preparePull(bad, TOKEN));
    }
  }
});
test('comment stream zero is valid independently of PR version; upper bound increments exactly', () => {
  const value = input('https://forge.test/repo.git', 'comment');
  value.fields.expected_version = '18446744073709551614';
  const intent = preparePull(value, TOKEN), p = publication(intent);
  assert.equal(validatePullPublication(p, intent, 200).comment_version, '18446744073709551615');
  value.fields.expected_version = '18446744073709551615'; assert.throws(() => preparePull(value, TOKEN));
});
for (const mutate of [
  v => v.fields.expected_version = 1, v => v.fields.expected_version = '01',
  v => v.fields.expected_version = '18446744073709551615', v => v.number = '0',
  v => v.fields.source_ref = 'refs/tags/topic', v => v.fields.source_ref = 'refs/heads/../main',
  v => v.fields.target_ref = v.fields.source_ref, v => v.fields.source_tip = '0'.repeat(40),
  v => v.fields.source_tip = 'a'.repeat(64), v => v.fields.source_tip = 'sha1:' + v.fields.source_tip,
  v => v.fields.title = '', v => v.fields.body = '\uD800', v => v.fields.body = '\0',
  v => v.fields.body = 'x'.repeat(65537), v => v.fields.principal = '4'.repeat(32),
  v => v.action = 'merge', v => v.action = '../outcomes', v => v.scope.object_format = 'sha512',
  v => v.endpoint = 'http://forge.test/repo.git', v => v.endpoint = 'https://forge.test/repo.git?key=secret',
]) test(`refuse malformed command ${mutate.toString()}`, () => {
  const v = input('https://forge.test/repo.git'); mutate(v); assert.throws(() => preparePull(v, TOKEN));
});
test('preparation detaches edits and refusal guards frozen intent tampering', () => {
  const source = input('https://forge.test/repo.git'), intent = preparePull(source, TOKEN);
  source.fields.title = 'changed'; source.scope.repository_id = 'f'.repeat(32);
  assert.notEqual(intent.fields.title, source.fields.title); assert.notEqual(intent.scope.repository_id, source.scope.repository_id);
  assert.deepEqual(validatePullIntent(JSON.parse(pullCanonical(intent))), intent);
  assert.equal(pullCanonical(intent).includes(TOKEN), false);
  for (const key of ['key', 'nonce', 'credential_fingerprint', 'body', 'endpoint', 'schema']) {
    const bad = structuredClone(intent); bad[key] += 'x'; assert.throws(() => validatePullIntent(bad));
  }
  const bad = structuredClone(intent); bad.fields.title = 'other'; assert.throws(() => validatePullIntent(bad));
});
for (const raw of ['{"number":1,"number":2}', '{"number":1,"num\\u0062er":2}',
  '{"number":1e1}', '{"number":-0}', '{"number":1.5}', '['.repeat(17) + ']'.repeat(17),
  '{"body":"broken}', '{"schema_version":9007199254740993}']) test(`reject unsafe JSON ${raw.slice(0, 70)}`, () => {
  assert.throws(() => parsePullJson(Buffer.from(raw), { wire: true }));
});
test('parser preserves raw native counter lexemes and strings containing JSON-looking text', () => {
  const value = parsePullJson(Buffer.from('{"number":18446744073709551615,"body":"{\\\"number\\\":7}"}'), { wire: true });
  assert.equal(value.number, '18446744073709551615'); assert.equal(value.body, '{"number":7}');
  assert.throws(() => parsePullJson(Buffer.from([0xff])));
});
for (const field of ['tenant_id', 'repository_id', 'repository_incarnation', 'principal_id']) test(`foreign ${field} refuses before publication`, async t => {
  const p = await peer(t, { handle(r, res, s) { const o = outcome(s.intent); o[field] = 'f'.repeat(32); respond(res, o); return true; } });
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent)), e => e.dispatched === false);
  assert.equal(p.requests.length, 1);
});
for (const status of [401, 403, 404, 429, 503]) test(`publication HTTP ${status} is not a canonical refusal`, async t => {
  const p = await peer(t, { handle(r, res) { if (!r.url.endsWith('/outcomes')) { res.writeHead(status); res.end(); return true; } } });
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent)), e => e.outcomeUnknown && e.phase === 'publication' && e.status === status);
  assert.equal(p.requests.length, 2); assert.equal(p.published, false);
});
test('explicit merge consent and exact original token/key are mandatory before I/O', async t => {
  const p = await peer(t, { action: 'fast-forward' });
  await assert.rejects(submitPull(p.intent, TOKEN, { confirmKey: p.intent.key }));
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent, { confirmKey: 'wrong' })));
  await assert.rejects(submitPull(p.intent, ROTATED, consent(p.intent)));
  assert.equal(p.requests.length, 0);
  const value = await submitPull(p.intent, TOKEN, consent(p.intent)); assert.equal(value.outcome.state, 'committed');
});
test('a dropped publication reply recovers under rotated credential without another write', async t => {
  const p = await peer(t, { handle(r, res, s) { if (!r.url.endsWith('/outcomes')) { s.published = true; res.destroy(); return true; } } });
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent)), e => e.dispatched && e.outcomeUnknown);
  const recovered = await recoverPull(p.intent, ROTATED); assert.equal(recovered.outcome.state, 'committed');
  assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
  assert.equal(p.requests.at(-1).headers.authorization, `Bearer ${ROTATED}`);
});
test('unobserved retry preserves the original bytes; no automatic retry occurs', async t => {
  let attempts = 0;
  const p = await peer(t, { handle(r, res) { if (!r.url.endsWith('/outcomes') && attempts++ === 0) { res.destroy(); return true; } } });
  const original = structuredClone(p.intent);
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent)));
  assert.equal(attempts, 1); assert.equal(p.requests.length, 2);
  assert.equal((await submitPull(p.intent, TOKEN, consent(p.intent))).outcome.state, 'committed');
  assert.equal(attempts, 2);
  for (const r of p.requests.filter(r => !r.url.endsWith('/outcomes'))) { assert.equal(r.body, original.body); assert.equal(r.headers['idempotency-key'], original.key); }
});
for (const edit of [
  p => p.number = '1', p => p.expected_version = '1', p => p.repository_incarnation = 'f'.repeat(32),
  p => p.principal_id = 'f'.repeat(32), p => p.object_format = 'sha256', p => p.action = 'close',
  p => p.delivery_acknowledged = true, p => p.refusal_code = 'other', p => p.extra = true,
]) test(`mismatched publication stays unknown: ${edit.toString()}`, async t => {
  const p = await peer(t, { handle(r, res, s) { if (!r.url.endsWith('/outcomes')) { const v = publication(s.intent); edit(v); respond(res, v); return true; } } });
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent)), e => e.outcomeUnknown && e.publication === null);
});
for (const side of ['source', 'target']) test(`fast-forward receipt binds ${side} native text, bytes and tip`, () => {
  const intent = preparePull(input('https://forge.test/repo.git', 'fast-forward'), TOKEN);
  for (const key of [`${side}_ref`, `${side}_ref_hex`, `${side}_tip`]) {
    const value = publication(intent); value[key] += 'f'; assert.throws(() => validatePullPublication(value, intent, 200));
  }
});
test('a confirmed publication and conflicting outcome never silently discard the receipt', async t => {
  const p = await peer(t, { handle(r, res, s) {
    if (r.url.endsWith('/outcomes') && s.published) { const o = outcome(s.intent, 'committed'); o.decision.repository_commit_id = 'other-rcr'; respond(res, o); return true; }
  } });
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent)), e => e.phase === 'confirmation' && e.publication?.tx_id === 'native-transaction');
  assert.equal(p.requests.length, 3);
});
test('retained terminal publication suppresses resend even while outcome is unavailable', async t => {
  const p = await peer(t), pub = publication(p.intent);
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent, { publication: pub })), e => e.publication?.tx_id === pub.tx_id && !e.dispatched);
  assert.equal(p.requests.length, 1);
});
for (const kind of ['redirect', 'encoding', 'duplicate', 'too_large', 'truncated', 'invalid_utf8', 'duplicate_header']) test(`hostile publication ${kind}`, async t => {
  const p = await peer(t, { handle(r, res, s) {
    if (r.url.endsWith('/outcomes')) return false;
    const body = wire(publication(s.intent));
    if (kind === 'redirect') { res.writeHead(307, { Location: '/other' }); res.end(); }
    if (kind === 'encoding') { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }); res.end(body); }
    if (kind === 'duplicate') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(body.replace('"schema_version":1', '"schema_version":1,"schema_version":1')); }
    if (kind === 'too_large') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(' '.repeat(PULL_LIMITS.reply + 1)); }
    if (kind === 'truncated') { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) + 1 }); res.end(body); }
    if (kind === 'invalid_utf8') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(Buffer.from([255])); }
    if (kind === 'duplicate_header') { res.writeHead(200, ['Content-Type', 'application/json', 'Content-Type', 'application/json']); res.end(body); }
    return true;
  } });
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent, { timeoutMs: 1000 })), e => e.outcomeUnknown);
  assert.equal(p.requests.length, 2);
});
test('one operation deadline owns a stalled publication and cleans up sockets', async t => {
  const p = await peer(t, { handle(r) { return !r.url.endsWith('/outcomes'); } });
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent, { timeoutMs: 50 })), e => e.dispatched && e.outcomeUnknown);
  assert.equal(p.requests.length, 2);
});
test('abort before any request, and abort during publication, never assert rollback', async t => {
  const controller = new AbortController(), p = await peer(t, { handle(r) { if (!r.url.endsWith('/outcomes')) { controller.abort(); return true; } } });
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent, { signal: controller.signal })), e => e.dispatched && e.outcomeUnknown);
  const size = p.requests.length;
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent, { signal: controller.signal })), e => !e.dispatched);
  assert.equal(p.requests.length, size);
});
test('caller mutation during preflight cannot alter the saved command or scope', async t => {
  let submitted;
  const p = await peer(t, { handle(r, res, s) { if (r.url.endsWith('/outcomes') && !s.published) {
    submitted.fields.title = 'mutated'; submitted.scope.repository_incarnation = 'f'.repeat(32);
  } } });
  submitted = structuredClone(p.intent);
  const result = await submitPull(submitted, TOKEN, consent(p.intent)); assert.equal(result.outcome.state, 'committed');
  assert.equal(p.requests[1].body, p.intent.body);
});
test('full-size escaped bodies fit bounded forms and retained intents', () => {
  const v = input('https://forge.test/repo.git'); v.fields.body = '\u0001'.repeat(65536);
  assert.ok(preparePull(v, TOKEN).body.length < PULL_LIMITS.form);
  v.fields.body = 'é'.repeat(32768); assert.ok(preparePull(v, TOKEN).body.length < PULL_LIMITS.form);
  v.fields.body += 'é'; assert.throws(() => preparePull(v, TOKEN));
  assert.throws(() => pullCommand('1', 'fast-forward', { ...input(v.endpoint, 'fast-forward').fields, force: true }, 'sha1'));
});
test('private CA succeeds; untrusted and wrong-name certificates refuse without publication', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'fg-pull-tls-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const generate = (name, alt) => { execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, `${name}.key`),
    '-out', join(dir, `${name}.crt`), '-days', '1', '-subj', `/CN=${name}`, '-addext', `subjectAltName=${alt}`], { stdio: 'ignore', timeout: 15000 }); };
  generate('local', 'IP:127.0.0.1'); generate('wrong', 'DNS:wrong.test');
  for (const name of ['local', 'wrong']) {
    const cert = await readFile(join(dir, `${name}.crt`)), key = await readFile(join(dir, `${name}.key`));
    const p = await peer(t, { tls: { key, cert } });
    await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent)), e => !e.dispatched);
    assert.equal(p.requests.length, 0);
    if (name === 'local') assert.equal((await submitPull(p.intent, TOKEN, consent(p.intent, { ca: cert }))).outcome.state, 'committed');
    else { await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent, { ca: cert }))); assert.equal(p.requests.length, 0); }
  }
});
