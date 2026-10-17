import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, unlink, readdir, mkdir, link, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { prepareRemoteBundle, runRemoteBundle, inspectRemoteBundle } from '../../scripts/operator/remote_bundle.mjs';
import { prepareBundleRequest, checkedRequest, selection, hash, encode, parse, publication, mergeObservation,
  BUNDLE_REMOTE_LIMITS as L } from '../../scripts/operator/remote_bundle_protocol.mjs';
import { fixture, TOKEN, SCOPE, payload, outcome, publication as pub, SEQ, hex } from './remote-bundle-fixture.mjs';

async function prepared(t, config) {
  const f = await fixture(t, config), r = await prepareRemoteBundle(f.options);
  return { ...f, r, execute: { workdir: r.workdir, confirm: r.intent_sha256, tokenFile: f.token } };
}
const uploads = f => f.requests.filter(r => r.path.includes('/source/bundle/'));
const status = f => inspectRemoteBundle({ workdir: f.r.workdir, confirm: f.r.intent_sha256 });

for (const format of ['sha1', 'sha256']) for (const operation of ['import', 'fetch'])
  test(`real HTTP ${operation} retains exact bytes and native u64 outcome in ${format}`, async t => {
    const f = await prepared(t, { format, operation }); assert.equal(f.requests.length, 0); assert.equal(f.r.native_bundle_validated, false);
    const r = await runRemoteBundle(f.execute); assert.equal(r.complete, true); assert.equal(r.observation.outcome.decision.decision_sequence, SEQ);
    assert.equal(f.requests.length, 3); assert.equal(uploads(f).length, 1); assert(uploads(f)[0].payload.equals(payload));
    assert(f.requests.every(c => c.key === f.r.key));
    if (operation === 'fetch') assert.deepEqual(uploads(f)[0].form.getAll('mapping'), f.selection.mappings.map(m => `${m.source_hex}:${m.destination_hex}:${m.expected_old}`));
    await unlink(f.token); await unlink(f.bundle); await unlink(join(f.r.workdir, 'repository.bundle')); await f.close();
    assert.equal((await status(f)).complete, true);
    const cached = await runRemoteBundle({ workdir: f.r.workdir, confirm: f.r.intent_sha256 });
    assert.equal(cached.complete, true); assert.equal(cached.network_accessed, false);
  });

test('source removal after preparation does not change the upload', async t => {
  const f = await prepared(t); await unlink(f.bundle); const r = await runRemoteBundle(f.execute); assert.equal(r.complete, true);
  assert(uploads(f)[0].payload.equals(payload));
});
test('lost committed response recovers using the original key without the payload', async t => {
  let lost = false;
  const f = await prepared(t, { intercept: ({ call, req }) => { if (call.path.includes('/source/bundle/') && !lost) { lost = true; req.socket.destroy(); return false; } } });
  const first = await runRemoteBundle(f.execute); assert.equal(first.complete, false); assert.equal(first.state, 'unresolved');
  await unlink(join(f.r.workdir, 'repository.bundle')); const next = await runRemoteBundle(f.execute);
  assert.equal(next.complete, true); assert.equal(uploads(f).length, 1); assert.equal(next.mutation_submitted, false);
});
test('unknown send remains fenced until exact-key retry, never a new nonce', async t => {
  let drop = true;
  const config = { noCommit: true, intercept: ({ call, req, states }) => {
    if (call.path.includes('/source/bundle/')) { if (drop) { req.socket.destroy(); return false; } states.set(call.key, 'committed'); }
  } };
  const f = await prepared(t, config); await runRemoteBundle(f.execute);
  assert.equal((await runRemoteBundle(f.execute)).complete, false); assert.equal(uploads(f).length, 1);
  await assert.rejects(runRemoteBundle({ ...f.execute, retryKey: 'new' }), /retry_key/);
  drop = false; const r = await runRemoteBundle({ ...f.execute, retryKey: f.r.key }); assert.equal(r.complete, true);
  assert.equal(uploads(f).length, 2); assert(uploads(f)[0].body.equals(uploads(f)[1].body));
});
test('retained publication forbids resend after confirmation lookup failure', async t => {
  let block = true;
  const f = await prepared(t, { intercept: ({ call, res, requests }) => {
    if (call.path.endsWith('outcomes') && requests.length === 3 && block) { res.writeHead(503); res.end(); return false; }
  } });
  const r = await runRemoteBundle(f.execute); assert.equal(r.complete, false); assert.equal(r.observation.publication.outcome, 'committed');
  block = false; const recovered = await runRemoteBundle({ ...f.execute, retryKey: f.r.key });
  assert.equal(recovered.complete, true); assert.equal(uploads(f).length, 1);
});
test('native refusal is retained and cannot be bypassed by retry', async t => {
  const f = await prepared(t, { refuse: true }); const r = await runRemoteBundle(f.execute);
  assert.equal(r.state, 'refused'); assert.equal(r.complete, false);
  const n = f.requests.length; assert.equal((await runRemoteBundle({ ...f.execute, retryKey: f.r.key })).state, 'refused'); assert.equal(f.requests.length, n);
});
test('recover never submits an unattempted request', async t => {
  const f = await prepared(t); const r = await runRemoteBundle({ ...f.execute, operation: 'recover' });
  assert.equal(r.state, 'ready'); assert.equal(f.requests.length, 0);
});
test('rotated credential can recover the original principal but never send', async t => {
  const f = await prepared(t, { intercept: ({ call, req }) => { if (call.path.includes('/source/bundle/')) { req.socket.destroy(); return false; } } });
  await writeFile(f.token, 'bb'.repeat(32)); await assert.rejects(runRemoteBundle(f.execute), /original_credential/); assert.equal(f.requests.length, 0);
  await writeFile(f.token, TOKEN); await runRemoteBundle(f.execute); await writeFile(f.token, 'bb'.repeat(32));
  const r = await runRemoteBundle({ ...f.execute, operation: 'recover' }); assert.equal(r.complete, true); assert.equal(uploads(f).length, 1);
});
test('wrong recovery principal cannot settle a request', async t => {
  const config = { intercept: ({ call, req }) => { if (call.path.includes('/source/bundle/')) { req.socket.destroy(); return false; } } };
  const f = await prepared(t, config); await runRemoteBundle(f.execute); config.recoveryScope = { ...f.scope, principal_id: '99'.repeat(16) };
  const r = await runRemoteBundle(f.execute); assert.equal(r.complete, false); assert.equal(uploads(f).length, 1);
});
for (const [label, alter] of [
  ['wrong native scope', r => { r.repository_incarnation = '77'.repeat(16); }],
  ['false atomicity', r => { r.atomic = false; }],
  ['forge authority', r => { r.forge_state_imported = true; }],
  ['wrong operation', r => { r.operation = 'fetch'; }],
  ['conflicting refusal fields', r => { r.decision.code = 'hidden'; }],
  ['unsupported response fields', r => { r.unexpected = true; }],
]) test(`publication rejects ${label} rather than trusting HTTP 200`, async t => {
  const f = await prepared(t, { intercept: ({ call, reply }) => { if (call.path.includes('/source/bundle/')) alter(reply); } });
  const r = await runRemoteBundle(f.execute); assert.equal(r.complete, false); assert(r.error);
  assert.equal((await runRemoteBundle(f.execute)).complete, true); assert.equal(uploads(f).length, 1);
});
for (const [label, alter] of [
  ['pin', async f => { const p = join(f.r.workdir, 'intent.json'); const v = JSON.parse(await readFile(p)); v.nonce = '00'.repeat(16); await writeFile(p, encode(v)); }],
  ['payload', async f => writeFile(join(f.r.workdir, 'repository.bundle'), Buffer.alloc(payload.length, 8))],
  ['hardlink', async f => link(join(f.r.workdir, 'intent.json'), join(f.root, 'linked'))],
  ['unknown file', async f => writeFile(join(f.r.workdir, 'extra'), 'x', { mode: 0o600 })],
  ['empty attempt', async f => mkdir(join(f.r.workdir, 'attempts', 'attempt-000001'), { mode: 0o700 })],
  ['journal gap', async f => mkdir(join(f.r.workdir, 'attempts', 'attempt-000002'), { mode: 0o700 })],
]) test(`corrupt ${label} refuses before network`, async t => {
  const f = await prepared(t); await alter(f); await assert.rejects(runRemoteBundle(f.execute)); assert.equal(f.requests.length, 0);
});
test('missing result is unknown and requires lookup even with no previous HTTP', async t => {
  const f = await prepared(t);
  const a = join(f.r.workdir, 'attempts', 'attempt-000001'); await mkdir(a, { mode: 0o700 });
  await writeFile(join(a, 'started.json'), encode({ schema: 'frankengit-bundle-attempt-v1', intent_sha256: f.r.intent_sha256,
    key: f.r.key, sequence: 1, previous_sha256: f.r.intent_sha256, mode: 'send' }), { mode: 0o600 });
  const r = await runRemoteBundle(f.execute); assert.equal(r.state, 'unresolved'); assert.equal(r.unsettled_attempts, 1);
  assert.equal(f.requests.length, 1); assert.equal(uploads(f).length, 0);
});
test('torn result and altered reservation are not ignored', async t => {
  const f = await prepared(t); await runRemoteBundle(f.execute);
  await writeFile(join(f.r.workdir, 'attempts', 'attempt-000001', 'result.json'), '{');
  await assert.rejects(status(f)); const n = f.requests.length; await assert.rejects(runRemoteBundle(f.execute)); assert.equal(f.requests.length, n);
});
test('preparation never overwrites existing custody', async t => {
  const f = await prepared(t); const original = await readFile(join(f.r.workdir, 'intent.json'));
  await assert.rejects(prepareRemoteBundle(f.options), /exists/); assert((await readFile(join(f.r.workdir, 'intent.json'))).equals(original));
});
test('cancelled upload drains a result and retains original retry responsibility', async t => {
  const stop = new AbortController();
  const f = await prepared(t, { intercept: ({ call, res }) => {
    if (call.path.includes('/source/bundle/')) { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); setTimeout(() => stop.abort(), 20); return false; }
  } });
  const r = await runRemoteBundle({ ...f.execute, signal: stop.signal, timeoutMs: 2000 }); assert.equal(r.complete, false);
  assert.equal((await status(f)).attempts, 1); assert.equal((await runRemoteBundle(f.execute)).complete, true); assert.equal(uploads(f).length, 1);
});
test('one invocation deadline applies to the entire network sequence', async t => {
  const f = await prepared(t, { intercept: async ({ call, res }) => {
    if (call.path.endsWith('outcomes')) await new Promise(r => setTimeout(r, 70));
    else { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); return false; }
  } });
  const r = await runRemoteBundle({ ...f.execute, timeoutMs: 120 }); assert.equal(r.complete, false); assert(r.error);
});
test('concurrent first sends cannot both reserve the initial upload', async t => {
  const f = await prepared(t); const r = await Promise.allSettled([runRemoteBundle(f.execute), runRemoteBundle(f.execute)]);
  assert(r.some(x => x.status === 'fulfilled')); assert.equal(uploads(f).length, 1); assert.equal((await status(f)).complete, true);
});
test('wire duplicates and rounded/scientific counters refuse', () => {
  for (const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a":1e2}', '{"a":9007199254740993}', '{"a":-0}', '['.repeat(17) + ']'.repeat(17)])
    assert.throws(() => parse(Buffer.from(text), 16384, true));
  assert.equal(parse(Buffer.from(`{"decision_sequence":${SEQ}}`), 16384, true).decision_sequence, SEQ);
});
test('late nonterminal cannot erase a committed observation; conflicts refuse', () => {
  const request = prepareBundleRequest({ endpoint: 'https://forge.example/repo', scope: SCOPE, operation: 'import' }, payload, TOKEN);
  const stable = { outcome: outcome(SCOPE, 'committed'), publication: pub(SCOPE, 'import') };
  assert.equal(mergeObservation(stable, { outcome: outcome(SCOPE), publication: null }, request).outcome.state, 'committed');
  const changed = outcome(SCOPE, 'committed'); changed.decision.repository_commit_id = 'wrong';
  assert.throws(() => mergeObservation(stable, { outcome: changed, publication: null }, request));
});
for (const [label, mappings] of [
  ['no lease', [{ source_hex: hex('refs/heads/a'), destination_hex: hex('refs/heads/b') }]],
  ['zero lease', [{ source_hex: hex('refs/heads/a'), destination_hex: hex('refs/heads/b'), expected_old: '0'.repeat(40) }]],
  ['bad namespace', [{ source_hex: hex('refs/heads/a'), destination_hex: hex('refs/other/b'), expected_old: 'absent' }]],
  ['duplicate', Array(2).fill({ source_hex: hex('refs/heads/a'), destination_hex: hex('refs/heads/b'), expected_old: 'absent' })],
  ['wildcard', [{ source_hex: hex('refs/heads/*'), destination_hex: hex('refs/heads/b'), expected_old: 'absent' }]],
]) test(`mapped fetch requires exact mappings: ${label}`, () => {
  assert.throws(() => selection({ endpoint: 'https://forge.example/repo', scope: SCOPE, operation: 'fetch', mappings }));
});
test('64 mappings and lossless non-UTF8 refs are supported without a Git parser', () => {
  const mappings = Array.from({ length: 64 }, (_, i) => ({ source_hex: hex('refs/heads/') + 'ff',
    destination_hex: hex(`refs/remotes/import/${i}`), expected_old: 'absent' }));
  const r = prepareBundleRequest({ endpoint: 'https://forge.example/repo', scope: SCOPE, operation: 'fetch', mappings }, payload, TOKEN);
  assert.equal(checkedRequest(r).selection.mappings.length, 64);
  assert.throws(() => selection({ ...r.selection, mappings: [...mappings, mappings[0]] }));
});
test('credential bytes cannot be ASCII-folded and symlink paths refuse', async t => {
  const f = await fixture(t); await writeFile(f.token, Buffer.alloc(64, 0xe1)); await assert.rejects(prepareRemoteBundle(f.options));
  await writeFile(f.token, TOKEN); const alias = join(f.root, 'alias'); await symlink(f.bundle, alias);
  await assert.rejects(prepareRemoteBundle({ ...f.options, bundleFile: alias })); assert.equal(f.requests.length, 0);
});
test('byte ceiling has exact permitted and one-byte-over twins', () => {
  const bytes = Buffer.alloc(L.bundle, 9), s = { endpoint: 'https://forge.example/repo', scope: SCOPE, operation: 'import' };
  assert.equal(prepareBundleRequest(s, bytes, TOKEN).bundle.bytes, L.bundle);
  assert.throws(() => prepareBundleRequest(s, Buffer.alloc(L.bundle + 1), TOKEN), /limit/);
});
