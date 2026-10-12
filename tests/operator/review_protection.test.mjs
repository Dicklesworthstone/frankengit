import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, chmod, symlink, link, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { endpoint, policy, snapshotReply, prepareIntent, validateIntent, inspectProtection, jsonRequest,
  parseJson, canonical, LIMITS } from '../../scripts/operator/review_protection.mjs';
import { saveIntent, loadIntent, readToken, readPrivate } from '../../scripts/operator/protection_files.mjs';
import { run, parseArgs, intentSummary } from '../../scripts/fg_protection_admin.mjs';
import { TOKEN, ACTOR, REVIEWER, SCOPE, HEAD, POLICY, NEXT, ref, state, json, peer, files } from './protection_fixtures.mjs';
const plan = extra => prepareIntent({ endpoint: 'https://forge.example/team/repo.git', token: TOKEN, principal_id: ACTOR,
  expectedScope: SCOPE, snapshot: state(), replacement: NEXT, nonce: 'e'.repeat(32), ...extra });

test('both native hash domains retain exact strings above the safe-number ceiling', () => {
  for (const object_format of ['sha1', 'sha256']) {
    const expectedScope = { ...SCOPE, object_format };
    const intent = plan({ expectedScope, snapshot: state({ object_format, version: '9007199254740993', policy_epoch: '18446744073709551614' }) });
    assert.equal(intent.source.version, '9007199254740993'); assert.equal(intent.source.policy_epoch, '18446744073709551614');
    const body = new URLSearchParams(intent.request.body);
    assert.equal(body.get('expected_version'), intent.source.version); assert.equal(body.get('expected_epoch'), intent.source.policy_epoch);
    assert.equal(body.has('principal'), false); assert.equal(body.has('object_format'), false);
    assert.deepEqual(body.getAll('administrator'), NEXT.administrators);
    assert.deepEqual(validateIntent(JSON.parse(canonical(intent))), intent);
  }
});
test('outcome JSON u64 decoding is lossless and refuses noncanonical numeric spellings', () => {
  assert.equal(parseJson(Buffer.from('{"decision_sequence":18446744073709551615}')).decision_sequence, '18446744073709551615');
  for (const value of ['0', '1e3', '-1', '1.0', '18446744073709551616']) assert.throws(() => parseJson(Buffer.from(`{"decision_sequence":${value}}`)));
  assert.throws(() => parseJson(Buffer.from('{"schema_version":9007199254740993}')));
  assert.throws(() => parseJson(Buffer.from([0xff])));
});
test('remote bootstrap and exhausted version or epoch are refused, never synthesized', () => {
  const absent = state({ version: '0', installed: false, enabled: false, policy: null });
  assert.equal(snapshotReply(absent).policy, null);
  assert.throws(() => plan({ snapshot: absent }), /bootstrap/);
  for (const key of ['version', 'policy_epoch']) {
    for (const value of ['18446744073709551615', 2, '02', '-1', '', '1e3']) assert.throws(() => plan({ snapshot: state({ [key]: value }) }));
  }
});
test('complete policy replacement preserves arbitrary native branch bytes', () => {
  const name = `${ref('refs/heads/release/')}ff`;
  const replacement = { administrators: [REVIEWER, ACTOR], branches: [{ reference_hex: name, required_reviewers: [REVIEWER] }, ...POLICY.branches] };
  const intent = plan({ replacement });
  assert.equal(new URLSearchParams(intent.request.body).getAll('required_reviewer').includes(`${name}:${REVIEWER}`), true);
  assert.deepEqual(intent.replacement.administrators, [ACTOR, REVIEWER]);
  assert.deepEqual(plan({ replacement: { administrators: [ACTOR, REVIEWER], branches: [...replacement.branches].reverse() } }), intent);
});
test('clearing requires explicit intent and retains nonempty policy ownership', () => {
  const replacement = { administrators: [ACTOR], branches: [] };
  assert.throws(() => plan({ replacement }), /explicit_clear/);
  assert.throws(() => plan({ clear: true }), /explicit_clear/);
  assert.throws(() => plan({ replacement: { administrators: [], branches: [] }, clear: true }));
  const intent = plan({ replacement, clear: true });
  assert.equal(new URLSearchParams(intent.request.body).get('clear'), 'true');
  assert.equal(intentSummary(intent).branches[0].removed[0], REVIEWER);
});
test('principal, branch, reference and encoded-command limits all fail closed', () => {
  for (const replacement of [{ ...NEXT, administrators: [] }, { ...NEXT, administrators: [ACTOR, ACTOR] },
    { ...NEXT, administrators: Array.from({ length: 33 }, (_, i) => i.toString(16).padStart(32, '0')) },
    { ...NEXT, branches: [...NEXT.branches, ...NEXT.branches] },
    { ...NEXT, branches: [{ ...NEXT.branches[0], required_reviewers: [] }] },
    { ...NEXT, branches: [{ ...NEXT.branches[0], required_reviewers: [REVIEWER, REVIEWER] }] },
    { ...NEXT, role: 'admin' }]) assert.throws(() => plan({ replacement }));
  for (const name of ['refs/tags/main', 'refs/heads/', 'refs/heads/.hidden', 'refs/heads/a..b', 'refs/heads/a.lock', 'refs/heads/a b', 'refs/heads/a\n', 'refs/heads/a//b']) {
    assert.throws(() => policy({ ...NEXT, branches: [{ reference_hex: ref(name), required_reviewers: [REVIEWER] }] }));
  }
  const reviewers = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(32, '0'));
  const branches = Array.from({ length: 64 }, (_, i) => ({ reference_hex: ref(`refs/heads/${i}-${'x'.repeat(900)}`), required_reviewers: reviewers }));
  assert.equal(policy({ administrators: [ACTOR], branches }).branches.length, 64);
  assert.throws(() => plan({ replacement: { administrators: [ACTOR], branches } }), /command_byte_limit/);
});
test('incomplete, inconsistent, wrong-scope and unpinned snapshots are rejected', () => {
  for (const extra of [{ complete: false }, { published: true }, { transaction_created: true }, { schema_version: 2 },
    { installed: false }, { enabled: false }, { policy: null }, { policy_epoch: '0' }, { version: '0' },
    { source_head: 'untyped' }, { repository_incarnation: '4'.repeat(32) }, { actor: ACTOR }]) assert.throws(() => snapshotReply(state(extra), SCOPE));
  assert.throws(() => snapshotReply(state(), SCOPE, `alg:2:${'f'.repeat(64)}`), /source_head_changed/);
});
test('intent digest binds origin, scope, prior policy, replacement, actor, credential and nonce', () => {
  const original = plan();
  for (const edit of [value => { value.endpoint = 'https://other.example/repo.git'; }, value => { value.scope.repository_id = '4'.repeat(32); },
    value => { value.principal_id = REVIEWER; }, value => { value.credential_sha256 = 'f'.repeat(64); },
    value => { value.source.policy_epoch = '3'; }, value => { value.source.policy.administrators = [REVIEWER]; },
    value => { value.replacement.administrators = [REVIEWER]; }, value => { value.request.body += '&clear=true'; },
    value => { value.request.key += 'x'; }, value => { value.clear = true; }, value => { value.nonce = 'f'.repeat(32); },
    value => { value.schema = 'other'; }]) { const changed = structuredClone(original); edit(changed); assert.throws(() => validateIntent(changed)); }
  assert.equal(canonical(original).includes(TOKEN), false);
  assert.equal(original.request.key, plan().request.key);
  const input = structuredClone(NEXT), captured = plan({ replacement: input }); input.administrators.length = 0;
  assert.deepEqual(captured.replacement, NEXT);
});
test('endpoint validation refuses ambient credentials, DNS cleartext and normalized aliases', () => {
  assert.equal(endpoint('https://forge.example/team/repo.git'), 'https://forge.example/team/repo.git');
  assert.equal(endpoint('http://[::1]:8080/repo.git'), 'http://[::1]:8080/repo.git');
  for (const value of ['http://localhost/repo.git', 'http://example.org/repo.git', 'https://user:secret@forge.example/repo.git',
    'https://forge.example/repo.git?token=x', 'https://forge.example/repo.git#x', 'https://forge.example/repo.git/',
    'https://forge.example/a/../repo.git', 'https://forge.example/%2e/repo.git', 'file:///repo.git', 'https://forge.example/']) assert.throws(() => endpoint(value), value);
});
test('real loopback requests bind the scope/head, use only Bearer and drain sockets', async t => {
  const p = await peer(t);
  const observed = await inspectProtection(p.endpoint, TOKEN, { expectedScope: SCOPE, expectedHead: HEAD });
  assert.deepEqual(observed, state());
  assert.equal(p.calls.length, 1); const call = p.calls[0];
  assert.equal(call.headers.authorization, `Bearer ${TOKEN}`); assert.equal(call.headers.cookie, undefined);
  assert.equal(call.headers['idempotency-key'], undefined); assert.equal(call.body, ''); assert.equal(call.method, 'GET');
  assert.equal(new URL(call.url, p.endpoint).searchParams.get('expected_head'), HEAD);
  await new Promise(setImmediate); await new Promise(setImmediate); assert.equal(p.sockets.size, 0);
});
test('HTTP refusals, redirects and forged scope never become an empty policy', async t => {
  for (const status of [301, 302, 401, 403, 404, 409, 429, 503]) {
    const p = await peer(t, (_, response) => json(response, { secret: TOKEN }, status, { Location: '/other' }));
    await assert.rejects(inspectProtection(p.endpoint, TOKEN), error => error.status === status && !error.message.includes(TOKEN));
    assert.equal(p.calls.length, 1);
  }
  const wrong = await peer(t, (_, response) => json(response, state({ repository_id: '4'.repeat(32) })));
  await assert.rejects(inspectProtection(wrong.endpoint, TOKEN, { expectedScope: SCOPE }), /repository_scope/);
});
test('response caps, content encodings, invalid UTF8 and truncated frames are bounded failures', async t => {
  for (const handle of [(_, response) => json(response, state(), 200, { 'Content-Encoding': 'gzip' }),
    (_, response) => { response.writeHead(200, { 'Content-Type': 'text/html' }); response.end('<html>'); },
    (_, response) => { response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': LIMITS.response + 1 }); response.flushHeaders(); },
    (_, response) => { response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(Buffer.from([0xff])); },
    (_, response) => { response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 100 }); response.end('{}'); }]) {
    const p = await peer(t, handle); await assert.rejects(inspectProtection(p.endpoint, TOKEN, { timeoutMs: 100 }));
  }
  const p = await peer(t, (_, response) => { response.writeHead(200, { 'Content-Type': 'application/json' }); response.end('x'.repeat(2048)); });
  await assert.rejects(jsonRequest(p.endpoint, TOKEN, { maximum: 1024 }), /response_byte_limit/);
});
test('one deadline includes a delayed response body and cancellation closes owned work', async t => {
  const p = await peer(t, (_, response) => { response.writeHead(200, { 'Content-Type': 'application/json' }); response.write('{'); });
  await assert.rejects(inspectProtection(p.endpoint, TOKEN, { timeoutMs: 20 }), /request_timeout/);
  const controller = new AbortController(), pending = inspectProtection(p.endpoint, TOKEN, { signal: controller.signal });
  setTimeout(() => controller.abort(), 20); await assert.rejects(pending, /cancelled/);
  const count = p.calls.length; await assert.rejects(inspectProtection(p.endpoint, TOKEN, { signal: controller.signal }), /cancelled/);
  assert.equal(p.calls.length, count);
});
test('invalid envelopes never reach the HTTP peer', async t => {
  const p = await peer(t);
  for (const options of [{ path: 'other' }, { method: 'GET', key: 'leak' }, { path: 'outcomes', method: 'POST', body: 'x', key: 'original' },
    { path: 'protection', method: 'DELETE' }, { method: 'POST', body: 'x' }, { maximum: LIMITS.response + 1 },
    { timeoutMs: 0 }, { path: 'protection?token=secret' }]) await assert.rejects(jsonRequest(p.endpoint, TOKEN, options));
  assert.equal(p.calls.length, 0);
});
test('private intents are create-only, token-free, hash-checked and canonical', async t => {
  const f = await files(t), intent = plan(); await saveIntent(f.intent, intent);
  assert.deepEqual(await loadIntent(f.intent), intent);
  const bytes = await readFile(join(f.intent, 'intent.json')); assert.equal(bytes.includes(TOKEN), false);
  await assert.rejects(saveIntent(f.intent, intent), /EEXIST/);
  await writeFile(join(f.intent, 'intent.json'), `${bytes.toString()} `);
  await assert.rejects(loadIntent(f.intent), /noncanonical/);
});
test('token/control file symlinks, hardlinks, permissive modes and size changes refuse', async t => {
  const f = await files(t); assert.equal(await readToken(f.token), TOKEN);
  const alias = join(f.root, 'alias'); await symlink(f.token, alias); await assert.rejects(readToken(alias));
  await chmod(f.token, 0o644); await assert.rejects(readToken(f.token)); await chmod(f.token, 0o600);
  await link(f.token, join(f.root, 'hard')); await assert.rejects(readToken(f.token));
  const special = await f.write('high-bit-newline', Buffer.concat([Buffer.from(TOKEN), Buffer.from([138])]));
  await assert.rejects(readToken(special));
  await assert.rejects(readPrivate(f.policy, 1), /byte_limit/);
  const dir = join(f.root, 'dir'); await mkdir(dir, { mode: 0o700 }); const directoryAlias = join(f.root, 'dir-alias'); await symlink(dir, directoryAlias);
  await assert.rejects(saveIntent(join(directoryAlias, 'request'), plan()), /alias/);
});
test('CLI inspect and preparation run real HTTP reads but never dispatch mutations', async t => {
  const f = await files(t), p = await peer(t), output = [];
  const common = ['--endpoint', p.endpoint, '--token-file', f.token, '--scope-file', f.scope];
  assert.equal(await run(['inspect', ...common], { output: async text => output.push(JSON.parse(text)) }), 0);
  assert.equal(await run(['prepare', ...common, '--principal', ACTOR, '--policy-file', f.policy, '--intent', f.intent], { output: async text => output.push(JSON.parse(text)) }), 0);
  assert.equal(p.calls.length, 2); assert.ok(p.calls.every(call => call.method === 'GET' && !call.body));
  assert.equal(output[1].transaction_created, false); assert.equal(output[1].published, false);
  assert.deepEqual(output[1].administrators.added, ['c'.repeat(32)]);
  assert.equal(await run(['show-intent', '--intent', f.intent], { output: async text => output.push(JSON.parse(text)) }), 0);
  assert.deepEqual(output[2], output[1]); assert.equal(p.calls.length, 2);
});
test('CLI input refusals precede networking and output failure preserves the prepared intent', async t => {
  const f = await files(t), p = await peer(t);
  for (const args of [[], ['prepare'], ['inspect', '--token', TOKEN], ['show-intent', '--intent', f.intent, '--intent', f.intent],
    ['inspect', '--endpoint', p.endpoint, '--token-file', f.token, '--timeout-ms', '01']]) assert.throws(() => parseArgs(args));
  const bad = await f.write('bad-policy', { ...NEXT, administrators: [] });
  const args = ['prepare', '--endpoint', p.endpoint, '--token-file', f.token, '--scope-file', f.scope, '--principal', ACTOR, '--policy-file', bad, '--intent', f.intent];
  await assert.rejects(run(args, { output: async () => {} })); assert.equal(p.calls.length, 0);
  args[args.indexOf(bad)] = f.policy;
  await assert.rejects(run(args, { output: async () => { throw new Error('stdout closed'); } }), /stdout closed/);
  assert.equal((await loadIntent(f.intent)).principal_id, ACTOR); assert.equal(p.calls.length, 1);
});
