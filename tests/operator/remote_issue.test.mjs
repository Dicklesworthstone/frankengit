// Real HTTP/TLS sockets with explicit native-schema peers, not a Rust fg node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { prepareIssue, validateIssueIntent, issueCommand, issueCanonical, issueHash, parseIssueJson,
  submitIssue, recoverIssue, ISSUE_LIMITS } from '../../scripts/operator/remote_issue.mjs';

export const scope = Object.freeze({ tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16),
  repository_incarnation: '33'.repeat(16), principal_id: '44'.repeat(16) });
export const token = 'ab'.repeat(32), rotated = 'cd'.repeat(32);
const clone = value => structuredClone(value);
const tx = { tx_id: 'tx:fixture', seal_id: 'seal:fixture', request_schema: 'issue-fixture-v1',
  canonical_request_digest: { algorithm: 1, hex: 'ef'.repeat(32) } };
export function outcome(state = 'key_not_observed', extra = {}) {
  return { type: 'transaction_outcome', schema_version: 1, ...scope, selector: 'transaction', command_index: null,
    state, terminal: ['committed', 'refused'].includes(state), transaction: ['key_not_observed', 'seal_not_observed'].includes(state) ? null : clone(tx),
    decision: state === 'committed' ? { kind: state, decision_sequence: '9007199254740993', repository_commit_id: 'rcr:fixture' }
      : state === 'refused' ? { kind: state, decision_sequence: '9007199254740993', code: 'ExpectedVersionMismatch', code_point: 7, refusal_record_id: 'refusal:fixture' } : null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false, ...extra };
}
function publication(intent, state = 'committed') {
  return { type: 'issue_publication', schema_version: 1, tenant_id: scope.tenant_id, repository_id: scope.repository_id,
    principal_id: scope.principal_id, number: intent.number, expected_version: intent.expected_version, action: intent.action,
    tx_id: tx.tx_id, outcome: state, decision_sequence: '9007199254740993',
    repository_commit_id: state === 'committed' ? 'rcr:fixture' : null,
    refusal_record_id: state === 'refused' ? 'refusal:fixture' : null, refusal_code: state === 'refused' ? 'ExpectedVersionMismatch' : null,
    delivery_acknowledged: null };
}
export const wire = value => JSON.stringify(value, (key, value) =>
  ['number', 'expected_version', 'decision_sequence'].includes(key) && typeof value === 'string' ? JSON.rawJSON(value) : value);
export function input(endpoint = 'https://forge.example/repo.git', changes = {}) {
  return { endpoint, scope, number: '7', expected_version: '2', action: 'comment', fields: { body: 'exact message\r\n💡' }, ...changes };
}
async function peer(t, options = {}) {
  const calls = [], sockets = new Set(); let intent, reads = 0, saved = options.saved ?? null;
  const handler = (request, response) => {
    let body = ''; request.setEncoding('utf8'); request.on('data', part => { body += part; });
    request.on('end', () => {
      const call = { path: request.url, method: request.method, headers: request.headers, body }; calls.push(call);
      const recovery = request.url.endsWith('/outcomes'); if (recovery) reads++;
      const phase = recovery ? reads === 1 ? 'preflight' : 'confirmation' : 'publication';
      if (options.handle?.({ request, response, phase, call, calls })) return;
      let value;
      if (recovery) value = options[phase] ? clone(options[phase]) : saved ? outcome(saved) : outcome();
      else { saved = options.state ?? 'committed'; value = publication(intent, saved); if (options.mutate) value = options.mutate(value); }
      if (phase === 'publication' && options.drop) { response.destroy(); return; }
      const encoded = options.encode?.(value, phase) ?? wire(value);
      response.writeHead(phase === 'publication' && saved === 'refused' ? 409 : 200,
        { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(encoded), ...(options.headers?.(phase) ?? {}) });
      response.end(encoded);
    });
  };
  const server = options.tls ? httpsServer(options.tls, handler) : httpServer(handler);
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  const endpoint = `${options.tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}/repo.git`;
  intent = prepareIssue(input(endpoint, options.input), token);
  return { intent, calls, sockets, server, send: more => submitIssue(intent, token, { confirmKey: intent.key, ...more }),
    recover: (credential = token, more) => recoverIssue(intent, credential, more) };
}

for (const [action, version, data, pairs] of [
  ['open', '0', { title: 'title', body: '', labels: ['z', 'a'] }, [['expected_version', '0'], ['title', 'title'], ['body', ''], ['label', 'a'], ['label', 'z']]],
  ['edit', '1', { labels: [] }, [['expected_version', '1'], ['clear_labels', 'true']]],
  ['comment', '2', { body: '  literal\r\n💡  ' }, [['expected_version', '2'], ['body', '  literal\r\n💡  ']]],
  ['close', '3', {}, [['expected_version', '3']]], ['reopen', '4', {}, [['expected_version', '4']]],
  ['assign', '5', { assignees: [scope.principal_id] }, [['expected_version', '5'], ['assignee', scope.principal_id]]],
  ['unassign', '6', { assignees: [scope.principal_id] }, [['expected_version', '6'], ['assignee', scope.principal_id]]],
]) test(`native ${action} exact form and full round trip`, async t => {
  const command = issueCommand('7', version, action, data);
  assert.deepEqual([...new URLSearchParams(command.body)], pairs);
  const p = await peer(t, { input: { action, expected_version: version, fields: data } });
  const result = await p.send(); assert.equal(result.outcome.state, 'committed');
  assert.equal(result.outcome.decision.decision_sequence, '9007199254740993');
  assert.equal(p.calls.length, 3); assert.equal(p.calls[1].body, command.body);
  for (const call of p.calls) {
    assert.equal(call.method, 'POST'); assert.equal(call.headers.authorization, `Bearer ${token}`);
    assert.equal(call.headers['idempotency-key'], p.intent.key); assert.equal(call.headers.cookie, undefined);
    assert.equal(call.headers.connection, 'close'); assert(!call.path.includes(token));
  }
  assert.equal(p.calls[0].body, ''); assert.equal(p.calls[2].body, '');
});

const invalidCommands = [
  ['open', '1', { title: 'x', body: '' }], ['close', '0', {}], ['delete', '1', {}],
  ['edit', '1', {}], ['comment', '1', { body: '   ' }], ['close', '1', { body: 'x' }],
  ['open', '0', { title: 'x' }], ['edit', '1', { title: 'x\n' }], ['comment', '1', { body: '\ud800' }],
  ['comment', '1', { body: 'a\0b' }], ['open', '0', { title: 'é'.repeat(129), body: '' }],
  ['edit', '1', { labels: ['same', 'same'] }], ['edit', '1', { labels: new Array(1) }],
  ['assign', '1', { assignees: [] }], ['assign', '1', { assignees: ['A'.repeat(32)] }],
  ['assign', '1', { assignees: [scope.principal_id, scope.principal_id] }],
  ['comment', '18446744073709551615', { body: 'x' }], ['close', '01', {}], ['close', 1, {}],
  ['comment', '1', { body: 'x', principal: scope.principal_id }],
  ['comment', '1', { body: 'x'.repeat(ISSUE_LIMITS.body + 1) }],
];
for (const [index, command] of invalidCommands.entries()) test(`refuse invalid native issue command ${index}`, () => {
  assert.throws(() => issueCommand('7', command[1], command[0], command[2]));
});
test('full-width issue identities, canonical ordering and lossless text', async t => {
  const p = await peer(t, { input: { number: '18446744073709551615', expected_version: '18446744073709551614' } });
  const result = await p.send(); assert.equal(result.number, '18446744073709551615');
  assert.equal(result.publication.expected_version, '18446744073709551614');
  const command = issueCommand('1', '1', 'edit', { labels: ['😀', '\ue000'] });
  assert.deepEqual(command.fields.labels, ['\ue000', '😀']);
  assert(!issueCanonical({ body: '\u202e' }).includes('\u202e'));
});
test('saved intent is detached, token-free and reproducibly validates its exact key', () => {
  const original = input(), intent = prepareIssue(original, token);
  original.fields.body = 'later'; assert.notEqual(intent.fields.body, 'later');
  assert.equal(issueHash(token), intent.credential_fingerprint); assert(!issueCanonical(intent).includes(token));
  assert.deepEqual(validateIssueIntent(parseIssueJson(Buffer.from(issueCanonical(intent)))), intent);
  assert.notEqual(prepareIssue(input(), token).key, intent.key);
  for (const name of ['body', 'nonce', 'key', 'credential_fingerprint', 'schema', 'endpoint', 'action', 'number', 'expected_version']) {
    const changed = clone(intent); changed[name] += 'x'; assert.throws(() => validateIssueIntent(changed), name);
  }
  const changed = clone(intent); changed.fields.body += 'changed'; assert.throws(() => validateIssueIntent(changed));
});
for (const address of ['http://forge.example/repo.git', 'http://localhost/repo.git', 'https://host/repo.git/',
  'https://user:pass@host/repo.git', 'https://host/a/../repo.git', 'https://host/repo.git?token=x', 'https://host/repo.git#x']) {
  test(`reject noncanonical or unsafe endpoint ${address}`, () => assert.throws(() => prepareIssue(input(address), token)));
}
for (const text of ['{"body":1,"body":2}', '{"body":1,"bo\\u0064y":2}', '{"a":{"b":1,"b":2}}',
  '[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]', '{"n":1e2}', '{"n":-0}', '{"n":0.5}', '{"n":9007199254740993}', '{"x":', '\ufeff{}']) {
  test(`bounded JSON rejects ${text.slice(0, 55)}`, () => assert.throws(() => parseIssueJson(Buffer.from(text))));
}
test('JSON accepts duplicate names in independent objects and punctuation in data', () => {
  assert.deepEqual(parseIssueJson(Buffer.from('[{"a":"}\\\"["},{"a":1}]')), [{ a: '}"[' }, { a: 1 }]);
  assert.throws(() => parseIssueJson(Buffer.from([0xff])));
});
test('a recovered terminal suppresses all mutation traffic', async t => {
  const p = await peer(t, { saved: 'committed' }); const value = await p.send();
  assert.equal(value.dispatched_this_call, false); assert.equal(p.calls.length, 1);
});
test('native terminal refusal survives 409 and is confirmed, not a transport success', async t => {
  const p = await peer(t, { state: 'refused' }); const result = await p.send();
  assert.equal(result.outcome.state, 'refused'); assert.equal(result.publication.refusal_code, 'ExpectedVersionMismatch');
});
for (const changed of ['tenant_id', 'repository_id', 'repository_incarnation', 'principal_id']) {
  test(`preflight binds ${changed} before dispatch`, async t => {
    const p = await peer(t, { preflight: outcome('key_not_observed', { [changed]: '99'.repeat(16) }) });
    await assert.rejects(p.send(), error => error.phase === 'preflight' && !error.dispatched && error.outcomeUnknown);
    assert.equal(p.calls.length, 1);
  });
}
test('explicit key confirmation and original write credential precede any traffic', async t => {
  const p = await peer(t);
  await assert.rejects(p.send({ confirmKey: 'another' }));
  await assert.rejects(submitIssue(p.intent, rotated, { confirmKey: p.intent.key }));
  await assert.rejects(p.send({ headers: { authorization: token } }));
  assert.equal(p.calls.length, 0);
});
test('lost publication reply recovers the original key without reposting', async t => {
  const p = await peer(t, { drop: true });
  await assert.rejects(p.send(), error => error.phase === 'publication' && error.dispatched && error.outcomeUnknown);
  const result = await p.recover(rotated); assert.equal(result.outcome.state, 'committed');
  assert.equal(result.dispatched_this_call, false); assert.equal(p.calls[2].headers.authorization, `Bearer ${rotated}`);
  assert.equal(p.calls.filter(call => !call.path.endsWith('/outcomes')).length, 1);
  const retried = await p.send(); assert.equal(retried.dispatched_this_call, false);
});
for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) test(`recovery ${state} never becomes a terminal refusal`, async t => {
  const p = await peer(t, { preflight: outcome(state) }); const result = await p.recover();
  assert.equal(result.outcome.terminal, false); assert.equal(result.absence_proves_non_commit, false); assert.equal(p.calls[0].body, '');
});
test('known seal cannot regress during recovery or before send', async t => {
  const p = await peer(t); await assert.rejects(p.send({ known: outcome('undecided') }), /regressed/);
  assert.equal(p.calls.length, 1);
});
for (const [field, value] of [['action', 'close'], ['number', '8'], ['expected_version', '3'],
  ['principal_id', '99'.repeat(16)], ['delivery_acknowledged', true], ['repository_commit_id', null], ['refusal_code', 'Bad']]) {
  test(`publication cannot substitute ${field}`, async t => {
    const p = await peer(t, { mutate: reply => ({ ...reply, [field]: value }) });
    await assert.rejects(p.send(), error => error.phase === 'publication' && error.dispatched);
    assert.equal(p.calls.length, 2);
  });
}
for (const changed of [outcome('undecided'), outcome('committed', { principal_id: '99'.repeat(16) }),
  outcome('refused'), outcome('committed', { transaction: { ...tx, tx_id: 'tx:other' } }),
  outcome('committed', { decision: { kind: 'committed', decision_sequence: '9007199254740994', repository_commit_id: 'rcr:fixture' } })]) {
  test('confirmation must reproduce the same native decision and complete scope', async t => {
    const p = await peer(t, { confirmation: changed });
    await assert.rejects(p.send(), error => error.phase === 'confirmation' && error.dispatched && error.publication?.outcome === 'committed');
  });
}
for (const status of [301, 302, 401, 403, 404, 429, 503]) test(`publication HTTP ${status} retains uncertainty without retry`, async t => {
  const p = await peer(t, { handle: ({ response, phase }) => {
    if (phase !== 'publication') return false;
    response.writeHead(status, { Location: 'https://elsewhere.example/' }); response.end(token); return true;
  } });
  await assert.rejects(p.send(), error => error.status === status && error.dispatched && !JSON.stringify(error).includes(token));
  assert.equal(p.calls.length, 2);
});
for (const [name, settings] of [
  ['wrong media', { headers: phase => phase === 'publication' ? { 'Content-Type': 'text/plain' } : {} }],
  ['encoding', { headers: phase => phase === 'publication' ? { 'Content-Encoding': 'gzip' } : {} }],
  ['oversize', { encode: (value, phase) => phase === 'publication' ? 'x'.repeat(ISSUE_LIMITS.reply + 1) : wire(value) }],
  ['duplicate key', { encode: (value, phase) => phase === 'publication' ? wire(value).replace('"action":', '"action":"close","action":') : wire(value) }],
  ['generic conflict', { handle: ({ response, phase }) => {
    if (phase !== 'publication') return false; response.writeHead(409, { 'Content-Type': 'application/json' }); response.end('{"type":"issue_error"}'); return true;
  } }],
  ['truncated', { handle: ({ response, phase }) => {
    if (phase !== 'publication') return false; response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '1000' }); response.end('{}'); return true;
  } }],
]) test(`refuse ${name} publication`, async t => {
  const p = await peer(t, settings); await assert.rejects(p.send({ timeoutMs: 1000 }), error => error.phase === 'publication' && error.dispatched);
});
test('pre-aborted invocation has no network activity', async t => {
  const p = await peer(t), controller = new AbortController(); controller.abort();
  await assert.rejects(p.send({ signal: controller.signal })); assert.equal(p.calls.length, 0);
});
test('cancellation owns the publication socket and never erases the key', async t => {
  const controller = new AbortController();
  const p = await peer(t, { handle: ({ response, phase }) => {
    if (phase !== 'publication') return false;
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.write('{'); setTimeout(() => controller.abort(), 10); return true;
  } });
  await assert.rejects(p.send({ signal: controller.signal }), error => error.dispatched && error.code === 'issue_cancelled');
  assert.equal(validateIssueIntent(p.intent).key, p.intent.key);
});
test('one deadline covers preflight, publication and confirmation', async t => {
  const p = await peer(t, { handle: ({ response, phase }) => {
    if (phase === 'preflight') { setTimeout(() => response.end(wire(outcome())), 60); response.setHeader('Content-Type', 'application/json'); return true; }
    if (phase === 'publication') return true; return false;
  } });
  const started = performance.now();
  await assert.rejects(p.send({ timeoutMs: 100 }), error => error.code === 'issue_timeout');
  assert(performance.now() - started < 500);
});
test('certificate-verified HTTPS supports private CA; untrusted and wrong-name peers cannot publish', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'fg-issue-tls-')); t.after(() => rm(directory, { recursive: true, force: true }));
  async function credentials(name, alt) {
    const key = join(directory, `${name}.key`), cert = join(directory, `${name}.crt`);
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=issue-test',
      '-addext', `subjectAltName=${alt}`, '-keyout', key, '-out', cert], { stdio: 'ignore', timeout: 10000 });
    return { key: await readFile(key), cert: await readFile(cert) };
  }
  const tls = await credentials('matching', 'IP:127.0.0.1'), p = await peer(t, { tls });
  await assert.rejects(p.send(), error => !error.dispatched);
  assert.equal(p.calls.length, 0); assert.equal((await p.send({ ca: tls.cert })).outcome.state, 'committed');
  const other = await credentials('wrong', 'DNS:wrong.example'), wrong = await peer(t, { tls: other });
  await assert.rejects(wrong.send({ ca: other.cert }), error => !error.dispatched); assert.equal(wrong.calls.length, 0);
});
