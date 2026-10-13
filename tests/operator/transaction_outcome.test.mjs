// Real loopback HTTP/TLS peers speaking the native outcome schema, not Rust fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { lookupOutcome, validateOutcomeReply, parseOutcomeJson, outcomeEndpoint, OUTCOME_BYTES } from '../../scripts/operator/transaction_outcome.mjs';

const scope = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), principal_id: '4'.repeat(32) };
const token = 'a'.repeat(64), key = 'fgwc1-original-key';
const selection = () => ({ ...scope, key });
function reply(state = 'committed') {
  const terminal = ['committed', 'refused'].includes(state), present = ['undecided', 'committed', 'refused'].includes(state);
  return { type: 'transaction_outcome', schema_version: 1, ...scope, selector: 'transaction', command_index: null, state, terminal,
    transaction: present ? { tx_id: 'tx-original', seal_id: 'seal-original', request_schema: 'receive-admission-v1',
      canonical_request_digest: { algorithm: 2, hex: 'b'.repeat(64) } } : null,
    decision: !terminal ? null : state === 'committed' ? { kind: state, decision_sequence: '18446744073709551615', repository_commit_id: 'rcr-original' }
      : { kind: state, decision_sequence: '18446744073709551615', code: 'EvidenceStale', code_point: 1, refusal_record_id: 'refusal-original' },
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
const wire = value => JSON.stringify(value).replace('"decision_sequence":"18446744073709551615"', '"decision_sequence":18446744073709551615');
const send = (res, value = reply()) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(wire(value)); };
async function server(t, handler, tls = null) {
  const requests = [], sockets = new Set();
  const instance = tls ? https.createServer(tls, listen) : http.createServer(listen);
  function listen(req, res) { requests.push(req); handler(req, res); }
  instance.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  instance.listen(0, '127.0.0.1'); await once(instance, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => instance.close(resolve)); });
  return { address: `${tls ? 'https' : 'http'}://127.0.0.1:${instance.address().port}/repo.git`, requests, sockets };
}

test('only an original-key bodyless POST is sent; exact u64 and full scope survive', async t => {
  let observed;
  const peer = await server(t, (req, res) => { let body = ''; req.on('data', chunk => body += chunk); req.on('end', () => { observed = { method: req.method, url: req.url, headers: req.headers, body }; send(res); }); });
  const result = await lookupOutcome(peer.address, token, selection());
  assert.equal(result.decision.decision_sequence, '18446744073709551615');
  assert.deepEqual(result, reply());
  assert.equal(observed.method, 'POST'); assert.equal(observed.url, '/repo.git/api/v1/outcomes'); assert.equal(observed.body, '');
  assert.equal(observed.headers['idempotency-key'], key); assert.equal(observed.headers.authorization, `Bearer ${token}`);
  assert.equal(observed.headers['content-length'], '0'); assert.equal(observed.headers['content-type'], undefined);
  assert.equal(observed.headers.cookie, undefined); assert.equal(observed.headers.connection, 'close');
  assert.equal(peer.requests.length, 1);
});
for (const state of ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused']) {
  test(`native ${state} remains an observation, not a resend or rollback`, async t => {
    const peer = await server(t, (_req, res) => send(res, reply(state)));
    const result = await lookupOutcome(peer.address, token, selection());
    assert.deepEqual(result, reply(state)); assert.equal(result.request_reexecuted, false);
    assert.equal(result.absence_proves_non_commit, false); assert.equal(peer.requests.length, 1);
  });
}

test('every scope dimension and returned principal is checked before a result is usable', async t => {
  for (const name of Object.keys(scope)) {
    const bad = reply(); bad[name] = 'f'.repeat(32);
    const peer = await server(t, (_req, res) => send(res, bad));
    await assert.rejects(lookupOutcome(peer.address, token, selection()), /scope_or_semantics/);
  }
});
test('rotated credentials identify the same original principal, never another key namespace', async t => {
  const peer = await server(t, (_req, res) => send(res));
  await lookupOutcome(peer.address, 'c'.repeat(64), selection());
  assert.equal(peer.requests[0].headers.authorization, `Bearer ${'c'.repeat(64)}`);
  assert.equal(peer.requests[0].headers['idempotency-key'], key);
});

test('known transaction, seal, digest and terminal decisions cannot regress or change', () => {
  const known = reply('undecided');
  assert.deepEqual(validateOutcomeReply(reply(), scope, known), reply());
  for (const state of ['key_not_observed', 'seal_not_observed']) assert.throws(() => validateOutcomeReply(reply(state), scope, known));
  for (const field of ['tx_id', 'seal_id', 'request_schema']) { const changed = reply(); changed.transaction[field] += '-other'; assert.throws(() => validateOutcomeReply(changed, scope, known), /regressed/); }
  const changed = reply(); changed.transaction.canonical_request_digest.hex = 'c'.repeat(64);
  assert.throws(() => validateOutcomeReply(changed, scope, known), /regressed/);
  for (const value of [reply('undecided'), reply('refused'), { ...reply(), decision: { ...reply().decision, repository_commit_id: 'other' } }]) {
    assert.throws(() => validateOutcomeReply(value, scope, reply()), /regressed/);
  }
  assert.throws(() => validateOutcomeReply(reply('key_not_observed'), scope, reply('seal_not_observed')), /regressed/);
  assert.deepEqual(validateOutcomeReply(reply(), scope, reply()), reply());
});
test('reply member order does not create false seal conflicts', () => {
  const old = reply('undecided'); old.transaction = Object.fromEntries(Object.entries(old.transaction).reverse());
  assert.deepEqual(validateOutcomeReply(reply(), scope, old), reply());
});

test('selection and prior evidence are detached before network awaits', async t => {
  let finish;
  const peer = await server(t, (_req, res) => { finish = () => send(res); });
  const chosen = selection(), known = reply('undecided');
  const pending = lookupOutcome(peer.address, token, chosen, { known });
  chosen.principal_id = 'f'.repeat(32); chosen.key = 'different'; known.transaction.tx_id = 'changed';
  while (!finish) await new Promise(setImmediate);
  finish(); assert.deepEqual(await pending, reply());
  assert.equal(peer.requests[0].headers['idempotency-key'], key);
});

test('invalid keys, credentials, endpoints and extra mutation options refuse before a socket', async t => {
  const peer = await server(t, (_req, res) => send(res));
  for (const bad of ['', 'x'.repeat(257), 'key\r\nInjected: yes', 'two words', 'é']) await assert.rejects(lookupOutcome(peer.address, token, { ...selection(), key: bad }));
  for (const bad of ['', token.toUpperCase(), token + '0']) await assert.rejects(lookupOutcome(peer.address, bad, selection()));
  for (const options of [{ body: 'mutation' }, { method: 'POST' }, { path: 'protection' }, { timeoutMs: 0 }, { timeoutMs: Infinity }, { signal: {} }, { ca: Buffer.alloc(131073) }]) {
    await assert.rejects(lookupOutcome(peer.address, token, selection(), options));
  }
  for (const address of ['http://localhost/repo.git', 'http://example.com/repo.git', `${peer.address}/`, `${peer.address}?key=x`, `${peer.address}#x`,
    `${peer.address}/../other`, 'https://user:password@example.com/repo.git', 'https://example.com/r%2fsecret', 'file:///repo.git', 'https://example.com:443/repo.git']) assert.throws(() => outcomeEndpoint(address));
  assert.equal(peer.requests.length, 0);
});
for (const status of [301, 302, 307, 401, 403, 404, 409, 429, 500]) {
  test(`HTTP ${status} neither follows a redirect nor invents an outcome`, async t => {
    const peer = await server(t, (_req, res) => { res.writeHead(status, { Location: '/another-repository', 'Content-Type': 'application/json' }); res.end(wire(reply())); });
    await assert.rejects(lookupOutcome(peer.address, token, selection()), error => error.status === status && error.outcomeUnknown && !error.message.includes(token) && !error.message.includes(key));
    assert.equal(peer.requests.length, 1);
  });
}

test('malformed, fractional, exponential, negative and overflowing JSON counters refuse', () => {
  for (const sequence of ['18446744073709551616', '0', '-1', '1e2', '1.0']) {
    const value = wire(reply()).replace('18446744073709551615', sequence);
    assert.throws(() => validateOutcomeReply(parseOutcomeJson(Buffer.from(value)), scope));
  }
  for (const value of [Buffer.from('{'), Buffer.from([0xff]), Buffer.from('\ufeff{}'), Buffer.alloc(OUTCOME_BYTES + 1)]) assert.throws(() => parseOutcomeJson(value));
});
test('wrong schemas, unknown effects and inconsistent terminal shapes refuse', () => {
  for (const patch of [{ request_reexecuted: true }, { absence_proves_non_commit: true }, { selector: 'receive_command' }, { command_index: 0 },
    { schema_version: 2 }, { transaction: null }, { terminal: false }, { object_format: 'sha1' }, { state: 'aborted' }, { type: 'review_protection_publication' }]) {
    assert.throws(() => validateOutcomeReply({ ...reply(), ...patch }, scope));
  }
  const bad = reply(); bad.decision.refusal_record_id = 'not-committed'; assert.throws(() => validateOutcomeReply(bad, scope));
});
test('decoded byte limits, MIME type and content encoding are enforced', async t => {
  for (const handler of [
    (_req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('html'); },
    (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }); res.end(wire(reply())); },
    (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': String(OUTCOME_BYTES + 1) }); res.end('x'); },
    (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('x'.repeat(OUTCOME_BYTES + 1)); },
    (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '5000' }); res.write(wire(reply())); res.socket.end(); },
  ]) {
    const peer = await server(t, handler); await assert.rejects(lookupOutcome(peer.address, token, selection(), { timeoutMs: 500 }));
  }
});
test('whole-operation deadline covers a silent peer and delayed response bodies', async t => {
  for (const start of [false, true]) {
    const peer = await server(t, (_req, res) => { if (start) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); } });
    await assert.rejects(lookupOutcome(peer.address, token, selection(), { timeoutMs: 30 }), /outcome_timeout/);
  }
});
test('abort cancels outstanding reads and pre-abort sends no request', async t => {
  let arrived;
  const waiting = new Promise(resolve => { arrived = resolve; });
  const peer = await server(t, () => arrived()); const controller = new AbortController();
  const result = lookupOutcome(peer.address, token, selection(), { signal: controller.signal });
  await waiting; controller.abort(); await assert.rejects(result, /cancelled/);
  await assert.rejects(lookupOutcome(peer.address, token, selection(), { signal: controller.signal }), /cancelled/);
  assert.equal(peer.requests.length, 1);
});
test('verified private-CA TLS works while an untrusted certificate refuses', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'fg-outcome-tls-')); t.after(() => rm(dir, { recursive: true, force: true }));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'),
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'], { timeout: 10000, stdio: 'ignore' });
  const cert = await readFile(join(dir, 'cert.pem')), privateKey = await readFile(join(dir, 'key.pem'));
  const peer = await server(t, (_req, res) => send(res), { key: privateKey, cert });
  await assert.rejects(lookupOutcome(peer.address, token, selection()), /transport_unavailable/);
  assert.deepEqual(await lookupOutcome(peer.address, token, selection(), { ca: cert }), reply());
  assert.equal(peer.requests.length, 1, 'rejected TLS never delivered a credential-bearing HTTP request');
});
test('duplicate framing headers cannot become a receipt', async t => {
  const peer = net.createServer(socket => socket.once('data', () => socket.end('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n' + wire(reply()))));
  peer.listen(0, '127.0.0.1'); await once(peer, 'listening'); t.after(() => new Promise(resolve => peer.close(resolve)));
  await assert.rejects(lookupOutcome(`http://127.0.0.1:${peer.address().port}/repo.git`, token, selection()), /response_encoding/);
});
