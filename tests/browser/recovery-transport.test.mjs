import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { Transport, hex, utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

const ORIGINAL = '1'.repeat(64), ROTATED = '2'.repeat(64);
const PRINCIPAL = 'a'.repeat(32), OTHER = 'b'.repeat(32), KEY = 'fgpr1-original-recovery-key';
const lookup = { method: 'POST', key: KEY, read: false };
const selection = () => ({ key: KEY, principal: PRINCIPAL });
const fingerprint = async token => hex(new Uint8Array(await webcrypto.subtle.digest('SHA-256', utf8.encode(token))));
const response = (value = { principal_id: PRINCIPAL, state: 'key_not_observed' }, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
function transport(fetchImpl = async () => response(), pageSuffix = '/ui/pulls/', extra = {}) {
  return new Transport({ href: `https://forge.example/repo.git${pageSuffix}`, pageSuffix,
    fetchImpl, cryptoImpl: webcrypto, ...extra });
}

test('ordinary reconnect still refuses a different credential for an unresolved request', async () => {
  const t = transport();
  await assert.rejects(t.connect(ROTATED, await fingerprint(ORIGINAL)), /another credential/);
  assert.equal(t.connected, false); assert.equal(t.recoveryOnly, false);
  await t.connect(ORIGINAL, await fingerprint(ORIGINAL));
  assert.equal(t.recoveryOnly, false);
});

test('explicit rotated recovery sends only the original key and verifies the principal', async () => {
  const requests = [], t = transport(async (url, options) => { requests.push({ url, options }); return response(); });
  await t.connect(ROTATED, await fingerprint(ORIGINAL), selection());
  assert.equal(t.connected, true); assert.equal(t.recoveryOnly, true);
  assert.equal(t.fingerprint, await fingerprint(ROTATED));
  const result = await t.request('outcomes', lookup);
  assert.equal(result.value.state, 'key_not_observed'); assert.equal(t.recoveryOnly, true);
  assert.equal(requests.length, 1);
  const { url, options } = requests[0];
  assert.equal(url.href, 'https://forge.example/repo.git/api/v1/outcomes');
  assert.equal(url.search, ''); assert.equal(options.body, undefined);
  assert.equal(options.headers.Authorization, `Bearer ${ROTATED}`);
  assert.equal(options.headers['Idempotency-Key'], KEY);
  assert.equal(options.headers['Content-Type'], undefined);
  assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error');
});

test('every existing mutation profile can use the closed recovery lane', async () => {
  for (const profile of ['pulls', 'source', 'initial', 'branches', 'transfers', 'tags', 'replay', 'rebase']) {
    const t = transport(undefined, `/ui/${profile}/`);
    await t.connect(ROTATED, null, selection());
    assert.equal((await t.request('outcomes', lookup)).value.principal_id, PRINCIPAL, profile);
  }
  const search = transport(undefined, '/ui/search/');
  await assert.rejects(search.connect(ROTATED, null, selection()), /no outcome recovery/);
  assert.equal(search.connected, false);
});

test('recovery-only refuses all mutation, read, alternate-key and response-shape escape hatches before fetch', async () => {
  let sends = 0;
  const t = transport(async () => { sends++; return response(); });
  await t.connect(ROTATED, null, selection());
  const requests = [
    ['pulls/1/open', { ...lookup, body: 'title=changed' }],
    ['pulls/1/merge', { ...lookup, body: new Blob(['bundle']) }],
    ['source/apply', { ...lookup, body: 'candidate=changed' }],
    ['pulls', {}], ['outcomes?key=other', lookup],
    ['outcomes', { ...lookup, key: 'another-key' }], ['outcomes', { ...lookup, body: '' }],
    ['outcomes', { ...lookup, body: new Uint8Array() }], ['outcomes', { ...lookup, method: 'GET' }],
    ['outcomes', { ...lookup, read: true }], ['outcomes', { ...lookup, binary: true }],
    ['outcomes', { ...lookup, statuses: [200, 409] }], ['outcomes', { ...lookup, statuses: '200' }],
  ];
  for (const [path, options] of requests) await assert.rejects(t.request(path, options), /Recovery-only/, path);
  assert.equal(sends, 0);
});

test('same-token recovery-only mode does not accidentally grant replay permission', async () => {
  const t = transport();
  await t.connect(ORIGINAL, await fingerprint(ORIGINAL), selection());
  await assert.rejects(t.request('pulls/1/open', { ...lookup, body: 'x' }), /cannot resend/);
  assert.equal(t.recoveryOnly, true);
});

test('selection is copied before asynchronous credential hashing', async () => {
  const selected = selection(), t = transport();
  const connecting = t.connect(ROTATED, null, selected);
  selected.key = 'different'; selected.principal = OTHER;
  await connecting;
  assert.equal((await t.request('outcomes', lookup)).value.principal_id, PRINCIPAL);
});

test('principal mismatch and missing or malformed identity never become a usable outcome', async () => {
  for (const value of [{ principal_id: OTHER, state: 'committed' }, {}, { principal_id: null },
    { principal_id: PRINCIPAL.toUpperCase() }, [], null]) {
    const t = transport(async () => response(value));
    await t.connect(ROTATED, null, selection());
    await assert.rejects(t.request('outcomes', lookup), /principal|record/);
    assert.equal(t.recoveryOnly, true);
  }
});

test('all server outcome states remain in recovery-only mode, including terminal states', async () => {
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused']) {
    const t = transport(async () => response({ principal_id: PRINCIPAL, state }));
    await t.connect(ROTATED, null, selection());
    assert.equal((await t.request('outcomes', lookup)).value.state, state);
    assert.equal(t.recoveryOnly, true);
    await assert.rejects(t.request('pulls/1/close', { ...lookup, body: 'x' }), /cannot resend/);
  }
});

test('invalid recovery selection never installs a credential', async () => {
  for (const selected of [{}, { key: KEY }, { ...selection(), principal: OTHER + '0' },
    { ...selection(), key: '' }, { ...selection(), key: 'x'.repeat(257) },
    { ...selection(), key: 'secret\r\nAuthorization: injected' },
    { ...selection(), key: 'non-ascii-é' }, { ...selection(), resend: true }, []]) {
    const t = transport();
    await assert.rejects(t.connect(ROTATED, null, selected));
    assert.equal(t.connected, false); assert.equal(t.recoveryOnly, false);
  }
});

test('receipt restoration can restrict an idle connection without falsifying its fingerprint', async () => {
  const t = transport();
  assert.throws(() => t.restrictToRecovery(selection()), /idle connected/);
  await t.connect(ROTATED);
  const originalFingerprint = t.fingerprint, selected = selection();
  t.restrictToRecovery(selected); selected.key = 'changed';
  assert.equal(t.fingerprint, originalFingerprint); assert.equal(t.recoveryOnly, true);
  await t.request('outcomes', lookup);
  t.restrictToRecovery(selection());
  assert.throws(() => t.restrictToRecovery({ ...selection(), key: 'another' }), /Reconnect explicitly/);
  assert.throws(() => t.restrictToRecovery({ ...selection(), principal: OTHER }), /Reconnect explicitly/);
});

test('restriction cannot change a connection with an in-flight request', async () => {
  let finish;
  const t = transport(() => new Promise(resolve => { finish = resolve; }));
  await t.connect(ORIGINAL);
  const reading = t.request('pulls');
  assert.throws(() => t.restrictToRecovery(selection()), /idle connected/);
  assert.equal(t.recoveryOnly, false);
  finish(response()); await reading;
  t.restrictToRecovery(selection()); assert.equal(t.recoveryOnly, true);
});

test('disconnect clears the restriction and reconnect remains an explicit action', async () => {
  const t = transport();
  await t.connect(ROTATED, null, selection()); t.disconnect();
  assert.equal(t.recoveryOnly, false); assert.equal(t.connected, false); assert.equal(t.fingerprint, '');
  await assert.rejects(t.request('outcomes', lookup), /Connect/);
  await t.connect(ORIGINAL); assert.equal(t.recoveryOnly, false);
  await t.request('pulls');
});

test('rejected or revoked rotated credentials cannot silently return normal access', async () => {
  const t = transport(async () => response({}, 401));
  await t.connect(ROTATED, null, selection());
  await assert.rejects(t.request('outcomes', lookup), error => error.status === 401);
  assert.equal(t.connected, false);
  await assert.rejects(t.request('pulls'), /Connect/);
});

test('recovery responses retain a hard decoded byte bound', async () => {
  const t = transport(async () => response({ principal_id: PRINCIPAL, padding: 'x'.repeat(32 * 1024) }));
  await t.connect(ROTATED, null, selection());
  await assert.rejects(t.request('outcomes', lookup), /byte limit/);
  assert.equal(t.recoveryOnly, true);
});

test('a reconnect fences a late old-principal response', async () => {
  let finish;
  const t = transport(() => new Promise(resolve => { finish = resolve; }));
  await t.connect(ORIGINAL);
  const reading = t.request('pulls');
  await t.connect(ROTATED, null, selection());
  finish(response({ principal_id: OTHER }));
  await assert.rejects(reading, /abort|superseded/i);
  assert.equal(t.recoveryOnly, true);
});
