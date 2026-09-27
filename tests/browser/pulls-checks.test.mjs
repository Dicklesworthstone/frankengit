// Mocked HTTP checks protocol consumers; the server owns native lifecycle tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { checkId, checksReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-checks.mjs';
import { token, row, data, scope, json, options, deferred } from './pulls-fixtures.mjs';
import { checksHead, checkLabel, checkRow, observation, checks, unavailable } from './pulls-checks-fixtures.mjs';

function validate(reply, observed = observation(), options = {}) { return checksReply(reply, 1, observed, { scope, ...options }); }
async function connected(reply = checks(), status = 200) {
  const calls = [];
  const client = new PullClient(options(async (url, init) => {
    calls.push({ url: String(url), ...init });
    if (new URL(url).pathname.endsWith('/pulls/1')) return json(observation().reply);
    return json(reply, status);
  }));
  await client.connect(token); const observed = await client.show(1); calls.length = 0;
  return { client, calls, observed };
}

test('native canonical labels reject aliases, padding and wrong domains', () => {
  for (const id of [`check/${'v'.repeat(51)}g`, `check/${'0'.repeat(52)}`]) assert.equal(checkId(id), id);
  for (const id of [`check/${'v'.repeat(51)}h`, `check/${'V'.repeat(51)}0`, `check/${'0'.repeat(51)}`,
    `check/${'w'.repeat(51)}0`, `run/${'0'.repeat(52)}`, `${checkLabel(1)}/more`, '']) assert.throws(() => checkId(id));
});

test('both Git domains preserve native tips and decimal string counts', () => {
  for (const format of ['sha1', 'sha256']) {
    const width = format === 'sha1' ? 40 : 64;
    const meta = data({ object_format: format, source_tip: 'a'.repeat(width), target_tip: 'b'.repeat(width) });
    const observed = observation({ object_format: format, pull_request: row(1, { data: meta }) });
    const reply = checks({ object_format: format, source_tip: meta.source_tip, target_tip: meta.target_tip,
      checks: [checkRow({ evidence_bytes: '1048576' })] });
    const result = checksReply(reply, 1, observed, { scope: observed.binding });
    assert.equal(result.reply.checks[0].evidence_bytes, '1048576');
    assert.equal(result.head, checksHead); assert.equal(result.reply.merge_permission, null);
  }
});

test('all four native conclusions remain observations, never successful protected checks', () => {
  for (const conclusion of ['action_required', 'failure', 'cancelled', 'timed_out']) {
    assert.equal(validate(checks({ checks: [checkRow({ conclusion })] })).reply.checks[0].conclusion, conclusion);
  }
  for (const conclusion of ['success', 'neutral', 'succeeded', 'approved', 'pending', null]) {
    assert.throws(() => validate(checks({ checks: [checkRow({ conclusion })] })));
  }
  for (const extra of [{ merge_permission: true }, { merge_permission: false }, { scope: 'protected_checks' }]) assert.throws(() => validate(checks(extra)));
});

test('stale sources withhold observations while absence discloses no subject', () => {
  assert.equal(validate(checks({ source_current: false, checks: [] })).reply.checks.length, 0);
  assert.throws(() => validate(checks({ source_current: false })));
  assert.throws(() => validate(checks({ source_current: false, checks: [], next_after: checkLabel(1), complete: false })));
  assert.equal(validate(checks({ checks: [] })).reply.complete, true);
  assert.equal(validate(unavailable()).head, null);
  for (const key of ['source_head', 'snapshot_token', 'pull_request_version', 'source_ref_hex', 'target_ref_hex', 'source_tip', 'target_tip', 'source_current']) {
    assert.throws(() => validate({ ...unavailable(), [key]: checks()[key] }), key);
  }
  assert.throws(() => validate({ ...unavailable(), checks: [checkRow()] }));
});

test('repository, snapshot, version, refs and tips cannot be mixed across views', () => {
  for (const extra of [{ tenant_id: 'other' }, { repository_id: 'other' }, { repository_incarnation: 'other' },
    { source_head: 'other' }, { snapshot_token: `alg:2:${'f'.repeat(64)}` }, { snapshot_token: `alg:1:${'b'.repeat(64)}` },
    { pull_request_version: '2' }, { number: '2' }, { source_ref_hex: data().source_ref_hex + 'ff' },
    { target_ref_hex: data().target_ref_hex + 'ff' }, { source_tip: 'c'.repeat(40) }, { target_tip: 'c'.repeat(40) },
    { source_tip: `sha1:${'a'.repeat(40)}` }, { source_current: null }]) assert.throws(() => validate(checks(extra)), JSON.stringify(extra));
  const bytes = data().source_ref_hex + 'ff';
  const observed = observation({ pull_request: row(1, { data: data({ source_ref: null, source_ref_hex: bytes }) }) });
  assert.equal(validate(checks({ source_ref_hex: bytes }), observed).reply.source_ref_hex, bytes);
  assert.throws(() => validate(checks(), observed));
});

test('merge-only observations bind the pre-merge target', () => {
  const meta = data(), merge = { object_format: 'sha1', source_ref: meta.source_ref, source_ref_hex: meta.source_ref_hex,
    target_ref: meta.target_ref, target_ref_hex: meta.target_ref_hex, source_tip: meta.source_tip,
    target_tip_before: meta.target_tip, base_tip: 'c'.repeat(40), merge_commit: 'd'.repeat(40) };
  const selected = observation({ pull_request: row(1, { data: null, merge_only: true, state: 'merged', merge }) });
  assert.equal(validate(checks(), selected).reply.target_tip, meta.target_tip);
  assert.throws(() => validate(checks({ target_tip: merge.merge_commit }), selected));
});

test('pagination requires ordered unique labels and exact continuation', () => {
  const rows = [checkRow(), checkRow({ id: checkLabel(2) })];
  const first = checks({ limit: 2, checks: rows, next_after: rows[1].id, complete: false });
  assert.equal(validate(first, observation(), { limit: 2 }).reply.next_after, rows[1].id);
  assert.equal(validate(checks({ after: rows[1].id, checks: [] }), observation(), { after: rows[1].id }).reply.complete, true);
  for (const extra of [{ checks: [rows[1], rows[0]] }, { checks: [rows[0], rows[0]] },
    { next_after: rows[0].id }, { next_after: null }, { complete: true }, { checks: [rows[1]] }, { limit: 1 }]) {
    assert.throws(() => validate({ ...first, ...extra }, observation(), { limit: 2 }));
  }
  assert.throws(() => validate(checks({ after: rows[1].id }), observation(), { after: rows[1].id }));
});

test('malformed, oversized and inexact fields fail before display', () => {
  for (const extra of [{ number: 1 }, { pull_request_version: 1 }, { pull_request_version: '01' },
    { number: '18446744073709551616' }, { checks: null }, { schema_version: 2 }, { extra: 'not admitted' }]) assert.throws(() => validate(checks(extra)));
  for (const extra of [{ publisher: '<script>' }, { run_id: 'a'.repeat(63) }, { attempt_id: 'A'.repeat(64) },
    { graph_root: null }, { evidence_sha256: 'zz'.repeat(32) }, { evidence_bytes: 64 }, { evidence_bytes: '0' },
    { evidence_bytes: '01' }, { evidence_bytes: '1048577' }, { evidence_bytes: '9007199254740993' },
    { job: '' }, { job: 'job\n' }, { job: '🦀'.repeat(257) }, { extra: true }]) assert.throws(() => validate(checks({ checks: [checkRow(extra)] })), JSON.stringify(extra));
});

test('client requests retain the selected snapshot and readonly credential transport', async () => {
  const { client, observed, calls } = await connected();
  const result = await client.checks(1, observed);
  assert.equal(result.head, observed.head); assert.equal(calls.length, 1);
  const request = calls[0], url = new URL(request.url);
  assert.ok(url.pathname.endsWith('/pulls/1/checks'));
  assert.equal(url.searchParams.get('expected_head'), observed.head);
  assert.equal(url.searchParams.get('limit'), '20'); assert.equal(url.searchParams.has('after'), false);
  assert.equal(request.method, 'GET'); assert.equal(request.body, undefined);
  assert.equal(request.headers.Authorization, `Bearer ${token}`); assert.equal(request.headers['Idempotency-Key'], undefined);
  assert.equal(request.credentials, 'omit'); assert.equal(request.cache, 'no-store'); assert.equal(request.redirect, 'error');
  assert.equal(client.pending, null); assert.equal(client.candidate, null);
  const cursor = checkLabel(1), next = await connected(checks({ after: cursor, checks: [] }));
  await next.client.checks(1, next.observed, { after: cursor });
  assert.equal(new URL(next.calls[0].url).searchParams.get('after'), cursor);
  assert.equal(new URL(next.calls[0].url).searchParams.get('expected_head'), observed.head);
});

test('client validates before HTTP and binds presence to HTTP status', async () => {
  const h = await connected();
  for (const options of [{ limit: 0 }, { limit: 101 }, { after: '' }, { after: `check/${'x'.repeat(52)}` }]) {
    await assert.rejects(h.client.checks(1, h.observed, options));
  }
  assert.equal(h.calls.length, 0);
  for (const [reply, status] of [[unavailable(), 200], [checks(), 404]]) {
    const h = await connected(reply, status); await assert.rejects(h.client.checks(1, h.observed), /presence/);
  }
  const absent = await connected(unavailable(), 404);
  assert.equal((await absent.client.checks(1, absent.observed)).reply.found, false);
});

test('checks transport rejects writes and other browser profiles', async () => {
  let calls = 0;
  const transport = new Transport(options(async () => { calls += 1; return json(checks()); }));
  await transport.connect(token);
  for (const extra of [{ method: 'POST' }, { body: '' }, { key: 'write-key' }, { read: false }, { binary: true }, { statuses: [200] }]) {
    await assert.rejects(transport.request('pulls/1/checks', { statuses: [200, 404], ...extra }), /read-only/);
  }
  const source = new Transport({ ...options(async () => { calls += 1; return json(checks()); }),
    href: 'https://forge.example/team/repo.git/ui/source/', pageSuffix: '/ui/source/' });
  await source.connect(token); await assert.rejects(source.request('pulls/1/checks', { statuses: [200, 404] }), /route/);
  assert.equal(calls, 0);
});

test('disconnect and read cancellation refuse late responses', async () => {
  for (const stop of ['disconnect', 'cancelReads']) {
    const pending = deferred();
    const client = new PullClient(options(async url => new URL(url).pathname.endsWith('/checks') ? pending.promise : json(observation().reply)));
    await client.connect(token); const selected = await client.show(1);
    const read = client.checks(1, selected), refusal = assert.rejects(read);
    client[stop](); pending.resolve(json(checks())); await refusal;
    assert.equal(client.pending, null); assert.equal(client.candidate, null);
  }
});
