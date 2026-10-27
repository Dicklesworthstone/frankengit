import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { CheckEvidenceClient, checkEvidenceReply, CHECK_EVIDENCE_LIMIT, CHECK_EVIDENCE_REPLY_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-check-evidence.mjs';
import { options, json, webcrypto, deferred, data, row } from './pulls-fixtures.mjs';
import { observation, checkLabel } from './pulls-checks-fixtures.mjs';
import { evidenceFixture, evidenceToken, report, step } from './pulls-checks-evidence-fixtures.mjs';

const validate = (fixture, reply = fixture.reply) => checkEvidenceReply(reply, 1, fixture.selected, fixture.check, webcrypto);
async function connected(fixture = evidenceFixture(), respond = () => json(fixture.reply), extra = {}) {
  const calls = [], client = new CheckEvidenceClient({ ...options(async (url, init) => {
    calls.push({ url: String(url), ...init }); return respond(calls.at(-1));
  }), ...extra });
  await client.connect(evidenceToken);
  return { fixture, client, calls, read: () => client.read(1, fixture.selected, fixture.prior, fixture.check.id) };
}

test('canonical evidence consumer verifies exact bytes and the native report in both Git domains', async () => {
  for (const format of ['sha1', 'sha256']) {
    const width = format === 'sha1' ? 40 : 64;
    const selected = observation({ object_format: format, pull_request: row(1, { data: data({ object_format: format,
      source_tip: 'a'.repeat(width), target_tip: 'b'.repeat(width) }) }) });
    const fixture = evidenceFixture({ selected }), result = await validate(fixture);
    assert.deepEqual(Buffer.from(result.bytes), fixture.bytes); assert.deepEqual(result.report, fixture.report);
    assert.equal(result.head, selected.head); assert.equal(result.binding.format, format);
  }
});

test('opaque evidence is verifiable and downloadable without inventing a log report', async () => {
  const fixture = evidenceFixture({ report: null, raw: Buffer.from('opaque evidence\0\xff', 'latin1'), check: { conclusion: 'action_required' } });
  const result = await validate(fixture);
  assert.equal(result.report, null); assert.deepEqual(Buffer.from(result.bytes), fixture.bytes);
  assert.equal(result.check.conclusion, 'action_required');
});

test('an older action_required check is never upgraded by a successful retained report', async () => {
  const recorded = report({ succeeded: true, jobs: [{ id: 'test', outcome: 'succeeded', steps: [step({ outcome: 'succeeded', exit_code: 0 })], failure: null }] });
  const fixture = evidenceFixture({ report: recorded, check: { conclusion: 'action_required' } });
  assert.equal((await validate(fixture)).check.conclusion, 'action_required');
});

test('evidence request uses only its separate credential and the exact selected check and snapshot', async () => {
  const h = await connected(), result = await h.read();
  assert.equal(result.check.id, h.fixture.check.id); assert.equal(h.calls.length, 1);
  const request = h.calls[0], url = new URL(request.url);
  assert.ok(url.pathname.endsWith('/pulls/1/checks/evidence'));
  assert.deepEqual([...url.searchParams], [['check', h.fixture.check.id], ['expected_head', h.fixture.selected.head]]);
  assert.equal(request.headers.Authorization, `Bearer ${evidenceToken}`);
  assert.equal(request.method, 'GET'); assert.equal(request.body, undefined); assert.equal(request.headers['Idempotency-Key'], undefined);
  assert.equal(request.credentials, 'omit'); assert.equal(request.cache, 'no-store'); assert.equal(request.redirect, 'error');
  assert.equal(request.referrerPolicy, 'no-referrer'); assert.ok(!request.url.includes(evidenceToken));
});

test('a check must already occur in the selected current PR page before any HTTP read', async () => {
  const h = await connected();
  await assert.rejects(h.client.read(1, h.fixture.selected, h.fixture.prior, checkLabel(2)));
  for (const mutate of [value => { value.reply.source_current = false; }, value => { value.reply.snapshot_token = `alg:2:${'f'.repeat(64)}`; },
    value => { value.reply.source_tip = 'f'.repeat(40); }, value => { value.reply.checks = []; }]) {
    const page = structuredClone(h.fixture.prior); mutate(page);
    await assert.rejects(h.client.read(1, h.fixture.selected, page, h.fixture.check.id));
  }
  assert.equal(h.calls.length, 0);
});

test('response page must preserve every selected check field and all PR coordinates', async () => {
  const fixture = evidenceFixture();
  for (const [field, value] of [['id', checkLabel(2)], ['publisher', 'f'.repeat(32)], ['run_id', 'f'.repeat(64)], ['attempt_id', 'f'.repeat(64)],
    ['graph_root', 'f'.repeat(64)], ['job', 'other'], ['conclusion', 'action_required'], ['evidence_sha256', 'f'.repeat(64)], ['evidence_bytes', '1']]) {
    const changed = structuredClone(fixture.reply); changed.page.checks[0][field] = value;
    await assert.rejects(validate(fixture, changed), /selected canonical check/);
  }
  for (const changes of [{ tenant_id: 'f'.repeat(32) }, { repository_id: 'f'.repeat(32) }, { repository_incarnation: 'f'.repeat(32) },
    { object_format: 'sha256' }, { source_head: 'other-head' }, { snapshot_token: `alg:2:${'f'.repeat(64)}` },
    { pull_request_version: '2' }, { source_ref_hex: Buffer.from('refs/heads/other').toString('hex') }, { target_ref_hex: '61' },
    { source_tip: 'f'.repeat(40) }, { target_tip: 'f'.repeat(40) }, { limit: 20 }, { after: checkLabel(1) },
    { source_current: false, checks: [] }, { checks: [] }, { next_after: checkLabel(1), complete: false }]) {
    await assert.rejects(validate(fixture, { ...fixture.reply, page: { ...fixture.reply.page, ...changes } }), JSON.stringify(changes));
  }
});

test('malformed envelope, oversized evidence, changed bytes and byte counts fail closed', async () => {
  const fixture = evidenceFixture();
  for (const changes of [{ schema_version: 2 }, { type: 'artifact' }, { read_only: false }, { merge_permission: true },
    { report: undefined }, { evidence_hex: null }, { evidence_hex: fixture.reply.evidence_hex + '0' },
    { evidence_hex: fixture.reply.evidence_hex.toUpperCase() }, { evidence_hex: fixture.reply.evidence_hex.slice(2) },
    { evidence_hex: '00' + fixture.reply.evidence_hex.slice(2) }, { evidence_hex: '00'.repeat(CHECK_EVIDENCE_LIMIT + 1) }]) {
    await assert.rejects(validate(fixture, { ...fixture.reply, ...changes }));
  }
});

test('report text must be the exact final length-framed byte span, never a substituted summary', async () => {
  const fixture = evidenceFixture();
  const substituted = fixture.reply.report.json.replace('Run tests', 'Other job');
  assert.notEqual(substituted, fixture.reply.report.json, 'the report substitution must alter actual JSON bytes');
  for (const changes of [{ offset: fixture.reply.report.offset - 1 }, { bytes: fixture.reply.report.bytes - 1 }, { offset: 7 },
    { offset: Number.MAX_SAFE_INTEGER }, { json: substituted }, { extra: true }]) {
    await assert.rejects(validate(fixture, { ...fixture.reply, report: { ...fixture.reply.report, ...changes } }));
  }
  const changed = structuredClone(fixture.reply), bytes = Buffer.from(fixture.bytes);
  bytes.writeBigUInt64BE(BigInt(changed.report.bytes - 1), changed.report.offset - 8);
  changed.evidence_hex = bytes.toString('hex');
  const check = { ...fixture.check, evidence_sha256: createHash('sha256').update(bytes).digest('hex') };
  changed.page.checks = [check];
  await assert.rejects(checkEvidenceReply(changed, 1, fixture.selected, check, webcrypto), /length-framed/);
});

test('unknown report fields, profiles, jobs, budgets and contradictory success refuse log display', async () => {
  const mutations = [value => { value.authoritative_check = true; }, value => { value.profile = 'hosted'; }, value => { value.unknown = true; },
    value => { value.environment.SECRET = 'untrusted'; }, value => { value.workflow_graph = `alg:2:${'f'.repeat(64)}`; },
    value => { value.jobs[0].id = 'other'; }, value => { value.jobs.push(value.jobs[0]); }, value => { value.succeeded = true; },
    value => { value.jobs[0].outcome = 'approved'; }, value => { value.jobs[0].steps[0].index = 512; },
    value => { value.jobs[0].steps.push(value.jobs[0].steps[0]); }, value => { value.jobs[0].steps[0].stdout_hex = 'zz'; },
    value => { value.jobs[0].steps[0].output_complete = 'true'; }, value => { value.jobs[0].steps[0].elapsed_millis = 9007199254740992; },
    value => { value.jobs[0].steps[0].outcome = 'succeeded'; }, value => { value.stream_bytes = 1; }, value => { value.total_output_bytes = 2; },
    value => { value.jobs[0].failure = { detail: 'failure', workspace_retained: 'false' }; }];
  for (const mutate of mutations) {
    const recorded = report(); mutate(recorded);
    await assert.rejects(validate(evidenceFixture({ report: recorded })));
  }
});

test('evidence Transport is a closed read lane and other browser profiles cannot borrow it', async () => {
  let calls = 0;
  const transport = new Transport({ ...options(async () => { calls += 1; return json({}); }), checkEvidenceOnly: true });
  await transport.connect(evidenceToken);
  const query = new URLSearchParams({ check: checkLabel(1), expected_head: observation().head }), path = `pulls/1/checks/evidence?${query}`;
  for (const changes of [{ method: 'POST' }, { body: '' }, { key: 'key' }, { read: false }, { binary: true }, { statuses: [200, 404] },
    { maximum: CHECK_EVIDENCE_REPLY_LIMIT + 1 }]) await assert.rejects(transport.request(path, changes));
  for (const invalid of ['outcomes', 'pulls/1/checks', 'pulls/1/merge', `${path}&after=${checkLabel(1)}`, `${path}&check=${checkLabel(1)}`,
    path.replace('/1/', '/01/'), path.replace('expected_head=', 'head='), path.replace('alg%3A2', 'alg%3A1'), `${path}#leak`]) await assert.rejects(transport.request(invalid));
  await assert.rejects(transport.connect(evidenceToken, null, { key: 'key', principal: 'a'.repeat(32) }));
  const ordinary = new Transport(options(async () => { calls += 1; return json({}); })); await ordinary.connect(evidenceToken);
  await assert.rejects(ordinary.request(path), /route/);
  assert.throws(() => new Transport({ ...options(() => {}), pageSuffix: '/ui/source/', checkEvidenceOnly: true }));
  assert.equal(calls, 0);
});

test('HTTP refuses unavailable or unauthorized evidence without treating it as an empty log', async () => {
  for (const status of [401, 403, 404, 409]) {
    const h = await connected(evidenceFixture(), () => new Response('', { status }));
    await assert.rejects(h.read(), error => error.status === status);
    assert.equal(h.client.connected, status !== 401 && status !== 403);
  }
});

for (const status of [401, 403]) test(`an earlier HTTP ${status} cannot disconnect a replacement evidence credential`, async () => {
  const fixture = evidenceFixture(), pending = deferred(), calls = [], replacementToken = 'e'.repeat(64);
  // Return the fetch promise directly so Transport processes the denial before
  // the reconnect microtask, but its caller receives rejection afterwards.
  const client = new CheckEvidenceClient(options((url, init) => {
    calls.push({ url: String(url), ...init }); return calls.length === 1 ? pending.promise : Promise.resolve(json(fixture.reply));
  }));
  await client.connect(evidenceToken);
  const read = () => client.read(1, fixture.selected, fixture.prior, fixture.check.id);
  const refusal = assert.rejects(read(), error => error.status === status);
  pending.resolve(new Response('', { status }));
  const replacement = new Promise((resolve, reject) => {
    queueMicrotask(() => { client.connect(replacementToken).then(resolve, reject); });
  });
  await Promise.all([refusal, replacement]);
  assert.equal(client.connected, true);
  assert.equal((await read()).check.id, fixture.check.id);
  assert.equal(calls.at(-1).headers.Authorization, `Bearer ${replacementToken}`);
});

test('a superseded HTTP 403 cannot invalidate a newer evidence read on the same connection', async () => {
  const fixture = evidenceFixture(), pending = deferred(); let calls = 0;
  const client = new CheckEvidenceClient(options(() => ++calls === 1 ? pending.promise : Promise.resolve(json(fixture.reply))));
  await client.connect(evidenceToken);
  const read = () => client.read(1, fixture.selected, fixture.prior, fixture.check.id);
  const refusal = assert.rejects(read(), error => error.status === 403);
  pending.resolve(new Response('', { status: 403 }));
  const replacement = new Promise((resolve, reject) => { queueMicrotask(() => { read().then(resolve, reject); }); });
  const [, result] = await Promise.all([refusal, replacement]);
  assert.equal(client.connected, true); assert.equal(result.check.id, fixture.check.id);
});

test('download transport enforces streaming and declared bounds, content type and redirects', async () => {
  const fixture = evidenceFixture();
  for (const respond of [() => new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': String(CHECK_EVIDENCE_REPLY_LIMIT + 1) } }),
    () => new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': '3' } }),
    () => new Response(JSON.stringify(fixture.reply), { headers: { 'Content-Type': 'text/html' } }),
    () => { const response = json(fixture.reply); Object.defineProperty(response, 'redirected', { value: true }); return response; },
    () => new Response(new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(CHECK_EVIDENCE_REPLY_LIMIT + 1)); controller.close(); } }),
      { headers: { 'Content-Type': 'application/json' } })]) {
    const h = await connected(fixture, respond); await assert.rejects(h.read());
  }
});

test('disconnect and cancellation reject late response bytes and digest completions', async () => {
  for (const action of ['disconnect', 'cancelReads']) {
    const pending = deferred(), fixture = evidenceFixture(), h = await connected(fixture, () => pending.promise);
    const read = h.read(), refusal = assert.rejects(read); h.client[action](); pending.resolve(json(fixture.reply)); await refusal;
    assert.equal(h.calls[0].signal.aborted, true);
  }
  const pending = deferred(), hashing = deferred(); let count = 0;
  const fixture = evidenceFixture(), h = await connected(fixture, () => json(fixture.reply), { cryptoImpl: { subtle: {
    digest(...args) { if (++count === 1) return webcrypto.subtle.digest(...args); hashing.resolve(); return pending.promise; }
  } } });
  const read = h.read(), refusal = assert.rejects(read); await hashing.promise; h.client.disconnect();
  pending.resolve(await webcrypto.subtle.digest('SHA-256', fixture.bytes)); await refusal;
});

test('selected observations are copied before the request can yield to caller edits', async () => {
  const pending = deferred(), fixture = evidenceFixture(), h = await connected(fixture, () => pending.promise);
  const original = structuredClone(fixture.reply);
  const read = h.read(); fixture.prior.reply.checks[0].job = 'replaced'; fixture.selected.reply.pull_request.data.source_tip = 'f'.repeat(40);
  pending.resolve(json(original));
  assert.equal((await read).check.job, 'test');
});
