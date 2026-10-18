// Focused success-path compatibility tests. HTTP peers below implement the
// native response schema; they are not a running Rust authority or CI runner.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { webcrypto } from 'node:crypto';
import { checksReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-checks.mjs';
import { Transport, showReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

const token = '12'.repeat(32);
const head = `alg:2:${'ab'.repeat(32)}`;
const checkId = index => `check/${String(index).padStart(51, '0')}0`;
const ref = value => Buffer.from(value).toString('hex');
const conclusionNames = ['action_required', 'success', 'failure', 'cancelled', 'timed_out'];
function fixtures(format = 'sha1', conclusions = ['success']) {
  const width = format === 'sha1' ? 40 : 64;
  const identity = { schema_version: 1, tenant_id: 'tenant', repository_id: 'repository',
    repository_incarnation: 'incarnation', object_format: format,
    source_head: 'selected-authority-head', snapshot_token: head };
  const data = { object_format: format, title: 'Reviewed change', body: '',
    source_ref: 'refs/heads/topic', target_ref: 'refs/heads/main',
    source_ref_hex: ref('refs/heads/topic'), target_ref_hex: ref('refs/heads/main'),
    source_tip: 'a'.repeat(width), target_tip: 'b'.repeat(width) };
  const observed = showReply({ ...identity, type: 'pull_request', number: 7, found: true,
    pull_request: { number: 7, version: 3, state: 'open', merge_only: false,
      data, merge: null, opened_by: '11'.repeat(16), last_metadata_actor: '22'.repeat(16) } }, 7);
  const reply = { ...identity, type: 'pull_request_checks', number: '7', found: true,
    pull_request_version: '3', source_ref_hex: data.source_ref_hex, target_ref_hex: data.target_ref_hex,
    source_tip: data.source_tip, target_tip: data.target_tip, source_current: true,
    after: null, limit: 20, next_after: null, complete: true,
    scope: 'trusted_workflow_observations', merge_permission: null,
    checks: conclusions.map((conclusion, index) => ({ id: checkId(index + 1), publisher: '33'.repeat(16),
      run_id: '44'.repeat(32), attempt_id: '55'.repeat(32), graph_root: '66'.repeat(32),
      job: `job-${index + 1}`, conclusion, evidence_sha256: '77'.repeat(32), evidence_bytes: '1024' })) };
  return { observed, reply };
}

for (const format of ['sha1', 'sha256']) {
  for (const conclusion of conclusionNames) test(`${format}: retain explicit ${conclusion} without granting merge permission`, () => {
    const { observed, reply } = fixtures(format, [conclusion]);
    const original = structuredClone(reply), result = checksReply(reply, 7, observed);
    assert.deepEqual(result.reply, original);
    assert.equal(result.reply.merge_permission, null);
    assert.equal(result.head, head);
    assert.equal(result.reply.checks[0].conclusion, conclusion);
  });

  test(`${format}: mixed successes and failures retain every original execution identity`, () => {
    const { observed, reply } = fixtures(format, conclusionNames);
    const result = checksReply(reply, 7, observed);
    assert.deepEqual(result.reply.checks.map(row => row.conclusion), conclusionNames);
    assert.deepEqual(result.reply.checks.map(row => row.id), reply.checks.map(row => row.id));
    assert.equal(Object.hasOwn(result, 'passed'), false);
    assert.equal(result.reply.merge_permission, null);
  });

  for (const [name, mutate] of [
    ['another repository', r => { r.repository_id = 'other'; }],
    ['another incarnation', r => { r.repository_incarnation = 'other'; }],
    ['another tenant', r => { r.tenant_id = 'other'; }],
    ['changed snapshot', r => { r.snapshot_token = `alg:2:${'cd'.repeat(32)}`; }],
    ['changed authority head', r => { r.source_head = 'other-head'; }],
    ['changed PR', r => { r.number = '8'; }],
    ['changed PR version', r => { r.pull_request_version = '4'; }],
    ['changed source ref', r => { r.source_ref_hex = ref('refs/heads/other'); }],
    ['changed target ref', r => { r.target_ref_hex = ref('refs/heads/other'); }],
    ['changed source commit', r => { r.source_tip = 'c'.repeat(r.source_tip.length); }],
    ['changed target commit', r => { r.target_tip = 'c'.repeat(r.target_tip.length); }],
    ['wrong Git hash domain', r => { r.object_format = format === 'sha1' ? 'sha256' : 'sha1'; }],
    ['stale source carrying success', r => { r.source_current = false; }],
    ['unavailable subject carrying success', r => { r.found = false; }],
    ['invented merge permission', r => { r.merge_permission = true; }],
    ['invented independent verification', r => { r.checks[0].independently_verified = true; }],
    ['raw evidence disclosure', r => { r.checks[0].evidence = 'private output'; }],
    ['missing evidence commitment', r => { delete r.checks[0].evidence_sha256; }],
    ['malformed evidence commitment', r => { r.checks[0].evidence_sha256 = 'z'.repeat(64); }],
    ['empty evidence', r => { r.checks[0].evidence_bytes = '0'; }],
    ['oversized evidence', r => { r.checks[0].evidence_bytes = '1048577'; }],
    ['rounded evidence size', r => { r.checks[0].evidence_bytes = 1024; }],
    ['forged publisher', r => { r.checks[0].publisher = 'unknown'; }],
    ['wrong run identity', r => { r.checks[0].run_id = 'short'; }],
    ['wrong attempt identity', r => { r.checks[0].attempt_id = 'short'; }],
    ['wrong graph identity', r => { r.checks[0].graph_root = 'short'; }],
    ['duplicate check', r => { r.checks.push(structuredClone(r.checks[0])); }],
    ['noncanonical check ID padding', r => { r.checks[0].id = checkId(1).slice(0, -1) + '1'; }],
    ['control-bearing job', r => { r.checks[0].job = 'build\nforged success'; }],
    ['unknown successful alias', r => { r.checks[0].conclusion = 'passed'; }],
    ['invented skipped success', r => { r.checks[0].conclusion = 'skipped'; }],
  ]) test(`${format}: success cannot bypass ${name}`, () => {
    const { observed, reply } = fixtures(format); mutate(reply);
    assert.throws(() => checksReply(reply, 7, observed));
  });

  test(`${format}: success preserves byte-only source references`, () => {
    const { observed, reply } = fixtures(format);
    const raw = ref('refs/heads/') + 'ff';
    observed.reply.pull_request.data.source_ref = null;
    observed.reply.pull_request.data.source_ref_hex = raw;
    reply.source_ref_hex = raw;
    assert.equal(checksReply(reply, 7, observed).reply.source_ref_hex, raw);
  });

  test(`${format}: successful observations remain readable for a merge-only subject`, () => {
    const { observed, reply } = fixtures(format), row = observed.reply.pull_request, data = row.data;
    row.data = null; row.state = 'merged'; row.merge_only = true;
    row.merge = { ...data, target_tip_before: data.target_tip,
      base_tip: data.target_tip, merge_commit: 'c'.repeat(data.target_tip.length) };
    assert.equal(checksReply(reply, 7, observed).reply.checks[0].conclusion, 'success');
  });

  test(`${format}: success paginates only under its original snapshot and cursor`, () => {
    const { observed, reply } = fixtures(format, ['success', 'failure']);
    reply.limit = 1; const second = structuredClone(reply.checks[1]); reply.checks.length = 1;
    reply.next_after = reply.checks[0].id; reply.complete = false;
    const first = checksReply(reply, 7, observed, { limit: 1 });
    const continuation = { ...reply, checks: [second], after: first.reply.next_after,
      next_after: null, complete: true };
    const next = checksReply(continuation, 7, observed, { limit: 1, after: first.reply.next_after });
    assert.equal(next.reply.checks[0].conclusion, 'failure');
    assert.equal(next.reply.merge_permission, null);
    assert.throws(() => checksReply(continuation, 7, observed, { limit: 1 }));
    continuation.checks = [reply.checks[0]];
    assert.throws(() => checksReply(continuation, 7, observed, { limit: 1, after: first.reply.next_after }));
  });
}

async function peer(t, handle) {
  const requests = [];
  const server = createServer((request, response) => {
    requests.push({ url: request.url, method: request.method, headers: request.headers });
    handle(request, response);
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const transport = new Transport({ href: `http://127.0.0.1:${server.address().port}/repo/ui/pulls/`,
    cryptoImpl: webcrypto, timeoutMs: 5000 });
  t.after(() => transport.disconnect()); await transport.connect(token);
  return { transport, requests };
}
function send(response, reply) {
  response.writeHead(200, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(reply));
}

for (const format of ['sha1', 'sha256']) test(`${format}: actual HTTP transport reads success then failure without mutation headers`, async t => {
  const { observed, reply } = fixtures(format, ['success', 'failure']);
  const { transport, requests } = await peer(t, (request, response) => {
    const url = new URL(request.url, 'http://localhost');
    assert.equal(url.pathname, '/repo/api/v1/pulls/7/checks');
    assert.equal(url.searchParams.get('expected_head'), observed.head);
    assert.equal(url.searchParams.get('limit'), '1');
    const later = url.searchParams.has('after');
    send(response, { ...reply, limit: 1, checks: [reply.checks[later ? 1 : 0]],
      after: later ? reply.checks[0].id : null, next_after: later ? null : reply.checks[0].id, complete: later });
  });
  let after = null; const conclusions = [];
  do {
    const query = new URLSearchParams({ expected_head: observed.head, limit: '1' });
    if (after !== null) query.set('after', after);
    const response = await transport.request(`pulls/7/checks?${query}`, { statuses: [200, 404] });
    const checked = checksReply(response.value, 7, observed, { limit: 1, after });
    assert.equal(checked.reply.merge_permission, null);
    conclusions.push(checked.reply.checks[0].conclusion); after = checked.reply.next_after;
  } while (after !== null);
  assert.deepEqual(conclusions, ['success', 'failure']); assert.equal(requests.length, 2);
  for (const request of requests) {
    assert.equal(request.method, 'GET');
    assert.equal(request.headers.authorization, `Bearer ${token}`);
    assert.equal(request.headers['idempotency-key'], undefined);
    assert.equal(request.headers['content-type'], undefined);
    assert.equal(request.headers['content-length'], undefined);
  }
});

test('check reads retain cancellation even when the peer has not finished its response', async t => {
  let received;
  const started = new Promise(resolve => { received = resolve; });
  const { transport, requests } = await peer(t, (_, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.write('{'); received();
  });
  const pending = transport.request(`pulls/7/checks?expected_head=${head}`, { statuses: [200, 404] });
  const refused = assert.rejects(pending);
  await started; transport.cancelReads(); await refused;
  assert.equal(requests.length, 1); assert.equal(transport.connected, true);
});

test('checks cannot be changed into a publication by method, body, key or lifecycle flags', async t => {
  const { transport, requests } = await peer(t, (_, response) => send(response, {}));
  for (const option of [{ method: 'POST' }, { body: 'approve=true' }, { key: 'write-key' },
    { read: false }, { binary: true }]) {
    await assert.rejects(transport.request('pulls/7/checks', { statuses: [200, 404], ...option }), /read-only/);
  }
  assert.equal(requests.length, 0);
});
