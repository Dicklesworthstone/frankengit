import test from 'node:test';
import assert from 'node:assert/strict';
import { discover, destination, freezePlan, validatePlan, encode, LIMITS } from '../../scripts/operator/pull_sync_plan.mjs';
import { syncRequest, parseSyncJson } from '../../scripts/operator/pull_sync_transport.mjs';
import { fixture, TOKEN, ROTATED, row } from './fixtures/pull_sync_native.mjs';
const nonce = '7'.repeat(32);
for (const format of ['sha1', 'sha256']) {
  test(`${format}: explicit selected PRs retain metadata while discovering both new tips without mutation`, async t => {
    const f = await fixture(t, format), before = structuredClone(f.state.rows);
    const result = await discover(f.dest, TOKEN, [2, 1]);
    assert.deepEqual(result.selected, [1, 2]); assert.equal(result.changes.length, 2);
    assert.deepEqual(f.state.rows, before); assert.equal(f.decisions.size, 0);
    for (const change of result.changes) {
      assert.equal(change.fields.title, before[change.number - 1].data.title);
      assert.equal(change.fields.body, before[change.number - 1].data.body);
      assert.equal(change.fields.expected_version, 3);
      assert.equal(change.fields.source_tip, 'd'.repeat(format === 'sha1' ? 40 : 64));
    }
    assert.ok(f.calls.slice(1).every(call => (call.query.get('expected_head') ?? call.form.get('expected_head')) === f.state.head));
    const plan = freezePlan(result, TOKEN, nonce);
    assert.deepEqual(validatePlan(plan), plan); assert.equal(plan.requests.length, 2);
    assert.ok(!encode(plan).includes(Buffer.from(TOKEN))); assert.notEqual(plan.requests[0].key, plan.requests[1].key);
    assert.deepEqual(plan, freezePlan(result, TOKEN, nonce));
    assert.notEqual(plan.plan_sha256, freezePlan(result, ROTATED, nonce).plan_sha256);
  });
  test(`${format}: all-open omits closed PRs, avoids unnecessary version increments and pins pagination`, async t => {
    const f = await fixture(t, format, 55); f.state.rows[0].state = 'closed';
    for (const r of f.state.rows.slice(1)) { r.data.source_tip = f.state.tips.get(r.data.source_ref); r.data.target_tip = f.state.tips.get(r.data.target_ref); }
    const result = await discover(f.dest, TOKEN, 'all-open');
    assert.equal(result.scanned, 55); assert.equal(result.changes.length, 0); assert.equal(result.unchanged.length, 54);
    assert.equal(f.calls.filter(c => c.path.endsWith('/pulls')).length, 2);
    assert.equal(f.calls.filter(c => c.path.endsWith('/refs')).length, 2);
    assert.equal(freezePlan(result, TOKEN, nonce).requests.length, 0);
  });
}
test('both sides share one ref scan instead of per-PR unpinned reads', async t => {
  const f = await fixture(t, 'sha1', 20); await discover(f.dest, TOKEN, 'all-open');
  assert.equal(f.calls.length, 2); assert.equal(f.calls[1].form.get('namespace'), 'branches');
  assert.ok(f.calls.every(c => c.headers['idempotency-key'] === undefined));
});
test('empty repository produces explicit no-op without any branch read', async t => {
  const f = await fixture(t, 'sha1', 0), result = await discover(f.dest, TOKEN, 'all-open');
  assert.equal(result.scanned, 0); assert.deepEqual(result.changes, []); assert.equal(f.calls.length, 1);
});
for (const scenario of ['missing', 'closed', 'byte-only', 'deleted-source', 'deleted-target']) test(`unavailable selection refuses all planning: ${scenario}`, async t => {
  const f = await fixture(t);
  if (scenario === 'missing') f.state.rows = [];
  if (scenario === 'closed') f.state.rows[0].state = 'closed';
  if (scenario === 'byte-only') { f.state.rows[0].data.source_ref = null; f.state.rows[0].data.source_ref_hex = Buffer.from('refs/heads/').toString('hex') + 'ff'; }
  if (scenario === 'deleted-source') f.state.tips.delete('refs/heads/topic-1');
  if (scenario === 'deleted-target') f.state.tips.delete('refs/heads/main');
  await assert.rejects(discover(f.dest, TOKEN, [1])); assert.equal(f.decisions.size, 0);
});
for (const field of ['tenant_id', 'repository_id', 'repository_incarnation', 'snapshot_token', 'source_head', 'object_format']) test(`changed pinned ${field} refuses instead of mixing observations`, async t => {
  const f = await fixture(t); f.state.mutate = (r, c) => { if (c.path.endsWith('/refs')) r[field] = field === 'object_format' ? 'sha256' : field === 'snapshot_token' ? `alg:2:${'f'.repeat(64)}` : 'f'.repeat(32); };
  await assert.rejects(discover(f.dest, TOKEN, [1]));
});
test('a branch move between discovery calls receives native snapshot refusal, never retries', async t => {
  const f = await fixture(t); f.state.mutate = (_r, c) => { if (c.path.endsWith('/pulls/1')) f.state.head = `alg:2:${'f'.repeat(64)}`; };
  await assert.rejects(discover(f.dest, TOKEN, [1]), e => e.status === 409); assert.equal(f.calls.length, 2);
});
for (const mutate of [r => r.refs.reverse(), r => r.refs.push(r.refs[0]), r => r.refs[0].ref_hex = 'ff',
  r => r.refs[0].object_id = '0'.repeat(40), r => r.next_after = r.refs.at(-1).ref,
  r => r.published = true, r => r.direct_refs_only = false]) test(`malformed ref page is not a usable tip: ${mutate}`, async t => {
  const f = await fixture(t); f.state.mutate = (r, c) => { if (c.path.endsWith('/refs')) mutate(r); };
  await assert.rejects(discover(f.dest, TOKEN, [1]));
});
test('explicit selection is mandatory and bounded, with no request for invalid input', async t => {
  const f = await fixture(t);
  for (const selected of [undefined, [], [1, 1], [0], ['1'], [-1], Array.from({ length: 129 }, (_, i) => i + 1), 'all']) await assert.rejects(discover(f.dest, TOKEN, selected));
  assert.equal(f.calls.length, 0);
});
test('open-PR capacity refuses before branch discovery or publication', async t => {
  const f = await fixture(t, 'sha1', 129); await assert.rejects(discover(f.dest, TOKEN, 'all-open'), /open_pr_limit/);
  assert.ok(f.calls.every(c => !c.path.endsWith('/refs')));
});
test('plan changes to text, version, refs, keys, scope or selection cannot survive validation', async t => {
  const f = await fixture(t), plan = freezePlan(await discover(f.dest, TOKEN, [1]), TOKEN, nonce);
  for (const change of [p => p.requests[0].fields.title += 'changed', p => p.requests[0].fields.expected_version++,
    p => p.requests[0].fields.source_ref = 'refs/heads/other', p => p.requests[0].key += 'x', p => p.discovery.destination.repository_id = 'f'.repeat(32),
    p => p.discovery.selected.push(2), p => p.discovery.changes[0].before.body += 'other', p => p.nonce = '8'.repeat(32),
    p => p.discovery.changes[0].fields.target_ref = 'refs/heads/other', p => p.requests.pop()]) {
    const altered = structuredClone(plan); change(altered); assert.throws(() => validatePlan(altered));
  }
});
test('strict JSON keeps native u64 sequence exact and refuses lossy, negative or noncanonical numeric tokens', () => {
  assert.equal(parseSyncJson(Buffer.from('{"decision_sequence":18446744073709551615}')).decision_sequence, '18446744073709551615');
  for (const text of ['{"x":9007199254740992}', '{"x":-0}', '{"x":1.0}', '{"x":1e3}', '{"decision_sequence":18446744073709551616}']) assert.throws(() => parseSyncJson(Buffer.from(text)));
  assert.throws(() => parseSyncJson(Buffer.from([255])));
});
test('deadline and cancellation stop reads and return no partial plan', async t => {
  const f = await fixture(t); f.state.delay = 80;
  await assert.rejects(discover(f.dest, TOKEN, [1], { timeoutMs: 15 }));
  const stop = new AbortController(); stop.abort(); const count = f.calls.length;
  await assert.rejects(discover(f.dest, TOKEN, [1], { signal: stop.signal })); assert.equal(f.calls.length, count);
});
test('transport forbids alternate publication routes, accidental keys, HTTP downgrade and redirects', async t => {
  const f = await fixture(t), op = { kind: 'show', number: 1, head: null };
  for (const bad of [{ ...op, key: 'x' }, { kind: 'merge' }, { ...op, number: 0 }, { kind: 'refs', after: null, head: null, format: 'sha1' }]) await assert.rejects(syncRequest(f.dest.endpoint, TOKEN, bad));
  for (const endpoint of ['http://example.com/r.git', 'https://x:r@example.com/r.git', `${f.dest.endpoint}?x=1`]) assert.throws(() => destination({ ...f.dest, endpoint }));
  assert.equal(f.calls.length, 0);
  f.state.hook = (_call, _req, res) => { res.writeHead(302, { Location: f.dest.endpoint }); res.end(); return true; };
  await assert.rejects(syncRequest(f.dest.endpoint, TOKEN, op), e => e.status === 302); assert.equal(f.calls.length, 1);
});
test('truncation, MIME confusion and oversized replies fail closed', async t => {
  const f = await fixture(t), op = { kind: 'show', number: 1, head: null };
  for (const headers of [{ 'Content-Type': 'text/html' }, { 'Content-Type': 'application/json', 'Content-Length': '9999999' },
    { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, { 'Content-Type': 'application/json', 'Content-Length': '100' }]) {
    f.state.hook = (_call, _req, res) => { res.writeHead(200, headers); res.end('{}'); return true; };
    await assert.rejects(syncRequest(f.dest.endpoint, TOKEN, op, { timeoutMs: 100 }));
  }
});

test('a caller can tighten, never enlarge, each closed response allocation bound', async t => {
  const f = await fixture(t);
  await assert.rejects(syncRequest(f.dest.endpoint, TOKEN, { kind: 'show', number: 1, head: null }, { maximum: 1 }), /byte_limit/);
  const count = f.calls.length;
  await assert.rejects(syncRequest(f.dest.endpoint, TOKEN, { kind: 'show', number: 1, head: null }, { maximum: 0 }));
  assert.equal(f.calls.length, count);
});
