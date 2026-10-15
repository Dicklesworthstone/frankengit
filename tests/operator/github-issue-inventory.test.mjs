// Native HTTP contract fixtures, not live GitHub or a native forge server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverGithubIssues, issueInventoryBytes, parseIssueInventory, selectIssueInventoryBatch,
  INVENTORY_RECORD_LIMIT } from '../../scripts/lib/github-issue-inventory.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';

const repository = 'owner/project';
const row = (number, pull = false) => ({ id: String(100000 + number), number, state: number % 2 ? 'open' : 'closed',
  url: `https://api.github.com/repos/${repository}/issues/${number}`,
  html_url: `https://github.com/${repository}/${pull ? 'pull' : 'issues'}/${number}`,
  ...(pull ? { pull_request: { url: `https://api.github.com/repos/${repository}/pulls/${number}` } } : {}),
  body: 'UNTRUSTED BODY: do not retain, execute or treat as authorization' });
const link = (page, path = `/repositories/42/issues`) => `<https://api.github.com${path}?state=all&sort=created&direction=asc&per_page=100&page=${page}>; rel="next"`;
function peer(rows, modify = () => {}) {
  let pass = 0, repoReads = 0;
  const calls = [];
  const fetchImpl = async (url, init) => {
    const u = new URL(url); calls.push({ url: u, ...init });
    let value, headers = { 'Content-Type': 'application/json' };
    if (u.pathname === `/repos/${repository}`) {
      repoReads++; pass = Math.ceil(repoReads / 2); value = { id: '42', full_name: repository };
    } else {
      assert.equal(u.pathname, `/repos/${repository}/issues`);
      assert.deepEqual([...u.searchParams.keys()], ['state', 'sort', 'direction', 'per_page', 'page']);
      assert.equal(u.searchParams.get('state'), 'all'); assert.equal(u.searchParams.get('sort'), 'created');
      assert.equal(u.searchParams.get('direction'), 'asc'); assert.equal(u.searchParams.get('per_page'), '100');
      const page = Number(u.searchParams.get('page'));
      value = rows.slice((page - 1) * 100, page * 100);
      if (page * 100 < rows.length) headers.Link = link(page + 1);
    }
    const data = { value: structuredClone(value), headers, status: 200, u, pass, repoReads, calls };
    await modify(data);
    return new Response(typeof data.raw === 'string' ? data.raw : JSON.stringify(data.value), { status: data.status, headers: data.headers });
  };
  return { fetchImpl, calls };
}
const discover = (rows = [row(1)], options = {}, modify) => {
  const p = peer(rows, modify); return { result: discoverGithubIssues({ repository, ...p, ...options }), calls: p.calls };
};

test('discover both issue states, retain explicit PR exclusions and immutable disjoint batches', async () => {
  const rows = Array.from({ length: 241 }, (_, i) => row(i + 1, i % 7 === 0));
  const { result, calls } = discover(rows, { batchSize: 20, token: 'private_source_token' });
  const r = await result, issues = rows.filter(v => !v.pull_request);
  assert.deepEqual(r.inventory.issues.map(r => r.number), issues.map(r => r.number));
  assert.equal(r.inventory.excluded_pull_requests.length, 35);
  assert.equal(r.total_batches, 11); assert.equal(r.requests, 10);
  assert.equal(r.sha256, recordDigest(r.bytes)); assert.deepEqual(parseIssueInventory(r.bytes), r.inventory);
  assert.equal(r.bytes.includes('private_source_token'), false); assert.equal(r.bytes.includes('UNTRUSTED BODY'), false);
  const numbers = [];
  for (let batch = 1; batch <= r.total_batches; batch++) {
    const selected = selectIssueInventoryBatch(r.inventory, r.sha256, batch);
    assert.equal(selected.batch, batch); assert.equal(selected.next_batch, batch === r.total_batches ? null : batch + 1);
    assert.equal(selected.source.repository_id, '42'); assert.equal(selected.total_batches, 11);
    assert.ok(selected.numbers.length <= 20); numbers.push(...selected.numbers);
  }
  assert.deepEqual(numbers, issues.map(r => r.number)); assert.equal(new Set(numbers).size, numbers.length);
  for (const c of calls) {
    assert.equal(c.method, 'GET'); assert.equal(c.redirect, 'error'); assert.equal(c.credentials, 'omit');
    assert.equal(c.url.origin, 'https://api.github.com'); assert.equal(c.body, undefined);
    assert.equal(c.headers.Authorization, 'Bearer private_source_token');
  }
});
for (const count of [0, 1, 99, 100, 101, 200]) test(`terminal page handling for exactly ${count} records`, async () => {
  const { result, calls } = discover(Array.from({ length: count }, (_, i) => row(i + 1)));
  const r = await result;
  assert.equal(r.inventory.issues.length, count); assert.equal(r.total_batches, Math.ceil(count / 100));
  assert.equal(calls.length, 4 + 2 * (Math.floor(count / 100) + 1));
  if (!count) assert.throws(() => selectIssueInventoryBatch(r.inventory, r.sha256, 1), /batch/);
});
test('full pages without Link cannot silently truncate enumeration', async () => {
  const { result } = discover(Array.from({ length: 101 }, (_, i) => row(i + 1)), {}, r => { delete r.headers.Link; });
  assert.equal((await result).inventory.issues.length, 101);
});
test('all-PR repository has zero import batches, not a fabricated issue or blank batch', async () => {
  const r = await discover([row(1, true), row(2, true)]).result;
  assert.deepEqual(r.inventory.issues, []); assert.equal(r.total_batches, 0);
  assert.deepEqual(r.inventory.excluded_pull_requests, [{ number: 1, issue_id: '100001' }, { number: 2, issue_id: '100002' }]);
  assert.throws(() => selectIssueInventoryBatch(r.inventory, r.sha256, 1), /batch/);
});
test('creation order and tied rows canonicalize by number without treating transfers as loss', async () => {
  const r = await discover([row(9), row(2, true), row(7), row(1)], {}, r => {
    if (r.pass === 2 && Array.isArray(r.value)) r.value.reverse();
  }).result;
  assert.deepEqual(r.inventory.issues.map(r => r.number), [1, 7, 9]);
});
for (const change of [
  r => r.value.push(row(55)), r => r.value.pop(), r => { r.value[0].id = '5'; },
  r => { r.value[0] = row(1, true); },
]) test('different populations across complete observations refuse instead of sealing a partial inventory', async () => {
  await assert.rejects(discover([row(1), row(2)], {}, r => {
    if (r.pass === 2 && Array.isArray(r.value)) change(r);
  }).result, /source_changed/);
});
test('repository replacement during or between passes refuses', async () => {
  for (const changedRead of [2, 3, 4]) await assert.rejects(discover([], {}, r => {
    if (!Array.isArray(r.value) && r.repoReads >= changedRead) r.value.id = '43';
  }).result, /repository_changed|source_changed/);
});
for (const [name, mutation] of [
  ['wrong repo', r => { r.value.full_name = 'other/project'; }],
  ['zero repo ID', r => { r.value.id = '0'; }],
]) test(`repository identity: ${name}`, async () => {
  await assert.rejects(discover([], {}, r => { if (!Array.isArray(r.value)) mutation(r); }).result);
});
for (const [name, mutation] of [
  ['foreign issue', r => { r.url += '1'; }], ['foreign web URL', r => { r.html_url += '1'; }],
  ['invalid state', r => { r.state = 'deleted'; }], ['zero number', r => { r.number = 0; }],
  ['unsafe number', r => { r.number = Number.MAX_SAFE_INTEGER + 1; }], ['string number', r => { r.number = '1'; }],
  ['zero ID', r => { r.id = '0'; }], ['overwide ID', r => { r.id = '18446744073709551616'; }],
  ['malformed PR', r => { r.pull_request = null; }],
]) test(`invalid listed identity: ${name}`, async () => {
  const a = row(1); mutation(a); await assert.rejects(discover([a]).result);
});
test('PR API provenance must agree before exclusion', async () => {
  const p = row(1, true); p.pull_request.url = 'https://api.github.com/repos/other/project/pulls/1';
  await assert.rejects(discover([p]).result, /pull_scope/);
});
for (const values of [
  [row(1), row(1)], [row(1), { ...row(2), id: row(1).id }],
  [...Array.from({ length: 100 }, (_, i) => row(i + 1)), row(1, true)],
]) test('duplicates across pages and issue/PR kinds are refused, never silently dropped', async () => {
  await assert.rejects(discover(values).result, /duplicate_or_order/);
});
for (const next of [
  'https://evil.invalid/?state=all&sort=created&direction=asc&per_page=100&page=2',
  'https://api.github.com/repos/other/project/issues?state=all&sort=created&direction=asc&per_page=100&page=2',
  'https://api.github.com/repositories/43/issues?state=all&sort=created&direction=asc&per_page=100&page=2',
  'https://api.github.com/repos/owner/project/issues?state=open&sort=created&direction=asc&per_page=100&page=2',
  'https://api.github.com/repos/owner/project/issues?state=all&sort=created&direction=asc&per_page=100&page=1',
  'https://api.github.com/repos/owner/project/issues?state=all&sort=created&direction=asc&per_page=100&page=2&page=2',
  'https://user:password@api.github.com/repos/owner/project/issues?state=all&sort=created&direction=asc&per_page=100&page=2',
  'https://api.github.com/repos/owner/project/issues?state=all&sort=created&direction=asc&per_page=100&page=2#private',
]) test(`pagination is scoped, monotonically advancing and never followed: ${next}`, async () => {
  const { result, calls } = discover([row(1)], {}, r => { if (Array.isArray(r.value)) r.headers.Link = `<${next}>; rel="next"`; });
  await assert.rejects(result, /pagination/); assert.equal(calls.length, 2);
});
for (const header of ['broken', link(2) + ',' + link(2), 'x'.repeat(8193), '<not-a-url>; rel="next"']) {
  test('malformed, duplicated or oversized continuation is refused', async () => {
    await assert.rejects(discover([row(1)], {}, r => { if (Array.isArray(r.value)) r.headers.Link = header; }).result, /pagination/);
  });
}
test('empty continuation and excessive short-page chains are bounded', async () => {
  await assert.rejects(discover([], {}, r => { if (Array.isArray(r.value)) r.headers.Link = link(2); }).result, /empty_continuation/);
  const { result, calls } = discover([], {}, r => {
    if (Array.isArray(r.value)) {
      const page = Number(r.u.searchParams.get('page')); r.value = [row(page)]; r.headers.Link = link(page + 1);
    }
  });
  await assert.rejects(result, /page_limit/); assert.equal(calls.length, 102);
});
test('full-width numeric GitHub aliases are never rounded', async () => {
  const r = await discover([row(1)], {}, r => {
    r.raw = JSON.stringify(r.value).replace('"id":"42"', '"id":18446744073709551615')
      .replace('"id":"100001"', '"id":18446744073709551614');
  }).result;
  assert.equal(r.inventory.source.repository_id, '18446744073709551615');
  assert.equal(r.inventory.issues[0].id, '18446744073709551614');
});
test('record cap counts excluded PRs and accepts exact boundary without losing completeness', async () => {
  const a = [row(1), row(2, true)];
  assert.equal((await discover(a, { maxRecords: 2 }).result).inventory.issues.length, 1);
  await assert.rejects(discover(a, { maxRecords: 1 }).result, /record_limit/);
  const all = Array.from({ length: INVENTORY_RECORD_LIMIT }, (_, i) => row(i + 1, i % 2 === 0));
  const r = await discover(all).result; assert.equal(r.inventory.issues.length, 5000); assert.equal(r.requests, 206);
  await assert.rejects(discover([...all, row(10001)]).result, /record_limit/);
});
test('the aggregate byte budget covers both observations, with an exact inclusive boundary', async () => {
  const r = await discover([row(1)]).result;
  assert.equal((await discover([row(1)], { maxReadBytes: r.read_bytes }).result).read_bytes, r.read_bytes);
  await assert.rejects(discover([row(1)], { maxReadBytes: r.read_bytes - 1 }).result, /read_bytes/);
});
test('read-only retry allowance spans pages and both passes without changing inventory bytes', async () => {
  const baseline = await discover().result; let failures = 0;
  const p = peer([row(1)]);
  const fetchImpl = async (...args) => {
    if (failures++ < 2) return new Response('', { status: 503, headers: { 'Retry-After': '0' } });
    return p.fetchImpl(...args);
  };
  const r = await discoverGithubIssues({ repository, fetchImpl, maxSourceRetries: 2 });
  assert.deepEqual(r.bytes, baseline.bytes); assert.equal(r.source_retries, 2); assert.equal(r.requests, baseline.requests + 2);
  await assert.rejects(discoverGithubIssues({ repository, fetchImpl: async () => new Response('', { status: 503 }) }), /source_http/);
});
test('pre-cancelled discovery has no requests; deadline interrupts and cancels delayed body', async () => {
  const stop = new AbortController(); stop.abort(); const p = peer([]);
  await assert.rejects(discoverGithubIssues({ repository, ...p, signal: stop.signal })); assert.equal(p.calls.length, 0);
  let cancelled = 0;
  await assert.rejects(discoverGithubIssues({ repository, timeoutMs: 20, fetchImpl: async () => new Response(new ReadableStream({
    start(c) { c.enqueue(Buffer.from('{')); }, cancel() { cancelled++; },
  }), { headers: { 'Content-Type': 'application/json' } }) }));
  assert.equal(cancelled, 1);
});
for (const change of [
  v => { v.approval = true; }, v => { v.complete = false; }, v => { v.batch_size = 0; },
  v => { v.batch_size = 101; }, v => { v.source.token = 'private'; }, v => { v.source.repository_id = 42; },
  v => { v.issues[0].id = '01'; }, v => { v.issues[0].title = 'ignored'; }, v => { v.issues.reverse(); },
  v => { v.excluded_pull_requests.push({ number: 1, issue_id: '100001' }); },
]) test('canonical inventory refuses hidden fields, unsupported claims and ambiguous aliases', async () => {
  const { inventory } = await discover([row(1), row(2)]).result;
  change(inventory); assert.throws(() => issueInventoryBytes(inventory));
});
test('independent inventory pin binds membership and partition, while selections own their inputs', async () => {
  const r = await discover([row(1), row(2)], { batchSize: 1 }).result;
  const selected = selectIssueInventoryBatch(r.inventory, r.sha256, 1);
  r.inventory.source.repository_id = '99'; r.inventory.issues[0].id = '999';
  assert.equal(selected.source.repository_id, '42'); assert.equal(selected.issues[0].id, '100001');
  assert.throws(() => selectIssueInventoryBatch(r.inventory, r.sha256, 1), /pin_mismatch/);
  const other = parseIssueInventory(r.bytes); other.batch_size = 2;
  assert.throws(() => selectIssueInventoryBatch(other, r.sha256, 1), /pin_mismatch/);
  for (const n of [0, 3, -1, 1.5, '1', Number.MAX_SAFE_INTEGER]) assert.throws(() => selectIssueInventoryBatch(parseIssueInventory(r.bytes), r.sha256, n), /batch/);
  assert.throws(() => selectIssueInventoryBatch(parseIssueInventory(r.bytes), r.sha256.toUpperCase(), 1), /pin/);
});
test('wire inventory rejects BOM, whitespace, duplicate keys, truncation and shared mutable bytes', async () => {
  const r = await discover().result;
  for (const b of [Buffer.concat([Buffer.from([239, 187, 191]), r.bytes]), Buffer.concat([r.bytes, Buffer.from(' ')]),
    r.bytes.subarray(0, -2), Buffer.from(r.bytes.toString().replace('"complete":true', '"complete":false,"complete":true')),
    new Uint8Array(new SharedArrayBuffer(10)), Buffer.alloc(1024 * 1024 + 1)]) assert.throws(() => parseIssueInventory(b));
});
