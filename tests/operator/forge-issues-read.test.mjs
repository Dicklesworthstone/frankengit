import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, rm, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { runIssueRead, issueReadOptions } from '../../scripts/lib/forge-issue-reader.mjs';
import { issueArguments, runIssueCommand } from '../../scripts/forge_issues.mjs';

const tenant = '11'.repeat(16), repository = '22'.repeat(16), actor = '33'.repeat(16);
const token = 'a'.repeat(64), head = 'alg:2:' + 'ab'.repeat(32);
const row = n => ({ number: n, version: 1, title: `issue ${n}`, body: n === 5 ? 'find needle' : 'other', labels: ['bug'],
  state: 'open', opened_by: actor, last_actor: actor, comments: 0 });
// Simulated native replies over real sockets. All validation and request
// construction belongs to the unchanged shipped client, not a fake client.
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-issue-read-'));
  const tokenFile = join(root, 'token'); await writeFile(tokenFile, token, { mode: 0o600 });
  const f = { root, tokenFile, calls: [], mutate: () => {}, delay: 0 };
  const server = createServer(async (req, res) => {
    let body = ''; for await (const b of req) body += b;
    const url = new URL(req.url, 'http://localhost'), params = req.method === 'POST' ? new URLSearchParams(body) : url.searchParams;
    const call = { path: url.pathname, method: req.method, params, key: req.headers['idempotency-key'], authorization: req.headers.authorization };
    f.calls.push(call);
    const common = { schema_version: 1, tenant_id: tenant, repository_id: repository, snapshot_token: head };
    const limit = Number(params.get('limit')), after = Number(params.get(url.pathname.endsWith('/1') ? 'after_version' : 'after'));
    let result;
    if (url.pathname === '/repo/api/v1/issues') {
      const issues = [1, 2, 3, 4, 5].filter(n => n > after).slice(0, limit).map(row);
      result = { ...common, type: 'issue_page', after, limit, issues, next_after: (issues.at(-1)?.number ?? 5) < 5 ? issues.at(-1).number : null };
    } else if (url.pathname === '/repo/api/v1/issues/1') {
      const issue = { ...row(1), version: 5, comments: 4 };
      const events = [1, 2, 3, 4, 5].filter(n => n > after).slice(0, limit).map(version => ({ version, actor,
        action: version === 1 ? { name: 'open', title: issue.title, body: issue.body, labels: issue.labels } : { name: 'comment', body: `comment ${version}` } }));
      result = { ...common, type: 'issue_history', after_version: after, limit, found: true, issue, events,
        next_after_version: (events.at(-1)?.version ?? 5) < 5 ? events.at(-1).version : null };
    } else if (url.pathname === '/repo/api/v1/issues/search') {
      const max_scan = Number(params.get('max_scan')), scanned = Math.min(max_scan, 5 - after);
      const end = after + scanned, issues = end === 5 ? [row(5)] : [];
      result = { ...common, type: 'issue_search_page', scope: 'repository_issues', refs_changed: false, transaction_created: false,
        query: { state: params.get('state') === 'all' ? null : params.get('state'), opened_by: params.get('opened_by'), text: params.get('query'),
          case_sensitive: params.get('case_sensitive') === 'true', labels: params.getAll('label'), text_scope: 'title_or_body' },
        after, limit, max_scan, issues, count: issues.length, scanned, stop_reason: end === 5 ? 'exhausted' : 'scan_limit',
        complete: end === 5, has_more_candidates: end !== 5, next_after: end === 5 ? null : end };
    } else { res.writeHead(404); res.end(); return; }
    f.mutate(result, f.calls.length);
    if (f.delay) await new Promise(resolve => setTimeout(resolve, f.delay));
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(result));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  f.href = `http://127.0.0.1:${server.address().port}/repo/ui/issues/`;
  f.options = (operation = 'list') => ({ operation, href: f.href, tenant, repository, tokenFile,
    ...(operation === 'show' ? { number: 1 } : {}), ...(operation === 'search' ? { query: { text: 'needle', labels: ['bug'] } } : {}) });
  f.flags = operation => [operation, '--url', f.href, '--tenant-id', tenant, '--repository-id', repository, '--token-file', tokenFile];
  t.after(async () => {
    assert.ok(f.calls.every(c => c.key === undefined && c.authorization === `Bearer ${token}`));
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true });
  });
  return f;
}
test('bounded list follows one snapshot and preserves exact page order without local writes', async t => {
  const f = await fixture(t), original = await readFile(f.tokenFile);
  const result = await runIssueRead({ ...f.options(), limit: 2, maxPages: 3 });
  assert.equal(result.complete, true); assert.equal(result.continuation, null); assert.equal(result.page_count, 3);
  assert.deepEqual(result.pages.flatMap(p => p.issues.map(i => i.number)), [1, 2, 3, 4, 5]);
  assert.equal(f.calls[0].params.has('expected_head'), false);
  assert.ok(f.calls.slice(1).every(c => c.params.get('expected_head') === head));
  assert.deepEqual(await readdir(f.root), ['token']); assert.deepEqual(await readFile(f.tokenFile), original);
});
test('one-page default returns explicit incomplete prefix and complete continuation identity', async t => {
  const f = await fixture(t), first = await runIssueRead({ ...f.options(), limit: 2 });
  assert.equal(first.complete, false); assert.equal(first.stop_reason, 'page_budget'); assert.equal(first.continuation.after, 2);
  assert.equal(first.continuation.expected_head, head);
  const rest = await runIssueRead({ ...f.options(), limit: 2, maxPages: 2, after: first.continuation.after, head: first.continuation.expected_head });
  assert.equal(rest.complete, true); assert.deepEqual(rest.pages.flatMap(p => p.issues.map(i => i.number)), [3, 4, 5]);
});
test('issue history keeps every event version and original expected-head pin', async t => {
  const f = await fixture(t), result = await runIssueRead({ ...f.options('show'), limit: 2, maxPages: 3 });
  assert.equal(result.complete, true); assert.deepEqual(result.pages.flatMap(p => p.events.map(e => e.version)), [1, 2, 3, 4, 5]);
  assert.deepEqual(f.calls.map(c => c.params.get('after_version')), ['0', '2', '4']);
});
test('zero-hit scan-limited search pages advance without dropping later matches', async t => {
  const f = await fixture(t), result = await runIssueRead({ ...f.options('search'), limit: 2, maxPages: 3, maxScan: 2 });
  assert.equal(result.complete, true); assert.deepEqual(result.pages.map(p => p.issues.length), [0, 0, 1]);
  assert.deepEqual(f.calls.map(c => c.params.get('after')), ['0', '2', '4']);
  assert.ok(f.calls.every(c => c.method === 'POST' && c.path.endsWith('/issues/search')));
});
test('search continuation retains exact predicate, scan budget and source', async t => {
  const f = await fixture(t), result = await runIssueRead({ ...f.options('search'), limit: 2, maxScan: 2 });
  assert.equal(result.continuation.query.text, 'needle'); assert.deepEqual(result.continuation.query.labels, ['bug']);
  assert.equal(result.continuation.max_scan, 2); assert.equal(result.continuation.expected_head, head); assert.equal(result.continuation.after, 2);
});
for (const what of ['snapshot', 'identity', 'order', 'query', 'cursor']) {
  test('later ' + what + ' disagreement refuses the whole read rather than emitting a prefix', async t => {
    const f = await fixture(t);
    f.mutate = (reply, n) => {
      if (n !== 2) return;
      if (what === 'snapshot') reply.snapshot_token = 'alg:2:' + 'cd'.repeat(32);
      if (what === 'identity') reply.repository_id = '66'.repeat(16);
      if (what === 'order') reply.issues[1].number = reply.issues[0].number;
      if (what === 'query') reply.query.text = 'other';
      if (what === 'cursor') reply.next_after = reply.after;
    };
    await assert.rejects(runIssueRead({ ...f.options(what === 'query' || what === 'cursor' ? 'search' : 'list'), limit: 2, maxPages: 3, ...(what === 'query' || what === 'cursor' ? { maxScan: 2 } : {}) }));
    assert.equal(f.calls.length, 2);
  });
}
test('response and wrapper overhead count against an independent aggregate output bound', async t => {
  const f = await fixture(t);
  await assert.rejects(runIssueRead({ ...f.options(), maxOutputBytes: 20 }), e => e.code === 'issue_read_output_limit');
  const permitted = await runIssueRead({ ...f.options(), maxOutputBytes: 10000 }); assert.equal(permitted.complete, true);
});
test('cancel between pages prevents the next request and returns no partial result', async t => {
  const f = await fixture(t), stop = new AbortController();
  await assert.rejects(runIssueRead({ ...f.options(), limit: 2, maxPages: 3, signal: stop.signal, onProgress: () => stop.abort() }));
  assert.equal(f.calls.length, 1);
});
test('one shared deadline covers multiple slow pages rather than renewing per page', async t => {
  const f = await fixture(t); f.delay = 60;
  await assert.rejects(runIssueRead({ ...f.options(), limit: 2, maxPages: 3, timeoutMs: 100 }));
  assert.ok(f.calls.length <= 2); f.delay = 0;
  assert.equal((await runIssueRead({ ...f.options(), limit: 2, maxPages: 3 })).complete, true);
});
test('caller cannot mutate selected query or target between pages', async t => {
  const f = await fixture(t), o = { ...f.options('search'), limit: 2, maxScan: 2, maxPages: 3 };
  o.onProgress = () => { o.query.text = 'substitute'; o.query.labels.push('private'); o.href = 'http://other.invalid/'; };
  const result = await runIssueRead(o); assert.equal(result.complete, true);
  assert.ok(f.calls.every(c => c.params.get('query') === 'needle' && c.params.getAll('label').join() === 'bug'));
});
test('strict read grammar rejects mutations, unpinned cursors and oversized budgets before I/O', async t => {
  const f = await fixture(t);
  for (const patch of [{ after: 1 }, { maxPages: 101 }, { maxOutputBytes: 8388609 }, { limit: 0 }, { record: 'x' },
    { number: 1 }, { query: {} }, { maxScan: 1 }, { expectedVersion: 0 }]) assert.throws(() => issueReadOptions({ ...f.options(), ...patch }));
  for (const tail of [['--record', 'x'], ['--title', 'x'], ['--body-file', '/missing'], ['--label', 'bug'], ['--case-sensitive'], ['--expected-version', '0']]) {
    assert.throws(() => issueArguments([...f.flags('list'), ...tail]));
  }
  assert.throws(() => issueArguments([...f.flags('search'), '--case-sensitive'])); assert.equal(f.calls.length, 0);
});
test('CLI makes complete vs partial reads observable without a mutation record', async t => {
  const f = await fixture(t);
  const prefix = await runIssueCommand([...f.flags('list'), '--limit', '2']); assert.equal(prefix.exitCode, 4);
  const complete = await runIssueCommand([...f.flags('show'), '--number', '1', '--limit', '2', '--max-pages', '3']); assert.equal(complete.exitCode, 0);
  assert.equal(JSON.parse(complete.text).page_count, 3); assert.deepEqual(await readdir(f.root), ['token']);
});
test('real CLI process completes a paged authenticated search', async t => {
  const f = await fixture(t), child = spawn(process.execPath, [resolve('scripts/forge_issues.mjs'), ...f.flags('search'), '--query', 'needle',
    '--label', 'bug', '--limit', '2', '--max-pages', '3', '--max-scan', '2']);
  let stdout = '', stderr = ''; child.stdout.on('data', b => stdout += b); child.stderr.on('data', b => stderr += b);
  const code = await new Promise((resolve, reject) => { child.on('error', reject); child.on('close', resolve); });
  assert.equal(code, 0, stderr); assert.equal(JSON.parse(stdout).pages.at(-1).issues[0].number, 5); assert.ok(!stdout.includes(token));
});
