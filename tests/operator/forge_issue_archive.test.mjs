import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, readFile, readdir, rm, chmod, rename, mkdir, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportIssueArchive, inspectIssueArchive } from '../../scripts/lib/forge-issue-archive.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';

const tenant = '1'.repeat(32), repository = '2'.repeat(32), token = 'a'.repeat(64);
const actor = '3'.repeat(32), other = '4'.repeat(32), assignee = '5'.repeat(32);
const head = 'alg:2:' + '6'.repeat(64), sourceHead = 'head-immutable-1';
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const event = (version, who, name, fields = {}) => ({ version, actor: who, action: { name, ...fields } });
const data = () => [
  { issue: { number: 1, version: 5, title: 'Native title', body: 'New body <script>data</script>\r\n尾',
    labels: [], state: 'closed', opened_by: actor, last_actor: actor, comments: 1, assignees: [assignee] },
    events: [event(1, actor, 'open', { title: 'Native title', body: 'Old body', labels: ['label'] }),
      event(2, other, 'comment', { body: 'Original comment\n\u202e preserved' }),
      event(3, other, 'edit', { body: 'New body <script>data</script>\r\n尾', labels: [] }),
      event(4, other, 'assign', { assignees: [assignee] }), event(5, actor, 'close')] },
  { issue: { number: 9007199254740991, version: 1, title: 'Largest exact issue number', body: '',
    labels: [], state: 'open', opened_by: other, last_actor: other, comments: 0, assignees: [] },
    events: [event(1, other, 'open', { title: 'Largest exact issue number', body: '', labels: [] })] },
];
export async function fixture(t, { items = data(), change = null, handle = null } = {}) {
  const parent = await mkdtemp(join(tmpdir(), 'fg-archive-')); await chmod(parent, 0o700);
  const tokenFile = join(parent, 'token'); await writeFile(tokenFile, token + '\n', { mode: 0o600 });
  const calls = [];
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://127.0.0.1'), after = Number(url.searchParams.get('after') ?? url.searchParams.get('after_version') ?? 0);
      const limit = Number(url.searchParams.get('limit'));
      const id = url.pathname.match(/\/issues\/(\d+)$/)?.[1] ?? null;
      calls.push({ method: req.method, url, authorization: req.headers.authorization, key: req.headers['idempotency-key'] });
      if (handle && await handle(req, res, calls)) return;
      assert.equal(req.method, 'GET'); assert.equal(req.headers.authorization, 'Bearer ' + token);
      assert.equal(req.headers['idempotency-key'], undefined);
      assert.equal(url.searchParams.has('render'), false);
      if (calls.length > 1) assert.equal(url.searchParams.get('expected_head'), head);
      const header = { schema_version: 1, tenant_id: tenant, repository_id: repository, snapshot_token: head, source_head: sourceHead };
      let body;
      if (id === null) {
        const remaining = items.filter(row => row.issue.number > after), selected = remaining.slice(0, limit);
        body = { type: 'issue_page', ...header, after, limit, issues: selected.map(row => structuredClone(row.issue)),
          next_after: remaining.length > limit ? selected.at(-1).issue.number : null };
      } else {
        const item = items.find(row => row.issue.number === Number(id));
        const remaining = item.events.filter(row => row.version > after);
        body = { type: 'issue_history', ...header, found: true, requested_number: Number(id), issue: structuredClone(item.issue),
          after_version: after, limit, events: structuredClone(remaining.slice(0, limit)),
          next_after_version: remaining.length > limit ? after + limit : null };
      }
      const status = await change?.(body, calls.length, { parent, req, res });
      res.writeHead(status ?? 200, { 'Content-Type': 'application/json' }); res.end(encode(body));
    } catch (error) { res.writeHead(500); res.end(String(error)); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(parent, { recursive: true, force: true }); });
  const options = { workdir: join(parent, 'archive'), href: `http://127.0.0.1:${server.address().port}/repo/ui/issues/`,
    tenant, repository, tokenFile, pageSize: 1 };
  return { parent, options, calls, server };
}
async function noRoot(options) { await assert.rejects(readFile(join(options.workdir, 'archive.json')), { code: 'ENOENT' }); }
async function mutateRoot(options, edit) {
  const path = join(options.workdir, 'archive.json'); const value = JSON.parse(await readFile(path)); edit(value);
  const bytes = encode(value); await writeFile(path, bytes); return recordDigest(bytes);
}

test('real HTTP client exports every issue, raw comment and history at one pinned snapshot', async t => {
  const f = await fixture(t), result = await exportIssueArchive(f.options);
  assert.equal(result.complete, true); assert.equal(result.issues, 2); assert.equal(result.events, 6);
  assert.equal(result.pages, 8); assert.equal(result.requests, 8); assert.equal(result.canonical_backup, false);
  const inspected = await inspectIssueArchive({ workdir: f.options.workdir, confirm: result.archive_sha256 });
  assert.equal(inspected.archive_sha256, result.archive_sha256); assert.equal(inspected.network_accessed, false);
  assert.equal(inspected.events, 6); assert.equal(inspected.snapshot_token, head); assert.equal(f.calls.length, 8);
  const retained = await readFile(join(f.options.workdir, 'page-000003.json'), 'utf8');
  assert.equal(JSON.parse(retained).events[0].action.body, data()[0].events[1].action.body);
  assert.ok(!retained.includes(token));
  assert.deepEqual(f.calls.filter(row => row.url.pathname.endsWith('/issues')).map(row => row.url.searchParams.get('after')), ['0', '1']);
});
test('empty repository is a complete one-page read, not an invented issue', async t => {
  const f = await fixture(t, { items: [] }), result = await exportIssueArchive(f.options);
  assert.equal(result.issues, 0); assert.equal(result.events, 0); assert.equal(result.pages, 1);
  assert.equal((await inspectIssueArchive({ workdir: f.options.workdir, confirm: result.archive_sha256 })).complete, true);
});
test('explicit initial snapshot is sent before the first page and remains fixed', async t => {
  const f = await fixture(t); await exportIssueArchive({ ...f.options, head });
  assert.ok(f.calls.every(row => row.url.searchParams.get('expected_head') === head));
});
test('assignment deltas, reopen and partial edits reconstruct the retained final state', async t => {
  const items = data().slice(0, 1), item = items[0];
  item.events.push(event(6, other, 'unassign', { assignees: [assignee] }), event(7, other, 'reopen'),
    event(8, actor, 'edit', { title: 'Edited title', body: '' }));
  Object.assign(item.issue, { version: 8, state: 'open', title: 'Edited title', body: '', assignees: [] });
  const f = await fixture(t, { items }); const result = await exportIssueArchive({ ...f.options, pageSize: 2 });
  assert.equal(result.events, 8); assert.equal(result.pages, 5);
});
for (const [name, change, message] of [
  ['foreign repository', (b, n) => { if (n === 1) b.repository_id = '9'.repeat(32); }, /identity changed/],
  ['mixed snapshot', (b, n) => { if (n === 2) b.snapshot_token = 'alg:2:' + '7'.repeat(64); }, /snapshot moved/i],
  ['mixed source head', (b, n) => { if (n === 2) b.source_head = 'other-head'; }, /source_head_changed/],
  ['missing listed issue', (b, n) => { if (n === 2) { b.found = false; b.issue = null; b.events = []; b.next_after_version = null; } }, /list_history_disagreement/],
  ['missing history version', (b, n) => { if (n === 3) b.events[0].version++; }, /version gap/],
  ['truncated history', (b, n) => { if (n === 2) b.next_after_version = null; }, /Incomplete issue history/],
  ['changed listed snapshot', (b, n) => { if (n === 2) b.issue.title += '!'; }, /list_history_disagreement/],
  ['wrong comment total', b => { if (b.type === 'issue_page') b.issues[0].comments = 0; else b.issue.comments = 0; }, /history_state_disagreement/],
  ['wrong final text', (b, n) => { if (n === 4) b.events[0].action.body = 'substitution'; }, /history_state_disagreement/],
  ['wrong opening actor', (b, n) => { if (n === 2) b.events[0].actor = other; }, /history_state_disagreement/],
  ['wrong last actor', (b, n) => { if (n === 6) b.events[0].actor = other; }, /history_state_disagreement/],
  ['invalid issue ordering', b => { if (b.type === 'issue_page' && b.after > 0) b.issues[0].number = 1; }, /ordering/],
]) test(name + ' refuses without publishing a complete archive', async t => {
  const f = await fixture(t, { change }); await assert.rejects(exportIssueArchive(f.options), message); await noRoot(f.options);
});
for (const status of [401, 403, 409, 429, 503]) test('HTTP ' + status + ' is not an empty export or a retry', async t => {
  const f = await fixture(t, { handle: async (_req, res) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end('{}'); return true; } });
  await assert.rejects(exportIssueArchive(f.options)); assert.equal(f.calls.length, 1); await noRoot(f.options);
});
for (const [option, value, pattern] of [
  ['maxRequests', 2, /request_limit/], ['maxIssues', 1, /issue_limit/], ['maxEvents', 4, /event_limit/],
  ['maxReadBytes', 1, /read_limit/], ['maxArchiveBytes', 1, /archive_limit/],
]) test(option + ' is a whole-export bound, not a successful prefix', async t => {
  const f = await fixture(t); await assert.rejects(exportIssueArchive({ ...f.options, [option]: value }), pattern);
  await noRoot(f.options); if (option === 'maxRequests') assert.equal(f.calls.length, 2);
});
test('exact request and retained-byte budgets succeed; one byte less refuses', async t => {
  const f = await fixture(t), result = await exportIssueArchive(f.options);
  const size = result.data_bytes + (await readFile(join(f.options.workdir, 'archive.json'))).length;
  const opts = { ...f.options, workdir: join(f.parent, 'exact'), maxArchiveBytes: size, maxRequests: result.requests };
  f.calls.length = 0; assert.equal((await exportIssueArchive(opts)).complete, true);
  f.calls.length = 0; await assert.rejects(exportIssueArchive({ ...opts, workdir: join(f.parent, 'short'), maxArchiveBytes: size - 1 }), /archive_limit/);
});
test('offline inspection needs neither the original token nor any source service', async t => {
  const f = await fixture(t), result = await exportIssueArchive(f.options); await rm(f.options.tokenFile);
  f.server.closeAllConnections();
  const before = f.calls.length;
  assert.equal((await inspectIssueArchive({ workdir: f.options.workdir, confirm: result.archive_sha256 })).complete, true);
  assert.equal(f.calls.length, before);
});
test('wrong independent root pin refuses before accepting any archive', async t => {
  const f = await fixture(t); await exportIssueArchive(f.options);
  await assert.rejects(inspectIssueArchive({ workdir: f.options.workdir, confirm: '0'.repeat(64) }), /pin_mismatch/);
});
for (const what of ['page_bytes', 'missing', 'extra', 'symlink', 'hardlink', 'public']) test('offline ' + what + ' is rejected', async t => {
  const f = await fixture(t), result = await exportIssueArchive(f.options), path = join(f.options.workdir, 'page-000002.json');
  if (what === 'page_bytes') await writeFile(path, '{}\n');
  if (what === 'missing') await rm(path);
  if (what === 'extra') await writeFile(join(f.options.workdir, 'unexpected.json'), '{}', { mode: 0o600 });
  if (what === 'symlink') { const saved = join(f.parent, 'saved'); await rename(path, saved); await symlink(saved, path); }
  if (what === 'hardlink') await link(path, join(f.parent, 'linked'));
  if (what === 'public') await chmod(path, 0o644);
  await assert.rejects(inspectIssueArchive({ workdir: f.options.workdir, confirm: result.archive_sha256 }));
});
for (const [name, edit] of [
  ['remove last page', m => { m.pages.pop(); }], ['swap pages', m => { [m.pages[1], m.pages[2]] = [m.pages[2], m.pages[1]]; }],
  ['change issue count', m => { m.issue_count--; }], ['change event count', m => { m.event_count--; }],
  ['change source', m => { m.source_head = 'different'; }], ['change page size', m => { m.page_size++; }],
]) test('recomputed manifest hash cannot hide ' + name, async t => {
  const f = await fixture(t); await exportIssueArchive(f.options);
  const confirm = await mutateRoot(f.options, edit); await assert.rejects(inspectIssueArchive({ workdir: f.options.workdir, confirm }));
});
test('same-snapshot semantic corruption is refused even with recalculated page and root hashes', async t => {
  const f = await fixture(t); await exportIssueArchive(f.options);
  const path = join(f.options.workdir, 'page-000004.json'), value = JSON.parse(await readFile(path));
  value.events[0].action.body = 'changed'; const bytes = encode(value); await writeFile(path, bytes);
  const confirm = await mutateRoot(f.options, m => { m.pages[3][2] = recordDigest(bytes); m.data_bytes += bytes.length - m.pages[3][3]; m.pages[3][3] = bytes.length; });
  await assert.rejects(inspectIssueArchive({ workdir: f.options.workdir, confirm }), /history_state_disagreement/);
});
test('duplicate-key manifest is rejected even with its new independent digest', async t => {
  const f = await fixture(t); await exportIssueArchive(f.options);
  const path = join(f.options.workdir, 'archive.json');
  const bytes = Buffer.from((await readFile(path, 'utf8')).replace('"page_size":1', '"page_size":9,"page_size":1'));
  await writeFile(path, bytes);
  await assert.rejects(inspectIssueArchive({ workdir: f.options.workdir, confirm: recordDigest(bytes) }), /encoding/);
});
test('occupied output never starts another acquisition', async t => {
  const f = await fixture(t); await exportIssueArchive(f.options); const before = f.calls.length;
  await assert.rejects(exportIssueArchive(f.options), { code: 'EEXIST' }); assert.equal(f.calls.length, before);
});
test('competing creators publish at most one complete original archive', async t => {
  const f = await fixture(t); const results = await Promise.allSettled([exportIssueArchive(f.options), exportIssueArchive(f.options)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(f.calls.length, 8);
});
test('pre-cancellation creates nothing and sends nothing', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  await assert.rejects(exportIssueArchive({ ...f.options, signal: stop.signal })); assert.equal(f.calls.length, 0);
  await assert.rejects(readdir(f.options.workdir), { code: 'ENOENT' });
});
test('cancellation during a real stalled HTTP body drains and publishes no root', async t => {
  const stop = new AbortController(); let closed;
  const closure = new Promise(resolve => { closed = resolve; });
  const f = await fixture(t, { handle: async (req, res) => {
    req.on('close', closed); res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{');
    setTimeout(() => stop.abort(), 20); return true;
  } });
  await assert.rejects(exportIssueArchive({ ...f.options, signal: stop.signal }));
  await Promise.race([closure, new Promise((_, reject) => setTimeout(() => reject(new Error('HTTP not drained')), 1000).unref())]);
  assert.equal(f.calls.length, 1); await noRoot(f.options);
});
test('whole-operation deadline terminates a stalled response', async t => {
  const f = await fixture(t, { handle: async (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); return true; } });
  await assert.rejects(exportIssueArchive({ ...f.options, timeoutMs: 50 })); await noRoot(f.options);
});
test('replacement of output directory between reads is not treated as original custody', async t => {
  const f = await fixture(t, { change: async (_b, n, { parent }) => {
    if (n === 2) { await rename(join(parent, 'archive'), join(parent, 'old')); await mkdir(join(parent, 'archive'), { mode: 0o700 }); }
  } });
  await assert.rejects(exportIssueArchive(f.options), /directory_changed_or_unsafe/); await noRoot(f.options);
  assert.deepEqual(await readdir(f.options.workdir), []);
});
test('archive field and budget grammar is closed before filesystem work', async () => {
  const options = { workdir: '/not-present/output', href: 'https://forge.example/repo/ui/issues/', tenant, repository, tokenFile: '/not-present/token' };
  for (const more of [{ pageSize: 0 }, { maxRequests: 8193 }, { maxIssues: 0 }, { maxEvents: -1 }, { unknown: true }, { head: 'bad' }]) {
    await assert.rejects(exportIssueArchive({ ...options, ...more }), error => error.code !== 'ENOENT');
  }
});
