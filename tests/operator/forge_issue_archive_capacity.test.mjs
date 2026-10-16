// Capacity/adversarial response peers drive the complete production client.
// These are not native-server capacity measurements or performance claims.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, writeFile, readFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportIssueArchive, inspectIssueArchive } from '../../scripts/lib/forge-issue-archive.mjs';
const tenant = '1'.repeat(32), repository = '2'.repeat(32), token = 'a'.repeat(64), actor = '3'.repeat(32);
const head = 'alg:2:' + '6'.repeat(64);
async function source(t, { issues = 1, events = 1, body = 'body', intercept } = {}) {
  const parent = await mkdtemp(join(tmpdir(), 'fg-archive-cap-')); await chmod(parent, 0o700);
  const tokenFile = join(parent, 'token'); await writeFile(tokenFile, token, { mode: 0o600 });
  t.after(() => rm(parent, { recursive: true, force: true }));
  let calls = 0;
  const snapshot = number => ({ number, version: events, title: 'title', body, labels: [], assignees: [],
    state: 'open', opened_by: actor, last_actor: actor, comments: events - 1 });
  const fetchImpl = async (input, init) => {
    assert.equal(init.method, 'GET'); assert.equal(init.headers.Authorization, 'Bearer ' + token); calls++;
    const url = new URL(input), id = url.pathname.match(/\/issues\/(\d+)$/)?.[1] ?? null;
    const after = Number(url.searchParams.get(id === null ? 'after' : 'after_version')), limit = Number(url.searchParams.get('limit'));
    const header = { schema_version: 1, tenant_id: tenant, repository_id: repository, snapshot_token: head, source_head: 'stable-source' };
    const value = id === null ? { type: 'issue_page', ...header, after, limit,
      issues: Array.from({ length: Math.min(limit, issues - after) }, (_, i) => snapshot(after + i + 1)),
      next_after: after + limit < issues ? after + limit : null }
      : { type: 'issue_history', ...header, found: true, issue: snapshot(Number(id)), after_version: after, limit,
        events: Array.from({ length: Math.min(limit, events - after) }, (_, i) => ({ version: after + i + 1, actor,
          action: after + i === 0 ? { name: 'open', title: 'title', body, labels: [] } : { name: 'comment', body } })),
        next_after_version: after + limit < events ? after + limit : null };
    await intercept?.({ calls, parent, value });
    return new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
  };
  return { parent, calls: () => calls, options: { workdir: join(parent, 'archive'), href: 'https://fixture.invalid/repo/ui/issues/',
    tenant, repository, tokenFile, pageSize: 100, fetchImpl } };
}
test('the full 4096-issue population fits and validates without truncated success', async t => {
  const f = await source(t, { issues: 4096 }), result = await exportIssueArchive(f.options);
  assert.equal(result.issues, 4096); assert.equal(result.events, 4096); assert.equal(result.requests, 4137);
  assert.equal((await inspectIssueArchive({ workdir: f.options.workdir, confirm: result.archive_sha256 })).issues, 4096);
});
test('the full 65536-event history is preserved across native page boundaries', async t => {
  const f = await source(t, { events: 65536 }), result = await exportIssueArchive(f.options);
  assert.equal(result.events, 65536); assert.equal(result.requests, 657);
  assert.equal((await inspectIssueArchive({ workdir: f.options.workdir, confirm: result.archive_sha256 })).events, 65536);
});
test('one over the event capacity refuses before fetching the oversized history', async t => {
  const f = await source(t, { events: 65537 }); await assert.rejects(exportIssueArchive(f.options), /event_limit/);
  assert.equal(f.calls(), 1); assert.deepEqual(await readdir(f.options.workdir), []);
});
test('all 8192 permitted page descriptors fit the sealed manifest and validate', async t => {
  const f = await source(t, { events: 8191 }), result = await exportIssueArchive({ ...f.options, pageSize: 1 });
  assert.equal(result.pages, 8192); assert.equal(result.requests, 8192);
  assert.ok((await readFile(join(f.options.workdir, 'archive.json'))).length <= 1024 * 1024);
  assert.equal((await inspectIssueArchive({ workdir: f.options.workdir, confirm: result.archive_sha256 })).pages, 8192);
});
test('large escaped bodies refuse oversized pages but work with an explicit smaller page size', async t => {
  const f = await source(t, { events: 6, body: '\x01'.repeat(32768) });
  await assert.rejects(exportIssueArchive(f.options), /read_limit/);
  const result = await exportIssueArchive({ ...f.options, workdir: join(f.parent, 'smaller'), pageSize: 1 });
  assert.equal(result.events, 6); assert.equal(result.complete, true);
});
test('equal source observations produce byte-identical archives without local path identity leakage', async t => {
  const f = await source(t, { issues: 3, events: 2 }), left = await exportIssueArchive(f.options);
  const right = await exportIssueArchive({ ...f.options, workdir: join(f.parent, 'second') });
  assert.equal(left.archive_sha256, right.archive_sha256);
  for (const name of await readdir(f.options.workdir)) {
    assert.deepEqual(await readFile(join(f.options.workdir, name)), await readFile(join(f.parent, 'second', name)));
  }
});
test('corruption of an earlier retained page during capture prevents root publication', async t => {
  const f = await source(t, { events: 3, intercept: async ({ calls, parent }) => {
    if (calls === 3) await writeFile(join(parent, 'archive/page-000001.json'), '{}\n');
  } });
  await assert.rejects(exportIssueArchive({ ...f.options, pageSize: 1 }), /page_commitment/);
  await assert.rejects(readFile(join(f.options.workdir, 'archive.json')), { code: 'ENOENT' });
});
test('a redirected source is rejected before parsing an apparently valid page', async t => {
  const f = await source(t); const original = f.options.fetchImpl;
  f.options.fetchImpl = async (...args) => {
    const response = await original(...args); Object.defineProperty(response, 'url', { value: 'https://other.invalid/issue' }); return response;
  };
  await assert.rejects(exportIssueArchive(f.options), /redirect/); assert.equal(f.calls(), 1);
});
