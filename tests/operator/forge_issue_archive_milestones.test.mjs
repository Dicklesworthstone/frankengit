// Production v2 archive traversal and offline revalidation against a socket
// schema peer. Native authority execution is covered separately by the fg E2E.
import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { mkdtemp, writeFile, readFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { exportIssueArchive, inspectIssueArchive, readIssueArchive, ISSUE_ARCHIVE_SCHEMA_V2 }
  from '../../scripts/lib/forge-issue-archive.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { milestonePeer, setupMilestones, fixtureMilestones, fixtureMilestoneIssues,
  issueSnapshot, milestoneSnapshot, tenant, repository, head, encode }
  from './native_milestone_transfer_helper.mjs';

async function fixture(t, rows = fixtureMilestoneIssues(), milestones = fixtureMilestones()) {
  const root = await mkdtemp(join(tmpdir(), 'fg-milestone-archive-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const src = await milestonePeer({ rows, milestones }); t.after(() => src.close());
  const tokenFile = join(root, 'token'); await writeFile(tokenFile, src.token, { mode: 0o600 });
  const options = { workdir: join(root, 'archive'), href: src.href, tenant, repository, tokenFile, includeMilestones: true };
  return { root, src, options };
}
async function absentRoot(workdir) {
  await assert.rejects(access(join(workdir, 'archive.json')), { code: 'ENOENT' });
}
function transform(change) {
  return async (url, init) => {
    const response = await fetch(url, init), value = await response.json();
    change(value, new URL(url));
    return new Response(encode(value), { status: response.status, headers: { 'Content-Type': 'application/json' } });
  };
}

test('archive v2 pins complete milestone and issue histories at one head and checks same-head progress', async t => {
  const f = await setupMilestones(t, { pageSize: 1 });
  assert.equal(f.archive.schema_version, 2); assert.equal(f.archive.milestones, 3);
  assert.equal(f.archive.issues, 4); assert.equal(f.archive.events, 21); assert.equal(f.archive.pages, 28);
  assert.equal(f.archive.canonical_backup, false); assert.equal(f.archive.mutation_submitted, false);
  assert.equal(f.src.calls.length, 28); assert.ok(f.src.calls.every(call => call.method === 'GET' && !call.key));
  assert.ok(f.src.calls[0].path.endsWith('/milestones'));
  assert.equal(f.src.calls[0].query.has('expected_head'), false);
  assert.ok(f.src.calls.slice(1).every(call => call.query.get('expected_head') === head));
  const manifest = JSON.parse(await readFile(join(f.archiveDir, 'archive.json')));
  assert.equal(manifest.schema, ISSUE_ARCHIVE_SCHEMA_V2);
  assert.equal(manifest.milestone_count, 3);
  assert.ok(manifest.pages.slice(0, 12).every(row => row[0] === 'milestone'));
  assert.ok(manifest.pages.slice(12).every(row => row[0] === 'issue'));
  const view = await readIssueArchive({ workdir: f.archiveDir, confirm: f.archive.archive_sha256 });
  assert.equal(view.archive.network_accessed, false); assert.equal(f.src.calls.length, 28);
  assert.deepEqual(view.records.map(row => row.snapshot), fixtureMilestoneIssues().map(issueSnapshot));
  assert.deepEqual(view.milestones.map(row => row.snapshot), fixtureMilestones().map(row => milestoneSnapshot(row, fixtureMilestoneIssues())));
  assert.deepEqual(view.milestones.map(row => row.events), fixtureMilestones().map(row => row.events));
  assert.equal(view.records[1].snapshot.milestone, null);
  const allPages = await Promise.all(manifest.pages.map((_, i) => readFile(join(f.archiveDir,
    `page-${String(i + 1).padStart(6, '0')}.json`), 'utf8')));
  const historical = allPages.map(JSON.parse).filter(page => page.type === 'issue_history' && page.issue.number === 2)
    .flatMap(page => page.events);
  assert.deepEqual(historical.map(event => event.action.name), ['open', 'set-milestone', 'clear-milestone', 'comment']);
  assert.ok(allPages.every(bytes => !bytes.includes(f.src.token)), 'source credentials never enter portable archive pages');
});

test('frozen archive v1 refuses historical membership even when the issue is currently unassigned', async t => {
  const f = await fixture(t, [fixtureMilestoneIssues()[1]]);
  await assert.rejects(exportIssueArchive({ ...f.options, includeMilestones: false }), /milestones_unsupported/);
  assert.ok(f.src.calls.every(call => !call.path.includes('/milestones')));
  await absentRoot(f.options.workdir);
});

test('v2 rejects a historical selected milestone version that is closed or absent even after a later clear', async t => {
  for (const selected of [3, 999]) {
    const rows = [fixtureMilestoneIssues()[1]];
    rows[0].events[1].action.expected_milestone_version = selected;
    const f = await fixture(t, rows);
    await assert.rejects(exportIssueArchive(f.options), /invalid_milestone_selection/);
    await absentRoot(f.options.workdir);
  }
  const rows = [fixtureMilestoneIssues()[1]]; rows[0].events[1].action.milestone = 999;
  const f = await fixture(t, rows);
  await assert.rejects(exportIssueArchive(f.options), /invalid_milestone_selection/);
  await absentRoot(f.options.workdir);
});

test('v2 validates milestone progress against the complete issue population and refuses partial or moved source views', async t => {
  const f = await fixture(t);
  await assert.rejects(exportIssueArchive({ ...f.options, fetchImpl: transform(value => {
    for (const row of value.milestones ?? (value.milestone ? [value.milestone] : [])) {
      if (row.number === 3) row.open_issues = 1;
    }
  }) }), /milestone_progress_disagreement/);
  await absentRoot(f.options.workdir);
  const moved = await fixture(t);
  await assert.rejects(exportIssueArchive({ ...moved.options, fetchImpl: transform(value => {
    if (value.type === 'issue_page') value.snapshot_token = `alg:2:${'b'.repeat(64)}`;
  }) }), /snapshot moved/i);
  await absentRoot(moved.options.workdir);
  assert.ok(moved.src.calls.filter(call => call.path.endsWith('/issues')).every(call => call.query.get('expected_head') === head));
});

test('v2 shares event, request and byte allowances across both aggregate families', async t => {
  const limited = await fixture(t);
  await assert.rejects(exportIssueArchive({ ...limited.options, maxEvents: 20 }), /event_limit/);
  await absentRoot(limited.options.workdir);
  const count = await fixture(t);
  await assert.rejects(exportIssueArchive({ ...count.options, maxMilestones: 2 }), /milestone_limit/);
  assert.ok(count.src.calls.every(call => !call.path.includes('/issues')));
  await absentRoot(count.options.workdir);
  const requests = await fixture(t);
  await assert.rejects(exportIssueArchive({ ...requests.options, maxRequests: 4, pageSize: 100 }), /request_limit/);
  assert.equal(requests.src.calls.length, 4);
  assert.ok(requests.src.calls.every(call => !call.path.includes('/issues')));
  await absentRoot(requests.options.workdir);
  const complete = await setupMilestones(t, { pageSize: 100 });
  const bytes = await fixture(t);
  await assert.rejects(exportIssueArchive({ ...bytes.options, pageSize: 100,
    maxReadBytes: complete.archive.read_bytes - 1 }), /read_limit/);
  await absentRoot(bytes.options.workdir);
});

test('offline v2 verification replays cross-stream membership even with newly recomputed page and root hashes', async t => {
  const f = await setupMilestones(t, { pageSize: 100 });
  const path = join(f.archiveDir, 'archive.json'), manifest = JSON.parse(await readFile(path));
  const index = manifest.pages.findIndex(row => row[0] === 'issue' && row[1] === 2);
  assert.ok(index >= 0);
  const pagePath = join(f.archiveDir, `page-${String(index + 1).padStart(6, '0')}.json`);
  const page = JSON.parse(await readFile(pagePath));
  page.events.find(event => event.action.name === 'set-milestone').action.expected_milestone_version = 3;
  const bytes = encode(page), descriptor = manifest.pages[index];
  manifest.data_bytes += bytes.length - descriptor[4]; descriptor[3] = recordDigest(bytes); descriptor[4] = bytes.length;
  await writeFile(pagePath, bytes); const root = encode(manifest); await writeFile(path, root);
  const before = f.src.calls.length;
  await assert.rejects(inspectIssueArchive({ workdir: f.archiveDir, confirm: recordDigest(root) }), /invalid_milestone_selection/);
  assert.equal(f.src.calls.length, before);
});

test('milestone-only and empty v2 read archives remain complete observations', async t => {
  for (const milestones of [fixtureMilestones(), []]) {
    const f = await setupMilestones(t, { rows: [], milestones, pageSize: 100 });
    const view = await readIssueArchive({ workdir: f.archiveDir, confirm: f.archive.archive_sha256 });
    assert.equal(view.archive.complete, true); assert.equal(view.archive.issues, 0);
    assert.equal(view.archive.milestones, milestones.length); assert.deepEqual(view.records, []);
  }
});
