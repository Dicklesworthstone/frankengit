// Milestone membership through the real issue CLI codec and existing HTTP schema peer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { issueArguments, runIssueCommand } from '../../scripts/forge_issues.mjs';
import { runMilestoneCommand } from '../../scripts/forge_milestones.mjs';
import { milestonePeer, issueSnapshot, milestoneSnapshot, fixtureMilestones, fixtureMilestoneIssues,
  tenant, repository, actor, head } from './native_milestone_transfer_helper.mjs';

const mutations = peer => peer.calls.filter(call => call.method === 'POST' &&
  !call.path.endsWith('/outcomes') && !call.path.endsWith('/search'));
async function fixture(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-issue-milestone-cli-')), f = { changeSearch() {} };
  const peer = await milestonePeer({ rows: fixtureMilestoneIssues(), milestones: fixtureMilestones(), ...options,
    async fault(context) {
      if (options.fault && await options.fault(context)) return true;
      const { call, source, send } = context;
      if (!call.path.endsWith('/issues/search')) return false;
      // The shared peer has no search route. This response-schema fixture scans
      // actual fixture issue rows; production request and reply checking remain untouched.
      const params = new URLSearchParams(call.body), milestone = params.get('milestone');
      const query = { state: params.get('state') === 'all' ? null : params.get('state'),
        opened_by: params.get('opened_by'), text: params.get('query'),
        case_sensitive: params.get('case_sensitive') === 'true', labels: params.getAll('label'),
        text_scope: 'title_or_body', ...(milestone === null ? {} : { milestone: milestone === 'none' ? 'none' : Number(milestone) }) };
      const after = Number(params.get('after')), limit = Number(params.get('limit')), max_scan = Number(params.get('max_scan'));
      if (params.has('expected_head') && params.get('expected_head') !== head) { send({}, 409); return true; }
      const candidates = [...source.values()].map(issueSnapshot).filter(row => row.number > after).sort((a, b) => a.number - b.number);
      const issues = []; let scanned = 0, last = after;
      const fold = value => query.case_sensitive ? value : value.replace(/[A-Z]/g, c => c.toLowerCase());
      while (scanned < candidates.length && scanned < max_scan && issues.length < limit) {
        const row = candidates[scanned++]; last = row.number;
        if (query.milestone !== undefined && row.milestone !== (query.milestone === 'none' ? null : query.milestone)) continue;
        if (query.state !== null && row.state !== query.state) continue;
        if (query.opened_by !== null && row.opened_by !== query.opened_by) continue;
        if (!query.labels.every(label => row.labels.includes(label))) continue;
        if (query.text !== null && !fold(row.title).includes(fold(query.text)) && !fold(row.body).includes(fold(query.text))) continue;
        issues.push(row);
      }
      const complete = scanned === candidates.length;
      const reply = { schema_version: 1, tenant_id: tenant, repository_id: repository, snapshot_token: head,
        type: 'issue_search_page', scope: 'repository_issues', refs_changed: false, transaction_created: false,
        query, after, limit, max_scan, issues, count: issues.length, scanned,
        stop_reason: complete ? 'exhausted' : issues.length === limit ? 'result_limit' : 'scan_limit',
        complete, has_more_candidates: !complete, next_after: complete ? null : last };
      f.changeSearch(reply); send(reply); return true;
    } });
  const tokenFile = join(root, 'token'); await writeFile(tokenFile, peer.token, { mode: 0o600 });
  f.root = root; f.peer = peer;
  f.flags = (operation, record = null) => [operation, '--url', peer.href, '--tenant-id', tenant, '--repository-id', repository,
    '--token-file', tokenFile, ...(record === null ? [] : ['--record', record])];
  t.after(async () => { await peer.close(); await rm(root, { recursive: true, force: true }); });
  return f;
}

test('issue CLI distinguishes exact membership commands, no-membership search, and existing strict comments', async t => {
  const f = await fixture(t), record = join(f.root, 'request.json');
  const set = [...f.flags('set-milestone', record), '--number', '1', '--expected-version', '5'];
  assert.deepEqual(issueArguments([...set, '--milestone', '2', '--expected-milestone-version', '5']).options.fields,
    { milestone: 2, expected_milestone_version: 5 });
  const clear = [...f.flags('clear-milestone', record), '--number', '1', '--expected-version', '5'];
  assert.deepEqual(issueArguments(clear).options.fields, {});
  assert.equal(issueArguments([...f.flags('search'), '--milestone', 'none']).options.query.milestone, 'none');
  assert.equal(issueArguments([...f.flags('search'), '--milestone', '2']).options.query.milestone, 2);
  const invalid = [
    set, [...set, '--milestone', '2'], [...set, '--expected-milestone-version', '5'],
    [...set, '--milestone', 'none', '--expected-milestone-version', '5'],
    [...set, '--milestone', '0', '--expected-milestone-version', '5'],
    [...set, '--milestone', '2', '--expected-milestone-version', '0'],
    [...set, '--milestone', '2', '--expected-milestone-version', '5', '--label', 'plan'],
    [...clear, '--milestone', '2'], [...clear, '--expected-milestone-version', '5'],
    [...f.flags('comment', record), '--number', '1', '--body', 'Strict still needs version'],
    [...f.flags('append-comment', record), '--number', '1', '--expected-version', '5', '--body', 'No hidden strictness change'],
    [...f.flags('edit', record), '--number', '1', '--expected-version', '5', '--milestone', '2'],
    [...f.flags('list'), '--milestone', '2'], [...f.flags('show'), '--number', '1', '--milestone', 'none'],
    [...f.flags('search'), '--milestone', '01'], [...f.flags('search'), '--milestone', '-1'],
    [...f.flags('search'), '--milestone', 'none', '--expected-milestone-version', '5'],
    [...f.flags('retry', record), '--milestone', '2'],
  ];
  for (const args of invalid) assert.throws(() => issueArguments(args));
  assert.equal(f.peer.calls.length, 0);
});

test('closed and locked issues can join and leave a release without changing their other fields or milestone version', async t => {
  const f = await fixture(t), before = issueSnapshot(f.peer.source.get(1)), record = join(f.root, 'set.json');
  const set = await runIssueCommand([...f.flags('set-milestone', record), '--number', '1', '--expected-version', '5',
    '--milestone', '2', '--expected-milestone-version', '5']);
  assert.equal(set.exitCode, 0);
  let current = issueSnapshot(f.peer.source.get(1));
  assert.deepEqual(current, { ...before, version: 6, milestone: 2, last_actor: actor });
  assert.equal(milestoneSnapshot(f.peer.milestoneSource.get(2)).version, 5);
  const request = JSON.parse(await readFile(record)).receipt.request, form = new URLSearchParams(request.body);
  assert.equal(form.get('expected_version'), '5'); assert.equal(form.get('milestone'), '2');
  assert.equal(form.get('expected_milestone_version'), '5'); assert.equal(request.action, 'set-milestone');
  // Admission checks the milestone atomically; membership must not demand an
  // extra milestone-read grant merely to refresh an explicitly selected target.
  assert.ok(f.peer.calls.every(call => !call.path.includes('/milestones')));
  const issueEvents = JSON.stringify([...f.peer.source.values()]);
  const closed = await runMilestoneCommand([...f.flags('close', join(f.root, 'close-release.json')), '--number', '2', '--expected-version', '5']);
  assert.equal(closed.exitCode, 0); assert.equal(JSON.stringify([...f.peer.source.values()]), issueEvents);
  const clear = await runIssueCommand([...f.flags('clear-milestone', join(f.root, 'clear.json')), '--number', '1', '--expected-version', '6']);
  assert.equal(clear.exitCode, 0);
  current = issueSnapshot(f.peer.source.get(1));
  assert.deepEqual(current, { ...before, version: 7, milestone: null, last_actor: actor });
  assert.equal(milestoneSnapshot(f.peer.milestoneSource.get(2)).version, 6);
  assert.equal(milestoneSnapshot(f.peer.milestoneSource.get(2), f.peer.source.values()).closed_issues, 0);
});

test('stale or closed milestone targets retain native refusal and original-key recovery without refreshing the target', async t => {
  const f = await fixture(t), before = JSON.stringify([...f.peer.source.values()]);
  for (const [milestone, version, refusal] of [[2, 4, 'EvidenceStale'], [1, 3, 'ProtectedRefTransitionDenied'], [99, 1, 'EvidenceStale']]) {
    const record = join(f.root, 'target-' + milestone + '.json');
    const result = await runIssueCommand([...f.flags('set-milestone', record), '--number', '4', '--expected-version', '1',
      '--milestone', String(milestone), '--expected-milestone-version', String(version)]);
    assert.equal(result.exitCode, 3); assert.equal(JSON.parse(result.text).result.refusal, refusal);
    const bytes = await readFile(record), count = mutations(f.peer).length;
    const retry = await runIssueCommand(f.flags('retry', record));
    assert.equal(retry.exitCode, 3); assert.equal(JSON.parse(retry.text).mutation_submitted, false);
    assert.equal(mutations(f.peer).length, count); assert.deepEqual(await readFile(record), bytes);
  }
  assert.equal(JSON.stringify([...f.peer.source.values()]), before);
  assert.ok(f.peer.calls.every(call => !call.path.includes('/milestones')));
});

test('milestone-filtered issue search pins zero-hit scan continuations and preserves conjunctions', async t => {
  const f = await fixture(t);
  const filters = ['--milestone', '2', '--state', 'open', '--opened-by', actor, '--query', 'Issue', '--label', 'plan',
    '--limit', '2', '--max-scan', '1'];
  const prefix = await runIssueCommand([...f.flags('search'), ...filters]);
  assert.equal(prefix.exitCode, 4);
  const value = JSON.parse(prefix.text);
  assert.equal(value.pages[0].issues.length, 0); assert.equal(value.continuation.query.milestone, 2);
  assert.equal(value.continuation.after, 1); assert.equal(value.continuation.expected_head, head);
  const rest = await runIssueCommand([...f.flags('search'), ...filters, '--after', '1', '--expected-head', head, '--max-pages', '3']);
  assert.equal(rest.exitCode, 0);
  assert.deepEqual(JSON.parse(rest.text).pages.flatMap(page => page.issues.map(row => row.number)), [3]);
  const unplanned = await runIssueCommand([...f.flags('search'), '--milestone', 'none']);
  assert.equal(unplanned.exitCode, 0);
  assert.deepEqual(JSON.parse(unplanned.text).pages[0].issues.map(row => row.number), [2, 4]);
  assert.equal(mutations(f.peer).length, 0); assert.deepEqual(await readdir(f.root), ['token']);
  assert.ok(f.peer.calls.every(call => call.key === undefined && call.method === 'POST' && call.path.endsWith('/issues/search')));
  const continued = f.peer.calls.slice(1, 4);
  assert.ok(continued.every(call => new URLSearchParams(call.body).get('expected_head') === head));
  assert.ok(continued.every(call => new URLSearchParams(call.body).get('milestone') === '2'));
  f.changeSearch = reply => { reply.query.milestone = 'none'; };
  await assert.rejects(runIssueCommand([...f.flags('search'), '--milestone', '2']),
    error => error.operator_state === 'read_incomplete');
});
