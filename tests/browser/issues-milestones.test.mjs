// Native JSON/client contract doubles; actual Rust HTTP coverage lives in issue_http.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { IssueClient, issueAction, issueMilestone, issuePage, issueHistory, mutationRequest,
  issueSearchPage, issueSearchQuery } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { token, head, actor, identity, issue, searchPage, json, terminal }
  from './issues-search-fixture.mjs';
const page = row => ({ ...identity, type: 'issue_page', after: 0, limit: 20, next_after: null, issues: [row] });
const fresh = fetchImpl => new IssueClient({ href: 'https://forge.example/repo.git/ui/issues/', fetchImpl, cryptoImpl: webcrypto });
const opening = row => ({ version: 1, actor, action: { name: 'open', title: row.title, body: row.body, labels: row.labels } });
function history() {
  const row = issue(1, { version: 4, milestone: null });
  return { ...identity, type: 'issue_history', after_version: 0, limit: 20, found: true,
    issue: row, next_after_version: null, events: [opening(row),
      { version: 2, actor, action: { name: 'set-milestone', milestone: 7, expected_milestone_version: 1 } },
      { version: 3, actor, action: { name: 'set-milestone', milestone: 7, expected_milestone_version: 2 } },
      { version: 4, actor, action: { name: 'clear-milestone' } }] };
}

test('legacy missing membership remains null without rewriting canonical snapshot bytes', () => {
  const legacy = page(issue()), original = JSON.stringify(legacy);
  assert.equal(issueMilestone(issuePage(legacy).reply.issues[0]), null);
  assert.equal(JSON.stringify(legacy), original);
  for (const milestone of [null, 1, Number.MAX_SAFE_INTEGER]) {
    const value = page(issue(1, { milestone }));
    assert.equal(issueMilestone(issuePage(value).reply.issues[0]), milestone);
  }
  for (const milestone of [undefined, 0, -1, 1.5, '7', Number.MAX_SAFE_INTEGER + 1, {}, []]) {
    assert.throws(() => issuePage(page(issue(1, { milestone }))));
  }
});

test('set and clear membership forms require exact versions and reject extra authority or payload', () => {
  const request = mutationRequest(1, 2, 'set-milestone', { milestone: 7, expected_milestone_version: 3 });
  assert.equal(request.body, 'expected_version=2&milestone=7&expected_milestone_version=3');
  assert.equal(mutationRequest(1, 2, 'clear-milestone', {}).body, 'expected_version=2');
  for (const fields of [{ milestone: 7 }, { expected_milestone_version: 3 },
    { milestone: 7, expected_milestone_version: 3, principal: actor },
    ...[0, '1', -1, Number.MAX_SAFE_INTEGER + 1, null].flatMap(value => [
      { milestone: value, expected_milestone_version: 3 }, { milestone: 7, expected_milestone_version: value }])]) {
    assert.throws(() => issueAction('set-milestone', fields));
  }
  for (const fields of [{ milestone: 7 }, { body: 'clear' }, { expected_milestone_version: 3 }]) {
    assert.throws(() => mutationRequest(1, 2, 'clear-milestone', fields));
  }
});

test('membership histories retain repeated exact assignments and explicit clears across pages', () => {
  const value = history(), original = JSON.stringify(value);
  assert.equal(issueHistory(value, 1).reply.issue.milestone, null);
  assert.equal(JSON.stringify(value), original);
  const selected = structuredClone(value);
  selected.issue.version = 3; selected.issue.milestone = 7; selected.events.pop();
  assert.equal(issueHistory(selected, 1).reply.issue.milestone, 7);
  assert.equal(issueHistory({ ...value, after_version: 2, events: value.events.slice(2) }, 1, { after: 2, head }).reply.issue.milestone, null);
  for (const alter of [
    v => { delete v.issue.milestone; }, v => { v.issue.milestone = 7; },
    v => { v.events[1].action.expected_milestone_version = 0; },
    v => { v.events[2].action.milestone = '7'; },
    v => { v.events[3].action.milestone = 7; },
  ]) { const bad = history(); alter(bad); assert.throws(() => issueHistory(bad, 1)); }
});

test('search sends and verifies exact milestone predicates while old unfiltered echoes remain valid', async () => {
  assert.equal(Object.hasOwn(issueSearchQuery({}), 'milestone'), false);
  assert.equal(issueSearchPage(searchPage(), {}).reply.count, 1);
  assert.equal(issueSearchPage(searchPage({}, { milestone: null }), {}).reply.count, 1);
  for (const milestone of [7, 'none']) {
    const query = { milestone }, rows = [issue(1, { milestone: milestone === 'none' ? null : milestone })];
    const value = searchPage({ issues: rows }, query);
    assert.equal(issueSearchPage(value, query).query.milestone, milestone);
    assert.throws(() => issueSearchPage({ ...value, query: { ...value.query, milestone: null } }, query));
    assert.throws(() => issueSearchPage({ ...value, issues: [issue(1, { milestone: milestone === 'none' ? 7 : null })] }, query));
    let call;
    const client = fresh(async (url, options) => { call = { url, ...options }; return json(value); });
    await client.connect(token); await client.search(query);
    assert.equal(new URLSearchParams(call.body).get('milestone'), String(milestone));
    assert.equal(call.headers['Idempotency-Key'], undefined);
  }
  for (const milestone of [0, '7', false, [], -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => issueSearchQuery({ milestone }));
  }
});

test('membership request custody retains the original milestone version and key after response loss', async () => {
  const calls = [], fields = { milestone: 7, expected_milestone_version: 3 };
  const first = fresh(async (url, options) => { calls.push({ url: String(url), ...options }); throw new Error('lost reply'); });
  await first.connect(token); await first.stage(1, 2, 'set-milestone', fields);
  await assert.rejects(first.send()); const receipt = first.exportReceipt();
  const restored = fresh(async (url, options) => { calls.push({ url: String(url), ...options });
    return json({ ...terminal, action: 'set-milestone', expected_version: 2 }); });
  await restored.connect(token); await restored.restoreReceipt(receipt);
  assert.equal((await restored.send()).outcome, 'committed');
  assert.equal(calls[1].body, calls[0].body);
  assert.equal(calls[1].headers['Idempotency-Key'], calls[0].headers['Idempotency-Key']);
  assert.equal(new URLSearchParams(calls[1].body).get('expected_milestone_version'), '3');
  assert.equal(receipt.includes(token), false);
});
