// DOM/fetch doubles. These test the actual controller/client, not Chromium or a live node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { IssueClient } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { mountIssues } from '../../crates/fgit-node/src/smart_http/server/browser/issues-view.mjs';
import { token, head, actor, identity, issue, searchPage, json, terminal, deferred } from './issues-search-fixture.mjs';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/issues.html', import.meta.url), 'utf8');
const href = 'https://forge.example/repo.git/ui/issues/';
const tick = () => new Promise(resolve => setImmediate(resolve));
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.checked = false; this.disabled = false; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text = ''; this.children = children; }
  addEventListener(type, listener) { if (!this.listeners.has(type)) this.listeners.set(type, []); this.listeners.get(type).push(listener); }
  async fire(type) {
    await Promise.all((this.listeners.get(type) ?? []).map(listener => listener({ preventDefault() {} })));
    await tick();
  }
}
function dom() {
  const nodes = new Map([...html.matchAll(/<([a-z]+)\b[^>]*\bid="([^"]+)"[^>]*>/g)].map(match => {
    const node = new Element(match[1]); node.value = /\bvalue="([^"]*)"/.exec(match[0])?.[1] ?? '';
    node.checked = /\bchecked\b/.test(match[0]); return [match[2], node];
  }));
  nodes.get('change-action').value = 'open'; nodes.get('issue-search-state').value = 'all';
  return { body: new Element('body'), createElement: tag => new Element(tag),
    getElementById: id => { assert.ok(nodes.has(id), `UI references undeclared element ${id}`); return nodes.get(id); },
    defaultView: new Element('window'), nodes };
}
function button(root, label) {
  const scan = element => element.tagName === 'button' && element.textContent.includes(label)
    ? element : element.children.map(scan).find(Boolean);
  const found = scan(root); assert.ok(found, `button ${label}`); return found;
}
async function setup(respond, prepare = false) {
  const calls = [], client = new IssueClient({ href, cryptoImpl: webcrypto,
    fetchImpl: (url, options) => { const call = { url: String(url), ...options }; calls.push(call); return respond(call, calls.length); } });
  await client.connect(token);
  if (prepare) await client.stage(1, 1, 'comment', { body: 'private prepared draft' });
  const document = dom(), view = mountIssues(document, { href }, { client });
  return { document, view, client, calls, get: id => document.getElementById(id) };
}
function listReply(rows = []) {
  return { ...identity, type: 'issue_page', after: 0, limit: 20, next_after: null, issues: rows };
}
function historyReply() {
  const row = issue();
  return { ...identity, type: 'issue_history', found: true, issue: row, after_version: 0,
    limit: 20, next_after_version: null, events: [{ version: 1, actor,
      action: { name: 'open', title: row.title, body: row.body, labels: row.labels } }] };
}

test('triage form sends the native AND predicate and a bounded read only', async () => {
  const query = { state: 'open', text: 'HTTP', opened_by: actor, assignee: actor, labels: ['bug'], case_sensitive: false };
  const ui = await setup(() => json(searchPage({ issues: [issue(1, { assignees: [actor] })] }, query)));
  ui.get('issue-search-query').value = 'HTTP'; ui.get('issue-search-state').value = 'open';
  ui.get('issue-search-opener').value = actor; ui.get('issue-search-labels').value = 'bug';
  ui.get('issue-search-assignee').value = actor;
  await ui.get('issue-search').fire('submit');
  assert.equal(ui.calls.length, 1);
  const call = ui.calls[0], form = new URLSearchParams(call.body);
  assert.equal(form.get('state'), 'open'); assert.equal(form.get('query'), 'HTTP');
  assert.deepEqual(form.getAll('label'), ['bug']); assert.equal(form.get('opened_by'), actor);
  assert.equal(form.get('assignee'), actor);
  assert.equal(form.get('max_scan'), '200'); assert.equal(form.get('limit'), '20');
  assert.equal(call.headers['Idempotency-Key'], undefined); assert.equal(call.url.includes(token), false);
  assert.match(ui.get('issue-content').textContent, /Applied filters/);
  assert.match(ui.get('issue-content').textContent, /1 matches/);
  assert.match(ui.get('issue-status').textContent, /Search complete/);
});

test('empty limited scans continue with frozen filters, native cursor and original head', async () => {
  const query = { text: 'original', labels: ['bug'], assignee: 'none' };
  const ui = await setup((_call, count) => json(count === 1
    ? searchPage({ issues: [], scanned: 200, complete: false, stop_reason: 'scan_limit',
      has_more_candidates: true, next_after: 350 }, query)
    : searchPage({ issues: [], after: 350 }, query)));
  ui.get('issue-search-query').value = 'original'; ui.get('issue-search-labels').value = 'bug';
  ui.get('issue-search-assignee').value = 'none';
  await ui.get('issue-search').fire('submit');
  assert.match(ui.get('issue-content').textContent, /Unexamined candidates remain/);
  assert.match(ui.get('issue-status').textContent, /another match is not guaranteed/);
  ui.get('issue-search-query').value = 'changed'; ui.get('issue-search-labels').value = 'later';
  ui.get('issue-search-assignee').value = actor;
  ui.get('issue-search-scan').value = '10';
  await button(ui.get('issue-paging'), 'Continue searching').fire('click');
  const next = new URLSearchParams(ui.calls[1].body);
  assert.equal(next.get('after'), '350'); assert.equal(next.get('expected_head'), head);
  assert.equal(next.get('query'), 'original'); assert.deepEqual(next.getAll('label'), ['bug']);
  assert.equal(next.get('assignee'), 'none');
  assert.equal(next.get('max_scan'), '200'); assert.equal(ui.get('issue-paging').children.length, 0);
  assert.match(ui.get('issue-content').textContent, /remaining snapshot suffix/);
  assert.match(ui.get('issue-status').textContent, /Search complete/);
});

test('a triaged issue opens its canonical history at the search snapshot', async () => {
  const ui = await setup(call => json(call.url.endsWith('/search') ? searchPage() : historyReply()));
  await ui.view.search({});
  await button(ui.get('issue-content'), '#1 Fix HTTP').fire('click');
  const target = new URL(ui.calls[1].url);
  assert.equal(target.pathname, '/repo.git/api/v1/issues/1'); assert.equal(target.searchParams.get('expected_head'), head);
  assert.match(ui.get('issue-content').textContent, /Canonical event history/);
  await button(ui.get('issue-content'), 'Comment').fire('click');
  assert.equal(ui.get('change-number').value, '1'); assert.equal(ui.get('change-version').value, '');
  assert.equal(ui.get('change-version').disabled, true);
  assert.equal(ui.get('change-action').value, 'append-comment'); assert.equal(ui.calls.length, 2);
});

test('search text and hostile issue titles remain inert DOM text', async () => {
  const hostile = '<img src=x onerror=alert(1)>\u202e';
  const ui = await setup(() => json(searchPage({ issues: [issue(1, { title: hostile })] }, { text: hostile })));
  await ui.view.search({ text: hostile });
  assert.ok(ui.get('issue-content').textContent.includes('<img src=x'));
  assert.ok(ui.get('issue-content').textContent.includes('\\u{202e}'));
  const tags = element => [element.tagName, ...element.children.flatMap(tags)];
  assert.ok(!tags(ui.get('issue-content')).some(tag => ['img', 'script', 'iframe'].includes(tag)));
});

test('disconnect clears private filters and late results but preserves the pending receipt', async () => {
  const pending = deferred(), ui = await setup(() => pending.promise, true);
  const before = ui.client.pending;
  ui.get('issue-search-query').value = 'private query'; ui.get('issue-search-labels').value = 'private label';
  ui.get('issue-search-opener').value = actor;
  ui.get('issue-search-assignee').value = actor;
  const search = ui.view.search({});
  ui.view.disconnect(); pending.resolve(json(searchPage())); await search;
  for (const id of ['issue-search-query', 'issue-search-labels', 'issue-search-opener', 'issue-search-assignee']) assert.equal(ui.get(id).value, '');
  assert.equal(ui.get('issue-content').textContent, ''); assert.match(ui.get('issue-status').textContent, /Disconnected/);
  assert.deepEqual(ui.client.pending, before); assert.equal(ui.client.connected, false);
});

test('opening a new list cancels the old search and forbids late view resurrection', async () => {
  const pending = deferred(), ui = await setup(call => call.url.endsWith('/search')
    ? pending.promise : json(listReply([issue(2, { title: 'new list' })])));
  const searching = ui.view.search({});
  await ui.view.read(null);
  assert.equal(ui.calls[0].signal.aborted, true);
  pending.resolve(json(searchPage({ issues: [issue(1, { title: 'stale search' })] })));
  await searching;
  assert.match(ui.get('issue-content').textContent, /new list/);
  assert.ok(!ui.get('issue-content').textContent.includes('stale search'));
});

test('cancel issue read never discards or dispatches the prepared change', async () => {
  const pending = deferred(), ui = await setup(() => pending.promise, true);
  const before = ui.client.pending, searching = ui.view.search({});
  await ui.get('issue-search-cancel').fire('click');
  assert.equal(ui.calls[0].signal.aborted, true);
  pending.resolve(json(searchPage())); await searching;
  assert.match(ui.get('issue-status').textContent, /read cancelled/);
  assert.equal(ui.get('issue-content').textContent, ''); assert.deepEqual(ui.client.pending, before);
  assert.equal(ui.calls.length, 1); assert.equal(ui.calls[0].headers['Idempotency-Key'], undefined);
});

test('stale continuation refuses and clears the old view without silently refreshing', async () => {
  const wrongHead = `alg:1:${'a'.repeat(64)}`;
  const ui = await setup(() => json(searchPage({ snapshot_token: wrongHead, after: 200, issues: [] })));
  await ui.view.search({}, 200, head);
  assert.match(ui.get('issue-status').textContent, /snapshot moved/);
  assert.equal(ui.get('issue-content').textContent, ''); assert.equal(ui.get('issue-paging').textContent, '');
  assert.equal(ui.calls.length, 1);
});

test('invalid filter input clears prior results and never becomes a broad query', async () => {
  const ui = await setup(() => json(searchPage())); await ui.view.search({});
  assert.ok(ui.get('issue-content').textContent.includes('Fix HTTP'));
  ui.get('issue-search-state').value = 'administrator'; await ui.get('issue-search').fire('submit');
  assert.equal(ui.calls.length, 1); assert.equal(ui.get('issue-content').textContent, '');
  assert.match(ui.get('issue-status').textContent, /Invalid issue search state/);
  ui.get('issue-search-scan').value = '1.5'; await ui.get('issue-search').fire('submit');
  assert.equal(ui.calls.length, 1); assert.match(ui.get('issue-status').textContent, /Invalid search scan limit/);
});

test('a forbidden search does not display a fabricated empty result', async () => {
  const ui = await setup(() => json({}, 403)); await ui.view.search({});
  assert.equal(ui.get('issue-content').textContent, ''); assert.match(ui.get('issue-status').textContent, /scope/);
  assert.ok(!ui.get('issue-status').textContent.includes('Search complete'));
});

test('the existing explicit publication workflow still clears stale search results', async () => {
  const ui = await setup(call => json(call.url.endsWith('/search') ? searchPage() : terminal), true);
  const key = ui.client.pending.key;
  await ui.view.search({}); await ui.get('send-change').fire('click');
  assert.equal(ui.client.pending, null); assert.equal(ui.get('issue-content').textContent, '');
  assert.match(ui.get('issue-status').textContent, /Committed/);
  assert.equal(ui.calls[1].headers['Idempotency-Key'], key);
  assert.equal(new URLSearchParams(ui.calls[1].body).get('body'), 'private prepared draft');
});

test('unassigned triage and a blank assignment field remain different explicit searches', async () => {
  const ui = await setup((_call, count) => json(searchPage({}, count === 1 ? { assignee: 'none' } : {})));
  ui.get('issue-search-assignee').value = 'none';
  await ui.get('issue-search').fire('submit');
  assert.equal(new URLSearchParams(ui.calls[0].body).get('assignee'), 'none');
  assert.match(ui.get('issue-content').textContent, /"assignee":"none"/);
  ui.get('issue-search-assignee').value = '';
  await ui.get('issue-search').fire('submit');
  assert.equal(new URLSearchParams(ui.calls[1].body).has('assignee'), false);
  assert.ok(!ui.get('issue-content').textContent.includes('"assignee"'));
});

test('issue assignment shortcuts preserve the issue snapshot and never mutate a draft', async () => {
  for (const assignees of [[actor, 'e'.repeat(32)], []]) {
    const history = historyReply();
    history.issue.assignees = assignees;
    if (assignees.length) {
      history.issue.version = 2;
      history.events.push({ version: 2, actor, action: { name: 'assign', assignees } });
    }
    const selected = assignees.at(-1) ?? 'none';
    const ui = await setup(call => json(call.url.endsWith('/search')
      ? searchPage({ issues: [issue(1, { assignees })] }, { assignee: selected }) : history), true);
    const pending = ui.client.pending;
    await ui.view.read(1);
    await button(ui.get('issue-content'), selected === 'none' ? 'Find unassigned issues' : `Find issues assigned to ${selected}`).fire('click');
    assert.equal(ui.calls.length, 2);
    const request = ui.calls[1], form = new URLSearchParams(request.body);
    assert.equal(form.get('assignee'), selected); assert.equal(form.get('expected_head'), head);
    assert.equal(form.get('after'), '0'); assert.equal(form.get('max_scan'), '200');
    assert.equal(form.has('principal'), false); assert.equal(request.headers['Idempotency-Key'], undefined);
    assert.deepEqual(ui.client.pending, pending); assert.equal(ui.client.pending.sent, false);
    assert.match(ui.get('issue-status').textContent, /Search complete/);
  }
});

test('detached assignment shortcuts cannot revive an old snapshot or disconnected session', async () => {
  const ui = await setup(call => json(call.url.includes('/issues/1?') ? historyReply() : listReply()));
  await ui.view.read(1);
  const stale = button(ui.get('issue-content'), 'Find unassigned issues');
  await ui.view.read(null);
  await stale.fire('click'); assert.equal(ui.calls.length, 2);
  await ui.view.read(1);
  const disconnected = button(ui.get('issue-content'), 'Find unassigned issues');
  ui.view.disconnect(); await disconnected.fire('click');
  assert.equal(ui.calls.length, 3); assert.equal(ui.get('issue-content').textContent, '');
});

test('invalid assignment input clears old results without silently broadening the query', async () => {
  const ui = await setup(() => json(searchPage())); await ui.view.search({});
  for (const value of ['None', 'admin', 'A'.repeat(32), '0'.repeat(31), '0'.repeat(33), ` ${actor}`, `${actor}\n`]) {
    ui.get('issue-search-assignee').value = value;
    await ui.get('issue-search').fire('submit');
    assert.equal(ui.calls.length, 1); assert.equal(ui.get('issue-content').textContent, '');
    assert.match(ui.get('issue-status').textContent, /assignee/);
  }
});

test('a delayed assignment result cannot replace a newer unassigned search', async () => {
  const pending = deferred();
  const ui = await setup((_call, count) => count === 1 ? pending.promise
    : json(searchPage({ issues: [issue(2, { title: 'unassigned result', assignees: [] })] }, { assignee: 'none' })));
  const old = ui.view.search({ assignee: actor });
  await ui.view.search({ assignee: 'none' });
  assert.equal(ui.calls[0].signal.aborted, true);
  pending.resolve(json(searchPage({ issues: [issue(1, { title: 'old assignment', assignees: [actor] })] }, { assignee: actor })));
  await old;
  assert.match(ui.get('issue-content').textContent, /unassigned result/);
  assert.ok(!ui.get('issue-content').textContent.includes('old assignment'));
  assert.match(ui.get('issue-content').textContent, /"assignee":"none"/);
});
