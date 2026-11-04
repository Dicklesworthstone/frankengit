// Actual controller and clients with explicit DOM/native-contract HTTP peers.
// These assertions do not claim execution in Chromium or against a Rust node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { IssueClient } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { MilestoneClient } from '../../crates/fgit-node/src/smart_http/server/browser/milestones.mjs';
import { mountIssues } from '../../crates/fgit-node/src/smart_http/server/browser/issues-view.mjs';
import { token, head, actor, identity, issue, searchPage, json, terminal, deferred } from './issues-search-fixture.mjs';

const href = 'https://forge.example/repo.git/ui/issues/';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/issues.html', import.meta.url), 'utf8');
const settle = async () => { for (let n = 0; n < 12; n += 1) await new Promise(setImmediate); };
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.checked = false; this.disabled = false; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { assert.fail('Executable HTML sink'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text = ''; this.children = children; }
  addEventListener(type, listener) { if (!this.listeners.has(type)) this.listeners.set(type, []); this.listeners.get(type).push(listener); }
  async fire(type) { await Promise.all((this.listeners.get(type) ?? []).map(fn => fn({ preventDefault() {} }))); await settle(); }
}
function dom() {
  const nodes = new Map([...html.matchAll(/<([a-z]+)\b[^>]*\bid="([^"]+)"[^>]*>/g)].map(match => {
    const node = new Element(match[1]); node.value = /\bvalue="([^"]*)"/.exec(match[0])?.[1] ?? '';
    node.checked = /\bchecked\b/.test(match[0]); return [match[2], node];
  }));
  nodes.get('change-action').value = 'open'; nodes.get('issue-search-state').value = 'all';
  return { body: new Element('body'), defaultView: new Element('window'), createElement: tag => new Element(tag),
    getElementById: id => { assert.ok(nodes.has(id), `undeclared element ${id}`); return nodes.get(id); } };
}
function button(root, label) {
  const scan = el => el.tagName === 'button' && el.textContent.includes(label) ? el : el.children.map(scan).find(Boolean);
  const result = scan(root); assert.ok(result, `missing button ${label}`); return result;
}
function history() {
  const row = issue(1, { version: 4, locked: true, state: 'closed', milestone: 7 });
  return { ...identity, type: 'issue_history', found: true, issue: row, after_version: 0, limit: 20,
    next_after_version: null, events: [
      { version: 1, actor, action: { name: 'open', title: row.title, body: row.body, labels: row.labels } },
      { version: 2, actor, action: { name: 'set-milestone', milestone: 7, expected_milestone_version: 1 } },
      { version: 3, actor, action: { name: 'lock' } }, { version: 4, actor, action: { name: 'close' } },
    ] };
}
const milestone = (number = 8, extra = {}) => ({ number, version: 3, title: `Release ${number}`, body: '', due_at: null,
  state: 'open', opened_by: actor, last_actor: actor, open_issues: 2, closed_issues: 3, ...extra });
const milestonePage = (extra = {}) => ({ ...identity, scope: 'repository_milestones', type: 'milestone_page',
  after: 0, limit: 20, next_after: null, milestones: [milestone()], ...extra });
async function setup(respond = () => json(milestonePage())) {
  const calls = [], fetchImpl = (url, init) => {
    const call = { url: String(url), ...init }; calls.push(call);
    return call.url.includes('/api/v1/issues/1?') ? json(history()) : respond(call, calls.length);
  };
  const client = new IssueClient({ href, cryptoImpl: webcrypto, fetchImpl });
  const milestoneClient = new MilestoneClient({ href, cryptoImpl: webcrypto, fetchImpl });
  await client.connect(token); await milestoneClient.connect(token);
  const document = dom(), view = mountIssues(document, { href }, { client, milestoneClient, cryptoImpl: webcrypto });
  const get = id => document.getElementById(id);
  await view.read(1); assert.match(get('issue-content').textContent, /Canonical event history/);
  return { client, milestoneClient, calls, document, view, get,
    async choose() {
      await button(get('issue-content'), 'Set or move milestone').fire('click');
      await view.readMilestones();
      await button(get('milestone-choices'), 'Use #8').fire('click');
    } };
}

test('moving a locked closed issue pins both observed versions and preserves the exact prepared request', async () => {
  const ui = await setup(call => json(call.method === 'POST'
    ? { ...terminal, action: 'set-milestone', expected_version: 4 } : milestonePage()));
  await ui.choose();
  assert.equal(new URL(ui.calls[1].url).searchParams.get('expected_head'), head);
  assert.equal(ui.get('milestone-field').hidden, false);
  assert.equal(ui.get('prepare-change').disabled, false);
  assert.match(ui.get('selected-milestone').textContent, /milestone version 3 · issue version 4/);
  await ui.get('issue-change').fire('submit');
  assert.equal(ui.calls.length, 2, 'preparation performs no mutation');
  const pending = ui.client.pending;
  assert.equal(pending.body, 'expected_version=4&milestone=8&expected_milestone_version=3');
  assert.equal(ui.client.exportReceipt().includes(token), false);
  ui.get('change-version').value = '99'; await ui.get('change-version').fire('input');
  await ui.get('send-change').fire('click');
  assert.equal(ui.calls[2].body, pending.body); assert.equal(ui.calls[2].headers['Idempotency-Key'], pending.key);
  assert.equal(ui.client.pending, null); assert.match(ui.get('issue-status').textContent, /^Committed/);
  assert.equal(ui.get('milestone-choices').textContent, '');
});

test('closed milestones are visible but cannot be selected or prepared even through a stale control', async () => {
  const ui = await setup(() => json(milestonePage({ milestones: [milestone(8, { state: 'closed' })] })));
  await button(ui.get('issue-content'), 'Set or move milestone').fire('click'); await ui.view.readMilestones();
  const choice = button(ui.get('milestone-choices'), 'Use #8'); assert.equal(choice.disabled, true);
  await choice.fire('click'); await ui.get('issue-change').fire('submit');
  assert.equal(ui.client.pending, null); assert.equal(ui.get('prepare-change').disabled, true);
  assert.match(ui.get('issue-status').textContent, /Select an open milestone/); assert.equal(ui.calls.length, 2);
});

test('issue identity edits invalidate the chosen milestone and detached choices cannot restore it', async () => {
  const ui = await setup(); await ui.choose();
  const staleChoice = button(ui.get('milestone-choices'), 'Use #8');
  ui.get('change-number').value = '2'; await ui.get('change-number').fire('input');
  await staleChoice.fire('click'); await ui.get('issue-change').fire('submit');
  assert.equal(ui.client.pending, null); assert.equal(ui.get('prepare-change').disabled, true);
  assert.equal(ui.get('milestone-choices').textContent, '');
  await ui.view.readMilestones(); assert.equal(ui.calls.length, 2);
  assert.match(ui.get('issue-status').textContent, /Open the issue/);
});

test('milestone choice pagination retains the issue snapshot and native numeric cursor', async () => {
  let page = 0;
  const ui = await setup(() => json(++page === 1 ? milestonePage({
    milestones: Array.from({ length: 20 }, (_, index) => milestone(index + 10)), next_after: 29,
  }) : milestonePage({ after: 29, milestones: [milestone(40)] })));
  await button(ui.get('issue-content'), 'Set or move milestone').fire('click'); await ui.view.readMilestones();
  await button(ui.get('milestone-paging'), 'Next milestone choices').fire('click');
  const query = new URL(ui.calls[2].url).searchParams;
  assert.equal(query.get('after'), '29'); assert.equal(query.get('expected_head'), head);
  assert.equal(query.get('limit'), '20'); assert.match(ui.get('milestone-choices').textContent, /Release 40/);
});

test('snapshot or repository mismatches and scope refusals never produce usable milestone choices', async () => {
  for (const response of [() => json(milestonePage({ snapshot_token: `alg:1:${'a'.repeat(64)}` })),
    () => json(milestonePage({ repository_id: 'other' })), () => json({}, 403), () => json({}, 409)]) {
    const ui = await setup(response);
    await button(ui.get('issue-content'), 'Set or move milestone').fire('click'); await ui.view.readMilestones();
    assert.equal(ui.get('milestone-choices').textContent, ''); assert.equal(ui.get('prepare-change').disabled, true);
    assert.equal(ui.client.pending, null); assert.equal(ui.calls.length, 2);
    assert.doesNotMatch(ui.get('issue-status').textContent, /No milestones|Choose an open milestone/);
  }
});

test('revocation during milestone selection disconnects both clients and clears private issue data', async () => {
  const ui = await setup(() => json({}, 401));
  await button(ui.get('issue-content'), 'Set or move milestone').fire('click'); await ui.view.readMilestones();
  assert.equal(ui.client.connected, false); assert.equal(ui.milestoneClient.connected, false);
  assert.equal(ui.get('issue-content').textContent, ''); assert.equal(ui.get('change-number').value, '');
  assert.match(ui.get('issue-status').textContent, /revoked/);
});

test('new issue reads cancel milestone reads and cannot resurrect their old choices', async () => {
  const delayed = deferred(), ui = await setup(() => delayed.promise);
  await button(ui.get('issue-content'), 'Set or move milestone').fire('click');
  const reading = ui.view.readMilestones(); await settle();
  await ui.view.read(1); assert.equal(ui.calls[1].signal.aborted, true);
  delayed.resolve(json(milestonePage())); await reading;
  assert.equal(ui.get('milestone-choices').textContent, ''); assert.match(ui.get('issue-content').textContent, /Canonical event history/);
});

test('clear membership works at the selected issue version and needs no milestone mutation', async () => {
  const ui = await setup(call => json({ ...terminal, action: 'clear-milestone', expected_version: 4 }));
  await button(ui.get('issue-content'), 'Clear milestone').fire('click');
  assert.equal(ui.get('milestone-field').hidden, true); await ui.get('issue-change').fire('submit');
  assert.equal(ui.client.pending.body, 'expected_version=4'); assert.equal(ui.calls.length, 1);
  await ui.get('send-change').fire('click');
  assert.ok(ui.calls[1].url.endsWith('/issues/1/clear-milestone')); assert.equal(ui.client.pending, null);
});

test('native stale-membership refusal settles only its original exact request without re-reading versions', async () => {
  const ui = await setup(call => call.method === 'POST' ? json({ ...terminal, action: 'set-milestone', expected_version: 4,
    outcome: 'refused', repository_commit_id: null, refusal_record_id: 'refusal', refusal_code: 'EvidenceStale' }, 409) : json(milestonePage()));
  await ui.choose(); await ui.get('issue-change').fire('submit'); await ui.get('send-change').fire('click');
  assert.equal(ui.client.pending, null); assert.equal(ui.calls.length, 3);
  assert.match(ui.get('issue-status').textContent, /^Refused.*EvidenceStale/);
});

test('milestone search accepts exact numbers and none, rejects invalid input, and freezes continued predicates', async () => {
  let page = 0;
  const ui = await setup(call => {
    const form = new URLSearchParams(call.body), value = form.get('milestone');
    const query = { milestone: value === 'none' ? 'none' : Number(value) };
    return json(++page === 1 ? searchPage({ issues: [], scanned: 200, complete: false, stop_reason: 'scan_limit',
      has_more_candidates: true, next_after: 350 }, query) : searchPage({ issues: [], after: Number(form.get('after')) }, query));
  });
  ui.get('issue-search-milestone').value = '7'; await ui.get('issue-search').fire('submit');
  ui.get('issue-search-milestone').value = 'none'; await button(ui.get('issue-paging'), 'Continue searching').fire('click');
  let form = new URLSearchParams(ui.calls[2].body);
  assert.equal(form.get('milestone'), '7'); assert.equal(form.get('expected_head'), head); assert.equal(form.get('after'), '350');
  await ui.get('issue-search').fire('submit'); form = new URLSearchParams(ui.calls[3].body);
  assert.equal(form.get('milestone'), 'none'); assert.equal(form.has('expected_head'), false);
  for (const invalid of ['0', '07', 'all', '9007199254740992']) {
    ui.get('issue-search-milestone').value = invalid; await ui.get('issue-search').fire('submit');
    assert.equal(ui.calls.length, 4); assert.equal(ui.get('issue-content').textContent, '');
  }
});

test('member navigation keeps the original issue snapshot without silently changing the form', async () => {
  const ui = await setup(() => json(searchPage({ issues: [issue(1, { milestone: 7 })] }, { milestone: 7 })));
  await button(ui.get('issue-content'), 'Show milestone issues').fire('click');
  const form = new URLSearchParams(ui.calls[1].body);
  assert.equal(form.get('milestone'), '7'); assert.equal(form.get('expected_head'), head);
  assert.match(ui.get('issue-content').textContent, /Issue search results/);
});

test('disconnect clears both selections and filters while retaining the exact token-free pending request', async () => {
  const ui = await setup(); await ui.choose(); await ui.get('issue-change').fire('submit');
  const pending = ui.client.pending; ui.get('issue-search-milestone').value = '7'; ui.view.disconnect();
  assert.deepEqual(ui.client.pending, pending); assert.equal(ui.client.connected, false); assert.equal(ui.milestoneClient.connected, false);
  assert.equal(ui.get('milestone-choices').textContent, ''); assert.equal(ui.get('issue-content').textContent, '');
  assert.equal(ui.get('issue-search-milestone').value, ''); assert.equal(ui.get('prepared-summary').textContent.includes('milestone": 8'), false);
});
