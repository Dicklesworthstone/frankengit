// DOM/fetch doubles exercise user-visible flows without a live authority service.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mountIssues } from '../../crates/fgit-node/src/smart_http/server/browser/issues-view.mjs';

class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.checked = true; this.files = []; this.text = ''; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { assert.fail('Executable HTML sink'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  addEventListener(name, handler) { this.listeners.set(name, handler); }
  fire(name, event = { preventDefault() {} }) { return this.listeners.get(name)?.(event); }
}
const token = 'c'.repeat(64), actor = '3'.repeat(32), head = `alg:1:${'b'.repeat(64)}`;
const ids = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32) };
const state = (number = 1, extra = {}) => ({ number, version: 1, title: '<img onerror=alert(1)>', body: 'body\u202e<script>', labels: ['bug'],
  state: 'open', opened_by: actor, last_actor: actor, comments: 0, ...extra });
const page = (extra = {}) => ({ ...ids, type: 'issue_page', object_format: 'sha1', snapshot_token: head, source_head: 'head',
  after: 0, limit: 20, next_after: null, issues: [state()], ...extra });
const history = (extra = {}) => ({ ...ids, type: 'issue_history', object_format: 'sha1', snapshot_token: head, source_head: 'head',
  found: true, issue: state(), after_version: 0, limit: 20, next_after_version: null,
  events: [{ version: 1, actor, action: { name: 'open', title: state().title, body: state().body, labels: ['bug'] } }], ...extra });
const committed = (extra = {}) => ({ ...ids, type: 'issue_publication', principal_id: actor, number: 1,
  expected_version: null, action: 'append-comment', tx_id: 'tx-1', outcome: 'committed', decision_sequence: 2,
  repository_commit_id: 'rcr-1', refusal_code: null, refusal_record_id: null, delivery_acknowledged: null, ...extra });
const undecided = { ...ids, type: 'transaction_outcome', repository_incarnation: '4'.repeat(32), principal_id: actor,
  selector: 'transaction', command_index: null, state: 'key_not_observed', terminal: false, transaction: null, decision: null,
  read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
async function settled() { for (let i = 0; i < 10; i += 1) await new Promise(setImmediate); }
function buttons(root) { return root.children.flatMap(child => [...(child.tagName === 'button' ? [child] : []), ...buttons(child)]); }
function click(root, name) { const found = buttons(root).find(child => child.textContent === name); assert.ok(found, `button ${name}`); found.fire('click'); }
function harness(respond = () => json(page())) {
  const names = ['issue-connection', 'issue-token', 'issue-disconnect', 'issue-status', 'issue-snapshot', 'issue-list',
    'issue-show', 'show-number', 'issue-content', 'issue-paging', 'issue-change', 'change-number', 'change-version',
    'change-action', 'change-title', 'change-body', 'change-labels', 'change-assignees', 'replace-title', 'replace-body', 'replace-labels',
    'title-field', 'body-field', 'labels-field', 'assignees-field', 'replace-body-label', 'prepared-change', 'prepared-summary', 'prepare-change',
    'save-receipt', 'send-change', 'check-outcome', 'discard-change', 'restore-receipt',
    'issue-search', 'issue-search-query', 'issue-search-state', 'issue-search-opener',
    'issue-search-labels', 'issue-search-case', 'issue-search-scan', 'issue-search-cancel'];
  const elements = Object.fromEntries(names.map(name => [name, new Element()])); elements['change-action'].value = 'open';
  const lifecycle = new Element(); const document = { getElementById: id => elements[id], createElement: tag => new Element(tag), defaultView: lifecycle };
  const calls = [], receipts = [];
  const fetchImpl = (url, options) => { const call = { url: String(url), ...options }; calls.push(call); return respond(call, calls.length); };
  const mounted = mountIssues(document, new URL('https://forge.example/team/repo.git/ui/issues/'), {
    fetchImpl, cryptoImpl: webcrypto, saveReceipt: value => receipts.push(value),
  });
  return { elements, lifecycle, document, calls, receipts, ...mounted,
    async connect(secret = token) { elements['issue-token'].value = secret; await elements['issue-connection'].fire('submit'); },
    async prepare(action = 'append-comment', fields = {}) {
      elements['change-number'].value = '1'; elements['change-version'].value = action === 'open' ? '0' : '1';
      elements['change-action'].value = action; elements['change-title'].value = fields.title ?? 'New title';
      elements['change-body'].value = fields.body ?? 'New comment'; elements['change-labels'].value = fields.labels ?? '';
      elements['change-assignees'].value = fields.assignees ?? '';
      await elements['issue-change'].fire('submit');
    },
  };
}

test('label additions use an empty delta without a version, including on locked closed issues', async () => {
  const issue = state(1, { version: 3, state: 'closed', locked: true });
  const events = [...history().events, { version: 2, actor, action: { name: 'close' } },
    { version: 3, actor, action: { name: 'lock' } }];
  const h = harness(call => json(call.method === 'POST'
    ? committed({ action: 'add-labels', command_profile: 'issue.add-labels.v1' })
    : call.url.includes('/issues?') ? page({ issues: [issue] }) : history({ issue, events })));
  await h.connect(); await h.read(1); click(h.elements['issue-content'], 'Add labels');
  assert.equal(h.elements['change-labels'].value, '');
  assert.equal(h.elements['labels-field'].hidden, false);
  assert.equal(h.elements['title-field'].hidden, true); assert.equal(h.elements['body-field'].hidden, true);
  assert.equal(h.elements['replace-labels'].disabled, true);
  assert.equal(h.elements['change-version'].disabled, true); assert.equal(h.elements['change-version'].required, false);
  assert.equal(h.elements['prepare-change'].disabled, false);
  h.elements['change-version'].value = 'stale version must not be submitted';
  h.elements['change-labels'].value = 'transport\nbug'; await h.elements['issue-change'].fire('submit');
  assert.equal(h.calls.length, 2); assert.equal(h.client.pending.expected_version, null);
  assert.equal(h.client.pending.body, 'label=bug&label=transport');
  h.elements['change-labels'].value = 'later form edits';
  h.elements['send-change'].fire('click'); await settled();
  assert.ok(h.calls.at(-1).url.endsWith('/issues/1/add-labels'));
  assert.equal(h.calls.at(-1).body, 'label=bug&label=transport');
  assert.equal(h.client.pending, null); assert.match(h.elements['issue-status'].textContent, /^Committed/);
});

test('issue list renders inert names and erases the token input on connection', async () => {
  const h = harness(); await h.connect();
  assert.equal(h.elements['issue-token'].value, ''); assert.ok(h.elements['issue-content'].textContent.includes('<img onerror=alert(1)>'));
  assert.ok(h.elements['issue-snapshot'].textContent.includes(head));
  assert.equal(h.calls[0].method, 'GET'); assert.equal(h.calls[0].headers['Idempotency-Key'], undefined);
});
test('opening an issue follows the list snapshot and displays literal body and principal data', async () => {
  const h = harness(call => json(call.url.includes('/issues?') ? page() : history())); await h.connect();
  click(h.elements['issue-content'], '#1 <img onerror=alert(1)>'); await settled();
  assert.equal(new URL(h.calls[1].url).searchParams.get('expected_head'), head);
  assert.match(h.elements['issue-content'].textContent, /body\\u\{202e\}<script>/);
  assert.ok(h.elements['issue-content'].textContent.includes(actor)); assert.equal(h.elements['show-number'].value, '1');
});
test('issue pages carry the original head and exact cursor, not an inferred next number', async () => {
  const h = harness((_call, n) => json(n === 1 ? page({ issues: Array.from({ length: 20 }, (_, i) => state(i + 10)), next_after: 29 })
    : page({ after: 29, issues: [] })));
  await h.connect(); click(h.elements['issue-paging'], 'Next issue page'); await settled();
  const query = new URL(h.calls[1].url).searchParams; assert.equal(query.get('after'), '29'); assert.equal(query.get('expected_head'), head);
});
test('comment selection requires no issue version; preparation does not publish', async () => {
  const h = harness(call => json(call.url.includes('/issues?') ? page() : history())); await h.connect();
  click(h.elements['issue-content'], '#1 <img onerror=alert(1)>'); await settled(); click(h.elements['issue-content'], 'Comment');
  assert.equal(h.elements['change-version'].value, ''); assert.equal(h.elements['change-body'].value, '');
  assert.equal(h.elements['change-version'].disabled, true); assert.equal(h.elements['change-version'].required, false);
  assert.equal(h.elements['change-action'].value, 'append-comment');
  h.elements['change-version'].value = 'a stale or invalid version is irrelevant';
  h.elements['change-body'].value = '<svg onload=alert(1)>'; await h.elements['issue-change'].fire('submit');
  assert.equal(h.calls.length, 2); assert.equal(h.client.pending.sent, false);
  assert.equal(h.client.pending.expected_version, null); assert.equal(h.client.pending.action, 'append-comment');
  assert.equal(new URLSearchParams(h.client.pending.body).has('expected_version'), false);
  assert.ok(h.elements['prepared-summary'].textContent.includes('<svg onload=alert(1)>'));
  assert.equal(h.elements['prepare-change'].disabled, true); assert.equal(h.elements['send-change'].disabled, false);
});
for (const lifecycle of ['open', 'closed']) test(`locked ${lifecycle} issue blocks comments and prepares an exact unlock`, async () => {
  const events = [...history().events, { version: 2, actor, action: { name: 'lock' } }];
  if (lifecycle === 'closed') events.push({ version: 3, actor, action: { name: 'close' } });
  const issue = state(1, { version: events.length, state: lifecycle, locked: true });
  const h = harness(call => json(call.url.includes('/issues?') ? page({ issues: [issue] }) : history({ issue, events })));
  await h.connect(); assert.match(h.elements['issue-content'].textContent, /locked/);
  await h.read(1);
  assert.ok(h.elements['issue-content'].textContent.includes(`${lifecycle} · locked`));
  assert.equal(buttons(h.elements['issue-content']).find(b => b.textContent === 'Comment').disabled, true);
  click(h.elements['issue-content'], 'Comment'); assert.match(h.elements['issue-status'].textContent, /locked/);
  h.elements['change-number'].value = '1'; h.elements['change-action'].value = 'append-comment';
  h.elements['change-action'].fire('change');
  assert.equal(h.elements['change-body'].disabled, true); assert.equal(h.elements['prepare-change'].disabled, true);
  await h.prepare(); assert.equal(h.client.pending, null); assert.equal(h.calls.length, 2);
  click(h.elements['issue-content'], 'Edit issue');
  assert.equal(h.elements['change-body'].disabled, false); assert.equal(h.elements['prepare-change'].disabled, false);
  click(h.elements['issue-content'], lifecycle === 'open' ? 'Close issue' : 'Reopen issue');
  assert.equal(h.elements['change-version'].value, String(events.length));
  click(h.elements['issue-content'], 'Unlock discussion');
  assert.equal(h.elements['change-version'].disabled, false); assert.equal(h.elements['change-version'].required, true);
  assert.equal(h.elements['change-version'].value, String(events.length)); assert.equal(h.elements['body-field'].hidden, true);
  await h.elements['issue-change'].fire('submit');
  assert.equal(h.client.pending.action, 'unlock'); assert.deepEqual(h.client.pending.fields, {});
  assert.equal(h.client.pending.body, `expected_version=${events.length}`); assert.equal(h.calls.length, 2);
});
test('legacy unlocked issue exposes lock and sends its prepared exact-version request', async () => {
  const h = harness(call => json(call.method === 'POST' ? committed({ action: 'lock', expected_version: 1 })
    : call.url.includes('/issues?') ? page() : history()));
  await h.connect(); await h.read(1);
  assert.ok(h.elements['issue-content'].textContent.includes('open · unlocked'));
  assert.equal(buttons(h.elements['issue-content']).find(b => b.textContent === 'Comment').disabled, false);
  click(h.elements['issue-content'], 'Lock discussion'); await h.elements['issue-change'].fire('submit');
  assert.equal(h.client.pending.action, 'lock'); assert.deepEqual(h.client.pending.fields, {});
  const key = h.client.pending.key;
  h.elements['send-change'].fire('click'); await settled();
  assert.ok(h.calls.at(-1).url.endsWith('/issues/1/lock')); assert.equal(h.calls.at(-1).body, 'expected_version=1');
  assert.equal(h.calls.at(-1).headers['Idempotency-Key'], key); assert.equal(h.client.pending, null);
  assert.match(h.elements['issue-status'].textContent, /^Committed/);
});
test('newly observed lock does not suppress recovery of an already prepared comment', async () => {
  const issue = state(1, { version: 2, locked: true });
  const detail = history({ issue, events: [...history().events, { version: 2, actor, action: { name: 'lock' } }] });
  const h = harness(call => json(call.method === 'POST' ? committed() : call.url.includes('/issues?') ? page() : detail));
  await h.connect(); await h.prepare(); const key = h.client.pending.key, body = h.client.pending.body;
  await h.read(1);
  assert.equal(h.elements['prepare-change'].disabled, true); assert.equal(h.elements['change-body'].disabled, true);
  assert.equal(h.elements['send-change'].disabled, false); assert.equal(h.elements['check-outcome'].disabled, false);
  h.elements['send-change'].fire('click'); await settled();
  assert.equal(h.calls.at(-1).headers['Idempotency-Key'], key); assert.equal(h.calls.at(-1).body, body);
  assert.equal(h.client.pending, null);
});
for (const mode of ['missing locked continuation', 'explicit locked continuation', 'legacy unlocked continuation']) {
  test(`${mode} preserves the original snapshot lock contract`, async () => {
    const locked = mode !== 'legacy unlocked continuation';
    const issue = state(1, { version: 21, ...(locked ? { locked: true } : {}) });
    const events = [...history().events, ...Array.from({ length: 20 }, (_, i) => ({ version: i + 2, actor,
      action: i === 0 && locked ? { name: 'lock' } : { name: 'edit', title: issue.title } }))];
    const h = harness(call => {
      if (call.url.includes('/issues?')) return json(page({ issues: [issue] }));
      const after = Number(new URL(call.url).searchParams.get('after_version')), snapshot = { ...issue };
      if (after && mode === 'missing locked continuation') delete snapshot.locked;
      return json(history({ issue: snapshot, after_version: after, events: events.slice(after, after + 20),
        next_after_version: after === 0 ? 20 : null }));
    });
    await h.connect(); await h.read(1);
    click(h.elements['issue-paging'], 'Next history page'); await settled();
    assert.equal(new URL(h.calls.at(-1).url).searchParams.get('expected_head'), head);
    assert.equal(new URL(h.calls.at(-1).url).searchParams.get('after_version'), '20');
    if (mode === 'missing locked continuation') {
      assert.equal(h.elements['issue-content'].textContent, '');
      assert.match(h.elements['issue-status'].textContent, /lock state changed within the same snapshot/);
    } else {
      assert.ok(h.elements['issue-content'].textContent.includes(`open · ${locked ? 'locked' : 'unlocked'}`));
      assert.match(h.elements['issue-status'].textContent, /Read complete/);
    }
  });
}
test('explicit send publishes the exact prepared draft even after editing the form again', async () => {
  const h = harness(call => json(call.method === 'GET' ? page() : committed())); await h.connect();
  await h.prepare('append-comment', { body: 'original' }); h.elements['change-body'].value = 'changed later';
  h.elements['send-change'].fire('click'); await settled();
  assert.equal(new URLSearchParams(h.calls[1].body).get('body'), 'original');
  assert.equal(new URLSearchParams(h.calls[1].body).has('expected_version'), false);
  assert.ok(h.calls[1].url.endsWith('/issues/1/append-comment'));
  assert.match(h.elements['issue-status'].textContent, /^Committed/); assert.equal(h.client.pending, null);
  assert.equal(h.elements['change-version'].value, ''); assert.equal(h.elements['issue-content'].textContent, '');
});
test('edit checkboxes preserve omitted fields and explicitly clear empty labels', async () => {
  const h = harness(); await h.connect();
  h.elements['replace-title'].checked = false; h.elements['replace-body'].checked = false;
  await h.prepare('edit'); const form = new URLSearchParams(h.client.pending.body);
  assert.equal(form.has('title'), false); assert.equal(form.has('body'), false); assert.equal(form.get('clear_labels'), 'true');
});
test('assignment controls add principals without an expected version and keep removals strict', async () => {
  const a = '11'.repeat(16), b = '22'.repeat(16);
  const detail = history({ issue: state(1, { assignees: [a] }) });
  const h = harness(call => json(call.method === 'POST' ? committed({ action: 'add-assignees', command_profile: 'issue.add-assignees.v1' })
    : call.url.includes('/issues?') ? page() : detail));
  await h.connect(); click(h.elements['issue-content'], '#1 <img onerror=alert(1)>'); await settled();
  assert.ok(h.elements['issue-content'].textContent.includes(`Assigned principals: ${a}`));
  click(h.elements['issue-content'], 'Remove assignees');
  assert.equal(h.elements['change-assignees'].value, a);
  assert.equal(h.elements['change-version'].value, '1');
  assert.equal(h.elements['change-version'].disabled, false); assert.equal(h.elements['change-version'].required, true);
  await h.elements['issue-change'].fire('submit');
  assert.equal(h.client.pending.action, 'unassign'); assert.equal(h.client.pending.body, `expected_version=1&assignee=${a}`);
  h.elements['discard-change'].fire('click'); assert.equal(h.client.pending, null);
  click(h.elements['issue-content'], 'Add assignees');
  assert.equal(h.elements['change-action'].value, 'add-assignees');
  assert.equal(h.elements['change-assignees'].value, '');
  assert.equal(h.elements['assignees-field'].hidden, false);
  assert.equal(h.elements['body-field'].hidden, true);
  assert.equal(h.elements['change-version'].value, '');
  assert.equal(h.elements['change-version'].disabled, true); assert.equal(h.elements['change-version'].required, false);
  h.elements['change-version'].value = 'a stale version must not constrain additions';
  h.elements['change-assignees'].value = `${b}\n${a}`;
  await h.elements['issue-change'].fire('submit');
  assert.equal(h.calls.length, 2);
  assert.equal(h.client.pending.expected_version, null);
  assert.match(h.elements['prepared-summary'].textContent, /add-assignees · no expected version/);
  h.elements['change-assignees'].value = 'ff'.repeat(16);
  h.elements['send-change'].fire('click'); await settled();
  assert.deepEqual(new URLSearchParams(h.calls[2].body).getAll('assignee'), [a, b]);
  assert.equal(new URLSearchParams(h.calls[2].body).has('expected_version'), false);
  assert.ok(h.calls[2].url.endsWith('/issues/1/add-assignees'));
  assert.match(h.elements['issue-status'].textContent, /^Committed/);
});
for (const lifecycle of ['open', 'closed']) test(`locked ${lifecycle} issue still permits version-independent assignee additions`, async () => {
  const events = [...history().events, { version: 2, actor, action: { name: 'lock' } }];
  if (lifecycle === 'closed') events.push({ version: 3, actor, action: { name: 'close' } });
  const issue = state(1, { version: events.length, state: lifecycle, locked: true });
  const h = harness(call => json(call.method === 'POST'
    ? committed({ action: 'add-assignees', command_profile: 'issue.add-assignees.v1' })
    : call.url.includes('/issues?') ? page({ issues: [issue] }) : history({ issue, events })));
  await h.connect(); await h.read(1);
  assert.equal(buttons(h.elements['issue-content']).find(button => button.textContent === 'Comment').disabled, true);
  assert.equal(buttons(h.elements['issue-content']).find(button => button.textContent === 'Add assignees').disabled, false);
  click(h.elements['issue-content'], 'Add assignees');
  assert.equal(h.elements['prepare-change'].disabled, false); assert.equal(h.elements['change-version'].disabled, true);
  assert.equal(h.elements['assignees-field'].hidden, false);
  h.elements['change-assignees'].value = actor;
  await h.elements['issue-change'].fire('submit');
  assert.equal(h.client.pending.action, 'add-assignees'); assert.equal(h.client.pending.body, `assignee=${actor}`);
  assert.equal(h.calls.length, 2);
  h.elements['send-change'].fire('click'); await settled();
  assert.ok(h.calls[2].url.endsWith('/issues/1/add-assignees')); assert.equal(h.client.pending, null);
  assert.match(h.elements['issue-status'].textContent, /^Committed/);
});
test('close and reopen prepare no title, body or label replacements', async () => {
  for (const action of ['close', 'reopen']) {
    const h = harness(); await h.connect(); await h.prepare(action);
    assert.equal(h.client.pending.body, 'expected_version=1'); assert.equal(h.calls.length, 1);
  }
});
test('snapshot changes do not silently retry against newer issue state', async () => {
  const h = harness((_call, n) => n === 1 ? json(page()) : json({ type: 'issue_error' }, 409)); await h.connect();
  click(h.elements['issue-content'], '#1 <img onerror=alert(1)>'); await settled();
  assert.equal(h.calls.length, 2); assert.equal(h.elements['issue-content'].textContent, '');
  assert.match(h.elements['issue-status'].textContent, /Reload explicitly/);
});
test('lost-response UI preserves key, blocks a replacement change and permits exact manual retry', async () => {
  let writes = 0;
  const h = harness(call => { if (call.method === 'GET') return json(page());
    if (++writes === 1) throw new TypeError('Lost response'); return json(committed()); });
  await h.connect(); await h.prepare(); h.elements['send-change'].fire('click'); await settled();
  assert.equal(h.client.pending.sent, true); assert.equal(h.elements['discard-change'].disabled, true);
  assert.match(h.elements['issue-status'].textContent, /pending request is retained/);
  assert.equal(h.elements['send-change'].textContent, 'Retry identical change');
  h.elements['send-change'].fire('click'); await settled();
  assert.equal(h.calls[1].body, h.calls[2].body);
  assert.equal(h.calls[1].headers['Idempotency-Key'], h.calls[2].headers['Idempotency-Key']);
});
test('unknown canonical lookup is prominently distinguished from a refusal', async () => {
  const h = harness(call => json(call.method === 'GET' ? page() : undecided)); await h.connect(); await h.prepare();
  h.elements['check-outcome'].fire('click'); await settled();
  assert.match(h.elements['issue-status'].textContent, /Outcome still unknown/); assert.ok(h.client.pending);
  assert.equal(h.calls[1].body, undefined); assert.equal(h.calls[1].url.endsWith('/outcomes'), true);
});
test('native HTTP-409 terminal refusal is never shown as committed', async () => {
  const h = harness(call => json(call.method === 'GET' ? page() : committed({ outcome: 'refused', repository_commit_id: null,
    refusal_code: 'VersionMismatch', refusal_record_id: 'refusal-1' }), call.method === 'GET' ? 200 : 409));
  await h.connect(); await h.prepare(); h.elements['send-change'].fire('click'); await settled();
  assert.match(h.elements['issue-status'].textContent, /^Refused/); assert.equal(h.client.pending, null);
});
test('receipt save contains the exact request but no secret; import never executes it', async () => {
  const old = harness(); await old.connect(); await old.prepare('append-comment', { body: 'private draft' });
  old.elements['save-receipt'].fire('click'); assert.equal(old.receipts.length, 1);
  const receipt = old.receipts[0]; assert.equal(receipt.includes(token), false); assert.ok(receipt.includes('private draft'));
  const h = harness(); await h.connect(); const bytes = new TextEncoder().encode(receipt);
  h.elements['restore-receipt'].files = [{ size: bytes.length, async arrayBuffer() { return bytes.buffer; } }];
  await h.elements['restore-receipt'].fire('change');
  assert.equal(h.calls.length, 1); assert.equal(h.client.pending.key, old.client.pending.key); assert.equal(h.client.pending.sent, true);
  assert.match(h.elements['issue-status'].textContent, /restored, not sent/);
});
test('disconnect and pagehide clear visible drafts but retain a token-free unresolved receipt', async () => {
  const h = harness(); await h.connect(); await h.prepare(); const key = h.client.pending.key;
  h.lifecycle.fire('pagehide'); assert.equal(h.client.connected, false);
  for (const id of ['issue-token', 'change-body', 'change-title', 'change-labels']) assert.equal(h.elements[id].value, '');
  assert.equal(h.elements['issue-content'].textContent, ''); assert.equal(h.client.pending.key, key);
  assert.match(h.elements['prepared-summary'].textContent, /Reconnect the original credential/);
  h.elements['save-receipt'].fire('click'); assert.equal(h.receipts.length, 1);
});
test('beforeunload warns only while there is unresolved local responsibility', async () => {
  const h = harness(); await h.connect(); let warned = false;
  h.lifecycle.fire('beforeunload', { preventDefault() { warned = true; } }); assert.equal(warned, false);
  await h.prepare(); h.lifecycle.fire('beforeunload', { preventDefault() { warned = true; } }); assert.equal(warned, true);
});
test('write-only grants do not require a successful issue read or gain read access', async () => {
  const h = harness(call => call.method === 'GET' ? json({}, 403) : json(committed({ action: 'open', expected_version: 0 })));
  await h.connect(); assert.equal(h.client.connected, true); assert.equal(h.elements['prepare-change'].disabled, false);
  await h.prepare('open'); h.elements['send-change'].fire('click'); await settled();
  assert.match(h.elements['issue-status'].textContent, /^Committed/); assert.equal(h.calls.length, 2);
});
test('out-of-order reads and late pagehide replies cannot restore cleared repository data', async () => {
  let resolve;
  const pending = new Promise(r => { resolve = r; });
  const h = harness((_call, n) => n === 1 ? pending : json(page({ issues: [] })));
  const first = h.connect();
  for (let i = 0; h.calls.length === 0 && i < 200; i += 1) await new Promise(resolve => setTimeout(resolve, 1));
  assert.equal(h.calls.length, 1);
  h.elements['issue-list'].fire('click'); await settled();
  resolve(json(page())); await first; await settled(); assert.match(h.elements['issue-content'].textContent, /No issues/);
  h.disconnect(); assert.equal(h.elements['issue-content'].textContent, '');
});
test('an oversize or invalid-UTF8 recovery file is never interpreted as a request', async () => {
  const h = harness(); await h.connect();
  h.elements['restore-receipt'].files = [{ size: 512 * 1024 + 1, arrayBuffer() { assert.fail('oversize read'); } }];
  await h.elements['restore-receipt'].fire('change'); assert.equal(h.client.pending, null);
  h.elements['restore-receipt'].files = [{ size: 1, async arrayBuffer() { return Uint8Array.of(255).buffer; } }];
  await h.elements['restore-receipt'].fire('change'); assert.equal(h.client.pending, null); assert.equal(h.calls.length, 1);
});
test('shipped HTML declares every referenced element and relative module paths correctly', () => {
  const base = '../../crates/fgit-node/src/smart_http/server/browser/';
  const html = readFileSync(new URL(`${base}issues.html`, import.meta.url), 'utf8');
  const view = readFileSync(new URL(`${base}issues-view.mjs`, import.meta.url), 'utf8');
  for (const match of view.matchAll(/byId\('([^']+)'\)/g)) assert.ok(html.includes(`id="${match[1]}"`), match[1]);
  assert.ok(html.includes('src="../issues-view.mjs"')); assert.ok(html.includes('href="../browser.css"'));
  assert.ok(!html.includes('<script>')); assert.ok(!view.includes('innerHTML'));
});

test('a current authentication refusal clears visible private editor data', async () => {
  const h = harness((_call, n) => n === 1 ? json(page()) : json({}, 401));
  await h.connect(); h.elements['change-title'].value = 'private draft'; h.elements['change-body'].value = 'private body';
  h.elements['issue-list'].fire('click'); await settled();
  assert.equal(h.client.connected, false); assert.equal(h.elements['change-title'].value, '');
  assert.equal(h.elements['change-body'].value, ''); assert.equal(h.elements['issue-content'].textContent, '');
});
