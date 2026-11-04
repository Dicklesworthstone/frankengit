// Actual milestone client/controller with DOM and HTTP peers. These fixtures
// establish browser behavior, not live native authority or server execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { MilestoneClient } from '../../crates/fgit-node/src/smart_http/server/browser/milestones.mjs';
import { mountMilestones } from '../../crates/fgit-node/src/smart_http/server/browser/milestones-view.mjs';

class Element {
  constructor(tag = 'div') {
    this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.checked = true;
    this.files = []; this.text = ''; this.disabled = false; this.hidden = false;
  }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { assert.fail('Executable HTML sink'); }
  append(...children) { this.children.push(...children); for (const child of children) child.parent = this; this.lastAppend = children.at(-1); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  addEventListener(name, handler) { this.listeners.set(name, handler); }
  fire(name, event = { preventDefault() {} }) { return this.listeners.get(name)?.(event); }
  click() { assert.ok(this.parent, 'download anchor must be attached before click'); this.clicked = true; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); this.parent = null; }
}
const token = 'c'.repeat(64), actor = '3'.repeat(32), head = `alg:1:${'b'.repeat(64)}`;
const ids = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32) };
const row = { number: 7, version: 1, title: '<img onerror=alert(1)>', body: 'Private body\u202e<script>',
  due_at: 0, state: 'open', opened_by: actor, last_actor: actor, open_issues: 2, closed_issues: 3 };
const opening = value => ({ version: 1, actor, action: { name: 'open', title: value.title, body: value.body, due_at: value.due_at } });
const page = extra => ({ ...ids, type: 'milestone_page', scope: 'repository_milestones', snapshot_token: head,
  after: 0, limit: 20, next_after: null, milestones: [row], ...extra });
const history = extra => ({ ...ids, type: 'milestone_history', scope: 'repository_milestones', snapshot_token: head,
  found: true, milestone: row, after_version: 0, limit: 20, next_after_version: null, events: [opening(row)], ...extra });
const terminal = extra => ({ ...ids, type: 'milestone_publication', number: 7, expected_version: 1, action: 'edit',
  principal_id: actor, tx_id: 'original-tx', outcome: 'committed', decision_sequence: 2,
  repository_commit_id: 'original-rcr', refusal_record_id: null, refusal_code: null, delivery_acknowledged: null, ...extra });
const recovery = settled => ({ ...ids, type: 'transaction_outcome', selector: 'transaction', command_index: null,
  read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
  repository_incarnation: 'incarnation', principal_id: actor, terminal: settled, state: settled ? 'committed' : 'key_not_observed',
  transaction: settled ? { tx_id: 'original-tx' } : null,
  decision: settled ? { kind: 'committed', decision_sequence: 2, repository_commit_id: 'original-rcr' } : null });
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const ordinary = call => json(call.url.includes('/milestones?') ? page() : history());
function descendants(root, tag) { return root.children.flatMap(child => [...(child.tagName === tag ? [child] : []), ...descendants(child, tag)]); }
function findButton(root, label) {
  const control = descendants(root, 'button').find(child => child.textContent === label);
  assert.ok(control, `button ${label}`); return control;
}
const click = (root, label) => findButton(root, label).fire('click');
async function settled() { for (let i = 0; i < 8; i += 1) await new Promise(setImmediate); }
function harness(respond = ordinary, cryptoImpl = webcrypto, browserDownload = false) {
  const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/milestones.html', import.meta.url), 'utf8');
  const names = [...html.matchAll(/id="([^"]+)"/g)].map(match => match[1]);
  assert.equal(new Set(names).size, names.length, 'the rendered milestone page must have unique IDs');
  const elements = Object.fromEntries(names.map(name => [name, new Element()]));
  elements['change-action'].value = 'open'; elements['change-version'].value = '0';
  elements['change-due-mode'].value = 'clear'; elements['milestone-limit'].value = '20';
  const lifecycle = new Element(), document = { getElementById: id => elements[id], createElement: tag => new Element(tag), defaultView: lifecycle, body: new Element('body') };
  const calls = [], receipts = [];
  const mounted = mountMilestones(document, new URL('https://forge.example/repo.git/ui/milestones/'), {
    fetchImpl: (url, init) => { const call = { url: String(url), ...init }; calls.push(call); return respond(call, calls.length); },
    cryptoImpl, ...(browserDownload ? {} : { saveReceipt: receipt => receipts.push(receipt) }),
  });
  return { elements, lifecycle, calls, receipts, document, ...mounted,
    async connect() { elements['milestone-token'].value = token; await elements['milestone-connect'].fire('submit'); },
    async edit() { await mounted.read(7); await click(elements['milestone-content'], 'Edit milestone'); },
  };
}

test('milestone navigation shows inert native text, UTC epoch date and exact member counts at the selected head', async () => {
  const h = harness(); await h.connect();
  assert.equal(h.elements['milestone-token'].value, '');
  assert.match(h.elements['milestone-content'].textContent, /2 open · 3 closed · 5 issues/);
  assert.match(h.elements['milestone-content'].textContent, /Due 1970-01-01 00:00:00 UTC/);
  await click(h.elements['milestone-content'], '#7 ' + row.title);
  assert.equal(new URL(h.calls[1].url).searchParams.get('expected_head'), head);
  assert.equal(new URL(h.calls[1].url).searchParams.get('render'), 'html_safe');
  assert.ok(h.elements['milestone-content'].textContent.includes(row.title));
  assert.match(h.elements['milestone-content'].textContent, /Private body\\u\{202e\}<script>/);
  assert.equal(h.elements['show-number'].value, '7');
  assert.equal(descendants(h.elements['milestone-content'], 'a')[0].href, '../issues/');
  assert.ok(h.elements['milestone-snapshot'].textContent.includes(head));
  for (const call of h.calls) {
    assert.equal(call.headers.Authorization, `Bearer ${token}`);
    assert.equal(call.headers['Idempotency-Key'], undefined);
    assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error');
  }
  h.client.disconnect();
});

test('milestone list pagination retains its original snapshot and page size after form edits', async () => {
  const rows = Array.from({ length: 5 }, (_, i) => ({ ...row, number: i + 1 }));
  const h = harness(call => {
    const q = new URL(call.url).searchParams;
    return json(page({ after: Number(q.get('after')), limit: 5,
      milestones: q.get('after') === '0' ? rows : [{ ...row, number: 6 }], next_after: q.get('after') === '0' ? 5 : null }));
  });
  h.elements['milestone-limit'].value = '5'; await h.connect();
  const oldNext = findButton(h.elements['milestone-paging'], 'Next milestone page');
  h.elements['milestone-limit'].value = '100'; await oldNext.fire('click');
  const query = new URL(h.calls[1].url).searchParams;
  assert.equal(query.get('after'), '5'); assert.equal(query.get('limit'), '5'); assert.equal(query.get('expected_head'), head);
  assert.equal(h.elements['milestone-paging'].children.length, 0);
  await oldNext.fire('click'); assert.equal(h.calls.length, 2, 'a replaced page cannot issue another read');
  h.client.disconnect();
});

test('milestone history pagination retains observed versions, head and applied limit', async () => {
  const events = [opening(row), ...Array.from({ length: 5 }, (_, n) => ({ version: n + 2, actor, action: { name: 'edit', body: `description ${n}` } }))];
  const current = { ...row, version: 6, body: 'description 4' };
  const h = harness(call => {
    const q = new URL(call.url).searchParams, after = Number(q.get('after_version'));
    if (call.url.includes('/milestones?')) return json(page({ limit: 5, milestones: [current] }));
    return json(history({ milestone: current, limit: 5, after_version: after, events: events.slice(after, after + 5), next_after_version: after === 0 ? 5 : null }));
  });
  h.elements['milestone-limit'].value = '5'; await h.connect();
  await click(h.elements['milestone-content'], '#7 ' + row.title);
  h.elements['milestone-limit'].value = '100';
  await click(h.elements['milestone-paging'], 'Next milestone history page');
  const q = new URL(h.calls[2].url).searchParams;
  assert.equal(q.get('after_version'), '5'); assert.equal(q.get('limit'), '5'); assert.equal(q.get('expected_head'), head);
  assert.match(h.elements['milestone-content'].textContent, /Version 6 · edit/);
  await click(h.elements['milestone-content'], 'Edit milestone');
  assert.equal(h.elements['change-version'].value, '6');
  h.client.disconnect();
});

test('opening a milestone prepares an unused number and an exact UTC epoch without publishing', async () => {
  const h = harness(); await h.connect(); h.elements['milestone-new'].fire('click');
  h.elements['change-number'].value = '8'; h.elements['change-title-text'].value = 'Release 雪'; h.elements['change-body'].value = '';
  h.elements['change-due-mode'].value = 'set'; h.elements['change-due-mode'].fire('change');
  h.elements['change-due'].value = '1970-01-01T00:00';
  await h.elements['milestone-change'].fire('submit');
  assert.equal(h.calls.length, 1); assert.equal(h.client.pending.number, 8); assert.equal(h.client.pending.expected_version, 0);
  assert.equal(h.client.pending.action, 'open'); assert.equal(h.client.pending.fields.due_at, 0);
  assert.equal(new URLSearchParams(h.client.pending.body).get('due_at'), '0');
  assert.equal(h.client.pending.sent, false); assert.match(h.client.pending.key, /^fgmi-/);
  assert.equal(h.elements['change-due'].required, true); h.client.disconnect();
});

test('editing uses the observed version, preserves an untouched date and sends the exact prepared bytes', async () => {
  const h = harness(call => call.method === 'POST' ? json(terminal()) : ordinary(call));
  await h.connect(); await h.edit();
  const staleEdit = findButton(h.elements['milestone-content'], 'Edit milestone');
  assert.equal(h.elements['change-version'].value, '1'); assert.equal(h.elements['change-due-mode'].value, 'preserve');
  assert.equal(h.elements['change-due'].value, '1970-01-01T00:00:00');
  h.elements['change-title-text'].value = 'Changed & 雪'; h.elements['replace-body'].checked = false;
  await h.elements['milestone-change'].fire('submit');
  assert.deepEqual(h.client.pending.fields, { title: 'Changed & 雪' });
  const prepared = h.client.pending;
  h.elements['change-title-text'].value = 'Later form edit'; h.elements['change-version'].value = '99';
  await h.elements['send-change'].fire('click');
  assert.equal(h.calls[2].body, prepared.body); assert.equal(h.calls[2].headers['Idempotency-Key'], prepared.key);
  assert.equal(h.client.pending, null); assert.match(h.elements['milestone-status'].textContent, /^Committed/);
  assert.equal(h.elements['milestone-content'].textContent, '');
  await staleEdit.fire('click'); assert.equal(h.elements['change-title-text'].value, 'Later form edit');
  h.client.disconnect();
});

for (const [mode, input, expected, body] of [
  ['clear', '', null, 'expected_version=1&clear_due_at=true'],
  ['set', '1970-01-01T00:00:01', 1, 'expected_version=1&due_at=1'],
  ['set', '2028-02-29T12:34:56', Date.UTC(2028, 1, 29, 12, 34, 56) / 1000, null],
  ['set', '9999-12-31T23:59:59', 253402300799, 'expected_version=1&due_at=253402300799'],
]) test(`explicit ${mode} date ${input || '(none)'} preserves the exact due-date edit`, async () => {
  const h = harness(); await h.connect(); await h.edit();
  h.elements['replace-title'].checked = false; h.elements['replace-body'].checked = false;
  h.elements['change-due-mode'].value = mode; h.elements['change-due-mode'].fire('change'); h.elements['change-due'].value = input;
  await h.elements['milestone-change'].fire('submit');
  assert.deepEqual(h.client.pending.fields, { due_at: expected });
  if (body) assert.equal(h.client.pending.body, body);
  assert.equal(h.calls.length, 2); h.client.disconnect();
});

test('invalid calendar times and a no-op edit refuse before preparation or network mutation', async () => {
  const h = harness(); await h.connect(); await h.edit();
  h.elements['replace-title'].checked = false; h.elements['replace-body'].checked = false;
  await h.elements['milestone-change'].fire('submit'); assert.equal(h.client.pending, null);
  assert.match(h.elements['milestone-status'].textContent, /at least one/);
  h.elements['change-due-mode'].value = 'set';
  for (const value of ['', '2027-02-29T12:00', '2028-02-30T12:00', '2026-13-01T00:00', '1969-12-31T23:59:59', '2026-11-01T25:00', '2026-11-01T00:00Z']) {
    h.elements['change-due'].value = value; await h.elements['milestone-change'].fire('submit');
    assert.equal(h.client.pending, null, value); assert.match(h.elements['milestone-status'].textContent, /due date|Due date/);
  }
  assert.equal(h.calls.length, 2); h.client.disconnect();
});

for (const state of ['open', 'closed']) test(`${state} milestone offers its exact close or reopen transition without resending metadata`, async () => {
  const events = state === 'closed' ? [opening(row), { version: 2, actor, action: { name: 'close' } }] : [opening(row)];
  const current = { ...row, state, version: events.length };
  const h = harness(call => json(call.url.includes('/milestones?') ? page({ milestones: [current] }) : history({ milestone: current, events })));
  await h.connect(); await h.read(7);
  await click(h.elements['milestone-content'], state === 'open' ? 'Close milestone' : 'Reopen milestone');
  assert.equal(h.elements['due-field'].hidden, true); assert.equal(h.elements['title-field'].hidden, true);
  await h.elements['milestone-change'].fire('submit');
  assert.equal(h.client.pending.action, state === 'open' ? 'close' : 'reopen');
  assert.equal(h.client.pending.expected_version, events.length); assert.deepEqual(h.client.pending.fields, {});
  assert.equal(h.client.pending.body, `expected_version=${events.length}`); h.client.disconnect();
});

test('empty pages and missing milestone envelopes remain distinct observations', async () => {
  const h = harness(call => call.url.includes('/milestones?') ? json(page({ milestones: [] }))
    : json(history({ found: false, milestone: null, events: [] }), 404));
  await h.connect(); assert.match(h.elements['milestone-content'].textContent, /No milestones at this snapshot/);
  await h.read(7); assert.match(h.elements['milestone-content'].textContent, /Milestone #7 was not found/);
  assert.equal(descendants(h.elements['milestone-content'], 'button').length, 0); h.client.disconnect();
});

test('a canonical stale-version refusal settles the prepared request without a silent refresh or retry', async () => {
  const h = harness(call => call.method === 'POST' ? json(terminal({ outcome: 'refused', repository_commit_id: null,
    refusal_code: 'EvidenceStale', refusal_record_id: 'refusal-1' }), 409) : ordinary(call));
  await h.connect(); await h.edit(); h.elements['change-title-text'].value = 'Keep exact predecessor';
  await h.elements['milestone-change'].fire('submit'); await h.elements['send-change'].fire('click');
  assert.equal(h.client.pending, null); assert.match(h.elements['milestone-status'].textContent, /^Refused: EvidenceStale/);
  assert.equal(h.calls.length, 3); assert.equal(h.elements['milestone-content'].textContent, ''); h.client.disconnect();
});

for (const boundary of ['disconnect', 'pagehide', 'reconnect']) test(`${boundary} clears private milestone views and editors while retaining original retry custody`, async () => {
  const h = harness(call => { if (call.method === 'POST') throw new Error('reply lost'); return ordinary(call); });
  await h.connect(); await h.edit(); h.elements['change-body'].value = 'Private unresolved milestone';
  await h.elements['milestone-change'].fire('submit'); await h.elements['send-change'].fire('click');
  const original = h.client.pending; assert.equal(original.sent, true);
  if (boundary === 'reconnect') await h.connect();
  else if (boundary === 'pagehide') h.lifecycle.fire('pagehide');
  else h.elements['milestone-disconnect'].fire('click');
  for (const id of ['milestone-token', 'change-number', 'change-version', 'change-title-text', 'change-body', 'change-due', 'show-number', 'restore-receipt']) {
    assert.equal(h.elements[id].value, '', id);
  }
  assert.equal(h.client.pending.key, original.key); assert.equal(h.client.pending.body, original.body);
  assert.equal(h.elements['discard-change'].disabled, true);
  if (!h.client.connected) {
    assert.equal(h.elements['milestone-content'].textContent, '');
    assert.equal(h.elements['prepared-summary'].textContent.includes('Private unresolved milestone'), false);
  }
  await h.elements['save-receipt'].fire('click');
  assert.equal(JSON.parse(h.receipts[0]).request.key, original.key); assert.equal(h.receipts[0].includes(token), false);
  assert.match(h.elements['milestone-status'].textContent, /offered for download\. Verify it was saved/);
  h.client.disconnect();
});

test('recovery download attaches its anchor and retains the URL long enough for browser delivery', async t => {
  const h = harness(ordinary, webcrypto, true); await h.connect(); await h.edit();
  await h.elements['milestone-change'].fire('submit');
  let payload;
  const revoked = [];
  t.mock.method(URL, 'createObjectURL', blob => { payload = blob; return 'blob:milestone-retry'; });
  t.mock.method(URL, 'revokeObjectURL', value => revoked.push(value));
  t.mock.timers.enable({ apis: ['setTimeout'] });
  await h.elements['save-receipt'].fire('click');
  const link = h.document.body.lastAppend;
  assert.equal(link.clicked, true); assert.equal(link.parent, null); assert.equal(h.document.body.children.length, 0);
  assert.equal(link.download, 'frankengit-milestone-7-retry.json'); assert.equal(link.href, 'blob:milestone-retry');
  assert.equal(JSON.parse(await payload.text()).request.key, h.client.pending.key);
  assert.equal(h.client.pending.exported, true); assert.equal(h.calls.length, 2);
  assert.match(h.elements['milestone-status'].textContent, /offered for download\. Verify it was saved/);
  t.mock.timers.tick(29_999); assert.deepEqual(revoked, []);
  t.mock.timers.tick(1); assert.deepEqual(revoked, ['blob:milestone-retry']); h.client.disconnect();
});

test('saved legacy milestone receipts restore on the dedicated page and recover without resubmission', async () => {
  const old = new MilestoneClient({ href: 'https://forge.example/repo.git/ui/issues/', cryptoImpl: webcrypto });
  await old.connect(token); await old.stage(7, 1, 'edit', { due_at: null }, { tenant: ids.tenant_id, repository: ids.repository_id });
  const serialized = old.exportReceipt(), original = old.pending; old.disconnect();
  let known = false;
  const h = harness(call => call.url.endsWith('/outcomes') ? json(recovery(known)) : ordinary(call));
  await h.connect(); h.elements['restore-receipt'].files = [new File([serialized], 'retry.json')];
  await h.elements['restore-receipt'].fire('change');
  assert.equal(h.client.pending.key, original.key); assert.equal(h.calls.length, 1);
  await h.elements['check-outcome'].fire('click'); assert.ok(h.client.pending); assert.equal(h.elements['discard-change'].disabled, true);
  known = true; await h.elements['check-outcome'].fire('click');
  assert.equal(h.client.pending, null); assert.match(h.elements['milestone-status'].textContent, /^Committed/);
  for (const call of h.calls.slice(1)) {
    assert.ok(call.url.endsWith('/outcomes')); assert.equal(call.body, undefined);
    assert.equal(call.headers['Idempotency-Key'], original.key);
  }
  h.client.disconnect();
});

test('receipt imports reject oversized or malformed UTF-8 files before retaining a request', async () => {
  const h = harness(); await h.connect();
  h.elements['restore-receipt'].files = [{ size: 1024 * 1024, arrayBuffer() { assert.fail('oversized file read'); } }];
  await h.elements['restore-receipt'].fire('change'); assert.equal(h.client.pending, null);
  assert.match(h.elements['milestone-status'].textContent, /too large/);
  h.elements['restore-receipt'].files = [new File([new Uint8Array([0xff])], 'bad.json')];
  await h.elements['restore-receipt'].fire('change'); assert.equal(h.client.pending, null);
  assert.match(h.elements['milestone-status'].textContent, /UTF|encoded|valid/i); assert.equal(h.calls.length, 1); h.client.disconnect();
});

test('a receipt selected before reconnect cannot restore into the new connection', async () => {
  const source = harness(); await source.connect(); await source.edit();
  await source.elements['milestone-change'].fire('submit');
  const bytes = new TextEncoder().encode(source.client.exportReceipt()); source.client.disconnect();
  const h = harness(); await h.connect(); let finish;
  h.elements['restore-receipt'].files = [{ size: bytes.length, arrayBuffer: () => new Promise(resolve => { finish = () => resolve(bytes.buffer); }) }];
  const importing = h.elements['restore-receipt'].fire('change'); await settled(); assert.equal(typeof finish, 'function');
  await h.connect(); finish(); await importing;
  assert.equal(h.client.pending, null); assert.equal(h.calls.length, 2); h.client.disconnect();
});

test('late cancelled history cannot replace a fresh list or overwrite its status', async () => {
  let finish;
  const h = harness((call, count) => count === 2 ? new Promise(resolve => { finish = resolve; }) : ordinary(call));
  await h.connect(); h.elements['show-number'].value = '7';
  const reading = h.elements['milestone-show'].fire('submit'); await settled();
  await h.elements['milestone-list'].fire('click'); const status = h.elements['milestone-status'].textContent;
  finish(json(history())); await reading;
  assert.equal(h.elements['milestone-status'].textContent, status);
  assert.match(status, /milestones on this snapshot page/);
  assert.equal(descendants(h.elements['milestone-content'], 'h2').length, 0); h.client.disconnect();
});

test('cancellation and page hiding prevent late milestone bodies from restoring a view', async () => {
  for (const boundary of ['cancel', 'pagehide']) {
    let finish;
    const h = harness((call, count) => count === 2 ? new Promise(resolve => { finish = resolve; }) : ordinary(call));
    await h.connect(); const reading = h.read(7); await settled();
    if (boundary === 'cancel') h.elements['milestone-cancel'].fire('click'); else h.lifecycle.fire('pagehide');
    finish(json(history())); await reading;
    assert.equal(h.elements['milestone-content'].textContent, ''); assert.equal(h.elements['milestone-snapshot'].textContent, '');
    h.client.disconnect();
  }
});

test('read-grant refusal preserves an explicitly connected write-only milestone editor', async () => {
  const h = harness(call => call.method === 'GET' ? new Response('', { status: 403 }) : json(terminal({ number: 8, expected_version: 0, action: 'open' })));
  await h.connect(); assert.equal(h.client.connected, true);
  h.elements['milestone-new'].fire('click'); h.elements['change-number'].value = '8'; h.elements['change-title-text'].value = 'Write-only milestone';
  await h.elements['milestone-change'].fire('submit'); await h.elements['send-change'].fire('click');
  assert.equal(h.client.pending, null); assert.match(h.elements['milestone-status'].textContent, /^Committed/); h.client.disconnect();
});

test('credential expiry clears private milestone data while keeping an uncertain original mutation', async () => {
  const h = harness(call => call.method === 'POST' ? new Response('', { status: 401 }) : ordinary(call));
  await h.connect(); await h.edit(); h.elements['change-body'].value = 'Private expiring request';
  await h.elements['milestone-change'].fire('submit'); const original = h.client.pending;
  await h.elements['send-change'].fire('click');
  assert.equal(h.client.connected, false); assert.equal(h.client.pending.key, original.key); assert.equal(h.client.pending.body, original.body);
  assert.equal(h.elements['milestone-content'].textContent, ''); assert.equal(h.elements['change-body'].value, '');
  assert.equal(h.elements['prepared-summary'].textContent.includes('Private expiring request'), false);
  assert.equal(h.elements['discard-change'].disabled, true); assert.match(h.elements['milestone-status'].textContent, /Outcome unknown/);
});

test('leaving warns while a milestone request is unresolved and never sends it', async () => {
  const h = harness(); await h.connect();
  const unload = () => { let warned = false; const event = { preventDefault() { warned = true; } }; h.lifecycle.fire('beforeunload', event); return { warned, returnValue: event.returnValue }; };
  assert.equal(unload().warned, false); await h.edit(); await h.elements['milestone-change'].fire('submit');
  const calls = h.calls.length; assert.deepEqual(unload(), { warned: true, returnValue: '' }); assert.equal(h.calls.length, calls);
  await h.elements['discard-change'].fire('click'); assert.equal(unload().warned, false); h.client.disconnect();
});
