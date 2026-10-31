// Component tests use the real ProtectionClient, native-schema HTTP fixtures,
// real Web Crypto and a deliberately small inert DOM, not a live Rust node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mountProtection } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { TOKEN, ROTATED, ADMIN, REVIEWER, OTHER, HREF, hex, policy, refPolicy, snapshot, terminal, recovered, response, deferred, webcrypto } from './protection-fixtures.mjs';

class Node {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.parent = null; this.listeners = new Map();
    this.value = ''; this.checked = false; this.disabled = false; this.id = ''; this.attributes = new Map(); this.text = ''; }
  set textContent(value) { this.replaceChildren(); this.text = String(value); }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { throw new Error('HTML execution sink used'); }
  append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } }
  replaceChildren(...children) { for (const child of this.children) child.parent = null; this.children = []; this.text = ''; this.append(...children); }
  remove() { if (this.parent) { const parent = this.parent; parent.children.splice(parent.children.indexOf(this), 1); this.parent = null; } }
  setAttribute(name, value) { assert.equal(/^on/i.test(name), false); this.attributes.set(name, String(value)); }
  addEventListener(name, handler) { if (!this.listeners.has(name)) this.listeners.set(name, []); this.listeners.get(name).push(handler); }
  async emit(name, event = {}) {
    event.preventDefault ??= () => { event.defaultPrevented = true; };
    await Promise.all((this.listeners.get(name) ?? []).map(handler => handler(event))); return event;
  }
  all(tag) { return this.children.flatMap(child => [...(child.tagName === tag ? [child] : []), ...child.all(tag)]); }
}
class Doc {
  constructor() {
    this.body = new Node('body'); this.main = new Node('main'); this.main.id = 'pr-collaboration'; this.body.append(this.main);
    this.prToken = new Node('input'); this.prToken.id = 'token'; this.prToken.value = 'unrelated-pr-secret'; this.main.append(this.prToken);
    this.defaultView = new Node('window'); this.defaultView.location = { href: HREF };
    Object.defineProperty(this.defaultView, 'localStorage', { get() { throw new Error('Persistent secret storage used'); } });
  }
  createElement(tag) { return new Node(tag); }
  getElementById(id) { return [this.body, ...this.body.all('main'), ...this.body.all('details'),
    ...this.body.all('input'), ...this.body.all('textarea'), ...this.body.all('button'), ...this.body.all('pre'),
    ...this.body.all('p'), ...this.body.all('form'), ...this.body.all('div')].find(node => node.id === id) ?? null; }
}
function ui({ format = 'sha1', respond = () => null, cryptoImpl = webcrypto, downloadImpl = null } = {}) {
  const doc = new Doc(), calls = [], downloads = []; let view;
  view = mountProtection(doc, { href: HREF, cryptoImpl,
    downloadImpl: downloadImpl ?? ((name, text) => downloads.push({ name, text })),
    fetchImpl: async (url, request) => {
      const call = { url, ...request }; calls.push(call);
      const answer = await respond(call, view.client);
      if (answer !== null && answer !== undefined) return answer;
      return request.method === 'GET' ? response(snapshot(format))
        : url.pathname.endsWith('/outcomes') ? response(recovered(view.client.pending)) : response(terminal(view.client.pending));
    } });
  const node = name => { const found = doc.getElementById(`protection-${name}`); assert.ok(found, name); return found; };
  const fire = (name, event = 'click') => node(name).emit(event);
  const connect = async (token = TOKEN, person = ADMIN, recoveryOnly = false) => {
    node('token').value = token; node('principal').value = person; node('recovery-only').checked = recoveryOnly;
    await fire('connection', 'submit');
  };
  const ready = async () => { await connect(); await fire('load'); };
  const stage = async () => { await fire('editor', 'submit'); await fire('stage'); assert.ok(view.client.pending, node('status').textContent); };
  const send = async () => { node('confirm').checked = true; await fire('confirm', 'change'); await fire('send'); };
  const rows = () => node('branches').all('fieldset').map(group => ({ group, reference: group.all('input')[0],
    reviewers: group.all('textarea')[0], approvals: group.all('input')[1], remove: group.all('button')[0],
    addCheck: group.all('button').find(button => button.textContent === 'Add required workflow check') }));
  return { doc, calls, downloads, client: view.client, node, fire, connect, ready, stage, send, rows };
}

test('protection has an independent inert connection and no automatic reads or writes', async () => {
  const h = ui(); assert.equal(h.calls.length, 0); assert.equal(h.node('load').disabled, true);
  assert.equal(h.node('token').type, 'password'); assert.equal(h.node('token').autocomplete, 'off');
  await h.connect(); assert.equal(h.calls.length, 0); assert.equal(h.node('token').value, '');
  assert.equal(h.doc.prToken.value, 'unrelated-pr-secret');
  await h.fire('load'); assert.equal(h.calls.length, 1); assert.equal(h.calls[0].method, 'GET');
  assert.equal(h.calls[0].headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(h.doc.main.textContent.includes(TOKEN), false); assert.equal(h.node('status').attributes.get('role'), 'status');
});
for (const format of ['sha1', 'sha256']) {
  test(`${format}: full replacement preview, explicit stage, explicit send and exact u64 display`, async () => {
    const h = ui({ format }); await h.ready();
    assert.match(h.node('snapshot').textContent, /9007199254740992/); assert.match(h.node('snapshot').textContent, /9007199254740993/);
    h.node('administrators').value = OTHER; h.rows()[0].reviewers.value = OTHER;
    await h.fire('editor', 'submit'); assert.equal(h.client.pending, null); assert.equal(h.calls.length, 1);
    assert.match(h.node('changes').textContent, /administrators_removed/); assert.ok(h.node('changes').textContent.includes(ADMIN));
    assert.ok(h.node('changes').textContent.includes(REVIEWER)); assert.equal(h.node('stage').disabled, false);
    await h.fire('stage'); const intent = h.client.pending.intent;
    assert.equal(intent.source.scope.format, format); assert.equal(h.calls.length, 1);
    await h.fire('send'); assert.equal(h.calls.length, 1); assert.equal(h.node('send').disabled, true);
    assert.equal(h.node('administrators').disabled, true); assert.equal(h.rows()[0].reference.disabled, true);
    await h.send(); assert.equal(h.calls.length, 2);
    assert.equal(h.calls[1].body, intent.body); assert.equal(h.calls[1].headers['Idempotency-Key'], intent.key);
    const form = new URLSearchParams(h.calls[1].body);
    assert.deepEqual(form.getAll('administrator'), [OTHER]); assert.deepEqual(form.getAll('required_reviewer'), [`${hex('refs/heads/main')}:${OTHER}`]);
    assert.equal(form.get('expected_epoch'), '9007199254740993'); assert.equal(form.has('principal'), false);
    assert.match(h.node('status').textContent, /Canonical committed/); assert.match(h.node('status').textContent, /18446744073709551615/);
    assert.match(h.node('status').textContent, /delivery acknowledgement is not established/);
    assert.equal(h.client.pending, null); assert.equal(h.node('snapshot').textContent, ''); assert.equal(h.node('stage').disabled, true);
    await h.fire('stage'); assert.equal(h.calls.length, 2); assert.equal(h.client.pending, null);
  });
}
test('uninstalled policy cannot bootstrap remotely; disabled installed policy retains administrators', async () => {
  const absent = ui({ respond: () => response(snapshot('sha1', { version: '0', installed: false, enabled: false, policy: null })) });
  await absent.ready(); assert.match(absent.node('status').textContent, /trusted-local/); assert.equal(absent.node('administrators').disabled, true);
  await absent.fire('stage'); assert.equal(absent.client.pending, null); assert.equal(absent.calls.length, 1);
  const disabled = ui({ respond: () => response(snapshot('sha1', { enabled: false, policy: { administrators: [ADMIN], branches: [] } })) });
  await disabled.ready(); assert.equal(disabled.node('administrators').value, ADMIN); assert.equal(disabled.node('administrators').disabled, false);
  assert.match(disabled.node('status').textContent, /not an uninstalled policy/);
});
test('removing the last branch requires explicit clear-all and does not remove administrators', async () => {
  const h = ui(); await h.ready(); await h.rows()[0].remove.emit('click');
  await h.fire('editor', 'submit'); assert.match(h.node('status').textContent, /explicit clear-all/);
  assert.equal(h.node('stage').disabled, true); assert.equal(h.client.pending, null);
  h.node('clear').checked = true; await h.fire('clear', 'change'); await h.stage();
  const form = new URLSearchParams(h.client.pending.intent.body);
  assert.equal(form.get('clear'), 'true'); assert.deepEqual(form.getAll('administrator'), [ADMIN]);
  assert.deepEqual(form.getAll('required_reviewer'), []); assert.equal(h.calls.length, 1);
});
for (const profile of ['reference_facts_v1', 'reference_actor_id_v1', 'reference_authentication_v1']) {
test(`${profile}: PR editor preserves the enforced policy while editing administrators or removing the last branch`, async () => {
  const compiled = refPolicy(profile);
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: { ...policy(), ref_policy: compiled } })) : null });
  await h.ready(); assert.ok(h.node('snapshot').textContent.includes(compiled.snapshot_id));
  h.node('administrators').value = OTHER;
  await h.rows()[0].remove.emit('click');
  await h.stage();
  assert.deepEqual(h.client.pending.intent.replacement.ref_policy, compiled);
  const form = new URLSearchParams(h.client.pending.intent.body);
  assert.equal(form.get('ref_policy_frame_hex'), compiled.frame_hex);
  assert.equal(form.has('clear'), false);
  assert.deepEqual(h.client.pending.intent.replacement.branches, []);
  assert.equal(h.calls.length, 1, 'editing does not publish');
});
}
test('PR editor clears an enforced ref policy only through explicit empty clear-all', async () => {
  const p = { administrators: [ADMIN], branches: [], ref_policy: refPolicy() };
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: p })) : null });
  await h.ready(); assert.doesNotMatch(h.node('status').textContent, /no protected branches/);
  h.node('clear').checked = true; await h.fire('clear', 'change'); await h.stage();
  assert.equal(h.client.pending.intent.replacement.ref_policy, undefined);
  const form = new URLSearchParams(h.client.pending.intent.body);
  assert.equal(form.has('ref_policy_frame_hex'), false); assert.equal(form.get('clear'), 'true');
  assert.ok(h.node('pending').textContent.includes(refPolicy().snapshot_id));
});
test('clear-all cannot silently delete branches still present in the replacement', async () => {
  const h = ui(); await h.ready(); h.node('clear').checked = true; await h.fire('editor', 'submit');
  assert.match(h.node('status').textContent, /cannot accompany branch rules/); assert.equal(h.client.pending, null);
});
test('a changed preview cannot stage, including edits that skipped an input event', async () => {
  const h = ui(); await h.ready(); await h.fire('editor', 'submit');
  h.rows()[0].reviewers.value = OTHER; await h.fire('stage'); assert.equal(h.client.pending, null); assert.match(h.node('status').textContent, /Preview again/);
  await h.fire('editor', 'submit'); h.rows()[0].reference.value = hex('refs/heads/topic'); await h.rows()[0].reference.emit('input');
  assert.equal(h.node('stage').disabled, true); await h.fire('stage'); assert.equal(h.client.pending, null);
  assert.equal(h.calls.length, 1);
});
test('a refreshed source snapshot cannot be substituted underneath an existing preview', async () => {
  let reads = 0;
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { version: String(10 + ++reads) })) : null });
  await h.ready(); await h.fire('editor', 'submit'); await h.client.load(); await h.fire('stage');
  assert.equal(h.client.pending, null); assert.match(h.node('status').textContent, /source policy changed/); assert.equal(h.calls.length, 2);
});
test('byte-only branches and markup-like ref text remain exact inert data', async () => {
  const raw = Buffer.concat([Buffer.from('refs/heads/<svg>/'), Buffer.from([255])]).toString('hex');
  const p = { administrators: [ADMIN], branches: [{ reference_hex: raw, required_reviewers: [REVIEWER] }] };
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: p })) : null });
  await h.ready(); assert.equal(h.rows()[0].reference.value, raw); assert.equal(h.doc.body.all('svg').length, 0);
  assert.match(h.rows()[0].group.textContent, /\\xff/); await h.stage();
  assert.equal(new URLSearchParams(h.client.pending.intent.body).get('required_reviewer'), `${raw}:${REVIEWER}`);
});
test('policy editing rejects malformed, duplicate and oversized principal lists before staging', async () => {
  const h = ui(); await h.ready();
  for (const value of ['', `${ADMIN}\n${ADMIN}`, ` ${ADMIN}`, ADMIN.toUpperCase(), 'x'.repeat(1057)]) {
    h.node('administrators').value = value; await h.fire('editor', 'submit'); await h.fire('stage'); assert.equal(h.client.pending, null);
  }
  assert.equal(h.calls.length, 1);
});
test('branch rows have finite capacity even when a disabled add button is dispatched', async () => {
  const h = ui(); await h.ready(); for (let i = 1; i < 64; i++) await h.fire('add-branch');
  assert.equal(h.rows().length, 64); assert.equal(h.node('add-branch').disabled, true);
  await h.fire('add-branch'); assert.equal(h.rows().length, 64); assert.match(h.node('status').textContent, /At most 64/);
  assert.equal(h.calls.length, 1);
});
test('pending intent is immutable and exported receipts forbid local discard even after disconnect', async () => {
  const h = ui(); await h.ready(); await h.stage(); const intent = h.client.pending.intent;
  h.node('administrators').value = OTHER; await h.fire('administrators', 'input');
  await h.fire('export'); assert.equal(h.downloads.length, 1); assert.equal(h.downloads[0].text.includes(TOKEN), false);
  assert.deepEqual(JSON.parse(h.downloads[0].text).intent, intent); assert.equal(h.node('discard').disabled, true);
  await h.fire('discard'); assert.deepEqual(h.client.pending.intent, intent);
  await h.fire('disconnect'); assert.equal(h.node('token').value, ''); assert.equal(h.node('principal').value, '');
  assert.equal(h.node('export').disabled, false); await h.fire('export'); assert.deepEqual(JSON.parse(h.downloads[1].text).intent, intent);
  assert.equal(h.calls.length, 1);
});
test('never-sent, never-exported draft can be discarded but requires a new preview', async () => {
  const h = ui(); await h.ready(); await h.stage(); await h.fire('discard');
  assert.equal(h.client.pending, null); assert.equal(h.node('stage').disabled, true); assert.equal(h.calls.length, 1);
});
test('ambiguous send retries only original bytes/key and requires confirmation on every attempt', async () => {
  let attempts = 0;
  const h = ui({ respond: call => { if (call.method === 'POST' && ++attempts === 1) throw new Error('fixture lost reply'); } });
  await h.ready(); await h.stage(); const intent = h.client.pending.intent; await h.send();
  assert.match(h.node('status').textContent, /Outcome remains unknown/); assert.equal(h.client.pending.sent, true);
  assert.equal(h.node('confirm').checked, false); await h.fire('send'); assert.equal(h.calls.length, 2);
  await h.send(); assert.equal(h.calls.length, 3);
  assert.equal(h.calls[1].body, intent.body); assert.equal(h.calls[2].body, intent.body);
  assert.equal(h.calls[1].headers['Idempotency-Key'], h.calls[2].headers['Idempotency-Key']);
});
test('absence from outcome lookup is not non-commit and never submits a replacement', async () => {
  const h = ui({ respond: (call, client) => call.url.pathname.endsWith('/outcomes') ? response(recovered(client.pending, 'key_not_observed')) : null });
  await h.ready(); await h.stage(); const key = h.client.pending.intent.key; await h.fire('recover');
  assert.match(h.node('status').textContent, /Outcome unknown.*key_not_observed/); assert.equal(h.client.pending.intent.key, key);
  assert.equal(h.calls[1].body, undefined); assert.equal(h.calls[1].headers['Idempotency-Key'], key);
});
test('canonical refusal consumes the old proposal and requires an explicit policy reload', async () => {
  const h = ui({ respond: (call, client) => call.method === 'POST' ? response(terminal(client.pending, 'refused'), 409) : null });
  await h.ready(); await h.stage(); await h.send(); assert.match(h.node('status').textContent, /Canonical refused/);
  assert.equal(h.client.pending, null); assert.equal(h.node('administrators').value, ''); assert.equal(h.calls.length, 2);
  await h.fire('stage'); assert.equal(h.client.pending, null); assert.equal(h.calls.length, 2);
});
test('wrong-principal terminal response is not displayed as a committed policy', async () => {
  const h = ui({ respond: (call, client) => call.method === 'POST' ? response(terminal(client.pending, 'committed', { principal_id: OTHER })) : null });
  await h.ready(); await h.stage(); const key = h.client.pending.intent.key; await h.send();
  assert.doesNotMatch(h.node('status').textContent, /Canonical committed/); assert.equal(h.client.pending.intent.key, key);
});
test('disconnect fences a late policy read and reenables connection when it finally settles', async () => {
  const gate = deferred(); const h = ui({ respond: () => gate.promise }); await h.connect();
  const read = h.fire('load'); await Promise.resolve(); assert.equal(h.calls.length, 1);
  await h.fire('disconnect'); assert.equal(h.node('snapshot').textContent, '');
  gate.resolve(response(snapshot())); await read;
  assert.equal(h.client.connected, false); assert.equal(h.rows().length, 0); assert.equal(h.node('connect').disabled, false);
  assert.match(h.node('status').textContent, /Disconnected/); assert.equal(h.node('administrators').value, '');
});
test('disconnect during publication preserves the exact recovery responsibility', async () => {
  const gate = deferred(); const h = ui({ respond: call => call.method === 'POST' ? gate.promise : null });
  await h.ready(); await h.stage(); const pending = h.client.pending; const sending = h.send();
  await new Promise(resolve => setImmediate(resolve)); assert.equal(h.calls.length, 2);
  await h.fire('disconnect'); gate.resolve(response(terminal(pending))); await sending;
  assert.equal(h.client.pending.intent.key, pending.intent.key); assert.equal(h.client.pending.sent, true);
  assert.match(h.node('status').textContent, /Disconnected/); assert.equal(h.node('export').disabled, false);
});
test('rotated credential on a retained request is strictly outcome-only until explicit reconnect', async () => {
  const h = ui(); await h.ready(); await h.stage(); const key = h.client.pending.intent.key;
  await h.fire('disconnect'); await h.connect(ROTATED, ADMIN, true); assert.equal(h.client.recoveryOnly, true);
  await h.fire('load'); await h.fire('editor', 'submit'); await h.fire('stage'); await h.send(); await h.fire('discard');
  assert.equal(h.calls.length, 1); assert.equal(h.client.pending.intent.key, key);
  await h.fire('recover'); assert.equal(h.calls.length, 2); assert.equal(h.calls[1].headers.Authorization, `Bearer ${ROTATED}`);
  assert.equal(h.calls[1].headers['Idempotency-Key'], key); assert.equal(h.calls[1].body, undefined);
  assert.equal(h.client.pending, null); assert.equal(h.client.recoveryOnly, true); assert.equal(h.node('load').disabled, true);
});
test('page lifecycle clears credentials but warns and retains pending recovery data', async () => {
  const h = ui(); assert.equal((await h.doc.defaultView.emit('beforeunload')).defaultPrevented, undefined);
  await h.ready(); await h.stage(); const key = h.client.pending.intent.key;
  assert.equal((await h.doc.defaultView.emit('beforeunload')).defaultPrevented, true);
  await h.doc.defaultView.emit('pagehide'); assert.equal(h.client.connected, false); assert.equal(h.client.pending.intent.key, key);
});
test('a failed receipt download still prevents unsafe draft discard', async () => {
  const h = ui({ downloadImpl: () => { throw new Error('fixture download refused'); } }); await h.ready(); await h.stage(); await h.fire('export');
  assert.match(h.node('status').textContent, /download refused/); assert.equal(h.client.pending.exported, true);
  await h.fire('discard'); assert.ok(h.client.pending);
});
test('the same page cannot mount duplicate protection authority controls', () => {
  const h = ui(); assert.throws(() => mountProtection(h.doc, { downloadImpl: () => {} }), /mounted once/); assert.equal(h.calls.length, 0);
});

test('PR protection editor exposes quorum, preserves it through reviewer edits and freezes its exact count', async () => {
  const selected = { administrators: [ADMIN], branches: [{
    reference_hex: hex('refs/heads/main'), required_reviewers: [REVIEWER, OTHER, 'd'.repeat(32)],
    required_approvals: 2, required_checks: [{
      source_ref_hex: hex('refs/heads/ci'), publisher: OTHER, graph_root: '7'.repeat(64), job: 'test',
    }],
  }] };
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: selected })) : null });
  await h.ready();
  assert.equal(h.rows()[0].approvals.value, '2');
  assert.match(h.rows()[0].group.textContent, /2 of 3 listed reviewers/);
  h.rows()[0].reviewers.value += `\n${'e'.repeat(32)}`; await h.rows()[0].reviewers.emit('input');
  assert.equal(h.rows()[0].approvals.value, '2'); assert.match(h.rows()[0].group.textContent, /2 of 4 listed reviewers/);
  await h.stage();
  assert.equal(h.client.pending.intent.replacement.branches[0].required_approvals, 2);
  assert.deepEqual(h.client.pending.intent.replacement.branches[0].required_checks, selected.branches[0].required_checks);
  assert.equal(h.rows()[0].approvals.disabled, true);
  assert.deepEqual(new URLSearchParams(h.client.pending.intent.body).getAll('required_approvals'), [`${hex('refs/heads/main')}:2`]);
});
test('quorum edits invalidate a preview and invalid counts never submit a replacement', async () => {
  const selected = { administrators: [ADMIN], branches: [{
    reference_hex: hex('refs/heads/main'), required_reviewers: [REVIEWER, OTHER, 'd'.repeat(32)], required_approvals: 2,
  }] };
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: selected })) : null });
  await h.ready(); await h.fire('editor', 'submit');
  h.rows()[0].approvals.value = '1'; await h.fire('stage');
  assert.equal(h.client.pending, null); assert.match(h.node('status').textContent, /Preview again/);
  await h.fire('editor', 'submit'); h.rows()[0].approvals.value = '2'; await h.rows()[0].approvals.emit('input');
  assert.equal(h.node('stage').disabled, true);
  for (const value of ['0', '4', '01', '-1', '+1', '1.0', '1e0', '33']) {
    h.rows()[0].approvals.value = value; await h.fire('editor', 'submit');
    assert.equal(h.client.pending, null); assert.equal(h.node('stage').disabled, true);
  }
  assert.equal(h.calls.length, 1);
  h.rows()[0].approvals.value = ''; h.rows()[0].approvals.validity = { badInput: true };
  await h.fire('editor', 'submit');
  assert.equal(h.node('stage').disabled, true); assert.match(h.node('status').textContent, /whole approval count/);
  h.rows()[0].approvals.validity = { badInput: false };
  h.rows()[0].approvals.value = ''; await h.rows()[0].approvals.emit('input'); await h.stage();
  assert.equal(Object.hasOwn(h.client.pending.intent.replacement.branches[0], 'required_approvals'), false);
  assert.equal(new URLSearchParams(h.client.pending.intent.body).has('required_approvals'), false);
});


function requiredCheck(extra = {}) {
  return { source_ref_hex: hex('refs/heads/ci-main'), publisher: OTHER, graph_root: '7'.repeat(64), job: 'build', ...extra };
}

test('PR panel preserves queue-only rules and freezes an explicit queue checkbox', async () => {
  const selected = { administrators: [ADMIN], branches: [{
    reference_hex: hex('refs/heads/main'), required_reviewers: [], require_merge_queue: true,
  }] };
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: selected })) : null });
  await h.ready();
  const queue = h.rows()[0].group.all('input').find(input => input.attributes.has('data-require-merge-queue'));
  assert.ok(queue); assert.equal(queue.checked, true); assert.equal(queue.disabled, false);
  await h.stage();
  assert.deepEqual(h.client.pending.intent.replacement, selected);
  assert.deepEqual(new URLSearchParams(h.client.pending.intent.body).getAll('require_merge_queue'), [hex('refs/heads/main')]);
  assert.equal(queue.disabled, true);
  queue.checked = false;
  await h.send();
  const sent = h.calls.find(call => call.method === 'POST');
  assert.deepEqual(new URLSearchParams(sent.body).getAll('require_merge_queue'), [hex('refs/heads/main')]);
});

test('PR panel previews an explicit queue removal and rejects an empty rule', async () => {
  const selected = policy(); selected.branches[0].require_merge_queue = true;
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: selected })) : null });
  await h.ready();
  const row = h.rows()[0], queue = row.group.all('input').find(input => input.attributes.has('data-require-merge-queue'));
  queue.checked = false; await queue.emit('change');
  row.reviewers.value = ''; await row.reviewers.emit('input');
  await h.fire('editor', 'submit');
  assert.equal(h.node('stage').disabled, true); assert.equal(h.client.pending, null);
  row.reviewers.value = REVIEWER; await row.reviewers.emit('input');
  await h.stage();
  assert.equal(Object.hasOwn(h.client.pending.intent.replacement.branches[0], 'require_merge_queue'), false);
  assert.match(h.node('changes').textContent, /require_merge_queue_after/);
  assert.equal(new URLSearchParams(h.client.pending.intent.body).has('require_merge_queue'), false);
});
function checkRows(h, branch = h.rows()[0]) {
  return branch.group.all('div').filter(node => node.attributes.get('data-required-check-row') === 'true').map(group => ({
    group, fields: Object.fromEntries(group.all('input').map(input => [input.attributes.get('data-required-check-field'), input])),
    remove: group.all('button')[0],
  }));
}
async function appendCheck(h, selected = requiredCheck(), branch = h.rows()[0]) {
  const count = checkRows(h, branch).length;
  await branch.addCheck.emit('click');
  const checks = checkRows(h, branch); assert.equal(checks.length, count + 1);
  const check = checks.at(-1);
  for (const [name, value] of Object.entries(selected)) {
    check.fields[name].value = value; await check.fields[name].emit('input');
  }
  return check;
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: PR editor creates and publishes a check-only policy with exact byte and Unicode selectors`, async () => {
    const h = ui({ format }); await h.ready();
    const branch = h.rows()[0]; branch.reviewers.value = ''; await branch.reviewers.emit('input');
    const selector = requiredCheck({ source_ref_hex: `${hex('refs/heads/ci/')}ff`, job: '  build: β <script>  ' });
    await appendCheck(h, selector);
    assert.equal(h.calls.length, 1, 'editing must not publish');
    await h.stage();
    const replacement = h.client.pending.intent.replacement;
    assert.deepEqual(replacement.branches, [{ reference_hex: hex('refs/heads/main'), required_reviewers: [], required_checks: [selector] }]);
    assert.match(h.node('changes').textContent, /checks_added/);
    const body = h.client.pending.intent.body, form = new URLSearchParams(body);
    assert.deepEqual(form.getAll('required_reviewer'), []);
    assert.deepEqual(form.getAll('required_approvals'), []);
    assert.deepEqual(form.getAll('required_check'), [
      `${hex('refs/heads/main')}:${selector.source_ref_hex}:${selector.publisher}:${selector.graph_root}:${hex(selector.job)}`,
    ]);
    assert.equal(h.calls.length, 1);
    await h.send(); assert.equal(h.calls.length, 2); assert.equal(h.calls[1].body, body);
    assert.match(h.node('status').textContent, /Canonical committed/);
  });
}
test('editing one CI selector preserves unrelated rules, reviewers, quorum, administrators and the exact ref-policy frame', async () => {
  const shared = requiredCheck(), compiled = refPolicy();
  const selected = { administrators: [ADMIN, OTHER].sort(), branches: [
    { reference_hex: hex('refs/heads/ci-only'), required_reviewers: [], required_checks: [shared] },
    { reference_hex: hex('refs/heads/main'), required_reviewers: [REVIEWER, OTHER, 'd'.repeat(32)].sort(), required_approvals: 2,
      required_checks: [shared] },
    { reference_hex: hex('refs/heads/review-only'), required_reviewers: [REVIEWER] },
    { reference_hex: hex('refs/heads/untouched'), required_reviewers: [OTHER], required_checks: [shared] },
  ], ref_policy: compiled };
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha256', { policy: selected })) : null });
  await h.ready();
  const main = h.rows().find(row => row.reference.value === hex('refs/heads/main'));
  const row = checkRows(h, main)[0]; row.fields.graph_root.value = '8'.repeat(64); await row.fields.graph_root.emit('input');
  await h.stage();
  const expected = structuredClone(selected); expected.branches[1].required_checks = [requiredCheck({ graph_root: '8'.repeat(64) })];
  assert.deepEqual(h.client.pending.intent.replacement, expected);
  assert.deepEqual(h.client.observed.policy, selected, 'editing must not mutate the authenticated source snapshot');
  const form = new URLSearchParams(h.client.pending.intent.body);
  assert.equal(form.get('ref_policy_frame_hex'), compiled.frame_hex);
  assert.deepEqual(form.getAll('required_approvals'), [`${hex('refs/heads/main')}:2`]);
  assert.equal(form.getAll('required_check').length, 3, 'same selector may be required by multiple target branches');
  assert.equal(form.getAll('required_reviewer').length, 5);
  assert.equal(h.calls.length, 1);
});
test('required-check edits invalidate previews even when a programmatic edit omits its input event', async () => {
  const h = ui(); await h.ready(); const check = await appendCheck(h);
  await h.fire('editor', 'submit'); assert.equal(h.node('stage').disabled, false);
  check.fields.job.value = 'different exact job';
  await h.fire('stage'); assert.equal(h.client.pending, null); assert.match(h.node('status').textContent, /Preview again/);
  await h.fire('editor', 'submit');
  check.fields.graph_root.value = '8'.repeat(64); await check.fields.graph_root.emit('input');
  assert.equal(h.node('stage').disabled, true);
  await h.stage();
  assert.deepEqual(h.client.pending.intent.replacement.branches[0].required_checks,
    [requiredCheck({ job: 'different exact job', graph_root: '8'.repeat(64) })]);
  assert.equal(h.calls.length, 1);
});
test('removing workflow checks retains reviewer protection and its historical empty-check representation', async () => {
  const selected = policy(); selected.branches[0].required_checks = [requiredCheck(), requiredCheck({ job: 'test' })];
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: selected })) : null });
  await h.ready(); assert.equal(checkRows(h).length, 2);
  for (const check of checkRows(h)) await check.remove.emit('click');
  assert.equal(checkRows(h).length, 0); await h.stage();
  assert.deepEqual(h.client.pending.intent.replacement, policy());
  assert.equal(new URLSearchParams(h.client.pending.intent.body).has('required_check'), false);
  assert.match(h.node('changes').textContent, /checks_removed/); assert.equal(h.calls.length, 1);
});
test('removing the last check cannot silently erase a check-only branch', async () => {
  const selected = { administrators: [ADMIN], branches: [{ reference_hex: hex('refs/heads/main'), required_reviewers: [], required_checks: [requiredCheck()] }] };
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: selected })) : null });
  await h.ready(); await checkRows(h)[0].remove.emit('click'); await h.fire('editor', 'submit');
  assert.equal(h.client.pending, null); assert.equal(h.node('stage').disabled, true); assert.equal(h.rows().length, 1);
  assert.equal(h.calls.length, 1);
  await h.rows()[0].remove.emit('click'); h.node('clear').checked = true; await h.stage();
  assert.deepEqual(h.client.pending.intent.replacement.branches, []);
  assert.equal(new URLSearchParams(h.client.pending.intent.body).get('clear'), 'true');
  assert.match(h.node('changes').textContent, /checks_removed/);
});
test('branch-local checks follow an explicit target rename without changing their CI source identity', async () => {
  const selected = policy(); selected.branches[0].required_checks = [requiredCheck()];
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: selected })) : null });
  await h.ready(); const row = h.rows()[0];
  row.reference.value = hex('refs/heads/new-target'); await row.reference.emit('input');
  await h.stage();
  assert.deepEqual(h.client.pending.intent.replacement.branches[0], {
    reference_hex: hex('refs/heads/new-target'), required_reviewers: [REVIEWER], required_checks: [requiredCheck()],
  });
  assert.match(h.node('changes').textContent, /checks_added/); assert.match(h.node('changes').textContent, /checks_removed/);
  const body = new URLSearchParams(h.client.pending.intent.body);
  assert.equal(body.getAll('required_check')[0].split(':')[0], hex('refs/heads/new-target'));
  assert.equal(body.getAll('required_check')[0].split(':')[1], requiredCheck().source_ref_hex);
});
test('selector validation refuses malformed identities, noncanonical job bytes and duplicate requirements before staging', async () => {
  for (const extra of [
    { source_ref_hex: hex('refs/tags/wrong') }, { source_ref_hex: 'aa' },
    { publisher: 'F'.repeat(32) }, { graph_root: '7'.repeat(63) },
    { job: '' }, { job: 'bad\u0000job' }, { job: '\ud800' }, { job: '🦀'.repeat(257) },
  ]) {
    const h = ui(); await h.ready(); await appendCheck(h, requiredCheck(extra)); await h.fire('editor', 'submit');
    assert.equal(h.client.pending, null, JSON.stringify(extra)); assert.equal(h.node('stage').disabled, true);
    assert.equal(h.calls.length, 1);
  }
  const h = ui(); await h.ready(); await appendCheck(h); const second = await appendCheck(h);
  await h.fire('editor', 'submit'); assert.equal(h.client.pending, null); assert.match(h.node('status').textContent, /Duplicate required workflow check/);
  second.fields.graph_root.value = '8'.repeat(64); await second.fields.graph_root.emit('input'); await h.stage();
  assert.equal(h.client.pending.intent.replacement.branches[0].required_checks.length, 2);
});
test('the check editor enforces the native 32-per-branch limit even when a disabled button is invoked', async () => {
  const selected = policy(); selected.branches[0].required_checks = Array.from({ length: 32 }, (_, n) => requiredCheck({ job: `job-${String(n).padStart(2, '0')}` }));
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: selected })) : null });
  await h.ready(); const row = h.rows()[0]; assert.equal(row.addCheck.disabled, true);
  await row.addCheck.emit('click'); assert.equal(checkRows(h).length, 32); assert.match(h.node('status').textContent, /At most 32/);
  await checkRows(h)[0].remove.emit('click'); assert.equal(row.addCheck.disabled, false);
  await appendCheck(h, requiredCheck({ job: 'replacement' })); assert.equal(row.addCheck.disabled, true);
  await h.stage(); assert.equal(h.client.pending.intent.replacement.branches[0].required_checks.length, 32);
});
test('new selector controls freeze while an ambiguous publication retries its original exact body and key', async () => {
  let posts = 0;
  const h = ui({ respond: call => {
    if (call.method === 'POST' && !call.url.pathname.endsWith('/outcomes') && ++posts === 1) throw new TypeError('response lost');
    return null;
  } });
  await h.ready(); const branch = h.rows()[0], check = await appendCheck(h);
  await h.stage(); const { body, key } = h.client.pending.intent;
  assert.equal(branch.addCheck.disabled, true); assert.equal(check.remove.disabled, true);
  assert.ok(Object.values(check.fields).every(field => field.disabled));
  check.fields.job.value = 'a later DOM edit'; await check.fields.job.emit('input');
  await branch.addCheck.emit('click'); await check.remove.emit('click');
  assert.equal(checkRows(h).length, 1); assert.equal(h.client.pending.intent.body, body); assert.equal(h.client.pending.intent.key, key);
  await h.send(); assert.ok(h.client.pending?.sent); assert.match(h.node('status').textContent, /unknown/i);
  assert.ok(Object.values(check.fields).every(field => field.disabled));
  await h.send(); assert.equal(h.client.pending, null);
  const sent = h.calls.filter(call => call.method === 'POST'); assert.equal(sent.length, 2);
  assert.ok(sent.every(call => call.body === body && call.headers['Idempotency-Key'] === key));
});
test('disconnect and a fresh policy load discard editable check data and fence stale detached controls', async () => {
  const h = ui(); await h.ready(); const old = h.rows()[0]; const stale = await appendCheck(h);
  await h.fire('disconnect'); assert.equal(h.rows().length, 0); assert.equal(h.node('branches').textContent, '');
  await h.ready(); assert.equal(checkRows(h).length, 0);
  await old.addCheck.emit('click'); await stale.remove.emit('click');
  assert.equal(h.rows().length, 1); assert.equal(checkRows(h).length, 0); assert.equal(h.client.pending, null);
});
