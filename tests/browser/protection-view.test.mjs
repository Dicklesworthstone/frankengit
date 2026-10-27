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
    reviewers: group.all('textarea')[0], approvals: group.all('input')[1], remove: group.all('button')[0] }));
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
test('PR editor preserves the enforced ref policy while editing administrators or removing the last branch', async () => {
  const h = ui({ respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: { ...policy(), ref_policy: refPolicy() } })) : null });
  await h.ready(); assert.ok(h.node('snapshot').textContent.includes(refPolicy().snapshot_id));
  h.node('administrators').value = OTHER;
  await h.rows()[0].remove.emit('click');
  await h.stage();
  assert.deepEqual(h.client.pending.intent.replacement.ref_policy, refPolicy());
  const form = new URLSearchParams(h.client.pending.intent.body);
  assert.equal(form.get('ref_policy_frame_hex'), refPolicy().frame_hex);
  assert.equal(form.has('clear'), false);
  assert.deepEqual(h.client.pending.intent.replacement.branches, []);
  assert.equal(h.calls.length, 1, 'editing does not publish');
});
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
