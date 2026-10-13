// Actual membership verifier and view with real WebCrypto/Transport/HTTP plus a
// small DOM adapter. The peer is a native-schema fixture, NOT a live Rust node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { acquireContextMembership, verifyMembershipProof, mountContextMembership, MEMBERSHIP_PROFILE,
  MEMBERSHIP_LIMITS, MEMBERSHIP_PROOF_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-membership.mjs';
import { fixture, token, hex } from '../operator/fixtures/source_archive_native.mjs';
const clone = value => structuredClone(value);
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.listeners = {}; this.value = ''; this.files = []; this.checked = false; this.disabled = false; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); }
  setAttribute(name, value) { this[name] = value; }
  addEventListener(name, action) { (this.listeners[name] ??= []).push(action); }
  async emit(name) { for (const action of this.listeners[name] ?? []) await action({ preventDefault() {} }); }
  click() { this.clicked = true; return this.emit('click'); }
}
class Document {
  body = new Element('body');
  createElement(tag) { return new Element(tag); }
  getElementById(id) { const find = node => node.id === id ? node : node.children.map(find).find(Boolean); return find(this.body) ?? null; }
}
function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { resolve, reject, promise }; }
async function setup(t, format = 'sha1', timeoutMs = 5000) {
  const f = await fixture(t, { format });
  const transport = new Transport({ href: `${f.selection.endpoint}/ui/search/`, pageSuffix: '/ui/search/', cryptoImpl: webcrypto });
  await transport.connect(token); t.after(() => transport.disconnect());
  const selected = f.repo.files.get(hex('src/main.rs'));
  const result = { query: { mode: 'initial' }, scope: { tenant: f.repo.scope.tenant_id, repository: f.repo.scope.repository_id,
    incarnation: f.repo.scope.repository_incarnation, format },
    pin: { commit: f.repo.commit, tree: f.repo.root.id, head: f.repo.snapshot, sourceHead: f.repo.common.source_head, rcr: 'fixture-rcr' },
    vector: { lexical: { token: 'alg:2:' + 'e'.repeat(64), number: 1 }, symbols: null },
    context: { files: [{ pathHex: hex('src/main.rs'), blob: selected.id }] } };
  const proof = { schema: MEMBERSHIP_PROFILE, objectFormat: format, commit: { oid: f.repo.commit, bodyHex: hex(f.repo.body) },
    trees: [null, hex('src')].map(pathHex => { const row = f.repo.dirs.get(pathHex); return { pathHex, oid: row.id, bodyHex: hex(row.body) }; }),
    files: [{ pathHex: hex('src/main.rs'), blob: selected.id, kind: 'executable' }] };
  const doc = new Document(), acquired = [], blobs = new Map(), revoked = [], state = { current: true, busy: false, cancelCount: 0, runs: 0 };
  const behavior = {}; let urls = 0;
  const urlApi = { createObjectURL: blob => { if (behavior.exportError) throw new Error('No download'); const url = `blob:test-${++urls}`; blobs.set(url, blob); return url; },
    revokeObjectURL: url => { revoked.push(url); } };
  const panel = mountContextMembership(doc, result, { cryptoImpl: webcrypto, timeoutMs, urlApi,
    display: bytes => [...bytes].map(byte => byte >= 32 && byte < 127 ? String.fromCharCode(byte) : `\\x${byte.toString(16)}`).join(''),
    current: () => state.current, idle: () => !state.busy,
    cancelRead: () => { state.cancelCount++; transport.cancelReads(); },
    acquire: async (commit, limits) => { acquired.push({ commit, limits });
      return behavior.acquire ? behavior.acquire(commit, limits) : acquireContextMembership(result, f.selection.ref, commit,
        (path, options) => transport.request(path, options), webcrypto, () => {}, limits); },
    run: async action => { state.runs++; state.busy = true;
      try { return await action(() => { if (!state.current) throw new Error('Superseded'); }); } finally { state.busy = false; } },
  });
  doc.body.append(panel.element); t.after(() => panel.dispose());
  const get = name => doc.getElementById(`context-membership-${name}`);
  const consent = async () => { get('commit').value = f.repo.commit; get('consent').checked = true; await get('consent').emit('change'); };
  const load = (value = proof, sizeChange = 0) => { const data = new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value));
    get('file').files = [{ size: data.length + sizeChange, arrayBuffer: async () => data.buffer.slice(0) }]; };
  return { ...f, transport, proof, result, doc, panel, get, state, behavior, acquired, blobs, revoked, consent, load };
}
for (const format of ['sha1', 'sha256']) {
  test(`blank independent root and no automatic reads ${format}`, async t => {
    const f = await setup(t, format); assert.equal(f.get('commit').value, '');
    assert.equal(f.panel.submit.disabled, true); assert.equal(f.panel.inspect.disabled, true); assert.equal(f.panel.download.disabled, true);
    await f.panel.submit.click(); await f.panel.inspect.click();
    assert.equal(f.calls.length, 0); assert.equal(f.state.runs, 0); assert.equal(f.acquired.length, 0);
    for (const [name, value] of Object.entries(MEMBERSHIP_LIMITS)) assert.equal(f.get(name).value, String(value));
  });
  test(`explicit acquisition, bounded proof export and offline replay ${format}`, async t => {
    const f = await setup(t, format); await f.consent(); await f.panel.submit.click();
    assert.equal(f.calls.length, 3); assert.equal(f.acquired.length, 1); assert.equal(f.state.runs, 1);
    assert.equal(f.panel.download.disabled, false); assert.match(f.get('status').textContent, /independently supplied commit/);
    assert.match(f.get('status').textContent, /Blob bodies.*NOT verified/);
    assert.equal(f.get('consent').checked, false); assert.match(f.get('result').textContent, /executable/);
    await f.panel.download.click(); const serialized = await f.blobs.get('blob:test-1').text(), saved = JSON.parse(serialized);
    assert.deepEqual(saved, f.proof); assert.equal(serialized.includes(token), false);
    assert.equal('scope' in saved, false); assert.equal('generationVector' in saved, false);
    const verified = await verifyMembershipProof(saved, { format, commit: f.repo.commit, files: f.result.context.files }, webcrypto);
    assert.equal(verified.commitMembershipVerified, true); assert.equal(verified.blobBytesVerified, false);
    await f.panel.download.click(); assert.deepEqual(f.revoked, ['blob:test-1']);
    f.panel.invalidate(); assert.deepEqual(f.revoked, ['blob:test-1', 'blob:test-2']);
  });
  test(`import verifies retained selection without a request ${format}`, async t => {
    const f = await setup(t, format); f.load(); await f.consent(); await f.panel.inspect.click();
    assert.equal(f.calls.length, 0); assert.equal(f.acquired.length, 0); assert.equal(f.state.runs, 1);
    assert.equal(f.panel.download.disabled, false); assert.match(f.get('result').textContent, new RegExp(f.repo.commit));
    await f.panel.download.click(); assert.deepEqual(JSON.parse(await f.blobs.get('blob:test-1').text()), f.proof);
  });
  test(`a matching proof cannot choose its own independent root ${format}`, async t => {
    const f = await setup(t, format); f.load(); f.get('consent').checked = true;
    await f.panel.inspect.click(); assert.equal(f.get('commit').value, ''); assert.equal(f.state.runs, 0);
    f.get('commit').value = 'b'.repeat(format === 'sha1' ? 40 : 64); f.get('consent').checked = true;
    await f.panel.inspect.click(); assert.equal(f.state.runs, 0); assert.equal(f.panel.download.disabled, true);
  });
}
for (const [name, value] of [['maxRequests', '1'], ['maxTrees', '1'], ['maxEntries', '0'], ['maxTreeBytes', '4194305']]) {
  test(`pre-I/O limit refusal ${name}`, async t => {
    const f = await setup(t); await f.consent(); f.get(name).value = value; await f.panel.submit.click();
    assert.equal(f.calls.length, 0); assert.equal(f.acquired.length, 0); assert.equal(f.state.runs, 0); assert.equal(f.panel.download.disabled, true);
  });
}
for (const [label, change] of [
  ['missing parent', p => p.trees.pop()], ['detached parent', p => { p.trees[1].pathHex = hex('other'); }],
  ['changed root', p => { p.commit.oid = 'f'.repeat(40); }], ['changed mode', p => { p.files[0].kind = 'file'; }],
  ['extra authority flag', p => { p.authorization = 'admin'; }], ['omitted sibling', p => { p.trees[0].bodyHex = ''; }],
]) test(`import refuses ${label} without trusting a summary`, async t => {
  const f = await setup(t); const p = clone(f.proof); change(p); f.load(p); await f.consent(); await f.panel.inspect.click();
  assert.equal(f.acquired.length, 0); assert.equal(f.calls.length, 0); assert.equal(f.panel.download.disabled, true);
  assert.equal(f.get('result').textContent, ''); assert.match(f.get('status').textContent, /failed/);
});
for (const [label, configure] of [
  ['oversized file', f => { f.get('file').files = [{ size: MEMBERSHIP_PROOF_BYTES + 1, arrayBuffer: () => assert.fail('oversized input read') }]; }],
  ['multiple files', f => { f.load(); f.get('file').files.push(f.get('file').files[0]); }],
  ['changed size', f => { f.load(f.proof, 1); }],
  ['no file', f => {}], ['malformed JSON', f => { f.load('{'); }],
  ['invalid UTF-8', f => { f.get('file').files = [{ size: 1, arrayBuffer: async () => new Uint8Array([255]).buffer }]; }],
]) test(`bounded proof input refuses ${label}`, async t => {
  const f = await setup(t); configure(f); await f.consent(); await f.panel.inspect.click();
  assert.equal(f.panel.download.disabled, true); assert.equal(f.calls.length, 0); assert.equal(f.acquired.length, 0);
});
test('input edits revoke proof URLs and require fresh consent', async t => {
  const f = await setup(t); f.load(); await f.consent(); await f.panel.inspect.click(); await f.panel.download.click();
  f.get('maxEntries').value = '8192'; await f.get('maxEntries').emit('input');
  assert.equal(f.get('consent').checked, false); assert.equal(f.panel.download.disabled, true); assert.deepEqual(f.revoked, ['blob:test-1']);
  await f.panel.submit.click(); assert.equal(f.calls.length, 0);
});
test('silent field mutation cannot export a differently labeled proof', async t => {
  const f = await setup(t); f.load(); await f.consent(); await f.panel.inspect.click();
  f.get('maxTrees').value = '100'; await f.panel.download.click(); assert.equal(f.blobs.size, 0);
});
test('duplicate dispatch and late field changes never install a proof', async t => {
  const f = await setup(t), wait = deferred(); f.behavior.acquire = () => wait.promise;
  await f.consent(); const pending = f.panel.submit.click();
  f.get('consent').checked = true; await f.panel.submit.click(); assert.equal(f.acquired.length, 1);
  f.get('commit').value = 'b'.repeat(40); wait.resolve({ proof: f.proof }); await pending;
  assert.equal(f.get('result').textContent, ''); assert.equal(f.panel.download.disabled, true);
});
test('cancellation aborts a real metadata read without retries', async t => {
  const f = await setup(t), arrived = deferred(); f.control.respond = () => { arrived.resolve(); };
  await f.consent(); const pending = f.panel.submit.click(); await arrived.promise;
  f.transport.cancelReads(); f.panel.invalidate(); await pending;
  assert.equal(f.calls.length, 1); assert.equal(f.panel.download.disabled, true); assert.equal(f.get('result').textContent, '');
});
test('superseded source prevents late acquisition from receiving a verification label', async t => {
  const f = await setup(t), wait = deferred(); f.behavior.acquire = () => wait.promise;
  await f.consent(); const pending = f.panel.submit.click(); f.state.current = false; wait.resolve({ proof: f.proof }); await pending;
  assert.equal(f.panel.download.disabled, true); assert.equal(f.get('result').textContent, '');
});
test('offline file-read deadline clears busy state without calling acquire', async t => {
  const f = await setup(t, 'sha1', 50); f.get('file').files = [{ size: 1, arrayBuffer: () => new Promise(() => {}) }];
  await f.consent(); await f.panel.inspect.click();
  assert.equal(f.state.busy, false); assert.equal(f.state.cancelCount, 1); assert.equal(f.calls.length, 0);
  assert.equal(f.panel.download.disabled, true); assert.match(f.get('status').textContent, /failed/);
});
test('disposal during offline reading fences late bytes and clears the root', async t => {
  const f = await setup(t), wait = deferred(), bytes = new TextEncoder().encode(JSON.stringify(f.proof));
  f.get('file').files = [{ size: bytes.length, arrayBuffer: () => wait.promise }];
  await f.consent(); const pending = f.panel.inspect.click(); f.panel.dispose(); wait.resolve(bytes.buffer); await pending;
  assert.equal(f.get('commit').value, ''); assert.equal(f.panel.download.disabled, true); assert.equal(f.get('result').textContent, '');
});
test('acquisition reply must carry the complete valid proof, not a success flag', async t => {
  const f = await setup(t); f.behavior.acquire = async () => ({ verified: { commitMembershipVerified: true }, proof: { ...f.proof, files: [] } });
  await f.consent(); await f.panel.submit.click(); assert.equal(f.panel.download.disabled, true); assert.equal(f.get('result').textContent, '');
});
test('failed reinspection erases a prior success rather than preserving stale evidence', async t => {
  const f = await setup(t); f.load(); await f.consent(); await f.panel.inspect.click(); await f.panel.download.click();
  f.load('{'); await f.consent(); await f.panel.inspect.click();
  assert.equal(f.panel.download.disabled, true); assert.equal(f.get('result').textContent, ''); assert.deepEqual(f.revoked, ['blob:test-1']);
});
test('disposed panels revoke exported URLs and cannot perform new reads', async t => {
  const f = await setup(t); f.load(); await f.consent(); await f.panel.inspect.click(); await f.panel.download.click();
  f.panel.dispose(); await f.consent(); await f.panel.submit.click(); await f.panel.download.click();
  assert.equal(f.calls.length, 0); assert.deepEqual(f.revoked, ['blob:test-1']); assert.equal(f.blobs.size, 1);
});
test('a failed export never triggers networking or acquires a new root', async t => {
  const f = await setup(t); f.load(); await f.consent(); await f.panel.inspect.click(); f.behavior.exportError = true;
  await f.panel.download.click(); assert.equal(f.calls.length, 0); assert.equal(f.acquired.length, 0); assert.match(f.get('status').textContent, /export failed/);
});
