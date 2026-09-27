// Caller-supplied anchors are separate from server-selected snapshots. Tests run
// real production controls and WebCrypto with injected HTTP, not a live server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { sourceFields, snapshotOf, sourceBinding, verifySourceCommit, mount }
  from '../../crates/fgit-node/src/smart_http/server/browser/browser.mjs';
import { fixture, hex, webcrypto, dom, location, response, waitFor, queuedFetch }
  from './source-browser-fixtures.mjs';
const native = (format, kind, body) => createHash(format).update(`${kind} ${body.length}\0`).update(body).digest('hex');
function corpus(format = 'sha1') {
  const f = fixture(format);
  const tree = Buffer.concat([Buffer.from('100644 file.txt\0'), Buffer.from(f.oid, 'hex')]);
  f.common.root_tree = native(format, 'tree', tree);
  const body = Buffer.from(`tree ${f.common.root_tree}\nauthor A <a@example.test> 0 +0000\ncommitter A <a@example.test> 0 +0000\n\npinned bytes\n`);
  f.common.source_commit = native(format, 'commit', body);
  const log = () => {
    const { ref, source_rcr, root_tree, ...identity } = f.common;
    return { ...identity, type: 'source_log', author_identity_verified: false,
      ordering: 'child-before-parent-native-id-v1', page_complete: true, after: 0, limit: 1, total_commits: 1, next_after: null,
      commits: [{ object_id: f.common.source_commit, tree: root_tree, parents: [], body_hex: hex(body) }] };
  };
  return { ...f, log };
}
function setup(f, pin, replies) {
  const d = dom(), calls = []; d.get('format').value = f.format; d.get('expected-commit').value = pin;
  const client = mount(d.document, location, queuedFetch(replies, calls), { cryptoImpl: webcrypto, urlApi: d.urlApi });
  const connect = () => { d.get('token').value = 'a'.repeat(64); d.get('connection').emit('submit'); };
  return { ...d, calls, client, connect };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: supplied native commit reaches the first read and cannot be overwritten by a snapshot`, () => {
    const f = corpus(format), commit = f.common.source_commit;
    const selection = { ...f.selected, expectedCommit: `${format}:${commit}` };
    assert.deepEqual(sourceFields(selection, null), { ref: f.selected.reference, object_format: format, expected_commit: commit });
    const pin = snapshotOf(f.common, selection);
    assert.equal(sourceFields(selection, pin).expected_commit, commit);
    assert.equal(sourceFields(selection, { ...pin, commit: `${format}:${commit}` }).expected_commit, commit);
    assert.throws(() => sourceFields(selection, { ...pin, commit: 'e'.repeat(commit.length) }), /cannot override/);
    assert.throws(() => snapshotOf({ ...f.common, source_commit: 'e'.repeat(commit.length) }, selection), /caller-supplied/);
    assert.equal(sourceBinding(f.common, selection).commit, commit);
  });
  test(`${format}: a server ignoring the initial expected commit cannot install a source view`, async () => {
    const f = corpus(format), expected = 'd'.repeat(f.common.source_commit.length);
    const d = setup(f, expected, [f.tree()]); d.connect();
    await waitFor(() => /caller-supplied commit pin/.test(d.get('status').textContent));
    assert.equal(d.calls.length, 1); assert.equal(d.calls[0].fields.get('expected_commit'), expected);
    assert.equal(d.get('content').textContent, ''); assert.equal(d.get('snapshot').textContent, '');
    assert.equal(d.get('expected-commit').value, expected); assert.equal(d.urls.size, 0);
  });
  test(`${format}: complete proof and download are explicitly anchored to the caller's commit`, async () => {
    const f = corpus(format), commit = f.common.source_commit;
    const d = setup(f, `${format}:${commit}`, [f.tree(), f.blob(), f.log(), f.tree(), f.blob()]);
    d.connect(); await waitFor(() => d.buttons('content').length === 1);
    assert.match(d.get('snapshot').textContent, /Caller-supplied commit pin/);
    d.buttons('content')[0].click();
    await waitFor(() => d.buttons('content').some(b => b.textContent === 'Verify commit, path and complete file for download'));
    d.buttons('content').find(b => b.textContent === 'Verify commit, path and complete file for download').click();
    await waitFor(() => d.get('status').textContent.startsWith('Complete file verified.'));
    assert.match(d.get('content').textContent, /matches your caller-supplied commit pin/);
    assert.doesNotMatch(d.get('content').textContent, /commit was selected by the server/);
    assert.match(d.get('content').textContent, /branch freshness and author identity are not independently verified/);
    for (const call of d.calls) assert.equal(call.fields.get('expected_commit'), commit);
    d.buttons('content').find(b => b.textContent === 'Download verified file bytes').click();
    assert.deepEqual(new Uint8Array(await d.urls.values().next().value.arrayBuffer()), f.bytes);
    d.client.disconnect(); assert.equal(d.get('expected-commit').value, ''); assert.equal(d.urls.size, 0);
  });
}
test('malformed, partial, zero, cross-domain or explicitly null pins fail before requests', async () => {
  const f = corpus(), commit = f.common.source_commit;
  for (const pin of ['', 'a'.repeat(39), '0'.repeat(40), commit.toUpperCase(), ` ${commit}`, `${commit}\n`, `sha256:${'a'.repeat(64)}`, null, 3]) {
    assert.throws(() => sourceFields({ ...f.selected, expectedCommit: pin }, null));
  }
  for (const value of ['a'.repeat(39), '0'.repeat(40), `sha256:${'a'.repeat(64)}`, commit.toUpperCase()]) {
    const d = setup(f, value, []); d.connect();
    assert.equal(d.calls.length, 0); assert.match(d.get('status').textContent, /Invalid selected commit/);
  }
  const d = setup(f, '', [f.tree()]); d.connect(); await waitFor(() => d.buttons('content').length === 1);
  assert.equal(d.calls[0].fields.has('expected_commit'), false);
  assert.match(d.get('snapshot').textContent, /Commit selected by the server/);
});
test('commit proof refuses an already-selected source inconsistent with the independent anchor before I/O', async () => {
  const f = corpus(); let reads = 0;
  await assert.rejects(verifySourceCommit({ ...f.selected, expectedCommit: 'd'.repeat(40) }, sourceBinding(f.common, f.selected),
    () => { reads++; return f.log(); }, { cryptoImpl: webcrypto }), /cannot override/);
  assert.equal(reads, 0);
  assert.equal((await verifySourceCommit({ ...f.selected, expectedCommit: f.common.source_commit }, sourceBinding(f.common, f.selected),
    () => { reads++; return f.log(); }, { cryptoImpl: webcrypto })).commit, f.common.source_commit);
  assert.equal(reads, 1);
});
test('editing the pin cancels a pending view; detached controls and late responses cannot restore it', async () => {
  const f = corpus(); let finish;
  const d = setup(f, f.common.source_commit, [() => new Promise(resolve => { finish = resolve; })]);
  d.connect(); await waitFor(() => finish);
  d.get('expected-commit').value = 'd'.repeat(40); d.get('expected-commit').emit('input');
  finish(response(f.tree())); await new Promise(setImmediate);
  assert.equal(d.calls[0].init.signal.aborted, true); assert.equal(d.calls.length, 1);
  assert.equal(d.get('content').textContent, ''); assert.equal(d.get('snapshot').textContent, '');
  assert.equal(d.get('expected-commit').value, 'd'.repeat(40)); assert.match(d.get('status').textContent, /Connection settings changed/);
});
test('failure or explicit reopen never silently removes the supplied pin', async () => {
  const f = corpus(), d = setup(f, f.common.source_commit, [() => response({ error: 'moved' }, { status: 409 }), f.tree()]);
  d.connect(); await waitFor(() => /snapshot moved/.test(d.get('status').textContent));
  assert.equal(d.calls.length, 1); assert.equal(d.get('expected-commit').value, f.common.source_commit);
  d.connect(); await waitFor(() => d.buttons('content').length === 1);
  assert.equal(d.calls.length, 2);
  for (const c of d.calls) assert.equal(c.fields.get('expected_commit'), f.common.source_commit);
  d.document.defaultView.emit('pagehide'); assert.equal(d.get('expected-commit').value, ''); assert.equal(d.get('snapshot').textContent, '');
});
test('the connection captures the supplied pin rather than consulting mutable form values after awaits', async () => {
  const f = corpus(); let finish;
  const d = setup(f, f.common.source_commit, [() => new Promise(resolve => { finish = resolve; }), f.blob()]);
  d.connect(); await waitFor(() => finish); d.get('expected-commit').value = 'd'.repeat(40); // no input event
  finish(response(f.tree())); await waitFor(() => d.buttons('content').length === 1);
  assert.ok(d.get('snapshot').textContent.includes(`Caller-supplied commit pin: ${f.common.source_commit}`));
  d.buttons('content')[0].click(); await waitFor(() => d.calls.length === 2);
  assert.equal(d.calls[1].fields.get('expected_commit'), f.common.source_commit);
  d.client.disconnect();
});
test('the served form describes an independent full commit pin without claiming authentication', () => {
  const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/index.html', import.meta.url), 'utf8');
  assert.match(html, /id="expected-commit"[^>]*maxlength="71"/);
  assert.match(html, /id="commit-pin-help"/); assert.match(html, /obtained independently/);
  assert.match(html, /not a historical-object lookup/); assert.match(html, /including the first/);
});
