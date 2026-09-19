import test from 'node:test';
import assert from 'node:assert/strict';
import { HistoryClient } from '../../crates/fgit-node/src/smart_http/server/browser/history.mjs';
import { bytePath, commitRecord } from '../../crates/fgit-node/src/smart_http/server/browser/history-data.mjs';
import { fixture, token, crypto, href, bytes, hex, hash, commit, json, deferred } from './history-fixtures.mjs';
const client = f => new HistoryClient({ href, fetchImpl: f.fetchImpl, cryptoImpl: crypto });
async function opened(f) { const c = client(f); c.connect(token); await c.open(f.ref, f.algorithm); return c; }
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: log, exact path history and continuations retain the original snapshot`, async () => {
    const f = fixture(algorithm), c = await opened(f);
    assert.equal(c.selection.tip, f.tip.object_id);
    const first = await c.log({ limit: 1, path_hex: f.path });
    assert.equal(first.next, 1); assert.equal(first.commits[0].id, f.tip.object_id);
    const last = await c.log({ after: first.next, limit: 1, path_hex: first.path_hex });
    assert.equal(last.commits[0].id, f.base.object_id); assert.equal(last.next, null);
    const form = f.calls.at(-1).form;
    assert.equal(form.get('expected_head'), f.head); assert.equal(form.get('expected_commit'), f.tip.object_id);
    assert.equal(form.get('path_hex'), f.path); assert.equal(form.get('after'), '1');
    c.selection.scope.repository = 'forged'; assert.equal(c.selection.scope.repository, f.scope.repository);
  });
  test(`${algorithm}: full blame verifies native blob and origin navigation reproduces exact bytes`, async () => {
    const f = fixture(algorithm), c = await opened(f), result = await c.blame(f.path);
    assert.equal(result.fullBlobVerified, true); assert.deepEqual(result.lines.map(line => line.origin_commit), [f.tip.object_id, f.base.object_id]);
    result.lines[1].origin_commit = f.tip.object_id; // Public data cannot rewrite the private verified attribution.
    const original = await c.origin(1);
    assert.equal(original.originBytesVerified, true); assert.equal(original.source.content_hex, hex(bytes('two')));
    assert.equal(original.query.commit, f.base.object_id);
    const form = f.calls.at(-1).form;
    assert.equal(form.get('at_commit'), f.base.object_id); assert.equal(form.get('expected_ref_tip'), f.tip.object_id);
    assert.equal(form.get('expected_head'), f.head); assert.equal(form.get('offset'), '5'); assert.equal(form.get('limit'), '3');
  });
  test(`${algorithm}: narrow and empty line ranges preserve exact offsets and completeness`, async () => {
    const f = fixture(algorithm), c = await opened(f);
    const narrow = await c.blame(f.path, { first: 1, end: 2 });
    assert.equal(narrow.fullBlobVerified, false); assert.equal(narrow.lines[0].content_hex, hex(bytes('two')));
    assert.equal(narrow.raw.content_byte_start, 5);
    const empty = await c.blame(f.path, { first: 1, end: 1 }); assert.deepEqual(empty.lines, []); assert.deepEqual(empty.origins, []);
  });
  test(`${algorithm}: historical directories and exact file ranges retain both native commit identities`, async () => {
    const f = fixture(algorithm), c = await opened(f);
    const tree = await c.historical('tree', f.base.object_id);
    assert.equal(tree.source.root_tree, f.base.tree); assert.equal(tree.source.entries[0].object_id, f.oldBlob);
    const part = await c.historical('blob', f.base.object_id, f.path, { limit: 5 });
    assert.equal(part.source.content_hex, hex(bytes('one\r\n'))); assert.equal(part.source.next_offset, 5);
    const tail = await c.historical('blob', f.base.object_id, f.path, { offset: 5, limit: 5 });
    assert.equal(tail.source.content_hex, hex(bytes('two'))); assert.equal(tail.source.next_offset, null);
    assert.equal(c.selection.tip, f.tip.object_id);
    const full = await c.historical('blob', f.base.object_id, f.path); assert.equal(full.source.object_id, f.oldBlob);
  });
  test(`${algorithm}: complete absent-path history is valid, empty unfiltered history is not`, async () => {
    const f = fixture(algorithm), c = await opened(f);
    const empty = await c.log({ path_hex: '616273656e74' }); assert.equal(empty.total, 0); assert.equal(empty.next, null);
    f.config.mutate = value => { value.commits = []; value.total_commits = 0; value.next_after = null; };
    await assert.rejects(c.log());
  });
}
test('raw byte names, CRLF, control bytes and non-UTF8 commit messages remain lossless', async () => {
  const f = fixture('sha1', '66ff'), c = await opened(f);
  assert.equal((await c.log({ path_hex: f.path })).path_hex, '66ff');
  const body = Buffer.concat([bytes(`tree ${f.tip.tree}\nauthor A <a@invalid> 1 +0000\ncommitter A <a@invalid> 1 +0000\ngpgsig first\n parent not-an-actual-header\n\n`), Buffer.from([255, 0, 10])]);
  const row = { object_id: hash('commit', body), tree: f.tip.tree, parents: [], body_hex: hex(body) };
  const parsed = await commitRecord(row, 'sha1', crypto); assert.equal(parsed.message_hex, 'ff000a'); assert.equal(parsed.parents.length, 0);
});
test('raw commit parent order, duplicate headers and merge-side provenance are never rewritten', async () => {
  const f = fixture(), a = commit(f.base.tree, [f.base.object_id], 'side-a', 'sha1'), b = commit(f.tip.tree, [f.base.object_id], 'side-b', 'sha1');
  const merge = commit(f.tip.tree, [a.object_id, b.object_id], 'merge', 'sha1');
  const parsed = await commitRecord(merge, 'sha1', crypto); assert.deepEqual(parsed.parents, [a.object_id, b.object_id]);
  const repeated = commit(f.tip.tree, [a.object_id, a.object_id], 'duplicates', 'sha1');
  assert.deepEqual((await commitRecord(repeated, 'sha1', crypto)).parents, [a.object_id, a.object_id]);
  await assert.rejects(commitRecord({ ...merge, parents: [b.object_id, a.object_id] }, 'sha1', crypto));
});
test('wrong hashes, wrong decoded trees, and summaries not matching the native headers refuse', async () => {
  const f = fixture();
  for (const row of [{ ...f.tip, body_hex: f.tip.body_hex + '00' }, { ...f.tip, tree: f.base.tree },
    { ...f.tip, parents: [] }, { ...f.tip, parents: [f.tip.object_id] }, { ...f.tip, object_id: 'sha256:' + 'a'.repeat(64) }]) {
    await assert.rejects(commitRecord(row, 'sha1', crypto));
  }
});
test('unfiltered history refuses wrong snapshots, mixed repositories, count gaps and reordered ancestry', async () => {
  const changes = [r => r.snapshot_token = `alg:1:${'a'.repeat(64)}`, r => r.repository_incarnation = '9'.repeat(32),
    r => r.ref_hex = hex(bytes('refs/heads/other')), r => r.source_commit = 'a'.repeat(40), r => r.page_complete = false,
    r => r.author_identity_verified = true, r => r.total_commits = 3, r => r.next_after = 2,
    r => r.commits.reverse(), r => r.commits[1] = r.commits[0], r => r.commits.pop(), r => r.ordering = 'date', r => r.published = true];
  for (const change of changes) { const f = fixture(), c = await opened(f); f.config.mutate = change; await assert.rejects(c.log()); }
});
test('path filtering cannot substitute simplified, renamed, or differently selected history', async () => {
  for (const change of [r => r.path_hex = '61', r => r.path_selection = 'first-parent', r => r.total_commits_scope = 'all',
    r => r.history_simplified = true, r => r.renames_followed = true, r => r.type = 'source_log']) {
    const f = fixture(), c = await opened(f); f.config.mutate = change; await assert.rejects(c.log({ path_hex: f.path }));
  }
});
test('malformed blame ranges, line origins, hashes, and work reports cannot become a successful attribution', async () => {
  const changes = [r => r.lines[0].byte_start++, r => r.lines[0].origin_byte_end++, r => r.lines[0].line++,
    r => r.lines[1].origin_commit = 'a'.repeat(40), r => r.origins = [], r => r.origins.reverse(), r => r.lines.pop(),
    r => r.content_hex += '00', r => r.blob = 'a'.repeat(40), r => r.first_line++, r => r.end_line--,
    r => r.graph_commits = 0, r => r.comparisons = 129, r => r.max_diff_work = 1, r => r.range_complete = false,
    r => r.scope = 'renames', r => r.line_origin = 1, r => r.path_hex = '61', r => r.origins[0].body_hex += '00',
    r => r.content_hex = hex(bytes('ON\n\ntwo')), r => r.algorithms = ['Myers', 'Myers']];
  for (const change of changes) { const f = fixture(), c = await opened(f); f.config.mutate = change; await assert.rejects(c.blame(f.path)); await assert.rejects(c.origin(0)); }
});
test('historical source cannot change ref-tip/ancestor, path, hash domain, range, or traversal semantics', async () => {
  const changes = [r => r.source_ref_tip = 'a'.repeat(40), r => r.at_commit = 'a'.repeat(40),
    r => r.source.source_commit = 'a'.repeat(40), r => r.selection = 'arbitrary-object',
    r => r.source.path_hex = '61', r => r.source.repository_id = 'a'.repeat(32), r => r.source.offset = 1,
    r => r.source.content_hex = 'ff', r => r.source.returned_bytes++, r => r.source.next_offset = 1,
    r => r.source.symlink_followed = true, r => r.source.object_id = 'a'.repeat(40), r => r.source.kind = 'directory'];
  for (const change of changes) { const f = fixture(), c = await opened(f); f.config.mutate = change; await assert.rejects(c.historical('blob', f.base.object_id, f.path)); }
});
test('origin navigation rejects otherwise well-formed historical bytes that differ from the attributed line', async () => {
  const f = fixture(), c = await opened(f); await c.blame(f.path);
  f.config.mutate = r => { r.source.content_hex = hex(bytes('bad')); };
  await assert.rejects(c.origin(1), /attributed bytes/);
});
test('directory entries are byte-ordered, immediate, unique and self-delimited', async () => {
  for (const change of [r => r.source.entries.push(r.source.entries[0]), r => r.source.entries[0].name_hex = '612f62',
    r => r.source.entries[0].name_hex = '2e2e', r => r.source.entries[0].kind = 'html', r => r.source.next_after_hex = '61']) {
    const f = fixture(), c = await opened(f); f.config.mutate = change; await assert.rejects(c.historical('tree', f.base.object_id));
  }
});
test('invalid options, paths and unpublished guesses refuse without network activity', async () => {
  const f = fixture(), c = client(f); c.connect(token);
  await assert.rejects(c.log()); await assert.rejects(c.blame(f.path)); await assert.rejects(c.origin(0)); assert.equal(f.calls.length, 0);
  await c.open(f.ref, f.algorithm); const count = f.calls.length;
  for (const options of [{ after: -1 }, { limit: 0 }, { limit: 101 }, { path_hex: '' }, { force: true }, { after: Number.MAX_SAFE_INTEGER + 1 }]) await assert.rejects(c.log(options));
  for (const path of ['', '00', '2f61', '612f', '2e2e', '612f2f62', 'FF', 'a']) assert.throws(() => bytePath(path));
  await assert.rejects(c.blame(f.path, { first: 2, end: 1 })); await assert.rejects(c.blame(f.path, { first: 20001 }));
  await assert.rejects(c.historical('apply', f.base.object_id)); await assert.rejects(c.historical('blob', '0'.repeat(40), f.path));
  await assert.rejects(c.historical('tree', f.base.object_id, null, { after: '612f62' }));
  assert.equal(f.calls.length, count);
});
test('requests cannot gain write keys, ambient credentials, redirects, or extra HTTP verbs', async () => {
  const f = fixture(), c = await opened(f); await c.blame(f.path); await c.origin(0);
  for (const call of f.calls) {
    assert.equal(call.options.method, 'POST'); assert.equal(call.options.credentials, 'omit'); assert.equal(call.options.redirect, 'error');
    assert.equal(new Headers(call.options.headers).get('Idempotency-Key'), null); assert.equal(call.url.includes(token), false);
  }
  for (const bad of ['http://example.com/r.git/ui/history/', 'https://example.com/r.git/ui/history/?token=x',
    'https://example.com/r.git/ui/history/#x', 'https://u:p@example.com/r.git/ui/history/', 'https://example.com/r.git/ui/source/']) {
    assert.throws(() => new HistoryClient({ href: bad }));
  }
});
test('native refusal states do not become empty success or an automatic retry', async () => {
  for (const status of [403, 404, 409, 413, 429, 503]) {
    const f = fixture(), c = await opened(f); f.config.respond = () => json({}, status);
    await assert.rejects(c.log()); assert.equal(f.calls.length, 2); assert.equal(c.connected, true);
  }
});
test('superseded responses cannot replace the selected scope or disconnect a new credential', async () => {
  const f = fixture(), c = await opened(f), delayed = deferred(); f.config.respond = () => delayed.promise;
  const old = c.log(); const rejected = assert.rejects(old); c.disconnect(); c.connect('d'.repeat(64));
  f.config.respond = null; await c.open(f.ref, f.algorithm); delayed.resolve(json({}, 401)); await rejected;
  assert.equal(c.connected, true); assert.equal(c.selection.tip, f.tip.object_id);
});
test('new reads and explicit cancellation prevent late provenance from being retained', async () => {
  const f = fixture(), c = await opened(f), delayed = deferred();
  f.config.respond = call => call.endpoint === 'blame' ? delayed.promise : json(f.log(call.form));
  const old = c.blame(f.path), rejected = assert.rejects(old); await c.log();
  delayed.resolve(json(f.blame(new URLSearchParams()))); await rejected; await assert.rejects(c.origin(0));
  const next = deferred(); f.config.respond = () => next.promise;
  const reading = c.log(), cancelled = assert.rejects(reading); c.cancel(); next.resolve(json({})); await cancelled;
  assert.equal(c.selection.tip, f.tip.object_id);
});
test('cancellation during native hashing cannot retain a stale first page', async () => {
  const f = fixture(), stalled = deferred(); let started;
  const signal = new Promise(done => { started = done; });
  const delayedCrypto = { subtle: { digest: async (...args) => { started(); await stalled.promise; return crypto.subtle.digest(...args); } } };
  const c = new HistoryClient({ href, fetchImpl: f.fetchImpl, cryptoImpl: delayedCrypto }); c.connect(token);
  const reading = c.open(f.ref, f.algorithm), rejected = assert.rejects(reading); await signal; c.cancel(); stalled.resolve(); await rejected;
  assert.equal(c.selection, null);
});
test('invalid content type, malformed UTF-8 and declared oversize are refused', async () => {
  for (const response of [() => new Response('{}'), () => new Response(Uint8Array.of(255), { headers: { 'Content-Type': 'application/json' } }),
    () => new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': String(9 * 1024 * 1024) } }),
    () => new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': '3' } })]) {
    const f = fixture(), c = await opened(f); f.config.respond = response; await assert.rejects(c.log());
  }
});
test('current authentication rejection clears the selected repository and original credential', async () => {
  const f = fixture(), c = await opened(f); f.config.respond = () => json({}, 401);
  await assert.rejects(c.blame(f.path)); assert.equal(c.connected, false); assert.equal(c.selection, null);
});
