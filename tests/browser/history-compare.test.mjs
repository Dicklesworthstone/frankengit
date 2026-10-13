import test from 'node:test';
import assert from 'node:assert/strict';
import { comparisonPage, comparisonQuery, COMPARISON_LIMITS } from '../../crates/fgit-node/src/smart_http/server/browser/history-data.mjs';
import { fixture, harness, clone, hex, jsonResponse, token, gitHash } from './history-compare-fixtures.mjs';
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const selection = f => ({ ref: f.afterRef, object_format: f.algorithm, head: f.common.snapshot_token, tip: f.after,
  scope: { tenant: f.common.tenant_id, repository: f.common.repository_id, incarnation: f.common.repository_incarnation, format: f.algorithm } });
const check = (f, reply, query = comparisonQuery(f.beforeRef)) => comparisonPage(reply, selection(f), query);
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: direct and merge-base retain both tips, head and read-only transport`, async () => {
    const h = harness(fixture(algorithm)); await h.open();
    const initial = h.client.selection, first = await h.client.compare(h.f.beforeRef);
    assert.equal(first.before, h.f.before); assert.equal(first.after, h.f.after); assert.equal(first.base, h.f.before);
    assert.equal(first.entries[0].before.object_id, h.f.beforeBlob);
    const second = await h.client.compare(h.f.beforeRef, { mode: 'merge-base', path_prefixes_hex: [hex('src')] });
    assert.equal(second.base, h.f.base); assert.equal(second.query.expected_before, h.f.before);
    assert.deepEqual(h.client.selection, initial);
    const call = h.calls.at(-1);
    assert.equal(call.form.get('expected_before'), h.f.before); assert.equal(call.form.get('expected_after'), h.f.after);
    assert.equal(call.form.get('expected_head'), initial.head); assert.equal(call.form.get('mode'), 'merge-base');
    assert.deepEqual(call.form.getAll('path_prefix_hex'), [hex('src')]);
    for (const [field, amount] of Object.entries(COMPARISON_LIMITS)) assert.equal(call.form.get(field), String(amount));
    for (const request of h.calls) {
      assert.equal(request.method, 'POST'); assert.equal(request.headers['Idempotency-Key'], undefined);
      assert.equal(request.headers.Authorization, `Bearer ${token}`); assert.equal(new URL(request.url).search, '');
      assert.equal(request.redirect, 'error'); assert.equal(request.credentials, 'omit'); assert.equal(request.mode, 'same-origin');
    }
  });
  test(`${algorithm}: before/after files use distinct original refs and exact compared native objects`, async () => {
    const h = harness(fixture(algorithm)); await h.open();
    await h.client.compare(h.f.beforeRef, { mode: 'merge-base' });
    const a = await h.client.comparisonFile('before', hex('src/file.txt'), { limit: 3 });
    assert.equal(a.comparisonSide, 'before'); assert.equal(a.source.content_hex, hex(h.f.beforeBody.subarray(0, 3)));
    let form = h.calls.at(-1).form;
    assert.equal(form.get('ref'), h.f.beforeRef); assert.equal(form.get('expected_ref_tip'), h.f.before); assert.equal(form.get('at_commit'), h.f.base);
    const b = await h.client.comparisonFile('after', hex('src/file.txt'));
    assert.equal(b.source.content_hex, hex(h.f.afterBody)); form = h.calls.at(-1).form;
    assert.equal(form.get('ref'), h.f.afterRef); assert.equal(form.get('expected_ref_tip'), h.f.after); assert.equal(form.get('at_commit'), h.f.after);
    assert.equal(h.client.selection.ref, h.f.afterRef); assert.equal(h.client.selection.tip, h.f.after);
  });
  test(`${algorithm}: explicit before tip is checked before accepting a comparison`, async () => {
    const h = harness(fixture(algorithm)); await h.open();
    await assert.rejects(h.client.compare(h.f.beforeRef, { expected_before: 'e'.repeat(h.f.width) }), /changed/);
    await assert.rejects(h.client.comparisonFile('before', hex('src/file.txt')), /complete/);
    await h.client.compare(h.f.beforeRef, { expected_before: h.f.tag(h.f.before) });
    assert.equal(h.calls.at(-1).form.get('expected_before'), h.f.before);
  });
  test(`${algorithm}: binary, executable, symlink, directory and gitlink changes remain distinct`, () => {
    const f = fixture(algorithm), raw = f.diff(), make = (path, a, b, kind, content) => ({ path_hex: hex(path), before: a, after: b, kind, content });
    const blob = mode => ({ mode, object_id: f.tag(f.beforeBlob) }), tree = { mode: '040000', object_id: f.tag(f.beforeTree) };
    raw.entries = [
      make('a', null, blob('100644'), 'added', { kind: 'binary', before_bytes: 0, after_bytes: 8 }),
      make('b', blob('100644'), null, 'deleted', { kind: 'binary', before_bytes: 8, after_bytes: 0 }),
      make('c', blob('100644'), blob('100755'), 'mode_changed', { kind: 'identical' }),
      make('d', blob('120000'), tree, 'type_changed', { kind: 'binary', before_bytes: 8, after_bytes: 0 }),
      make('e', null, { mode: '160000', object_id: f.tag(f.before) }, 'added', { kind: 'object_only' }),
    ];
    raw.entry_count = raw.entries.length; assert.equal(check(f, raw).entries.length, 5);
  });
}

test('an empty comparison is readable without implying a merge or approval', () => {
  const f = fixture(), raw = f.diff({ entries: [], entry_count: 0 });
  assert.equal(check(f, raw).entries.length, 0); raw.before_tree = raw.after_tree;
  assert.equal(check(f, raw).entries.length, 0);
});

test('CRLF, non-UTF-8 and missing final newline hunk bytes are preserved', () => {
  const f = fixture(), raw = f.diff(), c = raw.entries[0].content, before = Buffer.from([0xff, 13, 10]), after = Buffer.from([0xfe]);
  c.before_bytes = 3; c.after_bytes = 1; c.hunks = [{ old: f.lineSpan(before), new: f.lineSpan(after), before_hex: hex(before), after_hex: hex(after) }];
  assert.equal(check(f, raw).entries[0].content.hunks[0].after_hex, 'fe');
});

test('full UTF-8 refs and raw byte paths retain exact native form values', async () => {
  const f = fixture(); f.beforeRef = 'refs/heads/日本語';
  const path = '7372632fff', raw = f.diff({ before_ref_hex: hex(f.beforeRef), path_prefixes_hex: [path] });
  raw.entries[0].path_hex = path;
  const h = harness(f, call => call.url.endsWith('/diff') ? jsonResponse(raw) : null); await h.open();
  await h.client.compare(f.beforeRef, { path_prefixes_hex: [path] });
  assert.equal(h.calls.at(-1).form.get('before_ref'), f.beforeRef); assert.equal(h.calls.at(-1).form.get('path_prefix_hex'), path);
});

const badReplies = [
  ['wrong repository', r => { r.repository_id = 'other'; }], ['wrong incarnation', r => { r.repository_incarnation = 'other'; }],
  ['changed head', r => { r.snapshot_token = `alg:2:${'e'.repeat(64)}`; }], ['swapped references', r => { [r.before_ref_hex, r.after_ref_hex] = [r.after_ref_hex, r.before_ref_hex]; }],
  ['changed after tip', r => { r.requested_after = `sha1:${'e'.repeat(40)}`; }], ['wrong mode', r => { r.mode = 'merge-base'; }],
  ['direct base differs', r => { r.compared_before = `sha1:${'e'.repeat(40)}`; }], ['incomplete', r => { r.complete = false; }],
  ['missing path', r => { r.entry_count = 2; }], ['PR substitution', r => { r.pull_request = { number: 1, version: 1 }; }],
  ['approval claim', r => { r.approval_created = true; }], ['write claim', r => { r.transaction_created = true; }],
  ['wrong context', r => { r.context_lines = 5; }], ['unknown field', r => { r.merge_allowed = true; }],
  ['unknown content', r => { r.entries[0].content = { kind: 'unsupported' }; }], ['bad mode', r => { r.entries[0].before.mode = '100600'; }],
  ['wrong change kind', r => { r.entries[0].kind = 'added'; }], ['duplicate path', r => { r.entries.push(clone(r.entries[0])); r.entry_count++; }],
  ['unsafe path', r => { r.entries[0].path_hex = hex('src/../private'); }], ['false identical', r => { r.entries[0].content = { kind: 'identical' }; }],
  ['false object-only', r => { r.entries[0].content = { kind: 'object_only' }; }], ['inconsistent tree', r => { r.before_tree = r.after_tree; }],
  ['oversized blob', r => { r.entries[0].content.before_bytes = 1048577; }], ['unsafe integer', r => { r.entries[0].content.additions = 2 ** 54; }],
  ['mismatched hunk span', r => { r.entries[0].content.hunks[0].old.byte_end++; }], ['mismatched line count', r => { r.entries[0].content.hunks[0].new.line_count++; }],
  ['overlapping hunks', r => { r.entries[0].content.hunks.push(clone(r.entries[0].content.hunks[0])); }],
  ['empty both sides', r => { r.entries[0].before = r.entries[0].after = null; }],
];
for (const [name, mutate] of badReplies) test(`malformed ${name} is refused rather than displayed as a clean comparison`, () => {
  const f = fixture(), valid = f.diff(); assert.equal(check(f, valid).entries.length, 1);
  const raw = clone(valid); mutate(raw); assert.throws(() => check(f, raw));
});

test('path prefix matching respects components rather than textual prefixes', () => {
  const f = fixture(), query = comparisonQuery(f.beforeRef, { path_prefixes_hex: [hex('src')] }), raw = f.diff({ path_prefixes_hex: query.path_prefixes_hex });
  assert.equal(check(f, raw, query).entries.length, 1);
  raw.entries[0].path_hex = hex('src-other/file.txt'); assert.throws(() => check(f, raw, query), /filter/);
  raw.path_prefixes_hex = []; assert.throws(() => check(f, raw, query), /profile/);
});

test('invalid options and publication escape hatches refuse before fetch', async () => {
  const h = harness(); await h.open(); const count = h.calls.length;
  for (const options of [{ key: 'mutation' }, { mode: 'squash' }, { path_prefixes_hex: ['00'] },
    { expected_before: 'sha256:' + 'a'.repeat(64) }, { path_prefixes_hex: [hex('src'), hex('src')] },
    { path_prefixes_hex: Array(65).fill(hex('src')) }, { expected_before: '0'.repeat(40) }]) {
    await assert.rejects(h.client.compare(h.f.beforeRef, options));
  }
  for (const ref of ['main', 'https://other.test/x', 'refs/heads/../x', 'refs/heads/x?y', 'refs/heads/x\n']) await assert.rejects(h.client.compare(ref));
  assert.equal(h.calls.length, count);
});

test('a retained before tip cannot be changed by editing or clearing its input', async () => {
  let override = null; const h = harness(fixture(), call => call.url.endsWith('/diff') && override ? jsonResponse(override) : null);
  await h.open(); await h.client.compare(h.f.beforeRef);
  const count = h.calls.length;
  await assert.rejects(h.client.compare(h.f.beforeRef, { expected_before: 'e'.repeat(40) }), /pin changed/); assert.equal(h.calls.length, count);
  override = h.f.diff({ requested_before: `sha1:${'e'.repeat(40)}`, compared_before: `sha1:${'e'.repeat(40)}` });
  await assert.rejects(h.client.compare(h.f.beforeRef), /changed/);
  assert.equal(h.calls.at(-1).form.get('expected_before'), h.f.before);
  await h.client.open(h.f.afterRef, h.f.algorithm); await h.client.compare(h.f.beforeRef);
  assert.equal(h.calls.at(-1).form.has('expected_before'), false);
});

test('comparison results and caller arrays cannot mutate retained file selection', async () => {
  const h = harness(); await h.open(); const paths = [hex('src')], pending = h.client.compare(h.f.beforeRef, { path_prefixes_hex: paths });
  paths[0] = hex('other'); const result = await pending;
  result.before = 'e'.repeat(40); result.entries[0].before.object_id = 'e'.repeat(40); result.entries[0].path_hex = hex('other');
  await h.client.comparisonFile('before', hex('src/file.txt'));
  assert.equal(h.calls.at(-1).form.get('expected_ref_tip'), h.f.before);
});

for (const status of [401, 403, 404, 409, 413, 429, 500]) test(`HTTP ${status} never becomes an empty comparison or automatic retry`, async () => {
  const h = harness(fixture(), call => call.url.endsWith('/diff') ? jsonResponse({}, status) : null); await h.open();
  const prior = h.client.selection; await assert.rejects(h.client.compare(h.f.beforeRef), e => e.status === status);
  assert.equal(h.calls.length, 2); assert.equal(h.client.connected, status !== 401);
  assert.deepEqual(h.client.selection, status === 401 ? null : prior);
  await assert.rejects(h.client.comparisonFile('before', hex('src/file.txt')));
});

test('disconnect fences a late response and clears comparison state and credentials', async () => {
  const gate = deferred(), h = harness(fixture(), call => call.url.endsWith('/diff') ? gate.promise : null); await h.open();
  const read = h.client.compare(h.f.beforeRef); h.client.disconnect(); gate.resolve(jsonResponse(h.f.diff()));
  await assert.rejects(read); assert.equal(h.client.selection, null);
  await assert.rejects(h.client.comparisonFile('before', hex('src/file.txt')));
});

test('a new comparison cancels and fences the older request', async () => {
  const gate = deferred(); let requests = 0;
  const h = harness(fixture(), call => call.url.endsWith('/diff') && ++requests === 1 ? gate.promise : null); await h.open();
  const first = h.client.compare(h.f.beforeRef), second = await h.client.compare(h.f.beforeRef, { mode: 'merge-base' });
  gate.resolve(jsonResponse(h.f.diff())); await assert.rejects(first); assert.equal(second.base, h.f.base);
  await h.client.comparisonFile('before', hex('src/file.txt')); assert.equal(h.calls.at(-1).form.get('at_commit'), h.f.base);
});

test('stream deadlines and declared reply limits bound the new endpoint', async () => {
  for (const mode of ['timeout', 'oversize']) {
    const h = harness(fixture(), call => !call.url.endsWith('/diff') ? null : mode === 'timeout'
      ? new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{')); } }), { headers: { 'Content-Type': 'application/json' } })
      : new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': String(8 * 1024 * 1024 + 1) } }), { timeoutMs: 50 });
    await h.open(); await assert.rejects(h.client.compare(h.f.beforeRef)); assert.equal(h.calls.length, 2);
  }
});

test('changed historical file identity, mode or root tree refuses even with a valid body hash', async () => {
  for (const patch of [{ kind: 'symlink' }, { root_tree: `sha1:${'e'.repeat(40)}` }, { object_id: `sha1:${'e'.repeat(40)}` }]) {
    const h = harness(fixture(), call => {
      if (!call.url.endsWith('/historical-blob')) return null;
      const reply = h.f.historical(call.form); Object.assign(reply.source, patch); return jsonResponse(reply);
    });
    await h.open(); await h.client.compare(h.f.beforeRef); await assert.rejects(h.client.comparisonFile('before', hex('src/file.txt')));
  }
});

test('directories, gitlinks, absent sides and paths outside the comparison never trigger a historical read', async () => {
  const f = fixture(), raw = f.diff(); raw.entries[0] = { path_hex: hex('submodule'), kind: 'added', before: null,
    after: { mode: '160000', object_id: f.tag(f.after) }, content: { kind: 'object_only' } };
  const h = harness(f, call => call.url.endsWith('/diff') ? jsonResponse(raw) : null); await h.open(); await h.client.compare(f.beforeRef);
  for (const [side, path] of [['before', 'submodule'], ['after', 'submodule'], ['after', 'other'], ['unsafe', 'submodule']]) await assert.rejects(h.client.comparisonFile(side, hex(path)));
  assert.equal(h.calls.length, 2);
});

test('text/entry/hunk aggregate bounds refuse before a result is installed', () => {
  const f = fixture();
  for (const count of [513, 65]) {
    const entries = Array.from({ length: count }, (_, i) => f.entry(`src/${String(i).padStart(4, '0')}`));
    assert.throws(() => check(f, f.diff({ entries, entry_count: entries.length })));
  }
  const raw = f.diff(); raw.entries[0].content.hunks = Array(4097).fill(raw.entries[0].content.hunks[0]);
  assert.throws(() => check(f, raw), /limit/);
  let calls = 0; assert.throws(() => comparisonPage(f.diff(), selection(f), comparisonQuery(f.beforeRef), () => { if (++calls === 3) throw new Error('cancelled'); }), /cancelled/);
});

test('a non-settling refused body cleanup does not keep the history read pending', { timeout: 1000 }, async () => {
  let cancelled = false;
  const h = harness(fixture(), call => call.url.endsWith('/diff') ? new Response(new ReadableStream({
    cancel() { cancelled = true; return new Promise(() => {}); },
  }), { status: 403 }) : null);
  await h.open(); await assert.rejects(h.client.compare(h.f.beforeRef), e => e.status === 403);
  assert.equal(cancelled, true);
});

test('full compared-file reads verify the blob while ranges retain a weaker claim', async () => {
  const h = harness(); await h.open(); await h.client.compare(h.f.beforeRef);
  assert.equal((await h.client.comparisonFile('after', hex('src/file.txt'), { limit: 2 })).fullBlobVerified, false);
  assert.equal((await h.client.comparisonFile('after', hex('src/file.txt'), { limit: 1048576 })).fullBlobVerified, true);
});

test('the payload boundary includes raw path bytes, not just hunk data', () => {
  const f = fixture(), raw = f.diff(), entry = raw.entries[0], max = COMPARISON_LIMITS.max_blob_bytes;
  entry.path_hex = hex('x');
  const a = Buffer.alloc(max, 120), b = Buffer.alloc(max - 1, 121);
  entry.content = { kind: 'text', algorithm: 'Myers', additions: 1, deletions: 1, before_bytes: a.length, after_bytes: b.length,
    hunks: [{ old: f.lineSpan(a), new: f.lineSpan(b), before_hex: hex(a), after_hex: hex(b) }] };
  assert.equal(check(f, raw).entries.length, 1);
  const longer = Buffer.alloc(max, 121); entry.content.after_bytes = longer.length;
  entry.content.hunks[0].new = f.lineSpan(longer); entry.content.hunks[0].after_hex = hex(longer);
  assert.throws(() => check(f, raw), /payload limit/);
});

test('one reference at one snapshot cannot report two different tips', () => {
  const f = fixture(), raw = f.diff({ before_ref_hex: hex(f.afterRef) });
  assert.throws(() => check(f, raw, comparisonQuery(f.afterRef)), /changed/);
  const same = f.diff({ mode: 'merge-base', requested_before: f.tag(f.after), compared_before: f.tag(f.before) });
  assert.throws(() => check(f, same, comparisonQuery(f.beforeRef, { mode: 'merge-base' })), /changed/);
});
