// Protocol/DOM peers verify the shipped client, not native authorization or scale.
import test from 'node:test';
import assert from 'node:assert/strict';
import { HistoryClient } from '../../crates/fgit-node/src/smart_http/server/browser/history.mjs';
import { fixture, token, crypto, href, bytes, hex, commit, json, deferred } from './history-fixtures.mjs';

const client = f => new HistoryClient({ href, fetchImpl: f.fetchImpl, cryptoImpl: crypto });
async function opened(f, options = { first_parent: true, limit: 1 }) {
  const c = client(f); c.connect(token); const first = await c.open(f.ref, f.algorithm, options); return { c, first };
}

for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: first-parent pages retain native identity and never infer a history total`, async () => {
    const f = fixture(algorithm), { c, first } = await opened(f);
    assert.equal(first.commits[0].id, f.tip.object_id); assert.equal(first.rootReached, false);
    assert.equal(first.visitedCommits, 1); assert.equal(first.visitedParentEdges, 1);
    assert.equal(first.metadataBytes, f.tip.body_hex.length / 2);
    assert.equal(Object.hasOwn(first.raw, 'total_commits'), false); assert.equal(Object.hasOwn(first, 'total'), false);
    const next = await c.log({ first_parent: true, cursor: first.nextCursor, limit: 1 });
    assert.equal(next.commits[0].id, f.base.object_id); assert.equal(next.rootReached, true); assert.equal(next.nextCursor, null);
    assert.equal(next.visitedCommits, 2); assert.equal(next.metadataBytes, (f.tip.body_hex.length + f.base.body_hex.length) / 2);
    const form = f.calls.at(-1).form;
    assert.equal(form.get('cursor'), first.nextCursor); assert.equal(form.get('expected_head'), f.head);
    assert.equal(form.get('expected_commit'), f.tip.object_id); assert.equal(form.has('after'), false);
    assert.equal(form.has('path_hex'), false); assert.equal(new Headers(f.calls.at(-1).options.headers).has('Idempotency-Key'), false);
    const all = await c.log(); assert.equal(all.total, 2); assert.equal(all.first_parent, undefined);
  });
  test(`${algorithm}: recent view can open when complete graph reads refuse, without automatic fallback`, async () => {
    const f = fixture(algorithm);
    f.config.respond = call => call.form.get('first_parent') === 'true' ? json(f.log(call.form)) : json({}, 413);
    const c = client(f); c.connect(token);
    await assert.rejects(c.open(f.ref, algorithm), /resource limit/);
    assert.equal(c.selection, null); assert.equal(f.calls.length, 1);
    const first = await c.open(f.ref, algorithm, { first_parent: true, limit: 1 });
    assert.equal(first.commits[0].id, f.tip.object_id); assert.equal(f.calls.length, 2);
  });
  test(`${algorithm}: a merge preserves every parent header while following only the stored first parent`, async () => {
    const f = fixture(algorithm), side = 'd'.repeat(algorithm === 'sha1' ? 40 : 64);
    const merge = commit(f.tip.tree, [f.base.object_id, side], 'merge', algorithm);
    f.records[0] = merge;
    f.config.mutate = response => { response.source_commit = merge.object_id; };
    const { first } = await opened(f, { first_parent: true, limit: 20 });
    assert.deepEqual(first.commits[0].parents, [f.base.object_id, side]);
    assert.equal(first.commits.length, 2); assert.equal(first.visitedParentEdges, 2);
    assert.ok(!first.commits.some(row => row.id === side));
  });
}

test('first-parent cursors cannot be retargeted, aliased, or used with another history profile', async () => {
  const f = fixture(), { c, first } = await opened(f), count = f.calls.length, cursor = first.nextCursor;
  for (const options of [
    { cursor }, { first_parent: false }, { first_parent: 'true' }, { first_parent: true, after: 0 },
    { first_parent: true, path_hex: null }, { first_parent: true, path_hex: f.path }, { first_parent: true, limit: 0 },
    ...[
      '', cursor + '/extra', cursor.replace('fgfp1/', 'fgfp2/'), cursor.replace('alg:1:', 'alg:01:'),
      cursor.replace(f.head, `alg:1:${'a'.repeat(64)}`), cursor.replace(hex(bytes(f.ref)), hex(bytes('refs/heads/other'))),
      cursor.replace('/sha1/', '/sha256/'), cursor.replace(f.tip.object_id, f.base.object_id),
      cursor.replace(/\/1$/, '/01'), cursor.replace(/\/1$/, '/0'), cursor.replace(/\/1$/, '/4097'),
      'x'.repeat(4097),
    ].map(value => ({ first_parent: true, cursor: value })),
  ]) await assert.rejects(c.log(options));
  assert.equal(f.calls.length, count);
  await assert.rejects(c.open(f.ref, f.algorithm, { first_parent: true, cursor }));
  assert.equal(f.calls.length, count); assert.equal(c.selection, null);
});

test('invalid profile, work counters, chain, root and continuation cannot become successful pages', async () => {
  const changes = [
    r => r.type = 'source_log', r => r.profile = 'topo-oid-v1', r => r.ordering = 'date', r => r.page_complete = false,
    r => r.author_identity_verified = true, r => r.root_reached = 'false', r => r.root_reached = true,
    r => r.visited_commits++, r => r.visited_parent_edges = 0, r => r.visited_parent_edges++,
    r => r.metadata_bytes--, r => r.metadata_bytes++, r => r.metadata_bytes = 4194305,
    r => r.total_commits = 2, r => r.next_after = null, r => r.next_cursor = null,
    r => r.next_cursor += '/extra', r => r.next_cursor = r.next_cursor.replace(/\/1$/, '/2'),
    r => r.commits = [], r => r.commits.push(r.commits[0]), r => r.commits[0].body_hex += '00',
    r => r.source_commit = 'a'.repeat(40), r => r.after++, r => r.limit++, r => r.published = true,
  ];
  for (const change of changes) {
    const f = fixture(); f.config.mutate = change;
    const c = client(f); c.connect(token);
    await assert.rejects(c.open(f.ref, f.algorithm, { first_parent: true, limit: 1 }));
    assert.equal(c.selection, null);
  }
  const f = fixture(), { c } = await opened(f);
  f.config.mutate = r => { r.commits.reverse(); };
  await assert.rejects(c.log({ first_parent: true, limit: 20 }));
});

test('a validly hashed side-parent chain is refused as a replacement first-parent page', async () => {
  const f = fixture(), side = commit(f.base.tree, [], 'side root', 'sha1');
  const merge = commit(f.tip.tree, [f.base.object_id, side.object_id], 'merge', 'sha1');
  f.records.splice(0, f.records.length, merge, side);
  f.config.mutate = r => { r.source_commit = merge.object_id; };
  await assert.rejects(opened(f, { first_parent: true, limit: 20 }), /first-parent chain/);
});

test('authority movement, revocation and cancellation do not trigger refresh or truncate a page', async () => {
  for (const status of [401, 403, 404, 409, 413, 429, 503]) {
    const f = fixture(), { c, first } = await opened(f);
    f.config.respond = () => json({}, status);
    await assert.rejects(c.log({ first_parent: true, cursor: first.nextCursor, limit: 1 }));
    assert.equal(f.calls.length, 2); assert.equal(c.connected, status !== 401);
  }
  const f = fixture(), { c, first } = await opened(f), delayed = deferred();
  f.config.respond = () => delayed.promise;
  const pending = c.log({ first_parent: true, cursor: first.nextCursor, limit: 1 }), rejected = assert.rejects(pending);
  c.cancel(); delayed.resolve(json(f.log(new URLSearchParams({ first_parent: 'true', cursor: first.nextCursor, limit: '1' }))));
  await rejected; assert.equal(c.selection.tip, f.tip.object_id);
});

test('a continued page rejects a different repository, snapshot or native tip', async () => {
  for (const change of [r => r.repository_incarnation = '9'.repeat(32), r => r.snapshot_token = `alg:1:${'a'.repeat(64)}`,
    r => r.ref_hex = hex(bytes('refs/heads/other')), r => r.source_commit = 'a'.repeat(40)]) {
    const f = fixture(), { c, first } = await opened(f); f.config.mutate = change;
    await assert.rejects(c.log({ first_parent: true, cursor: first.nextCursor, limit: 1 }));
    assert.equal(c.selection.head, f.head); assert.equal(c.selection.tip, f.tip.object_id);
  }
});
