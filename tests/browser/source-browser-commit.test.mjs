// Executes the production commit/path/blob verifier with native HTTP wire shapes,
// real WebCrypto and observable DOM controls; not live-node or browser evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifySourceCommit, sourceBinding, mount, COMMIT_PROOF_LIMITS }
  from '../../crates/fgit-node/src/smart_http/server/browser/browser.mjs';
import { fixture, hex, webcrypto, response, PAGE, dom, location, waitFor, queuedFetch }
  from './source-browser-fixtures.mjs';

const native = (format, kind, bytes) => createHash(format).update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
function corpus(format = 'sha1', options = {}) {
  const f = fixture(format, options.bytes ?? Buffer.from('source\n'), options.kind ?? 'file');
  const mode = { file: '100644', executable: '100755', symlink: '120000' }[f.blob().kind];
  const tree = Buffer.concat([Buffer.from(mode + ' '), Buffer.from(f.path, 'hex'), Buffer.from([0]), Buffer.from(f.oid, 'hex')]);
  f.common.root_tree = native(format, 'tree', tree);
  const parents = options.parents ?? [];
  let body = options.body ?? Buffer.from(`tree ${f.common.root_tree}\n${parents.map(p => `parent ${p}\n`).join('')}author A <a@example.test> 0 +0000\ncommitter A <a@example.test> 0 +0000\n\noriginal message\n`);
  if (options.transform) body = options.transform(body, f);
  const commit = native(format, 'commit', body);
  f.common.source_commit = commit;
  const log = () => {
    // source/log does not emit ref text, RCR or root_tree at the outer level.
    const { ref, source_rcr, root_tree, ...identity } = f.common;
    return { ...identity, type: 'source_log', author_identity_verified: false,
      ordering: 'child-before-parent-native-id-v1', page_complete: true, after: 0, limit: 1,
      total_commits: parents.length ? 2 : 1, next_after: parents.length ? 1 : null,
      commits: [{ object_id: `${format}:${commit}`, tree: `${format}:${root_tree}`, parents, body_hex: hex(body) }] };
  };
  return { ...f, body, commit, log, treeBody: tree };
}
const prove = (f, read = () => f.log(), options = {}) => verifySourceCommit(f.selected,
  sourceBinding(f.common, f.selected), read, { cryptoImpl: webcrypto, ...options });
const ACTION = 'Verify commit, path and complete file for download';
async function opened(f, extra, options = {}) {
  const d = dom(), calls = []; d.get('format').value = f.format;
  const client = mount(d.document, location, queuedFetch([f.tree(), f.blob(), ...extra], calls),
    { cryptoImpl: webcrypto, urlApi: d.urlApi, ...options });
  d.get('token').value = 'a'.repeat(64); d.get('connection').emit('submit');
  await waitFor(() => d.buttons('content').length === 1); d.buttons('content')[0].click();
  await waitFor(() => d.buttons('content').some(b => b.textContent === ACTION));
  return { ...d, calls, client, verify: () => d.buttons('content').find(b => b.textContent === ACTION).click() };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: first history page binds original commit bytes to the selected root`, async () => {
    const f = corpus(format, { parents: ['a'.repeat(format === 'sha1' ? 40 : 64)] }), calls = [];
    const result = await prove(f, fields => { calls.push(fields); return f.log(); });
    assert.deepEqual(result, { commit: f.commit, rootTree: f.common.root_tree, commitBytes: f.body.length,
      commitVerified: true, rootTreeVerified: true, authorityVerified: false, authorIdentityVerified: false });
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0], { ref: f.selected.reference, object_format: format,
      expected_head: f.common.snapshot_token, expected_commit: f.commit, after: '0', limit: '1',
      max_commits: '4096', max_edges: '16384', max_metadata_bytes: '4194304' });
  });
  test(`${format}: native body tampering fails even with a matching JSON tree summary`, async () => {
    const f = corpus(format);
    await assert.rejects(prove(f, () => { const log = f.log(); log.commits[0].body_hex += '0a'; return log; }), /native commit identity/);
    assert.equal((await prove(f)).commit, f.commit);
  });
  test(`${format}: a real commit hash cannot endorse a substituted root tree summary`, async () => {
    const f = corpus(format), other = 'd'.repeat(format === 'sha1' ? 40 : 64);
    const pinned = { ...sourceBinding(f.common, f.selected), tree: other };
    const log = f.log(); log.commits[0].tree = other;
    await assert.rejects(verifySourceCommit(f.selected, pinned, () => log, { cryptoImpl: webcrypto }), /reference headers/);
    assert.equal((await prove(f)).rootTree, f.common.root_tree);
  });
  test(`${format}: signature continuations and arbitrary message bytes cannot replace tree headers`, async () => {
    const f = corpus(format, { transform: (body, f) => Buffer.concat([
      body.subarray(0, body.indexOf('\n\n')), Buffer.from(`\ngpgsig -----BEGIN SIGNATURE-----\n tree ${'f'.repeat(f.common.root_tree.length)}\n binary `),
      Buffer.from([255, 0x80]), Buffer.from('\n -----END SIGNATURE-----\n\n'),
      Buffer.from(`tree ${'e'.repeat(f.common.root_tree.length)}\n`), Buffer.from([0, 255]),
    ]) });
    assert.equal((await prove(f)).rootTree, f.common.root_tree);
  });
  test(`${format}: uppercase native reference bytes are hashed unchanged and compared by value`, async () => {
    const parent = 'ab'.repeat(format === 'sha1' ? 20 : 32);
    const f = corpus(format, { parents: [parent], transform: body => Buffer.from(body.toString().replace(/^tree (.+)$/m, (_, id) => `tree ${id.toUpperCase()}`).replace(/^parent (.+)$/m, (_, id) => `parent ${id.toUpperCase()}`)) });
    assert.equal((await prove(f)).commit, f.commit);
  });
  test(`${format}: actual controls verify commit, directory and paginated binary file before download`, async () => {
    const f = corpus(format, { bytes: Buffer.alloc(PAGE + 3, 255) });
    const d = await opened(f, [f.log(), f.tree(), f.blob(), f.blob(PAGE)]);
    d.verify(); assert.equal(d.urls.size, 0);
    await waitFor(() => d.get('status').textContent.startsWith('Complete file verified.'));
    assert.match(d.get('content').textContent, /Commit-to-file chain verified/);
    assert.match(d.get('content').textContent, /root-to-commit association was verified/);
    assert.ok(d.get('content').textContent.includes(f.commit));
    assert.match(d.get('content').textContent, /not independent authentication/);
    assert.deepEqual(d.calls.slice(2).map(c => c.url.split('/').at(-1)), ['log', 'tree', 'blob', 'blob']);
    for (const call of d.calls.slice(2)) {
      assert.equal(call.fields.get('expected_commit'), f.commit); assert.equal(call.fields.get('expected_head'), f.common.snapshot_token);
      assert.equal(call.init.headers['Idempotency-Key'], undefined);
    }
    d.buttons('content').find(b => b.textContent === 'Download verified file bytes').click();
    assert.deepEqual(new Uint8Array(await d.urls.values().next().value.arrayBuffer()), f.bytes);
    d.client.disconnect(); assert.equal(d.urls.size, 0);
  });
}
test('history disclosure scope, snapshot and first-page envelope are checked before hashing', async () => {
  const f = corpus(); let digests = 0;
  const cryptoImpl = { subtle: { digest: async (...args) => { digests++; return webcrypto.subtle.digest(...args); } } };
  for (const change of [{ tenant_id: 'wrong' }, { repository_id: 'wrong' }, { repository_incarnation: 'wrong' },
    { object_format: 'sha256' }, { source_head: 'wrong' }, { ref_hex: '61' }, { source_commit: 'e'.repeat(40) },
    { snapshot_token: `alg:2:${'e'.repeat(64)}` }, { schema_version: 2 }, { read_only: false }, { transaction_created: true },
    { published: true }, { type: 'source_path_log' }, { author_identity_verified: true }, { ordering: 'other' },
    { page_complete: false }, { after: 1 }, { limit: 2 }, { total_commits: 0 }, { total_commits: 4097 },
    { total_commits: '1' }, { next_after: 1 }, { commits: [] }, { commits: [f.log().commits[0], f.log().commits[0]] }]) {
    await assert.rejects(prove(f, () => ({ ...f.log(), ...change }), { cryptoImpl }), undefined, JSON.stringify(change));
  }
  assert.equal(digests, 0); assert.equal((await prove(f, undefined, { cryptoImpl })).commit, f.commit); assert.equal(digests, 1);
});
test('original commit reference grammar rejects duplicate, missing, continued and misplaced tree headers', async () => {
  for (const transform of [
    (body, f) => Buffer.from(body.toString().replace('\nauthor', `\ntree ${f.common.root_tree}\nauthor`)),
    body => Buffer.from(body.toString().replace(/^tree [^\n]+\n/, '')),
    body => Buffer.from(body.toString().replace('\nauthor', '\n continued\nauthor')),
    body => Buffer.from('encoding utf-8\n' + body),
    body => Buffer.from(body.toString().replace('\n\n', '\n')),
    body => Buffer.from(body.toString().replace(/^tree /, 'tree 0')),
    body => Buffer.from(body.toString().replace(/^tree /, 'tree sha1:')),
  ]) {
    const f = corpus('sha1', { transform });
    await assert.rejects(prove(f), /tree|reference|headers/);
  }
  assert.equal((await prove(corpus())).rootTreeVerified, true);
});
test('parent summaries cannot disagree with hashed reference headers', async () => {
  const parent = 'a'.repeat(40), f = corpus('sha1', { parents: [parent] });
  for (const parents of [[], ['b'.repeat(40)], [parent, parent]]) {
    await assert.rejects(prove(f, () => { const log = f.log(); log.commits[0].parents = parents; return log; }), /reference headers/);
  }
  assert.equal((await prove(f)).commitVerified, true);
});
test('commit-byte ceiling has an exact permitted boundary and refuses one extra byte before hashing', async () => {
  const base = corpus(), padding = COMMIT_PROOF_LIMITS.maxCommitBytes - base.body.length;
  const exact = corpus('sha1', { body: Buffer.concat([base.body, Buffer.alloc(padding, 65)]) });
  assert.equal((await prove(exact)).commitBytes, COMMIT_PROOF_LIMITS.maxCommitBytes);
  const excessive = corpus('sha1', { body: Buffer.concat([exact.body, Buffer.from('a')]) });
  let hashes = 0;
  await assert.rejects(prove(excessive, undefined, { cryptoImpl: { subtle: { digest() { hashes++; throw new Error('unexpected'); } } } }), /encoding/);
  assert.equal(hashes, 0);
  await assert.rejects(prove(base, () => { throw new Error('must not read'); }, { cryptoImpl: {} }), /WebCrypto/);
});
test('caller and response mutation across awaits cannot switch the hashed source or summary', async () => {
  const f = corpus(), selected = { ...f.selected }, pinned = sourceBinding(f.common, f.selected), log = f.log();
  const result = await verifySourceCommit(selected, pinned, async () => {
    selected.reference = 'refs/heads/other'; pinned.tree = 'e'.repeat(40); return log;
  }, { cryptoImpl: { subtle: { digest(...args) {
    log.commits[0].parents.push('a'.repeat(40)); log.commits[0].body_hex = ''; log.commits[0].tree = 'f'.repeat(40);
    return webcrypto.subtle.digest(...args);
  } } } });
  assert.equal(result.commit, f.commit); assert.equal(result.rootTree, f.common.root_tree);
});
test('every commit verifier checkpoint can interrupt without a success receipt', async () => {
  const f = corpus(); let total = 0;
  await prove(f, undefined, { checkpoint: () => total++ }); assert.ok(total >= 8);
  for (let stop = 1; stop <= total; stop++) {
    let count = 0;
    await assert.rejects(prove(f, undefined, { checkpoint: () => { if (++count === stop) throw new Error('cancelled'); } }), /cancelled/);
    assert.equal(count, stop);
  }
});
test('unavailable history stops before tree or file reads, with no downgrade to path-only', async () => {
  const f = corpus();
  for (const status of [401, 403, 404, 409, 413, 429, 503]) {
    const d = await opened(f, [() => response({ error: 'unavailable' }, { status })]); d.verify();
    await waitFor(() => d.calls.length === 3 && d.get('status').textContent.includes(status === 401 ? 'Token rejected' : status === 403 ? 'lacks read scope' : status === 404 ? 'unavailable' : status === 409 ? 'snapshot moved' : status === 429 ? 'quota exceeded' : `HTTP ${status}`));
    assert.equal(d.calls.length, 3); assert.equal(d.urls.size, 0); assert.equal(d.get('content').textContent, '');
  }
});
test('oversized log response is rejected while streaming and never starts tree verification', async () => {
  const f = corpus(); let cancelled = false;
  const d = await opened(f, [() => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(COMMIT_PROOF_LIMITS.maxReplyBytes + 1)); }, cancel() { cancelled = true; } }), { headers: { 'Content-Type': 'application/json' } })]);
  d.verify(); await waitFor(() => /byte limit/.test(d.get('status').textContent));
  assert.equal(cancelled, true); assert.equal(d.calls.length, 3); assert.equal(d.urls.size, 0);
});
test('late commit digest cannot resurrect a cancelled result or start parent reads', async () => {
  const f = corpus(); let finish, hashes = 0;
  const cryptoImpl = { subtle: { digest(...args) { return ++hashes === 2 ? new Promise(resolve => { finish = resolve; }) : webcrypto.subtle.digest(...args); } } };
  const d = await opened(f, [f.log()], { cryptoImpl }); d.verify(); await waitFor(() => finish);
  d.client.cancel(); finish(Buffer.from(f.commit, 'hex')); await new Promise(setImmediate);
  assert.equal(d.calls.length, 3); assert.equal(d.urls.size, 0); assert.equal(d.get('content').textContent, '');
});
test('commit, directory and blob reads consume one deadline, not one allowance per stage', async t => {
  const f = corpus(); let now = performance.now(); t.mock.method(performance, 'now', () => now);
  const advance = value => () => { now += 20_000; return response(value); };
  const d = await opened(f, [advance(f.log()), advance(f.tree()), advance(f.blob())], { timeoutMs: 45_000 });
  d.verify();
  const until = Date.now() + 2000;
  while (!/timed out/.test(d.get('status').textContent)) {
    assert.ok(Date.now() < until, 'operation must settle after its virtual deadline');
    await new Promise(resolve => setTimeout(resolve, 2));
  }
  assert.match(d.get('status').textContent, /timed out/); assert.equal(d.calls.length, 5); assert.equal(d.urls.size, 0);
});
test('original blob-only and root-relative path choices do not acquire a history requirement', async () => {
  const f = corpus();
  for (const [label, reads, routes] of [
    ['Verify complete file for download', [f.blob()], ['blob']],
    ['Verify path and complete file for download', [f.tree(), f.blob()], ['tree', 'blob']],
  ]) {
    const d = await opened(f, reads); d.buttons('content').find(b => b.textContent === label).click();
    await waitFor(() => d.get('status').textContent.startsWith('Complete file verified.'));
    assert.deepEqual(d.calls.slice(2).map(c => c.url.split('/').at(-1)), routes);
    assert.doesNotMatch(d.get('content').textContent, /Commit-to-file chain verified/);
  }
});
