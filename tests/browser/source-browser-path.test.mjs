// Production verifier/controller execution with native wire fixtures. Tree bodies
// are independently encoded below; no live fg or authority-signature claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyDirectory, verifyBlobPath, sourceBinding, mount, PATH_PROOF_LIMITS }
  from '../../crates/fgit-node/src/smart_http/server/browser/browser.mjs';
import { fixture, hex, webcrypto, response, PAGE, dom, location, waitFor, queuedFetch }
  from './source-browser-fixtures.mjs';

const modes = { file: '100644', executable: '100755', directory: '40000', symlink: '120000', gitlink: '160000' };
const row = (name, kind, object_id) => ({ name_hex: hex(Buffer.from(name)), kind, object_id });
function nativeTree(format, entries, overrides = {}) {
  const ordered = entries.map(entry => ({ ...entry, name: Buffer.from(entry.name_hex, 'hex') }));
  ordered.sort((a, b) => Buffer.compare(
    Buffer.concat([a.name, Buffer.from(a.kind === 'directory' ? '/' : '\0')]),
    Buffer.concat([b.name, Buffer.from(b.kind === 'directory' ? '/' : '\0')])));
  const body = Buffer.concat(ordered.map(entry => Buffer.concat([
    Buffer.from((overrides[entry.name_hex] ?? modes[entry.kind]) + ' '), entry.name, Buffer.from([0]),
    Buffer.from(entry.object_id.replace(/^(sha1|sha256):/, ''), 'hex'),
  ])));
  const id = createHash(format).update(`tree ${body.length}\0`).update(body).digest('hex');
  return { id, bytes: body.length, body, entries: entries.map(e => ({ ...e })) };
}
function corpus(format = 'sha1', { nested = true, extra = 0, kind = 'file', binary = false } = {}) {
  const parent = binary ? Buffer.from([0xa2, 0xf0]) : Buffer.from('src');
  const name = binary ? Buffer.from([0xff, 0x61]) : Buffer.from('a.txt');
  const path = nested ? Buffer.concat([parent, Buffer.from('/'), name]) : name;
  const f = fixture(format, Buffer.from('exact file bytes\n'), kind, path);
  const target = row(name, kind, f.oid);
  const fillers = Array.from({ length: extra }, (_, i) => row(`z${String(i).padStart(4, '0')}`, 'file', f.oid));
  const leaf = nativeTree(format, [target, ...fillers]);
  const root = nested ? nativeTree(format, [row(parent, 'directory', leaf.id)]) : leaf;
  f.common.root_tree = root.id;
  const trees = new Map([['', root], ...(nested ? [[hex(parent), leaf]] : [])]);
  function page(fields) {
    assert.equal(fields.object_format, format); assert.equal(fields.ref, f.selected.reference);
    const path = fields.path_hex ?? '', tree = trees.get(path);
    assert.ok(tree, `unexpected tree path ${path}`);
    const after = fields.after_hex ?? null;
    const available = tree.entries.slice().sort((a, b) => Buffer.compare(Buffer.from(a.name_hex, 'hex'), Buffer.from(b.name_hex, 'hex')))
      .filter(e => after === null || e.name_hex > after);
    const entries = available.slice(0, 100).map(e => ({ ...e }));
    return { ...f.common, type: 'source_tree', object_id: tree.id, path_hex: path || null,
      after_hex: after, limit: 100, entries, next_after_hex: available.length > 100 ? entries.at(-1).name_hex : null };
  }
  return { ...f, root, leaf, trees, page, target, parent: hex(parent) };
}
const expected = f => ({ id: f.oid, kind: f.target.kind });
const proof = (f, read = fields => f.page(fields), options = {}) => verifyBlobPath(
  f.selected, sourceBinding(f.common, f.selected), f.path, expected(f), read, { cryptoImpl: webcrypto, ...options });
async function opened(f, extra, options = {}) {
  const d = dom(), calls = []; d.get('format').value = f.format;
  const client = mount(d.document, location, queuedFetch([
    f.page({ ...f.selected, object_format: f.format, ref: f.selected.reference }),
    ...(f.trees.size > 1 ? [f.page({ object_format: f.format, ref: f.selected.reference, path_hex: f.parent })] : []),
    f.blob(), ...extra,
  ], calls), { cryptoImpl: webcrypto, urlApi: d.urlApi, ...options });
  d.get('token').value = 'a'.repeat(64); d.get('connection').emit('submit');
  await waitFor(() => /Read complete/.test(d.get('status').textContent));
  d.buttons('content')[0].click();
  if (f.trees.size > 1) {
    await waitFor(() => /Read complete/.test(d.get('status').textContent) && calls.length === 2);
    d.buttons('content')[0].click();
  }
  await waitFor(() => d.buttons('content').some(b => b.textContent === 'Verify path and complete file for download'));
  return { ...d, calls, client, verify: () => d.buttons('content').find(b => b.textContent === 'Verify path and complete file for download').click() };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: canonical directory hashing handles all modes and native slash ordering`, async () => {
    const width = format === 'sha1' ? 40 : 64;
    const entries = [row('foo', 'directory', '1'.repeat(width)), row('foo.bar', 'file', '2'.repeat(width)),
      row('foo0', 'executable', '3'.repeat(width)), row('link', 'symlink', '4'.repeat(width)), row('sub', 'gitlink', '5'.repeat(width)),
      row(Buffer.from([0xa2, 0xf0, 0xff]), 'file', '6'.repeat(width))];
    const tree = nativeTree(format, entries);
    // Independently observed with installed Git 2.47.3: mktree -z --missing.
    // Fixed regression vectors, not a pinned-oracle or live-native-server claim.
    assert.equal(tree.id, format === 'sha1' ? '5d170300b2852e5dde78028cf7048d2650a991ba'
      : '2113b0a9ec15499604164b8dc4f5feeebe1d06b9d84d4a3a9ce95c0f381c0f28');
    const result = await verifyDirectory(entries.toReversed(), format, tree.id, webcrypto);
    assert.deepEqual(result, { id: tree.id, bytes: tree.bytes, entries: entries.length });
    const empty = nativeTree(format, []);
    if (format === 'sha1') assert.equal(empty.id, '4b825dc642cb6eb9a060e54bf8d69288fbee4904');
    assert.equal((await verifyDirectory([], format, empty.id, webcrypto)).entries, 0);
  });
  test(`${format}: every parent is verified before the native file and kind are accepted`, async () => {
    const f = corpus(format), calls = [];
    const result = await proof(f, fields => { calls.push(fields); return f.page(fields); });
    assert.equal(result.pathVerified, true); assert.equal(result.authorityVerified, false);
    assert.equal(result.rootTree, f.root.id); assert.equal(result.id, f.oid);
    assert.equal(result.directories, 2); assert.equal(result.pages, 2); assert.equal(result.entries, 2);
    assert.equal(result.bytes, f.root.bytes + f.leaf.bytes);
    assert.deepEqual(calls.map(c => c.path_hex ?? null), [null, f.parent]);
    for (const fields of calls) { assert.equal(fields.expected_head, f.common.snapshot_token); assert.equal(fields.expected_commit, f.common.source_commit); }
  });
  test(`${format}: all directory pages are needed even when the wanted child is on page one`, async () => {
    const f = corpus(format, { extra: 101 }), calls = [];
    const result = await proof(f, fields => { calls.push(fields); return f.page(fields); });
    assert.equal(result.pages, 3); assert.equal(result.entries, 103);
    assert.equal(calls[2].after_hex, hex(Buffer.from('z0098')));
    await assert.rejects(proof(f, fields => {
      const page = f.page(fields);
      if (fields.path_hex && !fields.after_hex) page.next_after_hex = null;
      return page;
    }), /does not reproduce/);
  });
  test(`${format}: raw path components are split on byte slashes, not unaligned hex digits`, async () => {
    const f = corpus(format, { binary: true });
    assert.ok(f.parent.includes('2f')); // a2 f0 is not a slash byte.
    assert.equal((await proof(f)).path, f.path);
  });
  test(`${format}: actual controls verify both nested inclusion and full bytes before download`, async () => {
    const f = corpus(format);
    const treeRead = (_url, init) => response(f.page(Object.fromEntries(new URLSearchParams(init.body))));
    const d = await opened(f, [treeRead, treeRead, f.blob()]);
    d.verify(); assert.equal(d.urls.size, 0);
    await waitFor(() => d.get('status').textContent.startsWith('Complete file verified.'));
    assert.match(d.get('content').textContent, /Path inclusion verified/);
    assert.ok(d.get('content').textContent.includes(f.root.id));
    assert.match(d.get('content').textContent, /root-to-commit association and authority remain server claims/);
    d.buttons('content').find(b => b.textContent === 'Download verified file bytes').click();
    assert.deepEqual(new Uint8Array(await d.urls.values().next().value.arrayBuffer()), f.bytes);
    assert.deepEqual(d.calls.slice(3).map(c => c.url.split('/').at(-1)), ['tree', 'tree', 'blob']);
    for (const c of d.calls.slice(3)) assert.equal(c.fields.get('expected_head'), f.common.snapshot_token);
    d.client.disconnect(); assert.equal(d.urls.size, 0);
  });
}
test('duplicate names, unsupported modes, missing crypto and excessive input never verify', async () => {
  const f = corpus('sha1', { nested: false });
  for (const entry of [{ ...f.target, kind: 'constructor' }, { ...f.target, name_hex: '2e2e' },
    { ...f.target, name_hex: '612f62' }, { ...f.target, object_id: '0'.repeat(40) }]) {
    await assert.rejects(verifyDirectory([entry], 'sha1', f.root.id, webcrypto));
  }
  await assert.rejects(verifyDirectory([f.target, f.target], 'sha1', f.root.id, webcrypto), /Duplicate/);
  await assert.rejects(verifyDirectory([], 'sha1', f.root.id, {}), /WebCrypto/);
  await assert.rejects(verifyDirectory(Array(PATH_PROOF_LIMITS.maxEntries + 1).fill(f.target), 'sha1', f.root.id, webcrypto), /entry budget/);
  const long = Array.from({ length: 1030 }, (_, i) => row(`${String(i).padStart(4, '0')}${'a'.repeat(4090)}`, 'file', f.oid));
  await assert.rejects(verifyDirectory(long, 'sha1', f.root.id, webcrypto), /byte budget/);
});
test('legacy directory spelling is refused rather than normalized into a native proof', async () => {
  const f = corpus();
  const legacy = nativeTree('sha1', f.root.entries, { [f.parent]: '040000' });
  assert.notEqual(legacy.id, f.root.id);
  await assert.rejects(verifyDirectory(legacy.entries, 'sha1', legacy.id, webcrypto), /unsupported original modes/);
  assert.equal((await verifyDirectory(f.root.entries, 'sha1', f.root.id, webcrypto)).id, f.root.id);
});
test('changed rows, omitted siblings, wrong selected root and file-kind substitution fail hashes', async () => {
  const f = corpus('sha1', { extra: 2 });
  for (const mutate of [
    page => { page.entries[0].object_id = 'f'.repeat(40); },
    page => { page.entries[0].kind = 'symlink'; },
    page => { page.entries[0].name_hex = hex(Buffer.from('renamed')); },
    page => { page.entries.pop(); },
  ]) await assert.rejects(proof(f, fields => { const page = f.page(fields); if (fields.path_hex) mutate(page); return page; }));
  await assert.rejects(verifyBlobPath(f.selected, { ...sourceBinding(f.common, f.selected), tree: 'd'.repeat(40) }, f.path,
    expected(f), fields => f.page(fields), { cryptoImpl: webcrypto }), /changed/);
  await assert.rejects(verifyBlobPath(f.selected, sourceBinding(f.common, f.selected), f.path,
    { ...expected(f), kind: 'executable' }, fields => f.page(fields), { cryptoImpl: webcrypto }), /not the verified tree entry/);
  await assert.rejects(verifyBlobPath(f.selected, sourceBinding(f.common, f.selected), f.path,
    { ...expected(f), id: 'e'.repeat(40) }, fields => f.page(fields), { cryptoImpl: webcrypto }), /not the verified tree entry/);
});
test('the complete source tuple and continuation envelope remain pinned on later pages', async () => {
  const f = corpus('sha256', { extra: 101 });
  for (const change of [{ tenant_id: 'other' }, { repository_id: 'other' }, { repository_incarnation: 'other' },
    { source_head: 'other' }, { source_rcr: 'other' }, { source_commit: 'd'.repeat(64) }, { root_tree: 'e'.repeat(64) },
    { ref: 'refs/heads/other' }, { ref_hex: '61' }, { snapshot_token: `alg:2:${'d'.repeat(64)}` },
    { read_only: false }, { transaction_created: true }, { published: true }, { path_hex: null },
    { object_id: 'e'.repeat(64) }, { after_hex: null }, { limit: 99 }, { next_after_hex: '61' }]) {
    await assert.rejects(proof(f, fields => ({ ...f.page(fields), ...(fields.after_hex ? change : {}) })), undefined, JSON.stringify(change));
  }
  for (const mutate of [
    page => { page.entries.reverse(); }, page => { page.entries[1] = page.entries[0]; },
    page => { page.next_after_hex = page.entries[0].name_hex; }, page => { page.entries.pop(); },
  ]) await assert.rejects(proof(f, fields => { const page = f.page(fields); if (fields.path_hex && !fields.after_hex) mutate(page); return page; }));
});
test('a valid hash cannot turn symlink targets, regular files or gitlinks into directories', async () => {
  for (const kind of ['file', 'symlink', 'gitlink']) {
    const f = corpus(); const root = nativeTree('sha1', [row(Buffer.from(f.parent, 'hex'), kind, f.oid)]);
    f.common.root_tree = root.id; f.trees.set('', root);
    let reads = 0;
    await assert.rejects(proof(f, fields => { reads++; return f.page(fields); }), /never traverses/);
    assert.equal(reads, 1);
  }
  for (const kind of ['executable', 'symlink']) {
    const f = corpus('sha256', { kind }); assert.equal((await proof(f)).kind, kind);
  }
});
test('missing paths are absence in a verified directory, not a fabricated blob grant', async () => {
  const f = corpus('sha1', { nested: false });
  await assert.rejects(verifyBlobPath(f.selected, sourceBinding(f.common, f.selected), hex(Buffer.from('missing')),
    expected(f), fields => f.page(fields), { cryptoImpl: webcrypto }), /absent from the verified directory/);
});
test('page, entry and native-byte budgets are cumulative across the entire ancestry', async () => {
  const f = corpus('sha256'), exact = { maxPages: 2, maxEntries: 2, maxBytes: f.root.bytes + f.leaf.bytes };
  assert.equal((await proof(f, undefined, { limits: exact })).bytes, exact.maxBytes);
  for (const [key, pattern] of [['maxPages', /page budget/], ['maxEntries', /entry budget/], ['maxBytes', /byte budget/]]) {
    let reads = 0;
    await assert.rejects(proof(f, fields => { reads++; return f.page(fields); }, { limits: { ...exact, [key]: exact[key] - 1 } }), pattern);
    assert.equal(reads, key === 'maxPages' ? 1 : 2);
  }
  for (const limits of [{ maxPages: 129 }, { maxEntries: 12801 }, { maxBytes: 4 * 1024 * 1024 + 1 },
    { maxPages: 0 }, { maxBytes: NaN }, { maxEntries: '10' }, { unknown: 1 }, null]) {
    await assert.rejects(proof(f, () => { throw new Error('should not read'); }, { limits }), /budget|bounded/);
  }
});
test('source and requested file are copied before the first asynchronous read', async () => {
  const f = corpus(), selected = { ...f.selected }, source = sourceBinding(f.common, f.selected), wanted = expected(f), calls = [];
  const result = await verifyBlobPath(selected, source, f.path, wanted, async fields => {
    calls.push(fields); selected.reference = 'refs/heads/other'; source.tree = 'e'.repeat(40); wanted.id = 'f'.repeat(40);
    return f.page(fields);
  }, { cryptoImpl: webcrypto });
  assert.equal(result.id, f.oid); assert.equal(calls.length, 2);
  for (const fields of calls) assert.equal(fields.ref, f.selected.reference);
});
test('every checkpoint, including native tree digests, can cancel without producing a proof', async () => {
  const f = corpus(); let total = 0;
  await proof(f, undefined, { checkpoint: () => { total++; } });
  assert.ok(total > 10);
  for (let at = 1; at <= total; at++) {
    let count = 0;
    await assert.rejects(proof(f, undefined, { checkpoint: () => { if (++count === at) throw new Error('cancelled'); } }), /cancelled/);
    assert.equal(count, at);
  }
});
test('failed parent reads never fall back to blob-only downloads', async () => {
  const f = corpus('sha1', { nested: false });
  for (const status of [401, 403, 404, 409, 413, 503]) {
    const d = await opened(f, [() => response({ error: 'refused' }, { status })]); d.verify();
    await waitFor(() => d.calls.length === 3 && !d.get('status').textContent.startsWith('Verifying'));
    assert.equal(d.calls.length, 3); assert.equal(d.urls.size, 0); assert.equal(d.get('content').textContent, '');
  }
});
test('a cancelled pending tree digest cannot enable a late download', async () => {
  const f = corpus('sha1', { nested: false }); let finish, digests = 0;
  const cryptoImpl = { subtle: { digest(...args) {
    if (++digests === 2) return new Promise(resolve => { finish = resolve; });
    return webcrypto.subtle.digest(...args);
  } } };
  const d = await opened(f, [(_url, init) => response(f.page(Object.fromEntries(new URLSearchParams(init.body))))], { cryptoImpl });
  d.verify(); await waitFor(() => finish); d.client.cancel(); finish(Buffer.from(f.root.id, 'hex'));
  await new Promise(setImmediate);
  assert.equal(d.calls.length, 3); assert.equal(d.get('content').textContent, ''); assert.equal(d.urls.size, 0);
  assert.match(d.get('status').textContent, /canceled/);
});
test('directory proof and complete-file fetch share one operation deadline', async t => {
  const f = corpus('sha1', { nested: false }); let now = performance.now();
  t.mock.method(performance, 'now', () => now);
  const d = await opened(f, [(_url, init) => { now += 30_000; return response(f.page(Object.fromEntries(new URLSearchParams(init.body)))); },
    () => { now += 30_000; return response(f.blob()); }], { timeoutMs: 45_000 });
  d.verify();
  for (let turn = 0; turn < 100 && !/timed out/.test(d.get('status').textContent); turn++) await new Promise(setImmediate);
  assert.match(d.get('status').textContent, /timed out/); assert.equal(d.calls.length, 4);
  assert.equal(d.get('content').textContent, ''); assert.equal(d.urls.size, 0);
});
