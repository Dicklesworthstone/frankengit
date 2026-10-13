// Complete membership + shared Transport with real Fetch/WebCrypto/HTTP. The
// peer is the existing independent native-schema fixture, not a Rust fg server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { acquireContextMembership, verifyMembershipProof, contextMembershipSelection, MEMBERSHIP_LIMITS } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-membership.mjs';
import { fixture, token, hex } from '../operator/fixtures/source_archive_native.mjs';
const clone = value => structuredClone(value);
const definitions = [
  { path: 'src/main.rs', data: Buffer.from('fn main() {}\n'), kind: 'executable' },
  { path: 'src/other.rs', data: Buffer.from('fn other() {}\n') },
  { path: 'src.c', data: Buffer.from('not selected') },
  { path: Buffer.from('80ff2e7273', 'hex'), data: Buffer.from('raw name') },
  { path: 'unrelated/deep/hidden', data: Buffer.from('must not fetch') },
  { path: 'link', kind: 'symlink', data: Buffer.from('/outside') },
  { path: 'submodule', kind: 'gitlink', target: 'c'.repeat(40) },
];
async function setup(t, format = 'sha1', defs = definitions, paths = ['src/main.rs', 'src/other.rs']) {
  const f = await fixture(t, { format, definitions: defs.map(row => row.kind === 'gitlink' ? { ...row, target: 'c'.repeat(format === 'sha1' ? 40 : 64) } : row) });
  const client = new Transport({ href: `${f.selection.endpoint}/ui/search/`, pageSuffix: '/ui/search/', cryptoImpl: webcrypto, timeoutMs: 500 });
  await client.connect(token); t.after(() => client.disconnect());
  const result = { query: { mode: 'initial' }, scope: { tenant: f.repo.scope.tenant_id, repository: f.repo.scope.repository_id,
    incarnation: f.repo.scope.repository_incarnation, format },
    pin: { commit: f.repo.commit, tree: f.repo.root.id, head: f.repo.snapshot, sourceHead: f.repo.common.source_head, rcr: 'fixture-rcr' },
    vector: { lexical: { token: 'alg:2:' + 'e'.repeat(64), number: 1 }, symbols: null },
    context: { files: paths.map(path => { const pathHex = hex(path); return { pathHex, blob: f.repo.files.get(pathHex)?.id ?? 'e'.repeat(format === 'sha1' ? 40 : 64) }; }).sort((a, b) => a.pathHex < b.pathHex ? -1 : 1) } };
  const read = (path, options) => client.request(path, options);
  return { ...f, client, result, read, expected: () => contextMembershipSelection(result, f.repo.commit),
    acquire: (limits = {}, check = () => {}) => acquireContextMembership(result, 'refs/heads/main', f.repo.commit, read, webcrypto, check, limits) };
}
for (const format of ['sha1', 'sha256']) {
  test(`commit-bound sparse parent acquisition and offline replay ${format}`, async t => {
    const f = await setup(t, format); const original = clone(f.result), answer = await f.acquire();
    assert.deepEqual(f.result, original); assert.equal(answer.requests, 3);
    assert.deepEqual(f.calls.map(c => [c.operation, c.form.get('path_hex')]), [['log', null], ['tree', null], ['tree', hex('src')]]);
    for (const call of f.calls) {
      assert.equal(call.method, 'POST'); assert.equal(call.headers.authorization, `Bearer ${token}`);
      assert.equal(call.headers['idempotency-key'], undefined); assert.equal(call.form.get('expected_commit'), f.repo.commit);
      assert.equal(call.form.get('expected_head'), f.repo.snapshot);
    }
    assert.equal(answer.verified.commitMembershipVerified, true); assert.equal(answer.verified.blobBytesVerified, false);
    for (const name of ['authorityVerified', 'freshnessVerified', 'searchCoverageVerified', 'signatureVerified']) assert.equal(answer.verified[name], false);
    assert.deepEqual(answer.proof.files.map(file => file.kind), ['executable', 'file']);
    const saved = JSON.stringify(answer.proof); assert.equal(saved.includes(token), false);
    f.client.disconnect(); const checked = await verifyMembershipProof(JSON.parse(saved), f.expected(), webcrypto);
    assert.deepEqual(checked, answer.verified); assert.equal(f.calls.length, 3);
  });
  test(`raw path, empty file and native Git directory ordering ${format}`, async t => {
    const f = await setup(t, format, [...definitions, { path: 'src/empty', data: Buffer.alloc(0) }], [Buffer.from('80ff2e7273', 'hex'), 'src/empty']);
    const answer = await f.acquire(); const dir = mkdtempSync(join(tmpdir(), 'fg-membership-git-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
    const git = (args, input) => { const r = spawnSync('git', args, { cwd: dir, input, env: { PATH: process.env.PATH,
      HOME: dir, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LANG: 'C' } }); assert.equal(r.status, 0, r.stderr.toString()); return r.stdout.toString().trim(); };
    git(['init', '--bare', `--object-format=${format}`]);
    const types = { directory: ['040000', 'tree'], file: ['100644', 'blob'], executable: ['100755', 'blob'], symlink: ['120000', 'blob'], gitlink: ['160000', 'commit'] };
    for (const parent of answer.proof.trees) {
      const actual = f.repo.dirs.get(parent.pathHex);
      const input = Buffer.concat([...actual.children.values()].reverse().map(row => Buffer.concat([
        Buffer.from(`${types[row.kind].join(' ')} ${row.id}\t`), row.name, Buffer.from([0])])));
      assert.equal(git(['mktree', '--missing', '-z'], input), parent.oid);
      assert.equal(parent.bodyHex, hex(actual.body));
    }
    assert.equal(git(['hash-object', '-t', 'commit', '--stdin'], f.repo.body), answer.proof.commit.oid);
    assert.equal(answer.proof.files.length, 2); assert.equal(f.calls.some(c => c.operation === 'blob'), false);
  });
  test(`exact tree limits pass and one-under limits refuse ${format}`, async t => {
    const f = await setup(t, format); const first = await f.acquire();
    const limits = { maxTrees: first.verified.trees, maxEntries: first.verified.entries, maxTreeBytes: first.verified.treeBytes, maxRequests: first.requests };
    assert.equal((await f.acquire(limits)).verified.commitMembershipVerified, true);
    for (const name of Object.keys(limits)) await assert.rejects(f.acquire({ ...limits, [name]: limits[name] - 1 }));
    assert.equal((await verifyMembershipProof(first.proof, f.expected(), webcrypto, () => {}, limits)).treeBytes, limits.maxTreeBytes);
  });
  test(`all parent pages, never a hash-valid successful prefix ${format}`, async t => {
    const rows = Array.from({ length: 101 }, (_, i) => ({ path: `s/${String(i).padStart(3, '0')}`, data: Buffer.from('x') }));
    const f = await setup(t, format, rows, ['s/100']); const answer = await f.acquire();
    assert.equal(answer.requests, 4); assert.equal(answer.verified.entries, 102);
    const last = f.calls.at(-1); assert.equal(last.form.get('after_hex'), hex('099'));
    await assert.rejects(f.acquire({ maxRequests: 3 }), /request budget/);
    f.control.mutate = (value, call) => { if (call.operation === 'tree' && call.form.get('path_hex') === hex('s')) value.next_after_hex = null; };
    await assert.rejects(f.acquire(), /reconstruct/);
  });
  test(`same tree ID under two needed directories keeps both memberships ${format}`, async t => {
    const f = await setup(t, format, [{ path: 'a/x', data: Buffer.from('x') }, { path: 'b/x', data: Buffer.from('x') }], ['a/x', 'b/x']);
    const answer = await f.acquire(); assert.equal(answer.proof.trees[1].oid, answer.proof.trees[2].oid);
    assert.equal(answer.verified.trees, 3); assert.equal(answer.proof.files.length, 2);
  });
  test(`a matching blob at another path does not prove selected membership ${format}`, async t => {
    const f = await setup(t, format); f.result.context.files[0].pathHex = hex('src/missing.rs');
    f.result.context.files.sort((a, b) => a.pathHex < b.pathHex ? -1 : 1);
    await assert.rejects(f.acquire(), /missing selected/);
  });
  test(`selected symlinks do not acquire regular-file or ancestor authority ${format}`, async t => {
    const f = await setup(t, format, definitions, ['link']); await assert.rejects(f.acquire(), /does not bind/);
    f.result.context.files[0].pathHex = hex('link/child'); await assert.rejects(f.acquire(), /ancestor/);
    assert.equal(f.calls.some(c => c.operation === 'blob'), false);
  });
}
for (const [label, change] of [
  ['independent commit', f => { f.repo.commit = '1'.repeat(40); }],
  ['empty selection', f => { f.result.context.files = []; }],
  ['duplicate path', f => { f.result.context.files.push(clone(f.result.context.files[0])); }],
  ['over 32 files', f => { f.result.context.files = Array(33).fill(f.result.context.files[0]); }],
  ['unsafe path', f => { f.result.context.files[0].pathHex = hex('../other'); }],
  ['hash domain', f => { f.result.context.files[0].blob = 'sha256:' + 'a'.repeat(64); }],
  ['zero identity', f => { f.result.context.files[0].blob = '0'.repeat(40); }],
  ['file/ancestor overlap', f => { f.result.context.files = [{ pathHex: hex('src'), blob: '1'.repeat(40) }, f.result.context.files[0]]; }],
]) test(`pre-I/O refusal: ${label}`, async t => { const f = await setup(t); change(f); await assert.rejects(f.acquire()); assert.equal(f.calls.length, 0); });
for (const [label, change] of [
  ['commit body', (r, c) => { if (c.operation === 'log') r.commits[0].body_hex += '20'; }],
  ['commit summary', (r, c) => { if (c.operation === 'log') r.commits[0].tree = 'a'.repeat(40); }],
  ['parent summary', (r, c) => { if (c.operation === 'log') r.commits[0].parents = ['a'.repeat(40)]; }],
  ['log page', (r, c) => { if (c.operation === 'log') r.page_complete = false; }],
  ['source scope', r => { r.repository_incarnation = '4'.repeat(32); }],
  ['source head', r => { r.snapshot_token = 'alg:2:' + 'e'.repeat(64); }],
  ['source read flag', r => { r.published = true; }],
  ['tree root', (r, c) => { if (c.operation === 'tree') r.root_tree = 'a'.repeat(40); }],
  ['source record', (r, c) => { if (c.operation === 'tree') r.source_rcr = 'changed'; }],
  ['sibling omitted', (r, c) => { if (c.operation === 'tree' && r.path_hex === null) r.entries.pop(); }],
  ['tree mode', (r, c) => { if (c.operation === 'tree') r.entries[0].kind = 'executable'; }],
  ['unknown mode', (r, c) => { if (c.operation === 'tree') r.entries[0].kind = 'device'; }],
  ['entry identity', (r, c) => { if (c.operation === 'tree') r.entries[0].object_id = 'b'.repeat(40); }],
  ['duplicate name', (r, c) => { if (c.operation === 'tree') r.entries.push(r.entries[0]); }],
  ['reordered page', (r, c) => { if (c.operation === 'tree') r.entries.reverse(); }],
  ['fake continuation', (r, c) => { if (c.operation === 'tree') r.next_after_hex = r.entries.at(-1).name_hex; }],
  ['non-immediate name', (r, c) => { if (c.operation === 'tree') r.entries[0].name_hex = hex('outside/file'); }],
]) test(`native reply refusal: ${label}`, async t => { const f = await setup(t); f.control.mutate = change; await assert.rejects(f.acquire()); assert.equal(f.calls.some(c => c.operation === 'blob'), false); });
for (const [label, change] of [
  ['wrong independent root', (p, e) => { e.commit = '1'.repeat(40); }],
  ['wrong independent path', (p, e) => { e.files[0].pathHex = hex('src/fake.rs'); }],
  ['wrong independent blob', (p, e) => { e.files[0].blob = '1'.repeat(40); }],
  ['hash-qualified wrong domain', p => { p.commit.oid = 'sha256:' + 'a'.repeat(64); }],
  ['missing parent', p => { p.trees.pop(); }],
  ['extra parent', p => { p.trees.push(clone(p.trees[0])); }],
  ['detached parent', p => { p.trees[1].pathHex = hex('other'); }],
  ['tree body changed', p => { p.trees[1].bodyHex += '00'; }],
  ['commit body changed', p => { p.commit.bodyHex += '00'; }],
  ['file kind changed', p => { p.files[0].kind = 'file'; }],
  ['proof unknown fields', p => { p.grant = 'admin'; }],
  ['over-limit tree bytes', p => { p.trees[0].bodyHex = '00'.repeat(MEMBERSHIP_LIMITS.maxTreeBytes + 1); }],
]) test(`offline proof rejects ${label}`, async t => {
  const f = await setup(t), answer = await f.acquire(), expected = f.expected(); change(answer.proof, expected);
  await assert.rejects(verifyMembershipProof(answer.proof, expected, webcrypto)); assert.equal(f.calls.length, 3);
});
test('offline verifier owns every byte and expected selection before WebCrypto yields', async t => {
  const f = await setup(t), answer = await f.acquire(), expected = f.expected();
  const checked = verifyMembershipProof(answer.proof, expected, { subtle: { digest: async (...args) => {
    answer.proof.trees = []; answer.proof.files[0].kind = 'symlink'; expected.commit = '1'.repeat(40); expected.files[0].blob = '2'.repeat(40);
    return webcrypto.subtle.digest(...args);
  } } });
  assert.equal((await checked).commit, f.repo.commit);
});
test('cancelled metadata read cannot progress to another parent', async t => {
  const f = await setup(t); let arrived; const ready = new Promise(resolve => { arrived = resolve; });
  f.control.respond = () => { arrived(); };
  const waiting = f.acquire(); await ready; f.client.cancelReads(); await assert.rejects(waiting);
  assert.equal(f.calls.length, 1);
});
test('transport timeout cannot leave a successful or retried proof', async t => {
  const f = await setup(t); f.control.respond = () => {};
  await assert.rejects(f.acquire()); assert.equal(f.calls.length, 1);
});
for (const [label, options] of [
  ['GET', { method: 'GET', body: undefined }], ['key', { key: 'mutation' }], ['write lifecycle', { read: false }],
  ['binary', { binary: true }], ['alternative success', { statuses: [200, 409] }],
]) test(`membership metadata keeps closed search envelope: ${label}`, async t => {
  const f = await setup(t); for (const path of ['source/log', 'source/tree']) await assert.rejects(f.client.request(path, { method: 'POST', body: 'x=1', ...options }));
  assert.equal(f.calls.length, 0);
});
test('metadata support does not admit writes, arbitrary objects or other profiles', async t => {
  const f = await setup(t);
  for (const path of ['source/apply', 'outcomes', 'source/object', 'source/tree?path=x', 'source/log/../apply']) {
    await assert.rejects(f.client.request(path, { method: 'POST', body: 'x=1' }));
  }
  const other = new Transport({ href: `${f.selection.endpoint}/ui/pulls/`, cryptoImpl: webcrypto }); await other.connect(token); t.after(() => other.disconnect());
  await assert.rejects(other.request('source/log', { method: 'POST', body: 'x=1' })); assert.equal(f.calls.length, 0);
});
