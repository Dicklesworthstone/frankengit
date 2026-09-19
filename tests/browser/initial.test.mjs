import test from 'node:test';
import assert from 'node:assert/strict';
import { InitialSourceClient } from '../../crates/fgit-node/src/smart_http/server/browser/initial.mjs';
import { initialPlan, verifyInitial, initialFields, initialEnvelope } from '../../crates/fgit-node/src/smart_http/server/browser/initial-plan.mjs';
import { Transport, utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fixture, file, fields, metadata, crypto, token, href, envelope } from './initial-fixtures.mjs';
const connected = async f => { const c = new InitialSourceClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl }); await c.connect(token); return c; };
const staged = async f => { const c = await connected(f); await c.prepare(f.fields, f.files, metadata); await c.stageApply(); return c; };
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: bootstrap needs no existing branch or synthetic parent, and staging sends no mutation`, async () => {
    const f = await fixture(algorithm, [file('z', ''), file('dir/a', 'x', 0o100755), file('dir.c', 'same'), file('dir/b', 'same')]);
    const c = await connected(f), a = await c.prepare(f.fields, f.files, metadata);
    assert.equal(a.fields.expected_absent, true); assert.deepEqual(a.preparation.parents, []);
    assert.equal(a.preparation.candidate_commit, f.plan.commit); assert.equal(a.preparation.root_tree, f.plan.tree);
    assert.equal(a.preparation.object_count, 6); // 3 unique blobs, 2 trees, 1 commit.
    await c.stageApply(); assert.deepEqual(f.calls.map(c => c.endpoint), ['source/initial/prepare']);
    const old = c.pending; old.fields.expected_absent = false; assert.equal(c.pending.fields.expected_absent, true);
    const sent = await c.send(); assert.equal(sent.outcome, 'committed'); assert.equal(c.pending, null);
    assert.equal(c.candidate, null); assert.equal(sent.defaultBranchChanged, false);
    const body = new TextDecoder().decode(f.calls.at(-1).body);
    assert.match(body, /expected_absent=true/); assert.doesNotMatch(body, /expected_commit|expected_head|parent/);
  });
  for (const [name, corrupt] of [
    ['tree', r => { r.root_tree = 'a'.repeat(algorithm === 'sha1' ? 40 : 64); }],
    ['commit metadata', r => { r.candidate_commit_body_hex += '0a'; }],
    ['parent', r => { r.parents.push('a'.repeat(40)); }],
    ['prerequisite', r => { r.prerequisites.push('hidden-history'); }],
    ['path', r => { r.files[0].path_hex = 'ff'; }],
    ['mode', r => { r.files[0].mode = 0o100755; }],
    ['blob bytes', r => { r.files[0].bytes++; }],
    ['blob identity', r => { r.files[0].blob = 'a'.repeat(algorithm === 'sha1' ? 40 : 64); }],
    ['object count', r => { r.object_count++; }],
    ['missing file', r => { r.files.pop(); }],
    ['extra file', r => { r.files.push(structuredClone(r.files[0])); }],
    ['patch digest', r => { r.patch_sha256 = '0'.repeat(64); }],
    ['bundle digest', r => { r.bundle.sha256 = '0'.repeat(64); }],
    ['bundle length', r => { r.bundle.bytes++; }],
    ['branch', r => { r.ref = 'refs/heads/other'; r.ref_hex = hex(utf8.encode(r.ref)); }],
    ['format', r => { r.object_format = algorithm === 'sha1' ? 'sha256' : 'sha1'; }],
    ['absence', r => { r.expected_absent = false; }],
    ['publication', r => { r.published = true; }],
    ['staging', r => { r.objects_staged = true; }],
    ['default branch', r => { r.default_branch_changed = true; }],
  ]) test(`${algorithm}: changed ${name} cannot produce an initial candidate`, async () => {
    const f = await fixture(algorithm), c = await connected(f); f.config.prepare = corrupt;
    await assert.rejects(c.prepare(f.fields, f.files, metadata)); assert.equal(c.candidate, null); assert.equal(c.pending, null);
    assert.equal(f.calls.length, 1);
  });
  test(`${algorithm}: lost response retries exact bytes without rechecking branch absence`, async () => {
    const f = await fixture(algorithm), c = await staged(f); f.config.lose = true;
    await assert.rejects(c.send(), e => e.outcomeUnknown === true); const p = c.pending, first = f.calls.at(-1);
    assert.throws(() => c.discardUnsent()); await assert.rejects(c.prepare(f.fields, f.files, metadata));
    c.disconnect(); await assert.rejects(c.connect('8'.repeat(64))); await c.connect(token);
    f.config.lose = false; assert.equal((await c.send()).outcome, 'committed');
    assert.deepEqual(f.calls.at(-1).body, first.body); assert.equal(f.calls.at(-1).headers['idempotency-key'], p.key);
    assert.deepEqual(f.calls.map(c => c.endpoint), ['source/initial/prepare', 'source/initial/apply', 'source/initial/apply']);
  });
}
test('native root plan copies caller bytes before asynchronous work and is independent of file order', async () => {
  const files = [file('b', 'x'), file('a', 'y')], original = structuredClone(files);
  const work = initialPlan(files, metadata, 'sha1', crypto); files[0].bytes[0] = 123; files.reverse();
  const a = await work, b = await initialPlan(original.reverse(), metadata, 'sha1', crypto);
  assert.equal(a.commit, b.commit); assert.deepEqual(a.files, b.files); assert.deepEqual(a.patch, b.patch);
});
for (const [name, files] of [
  ['empty', []], ['duplicate', [file(), file()]], ['overlap', [file('a'), file('a/b')]],
  ['nonadjacent overlap', [file('a'), file('a-'), file('a/b')]], ['dotgit', [file('a/.GiT/config')]],
  ['traversal', [file('../x')]], ['symlink', [file('x', 'y', 0o120000)]],
  ['NUL content', [file('x', '\0')]], ['too large', [file('x', 'x'.repeat(256 * 1024 + 1))]],
]) test(`invalid initial files (${name}) refuse before network work`, async () => {
  const f = await fixture(), c = await connected(f); await assert.rejects(c.prepare(f.fields, files, metadata)); assert.equal(f.calls.length, 0);
});
test('absence, branch scope and preparation-only snapshot are explicit and cannot become an update', () => {
  for (const bad of [{ ...fields('sha1'), expected_absent: false }, { ...fields('sha1'), expected_absent: 'true' },
    { ...fields('sha1'), expected_commit: 'a'.repeat(40) }, { ...fields('sha1'), ref: 'refs/tags/v1' }]) assert.throws(() => initialFields(bad));
  assert.throws(() => initialFields({ ...fields('sha1'), candidate_commit: 'a'.repeat(40), expected_head: `alg:1:${'a'.repeat(64)}` }, true));
});
test('snapshot mismatch and scope replacement leave no candidate', async () => {
  const f = await fixture(), c = await connected(f);
  await assert.rejects(c.prepare({ ...f.fields, expected_head: `alg:1:${'6'.repeat(64)}` }, f.files, metadata));
  await c.prepare(f.fields, f.files, metadata); f.config.prepare = r => { r.repository_incarnation = 'changed-incarnation'; };
  await assert.rejects(c.prepare(f.fields, f.files, metadata)); assert.equal(c.candidate, null);
});
test('truncated or ambiguous multipart initial artifacts cannot yield usable bundles', async () => {
  const f = await fixture(), r = envelope(f.prepared, f.bundle, f.sha);
  for (const end of [0, 1, 128, r.value.length - 1]) assert.throws(() => initialEnvelope({ ...r, value: r.value.slice(0, end) }));
  assert.throws(() => initialEnvelope({ ...r, value: new Uint8Array([...r.value, 10]) }));
  assert.throws(() => initialEnvelope({ ...r, type: r.type.replace('fg-initial-', 'fg-source-') }));
});
test('initial transport does not inherit source editing, PR or issue endpoints', async () => {
  const t = new Transport({ href, pageSuffix: '/ui/initial/', cryptoImpl: crypto, fetchImpl: () => { throw new Error('Network must not run'); } }); await t.connect(token);
  for (const path of ['source/apply', 'source/tree', 'source/inspect', 'pulls', 'issues', 'source/initial/apply?force=true', '../outcomes', 'https://attacker.invalid/']) await assert.rejects(t.request(path), /Invalid API route/);
});
for (const action of ['disconnect', 'invalidateCandidate']) test(`${action} during preparation cannot resurrect a candidate`, async () => {
  const f = await fixture(), c = await connected(f); let release, reached;
  const entered = new Promise(r => { reached = r; }); f.config.prepare = () => new Promise(r => { release = r; reached(); });
  const work = c.prepare(f.fields, f.files, metadata); await entered; c[action](); release();
  await assert.rejects(work); assert.equal(c.candidate, null); assert.equal(c.pending, null);
});
test('prepare-stage races and cancellation during local hashing never create a mutation', async () => {
  const f = await fixture(), c = await connected(f); await c.prepare(f.fields, f.files, metadata);
  const work = c.stageApply(); c.invalidateCandidate(); await assert.rejects(work); assert.equal(c.pending, null);
  await assert.rejects(initialPlan(f.files, metadata, 'sha1', crypto, () => { throw new Error('cancelled'); }));
});
for (const outcome of ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused']) test(`outcome lookup (${outcome}) is read-only and absence never clears the request`, async () => {
  const f = await fixture(), c = await staged(f); f.config.outcome = outcome;
  const result = await c.recover(), last = f.calls.at(-1);
  assert.equal(last.endpoint, 'outcomes'); assert.equal(last.body, undefined);
  assert.equal(c.pending === null, ['committed', 'refused'].includes(outcome));
  assert.equal(result.terminal, ['committed', 'refused'].includes(outcome));
});
test('only a matching canonical 409 is terminal; status code and generic conflicts prove nothing', async () => {
  const f = await fixture(), c = await staged(f); f.config.refused = true;
  assert.equal((await c.send()).outcome, 'refused'); assert.equal(c.pending, null);
  const g = await fixture(), d = await staged(g); g.config.status = 409;
  await assert.rejects(d.send(), e => e.outcomeUnknown); assert.ok(d.pending);
  g.config.publish = r => { r.type = 'source_error'; };
  await assert.rejects(d.send(), e => e.outcomeUnknown); assert.ok(d.pending);
});
test('recovered transaction and actor cannot be replaced by another terminal receipt', async () => {
  const f = await fixture(), c = await staged(f); f.config.outcome = 'undecided'; await c.recover();
  f.config.publish = r => { r.tx_id = 'different'; }; await assert.rejects(c.send()); assert.ok(c.pending);
  f.config.publish = r => { r.principal_id = 'a'.repeat(32); }; await assert.rejects(c.send()); assert.ok(c.pending);
  f.config.outcome = 'key_not_observed'; await assert.rejects(c.recover()); assert.ok(c.pending);
});
test('recovery export/restore retains exact bytes, original key, branch absence and credential without executing', async () => {
  const f = await fixture(), c = await staged(f), original = c.pending, receipt = c.exportReceipt();
  assert.ok(!receipt.includes(token)); assert.throws(() => c.discardUnsent());
  const d = await connected(f), n = f.calls.length; await d.restoreReceipt(receipt); assert.equal(f.calls.length, n);
  assert.equal(d.pending.key, original.key); assert.equal(d.pending.requestSha256, original.requestSha256);
  assert.throws(() => d.discardUnsent()); await d.send(); assert.equal(d.pending, null);
});
for (const [name, mutate] of [
  ['branch', r => { r.fields.ref = 'refs/heads/other'; }], ['absence', r => { r.fields.expected_absent = false; }],
  ['candidate', r => { r.fields.candidate_commit = 'a'.repeat(40); }], ['key', r => { r.key += 'x'; }],
  ['scope', r => { r.scope.incarnation = 'foreign'; }], ['route', r => { r.route += '-else'; }],
  ['credential', r => { r.fingerprint = 'f'.repeat(64); }], ['bundle', r => { r.bundle_base64 = btoa('different bundle'); }],
  ['family', r => { r.type = 'frankengit-source-retry-v1'; }], ['extra field', r => { r.force = true; }],
]) test(`tampered initial receipt (${name}) cannot be restored`, async () => {
  const f = await fixture(), c = await staged(f), r = JSON.parse(c.exportReceipt()); mutate(r);
  const d = await connected(f), n = f.calls.length; await assert.rejects(d.restoreReceipt(JSON.stringify(r))); assert.equal(d.pending, null); assert.equal(f.calls.length, n);
});
