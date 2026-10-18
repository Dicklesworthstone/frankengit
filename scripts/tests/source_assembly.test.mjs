// Actual Git is a test-only tree oracle. These are not native agent execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { assembleSourceChanges, ASSEMBLY_LIMITS } from '../operator/source_assembly.mjs';
import { canonical, sha256, ownSourceChangeInputs } from '../operator/source_changes.mjs';
import { changeFixture, intent, replace, hexPath } from './source_changes_fixture.mjs';
import { withParent } from './source_replay_fixture.mjs';
import { contribution } from './source_assembly_fixture.mjs';
const rows = [{ path: 'src/a', bytes: 'old A\n' }, { path: 'src/b', bytes: 'old B\n' }, { path: 'context', bytes: 'shared\n' }];
async function pair(format = 'sha1', profiles = {}) {
  const f = changeFixture(format, rows);
  return { f, inputs: await Promise.all([
    contribution(f, 'agent-a', ['src/a', 'context'], { ...intent([replace('src/a', 'new A\n')]), ...profiles }),
    contribution(f, 'agent-b', ['src/b', 'context'], { ...intent([replace('src/b', 'new B\n')]), ...profiles }),
  ]) };
}
async function gitOracle(t, f, patch, expectedTree) {
  const path = await mkdtemp(join(tmpdir(), 'fg-assembly-git-')); t.after(() => rm(path, { recursive: true, force: true }));
  const env = { PATH: process.env.PATH, HOME: path, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_COUNT: '0', LC_ALL: 'C' };
  const git = (args, input) => execFileSync('git', ['-C', path, ...args], { input, env, timeout: 15000 });
  git(['init', '-q', `--object-format=${f.format}`]);
  for (const file of f.files) git(['hash-object', '-w', '--stdin'], file.bytes);
  for (const tree of f.value.membership.trees) git(['hash-object', '-w', '-t', 'tree', '--stdin'], Buffer.from(tree.bodyHex, 'hex'));
  git(['read-tree', f.tree]); git(['apply', '--cached', '--whitespace=nowarn', '-'], patch);
  assert.equal(git(['write-tree']).toString().trim(), expectedTree);
  git(['apply', '--cached', '--reverse', '--whitespace=nowarn', '-'], patch);
  assert.equal(git(['write-tree']).toString().trim(), f.tree);
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: assemble independent reviews, shared context and exact tree; order cannot choose a winner`, async t => {
    const { f, inputs } = await pair(format), a = await assembleSourceChanges(inputs), b = await assembleSourceChanges([...inputs].reverse());
    assert.deepEqual(a.receipt, b.receipt); assert.deepEqual(a.combined, b.combined); assert.deepEqual(a.draft.bytes, b.draft.bytes);
    assert.equal(a.receipt.selected_file_count, 3); assert.equal(a.receipt.effect_count, 2);
    assert.equal(a.receipt.new_review_required, true); assert.equal(a.receipt.contributor_identity_authenticated, false);
    assert.ok(inputs.every(row => row.confirmDraftSha256 !== a.receipt.draft_sha256));
    assert.equal(a.draft.tree.afterTree, changeFixture(format, [replaceRow('src/a', 'new A\n'), replaceRow('src/b', 'new B\n'), rows[2]]).tree);
    await gitOracle(t, f, a.draft.bytes, a.draft.tree.afterTree);
  });
  test(`${format}: disjoint effects cannot change another contributor's selected context`, async () => {
    const { f, inputs } = await pair(format);
    inputs[1] = await contribution(f, 'agent-b', ['src/a', 'src/b'], intent([replace('src/b', 'new B\n')]));
    await assert.rejects(assembleSourceChanges(inputs), /source_assembly_read_write_conflict/);
  });
  test(`${format}: identical and different overlapping writes are both explicit conflicts`, async () => {
    const { f, inputs } = await pair(format);
    for (const text of ['new A\n', 'other A\n']) {
      inputs[1] = await contribution(f, 'agent-b', ['src/a'], intent([replace('src/a', text)]));
      await assert.rejects(assembleSourceChanges(inputs), /source_assembly_write_conflict/);
    }
  });
  test(`${format}: modes, deletes, splices, creates and renames retain their original effect accounting`, async t => {
    const f = changeFixture(format, [{ path: 'a', bytes: 'hello\n' }, { path: 'b', bytes: 'old\n' }, { path: 'c', bytes: 'C\n' }, { path: 'd', bytes: 'D\n' }]);
    const inputs = await Promise.all([
      contribution(f, 'a', ['a'], intent([
        { operation: 'rename', from_path_hex: hexPath('a'), path_hex: hexPath('new/name'), executable: true }])),
      contribution(f, 'b', ['b'], intent([{ operation: 'splice', path_hex: hexPath('b'), splices: [{ byte_offset: 0, before_utf8: 'old', after_utf8: 'new' }] }])),
      contribution(f, 'c', ['c'], intent([{ operation: 'delete', path_hex: hexPath('c') }, { operation: 'create', path_hex: hexPath('new/empty'), executable: false, content_utf8: '' }])),
      contribution(f, 'd', ['d'], intent([{ operation: 'mode', path_hex: hexPath('d'), executable: true }])),
    ]);
    const a = await assembleSourceChanges(inputs); assert.equal(a.receipt.effect_count, 6);
    assert.equal(a.draft.manifest.relocations.length, 1); await gitOracle(t, f, a.draft.bytes, a.draft.tree.afterTree);
  });
  test(`${format}: read-only copy source is preserved; editing it in another draft conflicts`, async () => {
    const { f, inputs } = await pair(format);
    inputs[0] = await contribution(f, 'agent-a', ['src/a'], intent([{ operation: 'copy', from_path_hex: hexPath('src/a'), path_hex: hexPath('new') }]));
    await assembleSourceChanges(inputs);
    inputs[1] = await contribution(f, 'agent-b', ['src/a'], intent([replace('src/a', 'changed source')]));
    await assert.rejects(assembleSourceChanges(inputs), /source_assembly_read_write_conflict/);
  });
  test(`${format}: binary multi-hunk contributions reach the same exact tree`, async t => {
    const before = Buffer.from('old\n' + 'common\n'.repeat(30) + 'end\n'); before[1] = 0;
    const after = Buffer.from(before); after[0] = 255; after[after.length - 3] = 254;
    const f = changeFixture(format, [{ path: Buffer.from([255, 97]), bytes: before }, { path: 'b', bytes: before }]);
    const profiles = { byte_profile: 'binary-safe-v1', patch_profile: 'bounded-line-hunks-v1' };
    const inputs = await Promise.all(f.files.map((file, i) => contribution(f, `id-${i}`, [file.path],
      { ...intent([{ operation: 'replace', path_hex: hexPath(file.path), content_hex: after.toString('hex') }]), ...profiles })));
    const a = await assembleSourceChanges(inputs); assert.ok(a.draft.manifest.effects.every(e => e.hunks === 2));
    await gitOracle(t, f, a.draft.bytes, a.draft.tree.afterTree);
  });
}
function replaceRow(path, bytes) { return { path, bytes }; }
test('all original pins must match, and invalid sources cannot borrow another proof', async () => {
  const { inputs } = await pair();
  const bad = structuredClone(inputs); bad[1].confirmDraftSha256 = '0'.repeat(64);
  await assert.rejects(assembleSourceChanges(bad), /source_assembly_confirmation/);
  const value = JSON.parse(inputs[0].packageBytes); value.membership.trees = value.membership.trees.filter(t => t.pathHex === null);
  inputs[0].packageBytes = Buffer.from(JSON.stringify(value));
  await assert.rejects(assembleSourceChanges(inputs));
});
test('different selected commits, hash domains or explicit profiles cannot be combined', async () => {
  const { f, inputs } = await pair(), next = withParent(f, f.commit);
  inputs[1] = await contribution(next, 'agent-b', ['src/b'], intent([replace('src/b', 'new B\n')]));
  await assert.rejects(assembleSourceChanges(inputs), /source_assembly_basis/);
  const other = await pair('sha256'); await assert.rejects(assembleSourceChanges([inputs[0], other.inputs[1]]), /source_assembly_basis/);
  for (const profiles of [{ byte_profile: 'binary-safe-v1' }, { patch_profile: 'trim-common-lines-v1' }]) {
    const other = await pair('sha1', profiles); await assert.rejects(assembleSourceChanges([inputs[0], other.inputs[1]]), /source_assembly_profiles/);
  }
});
test('creation and ancestor collisions do not depend on contribution order', async () => {
  const { f, inputs } = await pair();
  inputs[0] = await contribution(f, 'agent-a', ['src/a'], intent([{ operation: 'create', path_hex: hexPath('new'), content_utf8: 'x', executable: false }]));
  inputs[1] = await contribution(f, 'agent-b', ['src/b'], intent([{ operation: 'create', path_hex: hexPath('new/child'), content_utf8: 'x', executable: false }]));
  await assert.rejects(assembleSourceChanges(inputs), /source_assembly_write_conflict/);
});
test('no-op intent remains accounted for and cannot silently combine with another write', async () => {
  const f = changeFixture('sha1', [...rows, { path: 'unused', bytes: 'U' }]);
  const a = await contribution(f, 'a', ['src/a', 'unused'], intent([replace('src/a', 'new A'), replace('unused', 'U')]));
  const b = await contribution(f, 'b', ['src/b'], intent([replace('src/b', 'new B')]));
  const r = await assembleSourceChanges([a, b]); assert.deepEqual(r.draft.manifest.no_op_paths_hex, [hexPath('unused')]);
  const c = await contribution(f, 'c', ['unused'], intent([replace('unused', 'CHANGED')]));
  await assert.rejects(assembleSourceChanges([a, c]), /source_assembly_write_conflict/);
});
test('identical read-only copy sources can produce two distinct creations', async () => {
  const { f } = await pair();
  const rows = await Promise.all(['x', 'y'].map(id => contribution(f, id, ['src/a'], intent([{ operation: 'copy', from_path_hex: hexPath('src/a'), path_hex: hexPath(id) }]))));
  const r = await assembleSourceChanges(rows); assert.equal(r.receipt.effect_count, 2); assert.equal(r.receipt.selected_file_count, 1);
});
test('owns later contributions and pins before any asynchronous hashing', async () => {
  const { inputs } = await pair(), expected = await assembleSourceChanges(inputs);
  const task = assembleSourceChanges(inputs); inputs[1].packageBytes.fill(0); inputs[1].id = 'other';
  inputs[1].changes.changes[0].content_utf8 = 'changed'; inputs[1].expected.commit = 'f'.repeat(40); inputs.length = 0;
  const actual = await task; assert.deepEqual(actual.receipt, expected.receipt);
});
test('exact combined byte ceiling charges repeated packages and normalizations', async () => {
  const { inputs } = await pair();
  const bytes = inputs.reduce((n, row) => { const owned = ownSourceChangeInputs(row.packageBytes, row.expected, row.changes);
    return n + owned.packageBytes.length + canonical(owned.expected).length + canonical(owned.changes).length; }, 0);
  await assembleSourceChanges(inputs, { limits: { inputBytes: bytes } });
  await assert.rejects(assembleSourceChanges(inputs, { limits: { inputBytes: bytes - 1 } }), /source_assembly_input_limit/);
});
test('eight contributors and 32 effects succeed; the ninth or 33rd cannot widen limits', async () => {
  const files = Array.from({ length: 33 }, (_, i) => ({ path: `f${String(i).padStart(2, '0')}`, bytes: 'old' }));
  const f = changeFixture('sha1', files), inputs = [];
  for (let i = 0; i < 8; i++) { const paths = files.slice(i * 4, i * 4 + 4).map(f => f.path);
    inputs.push(await contribution(f, `id${i}`, paths, intent(paths.map(p => replace(p, 'new'))))); }
  const result = await assembleSourceChanges(inputs); assert.equal(result.receipt.effect_count, 32);
  await assert.rejects(assembleSourceChanges([...inputs, { ...inputs[0], id: 'extra' }]), /source_assembly_count/);
  inputs[7] = await contribution(f, 'id7', files.slice(28).map(f => f.path), intent(files.slice(28).map(f => replace(f.path, 'new'))));
  await assert.rejects(assembleSourceChanges(inputs), /source_union_selection_limit/);
});
test('combined retained bytes cannot borrow separate contributor budgets', async () => {
  const body = 'X'.repeat(800000), f = changeFixture('sha1', ['a', 'b', 'c'].map(path => ({ path, bytes: body })));
  const inputs = await Promise.all(['a', 'b', 'c'].map(id => contribution(f, id, [id], intent([{ operation: 'mode', path_hex: hexPath(id), executable: true }]))));
  await assert.rejects(assembleSourceChanges(inputs), /source_changes_retained_budget/);
});
test('malformed count, labels, pins, options and unrequested capabilities refuse', async () => {
  const { inputs } = await pair();
  for (const input of [null, [], [inputs[0]], [inputs[0], { ...inputs[1], id: inputs[0].id }],
    [inputs[0], { ...inputs[1], id: '../outside' }], [inputs[0], { ...inputs[1], confirmDraftSha256: 'bad' }],
    [inputs[0], { ...inputs[1], token: 'secret' }]]) await assert.rejects(assembleSourceChanges(input));
  for (const options of [{ token: 'secret' }, { timeoutMs: 0 }, { limits: { inputBytes: ASSEMBLY_LIMITS.inputBytes + 1 } },
    { limits: { contributions: 1 } }, { limits: { unexpected: 1 } }]) await assert.rejects(assembleSourceChanges(inputs, options));
});
test('cancellation and one shared deadline return no assembled subset', async () => {
  const { inputs } = await pair(), stopped = new AbortController(); stopped.abort();
  await assert.rejects(assembleSourceChanges(inputs, { signal: stopped.signal }), /cancel/);
  const during = new AbortController(), task = assembleSourceChanges(inputs, { signal: during.signal }); during.abort();
  await assert.rejects(task, /cancel|Abort/);
  await assert.rejects(assembleSourceChanges(inputs, { timeoutMs: 1 }), /timeout/);
});
