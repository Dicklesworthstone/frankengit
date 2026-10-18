// Actual patch bytes checked by installed Git. The HTTP peer is not Rust fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { buildPatch } from '../../crates/fgit-node/src/smart_http/server/browser/source-patch.mjs';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { changeFixture, hexPath } from './source_changes_fixture.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
import { prepareSourceChanges, verifySourceChangeCandidate } from '../operator/source_changes_prepare.mjs';

import { replaySourceChanges } from '../operator/source_replay.mjs';
import { replayPair } from './source_replay_fixture.mjs';

const PROFILE = 'trim-common-lines-v1';
const input = rows => ({ schema: 'frankengit-source-changes-v1', patch_profile: PROFILE, changes: rows });
const replacement = (bytes, path = 'file') => ({ path_hex: hexPath(path), operation: 'replace', content_hex: Buffer.from(bytes).toString('hex') });
async function oracle(format, before, after, patch, mode = 0o100644) {
  const root = await mkdtemp(join(tmpdir(), 'fg-compact-oracle-'));
  const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_COUNT: '0', LC_ALL: 'C', GIT_OPTIONAL_LOCKS: '0' };
  const git = (args, bytes) => execFileSync('git', ['-C', root, ...args], { env, input: bytes, timeout: 15000, maxBuffer: 8 * 1024 * 1024 });
  try {
    git(['init', '--quiet', `--object-format=${format}`]);
    if (before !== null) {
      const id = git(['hash-object', '-w', '--stdin'], Buffer.from(before)).toString().trim();
      git(['update-index', '--add', '--cacheinfo', `100644,${id},file`]);
    }
    git(['apply', '--cached', '--binary', '--whitespace=nowarn', '-'], patch);
    const expected = changeFixture(format, after === null ? [] : [{ path: 'file', bytes: after, mode }]);
    assert.equal(git(['write-tree']).toString().trim(), expected.tree);
    if (after !== null) assert.deepEqual(git(['cat-file', 'blob', expected.files[0].id]), Buffer.from(after));
    // Reverse application must restore the same exact original tree and bytes.
    git(['apply', '--cached', '--binary', '--reverse', '--whitespace=nowarn', '-'], patch);
    assert.equal(git(['write-tree']).toString().trim(), changeFixture(format, before === null ? [] : [{ path: 'file', bytes: before }]).tree);
    return expected.tree;
  } finally { await rm(root, { recursive: true, force: true }); }
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: a one-line edit in a near-one-MiB file fits the unchanged operator patch limit`, async () => {
    const before = Buffer.from('unchanged line\n'.repeat(65500));
    const after = Buffer.from(before); Buffer.from('different line').copy(after, 15 * 32750);
    const f = changeFixture(format, [{ path: 'file', bytes: before }]);
    const rows = [replacement(after)];
    await assert.rejects(buildSourceChanges(f.bytes, f.expected, { schema: input(rows).schema, changes: rows }), /patch_budget/);
    const result = await buildSourceChanges(f.bytes, f.expected, input(rows));
    assert.equal(result.manifest.patch_profile, PROFILE);
    assert.ok(result.bytes.length < 512, result.bytes.length);
    assert.equal(result.tree.afterTree, await oracle(format, before, after, result.bytes));
    assert.deepEqual(await buildSourceChanges(f.bytes, f.expected, input(rows)), result);
  });
  test(`${format}: compact hunks preserve insert/delete/replace boundaries and missing final LF`, async () => {
    const cases = [
      ['', 'new\n'], ['old\n', ''], ['a\nb\nc\n', 'x\na\nb\nc\n'],
      ['a\nb\nc\n', 'a\nb\nc\nx\n'], ['x\na\nb\nc\n', 'a\nb\nc\n'],
      ['a\nb\nc\nx\n', 'a\nb\nc\n'], ['a\nb\nc', 'a\nX\nc'],
      ['a\nb\n', 'a\nb'], ['a\nb', 'a\nb\n'], ['same', 'same appended'], ['\na', '\nb'], ['\n\n', '\n\nx\n'], ['x\n\n', 'y\n\n'], ['\n', ''], ['', '\n'],
      ['1\n2\n3\n4\n5\n6\n7\n8\n', '1\n2\n3\nx\n4\n5\n6\n7\n8\n'],
      ['p\na\na\na\ns\n', 'p\na\ns\n'], ['a\r\nb\r\nc\r\n', 'a\r\nB\r\nc\r\n'],
    ];
    for (const [before, after] of cases) {
      const edits = [{ path_hex: hexPath('file'), before: { mode: 0o100644, bytes: Buffer.from(before) }, after: { mode: 0o100644, bytes: Buffer.from(after) } }];
      const result = await buildPatch(edits, format, { crypto: webcrypto, patchProfile: PROFILE });
      await oracle(format, before, after, result.bytes);
    }
    for (const [before, after] of [[null, 'created\n'], ['removed', null], [null, ''], ['', null]]) {
      const result = await buildPatch([{ path_hex: hexPath('file'), before: before === null ? null : { mode: 0o100644, bytes: Buffer.from(before) },
        after: after === null ? null : { mode: 0o100755, bytes: Buffer.from(after) } }], format, { crypto: webcrypto, patchProfile: PROFILE });
      await oracle(format, before, after, result.bytes, 0o100755);
    }
  });
  test(`${format}: binary opt-in composes with compact patches but does not select it implicitly`, async () => {
    const before = Buffer.concat([Buffer.from('same\n'.repeat(20)), Buffer.from([0, 255, 10]), Buffer.from('tail\n'.repeat(20))]);
    const after = Buffer.from(before); after[101] = 254;
    const f = changeFixture(format, [{ path: 'file', bytes: before }]), chosen = { ...input([replacement(after)]), byte_profile: 'binary-safe-v1' };
    const result = await buildSourceChanges(f.bytes, f.expected, chosen);
    await oracle(format, before, after, result.bytes);
    assert.ok(result.bytes.includes(0)); assert.equal(result.manifest.byte_profile, 'binary-safe-v1');
    await assert.rejects(buildSourceChanges(f.bytes, f.expected, input([replacement(after)])), /binary_unsupported/);
  });
  test(`${format}: profile binds fresh draft consent while after-images and expected trees stay identical`, async () => {
    const f = changeFixture(format, [{ path: 'file', bytes: 'a\nb\nc\nd\ne\nf\ng\nh\ni\n' }]);
    const chosen = input([replacement('a\nb\nc\nd\nNEW\nf\ng\nh\ni\n')]);
    const compact = await buildSourceChanges(f.bytes, f.expected, chosen);
    const full = await buildSourceChanges(f.bytes, f.expected, { schema: chosen.schema, changes: chosen.changes });
    assert.deepEqual(compact.manifest.effects, full.manifest.effects); assert.deepEqual(compact.tree, full.tree);
    assert.notEqual(sha256(canonical(compact.manifest)), sha256(canonical(full.manifest)));
    assert.equal(Object.hasOwn(full.manifest, 'patch_profile'), false);
  });
  test(`${format}: compact draft reaches real HTTP preparation and offline candidate checks`, async () => {
    const peer = await nativePeer(format, { files: [{ path: 'file', bytes: 'same\n'.repeat(30) }] });
    try {
      const chosen = input([replacement('same\n'.repeat(15) + 'CHANGED\n' + 'same\n'.repeat(14))]);
      const f = peer.fixture, draft = await buildSourceChanges(f.bytes, f.expected, chosen), pin = sha256(canonical(draft.manifest));
      const full = await buildSourceChanges(f.bytes, f.expected, { schema: chosen.schema, changes: chosen.changes });
      await assert.rejects(prepareSourceChanges(f.bytes, f.expected, chosen, peer.selection([hexPath('file')]), TOKEN,
        { confirmDraftSha256: sha256(canonical(full.manifest)) }), /confirmation/);
      assert.equal(peer.requests.length, 0);
      const prepared = await prepareSourceChanges(f.bytes, f.expected, chosen, peer.selection([hexPath('file')]), TOKEN, { confirmDraftSha256: pin });
      assert.deepEqual(peer.candidate.patch, draft.bytes);
      const inspected = await verifySourceChangeCandidate(f.bytes, f.expected, chosen, prepared.capture, prepared.bundle, { confirmDraftSha256: pin });
      assert.equal(inspected.binding.expected_tree, draft.tree.afterTree); assert.deepEqual(peer.failures, []);
    } finally { await peer.close(); }
  });
}

test('closed profile grammar and pre-cancelled operations refuse before patch production', async () => {
  const f = changeFixture('sha1', [{ path: 'file', bytes: 'old' }]);
  for (const patch_profile of [null, true, 1, 'compact', {}, ['trim-common-lines-v1']]) {
    await assert.rejects(buildSourceChanges(f.bytes, f.expected, { ...input([replacement('new')]), patch_profile }), /patch_profile/);
  }
  const c = new AbortController(); c.abort();
  await assert.rejects(buildSourceChanges(f.bytes, f.expected, input([replacement('new')]), { signal: c.signal }));
});

test('exact final patch bound, caller ownership, and checkpoint interruption survive trimming', async () => {
  const f = changeFixture('sha1', [{ path: 'file', bytes: 'keep\n'.repeat(100) }]);
  const chosen = input([replacement('keep\n'.repeat(50) + 'new\n' + 'keep\n'.repeat(49))]);
  const draft = await buildSourceChanges(f.bytes, f.expected, chosen);
  assert.deepEqual(await buildSourceChanges(f.bytes, f.expected, chosen, { limits: { patchBytes: draft.bytes.length } }), draft);
  await assert.rejects(buildSourceChanges(f.bytes, f.expected, chosen, { limits: { patchBytes: draft.bytes.length - 1 } }), /patch_budget/);
  const bytes = Buffer.from(f.bytes), expected = structuredClone(f.expected), request = structuredClone(chosen);
  const pending = buildSourceChanges(bytes, expected, request); bytes.fill(0); expected.files.length = 0; request.patch_profile = 'bad';
  assert.deepEqual(await pending, draft);
  const before = Buffer.from('x\n'.repeat(100000)), after = Buffer.from(before); after[100000] = 121;
  let checkpoints = 0;
  await assert.rejects(buildPatch([{ path_hex: hexPath('file'), before: { mode: 0o100644, bytes: before }, after: { mode: 0o100644, bytes: after } }], 'sha1',
    { crypto: webcrypto, patchProfile: PROFILE, signal: { throwIfAborted() { if (++checkpoints === 20) throw new Error('trim interrupted'); } } }), /trim interrupted/);
});

test('seeded line edits round trip through forward and reverse Git application', async () => {
  let seed = 0x431112;
  const next = () => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return seed >>> 0; };
  for (const format of ['sha1', 'sha256']) for (let n = 0; n < 24; n++) {
    const lines = Array.from({ length: 5 + next() % 40 }, (_, i) => `${i}:${next() % 10}\n`);
    const changed = [...lines], at = next() % changed.length;
    changed.splice(at, next() % 3, ...Array.from({ length: next() % 4 }, () => `new:${next()}\n`));
    let before = lines.join(''), after = changed.join('');
    if (before === after) after += 'different\n';
    if (n % 2) { before = before.replace(/\n$/, ''); after = after.replace(/\n$/, ''); }
    const result = await buildPatch([{ path_hex: hexPath('file'), before: { mode: 0o100644, bytes: Buffer.from(before) },
      after: { mode: 0o100644, bytes: Buffer.from(after) } }], format, { crypto: webcrypto, patchProfile: PROFILE });
    await oracle(format, before, after, result.bytes);
  }
});


function cli(script, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [new URL(`../${script}`, import.meta.url).pathname, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [], stderr = []; let size = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('CLI deadline')); }, 15000);
    for (const [stream, target] of [[child.stdout, stdout], [child.stderr, stderr]]) stream.on('data', chunk => {
      size += chunk.length; if (size > 131072) { child.kill('SIGKILL'); reject(new Error('CLI output limit')); } else target.push(chunk);
    });
    child.once('error', e => { clearTimeout(timer); reject(e); });
    child.once('close', code => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() }); });
  });
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: selected-base replay preserves the compact profile and exact reviewed patch`, async () => {
    const { old, next } = replayPair(format);
    const changes = input([{ path_hex: hexPath('src/file'), operation: 'replace-once', before_utf8: 'beta', after_utf8: 'reviewed' }]);
    const draft = await buildSourceChanges(old.bytes, old.expected, changes), pin = sha256(canonical(draft.manifest));
    const replay = await replaySourceChanges(old.bytes, old.expected, changes, next.bytes, next.expected, { confirmDraftSha256: pin });
    assert.deepEqual(replay.draft.bytes, draft.bytes); assert.equal(replay.next.changes.patch_profile, PROFILE);
    assert.equal(replay.draft.manifest.patch_profile, PROFILE); assert.equal(replay.receipt.new_review_required, true);
  });
  test(`${format}: CLI compact draft/prepare/stage retains one-shot recovery after lost response`, async t => {
    const peer = await nativePeer(format, { files: [{ path: 'file', bytes: 'kept\n'.repeat(1000) }] });
    const root = await mkdtemp(join(tmpdir(), 'fg-compact-cli-'));
    t.after(async () => { await peer.close(); await rm(root, { recursive: true, force: true }); });
    const f = peer.fixture, changes = input([replacement('kept\n'.repeat(500) + 'new\n' + 'kept\n'.repeat(499))]);
    const payloads = { 'source.json': f.bytes, 'expected.json': canonical(f.expected), 'changes.json': canonical(changes),
      'selection.json': canonical(peer.selection([hexPath('file')])), token: Buffer.from(TOKEN), rotated: Buffer.from(ROTATED_TOKEN) };
    for (const [name, bytes] of Object.entries(payloads)) await writeFile(join(root, name), bytes, { mode: 0o600 });
    const common = ['--package', join(root, 'source.json'), '--expect', join(root, 'expected.json'), '--changes', join(root, 'changes.json')];
    const invoke = async (script, args, expected = 0) => { const reply = await cli(script, args); assert.equal(reply.code, expected, reply.stderr); return reply; };
    const drafted = JSON.parse((await invoke('fg_source_changes.mjs', ['draft', ...common, '--output', join(root, 'draft')])).stdout);
    const manifest = JSON.parse(await readFile(join(root, 'draft/manifest.json'))); assert.equal(manifest.patch_profile, PROFILE);
    assert.ok((await readFile(join(root, 'draft/patch.diff'))).length < 512);
    const prepared = JSON.parse((await invoke('fg_source_changes.mjs', ['prepare', ...common, '--selection', join(root, 'selection.json'),
      '--token-file', join(root, 'token'), '--confirm-draft-sha256', drafted.manifest_sha256, '--output', join(root, 'candidate')])).stdout);
    const staged = JSON.parse((await invoke('fg_source_changes.mjs', ['stage', ...common, '--selection', join(root, 'selection.json'),
      '--candidate', join(root, 'candidate'), '--sha256', prepared.manifest_sha256, '--confirm-draft-sha256', drafted.manifest_sha256,
      '--principal', PRINCIPAL, '--confirm-candidate', prepared.candidate_commit, '--journal', join(root, 'journal')])).stdout);
    for (const name of ['source.json', 'expected.json', 'changes.json', 'selection.json', 'candidate', 'draft']) await rm(join(root, name), { recursive: true });
    peer.lostApply = true;
    const journal = ['--journal', staged.journal, '--request-sha256', staged.request_sha256];
    const lost = await invoke('fg_source_edit.mjs', ['apply', ...journal, '--token-file', join(root, 'token')], 3);
    assert.equal(JSON.parse(lost.stderr).retained_request.key, staged.key);
    const recovered = JSON.parse((await invoke('fg_source_edit.mjs', ['recover', ...journal, '--token-file', join(root, 'rotated')])).stdout);
    assert.equal(recovered.key, staged.key); assert.equal(recovered.decision.decision_sequence, '18446744073709551615');
    assert.equal(recovered.decision.outcome, 'committed'); assert.equal(peer.applies, 1); assert.deepEqual(peer.failures, []);
  });
}
test('many unchanged blank lines are scanned without expanding them into patch rows', async () => {
  const before = Buffer.alloc(800000, 10), after = Buffer.from(before); after[400000] = 120;
  const result = await buildPatch([{ path_hex: hexPath('file'), before: { bytes: before, mode: 0o100644 },
    after: { bytes: after, mode: 0o100644 } }], 'sha1', { crypto: webcrypto, patchProfile: PROFILE });
  assert.ok(result.bytes.length < 512); await oracle('sha1', before, after, result.bytes);
});
