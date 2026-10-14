// A real Git-created candidate with an omitted extra change is an internally
// coherent response, not a native fg execution. Exercise complete client modules.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { prepareSourceChanges, verifySourceChangeCandidate } from '../operator/source_changes_prepare.mjs';
import { captureSourceEdit, validateSourceEdit } from '../operator/source_edit_candidate.mjs';
import { saveSourceEdit, loadSourceEdit } from '../operator/source_edit_publish.mjs';
import { nativePeer, TOKEN } from './source_changes_native_fixture.mjs';
import { intent, replace, hexPath, changeFixture } from './source_changes_fixture.mjs';
for (const format of ['sha1', 'sha256']) {
  test(`${format}: coherent candidate cannot hide an unrelated tree change behind exact effect reports`, async () => {
    const peer = await nativePeer(format);
    try {
      const changes = intent([replace('src/main.rs', 'fn main() { intended(); }\n')]);
      const draft = await buildSourceChanges(peer.fixture.bytes, peer.fixture.expected, changes);
      const selection = peer.selection(draft.manifest.effects.map(row => row.path_hex));
      const options = { confirmDraftSha256: sha256(canonical(draft.manifest)) };
      peer.fault = 'unreported-addition';
      const captured = await captureSourceEdit(selection, draft.bytes, TOKEN);
      const checked = validateSourceEdit(captured.capture, captured.bundle);
      assert.equal(checked.candidate_commit, peer.candidate.commit);
      assert.equal(captured.capture.inspection.comparison.entries.length, 1);
      // All previous effect checks still match; only a full-root commitment
      // distinguishes the extra unreported file in the genuine candidate tree.
      const effect = draft.manifest.effects[0], reported = captured.capture.inspection.comparison.entries[0];
      assert.equal(reported.path_hex, effect.path_hex); assert.equal(reported.after.oid, effect.new_blob);
      assert.equal(reported.after.mode, effect.new_mode); assert.equal(reported.before.oid, effect.old_blob);
      await assert.rejects(verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, changes,
        captured.capture, captured.bundle, options), { code: 'source_changes_candidate_tree' });
      await assert.rejects(prepareSourceChanges(peer.fixture.bytes, peer.fixture.expected, changes, selection, TOKEN, options),
        { code: 'source_changes_candidate_tree' });
      assert.equal(peer.applies, 0);
      peer.fault = null;
      const accepted = await prepareSourceChanges(peer.fixture.bytes, peer.fixture.expected, changes, selection, TOKEN, options);
      assert.equal(accepted.binding.candidate_root_matches_exact_effects, true);
      assert.equal(accepted.binding.expected_tree, peer.candidate.tree);
      assert.equal(accepted.binding.bundle_objects_independently_verified, false);
      assert.deepEqual(peer.failures, []);
    } finally { await peer.close(); }
  });
  test(`${format}: mixed creation, deletion and untouched siblings bind the expected native root on offline replay`, async () => {
    const peer = await nativePeer(format), root = await mkdtemp(join(tmpdir(), 'fg-tree-bound-'));
    try {
      const changes = intent([{ path_hex: hexPath('src/main.rs'), operation: 'delete' },
        { path_hex: hexPath('newdir/deep/file'), operation: 'create', executable: true, content_utf8: 'new\n' },
        { path_hex: hexPath('run.sh'), operation: 'mode', executable: false }]);
      const expected = changeFixture(format, [{ path: 'empty.txt', bytes: '' }, { path: 'run.sh', bytes: '#!/bin/sh\necho old\n' },
        { path: 'newdir/deep/file', bytes: 'new\n', mode: 0o100755 }]);
      const draft = await buildSourceChanges(peer.fixture.bytes, peer.fixture.expected, changes);
      const selection = peer.selection(draft.manifest.effects.map(row => row.path_hex)), options = { confirmDraftSha256: sha256(canonical(draft.manifest)) };
      const result = await prepareSourceChanges(peer.fixture.bytes, peer.fixture.expected, changes, selection, TOKEN, options);
      assert.equal(result.binding.expected_tree, expected.tree); assert.equal(result.binding.expected_tree, peer.candidate.tree);
      const saved = await saveSourceEdit(join(root, 'candidate'), result.capture, result.bundle), loaded = await loadSourceEdit(join(root, 'candidate'), saved.manifest_sha256);
      await peer.close();
      const replay = await verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, changes, loaded.capture, loaded.bundle, options);
      assert.deepEqual(replay.binding, result.binding); assert.equal(replay.binding.candidate_root_matches_exact_effects, true);
      assert.equal(replay.binding.publication_authorized, false);
    } finally { await peer.close(); await rm(root, { recursive: true, force: true }); }
  });
}

function cli(args) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, [resolve('scripts/fg_source_changes.mjs'), ...args], { stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, NODE_OPTIONS: '' } });
    const stdout = [], stderr = []; let bytes = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('tree binding CLI deadline')); }, 15000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    for (const [stream, chunks] of [[child.stdout, stdout], [child.stderr, stderr]]) stream.on('data', part => {
      if ((bytes += part.length) > 128 * 1024) { child.kill('SIGKILL'); reject(new Error('tree binding output limit')); }
      else chunks.push(part);
    });
    child.once('close', code => { clearTimeout(timer); resolveResult({ code, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() }); });
  });
}
for (const format of ['sha1', 'sha256']) test(`${format}: executable CLI rejects an unreported file before candidate publication, then accepts the permitted twin`, async () => {
  const peer = await nativePeer(format, { tls: true }), root = await mkdtemp(join(tmpdir(), 'fg-bound-cli-'));
  try {
    const changes = intent([replace('src/main.rs', 'fn main() { expected(); }\n')]);
    const draft = await buildSourceChanges(peer.fixture.bytes, peer.fixture.expected, changes);
    const selection = peer.selection(draft.manifest.effects.map(row => row.path_hex));
    for (const [name, bytes] of [['package', peer.fixture.bytes], ['expect', canonical(peer.fixture.expected)], ['changes', canonical(changes)],
      ['selection', canonical(selection)], ['token', Buffer.from(TOKEN)], ['ca', peer.ca]]) await writeFile(join(root, name), bytes, { mode: 0o600 });
    const common = ['--package', join(root, 'package'), '--expect', join(root, 'expect'), '--changes', join(root, 'changes')];
    const drafted = await cli(['draft', ...common, '--output', join(root, 'draft')]);
    assert.equal(drafted.code, 0, drafted.stderr); const receipt = JSON.parse(drafted.stdout);
    assert.equal(receipt.expected_tree, draft.tree.afterTree);
    const args = ['prepare', ...common, '--selection', join(root, 'selection'), '--token-file', join(root, 'token'),
      '--ca-file', join(root, 'ca'), '--confirm-draft-sha256', receipt.manifest_sha256, '--output', join(root, 'candidate')];
    peer.fault = 'unreported-addition'; const bad = await cli(args);
    assert.equal(bad.code, 2); assert.equal(JSON.parse(bad.stderr).code, 'source_changes_candidate_tree');
    await assert.rejects(lstat(join(root, 'candidate')), { code: 'ENOENT' }); assert.equal(peer.applies, 0);
    peer.fault = null; const good = await cli(args);
    assert.equal(good.code, 0, good.stderr); const saved = JSON.parse(good.stdout);
    assert.equal(saved.binding.expected_tree, receipt.expected_tree); assert.equal(saved.binding.candidate_root_matches_exact_effects, true);
    await peer.close();
    const replay = await cli(['inspect-candidate', ...common, '--candidate', join(root, 'candidate'), '--sha256', saved.manifest_sha256,
      '--confirm-draft-sha256', receipt.manifest_sha256]);
    assert.equal(replay.code, 0, replay.stderr); assert.deepEqual(JSON.parse(replay.stdout).binding, saved.binding);
    assert.deepEqual(peer.failures, []);
  } finally { await peer.close(); await rm(root, { recursive: true, force: true }); }
});
