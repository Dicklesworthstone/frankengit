// Complete CLI/files/socket composition. Peers are not the Rust server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, writeFile, readFile, rm, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { changeFixture, hexPath } from './source_changes_fixture.mjs';
import { selectSource, withParent } from './source_replay_fixture.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { createSourceWorkspace, localPath } from '../operator/source_workspace.mjs';
import { captureWorkspaceChanges } from '../operator/source_workspace_changes.mjs';
import { prepareSourceChanges } from '../operator/source_changes_prepare.mjs';
import { replaySourceChanges } from '../operator/source_replay.mjs';
const PROFILE = 'bounded-line-hunks-v1';
const write = async (path, bytes) => { await writeFile(path, bytes, { mode: 0o600 }); await chmod(path, 0o600); };
async function privateRoot(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-hunk-pipeline-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true })); return root;
}
async function cli(name, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL(`../${name}`, import.meta.url)), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [], err = []; let bytes = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('multi-hunk CLI deadline')); }, 20000);
    for (const [stream, chunks] of [[child.stdout, out], [child.stderr, err]]) stream.on('data', b => {
      if ((bytes += b.length) > 262144) { child.kill('SIGKILL'); reject(new Error('output overflow')); } else chunks.push(b);
    });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
  });
}
function ok(result) { assert.equal(result.code, 0, result.stderr); assert.equal(result.signal, null); return JSON.parse(result.stdout); }
for (const format of ['sha1', 'sha256']) {
  test(`${format}: large two-hunk workspace capture reaches explicit stage and original-key recovery`, async t => {
    const root = await privateRoot(t), before = Buffer.from('unchanged line\n'.repeat(65500));
    const binary = format === 'sha256'; if (binary) before[0] = 0;
    const after = Buffer.from(before); Buffer.from('different line').copy(after, 15 * 10); Buffer.from('different line').copy(after, 15 * 65480);
    const peer = await nativePeer(format, { files: [{ path: 'file', bytes: before }], tls: binary }); t.after(peer.close);
    const f = peer.fixture, workspace = join(root, 'workspace'), capture = join(root, 'capture');
    const source = join(root, 'source.json'), expected = join(root, 'expected.json'), paths = join(root, 'paths.json');
    await write(source, f.bytes); await write(expected, canonical(f.expected));
    await write(paths, canonical({ paths_hex: [hexPath('file')], patch_profile: PROFILE, ...(binary ? { byte_profile: 'binary-safe-v1' } : {}) }));
    const created = ok(await cli('fg_source_workspace.mjs', ['create', '--package', source, '--expect', expected, '--output', workspace]));
    await write(localPath(workspace, hexPath('file')), after);
    const captured = ok(await cli('fg_source_workspace.mjs', ['capture', '--workspace', workspace, '--sha256', created.workspace_sha256, '--paths', paths, '--output', capture]));
    assert.equal(captured.patch_profile, PROFILE); assert.ok((await readFile(join(capture, 'patch.diff'))).length < 700);
    const draft = JSON.parse(await readFile(join(capture, 'draft.json'))); assert.equal(draft.effects[0].hunks, 2);
    ok(await cli('fg_source_workspace.mjs', ['inspect-capture', '--capture', capture, '--sha256', captured.capture_sha256]));
    const token = join(root, 'token'), rotated = join(root, 'rotated'), target = join(root, 'selection.json'), ca = join(root, 'ca.pem');
    await write(token, TOKEN); await write(rotated, ROTATED_TOKEN); await write(target, canonical(peer.selection([hexPath('file')])));
    if (peer.ca) await write(ca, peer.ca); const net = peer.ca ? ['--ca-file', ca] : [];
    const candidate = join(root, 'candidate'), journal = join(root, 'journal');
    const inputs = ['--package', join(capture, 'source.json'), '--expect', join(capture, 'expected.json'), '--changes', join(capture, 'changes.json'), '--selection', target];
    const wrong = await cli('fg_source_changes.mjs', ['prepare', ...inputs, '--confirm-draft-sha256', '1'.repeat(64), '--token-file', token, '--output', candidate, ...net]);
    assert.equal(wrong.code, 2); assert.equal(peer.requests.length, 0); await assert.rejects(lstat(candidate), { code: 'ENOENT' });
    const consent = ['--confirm-draft-sha256', captured.draft_sha256];
    const prepared = ok(await cli('fg_source_changes.mjs', ['prepare', ...inputs, ...consent, '--token-file', token, '--output', candidate, ...net]));
    assert.equal(prepared.binding.patch_profile, PROFILE); assert.equal(prepared.binding.expected_tree, captured.expected_tree);
    assert.deepEqual(peer.candidate.patch, await readFile(join(capture, 'patch.diff')));
    const staged = ok(await cli('fg_source_changes.mjs', ['stage', ...inputs, ...consent, '--candidate', candidate, '--sha256', prepared.manifest_sha256,
      '--principal', PRINCIPAL, '--confirm-candidate', prepared.candidate_commit, '--journal', journal]));
    assert.equal(staged.binding.patch_profile, PROFILE); assert.equal(staged.transmission_attempted, false);
    for (const path of [workspace, capture, candidate]) await rm(path, { recursive: true }); await rm(source); await rm(expected);
    peer.lostApply = true;
    const applied = await cli('fg_source_edit.mjs', ['apply', '--journal', journal, '--request-sha256', staged.request_sha256, '--token-file', token, ...net]);
    assert.equal(applied.code, 3, applied.stderr);
    const recovered = ok(await cli('fg_source_edit.mjs', ['recover', '--journal', journal, '--request-sha256', staged.request_sha256, '--token-file', rotated, ...net]));
    assert.equal(recovered.key, staged.key); assert.equal(peer.applies, 1); assert.equal(recovered.decision.decision_sequence, '18446744073709551615');
    assert.equal(recovered.submission_retried, false); assert.deepEqual(peer.failures, []);
  });
  test(`${format}: multi-hunk replay preserves exact patch and selected read-set while requiring new consent`, async () => {
    const before = 'old\n' + 'same\n'.repeat(30) + 'end\n', after = 'new\n' + 'same\n'.repeat(30) + 'END\n';
    const source = extra => changeFixture(format, [{ path: 'file', bytes: before }, { path: 'other', bytes: extra }]);
    const original = selectSource(source('original'), ['file']), next = selectSource(withParent(source('advanced'), original.commit), ['file']);
    const changes = { schema: 'frankengit-source-changes-v1', patch_profile: PROFILE, changes: [{ path_hex: hexPath('file'), operation: 'replace', content_utf8: after }] };
    const draft = await buildSourceChanges(original.bytes, original.expected, changes), confirmed = sha256(canonical(draft.manifest));
    const replay = await replaySourceChanges(original.bytes, original.expected, changes, next.bytes, next.expected, { confirmDraftSha256: confirmed });
    assert.deepEqual(replay.draft.bytes, draft.bytes); assert.equal(replay.draft.manifest.effects[0].hunks, 2);
    assert.equal(replay.next.changes.patch_profile, PROFILE); assert.notEqual(replay.receipt.draft_sha256, confirmed);
    assert.equal(replay.receipt.new_review_required, true); assert.notEqual(replay.draft.tree.afterTree, draft.tree.afterTree);
  });
  test(`${format}: self-consistent hidden changes are still refused with a multi-hunk candidate`, async t => {
    const before = 'old\n' + 'same\n'.repeat(20) + 'end\n', after = 'new\n' + 'same\n'.repeat(20) + 'END\n';
    const peer = await nativePeer(format, { files: [{ path: 'file', bytes: before }] }); t.after(peer.close);
    const f = peer.fixture, changes = { schema: 'frankengit-source-changes-v1', patch_profile: PROFILE,
      changes: [{ path_hex: hexPath('file'), operation: 'replace', content_utf8: after }] };
    const draft = await buildSourceChanges(f.bytes, f.expected, changes), opts = { confirmDraftSha256: sha256(canonical(draft.manifest)) };
    peer.fault = 'unreported-addition';
    await assert.rejects(prepareSourceChanges(f.bytes, f.expected, changes, peer.selection([hexPath('file')]), TOKEN, opts), /candidate_tree/);
    peer.fault = null;
    assert.equal((await prepareSourceChanges(f.bytes, f.expected, changes, peer.selection([hexPath('file')]), TOKEN, opts)).binding.candidate_root_matches_exact_effects, true);
    assert.deepEqual(peer.failures, []);
  });
}
test('diff budget refusal leaves no workspace capture slot and an explicitly chosen alternative remains usable', async t => {
  const root = await privateRoot(t), before = Array.from({ length: 129 }, (_, i) => `a${i}\n`).join(''), after = before.replaceAll('a', 'b');
  const f = changeFixture('sha1', [{ path: 'file', bytes: before }]), workspace = join(root, 'workspace'), output = join(root, 'capture');
  const saved = await createSourceWorkspace(workspace, f.bytes, f.expected); await write(localPath(workspace, hexPath('file')), after);
  await assert.rejects(captureWorkspaceChanges(workspace, saved.workspace_sha256, { paths_hex: [hexPath('file')], patch_profile: PROFILE }, output), { code: 'source_patch_diff_distance_limit' });
  await assert.rejects(lstat(output), { code: 'ENOENT' });
  const captured = await captureWorkspaceChanges(workspace, saved.workspace_sha256, { paths_hex: [hexPath('file')], patch_profile: 'trim-common-lines-v1' }, output);
  assert.equal(captured.patch_profile, 'trim-common-lines-v1');
});
