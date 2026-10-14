// Real private files and CLI processes; HTTP responses are native-schema fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, writeFile, readFile, rm, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { changeFixture, hexPath } from './source_changes_fixture.mjs';
import { createSourceWorkspace, localPath } from '../operator/source_workspace.mjs';
import { collectWorkspaceChanges, captureWorkspaceChanges, inspectWorkspaceChangeCapture, workspaceChangeSelection } from '../operator/source_workspace_changes.mjs';
import { canonical, sha256, buildSourceChanges } from '../operator/source_changes.mjs';
import { prepareSourceChanges } from '../operator/source_changes_prepare.mjs';
import { nativePeer, TOKEN } from './source_changes_native_fixture.mjs';
const PROFILE = 'trim-common-lines-v1';
const chosen = { paths_hex: [hexPath('file')], patch_profile: PROFILE };
const write = async (path, bytes) => { await writeFile(path, bytes, { mode: 0o600 }); await chmod(path, 0o600); };
async function privateRoot(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-workspace-profile-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true })); return root;
}
async function setup(t, format, bytes) {
  const root = await privateRoot(t), f = changeFixture(format, [{ path: 'file', bytes }]);
  const path = join(root, 'workspace'), saved = await createSourceWorkspace(path, f.bytes, f.expected);
  return { root, f, path, pin: saved.workspace_sha256 };
}
async function cli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('../fg_source_workspace.mjs', import.meta.url)), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [], stderr = []; let bytes = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('workspace CLI exceeded deadline')); }, 15000);
    for (const [stream, chunks] of [[child.stdout, stdout], [child.stderr, stderr]]) stream.on('data', b => {
      if ((bytes += b.length) > 262144) { child.kill('SIGKILL'); reject(new Error('output limit')); } else chunks.push(b);
    });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() }); });
  });
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: a large-file workspace edit becomes a compact CLI capture and survives workspace removal`, async t => {
    const before = Buffer.from('unchanged line\n'.repeat(65500)), after = Buffer.from(before);
    Buffer.from('different line').copy(after, 15 * 32750);
    const s = await setup(t, format, before); await write(localPath(s.path, hexPath('file')), after);
    const dest = join(s.root, 'capture'), paths = join(s.root, 'paths.json');
    await assert.rejects(captureWorkspaceChanges(s.path, s.pin, { paths_hex: chosen.paths_hex }, dest), /patch_budget/);
    await assert.rejects(lstat(dest), { code: 'ENOENT' });
    await write(paths, canonical(chosen));
    const raw = await cli(['capture', '--workspace', s.path, '--sha256', s.pin, '--paths', paths, '--output', dest]);
    assert.equal(raw.code, 0, raw.stderr); const receipt = JSON.parse(raw.stdout);
    assert.equal(receipt.patch_profile, PROFILE); assert.equal(Object.hasOwn(receipt, 'byte_profile'), false);
    assert.ok((await readFile(join(dest, 'patch.diff'))).length < 512);
    const changes = JSON.parse(await readFile(join(dest, 'changes.json')));
    assert.equal(changes.patch_profile, PROFILE);
    const draft = await buildSourceChanges(s.f.bytes, s.f.expected, changes);
    assert.equal(draft.tree.afterTree, changeFixture(format, [{ path: 'file', bytes: after }]).tree);
    assert.equal(receipt.draft_sha256, sha256(canonical(draft.manifest)));
    await rm(s.path, { recursive: true });
    const inspect = await cli(['inspect-capture', '--capture', dest, '--sha256', receipt.capture_sha256]);
    assert.equal(inspect.code, 0, inspect.stderr); assert.equal(JSON.parse(inspect.stdout).patch_profile, PROFILE);
  });
  test(`${format}: binary consent and patch encoding are independent and both reach the candidate check`, async t => {
    const before = Buffer.from('same\n'.repeat(30) + '\0old\n' + 'tail\n'.repeat(30));
    const after = Buffer.from(before); after[151] = 110;
    const root = await privateRoot(t), peer = await nativePeer(format, { files: [{ path: 'file', bytes: before }] });
    t.after(peer.close);
    const path = join(root, 'workspace'), saved = await createSourceWorkspace(path, peer.fixture.bytes, peer.fixture.expected);
    await write(localPath(path, hexPath('file')), after);
    await assert.rejects(collectWorkspaceChanges(path, saved.workspace_sha256, chosen), /binary_unsupported/);
    const both = { ...chosen, byte_profile: 'binary-safe-v1' };
    const captured = await collectWorkspaceChanges(path, saved.workspace_sha256, both);
    assert.equal(captured.changes.byte_profile, both.byte_profile); assert.equal(captured.changes.patch_profile, PROFILE);
    const old = await collectWorkspaceChanges(path, saved.workspace_sha256, { paths_hex: chosen.paths_hex, byte_profile: both.byte_profile });
    const target = peer.selection(chosen.paths_hex);
    await assert.rejects(prepareSourceChanges(peer.fixture.bytes, peer.fixture.expected, captured.changes, target, TOKEN,
      { confirmDraftSha256: sha256(canonical(old.draft.manifest)) }), /confirmation/);
    assert.equal(peer.requests.length, 0);
    const result = await prepareSourceChanges(peer.fixture.bytes, peer.fixture.expected, captured.changes, target, TOKEN,
      { confirmDraftSha256: sha256(canonical(captured.draft.manifest)) });
    assert.equal(result.binding.patch_profile, PROFILE); assert.equal(result.binding.byte_profile, both.byte_profile);
    assert.deepEqual(peer.candidate.patch, captured.draft.bytes); assert.deepEqual(peer.failures, []);
  });
  test(`${format}: capture owns profile and path values before asynchronous work`, async t => {
    const s = await setup(t, format, 'old\n'); await write(localPath(s.path, hexPath('file')), 'new\n');
    const input = structuredClone(chosen), pending = collectWorkspaceChanges(s.path, s.pin, input);
    input.patch_profile = 'invalid'; input.paths_hex[0] = '00';
    const c = await pending; assert.equal(c.changes.patch_profile, PROFILE);
    assert.equal(c.changes.changes[0].path_hex, hexPath('file'));
  });
}
for (const tamper of ['drop-path-profile', 'add-change-profile', 'change-path-profile']) {
  test(`rehashing payloads cannot substitute selected patch encoding: ${tamper}`, async t => {
    const s = await setup(t, 'sha1', 'old\n'); await write(localPath(s.path, hexPath('file')), 'new\n');
    const dest = join(s.root, 'capture'), selection = tamper === 'add-change-profile' ? { paths_hex: chosen.paths_hex } : chosen;
    const saved = await captureWorkspaceChanges(s.path, s.pin, selection, dest);
    assert.equal((await inspectWorkspaceChangeCapture(dest, saved.capture_sha256)).offline_recomputed, true);
    const name = tamper === 'add-change-profile' ? 'changes.json' : 'paths.json';
    const value = JSON.parse(await readFile(join(dest, name)));
    if (tamper === 'drop-path-profile') delete value.patch_profile;
    else value.patch_profile = tamper === 'add-change-profile' ? PROFILE : 'other-profile';
    await write(join(dest, name), canonical(value));
    const root = JSON.parse(await readFile(join(dest, 'manifest.json')));
    for (const row of root.payloads) { const b = await readFile(join(dest, row.name)); row.sha256 = sha256(b); row.bytes = b.length; }
    const bytes = canonical(root); await write(join(dest, 'manifest.json'), bytes);
    await assert.rejects(inspectWorkspaceChangeCapture(dest, sha256(bytes)), /capture_profile|patch_profile/);
  });
}
test('profile grammar refuses malformed encodings; ordinary capture retains exact omitted-default fields', async t => {
  for (const patch_profile of [undefined, null, false, [], {}, 'compact']) assert.throws(() => workspaceChangeSelection({ ...chosen, patch_profile }), /patch_profile/);
  assert.deepEqual(workspaceChangeSelection({ paths_hex: chosen.paths_hex }), { paths_hex: chosen.paths_hex });
  const s = await setup(t, 'sha1', 'old\n'); await write(localPath(s.path, hexPath('file')), 'new\n');
  const c = await collectWorkspaceChanges(s.path, s.pin, { paths_hex: chosen.paths_hex });
  for (const value of [c.selection, c.changes, c.manifest, c.draft.manifest]) {
    assert.equal(Object.hasOwn(value, 'byte_profile'), false); assert.equal(Object.hasOwn(value, 'patch_profile'), false);
  }
});
