// Binary files through actual private workspaces and operator CLI consumers.
// HTTP/TLS peers are native-schema fixtures backed by test-only Git, not Rust fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, chmod, rm, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { changeFixture, hexPath, intent } from './source_changes_fixture.mjs';
import { selectSource, withParent } from './source_replay_fixture.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
import { createSourceWorkspace, localPath } from '../operator/source_workspace.mjs';
import { collectWorkspaceChanges, captureWorkspaceChanges, inspectWorkspaceChangeCapture } from '../operator/source_workspace_changes.mjs';
import { buildSourceChanges, canonical, sha256, BINARY_CHANGE_PROFILE } from '../operator/source_changes.mjs';
import { prepareSourceChanges, verifySourceChangeCandidate } from '../operator/source_changes_prepare.mjs';
import { captureSourceEdit } from '../operator/source_edit_candidate.mjs';
import { replaySourceChanges } from '../operator/source_replay.mjs';
import { captureSourceReplay, loadSourceReplay } from '../operator/source_replay_capture.mjs';

const script = name => fileURLToPath(new URL(`../${name}`, import.meta.url));
const profile = { byte_profile: BINARY_CHANGE_PROFILE };
const binary = rows => ({ ...intent(rows), ...profile });
const pathSelection = paths => ({ paths_hex: paths.map(hexPath), ...profile });
const write = async (path, bytes) => { await writeFile(path, bytes, { mode: 0o600 }); await chmod(path, 0o600); };
const absent = path => assert.rejects(lstat(path), { code: 'ENOENT' });
async function privateRoot(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-binary-pipeline-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true })); return root;
}
async function cli(name, args) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, [script(name), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [], stderr = []; let size = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Binary CLI deadline')); }, 15000);
    for (const [stream, target] of [[child.stdout, stdout], [child.stderr, stderr]]) stream.on('data', part => {
      size += part.length;
      if (size > 262144) { child.kill('SIGKILL'); reject(new Error('Binary CLI output budget')); } else target.push(part);
    });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolveResult({ code, signal,
      stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }); });
  });
}
function success(reply) { assert.equal(reply.code, 0, reply.stderr); assert.equal(reply.signal, null); return JSON.parse(reply.stdout); }
async function workspace(t, format = 'sha1', files = [{ path: 'a.bin', bytes: Buffer.from([0, 1, 255]) }, { path: 'text', bytes: 'before\n' }]) {
  const root = await privateRoot(t), f = changeFixture(format, files), directory = join(root, 'workspace');
  const saved = await createSourceWorkspace(directory, f.bytes, f.expected);
  return { root, f, directory, hash: saved.workspace_sha256 };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: actual CLI binary workspace capture reaches stage and original-key lost-reply recovery`, async t => {
    const files = [{ path: 'asset.bin', bytes: Buffer.from([0, 1, 255, 13, 10, 2]) },
      { path: 'old.bin', bytes: Buffer.from([0, 3]) }, { path: 'text', bytes: 'before\n' }];
    const root = await privateRoot(t), peer = await nativePeer(format, { files, tls: format === 'sha256' }); t.after(peer.close);
    const f = peer.fixture, source = join(root, 'source.json'), expected = join(root, 'expected.json');
    const token = join(root, 'token'), rotated = join(root, 'rotated'), ca = join(root, 'ca.pem');
    await write(source, f.bytes); await write(expected, canonical(f.expected));
    await write(token, TOKEN); await write(rotated, ROTATED_TOKEN); if (peer.ca) await write(ca, peer.ca);
    const directory = join(root, 'workspace');
    const created = success(await cli('fg_source_workspace.mjs', ['create', '--package', source, '--expect', expected, '--output', directory]));
    const after = Buffer.from([0, 254, 0, 13, 10, 255]);
    await write(localPath(directory, hexPath('asset.bin')), after);
    await rm(localPath(directory, hexPath('old.bin')));
    await mkdir(join(directory, 'files', 'new'), { mode: 0o700 });
    await write(join(directory, 'files', 'new', 'data.bin'), Buffer.from([0, 0, 255]));
    const paths = join(root, 'paths.json'); await write(paths, canonical(pathSelection(['asset.bin', 'old.bin', 'new/data.bin'])));
    const output = join(root, 'capture');
    const captured = success(await cli('fg_source_workspace.mjs', ['capture', '--workspace', directory,
      '--sha256', created.workspace_sha256, '--paths', paths, '--output', output]));
    assert.equal(captured.byte_profile, BINARY_CHANGE_PROFILE);
    const changesPath = join(output, 'changes.json'), changes = JSON.parse(await readFile(changesPath));
    assert.equal(changes.byte_profile, BINARY_CHANGE_PROFILE); assert.equal((await readFile(join(output, 'patch.diff'))).includes(0), true);
    await rm(directory, { recursive: true });
    const inspected = success(await cli('fg_source_workspace.mjs', ['inspect-capture', '--capture', output, '--sha256', captured.capture_sha256]));
    assert.equal(inspected.offline_recomputed, true); assert.equal(inspected.byte_profile, BINARY_CHANGE_PROFILE);
    const draft = await buildSourceChanges(f.bytes, f.expected, changes);
    const selection = peer.selection(draft.manifest.effects.map(row => row.path_hex)), target = join(root, 'target.json'); await write(target, canonical(selection));
    const candidatePath = join(root, 'candidate'), journal = join(root, 'journal');
    const common = ['--package', join(output, 'source.json'), '--expect', join(output, 'expected.json'), '--changes', changesPath,
      '--selection', target, '--confirm-draft-sha256', captured.draft_sha256];
    // Exercise the native binary-summary branch, with no body disclosure. Exact
    // object identities and independently computed root, not this prose, bind it.
    peer.onRequest = route => {
      if (route === 'source/inspect') for (const entry of peer.candidate.inspection.comparison.entries) entry.content = {
        type: 'binary', before_bytes: entry.before ? f.files.find(file => file.path.toString('hex') === entry.path_hex).bytes.length : 0,
        after_bytes: entry.after ? (entry.path_hex === hexPath('asset.bin') ? after.length : 3) : 0, body_included: false };
    };
    const net = peer.ca ? ['--ca-file', ca] : [];
    const prepared = success(await cli('fg_source_changes.mjs', ['prepare', ...common, '--token-file', token, '--output', candidatePath, ...net]));
    assert.equal(prepared.binding.byte_profile, BINARY_CHANGE_PROFILE);
    assert.equal(prepared.binding.expected_tree, captured.expected_tree);
    assert.deepEqual(peer.candidate.patch, draft.bytes);
    const staged = success(await cli('fg_source_changes.mjs', ['stage', ...common, '--candidate', candidatePath,
      '--sha256', prepared.manifest_sha256, '--principal', PRINCIPAL, '--confirm-candidate', prepared.candidate_commit, '--journal', journal]));
    assert.equal(staged.binding.byte_profile, BINARY_CHANGE_PROFILE); assert.equal(staged.transmission_attempted, false);
    await rm(output, { recursive: true }); await rm(candidatePath, { recursive: true }); await rm(source); await rm(expected);
    peer.lostApply = true;
    const applied = await cli('fg_source_edit.mjs', ['apply', '--journal', journal, '--request-sha256', staged.request_sha256, '--token-file', token, ...net]);
    assert.equal(applied.code, 3, applied.stderr);
    const recovered = success(await cli('fg_source_edit.mjs', ['recover', '--journal', journal, '--request-sha256', staged.request_sha256, '--token-file', rotated, ...net]));
    assert.equal(recovered.key, staged.key); assert.equal(recovered.decision.outcome, 'committed');
    assert.equal(recovered.decision.decision_sequence, '18446744073709551615'); assert.equal(peer.applies, 1);
    assert.equal(recovered.submission_retried, false); assert.deepEqual(peer.failures, []);
    const count = peer.requests.length;
    success(await cli('fg_source_edit.mjs', ['recover', '--journal', journal, '--request-sha256', staged.request_sha256, '--token-file', rotated, ...net]));
    assert.equal(peer.requests.length, count);
  });
  test(`${format}: default capture refuses changed binary before reserving output; opt-in owns exact bytes`, async t => {
    const s = await workspace(t, format), output = join(s.root, 'capture');
    await write(localPath(s.directory, hexPath('a.bin')), Buffer.from([0, 2, 255]));
    await assert.rejects(captureWorkspaceChanges(s.directory, s.hash, { paths_hex: [hexPath('a.bin')] }, output), /source_changes_binary_unsupported/);
    await absent(output);
    const input = pathSelection(['a.bin']), pending = captureWorkspaceChanges(s.directory, s.hash, input, output);
    input.byte_profile = 'invalid'; input.paths_hex[0] = hexPath('text');
    const result = await pending; assert.equal(result.byte_profile, BINARY_CHANGE_PROFILE);
    const changes = JSON.parse(await readFile(join(output, 'changes.json')));
    assert.equal(changes.changes[0].content_hex, '0002ff');
    assert.equal(changes.changes[0].path_hex, hexPath('a.bin'));
    assert.equal((await inspectWorkspaceChangeCapture(output, result.capture_sha256)).byte_profile, BINARY_CHANGE_PROFILE);
  });
  test(`${format}: existing default capture skips unchanged binary and remains profile-free`, async t => {
    const s = await workspace(t, format); await write(localPath(s.directory, hexPath('text')), 'after\n');
    const result = await collectWorkspaceChanges(s.directory, s.hash, { paths_hex: s.f.expected.files.map(row => row.pathHex) });
    assert.equal(result.changes.changes.length, 1); assert.equal(result.changes.changes[0].path_hex, hexPath('text'));
    assert.equal(Object.hasOwn(result.changes, 'byte_profile'), false);
    assert.equal(Object.hasOwn(result.manifest, 'byte_profile'), false);
    assert.equal(Object.hasOwn(result.draft.manifest, 'byte_profile'), false);
    const opted = await collectWorkspaceChanges(s.directory, s.hash, pathSelection(['a.bin', 'text']));
    assert.deepEqual(opted.draft.bytes, result.draft.bytes);
    assert.notEqual(sha256(canonical(opted.draft.manifest)), sha256(canonical(result.draft.manifest)));
  });
  test(`${format}: profile consent cannot be downgraded before preparation even with an unchanged NUL-free patch`, async t => {
    const peer = await nativePeer(format, { files: [{ path: 'a', bytes: 'old' }] }); t.after(peer.close);
    const f = peer.fixture, rows = [{ path_hex: '61', operation: 'replace', content_utf8: 'new' }];
    const previous = await buildSourceChanges(f.bytes, f.expected, intent(rows)), next = await buildSourceChanges(f.bytes, f.expected, binary(rows));
    const selection = peer.selection(['61']);
    await assert.rejects(prepareSourceChanges(f.bytes, f.expected, binary(rows), selection, TOKEN,
      { confirmDraftSha256: sha256(canonical(previous.manifest)) }), /source_changes_confirmation/);
    assert.equal(peer.requests.length, 0);
    const candidate = await prepareSourceChanges(f.bytes, f.expected, binary(rows), selection, TOKEN,
      { confirmDraftSha256: sha256(canonical(next.manifest)) });
    assert.equal(candidate.binding.byte_profile, BINARY_CHANGE_PROFILE);
    await assert.rejects(verifySourceChangeCandidate(f.bytes, f.expected, intent(rows), candidate.capture, candidate.bundle,
      { confirmDraftSha256: sha256(canonical(next.manifest)) }), /source_changes_confirmation/);
  });
  test(`${format}: binary-safe candidate root verification still rejects self-consistent hidden changes`, async t => {
    const peer = await nativePeer(format, { files: [{ path: 'a', bytes: Buffer.from([0, 1]) }] }); t.after(peer.close);
    const f = peer.fixture, changes = binary([{ path_hex: '61', operation: 'replace', content_hex: '0002' }]);
    const draft = await buildSourceChanges(f.bytes, f.expected, changes), options = { confirmDraftSha256: sha256(canonical(draft.manifest)) };
    peer.fault = 'unreported-addition';
    const wrong = await captureSourceEdit(peer.selection(['61']), draft.bytes, TOKEN);
    await assert.rejects(verifySourceChangeCandidate(f.bytes, f.expected, changes, wrong.capture, wrong.bundle, options), /source_changes_candidate_tree/);
    peer.fault = null;
    assert.equal((await prepareSourceChanges(f.bytes, f.expected, changes, peer.selection(['61']), TOKEN, options)).binding.candidate_root_matches_exact_effects, true);
  });
  test(`${format}: binary profile survives two-base replay capture and reopening with fresh consent`, async t => {
    const root = await privateRoot(t), selected = [{ path: 'a.bin', bytes: Buffer.from([0, 1, 255]) }];
    const old = selectSource(changeFixture(format, [...selected, { path: 'other', bytes: 'old' }]), ['a.bin']);
    const next = selectSource(withParent(changeFixture(format, [...selected, { path: 'other', bytes: 'new' }]), old.commit), ['a.bin']);
    const changes = binary([{ path_hex: hexPath('a.bin'), operation: 'replace', content_hex: '0002ff' }]);
    const draft = await buildSourceChanges(old.bytes, old.expected, changes), options = { confirmDraftSha256: sha256(canonical(draft.manifest)) };
    const replay = await replaySourceChanges(old.bytes, old.expected, changes, next.bytes, next.expected, options);
    assert.deepEqual(replay.draft.bytes, draft.bytes); assert.equal(replay.next.changes.byte_profile, BINARY_CHANGE_PROFILE);
    assert.notEqual(replay.receipt.draft_sha256, options.confirmDraftSha256);
    const output = join(root, 'replay'), saved = await captureSourceReplay(output, old.bytes, old.expected, changes, next.bytes, next.expected, options);
    assert.equal((await loadSourceReplay(output, saved.capture_sha256)).draft.manifest.byte_profile, BINARY_CHANGE_PROFILE);
    for (const [name, bytes] of Object.entries({ 'old.json': old.bytes, 'old-expect.json': canonical(old.expected),
      'next.json': next.bytes, 'next-expect.json': canonical(next.expected), 'input.json': canonical(changes) })) await write(join(root, name), bytes);
    const cliOutput = join(root, 'cli-replay');
    const cliSaved = success(await cli('fg_source_replay.mjs', ['capture', '--package', join(root, 'old.json'), '--expect', join(root, 'old-expect.json'),
      '--changes', join(root, 'input.json'), '--next-package', join(root, 'next.json'), '--next-expect', join(root, 'next-expect.json'),
      '--confirm-draft-sha256', options.confirmDraftSha256, '--output', cliOutput]));
    assert.equal(JSON.parse(await readFile(join(cliOutput, 'changes.json'))).byte_profile, BINARY_CHANGE_PROFILE);
    success(await cli('fg_source_replay.mjs', ['inspect', '--capture', cliOutput, '--sha256', cliSaved.capture_sha256]));
    const changed = selectSource(withParent(changeFixture(format, [{ path: 'a.bin', bytes: Buffer.from([0, 2, 255]) }, { path: 'other', bytes: 'new' }]), old.commit), ['a.bin']);
    await assert.rejects(replaySourceChanges(old.bytes, old.expected, changes, changed.bytes, changed.expected, options), /source_replay_read_set_changed/);
  });
}

test('rehashing all capture payloads cannot detach the binary profile from the explicit path consent', async t => {
  const s = await workspace(t), output = join(s.root, 'capture'); await write(localPath(s.directory, hexPath('a.bin')), Buffer.from([0, 7]));
  const result = await captureWorkspaceChanges(s.directory, s.hash, pathSelection(['a.bin']), output);
  assert.equal((await inspectWorkspaceChangeCapture(output, result.capture_sha256)).offline_recomputed, true);
  const selection = JSON.parse(await readFile(join(output, 'paths.json'))); delete selection.byte_profile;
  await write(join(output, 'paths.json'), canonical(selection));
  const root = JSON.parse(await readFile(join(output, 'manifest.json')));
  for (const row of root.payloads) { const bytes = await readFile(join(output, row.name)); row.sha256 = sha256(bytes); row.bytes = bytes.length; }
  const rewritten = canonical(root); await write(join(output, 'manifest.json'), rewritten);
  await assert.rejects(inspectWorkspaceChangeCapture(output, sha256(rewritten)), /source_workspace_capture_profile/);
});
test('binary-safe mode changes still require consent and capture only explicitly named paths', async t => {
  const s = await workspace(t); await chmod(localPath(s.directory, hexPath('a.bin')), 0o700);
  await write(join(s.directory, 'files', 'unselected-secret'), Buffer.from([0, 99]));
  const result = await collectWorkspaceChanges(s.directory, s.hash, pathSelection(['a.bin']));
  assert.equal(result.changes.changes.length, 1); assert.equal(result.changes.changes[0].executable, true);
  assert.equal(result.draft.manifest.effects[0].hunks, 0); assert.equal(result.draft.manifest.effects[0].old_blob, result.draft.manifest.effects[0].new_blob);
  assert.equal(result.draft.bytes.includes(0), false); assert.equal(result.manifest.unselected_paths_examined, false);
});
test('invalid binary selectors and cancellation cannot reserve capture output', async t => {
  const s = await workspace(t), output = join(s.root, 'capture');
  for (const value of [true, null, 'binary', undefined]) await assert.rejects(captureWorkspaceChanges(s.directory, s.hash,
    { paths_hex: [hexPath('a.bin')], byte_profile: value }, output), /source_changes_byte_profile/);
  const stop = new AbortController(); stop.abort();
  await assert.rejects(captureWorkspaceChanges(s.directory, s.hash, pathSelection(['a.bin']), output, { signal: stop.signal }));
  await absent(output);
  await write(localPath(s.directory, hexPath('a.bin')), Buffer.from([0, 3]));
  assert.ok((await captureWorkspaceChanges(s.directory, s.hash, pathSelection(['a.bin']), output)).capture_sha256);
});
test('competing binary capture creators preserve one complete immutable output', async t => {
  const s = await workspace(t), output = join(s.root, 'capture'); await write(localPath(s.directory, hexPath('a.bin')), Buffer.from([0, 9]));
  const results = await Promise.allSettled([0, 1].map(() => captureWorkspaceChanges(s.directory, s.hash, pathSelection(['a.bin']), output)));
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const saved = results.find(r => r.status === 'fulfilled').value;
  assert.equal((await inspectWorkspaceChangeCapture(output, saved.capture_sha256)).offline_recomputed, true);
});
