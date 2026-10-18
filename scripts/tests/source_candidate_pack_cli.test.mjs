// Executable packed-candidate workflow with real private files/child processes.
// The HTTP peer uses Git as a test oracle; it does not execute the Rust node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, lstat, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { prepareSourceChanges } from '../operator/source_changes_prepare.mjs';
import { saveSourceEdit, inspectSourceApply } from '../operator/source_edit_publish.mjs';
import { createSourceWorkspace } from '../operator/source_workspace.mjs';
import { captureWorkspaceChanges } from '../operator/source_workspace_changes.mjs';
import { main } from '../fg_source_changes.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
import { hexPath, intent } from './source_changes_fixture.mjs';
const CLI = new URL('../fg_source_changes.mjs', import.meta.url).pathname;
const EDIT = new URL('../fg_source_edit.mjs', import.meta.url).pathname;
const absent = async path => assert.rejects(lstat(path), { code: 'ENOENT' });
function launch(args, executable = CLI) {
  const child = spawn(process.execPath, [executable, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  const done = new Promise((resolve, reject) => {
    const stdout = [], stderr = []; let size = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('CLI did not settle')); }, 20000);
    child.once('error', e => { clearTimeout(timer); reject(e); });
    for (const [stream, out] of [[child.stdout, stdout], [child.stderr, stderr]]) stream.on('data', chunk => {
      if ((size += chunk.length) > 131072) { child.kill('SIGKILL'); clearTimeout(timer); reject(new Error('CLI output overflow')); }
      else out.push(chunk);
    });
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal,
      stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() }); });
  });
  return { child, done };
}
const cli = (args, executable) => launch(args, executable).done;
const success = response => { assert.equal(response.code, 0, response.stderr); assert.equal(response.signal, null); return JSON.parse(response.stdout); };
async function setup(t, format = 'sha1', config = {}) {
  const peer = await nativePeer(format, { nativePatchBundle: true, ...config });
  const root = await mkdtemp(join(tmpdir(), 'fg-pack-cli-'));
  t.after(async () => { await peer.close(); await rm(root, { recursive: true, force: true }); });
  const f = peer.fixture, changes = intent([{ path_hex: hexPath('src/main.rs'), operation: 'replace', content_utf8: 'verified packed file\n' }]);
  const draft = await buildSourceChanges(f.bytes, f.expected, changes), pin = sha256(canonical(draft.manifest));
  const selection = peer.selection(draft.manifest.effects.map(e => e.path_hex));
  const files = { source: join(root, 'source.json'), expect: join(root, 'expect.json'), changes: join(root, 'changes.json'),
    selection: join(root, 'selection.json'), token: join(root, 'token'), ca: join(root, 'ca.pem') };
  for (const [name, bytes] of Object.entries({ source: f.bytes, expect: canonical(f.expected), changes: canonical(changes),
    selection: canonical(selection), token: Buffer.from(TOKEN), ...(peer.ca ? { ca: peer.ca } : {}) })) await writeFile(files[name], bytes, { mode: 0o600 });
  const common = ['--package', files.source, '--expect', files.expect, '--changes', files.changes, '--confirm-draft-sha256', pin];
  const candidatePath = join(root, 'candidate'), journal = join(root, 'journal');
  const prepare = (op = 'prepare-packed', path = candidatePath) => [op, ...common, '--selection', files.selection,
    '--token-file', files.token, '--output', path, ...(peer.ca ? ['--ca-file', files.ca] : [])];
  const inspect = (saved, op = 'inspect-packed', path = candidatePath) => [op, ...common, '--candidate', path, '--sha256', saved.manifest_sha256];
  const stage = (saved, op = 'stage-packed', path = candidatePath, out = journal) => [op, ...common, '--selection', files.selection,
    '--candidate', path, '--sha256', saved.manifest_sha256, '--principal', PRINCIPAL,
    '--confirm-candidate', saved.candidate_commit, '--journal', out];
  return { peer, root, f, changes, draft, pin, selection, files, common, candidatePath, journal, prepare, inspect, stage };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: CLI packed preparation, offline inspection, staging and lost-response recovery`, async t => {
    const s = await setup(t, format, { tls: true });
    const saved = success(await cli(s.prepare()));
    assert.equal(saved.pack_verification.packed_objects_independently_verified, true);
    assert.equal(saved.binding.bundle_objects_independently_verified, true);
    assert.equal(saved.pack_verification.bundle_sha256, saved.bundle_sha256);
    assert.equal(saved.read_metrics.requests, 2); assert.equal(s.peer.requests.length, 2);
    const inspected = success(await cli(s.inspect(saved)));
    assert.equal(inspected.pack_verification.base_closure_verified, false);
    assert.equal(inspected.pack_verification.candidate_commit, saved.candidate_commit);
    const staged = success(await cli(s.stage(saved)));
    assert.equal(staged.pack_verification.candidate_manifest_sha256, saved.manifest_sha256);
    assert.equal(staged.transmission_attempted, false); assert.equal(s.peer.requests.length, 2);
    assert.equal((await lstat(s.journal)).mode & 0o777, 0o700);
    await rm(s.candidatePath, { recursive: true });
    for (const key of ['source', 'expect', 'changes', 'selection']) await rm(s.files[key]);
    s.peer.lostApply = true;
    const args = ['--journal', s.journal, '--request-sha256', staged.request_sha256, '--token-file', s.files.token, '--ca-file', s.files.ca];
    const lost = await cli(['apply', ...args], EDIT);
    assert.equal(lost.code, 3, lost.stderr);
    assert.equal(JSON.parse(lost.stderr).retained_request.key, staged.key);
    await writeFile(s.files.token, ROTATED_TOKEN);
    const recovered = success(await cli(['recover', ...args], EDIT));
    assert.equal(recovered.key, staged.key); assert.equal(recovered.decision.outcome, 'committed');
    assert.equal(recovered.decision.decision_sequence, '18446744073709551615'); assert.equal(s.peer.applies, 1);
    const count = s.peer.requests.length;
    success(await cli(['recover', ...args], EDIT)); assert.equal(s.peer.requests.length, count); assert.deepEqual(s.peer.failures, []);
  });
  test(`${format}: report-consistent corrupt pack is refused by packed inspect/stage, without fallback`, async t => {
    const s = await setup(t, format); const candidate = await prepareSourceChanges(s.f.bytes, s.f.expected, s.changes,
      s.selection, TOKEN, { confirmDraftSha256: s.pin });
    candidate.bundle[candidate.bundle.length - 1] ^= 1;
    const hash = sha256(candidate.bundle); candidate.capture.preparation.bundle.sha256 = hash; candidate.capture.inspection.bundle_sha256 = hash;
    const saved = await saveSourceEdit(s.candidatePath, candidate.capture, candidate.bundle);
    const old = success(await cli(s.inspect(saved, 'inspect-candidate')));
    assert.equal(old.binding.bundle_objects_independently_verified, false); assert.equal(old.pack_verification, undefined);
    for (const args of [s.inspect(saved), s.stage(saved)]) {
      const reply = await cli(args); assert.equal(reply.code, 2, reply.stderr); assert.equal(reply.stdout, '');
      assert.equal(reply.stderr.includes('private server'), false);
    }
    await absent(s.journal); assert.equal(s.peer.requests.length, 2); assert.equal(s.peer.applies, 0);
  });
  test(`${format}: corrupt remote bytes never claim an output candidate in packed preparation`, async t => {
    const s = await setup(t, format);
    s.peer.transformPack = bytes => { const bad = Buffer.from(bytes); bad[bad.length - 1] ^= 1; return bad; };
    const reply = await cli(s.prepare()); assert.equal(reply.code, 2); await absent(s.candidatePath);
    assert.equal(s.peer.requests.length, 2); assert.equal(s.peer.applies, 0);
    delete s.peer.transformPack;
    assert.equal(success(await cli(s.prepare())).pack_verification.exact_object_inventory_verified, true);
  });
  test(`${format}: wrong review and publication target fail before new network or journal effects`, async t => {
    const s = await setup(t, format), args = s.prepare(); args[args.indexOf('--confirm-draft-sha256') + 1] = 'a'.repeat(64);
    assert.equal((await cli(args)).code, 2); assert.equal(s.peer.requests.length, 0); await absent(s.candidatePath);
    const saved = success(await cli(s.prepare()));
    await writeFile(s.files.selection, canonical({ ...s.selection, ref: 'refs/heads/unreviewed' }));
    assert.equal((await cli(s.stage(saved))).code, 2); await absent(s.journal); assert.equal(s.peer.requests.length, 2);
    await writeFile(s.files.selection, canonical(s.selection)); assert.ok(success(await cli(s.stage(saved))).key);
  });
}
test('strict CLI accepts actual workspace captures combining binary and multi-hunk profiles', async t => {
  const s = await setup(t, 'sha256', { files: [{ path: 'src/main.rs', bytes: 'line\n'.repeat(1000), mode: 0o100644 }] });
  const workspace = join(s.root, 'workspace'), made = await createSourceWorkspace(workspace, s.f.bytes, s.f.expected);
  const lines = Array.from({ length: 1000 }, (_, i) => i === 5 || i === 990 ? `binary\0change${i}\n` : 'line\n');
  await writeFile(join(workspace, 'files/src/main.rs'), Buffer.from(lines.join('')));
  const out = join(s.root, 'capture');
  const captured = await captureWorkspaceChanges(workspace, made.workspace_sha256,
    { paths_hex: [hexPath('src/main.rs')], byte_profile: 'binary-safe-v1', patch_profile: 'bounded-line-hunks-v1' }, out);
  const common = ['--package', join(out, 'source.json'), '--expect', join(out, 'expected.json'), '--changes', join(out, 'changes.json'),
    '--confirm-draft-sha256', captured.draft_sha256];
  const saved = success(await cli(['prepare-packed', ...common, '--selection', s.files.selection, '--token-file', s.files.token,
    '--output', s.candidatePath]));
  assert.equal(saved.binding.byte_profile, 'binary-safe-v1'); assert.equal(saved.binding.patch_profile, 'bounded-line-hunks-v1');
  assert.equal(saved.pack_verification.packed_candidate_matches_reviewed_effects, true);
  const inspected = success(await cli(['inspect-packed', ...common, '--candidate', s.candidatePath, '--sha256', saved.manifest_sha256]));
  assert.equal(inspected.pack_verification.expected_tree, saved.pack_verification.expected_tree);
});
test('concurrent strict CLI staging has one create-only winner and no network requests', async t => {
  const s = await setup(t), saved = success(await cli(s.prepare()));
  const results = await Promise.all([cli(s.stage(saved)), cli(s.stage(saved))]);
  assert.deepEqual(results.map(r => r.code).sort(), [0, 2]);
  const winner = JSON.parse(results.find(r => r.code === 0).stdout);
  assert.equal((await inspectSourceApply(s.journal, winner.request_sha256)).key, winner.key);
  assert.equal(s.peer.requests.length, 2); assert.equal(s.peer.applies, 0);
});
test('lost strict staging stdout retains pack evidence and the usable original journal', async t => {
  const s = await setup(t), saved = success(await cli(s.prepare())), errors = [];
  const stdout = new Writable({ write(_b, _e, cb) { cb(new Error('output lost')); } });
  const stderr = new Writable({ write(b, _e, cb) { errors.push(Buffer.from(b)); cb(); } });
  assert.equal(await main(s.stage(saved), { stdout, stderr }), 4);
  const result = JSON.parse(Buffer.concat(errors)).retained_result;
  assert.equal(result.pack_verification.exact_object_inventory_verified, true);
  assert.equal((await inspectSourceApply(result.journal, result.request_sha256)).key, result.key);
  assert.equal(s.peer.requests.length, 2);
});
test('signal during packed preparation drains the request and creates no candidate', async t => {
  const s = await setup(t); s.peer.held = true;
  let child; s.peer.onRequest = () => child.kill('SIGTERM');
  const process = launch(s.prepare()); child = process.child;
  const result = await process.done;
  assert.equal(result.code, 3, result.stderr); assert.equal(result.signal, null); await absent(s.candidatePath);
  assert.equal(s.peer.requests.length, 1); assert.equal(s.peer.applies, 0);
});
test('packed CLI validates required fields, offline grammar and private inputs', async t => {
  const s = await setup(t), saved = success(await cli(s.prepare()));
  for (const args of [[...s.inspect(saved), '--token-file', s.files.token], [...s.stage(saved), '--ca-file', s.files.source],
    [...s.stage(saved), '--force', 'true'], [...s.prepare('prepare-packed', join(s.root, 'next')), '--timeout-ms', '0']]) {
    assert.equal((await cli(args)).code, 2); await absent(s.journal);
  }
  for (const flag of ['--selection', '--principal', '--confirm-candidate', '--confirm-draft-sha256']) {
    const args = s.stage(saved), index = args.indexOf(flag); args.splice(index, 2);
    assert.equal((await cli(args)).code, 2); await absent(s.journal);
  }
  await chmod(s.files.expect, 0o644);
  assert.equal((await cli(s.inspect(saved))).code, 2); await absent(s.journal);
  await chmod(s.files.expect, 0o600); assert.ok(success(await cli(s.stage(saved))).key);
  assert.equal(s.peer.requests.length, 2);
});
