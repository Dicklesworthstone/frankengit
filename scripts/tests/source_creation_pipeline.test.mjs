// Real external-client composition with native-schema HTTP/TLS peers. The peer
// uses installed Git only to build/check fixtures, not as a production engine.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { prepareSourceChanges, verifySourceChangeCandidate } from '../operator/source_changes_prepare.mjs';
import { captureSourceEdit, validateSourceEdit } from '../operator/source_edit_candidate.mjs';
import { saveSourceEdit, loadSourceEdit, stageSourceApply, dispatchSourceApply, recoverSourceApply, inspectSourceApply } from '../operator/source_edit_publish.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
import { intent, replace, hexPath, changeFixture } from './source_changes_fixture.mjs';
const create = (path, text, executable = false) => ({ path_hex: hexPath(path), operation: 'create', content_utf8: text, executable });
async function basis(peer, changes) {
  const f = peer.fixture, draft = await buildSourceChanges(f.bytes, f.expected, changes);
  return { changes, draft, selection: peer.selection(draft.manifest.effects.map(e => e.path_hex)),
    options: { confirmDraftSha256: sha256(canonical(draft.manifest)) } };
}
const prepare = (peer, b, extra = {}) => prepareSourceChanges(peer.fixture.bytes, peer.fixture.expected, b.changes, b.selection, TOKEN, { ...b.options, ...extra });
function run(args) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, [resolve('scripts/fg_source_changes.mjs'), ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NODE_OPTIONS: '' } });
    const stdout = [], stderr = []; let total = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('creation CLI deadline')); }, 15000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    for (const [stream, chunks] of [[child.stdout, stdout], [child.stderr, stderr]]) stream.on('data', b => {
      if ((total += b.length) > 128 * 1024) { child.kill('SIGKILL'); reject(new Error('creation CLI output limit')); }
      else chunks.push(b);
    });
    child.once('close', code => { clearTimeout(timer); resolveResult({ code, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() }); });
  });
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: created files survive prepare, offline inspection and original-key lost-reply recovery`, async () => {
    const peer = await nativePeer(format), root = await mkdtemp(join(tmpdir(), 'fg-create-pipeline-'));
    try {
      const changes = intent([create('src/added.rs', 'pub fn added() {}\n'), create('tools/bin/check', '#!/bin/sh\necho verified\n', true),
        create('empty-new', ''), replace('src/main.rs', 'fn main() { new(); }\n')]);
      const b = await basis(peer, changes), result = await prepare(peer, b);
      assert.equal(result.binding.created_path_count, 3); assert.equal(result.binding.creation_absence_independently_verified, true);
      assert.equal(result.binding.publication_authorized, false);
      const expectedTree = changeFixture(format, [
        ...peer.fixture.files.map(f => ({ path: f.path, bytes: f.path.equals(Buffer.from('src/main.rs')) ? 'fn main() { new(); }\n' : f.bytes, mode: f.mode })),
        { path: 'src/added.rs', bytes: 'pub fn added() {}\n' }, { path: 'tools/bin/check', bytes: '#!/bin/sh\necho verified\n', mode: 0o100755 }, { path: 'empty-new', bytes: '' },
      ]).tree;
      assert.equal(peer.candidate.tree, expectedTree);
      assert.deepEqual(result.capture.preparation.paths.filter(p => p.old_blob === null).map(p => p.path_hex).sort(),
        ['src/added.rs', 'tools/bin/check', 'empty-new'].map(hexPath).sort());
      const candidate = join(root, 'candidate'), saved = await saveSourceEdit(candidate, result.capture, result.bundle);
      const loaded = await loadSourceEdit(candidate, saved.manifest_sha256);
      const verified = await verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, changes, loaded.capture, loaded.bundle, b.options);
      assert.deepEqual(verified.binding, result.binding);
      const journal = join(root, 'journal'), staged = await stageSourceApply(journal, candidate, saved.manifest_sha256, PRINCIPAL);
      peer.lostApply = true;
      await assert.rejects(dispatchSourceApply(journal, staged.request_sha256, TOKEN));
      assert.equal(peer.applies, 1);
      const outcome = await recoverSourceApply(journal, staged.request_sha256, ROTATED_TOKEN);
      assert.equal(outcome.decision.outcome, 'committed'); assert.equal(outcome.decision.decision_sequence, '18446744073709551615');
      assert.equal(outcome.key, staged.key); assert.equal(peer.applies, 1);
      await peer.close();
      assert.equal((await inspectSourceApply(journal, staged.request_sha256)).state, 'terminal');
      assert.deepEqual((await verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, changes, loaded.capture, loaded.bundle, b.options)).binding, verified.binding);
      assert.deepEqual(peer.failures, []);
    } finally { await peer.close(); await rm(root, { recursive: true, force: true }); }
  });
  test(`${format}: self-consistent substitution of a newly created file is refused by intent binding`, async () => {
    const peer = await nativePeer(format, { files: [{ path: 'anchor', bytes: 'root\n' }] });
    try {
      const b = await basis(peer, intent([create('src/main.rs', 'fn main() { intended(); }\n')])); peer.fault = 'wrong-after';
      const internallyValid = await captureSourceEdit(b.selection, b.draft.bytes, TOKEN);
      assert.equal(validateSourceEdit(internallyValid.capture, internallyValid.bundle).candidate_commit, peer.candidate.commit);
      assert.equal(internallyValid.capture.inspection.comparison.entries[0].before, null);
      await assert.rejects(verifySourceChangeCandidate(peer.fixture.bytes, peer.fixture.expected, b.changes,
        internallyValid.capture, internallyValid.bundle, b.options), { code: 'source_changes_candidate_effects' });
      await assert.rejects(prepare(peer, b), { code: 'source_changes_candidate_effects' });
      peer.fault = null; assert.equal((await prepare(peer, b)).binding.created_path_count, 1);
      assert.deepEqual(peer.failures, []);
    } finally { await peer.close(); }
  });
  test(`${format}: actual private-file CLI drafts, prepares and replays an empty executable creation`, async () => {
    const peer = await nativePeer(format, { tls: true }), root = await mkdtemp(join(tmpdir(), 'fg-create-cli-'));
    try {
      const b = await basis(peer, intent([create('src/empty-tool', '', true)]));
      for (const [name, value] of [['package', peer.fixture.bytes], ['expect', canonical(peer.fixture.expected)], ['changes', canonical(b.changes)],
        ['selection', canonical(b.selection)], ['token', Buffer.from(TOKEN)], ['ca', peer.ca]]) await writeFile(join(root, name), value, { mode: 0o600 });
      const common = ['--package', join(root, 'package'), '--expect', join(root, 'expect'), '--changes', join(root, 'changes')];
      const drafted = await run(['draft', ...common, '--output', join(root, 'draft')]);
      assert.equal(drafted.code, 0, drafted.stderr); const receipt = JSON.parse(drafted.stdout);
      assert.equal(receipt.created_path_count, 1); assert.equal(receipt.manifest_sha256, b.options.confirmDraftSha256);
      assert.equal((await stat(join(root, 'draft/manifest.json'))).mode & 0o777, 0o600);
      const manifest = JSON.parse(await readFile(join(root, 'draft/manifest.json')));
      assert.equal(manifest.creation_preconditions.paths[0].pathHex, hexPath('src/empty-tool'));
      assert.equal(peer.requests.length, 0);
      const prepared = await run(['prepare', ...common, '--selection', join(root, 'selection'), '--token-file', join(root, 'token'),
        '--ca-file', join(root, 'ca'), '--confirm-draft-sha256', receipt.manifest_sha256, '--output', join(root, 'candidate')]);
      assert.equal(prepared.code, 0, prepared.stderr); const capture = JSON.parse(prepared.stdout);
      assert.equal(capture.binding.creation_absence_independently_verified, true); assert.equal(capture.binding.created_path_count, 1);
      assert.deepEqual(peer.requests.map(r => r.route), ['source/prepare', 'source/inspect']);
      await peer.close();
      const replayed = await run(['inspect-candidate', ...common, '--candidate', join(root, 'candidate'), '--sha256', capture.manifest_sha256,
        '--confirm-draft-sha256', receipt.manifest_sha256]);
      assert.equal(replayed.code, 0, replayed.stderr); assert.deepEqual(JSON.parse(replayed.stdout).binding, capture.binding);
      assert.deepEqual(peer.failures, []);
    } finally { await peer.close(); await rm(root, { recursive: true, force: true }); }
  });
}
test('changed creation path, mode or content invalidates draft consent before any native request', async () => {
  const peer = await nativePeer();
  try {
    const b = await basis(peer, intent([create('src/new', 'correct\n')]));
    for (const mutate of [r => { r.path_hex = hexPath('src/other'); }, r => { r.executable = true; }, r => { r.content_utf8 = 'wrong\n'; }]) {
      const changed = structuredClone(b); mutate(changed.changes.changes[0]);
      await assert.rejects(prepare(peer, changed), { code: 'source_changes_confirmation' });
    }
    assert.equal(peer.requests.length, 0);
    const collision = structuredClone(b); collision.changes.changes[0].path_hex = hexPath('src/main.rs');
    await assert.rejects(prepare(peer, collision), /already exists/); assert.equal(peer.requests.length, 0);
    assert.equal((await prepare(peer, b)).binding.created_path_count, 1);
  } finally { await peer.close(); }
});
test('one creation operation owns cancellation and deadline across native preparation', async () => {
  const peer = await nativePeer();
  try {
    const b = await basis(peer, intent([create('new', 'new\n')])); peer.held = true;
    await assert.rejects(prepare(peer, b, { timeoutMs: 80 }), error => ['source_edit_timeout', 'source_edit_transport'].includes(error.code));
    const controller = new AbortController(), pending = prepare(peer, b, { signal: controller.signal });
    const timer = setTimeout(() => controller.abort(), 30);
    try { await assert.rejects(pending, error => error.name === 'AbortError' || error.code === 'source_edit_cancelled'); }
    finally { clearTimeout(timer); }
    assert.equal(peer.applies, 0); peer.held = false;
    assert.equal((await prepare(peer, b)).binding.created_path_count, 1);
  } finally { await peer.close(); }
});
