// Actual files and complete production validators. Native HTTP reports remain
// explicit fixtures; gitFixture independently constructs real Git bundles.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, mkdir, chmod, lstat, readdir, rm, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { capturePullCandidate, candidateCanonical, candidateHash } from '../../scripts/operator/pull_candidate_capture.mjs';
import { saveCandidatePackage, loadCandidatePackage, readCandidatePrivate, readCandidateToken, candidateClock } from '../../scripts/operator/pull_candidate_files.mjs';
import { candidatePeer, TOKEN } from './pull_candidate_fixture.mjs';
import { localCapture } from './pull_candidate_package_fixture.mjs';

async function directory(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-candidate-files-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true })); return root;
}
async function saved(t, config = []) {
  const root = await directory(t), result = await localCapture(...config), path = join(root, 'package');
  const receipt = await saveCandidatePackage(path, result.capture, result.bundle);
  return { ...result, root, path, receipt };
}
for (const algorithm of ['sha1', 'sha256']) for (const method of ['merge-commit', 'squash']) {
  test(`${algorithm} ${method}: real acquisition survives private save and offline load`, async t => {
    const p = await candidatePeer(t, { algorithm, method, reviewCount: 51 }), root = await directory(t);
    const result = await capturePullCandidate(p.input, TOKEN), count = p.requests.length;
    const receipt = await saveCandidatePackage(join(root, 'capture'), result.capture, result.bundle);
    const loaded = await loadCandidatePackage(receipt.path, receipt.sha256);
    assert.deepEqual(loaded.capture, result.capture); assert.deepEqual(loaded.bundle, p.fixture.bundle);
    assert.equal(loaded.reviews.length, 51); assert.equal(loaded.artifact.fields.candidate_commit, p.fixture.candidate);
    assert.equal(loaded.capture.inspection.comparison.entries[0].path_hex.endsWith('ff'), true);
    assert.equal(p.requests.length, count); assert.equal(loaded.capture.inspection.merge_authorized, false);
    assert.deepEqual((await readdir(receipt.path)).sort(), ['candidate.bundle', 'capture.json', 'manifest.json']);
    assert.equal((await lstat(receipt.path)).mode & 0o777, 0o700);
    for (const name of await readdir(receipt.path)) assert.equal((await lstat(join(receipt.path, name))).mode & 0o777, 0o600);
    assert.equal((await readFile(join(receipt.path, 'capture.json'), 'utf8')).includes(TOKEN), false);
    assert.deepEqual(await readFile(receipt.bundle_path), result.bundle);
    const second = await saveCandidatePackage(join(root, 'copy'), result.capture, result.bundle);
    assert.equal(second.sha256, receipt.sha256, 'identical native observations produce identical roots');
    t.diagnostic(`Git fixture oracle: ${p.fixture.version}; HTTP peer is not Rust fg.`);
  });
}
for (const algorithm of ['sha1', 'sha256']) for (const state of ['conflicted', 'already_up_to_date']) {
  test(`${algorithm} ${state}: retain noncandidate without inventing bundle or inspection`, async t => {
    const s = await saved(t, [algorithm, 'merge-commit', state]), value = await loadCandidatePackage(s.path, s.receipt.sha256);
    assert.equal(s.receipt.state, state); assert.equal(s.receipt.bundle_path, null);
    assert.equal(value.bundle, null); assert.equal(value.artifact, null); assert.equal(value.capture.inspection, null);
    assert.deepEqual((await readdir(s.path)).sort(), ['capture.json', 'manifest.json']);
  });
}
for (const pin of [null, '', 'f'.repeat(64), 'A'.repeat(64)]) test(`independent manifest pin required: ${pin}`, async t => {
  const s = await saved(t); await assert.rejects(loadCandidatePackage(s.path, pin));
});
for (const name of ['manifest.json', 'capture.json', 'candidate.bundle']) for (const action of ['delete', 'truncate', 'alter', 'public', 'symlink', 'hardlink']) {
  test(`${name} ${action}: changed package is never a successful capture`, async t => {
    const s = await saved(t), path = join(s.path, name), bytes = await readFile(path);
    if (action === 'delete') await rm(path);
    if (action === 'truncate') await writeFile(path, bytes.subarray(0, bytes.length - 1));
    if (action === 'alter') { bytes[0] ^= 1; await writeFile(path, bytes); }
    if (action === 'public') await chmod(path, 0o644);
    if (action === 'symlink') { const replacement = join(s.root, 'replacement'); await writeFile(replacement, bytes, { mode: 0o600 }); await rm(path); await symlink(replacement, path); }
    if (action === 'hardlink') await link(path, join(s.root, 'alias'));
    await assert.rejects(loadCandidatePackage(s.path, s.receipt.sha256));
  });
}
for (const mutate of [c => c.inspection.source_head = 'another-source', c => c.inspection.comparison.entry_count = 0,
  c => c.review_pages = [], c => c.preparation.merge_authorized = true]) {
  test(`rehashed local bytes still undergo native consistency checks: ${mutate}`, async t => {
    const s = await saved(t), c = structuredClone(s.capture); mutate(c);
    const bytes = Buffer.from(candidateCanonical(c)), manifest = JSON.parse(await readFile(join(s.path, 'manifest.json'), 'utf8'));
    manifest.capture = { bytes: bytes.length, sha256: candidateHash(bytes) };
    const root = Buffer.from(candidateCanonical(manifest));
    await writeFile(join(s.path, 'capture.json'), bytes); await writeFile(join(s.path, 'manifest.json'), root);
    await assert.rejects(loadCandidatePackage(s.path, candidateHash(root)));
  });
}
test('extra entries and fake candidate bytes on noncandidate reports refuse', async t => {
  for (const config of [[], ['sha1', 'merge-commit', 'conflicted']]) {
    const s = await saved(t, config);
    await writeFile(join(s.path, config.length ? 'candidate.bundle' : 'unexpected'), 'not selected', { mode: 0o600 });
    await assert.rejects(loadCandidatePackage(s.path, s.receipt.sha256));
  }
});
test('existing or interrupted slots are never overwritten or repaired', async t => {
  const root = await directory(t), path = join(root, 'package'), value = await localCapture();
  await mkdir(path, { mode: 0o700 }); await writeFile(join(path, 'capture.json'), '{partial', { mode: 0o600 });
  await assert.rejects(saveCandidatePackage(path, value.capture, value.bundle));
  await assert.rejects(loadCandidatePackage(path, 'a'.repeat(64)));
  assert.equal(await readFile(join(path, 'capture.json'), 'utf8'), '{partial');
});
test('concurrent preparation has one winner and leaves a replayable root', async t => {
  const root = await directory(t), value = await localCapture(), path = join(root, 'package');
  const results = await Promise.allSettled([saveCandidatePackage(path, value.capture, value.bundle), saveCandidatePackage(path, value.capture, value.bundle)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const receipt = results.find(r => r.status === 'fulfilled').value;
  assert.deepEqual((await loadCandidatePackage(path, receipt.sha256)).bundle, value.bundle);
});
test('caller edits during asynchronous validation cannot change the retained candidate', async t => {
  const root = await directory(t), value = await localCapture(), expected = structuredClone(value.capture), bundle = Buffer.from(value.bundle);
  const pending = saveCandidatePackage(join(root, 'package'), value.capture, value.bundle);
  value.capture.request.metadata.message = 'edited'; value.bundle.fill(0);
  const receipt = await pending, read = await loadCandidatePackage(receipt.path, receipt.sha256);
  assert.deepEqual(read.capture, expected); assert.deepEqual(read.bundle, bundle);
  read.bundle.fill(0); assert.deepEqual((await loadCandidatePackage(receipt.path, receipt.sha256)).bundle, bundle);
});
test('cancellation before publication leaves no success or overwritten destination', async t => {
  const root = await directory(t), value = await localCapture(), controller = new AbortController(), path = join(root, 'package');
  const pending = saveCandidatePackage(path, value.capture, value.bundle, { signal: controller.signal }); controller.abort();
  await assert.rejects(pending, e => e.code === 'candidate_cancelled');
  await assert.rejects(lstat(path), { code: 'ENOENT' });
});
test('private reader admits exact byte ceiling and refuses the next byte', async t => {
  const root = await directory(t), path = join(root, 'binary'), bytes = Buffer.alloc(16 * 1024 * 1024, 255);
  await writeFile(path, bytes, { mode: 0o600 }); assert.deepEqual(await readCandidatePrivate(path, bytes.length), bytes);
  await assert.rejects(readCandidatePrivate(path, bytes.length - 1));
  await writeFile(path, Buffer.concat([bytes, Buffer.from([0])])); await assert.rejects(readCandidatePrivate(path, bytes.length));
});
for (const kind of ['worktree', 'alias', 'public-parent']) test(`unsafe package location: ${kind}`, async t => {
  const s = await saved(t); let path = s.path;
  if (kind === 'worktree') await mkdir(join(s.root, '.git'));
  if (kind === 'alias') { path = join(s.root, 'alias'); await symlink(s.path, path); }
  if (kind === 'public-parent') await chmod(s.path, 0o755);
  await assert.rejects(loadCandidatePackage(path, s.receipt.sha256));
});
test('tokens are explicit private files; malformed and public files refuse', async t => {
  const root = await directory(t), path = join(root, 'token');
  await writeFile(path, TOKEN + '\n', { mode: 0o600 }); assert.equal(await readCandidateToken(path), TOKEN);
  await chmod(path, 0o644); await assert.rejects(readCandidateToken(path)); await chmod(path, 0o600);
  await writeFile(path, TOKEN + '\r\n'); await assert.rejects(readCandidateToken(path));
});
test('bounded options and shared mutable bundle storage refuse', async t => {
  for (const options of [{ timeoutMs: 0 }, { timeoutMs: 300001 }, { signal: {} }, { force: true }]) assert.throws(() => candidateClock(options));
  const root = await directory(t), value = await localCapture();
  await assert.rejects(saveCandidatePackage(join(root, 'package'), value.capture, new Uint8Array(new SharedArrayBuffer(5))));
});
