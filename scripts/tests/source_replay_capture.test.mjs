// Real private files and complete production imports. Local custody does not
// establish native publication, hostile-parent confinement or physical durability.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile, lstat, chmod, symlink, link, unlink } from 'node:fs/promises';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { captureSourceReplay, loadSourceReplay, REPLAY_PAYLOAD_LIMITS } from '../operator/source_replay_capture.mjs';
import { replayPair } from './source_replay_fixture.mjs';
import { hexPath, intent } from './source_changes_fixture.mjs';
const missing = path => assert.rejects(lstat(path), { code: 'ENOENT' });
async function setup(t, format = 'sha1') {
  const p = replayPair(format), changes = intent([{ operation: 'replace-once', path_hex: hexPath('src/file'), before_utf8: 'beta', after_utf8: 'reviewed' }]);
  const draft = await buildSourceChanges(p.old.bytes, p.old.expected, changes), pin = sha256(canonical(draft.manifest));
  const root = await mkdtemp(join(tmpdir(), 'fg-source-replay-')), output = join(root, 'capture');
  t.after(() => rm(root, { recursive: true, force: true }));
  return { ...p, changes, draft, pin, root, output,
    capture: (options = {}) => captureSourceReplay(output, p.old.bytes, p.old.expected, changes, p.next.bytes, p.next.expected,
      { confirmDraftSha256: pin, ...options }) };
}
async function rehash(path, mutate) {
  const root = JSON.parse(await readFile(join(path, 'manifest.json')));
  await mutate(root);
  for (const row of root.payloads) { const bytes = await readFile(join(path, row.name)); row.bytes = bytes.length; row.sha256 = sha256(bytes); }
  const bytes = canonical(root); await writeFile(join(path, 'manifest.json'), bytes); return sha256(bytes);
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: create-only replay captures reopen with both independently selected bases and standard draft inputs`, async t => {
    const s = await setup(t, format), r = await s.capture(), replay = await loadSourceReplay(s.output, r.capture_sha256);
    assert.equal(replay.saved.draft_sha256, r.draft_sha256); assert.notEqual(r.draft_sha256, s.pin);
    assert.equal(replay.saved.new_review_required, true); assert.equal(replay.saved.repository_changed, false);
    assert.deepEqual(replay.draft.bytes, s.draft.bytes);
    assert.equal((await lstat(s.output)).mode & 0o777, 0o700);
    for (const name of [...Object.keys(REPLAY_PAYLOAD_LIMITS), 'manifest.json']) assert.equal((await lstat(join(s.output, name))).mode & 0o777, 0o600);
    const rebuilt = await buildSourceChanges(replay.next.packageBytes, replay.next.expected, replay.next.changes);
    assert.equal(sha256(canonical(rebuilt.manifest)), r.draft_sha256); assert.equal(rebuilt.tree.afterTree, r.expected_tree);
    assert.deepEqual(await readFile(join(s.output, 'source.json')), s.next.bytes);
    assert.deepEqual(await readFile(join(s.output, 'original-source.json')), s.old.bytes);
    s.old.bytes.fill(0); s.next.bytes.fill(0); s.changes.changes.length = 0;
    assert.equal((await loadSourceReplay(s.output, r.capture_sha256)).saved.draft_sha256, r.draft_sha256);
  });
  test(`${format}: existing output is never replaced and competing captures leave exactly one complete owner`, async t => {
    const s = await setup(t, format), results = await Promise.allSettled([s.capture(), s.capture()]);
    assert.equal(results.filter(x => x.status === 'fulfilled').length, 1);
    const r = results.find(x => x.status === 'fulfilled').value;
    const bytes = await readFile(join(s.output, 'manifest.json'));
    await assert.rejects(s.capture()); assert.deepEqual(await readFile(join(s.output, 'manifest.json')), bytes);
    assert.equal((await loadSourceReplay(s.output, r.capture_sha256)).saved.draft_sha256, r.draft_sha256);
  });
  test(`${format}: rehashed corrupt patch cannot replace regenerated verified bytes`, async t => {
    const s = await setup(t, format), r = await s.capture();
    const hash = await rehash(s.output, async () => {
      const patch = await readFile(join(s.output, 'patch.diff')); patch[patch.length - 2] ^= 1; await writeFile(join(s.output, 'patch.diff'), patch);
    });
    await assert.rejects(loadSourceReplay(s.output, r.capture_sha256), /capture_changed/);
    await assert.rejects(loadSourceReplay(s.output, hash), /regeneration_mismatch/);
  });
  test(`${format}: rehashed receipt flags and original or new draft cannot forge replay verification`, async t => {
    const s = await setup(t, format), r = await s.capture();
    for (const name of ['replay.json', 'original-draft.json', 'draft.json']) {
      const original = await readFile(join(s.output, name));
      const hash = await rehash(s.output, async root => {
        const changed = JSON.parse(original); changed[name === 'replay.json' ? 'ancestry_verified' : 'authority_verified'] = true;
        const bytes = canonical(changed); await writeFile(join(s.output, name), bytes);
        if (name === 'replay.json') root.replay_sha256 = sha256(bytes);
        if (name === 'draft.json') root.draft_sha256 = sha256(bytes);
      });
      await assert.rejects(loadSourceReplay(s.output, hash), /regeneration_mismatch/);
      await writeFile(join(s.output, name), original);
    }
    // Recreate a clean independent slot as the permitted twin, not by accepting
    // the tampered root or weakening the original retained pin.
    const twin = join(s.root, 'clean');
    const clean = await captureSourceReplay(twin, s.old.bytes, s.old.expected, s.changes, s.next.bytes, s.next.expected, { confirmDraftSha256: s.pin });
    assert.equal(clean.capture_sha256, r.capture_sha256); assert.ok(await loadSourceReplay(twin, clean.capture_sha256));
  });
}
test('missing, renamed or path-traversing payload inventories fail closed', async t => {
  const s = await setup(t), r = await s.capture(), original = await readFile(join(s.output, 'manifest.json'));
  for (const mutate of [m => { m.payloads.pop(); }, m => { m.payloads.reverse(); }, m => { m.payloads[0].name = '../outside'; },
    m => { m.payloads[1] = m.payloads[0]; }, m => { m.extra = true; }]) {
    const m = JSON.parse(original); mutate(m); const bytes = canonical(m); await writeFile(join(s.output, 'manifest.json'), bytes);
    await assert.rejects(loadSourceReplay(s.output, sha256(bytes)));
  }
  await writeFile(join(s.output, 'manifest.json'), original); await unlink(join(s.output, 'expected.json'));
  await assert.rejects(loadSourceReplay(s.output, r.capture_sha256), { code: 'ENOENT' });
});
test('private custody rejects public files, symlink aliases and hardlinked payloads', async t => {
  const s = await setup(t), r = await s.capture(), path = join(s.output, 'changes.json'), bytes = await readFile(path);
  await chmod(path, 0o644); await assert.rejects(loadSourceReplay(s.output, r.capture_sha256)); await chmod(path, 0o600);
  await link(path, join(s.root, 'hardlink')); await assert.rejects(loadSourceReplay(s.output, r.capture_sha256)); await unlink(join(s.root, 'hardlink'));
  await unlink(path); await writeFile(join(s.root, 'elsewhere'), bytes, { mode: 0o600 }); await symlink(join(s.root, 'elsewhere'), path);
  await assert.rejects(loadSourceReplay(s.output, r.capture_sha256)); await unlink(path); await writeFile(path, bytes, { mode: 0o600 });
  assert.ok(await loadSourceReplay(s.output, r.capture_sha256));
  await symlink(s.output, join(s.root, 'alias')); await assert.rejects(loadSourceReplay(join(s.root, 'alias'), r.capture_sha256));
});
test('cancellation before output creation leaves no claimed directory', async t => {
  const s = await setup(t), c = new AbortController(); c.abort();
  await assert.rejects(s.capture({ signal: c.signal })); await missing(s.output);
  await assert.rejects(s.capture({ confirmDraftSha256: 'f'.repeat(64) })); await missing(s.output);
  assert.ok((await s.capture()).capture_sha256);
});
test('a stop after payload publication retains an incomplete slot without claiming a complete root', async t => {
  const s = await setup(t), c = new AbortController(), original = performance.now.bind(performance);
  Object.defineProperty(performance, 'now', { configurable: true, value: () => {
    if (existsSync(join(s.output, 'original-source.json'))) c.abort(); return original();
  } });
  try {
    await assert.rejects(s.capture({ signal: c.signal }), e => { assert.equal(e.publication_unconfirmed.directory, s.output); return true; });
  } finally { Object.defineProperty(performance, 'now', { configurable: true, value: original }); }
  assert.ok((await lstat(s.output)).isDirectory()); await missing(join(s.output, 'manifest.json'));
  await assert.rejects(s.capture());
});
test('a competing file writer cannot be overwritten inside a claimed output slot', async t => {
  const s = await setup(t), original = performance.now.bind(performance); let injected = false;
  Object.defineProperty(performance, 'now', { configurable: true, value: () => {
    if (!injected && existsSync(s.output)) { injected = true; writeFileSync(join(s.output, 'source.json'), 'competing writer', { mode: 0o600, flag: 'wx' }); }
    return original();
  } });
  try { await assert.rejects(s.capture(), e => { assert.ok(e.publication_unconfirmed.capture_sha256); return true; }); }
  finally { Object.defineProperty(performance, 'now', { configurable: true, value: original }); }
  assert.equal(await readFile(join(s.output, 'source.json'), 'utf8'), 'competing writer'); await missing(join(s.output, 'manifest.json'));
});
test('read-only reopening does not repair, rewrite or delete captured files', async t => {
  const s = await setup(t), r = await s.capture(), paths = [...Object.keys(REPLAY_PAYLOAD_LIMITS), 'manifest.json'];
  const before = await Promise.all(paths.map(async n => [await readFile(join(s.output, n)), await lstat(join(s.output, n))]));
  await loadSourceReplay(s.output, r.capture_sha256);
  for (const [i, name] of paths.entries()) {
    const after = await lstat(join(s.output, name)); assert.equal(after.mtimeMs, before[i][1].mtimeMs);
    assert.deepEqual(await readFile(join(s.output, name)), before[i][0]);
  }
});
test('capture owns mutable inputs before any asynchronous output check', async t => {
  const s = await setup(t), old = Buffer.from(s.old.bytes), next = Buffer.from(s.next.bytes), a = structuredClone(s.old.expected), b = structuredClone(s.next.expected), changes = structuredClone(s.changes);
  const promise = captureSourceReplay(s.output, old, a, changes, next, b, { confirmDraftSha256: s.pin });
  old.fill(0); next.fill(0); a.files.length = 0; b.files.length = 0; changes.changes.length = 0;
  const r = await promise; assert.equal((await loadSourceReplay(s.output, r.capture_sha256)).saved.original_draft_sha256, s.pin);
});
test('reopen refuses an incorrect retained root and unsupported options', async t => {
  const s = await setup(t), r = await s.capture();
  await assert.rejects(loadSourceReplay(s.output, 'f'.repeat(64)), /capture_changed/);
  for (const options of [{ timeoutMs: 0 }, { journal: '/not-used' }, { ca: Buffer.from('x') }]) await assert.rejects(loadSourceReplay(s.output, r.capture_sha256, options));
});
