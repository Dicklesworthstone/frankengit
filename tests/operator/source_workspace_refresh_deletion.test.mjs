// Real commit/tree/blob proofs, POSIX custody and offline source capture.
// No verifier substitution, native server, authority or ancestry claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, writeFileSync } from 'node:fs';
import { chmod, lstat, mkdtemp, readFile, realpath, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { createSourceWorkspace, loadSourceWorkspace, localPath, previewSourceWorkspaceRefresh, refreshSourceWorkspace,
  WORKSPACE_REFRESH_DELETIONS, WORKSPACE_REFRESH_RESOLUTIONS, WORKSPACE_TEXT_MERGE_PROFILE, WORKSPACE_LIMITS,
} from '../../scripts/operator/source_workspace.mjs';
import { captureWorkspaceChanges, inspectWorkspaceChangeCapture } from '../../scripts/operator/source_workspace_changes.mjs';
import { canonical, sha256 } from '../../scripts/operator/source_changes.mjs';
import { changeFixture, hexPath } from '../../scripts/tests/source_changes_fixture.mjs';
import { main } from '../../scripts/fg_source_workspace.mjs';

const pathFor = (root, name) => localPath(root, hexPath(name));
const deletion = (...names) => ({ schema: WORKSPACE_REFRESH_DELETIONS, paths_hex: names.map(hexPath).sort() });
const resolve = (plan, name, choice) => ({ schema: WORKSPACE_REFRESH_RESOLUTIONS, plan_sha256: plan.refresh_sha256,
  choices: [{ path_hex: hexPath(name), choice }] });
const anchor = { path: 'keep.txt', bytes: 'original anchor\n' };
const retired = { path: 'retired.txt', bytes: 'original file\n' };
const successor = format => changeFixture(format, [{ ...anchor, bytes: 'next anchor\n' }]);
async function setup(t, format = 'sha1', rows = [anchor, retired]) {
  const parent = await realpath(await mkdtemp(join(tmpdir(), 'fg-refresh-deletion-')));
  await chmod(parent, 0o700);
  t.after(() => rm(parent, { recursive: true, force: true }));
  const root = join(parent, 'original'), output = join(parent, 'refreshed'), original = changeFixture(format, rows);
  const created = await createSourceWorkspace(root, original.bytes, original.expected);
  const preview = (next, options) => previewSourceWorkspaceRefresh(root, created.workspace_sha256, next.bytes, next.expected, options);
  const apply = (next, hash, options) => refreshSourceWorkspace(root, created.workspace_sha256, next.bytes, next.expected, output, hash, options);
  return { parent, root, output, original, created, preview, apply };
}
function select(fixture, names) {
  const selected = new Set(names.map(hexPath)), needed = new Set([null]);
  for (const path of names) {
    const parts = path.split('/');
    for (let i = 1; i < parts.length; i++) needed.add(hexPath(parts.slice(0, i).join('/')));
  }
  fixture.expected.files = fixture.expected.files.filter(f => selected.has(f.pathHex));
  fixture.value.membership.files = fixture.value.membership.files.filter(f => selected.has(f.pathHex));
  fixture.value.membership.trees = fixture.value.membership.trees.filter(t => needed.has(t.pathHex));
  const blobs = new Set(fixture.expected.files.map(f => f.blob));
  fixture.value.blobs = fixture.value.blobs.filter(b => blobs.has(b.oid));
  fixture.bytes = canonical(fixture.value);
  return fixture;
}

for (const format of ['sha1', 'sha256']) {
  for (const locallyAbsent of [false, true]) test(format + ': proven deletion ' + (locallyAbsent ? 'converges with local deletion' : 'removes unchanged local file'), async t => {
    const f = await setup(t, format), next = successor(format), deletions = deletion('retired.txt');
    if (locallyAbsent) await unlink(pathFor(f.root, 'retired.txt'));
    await assert.rejects(f.preview(next), { code: 'source_workspace_refresh_selection' });
    const plan = await f.preview(next, { deletions }), entry = plan.entries.find(e => e.path_hex === hexPath('retired.txt'));
    assert.equal(plan.ready, true);
    assert.equal(entry.disposition, locallyAbsent ? 'converged' : 'deleted');
    assert.equal(entry.selected, null); assert.equal(entry.result, null);
    assert.equal(plan.deletion_absence.pathAbsenceVerified, true);
    assert.equal(plan.deletion_absence.commit, next.expected.commit);
    assert.equal(plan.deletion_absence.rootTree, next.tree);
    assert.equal(plan.deletion_absence.authorityVerified, false);
    assert.deepEqual(plan.deletions, deletions);
    assert.deepEqual(await f.preview(next, { deletions }), plan);
    assert(!existsSync(f.output));
    const done = await f.apply(next, plan.refresh_sha256, { deletions });
    assert(!existsSync(pathFor(f.output, 'retired.txt')));
    assert.equal((await readFile(pathFor(f.output, 'keep.txt'))).toString(), 'next anchor\n');
    assert.deepEqual((await loadSourceWorkspace(f.output, done.workspace_sha256)).expected, next.expected);
    assert.equal(sha256(await readFile(join(f.output, 'refresh.json'))), plan.refresh_sha256);
    assert.deepEqual(await readFile(join(f.root, 'source.json')), f.original.bytes);
    assert.equal(existsSync(pathFor(f.root, 'retired.txt')), !locallyAbsent);
  });

  for (const change of ['bytes', 'mode']) for (const choice of ['local', 'selected']) {
    test(format + ': ' + change + ' versus source deletion requires explicit ' + choice + ' choice', async t => {
      const f = await setup(t, format), next = successor(format), deletions = deletion('retired.txt');
      const local = change === 'bytes' ? Buffer.from([0, 255, 13, 10, 1]) : Buffer.from(retired.bytes);
      await writeFile(pathFor(f.root, 'retired.txt'), local);
      await chmod(pathFor(f.root, 'retired.txt'), 0o700);
      const original = await f.preview(next, { deletions, mergeProfile: WORKSPACE_TEXT_MERGE_PROFILE });
      assert.equal(original.ready, false); assert.equal(original.conflict_count, 1);
      assert.equal(original.entries.find(e => e.path_hex === hexPath('retired.txt')).conflict, 'local_modify_source_delete');
      assert.equal(original.text_merge.attempts, 0);
      await assert.rejects(f.apply(next, original.refresh_sha256, { deletions, mergeProfile: WORKSPACE_TEXT_MERGE_PROFILE }), { code: 'source_workspace_refresh_conflict' });
      const resolutions = resolve(original, 'retired.txt', choice);
      const options = { deletions, resolutions, mergeProfile: WORKSPACE_TEXT_MERGE_PROFILE };
      const plan = await f.preview(next, options);
      assert.equal(plan.ready, true); assert.notEqual(plan.refresh_sha256, original.refresh_sha256);
      await assert.rejects(f.apply(next, original.refresh_sha256, options), { code: 'source_workspace_refresh_review_changed' });
      const done = await f.apply(next, plan.refresh_sha256, options);
      assert(!next.expected.files.some(row => row.pathHex === hexPath('retired.txt')));
      if (choice === 'selected') assert(!existsSync(pathFor(f.output, 'retired.txt')));
      else {
        assert.deepEqual(await readFile(pathFor(f.output, 'retired.txt')), local);
        assert.equal((await lstat(pathFor(f.output, 'retired.txt'))).mode & 0o777, 0o700);
        // This retained local image is a new creation against the next source,
        // including real absence verification and independently replayed capture.
        const capture = join(f.parent, 'capture');
        const result = await captureWorkspaceChanges(f.output, done.workspace_sha256,
          { paths_hex: [hexPath('retired.txt')], byte_profile: 'binary-safe-v1' }, capture);
        const changes = JSON.parse(await readFile(join(capture, 'changes.json'), 'utf8'));
        assert.deepEqual(changes.changes, [{ path_hex: hexPath('retired.txt'), operation: 'create',
          content_hex: local.toString('hex'), executable: true }]);
        assert.equal((await inspectWorkspaceChangeCapture(capture, result.capture_sha256)).offline_recomputed, true);
      }
      assert.deepEqual(await readFile(pathFor(f.root, 'retired.txt')), local);
    });
  }

  test(format + ': authenticated nested parent or missing ancestor proves deletion', async t => {
    for (const survives of [false, true]) {
      const f = await setup(t, format, [anchor, { ...retired, path: 'src/retired.txt' }]);
      const rows = [{ ...anchor, bytes: 'next' }, ...(survives ? [{ path: 'src/other.txt', bytes: 'survivor' }] : [])];
      const next = changeFixture(format, rows), options = { deletions: deletion('src/retired.txt') };
      const plan = await f.preview(next, options), witness = plan.deletion_absence.paths[0];
      assert.equal(witness.parentPathHex, survives ? hexPath('src') : null);
      assert.equal(witness.absentPrefixHex, hexPath(survives ? 'src/retired.txt' : 'src'));
      await f.apply(next, plan.refresh_sha256, options);
      assert(!existsSync(pathFor(f.output, 'src/retired.txt')));
    }
  });

  test(format + ': omitted extant file and opaque surviving parent are not deletion', async t => {
    const f = await setup(t, format), extant = select(changeFixture(format, [
      { ...anchor, bytes: 'next' }, retired,
    ]), ['keep.txt']);
    await assert.rejects(f.preview(extant, { deletions: deletion('retired.txt') }), /requested path already exists/);
    assert(!existsSync(f.output));
    const nested = await setup(t, format, [anchor, { ...retired, path: 'src/retired.txt' }]);
    const opaque = select(changeFixture(format, [{ ...anchor, bytes: 'next' }, { path: 'src/survivor.txt', bytes: 'retained' }]), ['keep.txt']);
    await assert.rejects(nested.preview(opaque, { deletions: deletion('src/retired.txt') }), /existing parent tree is not proved/);
    assert(!existsSync(nested.output));
  });

  test(format + ': package, expected selection and deletion inputs are owned before awaiting', async t => {
    const f = await setup(t, format), next = successor(format), deletions = deletion('retired.txt');
    const expected = await f.preview(next, { deletions });
    const pending = f.preview(next, { deletions });
    next.bytes.fill(0); next.expected.commit = '0'.repeat(next.expected.commit.length);
    next.expected.files[0].pathHex = hexPath('injected');
    deletions.schema = 'changed'; deletions.paths_hex[0] = hexPath('unselected');
    assert.deepEqual(await pending, expected);
    assert(!existsSync(f.output));
  });

  test(format + ': changed local deletion or source package invalidates the reviewed plan', async t => {
    const f = await setup(t, format), next = successor(format), options = { deletions: deletion('retired.txt') };
    const plan = await f.preview(next, options);
    const reencoded = { ...next, bytes: Buffer.concat([next.bytes, Buffer.from('\n')]) };
    await assert.rejects(f.apply(reencoded, plan.refresh_sha256, options), { code: 'source_workspace_refresh_review_changed' });
    await unlink(pathFor(f.root, 'retired.txt'));
    await assert.rejects(f.apply(next, plan.refresh_sha256, options), { code: 'source_workspace_refresh_review_changed' });
    assert(!existsSync(f.output));
  });
}

test('deletion selections are closed, sorted and exactly cover omitted original paths', async t => {
  const f = await setup(t, 'sha1', [anchor, { ...retired, path: 'a.txt' }, { ...retired, path: 'b.txt' }]);
  const next = successor('sha1'), valid = deletion('a.txt', 'b.txt');
  for (const deletions of [
    null, {}, { ...valid, extra: true }, { ...valid, schema: 'unknown' },
    { ...valid, paths_hex: [] }, { ...valid, paths_hex: [...valid.paths_hex].reverse() },
    { ...valid, paths_hex: [valid.paths_hex[0], valid.paths_hex[0]] },
    deletion('a.txt'), deletion('a.txt', 'b.txt', 'not-selected.txt'),
    deletion('a.txt', 'keep.txt'), deletion('../escape'),
  ]) {
    await assert.rejects(f.preview(next, { deletions }));
    assert(!existsSync(f.output));
  }
  await assert.rejects(f.preview(changeFixture('sha1', []), { deletions: valid }), { code: 'source_union_selection' });
});

test('deletion paths share successor count and ancestor-collision limits', async t => {
  const f = await setup(t), options = { deletions: deletion('retired.txt') };
  const full = changeFixture('sha1', [{ ...anchor, bytes: 'next' },
    ...Array.from({ length: 31 }, (_, i) => ({ path: 'new-' + i + '.txt', bytes: 'new' }))]);
  await assert.rejects(f.preview(full, options), { code: 'source_workspace_paths' });
  const collision = changeFixture('sha1', [{ ...anchor, bytes: 'next' }, { path: 'retired.txt/new.txt', bytes: 'nested' }]);
  await assert.rejects(f.preview(collision, options), { code: 'source_workspace_paths' });
  assert(!existsSync(f.output));
});

test('retained local creations share the aggregate refreshed output limit', async t => {
  const f = await setup(t), deletions = deletion('retired.txt');
  await writeFile(pathFor(f.root, 'retired.txt'), Buffer.alloc(WORKSPACE_LIMITS.fileBytes, 65));
  const next = changeFixture('sha1', Array.from({ length: 8 }, (_, i) => ({
    path: i === 0 ? 'keep.txt' : 'added-' + i + '.txt', bytes: Buffer.alloc(WORKSPACE_LIMITS.fileBytes, 66 + i),
  })));
  const original = await f.preview(next, { deletions });
  assert.equal(original.result_bytes, WORKSPACE_LIMITS.totalBytes);
  await assert.rejects(f.preview(next, { deletions, resolutions: resolve(original, 'retired.txt', 'local') }),
    { code: 'source_workspace_refresh_output_budget' });
  assert(!existsSync(f.output));
});

test('one deadline and cancellation span deletion verification without acquiring output', async t => {
  const f = await setup(t), next = successor('sha1'), deletions = deletion('retired.txt');
  const plan = await f.preview(next, { deletions });
  let delayed = false;
  await assert.rejects(f.apply(next, plan.refresh_sha256, { deletions, timeoutMs: 1, check: () => {
    if (!delayed) { delayed = true; const end = performance.now() + 5; while (performance.now() < end) {} }
  } }), { code: 'source_workspace_deadline' });
  const controller = new AbortController(); let checks = 0;
  await assert.rejects(f.apply(next, plan.refresh_sha256, { deletions, signal: controller.signal,
    check: () => { if (++checks === 50) controller.abort(); } }), e => e.name === 'AbortError');
  assert(controller.signal.aborted); assert(!existsSync(f.output));
});

test('deleted-path observations are rechecked before the final output manifest', async t => {
  const f = await setup(t), next = successor('sha1'), deletions = deletion('retired.txt');
  await unlink(pathFor(f.root, 'retired.txt'));
  const plan = await f.preview(next, { deletions }); let changed = false;
  await assert.rejects(f.apply(next, plan.refresh_sha256, { deletions, check: () => {
    if (!changed && existsSync(f.output)) {
      changed = true;
      writeFileSync(pathFor(f.root, 'retired.txt'), 'late local creation', { mode: 0o600 });
    }
  } }), e => e.code === 'source_workspace_changed' && e.publication_unconfirmed?.directory === f.output);
  assert(changed); assert(existsSync(f.output)); assert(!existsSync(join(f.output, 'manifest.json')));
  assert.equal((await readFile(pathFor(f.root, 'retired.txt'))).toString(), 'late local creation');
});

function sink() {
  let text = '';
  return { stream: new Writable({ write(bytes, _encoding, done) { text += bytes; done(); } }),
    get value() { return text ? JSON.parse(text) : null; } };
}
async function invoke(args) {
  const stdout = sink(), stderr = sink();
  const code = await main(args, { stdout: stdout.stream, stderr: stderr.stream });
  return { code, out: stdout.value, error: stderr.value };
}
test('real CLI accepts deletion, resolution, merge and deadline together and requires private choices', async t => {
  const f = await setup(t), next = successor('sha1');
  await writeFile(pathFor(f.root, 'retired.txt'), 'local surviving change\n');
  const files = { package: join(f.parent, 'next.json'), expect: join(f.parent, 'expected.json'),
    deletions: join(f.parent, 'deletions.json'), resolutions: join(f.parent, 'resolutions.json') };
  await writeFile(files.package, next.bytes, { mode: 0o600 });
  await writeFile(files.expect, canonical(next.expected), { mode: 0o600 });
  await writeFile(files.deletions, canonical(deletion('retired.txt')), { mode: 0o600 });
  const args = ['--workspace', f.root, '--sha256', f.created.workspace_sha256, '--package', files.package, '--expect', files.expect,
    '--deletions', files.deletions, '--merge-profile', WORKSPACE_TEXT_MERGE_PROFILE, '--timeout-ms', '30000'];
  const original = await invoke(['refresh-preview', ...args]);
  assert.equal(original.code, 1); assert.equal(original.out.conflict_count, 1);
  await writeFile(files.resolutions, canonical(resolve(original.out, 'retired.txt', 'local')), { mode: 0o600 });
  const resolved = await invoke(['refresh-preview', ...args, '--resolutions', files.resolutions]);
  assert.equal(resolved.code, 0); assert.equal(resolved.out.ready, true);
  await chmod(files.deletions, 0o644);
  assert.equal((await invoke(['refresh-preview', ...args])).code, 2);
  await chmod(files.deletions, 0o600);
  const all = ['refresh', ...args, '--resolutions', files.resolutions,
    '--approve-refresh-sha256', resolved.out.refresh_sha256, '--output', f.output];
  assert.equal(all.length, 21);
  const done = await invoke(all);
  assert.equal(done.code, 0, JSON.stringify(done.error));
  assert.equal(done.out.refresh_sha256, resolved.out.refresh_sha256);
  assert.equal((await readFile(pathFor(f.output, 'retired.txt'))).toString(), 'local surviving change\n');
});
