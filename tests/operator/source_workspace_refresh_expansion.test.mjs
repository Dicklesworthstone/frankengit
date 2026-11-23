// Real workspace, membership verification and POSIX custody. The packages below
// are independently framed Git objects, not a native server or authority proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSourceWorkspace, inspectSourceWorkspace, loadSourceWorkspace, localPath,
  previewSourceWorkspaceRefresh, refreshSourceWorkspace, WORKSPACE_LIMITS,
} from '../../scripts/operator/source_workspace.mjs';
import { canonical, sha256 } from '../../scripts/operator/source_changes.mjs';
import { changeFixture, hexPath } from '../../scripts/tests/source_changes_fixture.mjs';

const pathFor = (root, name) => localPath(root, hexPath(name));
async function setup(t, format, rows = [{ path: 'old.txt', bytes: 'base' }], chosen) {
  const parent = await realpath(await mkdtemp(join(tmpdir(), 'fg-refresh-expansion-')));
  await chmod(parent, 0o700);
  t.after(() => rm(parent, { recursive: true, force: true }));
  const root = join(parent, 'original'), output = join(parent, 'refreshed');
  const original = changeFixture(format, rows);
  if (chosen) {
    // Root-level siblings remain committed by the complete root-tree body;
    // only explicitly selected blobs are included in this sparse package.
    const selected = new Set(chosen.map(hexPath));
    original.value.membership.files = original.value.membership.files.filter(f => selected.has(f.pathHex));
    const blobs = new Set(original.value.membership.files.map(f => f.blob));
    original.value.blobs = original.value.blobs.filter(b => blobs.has(b.oid));
    original.expected.files = original.expected.files.filter(f => selected.has(f.pathHex));
    original.bytes = canonical(original.value);
  }
  const created = await createSourceWorkspace(root, original.bytes, original.expected);
  const preview = (next, options) => previewSourceWorkspaceRefresh(root, created.workspace_sha256, next.bytes, next.expected, options);
  const apply = (next, hash, options) => refreshSourceWorkspace(root, created.workspace_sha256, next.bytes, next.expected, output, hash, options);
  return { parent, root, output, original, created, preview, apply };
}
const base = { path: 'old.txt', bytes: 'base' };

for (const format of ['sha1', 'sha256']) {
  test(`${format}: refresh expands before and after existing paths, preserving edits, modes and deletion`, async t => {
    const f = await setup(t, format, [
      { path: 'src/main.rs', bytes: 'base main\n' },
      { path: 'src/deleted.rs', bytes: 'base deleted\n' },
    ]);
    await writeFile(pathFor(f.root, 'src/main.rs'), 'local main\r\n');
    await unlink(pathFor(f.root, 'src/deleted.rs'));
    await symlink('/unavailable/unselected', pathFor(f.root, 'private-notes'));
    const next = changeFixture(format, [
      { path: 'a/new/deep.bin', bytes: Buffer.from([0, 255, 13, 10]), mode: 0o100755 },
      { path: 'src/main.rs', bytes: 'base main\n', mode: 0o100755 },
      { path: 'src/deleted.rs', bytes: 'base deleted\n' },
      { path: 'src/support.rs', bytes: 'new support\n' },
      { path: 'z.txt', bytes: '' },
    ]);
    const plan = await f.preview(next);
    assert.deepEqual(await f.preview(next), plan);
    assert.equal(plan.ready, true); assert.equal(plan.conflict_count, 0);
    assert.deepEqual(plan.entries.map(e => e.path_hex), next.expected.files.map(f => f.pathHex));
    assert.deepEqual(plan.entries.map(e => e.disposition), ['added', 'carried', 'combined', 'added', 'added']);
    for (const entry of plan.entries.filter(e => e.disposition === 'added')) {
      assert.equal(entry.before, null); assert.equal(entry.local, null);
      assert.deepEqual(entry.result, entry.selected);
    }
    assert.equal(plan.result_bytes, Buffer.byteLength('local main\r\nnew support\n') + 4);
    assert.equal(existsSync(f.output), false);
    const result = await f.apply(next, plan.refresh_sha256);
    assert.equal(result.type, 'source_workspace_refreshed'); assert.equal(result.files, 5);
    assert.deepEqual(await readFile(pathFor(f.output, 'a/new/deep.bin')), Buffer.from([0, 255, 13, 10]));
    assert.equal((await lstat(pathFor(f.output, 'a/new/deep.bin'))).mode & 0o777, 0o700);
    assert.equal((await readFile(pathFor(f.output, 'src/main.rs'))).toString(), 'local main\r\n');
    assert.equal((await lstat(pathFor(f.output, 'src/main.rs'))).mode & 0o777, 0o700);
    assert.equal(existsSync(pathFor(f.output, 'src/deleted.rs')), false);
    assert.deepEqual(await readdir(localPath(f.output)), ['a', 'src', 'z.txt']);
    assert((await lstat(pathFor(f.root, 'private-notes'))).isSymbolicLink());
    assert.deepEqual((await loadSourceWorkspace(f.output, result.workspace_sha256)).expected, next.expected);
    const status = await inspectSourceWorkspace(f.output, result.workspace_sha256);
    assert.deepEqual(status.entries.map(e => e.state), ['unchanged', 'deleted', 'modified', 'unchanged', 'unchanged']);
    const { refresh_sha256, ...reviewed } = plan;
    assert.equal(sha256(await readFile(join(f.output, 'refresh.json'))), refresh_sha256);
    assert.deepEqual(JSON.parse(await readFile(join(f.output, 'refresh.json'), 'utf8')), reviewed);
    assert.deepEqual(await readFile(join(f.root, 'source.json')), f.original.bytes);
  });

  test(`${format}: expansion may select a previously unselected source sibling without claiming original absence`, async t => {
    const f = await setup(t, format, [base, { path: 'known.txt', bytes: 'already in old source' }], ['old.txt']);
    assert.equal(existsSync(pathFor(f.root, 'known.txt')), false);
    const next = changeFixture(format, [{ ...base, bytes: 'updated' }, { path: 'known.txt', bytes: 'already in old source' }]);
    const plan = await f.preview(next), added = plan.entries.find(e => e.path_hex === hexPath('known.txt'));
    assert.equal(added.disposition, 'added'); assert.equal(added.before, null);
    await f.apply(next, plan.refresh_sha256);
    assert.equal((await readFile(pathFor(f.output, 'known.txt'))).toString(), 'already in old source');
  });

  for (const contents of ['untracked edit', 'new source']) test(`${format}: occupied newly selected file refuses even for ${contents === 'new source' ? 'identical bytes' : 'different bytes'}`, async t => {
    const f = await setup(t, format), next = changeFixture(format, [base, { path: 'new.txt', bytes: 'new source' }]);
    await writeFile(pathFor(f.root, 'new.txt'), contents, { mode: 0o600 });
    await assert.rejects(f.preview(next), { code: 'source_workspace_refresh_expansion_occupied' });
    assert.equal((await readFile(pathFor(f.root, 'new.txt'))).toString(), contents);
    assert.equal(existsSync(f.output), false);
  });

  for (const kind of ['file-ancestor', 'symlink-ancestor', 'directory-terminal', 'symlink-terminal']) test(`${format}: added selection refuses ${kind} without replacing local work`, async t => {
    const f = await setup(t, format), next = changeFixture(format, [base, { path: 'new/deep.txt', bytes: 'new source' }]);
    const ancestor = pathFor(f.root, 'new'), terminal = pathFor(f.root, 'new/deep.txt');
    if (kind === 'file-ancestor') await writeFile(ancestor, 'untracked ancestor', { mode: 0o600 });
    else if (kind === 'symlink-ancestor') await symlink(f.parent, ancestor);
    else {
      await mkdir(ancestor, { mode: 0o700 });
      if (kind === 'directory-terminal') await mkdir(terminal, { mode: 0o700 });
      else await symlink('/unavailable/untracked', terminal);
    }
    await assert.rejects(f.preview(next), { code: kind.endsWith('ancestor') ? 'source_workspace_unsafe_directory' : 'source_workspace_unsafe_file_or_budget' });
    assert.equal(existsSync(f.output), false);
    if (kind === 'file-ancestor') assert.equal((await readFile(ancestor)).toString(), 'untracked ancestor');
    else if (kind.startsWith('symlink')) assert((await lstat(kind.endsWith('ancestor') ? ancestor : terminal)).isSymbolicLink());
    else assert((await lstat(terminal)).isDirectory());
  });

  test(`${format}: existing private ancestor allows a new file while unselected siblings stay in the original`, async t => {
    const f = await setup(t, format), next = changeFixture(format, [base, { path: 'new/deep.txt', bytes: 'new source' }]);
    await mkdir(pathFor(f.root, 'new'), { mode: 0o700 });
    await symlink('/unavailable/unselected', pathFor(f.root, 'new/private'));
    const plan = await f.preview(next); await f.apply(next, plan.refresh_sha256);
    assert.deepEqual(await readdir(pathFor(f.output, 'new')), ['deep.txt']);
    assert((await lstat(pathFor(f.root, 'new/private'))).isSymbolicLink());
  });

  test(`${format}: an omitted original selection still refuses after its local deletion`, async t => {
    const f = await setup(t, format); await unlink(pathFor(f.root, 'old.txt'));
    const next = changeFixture(format, [{ path: 'new.txt', bytes: 'new source' }]);
    await assert.rejects(f.preview(next), { code: 'source_workspace_refresh_selection' });
    assert.equal(existsSync(f.output), false);
  });

  test(`${format}: a combined file/descendant selection refuses before observing local files`, async t => {
    const f = await setup(t, format), next = changeFixture(format, [base, { path: 'new.txt', bytes: 'new source' }]);
    next.expected.files.push({ pathHex: hexPath('old.txt/child'), blob: next.expected.files.at(-1).blob });
    next.expected.files.sort((a, b) => a.pathHex < b.pathHex ? -1 : 1);
    await chmod(pathFor(f.root, 'old.txt'), 0o666);
    await assert.rejects(f.preview(next), { code: 'source_workspace_paths' });
    assert.equal(existsSync(f.output), false);
  });

  test(`${format}: additions require exact independent membership and source bytes`, async t => {
    const f = await setup(t, format), next = changeFixture(format, [base, { path: 'new.txt', bytes: 'new source' }]);
    const wrongPin = structuredClone(next.expected);
    wrongPin.files.find(f => f.pathHex === hexPath('new.txt')).blob = '1'.repeat(format === 'sha1' ? 40 : 64);
    await assert.rejects(f.preview({ ...next, expected: wrongPin }), /independent|selected|membership|expected|blob/i);
    const corrupt = structuredClone(next.value), blob = corrupt.blobs.find(b => b.oid === next.expected.files.find(f => f.pathHex === hexPath('new.txt')).blob);
    blob.bytesHex = Buffer.from('tampered source').toString('hex');
    await assert.rejects(f.preview({ ...next, bytes: canonical(corrupt) }), /blob|hash|identity/i);
    assert.equal(existsSync(f.output), false);
  });

  test(`${format}: changing the additional selection or its source invalidates the reviewed plan`, async t => {
    const f = await setup(t, format), next = changeFixture(format, [base, { path: 'new.txt', bytes: 'new source' }]);
    const plan = await f.preview(next);
    for (const other of [
      changeFixture(format, [base, { path: 'new.txt', bytes: 'changed source' }]),
      changeFixture(format, [base, { path: 'other.txt', bytes: 'new source' }]),
    ]) await assert.rejects(f.apply(other, plan.refresh_sha256), { code: 'source_workspace_refresh_review_changed' });
    assert.equal(existsSync(f.output), false);
  });

  for (const kind of ['new-file', 'missing-ancestor', 'old-source']) test(`${format}: late ${kind} mutation retains an incomplete output and refuses completion`, async t => {
    const f = await setup(t, format), next = changeFixture(format, [base, { path: 'new/deep.txt', bytes: 'new source' }]);
    if (kind === 'new-file') await mkdir(pathFor(f.root, 'new'), { mode: 0o700 });
    const plan = await f.preview(next); let changed = false;
    await assert.rejects(f.apply(next, plan.refresh_sha256, { check: () => {
      if (changed || !existsSync(join(f.output, 'source.json'))) return;
      changed = true;
      if (kind === 'new-file') writeFileSync(pathFor(f.root, 'new/deep.txt'), 'late user work', { mode: 0o600 });
      else if (kind === 'missing-ancestor') mkdirSync(pathFor(f.root, 'new'), { mode: 0o700 });
      else writeFileSync(join(f.root, 'source.json'), '{}\n');
    } }), error => error.code === (kind === 'old-source' ? 'source_workspace_baseline_changed' : 'source_workspace_changed')
      && error.publication_unconfirmed?.refresh_sha256 === plan.refresh_sha256);
    assert.equal(changed, true); assert.equal(existsSync(f.output), true);
    assert.equal(existsSync(join(f.output, 'manifest.json')), false);
    if (kind === 'new-file') assert.equal((await readFile(pathFor(f.root, 'new/deep.txt'))).toString(), 'late user work');
  });

  test(`${format}: the complete expanded selection fits exactly 32 files and refuses 33`, async t => {
    const f = await setup(t, format);
    const rows = Array.from({ length: WORKSPACE_LIMITS.files - 1 }, (_, i) => ({ path: `new${String(i).padStart(2, '0')}`, bytes: 'new' }));
    const next = changeFixture(format, [base, ...rows]), plan = await f.preview(next);
    const oversized = changeFixture(format, [base, ...rows, { path: 'overflow', bytes: '' }]);
    await assert.rejects(f.preview(oversized), { code: 'source_union_selection' });
    assert.equal(existsSync(f.output), false);
    const result = await f.apply(next, plan.refresh_sha256);
    assert.equal(result.files, WORKSPACE_LIMITS.files);
    assert.equal((await inspectSourceWorkspace(f.output, result.workspace_sha256)).entries.length, WORKSPACE_LIMITS.files);
  });

  test(`${format}: added files retain the per-file source limit`, async t => {
    const f = await setup(t, format), next = changeFixture(format, [base,
      { path: 'large', bytes: Buffer.alloc(WORKSPACE_LIMITS.fileBytes + 1, 65) }]);
    await assert.rejects(f.preview(next), { code: 'source_workspace_source_budget' });
    assert.equal(existsSync(f.output), false);
  });

  test(`${format}: combined local edits and added source enforce the output limit at the exact boundary`, async t => {
    const f = await setup(t, format, [{ path: 'old.txt', bytes: '' }]);
    const big = Buffer.alloc(WORKSPACE_LIMITS.fileBytes, 65);
    await writeFile(pathFor(f.root, 'old.txt'), big);
    const additions = Array.from({ length: 7 }, (_, i) => ({ path: `new${i}`, bytes: big }));
    const exact = changeFixture(format, [{ path: 'old.txt', bytes: '' }, ...additions]);
    const plan = await f.preview(exact);
    assert.equal(plan.result_bytes, WORKSPACE_LIMITS.totalBytes);
    const oversized = changeFixture(format, [{ path: 'old.txt', bytes: '' }, ...additions, { path: 'overflow', bytes: 'x' }]);
    // Both source and local snapshots fit on their own; only their materialized
    // combination exceeds the limit. A preview must never approve that result.
    await assert.rejects(f.preview(oversized), { code: 'source_workspace_refresh_output_budget' });
    assert.equal(existsSync(f.output), false);
    const result = await f.apply(exact, plan.refresh_sha256);
    assert.equal((await inspectSourceWorkspace(f.output, result.workspace_sha256)).bytes_read, WORKSPACE_LIMITS.totalBytes);
  });
}
