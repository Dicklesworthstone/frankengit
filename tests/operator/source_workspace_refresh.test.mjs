import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, chmod, lstat, readdir, mkdir, symlink, link, rename } from 'node:fs/promises';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { workspace, setup, source, local, canonical, sha256, hooks, initWorkspace } from './source_workspace_refresh.fixture.mjs';
await initWorkspace();

for (const format of ['sha1', 'sha256']) {
  for (const [name, localBytes, nextBytes, disposition, expected] of [
    ['clean source update', 'base', 'source', 'updated', 'source'],
    ['unchanged path', 'base', 'base', 'unchanged', 'base'],
    ['carry edit', 'local', 'base', 'carried', 'local'],
    ['already landed edit', 'local', 'local', 'converged', 'local'],
    ['carry deletion', null, 'base', 'carried', null],
    ['binary content', Buffer.from([0, 255, 10]), 'base', 'carried', Buffer.from([0, 255, 10])],
    ['empty replacement', '', 'base', 'carried', ''],
    ['conflicting content', 'local', 'source', 'conflict', undefined],
    ['delete/modify conflict', null, 'source', 'conflict', undefined],
  ]) test(`${format}: ${name}`, async t => {
    const f = await setup(t, undefined, format); await local(f, '61', localBytes);
    const next = source([{ bytes: nextBytes }], format, 'next'), plan = await f.preview(next);
    assert.equal(plan.entries[0].disposition, disposition); assert.equal(plan.ready, expected !== undefined);
    assert.equal(sha256(canonical(Object.fromEntries(Object.entries(plan).filter(([k]) => k !== 'refresh_sha256')))), plan.refresh_sha256);
    assert.equal(plan.authority_verified, false); assert.equal(plan.ancestry_verified, false);
    if (expected === undefined) {
      await assert.rejects(f.apply(next, plan.refresh_sha256), { code: 'source_workspace_refresh_conflict' });
      assert(!existsSync(f.output)); return;
    }
    const result = await f.apply(next, plan.refresh_sha256);
    assert.equal(result.type, 'source_workspace_refreshed'); assert.equal(result.refresh_sha256, plan.refresh_sha256);
    assert.equal(result.original_workspace_changed, false);
    const observed = await workspace.readWorkspaceFiles(f.output, ['61']);
    assert.deepEqual(observed.files.get('61')?.bytes ?? null, expected === null ? null : Buffer.from(expected));
    assert.deepEqual((await workspace.readWorkspaceFiles(f.root, ['61'])).files.get('61')?.bytes ?? null, localBytes === null ? null : Buffer.from(localBytes));
    const saved = await readFile(join(f.output, 'refresh.json')); assert.equal(sha256(saved), plan.refresh_sha256);
    assert.deepEqual(await readFile(join(f.output, 'source.json')), next.bytes);
    const status = await workspace.inspectSourceWorkspace(f.output, result.workspace_sha256);
    assert.equal(status.source_commit, next.expected.commit);
    assert.equal(status.entries[0].state, expected === null ? 'deleted' : Buffer.from(expected).equals(Buffer.from(nextBytes)) ? 'unchanged' : 'modified');
  });
  test(`${format}: all independent content/mode combinations`, async t => {
    for (const beforeMode of [false, true]) for (const localMode of [false, true]) for (const nextMode of [false, true]) {
      for (const [ours, theirs, content] of [['base', 'source', 'source'], ['local', 'base', 'local'], ['both', 'both', 'both']]) {
        const f = await setup(t, [{ bytes: 'base', executable: beforeMode }], format);
        await local(f, '61', ours, localMode);
        const next = source([{ bytes: theirs, executable: nextMode }], format, 'next');
        const plan = await f.preview(next); assert(plan.ready);
        const result = await f.apply(next, plan.refresh_sha256);
        const actual = (await workspace.readWorkspaceFiles(f.output, ['61'])).files.get('61');
        assert.deepEqual(actual.bytes, Buffer.from(content));
        assert.equal(actual.executable, localMode === beforeMode ? nextMode : localMode);
        assert.equal(result.source_commit, next.expected.commit);
      }
    }
  });
}

test('preview collects all conflicts in deterministic byte-path order and creates nothing', async t => {
  const f = await setup(t, [{ path: '622fff', bytes: 'B' }, { path: '61', bytes: 'A' }]);
  await local(f, '61', 'local A'); await local(f, '622fff', null);
  const next = source([{ path: '622fff', bytes: 'other B' }, { path: '61', bytes: 'other A' }], 'sha1', 'next');
  const a = await f.preview(next), b = await f.preview(next);
  assert.deepEqual(a, b); assert.equal(a.conflict_count, 2); assert.equal(a.result_bytes, 0);
  assert.deepEqual(a.entries.map(e => e.path_hex), ['61', '622fff']);
  assert.deepEqual(await readdir(f.parent), ['original']);
});
for (const [name, change] of [
  ['content', f => local(f, '61', 'second edit')],
  ['mode', f => chmod(workspace.localPath(f.root, '61'), 0o700)],
  ['deletion', f => local(f, '61', null)],
]) test(`stale approval after changed ${name} refuses without output`, async t => {
  const f = await setup(t), next = source([{ bytes: 'base' }], 'sha1', 'next');
  const plan = await f.preview(next); await change(f);
  await assert.rejects(f.apply(next, plan.refresh_sha256), { code: 'source_workspace_refresh_review_changed' });
  assert(!existsSync(f.output));
});
test('review pins complete next package bytes and independently selected commit', async t => {
  const f = await setup(t), next = source([{ bytes: 'next' }], 'sha1', 'next');
  const plan = await f.preview(next);
  const other = source([{ bytes: 'next' }], 'sha1', 'other');
  await assert.rejects(f.apply(other, plan.refresh_sha256), { code: 'source_workspace_refresh_review_changed' });
  const padded = { ...next, bytes: Buffer.concat([next.bytes, Buffer.from(' ')]) };
  await assert.rejects(f.apply(padded, plan.refresh_sha256), { code: 'source_workspace_refresh_review_changed' });
  assert(!existsSync(f.output));
});
for (const [name, make, code] of [
  ['same commit', f => f.original, 'source_workspace_refresh_same_commit'],
  ['other format', () => source([{ bytes: 'base' }], 'sha256', 'next'), 'source_workspace_refresh_format'],
  ['dropped selected path', () => source([{ path: '62', bytes: 'base' }], 'sha1', 'next'), 'source_workspace_refresh_selection'],
  ['extra selected path', () => source([{ bytes: 'base' }, { path: '62', bytes: 'new' }], 'sha1', 'next'), 'source_workspace_refresh_selection'],
]) test(`${name} is not silently treated as a refresh`, async t => {
  const f = await setup(t);
  await assert.rejects(f.preview(make(f)), { code }); assert(!existsSync(f.output));
});
test('bad independent source expectation is rejected before local file reads', async t => {
  const f = await setup(t), next = source([{ bytes: 'next' }], 'sha1', 'next');
  next.expected.files[0].blob = '1'.repeat(40);
  await chmod(workspace.localPath(f.root, '61'), 0o666);
  await assert.rejects(f.preview(next), e => e.code === 'ERR_ASSERTION');
  assert(!existsSync(f.output));
});
test('caller changes after invocation cannot substitute next bytes or expectation', async t => {
  const f = await setup(t), next = source([{ bytes: 'next' }], 'sha1', 'next');
  const chosen = next.expected.commit, task = f.preview(next);
  next.bytes.fill(0); next.expected.commit = 'f'.repeat(40); next.expected.files.length = 0;
  assert.equal((await task).selected_commit, chosen);
});
test('source verifier cancellation runs before observing mutable files', async t => {
  const f = await setup(t), next = source([{ bytes: 'next' }], 'sha1', 'next'), c = new AbortController();
  hooks.verify = async (_bytes, expected) => { if (expected.commit === next.expected.commit) c.abort(); };
  try { await assert.rejects(f.preview(next, { signal: c.signal }), { name: 'AbortError' }); }
  finally { hooks.verify = null; }
  assert(!existsSync(f.output));
});
test('unselected local files are retained only in the original and never examined', async t => {
  const f = await setup(t), next = source([{ bytes: 'next' }], 'sha1', 'next');
  await symlink('/unavailable/secret', join(f.root, 'files', 'unselected'));
  const plan = await f.preview(next); await f.apply(next, plan.refresh_sha256);
  assert.deepEqual(await readdir(join(f.output, 'files')), ['a']);
  assert((await lstat(join(f.root, 'files', 'unselected'))).isSymbolicLink());
});
for (const name of ['symlink', 'hardlink', 'world-readable', 'directory']) test(`${name} at a selected file is refused`, async t => {
  const f = await setup(t), next = source([{ bytes: 'base' }], 'sha1', 'next'), path = workspace.localPath(f.root, '61');
  if (name === 'world-readable') await chmod(path, 0o644);
  else if (name === 'hardlink') await link(path, join(f.parent, 'alias'));
  else { await local(f, '61', null); if (name === 'symlink') await symlink('/unavailable', path); else await mkdir(path, { mode: 0o700 }); }
  await assert.rejects(f.preview(next)); assert(!existsSync(f.output));
});
test('original baseline root alteration is refused', async t => {
  const f = await setup(t), next = source([{ bytes: 'base' }], 'sha1', 'next');
  await writeFile(join(f.root, 'manifest.json'), '{}\n');
  await assert.rejects(f.preview(next), { code: 'source_workspace_manifest_changed' });
});
test('combined materialization budget applies even when both source and local fit separately', async t => {
  const before = Array.from({ length: 16 }, (_, i) => ({ path: Buffer.from(`file${String(i).padStart(2, '0')}`).toString('hex'), bytes: '' }));
  const f = await setup(t, before), big = Buffer.alloc(workspace.WORKSPACE_LIMITS.fileBytes, 65);
  for (const row of before.slice(0, 8)) await local(f, row.path, big);
  const next = source(before.map((row, i) => ({ ...row, bytes: i < 8 ? '' : big })), 'sha1', 'next');
  await assert.rejects(f.preview(next), { code: 'source_workspace_refresh_output_budget' }); assert(!existsSync(f.output));
});
test('competing refresh creators never overwrite each other', async t => {
  const f = await setup(t), next = source([{ bytes: 'source' }], 'sha1', 'next'), plan = await f.preview(next);
  const results = await Promise.allSettled([f.apply(next, plan.refresh_sha256), f.apply(next, plan.refresh_sha256)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal((await readFile(workspace.localPath(f.output, '61'))).toString(), 'source');
});
test('overlapping destinations refuse before creating or modifying directories', async t => {
  const f = await setup(t), next = source([{ bytes: 'source' }], 'sha1', 'next'), plan = await f.preview(next);
  for (const dest of [f.root, join(f.root, 'child'), f.parent]) {
    await assert.rejects(workspace.refreshSourceWorkspace(f.root, f.created.workspace_sha256, next.bytes, next.expected, dest, plan.refresh_sha256), { code: 'source_workspace_overlapping_output' });
  }
  assert.deepEqual(await readdir(f.parent), ['original']);
});
test('pre-cancelled refresh does not own an output slot', async t => {
  const f = await setup(t), next = source([{ bytes: 'source' }], 'sha1', 'next'), c = new AbortController(); c.abort();
  await assert.rejects(f.apply(next, 'a'.repeat(64), { signal: c.signal }), { name: 'AbortError' }); assert(!existsSync(f.output));
});
test('stop after output ownership retains the slot and both original pins', async t => {
  const f = await setup(t), next = source([{ bytes: 'source' }], 'sha1', 'next'), plan = await f.preview(next), c = new AbortController();
  await assert.rejects(f.apply(next, plan.refresh_sha256, { signal: c.signal, check: () => {
    if (existsSync(f.output)) { c.abort(); c.signal.throwIfAborted(); }
  } }), e => e.name === 'AbortError' && e.publication_unconfirmed.directory === f.output && e.publication_unconfirmed.refresh_sha256 === plan.refresh_sha256);
  assert(existsSync(f.output)); assert(!existsSync(join(f.output, 'manifest.json')));
  await assert.rejects(f.apply(next, plan.refresh_sha256), { code: 'source_workspace_output_exists' });
});
test('editor race during publication never marks a changed observation complete', async t => {
  const f = await setup(t), next = source([{ bytes: 'base' }], 'sha1', 'next'), plan = await f.preview(next); let changed = false;
  await assert.rejects(f.apply(next, plan.refresh_sha256, { check: () => {
    if (!changed && existsSync(join(f.output, 'source.json'))) { changed = true; writeFileSync(workspace.localPath(f.root, '61'), 'late edit'); }
  } }), e => e.code === 'source_workspace_changed' && e.publication_unconfirmed.refresh_sha256 === plan.refresh_sha256);
  assert(changed); assert(!existsSync(join(f.output, 'manifest.json')));
  assert.equal((await readFile(workspace.localPath(f.root, '61'))).toString(), 'late edit');
});
test('original root replacement during publication is refused', async t => {
  const f = await setup(t), next = source([{ bytes: 'base' }], 'sha1', 'next'), plan = await f.preview(next); let replaced = false;
  // Trigger from a verified-source boundary, not from a production test hook.
  hooks.verify = async (_bytes, expected) => {
    if (expected.commit === next.expected.commit && !replaced) {
      replaced = true; await rename(f.root, `${f.root}-old`); await mkdir(f.root, { mode: 0o700 });
    }
  };
  try { await assert.rejects(f.apply(next, plan.refresh_sha256)); } finally { hooks.verify = null; }
  assert(replaced); assert(!existsSync(f.output));
});
