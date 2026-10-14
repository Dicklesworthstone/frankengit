// Real private POSIX custody; no native authority or hardware durability claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile, lstat, chmod, link, symlink, unlink } from 'node:fs/promises';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { canonical, sha256 } from '../operator/source_changes.mjs';
import { assembleSourceChanges } from '../operator/source_assembly.mjs';
import { captureSourceAssembly, loadSourceAssembly } from '../operator/source_assembly_capture.mjs';
import { changeFixture, intent, replace } from './source_changes_fixture.mjs';
import { contribution } from './source_assembly_fixture.mjs';
const missing = path => assert.rejects(lstat(path), { code: 'ENOENT' });
async function setup(t, format = 'sha1') {
  const f = changeFixture(format, [{ path: 'a', bytes: 'A' }, { path: 'b', bytes: 'B' }, { path: 'context', bytes: 'read only' }]);
  const input = await Promise.all(['a', 'b'].map(id => contribution(f, id, [id, 'context'], intent([replace(id, `${id} changed`)]))));
  const root = await mkdtemp(join(tmpdir(), 'fg-source-assembly-')); t.after(() => rm(root, { recursive: true, force: true }));
  const output = join(root, 'capture'); return { f, input, root, output, capture: (options = {}) => captureSourceAssembly(output, input, options) };
}
async function rehash(path, change) {
  const manifest = JSON.parse(await readFile(join(path, 'manifest.json'))); await change(manifest);
  for (const row of manifest.payloads) { const bytes = await readFile(join(path, row.name)); row.bytes = bytes.length; row.sha256 = sha256(bytes); }
  const root = canonical(manifest); await writeFile(join(path, 'manifest.json'), root); return sha256(root);
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: self-contained capture re-verifies original reviews and exact combined draft`, async t => {
    const s = await setup(t, format), expected = await assembleSourceChanges(s.input), saved = await s.capture();
    const result = await loadSourceAssembly(s.output, saved.capture_sha256);
    assert.deepEqual(result.receipt, expected.receipt); assert.deepEqual(result.draft.bytes, expected.draft.bytes);
    assert.equal(saved.draft_sha256, expected.receipt.draft_sha256); assert.equal(saved.contribution_count, 2);
    assert.equal((await lstat(s.output)).mode & 0o777, 0o700);
    const manifest = JSON.parse(await readFile(join(s.output, 'manifest.json')));
    for (const name of [...manifest.payloads.map(row => row.name), 'manifest.json']) assert.equal((await lstat(join(s.output, name))).mode & 0o777, 0o600);
    s.input[0].packageBytes.fill(0); s.input[1].changes.changes.length = 0;
    assert.deepEqual((await loadSourceAssembly(s.output, saved.capture_sha256)).receipt, expected.receipt);
  });
  test(`${format}: capture order does not change retained roots and existing output cannot be replaced`, async t => {
    const s = await setup(t, format), saved = await s.capture(), another = await captureSourceAssembly(join(s.root, 'other'), [...s.input].reverse());
    assert.equal(saved.capture_sha256, another.capture_sha256);
    const bytes = await readFile(join(s.output, 'manifest.json')); await assert.rejects(s.capture());
    assert.deepEqual(await readFile(join(s.output, 'manifest.json')), bytes);
  });
  test(`${format}: rehashed patch corruption still fails exact regeneration`, async t => {
    const s = await setup(t, format), saved = await s.capture();
    const hash = await rehash(s.output, async () => { const path = join(s.output, 'patch.diff'), bytes = await readFile(path); bytes[bytes.length - 2] ^= 1; await writeFile(path, bytes); });
    await assert.rejects(loadSourceAssembly(s.output, saved.capture_sha256), /capture_changed/);
    await assert.rejects(loadSourceAssembly(s.output, hash), /regeneration_mismatch/);
  });
  test(`${format}: rewritten contributor draft, union and attribution hashes cannot manufacture evidence`, async t => {
    const s = await setup(t, format); await s.capture();
    for (const name of ['contribution-0-draft.json', 'assembly.json', 'draft.json', 'changes.json']) {
      const path = join(s.output, name), original = await readFile(path);
      const hash = await rehash(s.output, async manifest => {
        const value = JSON.parse(original); value.authority_verified = true; const bytes = canonical(value); await writeFile(path, bytes);
        if (name === 'draft.json') manifest.draft_sha256 = sha256(bytes);
      });
      await assert.rejects(loadSourceAssembly(s.output, hash), /regeneration_mismatch/); await writeFile(path, original);
    }
    const hash = await rehash(s.output, async manifest => { manifest.contributions[0].confirm_draft_sha256 = '0'.repeat(64); });
    await assert.rejects(loadSourceAssembly(s.output, hash), /source_assembly_confirmation/);
  });
}
test('competing captures leave one fully verifiable owner', async t => {
  const s = await setup(t), results = await Promise.allSettled([s.capture(), s.capture()]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const saved = results.find(r => r.status === 'fulfilled').value;
  assert.equal((await loadSourceAssembly(s.output, saved.capture_sha256)).saved.draft_sha256, saved.draft_sha256);
});
test('validate every imported payload name and bound before opening any payload', async t => {
  const s = await setup(t); await s.capture(); const bytes = await readFile(join(s.output, 'manifest.json'));
  for (const mutate of [m => m.payloads.reverse(), m => m.payloads.pop(), m => { m.payloads[0].name = '../outside'; },
    m => { m.payloads[0].bytes = 1000000000; }, m => { m.contributions[1].id = m.contributions[0].id; },
    m => { m.contributions.push(...m.contributions, ...m.contributions, ...m.contributions, ...m.contributions); }]) {
    const value = JSON.parse(bytes); mutate(value); const root = canonical(value); await writeFile(join(s.output, 'manifest.json'), root);
    await assert.rejects(loadSourceAssembly(s.output, sha256(root)), /capture_inventory|capture_schema/);
  }
  await writeFile(join(s.output, 'manifest.json'), bytes); await unlink(join(s.output, 'contribution-0-source.json'));
  await assert.rejects(loadSourceAssembly(s.output, sha256(bytes)), { code: 'ENOENT' });
});
test('public, symlink and hardlinked payloads refuse with a private-file permitted twin', async t => {
  const s = await setup(t), saved = await s.capture(), path = join(s.output, 'source.json');
  await chmod(path, 0o644); await assert.rejects(loadSourceAssembly(s.output, saved.capture_sha256)); await chmod(path, 0o600);
  await link(path, join(s.root, 'hard')); await assert.rejects(loadSourceAssembly(s.output, saved.capture_sha256)); await unlink(join(s.root, 'hard'));
  const bytes = await readFile(path); await unlink(path); await writeFile(join(s.root, 'elsewhere'), bytes, { mode: 0o600 });
  await symlink(join(s.root, 'elsewhere'), path); await assert.rejects(loadSourceAssembly(s.output, saved.capture_sha256));
  await unlink(path); await writeFile(path, bytes, { mode: 0o600 }); assert.ok(await loadSourceAssembly(s.output, saved.capture_sha256));
  await symlink(s.output, join(s.root, 'alias')); await assert.rejects(loadSourceAssembly(join(s.root, 'alias'), saved.capture_sha256));
});
test('cancellation and bad original reviews before reservation leave no output', async t => {
  const s = await setup(t), stop = new AbortController(); stop.abort();
  await assert.rejects(s.capture({ signal: stop.signal })); await missing(s.output);
  const pin = s.input[1].confirmDraftSha256; s.input[1].confirmDraftSha256 = 'f'.repeat(64);
  await assert.rejects(s.capture(), /confirmation/); await missing(s.output);
  s.input[1].confirmDraftSha256 = pin; assert.ok(await s.capture());
});
test('interrupted owned payload writes retain an incomplete slot, not a false complete root', async t => {
  const s = await setup(t), stop = new AbortController(), original = performance.now.bind(performance);
  Object.defineProperty(performance, 'now', { configurable: true, value: () => {
    if (existsSync(join(s.output, 'contribution-0-source.json'))) stop.abort(); return original();
  } });
  try { await assert.rejects(s.capture({ signal: stop.signal }), e => { assert.equal(e.publication_unconfirmed.directory, s.output); return true; }); }
  finally { Object.defineProperty(performance, 'now', { configurable: true, value: original }); }
  assert.ok(existsSync(s.output)); await missing(join(s.output, 'manifest.json')); await assert.rejects(s.capture());
});
test('a competing payload file is not overwritten after the directory was reserved', async t => {
  const s = await setup(t), original = performance.now.bind(performance); let injected = false;
  Object.defineProperty(performance, 'now', { configurable: true, value: () => {
    if (!injected && existsSync(s.output)) { injected = true; writeFileSync(join(s.output, 'source.json'), 'another writer', { mode: 0o600, flag: 'wx' }); }
    return original();
  } });
  try { await assert.rejects(s.capture(), e => !!e.publication_unconfirmed); }
  finally { Object.defineProperty(performance, 'now', { configurable: true, value: original }); }
  assert.equal(await readFile(join(s.output, 'source.json'), 'utf8'), 'another writer'); await missing(join(s.output, 'manifest.json'));
});
test('read-only inspection does not repair or modify any payload or manifest', async t => {
  const s = await setup(t), saved = await s.capture(); const manifest = JSON.parse(await readFile(join(s.output, 'manifest.json')));
  const names = [...manifest.payloads.map(r => r.name), 'manifest.json'];
  const before = await Promise.all(names.map(async n => [await lstat(join(s.output, n)), await readFile(join(s.output, n))]));
  await loadSourceAssembly(s.output, saved.capture_sha256);
  for (const [i, name] of names.entries()) { const stat = await lstat(join(s.output, name));
    assert.equal(stat.mtimeMs, before[i][0].mtimeMs); assert.deepEqual(await readFile(join(s.output, name)), before[i][1]); }
});
test('capture owns all source and review inputs before the first asynchronous file check', async t => {
  const s = await setup(t), expected = await assembleSourceChanges(s.input), promise = s.capture();
  s.input[0].packageBytes.fill(0); s.input[1].confirmDraftSha256 = 'f'.repeat(64); s.input[1].changes.changes.length = 0;
  const saved = await promise; assert.deepEqual((await loadSourceAssembly(s.output, saved.capture_sha256)).receipt, expected.receipt);
});
