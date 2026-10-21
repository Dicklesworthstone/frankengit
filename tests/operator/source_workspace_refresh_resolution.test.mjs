import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { workspace, initWorkspace, setup, source, local, canonical, sha256 } from './source_workspace_refresh.fixture.mjs';
await initWorkspace();
const resolve = (plan, choices) => ({ schema: workspace.WORKSPACE_REFRESH_RESOLUTIONS, plan_sha256: plan.refresh_sha256,
  choices: choices.map(([path_hex, choice]) => ({ path_hex, choice })) });

for (const format of ['sha1', 'sha256']) for (const choice of ['local', 'selected']) {
  for (const ours of [Buffer.from([0, 255, 10]), null]) test(`${format}: explicitly choose ${choice} for ${ours === null ? 'delete/modify' : 'content'} conflict`, async t => {
    const f = await setup(t, undefined, format); await local(f, '61', ours, true);
    const next = source([{ bytes: 'source', executable: false }], format, 'next');
    const original = await f.preview(next), resolutions = resolve(original, [['61', choice]]);
    const plan = await f.preview(next, { resolutions });
    assert(plan.ready); assert.equal(plan.conflict_count, 0); assert.equal(plan.resolved_conflict_count, 1);
    assert.equal(plan.entries[0].disposition, `resolved_${choice}`);
    assert.equal(plan.entries[0].conflict, ours === null ? 'local_delete_source_modify' : 'content_changed_both');
    assert.notEqual(plan.refresh_sha256, original.refresh_sha256);
    await assert.rejects(f.apply(next, original.refresh_sha256, { resolutions }), { code: 'source_workspace_refresh_review_changed' });
    await assert.rejects(f.apply(next, plan.refresh_sha256), { code: 'source_workspace_refresh_review_changed' });
    assert(!existsSync(f.output));
    const done = await f.apply(next, plan.refresh_sha256, { resolutions });
    const selected = (await workspace.readWorkspaceFiles(f.output, ['61'])).files.get('61');
    assert.deepEqual(selected?.bytes ?? null, choice === 'local' ? ours : Buffer.from('source'));
    if (selected) assert.equal(selected.executable, choice === 'local');
    const retained = await readFile(join(f.output, 'refresh.json')); assert.equal(sha256(retained), done.refresh_sha256);
    assert.deepEqual(JSON.parse(retained).resolution, resolutions);
    assert.equal((await workspace.loadSourceWorkspace(f.output, done.workspace_sha256)).expected.commit, next.expected.commit);
    assert.deepEqual((await workspace.readWorkspaceFiles(f.root, ['61'])).files.get('61')?.bytes ?? null, ours);
  });
}
for (const format of ['sha1', 'sha256']) for (const path of ['622ff09f98800a', '622fff']) test(`partial explicit resolutions still block all materialization; input order is canonical; ${format}; path=${path}${process.platform === 'darwin' && path === '622fff' ? ' (typed host refusal)' : ''}`, async t => {
  if (process.platform === 'darwin' && path === '622fff') {
    const f = await setup(t, undefined, format), raw = source([{ path: '61', bytes: 'valid first' }, { path, bytes: 'raw source' }], format);
    const output = join(f.parent, 'raw-name-output');
    await assert.rejects(workspace.createSourceWorkspace(output, raw.bytes, raw.expected),
      { code: 'source_workspace_host_path_unrepresentable' });
    assert.equal(existsSync(output), false);
    t.diagnostic('UNSUPPORTED_HOST_PATH: invalid UTF-8 refused before destination acquisition; identical raw-name semantics run on Linux, representable byte twin runs here.');
    return;
  }
  const f = await setup(t, [{ path: '61', bytes: 'base' }, { path, bytes: 'base' }], format);
  await local(f, '61', 'A'); await local(f, path, 'B');
  const next = source([{ path: '61', bytes: 'source A' }, { path, bytes: 'source B' }], format, 'next');
  const original = await f.preview(next), partial = resolve(original, [['61', 'selected']]);
  const plan = await f.preview(next, { resolutions: partial }); assert.equal(plan.conflict_count, 1); assert.equal(plan.ready, false);
  await assert.rejects(f.apply(next, plan.refresh_sha256, { resolutions: partial }), { code: 'source_workspace_refresh_conflict' });
  assert(!existsSync(f.output));
  const all = resolve(original, [[path, 'local'], ['61', 'selected']]);
  const completed = await f.preview(next, { resolutions: all });
  assert.deepEqual(completed, await f.preview(next, { resolutions: resolve(original, [['61', 'selected'], [path, 'local']]) }));
  await f.apply(next, completed.refresh_sha256, { resolutions: all });
  assert.equal((await readFile(workspace.localPath(f.output, '61'))).toString(), 'source A');
  assert.equal((await readFile(workspace.localPath(f.output, path))).toString(), 'B');
});
for (const [name, change] of [
  ['local bytes', async (f, _next) => local(f, '61', 'different local')],
  ['source bytes', async (_f, next) => Object.assign(next, source([{ bytes: 'different source' }], 'sha1', 'next'))],
  ['local mode', async (f, _next) => local(f, '61', 'local', true)],
  ['source commit', async (_f, next) => Object.assign(next, source([{ bytes: 'source' }], 'sha1', 'other'))],
]) test(`choices cannot carry over changed ${name}`, async t => {
  const f = await setup(t); await local(f, '61', 'local');
  const next = source([{ bytes: 'source' }], 'sha1', 'next'), original = await f.preview(next);
  const resolutions = resolve(original, [['61', 'selected']]); await change(f, next);
  await assert.rejects(f.preview(next, { resolutions }), { code: 'source_workspace_refresh_resolution_plan_changed' });
  assert(!existsSync(f.output));
});
for (const [name, change] of [
  ['unknown schema', r => r.schema = 'any'], ['null', () => null],
  ['missing pin', r => delete r.plan_sha256], ['upper-case pin', r => r.plan_sha256 = 'A'.repeat(64)],
  ['empty choices', r => r.choices = []], ['too many choices', r => r.choices = Array(33).fill(r.choices[0])],
  ['duplicate choices', r => r.choices.push({ ...r.choices[0] })],
  ['unknown choice', r => r.choices[0].choice = 'force'], ['extra field', r => r.force = true],
  ['inline bytes', r => r.choices[0].bytes = 'unreviewed'], ['unsafe path', r => r.choices[0].path_hex = '2e2e'],
]) test(`resolution input refuses ${name}`, async t => {
  const f = await setup(t); await local(f, '61', 'local');
  const next = source([{ bytes: 'source' }], 'sha1', 'next'), original = await f.preview(next);
  const resolutions = resolve(original, [['61', 'local']]);
  const replacement = change(resolutions);
  await assert.rejects(f.preview(next, { resolutions: name === 'null' ? replacement : resolutions })); assert(!existsSync(f.output));
});
for (const target of ['61', '62']) test(`a resolution for ${target} cannot override a non-conflict or invent a path`, async t => {
  const f = await setup(t), next = source([{ bytes: 'source' }], 'sha1', 'next'), original = await f.preview(next);
  await assert.rejects(f.preview(next, { resolutions: resolve(original, [[target, 'local']]) }), { code: 'source_workspace_refresh_resolution_not_conflict' });
});
test('resolution objects are owned before an async source read', async t => {
  const f = await setup(t); await local(f, '61', 'local');
  const next = source([{ bytes: 'source' }], 'sha1', 'next'), original = await f.preview(next);
  const resolutions = resolve(original, [['61', 'local']]); const pending = f.preview(next, { resolutions });
  resolutions.choices[0].choice = 'selected'; resolutions.choices.length = 0; resolutions.plan_sha256 = 'a'.repeat(64);
  const plan = await pending; assert.equal(plan.entries[0].disposition, 'resolved_local');
  assert.equal(plan.entries[0].result.sha256, sha256(Buffer.from('local')));
});
test('resolved output has its own byte ceiling, even for two individually bounded conflicting inputs', async t => {
  const rows = Array.from({ length: 10 }, (_, i) => ({ path: Buffer.from(`file${i}`).toString('hex'), bytes: 'base' }));
  const f = await setup(t, rows), big = Buffer.alloc(950000, 65);
  for (const [i, row] of rows.entries()) await local(f, row.path, i < 5 ? big : 'local');
  const next = source(rows.map((row, i) => ({ ...row, bytes: i < 5 ? 'source' : big })), 'sha1', 'next');
  const original = await f.preview(next); assert.equal(original.conflict_count, 10);
  const resolutions = resolve(original, rows.map((row, i) => [row.path, i < 5 ? 'local' : 'selected']));
  await assert.rejects(f.preview(next, { resolutions }), { code: 'source_workspace_refresh_output_budget' }); assert(!existsSync(f.output));
});
test('preview and side choice never change earlier publication or recovery keys', async t => {
  const f = await setup(t); await local(f, '61', 'local');
  const next = source([{ bytes: 'source' }], 'sha1', 'next'), original = await f.preview(next);
  const plan = await f.preview(next, { resolutions: resolve(original, [['61', 'selected']]) });
  const text = canonical(plan).toString();
  assert(!text.includes('idempotency')); assert(!text.includes('principal_id'));
  assert.equal(plan.repository_changed, false); assert.equal(plan.authority_verified, false);
  assert.deepEqual((await workspace.readWorkspaceFiles(f.root, ['61'])).files.get('61').bytes, Buffer.from('local'));
});
