// Real merge kernel, workspace ownership and CLI bodies; pre-existing source
// verification/codec services remain the explicit refresh contract fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { workspace, initWorkspace, setup, source, local, canonical, sha256, loadCli } from './source_workspace_refresh.fixture.mjs';
await initWorkspace();
const cli = await loadCli(), mergeProfile = workspace.WORKSPACE_TEXT_MERGE_PROFILE;
const base = 'alpha\nbeta\ngamma\ndelta\nepsilon\n', ours = base.replace('alpha', 'local'), theirs = base.replace('epsilon', 'selected');
const output = ours.replace('epsilon', 'selected');
for (const format of ['sha1', 'sha256']) for (const localMode of [false, true]) test(`${format}/${localMode}: refresh merges disjoint content with independent modes`, async t => {
  const f = await setup(t, [{ bytes: base }], format); await local(f, '61', ours, localMode);
  const next = source([{ bytes: theirs, executable: !localMode }], format, 'next');
  const conservative = await f.preview(next); assert.equal(conservative.ready, false); assert(!Object.hasOwn(conservative, 'merge_profile'));
  const plan = await f.preview(next, { mergeProfile });
  assert(plan.ready); assert.equal(plan.entries[0].disposition, 'text_merged'); assert.equal(plan.merge_profile, mergeProfile);
  assert.equal(plan.entries[0].result.sha256, sha256(Buffer.from(output))); assert.equal(plan.text_merge.attempts, 1);
  assert.equal(plan.text_merge.exhausted, null); assert(plan.text_merge.work_used > 0);
  assert.deepEqual(plan, await f.preview(next, { mergeProfile }));
  await assert.rejects(f.apply(next, conservative.refresh_sha256, { mergeProfile }), { code: 'source_workspace_refresh_review_changed' });
  await assert.rejects(f.apply(next, plan.refresh_sha256), { code: 'source_workspace_refresh_review_changed' }); assert(!existsSync(f.output));
  const done = await f.apply(next, plan.refresh_sha256, { mergeProfile });
  const files = await workspace.readWorkspaceFiles(f.output, ['61']), merged = files.files.get('61');
  assert.equal(merged.bytes.toString(), output); assert.equal(merged.executable, true);
  assert.equal((await readFile(workspace.localPath(f.root, '61'))).toString(), ours);
  assert.equal((await workspace.inspectSourceWorkspace(f.output, done.workspace_sha256)).entries[0].state, 'modified');
  assert.equal(sha256(await readFile(join(f.output, 'refresh.json'))), plan.refresh_sha256);
});
test('explicit profile changes consent even when no text merge is needed', async t => {
  const f = await setup(t, [{ bytes: base }]), next = source([{ bytes: theirs }], 'sha1', 'next');
  const old = await f.preview(next), chosen = await f.preview(next, { mergeProfile });
  assert.notEqual(chosen.refresh_sha256, old.refresh_sha256); assert.equal(chosen.text_merge.attempts, 0);
  assert.deepEqual(chosen.entries, old.entries);
  await assert.rejects(f.apply(next, old.refresh_sha256, { mergeProfile }), { code: 'source_workspace_refresh_review_changed' });
});
for (const value of [null, undefined, '', true, 'git', 'bounded-line-merge-v2']) test(`unknown/implicit merge profile ${String(value)} refuses`, async t => {
  const f = await setup(t), next = source([{ bytes: 'next' }], 'sha1', 'next');
  await assert.rejects(f.preview(next, { mergeProfile: value }), { code: 'source_workspace_refresh_merge_profile' }); assert(!existsSync(f.output));
});
for (const [kind, old, localBytes, newBytes, reason] of [
  ['overlap', base, ours, base.replace('alpha', 'different'), 'overlapping_changes'],
  ['NUL', 'a\nb\nc\n', Buffer.from('A\0\nb\nc\n'), Buffer.from('a\nb\nC\n'), 'not_text'],
  ['invalid UTF8', 'a\nb\nc\n', Buffer.from([255, 10, 98, 10, 99, 10]), Buffer.from('a\nb\nC\n'), 'not_text'],
]) test(`${kind}: unresolved text merge stays visible and explicit choices require new approval`, async t => {
  const f = await setup(t, [{ bytes: old }]); await local(f, '61', localBytes);
  const next = source([{ bytes: newBytes }], 'sha1', 'next'), plan = await f.preview(next, { mergeProfile });
  assert(!plan.ready); assert.equal(plan.entries[0].text_merge.reason, reason); assert.equal(plan.entries[0].result, null);
  await assert.rejects(f.apply(next, plan.refresh_sha256, { mergeProfile }), { code: 'source_workspace_refresh_conflict' });
  const resolutions = { schema: workspace.WORKSPACE_REFRESH_RESOLUTIONS, plan_sha256: plan.refresh_sha256, choices: [{ path_hex: '61', choice: 'local' }] };
  const resolved = await f.preview(next, { mergeProfile, resolutions }); assert(resolved.ready);
  await assert.rejects(f.apply(next, plan.refresh_sha256, { mergeProfile, resolutions }), { code: 'source_workspace_refresh_review_changed' });
  await f.apply(next, resolved.refresh_sha256, { mergeProfile, resolutions });
  assert.deepEqual(await readFile(workspace.localPath(f.output, '61')), Buffer.from(localBytes));
});
test('work remains bounded across a multi-file refresh, with no successful prefix', async t => {
  const many = Array.from({ length: 8000 }, (_, i) => `line${i}\n`).join('');
  const rows = Array.from({ length: 6 }, (_, i) => ({ path: Buffer.from(`p${i}`).toString('hex'), bytes: many }));
  const f = await setup(t, rows); for (const row of rows) await local(f, row.path, many.replace('line1\n', 'local\n'));
  const next = source(rows.map(row => ({ ...row, bytes: many.replace('line7999\n', 'selected\n') })), 'sha1', 'next');
  const plan = await f.preview(next, { mergeProfile }); assert(!plan.ready); assert.equal(plan.text_merge.exhausted, 'line_limit');
  assert(plan.text_merge.lines_used <= plan.text_merge.limits.lines); assert(plan.entries.some(e => e.disposition === 'text_merged'));
  assert(plan.entries.some(e => e.text_merge.reason === 'line_limit'));
  await assert.rejects(f.apply(next, plan.refresh_sha256, { mergeProfile }), { code: 'source_workspace_refresh_conflict' }); assert(!existsSync(f.output));
});
test('same-line choices from the old profile cannot apply under the textual profile', async t => {
  const f = await setup(t, [{ bytes: base }]); await local(f, '61', ours);
  const next = source([{ bytes: base.replace('alpha', 'remote') }], 'sha1', 'next'), old = await f.preview(next);
  const resolutions = { schema: workspace.WORKSPACE_REFRESH_RESOLUTIONS, plan_sha256: old.refresh_sha256, choices: [{ path_hex: '61', choice: 'local' }] };
  await assert.rejects(f.preview(next, { mergeProfile, resolutions }), { code: 'source_workspace_refresh_resolution_plan_changed' });
});
test('changed editor image cannot reuse an approved automatic merge', async t => {
  const f = await setup(t, [{ bytes: base }]); await local(f, '61', ours);
  const next = source([{ bytes: theirs }], 'sha1', 'next'), plan = await f.preview(next, { mergeProfile });
  await local(f, '61', `${ours}later\n`);
  await assert.rejects(f.apply(next, plan.refresh_sha256, { mergeProfile }), { code: 'source_workspace_refresh_review_changed' }); assert(!existsSync(f.output));
});
test('editor race during automatic-merge output keeps manifest unpublished and original work intact', async t => {
  const f = await setup(t, [{ bytes: base }]); await local(f, '61', ours);
  const next = source([{ bytes: theirs }], 'sha1', 'next'), plan = await f.preview(next, { mergeProfile }); let changed = false;
  await assert.rejects(f.apply(next, plan.refresh_sha256, { mergeProfile, check() {
    if (!changed && existsSync(join(f.output, 'source.json'))) { changed = true; writeFileSync(workspace.localPath(f.root, '61'), 'late edit'); }
  } }), error => error.code === 'source_workspace_changed' && error.publication_unconfirmed.refresh_sha256 === plan.refresh_sha256);
  assert(changed); assert(!existsSync(join(f.output, 'manifest.json')));
  assert.equal((await readFile(workspace.localPath(f.root, '61'))).toString(), 'late edit');
});
async function invoke(args, failOutput = false) {
  let out = '', err = '';
  const stdout = new Writable({ write(b, _e, done) { out += b; done(failOutput ? new Error('lost stdout') : null); } });
  const stderr = new Writable({ write(b, _e, done) { err += b; done(); } });
  const code = await cli.main(args, { stdout, stderr });
  return { code, out: out ? JSON.parse(out) : null, err: err ? JSON.parse(err) : null };
}
for (const loseOutput of [false, true]) test(`CLI textual preview and application with lost output = ${loseOutput}`, async t => {
  const f = await setup(t, [{ bytes: base }]); await local(f, '61', ours);
  const next = source([{ bytes: theirs }], 'sha1', 'next');
  const pkg = join(f.parent, 'next.json'), expect = join(f.parent, 'expected.json');
  await writeFile(pkg, next.bytes, { mode: 0o600 }); await writeFile(expect, canonical(next.expected), { mode: 0o600 });
  const args = ['--workspace', f.root, '--sha256', f.created.workspace_sha256, '--package', pkg, '--expect', expect, '--merge-profile', mergeProfile];
  const preview = await invoke(['refresh-preview', ...args]); assert.equal(preview.code, 0); assert(preview.out.ready);
  const result = await invoke(['refresh', ...args, '--approve-refresh-sha256', preview.out.refresh_sha256, '--output', f.output], loseOutput);
  assert.equal(result.code, loseOutput ? 4 : 0);
  assert.equal((await readFile(workspace.localPath(f.output, '61'))).toString(), output);
  if (loseOutput) assert.equal(result.err.retained_result.refresh_sha256, preview.out.refresh_sha256);
  assert.equal((await invoke(['refresh', ...args, '--approve-refresh-sha256', preview.out.refresh_sha256, '--output', f.output])).code, 2);
});
test('CLI merge profile cannot enter other operations or select unknown algorithms', async t => {
  const f = await setup(t);
  for (const args of [
    ['status', '--workspace', f.root, '--sha256', f.created.workspace_sha256, '--merge-profile', mergeProfile],
    ['refresh-preview', '--workspace', f.root, '--sha256', f.created.workspace_sha256, '--package', '/absent', '--expect', '/absent', '--merge-profile', 'unknown'],
  ]) { const result = await invoke(args); assert.equal(result.code, 2); assert.equal(result.out, null); }
});
