import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile, chmod, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { spawn } from 'node:child_process';
import { setup, source, local, canonical, workspace, initWorkspace, loadCli } from './source_workspace_refresh.fixture.mjs';
await initWorkspace();
const cli = await loadCli();
function sink(failure = false) {
  let text = ''; const stream = new Writable({ write(bytes, _encoding, done) { text += bytes; done(failure ? new Error('lost stdout') : null); } });
  return { stream, get text() { return text; } };
}
async function input(f, next) {
  const pkg = join(f.parent, 'next.json'), expected = join(f.parent, 'expect.json');
  await writeFile(pkg, next.bytes, { mode: 0o600 }); await writeFile(expected, canonical(next.expected), { mode: 0o600 });
  return ['--workspace', f.root, '--sha256', f.created.workspace_sha256, '--package', pkg, '--expect', expected];
}
async function invoke(args, brokenOutput = false) {
  const stdout = sink(brokenOutput), stderr = sink(), before = process.listenerCount('SIGTERM');
  const code = await cli.main(args, { stdout: stdout.stream, stderr: stderr.stream });
  assert.equal(process.listenerCount('SIGTERM'), before);
  return { code, out: stdout.text ? JSON.parse(stdout.text) : null, error: stderr.text ? JSON.parse(stderr.text) : null };
}
for (const format of ['sha1', 'sha256']) test(`${format}: CLI preview -> approved refresh -> reopened status`, async t => {
  const f = await setup(t, undefined, format); await local(f, '61', 'edited');
  const args = await input(f, source([{ bytes: 'base' }], format, 'next'));
  const preview = await invoke(['refresh-preview', ...args]); assert.equal(preview.code, 0); assert(preview.out.ready);
  const result = await invoke(['refresh', ...args, '--approve-refresh-sha256', preview.out.refresh_sha256, '--output', f.output]);
  assert.equal(result.code, 0); assert.equal(result.out.type, 'source_workspace_refreshed');
  const status = await invoke(['status', '--workspace', f.output, '--sha256', result.out.workspace_sha256]);
  assert.equal(status.code, 0); assert.equal(status.out.entries[0].state, 'modified');
  assert.equal((await readFile(workspace.localPath(f.output, '61'))).toString(), 'edited');
});
test('CLI conflict preview is distinct from a completed refresh', async t => {
  const f = await setup(t); await local(f, '61', 'local');
  const args = await input(f, source([{ bytes: 'remote' }], 'sha1', 'next'));
  const preview = await invoke(['refresh-preview', ...args]); assert.equal(preview.code, 1); assert.equal(preview.out.conflict_count, 1);
  const result = await invoke(['refresh', ...args, '--approve-refresh-sha256', preview.out.refresh_sha256, '--output', f.output]);
  assert.equal(result.code, 2); assert.equal(result.error.code, 'source_workspace_refresh_conflict'); assert(!existsSync(f.output));
});
for (const [name, transform] of [
  ['missing approval', a => a.filter((_s, i) => i < 9).concat(['--output', '/not-created'])],
  ['unknown override', a => [...a, '--force', 'true']],
  ['duplicate workspace', a => [...a, '--workspace', '/elsewhere']],
  ['invalid approval', a => a.map(v => v === 'a'.repeat(64) ? 'APPROVE' : v)],
]) test(`CLI ${name} refuses before work`, async t => {
  const f = await setup(t), args = ['refresh', ...await input(f, source([{ bytes: 'next' }], 'sha1', 'next')),
    '--approve-refresh-sha256', 'a'.repeat(64), '--output', f.output];
  const result = await invoke(transform(args)); assert.equal(result.code, 2); assert(!existsSync(f.output));
});
test('CLI rejects non-private source files', async t => {
  const f = await setup(t), args = await input(f, source([{ bytes: 'next' }], 'sha1', 'next'));
  await chmod(join(f.parent, 'next.json'), 0o644);
  const result = await invoke(['refresh-preview', ...args]); assert.equal(result.code, 2); assert.equal(result.out, null);
});
test('lost CLI output retains the completed workspace and its original plan pin', async t => {
  const f = await setup(t), args = await input(f, source([{ bytes: 'next' }], 'sha1', 'next'));
  const preview = await invoke(['refresh-preview', ...args]);
  const result = await invoke(['refresh', ...args, '--approve-refresh-sha256', preview.out.refresh_sha256, '--output', f.output], true);
  assert.equal(result.code, 4); assert.equal(result.error.retained_result.refresh_sha256, preview.out.refresh_sha256);
  assert(existsSync(join(f.output, 'manifest.json')));
  const repeated = await invoke(['refresh', ...args, '--approve-refresh-sha256', preview.out.refresh_sha256, '--output', f.output]);
  assert.equal(repeated.code, 2); assert.equal(repeated.error.code, 'source_workspace_output_exists');
});
test('production CLI body executes in a real child with explicit source-service fixtures', async t => {
  const f = await setup(t), args = await input(f, source([{ bytes: 'next' }], 'sha1', 'next'));
  const fixture = new URL('./source_workspace_refresh.fixture.mjs', import.meta.url).href;
  const code = `const f = await import(${JSON.stringify(fixture)}); await f.initWorkspace(); const c = await f.loadCli(); process.exitCode = await c.main(process.argv.slice(1));`;
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', code, 'refresh-preview', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = ''; child.stdout.on('data', b => out += b); child.stderr.on('data', b => err += b);
    child.once('error', reject); child.once('close', exit => resolve({ exit, out, err }));
  });
  assert.equal(result.exit, 0, result.err); assert.equal(JSON.parse(result.out).type, 'source_workspace_refresh_plan');
  assert.deepEqual((await readdir(f.parent)).sort(), ['expect.json', 'next.json', 'original']);
});

test('CLI selects exact conflict sides only after a new resolved-plan review', async t => {
  const f = await setup(t); await local(f, '61', 'local');
  const args = await input(f, source([{ bytes: 'source' }], 'sha1', 'next'));
  const original = await invoke(['refresh-preview', ...args]); assert.equal(original.code, 1);
  const file = join(f.parent, 'choices.json');
  await writeFile(file, canonical({ schema: workspace.WORKSPACE_REFRESH_RESOLUTIONS, plan_sha256: original.out.refresh_sha256,
    choices: [{ path_hex: '61', choice: 'selected' }] }), { mode: 0o600 });
  const resolved = await invoke(['refresh-preview', ...args, '--resolutions', file]); assert.equal(resolved.code, 0); assert(resolved.out.ready);
  const wrong = await invoke(['refresh', ...args, '--resolutions', file, '--approve-refresh-sha256', original.out.refresh_sha256, '--output', f.output]);
  assert.equal(wrong.code, 2); assert(!existsSync(f.output));
  const result = await invoke(['refresh', ...args, '--resolutions', file, '--approve-refresh-sha256', resolved.out.refresh_sha256, '--output', f.output, '--timeout-ms', '30000']);
  assert.equal(result.code, 0); assert.equal((await readFile(workspace.localPath(f.output, '61'))).toString(), 'source');
  assert.equal((await readFile(workspace.localPath(f.root, '61'))).toString(), 'local');
});
test('CLI rejects stale/private-invalid/unknown resolution inputs rather than omitting them', async t => {
  const f = await setup(t); await local(f, '61', 'local');
  const args = await input(f, source([{ bytes: 'source' }], 'sha1', 'next'));
  const file = join(f.parent, 'choices.json');
  await writeFile(file, canonical({ schema: workspace.WORKSPACE_REFRESH_RESOLUTIONS, plan_sha256: '0'.repeat(64), choices: [{ path_hex: '61', choice: 'local' }] }), { mode: 0o600 });
  const stale = await invoke(['refresh-preview', ...args, '--resolutions', file]);
  assert.equal(stale.code, 2); assert.equal(stale.error.code, 'source_workspace_refresh_resolution_plan_changed');
  await chmod(file, 0o644); assert.equal((await invoke(['refresh-preview', ...args, '--resolutions', file])).code, 2);
  assert.equal((await invoke(['status', '--workspace', f.root, '--sha256', f.created.workspace_sha256, '--resolutions', file])).code, 2);
});
