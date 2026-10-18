import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { fixture, TOKEN } from './fixtures/pull_sync_native.mjs';
import { main } from '../../scripts/fg_pull_sync.mjs';
import { loadPlan } from '../../scripts/operator/pull_sync_custody.mjs';
const cli = new URL('../../scripts/fg_pull_sync.mjs', import.meta.url).pathname;
async function local(t) {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'fg-sync-')); t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'state'), { mode: 0o700 });
  await writeFile(join(root, 'dest'), JSON.stringify(f.dest), { mode: 0o600 }); await writeFile(join(root, 'token'), TOKEN + '\n', { mode: 0o600 });
  return { ...f, root, stateDir: join(root, 'state'), base: ['--destination', join(root, 'dest'), '--token-file', join(root, 'token'), '--pr', '1'] };
}
function child(args) {
  const p = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] }); let out = '', err = '';
  p.stdout.on('data', b => out += b); p.stderr.on('data', b => err += b);
  return new Promise((resolve, reject) => { p.once('error', reject); p.once('close', code => resolve({ code, out, err })); });
}
test('CLI inspect/prepare/show use actual private files and create no remote mutation', async t => {
  const f = await local(t); let result = await child(['inspect', ...f.base]); assert.equal(result.code, 0, result.err);
  assert.equal(JSON.parse(result.out).changes.length, 1);
  result = await child(['prepare', ...f.base, '--state', f.stateDir]); assert.equal(result.code, 0, result.err);
  const plan = await loadPlan(f.stateDir); assert.equal(plan.requests.length, 1); assert.ok(!JSON.stringify(plan).includes(TOKEN));
  const count = f.calls.length; result = await child(['show', '--state', f.stateDir]); assert.equal(result.code, 0, result.err);
  assert.equal(JSON.parse(result.out).plan_sha256, plan.plan_sha256); assert.equal(f.calls.length, count);
  assert.equal(f.decisions.size, 0); assert.ok(f.calls.every(c => !c.path.endsWith('/update')));
});
test('CLI refuses ambiguous selection, duplicate controls and unknown fields before HTTP', async t => {
  const f = await local(t);
  for (const extras of [['--all-open'], ['--pr', '1'], ['--timeout-ms', '01'], ['--force'], ['--token-file', join(f.root, 'token')]]) {
    const result = await child(['inspect', ...f.base, ...extras]); assert.equal(result.code, 2, result.err);
  }
  assert.equal(f.calls.length, 0);
});
test('existing plans are never replaced, even when newly observed branch tips differ', async t => {
  const f = await local(t); await child(['prepare', ...f.base, '--state', f.stateDir]); const bytes = await readFile(join(f.stateDir, 'plan.json'));
  f.state.tips.set('refs/heads/topic-1', 'f'.repeat(40)); const result = await child(['prepare', ...f.base, '--state', f.stateDir]);
  assert.equal(result.code, 2); assert.deepEqual(await readFile(join(f.stateDir, 'plan.json')), bytes);
});
test('unsafe token files and aliased state directories refuse', async t => {
  const f = await local(t); await chmod(join(f.root, 'token'), 0o644);
  assert.equal((await child(['inspect', ...f.base])).code, 2); assert.equal(f.calls.length, 0);
  await chmod(join(f.root, 'token'), 0o600); await symlink(f.stateDir, join(f.root, 'alias'));
  assert.equal((await child(['prepare', ...f.base, '--state', join(f.root, 'alias')])).code, 2);
});
test('output failure after preparation preserves the saved plan and reports exit four', async t => {
  const f = await local(t); let errors = '';
  const stdout = new Writable({ write(_b, _enc, done) { done(new Error('output lost')); } });
  const stderr = new Writable({ write(b, _enc, done) { errors += b; done(); } });
  const result = await main(['prepare', ...f.base, '--state', f.stateDir], { stdout, stderr });
  assert.equal(result, 4); assert.equal(JSON.parse(errors).retained_plan_sha256, (await loadPlan(f.stateDir)).plan_sha256);
});
