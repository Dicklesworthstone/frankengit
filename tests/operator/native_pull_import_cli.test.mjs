import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main } from '../../scripts/migrate_native_pulls.mjs';
import { importFixture } from './native-pull-import-fixture.mjs';
const script = fileURLToPath(new URL('../../scripts/migrate_native_pulls.mjs', import.meta.url));
export function child(args) {
  const proc = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  return { proc, done: new Promise((resolve, reject) => {
    let out = '', err = ''; const timer = setTimeout(() => { proc.kill('SIGKILL'); reject(new Error('CLI test deadline')); }, 15000);
    proc.stdout.on('data', b => out += b); proc.stderr.on('data', b => err += b);
    proc.on('error', reject); proc.on('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, out, err }); });
  }) };
}
async function preparation(f) {
  const selectionFile = join(f.root, 'selection.json'); await writeFile(selectionFile, JSON.stringify(f.selection), { mode: 0o600 });
  return ['prepare', '--archive-dir', f.archiveDir, '--archive-confirm', f.archiveConfirm, '--selection', selectionFile, '--token-file', f.tokenFile, '--workdir', f.workdir];
}
test('real CLI prepares and inspects without source access or a credential', async t => {
  const f = await importFixture(t), before = f.requests.length;
  const first = await child(await preparation(f)).done; assert.equal(first.code, 0, first.err);
  const p = JSON.parse(first.out); await rm(f.archiveDir, { recursive: true }); await rm(f.tokenFile);
  const result = await child(['inspect', '--workdir', f.workdir, '--confirm', p.plan_sha256]).done;
  assert.equal(result.code, 0, result.err); assert.equal(JSON.parse(result.out).steps, p.steps); assert.equal(f.requests.length, before);
});
test('output failure keeps the prepared plan and its original pin', async t => {
  const f = await importFixture(t); let errors = '';
  const stdout = new Writable({ write(_c, _e, callback) { callback(new Error('broken pipe')); } });
  const stderr = new Writable({ write(c, _e, callback) { errors += c; callback(); } });
  assert.equal(await main(await preparation(f), { stdout, stderr }), 4);
  const p = JSON.parse(errors).retained_result; assert(p.plan_sha256);
  assert.equal((await child(['inspect', '--workdir', f.workdir, '--confirm', p.plan_sha256]).done).code, 0);
});
test('CLI refuses duplicate, unknown and malformed arguments', async t => {
  const f = await importFixture(t), args = await preparation(f), before = f.requests.length;
  for (const more of [['--workdir', f.workdir], ['--timeout-ms', '1e2'], ['--allow-approvals', 'yes']]) {
    const result = await child([...args, ...more]).done; assert.equal(result.code, 2); assert.equal(result.out, '');
  }
  assert.equal(f.requests.length, before);
});
