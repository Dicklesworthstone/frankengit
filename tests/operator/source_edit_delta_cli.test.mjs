// Execute the actual offline operator. Every Git application starts without the
// desired blobs. These tests are not a Rust fg service or admission campaign.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, stat, readdir, chmod, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { Writable } from 'node:stream';
import { main } from '../../scripts/fg_source_patch.mjs';
import { compileSourceReplacements, REPLACEMENT_PROFILE, DELTA_REPLACEMENT_PROFILE } from '../../scripts/operator/source_edit_replacements.mjs';
import { change } from './source_edit_binary_fixture.mjs';
import { coldOracle } from './source_edit_delta_fixture.mjs';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const sink = () => new Writable({ write(_b, _e, done) { done(); } });
function large(format) {
  const old = Buffer.alloc(1048576, 7); old[0] = 0; const next = Buffer.from(old); next[524288] = 8;
  return [change(format, 'asset.bin', old, next)];
}
async function fixture(t, format = 'sha1', rows = large(format)) {
  const dir = await mkdtemp(join(tmpdir(), 'fg-delta-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const changes = [];
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i], entry = { path_hex: row.path_hex, before: null, after: null };
    for (const side of ['before', 'after']) {
      if (!row[side]) continue;
      const file = join(dir, `${i}-${side}`); await writeFile(file, row[side].bytes, { mode: 0o600 });
      entry[side] = { file, mode: row[side].mode, ...(side === 'before' ? { blob: row.before.blob } : {}) };
    }
    changes.push(entry);
  }
  const plan = { schema: REPLACEMENT_PROFILE, object_format: format, changes }, input = join(dir, 'input.json'), output = join(dir, 'patch');
  const save = () => writeFile(input, JSON.stringify(plan), { mode: 0o600 }); await save();
  const base = ['compile', '--changes-file', input, '--output', output];
  return { dir, input, output, plan, save, base, rows, format, args: [...base, '--binary', 'delta'] };
}
function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['scripts/fg_source_patch.mjs', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [], err = []; let size = 0, overflow = false, expired = false;
    const timer = setTimeout(() => { expired = true; child.kill('SIGKILL'); }, 15000);
    const collect = target => bytes => { size += bytes.length; if (size > 262144) { overflow = true; child.kill('SIGKILL'); } else target.push(bytes); };
    child.stdout.on('data', collect(out)); child.stderr.on('data', collect(err));
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (overflow || expired) reject(Error('test child exceeded output/time limit'));
      else resolve({ code, signal, out: Buffer.concat(out).toString(), err: Buffer.concat(err).toString() });
    });
  });
}
function applyBoth(f, patch) {
  coldOracle(f.format, f.rows, patch); coldOracle(f.format, f.rows, patch, true);
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: real CLI publishes a sub-512-byte reversible 1 MiB edit`, async t => {
    const f = await fixture(t, format);
    const old = await run([...f.base, '--binary', 'literal']); assert.equal(old.code, 2);
    assert.equal(JSON.parse(old.err).code, 'source_replacement_patch_limit');
    await assert.rejects(readFile(f.output), { code: 'ENOENT' });
    const result = await run(f.args); assert.equal(result.code, 0, result.err);
    const receipt = JSON.parse(result.out), patch = await readFile(f.output);
    assert.equal(receipt.profile, DELTA_REPLACEMENT_PROFILE); assert.equal(receipt.delta_members, 2); assert.equal(receipt.literal_members, 0);
    assert.equal(receipt.binary_files, 1); assert.equal(receipt.patch_sha256, hash(patch)); assert.equal(receipt.patch_bytes, patch.length);
    assert.ok(patch.length < 512); assert.equal(receipt.source_bytes, 1048576); assert.equal(receipt.result_bytes, 1048576);
    assert.equal(receipt.publication_attempted, false); assert.equal(receipt.source_membership_verified, false);
    assert.equal((await stat(f.output)).mode & 0o777, 0o600); applyBoth(f, patch);
  });
  test(`${format}: actual CLI preserves raw paths, mixed text/literals/deltas, empty files and executable modes`, async t => {
    const a = Buffer.alloc(20000, 3); a[0] = 0; const b = Buffer.from(a); b[10000] = 255;
    const f = await fixture(t, format, [change(format, Buffer.from([255, 32, 34, 92]), a, b, 0o100644, 0o100755),
      change(format, 'create/bin', null, Buffer.from([0, 9])), change(format, 'gone', Buffer.from([0, 7]), null),
      change(format, 'text', 'old\r\nlast', 'new\r\nlast'), change(format, 'empty', null, ''),
      change(format, 'mode', Buffer.from([0]), Buffer.from([0]), 0o100755, 0o100644)]);
    const result = await run(f.args); assert.equal(result.code, 0, result.err);
    const receipt = JSON.parse(result.out); assert.equal(receipt.delta_members, 4); assert.equal(receipt.literal_members, 2);
    assert.equal(receipt.changed_paths, 6); applyBoth(f, await readFile(f.output));
  });
}
test('CLI byte allowance has an exact permitted twin, and shrinking it publishes no prefix', async t => {
  const yes = await fixture(t), no = await fixture(t);
  const size = compileSourceReplacements('sha1', yes.rows, { binary: 'delta' }).patch.length;
  const result = await run([...yes.args, '--max-patch-bytes', String(size)]); assert.equal(result.code, 0, result.err);
  assert.equal((await readFile(yes.output)).length, size);
  const bad = await run([...no.args, '--max-patch-bytes', String(size - 1)]); assert.equal(bad.code, 2);
  assert.equal(JSON.parse(bad.err).code, 'source_replacement_patch_limit');
  await assert.rejects(readFile(no.output), { code: 'ENOENT' });
});
test('source changes cannot enable delta mode; no implicit mode or credential option is accepted', async t => {
  for (const extra of [[], ['--binary', 'auto'], ['--binary', 'delta-v2'], ['--binary', 'Delta'],
    ['--binary', 'delta', '--binary', 'literal'], ['--binary', 'delta', '--token-file', '/never-read']]) {
    const f = await fixture(t); assert.equal((await run([...f.base, ...extra])).code, 2);
    await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  }
  const f = await fixture(t); f.plan.binary = 'delta'; await f.save();
  assert.equal((await run(f.args)).code, 2); await assert.rejects(readFile(f.output), { code: 'ENOENT' });
});
test('delta compilation retains private source, exact hash and safe path requirements', async t => {
  for (const kind of ['hash', 'public', 'symlink', 'path']) {
    const f = await fixture(t);
    if (kind === 'hash') f.plan.changes[0].before.blob = 'f'.repeat(40);
    if (kind === 'public') await chmod(f.plan.changes[0].after.file, 0o644);
    if (kind === 'symlink') { const link = join(f.dir, 'alias'); await symlink(f.plan.changes[0].after.file, link); f.plan.changes[0].after.file = link; }
    if (kind === 'path') f.plan.changes[0].path_hex = Buffer.from('../escape').toString('hex');
    await f.save(); assert.equal((await run(f.args)).code, 2); await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  }
});
test('competing delta exporters produce one complete output and never replace its bytes', async t => {
  const f = await fixture(t), results = await Promise.all([run(f.args), run(f.args)]);
  assert.deepEqual(results.map(r => r.code).sort(), [0, 2]);
  const receipt = JSON.parse(results.find(r => r.code === 0).out), bytes = await readFile(f.output);
  assert.equal(receipt.patch_sha256, hash(bytes)); assert.equal((await run(f.args)).code, 2);
  assert.deepEqual(await readFile(f.output), bytes); assert.ok(!(await readdir(f.dir)).some(n => n.includes('.writing-')));
  applyBoth(f, bytes);
});
test('pre-cancelled delta command creates no final patch', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  assert.equal(await main(f.args, { stdout: sink(), stderr: sink(), signal: stop.signal }), 2);
  await assert.rejects(readFile(f.output), { code: 'ENOENT' });
});
test('lost stdout retains the completed delta patch and exact digest instead of asking for replay', async t => {
  const f = await fixture(t), errors = [];
  const stdout = new Writable({ write(_b, _e, cb) { cb(Error('closed')); } });
  const stderr = new Writable({ write(b, _e, cb) { errors.push(b); cb(); } });
  assert.equal(await main(f.args, { stdout, stderr }), 4);
  const receipt = JSON.parse(Buffer.concat(errors)).retained_result, bytes = await readFile(f.output);
  assert.equal(receipt.profile, DELTA_REPLACEMENT_PROFILE); assert.equal(receipt.delta_members, 2);
  assert.equal(receipt.patch_sha256, hash(bytes)); applyBoth(f, bytes);
});
test('late cancellation after write does not withdraw the completed local receipt', async t => {
  const f = await fixture(t), stop = new AbortController(), output = [];
  const stdout = new Writable({ write(b, _e, cb) { output.push(b); stop.abort(); cb(); } });
  assert.equal(await main(f.args, { stdout, stderr: sink(), signal: stop.signal }), 0);
  const receipt = JSON.parse(Buffer.concat(output)); assert.equal(receipt.patch_sha256, hash(await readFile(f.output)));
  assert.equal(receipt.publication_attempted, false);
});
test('text-only delta opt-in changes profile metadata, not exact text patch bytes', async t => {
  const rows = [change('sha1', 'file', 'before\n', 'after')], a = await fixture(t, 'sha1', rows), b = await fixture(t, 'sha1', rows);
  assert.equal((await run(a.base)).code, 0); const result = await run(b.args); assert.equal(result.code, 0);
  const receipt = JSON.parse(result.out); assert.equal(receipt.delta_members, 0); assert.equal(receipt.literal_members, 0);
  assert.deepEqual(await readFile(a.output), await readFile(b.output));
});
