import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, stat, readdir, symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { Writable } from 'node:stream';
import { main } from '../../scripts/fg_source_patch.mjs';
import { compileSourceReplacements, REPLACEMENT_PROFILE } from '../../scripts/operator/source_edit_replacements.mjs';
const native = (b, f) => createHash(f).update(`blob ${b.length}\0`).update(b).digest('hex');
const sha = b => createHash('sha256').update(b).digest('hex');
async function fixture(t, format = 'sha1') {
  const dir = await mkdtemp(join(tmpdir(), 'fg-patch-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const before = Buffer.from('old\r\nlast'), after = Buffer.from('new\r\nlast');
  const old = join(dir, 'old'), next = join(dir, 'next'), input = join(dir, 'plan.json'), output = join(dir, 'change.patch');
  await writeFile(old, before, { mode: 0o600 }); await writeFile(next, after, { mode: 0o600 });
  const plan = { schema: REPLACEMENT_PROFILE, object_format: format, changes: [{ path_hex: Buffer.from('src/file').toString('hex'),
    before: { file: old, blob: native(before, format), mode: 0o100644 }, after: { file: next, mode: 0o100755 } }] };
  const save = () => writeFile(input, JSON.stringify(plan), { mode: 0o600 }); await save();
  const args = ['compile', '--changes-file', input, '--output', output];
  return { dir, before, after, old, next, plan, input, output, args, save, format };
}
function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['scripts/fg_source_patch.mjs', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [], err = []; child.stdout.on('data', b => out.push(b)); child.stderr.on('data', b => err.push(b));
    child.on('error', reject); child.on('close', (code, signal) => resolve({ code, signal, out: Buffer.concat(out).toString(), err: Buffer.concat(err).toString() }));
  });
}
for (const format of ['sha1', 'sha256']) test(`${format}: actual executable publishes the same exact patch without changing inputs`, async t => {
  const f = await fixture(t, format), result = await run(f.args);
  assert.equal(result.code, 0, result.err);
  const receipt = JSON.parse(result.out), patch = await readFile(f.output);
  assert.equal(receipt.patch_sha256, sha(patch)); assert.equal(receipt.patch_bytes, patch.length);
  assert.equal(receipt.publication_attempted, false); assert.equal(receipt.source_membership_verified, false);
  assert.equal((await stat(f.output)).mode & 0o777, 0o600);
  const compiled = compileSourceReplacements(format, [{ path_hex: f.plan.changes[0].path_hex,
    before: { mode: 0o100644, bytes: f.before, blob: native(f.before, format) }, after: { mode: 0o100755, bytes: f.after } }]);
  assert.deepEqual(patch, compiled.patch);
  assert.deepEqual(await readFile(f.old), f.before); assert.deepEqual(await readFile(f.next), f.after);
});
test('exclusive output never replaces an existing file or competing exporter', async t => {
  const f = await fixture(t);
  const both = await Promise.all([run(f.args), run(f.args)]);
  assert.deepEqual(both.map(r => r.code).sort(), [0, 2]);
  const receipt = JSON.parse(both.find(r => r.code === 0).out), before = await readFile(f.output);
  assert.equal(sha(before), receipt.patch_sha256);
  assert.equal((await run(f.args)).code, 2); assert.deepEqual(await readFile(f.output), before);
});
test('a changed independent original hash refuses before output exists', async t => {
  const f = await fixture(t); await writeFile(f.old, 'another original');
  assert.equal((await run(f.args)).code, 2);
  await assert.rejects(readFile(f.output), { code: 'ENOENT' });
});
test('unknown input fields, binary after bytes and later invalid rows yield no successful prefix', async t => {
  for (const mutate of [async f => { f.plan.token = 'secret'; }, async f => { await writeFile(f.next, 'x\0y'); },
    async f => { f.plan.changes.push({ path_hex: '7a', before: null, after: { file: f.next, mode: 0o120000 } }); }]) {
    const f = await fixture(t); await mutate(f); await f.save();
    assert.equal((await run(f.args)).code, 2); await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  }
});
test('public or symlinked source inputs are not read as private replacement bytes', async t => {
  for (const mode of ['public', 'symlink']) {
    const f = await fixture(t);
    if (mode === 'public') await chmod(f.next, 0o644);
    else { const link = join(f.dir, 'link'); await symlink(f.next, link); f.plan.changes[0].after.file = link; await f.save(); }
    assert.equal((await run(f.args)).code, 2); await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  }
});
test('bounded patch size and closed flags refuse without writes', async t => {
  for (const extra of [['--max-patch-bytes', '1'], ['--force', 'true'], ['--token-file', '/not/read'], ['--timeout-ms', '0'], ['--output', '/other']]) {
    const f = await fixture(t); assert.equal((await run([...f.args, ...extra])).code, 2);
    await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  }
});
test('pre-cancellation creates no patch while lost stdout retains its original receipt', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  const errors = [], sink = () => new Writable({ write(_b, _e, cb) { cb(); } });
  assert.equal(await main(f.args, { signal: stop.signal, stdout: sink(), stderr: sink() }), 2);
  await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  const broken = new Writable({ write(_b, _e, cb) { cb(new Error('closed')); } });
  const stderr = new Writable({ write(b, _e, cb) { errors.push(b); cb(); } });
  assert.equal(await main(f.args, { stdout: broken, stderr }), 4);
  const receipt = JSON.parse(Buffer.concat(errors)).retained_result;
  assert.equal(sha(await readFile(f.output)), receipt.patch_sha256);
  assert.ok(!(await readdir(f.dir)).some(n => n.includes('.writing-')));
});
test('empty addition and explicit deletion are distinct executable inputs', async t => {
  const f = await fixture(t); await writeFile(f.next, '');
  f.plan.changes = [{ path_hex: '616464', before: null, after: { file: f.next, mode: 0o100644 } },
    { path_hex: '64656c', before: f.plan.changes[0].before, after: null }]; await f.save();
  const result = await run(f.args); assert.equal(result.code, 0, result.err);
  const patch = await readFile(f.output); assert.ok(patch.includes(Buffer.from('new file mode')));
  assert.ok(patch.includes(Buffer.from('deleted file mode')));
});
