// Actual executable/private files; Git is only the independent test oracle.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, stat, readdir, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { Writable } from 'node:stream';
import { main } from '../../scripts/fg_source_patch.mjs';
import { compileSourceReplacements, REPLACEMENT_PROFILE, BINARY_REPLACEMENT_PROFILE } from '../../scripts/operator/source_edit_replacements.mjs';
import { change, withOracle } from './source_edit_binary_fixture.mjs';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const sink = () => new Writable({ write(_b, _e, done) { done(); } });
async function fixture(t, format = 'sha1', rows = [change(format, 'file', Buffer.from('old\0bytes'), Buffer.from('new\0bytes'))]) {
  const dir = await mkdtemp(join(tmpdir(), 'fg-binary-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const input = join(dir, 'plan.json'), output = join(dir, 'patch'), changes = [];
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i], result = { path_hex: row.path_hex, before: null, after: null };
    for (const side of ['before', 'after']) {
      if (row[side] === null) continue;
      const file = join(dir, `${i}-${side}`);
      await writeFile(file, row[side].bytes, { mode: 0o600 });
      result[side] = { file, mode: row[side].mode, ...(side === 'before' ? { blob: row.before.blob } : {}) };
    }
    changes.push(result);
  }
  const plan = { schema: REPLACEMENT_PROFILE, object_format: format, changes };
  const save = () => writeFile(input, JSON.stringify(plan), { mode: 0o600 }); await save();
  const base = ['compile', '--changes-file', input, '--output', output];
  return { dir, input, output, rows, format, plan, save, base, args: [...base, '--binary', 'literal'] };
}
function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['scripts/fg_source_patch.mjs', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [], err = [];
    child.stdout.on('data', b => out.push(b)); child.stderr.on('data', b => err.push(b));
    child.on('error', reject);
    child.on('close', (code, signal) => resolve({ code, signal, out: Buffer.concat(out).toString(), err: Buffer.concat(err).toString() }));
  });
}
function applyBoth(format, rows, patch) {
  withOracle(format, rows, ({ git, id, before, after }) => {
    git(['apply', '--cached', '--unidiff-zero', '-'], patch); assert.equal(id(['write-tree']), after);
    git(['apply', '--cached', '--unidiff-zero', '-R', '-'], patch); assert.equal(id(['write-tree']), before);
  });
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: real CLI emits mixed binary/text/raw/empty changes with exact forward and reverse trees`, async t => {
    const rows = [change(format, Buffer.from([255, 32, 34, 92]), Buffer.from([0, 1]), Buffer.from([0, 255]), 0o100644, 0o100755),
      change(format, 'nested/new', null, Buffer.from('new\0')), change(format, 'removed', Buffer.from('gone\0'), null),
      change(format, 'text', 'before\r\nlast', 'after\r\nlast'), change(format, 'empty', null, '')];
    const f = await fixture(t, format, rows), r = await run(f.args);
    assert.equal(r.code, 0, r.err); const receipt = JSON.parse(r.out), patch = await readFile(f.output);
    assert.equal(receipt.profile, BINARY_REPLACEMENT_PROFILE); assert.equal(receipt.binary_files, 3);
    assert.equal(receipt.patch_sha256, sha(patch)); assert.equal(receipt.patch_bytes, patch.length);
    assert.equal(receipt.changed_paths, 5); assert.equal(receipt.publication_attempted, false);
    assert.equal(receipt.source_membership_verified, false); assert.equal((await stat(f.output)).mode & 0o777, 0o600);
    applyBoth(format, rows, patch);
    for (let i = 0; i < rows.length; i++) for (const side of ['before', 'after']) if (rows[i][side]) {
      assert.deepEqual(await readFile(f.plan.changes[i][side].file), rows[i][side].bytes);
    }
  });
  test(`${format}: executable-only change to a binary file has no literal body`, async t => {
    const bytes = Buffer.from([0, 255, 10]), rows = [change(format, 'file', bytes, bytes, 0o100644, 0o100755)];
    const f = await fixture(t, format, rows), r = await run(f.args); assert.equal(r.code, 0, r.err);
    assert.equal(JSON.parse(r.out).binary_files, 0); const patch = await readFile(f.output);
    assert.ok(!patch.includes(Buffer.from('literal '))); applyBoth(format, rows, patch);
  });
}
test('default CLI still refuses binary inputs before output publication', async t => {
  const f = await fixture(t), r = await run(f.base);
  assert.equal(r.code, 2); assert.equal(JSON.parse(r.err).code, 'source_replacement_binary');
  await assert.rejects(readFile(f.output), { code: 'ENOENT' });
});
test('opt-in does not rewrite text-only patch bytes or legacy receipt fields', async t => {
  const rows = [change('sha1', 'file', 'old\r\nlast', 'new\r\nlast')];
  const old = await fixture(t, 'sha1', rows), explicit = await fixture(t, 'sha1', rows);
  const a = await run(old.base), b = await run(explicit.args);
  assert.equal(a.code, 0, a.err); assert.equal(b.code, 0, b.err);
  assert.deepEqual(await readFile(old.output), await readFile(explicit.output));
  const ar = JSON.parse(a.out), br = JSON.parse(b.out);
  assert.equal(ar.profile, REPLACEMENT_PROFILE); assert.equal(Object.hasOwn(ar, 'binary_files'), false);
  assert.equal(br.profile, BINARY_REPLACEMENT_PROFILE); assert.equal(br.binary_files, 0);
  delete ar.output; delete br.output; delete ar.profile; delete br.profile; delete br.binary_files;
  assert.deepEqual(ar, br);
});
test('unknown or repeated binary profiles and credential flags never create output', async t => {
  for (const extra of [['--binary', 'auto'], ['--binary', 'delta-v2'], ['--binary', 'true'], ['--binary', 'Literal'],
    ['--binary'], ['--binary', 'literal', '--binary', 'literal'], ['--binary', 'literal', '--token-file', '/not/read']]) {
    const f = await fixture(t); assert.equal((await run([...f.base, ...extra])).code, 2);
    await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  }
});
test('actual CLI enforces the complete two-member output budget with an exact permitted twin', async t => {
  const good = await fixture(t), bad = await fixture(t);
  const size = compileSourceReplacements('sha1', good.rows, { binary: 'literal' }).patch.length;
  const r = await run([...good.args, '--max-patch-bytes', String(size), '--timeout-ms', '30000']);
  assert.equal(r.code, 0, r.err); assert.equal((await readFile(good.output)).length, size);
  assert.equal((await run([...bad.args, '--max-patch-bytes', String(size - 1)])).code, 2);
  await assert.rejects(readFile(bad.output), { code: 'ENOENT' });
});
test('later invalid effects or wrong original bytes cannot produce a binary prefix', async t => {
  for (const alter of [async f => { await writeFile(f.plan.changes[0].before.file, 'bad\0data'); },
    async f => { f.plan.changes.push({ path_hex: '7a', before: null, after: { file: f.plan.changes[0].after.file, mode: 0o120000 } }); await f.save(); },
    async f => { f.plan.binary = 'literal'; await f.save(); }]) {
    const f = await fixture(t); await alter(f); assert.equal((await run(f.args)).code, 2);
    await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  }
});
test('binary opt-in preserves private regular-file and no-symlink input rules', async t => {
  for (const kind of ['public', 'symlink']) {
    const f = await fixture(t), selected = f.plan.changes[0].after.file;
    if (kind === 'public') await chmod(selected, 0o644);
    else { const link = join(f.dir, 'alias'); await symlink(selected, link); f.plan.changes[0].after.file = link; await f.save(); }
    assert.equal((await run(f.args)).code, 2); await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  }
});
test('competing binary CLI exporters cannot replace the first completed patch', async t => {
  const f = await fixture(t), both = await Promise.all([run(f.args), run(f.args)]);
  assert.deepEqual(both.map(r => r.code).sort(), [0, 2]);
  const receipt = JSON.parse(both.find(r => r.code === 0).out), bytes = await readFile(f.output);
  assert.equal(sha(bytes), receipt.patch_sha256);
  assert.equal((await run(f.args)).code, 2); assert.deepEqual(await readFile(f.output), bytes);
  assert.ok(!(await readdir(f.dir)).some(n => n.includes('.writing-')));
});
test('pre-cancelled binary compilation never claims a final patch', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  assert.equal(await main(f.args, { stdout: sink(), stderr: sink(), signal: stop.signal }), 2);
  await assert.rejects(readFile(f.output), { code: 'ENOENT' });
});
test('lost stdout keeps the exact binary publication receipt and completed patch', async t => {
  const f = await fixture(t), errors = [];
  const stdout = new Writable({ write(_b, _e, cb) { cb(new Error('closed')); } });
  const stderr = new Writable({ write(b, _e, cb) { errors.push(b); cb(); } });
  assert.equal(await main(f.args, { stdout, stderr }), 4);
  const r = JSON.parse(Buffer.concat(errors)).retained_result;
  assert.equal(r.profile, BINARY_REPLACEMENT_PROFILE); assert.equal(r.binary_files, 1);
  const patch = await readFile(f.output); assert.equal(sha(patch), r.patch_sha256); applyBoth('sha1', f.rows, patch);
});
test('late cancellation after patch publication does not undo or replace its receipt', async t => {
  const f = await fixture(t), stop = new AbortController(), output = [];
  const stdout = new Writable({ write(b, _e, cb) { output.push(b); stop.abort(); cb(); } });
  assert.equal(await main(f.args, { stdout, stderr: sink(), signal: stop.signal }), 0);
  const r = JSON.parse(Buffer.concat(output)); assert.equal(r.patch_sha256, sha(await readFile(f.output)));
  assert.equal(r.publication_attempted, false); assert.ok(!(await readdir(f.dir)).some(n => n.includes('.writing-')));
});
