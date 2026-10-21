// The actual executable and create-only publisher; no replacement filesystem.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, stat, chmod, symlink, link, readdir, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { Writable } from 'node:stream';
import { main } from '../../scripts/fg_source_patch.mjs';
import { compileSourceSplices, SPLICE_PROFILE } from '../../scripts/operator/source_edit_splices.mjs';
const hex = s => Buffer.from(s).toString('hex');
const hash = b => createHash('sha256').update(b).digest('hex');
const blob = (b, f) => createHash(f).update(`blob ${b.length}\0`).update(b).digest('hex');
async function fixture(t, format = 'sha1') {
  const dir = await mkdtemp(join(await realpath(tmpdir()), 'fg-splice-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const original = Buffer.from('old\r\nkeep\r\nlast'), source = join(dir, 'original'), input = join(dir, 'splices.json'), output = join(dir, 'change.patch');
  await writeFile(source, original, { mode: 0o600 });
  const plan = { schema: SPLICE_PROFILE, object_format: format, files: [{ path_hex: hex('src/file'),
    before: { file: source, blob: blob(original, format), mode: 0o100644 }, after_mode: 0o100755,
    edits: [{ byte_start: 0, before_hex: hex('old'), after_hex: hex('LONGER') }, { byte_start: 11, before_hex: hex('last'), after_hex: hex('tail') }] }] };
  const save = () => writeFile(input, JSON.stringify(plan), { mode: 0o600 }); await save();
  const args = ['splice', '--splices-file', input, '--output', output];
  return { dir, original, source, input, output, format, plan, args, save };
}
function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['scripts/fg_source_patch.mjs', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [], err = []; child.stdout.on('data', b => out.push(b)); child.stderr.on('data', b => err.push(b));
    child.on('error', reject); child.on('close', (code, signal) => resolve({ code, signal, out: Buffer.concat(out).toString(), err: Buffer.concat(err).toString() }));
  });
}
const sink = callback => new Writable({ write(b, _e, cb) { callback?.(b); cb(); } });
for (const format of ['sha1', 'sha256']) test(`${format}: executable emits the exact source-pinned patch and private receipt`, async t => {
  const f = await fixture(t, format), result = await run(f.args); assert.equal(result.code, 0, result.err);
  const receipt = JSON.parse(result.out), patch = await readFile(f.output), row = f.plan.files[0];
  const compiled = compileSourceSplices(format, [{ path_hex: row.path_hex, before: { bytes: f.original, blob: row.before.blob, mode: row.before.mode },
    after_mode: row.after_mode, edits: row.edits.map(e => ({ byte_start: e.byte_start, before: Buffer.from(e.before_hex, 'hex'), after: Buffer.from(e.after_hex, 'hex') })) }]);
  assert.deepEqual(patch, compiled.patch); assert.equal(receipt.patch_sha256, hash(patch)); assert.equal(receipt.patch_bytes, patch.length);
  assert.equal(receipt.splice_profile, SPLICE_PROFILE); assert.equal(receipt.splice_count, 2);
  assert.equal(receipt.preimages_verified, true); assert.equal(receipt.source_membership_verified, false); assert.equal(receipt.publication_attempted, false);
  assert.equal(receipt.expected_bytes, 7); assert.equal(receipt.inserted_bytes, 10);
  assert.equal((await stat(f.output)).mode & 0o777, 0o600); assert.deepEqual(await readFile(f.source), f.original);
  assert.ok(patch.includes(Buffer.from('+LONGER\r\n'))); assert.ok(patch.includes(Buffer.from('+tail\n\\ No newline')));
});
for (const [label, mutate] of [
  ['changed original hash', async f => { await writeFile(f.source, 'changed'); }],
  ['stale expected bytes', async f => { f.plan.files[0].edits[0].before_hex = hex('xxx'); }],
  ['wrong source offset', async f => { f.plan.files[0].edits[0].byte_start = 1; }],
  ['duplicate offset', async f => { f.plan.files[0].edits.push({ ...f.plan.files[0].edits[0] }); }],
  ['overlap', async f => { f.plan.files[0].edits.push({ byte_start: 1, before_hex: hex('ld'), after_hex: hex('x') }); }],
  ['malformed lowercase hex', async f => { f.plan.files[0].edits[0].after_hex = 'AA'; }],
  ['odd-length hex', async f => { f.plan.files[0].edits[0].before_hex = '0'; }],
  ['noninteger offset', async f => { f.plan.files[0].edits[0].byte_start = 0.5; }],
  ['source path is not creation', async f => { f.plan.files[0].before = null; }],
  ['unknown instruction', async f => { f.plan.files[0].edits[0].regex = true; }],
  ['unknown plan field', async f => { f.plan.force = true; }],
  ['NUL without opt-in', async f => { f.plan.files[0].edits[0].after_hex = '00'; }],
  ['late invalid file', async f => { f.plan.files.push({ ...f.plan.files[0], path_hex: hex('other'), after_mode: 0o120000 }); }],
]) test(`CLI refuses ${label} without any final patch`, async t => {
  const f = await fixture(t); await mutate(f); await f.save();
  const result = await run(f.args); assert.equal(result.code, 2, result.out);
  await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  assert.ok(!(await readdir(f.dir)).some(n => n.includes('.writing-')));
});
test('binary edits require the explicit option and reuse the existing binary profile', async t => {
  const f = await fixture(t); f.plan.files[0].edits[0].after_hex = '00ff'; await f.save();
  const result = await run([...f.args, '--binary', 'literal']); assert.equal(result.code, 0, result.err);
  const receipt = JSON.parse(result.out); assert.equal(receipt.profile, 'frankengit-source-replacements-binary-v1');
  assert.equal(receipt.binary_files, 1); assert.equal(receipt.splice_profile, SPLICE_PROFILE);
  assert.ok((await readFile(f.output)).includes(Buffer.from('GIT binary patch\n')));
});
test('empty result keeps file existence and explicit mode-only edits remain possible', async t => {
  const f = await fixture(t);
  f.plan.files[0].edits = [{ byte_start: 0, before_hex: hex(f.original), after_hex: '' }]; await f.save();
  const result = await run(f.args); assert.equal(result.code, 0, result.err);
  assert.ok(!(await readFile(f.output)).includes(Buffer.from('deleted file mode')));
  const g = await fixture(t); g.plan.files[0].edits = []; await g.save();
  const mode = await run(g.args); assert.equal(mode.code, 0, mode.err);
  assert.equal(JSON.parse(mode.out).splice_count, 0); assert.ok((await readFile(g.output)).includes(Buffer.from('new mode 100755')));
});
test('competing exporters cannot overwrite the winner or any existing path', async t => {
  const f = await fixture(t), results = await Promise.all([run(f.args), run(f.args)]);
  assert.deepEqual(results.map(r => r.code).sort(), [0, 2]);
  const receipt = JSON.parse(results.find(r => r.code === 0).out), patch = await readFile(f.output);
  assert.equal(hash(patch), receipt.patch_sha256);
  assert.equal((await run(f.args)).code, 2); assert.deepEqual(await readFile(f.output), patch);
});
test('symlinks, hardlinks and public source files do not become trusted originals', async t => {
  for (const kind of ['symlink', 'hardlink', 'public']) {
    const f = await fixture(t);
    if (kind === 'public') await chmod(f.source, 0o644);
    else {
      const target = join(f.dir, 'alias'); await (kind === 'symlink' ? symlink : link)(f.source, target);
      f.plan.files[0].before.file = target; await f.save();
    }
    assert.equal((await run(f.args)).code, 2); await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  }
});
test('shared patch ceiling has an exact success boundary; plan and flags stay closed', async t => {
  const f = await fixture(t); const first = await run(f.args); assert.equal(first.code, 0, first.err);
  const size = JSON.parse(first.out).patch_bytes;
  for (const n of [size, size - 1]) {
    const next = join(f.dir, `limit-${n}.patch`), args = [...f.args]; args[4] = next;
    const result = await run([...args, '--max-patch-bytes', String(n)]); assert.equal(result.code, n === size ? 0 : 2);
    if (n < size) await assert.rejects(readFile(next), { code: 'ENOENT' });
  }
  for (const extra of [['--force', 'true'], ['--token-file', '/not/read'], ['--binary', 'auto'], ['--output', '/other'], ['--changes-file', '/other'], ['--timeout-ms', '0']]) {
    const g = await fixture(t); assert.equal((await run([...g.args, ...extra])).code, 2); await assert.rejects(readFile(g.output), { code: 'ENOENT' });
  }
  const g = await fixture(t); await writeFile(g.input, Buffer.alloc(512 * 1024 + 1, 32));
  assert.equal((await run(g.args)).code, 2); await assert.rejects(readFile(g.output), { code: 'ENOENT' });
});
test('pre-cancellation leaves no output; confirmed publication wins over late cancellation', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  assert.equal(await main(f.args, { signal: stop.signal, stdout: sink(), stderr: sink() }), 2);
  await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  const late = new AbortController(), out = [];
  assert.equal(await main(f.args, { signal: late.signal, stdout: sink(b => { out.push(b); late.abort(); }), stderr: sink() }), 0);
  assert.equal(hash(await readFile(f.output)), JSON.parse(Buffer.concat(out)).patch_sha256);
});
test('lost stdout retains the exact published result and cannot authorize a rewrite', async t => {
  const f = await fixture(t), errors = [], broken = new Writable({ write(_b, _e, cb) { cb(new Error('closed')); } });
  assert.equal(await main(f.args, { stdout: broken, stderr: sink(b => errors.push(b)) }), 4);
  const receipt = JSON.parse(Buffer.concat(errors)).retained_result;
  assert.equal(receipt.splice_profile, SPLICE_PROFILE); assert.equal(hash(await readFile(f.output)), receipt.patch_sha256);
  assert.equal((await run(f.args)).code, 2);
});
test('ordinary compile still has the identical receipt fields and output path behavior', async t => {
  const f = await fixture(t), desired = join(f.dir, 'desired'); await writeFile(desired, 'desired\n', { mode: 0o600 });
  await writeFile(f.input, JSON.stringify({ schema: 'frankengit-source-replacements-v1', object_format: 'sha1', changes: [
    { path_hex: hex('file'), before: f.plan.files[0].before, after: { file: desired, mode: 0o100644 } }] }));
  const result = await run(['compile', '--changes-file', f.input, '--output', f.output]); assert.equal(result.code, 0, result.err);
  const receipt = JSON.parse(result.out);
  assert.deepEqual(Object.keys(receipt), ['type', 'profile', 'output', 'object_format', 'patch_sha256', 'patch_bytes', 'changed_paths',
    'source_bytes', 'result_bytes', 'source_membership_verified', 'publication_attempted']);
  assert.ok(!(await readFile(f.output)).includes(Buffer.from('GIT binary patch')));
});

for (const format of ['sha1', 'sha256']) test(`${format}: splice and ordinary compile preserve binary delta output and receipts`, async t => {
  const f = await fixture(t, format), original = Buffer.alloc(800000, 97);
  original[0] = 0; const desired = Buffer.from(original); desired[400000] = 255;
  await writeFile(f.source, original);
  const row = f.plan.files[0]; row.before.blob = blob(original, format); row.after_mode = 0o100644;
  row.edits = [{ byte_start: 400000, before_hex: '61', after_hex: 'ff' }]; await f.save();
  const literal = await run([...f.args, '--binary', 'literal']);
  assert.equal(literal.code, 2); await assert.rejects(readFile(f.output), { code: 'ENOENT' });
  const result = await run([...f.args, '--binary', 'delta']); assert.equal(result.code, 0, result.err);
  const receipt = JSON.parse(result.out), patch = await readFile(f.output);
  assert.equal(receipt.profile, 'frankengit-source-replacements-delta-v1');
  assert.equal(receipt.splice_profile, SPLICE_PROFILE); assert.equal(receipt.splice_count, 1);
  assert.equal(receipt.binary_files, 1); assert.equal(receipt.delta_members, 2);
  assert.equal(receipt.literal_members, 0); assert.equal(receipt.patch_sha256, hash(patch));
  assert.ok(patch.length < 1024);
  const expected = compileSourceSplices(format, [{ path_hex: row.path_hex,
    before: { bytes: original, mode: row.before.mode, blob: row.before.blob }, after_mode: row.after_mode,
    edits: [{ byte_start: 400000, before: Buffer.from([97]), after: Buffer.from([255]) }] }], { binary: 'delta' });
  assert.deepEqual(patch, expected.patch);
  const body = join(f.dir, 'desired'), plan = join(f.dir, 'compile.json'), output = join(f.dir, 'compile.patch');
  await writeFile(body, desired, { mode: 0o600 });
  await writeFile(plan, JSON.stringify({ schema: 'frankengit-source-replacements-v1', object_format: format,
    changes: [{ path_hex: row.path_hex, before: row.before, after: { file: body, mode: row.after_mode } }] }), { mode: 0o600 });
  const ordinary = await run(['compile', '--changes-file', plan, '--output', output, '--binary', 'delta']);
  assert.equal(ordinary.code, 0, ordinary.err); assert.deepEqual(await readFile(output), patch);
  const prior = JSON.parse(ordinary.out);
  assert.equal(prior.delta_members, 2); assert.equal(prior.literal_members, 0);
  assert.equal(Object.hasOwn(prior, 'splice_profile'), false); assert.equal(Object.hasOwn(prior, 'preimages_verified'), false);
});
