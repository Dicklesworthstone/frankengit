// Actual CLI and private-file tests. This lane is not a native Rust service.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, writeFileSync, readFileSync, chmodSync, rmSync, existsSync, symlinkSync, linkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { Writable } from 'node:stream';
import { main } from '../../scripts/fg_source_patch.mjs';
import { loadSourceSpliceFiles, readSourceSplicePlan, SPLICE_FILE_PROFILE } from '../../scripts/operator/source_edit_splice_files.mjs';
import { compileSourceSplices } from '../../scripts/operator/source_edit_splices.mjs';
const CLI = fileURLToPath(new URL('../../scripts/fg_source_patch.mjs', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const blob = (format, bytes) => createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
function fixture(t, format = 'sha256', original = Buffer.from('abcd\n')) {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'fg-file-splice-')); chmodSync(root, 0o700);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const put = (name, bytes) => { const path = join(root, name); writeFileSync(path, bytes, { mode: 0o600 }); return path; };
  const source = put('original', original), input = join(root, 'plan.json'), output = join(root, 'patch');
  const plan = { schema: SPLICE_FILE_PROFILE, object_format: format, files: [{ path_hex: '612e747874',
    before: { file: source, blob: blob(format, original), mode: 0o100644 }, after_mode: 0o100644,
    edits: [{ byte_start: 1, before: { hex: original.subarray(1, 2).toString('hex') }, after: { file: put('insert', 'LONG') } }] }] };
  const save = () => put('plan.json', JSON.stringify(plan));
  const args = extra => ['splice', '--splices-file', input, '--output', output, ...extra];
  const run = (extra = []) => { save(); return spawnSync(process.execPath, [CLI, ...args(extra)], { encoding: 'utf8', timeout: 15000, maxBuffer: 65536, env: { ...process.env, PATH: '' } }); };
  return { root, source, input, output, plan, put, save, args, run, original };
}
function success(f, extra = []) {
  const result = f.run(extra); assert.equal(result.status, 0, result.stderr);
  const receipt = JSON.parse(result.stdout), patch = readFileSync(f.output);
  assert.equal(receipt.splice_plan_profile, SPLICE_FILE_PROFILE);
  assert.equal(receipt.splice_plan_sha256, hash(readFileSync(f.input)));
  assert.equal(receipt.patch_sha256, hash(patch)); assert.equal(receipt.patch_bytes, patch.length);
  assert.equal(receipt.preimages_verified, true); assert.equal(receipt.source_membership_verified, false);
  assert.equal(receipt.publication_attempted, false); assert.deepEqual(readFileSync(f.source), f.original);
  return { receipt, patch };
}
function refusal(f, expected, extra = []) {
  const result = f.run(extra); assert.equal(result.status, 2, result.stderr); assert.equal(result.stdout, '');
  const error = JSON.parse(result.stderr); if (expected) assert.equal(error.code, expected);
  assert.equal(error.repository_publication_attempted, false); assert.ok(!existsSync(f.output)); return error;
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: mixed file/hex operands preserve original offsets and kernel bytes`, async t => {
    const f = fixture(t, format); f.plan.files[0].edits.unshift({ byte_start: 4, before: { hex: '0a' }, after: { hex: '21' } });
    f.plan.files[0].after_mode = 0o100755; f.save();
    const loaded = await readSourceSplicePlan(f.input), compiled = compileSourceSplices(format, loaded.files);
    const { patch, receipt } = success(f); assert.deepEqual(patch, compiled.patch); assert.equal(receipt.splice_count, 2);
    assert.ok(patch.includes('+aLONGcd!')); assert.ok(patch.includes('new mode 100755'));
  });
  test(`${format}: large replacement exceeds inline plan capacity but not patch ceiling`, t => {
    const f = fixture(t, format, Buffer.alloc(0)); f.plan.files[0].edits = [{ byte_start: 0, before: { hex: '' }, after: { file: f.put('large', Buffer.alloc(400000, 97)) } }];
    const { receipt, patch } = success(f); assert.equal(receipt.result_bytes, 400000); assert.ok(patch.length < 1048576);
    assert.ok(readFileSync(f.input).length < 1024); assert.ok(800000 > 512 * 1024);
  });
  test(`${format}: reversible binary delta and compact text options retain their owners`, async t => {
    const old = Buffer.alloc(1048576, 7); old[0] = 0;
    const f = fixture(t, format, old); f.plan.files[0].edits[0] = { byte_start: 500000, before: { hex: '07' }, after: { file: f.put('new-byte', Buffer.from([8])) } };
    refusal(f, 'source_replacement_binary'); const { receipt, patch } = success(f, ['--binary', 'delta']);
    assert.equal(receipt.delta_members, 2); assert.ok(patch.length < 512);
    const g = fixture(t, format); const result = success(g, ['--patch-profile', 'bounded-line-hunks-v1']);
    assert.equal(result.receipt.patch_profile, 'bounded-line-hunks-v1');
  });
}
for (const [name, mutate, code] of [
  ['wrong preimage before reading absent operand', f => { f.plan.files[0].before.blob = 'f'.repeat(64); f.plan.files[0].edits[0].after.file = join(f.root, 'absent'); }, 'source_splice_preimage'],
  ['wrong range before reading absent insertion', f => { f.plan.files[0].edits[0].before.hex = 'ff'; f.plan.files[0].edits[0].after.file = join(f.root, 'absent'); }, 'source_splice_context_mismatch'],
  ['ambiguous operand', f => { f.plan.files[0].edits[0].after.hex = '00'; }, 'source_patch_splice_operand'],
  ['uppercase hex', f => { f.plan.files[0].edits[0].before.hex = 'AF'; }, 'source_patch_splice_hex'],
  ['unknown authority field', f => { f.plan.permission = 'write'; }, 'source_edit_fields'],
  ['path traversal', f => { f.plan.files[0].path_hex = Buffer.from('../a').toString('hex'); }, 'source_splice_path'],
  ['duplicate inventory', f => { f.plan.files.push(structuredClone(f.plan.files[0])); }, 'source_splice_paths'],
  ['duplicate offsets', f => { f.plan.files[0].edits.push(structuredClone(f.plan.files[0].edits[0])); }, 'source_splice_overlap'],
  ['result overflow', f => { f.plan.files[0].edits[0].after.file = f.put('large', Buffer.alloc(1048576, 97)); }, 'source_splice_result_limit'],
  ['unsupported mode', f => { f.plan.files[0].after_mode = 0o120000; }, 'source_patch_mode'],
]) test(`file plan refuses ${name} without publication`, t => { const f = fixture(t); mutate(f); refusal(f, code); });
test('shared file operands exhaust a separate allowance before another allocation', async t => {
  const f = fixture(t, 'sha256', Buffer.alloc(0)), insert = f.put('large', Buffer.alloc(1048576, 97));
  f.plan.files = Array.from({ length: 8 }, (_, i) => ({ ...structuredClone(f.plan.files[0]), path_hex: Buffer.from(`f${i}`).toString('hex'),
    edits: [{ byte_start: 0, before: { hex: '' }, after: { file: insert } }] }));
  f.save(); const loaded = await readSourceSplicePlan(f.input); assert.equal(loaded.files.reduce((n, r) => n + r.edits[0].after.length, 0), 8388608);
  f.plan.files.push({ ...structuredClone(f.plan.files[0]), path_hex: '6e696e7468' }); f.save();
  await assert.rejects(readSourceSplicePlan(f.input), /bounded private regular/);
});
test('descriptor mutation across payload awaits cannot redirect paths or hashes', async t => {
  const f = fixture(t); const original = structuredClone(f.plan); const pending = loadSourceSpliceFiles(f.plan);
  f.plan.object_format = 'sha1'; f.plan.files[0].before.file = join(f.root, 'missing'); f.plan.files[0].path_hex = 'ff';
  f.plan.files[0].edits[0].after.file = join(f.root, 'missing');
  const loaded = await pending; assert.equal(loaded.format, original.object_format); assert.equal(loaded.files[0].path_hex, original.files[0].path_hex);
  assert.equal(loaded.files[0].edits[0].after.toString(), 'LONG');
});
test('links and nonprivate operands refuse beside a permitted file', t => {
  const f = fixture(t); success(f); rmSync(f.output);
  const operand = f.plan.files[0].edits[0].after.file, target = f.put('target', 'LONG');
  rmSync(operand); symlinkSync(target, operand); refusal(f, 'ELOOP'); rmSync(operand);
  linkSync(target, operand); refusal(f, 'source_patch_failed'); rmSync(operand); f.put('insert', 'LONG');
  chmodSync(operand, 0o644); refusal(f, 'source_patch_failed'); chmodSync(operand, 0o600); success(f);
});
test('cancellation before output leaves original files untouched', async t => {
  const f = fixture(t); f.save(); let checks = 0;
  await assert.rejects(readSourceSplicePlan(f.input, () => { if (++checks === 10) throw Error('stop'); }), /stop/);
  assert.equal(checks, 10); assert.ok(!existsSync(f.output)); assert.deepEqual(readFileSync(f.source), f.original);
});
test('lost stdout retains a hash-pinned patch and refuses overwrite', async t => {
  const f = fixture(t); f.save(); let text = '';
  const stdout = new Writable({ write(_b, _e, cb) { cb(Object.assign(Error('closed'), { code: 'EPIPE' })); } });
  const stderr = new Writable({ write(b, _e, cb) { text += b; cb(); } });
  assert.equal(await main(f.args([]), { stdout, stderr }), 4);
  const retained = JSON.parse(text).retained_result; assert.equal(retained.splice_plan_sha256, hash(readFileSync(f.input)));
  const original = readFileSync(f.output); assert.equal(retained.patch_sha256, hash(original));
  assert.equal(f.run().status, 2); assert.deepEqual(readFileSync(f.output), original);
});
