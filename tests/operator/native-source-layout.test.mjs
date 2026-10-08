import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { prepareNativeGitBundleRecovery as prepare } from '../../scripts/lib/native-source-layout.mjs';
import { verifyNativeGitBundle, normalizeNativeBundleOptions } from '../../scripts/lib/native-bundle-verifier.mjs';
import { harness, head, readFixture } from './fixtures/native-recovery-harness.mjs';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

for (const format of ['sha1', 'sha256']) test(`native ${format} layout uses original pack, golden index and stable plan`, async t => {
  const h = await harness(t, format);
  const plan = await prepare(h.bytes, h.request, { fg: h.fg });
  assert.equal(plan.receipt.schema, 'frankengit-native-source-recovery-plan-v1');
  assert.equal(plan.receipt.object_format, format);
  assert.equal(plan.receipt.artifact_sha256, hash(h.bytes));
  assert.equal(plan.verification.verifier_backend, 'native-fg');
  assert.equal(plan.verification.recovery, undefined);
  assert.equal(plan.files.length, 5);
  assert.deepEqual(plan.files[0].bytes, h.bytes.subarray(format === 'sha1' ? 128 : 198));
  assert.deepEqual(plan.files[1].bytes, await readFixture(format, 'idx'));
  assert.equal(plan.files.at(-1).path, 'HEAD');
  assert.equal(plan.files.at(-1).bytes.toString(), 'ref: refs/heads/main\n');
  assert.equal(plan.plan_sha256, hash(Buffer.from(JSON.stringify(plan.receipt))));
  const second = await prepare(h.bytes, h.request, { fg: h.fg, timeoutMs: 10000 });
  assert.equal(second.plan_sha256, plan.plan_sha256);
  assert.equal((await h.calls())[0].includes('--recovery-head-hex'), true);
  const constrained = await prepare(h.bytes, { ...h.request, expectations: { sha256: hash(h.bytes) } }, { fg: h.fg });
  assert.notEqual(constrained.plan_sha256, plan.plan_sha256, 'constraints belong to resume identity');
});

test('mutable source and request are captured before yielding', async t => {
  const h = await harness(t);
  const source = Buffer.from(h.bytes), request = { ...h.request, expectations: { sha256: hash(h.bytes) } };
  const pending = prepare(source, request, { fg: h.fg });
  source.fill(0); request.head_ref_hex = '00'; request.expectations.sha256 = '0'.repeat(64);
  const plan = await pending;
  assert.equal(plan.receipt.head_ref_hex, head);
  assert.equal(plan.receipt.artifact_sha256, hash(h.bytes));
});

test('ordinary verification keeps its report and budget, without layout', async t => {
  const h = await harness(t);
  const report = await verifyNativeGitBundle(h.bytes, { fg: h.fg });
  assert.equal(report.recovery, undefined);
  assert.equal((await h.calls())[0].includes('--recovery-head-hex'), false);
  assert.throws(() => normalizeNativeBundleOptions({ fg: h.fg, maxReportBytes: 9 * 1024 * 1024 }));
  assert.equal(normalizeNativeBundleOptions({ fg: h.fg, recoveryHead: head }).maxReportBytes, 16 * 1024 * 1024);
});

for (const layout of [
  { pack_offset: 0 }, { pack_offset: 129 }, { head_ref_hex: '726566732f68656164732f6f74686572' },
  { profile: 'unknown' }, { index_hex: '00' }, { index_hex: 'GG' }, { head_hex: '00' },
  { config_hex: Buffer.from('[include]\npath=/etc/gitconfig\n').toString('hex') },
  { packed_refs_hex: '00' }, { path: '../../outside' },
]) test(`contradictory native layout refuses: ${JSON.stringify(layout)}`, async t => {
  const h = await harness(t, 'sha1', { layout });
  await assert.rejects(prepare(h.bytes, h.request, { fg: h.fg }), /native_/);
});
for (const mode of ['missing-layout', 'refuse', 'huge']) test(`native ${mode} cannot fall back`, async t => {
  const h = await harness(t, 'sha1', { mode });
  await assert.rejects(prepare(h.bytes, h.request, { fg: h.fg }), /native_/);
  assert.equal((await h.calls()).length, 1);
});

test('validly encoded but corrupted index checksum refuses', async t => {
  const h = await harness(t), index = await readFixture('sha1', 'idx'); index[100] ^= 1;
  await h.configure({ layout: { index_hex: index.toString('hex') } });
  await assert.rejects(prepare(h.bytes, h.request, { fg: h.fg }), /native_recovery_layout_binding/);
});

test('raw native branch bytes stay in metadata, never paths', async t => {
  const rawHead = Buffer.concat([Buffer.from('refs/heads/'), Buffer.from([0xff, 0xfe])]).toString('hex');
  const h = await harness(t, 'sha1', { rawHead });
  const plan = await prepare(h.bytes, { head_ref_hex: rawHead }, { fg: h.fg });
  assert.deepEqual(plan.files.at(-1).bytes, Buffer.concat([Buffer.from('ref: '), Buffer.from(rawHead, 'hex'), Buffer.from('\n')]));
  assert.equal(plan.files.every(file => /^[a-zA-Z0-9./-]+$/.test(file.path)), true);
});

test('invalid inputs and pins refuse without process creation', async t => {
  const h = await harness(t);
  for (const value of ['', '00', head + '0a', head + '0', 'gg']) {
    await assert.rejects(prepare(h.bytes, { head_ref_hex: value }, { fg: h.fg }));
  }
  await assert.rejects(prepare(new Uint8Array(new SharedArrayBuffer(8)), h.request, { fg: h.fg }));
  await assert.rejects(prepare(h.bytes, { ...h.request, expectations: { sha256: '0'.repeat(64) } }, { fg: h.fg }));
  await assert.rejects(prepare(h.bytes, h.request, { fg: 'fg' }));
  await assert.rejects(prepare(h.bytes, h.request, { fg: h.fg, timeoutMs: 0 }));
  assert.equal((await h.calls()).length, 0);
});

test('cancelled native child is terminated and reaped', async t => {
  const h = await harness(t, 'sha1', { mode: 'hang' }), controller = new AbortController();
  const pending = assert.rejects(prepare(h.bytes, h.request, { fg: h.fg, signal: controller.signal, timeoutMs: 5000 }), /cancelled/);
  let pid;
  for (let i = 0; i < 200; i++) { try { pid = Number(await readFile(join(h.root, 'pid'), 'utf8')); break; } catch {} await new Promise(r => setTimeout(r, 10)); }
  assert.ok(pid); controller.abort(); await pending;
  assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
});

test('native refusal still preserves independent reference constraints', async t => {
  const h = await harness(t);
  await assert.rejects(prepare(h.bytes, { ...h.request, expectations: { object_format: 'sha1',
    refs: [{ ref_hex: head, object_id: '1'.repeat(40) }] } }, { fg: h.fg }), /native_expectation_report_mismatch/);
});
