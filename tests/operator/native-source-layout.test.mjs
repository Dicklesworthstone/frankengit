import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { prepareNativeGitBundleRecovery as prepare, withNativeGitBundleFileRecovery as withFilePlan } from '../../scripts/lib/native-source-layout.mjs';
import { verifyNativeGitBundle, normalizeNativeBundleOptions } from '../../scripts/lib/native-bundle-verifier.mjs';
import { harness, head, readFixture } from './fixtures/native-recovery-harness.mjs';
import { makeLargeRecoveryHarness } from './fixtures/native-recovery-large.mjs';
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


for (const format of ['sha1', 'sha256']) test('streamed ' + format + ' plan preserves exact v1 identity and bounded repeatable pack bytes', async t => {
  const h = await makeLargeRecoveryHarness(t, { format }), approvalBinding = 'a'.repeat(64);
  const memory = await prepare(h.bytes, h.request, { fg: h.fg, approvalBinding });
  const expectedDigest = hash(h.bytes), allocations = [], allocate = Buffer.alloc;
  let escapedPack, snapshotPath;
  t.mock.method(Buffer, 'alloc', (size, ...args) => {
    allocations.push(size); assert.ok(size <= 65536, 'file preparation never allocates a complete pack');
    return allocate(size, ...args);
  });
  try {
    const result = await withFilePlan(h.input, h.request, { fg: h.fg, approvalBinding,
      maxInputMiB: 16384, maxExpandedMiB: 16384, artifact: { sha256: expectedDigest, bytes: h.bytes.length } },
    async plan => {
      assert.deepEqual(plan.receipt, memory.receipt);
      assert.equal(plan.plan_sha256, memory.plan_sha256);
      assert.deepEqual(plan.receipt.expectations, { refs: [], exact_refs: false },
        'signed artifact pin is not inserted into the caller intent');
      const pack = plan.files[0].bytes; escapedPack = pack;
      assert.equal(Object.isFrozen(pack), true); assert.equal(pack instanceof Uint8Array, false);
      assert.equal(pack.length, h.expected_pack.length); assert.equal(pack.sha256, hash(h.expected_pack));
      assert.equal(plan.files.slice(1).every(file => file.bytes instanceof Uint8Array), true);
      assert.deepEqual(plan.files[1].bytes, h.expected_index);
      for (let replay = 0; replay < 2; replay++) {
        let consumed = 0, chunks = 0, checks = 0;
        for await (const chunk of pack.chunks(() => { checks++; })) {
          assert.ok(chunk.length > 0 && chunk.length <= 65536);
          assert.deepEqual(chunk, h.expected_pack.subarray(consumed, consumed + chunk.length));
          consumed += chunk.length; chunks++;
        }
        assert.equal(consumed, pack.length); assert.ok(chunks > 2); assert.ok(checks > chunks);
      }
      const args = (await h.calls()).at(-1); snapshotPath = args.at(-1);
      assert.notEqual(snapshotPath, h.input);
      assert.equal(args[args.indexOf('--max-input-mib') + 1], '16384');
      return plan.plan_sha256;
    });
    assert.equal(result, memory.plan_sha256);
  } finally { t.mock.restoreAll(); }
  assert.equal(Math.max(...allocations), 65536);
  await assert.rejects(lstat(dirname(snapshotPath)), { code: 'ENOENT' });
  await assert.rejects(escapedPack.chunks(() => {}).next(), { code: 'native_snapshot_closed' });
});

test('file recovery captures mutable request, artifact and limits before yielding', async t => {
  const h = await makeLargeRecoveryHarness(t);
  const digest = hash(h.bytes), approvalBinding = 'b'.repeat(64);
  const request = { ...h.request, expectations: { object_format: 'sha1' } };
  const options = { fg: h.fg, maxInputMiB: 1, maxExpandedMiB: 1, approvalBinding,
    artifact: { sha256: digest, bytes: h.bytes.length } };
  const pending = withFilePlan(h.input, request, options, async plan => plan.receipt);
  request.head_ref_hex = '00'; request.expectations.object_format = 'sha256';
  options.artifact.sha256 = '0'.repeat(64); options.artifact.bytes = 1;
  options.maxInputMiB = 0; options.approvalBinding = 'c'.repeat(64);
  const receipt = await pending;
  assert.equal(receipt.artifact_sha256, digest); assert.equal(receipt.head_ref_hex, head);
  assert.equal(receipt.approval_sha256, approvalBinding);
  assert.deepEqual(receipt.expectations, { refs: [], exact_refs: false, object_format: 'sha1' });
});

test('declared signed size and conflicting identity refuse before native verification', async t => {
  const h = await harness(t), input = join(h.root, 'input.bundle'); await writeFile(input, h.bytes);
  let entered = false;
  await assert.rejects(withFilePlan(input, h.request, { fg: h.fg,
    artifact: { sha256: hash(h.bytes), bytes: h.bytes.length + 1 } }, () => { entered = true; }),
  { code: 'native_expected_size_mismatch' });
  await assert.rejects(withFilePlan('/does-not-exist', { ...h.request,
    expectations: { sha256: '0'.repeat(64) } }, { fg: h.fg,
    artifact: { sha256: hash(h.bytes), bytes: h.bytes.length } }, () => { entered = true; }),
  { code: 'native_expected_sha256_mismatch' });
  assert.equal(entered, false); assert.deepEqual(await h.calls(), []);
});

test('file recovery requires well-formed bounded options without changing byte API limits', async t => {
  const h = await harness(t);
  for (const patch of [{ maxInputMiB: 16385 }, { maxExpandedMiB: 16385 }, { maxObjects: 100001 },
    { maxRefs: 4097 }, { artifact: { sha256: hash(h.bytes), bytes: 0 } },
    { artifact: { sha256: hash(h.bytes), bytes: 16 * 1024 * 1024 + 1 } },
    { artifact: { sha256: hash(h.bytes), bytes: h.bytes.length, trusted: true } },
    { artifact: { sha256: 'bad', bytes: h.bytes.length } }, { fileBacked: true }]) {
    await assert.rejects(withFilePlan('/does-not-exist', h.request, { fg: h.fg, ...patch }, () => {}),
      error => error.code !== 'ENOENT');
  }
  await assert.rejects(prepare(h.bytes, h.request, { fg: h.fg, maxInputMiB: 32 }),
    { code: 'native_invalid_recovery_options' });
  await assert.rejects(withFilePlan('/does-not-exist', h.request, { fg: h.fg }, null),
    { code: 'native_invalid_consumer' });
  assert.deepEqual(await h.calls(), []);
});

for (const format of ['sha1', 'sha256']) test('contradictory ' + format + ' pack SHA refuses before the plan consumer', async t => {
  const h = await harness(t, format), input = join(h.root, 'input.bundle');
  await writeFile(input, h.bytes); await h.configure({ report: { pack_sha256: '0'.repeat(64) } });
  let entered = false;
  await assert.rejects(withFilePlan(input, h.request, { fg: h.fg }, () => { entered = true; }),
    { code: 'native_recovery_layout_binding' });
  assert.equal(entered, false);
  const snapshotPath = (await h.calls()).at(-1).at(-1);
  await assert.rejects(lstat(dirname(snapshotPath)), { code: 'ENOENT' });
});

test('native trailer is independently checked before exposing a streamed plan', async t => {
  const h = await harness(t), input = join(h.root, 'input.bundle'), fixtures = join(h.root, 'contradictory');
  // Deliberately inconsistent FAKE success: the complete-artifact and pack
  // SHA-256 claims match these bytes, but the native pack trailer no longer does.
  const changed = Buffer.from(h.bytes); changed[128 + 12] ^= 1;
  await mkdir(fixtures, { mode: 0o700 });
  await writeFile(join(fixtures, 'sha1.bundle.hex'), changed.toString('hex') + '\n');
  await writeFile(join(fixtures, 'sha1.idx.hex'), (await readFixture('sha1', 'idx')).toString('hex') + '\n');
  await writeFile(input, changed); await h.configure({ fixtures });
  let entered = false;
  await assert.rejects(withFilePlan(input, h.request, { fg: h.fg }, () => { entered = true; }),
    { code: 'native_recovery_layout_binding' });
  assert.equal(entered, false);
});

test('a retained snapshot mutation invalidates a later pack replay before EOF', async t => {
  const h = await makeLargeRecoveryHarness(t);
  let snapshotPath;
  await assert.rejects(withFilePlan(h.input, h.request, { fg: h.fg }, async plan => {
    const reader = plan.files[0].bytes.chunks(() => {});
    const first = await reader.next(); assert.equal(first.done, false);
    snapshotPath = (await h.calls()).at(-1).at(-1);
    await writeFile(snapshotPath, Buffer.alloc(h.bytes.length));
    await reader.next();
  }), { code: 'native_snapshot_changed' });
  await assert.rejects(lstat(dirname(snapshotPath)), { code: 'ENOENT' });
});
