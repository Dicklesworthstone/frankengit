import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { prepareGitBundleRecovery, verifyGitBundle } from '../../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs';
import { fixture, main, bytes, bundle, webcrypto, withTemp, git } from './bundle-recovery-fixtures.mjs';
import { hash } from './bundle-verify-fixtures.mjs';
const options = { cryptoImpl: webcrypto };
for (const format of ['sha1', 'sha256']) for (const delta of [null, 6, 7]) {
  test(`${format} delta ${delta}: original pack and generated idx-v2 agree with installed Git`, () => withTemp(async root => {
    const f = fixture(format, delta), plan = await prepareGitBundleRecovery(f.input, f.request, options), repo = join(root, 'restored.git');
    mkdirSync(repo);
    for (const dir of plan.directories) mkdirSync(join(repo, dir));
    for (const file of plan.files) writeFileSync(join(repo, file.path), file.bytes);
    assert.equal(plan.filesystem_written, false); assert.equal(plan.forge_state_restored, false);
    assert.equal(plan.verification.caller_expectations_matched, true);
    const index = plan.files.find(file => file.path.endsWith('.idx')), pack = plan.files.find(file => file.path.endsWith('.pack'));
    assert.deepEqual(Buffer.from(pack.bytes), f.input.subarray(plan.verification.header_bytes));
    const width = format === 'sha1' ? 20 : 32;
    assert.deepEqual(Buffer.from(index.bytes.subarray(-width)), hash(index.bytes.subarray(0, -width), format));
    // Native Git must validate all offsets, CRCs, checksums and reconstructed IDs.
    git(root, ['--git-dir', repo, 'verify-pack', '-v', join(repo, index.path)]);
    git(root, ['--git-dir', repo, 'fsck', '--full', '--strict', '--no-reflogs']);
    const oracleIndex = join(root, 'oracle.idx');
    git(root, ['--git-dir', repo, 'index-pack', '--index-version=2', '-o', oracleIndex, join(repo, pack.path)]);
    assert.deepEqual(readFileSync(oracleIndex), Buffer.from(index.bytes), 'byte-for-byte independent idx encoding');
    assert.equal(git(root, ['--git-dir', repo, 'rev-parse', 'HEAD']).toString().trim(), f.tip);
    assert.deepEqual(git(root, ['--git-dir', repo, 'show', 'HEAD:executable']), f.content);
    assert.equal(git(root, ['--git-dir', repo, 'rev-list', '--count', 'HEAD']).toString().trim(), '2');
    assert.equal(git(root, ['--git-dir', repo, 'rev-parse', 'refs/tags/release']).toString().trim(), f.tag);
  }));
}
test('recovery HEAD must be an explicitly selected advertised branch', async () => {
  const f = fixture();
  for (const [head_ref_hex, code] of [[undefined, 'invalid_recovery_head'], ['zz', 'invalid_recovery_head'],
    [bytes('refs/tags/release').toString('hex'), 'recovery_head_not_branch'],
    [bytes('refs/heads/missing').toString('hex'), 'recovery_head_not_advertised']]) {
    await assert.rejects(prepareGitBundleRecovery(f.input, { head_ref_hex }, options), e => e.code === code);
  }
  await assert.rejects(prepareGitBundleRecovery(f.input, { ...f.request, hidden_grant: true }, options));
});
test('raw reference names are packed as bytes, never used as local paths', () => withTemp(async root => {
  const f = fixture('sha256'), name = bytes([...bytes('refs/heads/'), 255]);
  const input = bundle(f.records, f.format, { refs: [{ name, id: f.tip }] });
  const plan = await prepareGitBundleRecovery(input, { head_ref_hex: name.toString('hex') }, options), repo = join(root, 'raw.git');
  mkdirSync(repo); for (const dir of plan.directories) mkdirSync(join(repo, dir));
  for (const file of plan.files) { assert.match(file.path, /^(?:HEAD|config|packed-refs|objects\/pack\/pack-[0-9a-f]+\.(?:pack|idx))$/); writeFileSync(join(repo, file.path), file.bytes); }
  assert.deepEqual(readFileSync(join(repo, 'HEAD')), Buffer.concat([bytes('ref: '), name, bytes('\n')]));
  assert.equal(git(root, ['--git-dir', repo, 'rev-parse', 'HEAD']).toString().trim(), f.tip);
}));
test('overlapping ref namespaces refuse instead of creating unmaintainable loose refs', async () => {
  const f = fixture(), input = bundle(f.records, f.format, { refs: [...f.refs, { name: 'refs/heads/main/topic', id: f.tip }] });
  assert.equal((await verifyGitBundle(input, options)).object_closure_verified, true);
  await assert.rejects(prepareGitBundleRecovery(input, f.request, options), e => e.code === 'overlapping_recovery_refs');
});
test('missing history and wrong trusted anchors cannot produce recovery files', async () => {
  const f = fixture(), missing = bundle(f.records.filter(row => row.kind !== 'tree'), f.format, { refs: f.refs });
  await assert.rejects(prepareGitBundleRecovery(missing, f.request, options), e => e.code === 'missing_reachable_object');
  await assert.rejects(prepareGitBundleRecovery(f.input, { head_ref_hex: main, expectations: { sha256: 'a'.repeat(64) } }, options), e => e.code === 'expected_artifact_mismatch');
});
test('input and request are owned before awaits; the completed plan is deterministic', async () => {
  const f = fixture(), baseline = await prepareGitBundleRecovery(f.input, f.request, options); let changed = false;
  const cryptoImpl = { subtle: { digest(...args) {
    if (!changed) { changed = true; f.input.fill(0); f.request.head_ref_hex = 'ff'; f.request.expectations.refs.length = 0; }
    return webcrypto.subtle.digest(...args);
  } } };
  const actual = await prepareGitBundleRecovery(f.input, f.request, { cryptoImpl });
  assert.deepEqual(actual, baseline);
  actual.files[0].bytes.fill(0);
  assert.deepEqual(await prepareGitBundleRecovery(fixture().input, fixture().request, options), baseline);
});
test('index construction and file hashing obey the original shared work and cancellation budget', async () => {
  const f = fixture(), plan = await prepareGitBundleRecovery(f.input, f.request, options);
  assert.equal((await prepareGitBundleRecovery(f.input, f.request, { ...options, limits: { maxWork: plan.work } })).plan_sha256, plan.plan_sha256);
  await assert.rejects(prepareGitBundleRecovery(f.input, f.request, { ...options, limits: { maxWork: plan.work - 1 } }), e => e.code === 'work_limit');
  const controller = new AbortController(); let calls = 0;
  const cryptoImpl = { subtle: { async digest(...args) { const result = await webcrypto.subtle.digest(...args); if (++calls === 10) controller.abort(); return result; } } };
  await assert.rejects(prepareGitBundleRecovery(f.input, f.request, { cryptoImpl, signal: controller.signal }), e => e.code === 'cancelled');
});
