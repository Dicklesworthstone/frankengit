import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { verifyGitBundle, verifyGitBundleAgainst, normalizeBundleExpectation }
  from '../../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs';
import { bytes, hash, objectId, bundle, webcrypto } from './bundle-verify-fixtures.mjs';
const options = { cryptoImpl: webcrypto }, main = Buffer.from('refs/heads/main').toString('hex');
function fixture(format = 'sha1', content = 'expected content') {
  const blob = bytes(content), blobId = objectId('blob', blob, format);
  const tree = Buffer.concat([bytes('100644 file\0'), Buffer.from(blobId, 'hex')]), treeId = objectId('tree', tree, format);
  const commit = bytes(`tree ${treeId}\nauthor A <a@invalid> 1700000000 +0000\ncommitter A <a@invalid> 1700000000 +0000\n\nmessage\n`);
  const tip = objectId('commit', commit, format), records = [{ kind: 'commit', body: commit }, { kind: 'tree', body: tree }, { kind: 'blob', body: blob }];
  const refs = [{ name: bytes('refs/heads/main'), id: tip }, { name: bytes('refs/tags/version'), id: blobId }];
  const input = bundle(records, format, { refs });
  return { input, format, tip, refs, records, sha256: hash(input, 'sha256').toString('hex'),
    expected: { object_format: format, refs: [{ ref_hex: main, object_id: tip }] } };
}
const fail = (input, expected, code, extra = {}) => assert.rejects(verifyGitBundleAgainst(input, expected, { ...options, ...extra }), error => error.code === code);
for (const format of ['sha1', 'sha256']) {
  test(`${format}: caller-supplied artifact and branch anchors bind the complete closure`, async () => {
    const f = fixture(format), expected = { ...f.expected, sha256: f.sha256 };
    const result = await verifyGitBundleAgainst(f.input, expected, options);
    assert.equal(result.object_closure_verified, true); assert.equal(result.caller_expectations_matched, true);
    assert.equal(result.expectations.sha256, f.sha256); assert.equal(result.expectations.ref_set, 'contains');
    assert.equal(result.expectations.refs[0].object_id, f.tip); assert.equal(result.independently_authenticated, false);
    assert.equal(result.signatures_verified, false); assert.equal(result.author_identity_verified, false);
  });
  test(`${format}: a different internally complete backup cannot replace the caller's intended history`, async () => {
    const f = fixture(format), wrong = fixture(format, 'other valid history');
    assert.equal((await verifyGitBundle(wrong.input, options)).object_closure_verified, true);
    await fail(wrong.input, f.expected, 'expected_ref_mismatch');
    await fail(wrong.input, { sha256: f.sha256 }, 'expected_artifact_mismatch');
    assert.equal((await verifyGitBundleAgainst(f.input, f.expected, options)).caller_expectations_matched, true);
  });
  test(`${format}: exact reference sets refuse extras; subset pins make no completeness claim about the supplied pin list`, async () => {
    const f = fixture(format);
    assert.equal((await verifyGitBundleAgainst(f.input, f.expected, options)).expectations.ref_set, 'contains');
    await fail(f.input, { ...f.expected, exact_refs: true }, 'expected_ref_set_mismatch');
    const refs = f.refs.map(row => ({ ref_hex: row.name.toString('hex'), object_id: `${format}:${row.id.toUpperCase()}` })).reverse();
    const report = await verifyGitBundleAgainst(f.input, { object_format: format, refs, exact_refs: true }, options);
    assert.equal(report.expectations.ref_set, 'exact');
    assert.deepEqual(report.expectations.refs.map(row => row.ref_hex), [...refs.map(row => row.ref_hex)].sort());
  });
  test(`${format}: byte-only native reference anchors are never decoded or lossily substituted`, async () => {
    const f = fixture(format), name = bytes([...bytes('refs/tags/'), 255]), ref_hex = name.toString('hex');
    const input = bundle(f.records, format, { refs: [...f.refs, { name, id: f.tip }] });
    const expected = { object_format: format, refs: [{ ref_hex, object_id: f.tip }] };
    assert.equal((await verifyGitBundleAgainst(input, expected, options)).expectations.refs[0].ref_hex, ref_hex);
    await fail(f.input, expected, 'expected_ref_missing');
  });
  test(`${format}: matching pins cannot replace internal object or closure verification`, async () => {
    const f = fixture(format), incomplete = bundle(f.records.slice(0, 2), format, { refs: [f.refs[0]] });
    await fail(incomplete, { ...f.expected, sha256: hash(incomplete, 'sha256').toString('hex') }, 'missing_reachable_object');
    const corrupt = Buffer.from(f.input); corrupt[corrupt.length - 1] ^= 1;
    await fail(corrupt, { ...f.expected, sha256: hash(corrupt, 'sha256').toString('hex') }, 'pack_checksum_mismatch');
  });
}
test('hash-only anchoring works without inferring a native object hash domain', async () => {
  const f = fixture('sha256'), report = await verifyGitBundleAgainst(f.input, { sha256: f.sha256 }, options);
  assert.deepEqual(report.expectations, { sha256: f.sha256, object_format: null, refs: [], ref_set: null });
});
test('mismatches refuse before expensive pack decompression and do not return a partial proof', async () => {
  const f = fixture(); let digests = 0;
  const cryptoImpl = { subtle: { digest(...args) { digests++; return webcrypto.subtle.digest(...args); } } };
  await fail(f.input, { sha256: 'f'.repeat(64) }, 'expected_artifact_mismatch', { cryptoImpl });
  assert.equal(digests, 1, 'hash the artifact only; do not inflate/hash every object'); digests = 0;
  await fail(f.input, { ...f.expected, refs: [{ ref_hex: main, object_id: 'd'.repeat(40) }] }, 'expected_ref_mismatch', { cryptoImpl });
  assert.equal(digests, 0, 'wrong advertised anchor is rejected before hashing/decompression');
  await fail(f.input, { object_format: 'sha256', sha256: f.sha256 }, 'expected_object_format_mismatch', { cryptoImpl });
  assert.equal(digests, 0);
});
for (const [label, expected] of [
  ['absent', undefined], ['null', null], ['array', []], ['empty', {}], ['format alone', { object_format: 'sha1' }],
  ['unknown field', { sha256: 'a'.repeat(64), trust_me: true }], ['bad hash', { sha256: 'a'.repeat(63) }],
  ['uppercase artifact', { sha256: 'A'.repeat(64) }], ['wrong format', { sha256: 'a'.repeat(64), object_format: 'SHA-1' }],
  ['empty refs', { object_format: 'sha1', refs: [] }], ['null refs', { object_format: 'sha1', refs: null }],
  ['exact without refs', { sha256: 'a'.repeat(64), exact_refs: true }],
  ['nonboolean exact', { ...fixture().expected, exact_refs: 'true' }],
  ['no ref domain', { refs: fixture().expected.refs }], ['wrong ref domain', { object_format: 'sha256', refs: fixture().expected.refs }],
  ['unknown ref field', { object_format: 'sha1', refs: [{ ...fixture().expected.refs[0], grant: true }] }],
  ['zero identity', { object_format: 'sha1', refs: [{ ref_hex: main, object_id: '0'.repeat(40) }] }],
  ['duplicate ref', { object_format: 'sha1', refs: [...fixture().expected.refs, ...fixture().expected.refs] }],
  ['unsafe ref', { object_format: 'sha1', refs: [{ ref_hex: bytes('refs/heads/../main').toString('hex'), object_id: fixture().tip }] }],
  ['odd ref hex', { object_format: 'sha1', refs: [{ ref_hex: '726', object_id: fixture().tip }] }],
  ['nonhex ref', { object_format: 'sha1', refs: [{ ref_hex: 'zz', object_id: fixture().tip }] }],
]) test(`expectation grammar rejects ${label} before invoking crypto`, async () => {
  let calls = 0;
  await assert.rejects(verifyGitBundleAgainst(fixture().input, expected, { cryptoImpl: { subtle: { digest() { calls++; throw new Error('must not hash'); } } } }));
  assert.equal(calls, 0);
});
test('expectation reference counts and aggregate byte budgets are enforced before work', () => {
  const f = fixture(), row = f.expected.refs[0];
  assert.throws(() => normalizeBundleExpectation({ object_format: 'sha1', refs: Array(1025).fill(row) }), error => error.code === 'expectation_reference_limit');
  const refs = Array.from({ length: 65 }, (_, n) => ({ ref_hex: bytes(`refs/tags/${String(n).padStart(3, '0')}${'a'.repeat(4078)}`).toString('hex'), object_id: f.tip }));
  assert.throws(() => normalizeBundleExpectation({ object_format: 'sha1', refs }), error => error.code === 'expectation_header_limit');
});
test('caller mutation during the first digest cannot change the pin set or expected result', async () => {
  const f = fixture(), expected = { ...f.expected, sha256: f.sha256 }; let changed = false;
  const cryptoImpl = { subtle: { digest(...args) {
    if (!changed) { changed = true; expected.sha256 = 'f'.repeat(64); expected.refs[0].object_id = 'e'.repeat(40); expected.refs.length = 0; }
    return webcrypto.subtle.digest(...args);
  } } };
  const result = await verifyGitBundleAgainst(f.input, expected, { cryptoImpl });
  assert.equal(result.expectations.sha256, f.sha256); assert.equal(result.expectations.refs[0].object_id, f.tip);
});
test('anchored verification keeps shared work budgets, cancellation and total deadline', async () => {
  const f = fixture(), expected = { ...f.expected, sha256: f.sha256 }, report = await verifyGitBundleAgainst(f.input, expected, options);
  assert.equal((await verifyGitBundleAgainst(f.input, expected, { ...options, limits: { maxWork: report.work } })).caller_expectations_matched, true);
  await fail(f.input, expected, 'work_limit', { limits: { maxWork: report.work - 1 } });
  const controller = new AbortController();
  const cryptoImpl = { subtle: { async digest(...args) { const result = await webcrypto.subtle.digest(...args); controller.abort(); return result; } } };
  await fail(f.input, expected, 'cancelled', { cryptoImpl, signal: controller.signal });
  const delayed = { subtle: { async digest(...args) { await new Promise(resolve => setTimeout(resolve, 15)); return webcrypto.subtle.digest(...args); } } };
  await fail(f.input, expected, 'deadline', { cryptoImpl: delayed, limits: { timeoutMs: 5 } });
});
function withCli(work) {
  const dir = mkdtempSync(join(tmpdir(), 'fg-anchor-cli-')), file = join(dir, 'repo.bundle'), f = fixture(); writeFileSync(file, f.input);
  const cli = args => spawnSync(process.execPath, [resolve('scripts/verify_git_bundle.mjs'), ...args], { encoding: 'utf8', timeout: 10000, env: { ...process.env, PATH: dir } });
  try { return work({ f, file, cli, dir }); } finally { rmSync(dir, { recursive: true, force: true }); }
}
test('real offline CLI binds supplied hash/ref pins without Git, network or modifying the bundle', () => withCli(({ f, file, cli }) => {
  const result = cli([file, '--expect-sha256', f.sha256, '--expect-format', 'sha1', '--expect-ref', `refs/heads/main=${f.tip}`]);
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
  assert.equal(JSON.parse(result.stdout).caller_expectations_matched, true); assert.deepEqual(readFileSync(file), f.input);
  const wrong = cli([file, '--expect-sha256', 'f'.repeat(64)]);
  assert.equal(wrong.status, 1); assert.equal(wrong.stdout, ''); assert.equal(JSON.parse(wrong.stderr).error, 'expected_artifact_mismatch');
  const all = f.refs.flatMap(row => ['--expect-ref-hex', `${row.name.toString('hex')}=${row.id}`]);
  const exact = cli(['--expect-format', 'sha1', '--exact-refs', ...all, '--', file]);
  assert.equal(exact.status, 0, exact.stderr); assert.equal(JSON.parse(exact.stdout).expectations.ref_set, 'exact');
}));
test('CLI supports ref names containing equals signs and exact raw-byte pins', () => withCli(({ f, file, cli }) => {
  const names = [bytes('refs/tags/a=b'), bytes([...bytes('refs/tags/'), 255])];
  writeFileSync(file, bundle(f.records, 'sha1', { refs: names.map(name => ({ name, id: f.tip })) }));
  const result = cli([file, '--expect-format', 'sha1', '--expect-ref', `refs/tags/a=b=${f.tip}`, '--expect-ref-hex', `${names[1].toString('hex')}=${f.tip}`, '--exact-refs']);
  assert.equal(result.status, 0, result.stderr); assert.equal(JSON.parse(result.stdout).expectations.refs.length, 2);
}));
test('CLI malformed expectations fail before opening the requested file; help is nonmutating', () => withCli(({ cli, dir }) => {
  for (const args of [
    ['--expect-format', 'sha1'], ['--expect-sha256', 'bad'], ['--expect-sha256'], ['--unknown'],
    ['--expect-sha256', 'a'.repeat(64), '--expect-sha256', 'b'.repeat(64)],
    ['--expect-ref', 'refs/heads/main=' + 'a'.repeat(40)], ['--exact-refs'],
    ['--expect-format', 'sha1', '--expect-ref', 'malformed'],
  ]) {
    const result = cli([join(dir, 'does-not-exist'), ...args]);
    assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.notEqual(JSON.parse(result.stderr).error, 'ENOENT');
  }
  const help = cli(['--help']); assert.equal(help.status, 0, help.stderr); assert.match(help.stdout, /expect-ref/); assert.equal(help.stderr, '');
}));

test('native reference pins survive legitimate repacking while exact artifact hashes do not', async () => {
  const f = fixture();
  const repacked = bundle(f.records.map(row => ({ ...row, compression: { level: 0 } })), f.format, { refs: f.refs });
  assert.notEqual(hash(repacked, 'sha256').toString('hex'), f.sha256);
  const result = await verifyGitBundleAgainst(repacked, f.expected, options);
  assert.equal(result.caller_expectations_matched, true); assert.equal(result.object_closure_verified, true);
  await fail(repacked, { ...f.expected, sha256: f.sha256 }, 'expected_artifact_mismatch');
});
test('pin arrays and native hash domains are owned independently of later caller changes', () => {
  const f = fixture(), value = Object.assign(Object.create({ exact_refs: true }), f.expected);
  const normalized = normalizeBundleExpectation(value);
  assert.equal(normalized.ref_set, 'contains', 'only an explicitly owned exact-set flag selects exactness');
  value.refs[0].object_id = 'f'.repeat(40); value.refs.push({ ref_hex: 'dead', object_id: 'f'.repeat(40) });
  assert.equal(normalized.refs.length, 1); assert.equal(normalized.refs[0].object_id, f.tip);
});
