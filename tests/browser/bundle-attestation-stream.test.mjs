// Production streaming file/signature paths; no Git validity or native-node claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { open, mkdtemp, writeFile, readFile, rename, symlink, chmod, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { ATTESTATION_LIMITS, attestationFileLimits, signSourceBackup, signSourceBackupFile,
  verifySourceAttestation, authenticateSourceBackup, authenticateSourceBackupFile }
  from '../../scripts/lib/source-attestation.mjs';
const pair = generateKeyPairSync('ed25519');
const privatePem = Buffer.from(pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
const publicPem = Buffer.from(pair.publicKey.export({ type: 'spki', format: 'pem' }));
const now = Date.parse('2026-09-28T12:00:00Z');
const metadata = { repository: 'team/repo', sequence: '9007199254740993', issued_at: '2026-09-28T11:59:59Z' };
const policy = { repository: metadata.repository, minimum_sequence: metadata.sequence };
const options = { now };
const refused = code => error => error.code === code;
const body = Buffer.from(Array.from({ length: 150003 }, (_, i) => i % 251));
async function fixture(run) {
  const directory = await mkdtemp(join(tmpdir(), 'fg-attestation-stream-'));
  const input = join(directory, 'input.bundle'), envelope = join(directory, 'input.dsse.json');
  const key = join(directory, 'private.pem'), pub = join(directory, 'public.pem');
  await writeFile(input, body); await writeFile(key, privatePem, { mode: 0o600 }); await writeFile(pub, publicPem);
  try { return await run({ directory, input, envelope, key, pub }); }
  finally { await rm(directory, { recursive: true, force: true }); }
}
const cli = args => spawnSync(process.execPath, [resolve('scripts/attest_git_bundle.mjs'), ...args],
  { encoding: 'utf8', timeout: 30000, env: { ...process.env, PATH: '/nonexistent' } });

test('streamed signatures are byte-identical to the existing owned-byte signer', () => fixture(async f => {
  const old = await signSourceBackup(body, privatePem, metadata, options), events = [];
  const streamed = await signSourceBackupFile(f.input, privatePem, metadata, { ...options, onProgress: event => events.push(event) });
  assert.deepEqual(streamed.envelope, old.envelope); assert.deepEqual(streamed.statement, old.statement);
  assert.equal(streamed.signer_key_id, old.signer_key_id);
  assert.deepEqual(streamed.streaming, { read_calls: 3, maximum_read_bytes: 65536 });
  assert.deepEqual(events.map(e => e.bytes_hashed), [0, 65536, 131072, body.length]);
  assert(events.every(e => Object.isFrozen(e) && e.total_bytes === body.length));
  const result = await authenticateSourceBackupFile(f.input, old.envelope, publicPem, policy, options);
  assert.equal(result.authentication.signature_verified, true); assert(!Object.hasOwn(result, 'bytes'));
  for (const key of ['object_closure_verified', 'forge_state_verified', 'current_branch_verified']) assert.equal(result.authentication[key], false);
}));

test('explicit large-file policy does not silently widen the existing byte-returning APIs', () => fixture(async f => {
  const length = ATTESTATION_LIMITS.bundleBytes + 1;
  const file = await open(f.input, 'w'); await file.truncate(length); await file.close();
  await assert.rejects(signSourceBackupFile(f.input, privatePem, metadata, options), refused('attestation_file_size_or_type'));
  const signed = await signSourceBackupFile(f.input, privatePem, metadata, { ...options, maximumBytes: length });
  assert.equal(signed.statement.artifact.bytes, length);
  await assert.rejects(verifySourceAttestation(signed.envelope, publicPem, policy, options), refused('invalid_attestation_artifact'));
  const checked = await authenticateSourceBackupFile(f.input, signed.envelope, publicPem, policy, { ...options, maximumBytes: length });
  assert.equal(checked.authentication.signature_verified, true);
  await assert.rejects(authenticateSourceBackupFile(f.input, signed.envelope, publicPem, policy, { ...options, maximumBytes: length - 1 }), refused('invalid_attestation_artifact'));
  const bytes = Buffer.alloc(length);
  await assert.rejects(signSourceBackup(bytes, privatePem, metadata, options), refused('attestation_bundle_byte_limit'));
  await assert.rejects(authenticateSourceBackup(bytes, signed.envelope, publicPem, policy, options), refused('attestation_bundle_byte_limit'));
}));

for (const maximumBytes of [0, -1, 1.5, Infinity, NaN, null, '20', Number.MAX_SAFE_INTEGER + 1]) {
  test(`reject invalid file allowance ${String(maximumBytes)} before I/O`, async () => {
    assert.throws(() => attestationFileLimits({ maximumBytes }), refused('invalid_attestation_file_limits'));
    await assert.rejects(signSourceBackupFile('/missing', privatePem, metadata, { ...options, maximumBytes }), refused('invalid_attestation_file_limits'));
  });
}
for (const timeoutMs of [0, null, -1, 1.5, 86400001]) test(`reject invalid deadline ${String(timeoutMs)} before I/O`, async () => {
  await assert.rejects(signSourceBackupFile('/missing', privatePem, metadata, { ...options, timeoutMs }), refused('invalid_attestation_file_limits'));
});

test('byte-limit refusal precedes allocation and read callbacks, with an exact-size permitted twin', () => fixture(async f => {
  let callbacks = 0;
  await assert.rejects(signSourceBackupFile(f.input, privatePem, metadata, { ...options, maximumBytes: body.length - 1,
    onProgress() { callbacks++; } }), refused('attestation_file_size_or_type'));
  assert.equal(callbacks, 0);
  assert.equal((await signSourceBackupFile(f.input, privatePem, metadata, { ...options, maximumBytes: body.length })).statement.artifact.bytes, body.length);
}));

test('bad signature, wrong repository, rollback, and expiry refuse before opening an artifact', () => fixture(async f => {
  const signed = await signSourceBackup(body, privatePem, metadata, options);
  const missing = join(f.directory, 'does-not-exist');
  const wrong = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  await assert.rejects(authenticateSourceBackupFile(missing, signed.envelope, Buffer.from(wrong), policy, options), refused('attestation_key_hint_mismatch'));
  await assert.rejects(authenticateSourceBackupFile(missing, signed.envelope, publicPem, { ...policy, repository: 'other/repo' }, options), refused('attestation_repository_mismatch'));
  await assert.rejects(authenticateSourceBackupFile(missing, signed.envelope, publicPem, { ...policy, minimum_sequence: '9007199254740994' }, options), refused('attestation_below_sequence_floor'));
  const expires = await signSourceBackup(body, privatePem, { ...metadata, expires_at: '2026-09-28T12:00:01Z' }, options);
  await assert.rejects(authenticateSourceBackupFile(missing, expires.envelope, publicPem, policy, { now: now + 1000 }), refused('attestation_expired'));
  await assert.rejects(signSourceBackupFile(missing, Buffer.from('invalid key'), metadata, options), refused('invalid_attestation_key'));
}));

test('same-size artifact substitutions and wrong lengths fail despite genuine approvals', () => fixture(async f => {
  const signed = await signSourceBackup(body, privatePem, metadata, options);
  const changed = Buffer.from(body); changed[70000] ^= 1; await writeFile(f.input, changed);
  await assert.rejects(authenticateSourceBackupFile(f.input, signed.envelope, publicPem, policy, options), refused('attestation_artifact_mismatch'));
  await writeFile(f.input, body.subarray(1));
  let reads = 0;
  await assert.rejects(authenticateSourceBackupFile(f.input, signed.envelope, publicPem, policy, { ...options, onProgress() { reads++; } }), refused('attestation_artifact_mismatch'));
  assert.equal(reads, 0);
  await writeFile(f.input, body); assert.equal((await authenticateSourceBackupFile(f.input, signed.envelope, publicPem, policy, options)).authentication.signature_verified, true);
}));

for (const change of ['grow', 'truncate', 'overwrite', 'replace', 'permissions']) test(`a ${change} during hashing cannot produce a signed result`, () => fixture(async f => {
  let changed = false;
  const mutate = async event => {
    if (changed || !event.bytes_hashed) return; changed = true;
    if (change === 'replace') { await rename(f.input, f.input + '.old'); await writeFile(f.input, body); }
    else if (change === 'permissions') await chmod(f.input, 0o400);
    else {
      const file = await open(f.input, 'r+');
      try {
        if (change === 'truncate') await file.truncate(2);
        else await file.write(Buffer.from([255]), 0, 1, change === 'grow' ? body.length : 0);
      } finally { await file.close(); }
    }
  };
  await assert.rejects(signSourceBackupFile(f.input, privatePem, metadata, { ...options, onProgress: mutate }), refused('attestation_file_changed'));
  assert(changed);
}));

test('file mutation after final data read is checked before any authentication success', () => fixture(async f => {
  const signed = await signSourceBackup(body, privatePem, metadata, options);
  await assert.rejects(authenticateSourceBackupFile(f.input, signed.envelope, publicPem, policy, { ...options,
    async onProgress(event) { if (event.bytes_hashed === body.length) { await rename(f.input, f.input + '.old'); await writeFile(f.input, body); } }
  }), refused('attestation_file_changed'));
}));

test('nonregular and symlink input refusal does not affect permitted ordinary files', () => fixture(async f => {
  const link = f.input + '.link'; await symlink(f.input, link);
  await assert.rejects(signSourceBackupFile(link, privatePem, metadata, options), error => error.code === 'ELOOP');
  await assert.rejects(signSourceBackupFile(f.directory, privatePem, metadata, options), refused('attestation_file_size_or_type'));
  await writeFile(f.input, ''); await assert.rejects(signSourceBackupFile(f.input, privatePem, metadata, options), refused('attestation_file_size_or_type'));
  await writeFile(f.input, Buffer.of(0)); assert.equal((await signSourceBackupFile(f.input, privatePem, metadata, options)).statement.artifact.bytes, 1);
}));

test('preflight and midstream cancellation close the input and never return a partial result', () => fixture(async f => {
  const early = new AbortController(); early.abort();
  await assert.rejects(signSourceBackupFile('/missing', privatePem, metadata, { ...options, signal: early.signal }), refused('attestation_cancelled'));
  const active = new AbortController(); let last = 0;
  await assert.rejects(signSourceBackupFile(f.input, privatePem, metadata, { ...options, signal: active.signal,
    onProgress(event) { last = event.bytes_hashed; if (last) active.abort(); } }), refused('attestation_cancelled'));
  assert.equal(last, 65536);
  assert.equal((await signSourceBackupFile(f.input, privatePem, metadata, options)).statement.artifact.bytes, body.length);
}));

test('deadline covers a stalled progress callback and subsequent hashing/signing', () => fixture(async f => {
  await assert.rejects(signSourceBackupFile(f.input, privatePem, metadata, { ...options, timeoutMs: 5,
    async onProgress() { await new Promise(resolve => setTimeout(resolve, 20)); } }), refused('attestation_deadline'));
}));

test('approval lifetime is checked during long file authentication', () => fixture(async f => {
  const signed = await signSourceBackup(body, privatePem, { ...metadata, expires_at: '2026-09-28T12:00:01Z' }, options);
  const original = Date.now; let current = now;
  try {
    Date.now = () => current;
    await assert.rejects(authenticateSourceBackupFile(f.input, signed.envelope, publicPem, policy, {
      onProgress(event) { if (event.bytes_hashed) current = now + 1000; }
    }), refused('attestation_expired'));
  } finally { Date.now = original; }
}));

test('later caller edits cannot replace captured metadata, keys, ceilings or trust policies', () => fixture(async f => {
  const mutableMeta = { ...metadata }, mutableKey = Buffer.from(privatePem);
  const mutableOptions = { ...options, maximumBytes: body.length, onProgress() { mutableMeta.repository = 'other/repo'; mutableKey.fill(0); mutableOptions.maximumBytes = 1; } };
  const signed = await signSourceBackupFile(f.input, mutableKey, mutableMeta, mutableOptions);
  assert.equal(signed.statement.repository, metadata.repository);
  const mutablePolicy = { ...policy };
  const checked = await authenticateSourceBackupFile(f.input, signed.envelope, publicPem, mutablePolicy, { ...options,
    onProgress() { mutablePolicy.minimum_sequence = '18446744073709551615'; mutablePolicy.repository = 'other/repo'; } });
  assert.equal(checked.authentication.repository, policy.repository);
}));

test('actual CLI sign/check use streaming, retain no-overwrite semantics, and reject invalid options pre-I/O', () => fixture(async f => {
  const signArgs = ['sign', f.input, f.envelope, '--key', f.key, '--repository', 'team/repo', '--sequence', '42', '--max-input-bytes', String(body.length), '--timeout-secs', '20'];
  const signed = cli(signArgs); assert.equal(signed.status, 0, signed.stderr);
  const report = JSON.parse(signed.stdout); assert.equal(report.streaming.maximum_read_bytes, 65536);
  const encoded = await readFile(f.envelope), again = cli(signArgs); assert.equal(again.status, 1); assert.equal(again.stdout, ''); assert.deepEqual(await readFile(f.envelope), encoded);
  const checked = cli(['check', f.input, f.envelope, '--trust-key', f.pub, '--repository', 'team/repo', '--minimum-sequence', '42']);
  assert.equal(checked.status, 0, checked.stderr); assert.equal(JSON.parse(checked.stdout).signature_verified, true);
  for (const args of [['--max-input-bytes', '01'], ['--max-input-bytes', '9007199254740992'], ['--timeout-secs', '86401'], ['--timeout-secs', '0']]) {
    const result = cli(['sign', '/missing', f.envelope, '--key', '/missing-key', '--repository', 'team/repo', '--sequence', '1', ...args]);
    assert.equal(result.status, 1); assert.equal(JSON.parse(result.stderr).code, 'invalid_attestation_file_limits');
  }
  assert.deepEqual(await readFile(f.input), body);
}));

test('actual CLI signs and authenticates beyond the old 16 MiB input boundary', () => fixture(async f => {
  const length = ATTESTATION_LIMITS.bundleBytes + 123;
  const file = await open(f.input, 'w'); await file.truncate(length); await file.close();
  const signArgs = ['sign', f.input, f.envelope, '--key', f.key, '--repository', 'team/repo', '--sequence', '42'];
  assert.equal(cli(signArgs).status, 1);
  const signed = cli([...signArgs, '--max-input-bytes', String(length)]); assert.equal(signed.status, 0, signed.stderr);
  const checkArgs = ['check', f.input, f.envelope, '--trust-key', f.pub, '--repository', 'team/repo', '--minimum-sequence', '42'];
  assert.equal(cli(checkArgs).status, 1);
  const checked = cli([...checkArgs, '--max-input-bytes', String(length)]); assert.equal(checked.status, 0, checked.stderr);
  assert.equal(JSON.parse(checked.stdout).statement.artifact.bytes, length);
}));

test('over 1 GiB is hashed end to end with bounded observed read sizes and sublinear peak memory', t => fixture(async f => {
  const length = 1024 * 1024 * 1024 + 17;
  const file = await open(f.input, 'w'); await file.truncate(length); await file.close();
  const helper = resolve('tests/browser/bundle-attestation-stream-child.mjs');
  const child = spawnSync(process.execPath, ['--max-old-space-size=64', helper, f.input, f.key, f.pub, String(length)],
    { encoding: 'utf8', timeout: 60000, env: { ...process.env, PATH: '/nonexistent' } });
  assert.equal(child.status, 0, child.stderr);
  const report = JSON.parse(child.stdout); t.diagnostic(JSON.stringify(report));
  assert.equal(report.bytes, length); assert.equal(report.signature_verified, true);
  assert.equal(report.maximum_read_bytes, 65536); assert.equal(report.read_calls, Math.ceil(length / 65536));
  if (process.platform === 'linux') assert(report.max_rss_kib < 256 * 1024, JSON.stringify(report));
  // Independent expected hash over a logical zero stream, without reading the file.
  const digest = createHash('sha256'), zeros = Buffer.alloc(1024 * 1024);
  for (let at = 0; at < length; at += zeros.length) digest.update(zeros.subarray(0, Math.min(zeros.length, length - at)));
  assert.equal(report.sha256, digest.digest('hex'));
}));
