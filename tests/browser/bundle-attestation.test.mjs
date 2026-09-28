// Execute real Ed25519, file operations and the command. These attestations
// bind opaque artifact bytes; Git decoding and restore have separate tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign, verify, createPublicKey } from 'node:crypto';
import { mkdtemp, readFile, writeFile, chmod, symlink, link, readdir, lstat, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { ATTESTATION_LIMITS, ATTESTATION_TYPE, signSourceBackup, verifySourceAttestation,
  authenticateSourceBackup, readAttestationFile, readAuthenticatedSourceBackup,
  publishAttestation, attestationPolicy, attestationMetadata } from '../../scripts/lib/source-attestation.mjs';
const pair = () => {
  const keys = generateKeyPairSync('ed25519');
  return { privateKey: Buffer.from(keys.privateKey.export({ type: 'pkcs8', format: 'pem' })),
    publicKey: Buffer.from(keys.publicKey.export({ type: 'spki', format: 'pem' })) };
};
const keys = pair(), other = pair(), input = Buffer.from('private backup\0\xff\r\nbytes');
const now = Date.parse('2026-09-28T12:00:00Z');
const meta = { repository: 'team/repository', sequence: '7', issued_at: '2026-09-28T11:59:00Z' };
const policy = { repository: meta.repository, minimum_sequence: '7' };
const options = { now };
const fail = code => error => error.code === code;
const signed = extra => signSourceBackup(input, keys.privateKey, { ...meta, ...extra }, options);
// Independent DSSE encoding, not the implementation's exported helper.
const pae = (payload, type = ATTESTATION_TYPE) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${payload.length} `), payload]);
function resign(raw, type = ATTESTATION_TYPE, key = keys.privateKey) {
  const payload = Buffer.from(raw);
  return Buffer.from(JSON.stringify({ payloadType: type, payload: payload.toString('base64'), signatures: [{ sig: sign(null, pae(payload, type), key).toString('base64') }] }));
}
function alter(envelope, work) { const parsed = JSON.parse(envelope); work(parsed); return Buffer.from(JSON.stringify(parsed)); }

test('deterministic Ed25519 statement binds exact bytes, repository and sequence without claiming Git validity', async () => {
  const a = await signed(), b = await signed(); assert.deepEqual(a, b);
  const result = await authenticateSourceBackup(input, a.envelope, keys.publicKey, policy, options);
  assert.deepEqual(result.bytes, input); assert.notEqual(result.bytes, input);
  assert.equal(result.authentication.signature_verified, true);
  assert.equal(result.authentication.statement.artifact.sha256, createHash('sha256').update(input).digest('hex'));
  for (const key of ['object_closure_verified', 'forge_state_verified', 'current_branch_verified']) assert.equal(result.authentication[key], false);
  assert.equal(a.envelope.includes(keys.privateKey), false);
});
test('wire output verifies independently as Ed25519 DSSE, not a signature over untyped JSON', async () => {
  const a = await signed(), envelope = JSON.parse(a.envelope), body = Buffer.from(envelope.payload, 'base64'), sig = Buffer.from(envelope.signatures[0].sig, 'base64');
  assert(verify(null, pae(body), keys.publicKey, sig)); assert(!verify(null, body, keys.publicKey, sig));
  const der = createPublicKey(keys.publicKey).export({ format: 'der', type: 'spki' });
  assert.equal(envelope.signatures[0].keyid, 'sha256:' + createHash('sha256').update(der).digest('hex'));
  const noHint = alter(a.envelope, value => delete value.signatures[0].keyid);
  assert.equal((await verifySourceAttestation(noHint, keys.publicKey, policy, options)).signature_verified, true);
});
test('standard/url-safe base64 with canonical padding or without padding is accepted', async () => {
  const a = await signed();
  for (const url of [false, true]) for (const padded of [false, true]) {
    const envelope = alter(a.envelope, value => {
      const encode = text => { let v = url ? text.replaceAll('+', '-').replaceAll('/', '_') : text; return padded ? v : v.replace(/=+$/, ''); };
      value.payload = encode(value.payload); value.signatures[0].sig = encode(value.signatures[0].sig);
    });
    assert.equal((await verifySourceAttestation(envelope, keys.publicKey, policy, options)).signature_verified, true);
  }
});
test('forged key hints and embedded keys never choose the trust root', async () => {
  const a = await signed();
  await assert.rejects(verifySourceAttestation(a.envelope, other.publicKey, policy, options), fail('attestation_key_hint_mismatch'));
  const forged = await signSourceBackup(input, other.privateKey, meta, options);
  const hint = JSON.parse(a.envelope).signatures[0].keyid;
  await assert.rejects(verifySourceAttestation(alter(forged.envelope, e => e.signatures[0].keyid = hint), keys.publicKey, policy, options), fail('invalid_attestation_signature'));
  await assert.rejects(verifySourceAttestation(alter(forged.envelope, e => e.publicKey = other.publicKey.toString()), keys.publicKey, policy, options), fail('invalid_attestation_record'));
  await assert.rejects(verifySourceAttestation(alter(forged.envelope, e => delete e.signatures[0].keyid), keys.publicKey, policy, options), fail('invalid_attestation_signature'));
});
test('same-size substitutions and truncated artifacts fail despite a genuine signed statement', async () => {
  const a = await signed(), changed = Buffer.from(input); changed[0] ^= 1;
  for (const body of [changed, input.subarray(1)]) await assert.rejects(authenticateSourceBackup(body, a.envelope, keys.publicKey, policy, options), fail('attestation_artifact_mismatch'));
  assert.equal((await authenticateSourceBackup(input, a.envelope, keys.publicKey, policy, options)).authentication.signature_verified, true);
});
test('repository substitution and sequence rollback fail even with a valid signature', async () => {
  const a = await signed();
  await assert.rejects(verifySourceAttestation(a.envelope, keys.publicKey, { ...policy, repository: 'other/repository' }, options), fail('attestation_repository_mismatch'));
  await assert.rejects(verifySourceAttestation(a.envelope, keys.publicKey, { ...policy, minimum_sequence: '8' }, options), fail('attestation_below_sequence_floor'));
  assert.equal((await verifySourceAttestation(a.envelope, keys.publicKey, { ...policy, minimum_sequence: '6' }, options)).statement.sequence, '7');
});
test('unsigned policy is mandatory and cannot be replaced by envelope fields', async () => {
  const a = await signed();
  for (const bad of [{}, { repository: meta.repository }, { minimum_sequence: '7' }, { ...policy, trust: true }, null]) await assert.rejects(verifySourceAttestation(a.envelope, keys.publicKey, bad, options));
});
test('full-width u64 sequences remain exact beyond JavaScript safe integers', async () => {
  const a = await signed({ sequence: '18446744073709551615' });
  assert.equal((await verifySourceAttestation(a.envelope, keys.publicKey, { ...policy, minimum_sequence: '18446744073709551615' }, options)).statement.sequence, '18446744073709551615');
  for (const value of ['0', '01', '1e3', '-1', '18446744073709551616', 7, null]) {
    assert.throws(() => attestationPolicy({ ...policy, minimum_sequence: value }));
    await assert.rejects(signed({ sequence: value }));
  }
});
test('expiry has an exact refusal boundary while archival attestations have no invented expiry', async () => {
  const a = await signed({ expires_at: '2026-09-28T12:00:01Z' });
  assert.equal((await verifySourceAttestation(a.envelope, keys.publicKey, policy, { now: now + 999 })).signature_verified, true);
  await assert.rejects(verifySourceAttestation(a.envelope, keys.publicKey, policy, { now: now + 1000 }), fail('attestation_expired'));
  assert.equal((await verifySourceAttestation((await signed()).envelope, keys.publicKey, policy, { now: now + 31536000000 })).statement.expires_at, null);
});
test('future issuance is bounded to five minutes, including the exact boundary', async () => {
  const raw = (await signed()).statement;
  raw.issued_at = '2026-09-28T12:05:00Z';
  assert.equal((await verifySourceAttestation(resign(JSON.stringify(raw)), keys.publicKey, policy, options)).signature_verified, true);
  raw.issued_at = '2026-09-28T12:05:01Z';
  await assert.rejects(verifySourceAttestation(resign(JSON.stringify(raw)), keys.publicKey, policy, options), fail('attestation_issued_in_future'));
});
test('default wall clock is rechecked after asynchronous signature verification', async () => {
  const a = await signed({ expires_at: '2026-09-28T12:00:01Z' }), original = Date.now; let clock = now;
  try {
    Date.now = () => clock;
    const pending = verifySourceAttestation(a.envelope, keys.publicKey, policy); clock += 1000;
    await assert.rejects(pending, fail('attestation_expired'));
  } finally { Date.now = original; }
});
for (const value of ['2026-02-30T00:00:00Z', '2026-09-28', '2026-09-28T12:00:00+00:00', '2026-09-28T12:00:00.000Z']) test(`unambiguous UTC dates reject ${value}`, () => {
  assert.throws(() => attestationMetadata({ ...meta, issued_at: value }));
});
test('signature and domain substitutions cannot change statement semantics', async () => {
  const a = await signed();
  await assert.rejects(verifySourceAttestation(alter(a.envelope, e => { const p = JSON.parse(Buffer.from(e.payload, 'base64')); p.sequence = '99'; e.payload = Buffer.from(JSON.stringify(p)).toString('base64'); }), keys.publicKey, policy, options), fail('invalid_attestation_signature'));
  await assert.rejects(verifySourceAttestation(resign(JSON.stringify(a.statement), 'application/json'), keys.publicKey, policy, options), fail('unsupported_attestation_profile'));
  const rawSignature = alter(a.envelope, e => e.signatures[0].sig = sign(null, Buffer.from(e.payload, 'base64'), keys.privateKey).toString('base64'));
  await assert.rejects(verifySourceAttestation(rawSignature, keys.publicKey, policy, options), fail('invalid_attestation_signature'));
});
for (const [name, change] of [
  ['unknown authority claim', p => p.authority_verified = true], ['wrong scope', p => p.scope = 'full-capsule'],
  ['wrong artifact media', p => p.artifact.media_type = 'application/json'], ['wrong statement type', p => p.type = 'other'],
  ['numeric sequence', p => p.sequence = 7], ['oversized artifact', p => p.artifact.bytes = ATTESTATION_LIMITS.bundleBytes + 1],
  ['fractional length', p => p.artifact.bytes = 2.5], ['rounded length', p => p.artifact.bytes = 9007199254740992],
]) test(`even a signed ${name} is not a supported statement`, async () => {
  const a = await signed(), p = structuredClone(a.statement); change(p);
  await assert.rejects(verifySourceAttestation(resign(JSON.stringify(p)), keys.publicKey, policy, options));
});
test('authenticated duplicate keys and alternate spellings cannot be parsed as a new statement', async () => {
  const a = await signed(), text = JSON.stringify(a.statement);
  for (const payload of [text.replace('"sequence":"7"', '"sequence":"6","sequence":"7"'), JSON.stringify(a.statement, null, 2), text.replace('team/', 'te\\u0061m/')]) {
    await assert.rejects(verifySourceAttestation(resign(payload), keys.publicKey, policy, options), fail('noncanonical_attestation_statement'));
  }
});
test('malformed signature/envelope data and unsupported multisignature profiles fail closed', async () => {
  const a = await signed();
  for (const encoded of [Buffer.from('{'), Buffer.from([255]),
    alter(a.envelope, e => e.signatures.push(e.signatures[0])), alter(a.envelope, e => e.signatures = []),
    alter(a.envelope, e => e.signatures[0].sig = 'AA=='), alter(a.envelope, e => e.payload += '='),
    alter(a.envelope, e => e.payload += '\n'), alter(a.envelope, e => e.payload = 'AB==')]) await assert.rejects(verifySourceAttestation(encoded, keys.publicKey, policy, options));
});
test('non-Ed25519, private-as-public, concatenated and trailing-DER keys are refused', async () => {
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), a = await signed();
  const publicEc = Buffer.from(ec.publicKey.export({ type: 'spki', format: 'pem' })), privateEc = Buffer.from(ec.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  await assert.rejects(signSourceBackup(input, privateEc, meta, options), fail('attestation_requires_ed25519'));
  await assert.rejects(verifySourceAttestation(a.envelope, publicEc, policy, options), fail('attestation_requires_ed25519'));
  for (const key of [keys.privateKey, Buffer.concat([keys.publicKey, keys.publicKey]), Buffer.from('secret'), Buffer.from([255])]) await assert.rejects(verifySourceAttestation(a.envelope, key, policy, options));
  const der = createPublicKey(keys.publicKey).export({ type: 'spki', format: 'der' });
  const trailing = Buffer.from('-----BEGIN PUBLIC KEY-----\n' + Buffer.concat([der, Buffer.from('hidden')]).toString('base64') + '\n-----END PUBLIC KEY-----\n');
  await assert.rejects(verifySourceAttestation(a.envelope, trailing, policy, options));
});
test('PEM with CRLF works while key data stays outside all output records', async () => {
  const priv = Buffer.from(keys.privateKey.toString().replaceAll('\n', '\r\n'));
  const pub = Buffer.from(keys.publicKey.toString().replaceAll('\n', '\r\n'));
  const a = await signSourceBackup(input, priv, meta, options);
  const report = await verifySourceAttestation(a.envelope, pub, policy, options);
  assert.equal(report.signature_verified, true); assert(!JSON.stringify(report).includes('PRIVATE KEY'));
});
test('mutations of caller bytes, metadata, keys and policy cannot replace in-flight signed inputs', async () => {
  const data = Buffer.from(input), priv = Buffer.from(keys.privateKey), metadata = { ...meta };
  const signing = signSourceBackup(data, priv, metadata, options); data.fill(0); priv.fill(0); metadata.sequence = '99';
  const a = await signing; assert.equal(a.statement.sequence, '7');
  const envelope = Buffer.from(a.envelope), pub = Buffer.from(keys.publicKey), expected = { ...policy }, original = Buffer.from(input);
  const checking = authenticateSourceBackup(original, envelope, pub, expected, options);
  original.fill(0); envelope.fill(0); pub.fill(0); expected.repository = 'attacker/repo'; expected.minimum_sequence = '99';
  const result = await checking; assert.deepEqual(result.bytes, input); assert.equal(result.authentication.statement.repository, meta.repository);
});
test('byte ceilings and unsupported options refuse before a signature result', async () => {
  const a = await signed();
  await assert.rejects(signSourceBackup(Buffer.alloc(ATTESTATION_LIMITS.bundleBytes + 1), keys.privateKey, meta, options), fail('attestation_bundle_byte_limit'));
  await assert.rejects(verifySourceAttestation(Buffer.alloc(ATTESTATION_LIMITS.envelopeBytes + 1), keys.publicKey, policy, options), fail('attestation_envelope_byte_limit'));
  await assert.rejects(verifySourceAttestation(a.envelope, Buffer.alloc(ATTESTATION_LIMITS.keyBytes + 1), policy, options), fail('invalid_attestation_key'));
  for (const bad of [{ now: NaN }, { now: -1 }, { now: Infinity }, { unknown: true }, { signal: {} }]) await assert.rejects(verifySourceAttestation(a.envelope, keys.publicKey, policy, bad));
});
test('cancellation before hashing, during a large hash, and during signature verification yields no proof', async () => {
  const a = await signed(), stopped = new AbortController(); stopped.abort();
  await assert.rejects(signSourceBackup(input, keys.privateKey, meta, { ...options, signal: stopped.signal }), fail('attestation_cancelled'));
  const controller = new AbortController(); const pending = signSourceBackup(Buffer.alloc(2 * 1024 * 1024), keys.privateKey, meta, { ...options, signal: controller.signal }); controller.abort();
  await assert.rejects(pending, fail('attestation_cancelled'));
  const next = new AbortController(); const checking = verifySourceAttestation(a.envelope, keys.publicKey, policy, { ...options, signal: next.signal }); next.abort();
  await assert.rejects(checking, fail('attestation_cancelled'));
});
async function files(work) {
  const root = await mkdtemp(join(tmpdir(), 'fg-source-attestation-'));
  const f = { root, bundle: join(root, 'repo.bundle'), privateKey: join(root, 'key.pem'), publicKey: join(root, 'public.pem'), envelope: join(root, 'backup.dsse.json') };
  await writeFile(f.bundle, input); await writeFile(f.privateKey, keys.privateKey, { mode: 0o600 }); await writeFile(f.publicKey, keys.publicKey, { mode: 0o644 });
  try { return await work(f); } finally { await rm(root, { recursive: true, force: true }); }
}
test('private-key files require owner-only, regular, single-link storage; public keys may be readable', () => files(async f => {
  assert.deepEqual(await readAttestationFile(f.privateKey, 8192, { privateKey: true }), keys.privateKey);
  await chmod(f.privateKey, 0o640);
  await assert.rejects(readAttestationFile(f.privateKey, 8192, { privateKey: true }), fail('unsafe_attestation_private_key_permissions'));
  await chmod(f.privateKey, 0o400);
  assert.deepEqual(await readAttestationFile(f.privateKey, 8192, { privateKey: true }), keys.privateKey);
  await link(f.privateKey, join(f.root, 'duplicate-key'));
  await assert.rejects(readAttestationFile(f.privateKey, 8192, { privateKey: true }), fail('unsafe_attestation_private_key_permissions'));
  assert.deepEqual(await readAttestationFile(f.publicKey, 8192), keys.publicKey);
}));
test('source, key and envelope final-component symlinks and nonregular inputs are refused', () => files(async f => {
  for (const path of [f.bundle, f.privateKey, f.publicKey]) {
    const alias = path + '.link'; await symlink(path, alias);
    await assert.rejects(readAttestationFile(alias, ATTESTATION_LIMITS.bundleBytes));
  }
  await assert.rejects(readAttestationFile(f.root, 8192));
  await assert.rejects(readAttestationFile(f.bundle, input.length - 1), fail('attestation_file_size_or_type'));
}));
test('file-based authentication rejects bad signature/repository/floor before opening the bundle', () => files(async f => {
  const a = await signed(); await writeFile(f.envelope, a.envelope);
  const absent = join(f.root, 'absent.bundle');
  await assert.rejects(readAuthenticatedSourceBackup(absent, f.envelope, f.publicKey, { ...policy, minimum_sequence: '8' }, options), fail('attestation_below_sequence_floor'));
  await assert.rejects(readAuthenticatedSourceBackup(absent, f.envelope, f.publicKey, { ...policy, repository: 'other/repo' }, options), fail('attestation_repository_mismatch'));
  const good = await readAuthenticatedSourceBackup(f.bundle, f.envelope, f.publicKey, policy, options); assert.deepEqual(good.bytes, input);
}));
test('exclusive publication creates durable private bytes and refuses files, directories and dangling links', () => files(async f => {
  const a = await signed(), result = await publishAttestation(f.envelope, a.envelope);
  assert.equal(result.state, 'complete'); assert.deepEqual(await readFile(f.envelope), a.envelope);
  assert.equal((await lstat(f.envelope)).mode & 0o777, 0o600); const before = await lstat(f.envelope);
  await assert.rejects(publishAttestation(f.envelope, Buffer.from('other')), error => error.code === 'EEXIST' && error.attestation_state === 'not_created');
  assert.equal((await lstat(f.envelope)).ino, before.ino); assert.deepEqual(await readFile(f.envelope), a.envelope);
  await assert.rejects(publishAttestation(f.root, a.envelope));
  const dangling = join(f.root, 'dangling'); await symlink('absent', dangling);
  await assert.rejects(publishAttestation(dangling, a.envelope)); assert((await lstat(dangling)).isSymbolicLink());
  assert(!(await readdir(f.root)).some(name => name.endsWith('.attestation-tmp')));
}));
test('competing publishers cannot replace the winner and cancelled publication creates no output', () => files(async f => {
  const a = await signed(), b = await signed({ sequence: '8' });
  const results = await Promise.allSettled([publishAttestation(f.envelope, a.envelope), publishAttestation(f.envelope, b.envelope)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  const bytes = await readFile(f.envelope); assert(bytes.equals(a.envelope) || bytes.equals(b.envelope));
  const controller = new AbortController(); controller.abort();
  await assert.rejects(publishAttestation(join(f.root, 'cancelled'), a.envelope, { signal: controller.signal }), fail('attestation_cancelled'));
  assert(!(await readdir(f.root)).some(name => name.endsWith('.attestation-tmp') || name === 'cancelled'));
}));
const cli = args => spawnSync(process.execPath, [resolve('scripts/attest_git_bundle.mjs'), ...args], { encoding: 'utf8', timeout: 10000, env: { ...process.env, PATH: '/nonexistent' } });
test('actual sign/check commands work without Git or shell tools, preserve input and never overwrite output', () => files(async f => {
  const result = cli(['sign', f.bundle, f.envelope, '--key', f.privateKey, '--repository', meta.repository, '--sequence', '7']);
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
  assert.equal(JSON.parse(result.stdout).object_closure_verified, false);
  const checked = cli(['check', f.bundle, f.envelope, '--trust-key', f.publicKey, '--repository', meta.repository, '--minimum-sequence', '7']);
  assert.equal(checked.status, 0, checked.stderr); assert.equal(JSON.parse(checked.stdout).signature_verified, true);
  assert.deepEqual(await readFile(f.bundle), input);
  const refused = cli(['sign', f.bundle, f.envelope, '--key', f.privateKey, '--repository', meta.repository, '--sequence', '8']);
  assert.equal(refused.status, 1); assert.equal(refused.stdout, ''); assert.equal(JSON.parse(refused.stderr).code, 'EEXIST');
  const wrong = cli(['check', f.bundle, f.envelope, '--trust-key', f.publicKey, '--repository', meta.repository, '--minimum-sequence', '8']);
  assert.equal(wrong.status, 1); assert.equal(wrong.stdout, ''); assert.equal(JSON.parse(wrong.stderr).code, 'attestation_below_sequence_floor');
}));
test('command option validation precedes all file reads and help does not need files', () => {
  for (const args of [[], ['sign', 'absent', 'out'], ['sign', 'absent', 'out', '--key', 'none', '--repository', 'team/repo', '--sequence', '01'],
    ['check', 'absent', 'out', '--trust-key', 'none', '--repository', 'team/repo'], ['check', 'absent', 'out', '--trust-key', 'none', '--repository', 'team/repo', '--minimum-sequence', '7', '--minimum-sequence', '8']]) {
    const result = cli(args); assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.notEqual(JSON.parse(result.stderr).code, 'ENOENT');
  }
  const help = cli(['--help']); assert.equal(help.status, 0, help.stderr); assert.match(help.stdout, /minimum-sequence/);
});
