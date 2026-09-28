// Detached operator attestations for portable Git artifacts, NOT repository
// authority signatures. Trust comes only from a caller-supplied public key and
// repository/sequence policy. No key, URL, or trust floor is learned from input.
// DSSE v1 PAE: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
import { createHash, createPrivateKey, createPublicKey, sign, verify, randomBytes } from 'node:crypto';
import { open, link, lstat, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, basename, resolve, join } from 'node:path';
import { promisify } from 'node:util';

export const ATTESTATION_LIMITS = Object.freeze({ bundleBytes: 16 * 1024 * 1024,
  envelopeBytes: 16 * 1024, payloadBytes: 4096, keyBytes: 8192, futureSkewMs: 300000 });
export const ATTESTATION_TYPE = 'application/vnd.frankengit.source-backup-attestation.v1+json';
const STATEMENT_TYPE = 'frankengit-source-backup-attestation-v1';
const signAsync = promisify(sign), verifyAsync = promisify(verify);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export class SourceAttestationError extends Error {
  constructor(code) { super(code); this.name = 'SourceAttestationError'; this.code = code; }
}
const fail = code => { throw new SourceAttestationError(code); };
function check(signal) { if (signal?.aborted) fail('attestation_cancelled'); }
function record(value, fields, required = fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !fields.includes(key)) || required.some(key => !Object.hasOwn(value, key))) fail('invalid_attestation_record');
}
function owned(value, maximum, code) {
  if (!(value instanceof Uint8Array) || !value.length || value.length > maximum) fail(code);
  return Buffer.from(value); // Buffer.slice would alias the caller across awaits.
}
function sequence(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value) || BigInt(value) > 18446744073709551615n) fail('invalid_attestation_sequence');
  return value;
}
function repository(value) {
  if (typeof value !== 'string' || value.length > 256 || !/^[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)+$/.test(value) ||
      value.split('/').some(part => part === '.' || part === '..')) fail('invalid_attestation_repository');
  return value;
}
function instant(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) fail('invalid_attestation_time');
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString().replace('.000Z', 'Z') !== value) fail('invalid_attestation_time');
  return value;
}
function settings(options, allowMaximum = false) {
  record(options, ['signal', 'now', ...(allowMaximum ? ['maximumBytes'] : [])], []);
  const signal = options.signal, fixed = Object.hasOwn(options, 'now'), now = fixed ? options.now : Date.now();
  if ((signal !== undefined && !(signal instanceof AbortSignal)) || !Number.isSafeInteger(now) || now < 0 || now > 253402300799999) fail('invalid_attestation_options');
  check(signal); return { signal, now, current: () => fixed ? now : Date.now() };
}
export function attestationPolicy(value) {
  record(value, ['repository', 'minimum_sequence']);
  return { repository: repository(value.repository), minimum_sequence: sequence(value.minimum_sequence) };
}
export function attestationMetadata(value, now = Date.now()) {
  record(value, ['repository', 'sequence', 'issued_at', 'expires_at'], ['repository', 'sequence']);
  const issued = instant(value.issued_at ?? new Date(Math.floor(now / 1000) * 1000).toISOString().replace('.000Z', 'Z'));
  const expires = value.expires_at === undefined || value.expires_at === null ? null : instant(value.expires_at);
  if (expires !== null && Date.parse(expires) <= Date.parse(issued)) fail('invalid_attestation_lifetime');
  return { repository: repository(value.repository), sequence: sequence(value.sequence), issued_at: issued, expires_at: expires };
}
function base64(value, maximum) {
  if (typeof value !== 'string' || !value.length || value.length > Math.ceil(maximum / 3) * 4 ||
      !/^[A-Za-z0-9+/_-]+={0,2}$/.test(value) || (/[+/]/.test(value) && /[-_]/.test(value))) fail('invalid_attestation_base64');
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/'), bare = normalized.replace(/=+$/, '');
  const data = Buffer.from(normalized, 'base64');
  if (data.length > maximum || data.toString('base64').replace(/=+$/, '') !== bare ||
      (value.includes('=') && data.toString('base64') !== normalized)) fail('invalid_attestation_base64');
  return data;
}
function pemKey(input, privatePart = false) {
  const copy = owned(input, ATTESTATION_LIMITS.keyBytes, 'invalid_attestation_key');
  let der;
  try {
    if (copy.some(byte => byte > 127)) fail('invalid_attestation_key');
    const label = privatePart ? 'PRIVATE KEY' : 'PUBLIC KEY';
    const match = new RegExp(`^-----BEGIN ${label}-----\\r?\\n([A-Za-z0-9+/=\\r\\n]+)-----END ${label}-----(?:\\r?\\n)?$`).exec(copy.toString('ascii'));
    if (!match) fail('invalid_attestation_key');
    der = base64(match[1].replace(/[\r\n]/g, ''), ATTESTATION_LIMITS.keyBytes);
    let key;
    try { key = privatePart ? createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }) : createPublicKey({ key: der, format: 'der', type: 'spki' }); }
    catch { fail('invalid_attestation_key'); }
    if (key.asymmetricKeyType !== 'ed25519') fail('attestation_requires_ed25519');
    const canonical = key.export({ format: 'der', type: privatePart ? 'pkcs8' : 'spki' });
    try { if (!canonical.equals(der)) fail('noncanonical_attestation_key'); }
    finally { if (privatePart) canonical.fill(0); }
    return key;
  } finally { copy.fill(0); der?.fill(0); }
}
function keyId(key) { return `sha256:${hash((key.type === 'private' ? createPublicKey(key) : key).export({ format: 'der', type: 'spki' }))}`; }
// Lengths are byte counts, including the authenticated application-specific type.
export function attestationPAE(payload) {
  const type = Buffer.from(ATTESTATION_TYPE);
  return Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `), type, Buffer.from(` ${payload.length} `), payload]);
}
async function artifactHash(bytes, signal) {
  const digest = createHash('sha256');
  for (let at = 0; at < bytes.length; at += 65536) {
    check(signal); digest.update(bytes.subarray(at, at + 65536));
    if (at && at % (1024 * 1024) === 0) await new Promise(resolve => setImmediate(resolve));
  }
  check(signal); return digest.digest('hex');
}
function statement(metadata, bytes, sha256, maximum = ATTESTATION_LIMITS.bundleBytes) {
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > maximum || typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(sha256)) fail('invalid_attestation_artifact');
  return { type: STATEMENT_TYPE, ...metadata, artifact: { media_type: 'application/x-git-bundle', bytes, sha256 }, scope: 'portable-git-source-only' };
}
function freshness(signed, policy, now) {
  if (signed.repository !== policy.repository) fail('attestation_repository_mismatch');
  if (BigInt(signed.sequence) < BigInt(policy.minimum_sequence)) fail('attestation_below_sequence_floor');
  if (Date.parse(signed.issued_at) > now + ATTESTATION_LIMITS.futureSkewMs) fail('attestation_issued_in_future');
  if (signed.expires_at !== null && Date.parse(signed.expires_at) <= now) fail('attestation_expired');
}

// Signing approves an exact byte artifact. It deliberately makes NO assertion
// that the bytes are valid Git or a full capsule. Restore must also verify Git.
export async function signSourceBackup(input, privatePem, metadata, options = {}) {
  const { signal, now, current } = settings(options), data = attestationMetadata(metadata, now);
  freshness(data, { repository: data.repository, minimum_sequence: data.sequence }, now);
  const bytes = owned(input, ATTESTATION_LIMITS.bundleBytes, 'attestation_bundle_byte_limit'), key = pemKey(privatePem, true);
  const signed = statement(data, bytes.length, await artifactHash(bytes, signal));
  return signStatement(signed, key, () => {
    check(signal); freshness(data, { repository: data.repository, minimum_sequence: data.sequence }, current());
  });
}
async function signStatement(signed, key, guard) {
  guard(); const payload = Buffer.from(JSON.stringify(signed));
  const signature = await signAsync(null, attestationPAE(payload), key); guard();
  const envelope = { payloadType: ATTESTATION_TYPE, payload: payload.toString('base64'), signatures: [{ keyid: keyId(key), sig: signature.toString('base64') }] };
  return { envelope: Buffer.from(JSON.stringify(envelope) + '\n'), statement: signed, signer_key_id: keyId(key) };
}
export async function verifySourceAttestation(encoded, publicPem, expected, options = {}) {
  const { signal, now, current } = settings(options, true), policy = attestationPolicy(expected);
  const { maximumBytes } = attestationFileLimits({ maximumBytes: Object.hasOwn(options, 'maximumBytes') ? options.maximumBytes : ATTESTATION_LIMITS.bundleBytes });
  const bytes = owned(encoded, ATTESTATION_LIMITS.envelopeBytes, 'attestation_envelope_byte_limit'), key = pemKey(publicPem), trustedId = keyId(key);
  let envelope;
  try { envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { fail('invalid_attestation_envelope'); }
  record(envelope, ['payloadType', 'payload', 'signatures']);
  if (envelope.payloadType !== ATTESTATION_TYPE || !Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) fail('unsupported_attestation_profile');
  const signature = envelope.signatures[0]; record(signature, ['keyid', 'sig'], ['sig']);
  // keyid is only a hint. The actual trusted key is selected OUTSIDE the input
  // and always verifies the signature; an envelope-supplied key is never used.
  if (Object.hasOwn(signature, 'keyid') && signature.keyid !== trustedId) fail('attestation_key_hint_mismatch');
  const payload = base64(envelope.payload, ATTESTATION_LIMITS.payloadBytes), sig = base64(signature.sig, 64);
  if (sig.length !== 64) fail('invalid_attestation_signature');
  if (!await verifyAsync(null, attestationPAE(payload), key, sig)) fail('invalid_attestation_signature');
  check(signal);
  let parsed;
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(payload)); }
  catch { fail('invalid_attestation_payload'); }
  record(parsed, ['type', 'repository', 'sequence', 'issued_at', 'expires_at', 'artifact', 'scope']);
  record(parsed.artifact, ['media_type', 'bytes', 'sha256']);
  const data = attestationMetadata({ repository: parsed.repository, sequence: parsed.sequence, issued_at: parsed.issued_at, expires_at: parsed.expires_at }, now);
  const normalized = statement(data, parsed.artifact.bytes, parsed.artifact.sha256, maximumBytes);
  // The authenticated original payload is also the application payload. Exact
  // canonical bytes reject duplicates, ignored claims and alternate encodings.
  if (!Buffer.from(JSON.stringify(normalized)).equals(payload)) fail('noncanonical_attestation_statement');
  freshness(normalized, policy, current()); check(signal);
  return { signature_verified: true, trusted_key_id: trustedId, repository: policy.repository,
    minimum_sequence: policy.minimum_sequence, statement: normalized, object_closure_verified: false,
    forge_state_verified: false, current_branch_verified: false };
}
export async function authenticateSourceBackup(input, encoded, publicPem, expected, options = {}) {
  const { signal, now, current } = settings(options), captured = { signal, ...(Object.hasOwn(options, 'now') ? { now } : {}) };
  const bytes = owned(input, ATTESTATION_LIMITS.bundleBytes, 'attestation_bundle_byte_limit');
  const authentication = await verifySourceAttestation(encoded, publicPem, expected, captured);
  if (bytes.length !== authentication.statement.artifact.bytes || await artifactHash(bytes, signal) !== authentication.statement.artifact.sha256) fail('attestation_artifact_mismatch');
  freshness(authentication.statement, { repository: authentication.repository, minimum_sequence: authentication.minimum_sequence }, current());
  check(signal); return { bytes, authentication };
}

// Streaming is an explicit local-file profile, not a larger allocation budget
// for the byte-returning verifier/recovery APIs. No statement chooses its own
// resource allowance. Existing callers retain their 16 MiB default.
export function attestationFileLimits(value = {}) {
  record(value, ['maximumBytes', 'timeoutMs'], []);
  const maximumBytes = Object.hasOwn(value, 'maximumBytes') ? value.maximumBytes : ATTESTATION_LIMITS.bundleBytes;
  const timeoutMs = Object.hasOwn(value, 'timeoutMs') ? value.timeoutMs : 300000;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 86400000) fail('invalid_attestation_file_limits');
  return { maximumBytes, timeoutMs };
}
function fileSettings(options) {
  record(options, ['signal', 'now', 'maximumBytes', 'timeoutMs', 'onProgress'], []);
  const limits = attestationFileLimits(Object.fromEntries(['maximumBytes', 'timeoutMs']
    .filter(key => Object.hasOwn(options, key)).map(key => [key, options[key]])));
  const captured = { ...(Object.hasOwn(options, 'signal') ? { signal: options.signal } : {}),
    ...(Object.hasOwn(options, 'now') ? { now: options.now } : {}) };
  const clock = settings(captured), progress = Object.hasOwn(options, 'onProgress') ? options.onProgress : (() => {});
  if (typeof progress !== 'function') fail('invalid_attestation_options');
  const deadline = performance.now() + limits.timeoutMs;
  const guard = () => { check(clock.signal); if (performance.now() >= deadline) fail('attestation_deadline'); };
  guard(); return { ...limits, ...clock, captured, guard, progress };
}
const FILE_IDENTITY_FIELDS = ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'mode', 'uid', 'nlink'];
async function streamArtifact(path, context, expected = null) {
  const { guard, progress, maximumBytes } = context; guard();
  if (typeof path !== 'string' || !path || path.length > 8192 || path.includes('\0') || /[\uD800-\uDFFF]/u.test(path)) fail('invalid_attestation_path');
  if (constants.O_NOFOLLOW === undefined) fail('unsupported_attestation_file_profile');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let buffer;
  try {
    const before = await file.stat({ bigint: true }); guard();
    if (!before.isFile() || before.size < 1n || before.size > BigInt(maximumBytes)) fail('attestation_file_size_or_type');
    const total = Number(before.size);
    if (expected !== null && total !== expected.bytes) fail('attestation_artifact_mismatch');
    buffer = Buffer.alloc(Math.min(65536, total));
    const digest = createHash('sha256'); let at = 0, readCalls = 0, maximumRead = 0;
    await progress(Object.freeze({ bytes_hashed: 0, total_bytes: total })); guard();
    while (at < total) {
      guard(); const { bytesRead } = await file.read(buffer, 0, Math.min(buffer.length, total - at), at); guard();
      if (!bytesRead) fail('attestation_file_changed');
      digest.update(buffer.subarray(0, bytesRead)); at += bytesRead; readCalls++; maximumRead = Math.max(maximumRead, bytesRead);
      await progress(Object.freeze({ bytes_hashed: at, total_bytes: total })); guard();
    }
    if ((await file.read(buffer, 0, 1, total)).bytesRead) fail('attestation_file_changed');
    const after = await file.stat({ bigint: true });
    let named;
    try { named = await lstat(path, { bigint: true }); } catch { fail('attestation_file_changed'); }
    if (!named.isFile() || FILE_IDENTITY_FIELDS.some(key => before[key] !== after[key] || after[key] !== named[key])) fail('attestation_file_changed');
    guard(); const sha256 = digest.digest('hex');
    if (expected !== null && sha256 !== expected.sha256) fail('attestation_artifact_mismatch');
    return { bytes: total, sha256, streaming: { read_calls: readCalls, maximum_read_bytes: maximumRead } };
  } finally { buffer?.fill(0); await file.close(); }
}
// Same canonical DSSE statement as the in-memory path; only file traversal and
// explicitly supplied resource bounds differ. No complete artifact is retained.
export async function signSourceBackupFile(path, privatePem, metadata, options = {}) {
  const context = fileSettings(options), data = attestationMetadata(metadata, context.now);
  const policy = { repository: data.repository, minimum_sequence: data.sequence };
  const guard = () => { context.guard(); freshness(data, policy, context.current()); };
  guard(); const key = pemKey(privatePem, true); // validate/capture before file I/O
  const artifact = await streamArtifact(path, { ...context, guard }); guard();
  const signed = await signStatement(statement(data, artifact.bytes, artifact.sha256, context.maximumBytes), key, guard);
  return { ...signed, streaming: artifact.streaming };
}
// Authentication precedes opening the artifact. The returned report does not
// expose bytes or authorize reopening the path for restore; use the existing
// owned-byte boundary for that. It establishes identity at this read only.
export async function authenticateSourceBackupFile(path, encoded, publicPem, expected, options = {}) {
  const context = fileSettings(options), policy = attestationPolicy(expected);
  const authentication = await verifySourceAttestation(encoded, publicPem, policy,
    { ...context.captured, maximumBytes: context.maximumBytes });
  const guard = () => { context.guard(); freshness(authentication.statement, policy, context.current()); };
  guard(); const artifact = await streamArtifact(path, { ...context, guard }, authentication.statement.artifact); guard();
  return { authentication, streaming: artifact.streaming };
}

// Trusted local file boundary. Final path components are never followed; a
// private signing key additionally requires single-link owner-only storage.
export async function readAttestationFile(path, maximum, { signal, privateKey = false, expectedBytes = null } = {}) {
  check(signal);
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > ATTESTATION_LIMITS.bundleBytes ||
      typeof privateKey !== 'boolean' || (expectedBytes !== null && (!Number.isSafeInteger(expectedBytes) || expectedBytes < 1 || expectedBytes > maximum)) ||
      constants.O_NOFOLLOW === undefined) fail('unsupported_attestation_file_profile');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size < 1n || before.size > BigInt(maximum)) fail('attestation_file_size_or_type');
    if (expectedBytes !== null && before.size !== BigInt(expectedBytes)) fail('attestation_artifact_mismatch');
    if (privateKey && (typeof process.getuid !== 'function' || before.uid !== BigInt(process.getuid()) || (before.mode & 0o77n) !== 0n || before.nlink !== 1n)) fail('unsafe_attestation_private_key_permissions');
    const bytes = Buffer.alloc(Number(before.size)); let at = 0;
    while (at < bytes.length) {
      check(signal); const { bytesRead } = await file.read(bytes, at, Math.min(65536, bytes.length - at), at);
      if (!bytesRead) fail('attestation_file_changed'); at += bytesRead;
    }
    if ((await file.read(Buffer.alloc(1), 0, 1, bytes.length)).bytesRead) fail('attestation_file_changed');
    const after = await file.stat({ bigint: true });
    if (['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'mode', 'uid', 'nlink'].some(key => before[key] !== after[key])) fail('attestation_file_changed');
    check(signal); return bytes;
  } finally { await file.close(); }
}
export async function readAuthenticatedSourceBackup(path, envelopePath, keyPath, expected, options = {}) {
  const { signal, now, current } = settings(options), policy = attestationPolicy(expected);
  const captured = { signal, ...(Object.hasOwn(options, 'now') ? { now } : {}) };
  const encoded = await readAttestationFile(envelopePath, ATTESTATION_LIMITS.envelopeBytes, { signal });
  const key = await readAttestationFile(keyPath, ATTESTATION_LIMITS.keyBytes, { signal });
  const authentication = await verifySourceAttestation(encoded, key, policy, captured);
  const bytes = await readAttestationFile(path, ATTESTATION_LIMITS.bundleBytes, { signal, expectedBytes: authentication.statement.artifact.bytes });
  if (await artifactHash(bytes, signal) !== authentication.statement.artifact.sha256) fail('attestation_artifact_mismatch');
  // The guard owns its policy and verified timing fields. Changing a returned
  // display record cannot extend validity during downstream Git verification.
  const validity = { ...authentication.statement };
  const checkCurrent = () => { check(signal); freshness(validity, policy, current()); };
  checkCurrent(); return { bytes, authentication, checkCurrent };
}

// Publish a small detached envelope without replacing anything. Once linked,
// finalize synchronization/cleanup despite cancellation and report uncertainty
// on I/O failure. This journal-free output operation does not touch a repo.
export async function publishAttestation(path, input, { signal } = {}) {
  if (constants.O_NOFOLLOW === undefined || constants.O_DIRECTORY === undefined) fail('unsupported_attestation_file_profile');
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('invalid_attestation_options');
  const bytes = owned(input, ATTESTATION_LIMITS.envelopeBytes, 'attestation_envelope_byte_limit');
  const destination = resolve(path), parent = dirname(destination);
  const temporary = join(parent, `.${basename(destination)}.${randomBytes(16).toString('hex')}.attestation-tmp`);
  let file = null, directory = null, identity = null, published = false, linked = false, failure = null;
  async function removeOwned() {
    if (!identity) return;
    let current; try { current = await lstat(temporary); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
    if (current.dev !== identity.dev || current.ino !== identity.ino || !current.isFile()) fail('attestation_temporary_changed');
    await unlink(temporary); identity = null;
  }
  try {
    check(signal);
    directory = await open(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    file = await open(temporary, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    identity = await file.stat();
    let at = 0;
    while (at < bytes.length) {
      check(signal); const { bytesWritten } = await file.write(bytes, at, bytes.length - at, at);
      if (!bytesWritten) fail('attestation_output_short_write'); at += bytesWritten;
    }
    await file.sync(); check(signal);
    const actual = Buffer.alloc(bytes.length); let read = 0;
    while (read < actual.length) { const result = await file.read(actual, read, actual.length - read, read); if (!result.bytesRead) fail('attestation_output_short_read'); read += result.bytesRead; }
    if (!actual.equals(bytes)) fail('attestation_output_mismatch');
    check(signal); await link(temporary, destination); linked = true;
    await directory.sync(); published = true;
    await removeOwned(); await directory.sync();
    return { path: destination, state: 'complete', sha256: hash(bytes), bytes: bytes.length };
  } catch (error) {
    failure = error; error.attestation_state = published ? 'published' : linked ? 'publication_unknown' : 'not_created';
    try { await removeOwned(); } catch { error.attestation_cleanup_error = 'attestation_temporary_cleanup_failed'; }
    throw error;
  } finally {
    let closeError = null;
    for (const handle of [file, directory]) { try { await handle?.close(); } catch (error) { closeError ??= error; } }
    if (closeError) {
      if (failure) failure.attestation_cleanup_error = 'attestation_handle_close_failed';
      else { closeError.attestation_state = published ? 'published' : linked ? 'publication_unknown' : 'not_created'; throw closeError; }
    }
  }
}
