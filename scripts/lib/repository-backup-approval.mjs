// Detached operator approval for fg backup archives, NOT a Repository Capsule.
// The application-specific DSSE type cannot authenticate portable Git bundles.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { promisify } from 'node:util';
import { BACKUP_LIMITS, backupError, backupLifetime, exact, hashRepositoryBackup } from './repository-backup-io.mjs';

export const REPOSITORY_BACKUP_TYPE = 'application/vnd.frankengit.repository-backup-approval.v1+json';
const TYPE = 'frankengit-repository-backup-approval-v1', SCOPE = 'authority_and_selected_git_objects';
const IDENTITY = ['tenant_id', 'repository_id', 'incarnation_id', 'object_format'];
const signAsync = promisify(sign), verifyAsync = promisify(verify);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function fail(code) { throw backupError(code); }
export function backupDecimal(value, maximum = 18446744073709551615n) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value) || BigInt(value) > maximum) fail('backup_invalid_decimal');
  return value;
}
function identity(value) {
  for (const name of IDENTITY.slice(0, 3)) if (typeof value[name] !== 'string' || !/^[0-9a-f]{32}$/.test(value[name])) fail('backup_invalid_identity');
  if (!['sha1', 'sha256'].includes(value.object_format)) fail('backup_invalid_format');
  return Object.fromEntries(IDENTITY.map(k => [k, value[k]]));
}
export function backupPolicy(value) {
  if (!exact(value, [...IDENTITY, 'minimum_head_generation'])) fail('backup_invalid_policy');
  return Object.freeze({ ...identity(value), minimum_head_generation: backupDecimal(value.minimum_head_generation) });
}
function instant(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value)
    || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString().replace('.000Z', 'Z') !== value) fail('backup_invalid_time');
  return value;
}
export function repositoryBackupDeclarations(value, now = Date.now()) {
  const keys = [...IDENTITY, 'head_generation', 'issued_at', 'expires_at'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !keys.includes(k))) fail('backup_invalid_metadata');
  const issued_at = instant(value.issued_at ?? new Date(Math.floor(now / 1000) * 1000).toISOString().replace('.000Z', 'Z'));
  const expires_at = value.expires_at == null ? null : instant(value.expires_at);
  if (expires_at !== null && Date.parse(expires_at) <= Date.parse(issued_at)) fail('backup_invalid_lifetime');
  return { ...identity(value), head_generation: backupDecimal(value.head_generation), issued_at, expires_at };
}
function fresh(statement, policy, now) {
  if (IDENTITY.some(k => statement[k] !== policy[k])) fail('backup_approval_identity_mismatch');
  if (BigInt(statement.head_generation) < BigInt(policy.minimum_head_generation)) fail('backup_approval_below_floor');
  if (Date.parse(statement.issued_at) > now + 300000) fail('backup_approval_in_future');
  if (statement.expires_at !== null && Date.parse(statement.expires_at) <= now) fail('backup_approval_expired');
}
function copy(bytes, maximum) {
  if (!(bytes instanceof Uint8Array) || bytes.buffer instanceof SharedArrayBuffer || bytes.length < 1 || bytes.length > maximum) fail('backup_approval_byte_limit');
  return Buffer.from(bytes);
}
function base64(value, maximum) {
  if (typeof value !== 'string' || !value.length || value.length > Math.ceil(maximum / 3) * 4
    || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) fail('backup_invalid_base64');
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length > maximum || decoded.toString('base64') !== value) fail('backup_invalid_base64');
  return decoded;
}
function pem(input, privatePart) {
  const bytes = copy(input, BACKUP_LIMITS.keyBytes); let der;
  try {
    const label = privatePart ? 'PRIVATE KEY' : 'PUBLIC KEY';
    const match = new RegExp(`^-----BEGIN ${label}-----\\r?\\n([A-Za-z0-9+/=\\r\\n]+)-----END ${label}-----(?:\\r?\\n)?$`).exec(bytes.toString('ascii'));
    if (bytes.some(b => b > 127) || !match) fail('backup_invalid_key');
    der = base64(match[1].replace(/[\r\n]/g, ''), BACKUP_LIMITS.keyBytes);
    const key = privatePart ? createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }) : createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') fail('backup_ed25519_required');
    const canonical = key.export({ format: 'der', type: privatePart ? 'pkcs8' : 'spki' });
    try { if (!canonical.equals(der)) fail('backup_noncanonical_key'); }
    finally { if (privatePart) canonical.fill(0); }
    return key;
  } finally { bytes.fill(0); der?.fill(0); }
}
function keyId(key) {
  return 'sha256:' + sha256((key.type === 'private' ? createPublicKey(key) : key).export({ format: 'der', type: 'spki' }));
}
// DSSE v1 PAE binds the exact type AND original payload bytes. The application
// chooses a strict JSON profile; it never canonicalizes a payload before verify.
export function repositoryBackupPAE(payload) {
  const type = Buffer.from(REPOSITORY_BACKUP_TYPE);
  return Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `), type, Buffer.from(` ${payload.length} `), payload]);
}
function statement(data, artifact, maximum) {
  if (!exact(artifact, ['bytes', 'sha256']) || typeof artifact.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(artifact.sha256)) fail('backup_invalid_artifact');
  backupDecimal(artifact.bytes, BigInt(maximum));
  return Object.freeze({ type: TYPE, ...data, artifact: Object.freeze({ bytes: artifact.bytes, sha256: artifact.sha256 }), scope: SCOPE });
}
export async function signRepositoryBackupFile(path, privatePem, declarations, options = {}) {
  const live = backupLifetime(options), data = repositoryBackupDeclarations(declarations, live.now()), key = pem(privatePem, true);
  const policy = { ...identity(data), minimum_head_generation: data.head_generation };
  fresh(data, policy, live.now());
  const artifact = await hashRepositoryBackup(path, live);
  const signed = statement(data, { bytes: artifact.bytes, sha256: artifact.sha256 }, live.maximumBytes);
  const payload = Buffer.from(JSON.stringify(signed));
  live.check(); fresh(signed, policy, live.now());
  const signature = await signAsync(null, repositoryBackupPAE(payload), key);
  live.check(); fresh(signed, policy, live.now());
  return { envelope: Buffer.from(JSON.stringify({ payloadType: REPOSITORY_BACKUP_TYPE, payload: payload.toString('base64'),
    signatures: [{ keyid: keyId(key), sig: signature.toString('base64') }] }) + '\n'),
    statement: signed, trusted_key_id: keyId(key), native_content_verified: false,
    streaming: { read_calls: artifact.read_calls, maximum_read_bytes: artifact.maximum_read_bytes } };
}
export async function verifyRepositoryBackupApproval(encoded, publicPem, expected, options = {}) {
  const live = backupLifetime(options), policy = backupPolicy(expected);
  const bytes = copy(encoded, BACKUP_LIMITS.envelopeBytes), key = pem(publicPem, false), trusted = keyId(key);
  let envelope;
  try { envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { fail('backup_invalid_envelope'); }
  if (!exact(envelope, ['payloadType', 'payload', 'signatures']) || envelope.payloadType !== REPOSITORY_BACKUP_TYPE
    || !Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) fail('backup_invalid_envelope');
  const signature = envelope.signatures[0];
  if (!exact(signature, ['keyid', 'sig']) || signature.keyid !== trusted) fail('backup_untrusted_signer');
  const payload = base64(envelope.payload, 4096), sig = base64(signature.sig, 64);
  if (sig.length !== 64 || !await verifyAsync(null, repositoryBackupPAE(payload), key, sig)) fail('backup_invalid_signature');
  live.check(); let parsed;
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(payload)); }
  catch { fail('backup_invalid_statement'); }
  if (!exact(parsed, ['type', ...IDENTITY, 'head_generation', 'issued_at', 'expires_at', 'artifact', 'scope'])) fail('backup_invalid_statement');
  const data = repositoryBackupDeclarations(Object.fromEntries([...IDENTITY, 'head_generation', 'issued_at', 'expires_at'].map(k => [k, parsed[k]])), live.now());
  const signed = statement(data, parsed.artifact, live.maximumBytes);
  if (!Buffer.from(JSON.stringify(signed)).equals(payload)) fail('backup_noncanonical_statement');
  const checkCurrent = () => { live.check(); fresh(signed, policy, live.now()); };
  checkCurrent();
  const authentication = Object.freeze({ signature_verified: true, trusted_key_id: trusted, policy, statement: signed,
    native_content_verified: false, newest_checkpoint_verified: false, complete_capsule_verified: false });
  return Object.freeze({ authentication, checkCurrent });
}
export async function authenticateRepositoryBackupFile(path, encoded, publicPem, expected, options = {}) {
  const live = backupLifetime(options);
  const verified = await verifyRepositoryBackupApproval(encoded, publicPem, expected, { ...options, timeoutMs: live.remaining() });
  const artifact = await hashRepositoryBackup(path, live); verified.checkCurrent(); live.check();
  if (artifact.sha256 !== verified.authentication.statement.artifact.sha256 || artifact.bytes !== verified.authentication.statement.artifact.bytes) fail('backup_artifact_mismatch');
  return { ...verified, streaming: { read_calls: artifact.read_calls, maximum_read_bytes: artifact.maximum_read_bytes } };
}
