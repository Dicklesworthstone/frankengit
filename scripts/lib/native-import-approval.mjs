// Compose the existing DSSE/Ed25519 verifier with native import. This is not a
// new signature format, Git verifier, policy engine or canonical authorization.
import { createHash } from 'node:crypto';
import { ATTESTATION_LIMITS, attestationPolicy, authenticateSourceBackup, verifySourceAttestation } from './source-attestation.mjs';
import { importError } from './native-import-process.mjs';

export const APPROVAL_FILES = Object.freeze(['approval.dsse.json', 'trusted-public-key.pem']);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const exact = (v, names) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && Object.keys(v).length === names.length && names.every(name => Object.hasOwn(v, name));
function path(value) {
  if (typeof value !== 'string' || !value || value.length > 4096 || /[\0\r\n\uD800-\uDFFF]/u.test(value)) throw importError('invalid_import_approval_path');
  return value;
}
export function normalizeImportApproval(value) {
  if (value === undefined) return null;
  if (!exact(value, ['envelope', 'key', 'policy'])) throw importError('complete_import_approval_required');
  return { envelope: path(value.envelope), key: path(value.key), policy: attestationPolicy(value.policy) };
}
export function validateApprovalBinding(value) {
  if (!exact(value, ['profile', 'envelope_sha256', 'public_key_sha256', 'policy'])
    || value.profile !== 'dsse-ed25519-source-v1'
    || ![value.envelope_sha256, value.public_key_sha256].every(v => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v))) {
    throw importError('invalid_import_approval_binding');
  }
  attestationPolicy(value.policy);
}
async function authorization(encoded, key, policy, live) {
  live.check();
  await verifySourceAttestation(encoded, key, policy, { signal: live.signal }); live.check();
  return {
    binding: { profile: 'dsse-ed25519-source-v1', envelope_sha256: hash(encoded), public_key_sha256: hash(key), policy },
    files: [[APPROVAL_FILES[0], encoded], [APPROVAL_FILES[1], key]],
    async check(bytes) {
      live.check();
      const matched = await authenticateSourceBackup(bytes, encoded, key, policy, { signal: live.signal });
      live.check(); return matched.authentication;
    },
  };
}
/** Verify the caller's external key/repository/floor before opening the source. */
export async function prepareImportApproval(config, read, live) {
  if (config === null) return null;
  const encoded = await read(config.envelope, ATTESTATION_LIMITS.envelopeBytes);
  const key = await read(config.key, ATTESTATION_LIMITS.keyBytes);
  return authorization(encoded, key, config.policy, live);
}
/** An unresolved signed retry cannot select fresh trust material or downgrade.
 * A caller resolving an already terminal outcome does not invoke this path.
 */
export async function recoverImportApproval(binding, read, live) {
  validateApprovalBinding(binding);
  const encoded = await read(APPROVAL_FILES[0], ATTESTATION_LIMITS.envelopeBytes);
  const key = await read(APPROVAL_FILES[1], ATTESTATION_LIMITS.keyBytes);
  if (hash(encoded) !== binding.envelope_sha256 || hash(key) !== binding.public_key_sha256) {
    throw importError('native_import_approval_changed');
  }
  return authorization(encoded, key, attestationPolicy(binding.policy), live);
}
