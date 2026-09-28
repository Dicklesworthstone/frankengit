#!/usr/bin/env node
// Detached backup approval, separate from Git/capsule validity and authority.
import { resolve } from 'node:path';
import { ATTESTATION_LIMITS, attestationMetadata, attestationPolicy, signSourceBackup,
  readAttestationFile, readAuthenticatedSourceBackup, publishAttestation } from './lib/source-attestation.mjs';
const HELP = `Usage:
  node scripts/attest_git_bundle.mjs sign INPUT.bundle OUTPUT.dsse.json \\
    --key PRIVATE.pem --repository OWNER/REPO --sequence POSITIVE_DECIMAL [--expires-at UTC]
  node scripts/attest_git_bundle.mjs check INPUT.bundle ATTESTATION.dsse.json \\
    --trust-key PUBLIC.pem --repository OWNER/REPO --minimum-sequence POSITIVE_DECIMAL

Create or authenticate an Ed25519 DSSE statement binding exact artifact bytes,
repository name, sequence and issuance/optional expiration time. Key files must
be Ed25519 PKCS8 PRIVATE KEY or SPKI PUBLIC KEY PEM. Private keys must be owned
by the current user, single-linked and inaccessible to group/other users.
Sign output is exclusive: existing paths are never overwritten.

The public key and sequence floor must come from a separately trusted source.
No key, URL, repository name or trust floor is adopted from an untrusted backup.
No network, Git subprocess, key generation, repository write or native signing
authority is involved. This command authenticates bytes, not Git validity.
Use verify_git_bundle.mjs / recover_git_bundle.mjs for object/closure checks.
No expiration is assumed for archival backups. Sequence floors are mandatory.
Use -- before literal paths that start with a dash; --help opens no files.
`;
function parse(args) {
  const operation = args[0], paths = [], values = {}; let literal = false;
  const allowed = operation === 'sign' ? ['key', 'repository', 'sequence', 'expires-at'] : operation === 'check' ? ['trust-key', 'repository', 'minimum-sequence'] : [];
  if (!allowed.length) throw new Error('attestation_sign_or_check_required');
  for (let i = 1; i < args.length; i++) {
    const arg = args[i]; if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && arg.startsWith('-')) {
      const name = arg.slice(2);
      if (!arg.startsWith('--') || !allowed.includes(name) || Object.hasOwn(values, name)) throw new Error('invalid_attestation_option');
      const value = args[++i]; if (!value || value.startsWith('--') || value.length > 8192) throw new Error('invalid_attestation_option_value'); values[name] = value;
    } else { if (!arg || arg.length > 8192) throw new Error('invalid_attestation_path'); paths.push(arg); }
  }
  if (paths.length !== 2) throw new Error('attestation_input_and_output_required');
  const key = values[operation === 'sign' ? 'key' : 'trust-key']; if (!key) throw new Error('attestation_key_required');
  if (operation === 'sign') {
    const metadata = attestationMetadata({ repository: values.repository, sequence: values.sequence,
      ...(values['expires-at'] ? { expires_at: values['expires-at'] } : {}) });
    if (resolve(paths[0]) === resolve(paths[1]) || resolve(key) === resolve(paths[1])) throw new Error('attestation_output_conflicts_with_input');
    return { operation, paths, key, metadata };
  }
  return { operation, paths, key, policy: attestationPolicy({ repository: values.repository, minimum_sequence: values['minimum-sequence'] }) };
}
const controller = new AbortController(), cancel = () => controller.abort();
process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
const pipeError = () => { process.exitCode = 1; }; process.stdout.on('error', pipeError); process.stderr.on('error', pipeError);
let publication = null;
try {
  const args = process.argv.slice(2); let output;
  if (args.length === 1 && args[0] === '--help') output = HELP;
  else {
    const command = parse(args), signal = controller.signal;
    if (command.operation === 'sign') {
      const key = await readAttestationFile(command.key, ATTESTATION_LIMITS.keyBytes, { signal, privateKey: true });
      try {
        const bytes = await readAttestationFile(command.paths[0], ATTESTATION_LIMITS.bundleBytes, { signal });
        const signed = await signSourceBackup(bytes, key, command.metadata, { signal });
        publication = await publishAttestation(command.paths[1], signed.envelope, { signal });
        output = JSON.stringify({ type: 'frankengit-source-attestation-signed-v1', ...publication,
          signer_key_id: signed.signer_key_id, statement: signed.statement, object_closure_verified: false }, null, 2) + '\n';
      } finally { key.fill(0); }
    } else {
      const { authentication } = await readAuthenticatedSourceBackup(command.paths[0], command.paths[1], command.key, command.policy, { signal });
      output = JSON.stringify({ type: 'frankengit-source-attestation-checked-v1', ...authentication }, null, 2) + '\n';
    }
  }
  await new Promise((resolve, reject) => process.stdout.write(output, error => error ? reject(error) : resolve()));
} catch (error) {
  process.stderr.write(JSON.stringify({ type: 'frankengit-source-attestation-error-v1', code: error.code ?? error.message ?? 'attestation_failed',
    state: publication?.state ?? error.attestation_state ?? 'not_created', cleanup_error: error.attestation_cleanup_error ?? null }) + '\n'); process.exitCode = 1;
} finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
