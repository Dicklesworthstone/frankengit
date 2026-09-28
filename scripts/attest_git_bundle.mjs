#!/usr/bin/env node
// Detached backup approval, separate from Git/capsule validity and authority.
import { resolve } from 'node:path';
import { ATTESTATION_LIMITS, attestationMetadata, attestationPolicy, signSourceBackupFile,
  readAttestationFile, authenticateSourceBackupFile, copyAuthenticatedSourceBackup, attestationFileLimits, publishAttestation } from './lib/source-attestation.mjs';
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
Both modes stream local files in at most 64 KiB reads. Optional resource bounds:
  --max-input-bytes DECIMAL  Explicit file ceiling (default 16777216)
  --timeout-secs DECIMAL     Total streaming/signature deadline (default 300; max 86400)
Larger signing/authentication does not raise the Git verifier/restore limits.
Check mode also accepts --copy-to NEW.bundle to publish an authenticated copy
through a private staging file and no-replace installation. The destination
parent must be owned by this user and not writable by group/others.
Without --copy-to, check remains read-only. This does not restore a repository.
Use -- before literal paths that start with a dash; --help opens no files.
`;
function parse(args) {
  const operation = args[0], paths = [], values = {}; let literal = false;
  const allowed = operation === 'sign' ? ['key', 'repository', 'sequence', 'expires-at'] : operation === 'check' ? ['trust-key', 'repository', 'minimum-sequence'] : [];
  if (!allowed.length) throw new Error('attestation_sign_or_check_required');
  if (operation === 'check') allowed.push('copy-to');
  allowed.push('max-input-bytes', 'timeout-secs');
  for (let i = 1; i < args.length; i++) {
    const arg = args[i]; if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && arg.startsWith('-')) {
      const name = arg.slice(2);
      if (!arg.startsWith('--') || !allowed.includes(name) || Object.hasOwn(values, name)) throw new Error('invalid_attestation_option');
      const value = args[++i]; if (!value || value.startsWith('--') || value.length > 8192) throw new Error('invalid_attestation_option_value'); values[name] = value;
    } else { if (!arg || arg.length > 8192) throw new Error('invalid_attestation_path'); paths.push(arg); }
  }
  if (paths.length !== 2) throw new Error('attestation_input_and_output_required');
  const decimal = name => {
    const value = values[name];
    if (!/^[1-9][0-9]{0,15}$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error('invalid_attestation_file_limits');
    return Number(value);
  };
  const limits = attestationFileLimits({ ...(values['max-input-bytes'] ? { maximumBytes: decimal('max-input-bytes') } : {}),
    ...(values['timeout-secs'] ? { timeoutMs: decimal('timeout-secs') * 1000 } : {}) });
  const key = values[operation === 'sign' ? 'key' : 'trust-key']; if (!key) throw new Error('attestation_key_required');
  if (operation === 'sign') {
    const metadata = attestationMetadata({ repository: values.repository, sequence: values.sequence,
      ...(values['expires-at'] ? { expires_at: values['expires-at'] } : {}) });
    if (resolve(paths[0]) === resolve(paths[1]) || resolve(key) === resolve(paths[1])) throw new Error('attestation_output_conflicts_with_input');
    return { operation, paths, key, metadata, limits };
  }
  const copyTo = values['copy-to'] ?? null;
  if (copyTo !== null && [paths[0], paths[1], key].some(path => resolve(path) === resolve(copyTo))) throw new Error('attestation_output_conflicts_with_input');
  return { operation, paths, key, limits, copyTo, policy: attestationPolicy({ repository: values.repository, minimum_sequence: values['minimum-sequence'] }) };
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
        const signed = await signSourceBackupFile(command.paths[0], key, command.metadata, { signal, ...command.limits });
        publication = await publishAttestation(command.paths[1], signed.envelope, { signal });
        output = JSON.stringify({ type: 'frankengit-source-attestation-signed-v1', ...publication,
          signer_key_id: signed.signer_key_id, statement: signed.statement, streaming: signed.streaming, object_closure_verified: false }, null, 2) + '\n';
      } finally { key.fill(0); }
    } else {
      const encoded = await readAttestationFile(command.paths[1], ATTESTATION_LIMITS.envelopeBytes, { signal });
      const key = await readAttestationFile(command.key, ATTESTATION_LIMITS.keyBytes, { signal });
      const result = command.copyTo === null
        ? await authenticateSourceBackupFile(command.paths[0], encoded, key, command.policy, { signal, ...command.limits })
        : await copyAuthenticatedSourceBackup(command.paths[0], command.copyTo, encoded, key, command.policy, { signal, ...command.limits });
      publication = result.copy ?? null;
      output = JSON.stringify({ type: 'frankengit-source-attestation-checked-v1', ...result.authentication, streaming: result.streaming,
        ...(result.copy ? { copy: result.copy } : {}) }, null, 2) + '\n';
    }
  }
  await new Promise((resolve, reject) => process.stdout.write(output, error => error ? reject(error) : resolve()));
} catch (error) {
  process.stderr.write(JSON.stringify({ type: 'frankengit-source-attestation-error-v1', code: error.code ?? error.message ?? 'attestation_failed',
    state: publication?.state ?? error.attestation_state ?? 'not_created', cleanup_error: error.attestation_cleanup_error ?? null, temporary: error.attestation_temporary ?? null }) + '\n'); process.exitCode = 1;
} finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
