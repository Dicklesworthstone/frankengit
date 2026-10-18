#!/usr/bin/env node
// URLs can contain bearer capabilities. Read them only from a bounded private
// local file; never put them in command arguments, progress, errors or receipts.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, readBackupControl } from './lib/repository-backup-io.mjs';
import { backupDecimal, backupPolicy } from './lib/repository-backup-approval.mjs';
import { MAX_DOWNLOAD_SOURCES } from './lib/repository-backup-download.mjs';
import { downloadRepositoryBackupWithWitness } from './lib/repository-backup-download-witness.mjs';
import { repositoryBackupReplicationCheckpoint } from './lib/repository-backup-replication.mjs';

export const DOWNLOAD_USAGE = `Usage: node scripts/download_repository_backup.mjs [OPTIONS]
  --sources PRIVATE_JSON          Array of 1..16 explicit HTTPS URLs (max 16 KiB)
  --approval LOCAL_FILE           Original independently obtained signed approval
  --trust-key PUBLIC_PEM          Independently trusted Ed25519 public key
  --replica-directory DIRECTORY   Existing owner-private local directory
  --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
  --minimum-head-generation N     Independently retained checkpoint floor
  --witness DIRECTORY            Existing independently retained checkpoint witness
  --ca-file CERTIFICATE_PEM       Optional independently selected TLS CA certificate
  --checkpoint APPROVAL_SHA256 TRUSTED_KEY_ID   Constrain an exact original intent
  --max-archive-bytes N           Per-archive ceiling (default 1 GiB, max 1 TiB)
  --max-total-read-bytes N        Network and publication payload-read ceiling
  --timeout-secs N                One deadline across all phases (1..3600)
  --progress-json                Bounded redacted milestones on stderr

Each URL is a mirror of the SAME locally approved artifact, in caller preference
order. No redirect, URL credentials, insecure TLS, automatic signing or native
restore. The original signed hash and size are verified before local publication.
Missing/corrupt mirrors may try another explicitly supplied URL, not another
checkpoint. TLS, authentication, cancellation and observer failures are fatal.
The JSON result's candidate works with the existing signed native verify/restore
commands, whose native and retained-witness checks remain mandatory.
URLs may contain access tokens: the source file must be private, singly linked,
and not a symlink. Use an independently obtained approval and trust key, not a
key learned from a download endpoint. No global newest-checkpoint claim is made.
With --witness, retain signed observations before network work and hold its lease
through publication and cleanup. Missing/corrupt witnesses or crash-held leases
refuse; no lock stealing or automatic initialization is performed.
`;
const fields = { '--sources': 'sourceFile', '--approval': 'approval', '--trust-key': 'trustKey',
  '--replica-directory': 'destination', '--ca-file': 'caFile', '--witness': 'witness' };
const policyFields = { '--tenant-id': 'tenant_id', '--repository-id': 'repository_id',
  '--incarnation-id': 'incarnation_id', '--object-format': 'object_format', '--minimum-head-generation': 'minimum_head_generation' };
const fail = code => { throw backupError(code); };
export function downloadArguments(args) {
  if (!Array.isArray(args) || !args.length || args.length > 80 || args.some(v => typeof v !== 'string' || v.length > 8192 || v.includes('\0'))
    || args.reduce((n, s) => n + Buffer.byteLength(s), 0) > 65536) fail('backup_download_argument_limit');
  const result = { policy: {} }, seen = new Set();
  const value = at => { if (!args[at] || args[at].startsWith('--')) fail('backup_download_missing_value'); return args[at]; };
  for (let at = 0; at < args.length; at++) {
    const flag = args[at];
    if (seen.has(flag)) fail('backup_download_duplicate_option'); seen.add(flag);
    if (flag === '--progress-json') { result.progressJson = true; continue; }
    if (flag === '--checkpoint') {
      result.checkpoint = repositoryBackupReplicationCheckpoint({ approval_sha256: value(++at), trusted_key_id: value(++at) }); continue;
    }
    if (!Object.hasOwn(fields, flag) && !Object.hasOwn(policyFields, flag)
      && !['--max-archive-bytes', '--max-total-read-bytes', '--timeout-secs'].includes(flag)) fail('backup_download_unknown_option');
    const text = value(++at);
    if (Object.hasOwn(fields, flag)) result[fields[flag]] = resolve(backupPath(text));
    else if (Object.hasOwn(policyFields, flag)) result.policy[policyFields[flag]] = text;
    else if (flag === '--timeout-secs') result.timeoutMs = Number(backupDecimal(text, 3600n)) * 1000;
    else if (flag === '--max-archive-bytes') result.maximumBytes = Number(backupDecimal(text, BigInt(BACKUP_LIMITS.maximumArchiveBytes)));
    else result.maximumTotalBytes = Number(backupDecimal(text, BigInt((MAX_DOWNLOAD_SOURCES + 3) * BACKUP_LIMITS.maximumArchiveBytes)));
  }
  for (const field of ['sourceFile', 'approval', 'trustKey', 'destination']) backupPath(result[field]);
  result.policy = backupPolicy(result.policy);
  backupLifetime({ maximumBytes: result.maximumBytes, timeoutMs: result.timeoutMs });
  return Object.freeze(result);
}
const write = (output, text) => new Promise((resolve, reject) => {
  output.write(text, error => error ? reject(error) : resolve());
});
export async function runDownloadCommand(args, output = process.stdout, diagnostics = process.stderr, signal = undefined) {
  if (args.length === 1 && args[0] === '--help') { await write(output, DOWNLOAD_USAGE); return null; }
  const { sourceFile, progressJson, ...options } = downloadArguments(args);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs, signal });
  // Private-key-like storage rules apply to signed URLs, NOT to the public keys.
  const bytes = await readBackupControl(sourceFile, BACKUP_LIMITS.envelopeBytes, live, true);
  let sources;
  try { sources = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail('backup_download_invalid_source_file'); }
  finally { bytes.fill(0); }
  live.check();
  const result = await downloadRepositoryBackupWithWitness({ ...options, sourceFile, sources, timeoutMs: live.remaining(), signal,
    onProgress: async event => {
      // At most 34 records: pin + two per source + downloaded artifact.
      if (progressJson && ['checkpoint_pinned', 'source_started', 'source_unavailable', 'download_verified'].includes(event.phase)) {
        await write(diagnostics, JSON.stringify({ type: 'repository_backup_download_progress', ...event }) + '\n');
      }
      live.check();
    } });
  // The archive may already be published. A failed output pipe is not rollback.
  try { await write(output, JSON.stringify(result) + '\n'); }
  catch (error) { error.download_state = 'complete'; error.completed_result = result; throw error; }
  return result;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort();
  const pipeError = () => { controller.abort(); process.exitCode = 1; };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  process.stdout.on('error', pipeError); process.stderr.on('error', pipeError);
  try { await runDownloadCommand(process.argv.slice(2), process.stdout, process.stderr, controller.signal); }
  catch (error) {
    process.exitCode = 1;
    // No raw messages, causes, request/response objects or untrusted headers.
    process.stderr.write(JSON.stringify({ type: 'repository_backup_download_error', code: error.code ?? 'backup_download_failed',
      download_state: error.download_state ?? 'not_started', checkpoint: error.checkpoint ?? null, http_status: error.http_status ?? null,
      source_attempts: error.source_attempts ?? [], active_source_sha256: error.active_source_sha256 ?? null,
      streaming: error.download_streaming ?? null, publication_state: error.publication_state ?? null,
      replica: error.replica ?? null, retained_download: error.retained_download ?? null,
      download_cleanup_error: error.download_cleanup_error ?? null, cleanup_error: error.cleanup_error ?? null,
      witness: error.witness ?? null, witness_lock_retained: error.witness_lock_retained ?? false,
      witness_cleanup_error: error.witness_cleanup_error ?? null, witness_publication_state: error.witness_publication_state ?? null,
      completed_result: error.completed_result ?? null }) + '\n');
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
