// Durable operator intent for native canonical bundle import. This directory
// preserves responsibility, not repository authority. Only fg's selected
// terminal outcome can establish publication. Portable Git source, not a capsule.
import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { normalizeNativeBundleOptions, verifyNativeGitBundle } from './native-bundle-verifier.mjs';
import { importError, importJson, importLifetime, runImportProcess } from './native-import-process.mjs';
import { nativeKeyDigest, readNativeImportReceipt, readNativeOutcomeReceipt } from './native-import-receipt.mjs';
import { APPROVAL_FILES, normalizeImportApproval, prepareImportApproval, recoverImportApproval, validateApprovalBinding } from './native-import-approval.mjs';

const INPUT_MAX = 16 * 1024 * 1024, INTENT_MAX = 1024 * 1024;
const INTENT = 'intent.json', SNAPSHOT = 'source.bundle';
const FIELDS = ['type', 'schema_version', 'storage', 'storage_identity', 'tenant_id', 'repository_id',
  'principal_id', 'object_format', 'idempotency_key', 'key_digest', 'artifact', 'expectations', 'content'];
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const id = value => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value) && !/^0+$/.test(value);
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const exactKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const sameNode = (a, b) => a.dev === b.dev && a.ino === b.ino;
const sameFile = (a, b) => ['dev', 'ino', 'size', 'mode', 'uid', 'nlink', 'mtimeNs', 'ctimeNs']
  .every(key => a[key] === b[key]);
const identity = stat => ({ dev: String(stat.dev), ino: String(stat.ino) });
const sameIdentity = (stat, expected) => String(stat.dev) === expected.dev && String(stat.ino) === expected.ino;
function profile() {
  if (typeof process.getuid !== 'function' || constants.O_NOFOLLOW === undefined
    || constants.O_DIRECTORY === undefined || constants.O_NONBLOCK === undefined) throw importError('unsupported_native_import_host');
}
function pathValue(value, absolute = false) {
  if (typeof value !== 'string' || !value || value.length > 4096 || /[\0\r\n\uD800-\uDFFF]/u.test(value)
    || (absolute && !isAbsolute(value))) throw importError('invalid_native_import_path');
  return value;
}
function privateDirectory(stat) {
  if (!stat.isDirectory() || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o777n) !== 0o700n) {
    throw importError('unsafe_native_import_directory');
  }
}
async function directory(path, expected = null, privateOnly = false) {
  const stat = await lstat(path, { bigint: true });
  if (!stat.isDirectory() || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o22n) !== 0n
    || (expected !== null && !sameIdentity(stat, expected))) throw importError('native_import_directory_changed');
  if (privateOnly) privateDirectory(stat);
  return stat;
}
async function readFile(path, maximum, live, privateOnly = false) {
  live.check(); const named = await lstat(path, { bigint: true }); live.check();
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!named.isFile() || !before.isFile() || !sameFile(named, before) || before.size < 1n || before.size > BigInt(maximum)) {
      throw importError('native_import_file_size_or_type');
    }
    if (privateOnly && (before.uid !== BigInt(process.getuid()) || (before.mode & 0o777n) !== 0o600n || before.nlink !== 1n)) {
      throw importError('unsafe_native_import_file');
    }
    const bytes = Buffer.alloc(Number(before.size)); let at = 0;
    while (at < bytes.length) {
      live.check(); const { bytesRead } = await file.read(bytes, at, Math.min(65536, bytes.length - at), at);
      if (!bytesRead) throw importError('native_import_file_changed'); at += bytesRead;
    }
    if ((await file.read(Buffer.alloc(1), 0, 1, at)).bytesRead) throw importError('native_import_file_changed');
    const after = await file.stat({ bigint: true }), current = await lstat(path, { bigint: true }); live.check();
    if (!current.isFile() || !sameFile(before, after) || !sameFile(after, current)) throw importError('native_import_file_changed');
    return { bytes, stat: after };
  } finally { await file.close(); }
}
async function writeNew(path, bytes, live) {
  live.check(); const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await file.chmod(0o600); let at = 0;
    while (at < bytes.length) {
      live.check(); const { bytesWritten } = await file.write(bytes, at, Math.min(65536, bytes.length - at), at);
      if (!bytesWritten) throw importError('native_import_short_write'); at += bytesWritten;
    }
    await file.sync(); live.check();
  } finally { await file.close(); }
  const saved = await readFile(path, bytes.length, live, true);
  if (!saved.bytes.equals(bytes)) throw importError('native_import_write_mismatch');
}
async function syncDirectory(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try { await handle.sync(); } finally { await handle.close(); }
}
function options(value, recovery = false) {
  const allowed = recovery ? ['fg', 'timeoutMs', 'signal', 'intentSha256', 'trustedLocal']
    : ['fg', 'timeoutMs', 'signal', 'trustedLocal', 'storage', 'tenant', 'repository', 'principal', 'format', 'recovery', 'expected', 'approval'];
  if (value === null || typeof value !== 'object' || Object.keys(value).some(key => !allowed.includes(key)) || value.trustedLocal !== true) {
    throw importError('explicit_trusted_local_required');
  }
  profile(); pathValue(value.fg, true);
  const timeoutMs = value.timeoutMs ?? 300000;
  const live = importLifetime(timeoutMs, value.signal);
  if (recovery) {
    if (value.intentSha256 !== undefined && !digest(value.intentSha256)) throw importError('invalid_import_intent_pin');
    return { ...value, timeoutMs, live };
  }
  pathValue(value.storage, true); pathValue(value.recovery, true);
  if (![value.tenant, value.repository, value.principal].every(id) || !['sha1', 'sha256'].includes(value.format)) {
    throw importError('invalid_native_import_identity');
  }
  const expected = value.expected ?? {};
  if (expected.object_format !== undefined && expected.object_format !== value.format) throw importError('native_import_format_mismatch');
  const native = normalizeNativeBundleOptions({ fg: value.fg, expected: { ...expected, object_format: value.format },
    signal: value.signal, maxInputMiB: 16, maxRefs: 64, timeoutMs });
  return { ...value, native, timeoutMs, live, approval: normalizeImportApproval(value.approval) };
}
function nativeOptions(intent, config) {
  return { fg: config.fg, signal: config.signal, timeoutMs: config.live.remaining(), maxInputMiB: 16, maxRefs: 64,
    expected: { ...intent.expectations, sha256: intent.artifact.sha256, object_format: intent.object_format } };
}
async function lookup(intent, config) {
  config.live.check(); await directory(intent.storage, intent.storage_identity); config.live.check();
  const result = await runImportProcess(config.fg, ['outcome', intent.storage, intent.tenant_id,
    intent.repository_id, '--trusted-local', '--principal', intent.principal_id, '--key-stdin',
    '--object-format', intent.object_format], config.live, intent.idempotency_key);
  const found = readNativeOutcomeReceipt(result, intent);
  await directory(intent.storage, intent.storage_identity);
  return found;
}
function report(intent, recovery, intentHash, found, submitted) {
  return { type: 'native_source_import', schema_version: 1, recovery_directory: recovery, intent_sha256: intentHash,
    tenant_id: intent.tenant_id, repository_id: intent.repository_id, principal_id: intent.principal_id,
    object_format: intent.object_format, artifact_sha256: intent.artifact.sha256, artifact_bytes: intent.artifact.bytes,
    key_sha256: hash(intent.idempotency_key), key_digest: found.key_digest, transaction_id: found.transaction_id,
    node_closed: found.node_closed, cleanup_error: found.cleanup_error,
    outcome: found.outcome, terminal: found.terminal, submission_attempted: submitted,
    automatic_retry: false, absence_proves_non_commit: false, recovery_material_retained: true,
    scope: 'portable-git-source-only', forge_state_restored: false, capsule_restored: false,
    ...(intent.schema_version === 2 ? { source_approval: { required: true, checked_before_this_submission: submitted,
      policy: intent.approval.policy, envelope_sha256: intent.approval.envelope_sha256,
      public_key_sha256: intent.approval.public_key_sha256, current_validity_claimed: false } } : {}) };
}
function validateIntent(intent) {
  if (!exactKeys(intent, intent?.schema_version === 2 ? [...FIELDS, 'approval'] : FIELDS)
    || intent.type !== 'native-source-import-intent' || ![1, 2].includes(intent.schema_version)
    || ![intent.tenant_id, intent.repository_id, intent.principal_id].every(id)
    || !['sha1', 'sha256'].includes(intent.object_format) || !nativeKeyDigest(intent.key_digest)
    || !/^fg-source-import-[0-9a-f]{64}$/.test(intent.idempotency_key)
    || !exactKeys(intent.storage_identity, ['dev', 'ino'])
    || !Object.values(intent.storage_identity).every(value => typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value))
    || !exactKeys(intent.artifact, ['bytes', 'sha256']) || !digest(intent.artifact.sha256)
    || !Number.isSafeInteger(intent.artifact.bytes) || intent.artifact.bytes < 1 || intent.artifact.bytes > INPUT_MAX
    || !exactKeys(intent.content, ['declared_refs', 'pack_bytes'])
    || !Number.isSafeInteger(intent.content.declared_refs) || intent.content.declared_refs < 1 || intent.content.declared_refs > 64
    || !Number.isSafeInteger(intent.content.pack_bytes) || intent.content.pack_bytes < 1 || intent.content.pack_bytes > intent.artifact.bytes) {
    throw importError('invalid_native_import_intent');
  }
  if (intent.schema_version === 2) validateApprovalBinding(intent.approval);
  pathValue(intent.storage, true);
  const normalized = normalizeNativeBundleOptions({ fg: '/unused-native-fg', maxInputMiB: 16, maxRefs: 64, expected: intent.expectations });
  if (normalized.expected.object_format !== intent.object_format || JSON.stringify(normalized.expected) !== JSON.stringify(intent.expectations)
    || (normalized.expected.sha256 !== undefined && normalized.expected.sha256 !== intent.artifact.sha256)) throw importError('invalid_native_import_intent');
  return intent;
}
async function loadRecovery(path, config) {
  pathValue(path, true); const recovery = resolve(path);
  const before = await directory(recovery, null, true); config.live.check();
  const saved = await readFile(join(recovery, INTENT), INTENT_MAX, config.live, true);
  const intentHash = hash(saved.bytes);
  if (config.intentSha256 !== undefined && config.intentSha256 !== intentHash) throw importError('native_import_intent_pin_mismatch');
  const intent = validateIntent(importJson(saved.bytes));
  if (Buffer.from(JSON.stringify(intent) + '\n').compare(saved.bytes) !== 0) throw importError('invalid_native_import_intent');
  const after = await directory(recovery, identity(before), true);
  return { intent, recovery, intentHash, directoryIdentity: identity(after), intentIdentity: saved.stat };
}
async function guardRecovery(saved, config, snapshot = null) {
  config.live.check(); await directory(saved.recovery, saved.directoryIdentity, true);
  const current = await readFile(join(saved.recovery, INTENT), INTENT_MAX, config.live, true);
  if (!sameFile(current.stat, saved.intentIdentity) || hash(current.bytes) !== saved.intentHash) throw importError('native_import_intent_changed');
  await directory(saved.intent.storage, saved.intent.storage_identity);
  if (snapshot !== null) {
    const current = await lstat(join(saved.recovery, SNAPSHOT), { bigint: true });
    if (!current.isFile() || !sameFile(current, snapshot)) throw importError('native_import_snapshot_changed');
  }
  config.live.check();
}
async function submit(saved, config, bytes, snapshotStat) {
  await guardRecovery(saved, config, snapshotStat);
  // A retry may have recovered complete bytes from an interrupted preparation.
  // Re-establish persistence before acquiring publication responsibility.
  for (const name of [SNAPSHOT, INTENT, ...(saved.intent.schema_version === 2 ? APPROVAL_FILES : [])]) {
    config.live.check();
    const handle = await open(join(saved.recovery, name), constants.O_RDONLY | constants.O_NOFOLLOW);
    try { await handle.sync(); } finally { await handle.close(); }
  }
  await syncDirectory(saved.recovery); await syncDirectory(dirname(saved.recovery));
  if (saved.intent.schema_version === 2) {
    const approval = await retainedApproval(saved, config);
    await approval.check(bytes);
  }
  await guardRecovery(saved, config, snapshotStat);
  if (bytes.length !== saved.intent.artifact.bytes || hash(bytes) !== saved.intent.artifact.sha256) throw importError('native_import_snapshot_mismatch');
  // No cancellation check may be mistaken for rollback after this point.
  // The immutable intent and snapshot were synced and read back before spawn.
  try {
    const intent = saved.intent;
    const result = await runImportProcess(config.fg, ['bundle', 'import', intent.storage, intent.tenant_id,
      intent.repository_id, join(saved.recovery, SNAPSHOT), '--trusted-local', '--principal', intent.principal_id,
      '--key-stdin', '--object-format', intent.object_format], config.live, intent.idempotency_key);
    const found = readNativeImportReceipt(result, intent);
    if (!found.node_closed) return report(intent, saved.recovery, saved.intentHash, found, true);
    const confirmed = await lookup(intent, config);
    if (confirmed.transaction_id !== found.transaction_id || confirmed.outcome !== found.outcome
      || JSON.stringify(confirmed.terminal) !== JSON.stringify(found.terminal)) throw importError('native_import_confirmation_mismatch');
    return report(intent, saved.recovery, saved.intentHash, confirmed, true);
  } catch (error) {
    error.details = { recovery_directory: saved.recovery, intent_sha256: saved.intentHash,
      key_sha256: hash(saved.intent.idempotency_key), outcome: 'unknown_pending', submission_attempted: true,
      automatic_retry: false, absence_proves_non_commit: false, recovery_material_retained: true };
    throw error;
  }
}

/** Verify and import all advertised direct refs into an EXISTING trusted-local
 * node. Native admission requires absent destination refs and decides atomically.
 * A new exclusive recovery directory is retained on every path after creation.
 */
export async function importNativeSource(path, value) {
  const config = options(value); pathValue(path);
  const approval = await prepareImportApproval(config.approval,
    async (path, maximum) => (await readFile(path, maximum, config.live)).bytes, config.live);
  const input = await readFile(path, INPUT_MAX, config.live);
  if (approval !== null) await approval.check(input.bytes);
  const verified = await verifyNativeGitBundle(input.bytes, { ...config.native, timeoutMs: config.live.remaining() });
  if (approval !== null) await approval.check(input.bytes);
  config.live.check();
  const storage = await realpath(config.storage);
  // Do not silently follow a caller's final storage symlink.
  const named = await directory(config.storage), storageStat = await directory(storage);
  if (!sameNode(named, storageStat)) throw importError('native_import_directory_changed');
  const parent = await realpath(dirname(resolve(config.recovery))); await directory(parent);
  const recovery = join(parent, basename(resolve(config.recovery)));
  const contains = (a, b) => { const r = relative(a, b); return r === '' || (!r.startsWith(`..${sep}`) && r !== '..' && !isAbsolute(r)); };
  if (contains(storage, recovery) || contains(recovery, storage)) throw importError('native_import_recovery_overlaps_storage');
  const intent = { type: 'native-source-import-intent', schema_version: 1, storage, storage_identity: identity(storageStat),
    tenant_id: config.tenant, repository_id: config.repository, principal_id: config.principal, object_format: config.format,
    idempotency_key: `fg-source-import-${randomBytes(32).toString('hex')}`, key_digest: null,
    artifact: { bytes: input.bytes.length, sha256: hash(input.bytes) }, expectations: config.native.expected,
    content: { declared_refs: verified.reference_count, pack_bytes: verified.pack_bytes } };
  if (approval !== null) { intent.schema_version = 2; intent.approval = approval.binding; }
  const original = await lookup(intent, config);
  if (original.outcome !== 'unknown_pending' || original.node_closed !== true) throw importError('native_import_identity_already_decided');
  intent.key_digest = original.key_digest; validateIntent(intent);
  const encoded = Buffer.from(JSON.stringify(intent) + '\n');
  if (encoded.length > INTENT_MAX) throw importError('native_import_intent_limit');
  config.live.check(); await mkdir(recovery, { mode: 0o700 });
  // Never clean or replace a failed preparation: a later command may diagnose
  // it, but it cannot treat a torn directory as permission to generate a new key.
  try {
    await directory(recovery, null, true);
    await writeNew(join(recovery, SNAPSHOT), input.bytes, config.live);
    if (approval !== null) {
      for (const [name, bytes] of approval.files) await writeNew(join(recovery, name), bytes, config.live);
    }
    await writeNew(join(recovery, INTENT), encoded, config.live);
    await syncDirectory(recovery); await syncDirectory(parent); config.live.check();
    const saved = await loadRecovery(recovery, { ...config, intentSha256: hash(encoded) });
    const snapshot = await readFile(join(recovery, SNAPSHOT), INPUT_MAX, config.live, true);
    return await submit(saved, config, snapshot.bytes, snapshot.stat);
  } catch (error) {
    error.details ??= { recovery_directory: recovery, intent_sha256: hash(encoded), outcome: 'not_submitted',
      submission_attempted: false, recovery_material_retained: true, automatic_retry: false };
    throw error;
  }
}

/** Read-only canonical outcome observation. No source file, native verification,
 * admission, mutation, local acknowledgement or new key is created here.
 */
export async function readNativeImportOutcome(path, value) {
  const config = options(value, true), saved = await loadRecovery(path, config);
  const found = await lookup(saved.intent, config);
  await guardRecovery(saved, config);
  return report(saved.intent, saved.recovery, saved.intentHash, found, false);
}

/** Explicit retry of the SAME immutable request. A terminal outcome wins before
 * reading source bytes. Concurrent retries share native idempotency; there is no
 * second publication table or local lock whose loss can authorize a new request.
 */
export async function retryNativeSourceImport(path, value) {
  const config = options(value, true), saved = await loadRecovery(path, config);
  const found = await lookup(saved.intent, config);
  if (found.outcome !== 'unknown_pending') {
    await guardRecovery(saved, config);
    return report(saved.intent, saved.recovery, saved.intentHash, found, false);
  }
  if (found.node_closed !== true) throw importError('native_import_preflight_cleanup_failed');
  const snapshot = await readFile(join(saved.recovery, SNAPSHOT), INPUT_MAX, config.live, true);
  if (snapshot.bytes.length !== saved.intent.artifact.bytes || hash(snapshot.bytes) !== saved.intent.artifact.sha256) throw importError('native_import_snapshot_mismatch');
  if (saved.intent.schema_version === 2) {
    const approval = await retainedApproval(saved, config);
    await approval.check(snapshot.bytes);
  }
  const verified = await verifyNativeGitBundle(snapshot.bytes, nativeOptions(saved.intent, config));
  if (verified.reference_count !== saved.intent.content.declared_refs || verified.pack_bytes !== saved.intent.content.pack_bytes) throw importError('native_import_verification_changed');
  return await submit(saved, config, snapshot.bytes, snapshot.stat);
}

async function retainedApproval(saved, config) {
  return recoverImportApproval(saved.intent.approval,
    async (name, maximum) => (await readFile(join(saved.recovery, name), maximum, config.live, true)).bytes, config.live);
}
