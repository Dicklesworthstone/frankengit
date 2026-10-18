// Derived chunk hints for ORIGINAL signed source-backup bytes. Not a Git/archive
// decoder, erasure code, capsule, repository placement or authority publisher.
import { constants } from 'node:fs';
import { open, lstat, realpath, link, unlink } from 'node:fs/promises';
import { resolve, dirname, basename, join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, readBackupControl, exact } from './repository-backup-io.mjs';
import { backupPolicy, verifyRepositoryBackupApproval } from './repository-backup-approval.mjs';

export const BACKUP_CHUNK_BYTES = 4 * 1024 * 1024;
export const MAX_REPAIR_REPLICAS = 64;
const BUFFER_BYTES = 65536, HEADER_BYTES = 56, DIGEST_BYTES = 32;
export const MAX_BACKUP_CHUNK_CATALOG_BYTES = HEADER_BYTES + DIGEST_BYTES
  + (BACKUP_LIMITS.maximumArchiveBytes / BACKUP_CHUNK_BYTES) * DIGEST_BYTES;
const MAGIC = Buffer.from('FGCHNK01');
const fields = ['dev', 'ino', 'size', 'mode', 'uid', 'nlink', 'mtimeNs', 'ctimeNs'];
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const unchanged = (a, b) => fields.every(k => a[k] === b[k]);
const sha = bytes => createHash('sha256').update(bytes).digest();
const fail = code => { throw backupError(code); };
const unavailable = new Set(['ENOENT', 'ENOTDIR', 'ELOOP', 'EACCES', 'EPERM',
  'backup_chunk_source_type', 'backup_chunk_source_changed', 'backup_chunk_short_source']);

function supported() {
  if ([constants.O_NOFOLLOW, constants.O_NONBLOCK, constants.O_DIRECTORY].some(v => v === undefined)
    || typeof process.getuid !== 'function') fail('backup_chunk_unsupported_filesystem');
}
function privateOwner(stat) {
  if (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('backup_chunk_private_parent_required');
}
function optionsFor(raw, operation) {
  const allowed = ['input', 'replicas', 'catalog', 'output', 'approval', 'trustKey', 'policy',
    'maximumBytes', 'maximumReadBytes', 'timeoutMs', 'signal', 'now', 'onProgress', 'checkpoint'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !allowed.includes(k))) fail('backup_invalid_options');
  supported();
  const live = backupLifetime(Object.fromEntries(['maximumBytes', 'timeoutMs', 'signal', 'now', 'onProgress'].map(k => [k, raw[k]])));
  const maximumReadBytes = raw.maximumReadBytes ?? 4 * live.maximumBytes;
  if (!Number.isSafeInteger(maximumReadBytes) || maximumReadBytes < 1
    || maximumReadBytes > (MAX_REPAIR_REPLICAS + 1) * BACKUP_LIMITS.maximumArchiveBytes) fail('backup_chunk_read_limit');
  const path = name => { const value = resolve(backupPath(raw[name])); backupPath(value); return value; };
  const result = { operation, live, maximumReadBytes, output: path('output'), approval: path('approval'),
    trustKey: path('trustKey'), policy: backupPolicy(raw.policy), now: raw.now };
  if (raw.checkpoint !== undefined) {
    const pin = raw.checkpoint;
    if (!exact(pin, ['approval_sha256', 'trusted_key_id'])
      || typeof pin.approval_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(pin.approval_sha256)
      || typeof pin.trusted_key_id !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(pin.trusted_key_id)) fail('backup_chunk_invalid_checkpoint');
    result.checkpoint = Object.freeze({ ...pin });
  }
  if (operation === 'catalog') {
    if (raw.replicas !== undefined || raw.catalog !== undefined) fail('backup_chunk_inapplicable_option');
    result.input = path('input'); result.replicas = [result.input];
  } else {
    if (raw.input !== undefined || !Array.isArray(raw.replicas) || !raw.replicas.length
      || raw.replicas.length > MAX_REPAIR_REPLICAS) fail('backup_chunk_replica_limit');
    result.catalog = path('catalog');
    result.replicas = Array.from(raw.replicas, p => { const value = resolve(backupPath(p)); backupPath(value); return value; }).sort();
    if (new Set(result.replicas).size !== result.replicas.length
      || result.replicas.reduce((n, p) => n + Buffer.byteLength(p), 0) > 256 * 1024) fail('backup_chunk_replica_limit');
  }
  if ([result.approval, result.trustKey, result.catalog, ...result.replicas].includes(result.output)) fail('backup_chunk_separate_output_required');
  return result;
}
// Operator adapters may validate a complete grammar before acquiring a witness.
// This does no I/O and cannot grant or skip signature verification.
export function validateRepositoryBackupChunkOptions(raw, operation) {
  if (!['catalog', 'repair'].includes(operation)) fail('backup_chunk_operation');
  optionsFor(raw, operation);
}
async function authenticated(options) {
  const { live } = options;
  const encoded = await readBackupControl(options.approval, BACKUP_LIMITS.envelopeBytes, live);
  if (options.checkpoint && sha(encoded).toString('hex') !== options.checkpoint.approval_sha256) fail('backup_chunk_approval_changed');
  const key = await readBackupControl(options.trustKey, BACKUP_LIMITS.keyBytes, live);
  const verified = await verifyRepositoryBackupApproval(encoded, key, options.policy, {
    maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal,
    ...(options.now === undefined ? {} : { now: options.now }),
  });
  if (options.checkpoint && verified.authentication.trusted_key_id !== options.checkpoint.trusted_key_id) fail('backup_chunk_signer_changed');
  // Use the REAL clock during later checks; a caller's fixed test clock is
  // explicitly propagated only when supplied. Never freeze production expiry.
  return { encoded, key, verified };
}
function runtime(options, verified) {
  let bytes = 0, reads = 0;
  const check = () => { options.live.check(); verified.checkCurrent(); };
  const requireBytes = count => { check(); if (count > options.maximumReadBytes - bytes) fail('backup_chunk_read_budget'); };
  const progress = async event => {
    check();
    try { await options.live.onProgress(Object.freeze(event)); }
    catch (cause) { const error = backupError('backup_chunk_observer_failed'); error.cause = cause; throw error; }
    check();
  };
  return { check, requireBytes, progress,
    async read(file, buffer, offset, length, position) {
      requireBytes(length);
      const result = await file.read(buffer, offset, length, position);
      bytes += result.bytesRead; reads++; check(); return result.bytesRead;
    },
    counters: () => ({ payload_bytes_read: String(bytes), payload_read_calls: reads,
      maximum_read_bytes: BUFFER_BYTES, payload_read_budget: String(options.maximumReadBytes) }),
  };
}
async function source(path, maximum, check) {
  check(); const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat({ bigint: true });
    if (!stat.isFile() || stat.size < 1n || stat.size > BigInt(maximum)) fail('backup_chunk_source_type');
    const verify = async () => {
      check(); const current = await file.stat({ bigint: true }), named = await lstat(path, { bigint: true });
      if (!named.isFile() || !unchanged(stat, current) || !unchanged(current, named)) fail('backup_chunk_source_changed');
    };
    await verify(); return { file, stat, verify };
  } catch (error) { await file.close(); throw error; }
}
async function fromReplica(action) {
  try { return await action(); }
  catch (cause) {
    if (!unavailable.has(cause.code)) throw cause;
    const error = backupError('backup_chunk_replica_unavailable'); error.cause = cause; throw error;
  }
}
async function writeAll(file, bytes, position) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await file.write(bytes, offset, bytes.length - offset, position + offset);
    if (!bytesWritten) fail('backup_chunk_write_incomplete'); offset += bytesWritten;
  }
}
async function readCatalog(path, check) {
  const opened = await source(path, MAX_BACKUP_CHUNK_CATALOG_BYTES, check);
  try {
    const bytes = Buffer.alloc(Number(opened.stat.size)); let at = 0;
    while (at < bytes.length) {
      check(); const { bytesRead } = await opened.file.read(bytes, at, Math.min(BUFFER_BYTES, bytes.length - at), at);
      if (!bytesRead) fail('backup_chunk_catalog_truncated'); at += bytesRead;
    }
    await opened.verify(); check(); return bytes;
  } finally { await opened.file.close(); }
}
function catalogFor(statement) {
  const size = Number(statement.artifact.bytes), count = Math.ceil(size / BACKUP_CHUNK_BYTES);
  const bytes = Buffer.alloc(HEADER_BYTES + count * DIGEST_BYTES + DIGEST_BYTES);
  MAGIC.copy(bytes); bytes.writeBigUInt64BE(BigInt(size), 8);
  Buffer.from(statement.artifact.sha256, 'hex').copy(bytes, 16);
  bytes.writeUInt32BE(BACKUP_CHUNK_BYTES, 48); bytes.writeUInt32BE(count, 52);
  return bytes;
}
function parseCatalog(bytes, statement) {
  const size = Number(statement.artifact.bytes), count = Math.ceil(size / BACKUP_CHUNK_BYTES);
  if (bytes.length !== HEADER_BYTES + count * DIGEST_BYTES + DIGEST_BYTES
    || !bytes.subarray(0, 8).equals(MAGIC) || bytes.readBigUInt64BE(8) !== BigInt(size)
    || bytes.subarray(16, 48).toString('hex') !== statement.artifact.sha256
    || bytes.readUInt32BE(48) !== BACKUP_CHUNK_BYTES || bytes.readUInt32BE(52) !== count
    || !sha(bytes.subarray(0, -DIGEST_BYTES)).equals(bytes.subarray(-DIGEST_BYTES))) fail('backup_chunk_catalog_mismatch');
  return { size, count, digests: bytes.subarray(HEADER_BYTES, -DIGEST_BYTES) };
}

// One create-only file publication. No destination is overwritten, repaired in
// place or removed, including after visibility followed by a cleanup failure.
async function publish(options, rt, build) {
  const parent = await realpath(dirname(options.output)), destination = join(parent, basename(options.output));
  const directory = await open(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  let file, identity, parentIdentity, temporary, removed = false, state = 'not_created', problem, result;
  const checkParent = async () => {
    const named = await lstat(parent, { bigint: true }), current = await directory.stat({ bigint: true });
    if (!named.isDirectory() || !same(named, parentIdentity) || !same(current, parentIdentity)) fail('backup_chunk_parent_changed');
    privateOwner(named);
  };
  const retire = async () => {
    if (!identity || removed) return;
    await checkParent(); const named = await lstat(temporary, { bigint: true });
    if (!named.isFile() || !same(named, identity)) fail('backup_chunk_temporary_changed');
    await unlink(temporary); removed = true; await directory.sync();
  };
  try {
    parentIdentity = await directory.stat({ bigint: true }); await checkParent(); rt.check();
    try { await lstat(destination); fail('backup_chunk_output_exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    temporary = join(parent, `.fg-backup-chunks-${randomBytes(16).toString('hex')}.tmp`);
    file = await open(temporary, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    identity = await file.stat({ bigint: true }); state = 'staging';
    const built = await build(file); await file.sync(); rt.check();
    const before = await file.stat({ bigint: true }); privateOwner(before);
    if (before.size !== BigInt(built.bytes) || !before.isFile() || before.nlink !== 1n) fail('backup_chunk_readback_mismatch');
    const digest = createHash('sha256'), buffer = Buffer.alloc(BUFFER_BYTES); let at = 0;
    try {
      while (at < built.bytes) {
        rt.check(); const length = Math.min(buffer.length, built.bytes - at);
        // Catalog metadata is separately bounded; payload readback IS charged.
        const got = options.operation === 'repair' ? await rt.read(file, buffer, 0, length, at)
          : (await file.read(buffer, 0, length, at)).bytesRead;
        if (!got) fail('backup_chunk_readback_mismatch'); digest.update(buffer.subarray(0, got)); at += got;
        await rt.progress({ phase: 'readback', bytes_verified: at, total_bytes: built.bytes });
      }
    } finally { buffer.fill(0); }
    if (digest.digest('hex') !== built.sha256) fail('backup_chunk_readback_mismatch');
    if (!unchanged(before, await file.stat({ bigint: true }))) fail('backup_chunk_readback_mismatch');
    await rt.progress({ phase: 'before_publication', bytes: built.bytes });
    await checkParent(); rt.check();
    const named = await lstat(temporary, { bigint: true }), current = await file.stat({ bigint: true });
    if (!unchanged(before, current) || !unchanged(current, named)) fail('backup_chunk_temporary_changed');
    state = 'publication_unknown';
    try { await link(temporary, destination); }
    catch (error) { if (error.code === 'EEXIST') state = 'not_created'; throw error; }
    state = 'visible';
    // Publication already happened. Cleanup has no cancellation/expiry gate.
    await directory.sync(); await retire(); await checkParent();
    const final = await lstat(destination, { bigint: true }), opened = await file.stat({ bigint: true });
    if (!final.isFile() || !same(final, identity) || !unchanged(final, opened) || final.nlink !== 1n) fail('backup_chunk_published_file_changed');
    state = 'complete'; result = { ...built, output: destination, state, streaming: rt.counters() };
  } catch (caught) {
    problem = caught instanceof Error ? caught : backupError('backup_chunk_failed');
    problem.publication_state = state;
    try { await retire(); } catch (error) { problem.cleanup_error = error.code ?? 'backup_chunk_cleanup_failed'; problem.staging_path = temporary; }
  } finally {
    for (const handle of [file, directory]) {
      try { await handle?.close(); } catch (error) {
        if (problem) problem.cleanup_error = error.code ?? 'backup_chunk_close_failed';
        else { problem = error; problem.publication_state = state; problem.completed_result = result; }
      }
    }
  }
  if (problem) throw problem;
  return result;
}

/** Produce bounded, deterministic chunk hints while a complete approved copy is
 * available. The original archive digest, NOT the hints, authenticates output.
 */
export async function catalogRepositoryBackupChunks(raw) {
  const options = optionsFor(raw, 'catalog'), { verified } = await authenticated(options);
  const rt = runtime(options, verified), statement = verified.authentication.statement;
  const size = Number(statement.artifact.bytes); rt.requireBytes(size);
  return publish(options, rt, async output => {
    const input = await source(options.input, size, rt.check), bytes = catalogFor(statement);
    const whole = createHash('sha256'), buffer = Buffer.alloc(BUFFER_BYTES);
    try {
      if (input.stat.size !== BigInt(size)) fail('backup_artifact_mismatch');
      for (let at = 0, chunk = 0; at < size; chunk++) {
        const end = Math.min(size, at + BACKUP_CHUNK_BYTES), digest = createHash('sha256');
        while (at < end) {
          const got = await rt.read(input.file, buffer, 0, Math.min(buffer.length, end - at), at);
          if (!got) fail('backup_chunk_short_source');
          digest.update(buffer.subarray(0, got)); whole.update(buffer.subarray(0, got)); at += got;
          await rt.progress({ phase: 'catalog_scan', bytes_read: at, total_bytes: size });
        }
        digest.digest().copy(bytes, HEADER_BYTES + chunk * DIGEST_BYTES);
      }
      await input.verify();
      if (whole.digest('hex') !== statement.artifact.sha256) fail('backup_artifact_mismatch');
      sha(bytes.subarray(0, -DIGEST_BYTES)).copy(bytes, bytes.length - DIGEST_BYTES);
      await writeAll(output, bytes, 0);
      return { type: 'repository_backup_chunk_catalog', bytes: bytes.length, sha256: sha(bytes).toString('hex'),
        archive: statement.artifact, chunks: Math.ceil(size / BACKUP_CHUNK_BYTES), chunk_bytes: BACKUP_CHUNK_BYTES,
        original_archive_authenticated: true, catalog_is_authority: false, native_content_verified: false };
    } finally { buffer.fill(0); await input.file.close(); }
  });
}

/** Recover one explicitly approved artifact when no complete replica is usable.
 * Unverified fragments stay in an unpublished file. Catalog checks are hints;
 * the final staged full SHA-256 MUST match the ORIGINAL independently verified
 * signature before publication. No source repair, resigning or native restore.
 */
export async function reconstructRepositoryBackup(raw) {
  const options = optionsFor(raw, 'repair'), { verified } = await authenticated(options);
  const rt = runtime(options, verified), statement = verified.authentication.statement;
  const catalog = parseCatalog(await readCatalog(options.catalog, rt.check), statement);
  rt.requireBytes(2 * catalog.size); // At least one source pass plus full readback.
  return publish(options, rt, async output => {
    const sources = [], buffer = Buffer.alloc(BUFFER_BYTES);
    const counts = options.replicas.map(input => ({ input, chunks_used: 0, chunks_rejected: 0, unavailable: null }));
    let primary;
    try {
      for (const path of options.replicas) {
        try { sources.push(await source(path, catalog.size, rt.check)); }
        catch (error) {
          if (!unavailable.has(error.code)) throw error;
          counts[sources.length].unavailable = error.code; sources.push(null);
        }
      }
      for (let chunk = 0; chunk < catalog.count; chunk++) {
        const start = chunk * BACKUP_CHUNK_BYTES, length = Math.min(BACKUP_CHUNK_BYTES, catalog.size - start);
        let found = false;
        for (let index = 0; index < sources.length; index++) {
          const input = sources[index]; if (!input) continue;
          rt.check();
          if (input.stat.size < BigInt(start + length)) { counts[index].chunks_rejected++; continue; }
          // Reserve enough for this attempt, remaining successful chunks and
          // mandatory final readback. Unsuccessful attempts consume real work.
          rt.requireBytes(2 * catalog.size - start);
          let at = start; const digest = createHash('sha256');
          try {
            await fromReplica(() => input.verify());
            while (at < start + length) {
              const got = await fromReplica(async () => {
                const got = await rt.read(input.file, buffer, 0, Math.min(buffer.length, start + length - at), at);
                if (!got) fail('backup_chunk_short_source'); return got;
              });
              digest.update(buffer.subarray(0, got)); await writeAll(output, buffer.subarray(0, got), at); at += got;
              await rt.progress({ phase: 'repair_read', chunk_index: chunk, replica_index: index,
                ...rt.counters() });
            }
            await fromReplica(() => input.verify());
          } catch (error) {
            if (error.code !== 'backup_chunk_replica_unavailable') throw error;
            counts[index].unavailable = error.cause.code; counts[index].chunks_rejected++;
            // An input that changed is never reconsidered later in this run.
            await input.file.close(); sources[index] = null; continue;
          }
          if (!digest.digest().equals(catalog.digests.subarray(chunk * DIGEST_BYTES, (chunk + 1) * DIGEST_BYTES))) {
            counts[index].chunks_rejected++; continue;
          }
          counts[index].chunks_used++; found = true;
          await rt.progress({ phase: 'chunk_reconstructed', chunk_index: chunk, chunks: catalog.count, replica_index: index });
          break;
        }
        if (!found) {
          const error = backupError('backup_chunk_unrecoverable'); error.chunk_index = chunk;
          error.replicas = counts; throw error;
        }
      }
      return { type: 'repository_backup_reconstructed', bytes: catalog.size, sha256: statement.artifact.sha256,
        chunks: catalog.count, chunk_bytes: BACKUP_CHUNK_BYTES, replicas: counts,
        authentication: verified.authentication, original_archive_authenticated: true,
        catalog_is_authority: false, native_content_verified: false, repository_changed: false,
        complete_capsule_restored: false, newest_checkpoint_verified: false };
    } catch (error) { primary = error; throw error; }
    finally {
      buffer.fill(0); let closing;
      for (const input of sources) {
        try { await input?.file.close(); } catch (error) { closing ??= error; }
      }
      if (closing) { if (primary) primary.cleanup_error = closing.code ?? 'backup_chunk_source_close_failed'; else throw closing; }
    }
  });
}
