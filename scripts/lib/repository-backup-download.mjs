// Trusted-local acquisition of ONE independently approved checkpoint over HTTPS.
// Remote names, headers and TLS authenticate neither repository state nor a capsule.
// Byte publication is delegated to the existing create-only replica publisher.
import { Agent, request } from 'node:https';
import { constants } from 'node:fs';
import { open, lstat, realpath, unlink, mkdtemp, rmdir } from 'node:fs/promises';
import { resolve, join, dirname, isAbsolute, sep } from 'node:path';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, readBackupControl } from './repository-backup-io.mjs';
import { backupDecimal, backupPolicy, verifyRepositoryBackupApproval } from './repository-backup-approval.mjs';
import { replicateRepositoryBackup, repositoryBackupReplicationCheckpoint } from './repository-backup-replication.mjs';
import { backupLfsSha256 } from './repository-backup-lfs.mjs';

export const MAX_DOWNLOAD_SOURCES = 16;
export const MAX_PAIRED_DOWNLOAD_REQUESTS = MAX_DOWNLOAD_SOURCES * 2;
const CHUNK = 65536, MAX_HEADERS = 16384;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw backupError(code); };
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
// These errors are created only inside network ownership. Observer/disk errors
// never become eligible for mirror failover just by copying an error code.
const unavailable = new WeakSet();
function remoteError(code, retry = false, status) {
  const error = backupError(code);
  if (retry) unavailable.add(error);
  if (status !== undefined) error.http_status = status;
  return error;
}
const NETWORK = new Set(['ECONNRESET', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EPIPE', 'ETIMEDOUT']);
const TLS = new Set(['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_TLS_CERT_ALTNAME_INVALID']);
function networkFailure(error) {
  // Never retain a native Error.cause/request/socket: it can contain signed URLs.
  if (TLS.has(error?.code) || String(error?.code).startsWith('ERR_SSL')) return remoteError('backup_download_tls');
  return remoteError('backup_download_transport', NETWORK.has(error?.code));
}
export function repositoryBackupDownloadOptions(raw) {
  const allowed = ['sources', 'approval', 'trustKey', 'policy', 'destination', 'caFile', 'checkpoint',
    'maximumBytes', 'maximumTotalBytes', 'timeoutMs', 'signal', 'now', 'onProgress',
    'lfsSources', 'expectedLfsSha256', 'expectedLfsBytes', 'fg', 'verificationInstance', 'trustedLocal', 'maximumRequests'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
    || Object.keys(raw).some(k => !allowed.includes(k))) fail('backup_invalid_download_options');
  // Caller order is the explicit mirror preference. Snapshot every URL before await.
  // URLs may contain bearer capabilities: no URL, hostname, query or credentials
  // enter reports, errors or progress. A digest identifies an attempted location.
  const urls = values => {
    if (!Array.isArray(values) || !values.length || values.length > MAX_DOWNLOAD_SOURCES) fail('backup_download_source_limit');
    const seen = new Set(); let size = 0;
    return Array.from(values, value => {
      if (typeof value !== 'string' || !value || value.length > 8192 || /[\s\u0000-\u001f\u007f]/u.test(value)) fail('backup_download_invalid_url');
      let url; try { url = new URL(value); } catch { fail('backup_download_invalid_url'); }
      if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.hash) fail('backup_download_invalid_url');
      size += Buffer.byteLength(url.href);
      if (size > 65536 || seen.has(url.href)) fail('backup_download_source_limit');
      seen.add(url.href); return Object.freeze({ url: url.href, source_sha256: hash(url.href) });
    });
  };
  const sources = urls(raw.sources);
  const pairFields = ['lfsSources', 'expectedLfsSha256', 'expectedLfsBytes', 'fg', 'verificationInstance', 'trustedLocal'];
  const paired = pairFields.some(name => raw[name] !== undefined);
  let companion;
  if (paired) {
    if (pairFields.some(name => raw[name] === undefined)) fail('backup_lfs_pair_required');
    if (raw.trustedLocal !== true) fail('backup_explicit_local_operation_required');
    const fg = backupPath(raw.fg);
    if (!isAbsolute(fg)) fail('backup_absolute_fg_required');
    const lfsSources = urls(raw.lfsSources);
    const maximumRequests = raw.maximumRequests ?? sources.length + lfsSources.length;
    if (!Number.isSafeInteger(maximumRequests) || maximumRequests < 1 || maximumRequests > MAX_PAIRED_DOWNLOAD_REQUESTS) fail('backup_download_request_limit');
    companion = { lfsSources: Object.freeze(lfsSources), expectedLfsSha256: backupLfsSha256(raw.expectedLfsSha256),
      expectedLfsBytes: backupDecimal(raw.expectedLfsBytes, BigInt(BACKUP_LIMITS.maximumArchiveBytes)),
      fg, verificationInstance: backupDecimal(raw.verificationInstance, 9223372036854775807n), trustedLocal: true, maximumRequests };
  } else if (raw.maximumRequests !== undefined) fail('backup_download_inapplicable_request_limit');
  const paths = Object.fromEntries(['approval', 'trustKey', 'destination'].map(k => [k, resolve(backupPath(raw[k]))]));
  if (raw.caFile !== undefined) paths.caFile = resolve(backupPath(raw.caFile));
  for (const path of Object.values(paths)) backupPath(path);
  const policy = backupPolicy(raw.policy), checkpoint = repositoryBackupReplicationCheckpoint(raw.checkpoint);
  const live = backupLifetime({ maximumBytes: raw.maximumBytes, timeoutMs: raw.timeoutMs,
    signal: raw.signal, now: raw.now, onProgress: raw.onProgress });
  const maximumTotalBytes = raw.maximumTotalBytes ?? (sources.length + 3 + (companion ? companion.lfsSources.length + 2 : 0)) * live.maximumBytes;
  if (!Number.isSafeInteger(maximumTotalBytes) || maximumTotalBytes < 1
    || maximumTotalBytes > (companion ? MAX_PAIRED_DOWNLOAD_REQUESTS + 5 : MAX_DOWNLOAD_SOURCES + 3) * BACKUP_LIMITS.maximumArchiveBytes) fail('backup_download_read_limit');
  return Object.freeze({ ...paths, policy, checkpoint, sources: Object.freeze(sources), maximumTotalBytes,
    maximumBytes: live.maximumBytes, timeoutMs: raw.timeoutMs, signal: live.signal, now: raw.now, onProgress: live.onProgress, ...companion });
}

async function take(response, length) {
  for (;;) {
    if (response.errored) throw networkFailure(response.errored);
    // Read what is available, not an unsatisfied full chunk: reattaching
    // readable while smaller buffered data remains otherwise spins the loop.
    const bytes = response.read(Math.max(1, Math.min(length, response.readableLength)));
    if (bytes !== null) return bytes;
    if (response.readableEnded) return null;
    if (response.destroyed) throw remoteError('backup_download_truncated', true);
    await new Promise((resolve, reject) => {
      const done = () => { clean(); resolve(); };
      const failed = error => { clean(); reject(networkFailure(error)); };
      const clean = () => {
        for (const event of ['readable', 'end', 'close']) response.removeListener(event, done);
        response.removeListener('error', failed);
      };
      for (const event of ['readable', 'end', 'close']) response.once(event, done);
      response.once('error', failed);
    });
  }
}

// One fresh agent per attempt; never use shared cookies, proxies or pooled TLS
// sessions. Destroy and await the owned request/socket before failover/return.
async function transfer(source, ca, expected, file, gate, live, consume, progress) {
  const agent = new Agent({ keepAlive: false, maxSockets: 1, maxCachedSessions: 0 });
  let req, response, socket, socketClosed = Promise.resolve(), requestClosed = Promise.resolve(), stopReason;
  const stop = error => { stopReason ??= error; response?.destroy(); req?.destroy(); socket?.destroy(); };
  const cancelled = () => stop(backupError('backup_cancelled'));
  let timer;
  try {
    gate();
    const incoming = new Promise((resolve, reject) => {
      try { req = request(source.url, { agent, method: 'GET', rejectUnauthorized: true, minVersion: 'TLSv1.2',
        ...(ca === undefined ? {} : { ca }), maxHeaderSize: MAX_HEADERS, highWaterMark: CHUNK,
        headers: { accept: 'application/octet-stream', 'accept-encoding': 'identity', connection: 'close',
          'user-agent': 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)' } }); }
      catch (error) { reject(networkFailure(error)); return; }
      requestClosed = new Promise(resolve => req.once('close', resolve));
      req.once('socket', owned => {
        socket = owned; socketClosed = new Promise(resolve => owned.once('close', resolve));
        if (stopReason) owned.destroy();
      });
      req.on('error', error => reject(stopReason ?? networkFailure(error)));
      req.once('close', () => { if (!response) reject(stopReason ?? remoteError('backup_download_truncated', true)); });
      let information = 0;
      req.on('information', () => { if (++information > 8) stop(remoteError('backup_download_headers')); });
      req.on('upgrade', (_, upgraded) => { upgraded.destroy(); stop(remoteError('backup_download_upgrade')); reject(stopReason); });
      req.once('response', value => {
        response = value;
        // A reset can arrive during an awaited file write or trusted observer,
        // not just during take(). Keep it observed; take() checks .errored.
        value.on('error', () => {}); resolve(value);
      });
      req.end();
    });
    timer = setTimeout(() => stop(backupError('backup_deadline')), live.remaining());
    live.signal?.addEventListener('abort', cancelled, { once: true });
    if (live.signal?.aborted) cancelled();
    const res = await incoming;
    gate();
    if (res.statusCode >= 300 && res.statusCode < 400) throw remoteError('backup_download_redirect_refused');
    if (res.statusCode !== 200) throw remoteError('backup_download_http_status',
      [404, 410, 429, 500, 502, 503, 504].includes(res.statusCode), res.statusCode);
    if (res.rawHeaders.length > 128) throw remoteError('backup_download_headers');
    if (res.headers['content-encoding'] !== undefined && res.headers['content-encoding'] !== 'identity') throw remoteError('backup_download_encoding');
    if (res.headers['transfer-encoding'] !== undefined && res.headers['transfer-encoding'] !== 'chunked') throw remoteError('backup_download_encoding');
    if (res.headers['content-range'] !== undefined) throw remoteError('backup_download_partial_response');
    if (res.headers['content-length'] !== undefined && res.headers['content-length'] !== expected.bytes) throw remoteError('backup_download_length', true);
    const digest = createHash('sha256'); let offset = 0;
    while (offset < Number(expected.bytes)) {
      gate(); const bytes = await take(res, Math.min(CHUNK, Number(expected.bytes) - offset));
      gate(); if (!bytes) throw remoteError('backup_download_truncated', true);
      consume(bytes.length); digest.update(bytes);
      let at = 0;
      while (at < bytes.length) {
        gate(); const { bytesWritten } = await file.write(bytes, at, bytes.length - at, offset + at);
        if (!bytesWritten) fail('backup_download_write'); at += bytesWritten;
      }
      offset += bytes.length; await progress(offset); gate();
    }
    // A single bounded EOF probe per attempt is separate from payload accounting.
    if (await take(res, 1)) throw remoteError('backup_download_length', true);
    if (!res.complete) throw remoteError('backup_download_truncated', true);
    if (res.rawTrailers.length) throw remoteError('backup_download_trailers');
    gate();
    if (digest.digest('hex') !== expected.sha256) throw remoteError('backup_download_digest', true);
    await file.sync(); gate();
  } catch (error) {
    throw stopReason ?? error;
  } finally {
    clearTimeout(timer); live.signal?.removeEventListener('abort', cancelled);
    response?.destroy(); req?.destroy(); socket?.destroy(); agent.destroy();
    await requestClosed; await socketClosed;
  }
}

/** URLs are explicit operator inputs, never learned from candidate/remote data.
 * TLS verifies transport identity; only independent approval bytes select content.
 * No redirect, range resume, automatic signing, native restore or source deletion.
 */
export async function downloadRepositoryBackup(raw) {
  const options = repositoryBackupDownloadOptions(raw);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs,
    signal: options.signal, now: options.now });
  if (options.lfsSources) return downloadRepositoryBackupPair(options, live);
  let approved, checkpoint, parent, parentIdentity, canonical, temporary, file, fileIdentity, completed, problem;
  let state = 'not_started', total = 0, network = 0, publisherReads = 0, active = null;
  const attempts = [];
  const gate = () => { live.check(); approved?.checkCurrent(); };
  const budget = bytes => { if (bytes > options.maximumTotalBytes - total) fail('backup_download_read_budget'); };
  const progress = async (phase, details = {}) => {
    await options.onProgress(Object.freeze({ phase, ...details, total_payload_bytes_read: String(total) })); gate();
  };
  const accounting = () => Object.freeze({ total_payload_bytes_read: String(total), network_payload_bytes_read: String(network),
    publication_payload_bytes_read: String(publisherReads), total_payload_byte_budget: String(options.maximumTotalBytes), maximum_read_bytes: CHUNK });
  function privateDirectory(stat) {
    if (!stat.isDirectory() || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('backup_download_private_directory');
  }
  async function checkParent() {
    const opened = await parent.stat({ bigint: true }), named = await lstat(options.destination, { bigint: true });
    privateDirectory(opened); privateDirectory(named);
    if (!same(opened, parentIdentity) || !same(named, opened) || await realpath(options.destination) !== canonical) fail('backup_download_directory_changed');
  }
  async function checkTemporary() {
    await checkParent();
    const named = await lstat(temporary, { bigint: true }), opened = await file.stat({ bigint: true });
    if (!named.isFile() || !same(named, fileIdentity) || !same(opened, fileIdentity)
      || named.uid !== BigInt(process.getuid()) || (named.mode & 0o077n) || named.nlink !== 1n) fail('backup_download_temporary_changed');
  }
  try {
    if ([constants.O_NOFOLLOW, constants.O_NONBLOCK, constants.O_DIRECTORY].some(v => v === undefined)
      || typeof process.getuid !== 'function') fail('backup_unsupported_filesystem');
    const envelope = await readBackupControl(options.approval, BACKUP_LIMITS.envelopeBytes, live);
    const key = await readBackupControl(options.trustKey, BACKUP_LIMITS.keyBytes, live);
    approved = await verifyRepositoryBackupApproval(envelope, key, options.policy, {
      maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal,
      ...(options.now === undefined ? {} : { now: options.now }) });
    checkpoint = Object.freeze({ approval_sha256: hash(envelope), trusted_key_id: approved.authentication.trusted_key_id });
    if (options.checkpoint && (checkpoint.approval_sha256 !== options.checkpoint.approval_sha256
      || checkpoint.trusted_key_id !== options.checkpoint.trusted_key_id)) fail('backup_download_checkpoint_mismatch');
    const artifact = approved.authentication.statement.artifact, length = Number(artifact.bytes);
    let ca;
    if (options.caFile) {
      ca = await readBackupControl(options.caFile, BACKUP_LIMITS.envelopeBytes, live);
      // One explicitly chosen trust anchor; no remote learning or insecure mode.
      try {
        const parsed = new X509Certificate(ca);
        if (!parsed.ca || ca.some(byte => byte > 127)
          || ca.toString('ascii').replace(/\r\n/g, '\n').trim() !== parsed.toString().trim()) fail('backup_download_invalid_ca');
      }
      catch { fail('backup_download_invalid_ca'); }
    }
    privateDirectory(await lstat(options.destination, { bigint: true }));
    canonical = await realpath(options.destination);
    parent = await open(canonical, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    parentIdentity = await parent.stat({ bigint: true }); await checkParent(); gate();
    // Reserve one complete source AND the publisher's three local payload scans
    // before creating scratch or connecting. Failed mirrors share this budget.
    budget(length * 4);
    await progress('checkpoint_pinned', { checkpoint }); await checkParent(); gate();
    temporary = join(canonical, `.fg-backup-download-${randomBytes(16).toString('hex')}.tmp`);
    file = await open(temporary, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    fileIdentity = await file.stat({ bigint: true }); state = 'downloading';
    let found = false;
    for (const [index, source] of options.sources.entries()) {
      active = source.source_sha256; budget(length * 4); gate(); await checkTemporary();
      await file.truncate(0); let bytes = 0;
      await progress('source_started', { source_index: index + 1, source_sha256: active }); await checkTemporary(); gate();
      try {
        await transfer(source, ca, artifact, file, gate, live,
          count => { budget(count); total += count; network += count; bytes += count; },
          offset => progress('download', { source_index: index + 1, source_sha256: active, bytes_read: offset }));
        await checkTemporary(); gate();
        attempts.push(Object.freeze({ source_sha256: active, outcome: 'authenticated', bytes_read: String(bytes) })); found = true; break;
      } catch (error) {
        // Trusted callbacks and local writes never qualify for remote failover.
        if (!unavailable.has(error)) throw error;
        gate(); attempts.push(Object.freeze({ source_sha256: active, outcome: 'unavailable', code: error.code, bytes_read: String(bytes),
          ...(error.http_status === undefined ? {} : { http_status: error.http_status }) }));
        await progress('source_unavailable', { source_index: index + 1, source_sha256: active, code: error.code });
      }
    }
    if (!found) fail('backup_download_no_source');
    state = 'verified_download';
    await progress('download_verified'); await checkTemporary(); gate();
    state = 'publication_submitted';
    completed = await replicateRepositoryBackup({ candidates: [{ input: temporary, approval: options.approval }],
      trustKey: options.trustKey, policy: options.policy, destination: canonical, checkpoint,
      maximumBytes: live.maximumBytes, maximumTotalBytes: Math.min(options.maximumTotalBytes - total, BACKUP_LIMITS.maximumArchiveBytes * 4),
      timeoutMs: live.remaining(), signal: live.signal, ...(options.now === undefined ? {} : { now: options.now }),
      onProgress: async event => {
        const count = Number(event.total_payload_bytes_read), delta = count - publisherReads;
        if (!Number.isSafeInteger(count) || delta < 0) fail('backup_download_invalid_accounting');
        budget(delta); publisherReads = count; total += delta;
        await progress('publication', { event }); await checkTemporary();
      } });
    // No expiry/cancellation gate after the publisher has confirmed completion.
    state = 'complete';
    return Object.freeze({ type: 'repository_backup_download', schema_version: 1, state,
      candidate: completed.candidate, checkpoint, authentication: approved.authentication,
      source_attempts: Object.freeze(attempts), publication: completed, streaming: accounting(),
      native_content_verified: false, newest_checkpoint_verified: false, complete_capsule_verified: false });
  } catch (error) {
    problem = error instanceof Error ? error : backupError('backup_download_observer_failed');
    // A publisher may charge a read before a subsequent local write fails and
    // before it can emit progress. Reconcile its final bounded accounting.
    if (state === 'publication_submitted' && problem.streaming) {
      const count = Number(problem.streaming.total_payload_bytes_read);
      if (Number.isSafeInteger(count) && count >= publisherReads
        && count - publisherReads <= options.maximumTotalBytes - total) {
        total += count - publisherReads; publisherReads = count;
      }
    }
    problem.download_state = state; problem.checkpoint = checkpoint ?? null;
    problem.source_attempts = Object.freeze(attempts.slice()); problem.active_source_sha256 = active;
    problem.download_streaming = accounting(); throw problem;
  } finally {
    let cleanup;
    try { if (fileIdentity) { await checkTemporary(); await unlink(temporary); await parent.sync(); } }
    catch (error) { cleanup = error; }
    for (const owned of [file, parent]) { try { await owned?.close(); } catch (error) { cleanup ??= error; } }
    if (cleanup) {
      if (problem) { problem.download_cleanup_error = 'backup_download_cleanup_failed'; problem.retained_download = temporary ?? null; }
      else { cleanup.download_state = state; cleanup.completed_result = completed; cleanup.retained_download = temporary ?? null; throw cleanup; }
    }
  }
}

// Paired acquisition deliberately never enters the source-only publication
// path. Both originals stay in an independent private directory until the
// existing signed native verifier and paired replica publisher accept them.
async function downloadRepositoryBackupPair(options, live) {
  const fileFields = ['dev', 'ino', 'size', 'mode', 'uid', 'nlink', 'mtimeNs', 'ctimeNs'];
  const stages = [], sourceAttempts = [], lfsAttempts = [];
  let approved, checkpoint, canonical, destination, destinationIdentity;
  let quarantine, directory, directoryIdentity, completed, problem;
  let state = 'not_started', total = 0, network = 0, publisherReads = 0, requests = 0;
  let active = null, activeComponent = null;
  const gate = () => { live.check(); approved?.checkCurrent(); };
  const budget = bytes => { if (bytes > options.maximumTotalBytes - total) fail('backup_download_read_budget'); };
  const requestBudget = count => { if (count > options.maximumRequests - requests) fail('backup_download_request_budget'); };
  const accounting = () => Object.freeze({ total_payload_bytes_read: String(total), network_payload_bytes_read: String(network),
    publication_payload_bytes_read: String(publisherReads), total_payload_byte_budget: String(options.maximumTotalBytes), maximum_read_bytes: CHUNK,
    request_attempts: requests, maximum_requests: options.maximumRequests,
    byte_budget_scope: 'https_acquisition_and_replica_publication', native_preflight_metered: false,
    native_preflight_maximum_archive_bytes: String(live.maximumBytes) });
  function privateDirectory(stat) {
    if (!stat.isDirectory() || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('backup_download_private_directory');
  }
  async function checkDestination() {
    const named = await lstat(options.destination, { bigint: true }), opened = await destination.stat({ bigint: true });
    privateDirectory(named); privateDirectory(opened);
    if (!same(opened, destinationIdentity) || !same(named, opened) || await realpath(options.destination) !== canonical) fail('backup_download_directory_changed');
  }
  async function checkQuarantine() {
    const named = await lstat(quarantine, { bigint: true }), opened = await directory.stat({ bigint: true });
    privateDirectory(named); privateDirectory(opened);
    if (!same(named, directoryIdentity) || !same(opened, directoryIdentity) || await realpath(quarantine) !== quarantine) fail('backup_download_quarantine_changed');
  }
  async function checkStages(contents = true) {
    await checkQuarantine();
    for (const stage of stages) {
      const named = await lstat(stage.path, { bigint: true }), opened = await stage.file.stat({ bigint: true });
      if (!stage.identity || !named.isFile() || !same(named, stage.identity) || !same(opened, stage.identity)
        || named.uid !== BigInt(process.getuid()) || (named.mode & 0o077n) || named.nlink !== 1n
        || (contents && stage.sealed && fileFields.some(key => named[key] !== stage.sealed[key] || opened[key] !== stage.sealed[key]))) {
        fail('backup_download_temporary_changed');
      }
    }
  }
  const progress = async (phase, details = {}) => {
    await options.onProgress(Object.freeze({ phase, ...details, total_payload_bytes_read: String(total), request_attempts: requests }));
    gate();
    if (destination) await checkDestination();
    if (directory) await checkStages();
  };
  async function stage(kind) {
    await checkQuarantine(); gate();
    const path = join(quarantine, kind === 'source' ? 'source.fgbackup' : 'lfs.fglf');
    const file = await open(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const entry = { path, file, identity: null, sealed: null }; stages.push(entry);
    entry.identity = await file.stat({ bigint: true });
    await directory.sync(); await checkStages(); gate(); return entry;
  }
  async function acquire(kind, sources, expected, entry, futureBytes, futureRequests, publicationBytes, ca) {
    const attempts = kind === 'source' ? sourceAttempts : lfsAttempts;
    const length = Number(expected.bytes);
    activeComponent = kind;
    for (const [index, source] of sources.entries()) {
      budget(length + futureBytes + publicationBytes); requestBudget(1 + futureRequests);
      active = source.source_sha256; gate(); await checkStages();
      await entry.file.truncate(0); let bytes = 0;
      await progress('source_started', { component: kind, source_index: index + 1, source_sha256: active });
      requests++;
      try {
        await transfer(source, ca, expected, entry.file, gate, live,
          count => { budget(count); total += count; network += count; bytes += count; },
          offset => progress('download', { component: kind, source_index: index + 1, source_sha256: active, bytes_read: offset }));
        entry.sealed = await entry.file.stat({ bigint: true }); await checkStages(); gate();
        attempts.push(Object.freeze({ source_sha256: active, outcome: 'authenticated', bytes_read: String(bytes) }));
        await progress('component_verified', { component: kind }); return;
      } catch (error) {
        if (!unavailable.has(error)) throw error;
        gate(); attempts.push(Object.freeze({ source_sha256: active, outcome: 'unavailable', code: error.code, bytes_read: String(bytes),
          ...(error.http_status === undefined ? {} : { http_status: error.http_status }) }));
        await progress('source_unavailable', { component: kind, source_index: index + 1, source_sha256: active, code: error.code });
      }
    }
    fail('backup_download_no_source');
  }
  try {
    if ([constants.O_NOFOLLOW, constants.O_NONBLOCK, constants.O_DIRECTORY].some(value => value === undefined)
      || typeof process.getuid !== 'function') fail('backup_unsupported_filesystem');
    const envelope = await readBackupControl(options.approval, BACKUP_LIMITS.envelopeBytes, live);
    const key = await readBackupControl(options.trustKey, BACKUP_LIMITS.keyBytes, live);
    approved = await verifyRepositoryBackupApproval(envelope, key, options.policy, {
      maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal,
      ...(options.now === undefined ? {} : { now: options.now }) });
    checkpoint = Object.freeze({ approval_sha256: hash(envelope), trusted_key_id: approved.authentication.trusted_key_id });
    if (options.checkpoint && (checkpoint.approval_sha256 !== options.checkpoint.approval_sha256
      || checkpoint.trusted_key_id !== options.checkpoint.trusted_key_id)) fail('backup_download_checkpoint_mismatch');
    const artifact = approved.authentication.statement.artifact;
    const lfs = Object.freeze({ sha256: options.expectedLfsSha256, bytes: options.expectedLfsBytes });
    const sourceBytes = Number(artifact.bytes), lfsBytes = Number(lfs.bytes);
    if (lfsBytes > live.maximumBytes) fail('backup_download_lfs_archive_limit');
    let ca;
    if (options.caFile) {
      ca = await readBackupControl(options.caFile, BACKUP_LIMITS.envelopeBytes, live);
      try {
        const parsed = new X509Certificate(ca);
        if (!parsed.ca || ca.some(byte => byte > 127)
          || ca.toString('ascii').replace(/\r\n/g, '\n').trim() !== parsed.toString().trim()) fail('backup_download_invalid_ca');
      } catch { fail('backup_download_invalid_ca'); }
    }
    privateDirectory(await lstat(options.destination, { bigint: true }));
    canonical = await realpath(options.destination);
    destination = await open(canonical, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    destinationIdentity = await destination.stat({ bigint: true }); await checkDestination(); gate();
    // The paired publisher forbids its read inputs inside its writable output
    // directory. Check existing controls before acquisition; staged bodies use
    // an exclusively owned sibling directory, never the final replica names.
    for (const path of [options.approval, options.trustKey, options.fg, options.caFile].filter(Boolean)) {
      gate(); const physical = await realpath(path);
      if (physical === canonical || physical.startsWith(canonical + sep)) fail('backup_lfs_separate_path_required');
    }
    const publicationBytes = 3 * sourceBytes + 2 * lfsBytes;
    budget(sourceBytes + lfsBytes + publicationBytes); requestBudget(2);
    await progress('checkpoint_pinned', { checkpoint });
    quarantine = await mkdtemp(join(dirname(canonical), '.fg-backup-download-pair-'));
    directory = await open(quarantine, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    directoryIdentity = await directory.stat({ bigint: true }); await checkQuarantine(); gate();
    state = 'downloading';
    const source = await stage('source');
    await acquire('source', options.sources, artifact, source, lfsBytes, 1, publicationBytes, ca);
    const companion = await stage('lfs');
    await acquire('lfs', options.lfsSources, lfs, companion, 0, 0, publicationBytes, ca);
    state = 'verified_download';
    await progress('download_verified');
    state = 'publication_submitted';
    completed = await replicateRepositoryBackup({ candidates: [{ input: source.path, approval: options.approval }],
      trustKey: options.trustKey, policy: options.policy, destination: canonical, checkpoint,
      lfsArchive: companion.path, expectedLfsSha256: lfs.sha256, fg: options.fg,
      verificationInstance: options.verificationInstance, trustedLocal: true,
      maximumBytes: live.maximumBytes, maximumTotalBytes: Math.min(options.maximumTotalBytes - total, BACKUP_LIMITS.maximumArchiveBytes * 8),
      timeoutMs: live.remaining(), signal: live.signal, ...(options.now === undefined ? {} : { now: options.now }),
      onProgress: async event => {
        const count = Number(event.total_payload_bytes_read), delta = count - publisherReads;
        if (!Number.isSafeInteger(count) || delta < 0) fail('backup_download_invalid_accounting');
        budget(delta); publisherReads = count; total += delta;
        await progress('publication', { event });
      } });
    // Paired native verification and durable replica publication have completed.
    // A late cancellation cannot revoke the already published local result.
    state = 'complete';
    return Object.freeze({ type: 'repository_backup_download', schema_version: 1, state,
      candidate: completed.candidate, checkpoint, authentication: approved.authentication,
      source_attempts: Object.freeze(sourceAttempts), lfs_source_attempts: Object.freeze(lfsAttempts),
      publication: completed, streaming: accounting(), native_content_verified: true,
      lfs_archive: completed.lfs_archive, lfs_companion: completed.lfs_companion,
      lfs_companion_signed: false, lfs_payloads_verified: true,
      newest_checkpoint_verified: false, complete_capsule_verified: false });
  } catch (caught) {
    problem = caught instanceof Error ? caught : backupError('backup_download_observer_failed');
    if (state === 'publication_submitted' && problem.streaming) {
      const count = Number(problem.streaming.total_payload_bytes_read);
      if (Number.isSafeInteger(count) && count >= publisherReads && count - publisherReads <= options.maximumTotalBytes - total) {
        total += count - publisherReads; publisherReads = count;
      }
    }
    problem.download_state = state; problem.checkpoint = checkpoint ?? null;
    problem.source_attempts = Object.freeze(sourceAttempts.slice()); problem.lfs_source_attempts = Object.freeze(lfsAttempts.slice());
    problem.active_source_sha256 = active; problem.active_component = activeComponent;
    problem.download_streaming = accounting(); throw problem;
  } finally {
    let cleanup;
    // Containment uncertainty is not permission to unlink files a native child
    // may still read. Its approval/key scratch has a separate retaining owner.
    const retain = problem?.code === 'native_import_containment_failed';
    if (retain && quarantine) {
      problem.retained_download = quarantine;
      problem.retained_downloads = Object.freeze(stages.map(entry => entry.path));
      problem.download_quarantine_retained = true;
    } else if (directoryIdentity) {
      try {
        await checkStages(false);
        for (const entry of stages) await unlink(entry.path);
        await directory.sync(); await checkQuarantine(); await rmdir(quarantine);
      } catch (error) { cleanup = error; }
    } else if (quarantine) {
      // Creation succeeded but descriptor ownership could not be pinned. Keep
      // the path visible for recovery; never delete a directory by name alone.
      cleanup = backupError('backup_download_cleanup_failed');
    }
    for (const handle of [...stages.map(entry => entry.file), directory, destination]) {
      try { await handle?.close(); } catch (error) { cleanup ??= error; }
    }
    if (cleanup) {
      if (problem) { problem.download_cleanup_error = 'backup_download_cleanup_failed'; problem.retained_download = quarantine ?? null; }
      else { cleanup.download_state = state; cleanup.completed_result = completed; cleanup.retained_download = quarantine ?? null; throw cleanup; }
    }
  }
}
