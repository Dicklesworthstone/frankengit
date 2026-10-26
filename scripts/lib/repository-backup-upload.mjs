// Trusted-local conditional HTTPS publication, NOT canonical repository storage.
// Explicit GET/PUT capabilities; original signed bytes; archive before approval.
import { Agent, request } from 'node:https';
import { open, lstat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve } from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, exact, readBackupControl,
  hashRepositoryBackup } from './repository-backup-io.mjs';
import { backupPolicy, verifyRepositoryBackupApproval } from './repository-backup-approval.mjs';
import { repositoryBackupReplicationCheckpoint } from './repository-backup-replication.mjs';

const CHUNK = 65536;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw backupError(code); };
const fields = ['dev', 'ino', 'size', 'mode', 'uid', 'nlink', 'mtimeNs', 'ctimeNs'];
const same = (a, b) => fields.every(k => a[k] === b[k]);
function endpoint(value) {
  if (typeof value !== 'string' || !value || value.length > 8192 || /[\s\u0000-\u001f\u007f]/u.test(value)) fail('backup_upload_url');
  let url; try { url = new URL(value); } catch { fail('backup_upload_url'); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.hash) fail('backup_upload_url');
  return url;
}
// One parameter-only URL contract shared by direct and durable-job publication.
export function repositoryBackupUploadTarget(raw) {
  if (!exact(raw, ['archive', 'approval'])) fail('backup_upload_target');
  const target = {}; let textBytes = 0;
  for (const kind of ['archive', 'approval']) {
    if (!exact(raw[kind], ['get', 'put'])) fail('backup_upload_target');
    const get = endpoint(raw[kind].get), put = endpoint(raw[kind].put);
    // Signed query strings may differ by method, but the logical object may not.
    if (get.origin !== put.origin || get.pathname !== put.pathname) fail('backup_upload_target_mismatch');
    textBytes += Buffer.byteLength(get.href) + Buffer.byteLength(put.href);
    target[kind] = Object.freeze({ get: get.href, put: put.href });
  }
  if (textBytes > 32768 || new URL(target.archive.get).origin + new URL(target.archive.get).pathname
    === new URL(target.approval.get).origin + new URL(target.approval.get).pathname) fail('backup_upload_target_mismatch');
  return Object.freeze(target);
}
export function repositoryBackupUploadOptions(raw) {
  const allowed = ['input', 'approval', 'trustKey', 'policy', 'target', 'caFile', 'checkpoint',
    'maximumBytes', 'maximumTotalBytes', 'timeoutMs', 'signal', 'now', 'onProgress'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !allowed.includes(k))) fail('backup_upload_options');
  const target = repositoryBackupUploadTarget(raw.target);
  const paths = Object.fromEntries(['input', 'approval', 'trustKey'].map(k => [k, resolve(backupPath(raw[k]))]));
  if (raw.caFile !== undefined) paths.caFile = resolve(backupPath(raw.caFile));
  for (const path of Object.values(paths)) backupPath(path);
  const live = backupLifetime({ maximumBytes: raw.maximumBytes, timeoutMs: raw.timeoutMs, signal: raw.signal,
    now: raw.now, onProgress: raw.onProgress });
  const maximumTotalBytes = raw.maximumTotalBytes ?? 3 * live.maximumBytes;
  if (!Number.isSafeInteger(maximumTotalBytes) || maximumTotalBytes < 1 || maximumTotalBytes > 3 * BACKUP_LIMITS.maximumArchiveBytes) fail('backup_upload_budget');
  return Object.freeze({ ...paths, target: Object.freeze(target), policy: backupPolicy(raw.policy),
    checkpoint: repositoryBackupReplicationCheckpoint(raw.checkpoint), maximumBytes: live.maximumBytes,
    maximumTotalBytes, timeoutMs: raw.timeoutMs, signal: live.signal, now: raw.now, onProgress: live.onProgress });
}
const networkCutoff = new WeakSet();
function transportError() { const error = backupError('backup_upload_transport'); networkCutoff.add(error); return error; }
function earlyResponse() { const error = backupError('backup_upload_early_response'); networkCutoff.add(error); return error; }
async function take(res, length) {
  for (;;) {
    if (res.errored) throw transportError();
    const value = res.read(Math.max(1, Math.min(length, res.readableLength)));
    if (value !== null) return value;
    if (res.readableEnded) return null;
    if (res.destroyed) throw transportError();
    await new Promise((done, reject) => {
      const clean = () => { for (const name of ['readable', 'end', 'close']) res.removeListener(name, ready); res.removeListener('error', error); };
      const ready = () => { clean(); done(); }, error = () => { clean(); reject(transportError()); };
      for (const name of ['readable', 'end', 'close']) res.once(name, ready);
      res.once('error', error);
    });
  }
}
// Own and drain both producer and network. No pooled agent, redirects, ambient
// cookies, arbitrary headers, insecure TLS or automatic retry of a PUT.
async function exchange(url, method, expected, produce, ctx, payload) {
  const agent = new Agent({ keepAlive: false, maxSockets: 1, maxCachedSessions: 0 });
  let req, res, socket, reason, producer, producerError, sent = false;
  let requestClosed = Promise.resolve(), socketClosed = Promise.resolve(), timer, allowUpload;
  const uploadAllowed = new Promise(resolve => { allowUpload = resolve; });
  const stop = error => { reason ??= error; allowUpload(false); res?.destroy(); req?.destroy(); socket?.destroy(); };
  const abort = () => stop(backupError('backup_cancelled'));
  const gate = () => { if (reason) throw reason; ctx.gate(); };
  try {
    gate(); ctx.request();
    const incoming = new Promise((done, reject) => {
      try { req = request(url, { method, agent, rejectUnauthorized: true, minVersion: 'TLSv1.2',
        ...(ctx.ca === undefined ? {} : { ca: ctx.ca }), highWaterMark: CHUNK, maxHeaderSize: 16384,
        headers: { 'accept-encoding': 'identity', connection: 'close',
          ...(method === 'PUT' ? { expect: '100-continue', 'if-none-match': '*', 'content-length': expected.bytes, 'content-type': 'application/octet-stream' } : {}) } }); }
      catch { reject(transportError()); return; }
      requestClosed = new Promise(resolve => req.once('close', resolve));
      req.once('socket', value => { socket = value; socketClosed = new Promise(resolve => value.once('close', resolve)); if (reason) value.destroy(); });
      req.on('error', () => reject(reason ?? transportError()));
      req.once('close', () => { if (!res) reject(reason ?? transportError()); });
      let information = 0;
      req.on('information', () => { if (++information > 8) stop(backupError('backup_upload_headers')); });
      req.on('upgrade', (_, value) => { value.destroy(); stop(backupError('backup_upload_upgrade')); reject(reason); });
      req.once('continue', () => allowUpload(true));
      req.once('response', value => { res = value; allowUpload(false); res.on('error', () => {}); done(value); });
      if (method === 'GET') req.end(); else req.flushHeaders();
    });
    // A stalled peer is bounded even while waiting for a write callback or EOF.
    timer = setTimeout(() => stop(backupError('backup_deadline')), ctx.live.remaining());
    ctx.live.signal?.addEventListener('abort', abort, { once: true });
    if (ctx.live.signal?.aborted) abort();
    if (method === 'PUT') {
      producer = (async () => {
        try {
          // A conditional refusal can arrive without transmitting source bytes.
          // No timer-based fallback: a missing Continue remains deadline-bound.
          if (!await uploadAllowed) return;
          await produce(async bytes => {
            gate();
            if (res) throw earlyResponse();
            await new Promise((done, reject) => {
              const close = () => { clean(); reject(reason ?? transportError()); };
              const clean = () => req.removeListener('close', close);
              req.once('close', close);
              req.write(bytes, error => { clean(); error ? reject(reason ?? transportError()) : done(); });
            });
          }, gate);
          gate(); sent = true; req.end();
        } catch (error) { producerError = error; stop(error); throw error; }
      })();
      producer.catch(() => {});
    }
    const response = await incoming;
    // A received 412 resolves the conditional write even if it cuts off the
    // sender. Only our own network/cutoff errors may yield to that response.
    if (!(method === 'PUT' && response.statusCode === 412 && networkCutoff.has(reason))) gate();
    if (response.rawHeaders.length > 128) fail('backup_upload_headers');
    if ((response.headers['content-encoding'] !== undefined && response.headers['content-encoding'] !== 'identity')
      || (response.headers['transfer-encoding'] !== undefined && response.headers['transfer-encoding'] !== 'chunked')
      || response.headers['content-range'] !== undefined) fail('backup_upload_encoding');
    const status = response.statusCode;
    // Refused conditional writes may arrive before a body is fully sent. Abort
    // and quiesce that producer before checking the concurrent winner by GET.
    if (method === 'PUT' && status === 412) {
      const prior = producerError;
      stop(backupError('backup_upload_precondition'));
      await producer?.catch(() => {});
      if (prior && !networkCutoff.has(prior)) throw prior;
      if (producerError && producerError !== reason && !networkCutoff.has(producerError)) throw producerError;
      ctx.gate(); return { status };
    }
    if (method === 'GET' && status === 404) return { status };
    if (!(method === 'GET' ? status === 200 : [200, 201, 204].includes(status))) {
      const error = backupError('backup_upload_http_status'); error.http_status = status; throw error;
    }
    if (method === 'PUT') {
      // Content-Length permits the peer to respond before req.end(). Finish
      // original-source validation rather than rejecting that valid ordering.
      await producer;
      if (!sent) fail('backup_upload_early_response');
      // PUT replies convey no trusted body. Bound and discard their diagnostic
      // bytes; do not disclose them or mistake them for archive readback.
      let bytes = 0;
      for (;;) { const part = await take(response, Math.min(CHUNK, 16385 - bytes)); gate(); if (!part) break; bytes += part.length; if (bytes > 16384) fail('backup_upload_response_limit'); }
    } else {
      if (response.headers['content-length'] !== undefined && response.headers['content-length'] !== expected.bytes) fail('backup_upload_length');
      const digest = createHash('sha256'); let bytes = 0;
      while (bytes < Number(expected.bytes)) {
        gate(); const part = await take(response, Math.min(CHUNK, Number(expected.bytes) - bytes)); gate();
        if (!part) fail('backup_upload_length');
        if (payload) ctx.charge(part.length, 'received');
        digest.update(part); bytes += part.length;
      }
      if (await take(response, 1)) fail('backup_upload_length');
      if (digest.digest('hex') !== expected.sha256) fail('backup_upload_digest');
    }
    if (!response.complete || response.rawTrailers.length) fail('backup_upload_incomplete_response');
    gate(); return { status };
  } catch (error) { throw reason ?? error; }
  finally {
    clearTimeout(timer); ctx.live.signal?.removeEventListener('abort', abort);
    stop(backupError('backup_upload_closed')); agent.destroy();
    await producer?.catch(() => {}); await requestClosed; await socketClosed;
  }
}

/** Publish to an operator-selected conditional object service, body first.
 * GET/PUT capabilities must name the same objects. The service must implement
 * If-None-Match:*; an HTTP acknowledgment is NOT physical durability evidence.
 */
export async function uploadRepositoryBackup(raw) {
  const options = repositoryBackupUploadOptions(raw);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs, signal: options.signal, now: options.now });
  let approved, file, baseline, completed, problem, state = 'not_started', checkpoint;
  let total = 0, sent = 0, received = 0, local = 0, requests = 0;
  const target = Object.freeze(Object.fromEntries(Object.entries(options.target).map(([kind, pair]) =>
    [kind, Object.freeze({ get_sha256: hash(pair.get), put_sha256: hash(pair.put) })])));
  const gate = () => { live.check(); approved?.checkCurrent(); };
  const streaming = () => Object.freeze({ total_payload_bytes: String(total), local_bytes_read: String(local),
    upload_source_bytes_read: String(sent), network_bytes_received: String(received), requests,
    maximum_chunk_bytes: CHUNK, total_payload_budget: String(options.maximumTotalBytes) });
  const charge = (count, kind) => {
    if (count > options.maximumTotalBytes - total) fail('backup_upload_budget');
    total += count; if (kind === 'sent') sent += count; else if (kind === 'received') received += count; else local += count;
  };
  const progress = async phase => { await options.onProgress(Object.freeze({ phase, state, target, checkpoint, streaming: streaming() })); gate(); };
  async function unchanged() {
    const current = await file.stat({ bigint: true }), named = await lstat(options.input, { bigint: true });
    if (!named.isFile() || !same(baseline, current) || !same(current, named)) fail('backup_upload_source_changed');
  }
  try {
    const control = { ...live, onProgress: () => {} };
    const envelope = await readBackupControl(options.approval, BACKUP_LIMITS.envelopeBytes, control);
    const key = await readBackupControl(options.trustKey, BACKUP_LIMITS.keyBytes, control);
    approved = await verifyRepositoryBackupApproval(envelope, key, options.policy, {
      maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal, ...(options.now === undefined ? {} : { now: options.now }) });
    checkpoint = Object.freeze({ approval_sha256: hash(envelope), trusted_key_id: approved.authentication.trusted_key_id });
    if (options.checkpoint && JSON.stringify(options.checkpoint) !== JSON.stringify(checkpoint)) fail('backup_upload_checkpoint_mismatch');
    const artifact = approved.authentication.statement.artifact;
    // Conservative fresh-publication reserve before ANY remote request. Controls
    // and bounded status bodies are separate from archive payload accounting.
    if (3 * Number(artifact.bytes) > options.maximumTotalBytes) fail('backup_upload_budget');
    let ca;
    if (options.caFile) {
      ca = await readBackupControl(options.caFile, BACKUP_LIMITS.envelopeBytes, control);
      try { new X509Certificate(ca); } catch { fail('backup_upload_ca'); }
    }
    file = await open(options.input, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    baseline = await file.stat({ bigint: true });
    if (!baseline.isFile() || baseline.size !== BigInt(artifact.bytes)) fail('backup_upload_source_size');
    let previous = 0;
    const source = await hashRepositoryBackup(options.input, { ...live, onProgress(event) { charge(event.bytes_read - previous, 'local'); previous = event.bytes_read; } });
    await unchanged(); gate();
    if (source.sha256 !== artifact.sha256 || source.bytes !== artifact.bytes) fail('backup_upload_source_digest');
    state = 'source_verified'; await progress('source_verified'); await unchanged();
    const ctx = { live, gate, ca, charge, request() { if (++requests > 6) fail('backup_upload_request_limit'); } };
    const approvalExpected = { bytes: String(envelope.length), sha256: checkpoint.approval_sha256 };
    const get = (kind, expected, payload) => exchange(options.target[kind].get, 'GET', expected, null, ctx, payload);
    const put = (kind, expected, produce) => exchange(options.target[kind].put, 'PUT', expected, produce, ctx, false);
    // An existing advertised checkpoint must be complete; never silently repair
    // missing dependencies under an already-visible approval.
    const oldApproval = await get('approval', approvalExpected, false);
    const oldArchive = await get('archive', artifact, true);
    let archiveDisposition = 'reused', approvalDisposition = 'reused';
    if (oldApproval.status === 200 && oldArchive.status === 404) fail('backup_upload_missing_dependency');
    if (oldArchive.status === 404) {
      state = 'archive_put_unknown'; await progress('archive_put_started'); await unchanged();
      const result = await put('archive', artifact, async (write, sendingGate) => {
        const buffer = Buffer.alloc(CHUNK), digest = createHash('sha256'); let offset = 0;
        try {
          while (offset < Number(artifact.bytes)) {
            sendingGate(); const { bytesRead } = await file.read(buffer, 0, Math.min(CHUNK, Number(artifact.bytes) - offset), offset);
            if (!bytesRead) fail('backup_upload_source_changed');
            charge(bytesRead, 'sent'); digest.update(buffer.subarray(0, bytesRead));
            await write(buffer.subarray(0, bytesRead)); offset += bytesRead;
          }
          if ((await file.read(buffer, 0, 1, offset)).bytesRead) fail('backup_upload_source_changed');
          await unchanged(); sendingGate();
          if (digest.digest('hex') !== artifact.sha256) fail('backup_upload_source_digest');
        } finally { buffer.fill(0); }
      });
      archiveDisposition = result.status === 412 ? 'concurrent_exact' : 'created';
      if ((await get('archive', artifact, true)).status !== 200) fail('backup_upload_missing_readback');
    }
    state = 'archive_verified'; await progress('archive_verified');
    if (oldApproval.status === 404) {
      state = 'approval_put_unknown'; await progress('approval_put_started');
      const result = await put('approval', approvalExpected, async write => { await write(envelope); });
      approvalDisposition = result.status === 412 ? 'concurrent_exact' : 'created';
    }
    // Recheck an existing approval too: a preflight observation cannot vouch
    // for a root substituted while its dependency was being verified.
    if ((await get('approval', approvalExpected, false)).status !== 200) fail('backup_upload_missing_readback');
    // Exact readback is the completion boundary. Do not reinterpret a later
    // cancellation or descriptor/output failure as proof of non-publication.
    state = 'complete';
    completed = Object.freeze({ type: 'repository_backup_upload', schema_version: 1, state, checkpoint, target,
      artifact, authentication: approved.authentication, streaming: streaming(),
      disposition: Object.freeze({ archive: archiveDisposition, approval: approvalDisposition }),
      conditional_put_requested: true, remote_readback_verified: true,
      archive_verified_before_approval_put: true, existing_approval_verified: oldApproval.status === 200,
      native_content_verified: false, remote_physical_durability_verified: false,
      failure_domain_independence_verified: false, newest_checkpoint_verified: false });
    return completed;
  } catch (caught) {
    problem = caught instanceof Error ? caught : backupError('backup_upload_observer_failed');
    problem.publication_state = state; problem.checkpoint = checkpoint ?? null; problem.target = target; problem.streaming = streaming(); throw problem;
  } finally {
    try { await file?.close(); } catch (error) {
      if (problem) problem.cleanup_error = 'backup_upload_close_failed';
      else { const failure = backupError('backup_upload_close_failed'); failure.completed_result = completed; failure.publication_state = state; throw failure; }
    }
  }
}
