// External read-only operator for the existing native artifact API. A saved
// receipt selects expected bytes; it is not authenticated producer/check proof.
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createHash, randomBytes } from 'node:crypto';
import { constants as F } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { lstat, open, link, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { outcomeEndpoint } from './transaction_outcome.mjs';
import { absolute, directory, readPrivate, parseJson, syncDirectory } from './workflow_watch_io.mjs';

const MAX = 64 * 1024 * 1024, JSON_MAX = 16 * 1024;
const MANIFEST_MAX = 1024 * 1024;
// Native bounds its compact manifest, then wraps it. The file receipt envelope
// is the larger of the two fixed formats; do not charge it to the manifest.
const RECEIPT_MAX = MANIFEST_MAX + Buffer.byteLength(JSON.stringify({
  type: 'trusted_workflow_artifact_receipt', manifest_id_sha256: '0'.repeat(64), manifest: null,
})) - 4;
const TRUST = 'trusted-workflow-local-owner';
const STEP_OUTCOMES = ['succeeded', 'failed', 'cancelled', 'timed_out', 'output_limit', 'containment_failure'];
const JOB_OUTCOMES = ['succeeded', 'failed', 'skipped', 'cancelled', 'timed_out', 'output_limit', 'refused'];
export class ArtifactDownloadError extends Error {
  constructor(code) { super(code); this.name = 'ArtifactDownloadError'; this.code = code; }
}
const refuse = code => { throw new ArtifactDownloadError(code); };
function fields(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length ||
      keys.some(k => !Object.hasOwn(value, k))) refuse('artifact_fields_invalid');
}
function hex(value, width) {
  if (typeof value !== 'string' || value.length !== width || !/^[0-9a-f]+$/.test(value)) refuse('artifact_identity_invalid');
  return value;
}
function rawPath(value, maximum) {
  if (typeof value !== 'string' || !value.length || value.length > maximum * 2 || !/^(?:[0-9a-f]{2})+$/.test(value)) {
    refuse('artifact_selector_invalid');
  }
}
// The independently supplied scope is never learned from the downloaded reply.
export function selectArtifact(input, receipt) {
  const logs = input && (Object.hasOwn(input, 'step_index') || Object.hasOwn(input, 'stream'));
  fields(input, ['endpoint', 'scope', 'job_id_hex', ...(logs ? ['step_index', 'stream'] : ['path_hex'])]);
  const endpoint = outcomeEndpoint(input.endpoint), scope = input.scope;
  fields(scope, ['tenant_id', 'repository_id', 'repository_incarnation_id', 'trust_domain']);
  for (const key of ['tenant_id', 'repository_id', 'repository_incarnation_id']) hex(scope[key], 32);
  if (scope.trust_domain !== TRUST) refuse('artifact_scope_invalid');
  rawPath(input.job_id_hex, 256);
  if (logs) {
    if (!Number.isSafeInteger(input.step_index) || input.step_index < 0 || !['stdout', 'stderr'].includes(input.stream)) {
      refuse('artifact_log_selector_invalid');
    }
  } else rawPath(input.path_hex, 4096);
  fields(receipt, ['type', 'manifest_id_sha256', 'manifest']);
  hex(receipt.manifest_id_sha256, 64);
  const m = receipt.manifest, p = m?.producer;
  if (m?.schema_version !== 1 || m.job_id_hex !== input.job_id_hex ||
      p?.tenant_id !== scope.tenant_id || p.repository_id !== scope.repository_id ||
      p.repository_incarnation !== scope.repository_incarnation_id ||
      m.job_success_asserted !== false || m.cache_reuse_authorized !== false) refuse('artifact_receipt_mismatch');
  if (Buffer.byteLength(JSON.stringify(m)) > MANIFEST_MAX) refuse('artifact_manifest_limit');
  if (logs) return selectLog(input, receipt, endpoint, scope);
  if (receipt.type !== 'trusted_workflow_artifact_receipt' || m.type !== 'trusted_workflow_artifact_provenance' ||
      Object.hasOwn(m, 'logs') || !Array.isArray(m.outputs) || !m.outputs.length || m.outputs.length > 64) refuse('artifact_receipt_mismatch');
  const seen = new Set(); let selected;
  for (const file of m.outputs) {
    fields(file, ['path_hex', 'artifact_id_sha256', 'payload_sha256', 'payload_bytes', 'executable']);
    rawPath(file.path_hex, 4096); hex(file.artifact_id_sha256, 64); hex(file.payload_sha256, 64);
    if (seen.has(file.path_hex) || !Number.isSafeInteger(file.payload_bytes) || file.payload_bytes < 0 ||
        file.payload_bytes > MAX || typeof file.executable !== 'boolean') refuse('artifact_output_invalid');
    seen.add(file.path_hex); if (file.path_hex === input.path_hex) selected = file;
  }
  if (!selected) refuse('artifact_output_not_selected');
  return { endpoint, scope: { ...scope }, output: { ...selected }, manifest_id_sha256: receipt.manifest_id_sha256 };
}
function selectLog(input, receipt, endpoint, scope) {
  const m = receipt.manifest;
  if (receipt.type !== 'trusted_workflow_log_receipt' || m.type !== 'trusted_workflow_log_provenance' ||
      Object.hasOwn(m, 'outputs') || !JOB_OUTCOMES.includes(m.observed_job_outcome) ||
      !Array.isArray(m.logs) || !m.logs.length || m.logs.length > 8192) refuse('artifact_log_receipt_invalid');
  const pairs = new Map(); let selected;
  for (const log of m.logs) {
    fields(log, ['step_index', 'step_name_hex', 'script_sha256', 'stream', 'observed_step_outcome', 'exit_code',
      'output_complete', 'artifact_id_sha256', 'payload_sha256', 'payload_bytes']);
    hex(log.script_sha256, 64); hex(log.artifact_id_sha256, 64); hex(log.payload_sha256, 64);
    if (!Number.isSafeInteger(log.step_index) || log.step_index < 0 || !['stdout', 'stderr'].includes(log.stream) ||
        !STEP_OUTCOMES.includes(log.observed_step_outcome) || typeof log.output_complete !== 'boolean' ||
        (log.exit_code !== null && (!Number.isInteger(log.exit_code) || log.exit_code < -2147483648 || log.exit_code > 2147483647)) ||
        !Number.isSafeInteger(log.payload_bytes) || log.payload_bytes < 0 || log.payload_bytes > MAX ||
        (log.step_name_hex !== null && (typeof log.step_name_hex !== 'string' || log.step_name_hex.length > 1024 * 1024 ||
          !/^(?:[0-9a-f]{2})*$/.test(log.step_name_hex)))) refuse('artifact_log_observation_invalid');
    const pair = pairs.get(log.step_index) ?? new Map();
    if (pair.has(log.stream)) refuse('artifact_log_duplicate');
    const other = pair.values().next().value;
    if (other && ['step_name_hex', 'script_sha256', 'observed_step_outcome', 'exit_code', 'output_complete']
      .some(key => other[key] !== log[key])) refuse('artifact_log_observation_mismatch');
    pair.set(log.stream, log); pairs.set(log.step_index, pair);
    if (log.step_index === input.step_index && log.stream === input.stream) selected = log;
  }
  if ([...pairs.values()].some(pair => pair.size !== 2)) refuse('artifact_log_pair_incomplete');
  if (!selected) refuse('artifact_output_not_selected');
  return { endpoint, scope: { ...scope }, output: { ...selected }, manifest_id_sha256: receipt.manifest_id_sha256,
    // Retained observations, not authenticated execution or a completeness upgrade.
    log_observation: { step_index: selected.step_index, stream: selected.stream, script_sha256: selected.script_sha256,
      observed_job_outcome: m.observed_job_outcome, observed_step_outcome: selected.observed_step_outcome,
      exit_code: selected.exit_code, output_complete: selected.output_complete } };
}
function metadata(value, selected) {
  fields(value, ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation_id', 'trust_domain',
    'scope_sha256', 'artifact_id', 'payload_sha256', 'payload_bytes', 'media_type', 'kind', 'build_capsule_sha256',
    'check_receipt_sha256', 'source_rcr_sha256', 'retention_canonical_hex', 'payload_verified',
    'provenance_authenticated', 'canonical_repository_published', 'retention_enforced', 'read_only']);
  if (value.type !== 'artifact_metadata' || value.schema_version !== 1 ||
      Object.keys(selected.scope).some(k => value[k] !== selected.scope[k]) ||
      value.artifact_id !== selected.output.artifact_id_sha256 || value.payload_sha256 !== selected.output.payload_sha256 ||
      value.payload_bytes !== selected.output.payload_bytes || value.kind !== (selected.log_observation ? 'build_log' : 'ci_artifact') ||
      value.payload_verified !== true || value.provenance_authenticated !== false ||
      value.canonical_repository_published !== false || value.retention_enforced !== false || value.read_only !== true ||
      typeof value.media_type !== 'string' || value.media_type.length > 256) refuse('artifact_metadata_mismatch');
  hex(value.scope_sha256, 64);
  for (const key of ['build_capsule_sha256', 'check_receipt_sha256', 'source_rcr_sha256']) if (value[key] !== null) hex(value[key], 64);
  rawPath(value.retention_canonical_hex, 512);
}
async function absent(path) {
  try { await lstat(path); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  refuse('artifact_output_exists');
}
// The consumer owns one chunk at a time. Pausing at yield propagates disk
// backpressure to the socket; neither artifacts nor logs are buffered in full.
// Both GETs still own their connection through close, including early return.
// No redirects, retries, cookies, ambient proxy, or local custody fallback.
async function* responseChunks(url, token, maximum, expectedType, options, checkpoint, attachment) {
  let request, response, timer, closed, failure;
  const stop = error => {
    failure ??= error;
    response?.destroy(failure); request?.destroy(failure);
  };
  const abort = () => stop(new ArtifactDownloadError('artifact_download_cancelled'));
  try {
    const remaining = checkpoint();
    request = (url.startsWith('https:') ? httpsRequest : httpRequest)(url, {
      method: 'GET', agent: false, maxHeaderSize: JSON_MAX, rejectUnauthorized: true,
      ...(options.ca ? { ca: options.ca } : {}), headers: { Authorization: `Bearer ${token}`,
        'User-Agent': 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)',
        Accept: expectedType, 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store', Connection: 'close' },
    });
    let rejectHeaders;
    const headers = new Promise((resolve, reject) => {
      rejectHeaders = reject;
      request.once('response', incoming => {
        response = incoming;
        // Install before resolving: cancellation can race attaching the iterator.
        incoming.on('error', () => { failure ??= new ArtifactDownloadError('artifact_response_incomplete'); });
        resolve(incoming);
      });
      request.on('error', () => {
        failure ??= new ArtifactDownloadError('artifact_transport_unavailable');
        reject(failure);
      });
    });
    closed = new Promise(resolve => request.once('close', () => {
      if (!response) rejectHeaders(failure ?? new ArtifactDownloadError('artifact_response_incomplete'));
      resolve();
    }));
    options.signal?.addEventListener('abort', abort, { once: true });
    timer = setTimeout(() => stop(new ArtifactDownloadError('artifact_download_timeout')), remaining);
    if (options.signal?.aborted) abort(); else request.end();
    const incoming = await headers;
    if (failure) throw failure;
    if (incoming.statusCode !== 200) refuse('artifact_http_refused');
    const names = incoming.rawHeaders.filter((_, i) => i % 2 === 0).map(k => k.toLowerCase())
      .filter(k => ['content-type', 'content-length', 'content-encoding', 'content-disposition', 'transfer-encoding'].includes(k));
    const length = incoming.headers['content-length'];
    if (new Set(names).size !== names.length || incoming.headers['transfer-encoding'] !== undefined ||
        typeof length !== 'string' || !/^(0|[1-9][0-9]*)$/.test(length) || BigInt(length) > BigInt(maximum) ||
        incoming.headers['content-type']?.split(';')[0].trim().toLowerCase() !== expectedType ||
        (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity' ||
        (attachment && incoming.headers['content-disposition'] !== attachment)) refuse('artifact_response_framing');
    let size = 0, count = 0;
    for await (const chunk of incoming) {
      if (failure) throw failure;
      checkpoint();
      size += chunk.length;
      if (size > maximum || count++ >= 65536) refuse('artifact_response_limit');
      yield chunk;
    }
    if (failure) throw failure;
    checkpoint();
    if (!incoming.complete || size !== Number(length)) refuse('artifact_response_incomplete');
  } catch (error) {
    if (failure) throw failure;
    throw error instanceof ArtifactDownloadError ? error : new ArtifactDownloadError('artifact_transport_unavailable');
  } finally {
    clearTimeout(timer); options.signal?.removeEventListener('abort', abort);
    response?.destroy(); request?.destroy();
    if (closed) await closed;
  }
}
async function getMetadata(url, token, options, checkpoint) {
  const chunks = [];
  for await (const chunk of responseChunks(url, token, JSON_MAX, 'application/json', options, checkpoint)) chunks.push(chunk);
  return Buffer.concat(chunks);
}

// Private staging, exact length and digest, then create-only atomic visibility.
// The source is pulled only after each disk write finishes. A fixed-size owned
// block also prevents source buffer reuse from changing bytes between hash/write.
// This is exported for filesystem/stream contract tests, not forge authority.
export async function publishArtifactStream(destination, expected, source, checkpoint = () => {}) {
  const size = expected?.payload_bytes, digest = expected?.payload_sha256;
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX ||
      typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest) || typeof checkpoint !== 'function') {
    refuse('artifact_output_invalid');
  }
  const parent = dirname(absolute(destination));
  await directory(parent); checkpoint();
  const temporary = `${destination}.writing-${randomBytes(16).toString('hex')}`;
  const handle = await open(temporary, F.O_CREAT | F.O_EXCL | F.O_WRONLY | F.O_NOFOLLOW, 0o600);
  let failure, failed = false, received = 0;
  try {
    checkpoint();
    const hash = createHash('sha256'), block = Buffer.allocUnsafe(Math.min(size, 64 * 1024));
    for await (const chunk of source) {
      checkpoint();
      if (!Buffer.isBuffer(chunk) || chunk.length > size - received) refuse('artifact_payload_mismatch');
      for (let offset = 0; offset < chunk.length;) {
        checkpoint();
        const length = Math.min(block.length, chunk.length - offset);
        chunk.copy(block, 0, offset, offset + length);
        const owned = block.subarray(0, length);
        await handle.writeFile(owned);
        hash.update(owned); received += length; offset += length;
      }
    }
    if (received !== size || hash.digest('hex') !== digest) refuse('artifact_payload_mismatch');
    checkpoint(); await handle.sync(); checkpoint();
    // Publication is the cancellation boundary. Never erase a visible result,
    // even if cancellation or a cleanup/fsync error arrives after this point.
    await link(temporary, destination);
  } catch (error) { failure = error; failed = true; }
  // Attempt every cleanup step, retaining the primary failure. In particular,
  // a close error must not strand the staging name or skip directory fsync.
  for (const cleanup of [() => handle.close(), () => unlink(temporary), () => syncDirectory(parent)]) {
    try { await cleanup(); } catch (error) { if (!failed) { failure = error; failed = true; } }
  }
  if (failed) throw failure;
  return received;
}
export async function downloadArtifact(input, receipt, token, destination, options = {}) {
  const selected = selectArtifact(input, receipt);
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) refuse('artifact_token_invalid');
  if (!options || Object.keys(options).some(k => !['signal', 'timeoutMs', 'ca'].includes(k)) ||
      (options.signal !== undefined && !(options.signal instanceof AbortSignal)) ||
      (options.ca !== undefined && (!Buffer.isBuffer(options.ca) || !options.ca.length || options.ca.length > 128 * 1024))) {
    refuse('artifact_transport_options_invalid');
  }
  const timeout = options.timeoutMs ?? 30000;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300000) refuse('artifact_deadline_invalid');
  const transport = { ...options, ...(options.ca ? { ca: Buffer.from(options.ca) } : {}) };
  const deadline = performance.now() + timeout;
  const checkpoint = () => {
    if (transport.signal?.aborted) refuse('artifact_download_cancelled');
    const left = Math.floor(deadline - performance.now()); if (left < 1) refuse('artifact_download_timeout'); return left;
  };
  absolute(destination); await directory(dirname(destination)); await absent(destination); checkpoint();
  const url = `${selected.endpoint}/api/v1/artifacts/${selected.output.artifact_id_sha256}`;
  const raw = await getMetadata(url, token, transport, checkpoint);
  metadata(parseJson(raw, JSON_MAX), selected);
  const chunks = responseChunks(url + '/content', token, selected.output.payload_bytes, 'application/octet-stream', transport,
    checkpoint, `attachment; filename="artifact-${selected.output.artifact_id_sha256}"`);
  const received = await publishArtifactStream(destination, selected.output, chunks, checkpoint);
  return { type: 'workflow_artifact_download', schema_version: 1, artifact_id: selected.output.artifact_id_sha256,
    payload_sha256: selected.output.payload_sha256, payload_bytes: received, output: destination,
    payload_sha256_verified: true, scope_matches_expected: true, artifact_identity_independently_verified: false,
    provenance_authenticated: false, canonical_repository_published: false, job_success_asserted: false,
    execution_performed: false, executable_mode_applied: false, retention_enforced: false,
    ...(selected.log_observation ? { log_observation: selected.log_observation } : {}) };
}
export async function artifactDownloadCommand(args, { signal } = {}) {
  const flags = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!['--input', '--receipt', '--token-file', '--output', '--timeout-ms', '--ca-file'].includes(args[i]) ||
        Object.hasOwn(flags, args[i]) || typeof args[i + 1] !== 'string' || args[i + 1].startsWith('--')) refuse('artifact_arguments_invalid');
    flags[args[i]] = args[i + 1];
  }
  if (['--input', '--receipt', '--token-file', '--output'].some(k => !flags[k]) ||
      (flags['--timeout-ms'] && !/^[1-9][0-9]{0,5}$/.test(flags['--timeout-ms']))) refuse('artifact_arguments_invalid');
  async function privateBytes(path, max) { absolute(path); await directory(dirname(path)); return readPrivate(path, max); }
  const input = parseJson(await privateBytes(flags['--input'], 16384));
  const receipt = parseJson(await privateBytes(flags['--receipt'], RECEIPT_MAX), RECEIPT_MAX);
  const bytes = await privateBytes(flags['--token-file'], 65);
  let token;
  try {
    if (bytes.length !== 64 && !(bytes.length === 65 && bytes[64] === 10)) refuse('artifact_token_invalid');
    token = bytes.subarray(0, 64).toString('utf8');
  } finally { bytes.fill(0); }
  return downloadArtifact(input, receipt, token, flags['--output'], { signal,
    ...(flags['--timeout-ms'] ? { timeoutMs: Number(flags['--timeout-ms']) } : {}),
    ...(flags['--ca-file'] ? { ca: await privateBytes(flags['--ca-file'], 128 * 1024) } : {}) });
}
