// External read-only operator for the existing native artifact API. A saved
// receipt selects expected bytes; it is not authenticated producer/check proof.
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { lstat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { outcomeEndpoint } from './transaction_outcome.mjs';
import { absolute, directory, readPrivate, parseJson, writeNew } from './workflow_watch_io.mjs';

const MAX = 64 * 1024 * 1024, JSON_MAX = 16 * 1024;
const TRUST = 'trusted-workflow-local-owner';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
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
  fields(input, ['endpoint', 'scope', 'job_id_hex', 'path_hex']);
  const endpoint = outcomeEndpoint(input.endpoint), scope = input.scope;
  fields(scope, ['tenant_id', 'repository_id', 'repository_incarnation_id', 'trust_domain']);
  for (const key of ['tenant_id', 'repository_id', 'repository_incarnation_id']) hex(scope[key], 32);
  if (scope.trust_domain !== TRUST) refuse('artifact_scope_invalid');
  rawPath(input.job_id_hex, 256); rawPath(input.path_hex, 4096);
  fields(receipt, ['type', 'manifest_id_sha256', 'manifest']);
  hex(receipt.manifest_id_sha256, 64);
  const m = receipt.manifest, p = m?.producer;
  if (receipt.type !== 'trusted_workflow_artifact_receipt' || m?.type !== 'trusted_workflow_artifact_provenance' ||
      m.schema_version !== 1 || m.job_id_hex !== input.job_id_hex ||
      p?.tenant_id !== scope.tenant_id || p.repository_id !== scope.repository_id ||
      p.repository_incarnation !== scope.repository_incarnation_id ||
      m.job_success_asserted !== false || m.cache_reuse_authorized !== false ||
      !Array.isArray(m.outputs) || !m.outputs.length || m.outputs.length > 64) refuse('artifact_receipt_mismatch');
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
function metadata(value, selected) {
  fields(value, ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation_id', 'trust_domain',
    'scope_sha256', 'artifact_id', 'payload_sha256', 'payload_bytes', 'media_type', 'kind', 'build_capsule_sha256',
    'check_receipt_sha256', 'source_rcr_sha256', 'retention_canonical_hex', 'payload_verified',
    'provenance_authenticated', 'canonical_repository_published', 'retention_enforced', 'read_only']);
  if (value.type !== 'artifact_metadata' || value.schema_version !== 1 ||
      Object.keys(selected.scope).some(k => value[k] !== selected.scope[k]) ||
      value.artifact_id !== selected.output.artifact_id_sha256 || value.payload_sha256 !== selected.output.payload_sha256 ||
      value.payload_bytes !== selected.output.payload_bytes || value.kind !== 'ci_artifact' ||
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
// Both GETs own their connection through close. No redirects, retries, cookies,
// ambient proxy, arbitrary headers, idempotency key or local custody fallback.
function get(url, token, maximum, expectedType, options, checkpoint, attachment) {
  return new Promise((resolve, reject) => {
    let request, response, timer, closed = false, settled = false, finished = false, failure, result;
    const deliver = () => { if (!settled) { settled = true; failure ? reject(failure) : resolve(result); } };
    const finish = (error, bytes) => {
      if (finished) return; finished = true; failure = error; result = bytes;
      clearTimeout(timer); options.signal?.removeEventListener('abort', abort);
      response?.destroy(); request?.destroy(); if (!request || closed) deliver();
    };
    const abort = () => finish(new ArtifactDownloadError('artifact_download_cancelled'));
    try {
      const remaining = checkpoint();
      request = (url.startsWith('https:') ? httpsRequest : httpRequest)(url, {
        method: 'GET', agent: false, maxHeaderSize: JSON_MAX, rejectUnauthorized: true,
        ...(options.ca ? { ca: options.ca } : {}), headers: { Authorization: `Bearer ${token}`,
          'User-Agent': 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)',
          Accept: expectedType, 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store', Connection: 'close' },
      });
      request.once('close', () => { closed = true;
        if (!finished) finish(new ArtifactDownloadError('artifact_response_incomplete')); else deliver(); });
      request.on('error', () => finish(new ArtifactDownloadError('artifact_transport_unavailable')));
      request.once('response', incoming => {
        response = incoming;
        if (incoming.statusCode !== 200) { finish(new ArtifactDownloadError('artifact_http_refused')); return; }
        const names = incoming.rawHeaders.filter((_, i) => i % 2 === 0).map(k => k.toLowerCase())
          .filter(k => ['content-type', 'content-length', 'content-encoding', 'content-disposition', 'transfer-encoding'].includes(k));
        const length = incoming.headers['content-length'];
        if (new Set(names).size !== names.length || incoming.headers['transfer-encoding'] !== undefined ||
            typeof length !== 'string' || !/^(0|[1-9][0-9]*)$/.test(length) || BigInt(length) > BigInt(maximum) ||
            incoming.headers['content-type']?.split(';')[0].trim().toLowerCase() !== expectedType ||
            (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity' ||
            (attachment && incoming.headers['content-disposition'] !== attachment)) {
          finish(new ArtifactDownloadError('artifact_response_framing')); return;
        }
        const chunks = []; let size = 0;
        incoming.on('error', () => finish(new ArtifactDownloadError('artifact_response_incomplete')));
        incoming.on('data', chunk => {
          if (finished) return;
          size += chunk.length;
          if (size > maximum || chunks.length >= 65536) finish(new ArtifactDownloadError('artifact_response_limit'));
          else chunks.push(chunk);
        });
        incoming.once('end', () => {
          if (!incoming.complete || size !== Number(length)) finish(new ArtifactDownloadError('artifact_response_incomplete'));
          else finish(null, Buffer.concat(chunks, size));
        });
      });
      options.signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish(new ArtifactDownloadError('artifact_download_timeout')), remaining);
      if (options.signal?.aborted) abort(); else request.end();
    } catch (error) { finish(error instanceof ArtifactDownloadError ? error : new ArtifactDownloadError('artifact_transport_unavailable')); }
  });
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
  const raw = await get(url, token, JSON_MAX, 'application/json', transport, checkpoint);
  metadata(parseJson(raw, JSON_MAX), selected);
  const bytes = await get(url + '/content', token, selected.output.payload_bytes, 'application/octet-stream', transport,
    checkpoint, `attachment; filename="artifact-${selected.output.artifact_id_sha256}"`);
  if (bytes.length !== selected.output.payload_bytes || hash(bytes) !== selected.output.payload_sha256) refuse('artifact_payload_mismatch');
  checkpoint();
  // Verified body first, create-only root last. Once this publication begins,
  // finish it: a late cancellation cannot erase an already visible file.
  await writeNew(destination, bytes);
  return { type: 'workflow_artifact_download', schema_version: 1, artifact_id: selected.output.artifact_id_sha256,
    payload_sha256: selected.output.payload_sha256, payload_bytes: bytes.length, output: destination,
    payload_sha256_verified: true, scope_matches_expected: true, artifact_identity_independently_verified: false,
    provenance_authenticated: false, canonical_repository_published: false, job_success_asserted: false,
    execution_performed: false, executable_mode_applied: false, retention_enforced: false };
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
  const receipt = parseJson(await privateBytes(flags['--receipt'], 1024 * 1024), 1024 * 1024);
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
