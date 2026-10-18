// Read-only native bundle download. The native exporter constructs Git; this
// adapter checks scope, snapshot and transport commitments, not Git semantics.
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { outcomeEndpoint } from './transaction_outcome.mjs';
import { BUNDLE_REMOTE_LIMITS as L, fields, bounded, format, fail, pin, hash, encode, canonical } from './remote_bundle_protocol.mjs';
import { absolute, privateRoot, directory, inventory, absent, syncDirectory, readPrivate, readToken, writeNew, lifetime } from './remote_bundle_files.mjs';

const SCHEMA = 'frankengit-remote-bundle-download-v1';
const IDENTITY = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format'];
const HEADERS = ['content-type', 'content-length', 'content-encoding', 'x-fgit-bundle-profile', 'x-fgit-object-format',
  'x-fgit-tenant', 'x-fgit-repository', 'x-fgit-repository-incarnation', 'x-fgit-source-head',
  'x-fgit-snapshot', 'x-fgit-artifact-sha256', 'x-fgit-read-only'];
function snapshot(value) {
  if (typeof value !== 'string' || !/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){1,64}$/.test(value) || Number(value.split(':')[1]) > 65535) fail('snapshot');
  return value;
}
function identity(value) {
  fields(value, IDENTITY);
  for (const k of IDENTITY.slice(0, -1)) if (typeof value[k] !== 'string' || !/^[0-9a-f]{32}$/.test(value[k])) fail('identity');
  return { tenant_id: value.tenant_id, repository_id: value.repository_id,
    repository_incarnation: value.repository_incarnation, object_format: format(value.object_format) };
}
function head(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 256 || /[\s\x00-\x1f\x7f-\x9f\uD800-\uDFFF]/u.test(value)) fail('source_head'); return value;
}
export function exportSelection(raw) {
  fields(raw, ['endpoint', 'scope', 'expected_head', 'max_bytes'], ['endpoint', 'scope']);
  return { endpoint: outcomeEndpoint(raw.endpoint), scope: identity(raw.scope),
    expected_head: raw.expected_head == null ? null : snapshot(raw.expected_head), max_bytes: bounded(raw.max_bytes ?? L.bundle, 1, L.bundle) };
}
function descriptor(response, selected) {
  const names = response.rawHeaders.filter((_, i) => i % 2 === 0).map(k => k.toLowerCase()).filter(k => HEADERS.includes(k));
  if (new Set(names).size !== names.length) fail('export_duplicate_header');
  const h = response.headers;
  if (h['content-type']?.toLowerCase() !== 'application/x-git-bundle' || h['x-fgit-bundle-profile'] !== 'full-v1' ||
      h['x-fgit-read-only'] !== 'true' || (h['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') fail('export_headers');
  const observed = identity({ tenant_id: h['x-fgit-tenant'], repository_id: h['x-fgit-repository'],
    repository_incarnation: h['x-fgit-repository-incarnation'], object_format: h['x-fgit-object-format'] });
  if (IDENTITY.some(k => observed[k] !== selected.scope[k])) fail('export_scope');
  const token = snapshot(h['x-fgit-snapshot']);
  if (selected.expected_head !== null && selected.expected_head !== token) fail('export_snapshot_changed');
  const length = h['content-length'];
  if (typeof length !== 'string' || !/^[1-9][0-9]*$/.test(length) || BigInt(length) > BigInt(selected.max_bytes)) fail('export_byte_limit');
  return { scope: observed, snapshot_token: token, source_head: head(h['x-fgit-source-head']), bytes: Number(length), sha256: pin(h['x-fgit-artifact-sha256']) };
}
function download(selected, token, life, ca) {
  return new Promise((resolve, reject) => {
    let req, res, timer, bytes, captured, size = 0, finished = false, closed = false, delivered = false, result, error;
    const problem = code => Object.assign(new Error(`remote_bundle_${code}`), { code: `remote_bundle_${code}` });
    const deliver = () => { if (delivered) return; delivered = true; error ? reject(error) : resolve(result); };
    const finish = (failure, value) => {
      if (finished) return; finished = true; error = failure; result = value;
      clearTimeout(timer); life.signal.removeEventListener('abort', abort); res?.destroy(); req?.destroy();
      if (!req || closed) deliver();
    };
    const abort = () => finish(problem('cancelled'));
    try {
      life.check();
      const body = new URLSearchParams({ object_format: selected.scope.object_format });
      if (selected.expected_head !== null) body.set('expected_head', selected.expected_head);
      const encoded = body.toString(), url = new URL(`${selected.endpoint}/api/v1/source/bundle/export`);
      req = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, {
        method: 'POST', agent: false, rejectUnauthorized: true, maxHeaderSize: 16384, ...(ca ? { ca } : {}),
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': String(Buffer.byteLength(encoded)), Accept: 'application/x-git-bundle',
          'Accept-Encoding': 'identity', Connection: 'close', 'Cache-Control': 'no-store' },
      });
      req.once('close', () => { closed = true; if (!finished) finish(problem('export_incomplete')); else deliver(); });
      req.on('error', () => finish(problem('transport')));
      req.once('response', incoming => {
        res = incoming;
        if (res.statusCode !== 200) { finish(problem('export_http_refused')); return; }
        try { captured = descriptor(res, selected); bytes = Buffer.alloc(captured.bytes); } catch (e) { finish(e); return; }
        res.on('error', () => finish(problem('export_incomplete')));
        res.on('data', chunk => {
          if (finished) return;
          if (size + chunk.length > bytes.length) { finish(problem('export_byte_limit')); return; }
          chunk.copy(bytes, size); size += chunk.length;
        });
        res.once('end', () => {
          if (finished) return;
          try {
            life.check(); if (!res.complete || size !== captured.bytes) fail('export_incomplete');
            if (hash(bytes) !== captured.sha256) fail('export_digest');
            finish(null, { descriptor: captured, bytes });
          } catch (e) { finish(e); }
        });
      });
      life.signal.addEventListener('abort', abort, { once: true }); timer = setTimeout(abort, life.remaining());
      if (life.signal.aborted) abort(); else req.end(encoded);
    } catch (e) { finish(e); }
  });
}
function manifest(value) {
  fields(value, ['schema', 'selection', 'source', 'artifact']);
  if (value.schema !== SCHEMA) fail('export_schema');
  const s = exportSelection(value.selection);
  fields(value.source, ['scope', 'snapshot_token', 'source_head']); identity(value.source.scope);
  if (IDENTITY.some(k => s.scope[k] !== value.source.scope[k])) fail('export_scope');
  snapshot(value.source.snapshot_token); head(value.source.source_head);
  if (s.expected_head !== null && s.expected_head !== value.source.snapshot_token) fail('export_snapshot_changed');
  fields(value.artifact, ['bytes', 'sha256']); bounded(value.artifact.bytes, 1, s.max_bytes); pin(value.artifact.sha256);
  return value;
}
function summary(root, m) {
  return { type: 'remote_bundle_download', schema_version: 1, workdir: root,
    download_sha256: hash(encode(m)), bundle_file: join(root, 'repository.bundle'), artifact_sha256: m.artifact.sha256,
    bytes: m.artifact.bytes, source: m.source, complete: true, native_bundle_validated: false,
    canonical_backup: false, mutation_submitted: false };
}
export async function exportRemoteBundle(raw) {
  fields(raw, ['workdir', 'selection', 'tokenFile', 'caFile', 'timeoutMs', 'signal'], ['workdir', 'selection', 'tokenFile']);
  const root = absolute(raw.workdir), selected = exportSelection(raw.selection), tokenFile = absolute(raw.tokenFile),
    caFile = raw.caFile === undefined ? undefined : absolute(raw.caFile), life = lifetime(raw);
  let created = false, confirm = null;
  try {
    life.check(); await privateRoot(dirname(root)); await absent(root);
    const token = await readToken(tokenFile, life.check), ca = caFile === undefined ? undefined : await readPrivate(caFile, 128 * 1024, life.check);
    const received = await download(selected, token, life, ca), d = received.descriptor;
    const m = manifest({ schema: SCHEMA, selection: selected, source: { scope: d.scope, snapshot_token: d.snapshot_token, source_head: d.source_head },
      artifact: { bytes: d.bytes, sha256: d.sha256 } });
    const bytes = encode(m); confirm = hash(bytes);
    life.check(); await mkdir(root, { mode: 0o700 }); created = true; await syncDirectory(dirname(root)); const id = await directory(root);
    await writeNew(join(root, 'repository.bundle'), received.bytes); life.check(); await directory(root, id);
    await writeNew(join(root, 'download.json'), bytes);
    return { ...summary(root, m), network_accessed: true };
  } catch (cause) {
    const e = cause instanceof Error ? cause : new Error('remote_bundle_interrupted');
    e.bundle_progress = { workdir: root, directory_created: created, download_sha256: confirm, complete: false, mutation_submitted: false }; throw e;
  } finally { life.close(); }
}
export async function inspectRemoteDownload(raw) {
  fields(raw, ['workdir', 'confirm', 'timeoutMs', 'signal'], ['workdir', 'confirm']);
  const root = absolute(raw.workdir), expected = pin(raw.confirm), life = lifetime(raw);
  try {
    life.check(); await privateRoot(root); const id = await directory(root);
    await inventory(root, ['repository.bundle', 'download.json'], life.check);
    const bytes = await readPrivate(join(root, 'download.json'), 16384, life.check);
    if (hash(bytes) !== expected) fail('download_pin'); const m = manifest(canonical(bytes));
    const payload = await readPrivate(join(root, 'repository.bundle'), m.artifact.bytes, life.check);
    if (payload.length !== m.artifact.bytes || hash(payload) !== m.artifact.sha256) fail('export_digest');
    life.check(); await directory(root, id); return { ...summary(root, m), network_accessed: false, local_read_only: true };
  } finally { life.close(); }
}
