// Protocol peer and independent native-preimage fixtures. This exercises the
// real browser client; it is not a substitute for native HTTP integration.
import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
export const crypto = webcrypto;
export const href = 'https://forge.example/team/repo.git/ui/artifacts/';
export const token = 'ab'.repeat(32);
export const vectors = JSON.parse(readFileSync(new URL('./artifacts-native-vectors.json', import.meta.url), 'utf8'));
export const incarnation = vectors[0].metadata.repository_incarnation_id;
export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export const unhex = value => Uint8Array.from(Buffer.from(value, 'hex'));
export function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; }
function count(value, size) {
  const bytes = Buffer.alloc(size);
  if (size === 8) bytes.writeBigUInt64BE(BigInt(value)); else if (size === 4) bytes.writeUInt32BE(value); else bytes.writeUInt16BE(value);
  return bytes;
}
// Encodes the native formats independently of the production browser module.
export function bindMetadata(value) {
  const metadata = structuredClone(value), trust = Buffer.from(metadata.trust_domain), media = Buffer.from(metadata.media_type);
  metadata.scope_sha256 = digest(Buffer.concat([Buffer.from('frankengit/artifact-scope/v1\0'),
    ...['tenant_id','repository_id','repository_incarnation_id'].map(key => Buffer.from(metadata[key], 'hex')), count(trust.length, 2), trust]));
  const kind = ['ci_artifact','build_log','release_asset','sbom','signature','provenance','git_lfs'].indexOf(metadata.kind) + 1;
  const retention = Buffer.from(metadata.retention_canonical_hex, 'hex');
  metadata.artifact_id = digest(Buffer.concat([Buffer.from('frankengit/artifact-identity/v1\0'), Buffer.from(metadata.payload_sha256, 'hex'),
    count(metadata.payload_bytes, 8), Buffer.from([kind]), count(media.length, 4), media,
    ...['build_capsule_sha256','check_receipt_sha256','source_rcr_sha256'].map(key => metadata[key] === null
      ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), Buffer.from(metadata[key], 'hex')])), count(retention.length, 4), retention]));
  return metadata;
}
export function fixture(index = 1) {
  const vector = vectors[index], original = unhex(vector.payload_hex), calls = [];
  const config = { metadata: structuredClone(vector.metadata), content: original.slice(), metadataStatus: 200, contentStatus: 200,
    metadataHeaders: {}, contentHeaders: {}, before: null, response: null };
  const fetchImpl = async (url, options) => {
    const path = new URL(url).pathname.split('/api/v1/')[1];
    const call = { path, url: String(url), options, headers: Object.fromEntries(new Headers(options.headers)) }; calls.push(call);
    if (config.before) await config.before(call);
    if (config.response) return config.response(call);
    const content = path.endsWith('/content'), status = content ? config.contentStatus : config.metadataStatus;
    if (status !== 200) return new Response('private server error must not be displayed', { status, headers: { 'Content-Type': 'text/plain' } });
    const bytes = content ? config.content : new TextEncoder().encode(JSON.stringify(config.metadata));
    return new Response(bytes.slice(), { headers: { 'Content-Type': content ? 'application/octet-stream' : 'application/json; charset=utf-8',
      'Content-Length': String(bytes.length), 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', 'Vary': 'Authorization',
      ...(content ? { 'Content-Disposition': `attachment; filename="artifact-${path.split('/')[1]}"` } : {}),
      ...(content ? config.contentHeaders : config.metadataHeaders) } });
  };
  return { config, calls, original, fetchImpl };
}
