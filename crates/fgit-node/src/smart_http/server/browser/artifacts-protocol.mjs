// Native artifact and custody-namespace commitments, not producer authentication.
// Preimages are owned by fgit-object-fabric/src/artifact.rs and storage/codec.rs.
import { copy, fail, hex, integer, keys, rootFor, unhex, utf8 } from './pulls-core.mjs';

export const ARTIFACT_BYTES = 16 * 1024 * 1024;
export const NATIVE_ARTIFACT_BYTES = 64 * 1024 * 1024;
export const METADATA_BYTES = 16 * 1024;
export const PREVIEW_BYTES = 4096;
export const TRUST_DOMAIN = 'trusted-workflow-local-owner';
const KINDS = ['ci_artifact', 'build_log', 'release_asset', 'sbom', 'signature', 'provenance', 'git_lfs'];
const OPTIONAL_DIGESTS = ['build_capsule_sha256', 'check_receipt_sha256', 'source_rcr_sha256'];
const FIELDS = ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation_id', 'trust_domain',
  'scope_sha256', 'artifact_id', 'payload_sha256', 'payload_bytes', 'media_type', 'kind', ...OPTIONAL_DIGESTS,
  'retention_canonical_hex', 'payload_verified', 'provenance_authenticated', 'canonical_repository_published',
  'retention_enforced', 'read_only'];

export function artifactId(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('Use the exact 64-character lowercase artifact ID from the workflow receipt.');
  return value;
}
export function incarnationId(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('An exact 32-character lowercase repository incarnation is required.');
  return value;
}
export function artifactLocation(href) {
  const page = new URL(href), fragment = page.hash;
  let selected = null;
  if (fragment) {
    const match = /^#artifact=([0-9a-f]{64})&incarnation=([0-9a-f]{32})$/.exec(fragment);
    if (!match) fail('Use a pinned artifact link containing only its artifact ID and repository incarnation.');
    selected = { id: match[1], incarnation: match[2] };
  }
  page.hash = '';
  return { href: page.href, root: rootFor(page.href, '/ui/artifacts/'), selected };
}
export function pinnedArtifactLink(root, metadata) {
  return `${root.origin}${root.route}/ui/artifacts/#artifact=${artifactId(metadata.artifact_id)}&incarnation=${incarnationId(metadata.repository_incarnation_id)}`;
}
export function payloadPins(value = {}) {
  keys(value, ['payloadSha256', 'payloadBytes']);
  const digest = value.payloadSha256 ?? null, bytes = value.payloadBytes ?? null;
  if ((digest === null) !== (bytes === null)) fail('Supply both the expected payload SHA-256 and byte length, or leave both empty.');
  if (digest !== null) {
    artifactId(digest);
    integer(bytes, 'expected payload length', 0, NATIVE_ARTIFACT_BYTES);
  }
  return { payloadSha256: digest, payloadBytes: bytes };
}
function exact(value, fields) {
  keys(value, fields);
  if (fields.some(name => !Object.hasOwn(value, name))) fail('Incomplete artifact metadata.');
}
function concatenate(parts) {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}
function size(value, width) {
  const bytes = new Uint8Array(width), view = new DataView(bytes.buffer);
  if (width === 8) view.setBigUint64(0, BigInt(value));
  else if (width === 4) view.setUint32(0, value);
  else view.setUint16(0, value);
  return bytes;
}
export async function sha256(bytes, cryptoImpl = globalThis.crypto, checkpoint = () => {}) {
  checkpoint();
  const digest = await cryptoImpl.subtle.digest('SHA-256', bytes);
  checkpoint();
  if (!(digest instanceof ArrayBuffer) || digest.byteLength !== 32) fail('SHA-256 verification is unavailable.');
  return hex(new Uint8Array(digest));
}
function retention(encoded) {
  const bytes = unhex(encoded, 1040), view = new DataView(bytes.buffer);
  switch (bytes[0]) {
    case 1:
      if (bytes.length === 9) return { bytes, label: `Ephemeral: ${view.getBigUint64(1)} seconds` };
      break;
    case 2:
      if (bytes.length === 5) return { bytes, label: `Log retention: ${view.getUint32(1)} days` };
      break;
    case 3:
      if (bytes.length === 1) return { bytes, label: 'Permanent release retention' };
      break;
    case 4:
      if (bytes.length >= 13 && view.getUint32(9) <= 1024 && bytes.length === 13 + view.getUint32(9)) {
        let reason;
        try { reason = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(13)); }
        catch { fail('Invalid retained legal-hold text.'); }
        return { bytes, label: `Legal hold ${view.getBigUint64(1)}: ${reason}` };
      }
      break;
  }
  fail('Invalid native artifact retention encoding.');
}
export async function artifactMetadata(value, selected, cryptoImpl = globalThis.crypto, checkpoint = () => {}) {
  exact(value, FIELDS);
  if (value.type !== 'artifact_metadata' || value.schema_version !== 1 || value.trust_domain !== TRUST_DOMAIN ||
      value.payload_verified !== true || value.provenance_authenticated !== false ||
      value.canonical_repository_published !== false || value.retention_enforced !== false || value.read_only !== true) {
    fail('Unsupported artifact custody metadata or authority claims.');
  }
  const metadata = Object.fromEntries(FIELDS.map(name => [name, value[name]]));
  for (const field of ['tenant_id', 'repository_id', 'repository_incarnation_id']) incarnationId(metadata[field]);
  for (const field of ['artifact_id', 'payload_sha256', 'scope_sha256']) artifactId(metadata[field]);
  for (const field of OPTIONAL_DIGESTS) if (metadata[field] !== null) artifactId(metadata[field]);
  if (metadata.artifact_id !== artifactId(selected.id) || metadata.repository_incarnation_id !== incarnationId(selected.incarnation)) {
    fail('Artifact identity or repository incarnation changed. No replacement is selected.');
  }
  integer(metadata.payload_bytes, 'native artifact payload length', 0, NATIVE_ARTIFACT_BYTES);
  if (!KINDS.includes(metadata.kind) || typeof metadata.media_type !== 'string' ||
      !/^[A-Za-z0-9/._+-]{1,128}$/.test(metadata.media_type)) fail('Invalid artifact kind or media type.');
  const pins = payloadPins(selected.pins);
  if (pins.payloadSha256 !== null && (pins.payloadSha256 !== metadata.payload_sha256 || pins.payloadBytes !== metadata.payload_bytes)) {
    fail('Artifact payload differs from the independently supplied receipt pins.');
  }
  const scope = { tenant: metadata.tenant_id, repository: metadata.repository_id,
    incarnation: metadata.repository_incarnation_id, trust: metadata.trust_domain, sha256: metadata.scope_sha256 };
  if (selected.scope && Object.keys(scope).some(name => scope[name] !== selected.scope[name])) {
    fail('Artifact custody namespace changed. Reconnect explicitly for another repository.');
  }
  const policy = retention(metadata.retention_canonical_hex), trust = utf8.encode(TRUST_DOMAIN), media = utf8.encode(metadata.media_type);
  const scopeBytes = concatenate([utf8.encode('frankengit/artifact-scope/v1\0'), unhex(scope.tenant), unhex(scope.repository),
    unhex(scope.incarnation), size(trust.length, 2), trust]);
  if (await sha256(scopeBytes, cryptoImpl, checkpoint) !== metadata.scope_sha256) fail('Artifact namespace commitment does not match its scope.');
  const identityBytes = concatenate([utf8.encode('frankengit/artifact-identity/v1\0'), unhex(metadata.payload_sha256),
    size(metadata.payload_bytes, 8), Uint8Array.of(KINDS.indexOf(metadata.kind) + 1), size(media.length, 4), media,
    ...OPTIONAL_DIGESTS.map(name => metadata[name] === null ? Uint8Array.of(0) : concatenate([Uint8Array.of(1), unhex(metadata[name])])),
    size(policy.bytes.length, 4), policy.bytes]);
  if (await sha256(identityBytes, cryptoImpl, checkpoint) !== metadata.artifact_id) fail('Artifact metadata does not reproduce the selected native identity.');
  checkpoint();
  return { metadata: copy(metadata), scope, retention: policy.label,
    artifactIdentityVerified: true, scopeCommitmentVerified: true };
}
export function sameArtifact(left, right) {
  if (FIELDS.some(name => left[name] !== right[name])) fail('Previously inspected artifact metadata changed. Inspect it explicitly again.');
}
export function visible(value) {
  return String(value).replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
    char => `\\u{${char.codePointAt(0).toString(16)}}`);
}
export function preview(bytes) {
  const prefix = bytes.subarray(0, PREVIEW_BYTES);
  let text;
  try { text = visible(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(prefix)); }
  catch { text = Array.from(prefix, byte => byte === 10 ? '\n' : byte === 9 ? '\t' : byte >= 32 && byte < 127
    ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, '0')}`).join(''); }
  return { text, shownBytes: prefix.length, totalBytes: bytes.length, clipped: prefix.length < bytes.length };
}
