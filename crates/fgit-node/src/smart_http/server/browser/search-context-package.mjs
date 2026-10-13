// Portable selected source, not an authority receipt or a complete repository.
// Only the caller's independent root/selection is trusted during offline replay.
import { copy, form, hex, integer, keys, oid, unhex, utf8 } from './pulls-core.mjs';
import { fields, filePage, PAGE_BYTES } from './search-data.mjs';
import { acquireContextMembership, contextMembershipSelection, membershipLimits,
  MEMBERSHIP_PROFILE, verifyMembershipProof } from './search-context-membership.mjs';

export const SOURCE_PACKAGE_PROFILE = 'frankengit-selected-source-package-v1';
export const SOURCE_PACKAGE_BYTES = 32 * 1024 * 1024;
export const SOURCE_PACKAGE_LIMITS = Object.freeze({ maxSourceBytes: 8 * 1024 * 1024, maxBlobRequests: 160 });
const fail = message => { throw new Error(`Source package: ${message}`); };
function exact(value, names) {
  keys(value, names);
  if (names.some(name => !Object.hasOwn(value, name))) fail('missing field.');
  return value;
}
function hexLength(value, max) {
  if (typeof value !== 'string' || value.length > max * 2 || value.length % 2 || /[^0-9a-f]/u.test(value)) fail('invalid or oversized bytes.');
  return value.length / 2;
}
function encodeBody(value, check) {
  const chunks = [];
  for (let at = 0; at < value.length; at += 4096) { check(); chunks.push(hex(value.subarray(at, at + 4096))); }
  check(); return chunks.join('');
}
function decodeBody(value, check) {
  const bytes = new Uint8Array(value.length / 2);
  for (let at = 0; at < value.length; at += 8192) { check(); bytes.set(unhex(value.slice(at, at + 8192), 4096), at / 2); }
  check(); return bytes;
}
function normalized(value, format) {
  const id = oid(value, format);
  if (id !== value) fail('package identities must use canonical bare digests.');
  return id;
}
export function sourcePackageLimits(input = {}) {
  keys(input, ['membership', ...Object.keys(SOURCE_PACKAGE_LIMITS)]);
  return { membership: membershipLimits(input.membership), ...Object.fromEntries(Object.entries(SOURCE_PACKAGE_LIMITS)
    .map(([name, max]) => [name, integer(Object.hasOwn(input, name) ? input[name] : max, name, 1, max)])) };
}
// Resource-check every owned primitive before cloning or asynchronous hashing.
// The existing membership verifier still owns Git parsing, topology and hashes.
function ownPackage(value, input) {
  exact(value, ['schema', 'membership', 'blobs']);
  if (value.schema !== SOURCE_PACKAGE_PROFILE) fail('unsupported schema.');
  const limits = sourcePackageLimits(input), proof = exact(value.membership, ['schema', 'objectFormat', 'commit', 'trees', 'files']);
  if (proof.schema !== MEMBERSHIP_PROFILE || !['sha1', 'sha256'].includes(proof.objectFormat)) fail('unsupported membership proof.');
  exact(proof.commit, ['oid', 'bodyHex']); normalized(proof.commit.oid, proof.objectFormat); hexLength(proof.commit.bodyHex, 65536);
  if (!Array.isArray(proof.trees) || !proof.trees.length || proof.trees.length > limits.membership.maxTrees ||
      !Array.isArray(proof.files) || !proof.files.length || proof.files.length > 32 ||
      !Array.isArray(value.blobs) || !value.blobs.length || value.blobs.length > 32) fail('invalid package inventory.');
  let treeBytes = 0, pathBytes = 0, uniqueBytes = 0, logicalBytes = 0;
  const needed = new Map(), supplied = new Map();
  for (const tree of proof.trees) {
    exact(tree, ['pathHex', 'oid', 'bodyHex']);
    if (tree.pathHex !== null) hexLength(tree.pathHex, 4096);
    normalized(tree.oid, proof.objectFormat);
    treeBytes += hexLength(tree.bodyHex, limits.membership.maxTreeBytes);
    if (treeBytes > limits.membership.maxTreeBytes) fail('parent-tree bytes exceed the package limit.');
  }
  for (const file of proof.files) {
    exact(file, ['pathHex', 'blob', 'kind']);
    pathBytes += hexLength(file.pathHex, 4096); normalized(file.blob, proof.objectFormat);
    if (pathBytes > 32768 || !['file', 'executable'].includes(file.kind)) fail('invalid selected file.');
    needed.set(file.blob, (needed.get(file.blob) ?? 0) + 1);
  }
  let previous = '';
  for (const raw of value.blobs) {
    exact(raw, ['oid', 'bytesHex']); const id = normalized(raw.oid, proof.objectFormat);
    if (id <= previous || !needed.has(id)) fail('duplicate, unordered or unselected blob.');
    previous = id;
    const size = hexLength(raw.bytesHex, limits.maxSourceBytes);
    uniqueBytes += size; logicalBytes += size * needed.get(id);
    if (uniqueBytes > limits.maxSourceBytes || logicalBytes > limits.maxSourceBytes) fail('complete selected source exceeds its byte limit.');
    supplied.set(id, size);
  }
  if (supplied.size !== needed.size) fail('missing selected blob body.');
  return { value: copy(value), limits, uniqueBytes, logicalBytes };
}
async function blobHash(bytes, format, crypto, check) {
  check(); const prefix = utf8.encode(`blob ${bytes.length}\0`), framed = new Uint8Array(prefix.length + bytes.length);
  framed.set(prefix); framed.set(bytes, prefix.length);
  const actual = hex(new Uint8Array(await crypto.subtle.digest(format === 'sha1' ? 'SHA-1' : 'SHA-256', framed)));
  check(); return actual;
}
function host(crypto, check) {
  if (!crypto?.subtle || typeof check !== 'function') fail('missing verification host.');
  check();
}
async function verifyOwned(owned, expected, crypto, check) {
  const { value, limits } = owned;
  // This call captures its independently supplied expected file set before the
  // first await. Package fields cannot choose the root or widen that selection.
  const membership = await verifyMembershipProof(value.membership, expected, crypto, check, limits.membership);
  const blobs = new Map();
  for (const raw of value.blobs) {
    check(); const bytes = decodeBody(raw.bytesHex, check);
    if (await blobHash(bytes, value.membership.objectFormat, crypto, check) !== raw.oid) fail('complete native blob hash mismatch.');
    blobs.set(raw.oid, bytes);
  }
  check();
  return { profile: SOURCE_PACKAGE_PROFILE, commit: membership.commit, rootTree: membership.rootTree,
    commitMembershipVerified: true, blobBytesVerified: true, sourceMaterialUntrusted: true,
    authorityVerified: false, freshnessVerified: false, signatureVerified: false,
    searchCoverageVerified: false, declarationSemanticsVerified: false, completeRepository: false,
    logicalSourceBytes: owned.logicalBytes, uniqueSourceBytes: owned.uniqueBytes,
    files: membership.files.map(file => ({ ...file, sourceBytes: blobs.get(file.blob).length })),
    trees: membership.trees, entries: membership.entries, treeBytes: membership.treeBytes };
}
export async function verifySourcePackage(value, expected, crypto = globalThis.crypto, check = () => {}, input = {}) {
  host(crypto, check); const owned = ownPackage(value, input);
  return verifyOwned(owned, expected, crypto, check);
}
export async function readSourcePackage(bytes, expected, crypto = globalThis.crypto, check = () => {}, input = {}) {
  host(crypto, check);
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > SOURCE_PACKAGE_BYTES) fail('choose one bounded package.');
  // Decoding and JSON parsing finish before any await; no caller buffer survives.
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  const owned = ownPackage(value, input); check();
  const verified = await verifyOwned(owned, expected, crypto, check); check();
  return { package: owned.value, verified };
}
export async function encodeSourcePackage(value, expected, crypto = globalThis.crypto, check = () => {}, input = {}) {
  host(crypto, check); const owned = ownPackage(value, input);
  const verified = await verifyOwned(owned, expected, crypto, check); check();
  const serialized = JSON.stringify(owned.value);
  if (serialized.length > SOURCE_PACKAGE_BYTES || utf8.encode(serialized).length > SOURCE_PACKAGE_BYTES) fail('encoded package exceeds its byte limit.');
  check(); return { serialized, verified };
}
export function contextPackageCost(result, independentCommit, input = {}) {
  const limits = sourcePackageLimits(input);
  const expected = contextMembershipSelection(result, independentCommit, limits.membership);
  const fileLimit = integer(result.query.maxFileBytes, 'navigation byte limit', 1, SOURCE_PACKAGE_LIMITS.maxSourceBytes);
  let sourceBytes = 0, blobRequests = 0;
  for (const file of result.context.files) {
    sourceBytes += integer(file.sourceBytes, 'complete file size', 0, fileLimit);
    blobRequests += Math.max(1, Math.ceil(file.sourceBytes / PAGE_BYTES));
  }
  if (sourceBytes > limits.maxSourceBytes || blobRequests > limits.maxBlobRequests) fail('complete selection exceeds its budget; nothing was read.');
  return { expected, limits, sourceBytes, blobRequests };
}
// One caller-owned deadline spans membership, every full-file page, hashing and
// serialization. No data is returned until the complete selected package passes.
export async function acquireContextPackage(result, reference, independentCommit, request,
  crypto = globalThis.crypto, check = () => {}, input = {}) {
  host(crypto, check);
  const cost = contextPackageCost(result, independentCommit, input);
  if (typeof request !== 'function') fail('missing pinned source reader.');
  // Retain only source coordinates, sizes and expected identities. Query prose,
  // scores, credentials and server-supplied success flags never enter the package.
  const basis = copy({ query: { mode: 'initial', maxFileBytes: result.query.maxFileBytes },
    scope: result.scope, pin: result.pin, vector: result.vector,
    context: { files: result.context.files.map(({ pathHex, blob, sourceBytes }) => ({ pathHex, blob, sourceBytes })) } });
  const member = await acquireContextMembership(basis, reference, cost.expected.commit, request, crypto, check, cost.limits.membership);
  check(); const blobs = new Map(); let requests = 0, readBytes = 0;
  for (let i = 0; i < basis.context.files.length; i++) {
    check(); const file = basis.context.files[i], committed = member.verified.files[i];
    let offset = 0, bytes = null;
    do {
      check(); if (++requests > cost.limits.maxBlobRequests) fail('blob request limit exceeded.');
      const reply = await request('source/blob', { method: 'POST', body: form({
        ...fields({ reference, format: basis.scope.format }, basis.pin), path_hex: file.pathHex, offset, limit: PAGE_BYTES }),
        maximum: PAGE_BYTES * 2 + 65536 });
      check(); const page = filePage(reply.value, { reference, format: basis.scope.format }, basis, file, offset, file.sourceBytes);
      if (page.kind !== committed.kind) fail('blob mode differs from committed membership.');
      if (bytes === null) bytes = new Uint8Array(page.total);
      bytes.set(page.bytes, offset); readBytes += page.bytes.length; offset = page.next;
    } while (offset !== null);
    if (await blobHash(bytes, basis.scope.format, crypto, check) !== file.blob) fail('complete native blob hash mismatch.');
    // Dedup only the serialized bodies. Every selected path still spends its
    // full logical-byte budget and its own freshly authorized pinned page reads.
    const encoded = encodeBody(bytes, check), previous = blobs.get(file.blob);
    if (previous !== undefined && previous !== encoded) fail('conflicting bytes for one native identity.');
    blobs.set(file.blob, encoded);
  }
  if (requests !== cost.blobRequests || readBytes !== cost.sourceBytes) fail('complete source accounting changed.');
  const value = { schema: SOURCE_PACKAGE_PROFILE, membership: member.proof,
    blobs: [...blobs].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([id, bytesHex]) => ({ oid: id, bytesHex })) };
  const encoded = await encodeSourcePackage(value, cost.expected, crypto, check, cost.limits); check();
  return { package: value, ...encoded, limits: cost.limits,
    metrics: { metadataRequests: member.requests, blobRequests: requests, sourceBytesRead: readBytes } };
}
