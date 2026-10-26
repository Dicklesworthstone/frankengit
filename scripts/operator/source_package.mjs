// Selected-source acquisition for the existing offline verifier and verified-edit
// consumer. Saved search coordinates are candidates, never verification receipts.
import { createHash, webcrypto } from 'node:crypto';
import { prepareNativePackageRead, verifyNativePackageRead } from './source_package_native.mjs';
import { Transport, keys, oid, principal, rootFor, snapshot, integer } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { coordinates, selection as sourceSelection, pathHex, FILE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/search-data.mjs';
import { acquireContextPackage, contextPackageCost, readSourcePackage, sourcePackageLimits,
  SOURCE_PACKAGE_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';

export const PACKAGE_CONTEXT_BYTES = 12 * 1024 * 1024;
export { SOURCE_PACKAGE_BYTES };
const fail = message => { throw new Error(`Source package acquisition: ${message}`); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function exact(value, names, required = names) {
  keys(value, names);
  if (required.some(name => !Object.hasOwn(value, name))) fail('missing field.');
}
function pinned(bytes, expected, maximum) {
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > maximum ||
      typeof expected !== 'string' || !/^[0-9a-f]{64}$/.test(expected) || hash(bytes) !== expected) {
    fail('input differs from its independently retained hash or byte bound.');
  }
}
export function packageAcquisitionLimits(value = {}) {
  exact(value, ['timeoutMs', 'package'], []);
  return { timeoutMs: integer(value.timeoutMs ?? 30000, 'package operation deadline', 1, 300000),
    package: sourcePackageLimits(value.package) };
}
// Accept the same operator selection fields as source-context/source-archive.
// Reuse the browser's route, native-ref, identity and snapshot validators. Do not
// take a network address or expected commit from a saved server response.
export function packageAcquisitionSelection(value) {
  const names = ['endpoint', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'ref', 'expected_commit'];
  exact(value, [...names, 'expected_head'], names);
  if (typeof value.endpoint !== 'string' || value.endpoint.length > 4096 || /[\s\\]/u.test(value.endpoint)) fail('invalid endpoint.');
  const root = rootFor(`${value.endpoint}/ui/search/`, '/ui/search/');
  const url = new URL(value.endpoint);
  if (`${root.origin}${root.route}` !== value.endpoint || url.href !== value.endpoint ||
      (url.protocol === 'http:' && !['127.0.0.1', '[::1]'].includes(url.hostname))) fail('use a canonical HTTPS or numeric-loopback endpoint.');
  const selected = sourceSelection(value.ref, value.object_format);
  return { endpoint: value.endpoint, tenant_id: principal(value.tenant_id), repository_id: principal(value.repository_id),
    repository_incarnation: principal(value.repository_incarnation), ref: selected.reference, object_format: selected.format,
    expected_commit: oid(value.expected_commit, selected.format), expected_head: value.expected_head == null ? null : snapshot(value.expected_head) };
}
function parseContext(bytes) {
  try {
    // Preserve full-width generation numbers as their original spelling. They
    // are not source coordinates, and this operation makes no index claim.
    return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), (_key, value, context) =>
      typeof value === 'number' && !Number.isSafeInteger(value) ? context.source : value);
  } catch { fail('invalid saved context JSON.'); }
}
function expectedSelection(value, format, commit, files) {
  exact(value, ['format', 'commit', 'files']);
  if (value.format !== format || oid(value.commit, format) !== commit || !Array.isArray(value.files) || value.files.length !== files.length) {
    fail('independent expected selection differs from the saved context.');
  }
  return { format, commit, files: value.files.map((file, at) => {
    exact(file, ['pathHex', 'blob']);
    if (file.pathHex !== files[at].pathHex || oid(file.blob, format) !== files[at].blob) fail('independent path/blob selection changed.');
    return { pathHex: file.pathHex, blob: files[at].blob };
  }) };
}
function contextPlan(contextBytes, contextHash, selection, expected, limits, check) {
  check(); pinned(contextBytes, contextHash, PACKAGE_CONTEXT_BYTES);
  const selected = packageAcquisitionSelection(selection);
  let context = parseContext(contextBytes); check();
  if (context?.schema === 'frankengit-source-context-capture-v1') {
    if (context.endpoint !== selected.endpoint) fail('saved context endpoint differs from independent selection.');
    context = context.native_response;
  }
  const source = context?.retrieval;
  if (context?.type !== 'source_context_initial' || context.schema_version !== 1 || context.profile !== 'source-initial-context-v1' ||
      context.read_only !== true || context.transaction_created !== false || context.source_material_untrusted !== true ||
      source?.type !== 'source_search_initial' || source.schema_version !== 1 || source.profile !== 'source-initial-retrieval-v1' ||
      !Array.isArray(context.files) || context.files.length < 1 || context.files.length > 32 || context.returned_files !== context.files.length) {
    fail('choose a nonempty saved native Initial context.');
  }
  const scope = { tenant: selected.tenant_id, repository: selected.repository_id,
    incarnation: selected.repository_incarnation, format: selected.object_format };
  const observed = coordinates(source, sourceSelection(selected.ref, selected.object_format), scope);
  if (observed.pin.commit !== selected.expected_commit || (selected.expected_head !== null && observed.pin.head !== selected.expected_head)) {
    fail('saved context changed the independently selected commit or snapshot.');
  }
  let excerptCount = 0, excerptBytes = 0;
  const files = context.files.map(row => {
    check();
    const file = { pathHex: pathHex(row?.path_hex), blob: oid(row?.blob, selected.object_format),
      sourceBytes: integer(row?.source_bytes, 'complete selected file bytes', 0, FILE_LIMIT) };
    if (!Array.isArray(row.excerpts) || !row.excerpts.length || row.excerpts.length > 128) fail('invalid excerpt inventory.');
    let lastOffset = -1, end = 0;
    file.excerpts = row.excerpts.map(part => {
      check(); exact(part, ['byte_offset', 'untrusted_bytes_hex']);
      const offset = integer(part.byte_offset, 'excerpt offset', 0, file.sourceBytes), hex = part.untrusted_bytes_hex;
      if (typeof hex !== 'string' || hex.length > 2 * 1024 * 1024 || hex.length % 2 || /[^0-9a-f]/u.test(hex) ||
          offset <= lastOffset || offset < end || hex.length / 2 > file.sourceBytes - offset ||
          ++excerptCount > 128 || (excerptBytes += hex.length / 2) > 1024 * 1024) fail('invalid excerpt extent or aggregate budget.');
      lastOffset = offset; end = offset + hex.length / 2;
      return { offset, hex };
    });
    return file;
  }).sort((a, b) => a.pathHex < b.pathHex ? -1 : a.pathHex > b.pathHex ? 1 : 0);
  const independent = expectedSelection(expected, selected.object_format, selected.expected_commit, files);
  // This is a source-only projection, NOT a validated Initial search result.
  // No rankings, declaration semantics or generation vector enter the package.
  const basis = { query: { mode: 'initial', maxFileBytes: FILE_LIMIT }, ...observed, vector: null,
    context: { files: files.map(({ pathHex, blob, sourceBytes }) => ({ pathHex, blob, sourceBytes })) } };
  const cost = contextPackageCost(basis, independent.commit, limits.package); check();
  return { selected, independent, basis, files, excerptCount, excerptBytes, cost, contextHash };
}
function checkExcerpts(value, verified, plan, check) {
  const blobs = new Map(value.blobs.map(row => [row.oid, row.bytesHex]));
  for (let at = 0; at < plan.files.length; at++) {
    check(); const wanted = plan.files[at], actual = verified.files[at];
    if (actual.pathHex !== wanted.pathHex || actual.blob !== wanted.blob || actual.sourceBytes !== wanted.sourceBytes) fail('complete source differs from saved context.');
    const body = blobs.get(wanted.blob);
    for (const excerpt of wanted.excerpts) {
      check();
      if (body.slice(excerpt.offset * 2, excerpt.offset * 2 + excerpt.hex.length) !== excerpt.hex) fail('saved excerpt differs from the verified complete blob.');
    }
  }
}
function receipt(bytes, verified, plan) {
  return { type: 'selected_source_package', schema_version: 1, context_sha256: plan.contextHash,
    package_sha256: hash(bytes), package_bytes: bytes.length,
    expected_selection_sha256: hash(Buffer.from(JSON.stringify(plan.independent))),
    verified, context_excerpt_bytes_verified: true, excerpt_count: plan.excerptCount, excerpt_bytes: plan.excerptBytes,
    search_evidence_verified: false, remote_mutation_attempted: false, source_executed: false };
}
function operation(options, allowNative = false) {
  exact(options, ['limits', 'signal', ...(allowNative ? ['nativeFg'] : [])], []);
  const limits = packageAcquisitionLimits(options.limits), signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('invalid cancellation signal.');
  const deadline = performance.now() + limits.timeoutMs;
  const check = () => { signal?.throwIfAborted(); if (performance.now() >= deadline) fail('total operation deadline exceeded.'); };
  check(); return { limits, signal, check, deadline, nativeFg: options.nativeFg };
}
// Read exactly the previously captured selection, with a fresh native permission
// check on every page. No retries, source refresh, extraction or mutation lane.
export async function captureSourcePackage(contextBytes, contextHash, selected, expected, token, options = {}) {
  const { limits, signal, check, deadline, nativeFg } = operation(options, true);
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') fail('TLS verification must not be disabled.');
  const plan = contextPlan(contextBytes, contextHash, selected, expected, limits, check);
  const native = nativeFg === undefined ? null : await prepareNativePackageRead(nativeFg, plan, limits.package.maxBlobRequests, check);
  const transport = new Transport({ href: `${plan.selected.endpoint}/ui/search/`, pageSuffix: '/ui/search/',
    cryptoImpl: webcrypto, timeoutMs: limits.timeoutMs });
  const stop = () => transport.disconnect();
  signal?.addEventListener('abort', stop, { once: true });
  const timer = setTimeout(stop, Math.max(1, deadline - performance.now()));
  try {
    check(); await transport.connect(token); check();
    const result = await acquireContextPackage(plan.basis, plan.selected.ref, plan.independent.commit,
      async (path, options) => { check(); const reply = await transport.request(path, options); check(); return reply; },
      webcrypto, check, limits.package);
    checkExcerpts(result.package, result.verified, plan, check); check();
    const nativeRead = native === null ? null : await verifyNativePackageRead(native, plan, result.package, result.verified, token, deadline, signal, check);
    check();
    const bytes = Buffer.from(result.serialized); check();
    return { bytes, receipt: { ...receipt(bytes, result.verified, plan), ...(nativeRead === null ? {} : { native_read: nativeRead }) },
      metrics: { ...result.metrics, ...(nativeRead === null ? {} : { nativeProofRequests: nativeRead.files }) } };
  } finally {
    clearTimeout(timer); signal?.removeEventListener('abort', stop); transport.disconnect();
  }
}
// Offline replay also verifies the ORIGINAL saved excerpts, not only package
// commitments. Expected files and both retained input hashes remain separate.
export async function inspectSourcePackage(bytes, packageHash, contextBytes, contextHash, selected, expected, options = {}) {
  const { limits, check } = operation(options);
  const plan = contextPlan(contextBytes, contextHash, selected, expected, limits, check);
  pinned(bytes, packageHash, SOURCE_PACKAGE_BYTES); check();
  // Capture the byte receipt before the first await; the verifier owns its copy.
  const owned = Buffer.from(bytes);
  const result = await readSourcePackage(owned, plan.independent, webcrypto, check, limits.package);
  checkExcerpts(result.package, result.verified, plan, check); check();
  return receipt(owned, result.verified, plan);
}
