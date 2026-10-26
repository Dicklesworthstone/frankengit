// Adapt native verifier layouts to the existing filesystem owner. Native Rust
// remains the only bundle/pack/delta/object decoder on these explicit paths.
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { normalizeNativeBundleOptions, normalizeNativeRecoveryHead, verifyNativeGitBundle,
  withVerifiedNativeGitBundleFile } from './native-bundle-verifier.mjs';

const MIB = 1024 * 1024, CHUNK_BYTES = 65536;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function fail(code) { const error = new Error(code); error.code = code; throw error; }
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function normalizeNativeRecoveryRequest(request) {
  if (!record(request) || Object.keys(request).some(key => !['head_ref_hex', 'expectations'].includes(key))) fail('native_invalid_recovery_request');
  return normalizeNativeRecoveryHead(request.head_ref_hex);
}

function capture(request, options, fileBacked) {
  const head = normalizeNativeRecoveryRequest(request);
  const allowed = ['fg', 'signal', 'timeoutMs', 'approvalBinding'];
  if (fileBacked) allowed.push('maxInputMiB', 'maxExpandedMiB', 'maxBlobMiB', 'maxObjects', 'maxRefs', 'artifact');
  if (!record(options) || Object.keys(options).some(key => !allowed.includes(key))) fail('native_invalid_recovery_options');
  const { approvalBinding, artifact, ...native } = options;
  if (approvalBinding !== undefined && (typeof approvalBinding !== 'string' || !/^[0-9a-f]{64}$/.test(approvalBinding))) fail('native_invalid_approval_binding');
  let authenticated;
  if (artifact !== undefined) {
    if (!record(artifact) || Object.keys(artifact).some(key => !['sha256', 'bytes'].includes(key))
      || typeof artifact.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(artifact.sha256)) fail('native_invalid_artifact');
    if (!Number.isSafeInteger(artifact.bytes) || artifact.bytes < 1) fail('native_invalid_expected_bytes');
    authenticated = { sha256: artifact.sha256, bytes: artifact.bytes };
  }
  const config = normalizeNativeBundleOptions({ ...native, recoveryHead: head, fileBacked,
    expected: request.expectations ?? null,
    maxInputMiB: fileBacked && native.maxInputMiB !== undefined ? native.maxInputMiB : 16,
    ...(authenticated === undefined ? {} : { expectedBytes: authenticated.bytes }) });
  if (authenticated !== undefined && config.expected.sha256 !== undefined
    && config.expected.sha256 !== authenticated.sha256) fail('native_expected_sha256_mismatch');
  const until = performance.now() + config.timeoutMs;
  const check = () => {
    if (config.signal?.aborted) fail('native_recovery_cancelled');
    if (performance.now() >= until) fail('native_recovery_deadline');
  };
  return { head, approvalBinding, authenticated, config, check,
    remaining: () => Math.max(1, Math.ceil(until - performance.now())) };
}

function layoutPlan(report, head, expected, approvalBinding, pack, check) {
  const layout = report.recovery, format = report.object_format, width = format === 'sha1' ? 20 : 32;
  const digest = value => createHash(format).update(value).digest();
  const checksum = Buffer.from(report.pack_checksum, 'hex');
  // Envelope consistency only. Native Rust owns index structure/CRC/offsets,
  // object reconstruction and closure checks. Do not implement a second reader.
  const index = Buffer.from(layout.index_hex, 'hex');
  if (pack.length < 12 + width || index.length < 8 + 1024 + 2 * width
    || !index.subarray(-2 * width, -width).equals(checksum)
    || !digest(index.subarray(0, -width)).equals(index.subarray(-width))) fail('native_recovery_layout_binding');
  const packedRefs = Buffer.from(layout.packed_refs_hex, 'hex');
  const references = report.references.map(row => ({ ...row }))
    .sort((a, b) => a.ref_hex < b.ref_hex ? -1 : a.ref_hex > b.ref_hex ? 1 : 0);
  const expectedRefs = [Buffer.from('# pack-refs with: sorted\n')];
  for (const row of references) {
    check();
    const name = Buffer.from(row.ref_hex, 'hex');
    if (name.some(byte => byte === 0 || byte === 10 || byte === 13)) fail('native_recovery_layout_binding');
    expectedRefs.push(Buffer.from(`${row.object_id} `), name, Buffer.from('\n'));
  }
  const configBytes = Buffer.from(format === 'sha1'
    ? '[core]\n\trepositoryformatversion = 0\n\tbare = true\n'
    : '[core]\n\trepositoryformatversion = 1\n\tbare = true\n[extensions]\n\tobjectformat = sha256\n');
  const headBytes = Buffer.concat([Buffer.from('ref: '), Buffer.from(head, 'hex'), Buffer.from('\n')]);
  if (!packedRefs.equals(Buffer.concat(expectedRefs)) || layout.config_hex !== configBytes.toString('hex')
    || layout.head_hex !== headBytes.toString('hex')) fail('native_recovery_layout_binding');
  const stem = `objects/pack/pack-${report.pack_checksum}`;
  const directories = ['objects', 'objects/pack', 'refs', 'refs/heads', 'refs/tags'];
  const files = [{ path: `${stem}.pack`, bytes: pack }, { path: `${stem}.idx`, bytes: index },
    { path: 'packed-refs', bytes: packedRefs }, { path: 'config', bytes: configBytes }, { path: 'HEAD', bytes: headBytes }];
  // Storage profile and independently authenticated byte pins are not new
  // intent fields. Keep the exact v1 shape and original caller expectations so
  // the same source, approval and request can resume across storage profiles.
  const receipt = { schema: 'frankengit-native-source-recovery-plan-v1', object_format: format,
    artifact_sha256: report.artifact_sha256, artifact_bytes: report.bundle_bytes, head_ref_hex: head,
    references, expectations: expected, directories,
    files: files.map(file => ({ path: file.path, bytes: file.bytes.length,
      sha256: file.bytes instanceof Uint8Array ? sha256(file.bytes) : file.bytes.sha256 })) };
  // A local resume identity, NOT proof of approval. The signed CLI supplies
  // this only after authenticating and repeats authentication on every resume.
  if (approvalBinding !== undefined) receipt.approval_sha256 = approvalBinding;
  const plan_sha256 = sha256(Buffer.from(JSON.stringify(receipt)));
  const { recovery: _layout, ...verification } = report;
  check(); return { directories, files, receipt, plan_sha256, verification };
}

/** Verify an owned in-memory snapshot once with the Rust engine, then bind all
 * layout bytes to a deterministic local plan. Existing byte limits are fixed.
 */
export async function prepareNativeGitBundleRecovery(input, request, options) {
  const { head, approvalBinding, config, check } = capture(request, options, false);
  if (!(input instanceof Uint8Array) || !input.length || input.length > 16 * MIB
    || input.buffer instanceof SharedArrayBuffer) fail('native_recovery_input_limit');
  const bytes = Buffer.from(input); check();
  const report = await verifyNativeGitBundle(bytes, config);
  check();
  const pack = bytes.subarray(report.recovery.pack_offset), format = report.object_format;
  const width = format === 'sha1' ? 20 : 32;
  if (pack.length < 12 + width || pack.subarray(-width).toString('hex') !== report.pack_checksum
    || !createHash(format).update(pack.subarray(0, -width)).digest().equals(pack.subarray(-width))) {
    fail('native_recovery_layout_binding');
  }
  return layoutPlan(report, head, config.expected, approvalBinding, pack, check);
}

function streamedPack(snapshot) {
  const { report, size } = snapshot, offset = report.recovery.pack_offset, length = report.pack_bytes;
  const format = report.object_format, width = format === 'sha1' ? 20 : 32, payloadLength = length - width;
  if (length < 12 + width || offset + length !== size) fail('native_recovery_layout_binding');
  return Object.freeze({ length, sha256: report.pack_sha256,
    async *chunks(check) {
      if (typeof check !== 'function') fail('native_recovery_checkpoint_required');
      const artifact = createHash('sha256'), native = createHash(format), trailer = Buffer.alloc(width);
      let position = 0;
      while (position < length) {
        await check();
        const bytes = await snapshot.read(offset + position, Math.min(CHUNK_BYTES, length - position));
        await check();
        artifact.update(bytes);
        const contentBytes = Math.max(0, Math.min(bytes.length, payloadLength - position));
        if (contentBytes) native.update(bytes.subarray(0, contentBytes));
        if (contentBytes < bytes.length) bytes.subarray(contentBytes).copy(trailer, Math.max(0, position - payloadLength));
        position += bytes.length;
        yield bytes;
      }
      // Never report a successful EOF until this replay independently checks
      // the complete pack digest, its native trailer, and the retained inode.
      await check(); await snapshot.read(size, 0); await check();
      if (artifact.digest('hex') !== report.pack_sha256 || trailer.toString('hex') !== report.pack_checksum
        || !native.digest().equals(trailer)) fail('native_recovery_layout_binding');
    } });
}

/** Lend a verified file-backed recovery plan to the existing publication owner.
 * Only PACK is streamed; all metadata/index bytes stay bounded and owned.
 * The callback owns effect-time checks and must finish before the snapshot is
 * revoked. No cancellation check may reinterpret its completed publication.
 */
export async function withNativeGitBundleFileRecovery(input, request, options, consumePlan) {
  const { head, approvalBinding, authenticated, config, check, remaining } = capture(request, options, true);
  if (typeof consumePlan !== 'function') fail('native_invalid_consumer');
  check();
  const expected = config.expected;
  return await withVerifiedNativeGitBundleFile(input, { ...config, timeoutMs: remaining(),
    expected: authenticated === undefined ? expected : { ...expected, sha256: authenticated.sha256 } },
  async snapshot => {
    check();
    const width = snapshot.report.object_format === 'sha1' ? 20 : 32;
    const trailer = await snapshot.read(snapshot.size - width, width);
    check();
    if (trailer.toString('hex') !== snapshot.report.pack_checksum) fail('native_recovery_layout_binding');
    const pack = streamedPack(snapshot);
    const plan = layoutPlan(snapshot.report, head, expected, approvalBinding, pack, check);
    // Independently bind the reported pack digest/trailer before the owner may
    // create a destination. Later replays each repeat this bounded check.
    for await (const _chunk of pack.chunks(check)) { /* discard verified chunks */ }
    check(); return await consumePlan(plan);
  });
}
