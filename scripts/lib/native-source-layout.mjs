// Adapt the native verifier's fixed recovery layout to the existing filesystem
// owner. No bundle/pack/delta/object decoder and no caller-supplied file paths.
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { normalizeNativeBundleOptions, normalizeNativeRecoveryHead, verifyNativeGitBundle } from './native-bundle-verifier.mjs';

const MIB = 1024 * 1024;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function fail(code) { const error = new Error(code); error.code = code; throw error; }
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function normalizeNativeRecoveryRequest(request) {
  if (!record(request) || Object.keys(request).some(key => !['head_ref_hex', 'expectations'].includes(key))) fail('native_invalid_recovery_request');
  return normalizeNativeRecoveryHead(request.head_ref_hex);
}

/** Verify an owned snapshot once with the Rust engine, then bind all layout
 * bytes to a deterministic local plan. This grants no repository authority.
 * The native executable is operator-trusted, not authenticated by its report.
 */
export async function prepareNativeGitBundleRecovery(input, request, options) {
  const head = normalizeNativeRecoveryRequest(request);
  if (!record(options) || Object.keys(options).some(key => !['fg', 'signal', 'timeoutMs'].includes(key))) fail('native_invalid_recovery_options');
  const config = normalizeNativeBundleOptions({ ...options, recoveryHead: head,
    expected: request.expectations ?? null, maxInputMiB: 16 });
  // Capture all mutable inputs/constraints before the first await. The caller
  // cannot change the snapshot after validation or extend a copied deadline.
  if (!(input instanceof Uint8Array) || !input.length || input.length > 16 * MIB
    || input.buffer instanceof SharedArrayBuffer) fail('native_recovery_input_limit');
  const bytes = Buffer.from(input), until = performance.now() + config.timeoutMs;
  const check = () => {
    if (config.signal?.aborted) fail('native_recovery_cancelled');
    if (performance.now() >= until) fail('native_recovery_deadline');
  };
  check();
  const report = await verifyNativeGitBundle(bytes, config);
  check();
  const layout = report.recovery, format = report.object_format;
  const pack = bytes.subarray(layout.pack_offset), width = format === 'sha1' ? 20 : 32;
  const digest = value => createHash(format).update(value).digest();
  // Envelope consistency only. Native Rust owns index structure/CRC/offsets,
  // object reconstruction and closure checks. Do not implement a second reader.
  const index = Buffer.from(layout.index_hex, 'hex');
  if (pack.length < 12 + width || index.length < 8 + 1024 + 2 * width
    || pack.subarray(-width).toString('hex') !== report.pack_checksum
    || !digest(pack.subarray(0, -width)).equals(pack.subarray(-width))
    || !index.subarray(-2 * width, -width).equals(pack.subarray(-width))
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
  const receipt = { schema: 'frankengit-native-source-recovery-plan-v1', object_format: format,
    artifact_sha256: report.artifact_sha256, artifact_bytes: bytes.length, head_ref_hex: head,
    references, expectations: config.expected, directories,
    files: files.map(file => ({ path: file.path, bytes: file.bytes.length, sha256: sha256(file.bytes) })) };
  const plan_sha256 = sha256(Buffer.from(JSON.stringify(receipt)));
  // Large hex payloads are not copied into the durable marker or user receipt.
  const { recovery: _layout, ...verification } = report;
  check(); return { directories, files, receipt, plan_sha256, verification };
}
