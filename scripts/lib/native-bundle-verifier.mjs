// Trusted-local adapter to the existing Rust verifier, not another Git engine.
// A pathname is never used as a substitute for the owned bytes being verified.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdtemp, open, rmdir, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { performance } from 'node:perf_hooks';

export const NATIVE_BUNDLE_LIMITS = Object.freeze({
  maxInputMiB: 128, maxExpandedMiB: 128, maxObjects: 100000, maxRefs: 4096,
  timeoutMs: 300000, maxReportBytes: 2 * 1024 * 1024,
});
const MIB = 1024 * 1024;
const MAX_STDERR = 65536;
const TRUE_FIELDS = ['pack_checksum_verified', 'objects_verified', 'object_graph_verified'];
const FALSE_FIELDS = ['gitlink_targets_verified', 'signatures_verified', 'origin_authenticated',
  'current_branch_verified', 'strict_fsck_equivalent', 'repository_opened',
  'repository_changed', 'forge_state_verified'];
const COUNTS = ['bundle_bytes', 'pack_bytes', 'object_count', 'reference_count', 'payload_bytes',
  'local_edges', 'external_gitlinks', 'delta_objects', 'resolution_passes'];
const REPORT_KEYS = new Set(['type', 'schema_version', 'profile', 'object_format', 'artifact_sha256',
  'pack_checksum', 'advertised_head', 'references', 'graph_scope', 'caller_expectations_matched',
  'expectations', ...TRUE_FIELDS, ...FALSE_FIELDS, ...COUNTS]);

function fail(code, details = undefined) {
  const error = new Error(code); error.code = code;
  if (details !== undefined) error.details = details;
  return error;
}
function integer(value, minimum, maximum, code) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw fail(code);
  return value;
}
function hex(value, bytes) {
  return typeof value === 'string' && value.length === bytes * 2 && /^[0-9a-f]+$/.test(value);
}
function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function onlyKeys(value, keys) {
  return record(value) && Object.keys(value).every(key => keys.includes(key));
}
function oid(value, format) {
  return hex(value, format === 'sha1' ? 20 : 32) && !/^0+$/.test(value);
}

// This checks the bridge's option grammar and resource bounds. Native RefName
// validation, bundle framing, object identity and graph semantics belong to fg.
export function normalizeNativeBundleExpectation(value = null, maximumRefs = 4096) {
  if (value === null) return { refs: [], exact_refs: false };
  if (!onlyKeys(value, ['sha256', 'object_format', 'refs', 'exact_refs'])) throw fail('native_invalid_expectations');
  const result = { refs: [], exact_refs: value.exact_refs ?? false };
  if (typeof result.exact_refs !== 'boolean') throw fail('native_invalid_expectations');
  if (value.sha256 !== undefined) {
    if (!hex(value.sha256, 32)) throw fail('native_invalid_expected_sha256');
    result.sha256 = value.sha256;
  }
  if (value.object_format !== undefined) {
    if (!['sha1', 'sha256'].includes(value.object_format)) throw fail('native_invalid_expected_format');
    result.object_format = value.object_format;
  }
  if (value.refs !== undefined && !Array.isArray(value.refs)) throw fail('native_invalid_expected_refs');
  const refs = value.refs ?? [];
  if (refs.length > maximumRefs) throw fail('native_expected_ref_limit');
  if ((refs.length || result.exact_refs) && result.object_format === undefined) throw fail('native_expected_format_required');
  if (result.exact_refs && refs.length === 0) throw fail('native_exact_refs_require_pins');
  const names = new Set(); let nameBytes = 0;
  for (const item of refs) {
    if (!onlyKeys(item, ['ref_hex', 'object_id']) || typeof item.ref_hex !== 'string'
      || item.ref_hex.length < 2 || item.ref_hex.length > 8192 || item.ref_hex.length % 2
      || !/^[0-9a-f]+$/.test(item.ref_hex) || names.has(item.ref_hex)) throw fail('native_invalid_expected_ref');
    let id = item.object_id;
    const prefix = `${result.object_format}:`;
    if (typeof id === 'string' && id.startsWith(prefix)) id = id.slice(prefix.length);
    if (!oid(id, result.object_format)) throw fail('native_invalid_expected_oid');
    nameBytes += item.ref_hex.length / 2;
    if (nameBytes > MIB) throw fail('native_expected_ref_bytes');
    names.add(item.ref_hex); result.refs.push({ ref_hex: item.ref_hex, object_id: id });
  }
  result.refs.sort((a, b) => a.ref_hex < b.ref_hex ? -1 : a.ref_hex > b.ref_hex ? 1 : 0);
  return result;
}
/** Validate/copy a native invocation before authenticating or reading inputs.
 * No file, executable, signal listener or other resource is opened here.
 */
export function normalizeNativeBundleOptions(options) {
  if (!onlyKeys(options, ['fg', 'expected', 'signal', ...Object.keys(NATIVE_BUNDLE_LIMITS)]) || typeof options.fg !== 'string' || !isAbsolute(options.fg)
    || options.fg.length > 4096 || /[\0\r\n]/.test(options.fg)) throw fail('native_absolute_fg_path_required');
  const result = { ...NATIVE_BUNDLE_LIMITS, ...options };
  integer(result.maxInputMiB, 1, 128, 'native_input_limit');
  integer(result.maxExpandedMiB, 1, 128, 'native_expanded_limit');
  integer(result.maxObjects, 1, 100000, 'native_object_limit');
  integer(result.maxRefs, 1, 4096, 'native_ref_limit');
  integer(result.timeoutMs, 1, 3600000, 'native_timeout_limit');
  integer(result.maxReportBytes, 256, 8 * MIB, 'native_report_limit');
  if (result.signal !== undefined && !(result.signal instanceof AbortSignal)) throw fail('native_invalid_signal');
  result.expected = normalizeNativeBundleExpectation(result.expected ?? null, result.maxRefs);
  return result;
}
function lifetime(options) {
  const until = performance.now() + options.timeoutMs;
  const check = () => {
    if (options.signal?.aborted) throw fail('native_verification_cancelled');
    if (performance.now() >= until) throw fail('native_verification_deadline');
  };
  return { check, remaining: () => Math.max(1, Math.ceil(until - performance.now())) };
}
function sameFile(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mode === b.mode
    && a.uid === b.uid && a.nlink === b.nlink && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}

async function readInput(path, options, live) {
  live.check();
  if (typeof path !== 'string' || path.length === 0 || path.length > 4096 || path.includes('\0')) throw fail('native_invalid_input_path');
  const named = await lstat(path, { bigint: true }); live.check();
  if (!named.isFile() || named.size < 1n || named.size > BigInt(options.maxInputMiB * MIB)) throw fail('native_input_size_or_type');
  const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const before = await file.stat({ bigint: true }); live.check();
    if (!before.isFile() || !sameFile(named, before)) throw fail('native_input_changed');
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) {
      live.check();
      const read = await file.read(bytes, offset, Math.min(65536, bytes.length - offset), offset);
      live.check(); if (!read.bytesRead) throw fail('native_input_truncated'); offset += read.bytesRead;
    }
    const extra = Buffer.alloc(1);
    if ((await file.read(extra, 0, 1, offset)).bytesRead) throw fail('native_input_grew');
    const after = await file.stat({ bigint: true }), current = await lstat(path, { bigint: true });
    live.check();
    if (!current.isFile() || !sameFile(before, after) || !sameFile(after, current)) throw fail('native_input_changed');
    return bytes;
  } finally { await file.close(); }
}

function argumentsFor(path, digest, options, live) {
  const args = ['bundle', 'verify', '--max-input-mib', String(options.maxInputMiB),
    '--max-expanded-mib', String(options.maxExpandedMiB), '--max-objects', String(options.maxObjects),
    '--max-refs', String(options.maxRefs), '--timeout-secs', String(Math.max(1, Math.ceil(live.remaining() / 1000))),
    '--expect-sha256', digest];
  if (options.expected.object_format !== undefined) args.push('--expect-format', options.expected.object_format);
  for (const pin of options.expected.refs) args.push('--expect-ref-hex', `${pin.ref_hex}=${pin.object_id}`);
  if (options.expected.exact_refs) args.push('--exact-refs');
  args.push('--', path);
  if (args.reduce((total, argument) => total + Buffer.byteLength(argument), 0) > 2 * MIB) throw fail('native_argument_bytes');
  return args;
}

// Cancellation owns the actual process through close, not merely its Promise.
// fg is an explicitly trusted local executable, not a hostile-process sandbox.
async function runNative(path, digest, options, live) {
  live.check();
  const args = argumentsFor(path, digest, options, live);
  return await new Promise((resolve, reject) => {
    let child;
    try { child = spawn(options.fg, args, { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch { reject(fail('native_verifier_start_failed')); return; }
    const output = [], diagnostic = [];
    let outputBytes = 0, diagnosticBytes = 0, failure = null, escalation = null;
    const stop = error => {
      if (failure !== null) return;
      failure = error;
      child.kill('SIGTERM');
      escalation = setTimeout(() => child.kill('SIGKILL'), 500);
    };
    const abort = () => stop(fail('native_verification_cancelled'));
    options.signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => stop(fail('native_verification_deadline')), live.remaining());
    child.once('error', () => stop(fail('native_verifier_start_failed')));
    child.stdout.on('error', () => stop(fail('native_verifier_output_failed')));
    child.stderr.on('error', () => stop(fail('native_verifier_output_failed')));
    child.stdout.on('data', chunk => {
      if (failure !== null) return;
      outputBytes += chunk.length;
      if (outputBytes > options.maxReportBytes) { stop(fail('native_report_too_large')); return; }
      output.push(chunk);
    });
    child.stderr.on('data', chunk => {
      if (failure !== null) return;
      diagnosticBytes += chunk.length;
      if (diagnosticBytes > MAX_STDERR) { stop(fail('native_diagnostic_too_large')); return; }
      diagnostic.push(chunk);
    });
    child.once('close', (code, signal) => {
      clearTimeout(timer); clearTimeout(escalation);
      options.signal?.removeEventListener('abort', abort);
      if (failure !== null) { reject(failure); return; }
      try { live.check(); } catch (error) { reject(error); return; }
      if (code !== 0 || signal !== null) {
        reject(fail('native_verification_refused', { exit_code: code, signal,
          diagnostic: Buffer.concat(diagnostic).subarray(0, 4096).toString('utf8') })); return;
      }
      resolve(Buffer.concat(output));
    });
    // Abort can arrive between the pre-spawn checkpoint and listener install.
    if (options.signal?.aborted) abort();
  });
}
function validateReferences(refs, format, maximum) {
  if (!Array.isArray(refs) || refs.length > maximum) throw fail('native_invalid_report');
  const names = new Set(); let bytes = 0;
  for (const ref of refs) {
    if (!onlyKeys(ref, ['ref_hex', 'object_id']) || typeof ref.ref_hex !== 'string'
      || ref.ref_hex.length < 2 || ref.ref_hex.length > 8192 || ref.ref_hex.length % 2
      || !/^[0-9a-f]+$/.test(ref.ref_hex) || names.has(ref.ref_hex) || !oid(ref.object_id, format)) throw fail('native_invalid_report');
    names.add(ref.ref_hex); bytes += ref.ref_hex.length / 2;
    if (bytes > MIB) throw fail('native_invalid_report');
  }
  return new Map(refs.map(ref => [ref.ref_hex, ref.object_id]));
}
function validateReport(raw, digest, size, options) {
  let text, result;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw).trim(); result = JSON.parse(text);
  } catch { throw fail('native_invalid_report'); }
  // Native profile v1 emits compact JSON. Round-trip equality also refuses
  // duplicate object keys, trailing documents and lossy numeric spellings.
  if (!record(result) || JSON.stringify(result) !== text || Object.keys(result).some(key => !REPORT_KEYS.has(key))
    || result.type !== 'git_bundle_verification' || result.schema_version !== 1
    || result.profile !== 'native-full-bundle-graph-v1'
    || !['sha1', 'sha256'].includes(result.object_format)
    || result.artifact_sha256 !== digest || result.bundle_bytes !== size
    || result.graph_scope !== 'all-included-objects-and-advertised-direct-refs'
    || result.caller_expectations_matched !== true
    || TRUE_FIELDS.some(key => result[key] !== true) || FALSE_FIELDS.some(key => result[key] !== false)
    || COUNTS.some(key => !Number.isSafeInteger(result[key]) || result[key] < 0)) throw fail('native_invalid_report');
  if (result.pack_bytes > size || result.object_count > options.maxObjects || result.reference_count > options.maxRefs
    || result.payload_bytes > options.maxExpandedMiB * MIB || result.delta_objects > result.object_count
    || !hex(result.pack_checksum, result.object_format === 'sha1' ? 20 : 32)
    || (result.advertised_head !== null && !oid(result.advertised_head, result.object_format))) throw fail('native_invalid_report');
  const actual = validateReferences(result.references, result.object_format, options.maxRefs);
  const expected = options.expected, echo = result.expectations;
  if (!onlyKeys(echo, ['artifact_sha256', 'object_format', 'ref_set', 'references'])
    || echo.artifact_sha256 !== digest || echo.object_format !== (expected.object_format ?? null)
    || echo.ref_set !== (expected.refs.length ? expected.exact_refs ? 'exact' : 'contains' : null)
    || (expected.object_format !== undefined && result.object_format !== expected.object_format)) throw fail('native_expectation_report_mismatch');
  const echoed = validateReferences(echo.references, result.object_format, options.maxRefs);
  if (echoed.size !== expected.refs.length || (expected.exact_refs && actual.size !== expected.refs.length)
    || expected.refs.some(ref => actual.get(ref.ref_hex) !== ref.object_id || echoed.get(ref.ref_hex) !== ref.object_id)) throw fail('native_expectation_report_mismatch');
  return { ...result, verifier_backend: 'native-fg',
    caller_identity_pins_supplied: expected.sha256 !== undefined || expected.refs.length !== 0,
    input_snapshot_sha256: digest };
}

async function verifyOwned(bytes, options, live) {
  live.check();
  if (bytes.length < 1 || bytes.length > options.maxInputMiB * MIB) throw fail('native_input_size_or_type');
  const digest = createHash('sha256').update(bytes).digest('hex'); live.check();
  if (options.expected.sha256 !== undefined && options.expected.sha256 !== digest) throw fail('native_expected_sha256_mismatch');
  const directory = await mkdtemp(join(tmpdir(), 'fg-native-verify-'));
  let directoryIdentity, fileIdentity, file;
  const path = join(directory, 'input.bundle');
  try {
    directoryIdentity = await lstat(directory, { bigint: true }); live.check();
    if (!directoryIdentity.isDirectory() || (process.platform !== 'win32' && (directoryIdentity.mode & 0o077n))) throw fail('native_private_directory_required');
    file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    fileIdentity = await file.stat({ bigint: true });
    let offset = 0;
    while (offset < bytes.length) {
      live.check();
      const { bytesWritten } = await file.write(bytes, offset, Math.min(65536, bytes.length - offset), offset);
      live.check(); if (bytesWritten === 0) throw fail('native_snapshot_write_failed'); offset += bytesWritten;
    }
    // Keep the owned inode pinned until cleanup, including while fg reads it.
    await file.sync(); live.check();
    const result = await runNative(path, digest, options, live);
    live.check();
    const report = validateReport(result, digest, bytes.length, options);
    live.check(); return report;
  } finally {
    // The open descriptor prevents inode recycling during identity checks.
    // The private directory is a trusted-local namespace, not a same-UID sandbox.
    try {
      const currentDirectory = await lstat(directory, { bigint: true });
      if (directoryIdentity === undefined || !currentDirectory.isDirectory()
        || currentDirectory.dev !== directoryIdentity.dev || currentDirectory.ino !== directoryIdentity.ino) throw fail('native_snapshot_cleanup_refused');
      if (fileIdentity !== undefined) {
        const current = await lstat(path, { bigint: true });
        if (!current.isFile() || current.dev !== fileIdentity.dev || current.ino !== fileIdentity.ino
          || current.nlink !== 1n) throw fail('native_snapshot_cleanup_refused');
        await unlink(path);
      }
      // Windows needs the descriptor closed before removing its parent.
      if (file !== undefined) { const owned = file; file = undefined; await owned.close(); }
      await rmdir(directory);
    } finally {
      if (file !== undefined) await file.close();
    }
  }
}

/** Verify exactly these bytes through an explicitly selected local fg binary.
 * Copies mutable input and constraints before the first await. A successful
 * report attests native content checks only, not signer/origin/currentness.
 */
export async function verifyNativeGitBundle(bytes, options) {
  const config = normalizeNativeBundleOptions(options), live = lifetime(config); live.check();
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1 || bytes.byteLength > config.maxInputMiB * MIB) throw fail('native_input_size_or_type');
  if (bytes.buffer instanceof SharedArrayBuffer) throw fail('native_shared_input_refused');
  const owned = Buffer.from(bytes); live.check();
  return await verifyOwned(owned, config, live);
}

/** One quiescent local file read, one owned snapshot, one child, one deadline.
 * No fallback, source-path reopening by fg, Git executable, or node mutation.
 */
export async function verifyNativeGitBundleFile(path, options) {
  const config = normalizeNativeBundleOptions(options), live = lifetime(config); live.check();
  const bytes = await readInput(path, config, live);
  return await verifyOwned(bytes, config, live);
}
