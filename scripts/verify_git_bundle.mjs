#!/usr/bin/env node
// Offline product boundary: read one bounded bundle and print verifiable facts.
// No Git executable, server, working tree, network, or repository writes.
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { ATTESTATION_LIMITS, readAttestationFile, readAuthenticatedSourceBackup, verifySourceAttestation } from './lib/source-attestation.mjs';
import { SourceAttestationOptions, ATTESTATION_HELP } from './lib/source-attestation-options.mjs';
import { NATIVE_BUNDLE_LIMITS, normalizeNativeBundleOptions, verifyNativeGitBundleFile } from './lib/native-bundle-verifier.mjs';

const MIB = 1024 * 1024;

async function readBounded(path, signal, limits) {
  signal.throwIfAborted();
  const file = await open(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > limits.maxInputBytes) throw new Error('bundle_file_size_or_type');
    const bytes = new Uint8Array(stat.size); let offset = 0;
    while (offset < bytes.length) {
      signal.throwIfAborted();
      const { bytesRead } = await file.read(bytes, offset, Math.min(65536, bytes.length - offset), offset);
      if (!bytesRead) throw new Error('bundle_file_truncated'); offset += bytesRead;
    }
    const extra = new Uint8Array(1);
    if ((await file.read(extra, 0, 1, bytes.length)).bytesRead) throw new Error('bundle_file_grew');
    return bytes;
  } finally { await file.close(); }
}
const USAGE = `Usage: node scripts/verify_git_bundle.mjs PATH.bundle [OPTIONS]

Verify a complete local Git bundle without Git, network, or repository writes.
  --native-fg PATH          Use this absolute-path native Rust fg executable
  --native-timeout-secs N    Whole native operation, 1..3600 (default 300)
  --native-file-backed       Stream a private snapshot to native file-backed verification
  --native-max-input-mib N   Input ceiling (default 16; file-backed maximum 16384)
  --native-max-expanded-mib N Expanded payload ceiling (default 128; same maximum)
  --native-max-blob-mib N    Streamed blob/base/result ceiling (default 32; file-backed only)
Optional expectations must come from a separately trusted source:
  --expect-sha256 HEX         Exact SHA-256 of the entire bundle
  --expect-format sha1|sha256 Required when supplying native reference pins
  --expect-ref REF=OID        Repeat for each known full native reference
  --expect-ref-hex HEX=OID    Lossless byte-name alternative (lowercase hex)
  --exact-refs               Require exactly the supplied direct-ref set
${ATTESTATION_HELP}  --                        Treat the remaining argument as a literal path
  --help                    Print this help without opening a file

Without --exact-refs, ref pins constrain only the named refs; all advertised
refs still undergo closure verification. An unsigned adjacent manifest is not
an independent trust anchor. All four attestation options are required together;
failed authentication never falls back to unsigned mode. A detached source
approval is separate from Git author/signature, forge-state and gitlink checks.

--native-fg selects the existing Rust verifier, not another Git implementation.
It does not load the JavaScript Git decoder and never falls back on failure.
The executable is operator-trusted; its build is not authenticated here. Signed
and unsigned native inputs default to a 16 MiB input ceiling. Explicit native
limits may select up to 128 MiB in memory, or up to 16384 MiB with the explicit
file-backed profile. File-backed mode owns its private snapshot and scratch; it
does not raise object, reference, report or individual-object memory limits.
--native-max-blob-mib permits larger blobs and blob delta bases/results in that
profile. Total expansion, metadata, delta-program and work limits remain separate.
Native processing reaps its child on cancellation. The input hash sent to fg
binds a snapshot. Independent pins constrain content identity; a detached
approval authenticates the separately trusted signer.
Without --native-fg, the existing JavaScript profile and report remain selected.
`;
async function argumentsFor(args) {
  if (args.length > 8224 || args.reduce((sum, arg) => sum + Buffer.byteLength(arg), 0) > 2 * 1024 * 1024
    || args.some(arg => arg.length > 8300 || arg.includes('\0'))) throw new Error('argument_limit');
  let nativeFg = null, nativeTimeoutMs = NATIVE_BUNDLE_LIMITS.timeoutMs, nativeFileBacked = false;
  let nativeMaxInputMiB = ATTESTATION_LIMITS.bundleBytes / MIB, nativeMaxExpandedMiB = NATIVE_BUNDLE_LIMITS.maxExpandedMiB;
  let nativeMaxBlobMiB = NATIVE_BUNDLE_LIMITS.maxBlobMiB;
  let path = null, literal = false; const expected = {}, seen = new Set(), signed = new SourceAttestationOptions();
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && arg.startsWith('-')) {
      const next = signed.take(args, index); if (next !== index) { index = next; continue; }
      if (arg === '--exact-refs' || arg === '--native-file-backed') {
        if (seen.has(arg)) throw new Error('duplicate_option'); seen.add(arg);
        if (arg === '--exact-refs') expected.exact_refs = true; else nativeFileBacked = true;
        continue;
      }
      if (!['--expect-sha256', '--expect-format', '--expect-ref', '--expect-ref-hex', '--native-fg', '--native-timeout-secs',
        '--native-max-input-mib', '--native-max-expanded-mib', '--native-max-blob-mib'].includes(arg)) throw new Error('unknown_option');
      const value = args[++index];
      if (!value || value.startsWith('--')) throw new Error('missing_option_value');
      if (arg === '--expect-ref' || arg === '--expect-ref-hex') {
        const split = value.lastIndexOf('=');
        if (split < 1 || split === value.length - 1 || value.length > 8300) throw new Error('invalid_reference_pin');
        const name = value.slice(0, split), object_id = value.slice(split + 1);
        if (arg === '--expect-ref' && /[\uD800-\uDFFF]/u.test(name)) throw new Error('invalid_reference_pin');
        const ref_hex = arg === '--expect-ref-hex' ? name : Buffer.from(name, 'utf8').toString('hex');
        expected.refs ??= [];
        if (expected.refs.length >= NATIVE_BUNDLE_LIMITS.maxRefs) throw new Error('expectation_reference_limit');
        expected.refs.push({ ref_hex, object_id });
      } else {
        if (seen.has(arg)) throw new Error('duplicate_option'); seen.add(arg);
        if (arg === '--native-fg') nativeFg = value;
        else if (arg === '--native-timeout-secs') {
          if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > 3600) throw new Error('native_timeout_limit');
          nativeTimeoutMs = Number(value) * 1000;
        } else if (['--native-max-input-mib', '--native-max-expanded-mib', '--native-max-blob-mib'].includes(arg)) {
          if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value))) {
            const codes = { '--native-max-input-mib': 'native_input_limit',
              '--native-max-expanded-mib': 'native_expanded_limit', '--native-max-blob-mib': 'native_blob_limit' };
            throw new Error(codes[arg]);
          }
          if (arg === '--native-max-input-mib') nativeMaxInputMiB = Number(value);
          else if (arg === '--native-max-expanded-mib') nativeMaxExpandedMiB = Number(value);
          else nativeMaxBlobMiB = Number(value);
        } else expected[arg === '--expect-sha256' ? 'sha256' : 'object_format'] = value;
      }
    } else {
      if (path !== null || !arg) throw new Error('one_bundle_path_required'); path = arg;
    }
  }
  if (path === null) throw new Error('bundle_path_required');
  const attestation = signed.finish(), expectation = Object.keys(expected).length ? expected : null;
  if (nativeFg === null && seen.has('--native-timeout-secs')) throw new Error('native_fg_required_for_timeout');
  if (nativeFg === null && ['--native-file-backed', '--native-max-input-mib', '--native-max-expanded-mib', '--native-max-blob-mib'].some(flag => seen.has(flag))) {
    throw new Error('native_fg_required_for_file_limits');
  }
  if (seen.has('--native-max-blob-mib') && !nativeFileBacked) throw new Error('native_blob_limit_requires_file_profile');
  // Native selection never loads the legacy Git decoder, even for parsing pins.
  // Both backends validate all options before any input/authentication file I/O.
  if (nativeFg !== null) {
    const native = normalizeNativeBundleOptions({ fg: nativeFg, expected: expectation, fileBacked: nativeFileBacked,
      maxInputMiB: nativeMaxInputMiB, maxExpandedMiB: nativeMaxExpandedMiB,
      maxBlobMiB: nativeMaxBlobMiB, timeoutMs: nativeTimeoutMs });
    return { path, attestation, native, legacy: null, expected: expectation };
  }
  const legacy = await import('../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs');
  if ((expectation?.refs?.length ?? 0) > legacy.BUNDLE_VERIFY_LIMITS.maxRefs) throw new Error('expectation_reference_limit');
  if (expectation !== null) legacy.normalizeBundleExpectation(expectation);
  return { path, attestation, native: null, legacy, expected: expectation };
}
const args = process.argv.slice(2), controller = new AbortController();
const cancel = () => controller.abort(); process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
// A broken output pipe is a command failure, not an unhandled stream event.
const outputError = () => { controller.abort(); process.exitCode = 1; }; process.stdout.on('error', outputError); process.stderr.on('error', outputError);
let nativeTimer, nativeDeadline = null;
function nativeCheckpoint() {
  if (nativeDeadline !== null && performance.now() >= nativeDeadline) throw new Error('native_verification_deadline');
  controller.signal.throwIfAborted();
}
// Authenticate only the small controls before the artifact is opened. The
// native file adapter then hashes exactly one owned snapshot against this pin;
// there is no second full-file copy or approval of a later pathname reopening.
async function readNativeApproval(attestation, native) {
  nativeCheckpoint();
  const policy = { ...attestation.policy }, options = { signal: controller.signal, maximumBytes: native.maxInputMiB * MIB };
  const encoded = await readAttestationFile(attestation.envelope, ATTESTATION_LIMITS.envelopeBytes, { signal: controller.signal });
  nativeCheckpoint();
  const key = await readAttestationFile(attestation.key, ATTESTATION_LIMITS.keyBytes, { signal: controller.signal });
  nativeCheckpoint();
  // Recheck the captured original envelope, key and policy, never the mutable
  // adjacent paths or the returned display record. This also rechecks expiry.
  const checkCurrent = async () => {
    nativeCheckpoint();
    const authentication = await verifySourceAttestation(encoded, key, policy, options);
    nativeCheckpoint(); return authentication;
  };
  const authentication = await checkCurrent();
  const artifact = { ...authentication.statement.artifact };
  if (native.expected.sha256 !== undefined && native.expected.sha256 !== artifact.sha256) {
    throw new Error('native_expected_sha256_mismatch');
  }
  return { authentication, artifact, checkCurrent };
}
try {
  let output;
  if (args.length === 1 && args[0] === '--help') output = USAGE;
  else {
    const { path, expected, attestation, native, legacy } = await argumentsFor(args);
    if (native !== null) {
      nativeDeadline = performance.now() + native.timeoutMs;
      nativeTimer = setTimeout(() => controller.abort(), native.timeoutMs);
    }
    const signed = attestation === null ? null : native === null
      ? await readAuthenticatedSourceBackup(path, attestation.envelope, attestation.key, attestation.policy, { signal: controller.signal })
      : await readNativeApproval(attestation, native);
    // An authenticated artifact still undergoes the complete native content
    // checks and every independent format/ref pin. The legacy byte API is intact.
    let result;
    if (native !== null) {
      nativeCheckpoint();
      const options = { ...native, signal: controller.signal,
        expected: signed === null ? native.expected : { ...native.expected, sha256: signed.artifact.sha256 },
        timeoutMs: Math.max(1, Math.ceil(nativeDeadline - performance.now())) };
      result = await verifyNativeGitBundleFile(path, options);
      nativeCheckpoint();
      if (signed !== null && result.bundle_bytes !== signed.artifact.bytes) throw new Error('attestation_artifact_mismatch');
    } else {
      const bytes = signed === null ? await readBounded(path, controller.signal, legacy.BUNDLE_VERIFY_LIMITS) : signed.bytes;
      const options = { cryptoImpl: webcrypto, signal: controller.signal };
      result = expected === null ? await legacy.verifyGitBundle(bytes, options) : await legacy.verifyGitBundleAgainst(bytes, expected, options);
    }
    await signed?.checkCurrent();
    if (signed !== null) result.source_attestation = signed.authentication;
    output = `${JSON.stringify(result, null, 2)}\n`;
    if (native !== null) { nativeCheckpoint(); await signed?.checkCurrent(); nativeCheckpoint(); }
  }
  await new Promise((resolve, reject) => process.stdout.write(output, error => error ? reject(error) : resolve()));
} catch (error) {
  const code = nativeDeadline !== null && performance.now() >= nativeDeadline ? 'native_verification_deadline'
    : error?.code ?? (typeof error?.message === 'string' ? error.message : 'verification_failed');
  process.stderr.write(`${JSON.stringify({ verified: false, error: code, details: error?.details ?? null })}\n`); process.exitCode = 1;
} finally {
  clearTimeout(nativeTimer);
  process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel);
}
