#!/usr/bin/env node
// Offline product boundary: read one bounded bundle and print verifiable facts.
// No Git executable, server, working tree, network, or repository writes.
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { ATTESTATION_LIMITS, readAuthenticatedSourceBackup } from './lib/source-attestation.mjs';
import { SourceAttestationOptions, ATTESTATION_HELP } from './lib/source-attestation-options.mjs';
import { NATIVE_BUNDLE_LIMITS, normalizeNativeBundleOptions, verifyNativeGitBundle, verifyNativeGitBundleFile } from './lib/native-bundle-verifier.mjs';

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
The executable is operator-trusted; its build is not authenticated here. Both
signed and unsigned native inputs retain this command's 16 MiB input ceiling.
Native processing uses bounded private temporary storage and reaps its child on
cancellation. The input hash sent to fg binds a snapshot, not independent trust.
Without --native-fg, the existing JavaScript profile and report remain selected.
`;
async function argumentsFor(args) {
  if (args.length > 8224 || args.reduce((sum, arg) => sum + Buffer.byteLength(arg), 0) > 2 * 1024 * 1024
    || args.some(arg => arg.length > 8300 || arg.includes('\0'))) throw new Error('argument_limit');
  let nativeFg = null, nativeTimeoutMs = NATIVE_BUNDLE_LIMITS.timeoutMs;
  let path = null, literal = false; const expected = {}, seen = new Set(), signed = new SourceAttestationOptions();
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && arg.startsWith('-')) {
      const next = signed.take(args, index); if (next !== index) { index = next; continue; }
      if (arg === '--exact-refs') {
        if (seen.has(arg)) throw new Error('duplicate_option'); seen.add(arg); expected.exact_refs = true; continue;
      }
      if (!['--expect-sha256', '--expect-format', '--expect-ref', '--expect-ref-hex', '--native-fg', '--native-timeout-secs'].includes(arg)) throw new Error('unknown_option');
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
        } else expected[arg === '--expect-sha256' ? 'sha256' : 'object_format'] = value;
      }
    } else {
      if (path !== null || !arg) throw new Error('one_bundle_path_required'); path = arg;
    }
  }
  if (path === null) throw new Error('bundle_path_required');
  const attestation = signed.finish(), expectation = Object.keys(expected).length ? expected : null;
  if (nativeFg === null && seen.has('--native-timeout-secs')) throw new Error('native_fg_required_for_timeout');
  // Native selection never loads the legacy Git decoder, even for parsing pins.
  // Both backends validate all options before any input/authentication file I/O.
  if (nativeFg !== null) {
    const native = normalizeNativeBundleOptions({ fg: nativeFg, expected: expectation,
      maxInputMiB: ATTESTATION_LIMITS.bundleBytes / (1024 * 1024), timeoutMs: nativeTimeoutMs });
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
try {
  let output;
  if (args.length === 1 && args[0] === '--help') output = USAGE;
  else {
    const { path, expected, attestation, native, legacy } = await argumentsFor(args);
    if (native !== null) {
      nativeDeadline = performance.now() + native.timeoutMs;
      nativeTimer = setTimeout(() => controller.abort(), native.timeoutMs);
    }
    const signed = attestation === null ? null : await readAuthenticatedSourceBackup(path,
      attestation.envelope, attestation.key, attestation.policy, { signal: controller.signal });
    // Use exactly the authenticated bytes. Never reopen the path after checking
    // the signature or let an approval bypass object/closure and explicit pins.
    let result;
    if (native !== null) {
      nativeCheckpoint();
      const options = { ...native, signal: controller.signal,
        timeoutMs: Math.max(1, Math.ceil(nativeDeadline - performance.now())) };
      result = signed === null ? await verifyNativeGitBundleFile(path, options)
        : await verifyNativeGitBundle(signed.bytes, options);
      nativeCheckpoint();
    } else {
      const bytes = signed === null ? await readBounded(path, controller.signal, legacy.BUNDLE_VERIFY_LIMITS) : signed.bytes;
      const options = { cryptoImpl: webcrypto, signal: controller.signal };
      result = expected === null ? await legacy.verifyGitBundle(bytes, options) : await legacy.verifyGitBundleAgainst(bytes, expected, options);
    }
    signed?.checkCurrent();
    if (signed !== null) result.source_attestation = signed.authentication;
    output = `${JSON.stringify(result, null, 2)}\n`;
    if (native !== null) { nativeCheckpoint(); signed?.checkCurrent(); }
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
