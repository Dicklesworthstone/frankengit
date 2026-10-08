#!/usr/bin/env node
// Explicit, trusted-local source materialization. No automatic restore or retry.
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { recoverGitBundle } from './lib/source-recovery.mjs';
import { ATTESTATION_LIMITS, readAttestationFile, readAuthenticatedSourceBackup } from './lib/source-attestation.mjs';
import { SourceAttestationOptions, ATTESTATION_HELP } from './lib/source-attestation-options.mjs';
import { NATIVE_BUNDLE_LIMITS, normalizeNativeBundleOptions } from './lib/native-bundle-verifier.mjs';
import { normalizeNativeRecoveryRequest } from './lib/native-source-layout.mjs';

const HELP = `Usage: node scripts/recover_git_bundle.mjs INPUT.bundle NEW_DIRECTORY --head REF [OPTIONS]

Verify all objects and history, then create a new bare Git repository.
Requires an existing trusted parent directory. By default the destination must
be absent. --resume continues only this exact operation's private directory;
it never truncates mismatching files or replaces a published HEAD.
This is Git source recovery, not FrankenGit forge/authority/capsule restore.

  --native-fg PATH           Select an absolute-path trusted native Rust fg build
  --native-timeout-secs N    Whole native recovery, 1..300 seconds (default 60)
  --resume                   Resume an exact interrupted recovery, never overwrite
  --head REF                 Explicit advertised refs/heads/... for HEAD
  --head-hex HEX             Byte-exact hexadecimal alternative to --head
  --expect-sha256 HEX        Separately trusted hash of the entire bundle
  --expect-format sha1|sha256 Native hash domain for any ref pins
  --expect-ref REF=OID       Repeat for independently known native ref tips
  --expect-ref-hex HEX=OID   Raw-byte reference pin
  --exact-refs               Reject additional advertised direct refs
${ATTESTATION_HELP}  --                        Remaining arguments are literal paths
  --help                    Print help without opening files

Input is bounded to 16 MiB; expanded object data to 128 MiB. No Git executable,
network, hooks or checkout is used. HEAD is installed last. On failure, any
incomplete destination is retained and its publication state is reported.
Resume requires the same host/PID namespace and refuses live or unknown owners;
it is not arbitrary repair, a force option or distributed lock takeover.
Supply all four attestation options to require an externally trusted approval.
Authentication is repeated for --resume, even after an earlier published HEAD.
A failed approval never downgrades to unsigned recovery or changes the target.

--native-fg delegates Git parsing and layout derivation to the Rust engine; the
existing filesystem owner stages and publishes HEAD last. No JavaScript Git
decoder is loaded on this path, and native failures never cause fallback.
Native signed resume requires the same authenticated approval and trust policy;
those are part of its saved plan identity, not authority learned from a marker.
A native plan cannot resume a legacy plan. Without --native-fg, the existing
legacy backend remains selected. The native executable is operator-trusted.
`;
async function parse(args) {
  if (args.length > 8240 || args.some(arg => arg.length > 8300 || arg.includes('\0'))
    || args.reduce((sum, arg) => sum + Buffer.byteLength(arg), 0) > 2 * 1024 * 1024) throw new Error('argument_limit');
  let nativeFg = null, nativeTimeoutMs = 60000;
  const paths = [], expected = {}, seen = new Set(), signed = new SourceAttestationOptions(); let head = null, literal = false, resume = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && arg.startsWith('-')) {
      const next = signed.take(args, i); if (next !== i) { i = next; continue; }
      if (arg === '--resume') { if (resume) throw new Error('duplicate_option'); resume = true; continue; }
      if (arg === '--exact-refs') {
        if (seen.has(arg)) throw new Error('duplicate_option'); seen.add(arg); expected.exact_refs = true; continue;
      }
      if (!['--head', '--head-hex', '--expect-sha256', '--expect-format', '--expect-ref', '--expect-ref-hex', '--native-fg', '--native-timeout-secs'].includes(arg)) throw new Error('unknown_option');
      const value = args[++i]; if (!value || value.startsWith('--') || value.length > 8300) throw new Error('invalid_option_value');
      const encode = text => { if (/[\uD800-\uDFFF]/u.test(text)) throw new Error('invalid_unicode'); return Buffer.from(text).toString('hex'); };
      if (arg === '--head' || arg === '--head-hex') {
        if (head !== null) throw new Error('duplicate_head'); head = arg === '--head' ? encode(value) : value;
      } else if (arg === '--expect-ref' || arg === '--expect-ref-hex') {
        const at = value.lastIndexOf('='); if (at < 1 || at === value.length - 1) throw new Error('invalid_reference_pin');
        expected.refs ??= []; if (expected.refs.length >= NATIVE_BUNDLE_LIMITS.maxRefs) throw new Error('expectation_reference_limit');
        expected.refs.push({ ref_hex: arg === '--expect-ref' ? encode(value.slice(0, at)) : value.slice(0, at), object_id: value.slice(at + 1) });
      } else {
        if (seen.has(arg)) throw new Error('duplicate_option'); seen.add(arg);
        if (arg === '--native-fg') nativeFg = value;
        else if (arg === '--native-timeout-secs') {
          if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > 300) throw new Error('native_timeout_limit');
          nativeTimeoutMs = Number(value) * 1000;
        } else expected[arg === '--expect-sha256' ? 'sha256' : 'object_format'] = value;
      }
    } else paths.push(arg);
  }
  if (paths.length !== 2 || paths.some(path => !path)) throw new Error('input_and_new_destination_required');
  if (head === null || !head.startsWith('726566732f68656164732f')) throw new Error('explicit_branch_head_required');
  const attestation = signed.finish(), request = { head_ref_hex: head, ...(Object.keys(expected).length ? { expectations: expected } : {}) };
  if (nativeFg === null && seen.has('--native-timeout-secs')) throw new Error('native_fg_required_for_timeout');
  let legacyLimits = null;
  if (nativeFg !== null) {
    normalizeNativeRecoveryRequest(request);
    normalizeNativeBundleOptions({ fg: nativeFg, expected: request.expectations ?? null,
      recoveryHead: head, maxInputMiB: 16, timeoutMs: nativeTimeoutMs });
  } else {
    const legacy = await import('../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs');
    const { bundleRef } = await import('../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs');
    bundleRef(head);
    if ((expected.refs?.length ?? 0) > legacy.BUNDLE_VERIFY_LIMITS.maxRefs) throw new Error('expectation_reference_limit');
    if (Object.keys(expected).length) legacy.normalizeBundleExpectation(expected);
    legacyLimits = legacy.BUNDLE_VERIFY_LIMITS;
  }
  return { input: paths[0], destination: paths[1], resume, attestation, request, nativeFg, nativeTimeoutMs, legacyLimits };
}
async function readBundle(path, signal, limits) {
  signal.throwIfAborted(); const file = await open(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > limits.maxInputBytes) throw new Error('bundle_file_size_or_type');
    const bytes = new Uint8Array(stat.size); let offset = 0;
    while (offset < bytes.length) {
      signal.throwIfAborted(); const { bytesRead } = await file.read(bytes, offset, Math.min(65536, bytes.length - offset), offset);
      if (!bytesRead) throw new Error('bundle_file_truncated'); offset += bytesRead;
    }
    if ((await file.read(new Uint8Array(1), 0, 1, bytes.length)).bytesRead) throw new Error('bundle_file_grew');
    return bytes;
  } finally { await file.close(); }
}
const controller = new AbortController(), cancel = () => controller.abort();
process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
const pipeError = () => { controller.abort(); process.exitCode = 1; }; process.stdout.on('error', pipeError); process.stderr.on('error', pipeError);
let result = null, resumeDestination = null, nativeTimer, nativeDeadline = null;
function nativeCheckpoint() {
  if (nativeDeadline !== null && performance.now() >= nativeDeadline) throw new Error('recovery_deadline');
  controller.signal.throwIfAborted();
}
try {
  const args = process.argv.slice(2); let output;
  if (args.length === 1 && args[0] === '--help') output = HELP;
  else {
    const { input, destination, request, resume, attestation, nativeFg, nativeTimeoutMs, legacyLimits } = await parse(args);
    if (resume) resumeDestination = destination;
    if (nativeFg !== null) {
      nativeDeadline = performance.now() + nativeTimeoutMs;
      nativeTimer = setTimeout(() => controller.abort(), nativeTimeoutMs);
    }
    const signed = attestation === null ? null : await readAuthenticatedSourceBackup(input,
      attestation.envelope, attestation.key, attestation.policy, { signal: controller.signal });
    // Authentication and downstream native verification consume the SAME owned
    // bytes. Neither the CLI nor fg reopens the original signed source path.
    const bytes = signed !== null ? signed.bytes : nativeFg !== null
      ? await readAttestationFile(input, ATTESTATION_LIMITS.bundleBytes, { signal: controller.signal })
      : await readBundle(input, controller.signal, legacyLimits);
    nativeCheckpoint();
    const native = nativeFg === null ? {} : { nativeFg,
      timeoutMs: Math.max(1, Math.ceil(nativeDeadline - performance.now())),
      ...(signed === null ? {} : { nativeApprovalBinding: createHash('sha256')
        .update(JSON.stringify(signed.authentication)).digest('hex') }) };
    result = await recoverGitBundle(bytes, destination, request, { signal: controller.signal, resume, ...native,
      ...(signed === null ? {} : { onProgress(event) {
        // No destination write occurs before verified. Check again when starting
        // prepublication validation. After HEAD is visible, finalize responsibility
        // even if the approval expires; expiry never retroactively rolls it back.
        if (event.phase === 'verified' || event.phase === 'before_publication' || event.phase === 'publication_ready') signed.checkCurrent();
      } }) });
    if (signed !== null) result.source_attestation = signed.authentication;
    output = JSON.stringify(result, null, 2) + '\n';
  }
  await new Promise((resolve, reject) => process.stdout.write(output, error => error ? reject(error) : resolve()));
} catch (error) {
  process.stderr.write(JSON.stringify({ type: 'frankengit-source-recovery-error-v1',
    code: error.code ?? error.message ?? 'recovery_failed',
    state: result?.state ?? (resumeDestination !== null && (!error.state || error.state === 'not_created') ? 'existing_unknown' : error.state ?? 'not_created'),
    destination: result?.destination ?? error.destination ?? resumeDestination, cleanup_error: error.lock_cleanup_error ?? null }) + '\n'); process.exitCode = 1;
} finally { clearTimeout(nativeTimer); process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
