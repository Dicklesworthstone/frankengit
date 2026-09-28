#!/usr/bin/env node
// Offline product boundary: read one bounded bundle and print verifiable facts.
// No Git executable, server, working tree, network, or repository writes.
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { readAuthenticatedSourceBackup } from './lib/source-attestation.mjs';
import { SourceAttestationOptions, ATTESTATION_HELP } from './lib/source-attestation-options.mjs';
import { BUNDLE_VERIFY_LIMITS, verifyGitBundle, verifyGitBundleAgainst, normalizeBundleExpectation } from '../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs';

async function readBounded(path, signal) {
  signal.throwIfAborted();
  const file = await open(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > BUNDLE_VERIFY_LIMITS.maxInputBytes) throw new Error('bundle_file_size_or_type');
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
`;
function argumentsFor(args) {
  let path = null, literal = false; const expected = {}, seen = new Set(), signed = new SourceAttestationOptions();
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && arg.startsWith('-')) {
      const next = signed.take(args, index); if (next !== index) { index = next; continue; }
      if (arg === '--exact-refs') {
        if (seen.has(arg)) throw new Error('duplicate_option'); seen.add(arg); expected.exact_refs = true; continue;
      }
      if (!['--expect-sha256', '--expect-format', '--expect-ref', '--expect-ref-hex'].includes(arg)) throw new Error('unknown_option');
      const value = args[++index];
      if (!value || value.startsWith('--')) throw new Error('missing_option_value');
      if (arg === '--expect-ref' || arg === '--expect-ref-hex') {
        const split = value.lastIndexOf('=');
        if (split < 1 || split === value.length - 1 || value.length > 8300) throw new Error('invalid_reference_pin');
        const name = value.slice(0, split), object_id = value.slice(split + 1);
        if (arg === '--expect-ref' && /[\uD800-\uDFFF]/u.test(name)) throw new Error('invalid_reference_pin');
        const ref_hex = arg === '--expect-ref-hex' ? name : Buffer.from(name, 'utf8').toString('hex');
        expected.refs ??= [];
        if (expected.refs.length >= BUNDLE_VERIFY_LIMITS.maxRefs) throw new Error('expectation_reference_limit');
        expected.refs.push({ ref_hex, object_id });
      } else {
        if (seen.has(arg)) throw new Error('duplicate_option'); seen.add(arg);
        expected[arg === '--expect-sha256' ? 'sha256' : 'object_format'] = value;
      }
    } else {
      if (path !== null || !arg) throw new Error('one_bundle_path_required'); path = arg;
    }
  }
  if (path === null) throw new Error('bundle_path_required');
  // Validate the complete expectation grammar before opening even the input.
  if (Object.keys(expected).length) normalizeBundleExpectation(expected);
  return { path, expected: Object.keys(expected).length ? expected : null, attestation: signed.finish() };
}
const args = process.argv.slice(2), controller = new AbortController();
const cancel = () => controller.abort(); process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
// A broken output pipe is a command failure, not an unhandled stream event.
const outputError = () => { process.exitCode = 1; }; process.stdout.on('error', outputError); process.stderr.on('error', outputError);
try {
  let output;
  if (args.length === 1 && args[0] === '--help') output = USAGE;
  else {
    const { path, expected, attestation } = argumentsFor(args);
    const signed = attestation === null ? null : await readAuthenticatedSourceBackup(path,
      attestation.envelope, attestation.key, attestation.policy, { signal: controller.signal });
    // Use exactly the authenticated bytes. Never reopen the path after checking
    // the signature or let an approval bypass object/closure and explicit pins.
    const bytes = signed === null ? await readBounded(path, controller.signal) : signed.bytes;
    const options = { cryptoImpl: webcrypto, signal: controller.signal };
    const result = expected === null ? await verifyGitBundle(bytes, options) : await verifyGitBundleAgainst(bytes, expected, options);
    signed?.checkCurrent();
    if (signed !== null) result.source_attestation = signed.authentication;
    output = `${JSON.stringify(result, null, 2)}\n`;
  }
  await new Promise((resolve, reject) => process.stdout.write(output, error => error ? reject(error) : resolve()));
} catch (error) {
  const code = error?.code ?? (typeof error?.message === 'string' ? error.message : 'verification_failed');
  process.stderr.write(`${JSON.stringify({ verified: false, error: code, details: error?.details ?? null })}\n`); process.exitCode = 1;
} finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
