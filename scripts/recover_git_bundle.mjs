#!/usr/bin/env node
// Explicit, trusted-local source materialization. No automatic restore or retry.
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { recoverGitBundle } from './lib/source-recovery.mjs';
import { BUNDLE_VERIFY_LIMITS, normalizeBundleExpectation } from '../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs';
import { bundleRef } from '../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';

const HELP = `Usage: node scripts/recover_git_bundle.mjs INPUT.bundle NEW_DIRECTORY --head REF [OPTIONS]

Verify all objects and history, then create a new bare Git repository.
Requires an existing trusted parent directory. Never overwrites any destination.
This is Git source recovery, not FrankenGit forge/authority/capsule restore.

  --head REF                 Explicit advertised refs/heads/... for HEAD
  --head-hex HEX             Byte-exact hexadecimal alternative to --head
  --expect-sha256 HEX        Separately trusted hash of the entire bundle
  --expect-format sha1|sha256 Native hash domain for any ref pins
  --expect-ref REF=OID       Repeat for independently known native ref tips
  --expect-ref-hex HEX=OID   Raw-byte reference pin
  --exact-refs               Reject additional advertised direct refs
  --                        Remaining arguments are literal paths
  --help                    Print help without opening files

Input is bounded to 16 MiB; expanded object data to 128 MiB. No Git executable,
network, hooks or checkout is used. HEAD is installed last. On failure, any
incomplete destination is retained and its publication state is reported.
`;
function parse(args) {
  const paths = [], expected = {}, seen = new Set(); let head = null, literal = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && arg.startsWith('-')) {
      if (arg === '--exact-refs') {
        if (seen.has(arg)) throw new Error('duplicate_option'); seen.add(arg); expected.exact_refs = true; continue;
      }
      if (!['--head', '--head-hex', '--expect-sha256', '--expect-format', '--expect-ref', '--expect-ref-hex'].includes(arg)) throw new Error('unknown_option');
      const value = args[++i]; if (!value || value.startsWith('--') || value.length > 8300) throw new Error('invalid_option_value');
      const encode = text => { if (/[\uD800-\uDFFF]/u.test(text)) throw new Error('invalid_unicode'); return Buffer.from(text).toString('hex'); };
      if (arg === '--head' || arg === '--head-hex') {
        if (head !== null) throw new Error('duplicate_head'); head = arg === '--head' ? encode(value) : value;
      } else if (arg === '--expect-ref' || arg === '--expect-ref-hex') {
        const at = value.lastIndexOf('='); if (at < 1 || at === value.length - 1) throw new Error('invalid_reference_pin');
        expected.refs ??= []; if (expected.refs.length >= BUNDLE_VERIFY_LIMITS.maxRefs) throw new Error('expectation_reference_limit');
        expected.refs.push({ ref_hex: arg === '--expect-ref' ? encode(value.slice(0, at)) : value.slice(0, at), object_id: value.slice(at + 1) });
      } else {
        if (seen.has(arg)) throw new Error('duplicate_option'); seen.add(arg);
        expected[arg === '--expect-sha256' ? 'sha256' : 'object_format'] = value;
      }
    } else paths.push(arg);
  }
  if (paths.length !== 2 || paths.some(path => !path)) throw new Error('input_and_new_destination_required');
  if (head === null || !head.startsWith('726566732f68656164732f')) throw new Error('explicit_branch_head_required');
  bundleRef(head);
  if (Object.keys(expected).length) normalizeBundleExpectation(expected);
  return { input: paths[0], destination: paths[1], request: { head_ref_hex: head, ...(Object.keys(expected).length ? { expectations: expected } : {}) } };
}
async function readBundle(path, signal) {
  signal.throwIfAborted(); const file = await open(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > BUNDLE_VERIFY_LIMITS.maxInputBytes) throw new Error('bundle_file_size_or_type');
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
const pipeError = () => { process.exitCode = 1; }; process.stdout.on('error', pipeError); process.stderr.on('error', pipeError);
let result = null;
try {
  const args = process.argv.slice(2); let output;
  if (args.length === 1 && args[0] === '--help') output = HELP;
  else {
    const { input, destination, request } = parse(args);
    result = await recoverGitBundle(await readBundle(input, controller.signal), destination, request, { signal: controller.signal });
    output = JSON.stringify(result, null, 2) + '\n';
  }
  await new Promise((resolve, reject) => process.stdout.write(output, error => error ? reject(error) : resolve()));
} catch (error) {
  process.stderr.write(JSON.stringify({ type: 'frankengit-source-recovery-error-v1',
    code: error.code ?? error.message ?? 'recovery_failed', state: result?.state ?? error.state ?? 'not_created',
    destination: result?.destination ?? error.destination ?? null }) + '\n'); process.exitCode = 1;
} finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
