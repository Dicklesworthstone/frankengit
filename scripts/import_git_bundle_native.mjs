#!/usr/bin/env node
// Explicit trusted-local source restoration through fg's existing admission.
import { importNativeSource, readNativeImportOutcome, retryNativeSourceImport } from './lib/native-source-import.mjs';

const USAGE = `Usage:
  node scripts/import_git_bundle_native.mjs import SOURCE.bundle --trusted-local
    --fg /absolute/path/to/fg --storage /existing/node
    --tenant HEX --repository-id HEX --principal HEX --object-format sha1|sha256
    --recovery-directory /new/private/recovery-directory
    [--attestation DSSE --trust-key PEM --source-repository OWNER/REPO --minimum-sequence N]
    [--expect-sha256 HEX] [--expect-ref REF=OID | --expect-ref-hex HEX=OID] [--exact-refs]
  node scripts/import_git_bundle_native.mjs status /recovery-directory --trusted-local
    --fg /absolute/path/to/fg [--intent-sha256 HEX]
  node scripts/import_git_bundle_native.mjs retry /recovery-directory --trusted-local
    --fg /absolute/path/to/fg [--intent-sha256 HEX]

All commands accept --timeout-secs 1..3600 (default 300).
Import restores portable Git SOURCE into an already initialized node through
native verification and one atomic absent-ref import. It never initializes,
replaces, force-updates or restores forge/capsule state. The native executable
is explicitly operator-trusted; no shell, upstream Git or decoder fallback.
The input limit is 16 MiB with at most 64 direct references.

Before submission, an exclusive owner-only recovery directory retains and syncs
one exact snapshot and immutable intent. KEEP this directory after interruption.
status only observes the original canonical outcome. retry is explicit and uses
the SAME key/bytes; it never reopens the original bundle or creates a new key.
A missing response or unknown_pending observation is NOT proof of rollback.
Do not replace/reinitialize the target while an import outcome is unresolved.

Exit 0: committed; 3: canonical refusal; 4: unknown/nonterminal; 2: error.
An error after submission can still mean the import committed. Use status.
`;
function parse(args) {
  if (args.length < 2 || args.length > 170 || args.some(arg => arg.length > 8300 || arg.includes('\0'))
    || args.reduce((n, arg) => n + Buffer.byteLength(arg), 0) > 1024 * 1024) throw new Error('invalid_import_arguments');
  const [action, path] = args;
  if (!['import', 'status', 'retry'].includes(action) || !path || path.startsWith('--')) throw new Error('invalid_import_action_or_path');
  const options = {}, expected = {}, approval = {}, seen = new Set();
  const common = { '--fg': 'fg', '--timeout-secs': 'timeoutMs' };
  const initial = { '--storage': 'storage', '--tenant': 'tenant', '--repository-id': 'repository',
    '--principal': 'principal', '--object-format': 'format', '--recovery-directory': 'recovery' };
  const signed = { '--attestation': 'envelope', '--trust-key': 'key', '--source-repository': 'repository', '--minimum-sequence': 'minimum_sequence' };
  for (let at = 2; at < args.length; at++) {
    const flag = args[at];
    if (!['--expect-ref', '--expect-ref-hex'].includes(flag) && seen.has(flag)) throw new Error('duplicate_import_option');
    seen.add(flag);
    if (flag === '--trusted-local') { options.trustedLocal = true; continue; }
    if (action === 'import' && flag === '--exact-refs') { expected.exact_refs = true; continue; }
    const allowed = Object.hasOwn(common, flag) || (action === 'import'
      ? Object.hasOwn(initial, flag) || Object.hasOwn(signed, flag) || ['--expect-sha256', '--expect-ref', '--expect-ref-hex'].includes(flag)
      : flag === '--intent-sha256');
    if (!allowed) throw new Error('unknown_import_option');
    const value = args[++at];
    if (!value || value.startsWith('--')) throw new Error('missing_import_option_value');
    if (Object.hasOwn(signed, flag)) approval[signed[flag]] = value;
    else if (flag === '--timeout-secs') {
      if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > 3600) throw new Error('invalid_import_timeout');
      options.timeoutMs = Number(value) * 1000;
    } else if (flag === '--expect-sha256') expected.sha256 = value;
    else if (flag === '--intent-sha256') options.intentSha256 = value;
    else if (['--expect-ref', '--expect-ref-hex'].includes(flag)) {
      const split = value.lastIndexOf('=');
      if (split < 1 || split === value.length - 1 || /[\uD800-\uDFFF]/u.test(value)) throw new Error('invalid_import_reference_pin');
      const name = value.slice(0, split);
      expected.refs ??= [];
      if (expected.refs.length === 64) throw new Error('native_import_reference_limit');
      expected.refs.push({ ref_hex: flag === '--expect-ref-hex' ? name : Buffer.from(name).toString('hex'), object_id: value.slice(split + 1) });
    } else options[common[flag] ?? initial[flag]] = value;
  }
  if (action === 'import') {
    options.expected = expected;
    if (Object.keys(approval).length) {
      if (Object.keys(approval).length !== 4) throw new Error('complete_import_approval_required');
      options.approval = { envelope: approval.envelope, key: approval.key,
        policy: { repository: approval.repository, minimum_sequence: approval.minimum_sequence } };
    }
  }
  return { action, path, options };
}
const controller = new AbortController();
const stop = () => controller.abort();
const outputFailure = () => { controller.abort(); process.exitCode = 2; };
process.once('SIGTERM', stop); process.once('SIGINT', stop);
process.stdout.on('error', outputFailure); process.stderr.on('error', outputFailure);
try {
  const args = process.argv.slice(2);
  let text;
  if (args.length === 1 && args[0] === '--help') text = USAGE;
  else {
    const { action, path, options } = parse(args);
    const operation = { import: importNativeSource, status: readNativeImportOutcome, retry: retryNativeSourceImport }[action];
    const result = await operation(path, { ...options, signal: controller.signal });
    process.exitCode = !result.node_closed ? 2 : result.outcome === 'committed' ? 0 : result.outcome === 'refused' ? 3 : 4;
    text = JSON.stringify(result) + '\n';
  }
  await new Promise((resolve, reject) => process.stdout.write(text, error => error ? reject(error) : resolve()));
} catch (error) {
  const report = { type: 'native_source_import_error', error: error.code ?? error.message,
    details: error.details ?? null, absence_proves_non_commit: false, automatic_retry: false };
  process.stderr.write(JSON.stringify(report) + '\n'); process.exitCode = 2;
} finally { process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop); }
