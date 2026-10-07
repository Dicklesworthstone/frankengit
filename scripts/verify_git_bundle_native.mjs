#!/usr/bin/env node
// Explicit native offline verification. The selected fg owns all Git semantics.
import { verifyNativeGitBundleFile, normalizeNativeBundleExpectation } from './lib/native-bundle-verifier.mjs';

const USAGE = `Usage: node scripts/verify_git_bundle_native.mjs PATH.bundle --fg /absolute/path/to/fg [OPTIONS]

Run the existing native Rust fg bundle verify over an exclusive private snapshot.
No Git executable, network client, repository opening, restore, or fallback.
The executable is operator-trusted; this command does not authenticate its build.
  --max-input-mib N       Input bytes, 1..128 (default 128)
  --max-expanded-mib N    Native resolution/graph bytes, 1..128 (default 128)
  --max-objects N         Included objects, 1..100000
  --max-refs N            References, 1..4096
  --timeout-secs N        One read/staging/process deadline, 1..3600 (default 300)
  --expect-sha256 HEX     Independently known complete-artifact SHA-256
  --expect-format FORMAT sha1 or sha256; required for native ref pins
  --expect-ref REF=OID    Repeat for independently known full native references
  --expect-ref-hex HEX=OID Lossless raw reference-name bytes
  --exact-refs           Require precisely the supplied direct reference set
  --                     Treat the remaining argument as a literal input path
  --help                 Print help without file access or process creation

A matching input snapshot hash is not an independent trust anchor. A format alone
is not an identity pin. Native success does not authenticate an origin or signer,
prove freshness, verify submodule targets, restore a capsule, or approve a change.
The bounded native reader retains input in memory; this is not a streaming engine.
Cancellation terminates and reaps fg, escalating after 500 ms if necessary. It
cannot interrupt a blocking OS filesystem operation. Only our temporary inode is
removed; cleanup failure is a command failure, never recursive deletion.
`;
function argumentsFor(args) {
  if (args.length > 8224 || args.reduce((sum, arg) => sum + Buffer.byteLength(arg), 0) > 2 * 1024 * 1024
    || args.some(arg => arg.length > 8300 || arg.includes('\0'))) throw new Error('native_argument_limit');
  const options = {}, expected = {}, seen = new Set();
  let path = null, literal = false;
  const numbers = new Map([['--max-input-mib', 'maxInputMiB'], ['--max-expanded-mib', 'maxExpandedMiB'],
    ['--max-objects', 'maxObjects'], ['--max-refs', 'maxRefs'], ['--timeout-secs', 'timeoutMs']]);
  for (let at = 0; at < args.length; at++) {
    const arg = args[at];
    if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && arg.startsWith('-')) {
      const repeated = arg === '--expect-ref' || arg === '--expect-ref-hex';
      if (!repeated && seen.has(arg)) throw new Error('duplicate_option'); seen.add(arg);
      if (arg === '--exact-refs') { expected.exact_refs = true; continue; }
      if (!numbers.has(arg) && !repeated && !['--fg', '--expect-sha256', '--expect-format'].includes(arg)) throw new Error('unknown_option');
      const value = args[++at];
      if (!value || value.startsWith('--')) throw new Error('missing_option_value');
      if (numbers.has(arg)) {
        if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error('invalid_numeric_option');
        options[numbers.get(arg)] = Number(value) * (arg === '--timeout-secs' ? 1000 : 1);
      } else if (arg === '--fg') options.fg = value;
      else if (arg === '--expect-sha256') expected.sha256 = value;
      else if (arg === '--expect-format') expected.object_format = value;
      else {
        const split = value.lastIndexOf('=');
        if (split < 1 || split === value.length - 1) throw new Error('invalid_reference_pin');
        const name = value.slice(0, split);
        if (arg === '--expect-ref' && /[\uD800-\uDFFF]/u.test(name)) throw new Error('invalid_reference_pin');
        expected.refs ??= [];
        expected.refs.push({ ref_hex: arg === '--expect-ref-hex' ? name : Buffer.from(name, 'utf8').toString('hex'), object_id: value.slice(split + 1) });
      }
    } else {
      if (path !== null || !arg) throw new Error('one_bundle_path_required'); path = arg;
    }
  }
  if (path === null) throw new Error('bundle_path_required');
  options.expected = normalizeNativeBundleExpectation(expected, options.maxRefs ?? 4096);
  return { path, options };
}
const controller = new AbortController(), cancel = () => controller.abort();
process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
const outputError = () => { controller.abort(); process.exitCode = 1; };
process.stdout.on('error', outputError); process.stderr.on('error', outputError);
try {
  const args = process.argv.slice(2);
  let output;
  if (args.length === 1 && args[0] === '--help') output = USAGE;
  else {
    const { path, options } = argumentsFor(args);
    output = `${JSON.stringify(await verifyNativeGitBundleFile(path, { ...options, signal: controller.signal }), null, 2)}\n`;
  }
  await new Promise((resolve, reject) => process.stdout.write(output, error => error ? reject(error) : resolve()));
} catch (error) {
  process.exitCode = 1;
  process.stderr.write(`${JSON.stringify({ verified: false, error: error?.code ?? error?.message ?? 'native_verification_failed', details: error?.details ?? null })}\n`);
} finally {
  process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel);
}
