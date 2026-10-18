#!/usr/bin/env node
// Create-only private source packages. No extraction, execution or forge writes.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { lstat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { absolute, directory, readPrivate, parseJson, writeNew } from './operator/workflow_watch_io.mjs';
import { captureSourcePackage, inspectSourcePackage, packageAcquisitionLimits, packageAcquisitionSelection,
  PACKAGE_CONTEXT_BYTES, SOURCE_PACKAGE_BYTES } from './operator/source_package.mjs';

const USAGE = `node scripts/fg_source_package.mjs capture --selection PRIVATE_JSON
  --context PRIVATE_CONTEXT --context-sha256 RETAINED_HASH --expect PRIVATE_EXPECTATION
  --token-file PRIVATE_TOKEN --output ABSENT_PACKAGE [--limits PRIVATE_JSON]
node scripts/fg_source_package.mjs inspect --selection PRIVATE_JSON
  --context PRIVATE_CONTEXT --context-sha256 RETAINED_HASH --expect PRIVATE_EXPECTATION
  --package PRIVATE_PACKAGE --package-sha256 RETAINED_HASH [--limits PRIVATE_JSON]

Use normalized absolute paths in owner-private 0700 directories. Inputs must be
private, singly linked regular files. Capture creates a new 0600 package only
AFTER complete verification. Keep the original expectation independently; never
infer its commit or selected path/blob IDs from the package being checked.
Capture performs extra full-file and parent-tree reads at the original snapshot.
Inspect is offline, accepts no token, and rechecks the original saved excerpts.
Limits: {timeoutMs:30000,package:{maxSourceBytes:8388608,maxBlobRequests:160,
  membership:{maxRequests:512,maxTrees:128,maxEntries:16384,maxTreeBytes:4194304}}}.
Byte/request limits can only narrow these ceilings. Deadline range: 1..300000 ms.
Exit 0: fully verified; 2: refusal; 3: cancelled before publication; 4: retained
result or local publication uncertainty. Never retry an uncertain publication;
inspect the named file with the retained hashes. A begun write/sync/readback is
drained after cancellation; a late stop does not imply the file was removed.
No overwrite, checkout, source execution, mutation, credentials in arguments,
redirect, refresh or retry. TLS verification must remain enabled.`;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = () => { throw new Error('Source package command refused.'); };
function options(args) {
  if (!Array.isArray(args) || args.length > 17 || args.length % 2 !== 1 ||
      args.some(a => typeof a !== 'string' || Buffer.byteLength(a) > 4096) || !['capture', 'inspect'].includes(args[0])) fail();
  const common = ['--selection', '--context', '--context-sha256', '--expect'];
  const required = [...common, ...(args[0] === 'capture' ? ['--token-file', '--output'] : ['--package', '--package-sha256'])];
  const allowed = [...required, '--limits'], flags = new Map();
  for (let at = 1; at < args.length; at += 2) {
    const name = args[at], value = args[at + 1];
    if (!allowed.includes(name) || flags.has(name) || !value || value.startsWith('--')) fail();
    if (name.endsWith('-sha256')) { if (!/^[0-9a-f]{64}$/.test(value)) fail(); }
    else absolute(value);
    flags.set(name, value);
  }
  if (required.some(name => !flags.has(name))) fail();
  return { op: args[0], flags };
}
async function read(path, maximum, check = () => {}) {
  check(); await directory(dirname(absolute(path))); const bytes = await readPrivate(path, maximum); check(); return bytes;
}
// Standard reports retain raw path identities; CLI output intentionally does not.
function summary(receipt) {
  const { files, ...verified } = receipt.verified;
  return { ...receipt, verified: { ...verified, selected_file_count: files.length } };
}
async function emit(stream, value) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  if (bytes.length > 65536) fail();
  await new Promise((resolve, reject) => {
    let settled = false;
    const finish = error => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (!error) stream.removeListener('error', onError);
      error ? reject(error) : resolve();
    };
    const onError = error => finish(error);
    const timer = setTimeout(() => { const error = new Error('Output deadline exceeded.'); finish(error); stream.destroy(error); }, 10000);
    stream.once('error', onError);
    try { stream.write(bytes, error => finish(error)); } catch (error) { finish(error); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort();
  process.on('SIGINT', abort); process.on('SIGTERM', abort);
  let phase = 'arguments', attempted, receipt;
  try {
    if (Array.isArray(args) && args.length === 1 && args[0] === '--help') { await emit(stdout, { usage: USAGE }); return 0; }
    const { op, flags: f } = options(args);
    if (typeof process.getuid !== 'function') fail();
    phase = 'private_inputs';
    const start = performance.now();
    const limits = packageAcquisitionLimits(f.has('--limits') ? parseJson(await read(f.get('--limits'), 32768, () => stop.signal.throwIfAborted())) : {});
    const check = () => { stop.signal.throwIfAborted(); if (performance.now() - start >= limits.timeoutMs) fail(); };
    const remaining = () => { check(); return Math.max(1, Math.floor(limits.timeoutMs - (performance.now() - start))); };
    const selected = packageAcquisitionSelection(parseJson(await read(f.get('--selection'), 32768, check)));
    const expectation = await read(f.get('--expect'), 128 * 1024, check), expected = parseJson(expectation);
    const expectedHash = hash(expectation), context = await read(f.get('--context'), PACKAGE_CONTEXT_BYTES, check);
    const contextHash = f.get('--context-sha256'), local = () => ({ limits: { ...limits, timeoutMs: remaining() }, signal: stop.signal });
    if (op === 'inspect') {
      const bytes = await read(f.get('--package'), SOURCE_PACKAGE_BYTES, check);
      phase = 'inspect';
      receipt = { ...await inspectSourcePackage(bytes, f.get('--package-sha256'), context, contextHash, selected, expected, local()),
        package_path: f.get('--package'), expected_input_sha256: expectedHash, stop_requested: stop.signal.aborted };
    } else {
      const output = f.get('--output'); await directory(dirname(output)); check();
      const exists = await lstat(output).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; });
      if (exists) fail(); // Before any credential use or network request.
      const raw = await read(f.get('--token-file'), 66, check); let token;
      try {
        if (!/^[0-9a-f]{64}(?:\r?\n)?$/.test(raw.toString('utf8'))) fail();
        token = raw.subarray(0, 64).toString('ascii');
      } finally { raw.fill(0); }
      phase = 'capture';
      const result = await captureSourcePackage(context, contextHash, selected, expected, token, local()); check();
      attempted = { package_path: output, package_sha256: result.receipt.package_sha256,
        context_sha256: contextHash, expected_input_sha256: expectedHash };
      phase = 'publication';
      // Do not cancel an owned local effect underneath its fsync/readback. A
      // failure after create-only linking may leave the complete destination.
      await writeNew(output, result.bytes);
      phase = 'readback';
      const verified = await inspectSourcePackage(await read(output, SOURCE_PACKAGE_BYTES), attempted.package_sha256,
        context, contextHash, selected, expected, { limits });
      receipt = { ...verified, package_path: output, expected_input_sha256: expectedHash,
        read_metrics: result.metrics, stop_requested: stop.signal.aborted };
    }
    phase = 'stdout'; await emit(stdout, summary(receipt)); return 0;
  } catch {
    const code = receipt || attempted ? 4 : stop.signal.aborted ? 3 : 2;
    try {
      await emit(stderr, { type: 'source_package_error', phase, exit_code: code,
        remote_mutation_attempted: false, source_executed: false, stop_requested: stop.signal.aborted,
        ...(receipt ? { retained_receipt: summary(receipt) } : attempted ? { publication_unconfirmed: attempted } : {}) });
    } catch { /* The original destination and retained hashes remain unchanged. */ }
    return code;
  } finally { process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
