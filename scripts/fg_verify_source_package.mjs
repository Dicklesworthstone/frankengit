#!/usr/bin/env node
// Offline, read-only verification. No extraction, credential or network option.
import { open } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { readSourcePackage, SOURCE_PACKAGE_BYTES } from '../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';

const HELP = 'Usage: node scripts/fg_verify_source_package.mjs --package package.json --expect independently-retained-selection.json [--timeout-ms 30000]\n';
function args(values) {
  if (values.length === 1 && values[0] === '--help') return null;
  const result = {};
  if (!values.length || values.length % 2) throw new Error(HELP.trim());
  for (let at = 0; at < values.length; at += 2) {
    const key = values[at], value = values[at + 1];
    if (!['--package', '--expect', '--timeout-ms'].includes(key) || Object.hasOwn(result, key) || !value || value.startsWith('--')) throw new Error('Unknown, repeated or missing argument.');
    result[key] = value;
  }
  if (!result['--package'] || !result['--expect']) throw new Error('Supply both the package and an independent expected selection.');
  const timeout = result['--timeout-ms'] ?? '30000';
  if (!/^[1-9][0-9]{0,5}$/.test(timeout) || Number(timeout) > 300000) throw new Error('Invalid verification deadline.');
  return { package: result['--package'], expect: result['--expect'], timeoutMs: Number(timeout) };
}
async function readBounded(path, maximum, check) {
  check(); const file = await open(path, 'r');
  try {
    check(); const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size < 1n || before.size > BigInt(maximum)) throw new Error('Input is not a bounded regular file.');
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) {
      check(); const { bytesRead } = await file.read(bytes, offset, Math.min(65536, bytes.length - offset), offset); check();
      if (!bytesRead) throw new Error('Input was truncated during reading.'); offset += bytesRead;
    }
    const extra = await file.read(Buffer.alloc(1), 0, 1, offset), after = await file.stat({ bigint: true }); check();
    if (extra.bytesRead || ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].some(key => before[key] !== after[key])) throw new Error('Input changed during reading.');
    return bytes;
  } finally { await file.close(); }
}
async function main() {
  const options = args(process.argv.slice(2));
  if (options === null) { process.stdout.write(HELP); return; }
  const deadline = performance.now() + options.timeoutMs, controller = new AbortController();
  const stop = () => controller.abort(new Error('Verification canceled.'));
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  const check = () => { controller.signal.throwIfAborted(); if (performance.now() >= deadline) throw new Error('Verification deadline exceeded.'); };
  try {
    // Never infer expected pins from the package. Reading this separate input
    // cannot attest where the operator obtained it; retain it independently.
    const expectedBytes = await readBounded(options.expect, 128 * 1024, check);
    const expected = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(expectedBytes));
    const bytes = await readBounded(options.package, SOURCE_PACKAGE_BYTES, check);
    const { verified } = await readSourcePackage(bytes, expected, webcrypto, check); check();
    await new Promise((resolve, reject) => process.stdout.write(JSON.stringify(verified) + '\n', error => error ? reject(error) : resolve()));
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
process.stdout.on('error', () => { process.exitCode = 1; });
await main().catch(() => { process.stderr.write('Source package verification failed. No files were written and no network request was made.\n'); process.exitCode = 1; });
