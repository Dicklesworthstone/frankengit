#!/usr/bin/env node
// Offline product boundary: read one bounded bundle and print verifiable facts.
// No Git executable, server, working tree, network, or repository writes.
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { BUNDLE_VERIFY_LIMITS, verifyGitBundle } from '../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs';

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
const args = process.argv.slice(2), controller = new AbortController();
const cancel = () => controller.abort(); process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
// A broken output pipe is a command failure, not an unhandled stream event.
const outputError = () => { process.exitCode = 1; }; process.stdout.on('error', outputError); process.stderr.on('error', outputError);
try {
  if (args.length !== 1 || !args[0] || args[0].startsWith('-')) throw new Error('usage: node scripts/verify_git_bundle.mjs PATH.bundle');
  const result = await verifyGitBundle(await readBounded(args[0], controller.signal), { cryptoImpl: webcrypto, signal: controller.signal });
  await new Promise((resolve, reject) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`, error => error ? reject(error) : resolve()));
} catch (error) {
  const code = error?.code ?? (typeof error?.message === 'string' ? error.message : 'verification_failed');
  process.stderr.write(`${JSON.stringify({ verified: false, error: code, details: error?.details ?? null })}\n`); process.exitCode = 1;
} finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
