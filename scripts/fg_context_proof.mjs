#!/usr/bin/env node
// Read-only sparse commit proofs for saved context. No source execution or extraction.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { lstat } from 'node:fs/promises';
import { archiveSelection, archiveLimits } from './operator/source_archive.mjs';
import { captureContextProof, inspectContextProof, CONTEXT_INPUT_LIMIT, CONTEXT_PROOF_LIMIT } from './operator/source_context_proof.mjs';
import { parse } from './operator/source_archive_transport.mjs';
import { absolute, directory, readPrivate, writeNew } from './operator/workflow_watch_io.mjs';

const USAGE = `node scripts/fg_context_proof.mjs capture --selection <private-json>
  --context <private-capture.json-or-native-context.json> --context-sha256 <retained-hash>
  --token-file <private-token> --output <new-proof.json> [--limits <private-json>] [--ca-file <private-pem>]
node scripts/fg_context_proof.mjs inspect --selection <private-json>
  --context <private-context.json> --context-sha256 <retained-hash>
  --proof <private-proof.json> --proof-sha256 <retained-hash>

Selection requires an independently selected native commit. This is extra source
I/O (full selected blobs and parent trees), not an index-only search or a retry.
Defaults cap full source at 8 MiB; explicit archive limits may narrow or raise it
within the documented hard ceiling. Empty context has no source proof to acquire.
Inspection rechecks the pinned original context and proof offline without a token.
The proof retains FULL selected files and parent-tree names, not just excerpts.
No extraction, overwrite, source refresh, search/authority attestation or mutation.
Exit 0: byte/membership checks passed; 2: refusal; 3: cancellation before publication;
4: local publication or stdout needs inspection using the retained hashes.`;
function options(args) {
  if (args.length > 17 || args.length % 2 !== 1 || args.some(a => typeof a !== 'string' || a.length > 4096) ||
      !['capture', 'inspect'].includes(args[0])) throw new Error(USAGE);
  const required = ['--selection', '--context', '--context-sha256', ...(args[0] === 'capture' ? ['--token-file', '--output'] : ['--proof', '--proof-sha256'])];
  const allowed = [...required, ...(args[0] === 'capture' ? ['--limits', '--ca-file'] : [])], values = new Map();
  for (let i = 1; i < args.length; i += 2) {
    if (!allowed.includes(args[i]) || values.has(args[i]) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error(USAGE);
    values.set(args[i], args[i + 1]);
  }
  if (required.some(k => !values.has(k))) throw new Error(USAGE);
  for (const name of ['--context-sha256', '--proof-sha256']) if (values.has(name) && !/^[0-9a-f]{64}$/.test(values.get(name))) throw new Error('An independently retained input hash is required.');
  return values;
}
async function read(path, maximum) { absolute(path); await directory(dirname(path)); return readPrivate(path, maximum); }
// Keep diagnostics bounded even with 32 KiB of selected raw path bytes.
function summary(receipt) {
  const { verified_files, ...rest } = receipt;
  return { ...rest, verified_file_count: verified_files.length };
}
async function emit(stream, value) {
  const bytes = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(bytes) > 65536) throw new Error('Proof receipt exceeds output limit.');
  await new Promise((resolve, reject) => {
    let settled = false;
    const finish = error => { if (settled) return; settled = true; clearTimeout(timer); if (!error) stream.removeListener('error', onError); error ? reject(error) : resolve(); };
    const onError = error => finish(error), timer = setTimeout(() => {
      const error = new Error('Proof output deadline exceeded.'); finish(error); stream.destroy(error);
    }, 10000);
    stream.once('error', onError);
    try { stream.write(bytes, error => finish(error)); } catch (error) { finish(error); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort(new Error('Context proof cancelled.'));
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let receipt, attempted;
  try {
    if (args.length === 1 && args[0] === '--help') { await emit(stdout, { usage: USAGE }); return 0; }
    const f = options(args);
    if (typeof process.getuid !== 'function') throw new Error('Private proof files require POSIX ownership.');
    const start = performance.now();
    const limits = archiveLimits({ maxBlobBytes: 8388608, maxTotalBlobBytes: 8388608,
      ...(f.has('--limits') ? parse(await read(f.get('--limits'), 32768)) : {}) });
    const check = () => { stop.signal.throwIfAborted(); if (performance.now() - start >= limits.timeoutMs) throw new Error('Context proof operation deadline exceeded.'); };
    const selection = archiveSelection(parse(await read(f.get('--selection'), 32768))); check();
    const context = await read(f.get('--context'), CONTEXT_INPUT_LIMIT), contextHash = f.get('--context-sha256'); check();
    if (args[0] === 'inspect') {
      const proof = await read(f.get('--proof'), CONTEXT_PROOF_LIMIT); check();
      receipt = inspectContextProof(proof, f.get('--proof-sha256'), context, contextHash, selection, check);
    } else {
      const output = absolute(f.get('--output')); await directory(dirname(output));
      const exists = await lstat(output).then(() => true, e => { if (e.code === 'ENOENT') return false; throw e; });
      if (exists) throw new Error('Proof output already exists; overwrite is forbidden.');
      const raw = await read(f.get('--token-file'), 66); check();
      if (!/^[0-9a-f]{64}(?:\r?\n)?$/.test(raw.toString('utf8'))) throw new Error('Invalid private source token.');
      const token = raw.subarray(0, 64).toString('ascii'); raw.fill(0);
      const ca = f.has('--ca-file') ? await read(f.get('--ca-file'), 131072) : undefined; check();
      const remaining = Math.floor(limits.timeoutMs - (performance.now() - start));
      if (remaining < 1) throw new Error('Context proof operation deadline exceeded.');
      const result = await captureContextProof(context, contextHash, selection, token,
        { signal: stop.signal, ca, limits: { ...limits, timeoutMs: remaining } }); check();
      inspectContextProof(result.bytes, result.receipt.proof_sha256, context, contextHash, selection, check);
      attempted = { proof_path: output, proof_sha256: result.receipt.proof_sha256, context_sha256: contextHash };
      // Drain started write/sync/readback even on a late stop. No cancellation
      // observation or stdout failure proves that a published file disappeared.
      await writeNew(output, result.bytes);
      receipt = { ...inspectContextProof(await read(output, CONTEXT_PROOF_LIMIT), attempted.proof_sha256, context, contextHash, selection),
        proof_path: output, read_metrics: result.metrics, stop_requested: stop.signal.aborted };
    }
    await emit(stdout, summary(receipt)); return 0;
  } catch (error) {
    try { await emit(stderr, { type: 'source_context_proof_error', message: error.message, remote_mutation_attempted: false,
      source_reexecuted: false, ...(receipt ? { retained_receipt: summary(receipt) } : attempted ? { publication_unconfirmed: attempted } : {}) }); } catch { /* Retain the original file and hash. */ }
    return receipt || attempted ? 4 : stop.signal.aborted ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
