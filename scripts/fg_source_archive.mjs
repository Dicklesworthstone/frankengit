#!/usr/bin/env node
// Authenticated complete source export and network-free inspection. Never extract.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { lstat } from 'node:fs/promises';
import { captureSource, archiveSelection, archiveLimits, sha256 } from './operator/source_archive.mjs';
import { buildSourceArchive, inspectSourceArchive, TAR_LIMIT } from './operator/source_archive_tar.mjs';
import { parse } from './operator/source_archive_transport.mjs';
import { absolute, directory, readPrivate, writeNew } from './operator/workflow_watch_io.mjs';

const USAGE = `usage:
  node scripts/fg_source_archive.mjs capture --selection <private-json-file>
    --token-file <private-token-file> --layout <portable|objects> --output <new-archive.tar>
    [--ca-file <private-pem-file>] [--limits <private-json-file>]
  node scripts/fg_source_archive.mjs inspect --archive <private-archive.tar> --sha256 <retained-hash>

All paths must be normalized absolute paths with owner-private 0700 parents.
Capture requires an independently selected native commit and scoped read token.
Portable layout stores ASCII source paths, symlink payloads as regular files and
unhydrated gitlinks as empty directories; executable file bits are not installed.
Objects layout preserves arbitrary native names in the proof manifest, with safe
object-ID payload names. Neither layout is a checkout or a repository backup.
No extraction, overwrite, redirect, mutation, implicit source refresh or retry.
Exit 0: verified archive/inspection; 2: refused; 3: cancelled before publication;
4: file publication or output delivery needs inspection using retained hash.
See docs/VERIFIED_SOURCE_ARCHIVE.md.`;
function options(args) {
  const operation = args[0], fields = new Map();
  const required = operation === 'capture' ? ['--selection', '--token-file', '--layout', '--output'] : ['--archive', '--sha256'];
  const allowed = operation === 'capture' ? [...required, '--ca-file', '--limits'] : required;
  if (!['capture', 'inspect'].includes(operation) || args.length > 13 || args.length % 2 !== 1) throw new Error(USAGE);
  for (let index = 1; index < args.length; index += 2) {
    const flag = args[index], value = args[index + 1];
    if (!allowed.includes(flag) || fields.has(flag) || !value || value.startsWith('--')) throw new Error(USAGE);
    fields.set(flag, value);
  }
  if (required.some(flag => !fields.has(flag))) throw new Error(USAGE);
  return { operation, fields };
}
async function privateFile(path, maximum) {
  absolute(path); await directory(dirname(path)); return readPrivate(path, maximum);
}
async function write(stream, value) {
  const bytes = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(bytes) > 65536) throw new Error('Archive diagnostic exceeds limit.');
  return new Promise((resolve, reject) => {
    let settled = false;
    const onError = error => { if (!settled) { settled = true; clearTimeout(timer); reject(error); } };
    const timer = setTimeout(() => { const error = new Error('Archive output deadline exceeded.'); onError(error); stream.destroy(error); }, 10000);
    stream.once('error', onError);
    stream.write(bytes, error => {
      if (error) onError(error);
      else if (!settled) { settled = true; clearTimeout(timer); stream.removeListener('error', onError); resolve(); }
    });
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort(new Error('Source archive cancelled.'));
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let receipt = null, attempted = null;
  try {
    if (args.length === 1 && args[0] === '--help') { await write(stdout, { usage: USAGE }); return 0; }
    const { operation, fields } = options(args);
    if (typeof process.getuid !== 'function') throw new Error('Archive filesystem operations require the POSIX private-file profile.');
    if (operation === 'inspect') {
      // This branch loads no credentials and has no acquisition call.
      const bytes = await privateFile(fields.get('--archive'), TAR_LIMIT); stop.signal.throwIfAborted();
      receipt = inspectSourceArchive(bytes, fields.get('--sha256')); stop.signal.throwIfAborted();
    } else {
      const path = absolute(fields.get('--output')); await directory(dirname(path));
      const exists = await lstat(path).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; });
      if (exists) throw new Error('Archive destination already exists; overwrite is forbidden.');
      if (!['portable', 'objects'].includes(fields.get('--layout'))) throw new Error(USAGE);
      const selection = archiveSelection(parse(await privateFile(fields.get('--selection'), 32768)));
      const limits = archiveLimits(fields.has('--limits') ? parse(await privateFile(fields.get('--limits'), 32768)) : {});
      const tokenBytes = await privateFile(fields.get('--token-file'), 66);
      if (!/^[0-9a-f]{64}(?:\r?\n)?$/.test(tokenBytes.toString('utf8'))) throw new Error('Invalid private source token.');
      const token = tokenBytes.subarray(0, 64).toString('ascii');
      const ca = fields.has('--ca-file') ? await privateFile(fields.get('--ca-file'), 128 * 1024) : undefined;
      const deadline = performance.now() + limits.timeoutMs;
      const { capture, metrics } = await captureSource(selection, token, { limits, signal: stop.signal, ca });
      stop.signal.throwIfAborted(); const archive = buildSourceArchive(capture, fields.get('--layout'));
      inspectSourceArchive(archive.bytes, archive.receipt.archive_sha256);
      stop.signal.throwIfAborted();
      if (performance.now() >= deadline) throw new Error('Source archive deadline exceeded before file publication.');
      attempted = { archive_path: path, archive_sha256: archive.receipt.archive_sha256, archive_bytes: archive.bytes.length };
      // Once file publication starts, drain its write/sync/readback even if a
      // late stop arrives. A failed final sync is not proof the path is absent.
      await writeNew(path, archive.bytes);
      const saved = await privateFile(path, TAR_LIMIT);
      if (sha256(saved) !== attempted.archive_sha256) throw new Error('Published archive changed during readback.');
      receipt = { ...inspectSourceArchive(saved, attempted.archive_sha256), archive_path: path, read_metrics: metrics,
        stop_requested: stop.signal.aborted };
    }
    await write(stdout, receipt); return 0;
  } catch (error) {
    try { await write(stderr, { type: 'source_archive_error', schema_version: 1, message: error.message,
      ...(receipt ? { retained_receipt: receipt } : attempted ? { publication_unconfirmed: attempted } : {}),
      source_reexecuted: false, remote_mutation_attempted: false }); } catch { /* Original file/hash remains usable for offline inspection. */ }
    return receipt || attempted ? 4 : stop.signal.aborted ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
