#!/usr/bin/env node
// Offline refactoring author. Native fg owns source membership, destination
// absence, candidate validation and admission. This command writes only a patch.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { lstat } from 'node:fs/promises';
import { setImmediate as yieldTurn } from 'node:timers/promises';
import { absolute, directory, readPrivate, writeNew, syncDirectory } from './operator/workflow_watch_io.mjs';
import { fail, clock, hash } from './operator/source_edit_wire.mjs';
import { compileSourceRefactoring, REFACTOR_PROFILE, REPLACEMENT_LIMITS } from './operator/source_edit_replacements.mjs';
import { loadSourceRefactorFiles } from './operator/source_edit_refactor_files.mjs';
const USAGE = 'node scripts/fg_source_refactor.mjs compile --plan-file PRIVATE_JSON --output ABSENT_PRIVATE_PATCH [--binary literal|delta|delta-runs] [--max-patch-bytes 1..1048576] [--timeout-ms 1..300000]';
function argumentsFor(args) {
  if (!Array.isArray(args) || args.length > 11 || args.some(s => typeof s !== 'string' || Buffer.byteLength(s) > 4096) || args[0] !== 'compile') fail('source_refactor_arguments');
  const found = new Map(), allowed = ['--plan-file', '--output', '--binary', '--max-patch-bytes', '--timeout-ms'];
  for (let at = 1; at < args.length; at += 2) {
    const key = args[at], value = args[at + 1];
    if (!allowed.includes(key) || found.has(key) || !value || value.startsWith('--')) fail('source_refactor_arguments');
    found.set(key, value);
  }
  for (const key of ['--plan-file', '--output']) if (!found.has(key)) fail('source_refactor_arguments');
  if (found.has('--binary') && !['literal', 'delta', 'delta-runs'].includes(found.get('--binary'))) fail('source_refactor_binary_profile');
  const positive = (key, fallback, maximum) => {
    const value = found.get(key) ?? String(fallback);
    if (!/^[1-9][0-9]{0,8}$/.test(value) || Number(value) > maximum) fail('source_refactor_limit');
    return Number(value);
  };
  return { input: absolute(found.get('--plan-file')), output: absolute(found.get('--output')),
    ...(found.has('--binary') ? { binary: found.get('--binary') } : {}),
    maxPatchBytes: positive('--max-patch-bytes', REPLACEMENT_LIMITS.maxPatchBytes, REPLACEMENT_LIMITS.maxPatchBytes),
    timeoutMs: positive('--timeout-ms', 30000, 300000) };
}
async function emit(stream, value) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  if (bytes.length > 65536) fail('source_refactor_output_limit');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => { if (done) return; done = true; clearTimeout(timer);
      if (!error) stream.removeListener('error', onError); error ? reject(error) : resolve(); };
    const onError = error => finish(error);
    const timer = setTimeout(() => { const e = new Error('source_refactor_output_timeout'); stream.destroy(e); finish(e); }, 10000);
    stream.once('error', onError);
    try { stream.write(bytes, finish); } catch (error) { finish(error); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr, signal } = {}) {
  const stop = new AbortController(), abort = () => stop.abort();
  process.on('SIGTERM', abort); process.on('SIGINT', abort); signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) abort();
  let receipt, unconfirmed;
  try {
    if (args.length === 1 && args[0] === '--help') { await emit(stdout, { usage: USAGE }); return 0; }
    const options = argumentsFor(args), time = clock({ timeoutMs: options.timeoutMs, signal: stop.signal });
    time.check(); await directory(dirname(options.output));
    try { await lstat(options.output); fail('source_refactor_destination_exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const plan = await loadSourceRefactorFiles(options.input, time.check);
    const compiled = compileSourceRefactoring(plan.format, plan.changes,
      { maxPatchBytes: options.maxPatchBytes, ...(options.binary ? { binary: options.binary } : {}) }, time.check);
    const candidate = { type: 'source_refactoring_compiled', profile: REFACTOR_PROFILE, native_patch_profile: compiled.native_patch_profile,
      output: options.output, object_format: plan.format, plan_sha256: plan.plan_sha256,
      patch_sha256: hash(compiled.patch), patch_bytes: compiled.patch.length, changed_paths: compiled.changes.length,
      file_sections: compiled.file_sections, move_count: compiled.move_count, source_bytes: compiled.source_bytes, result_bytes: compiled.result_bytes,
      ...(options.binary ? { binary_profile: options.binary, binary_files: compiled.binary_files } : {}),
      ...(['delta', 'delta-runs'].includes(options.binary) ? { delta_members: compiled.delta_members, literal_members: compiled.literal_members } : {}),
      ...(options.binary === 'delta-runs' ? { aligned_copy_regions: compiled.aligned_copy_regions } : {}),
      preimages_verified: true, source_membership_verified: false, destinations_absent_verified: false, publication_attempted: false };
    // Deliver queued stop requests before publication. Once publication starts,
    // finish sync/readback instead of deleting or reusing an ambiguous output.
    await yieldTurn(); time.check();
    try {
      await writeNew(options.output, compiled.patch);
      if (!(await readPrivate(options.output, options.maxPatchBytes)).equals(compiled.patch)) fail('source_refactor_readback');
      await syncDirectory(dirname(options.output)); receipt = candidate;
    } catch (error) { if (error.code !== 'EEXIST') unconfirmed = candidate; throw error; }
    await emit(stdout, receipt); return 0;
  } catch (error) {
    try { await emit(stderr, { type: 'source_refactoring_error', code: error.code ?? 'source_refactor_failed',
      ...(receipt ? { retained_result: receipt } : {}), ...(unconfirmed ? { publication_unconfirmed: unconfirmed } : {}),
      repository_publication_attempted: false }); } catch { /* The output and independent hashes are retained. */ }
    return receipt || unconfirmed ? 4 : 2;
  } finally {
    process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); signal?.removeEventListener('abort', abort);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
