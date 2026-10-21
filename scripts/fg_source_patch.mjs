#!/usr/bin/env node
// Offline, create-only exact patch compilation from explicit private body files.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { lstat } from 'node:fs/promises';
import { absolute, directory, readPrivate, writeNew, syncDirectory } from './operator/workflow_watch_io.mjs';
import { fields, parse, fail, clock, hash } from './operator/source_edit_wire.mjs';
import { compileSourceReplacements, REPLACEMENT_PROFILE, REPLACEMENT_LIMITS } from './operator/source_edit_replacements.mjs';
const PLAN_BYTES = 512 * 1024;
const USAGE = 'node scripts/fg_source_patch.mjs compile --changes-file PRIVATE_JSON --output ABSENT_PRIVATE_PATCH [--binary literal] [--max-patch-bytes 1..1048576] [--timeout-ms 1..300000]';
function argumentsFor(args) {
  if (!Array.isArray(args) || args.length > 11 || args.some(s => typeof s !== 'string' || Buffer.byteLength(s) > 4096) || args[0] !== 'compile') fail('source_patch_arguments');
  const found = new Map(), allowed = ['--changes-file', '--output', '--max-patch-bytes', '--timeout-ms', '--binary'];
  for (let at = 1; at < args.length; at += 2) {
    const key = args[at], value = args[at + 1];
    if (!allowed.includes(key) || found.has(key) || !value || value.startsWith('--')) fail('source_patch_arguments');
    found.set(key, value);
  }
  for (const name of ['--changes-file', '--output']) if (!found.has(name)) fail('source_patch_arguments');
  const positive = (key, fallback, maximum) => {
    const value = found.get(key) ?? String(fallback);
    if (!/^[1-9][0-9]{0,8}$/.test(value) || Number(value) > maximum) fail('source_patch_limit');
    return Number(value);
  };
  if (found.has('--binary') && found.get('--binary') !== 'literal') fail('source_patch_binary_profile');
  return { input: absolute(found.get('--changes-file')), output: absolute(found.get('--output')),
    ...(found.has('--binary') ? { binary: 'literal' } : {}),
    maxPatchBytes: positive('--max-patch-bytes', REPLACEMENT_LIMITS.maxPatchBytes, REPLACEMENT_LIMITS.maxPatchBytes),
    timeoutMs: positive('--timeout-ms', 30000, 300000) };
}
async function read(path, maximum, check) {
  check(); await directory(dirname(absolute(path)));
  const bytes = await readPrivate(path, maximum); check(); return bytes;
}
async function changesFromFile(path, check) {
  const plan = parse(await read(path, PLAN_BYTES, check), PLAN_BYTES);
  fields(plan, ['schema', 'object_format', 'changes']);
  if (plan.schema !== REPLACEMENT_PROFILE || !['sha1', 'sha256'].includes(plan.object_format) ||
      !Array.isArray(plan.changes) || !plan.changes.length || plan.changes.length > 32) fail('source_patch_plan');
  const changes = []; let sourceBytes = 0, resultBytes = 0;
  for (const row of plan.changes) {
    fields(row, ['path_hex', 'before', 'after']);
    const value = { path_hex: row.path_hex, before: null, after: null };
    for (const name of ['before', 'after']) {
      if (row[name] === null) continue;
      const v = fields(row[name], name === 'before' ? ['file', 'blob', 'mode'] : ['file', 'mode']);
      if (![0o100644, 0o100755].includes(v.mode)) fail('source_patch_mode');
      const bytes = await read(v.file, 1048576, check);
      if (name === 'before') sourceBytes += bytes.length; else resultBytes += bytes.length;
      if (sourceBytes > REPLACEMENT_LIMITS.maxSourceBytes || resultBytes > REPLACEMENT_LIMITS.maxResultBytes) fail('source_replacement_bytes');
      value[name] = { mode: v.mode, bytes, ...(name === 'before' ? { blob: v.blob } : {}) };
    }
    changes.push(value);
  }
  return { format: plan.object_format, changes };
}
async function emit(stream, value) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  if (bytes.length > 65536) fail('source_patch_output_limit');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => { if (done) return; done = true; clearTimeout(timer);
      if (!error) stream.removeListener('error', onError); error ? reject(error) : resolve(); };
    const onError = error => finish(error);
    const timer = setTimeout(() => { const e = new Error('source_patch_output_timeout'); stream.destroy(e); finish(e); }, 10000);
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
    try { await lstat(options.output); fail('source_patch_destination_exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const plan = await changesFromFile(options.input, time.check);
    const compiled = compileSourceReplacements(plan.format, plan.changes, { maxPatchBytes: options.maxPatchBytes,
      ...(options.binary ? { binary: options.binary } : {}) }, time.check);
    const candidate = { type: 'source_patch_compiled', profile: compiled.profile, output: options.output,
      object_format: plan.format, patch_sha256: hash(compiled.patch), patch_bytes: compiled.patch.length,
      changed_paths: compiled.changes.length, source_bytes: compiled.source_bytes, result_bytes: compiled.result_bytes,
      ...(options.binary ? { binary_files: compiled.binary_files } : {}),
      source_membership_verified: false, publication_attempted: false };
    time.check();
    try {
      // Once started, finish filesystem publication/readback even if canceled.
      // No deletion, overwrite or second output path can mask uncertainty.
      await writeNew(options.output, compiled.patch);
      if (!(await readPrivate(options.output, options.maxPatchBytes)).equals(compiled.patch)) fail('source_patch_readback');
      await syncDirectory(dirname(options.output)); receipt = candidate;
    } catch (error) { if (error.code !== 'EEXIST') unconfirmed = candidate; throw error; }
    await emit(stdout, receipt); return 0;
  } catch (error) {
    try { await emit(stderr, { type: 'source_patch_error', code: error.code ?? 'source_patch_failed',
      ...(receipt ? { retained_result: receipt } : {}), ...(unconfirmed ? { publication_unconfirmed: unconfirmed } : {}),
      repository_publication_attempted: false }); } catch { /* Retain the original file and independent hash. */ }
    return receipt || unconfirmed ? 4 : 2;
  } finally {
    process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); signal?.removeEventListener('abort', abort);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
