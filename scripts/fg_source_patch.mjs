#!/usr/bin/env node
// Offline, create-only exact patch compilation from explicit private body files.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { lstat } from 'node:fs/promises';
import { absolute, directory, readPrivate, writeNew, syncDirectory } from './operator/workflow_watch_io.mjs';
import { fields, parse, fail, clock, hash } from './operator/source_edit_wire.mjs';
import { compileSourceReplacements, REPLACEMENT_PROFILE, REPLACEMENT_LIMITS } from './operator/source_edit_replacements.mjs';
import { compileSourceSplices, SPLICE_PROFILE, SPLICE_LIMITS } from './operator/source_edit_splices.mjs';
import { compileCompactSourceSplices, SPLICE_PATCH_PROFILES } from './operator/source_edit_compact_splices.mjs';
const PLAN_BYTES = 512 * 1024;
const USAGE = 'node scripts/fg_source_patch.mjs compile --changes-file PRIVATE_JSON --output ABSENT_PRIVATE_PATCH [--binary literal|delta] [--max-patch-bytes 1..1048576] [--timeout-ms 1..300000]\nnode scripts/fg_source_patch.mjs splice --splices-file PRIVATE_JSON --output ABSENT_PRIVATE_PATCH [--binary literal|delta | --patch-profile trim-common-lines-v1|bounded-line-hunks-v1] [--max-patch-bytes 1..1048576] [--timeout-ms 1..300000]';
function argumentsFor(args) {
  if (!Array.isArray(args) || args.length > 13 || args.some(s => typeof s !== 'string' || Buffer.byteLength(s) > 4096) || !['compile', 'splice'].includes(args[0])) fail('source_patch_arguments');
  const inputFlag = args[0] === 'splice' ? '--splices-file' : '--changes-file';
  const found = new Map(), allowed = [inputFlag, '--output', '--max-patch-bytes', '--timeout-ms', '--binary', ...(args[0] === 'splice' ? ['--patch-profile'] : [])];
  for (let at = 1; at < args.length; at += 2) {
    const key = args[at], value = args[at + 1];
    if (!allowed.includes(key) || found.has(key) || !value || value.startsWith('--')) fail('source_patch_arguments');
    found.set(key, value);
  }
  for (const name of [inputFlag, '--output']) if (!found.has(name)) fail('source_patch_arguments');
  const positive = (key, fallback, maximum) => {
    const value = found.get(key) ?? String(fallback);
    if (!/^[1-9][0-9]{0,8}$/.test(value) || Number(value) > maximum) fail('source_patch_limit');
    return Number(value);
  };
  if (found.has('--binary') && !['literal', 'delta'].includes(found.get('--binary'))) fail('source_patch_binary_profile');
  if (found.has('--patch-profile') && (found.has('--binary') || !SPLICE_PATCH_PROFILES.includes(found.get('--patch-profile')))) fail('source_splice_patch_profile');
  return { operation: args[0], input: absolute(found.get(inputFlag)), output: absolute(found.get('--output')),
    ...(found.has('--binary') ? { binary: found.get('--binary') } : {}),
    ...(found.has('--patch-profile') ? { patchProfile: found.get('--patch-profile') } : {}),
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
// Instructions and offsets are data, never strings to execute or a search rule.
// Read whole originals privately; the core checks their independent Git IDs and
// matches every range before any result or final patch is published.
async function splicesFromFile(path, check) {
  const plan = parse(await read(path, PLAN_BYTES, check), PLAN_BYTES);
  fields(plan, ['schema', 'object_format', 'files']);
  if (plan.schema !== SPLICE_PROFILE || !['sha1', 'sha256'].includes(plan.object_format) ||
      !Array.isArray(plan.files) || !plan.files.length || plan.files.length > 32) fail('source_splice_plan');
  const files = []; let sourceBytes = 0, count = 0;
  const decode = value => {
    if (typeof value !== 'string' || value.length > 2 * 1048576 || !/^(?:[0-9a-f]{2})*$/.test(value)) fail('source_splice_hex');
    return Buffer.from(value, 'hex');
  };
  for (const row of plan.files) {
    check(); fields(row, ['path_hex', 'before', 'after_mode', 'edits']);
    const before = fields(row.before, ['file', 'blob', 'mode']);
    if (![0o100644, 0o100755].includes(before.mode) || ![0o100644, 0o100755].includes(row.after_mode)) fail('source_patch_mode');
    if (!Array.isArray(row.edits) || row.edits.length > SPLICE_LIMITS.maxSplices - count) fail('source_splice_count');
    count += row.edits.length;
    const edits = row.edits.map(edit => {
      check(); fields(edit, ['byte_start', 'before_hex', 'after_hex']);
      if (!Number.isSafeInteger(edit.byte_start) || edit.byte_start < 0 || edit.byte_start > 1048576) fail('source_splice_range');
      return { byte_start: edit.byte_start, before: decode(edit.before_hex), after: decode(edit.after_hex) };
    });
    const bytes = await read(before.file, Math.min(1048576, REPLACEMENT_LIMITS.maxSourceBytes - sourceBytes), check);
    sourceBytes += bytes.length;
    files.push({ path_hex: row.path_hex, before: { bytes, blob: before.blob, mode: before.mode }, after_mode: row.after_mode, edits });
  }
  return { format: plan.object_format, files };
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
    const splice = options.operation === 'splice';
    const plan = await (splice ? splicesFromFile : changesFromFile)(options.input, time.check);
    const compiled = options.patchProfile
      ? await compileCompactSourceSplices(plan.format, plan.files, { patchProfile: options.patchProfile, maxPatchBytes: options.maxPatchBytes }, time.check)
      : (splice ? compileSourceSplices : compileSourceReplacements)(plan.format, splice ? plan.files : plan.changes,
        { maxPatchBytes: options.maxPatchBytes, ...(options.binary ? { binary: options.binary } : {}) }, time.check);
    const candidate = { type: 'source_patch_compiled', profile: compiled.profile, output: options.output,
      object_format: plan.format, patch_sha256: hash(compiled.patch), patch_bytes: compiled.patch.length,
      changed_paths: compiled.changes.length, source_bytes: compiled.source_bytes, result_bytes: compiled.result_bytes,
      ...(options.binary ? { binary_files: compiled.binary_files } : {}),
      ...(options.binary === 'delta' ? { delta_members: compiled.delta_members, literal_members: compiled.literal_members } : {}),
      ...(options.patchProfile ? { patch_profile: compiled.patch_profile, hunks: compiled.hunks } : {}),
      ...(splice ? { splice_profile: compiled.splice_profile, splice_count: compiled.splice_count,
        expected_bytes: compiled.expected_bytes, inserted_bytes: compiled.inserted_bytes, preimages_verified: true } : {}),
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
