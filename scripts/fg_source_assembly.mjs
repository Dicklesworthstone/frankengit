#!/usr/bin/env node
// Explicit offline composition. No task scheduling, credentials, mutation retry
// or authority decisions are inferred from contribution files or their labels.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { absolute, directory, readPrivate } from './operator/workflow_watch_io.mjs';
import { parse, fields, clock } from './operator/source_edit_wire.mjs';
import { ASSEMBLY_LIMITS, assemblyPin, contributionId, fail } from './operator/source_assembly.mjs';
import { SOURCE_PACKAGE_BYTES, CHANGES_INPUT_BYTES } from './operator/source_changes.mjs';
import { absentAssemblyOutput, captureSourceAssembly, loadSourceAssembly } from './operator/source_assembly_capture.mjs';

const USAGE = `node scripts/fg_source_assembly.mjs capture --contributions PRIVATE_JSON --output ABSENT_DIRECTORY
node scripts/fg_source_assembly.mjs inspect --capture PRIVATE_DIRECTORY --sha256 RETAINED_CAPTURE_HASH

Selection: {contributions: [{id, package, expect, changes, confirm_draft_sha256}, ...]}.
Supply 2..8 independently reviewed same-commit contributions. All file paths are
normalized absolute owner-private POSIX paths. Profiles must agree. Overlapping
writes and changes to another contributor's selected read set refuse.
Capture freezes every original review/input and a new combined source/draft.
Review the NEW draft.json and confirm its NEW hash with prepare-packed and
stage-packed; inspect regenerates everything offline under the retained hash.
Resolve uncertain existing publications by their original keys before assembling
another change. Labels are not authenticated identities, leases or permission.
No network, token, Git subprocess, overwrite, automatic merge or publication.
Both commands accept --timeout-ms 1..300000 (default 30000).
Exit 0: complete; 2: refusal; 3: cancelled before claiming output; 4: retained or
uncertain local output/result. Lost stdout never proves absence of that output.`;
function options(args) {
  if (!Array.isArray(args) || args.length > 9 || args.length % 2 !== 1 ||
      args.some(v => typeof v !== 'string' || Buffer.byteLength(v) > 4096)) fail('source_assembly_cli_arguments');
  const op = args[0], required = op === 'capture' ? ['--contributions', '--output'] : op === 'inspect' ? ['--capture', '--sha256'] : null;
  if (!required) fail('source_assembly_cli_operation');
  const f = new Map();
  for (let i = 1; i < args.length; i += 2) {
    const flag = args[i], value = args[i + 1];
    if (![...required, '--timeout-ms'].includes(flag) || f.has(flag) || !value || value.startsWith('--')) fail('source_assembly_cli_option');
    f.set(flag, value);
  }
  if (required.some(k => !f.has(k))) fail('source_assembly_cli_option');
  const timeout = f.get('--timeout-ms') ?? '30000';
  if (!/^[1-9][0-9]{0,5}$/.test(timeout) || Number(timeout) > 300000) fail('source_assembly_cli_timeout');
  for (const [key, value] of f) if (key !== '--timeout-ms') {
    if (key === '--sha256') assemblyPin(value); else absolute(value);
  }
  return { op, f, timeout: Number(timeout) };
}
function selected(value) {
  fields(value, ['contributions']);
  if (!Array.isArray(value.contributions) || value.contributions.length < 2 || value.contributions.length > ASSEMBLY_LIMITS.contributions) fail('source_assembly_count');
  const seen = new Set(); let pathBytes = 0;
  return value.contributions.map(row => {
    fields(row, ['id', 'package', 'expect', 'changes', 'confirm_draft_sha256']);
    const id = contributionId(row.id), confirmDraftSha256 = assemblyPin(row.confirm_draft_sha256);
    if (seen.has(id)) fail('source_assembly_duplicate_id'); seen.add(id);
    for (const name of ['package', 'expect', 'changes']) { absolute(row[name]); pathBytes += Buffer.byteLength(row[name]); }
    if (pathBytes > 65536) fail('source_assembly_cli_paths');
    return { id, package: row.package, expect: row.expect, changes: row.changes, confirmDraftSha256 };
  });
}
async function privateFile(path, maximum, check) {
  check(); await directory(dirname(path)); const bytes = await readPrivate(path, maximum); check(); return bytes;
}
async function emit(stream, value, signal) {
  const bytes = `${JSON.stringify(value)}\n`; if (Buffer.byteLength(bytes) > 32768) fail('source_assembly_output_limit');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => { if (done) return; done = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      if (!error) stream.removeListener('error', onError); error ? reject(error) : resolve(); };
    const onError = error => finish(error);
    const stop = code => { const error = new Error(code); finish(error); stream.destroy(error); };
    const abort = () => stop('source_assembly_output_cancelled');
    const timer = setTimeout(() => stop('source_assembly_output_timeout'), 10000);
    stream.once('error', onError); signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort(); else { try { stream.write(bytes, error => finish(error)); } catch (error) { finish(error); } }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort();
  process.on('SIGTERM', abort); process.on('SIGINT', abort); let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await emit(stdout, { usage: USAGE }, stop.signal); return 0; }
    const { op, f, timeout } = options(args), time = clock({ timeoutMs: timeout, signal: stop.signal });
    if (typeof process.getuid !== 'function') fail('source_assembly_posix_required');
    if (op === 'inspect') result = (await loadSourceAssembly(f.get('--capture'), f.get('--sha256'),
      { signal: stop.signal, timeoutMs: time.remaining() })).saved;
    else {
      await absentAssemblyOutput(f.get('--output')); time.check();
      const rows = selected(parse(await privateFile(f.get('--contributions'), 131072, time.check), 131072));
      const input = []; let total = 0;
      for (const row of rows) {
        const read = async (name, maximum) => {
          if (total >= ASSEMBLY_LIMITS.inputBytes) fail('source_assembly_input_limit');
          const bytes = await privateFile(row[name], Math.min(maximum, ASSEMBLY_LIMITS.inputBytes - total), time.check);
          total += bytes.length; return bytes;
        };
        const expected = parse(await read('expect', 131072), 131072);
        const changes = parse(await read('changes', CHANGES_INPUT_BYTES), CHANGES_INPUT_BYTES);
        const packageBytes = await read('package', SOURCE_PACKAGE_BYTES);
        input.push({ id: row.id, confirmDraftSha256: row.confirmDraftSha256, packageBytes, expected, changes });
      }
      result = await captureSourceAssembly(f.get('--output'), input, { signal: stop.signal, timeoutMs: time.remaining() });
    }
    await emit(stdout, result, stop.signal); return 0;
  } catch (error) {
    const code = /^source_(?:assembly|changes|edit|union)_[a-z0-9_]{1,80}$/.test(error.code ?? '') ? error.code : 'source_assembly_cli_refused';
    try { await emit(stderr, { type: 'source_assembly_error', code, repository_changed: false,
      ...(result ? { retained_result: result } : error.publication_unconfirmed ? { publication_unconfirmed: error.publication_unconfirmed } : {}) }); }
    catch { /* Independently retained root and paths still identify custody. */ }
    return result || error.publication_unconfirmed ? 4 : stop.signal.aborted ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
