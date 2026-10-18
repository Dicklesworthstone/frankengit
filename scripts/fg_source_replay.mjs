#!/usr/bin/env node
// Explicit offline replay; native publication and original-key outcome recovery
// remain separate. There is deliberately no endpoint, token or journal option.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { absolute, directory, readPrivate } from './operator/workflow_watch_io.mjs';
import { parse, clock } from './operator/source_edit_wire.mjs';
import { SOURCE_PACKAGE_BYTES, CHANGES_INPUT_BYTES } from './operator/source_changes.mjs';
import { fail, reviewedHash } from './operator/source_replay.mjs';
import { absentReplayOutput, captureSourceReplay, loadSourceReplay } from './operator/source_replay_capture.mjs';

const USAGE = `node scripts/fg_source_replay.mjs capture
  --package ORIGINAL_PACKAGE --expect ORIGINAL_INDEPENDENT_EXPECTATION --changes ORIGINAL_CHANGES
  --confirm-draft-sha256 REVIEWED_ORIGINAL_DRAFT_HASH
  --next-package NEXT_PACKAGE --next-expect NEXT_INDEPENDENT_EXPECTATION --output ABSENT_DIRECTORY
node scripts/fg_source_replay.mjs inspect --capture PRIVATE_DIRECTORY --sha256 RETAINED_CAPTURE_HASH

Both commands accept --timeout-ms 1..300000 (default 30000).
All paths are normalized absolute owner-private POSIX paths. Supply the next
commit independently; no commit is fetched or chosen automatically. Replay
requires the entire selected path/blob/mode read set unchanged, including context,
no-ops and copy sources. Exact patch/effects are retained; creations re-prove absence.
The saved source.json, expected.json and changes.json feed fg_source_changes.mjs.
Review the NEW draft.json and confirm its NEW hash before preparation/staging.
Resolve any uncertain original publication by its original key; this tool neither
finds nor retargets existing journals. No ancestry/semantic/permission claim.
No network, credential, overwrite, Git subprocess, automatic merge or retry.
Exit 0: complete result; 2: refusal; 3: cancelled before an output slot was claimed;
4: local output/result may exist, retain its location and hashes and inspect it.`;
function options(args) {
  if (!Array.isArray(args) || args.length > 17 || args.length % 2 !== 1 ||
      args.some(v => typeof v !== 'string' || Buffer.byteLength(v) > 4096)) fail('source_replay_cli_arguments');
  const op = args[0], required = op === 'capture'
    ? ['--package', '--expect', '--changes', '--confirm-draft-sha256', '--next-package', '--next-expect', '--output']
    : op === 'inspect' ? ['--capture', '--sha256'] : null;
  if (!required) fail('source_replay_cli_operation');
  const f = new Map();
  for (let i = 1; i < args.length; i += 2) {
    const flag = args[i], value = args[i + 1];
    if (![...required, '--timeout-ms'].includes(flag) || f.has(flag) || !value || value.startsWith('--')) fail('source_replay_cli_option');
    f.set(flag, value);
  }
  if (required.some(k => !f.has(k))) fail('source_replay_cli_option');
  const timeout = f.get('--timeout-ms') ?? '30000';
  if (!/^[1-9][0-9]{0,5}$/.test(timeout) || Number(timeout) > 300000) fail('source_replay_cli_timeout');
  for (const [key, value] of f) if (key !== '--timeout-ms') {
    if (key === '--sha256' || key === '--confirm-draft-sha256') reviewedHash(value); else absolute(value);
  }
  return { op, f, timeout: Number(timeout) };
}
async function privateFile(path, maximum, check) {
  check(); await directory(dirname(path)); const bytes = await readPrivate(path, maximum); check(); return bytes;
}
async function emit(stream, value, signal) {
  const bytes = `${JSON.stringify(value)}\n`; if (Buffer.byteLength(bytes) > 32768) fail('source_replay_output_limit');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => {
      if (done) return; done = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      if (!error) stream.removeListener('error', onError); error ? reject(error) : resolve();
    };
    const onError = error => finish(error);
    const stop = code => { const error = new Error(code); finish(error); stream.destroy(error); };
    const abort = () => stop('source_replay_output_cancelled');
    const timer = setTimeout(() => stop('source_replay_output_timeout'), 10000);
    stream.once('error', onError); signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort(); else { try { stream.write(bytes, error => finish(error)); } catch (e) { finish(e); } }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort();
  process.on('SIGTERM', abort); process.on('SIGINT', abort); let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await emit(stdout, { usage: USAGE }, stop.signal); return 0; }
    const { op, f, timeout } = options(args), time = clock({ timeoutMs: timeout, signal: stop.signal });
    if (typeof process.getuid !== 'function') fail('source_replay_posix_required');
    if (op === 'inspect') result = (await loadSourceReplay(f.get('--capture'), f.get('--sha256'),
      { signal: stop.signal, timeoutMs: time.remaining() })).saved;
    else {
      await absentReplayOutput(f.get('--output')); time.check();
      const expected = parse(await privateFile(f.get('--expect'), 131072, time.check), 131072);
      const nextExpected = parse(await privateFile(f.get('--next-expect'), 131072, time.check), 131072);
      const changes = parse(await privateFile(f.get('--changes'), CHANGES_INPUT_BYTES, time.check), CHANGES_INPUT_BYTES);
      const original = await privateFile(f.get('--package'), SOURCE_PACKAGE_BYTES, time.check);
      const next = await privateFile(f.get('--next-package'), SOURCE_PACKAGE_BYTES, time.check);
      result = await captureSourceReplay(f.get('--output'), original, expected, changes, next, nextExpected,
        { confirmDraftSha256: f.get('--confirm-draft-sha256'), signal: stop.signal, timeoutMs: time.remaining() });
    }
    await emit(stdout, result, stop.signal); return 0;
  } catch (error) {
    const code = /^source_(?:replay|changes|edit)_[a-z0-9_]{1,80}$/.test(error.code ?? '') ? error.code : 'source_replay_cli_refused';
    try { await emit(stderr, { type: 'source_replay_error', code, repository_changed: false,
      ...(result ? { retained_result: result } : error.publication_unconfirmed ? { publication_unconfirmed: error.publication_unconfirmed } : {}) }); }
    catch { /* Preserve any owned output and the original root pin. */ }
    return result || error.publication_unconfirmed ? 4 : stop.signal.aborted ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
