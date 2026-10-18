#!/usr/bin/env node
// Read-only source acquisition; destination preparation/publication stay separate.
import { pathToFileURL } from 'node:url';
import { captureGithubIssueMigration } from './lib/github-issue-capture-migration.mjs';
import { operatorJson } from './lib/forge-operator-io.mjs';

const USAGE = `usage: node scripts/capture_github_issue_migration.mjs <start|prepare|resume|status>
  --workdir <private-capture-directory>
  --inventory <private-inventory-file> --inventory-sha256 <independent-pin> (start/prepare)
  --confirm <original-session-sha256> (resume/status)
  [--token-file <private-GitHub-read-token>] (start/prepare/resume)
  [--offset <nonnegative-number> --max-capture-bytes <1..67108864> --max-steps <1..10000>] (start/prepare)
  [--max-batches <1..128> --max-requests <1..4096> --max-read-bytes <1..268435456>
   --source-retries <0..10>] (start/resume)
  [--timeout-ms <1..300000>]

Start prepares an absent directory, emits its independent session pin before any
network work, then captures missing batches. Prepare stops after offline setup.
Resume retains the original inventory, source visibility, offset and captured bytes.
Status reads local custody only and does not require the source credential.
The completed sources.json feeds migrate_github_issues.mjs prepare after separate
review and approval of sources.sha256. No native mutation or new key is created.
SIGTERM/SIGINT cancel source reads. A retained owner is never stolen or removed.
Exit 0: complete capture, or completed offline preparation; 3: incomplete/stopped
capture; 2: input/read failure before validated session progress; 4: known result
but output/cleanup failed. See docs/GITHUB_ISSUE_MIGRATION_CAPTURE.md.`;
const FLAGS = { '--workdir': 'workdir', '--inventory': 'inventoryFile', '--inventory-sha256': 'inventorySha256',
  '--confirm': 'confirm', '--token-file': 'tokenFile', '--offset': 'offset', '--max-capture-bytes': 'maxCaptureBytes',
  '--max-steps': 'maxSteps', '--max-batches': 'maxBatches', '--max-requests': 'maxRequests',
  '--max-read-bytes': 'maxReadBytes', '--source-retries': 'maxSourceRetries', '--timeout-ms': 'timeoutMs' };
const NUMBERS = new Set(['offset', 'maxCaptureBytes', 'maxSteps', 'maxBatches', 'maxRequests', 'maxReadBytes', 'maxSourceRetries', 'timeoutMs']);
function parse(args) {
  if (!Array.isArray(args) || args.length > 29 || args.length % 2 !== 1 ||
      !['start', 'prepare', 'resume', 'status'].includes(args[0]) ||
      args.some(arg => typeof arg !== 'string' || arg.length > 8192 || /[\x00-\x1f\x7f]/u.test(arg)) ||
      args.reduce((n, arg) => n + arg.length, 0) > 65536) throw new Error('capture_command_arguments');
  const result = { operation: args[0] };
  for (let i = 1; i < args.length; i += 2) {
    const key = FLAGS[args[i]], raw = args[i + 1];
    if (!Object.hasOwn(FLAGS, args[i]) || Object.hasOwn(result, key) || !raw || raw.startsWith('--')) throw new Error('capture_command_arguments');
    if (NUMBERS.has(key) && (!/^(?:0|[1-9][0-9]{0,15})$/.test(raw) || !Number.isSafeInteger(Number(raw)))) throw new Error('capture_command_number');
    result[key] = NUMBERS.has(key) ? Number(raw) : raw;
  }
  return result;
}
// Every write is bounded and awaited. Output failure never initiates another GET.
export function writeJson(stream, value, timeoutMs = 10000) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) return Promise.reject(new Error('capture_command_output_deadline'));
  const text = operatorJson(value);
  if (Buffer.byteLength(text) > 65536) return Promise.reject(new Error('capture_command_output_limit'));
  return new Promise((resolve, reject) => {
    let settled = false;
    const failed = error => {
      if (settled) return;
      settled = true; clearTimeout(timer); stream.removeListener('close', closed); reject(error);
      // Retain the error listener for Node's event after a failing write callback.
    };
    const closed = () => failed(new Error('capture_command_output_closed'));
    const timer = setTimeout(() => {
      const error = new Error('capture_command_output_deadline'); failed(error); stream.destroy(error);
    }, timeoutMs);
    stream.once('error', failed); stream.once('close', closed);
    try {
      stream.write(text, error => {
        if (error) { failed(error); return; }
        if (settled) return;
        settled = true; clearTimeout(timer); stream.removeListener('error', failed); stream.removeListener('close', closed); resolve();
      });
    } catch (error) { failed(error); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort();
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result, ready, timer, outputFailed = false;
  try {
    if (args.length === 1 && args[0] === '--help') { await writeJson(stdout, { usage: USAGE }); return 0; }
    const options = parse(args), timeout = options.timeoutMs ?? 300000;
    if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300000) throw new Error('capture_command_timeout');
    const end = performance.now() + timeout; timer = setTimeout(abort, timeout);
    const remaining = () => { if (performance.now() >= end) abort(); stop.signal.throwIfAborted(); return Math.max(1, Math.floor(end - performance.now())); };
    if (options.operation === 'start') {
      const { maxBatches, maxRequests, maxReadBytes, maxSourceRetries, ...preparation } = options;
      // Validate all start controls before even creating offline custody.
      for (const [value, min, max] of [[maxBatches, 1, 128], [maxRequests, 1, 4096], [maxReadBytes, 1, 268435456], [maxSourceRetries, 0, 10]]) {
        if (value !== undefined && (!Number.isSafeInteger(value) || value < min || value > max)) throw new Error('capture_command_budget');
      }
      ready = await captureGithubIssueMigration({ ...preparation, operation: 'prepare', signal: stop.signal, timeoutMs: remaining() });
      try { await writeJson(stdout, { ...ready, type: 'github_issue_capture_session_ready' }); }
      catch (error) { outputFailed = true; throw error; }
      result = await captureGithubIssueMigration({ operation: 'resume', workdir: ready.workdir, confirm: ready.session_sha256,
        tokenFile: options.tokenFile, maxBatches, maxRequests, maxReadBytes, maxSourceRetries, signal: stop.signal, timeoutMs: remaining() });
    } else result = await captureGithubIssueMigration({ ...options, signal: stop.signal, timeoutMs: remaining() });
    try { await writeJson(stdout, result); } catch (error) { outputFailed = true; throw error; }
    return options.operation === 'prepare' || result.complete ? 0 : 3;
  } catch (error) {
    const progress = error.capture_progress ?? result ?? ready ?? null;
    const code = error.code ?? error.message;
    try { await writeJson(stderr, { type: 'github_issue_capture_error', schema_version: 1,
      code: typeof code === 'string' && /^(?:(?:github_|operator_|capture_command_)[A-Za-z0-9_]+|E[A-Z_]+|ABORT_ERR)$/.test(code) ? code.slice(0, 128) : 'capture_command_failed',
      capture_progress: progress, output_failed: outputFailed, native_mutation_submitted: false,
      ...(ready ? { original_session_sha256: ready.session_sha256 } : {}) }); } catch { /* Original local custody remains. */ }
    return outputFailed || progress?.complete ? 4 : error.name === 'AbortError' || Number.isSafeInteger(progress?.captured_batches) ? 3 : 2;
  } finally { clearTimeout(timer); process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
