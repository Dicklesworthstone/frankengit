// Process ownership for the trusted native source-import command. No shell,
// PATH lookup, Git helper, background worker or automatic resubmission.
import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';

export function importError(code, details) {
  const error = new Error(code); error.code = code;
  if (details !== undefined) error.details = details;
  return error;
}
export function importLifetime(timeoutMs, signal) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3600000
    || (signal !== undefined && !(signal instanceof AbortSignal))) throw importError('invalid_import_lifetime');
  const until = performance.now() + timeoutMs;
  const check = () => {
    if (signal?.aborted) throw importError('native_import_cancelled');
    if (performance.now() >= until) throw importError('native_import_deadline');
  };
  check();
  return { signal, check, remaining: () => Math.max(1, Math.ceil(until - performance.now())) };
}
export async function runImportProcess(fg, args, live, key) {
  live.check();
  return await new Promise((resolve, reject) => {
    let child;
    try { child = spawn(fg, args, { shell: false, windowsHide: true, stdio: [key === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] }); }
    catch { reject(importError('native_import_spawn_failed')); return; }
    const output = [], diagnostic = []; let stdoutBytes = 0, stderrBytes = 0;
    let failure = null, escalation = null;
    const stop = code => {
      failure ??= importError(code);
      if (escalation !== null) return;
      child.kill('SIGTERM');
      escalation = setTimeout(() => child.kill('SIGKILL'), 500);
    };
    const abort = () => stop('native_import_cancelled');
    const timer = setTimeout(() => stop('native_import_deadline'), live.remaining());
    live.signal?.addEventListener('abort', abort, { once: true });
    child.on('error', () => { failure ??= importError('native_import_spawn_failed'); });
    child.stdout.on('error', () => stop('native_import_output_failed'));
    child.stderr.on('error', () => stop('native_import_output_failed'));
    child.stdout.on('data', chunk => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > 65536) stop('native_import_report_limit');
      else output.push(chunk);
    });
    child.stderr.on('data', chunk => {
      stderrBytes += chunk.length;
      if (stderrBytes > 65536) stop('native_import_diagnostic_limit');
      else diagnostic.push(chunk);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer); clearTimeout(escalation); live.signal?.removeEventListener('abort', abort);
      // A stopped/abnormal child is not evidence that its repository effect was
      // rolled back. The caller retains the exact identity for read-only lookup.
      if (failure) reject(failure);
      else if (signal !== null || !Number.isInteger(code)) reject(importError('native_import_process_interrupted'));
      else resolve({ code, stdout: Buffer.concat(output), stderr: Buffer.concat(diagnostic) });
    });
    if (key !== undefined) {
      child.stdin.on('error', () => stop('native_import_key_pipe_failed'));
      child.stdin.end(key);
    }
    if (live.signal?.aborted) abort();
  });
}

// Native receipts contain ordinary integers and one JSON document. Do not
// silently discard duplicate fields, trailing records or lossy numeric tokens.
export function importJson(bytes) {
  let text, value;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    value = JSON.parse(text, (_key, value, context) => {
      if (typeof value !== 'number' || Number.isSafeInteger(value)) return value;
      if (!context || !/^(0|[1-9][0-9]*)$/.test(context.source)) throw importError('native_import_integer_precision');
      const integer = BigInt(context.source);
      if (integer > 18446744073709551615n) throw importError('native_import_integer_precision');
      return integer;
    });
  } catch { throw importError('invalid_native_import_json'); }
  let bare = '', quoted = false, escaped = false;
  for (const char of text) {
    if (quoted) {
      bare += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') quoted = false;
    } else if (char === '"') { quoted = true; bare += char; }
    else if (!' \t\r\n'.includes(char)) bare += char;
  }
  if (canonical(value) !== bare || value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw importError('noncanonical_native_import_json');
  }
  return value;
}

function canonical(value, depth = 0) {
  if (depth > 32) throw importError('native_import_json_depth');
  if (typeof value === 'bigint') return String(value);
  if (Array.isArray(value)) return '[' + value.map(v => canonical(v, depth + 1)).join(',') + ']';
  if (value !== null && typeof value === 'object') return '{' + Object.entries(value)
    .map(([k, v]) => JSON.stringify(k) + ':' + canonical(v, depth + 1)).join(',') + '}';
  return JSON.stringify(value);
}
