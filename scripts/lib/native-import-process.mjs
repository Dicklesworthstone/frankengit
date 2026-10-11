// Process ownership for the trusted native source-import command. No shell,
// PATH lookup, Git helper, background worker or automatic resubmission.
import { runNativeProcess } from './native-process-owner.mjs';
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
  let result;
  try {
    result = await runNativeProcess(fg, args, { timeoutMs: live.remaining(), signal: live.signal, stdin: key });
  } catch (error) {
    const codes = {
      native_process_invalid_options: 'invalid_import_lifetime',
      native_process_spawn_failed: 'native_import_spawn_failed',
      native_process_cancelled: 'native_import_cancelled',
      native_process_deadline: 'native_import_deadline',
      native_process_output_failed: 'native_import_output_failed',
      native_process_stdout_limit: 'native_import_report_limit',
      native_process_stderr_limit: 'native_import_diagnostic_limit',
      native_process_input_failed: 'native_import_key_pipe_failed',
      native_process_descendants_remaining: 'native_import_containment_failed',
      native_process_containment_failed: 'native_import_containment_failed',
    };
    throw importError(codes[error.code] ?? 'native_import_process_interrupted', error.details);
  }
  // A stopped/abnormal child is not evidence that its repository effect was
  // rolled back. The caller retains the exact identity for read-only lookup.
  live.check();
  if (result.signal !== null || !Number.isInteger(result.code)) throw importError('native_import_process_interrupted');
  return { code: result.code, stdout: result.stdout, stderr: result.stderr };
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
