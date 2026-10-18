// One request/drain/finalize owner for explicitly trusted native executables.
// This is not a sandbox: a hostile child can leave its POSIX process group.
// POSIX children start a private group; Windows owns only the direct child.
import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { performance } from 'node:perf_hooks';

const TERM_GRACE_MS = 500;
const FINALIZE_MS = 2000;
const GROUP_POLL_MS = 25;
function error(code, details) {
  const value = new Error(`native_process_${code}`); value.code = value.message;
  if (details !== undefined) value.details = details;
  return value;
}

/** Run once, bound both output streams, and retain ownership through shutdown.
 * A rejection never proves that an already-started native mutation rolled back.
 * Limits cover the execution phase; shutdown has a separate 2-second bound.
 * If closure/quiescence cannot be established, report containment failure rather
 * than hanging or presenting a successful receipt. No automatic retry occurs.
 */
export async function runNativeProcess(executable, args, {
  timeoutMs, signal, stdin, stdoutLimit = 65536, stderrLimit = 65536,
} = {}) {
  if (typeof executable !== 'string' || !isAbsolute(executable) || executable.includes('\0')
    || !Array.isArray(args) || args.some(arg => typeof arg !== 'string' || arg.includes('\0'))
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3600000
    || [stdoutLimit, stderrLimit].some(limit => !Number.isSafeInteger(limit) || limit < 0)
    || (signal !== undefined && !(signal instanceof AbortSignal))
    || (stdin !== undefined && typeof stdin !== 'string' && !(stdin instanceof Uint8Array))) throw error('invalid_options');
  if (signal?.aborted) throw error('cancelled');
  const until = performance.now() + timeoutMs, group = process.platform !== 'win32';
  return await new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(executable, [...args], { shell: false, windowsHide: true,
        detached: group, stdio: [stdin === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
    } catch { reject(error('spawn_failed')); return; }
    const output = [], diagnostic = [];
    let outputBytes = 0, diagnosticBytes = 0, failure = null;
    let exited = false, closed = false, settled = false, draining = false;
    let exitCode = null, exitSignal = null, escalation, finalizer, poll, timer;
    // A missing PID is a spawn failure, never permission to signal PID 0 or the
    // operator's group. Unknown liveness fails closed, not as an empty group.
    function groupState() {
      if (!group || !child.pid) return 'absent';
      try { process.kill(-child.pid, 0); return 'present'; }
      catch (cause) { return cause.code === 'ESRCH' ? 'absent' : 'unknown'; }
    }
    function sendSignal(name) {
      try {
        if (group && child.pid) process.kill(-child.pid, name);
        else if (!exited && child.pid) child.kill(name);
      } catch (cause) {
        if (cause.code !== 'ESRCH') failure = error('containment_failed', {
          reason: failure?.code ?? 'native_process_signal_failed', signal_error: cause.code ?? 'unknown',
        });
      }
    }
    function finish(problem = failure) {
      if (settled) return;
      settled = true;
      clearTimeout(timer); clearTimeout(escalation); clearTimeout(finalizer); clearInterval(poll);
      signal?.removeEventListener('abort', abort);
      if (problem) { output.length = 0; diagnostic.length = 0; reject(problem); }
      else resolve({ code: exitCode, signal: exitSignal, stdout: Buffer.concat(output), stderr: Buffer.concat(diagnostic) });
    }
    function drained() {
      if (!settled && closed && groupState() === 'absent') finish();
    }
    function stop(problem) {
      if (settled) return;
      failure ??= problem;
      if (draining) return;
      draining = true;
      child.stdin?.destroy();
      sendSignal('SIGTERM');
      escalation = setTimeout(() => { sendSignal('SIGKILL'); drained(); }, TERM_GRACE_MS);
      poll = setInterval(drained, GROUP_POLL_MS);
      finalizer = setTimeout(() => {
        const problem = error('containment_failed', { reason: failure.code,
          leader_exited: exited, output_closed: closed, process_group: groupState(),
          scope: group ? 'posix-process-group' : 'direct-child' });
        // Retire local pipe handles only after reporting failed containment.
        // Closing a pipe is NOT evidence that the executable stopped writing.
        finish(problem);
        child.stdin?.destroy(); child.stdout.destroy(); child.stderr.destroy(); child.unref();
      }, FINALIZE_MS);
      drained();
    }
    const abort = () => stop(error('cancelled'));
    child.once('error', () => stop(error('spawn_failed')));
    child.stdout.on('error', () => stop(error('output_failed')));
    child.stderr.on('error', () => stop(error('output_failed')));
    child.stdout.on('data', chunk => {
      if (failure || settled) return;
      outputBytes += chunk.length;
      if (outputBytes > stdoutLimit) stop(error('stdout_limit'));
      else output.push(chunk);
    });
    child.stderr.on('data', chunk => {
      if (failure || settled) return;
      diagnosticBytes += chunk.length;
      if (diagnosticBytes > stderrLimit) stop(error('stderr_limit'));
      else diagnostic.push(chunk);
    });
    child.once('exit', () => {
      exited = true;
      // A successful leader must not leave live descendants behind, including
      // those that closed their inherited pipes. A private group detects them.
      if (groupState() !== 'absent') stop(error('descendants_remaining'));
    });
    child.once('close', (code, signalName) => {
      closed = true; exitCode = code; exitSignal = signalName;
      if (!failure && signal?.aborted) stop(error('cancelled'));
      if (!failure && performance.now() >= until) stop(error('deadline'));
      if (!failure && groupState() !== 'absent') stop(error('descendants_remaining'));
      if (failure) drained(); else finish();
    });
    signal?.addEventListener('abort', abort, { once: true });
    timer = setTimeout(() => stop(error('deadline')), Math.max(1, Math.ceil(until - performance.now())));
    if (stdin !== undefined) {
      child.stdin.on('error', () => stop(error('input_failed')));
      // Snapshot caller-owned input; it must not change while a pipe is pending.
      child.stdin.end(Buffer.from(stdin));
    }
    // Cover cancellation between the pre-spawn check and listener installation.
    if (signal?.aborted) abort();
  });
}
