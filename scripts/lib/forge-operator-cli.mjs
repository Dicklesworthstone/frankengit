// One-shot forge CLI owner: request cancellation, drain work, bound output.
// Output failure never changes a canonical result or replaces recovery custody.
import { operatorError } from './forge-operator-io.mjs';
import { write as writeDescriptor } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';

async function write(stream, text, signal) {
  const check = () => { if (signal.aborted) throw operatorError('operator_output_cancelled_or_deadline'); };
  check();
  const bytes = Buffer.from(text); let at = 0;
  // Node initializes pipe stdio as nonblocking, but its Writable queue retains
  // an uncancellable write request even after destroy()/unref(). Own one public
  // descriptor write at a time instead; EAGAIN owns no bytes or pending request.
  while (at < bytes.length) {
    check();
    try {
      const count = await new Promise((resolve, reject) => {
        writeDescriptor(stream.fd, bytes, at, Math.min(65536, bytes.length - at), null,
          (error, written) => error ? reject(error) : resolve(written));
      });
      if (!count) throw operatorError('operator_output_no_progress');
      at += count;
    } catch (error) {
      if (!['EAGAIN', 'EWOULDBLOCK', 'EINTR'].includes(error.code)) throw error;
      try { await delay(1, undefined, { signal }); }
      catch (cancelled) { check(); throw cancelled; }
    }
  }
  check();
}

// Called once by the executable, not by the reusable command APIs. Their
// operation timers remain; this owner also covers serialization/output delivery.
export async function runOperatorCli(args, { timeout, run, failure, failureExitCode = 2 }) {
  const started = performance.now(), stop = new AbortController(), abort = () => stop.abort();
  let completed = false, timer;
  // Repeated cancellation still belongs to this owner while work/diagnostics
  // drain; removing a once listener early restores the default abrupt exit.
  process.on('SIGINT', abort); process.on('SIGTERM', abort);
  // Keep these process-owned error handlers through asynchronous stdio closure.
  const unavailable = () => { abort(); process.exitCode = failureExitCode; };
  process.stdout.on('error', unavailable); process.stderr.on('error', unavailable);
  try {
    const milliseconds = timeout(args);
    if (!Number.isSafeInteger(milliseconds) || milliseconds < 1 || milliseconds > 300000) {
      throw operatorError('operator_cli_deadline_invalid');
    }
    const deadline = started + milliseconds, remaining = deadline - performance.now();
    if (remaining <= 0) abort(); else timer = setTimeout(abort, remaining);
    const result = await run(args, stop.signal); completed = true;
    if (performance.now() >= deadline) abort();
    process.exitCode = result.exitCode;
    await write(process.stdout, result.text, stop.signal);
    if (performance.now() >= deadline) throw operatorError('operator_output_cancelled_or_deadline');
  } catch (error) {
    process.exitCode = failureExitCode;
    // Final diagnostics have a separate finite drain, never a new operation
    // budget. A blocked stderr cannot keep the failed process alive forever.
    const diagnostics = new AbortController(), drain = setTimeout(() => diagnostics.abort(), 250);
    try { await write(process.stderr, failure(error, completed), diagnostics.signal); }
    catch { /* Original request records remain available for recovery. */ }
    finally { clearTimeout(drain); }
  } finally {
    clearTimeout(timer);
    process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
  }
}
