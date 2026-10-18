#!/usr/bin/env node
// Repository code is executed only after the operator selects the trusted-host profile.
import { pathToFileURL } from 'node:url';
import { loadConfiguration, once, reconcile, serve, status } from './operator/workflow_watch.mjs';

const USAGE = `usage: node scripts/fg_workflow_watch.mjs <once|serve|status|reconcile> --config <absolute-private-file> --trusted-local
  [--poll-millis <100..60000> --max-polls <1..1000000>] (serve only)

Observe one selected branch and dispatch its previously unseen commit through fg.
The configuration must explicitly trust selected branch code with host-user privileges.
This is an external operator, NOT a hostile-code sandbox or an accepted-push feed.
Each commit runs at most once per retained watcher configuration. Intermediate tips
between observations may be missed. All native source/incarnation pins are retained.

An unresolved run blocks new execution. Reconcile reads its original native report;
it never replays children, publishes a check, resets IDs, or steals an owner lock.
SIGTERM/SIGINT stop new work and drain active native dispatch within its watchdog.
A forced watchdog termination retains the lock and makes no containment claim.

Exit 0: idle, no matching workflows, or observed native success; 1: observed failure or settled stop;
2: invalid input or unavailable observation; 3: pending execution/containment unknown.
Native success is NOT a verified required check. See docs/TRUSTED_WORKFLOW_WATCH.md.`;
function write(stream, value) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      const error = new Error('Watcher output deadline exceeded; original custody retained.');
      stream.destroy(error); onError(error);
    }, 10_000);
    const onError = error => { clearTimeout(timer); reject(error); };
    const cleanup = () => { clearTimeout(timer); stream.removeListener('error', onError); };
    stream.once('error', onError);
    stream.write(`${JSON.stringify(value)}\n`, error => {
      if (error) onError(error); // Keep the listener for Node's subsequent error event.
      else { cleanup(); resolve(); }
    });
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  if (args.length === 1 && args[0] === '--help') { await write(stdout, { usage: USAGE }); return 0; }
  if (![4, 6, 8].includes(args.length) || !['once', 'serve', 'status', 'reconcile'].includes(args[0]) ||
      args[1] !== '--config' || args[3] !== '--trusted-local' || (args[0] !== 'serve' && args.length !== 4)) {
    await write(stderr, { error: USAGE }); return 2;
  }
  const loop = {}, seen = new Set();
  for (let i = 4; i < args.length; i += 2) {
    if (!['--poll-millis', '--max-polls'].includes(args[i]) || seen.has(args[i]) || !/^[1-9][0-9]{0,6}$/.test(args[i + 1])) {
      await write(stderr, { error: USAGE }); return 2;
    }
    seen.add(args[i]); loop[args[i] === '--poll-millis' ? 'pollMs' : 'maxPolls'] = Number(args[i + 1]);
  }
  const stop = new AbortController(), abort = () => stop.abort(new Error('Watcher stop requested; retain original run custody.'));
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let value;
  try {
    const config = await loadConfiguration(args[2]);
    value = await (args[0] === 'once' ? once(config, { signal: stop.signal })
      : args[0] === 'serve' ? serve(config, { ...loop, signal: stop.signal, onObservation: event => write(stdout, event) })
      : args[0] === 'status' ? status(config) : reconcile(config));
    await write(stdout, value);
    if (value.records?.some(row => ['execution_unknown', 'queued'].includes(row.state))) return 3;
    return ['observed_failed', 'observed_stopped'].includes(value.outcome) || value.failed_runs > 0 || value.stopped_runs > 0 ? 1 : 0;
  } catch (error) {
    const diagnostic = { type: 'workflow_watch_error', schema_version: 1, message: error.message,
      execution_retried: false, absence_proves_non_execution: false,
      ...(error.native_stderr_hex ? { native_stderr_hex: error.native_stderr_hex } : {}),
      ...(value || error.retained_observation ? { retained_observation: value ?? error.retained_observation } : {}) };
    try { await write(stderr, diagnostic); } catch { /* Custody files remain the recovery source. */ }
    return error.containment_unknown || /unresolved|incomplete|Dispatch unresolved|stop requested/i.test(error.message) ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
