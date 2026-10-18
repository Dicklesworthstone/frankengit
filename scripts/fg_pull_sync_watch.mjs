#!/usr/bin/env node
// Explicit operator opt-in, never a background service started by importing a module.
import { pathToFileURL } from 'node:url';
import { controlFile, credential, output } from './fg_pull_sync.mjs';
import { parseSyncJson } from './operator/pull_sync_transport.mjs';
import { configuration, once, serve, status } from './operator/pull_sync_watch.mjs';
const USAGE = `node scripts/fg_pull_sync_watch.mjs once|serve
  --config /private/watch.json --token-file /private/token --allow-tip-updates
  [--ca-file /private/ca.pem] [--timeout-ms <1..300000>] [--max-updates <1..128>]
  [--poll-millis <100..60000> --max-polls <1..1000000>] (serve only)
node scripts/fg_pull_sync_watch.mjs status --config /private/watch.json

The explicit policy authorizes only tip-only updates for the selected native PRs.
No merge, ref movement, approval reuse, workflow run, or implicit retry is allowed.
Original plans and decisions are retained under numbered batch directories.
Unknown publication stops all new work; use fg_pull_sync.mjs recover on that batch.
SIGTERM/SIGINT drain the active bounded update and stop before another job.
No lock is stolen and no history is evicted. Read-only status requires no token.
Exit 0: completed selected work; 1: observed refusal; 2: input/read/custody failure;
3: unresolved/pending work; 4: known result with local output/cleanup failure.
See docs/PR_TIP_SYNC_SERVICE.md.`;
function argumentsFor(args) {
  if (!Array.isArray(args) || args.length > 18 || args.some(a => typeof a !== 'string' || a.length > 8192) ||
      !['once', 'serve', 'status'].includes(args[0])) throw new Error(USAGE);
  const operation = args[0], fields = new Map();
  const allowed = operation === 'status' ? ['--config'] : ['--config', '--token-file', '--allow-tip-updates', '--ca-file', '--timeout-ms', '--max-updates',
    ...(operation === 'serve' ? ['--poll-millis', '--max-polls'] : [])];
  for (let i = 1; i < args.length;) {
    const key = args[i++];
    if (!allowed.includes(key) || fields.has(key)) throw new Error(USAGE);
    const value = key === '--allow-tip-updates' ? true : args[i++];
    if (value === undefined || value === '' || (typeof value === 'string' && value.startsWith('--'))) throw new Error(USAGE);
    fields.set(key, value);
  }
  if (!fields.has('--config') || (operation !== 'status' && (!fields.has('--token-file') || !fields.has('--allow-tip-updates')))) throw new Error(USAGE);
  const options = {};
  for (const [flag, name, min, max] of [['--timeout-ms', 'timeoutMs', 1, 300000], ['--max-updates', 'maxUpdates', 1, 128],
    ['--poll-millis', 'pollMs', 100, 60000], ['--max-polls', 'maxPolls', 1, 1000000]]) {
    if (!fields.has(flag)) continue;
    const value = fields.get(flag);
    if (!/^[1-9][0-9]{0,6}$/.test(value) || Number(value) < min || Number(value) > max) throw new Error(USAGE);
    options[name] = Number(value);
  }
  return { operation, fields, options };
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort();
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await output(stdout, { usage: USAGE }); return 0; }
    const { operation, fields, options } = argumentsFor(args);
    const config = configuration(parseSyncJson(await controlFile(fields.get('--config'), 32768), 32768));
    if (operation === 'status') result = await status(config);
    else {
      const token = await credential(fields.get('--token-file'));
      const ca = fields.has('--ca-file') ? await controlFile(fields.get('--ca-file'), 128 * 1024) : undefined;
      result = await (operation === 'serve' ? serve : once)(config, token, { ...options, ca, signal: stop.signal, onObservation: event => output(stdout, event) });
    }
    await output(stdout, result);
    const current = result.last ?? result;
    if (current.batches?.some(batch => batch.unknown || batch.prepared)) return 3;
    if (result.refused || current.refused || current.suppressed_historical_requests?.some(row => row.outcome === 'refused') ||
        (operation === 'status' && current.batches.some(batch => batch.refused))) return 1;
    return 0;
  } catch (error) {
    try { await output(stderr, { type: 'pull_sync_watch_error', message: error.message, absence_proves_non_commit: false,
      ...(error.retained_terminal ? { retained_terminal: error.retained_terminal } : {}),
      ...(error.retained_result ? { retained_operation: error.retained_result } : {}),
      publication_unknown: error.publication_unknown === true }); } catch { /* Preserve original custody. */ }
    return result || error.retained_terminal || error.local_cleanup_failed || error.local_output_failed ? 4
      : error.publication_unknown || /unresolved_publication|sender_owner/.test(error.message) ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
