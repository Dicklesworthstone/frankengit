#!/usr/bin/env node
// Explicitly selected trusted host workflows only. Never a required-check grant.
import { pathToFileURL } from 'node:url';
import { nativeController } from './operator/workflow_supervisor.mjs';

export function argumentsFor(argv) {
  if (argv.length === 1 && ['--help', '-h'].includes(argv[0])) return { help: true };
  const [action, ...args] = argv;
  if (!['once', 'serve', 'status'].includes(action)) throw new Error('Choose once, serve or status.');
  const values = new Map();
  for (let index = 0; index < args.length; index++) {
    const key = args[index];
    if (values.has(key)) throw new Error(`Duplicate option: ${key}`);
    if (key === '--trusted-local') { values.set(key, true); continue; }
    if (!['--config', '--max-publications', '--read-timeout-ms', '--dispatch-timeout-ms', '--publication-timeout-ms', '--concurrency', '--interval-ms', '--max-cycles'].includes(key)) throw new Error(`Unsupported option: ${key}`);
    const value = args[++index];
    if (!value || value.startsWith('--')) throw new Error(`Missing value: ${key}`);
    values.set(key, value);
  }
  if (!values.has('--config')) throw new Error('--config is required.');
  if (action !== 'status' && !values.has('--trusted-local')) throw new Error('Execution and publication require explicit --trusted-local consent.');
  const options = {};
  for (const [flag, name, maximum] of [['--max-publications', 'maxPublications', 128], ['--read-timeout-ms', 'readTimeoutMs', 30000],
    ['--dispatch-timeout-ms', 'dispatchTimeoutMs', 660000], ['--publication-timeout-ms', 'timeoutMs', 660000],
    ['--concurrency', 'concurrency', 16], ['--interval-ms', 'intervalMs', 3600000], ['--max-cycles', 'maxCycles', 1000000]]) {
    if (!values.has(flag)) continue;
    const text = values.get(flag), value = Number(text);
    if (action === 'status' || (['--interval-ms', '--max-cycles'].includes(flag) && action !== 'serve') ||
        !(flag === '--max-cycles' ? /^(0|[1-9][0-9]*)$/ : /^[1-9][0-9]*$/).test(text) || !Number.isSafeInteger(value) || value > maximum) throw new Error(`Invalid budget: ${flag}`);
    options[name] = value;
  }
  return { action, config: values.get('--config'), options };
}
export function exitCode(result) {
  if (result.type === 'workflow_supervisor_status') {
    if (result.lanes.some(row => row.error)) return 1;
    return result.owner_present || result.lanes.some(row => row.publication_owner_present || row.recovery_owner_present ||
      row.publication.pending > 0 || row.watcher.owner_present || row.watcher.queued > 0 || row.watcher.execution_unknown > 0) ? 2 : 0;
  }
  return result.failed ? 1 : result.pending || result.stopped || result.containment_unknown ? 2 : 0;
}
const HELP = `Usage: node scripts/fg_workflow_supervisor.mjs once|serve|status --config /absolute/config.json [--trusted-local]

once and serve require --trusted-local and run publication -> execution -> publication
for each explicitly configured branch. Unknown execution/publication is never
retried. Local success remains non-authoritative for protected merges.

Execution budgets: --max-publications 1..128, --read-timeout-ms 1..30000,
--dispatch-timeout-ms 1..660000, --publication-timeout-ms 1..660000,
--concurrency 1..16 (default 1; never overlaps lanes sharing a native store).
serve: --interval-ms 1..3600000 (default 5000), --max-cycles 0..1000000
(default 0, until stopped). Each cycle emits a bounded JSON line.
Exit: 0 settled, 1 failure/refusal, 2 pending/stopped. See docs/TRUSTED_WORKFLOW_SUPERVISOR.md.
`;
// Wait for the write callback, not only stream.write's boolean: no new cycle
// may be admitted while its previous observation is stuck behind a slow reader.
export function writeRecord(stream, value, timeoutMs = 30_000) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) throw new Error('Invalid report timeout.');
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  if (bytes.length > 1024 * 1024) throw new Error('Supervisor observation exceeds its output byte budget.');
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = error => {
      if (settled) return;
      settled = true; clearTimeout(timer); stream.removeListener('close', closed);
      // Writable may emit its error just after invoking the write callback.
      setImmediate(() => stream.removeListener('error', failed));
      if (error) reject(error); else resolve();
    };
    const failed = error => finish(error), closed = () => finish(new Error('Supervisor report stream closed.'));
    const timer = setTimeout(() => finish(new Error('Supervisor report deadline exceeded.')), timeoutMs);
    stream.on('error', failed); stream.once('close', closed);
    try { stream.write(bytes, error => finish(error)); } catch (error) { finish(error); }
  });
}
export async function main(argv = process.argv.slice(2)) {
  const selected = argumentsFor(argv);
  if (selected.help) { process.stdout.write(HELP); return; }
  const controller = await nativeController(), config = await controller.loadConfiguration(selected.config);
  const stop = new AbortController(), abort = () => stop.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  try {
    const result = selected.action === 'status' ? await controller.status(config)
      : selected.action === 'serve' ? await controller.serve(config, { ...selected.options, signal: stop.signal,
        onCycle: value => writeRecord(process.stdout, value) })
      : await controller.once(config, { ...selected.options, signal: stop.signal });
    await writeRecord(process.stdout, result);
    process.exitCode = exitCode(result);
  } finally { process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { process.stderr.write(`workflow-supervisor: ${error.message}\n`); process.exitCode = 1; });
}
