#!/usr/bin/env node
// Explicitly selected trusted host workflows only. Never a required-check grant.
import { pathToFileURL } from 'node:url';
import { nativeController } from './operator/workflow_supervisor.mjs';

export function argumentsFor(argv) {
  if (argv.length === 1 && ['--help', '-h'].includes(argv[0])) return { help: true };
  const [action, ...args] = argv;
  if (!['once', 'status'].includes(action)) throw new Error('Choose once or status.');
  const values = new Map();
  for (let index = 0; index < args.length; index++) {
    const key = args[index];
    if (values.has(key)) throw new Error(`Duplicate option: ${key}`);
    if (key === '--trusted-local') { values.set(key, true); continue; }
    if (!['--config', '--max-publications', '--read-timeout-ms', '--dispatch-timeout-ms', '--publication-timeout-ms'].includes(key)) throw new Error(`Unsupported option: ${key}`);
    const value = args[++index];
    if (!value || value.startsWith('--')) throw new Error(`Missing value: ${key}`);
    values.set(key, value);
  }
  if (!values.has('--config')) throw new Error('--config is required.');
  if (action === 'once' && !values.has('--trusted-local')) throw new Error('Execution and publication require explicit --trusted-local consent.');
  const options = {};
  for (const [flag, name, maximum] of [['--max-publications', 'maxPublications', 128], ['--read-timeout-ms', 'readTimeoutMs', 30000],
    ['--dispatch-timeout-ms', 'dispatchTimeoutMs', 660000], ['--publication-timeout-ms', 'timeoutMs', 660000]]) {
    if (!values.has(flag)) continue;
    const text = values.get(flag), value = Number(text);
    if (action === 'status' || !/^[1-9][0-9]*$/.test(text) || !Number.isSafeInteger(value) || value > maximum) throw new Error(`Invalid budget: ${flag}`);
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
const HELP = `Usage: node scripts/fg_workflow_supervisor.mjs once|status --config /absolute/config.json [--trusted-local]

once requires --trusted-local and runs publication -> execution -> publication
for each explicitly configured branch. Unknown execution/publication is never
retried. Local success remains non-authoritative for protected merges.

Optional once budgets: --max-publications 1..128, --read-timeout-ms 1..30000,
--dispatch-timeout-ms 1..660000, --publication-timeout-ms 1..660000.
Exit: 0 settled, 1 failure/refusal, 2 pending/stopped. See docs/TRUSTED_WORKFLOW_SUPERVISOR.md.
`;
export async function main(argv = process.argv.slice(2)) {
  const selected = argumentsFor(argv);
  if (selected.help) { process.stdout.write(HELP); return; }
  const controller = await nativeController(), config = await controller.loadConfiguration(selected.config);
  const stop = new AbortController(), abort = () => stop.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  try {
    const result = selected.action === 'status' ? await controller.status(config)
      : await controller.once(config, { ...selected.options, signal: stop.signal });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = exitCode(result);
  } finally { process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { process.stderr.write(`workflow-supervisor: ${error.message}\n`); process.exitCode = 1; });
}
