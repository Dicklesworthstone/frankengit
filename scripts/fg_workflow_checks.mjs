#!/usr/bin/env node
// Explicit trusted-local publication of retained job observations. No workflow execution.
import { pathToFileURL } from 'node:url';
import { loadConfiguration } from './operator/workflow_watch.mjs';
import { configuration, once, serve, status } from './operator/workflow_check_publish.mjs';

const USAGE = `usage: node scripts/fg_workflow_checks.mjs <once|serve|resume|status>
  --watch-config <absolute-private-watcher-config> --state <absolute-private-empty-directory>
  --principal-id <original-local-publisher-id> --trusted-local
  [--max-publications <1..128>] (once/resume/serve)
  [--poll-millis <100..60000> --max-polls <1..1000000>] (serve only)

Publish completed watcher jobs through native fg workflow recover/publish.
The original journal IDs, snapshots, facts and publication keys are saved before
admission. Resume reuses them and NEVER runs a workflow. Uncertain publication
stops automatic work; use resume explicitly with the original principal.
Success/skipped jobs remain action_required, NOT green required checks.
SIGTERM/SIGINT drain the active native publisher. Owner locks are never stolen.

Exit 0: all selected publications settled as committed (or no work);
1: at least one canonical refusal; 2: input/read failure;
3: publication pending/unknown or a reached work limit; 4: terminal known but
local cleanup/output failed. Status describes historical local observations.
See docs/TRUSTED_WORKFLOW_CHECK_AUTOMATION.md.`;
async function write(stream, value) {
  const text = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(text) > 4 * 1024 * 1024) throw new Error('Workflow check output exceeds limit.');
  return new Promise((resolve, reject) => {
    const error = cause => { clearTimeout(timer); reject(cause); };
    const timer = setTimeout(() => { const cause = new Error('Workflow check output deadline exceeded.'); stream.destroy(cause); error(cause); }, 10_000);
    stream.once('error', error);
    stream.write(text, cause => {
      if (cause) error(cause);
      else { clearTimeout(timer); stream.removeListener('error', error); resolve(); }
    });
  });
}
function options(args) {
  if (!['once', 'serve', 'resume', 'status'].includes(args[0]) || args.length > 16) throw new Error(USAGE);
  const fields = new Map();
  for (let index = 1; index < args.length;) {
    const flag = args[index++];
    if (!['--watch-config', '--state', '--principal-id', '--trusted-local', '--max-publications', '--poll-millis', '--max-polls'].includes(flag) || fields.has(flag)) throw new Error(USAGE);
    const value = flag === '--trusted-local' ? true : args[index++];
    if (value === undefined || value === '' || (typeof value === 'string' && value.startsWith('--'))) throw new Error(USAGE);
    fields.set(flag, value);
  }
  for (const flag of ['--watch-config', '--state', '--principal-id', '--trusted-local']) if (!fields.has(flag)) throw new Error(USAGE);
  if (args[0] !== 'serve' && (fields.has('--poll-millis') || fields.has('--max-polls')) || args[0] === 'status' && fields.has('--max-publications')) throw new Error(USAGE);
  const loop = {};
  for (const [flag, name, min, max] of [['--poll-millis', 'pollMs', 100, 60000], ['--max-polls', 'maxPolls', 1, 1000000], ['--max-publications', 'maxPublications', 1, 128]]) {
    if (!fields.has(flag)) continue;
    const value = fields.get(flag);
    if (!/^[1-9][0-9]{0,6}$/.test(value) || Number(value) < min || Number(value) > max) throw new Error(USAGE);
    loop[name] = Number(value);
  }
  return { operation: args[0], fields, loop };
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort(new Error('Workflow check stop requested; original publication responsibility retained.'));
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await write(stdout, { usage: USAGE }); return 0; }
    const { operation, fields, loop } = options(args);
    const config = configuration({ schema: 'frankengit-workflow-check-publisher-v1',
      watch: await loadConfiguration(fields.get('--watch-config')), state_directory: fields.get('--state'), principal_id: fields.get('--principal-id') });
    const request = { ...loop, signal: stop.signal, onObservation: value => write(stdout, value) };
    result = await (operation === 'status' ? status(config) : operation === 'serve' ? serve(config, request)
      : once(config, { ...request, resume: operation === 'resume' }));
    await write(stdout, result);
    const view = result.last ?? result;
    if (view.limit_reached || view.runs?.some(run => run.pending > 0)) return 3;
    return view.runs?.some(run => run.refused > 0) ? 1 : 0;
  } catch (error) {
    try { await write(stderr, { type: 'workflow_check_error', schema_version: 1, message: error.message,
      execution_retried: false, absence_proves_non_commit: false, publication_unknown: error.publication_unknown === true,
      ...(error.retained_terminal ? { retained_terminal: error.retained_terminal } : {}),
      ...(result ? { retained_operation: result } : {}),
      ...(error.native_stderr_hex ? { native_stderr_hex: error.native_stderr_hex } : {}) }); } catch { /* Original custody remains. */ }
    return error.retained_terminal || result ? 4 : error.publication_unknown || error.containment_unknown || /unresolved|stop requested/i.test(error.message) ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
