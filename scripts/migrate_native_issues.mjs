#!/usr/bin/env node
// Explicit issue DATA import. Source archives never authorize destination writes.
import { pathToFileURL } from 'node:url';
import { prepareNativeIssueMigration, inspectNativeIssueMigration, runNativeIssueMigration } from './lib/native-issue-migration.mjs';
import { operatorJson } from './lib/forge-operator-io.mjs';

const USAGE = `usage: node scripts/migrate_native_issues.mjs <prepare|inspect|run|status>
  --workdir <private-directory> --url <https-repository-url/ui/issues/>
  --tenant <32-hex> --repository <32-hex> --token-file <private-native-token-file>
  --archive <private-archive-directory> --archive-sha256 <independently-retained-pin> (prepare)
  [--offset <nonnegative>] [--max-steps <1..10000>] (prepare)
  [--max-capture-bytes <1..67108864> --max-request-bytes <1..134217728>] (prepare)
  --confirm <original-migration-plan-sha256> (inspect/run/status)
  [--max-mutations <1..10000> --retry-unresolved] (run only)
  [--timeout-ms <1..300000>] (prepare/inspect; run/status allow up to 3600000)

Preparation is offline and creates original request keys. Inspect is offline.
Run is explicit native issue mutation; status only queries original outcomes.
Retry uses original keys, bytes, versions and credential; never reprepare to retry.
Titles, labelled body provenance, labels, comments and final state are imported.
Source actors/assignees are attribution only. This is NOT canonical restore,
original audit history, assignments/permissions migration or an atomic transaction.
Retain original custody and pins after interruption. Locks are never stolen.
Exit 0: selected local phase complete, or all native steps observed committed;
1: canonical refusal; 2: input/read failure; 3: incomplete/uncertain work;
4: known completed work/progress followed by an error. See docs/NATIVE_ISSUE_IMPORT.md.`;
function options(args) {
  if (!Array.isArray(args) || args.length > 32 || args.some(a => typeof a !== 'string' || a.length > 8192 || /[\0\r\n]/u.test(a)) ||
      args.reduce((n, a) => n + a.length, 0) > 65536 || !['prepare', 'inspect', 'run', 'status'].includes(args[0])) throw new Error(USAGE);
  const operation = args[0], preparing = operation === 'prepare', executing = operation === 'run';
  const names = { '--workdir': 'workdir', '--url': 'href', '--tenant': 'tenant', '--repository': 'repository', '--token-file': 'tokenFile',
    '--timeout-ms': 'timeoutMs', ...(preparing ? { '--archive': 'archiveDir', '--archive-sha256': 'archiveSha256',
      '--offset': 'offset', '--max-steps': 'maxSteps', '--max-capture-bytes': 'maxCaptureBytes', '--max-request-bytes': 'maxRequestBytes' }
      : { '--confirm': 'confirm' }), ...(executing ? { '--max-mutations': 'maxMutations', '--retry-unresolved': 'retryUnresolved' } : {}) };
  const o = {};
  for (let index = 1; index < args.length;) {
    const flag = args[index++], name = names[flag];
    if (!name || Object.hasOwn(o, name)) throw new Error(USAGE);
    const value = flag === '--retry-unresolved' ? true : args[index++];
    if (value === undefined || value === '' || typeof value === 'string' && value.startsWith('--')) throw new Error(USAGE);
    o[name] = value;
  }
  for (const field of ['workdir', 'href', 'tenant', 'repository', 'tokenFile', ...(preparing ? ['archiveDir', 'archiveSha256'] : ['confirm'])]) {
    if (o[field] === undefined) throw new Error(USAGE);
  }
  for (const [field, min, max] of [['offset', 0, Number.MAX_SAFE_INTEGER], ['maxSteps', 1, 10000], ['maxMutations', 1, 10000],
    ['maxCaptureBytes', 1, 67108864], ['maxRequestBytes', 1, 134217728],
    ['timeoutMs', 1, ['run', 'status'].includes(operation) ? 3600000 : 300000]]) {
    if (o[field] === undefined) continue;
    if (!/^(0|[1-9][0-9]*)$/.test(o[field]) || !Number.isSafeInteger(Number(o[field])) || Number(o[field]) < min || Number(o[field]) > max) throw new Error(USAGE);
    o[field] = Number(o[field]);
  }
  return { operation, options: o };
}
export function writeOutput(stream, value) {
  const text = operatorJson(value);
  if (Buffer.byteLength(text) > 4 * 1024 * 1024) return Promise.reject(new Error('Native import output limit exceeded.'));
  return new Promise((resolve, reject) => {
    const onError = error => { clearTimeout(timer); reject(error); };
    const timer = setTimeout(() => { const error = new Error('Native import output deadline exceeded.'); stream.destroy(error); onError(error); }, 10000);
    stream.once('error', onError);
    stream.write(text, error => {
      if (error) onError(error);
      else { clearTimeout(timer); stream.removeListener('error', onError); resolve(); }
    });
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort(new Error('Native import stop requested; preserve original custody.'));
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await writeOutput(stdout, { usage: USAGE }); return 0; }
    const selected = options(args), o = { ...selected.options, signal: stop.signal };
    result = await (selected.operation === 'prepare' ? prepareNativeIssueMigration(o)
      : selected.operation === 'inspect' ? inspectNativeIssueMigration(o)
      : runNativeIssueMigration({ ...o, operation: selected.operation }));
    await writeOutput(stdout, result);
    if (['prepare', 'inspect'].includes(selected.operation) || result.complete) return 0;
    return result.stop_reason === 'terminal_refusal' ? 1 : 3;
  } catch (error) {
    try { await writeOutput(stderr, { type: 'native_issue_migration_error', message: String(error.message).slice(0, 8192),
      absence_proves_non_commit: false, request_reexecuted_automatically: false,
      ...(result ? { retained_operation: result } : {}),
      ...(error.migration_progress ? { migration_progress: error.migration_progress } : {}),
      ...(error.migration_preparation ? { migration_preparation: error.migration_preparation } : {}),
      ...(error.migration_observed_terminal ? { observed_terminal: error.migration_observed_terminal } : {}) }); } catch { /* Original files remain. */ }
    return result || error.migration_progress?.committed_observed > 0 || error.migration_observed_terminal ? 4
      : error.migration_progress?.total_steps !== null && error.migration_progress?.total_steps !== undefined ||
        error.migration_preparation?.directory_created ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
