#!/usr/bin/env node
// Explicit full-migration execution. Existing child plans own all mutation keys.
import { pathToFileURL } from 'node:url';
import { runGithubIssueMigration } from './lib/github-issue-migration-execute.mjs';
import { loadGithubIssueMigrationSources } from './lib/github-issue-migration-sources.mjs';

const USAGE = `usage: node scripts/migrate_github_issues.mjs <prepare|inspect|run|status>
  --workdir <absolute-migration-directory>
  --confirm <original-plan-sha256> (inspect/run/status)
  --sources <absolute-private-sources-json> --sources-sha256 <independent-pin> (prepare)
  --url <native-repository-url> --tenant <32-hex> --repository <32-hex>
  --token-file <absolute-private-original-token>
  [--timeout-ms <1..3600000>]
  [--max-mutations <1..10000> --retry-unresolved] (run only)

prepare delegates complete pinned capture preparation to the shipped importer.
Its destination must not exist. inspect verifies retained custody without network
access. Neither operation submits mutations or implicitly runs the migration.
Preparation/inspection timeout is at most 300000 ms. Retain the returned plan pin.

run validates the COMPLETE pinned migration before submitting original child
requests in order. One mutation budget and deadline cover every batch. An
uncertain request stops execution; only explicit --retry-unresolved permits
resending its original request after the existing outcome lookup.
status queries original outcomes across ALL batches without sending a mutation.
It can save child terminal observations and work while a sender lock is retained.
Neither command replaces keys, advances expected versions, clears locks or
reprepares a batch. Keep the entire migration directory and its independent pin.

Exit 0: preparation/inspection completed, or every execution step observed committed; 1: canonical refusal; 2: input/read error;
3: incomplete or unresolved migration; 4: committed progress known but subsequent
operation/output/cleanup failed. A migration is NOT a cross-batch transaction.
See docs/GITHUB_ISSUE_MIGRATION_EXECUTION.md.`;

function options(args) {
  if (!Array.isArray(args) || !['prepare', 'inspect', 'run', 'status'].includes(args[0]) || args.length > 24 ||
      args.some(arg => typeof arg !== 'string' || arg.length > 8192 || /[\0\r\n]/.test(arg))) throw new Error(USAGE);
  const fields = new Map();
  const names = new Map([['--workdir', 'workdir'], ['--confirm', 'confirm'], ['--url', 'href'],
    ['--tenant', 'tenant'], ['--repository', 'repository'], ['--token-file', 'tokenFile'],
    ['--sources', 'sources'], ['--sources-sha256', 'sourcesSha256'],
    ['--timeout-ms', 'timeoutMs'], ['--max-mutations', 'maxMutations'], ['--retry-unresolved', 'retryUnresolved']]);
  for (let index = 1; index < args.length;) {
    const flag = args[index++];
    if (!names.has(flag) || fields.has(flag)) throw new Error(USAGE);
    const value = flag === '--retry-unresolved' ? true : args[index++];
    if (value === undefined || value === '' || (typeof value === 'string' && value.startsWith('--'))) throw new Error(USAGE);
    fields.set(flag, value);
  }
  const preparing = args[0] === 'prepare';
  for (const key of ['--workdir', '--url', '--tenant', '--repository', '--token-file',
    ...(preparing ? ['--sources', '--sources-sha256'] : ['--confirm'])]) if (!fields.has(key)) throw new Error(USAGE);
  if ((preparing && fields.has('--confirm')) || (!preparing && (fields.has('--sources') || fields.has('--sources-sha256'))) ||
      (args[0] !== 'run' && (fields.has('--max-mutations') || fields.has('--retry-unresolved')))) throw new Error(USAGE);
  const result = { operation: args[0] };
  for (const [flag, value] of fields) result[names.get(flag)] = value;
  for (const [key, max] of [['timeoutMs', 3600000], ['maxMutations', 10000]]) if (result[key] !== undefined) {
    if (!/^[1-9][0-9]{0,6}$/.test(result[key]) || Number(result[key]) > max) throw new Error(USAGE);
    result[key] = Number(result[key]);
  }
  if (['prepare', 'inspect'].includes(args[0]) && result.timeoutMs > 300000) throw new Error(USAGE);
  return result;
}
async function prepareSelected(raw) {
  const { operation: _operation, sources, sourcesSha256, ...connection } = raw;
  const duration = connection.timeoutMs ?? 300000, stop = new AbortController();
  const signal = AbortSignal.any([connection.signal, stop.signal]);
  const deadline = performance.now() + duration;
  const timer = setTimeout(() => stop.abort(new Error('github_migration_preparation_deadline')), duration);
  try {
    const selected = await loadGithubIssueMigrationSources({ path: sources, sha256: sourcesSha256, signal });
    const { prepareGithubIssueMigration } = await import('./lib/github-issue-migration.mjs');
    signal.throwIfAborted();
    const remaining = Math.floor(deadline - performance.now());
    if (remaining < 1) throw new Error('github_migration_preparation_deadline');
    return await prepareGithubIssueMigration({ ...connection, ...selected, signal, timeoutMs: remaining });
  } finally { clearTimeout(timer); stop.abort(); }
}
async function inspectSelected(raw) {
  const { operation: _operation, ...request } = raw;
  const { inspectGithubIssueMigration } = await import('./lib/github-issue-migration.mjs');
  return inspectGithubIssueMigration(request);
}
async function write(stream, value) {
  const text = JSON.stringify(value) + '\n';
  if (Buffer.byteLength(text) > 1024 * 1024) throw new Error('github_migration_output_limit');
  return new Promise((resolve, reject) => {
    const failed = error => { clearTimeout(timer); reject(error); };
    const timer = setTimeout(() => {
      const error = new Error('github_migration_output_deadline'); stream.destroy(error); failed(error);
    }, 10000);
    stream.once('error', failed);
    try { stream.write(text, error => {
      if (error) failed(error);
      else { clearTimeout(timer); stream.removeListener('error', failed); resolve(); }
    }); } catch (error) { clearTimeout(timer); stream.removeListener('error', failed); reject(error); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr, execute = runGithubIssueMigration, prepare = prepareSelected, inspect = inspectSelected } = {}) {
  const stop = new AbortController(), abort = () => stop.abort(new Error('github_migration_stop_requested'));
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await write(stdout, { usage: USAGE }); return 0; }
    const selected = options(args);
    const handler = selected.operation === 'prepare' ? prepare : selected.operation === 'inspect' ? inspect : execute;
    result = await handler({ ...selected, signal: stop.signal });
    await write(stdout, result);
    if (['prepare', 'inspect'].includes(selected.operation) || result.complete) return 0;
    return result.batches?.some(batch => batch.stop_reason === 'terminal_refusal') ? 1 : 3;
  } catch (error) {
    const progress = result ?? error.migration_progress;
    try { await write(stderr, { type: 'github_issue_migration_error', schema_version: 1, message: error.message,
      absence_proves_non_commit: false, original_custody_preserved: true,
      ...(progress ? { migration_progress: progress } : {}),
      ...(error.migration_observed_terminal ? { observed_terminal: error.migration_observed_terminal } : {}),
      ...(error.migration_preparation ? { migration_preparation: error.migration_preparation } : {}),
      ...(error.migration_cleanup_error ? { cleanup_error: error.migration_cleanup_error } : {}) }); }
    catch { /* The original prepared requests and child observations remain the recovery source. */ }
    if (result || progress?.committed_observed > 0 || error.migration_observed_terminal) return 4;
    return stop.signal.aborted || progress?.mutation_count_complete === false || progress?.mutation_calls > 0 || progress?.stop_reason === 'unresolved_original_request' ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
