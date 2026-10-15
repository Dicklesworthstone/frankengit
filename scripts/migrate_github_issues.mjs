#!/usr/bin/env node
// Explicit full-migration execution. Existing child plans own all mutation keys.
import { pathToFileURL } from 'node:url';
import { runGithubIssueMigration } from './lib/github-issue-migration-execute.mjs';

const USAGE = `usage: node scripts/migrate_github_issues.mjs <run|status>
  --workdir <absolute-prepared-migration-directory> --confirm <original-plan-sha256>
  --url <native-repository-url> --tenant <32-hex> --repository <32-hex>
  --token-file <absolute-private-original-token>
  [--timeout-ms <1..3600000>]
  [--max-mutations <1..10000> --retry-unresolved] (run only)

run validates the COMPLETE pinned migration before submitting original child
requests in order. One mutation budget and deadline cover every batch. An
uncertain request stops execution; only explicit --retry-unresolved permits
resending its original request after the existing outcome lookup.
status queries original outcomes across ALL batches without sending a mutation.
It can save child terminal observations and work while a sender lock is retained.
Neither command replaces keys, advances expected versions, clears locks or
reprepares a batch. Keep the entire migration directory and its independent pin.

Exit 0: every step observed committed; 1: canonical refusal; 2: input/read error;
3: incomplete or unresolved migration; 4: committed progress known but subsequent
operation/output/cleanup failed. A migration is NOT a cross-batch transaction.
See docs/GITHUB_ISSUE_MIGRATION_EXECUTION.md.`;

function options(args) {
  if (!Array.isArray(args) || !['run', 'status'].includes(args[0]) || args.length > 20 ||
      args.some(arg => typeof arg !== 'string' || arg.length > 8192 || /[\0\r\n]/.test(arg))) throw new Error(USAGE);
  const fields = new Map();
  const names = new Map([['--workdir', 'workdir'], ['--confirm', 'confirm'], ['--url', 'href'],
    ['--tenant', 'tenant'], ['--repository', 'repository'], ['--token-file', 'tokenFile'],
    ['--timeout-ms', 'timeoutMs'], ['--max-mutations', 'maxMutations'], ['--retry-unresolved', 'retryUnresolved']]);
  for (let index = 1; index < args.length;) {
    const flag = args[index++];
    if (!names.has(flag) || fields.has(flag)) throw new Error(USAGE);
    const value = flag === '--retry-unresolved' ? true : args[index++];
    if (value === undefined || value === '' || (typeof value === 'string' && value.startsWith('--'))) throw new Error(USAGE);
    fields.set(flag, value);
  }
  for (const key of ['--workdir', '--confirm', '--url', '--tenant', '--repository', '--token-file']) if (!fields.has(key)) throw new Error(USAGE);
  if (args[0] === 'status' && (fields.has('--max-mutations') || fields.has('--retry-unresolved'))) throw new Error(USAGE);
  const result = { operation: args[0] };
  for (const [flag, value] of fields) result[names.get(flag)] = value;
  for (const [key, max] of [['timeoutMs', 3600000], ['maxMutations', 10000]]) if (result[key] !== undefined) {
    if (!/^[1-9][0-9]{0,6}$/.test(result[key]) || Number(result[key]) > max) throw new Error(USAGE);
    result[key] = Number(result[key]);
  }
  return result;
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
export async function main(args, { stdout = process.stdout, stderr = process.stderr, execute = runGithubIssueMigration } = {}) {
  const stop = new AbortController(), abort = () => stop.abort(new Error('github_migration_stop_requested'));
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await write(stdout, { usage: USAGE }); return 0; }
    result = await execute({ ...options(args), signal: stop.signal });
    await write(stdout, result);
    if (result.complete) return 0;
    return result.batches?.some(batch => batch.stop_reason === 'terminal_refusal') ? 1 : 3;
  } catch (error) {
    const progress = result ?? error.migration_progress;
    try { await write(stderr, { type: 'github_issue_migration_error', schema_version: 1, message: error.message,
      absence_proves_non_commit: false, original_custody_preserved: true,
      ...(progress ? { migration_progress: progress } : {}),
      ...(error.migration_observed_terminal ? { observed_terminal: error.migration_observed_terminal } : {}),
      ...(error.migration_cleanup_error ? { cleanup_error: error.migration_cleanup_error } : {}) }); }
    catch { /* The original prepared requests and child observations remain the recovery source. */ }
    if (result || progress?.committed_observed > 0 || error.migration_observed_terminal) return 4;
    return stop.signal.aborted || progress?.mutation_count_complete === false || progress?.mutation_calls > 0 || progress?.stop_reason === 'unresolved_original_request' ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
