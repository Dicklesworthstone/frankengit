#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { preparePullImport, inspectPullImport } from './lib/native-pull-import.mjs';
import { executePullImport } from './lib/native-pull-import-execute.mjs';
import { readPullPrivate } from './operator/pull_files.mjs';
import { parsePullJson, pullCanonical } from './operator/pull_command.mjs';

export const HELP = `Usage: node scripts/migrate_native_pulls.mjs prepare --archive-dir ABS --archive-confirm SHA256 --selection PRIVATE_JSON --token-file PRIVATE_TOKEN --workdir NEW_ABS [--timeout-ms 1..300000]
       node scripts/migrate_native_pulls.mjs inspect|status --workdir ABS --confirm PLAN_SHA256 [--timeout-ms 1..300000]
       node scripts/migrate_native_pulls.mjs run|recover --workdir ABS --confirm PLAN_SHA256 [--token-file PRIVATE_TOKEN] [--max-operations 1..8192] [--timeout-ms 1..300000] [--ca-file PRIVATE_PEM]
       run only: [--retry-key ORIGINAL_PENDING_KEY]
Selection: endpoint, scope {tenant_id, repository_id, repository_incarnation, principal_id, object_format}, number_start (decimal string).
Optional: merged (refuse|as-closed), ref_map [{source_hex,destination}], pull_ref_map [{source_number,source_ref,target_ref}], max_steps, max_source_bytes, max_request_bytes.
Preparation, inspection and status are offline. Only open/comment/close requests are produced; votes never become destination approvals.
Destination Git objects and branch coordinates must already exist. Existing PR numbers refuse; there is no automatic renumbering.
Run commits sequentially through the existing native sender, at most 100 operations by default. A reservation is synchronized before a possible send.
An interrupted key is recovered, never automatically resent. --retry-key consents only to that exact pending request. No missing outcome proves non-commit.
Recover only looks up an attempted original key, never starts or resubmits a mutation. Rotated tokens may recover the original principal, not send.
Retain plan_sha256 independently. Each requests/step-NNNNNN slot remains usable with scripts/remote_pull.mjs. Do not mix manual sends with batch execution.
Exit 0: prepared/inspected/status or all steps committed; 1: native refusal; 2: input/preflight refusal; 3: ready/paused/pending execution; 4: error with retained custody or output.
Complete plans can be inspected or run without token files. Partial/corrupt journals refuse in place; no lock stealing or automatic repair.\n`;
function parse(args) {
  if (!Array.isArray(args) || args.length > 25 || args.some(x => typeof x !== 'string' || x.length > 4096)) throw new Error('pull_import_arguments');
  const operation = args[0]; if (!['prepare', 'inspect', 'status', 'run', 'recover'].includes(operation)) throw new Error('pull_import_command');
  const required = operation === 'prepare' ? ['--archive-dir', '--archive-confirm', '--selection', '--token-file', '--workdir'] : ['--workdir', '--confirm'];
  const allowed = new Set([...required, '--timeout-ms', ...(['run', 'recover'].includes(operation)
    ? ['--token-file', '--max-operations', '--ca-file', ...(operation === 'run' ? ['--retry-key'] : [])] : [])]), values = {};
  for (let i = 1; i < args.length;) {
    const flag = args[i++], value = args[i++];
    if (!allowed.has(flag) || Object.hasOwn(values, flag) || !value || value.startsWith('--')) throw new Error('pull_import_arguments');
    values[flag] = value;
  }
  if (required.some(k => !Object.hasOwn(values, k))) throw new Error('pull_import_arguments');
  if (values['--timeout-ms'] !== undefined && (!/^[1-9][0-9]{0,5}$/.test(values['--timeout-ms']) || Number(values['--timeout-ms']) > 300000)) throw new Error('pull_import_timeout');
  if (values['--max-operations'] !== undefined && (!/^[1-9][0-9]{0,3}$/.test(values['--max-operations']) || Number(values['--max-operations']) > 8192)) throw new Error('pull_import_operation_limit');
  return { operation, values };
}
async function write(stream, value) {
  const text = pullCanonical(value); if (Buffer.byteLength(text) > 1024 * 1024) throw new Error('pull_import_output_limit');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => { if (done) return; done = true; clearTimeout(timer);
      setImmediate(() => { stream.removeListener?.('error', fail); error ? reject(error) : resolve(); }); };
    const fail = error => finish(error), timer = setTimeout(() => finish(new Error('pull_import_output_timeout')), 10000);
    stream.once?.('error', fail); try { stream.write(text, finish); } catch (e) { finish(e); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr, signal } = {}) {
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await write(stdout, { usage: HELP }); return 0; }
    const { operation, values: v } = parse(args); signal?.throwIfAborted();
    const shared = { workdir: v['--workdir'], ...(signal === undefined ? {} : { signal }),
      ...(v['--timeout-ms'] === undefined ? {} : { timeoutMs: Number(v['--timeout-ms']) }) };
    result = operation === 'prepare' ? await preparePullImport({ ...shared, archiveDir: v['--archive-dir'], archiveConfirm: v['--archive-confirm'],
      selection: parsePullJson(await readPullPrivate(v['--selection'], 1024 * 1024)), tokenFile: v['--token-file'] })
      : operation === 'inspect' ? await inspectPullImport({ ...shared, confirm: v['--confirm'] })
      : await executePullImport({ ...shared, operation, confirm: v['--confirm'],
        ...(v['--token-file'] === undefined ? {} : { tokenFile: v['--token-file'] }),
        ...(v['--ca-file'] === undefined ? {} : { caFile: v['--ca-file'] }),
        ...(v['--retry-key'] === undefined ? {} : { retryKey: v['--retry-key'] }),
        ...(v['--max-operations'] === undefined ? {} : { maxOperations: Number(v['--max-operations']) }) });
    await write(stdout, result);
    return ['run', 'recover'].includes(operation) ? result.complete ? 0 : result.state === 'refused' ? 1 : 3 : 0;
  } catch (error) {
    try { await write(stderr, { type: 'native_pull_import_error', code: error.code ?? 'pull_import_failure',
      ...(error.import_progress ? { import_progress: error.import_progress } : {}), ...(result ? { retained_result: result } : {}) }); } catch { /* Keep custody. */ }
    return result || error.import_progress?.directory_created || error.import_progress?.plan_verified ? 4 : 2;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController(), stop = () => controller.abort();
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  try { process.exitCode = await main(process.argv.slice(2), { signal: controller.signal }); }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
