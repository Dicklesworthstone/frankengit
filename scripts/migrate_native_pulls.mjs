#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { preparePullImport, inspectPullImport } from './lib/native-pull-import.mjs';
import { readPullPrivate } from './operator/pull_files.mjs';
import { parsePullJson, pullCanonical } from './operator/pull_command.mjs';

export const HELP = `Usage: node scripts/migrate_native_pulls.mjs prepare --archive-dir ABS --archive-confirm SHA256 --selection PRIVATE_JSON --token-file PRIVATE_TOKEN --workdir NEW_ABS [--timeout-ms 1..300000]
       node scripts/migrate_native_pulls.mjs inspect --workdir ABS --confirm PLAN_SHA256 [--timeout-ms 1..300000]
Selection: endpoint, scope {tenant_id, repository_id, repository_incarnation, principal_id, object_format}, number_start (decimal string).
Optional: merged (refuse|as-closed), ref_map [{source_hex,destination}], max_steps, max_source_bytes, max_request_bytes.
Preparation and inspection are offline. Only open/comment/close requests are produced; votes never become destination approvals.
Destination Git objects and branch coordinates must already exist. Existing PR numbers refuse; there is no automatic renumbering.
Retain the plan_sha256 independently. Each requests/step-NNNNNN slot is an ordinary remote_pull request usable by scripts/remote_pull.mjs.
Exit 0: prepared/inspected; 2: refusal; 4: failure with retained or uncertain preparation/output. No result proves non-commit.\n`;
function parse(args) {
  if (!Array.isArray(args) || args.length > 25 || args.some(x => typeof x !== 'string' || x.length > 4096)) throw new Error('pull_import_arguments');
  const operation = args[0]; if (!['prepare', 'inspect'].includes(operation)) throw new Error('pull_import_command');
  const required = operation === 'prepare' ? ['--archive-dir', '--archive-confirm', '--selection', '--token-file', '--workdir'] : ['--workdir', '--confirm'];
  const allowed = new Set([...required, '--timeout-ms']), values = {};
  for (let i = 1; i < args.length;) {
    const flag = args[i++], value = args[i++];
    if (!allowed.has(flag) || Object.hasOwn(values, flag) || !value || value.startsWith('--')) throw new Error('pull_import_arguments');
    values[flag] = value;
  }
  if (required.some(k => !Object.hasOwn(values, k))) throw new Error('pull_import_arguments');
  if (values['--timeout-ms'] !== undefined && (!/^[1-9][0-9]{0,5}$/.test(values['--timeout-ms']) || Number(values['--timeout-ms']) > 300000)) throw new Error('pull_import_timeout');
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
      : await inspectPullImport({ ...shared, confirm: v['--confirm'] });
    await write(stdout, result); return 0;
  } catch (error) {
    try { await write(stderr, { type: 'native_pull_import_error', code: error.code ?? 'pull_import_failure',
      ...(error.import_progress ? { import_progress: error.import_progress } : {}), ...(result ? { retained_result: result } : {}) }); } catch { /* Keep custody. */ }
    return result || error.import_progress?.directory_created ? 4 : 2;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController(), stop = () => controller.abort();
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  try { process.exitCode = await main(process.argv.slice(2), { signal: controller.signal }); }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
