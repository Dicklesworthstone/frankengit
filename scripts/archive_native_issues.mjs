#!/usr/bin/env node
// Authenticated native reads only. A read archive is not a restore authority.
import { pathToFileURL } from 'node:url';
import { exportIssueArchive, inspectIssueArchive, ISSUE_ARCHIVE_LIMITS as L } from './lib/forge-issue-archive.mjs';
import { operatorJson } from './lib/forge-operator-io.mjs';

const USAGE = `usage: node scripts/archive_native_issues.mjs export
  --workdir <absent-private-directory> --url <https-repository-url/ui/issues/>
  --tenant <32-hex> --repository <32-hex> --token-file <private-issues-read-token>
  [--head <original-snapshot-token> --page-size <1..100> --timeout-ms <1..300000>]
  [--max-requests <1..8192> --max-issues <1..4096> --max-events <1..65536>]
  [--max-read-bytes <1..67108864> --max-archive-bytes <1..67108864>]

node scripts/archive_native_issues.mjs inspect
  --workdir <existing-private-archive> --confirm <independently-retained-sha256>
  [--timeout-ms <1..300000>]

Export pins every list/history to one native snapshot, retains all actions and
comments, and publishes archive.json only after complete validation/readback.
Inspect is offline, read-only and needs no token or source server. Neither
operation creates a native mutation, restore grant or canonical repository backup.
Partial exports are never resumed, overwritten or reported complete.

Exit 0: complete selected read/inspection; 2: invalid input or inspection failure;
3: incomplete/uncertain local export; 4: result known but output failed.
See docs/NATIVE_ISSUE_ARCHIVE.md.`;

export function writeArchiveOutput(stream, value, timeoutMs = 10000) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) throw new Error('Invalid output deadline.');
  const text = operatorJson(value);
  if (Buffer.byteLength(text) > 16384) throw new Error('Archive output exceeds its bound.');
  return new Promise((resolve, reject) => {
    const error = cause => { clearTimeout(timer); reject(cause); };
    const timer = setTimeout(() => {
      const cause = new Error('Archive output deadline exceeded; original custody retained.');
      stream.destroy(cause); error(cause);
    }, timeoutMs);
    stream.once('error', error);
    try {
      stream.write(text, cause => {
        if (cause) error(cause); // Retain the listener for the subsequent error event.
        else { clearTimeout(timer); stream.removeListener('error', error); resolve(); }
      });
    } catch (cause) { error(cause); }
  });
}
function options(args) {
  if (!Array.isArray(args) || args.length > 31 || args.some(arg => typeof arg !== 'string' || arg.length > 8192 || arg.includes('\0')) ||
      args.reduce((n, arg) => n + arg.length, 0) > 65536 || !['export', 'inspect'].includes(args[0]) || args.length % 2 !== 1) throw new Error(USAGE);
  const operation = args[0], result = {}, seen = new Set();
  const fields = { '--workdir': 'workdir', '--url': 'href', '--tenant': 'tenant', '--repository': 'repository',
    '--token-file': 'tokenFile', '--confirm': 'confirm', '--head': 'head' };
  const budgets = { '--page-size': ['pageSize', 100], '--timeout-ms': ['timeoutMs', 300000],
    '--max-requests': ['maxRequests', L.pages], '--max-issues': ['maxIssues', L.issues], '--max-events': ['maxEvents', L.events],
    '--max-read-bytes': ['maxReadBytes', L.bytes], '--max-archive-bytes': ['maxArchiveBytes', L.bytes] };
  for (let i = 1; i < args.length; i += 2) {
    const flag = args[i], value = args[i + 1];
    if (seen.has(flag) || !value || value.startsWith('--') || !(Object.hasOwn(fields, flag) || Object.hasOwn(budgets, flag)) ||
        (operation === 'inspect' && !['--workdir', '--confirm', '--timeout-ms'].includes(flag)) ||
        (operation === 'export' && flag === '--confirm')) throw new Error(USAGE);
    seen.add(flag);
    if (Object.hasOwn(fields, flag)) result[fields[flag]] = value;
    else {
      const [name, max] = budgets[flag];
      if (!/^[1-9][0-9]{0,8}$/.test(value) || Number(value) > max) throw new Error(USAGE);
      result[name] = Number(value);
    }
  }
  const required = operation === 'export' ? ['workdir', 'href', 'tenant', 'repository', 'tokenFile'] : ['workdir', 'confirm'];
  if (required.some(key => !Object.hasOwn(result, key))) throw new Error(USAGE);
  return { operation, result };
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort(new Error('Archive stop requested; no native mutation was submitted.'));
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await writeArchiveOutput(stdout, { usage: USAGE }); return 0; }
    const parsed = options(args), input = { ...parsed.result, signal: stop.signal };
    result = await (parsed.operation === 'export' ? exportIssueArchive(input) : inspectIssueArchive(input));
    await writeArchiveOutput(stdout, result); return 0;
  } catch (error) {
    try { await writeArchiveOutput(stderr, { type: 'forge_issue_archive_error', schema_version: 1,
      message: String(error.message).slice(0, 4096), mutation_submitted: false,
      ...(error.archive_progress ? { archive_progress: error.archive_progress } : {}),
      ...(result ? { retained_result: result } : {}) }); } catch { /* The original archive remains available. */ }
    return result ? 4 : error.archive_progress?.directory_created ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
