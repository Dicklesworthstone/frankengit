#!/usr/bin/env node
// Standalone discussion reads only; no mutation, restore or recovery request.
import { pathToFileURL } from 'node:url';
import { exportDiscussionArchive, inspectDiscussionArchive, DISCUSSION_ARCHIVE_LIMITS as L }
  from './lib/forge-discussion-archive.mjs';
import { writeArchiveOutput } from './archive_native_issues.mjs';

const USAGE = `usage: node scripts/archive_native_discussions.mjs export
  --workdir <absent-private-directory> --url <https-repository-url/ui/discussions/>
  --tenant <32-hex> --repository <32-hex> --token-file <private-discussions-read-token>
  [--head <original-snapshot-token> --page-size <1..100> --timeout-ms <1..300000>]
  [--max-requests <1..8192> --max-discussions <1..4096> --max-events <1..65536>]
  [--max-read-bytes <1..67108864> --max-archive-bytes <1..67108864>]

node scripts/archive_native_discussions.mjs inspect
  --workdir <existing-private-archive> --confirm <independently-retained-sha256>
  [--timeout-ms <1..300000>]

Export retains every standalone discussion, original action and comment at one
native snapshot, checks full replay including final close/lock state, and only
then publishes archive.json after complete readback. Inspect is offline and
needs no credential or source service. Neither operation grants restore or
mutation authority. Partial exports are not resumed, overwritten or complete.

Exit 0: complete export/inspection; 2: invalid input or inspection failure;
3: incomplete/uncertain local export; 4: result known but output failed.
See docs/NATIVE_DISCUSSION_ARCHIVE.md.`;

function options(args) {
  if (!Array.isArray(args) || args.length > 32 || args.some(arg => typeof arg !== 'string' || arg.length > 8192 || arg.includes('\0')) ||
      args.reduce((n, arg) => n + arg.length, 0) > 65536 || !['export', 'inspect'].includes(args[0])) throw new Error(USAGE);
  const operation = args[0], result = {}, seen = new Set();
  const fields = { '--workdir': 'workdir', '--url': 'href', '--tenant': 'tenant', '--repository': 'repository',
    '--token-file': 'tokenFile', '--confirm': 'confirm', '--head': 'head' };
  const budgets = { '--page-size': ['pageSize', 100], '--timeout-ms': ['timeoutMs', 300000],
    '--max-requests': ['maxRequests', L.pages], '--max-discussions': ['maxDiscussions', L.discussions],
    '--max-events': ['maxEvents', L.events], '--max-read-bytes': ['maxReadBytes', L.bytes],
    '--max-archive-bytes': ['maxArchiveBytes', L.bytes] };
  for (let i = 1; i < args.length;) {
    const flag = args[i++], value = args[i++];
    if (seen.has(flag) || !value || value.startsWith('--') ||
        !(Object.hasOwn(fields, flag) || Object.hasOwn(budgets, flag)) ||
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
    result = await (parsed.operation === 'export' ? exportDiscussionArchive(input) : inspectDiscussionArchive(input));
    await writeArchiveOutput(stdout, result); return 0;
  } catch (error) {
    try { await writeArchiveOutput(stderr, { type: 'forge_discussion_archive_error', schema_version: 1,
      message: String(error.message).slice(0, 4096), mutation_submitted: false,
      ...(error.archive_progress ? { archive_progress: error.archive_progress } : {}),
      ...(result ? { retained_result: result } : {}) }); } catch { /* Original archive custody remains available. */ }
    return result ? 4 : error.archive_progress?.directory_created ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
