#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { exportPullArchive, inspectPullArchive } from './lib/forge-pull-archive.mjs';
import { preparePullCapture, resumePullCapture, inspectPullCapture } from './lib/forge-pull-capture.mjs';

const USAGE = `usage: node scripts/archive_native_pulls.mjs export|prepare --workdir ABS --url REPO_UI_PULLS --tenant HEX32 --repository HEX32 --token-file ABS [--head TOKEN] [--page-size 1..100] [--timeout-ms 1..300000]
       node scripts/archive_native_pulls.mjs inspect --workdir ARCHIVE --confirm ARCHIVE_SHA256 [--timeout-ms 1..300000]
       node scripts/archive_native_pulls.mjs resume --workdir JOB --confirm SELECTION_SHA256 [--token-file ABS] [--page-budget 1..16384] [--timeout-ms 1..300000]
       node scripts/archive_native_pulls.mjs status --workdir JOB --confirm SELECTION_SHA256 [--timeout-ms 1..300000]
export/prepare ceilings: --max-pages --max-pulls --max-reviews --max-comments --max-archive-bytes
resume exit 3 means a valid paused capture, not a complete archive. Retain the selection pin returned by prepare.`;
const COMMANDS = { export: exportPullArchive, inspect: inspectPullArchive,
  prepare: preparePullCapture, resume: resumePullCapture, status: inspectPullCapture };
const STRINGS = { '--workdir':'workdir', '--url':'href', '--tenant':'tenant', '--repository':'repository',
  '--token-file':'tokenFile', '--head':'head', '--confirm':'confirm' };
const NUMBERS = { '--timeout-ms':'timeoutMs', '--page-size':'pageSize', '--page-budget':'pageBudget',
  '--max-pages':'maxPages', '--max-pulls':'maxPulls', '--max-reviews':'maxReviews',
  '--max-comments':'maxComments', '--max-archive-bytes':'maxArchiveBytes' };
function options(args) {
  const operation = args[0];
  if (!Object.hasOwn(COMMANDS,operation)) throw new Error(USAGE);
  const selecting = operation === 'export' || operation === 'prepare';
  const required = selecting ? ['--workdir','--url','--tenant','--repository','--token-file'] : ['--workdir','--confirm'];
  const allowed = new Set([...required,'--timeout-ms',...(selecting
    ? ['--head','--page-size','--max-pages','--max-pulls','--max-reviews','--max-comments','--max-archive-bytes']
    : operation === 'resume' ? ['--token-file','--page-budget'] : [])]);
  const map = new Map(), values = {};
  for (let i=1;i<args.length;) {
    const flag = args[i++], value = args[i++];
    if (!allowed.has(flag) || map.has(flag) || value === undefined || value.startsWith('--')) throw new Error(USAGE);
    map.set(flag,value);
    if (Object.hasOwn(NUMBERS,flag)) {
      if (!/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error(USAGE);
      values[NUMBERS[flag]] = Number(value);
    } else values[STRINGS[flag]] = value;
  }
  if (required.some(flag => !map.has(flag))) throw new Error(USAGE);
  return {operation,values};
}
async function write(stream,value) {
  const text = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(text) > 1024*1024) throw new Error('pull archive output exceeds limit');
  await new Promise((resolve,reject) => {
    let done = false;
    const finish = error => {
      if (done) return; done = true; clearTimeout(timer);
      // A Node Writable emits its error after its write callback. Keep the
      // listener through that turn so a broken pipe cannot erase custody output.
      setImmediate(() => { stream.removeListener?.('error',onError); error ? reject(error) : resolve(); });
    };
    const onError = error => finish(error);
    const timer = setTimeout(() => finish(new Error('pull archive output deadline exceeded')),10000);
    stream.once?.('error',onError);
    try { stream.write(text,finish); } catch (error) { finish(error); }
  });
}
export async function main(args,{stdout=process.stdout,stderr=process.stderr}={}) {
  const stop = new AbortController(), abort = () => stop.abort(new Error('pull archive stop requested'));
  process.on('SIGTERM',abort); process.on('SIGINT',abort);
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await write(stdout,{usage:USAGE}); return 0; }
    const parsed = options(args);
    result = await COMMANDS[parsed.operation]({...parsed.values,signal:stop.signal});
    await write(stdout,result);
    return parsed.operation === 'resume' && !result.complete ? 3 : 0;
  } catch (error) {
    try { await write(stderr,{type:'pull_archive_error',message:error.message,
      ...(error.archive_progress ? {archive_progress:error.archive_progress} : {}),
      ...(error.capture_progress ? {capture_progress:error.capture_progress} : {}),
      ...(result ? {retained_result:result} : {})}); } catch { /* Custody stays available for explicit inspection. */ }
    const retained = result || error.archive_progress?.expected_archive_sha256 ||
      error.capture_progress?.selection_sha256 && (error.capture_progress.directory_created || error.capture_progress.selection_verified);
    return retained ? 4 : 2;
  } finally { process.removeListener('SIGTERM',abort); process.removeListener('SIGINT',abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
