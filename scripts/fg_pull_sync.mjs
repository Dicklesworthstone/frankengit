#!/usr/bin/env node
// Remote exact-tip PR synchronization over native APIs, not another Git engine.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { directory, readPrivate, absolute } from './operator/workflow_watch_io.mjs';
import { discover, destination, freezePlan } from './operator/pull_sync_plan.mjs';
import { loadPlan, savePlan, planSummary } from './operator/pull_sync_custody.mjs';
import { parseSyncJson, tokenValue } from './operator/pull_sync_transport.mjs';

const USAGE = `node scripts/fg_pull_sync.mjs inspect|prepare
  --destination /private/destination.json --token-file /private/token
  (--all-open | --pr <number> [--pr <number> ...])
  [--ca-file /private/ca.pem] [--timeout-ms <1..300000>]
  --state /private/empty-plan-directory (prepare only)
node scripts/fg_pull_sync.mjs show --state /private/plan-directory

Inspect open PR metadata and both current tips at ONE native snapshot. Preparation
saves exact tip-only updates without sending any mutation. Never edits title/body,
closes missing branches, moves refs, or carries approvals to changed code.
Use Node >=22 with raw JSON number sources, on POSIX. All control files are private;
state directories must already exist as nonsymlink 0700 directories.
Exit 0: complete result; 2: input/read/write failure; 4: saved result but output failed.
See docs/PULL_REQUEST_TIP_SYNCHRONIZATION.md.`;
export async function output(stream, value) {
  const bytes = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(bytes) > 24 * 1024 * 1024) throw new Error('sync_output_byte_limit');
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = error => { if (settled) return; settled = true; clearTimeout(timer); if (!error) stream.removeListener('error', failed); error ? reject(error) : resolve(); };
    const failed = error => finish(error);
    const timer = setTimeout(() => { stream.destroy(); finish(new Error('sync_output_deadline')); }, 10000);
    stream.once('error', failed);
    stream.write(bytes, finish);
  });
}
function options(args) {
  if (!Array.isArray(args) || args.length > 280 || args.some(arg => typeof arg !== 'string' || arg.length > 8192) ||
      args.reduce((n, arg) => n + arg.length, 0) > 65536 || !['inspect', 'prepare', 'show'].includes(args[0])) throw new Error(USAGE);
  const operation = args[0], fields = new Map(), prs = [];
  for (let i = 1; i < args.length;) {
    const flag = args[i++];
    if (!['--destination', '--token-file', '--all-open', '--pr', '--ca-file', '--timeout-ms', '--state'].includes(flag)) throw new Error(USAGE);
    const value = flag === '--all-open' ? true : args[i++];
    if (value === undefined || value === '' || (typeof value === 'string' && value.startsWith('--'))) throw new Error(USAGE);
    if (flag === '--pr') {
      if (!/^[1-9][0-9]{0,15}$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error(USAGE);
      prs.push(Number(value));
    } else { if (fields.has(flag)) throw new Error(USAGE); fields.set(flag, value); }
  }
  if (operation === 'show') {
    if (fields.size !== 1 || !fields.has('--state') || prs.length) throw new Error(USAGE);
  } else if (!fields.has('--destination') || !fields.has('--token-file') || (fields.has('--all-open') === (prs.length > 0)) ||
      (operation === 'prepare') !== fields.has('--state')) throw new Error(USAGE);
  let timeoutMs = 120000;
  if (fields.has('--timeout-ms')) {
    const value = fields.get('--timeout-ms');
    if (!/^[1-9][0-9]{0,5}$/.test(value) || Number(value) > 300000) throw new Error(USAGE);
    timeoutMs = Number(value);
  }
  return { operation, fields, selected: fields.has('--all-open') ? 'all-open' : prs, timeoutMs };
}
export async function controlFile(path, maximum) {
  absolute(path); await directory(dirname(path)); return readPrivate(path, maximum);
}
export async function credential(path) {
  const raw = await controlFile(path, 65), text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  return tokenValue(text.endsWith('\n') ? text.slice(0, -1) : text);
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort(new Error('sync_stop_requested'));
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await output(stdout, { usage: USAGE }); return 0; }
    const { operation, fields, selected, timeoutMs } = options(args);
    if (operation === 'show') result = planSummary(await loadPlan(fields.get('--state')));
    else {
      const dest = destination(parseSyncJson(await controlFile(fields.get('--destination'), 32768), 32768));
      const token = await credential(fields.get('--token-file'));
      const ca = fields.has('--ca-file') ? await controlFile(fields.get('--ca-file'), 128 * 1024) : undefined;
      const discovery = await discover(dest, token, selected, { timeoutMs, ca, signal: stop.signal });
      if (operation === 'inspect') result = discovery;
      else { stop.signal.throwIfAborted(); result = planSummary(await savePlan(fields.get('--state'), freezePlan(discovery, token))); }
    }
    await output(stdout, result); return 0;
  } catch (error) {
    try { await output(stderr, { type: 'pull_sync_error', message: error.message, mutations_sent: 0,
      ...(result ? { retained_plan_sha256: result.plan_sha256 ?? null } : {}) }); } catch { /* Retained plan is not erased. */ }
    return result ? 4 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
