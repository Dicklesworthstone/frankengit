#!/usr/bin/env node
// Explicit external operator; every native write still uses a retained key.
import { pathToFileURL } from 'node:url';
import { prepareRemoteBundle, inspectRemoteBundle, runRemoteBundle } from './operator/remote_bundle.mjs';
import { exportRemoteBundle, inspectRemoteDownload } from './operator/remote_bundle_export.mjs';
import { readPrivate, absolute, lifetime } from './operator/remote_bundle_files.mjs';
import { parse, bounded, BUNDLE_REMOTE_LIMITS as L } from './operator/remote_bundle_protocol.mjs';

export const HELP = `node scripts/remote_bundle.mjs <command> [options]
export --workdir NEW --selection PRIVATE_SOURCE_JSON --token-file PRIVATE_TOKEN [--ca-file PRIVATE_PEM]
inspect-download --workdir DOWNLOAD --confirm DOWNLOAD_SHA256
prepare --workdir NEW --selection PRIVATE_DESTINATION_JSON --token-file PRIVATE_TOKEN
        --bundle-file PRIVATE_BUNDLE --bundle-confirm ARTIFACT_SHA256
inspect|status --workdir JOB --confirm INTENT_SHA256
run|recover --workdir JOB --confirm INTENT_SHA256 [--token-file PRIVATE_TOKEN]
            [--ca-file PRIVATE_PEM] [--retry-key ORIGINAL_KEY (run only)]
All commands: [--timeout-ms 1..300000]. All file paths must be absolute.
Source selection: endpoint, scope {tenant_id,repository_id,repository_incarnation,object_format},
optional expected_head and max_bytes (1..67108864).
Destination selection: endpoint, scope also including principal_id, operation import|fetch,
optional mappings [{source_hex,destination_hex,expected_old}] (fetch requires 1..64).
Import creates every advertised ref; fetch requires explicit absent or exact old-OID leases.
Neither this CLI nor preparation validates Git. The native server owns all Git and admission checks.
inspect verifies payload too; status and recovery work without it. Uncertain sends stay fenced;
retry requires the original key and credential. No implicit force, refresh, redirects or retry.
Exit 0: operation succeeded (prepare/status may be incomplete); 1: native refusal;
2: argument/preflight failure; 3: execution unresolved/ready; 4: retained or uncertain output.
See docs/REMOTE_BUNDLE_TRANSFER.md.`;
function options(args) {
  if (!Array.isArray(args) || args.length > 32 || args.some(a => typeof a !== 'string' || a.length > 4096) ||
      args.reduce((n, a) => n + a.length, 0) > 32768) throw new Error('remote_bundle_arguments');
  const operation = args[0];
  const required = operation === 'export' ? ['workdir', 'selection', 'token-file']
    : operation === 'prepare' ? ['workdir', 'selection', 'token-file', 'bundle-file', 'bundle-confirm']
    : ['inspect-download', 'inspect', 'status', 'run', 'recover'].includes(operation) ? ['workdir', 'confirm'] : null;
  if (!required) throw new Error('remote_bundle_command');
  const allowed = new Set([...required, 'timeout-ms', ...(operation === 'export' ? ['ca-file']
    : ['run', 'recover'].includes(operation) ? ['token-file', 'ca-file', ...(operation === 'run' ? ['retry-key'] : [])] : [])]);
  const flags = {};
  for (let i = 1; i < args.length;) {
    const arg = args[i++], value = args[i++], name = arg.startsWith('--') ? arg.slice(2) : '';
    if (!allowed.has(name) || Object.hasOwn(flags, name) || value === undefined || !value || value.startsWith('--')) throw new Error('remote_bundle_arguments');
    flags[name] = value;
  }
  if (required.some(name => !Object.hasOwn(flags, name))) throw new Error('remote_bundle_arguments');
  if (flags['timeout-ms'] !== undefined && !/^[1-9][0-9]*$/.test(flags['timeout-ms'])) throw new Error('remote_bundle_timeout');
  const timeoutMs = bounded(flags['timeout-ms'] === undefined ? 300000 : Number(flags['timeout-ms']), 1, 300000);
  return { operation, flags, timeoutMs };
}
const output = value => `${JSON.stringify(value).replace(/[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu,
  c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)}\n`;
async function write(stream, value, timeoutMs = 10000) {
  const text = output(value); if (Buffer.byteLength(text) > 2 * L.intent) throw new Error('remote_bundle_output_limit');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => {
      if (done) return; done = true; clearTimeout(timer);
      // Writable emits its error after calling the callback. Retain the listener
      // through that turn so a broken pipe cannot erase our saved result.
      setImmediate(() => { stream.removeListener?.('error', onError); error ? reject(error) : resolve(); });
    };
    const onError = error => finish(error);
    const timer = setTimeout(() => { const e = new Error('remote_bundle_output_timeout'); stream.destroy?.(e); finish(e); }, Math.min(timeoutMs, 10000));
    stream.once?.('error', onError);
    try { stream.write(text, finish); } catch (e) { finish(e); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort();
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result, life;
  try {
    if (args.length === 1 && args[0] === '--help') { await write(stdout, { usage: HELP }); return 0; }
    const { operation, flags: f, timeoutMs } = options(args); life = lifetime({ timeoutMs, signal: stop.signal });
    const values = { workdir: absolute(f.workdir), signal: life.signal };
    if (f.confirm !== undefined) values.confirm = f.confirm;
    if (f['token-file'] !== undefined) values.tokenFile = absolute(f['token-file']);
    if (f['ca-file'] !== undefined) values.caFile = absolute(f['ca-file']);
    if (f.selection !== undefined) values.selection = parse(await readPrivate(absolute(f.selection), L.intent, life.check));
    values.timeoutMs = life.remaining();
    if (operation === 'prepare') result = await prepareRemoteBundle({ ...values, bundleFile: absolute(f['bundle-file']), bundleConfirm: f['bundle-confirm'] });
    else if (operation === 'export') result = await exportRemoteBundle(values);
    else if (operation === 'inspect-download') result = await inspectRemoteDownload(values);
    else if (operation === 'inspect' || operation === 'status') result = await inspectRemoteBundle({ ...values, verifyPayload: operation === 'inspect' });
    else result = await runRemoteBundle({ ...values, operation, ...(f['retry-key'] === undefined ? {} : { retryKey: f['retry-key'] }) });
    await write(stdout, result, life.remaining());
    return !['run', 'recover'].includes(operation) || result.complete ? 0 : result.state === 'refused' ? 1 : 3;
  } catch (e) {
    const code = typeof e?.code === 'string' && /^[a-z_]{1,128}$/.test(e.code) ? e.code
      : typeof e?.message === 'string' && /^remote_bundle_[a-z_]+$/.test(e.message) ? e.message : 'remote_bundle_command_failed';
    try { await write(stderr, { type: 'remote_bundle_error', code,
      ...(e.bundle_progress ? { bundle_progress: e.bundle_progress } : {}), ...(result ? { retained_result: result } : {}) }); }
    catch { /* Neither a broken output nor its diagnostic owns deletion/retry authority. */ }
    return result || e.bundle_progress?.directory_created || e.bundle_progress?.selection_verified ? 4 : 2;
  } finally { life?.close(); process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
