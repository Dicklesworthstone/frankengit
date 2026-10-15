#!/usr/bin/env node
// Explicit, bounded local discovery. No source execution or repository writes.
import { pathToFileURL } from 'node:url';
import { scanSourceWorkspace, readWorkspaceScanInput, SCAN_LIMITS } from './operator/source_workspace_scan.mjs';
const USAGE = `node scripts/fg_source_workspace_scan.mjs scan
  --workspace PRIVATE_WORKSPACE --sha256 INDEPENDENT_WORKSPACE_HASH
  --scope PRIVATE_SCOPE_JSON [--timeout-ms 1..300000]

Scope: {"roots_hex":["737263"],"exclude_hex":["7372632f746172676574"],"include_unselected":false}
Select directories below files/ using exact byte-path hex. The empty string
explicitly selects files/ itself. No ignore file is read. Exclusions are explicit
subtrees, not glob patterns. No scope is inferred. The returned scan_sha256 pins
the complete sorted report; retain it independently when reviewing discovered
edits. New local paths are labelled unselected: their absence in the native
repository has NOT been proved by this scan. It is not a complete Git checkout.
No symlinks, hardlinks, special files or nonprivate paths are followed. Limits
refuse the whole scan, never return a successful partial inventory. No file is
changed, no source executed, no network contacted, and no merge authorized.
Node 22.16 or later on POSIX is required. Exit 0: complete scan; 2: refusal or
output failure; 3: cancellation. Scope and workspace parents must remain stable
and operator-controlled. This is not an atomic or hostile-same-UID snapshot.`;
function options(args) {
  if (!Array.isArray(args) || args[0] !== 'scan' || args.length % 2 !== 1 || args.length > 9 ||
      args.some(a => typeof a !== 'string' || Buffer.byteLength(a) > 4096)) throw new Error('source_workspace_scan_arguments');
  const f = new Map();
  for (let i = 1; i < args.length; i += 2) {
    if (!['--workspace', '--sha256', '--scope', '--timeout-ms'].includes(args[i]) || f.has(args[i]) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('source_workspace_scan_arguments');
    f.set(args[i], args[i + 1]);
  }
  if (['--workspace', '--sha256', '--scope'].some(k => !f.has(k))) throw new Error('source_workspace_scan_arguments');
  const timeout = f.get('--timeout-ms') ?? '30000';
  if (!/^[1-9][0-9]{0,5}$/.test(timeout) || Number(timeout) > 300000) throw new Error('source_workspace_scan_timeout');
  return { f, timeout: Number(timeout) };
}
async function emit(stream, value) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  if (bytes.length > SCAN_LIMITS.reportBytes + 4096) throw new Error('source_workspace_scan_output_budget');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = e => { if (done) return; done = true; clearTimeout(timer); if (!e) stream.removeListener('error', onError); e ? reject(e) : resolve(); };
    const onError = e => finish(e), timer = setTimeout(() => { const e = new Error('source_workspace_scan_output_timeout'); finish(e); stream.destroy(e); }, 10000);
    stream.once('error', onError);
    try { stream.write(bytes, finish); } catch (e) { finish(e); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const controller = new AbortController(), stop = () => controller.abort();
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
  try {
    if (args.length === 1 && args[0] === '--help') { await emit(stdout, { usage: USAGE }); return 0; }
    const { f, timeout } = options(args), end = performance.now() + timeout;
    const remaining = () => { controller.signal.throwIfAborted(); const n = Math.ceil(end - performance.now()); if (n < 1) throw new Error('source_workspace_scan_deadline'); return n; };
    const scope = await readWorkspaceScanInput(f.get('--scope'), { signal: controller.signal, timeoutMs: remaining() });
    const report = await scanSourceWorkspace(f.get('--workspace'), f.get('--sha256'), scope, { signal: controller.signal, timeoutMs: remaining() });
    await emit(stdout, report); return 0;
  } catch (e) {
    const code = e.code ?? e.message;
    try { await emit(stderr, { type: 'source_workspace_scan_error', code: /^source_[a-z0-9_]{1,90}$/.test(code) ? code : 'source_workspace_scan_refused',
      repository_changed: false, source_executed: false, network_attempted: false }); } catch { /* Preserve the original failure. */ }
    return controller.signal.aborted ? 3 : 2;
  } finally { process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
