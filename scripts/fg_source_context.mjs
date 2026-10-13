#!/usr/bin/env node
// Remote model-free source context for scripts/agents; no repository execution.
import { pathToFileURL } from 'node:url';
import { acquire, endpoint, parse, query, fail } from './operator/source_context.mjs';
import { absolute, absentBundle, readPrivate, publishBundle, inspectBundle } from './operator/source_context_export.mjs';

const USAGE = `usage: node scripts/fg_source_context.mjs capture
  --endpoint <https-repository-endpoint> --query-file <absolute-private-json>
  --token-file <absolute-private-token> --output <absolute-new-bundle-directory>
  [--ca-file <absolute-private-pem>] [--timeout-ms <1..300000>] [--require-complete]

       node scripts/fg_source_context.mjs inspect
  --bundle <absolute-private-bundle-directory> --expected-sha256 <retained-manifest-sha256>

One native content/path query, with optional explicit symbols, supplies excerpts
under the original scope, source pins, independent index checkpoints and budgets.
No fallback, automatic retry, semantic ranking, workflow execution or write is allowed.
Tokens are read from 0600 files in private 0700 directories, never argv or output.
Outputs are capture.json (byte-exact hex excerpts), context.txt (quoted untrusted
source), and a last-written manifest.json. Keep its printed hash independently.
Inspect uses no credential, network or native executable. Never erase an existing
or incomplete bundle to make a retry succeed. See docs/REMOTE_SOURCE_CONTEXT.md.
Exit 0: complete context; 3: explicit partial coverage (or --require-complete refused);
2: input/read/export failure; 4: bundle committed locally but stdout failed.`;
function options(args) {
  if (args.length > 16 || args.some(v => typeof v !== 'string' || Buffer.byteLength(v) > 4096) ||
      !['capture', 'inspect'].includes(args[0])) fail('invalid_context_cli_arguments');
  const allowed = args[0] === 'capture' ? ['--endpoint', '--query-file', '--token-file', '--output', '--ca-file', '--timeout-ms', '--require-complete']
    : ['--bundle', '--expected-sha256'];
  const fields = new Map();
  for (let i = 1; i < args.length;) {
    const flag = args[i++];
    if (!allowed.includes(flag) || fields.has(flag)) fail('invalid_context_cli_option');
    const value = flag === '--require-complete' ? true : args[i++];
    if (value === undefined || value === '' || typeof value === 'string' && value.startsWith('--')) fail('missing_context_cli_value');
    fields.set(flag, value);
  }
  for (const name of args[0] === 'capture' ? ['--endpoint', '--query-file', '--token-file', '--output'] : ['--bundle', '--expected-sha256']) {
    if (!fields.has(name)) fail('missing_context_cli_option');
  }
  return { operation: args[0], fields };
}
async function emit(stream, value) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  if (bytes.length > 65536) fail('context_cli_output_limit');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => { if (done) return; done = true; clearTimeout(timer); if (!error) stream.removeListener('error', onError); error ? reject(error) : resolve(); };
    const onError = error => finish(error), timer = setTimeout(() => {
      const error = new Error('context_cli_output_timeout'); stream.destroy(error); finish(error);
    }, 10000);
    stream.once('error', onError);
    try { stream.write(bytes, error => finish(error)); } catch (error) { finish(error); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort(new Error('context_stop_requested'));
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await emit(stdout, { usage: USAGE }); return 0; }
    const { operation, fields } = options(args);
    if (operation === 'inspect') result = await inspectBundle(fields.get('--bundle'), fields.get('--expected-sha256'));
    else {
      const address = endpoint(fields.get('--endpoint')), output = absolute(fields.get('--output'));
      await absentBundle(output);
      const q = query(parse(await readPrivate(fields.get('--query-file'), 256 * 1024)));
      const tokenBytes = await readPrivate(fields.get('--token-file'), 66);
      if (!/^[0-9a-f]{64}(?:\r?\n)?$/.test(tokenBytes.toString('ascii')) || tokenBytes.some(b => b > 127)) fail('invalid_source_read_token_file');
      const token = tokenBytes.toString('ascii').replace(/\r?\n$/, ''); tokenBytes.fill(0);
      const ca = fields.has('--ca-file') ? await readPrivate(fields.get('--ca-file'), 256 * 1024) : undefined;
      const timeoutText = fields.get('--timeout-ms') ?? '30000';
      if (!/^[1-9][0-9]{0,5}$/.test(timeoutText) || Number(timeoutText) > 300000) fail('invalid_context_cli_timeout');
      const capture = await acquire(address, token, q, { timeoutMs: Number(timeoutText), ca, signal: stop.signal });
      if (fields.has('--require-complete') && !capture.summary.complete) {
        await emit(stdout, { type: 'source_context_incomplete', exported: false, complete: false,
          returned_files: capture.summary.returned_files, omitted_files: capture.summary.omitted_files,
          source: capture.summary.source, source_material_untrusted: true }); return 3;
      }
      result = await publishBundle(output, capture, { signal: stop.signal });
    }
    await emit(stdout, result); return result.complete ? 0 : 3;
  } catch (error) {
    try { await emit(stderr, { type: 'source_context_error', code: error.code ?? 'context_operation_failed', status: error.status ?? null,
      message: error.message, repository_mutated: false, acquisition_retried: false,
      ...(error.context_bundle ? { incomplete_or_unconfirmed_bundle: error.context_bundle } : {}),
      ...(result ? { retained_export: result } : {}) }); } catch { /* Preserve the original files and failure. */ }
    return result ? 4 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
