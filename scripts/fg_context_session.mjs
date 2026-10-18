#!/usr/bin/env node
// Explicit local session custody; the only network operation is one native read.
import { pathToFileURL } from 'node:url';
import { parse, fail } from './operator/source_context.mjs';
import { absolute, readPrivate } from './operator/source_context_export.mjs';
import { createSession, inspectSession, runSessionStep, acquireSessionStep, recoverSessionStep } from './operator/source_context_session.mjs';
import { exportSessionContext, inspectSessionContextExport } from './operator/source_context_session_export.mjs';

const USAGE = `node scripts/fg_context_session.mjs init --session ABSENT_PRIVATE_PATH
  --from-bundle PRIVATE_BUNDLE --from-sha256 RETAINED_MANIFEST --limits-file PRIVATE_JSON
node scripts/fg_context_session.mjs step --session PRIVATE_PATH --session-sha256 ROOT
  --tip-sha256 EXACT_TIP --followup-file PRIVATE_JSON --token-file PRIVATE_TOKEN
node scripts/fg_context_session.mjs status --session PRIVATE_PATH --session-sha256 ROOT
  --tip-sha256 RETAINED_TIP
node scripts/fg_context_session.mjs recover --session PRIVATE_PATH --session-sha256 ROOT
  --tip-sha256 RETAINED_TIP --request-sha256 ORIGINAL_REQUEST [--candidate-sha256 ORIGINAL_CANDIDATE]
node scripts/fg_context_session.mjs dispatch --session PRIVATE_PATH --session-sha256 ROOT
  --tip-sha256 EXACT_TIP --request-sha256 RESERVED_REQUEST --token-file PRIVATE_TOKEN

node scripts/fg_context_session.mjs export --session PRIVATE_PATH --session-sha256 ROOT
  --tip-sha256 RETAINED_TIP --output ABSENT_PRIVATE_PATH [--export-limits-file PRIVATE_JSON]
node scripts/fg_context_session.mjs inspect-export --session PRIVATE_PATH --session-sha256 ROOT
  --tip-sha256 RETAINED_TIP --output PRIVATE_EXPORT --export-sha256 RETAINED_MANIFEST

export/inspect-export are offline and select exactly the named terminal prefix,
including earlier captures' original path scopes. They do not examine later work,
recheck current repository authorization, advance the tip or refund reservations.
Source excerpts are deduplicated only when bytes agree; query omissions survive.
No global search-completeness or new ranking claim is made. Keep exports private.

All commands accept --timeout-ms 1..300000. Only step/dispatch accept --ca-file.
A limits file supplies queries, work, payload_bytes, source_bytes, excerpt_bytes.
No endpoint override, latest guess, retry, force, reset or budget refund exists.
step reserves, acquires and finalizes once. dispatch is only for an explicitly
reserved request that has NEVER started; it stages a candidate for recover.
recover/status need no credential or network. Preserve every returned root/tip
and request/candidate hash. Never delete interrupted state to make a step run.
Private directories are 0700 and files 0600. No source text grants authority.
Exit 0: initialized or settled complete result; 3: staged/pending/partial result;
2: refusal or error; 4: local result retained but output failed.
See docs/SOURCE_CONTEXT_SESSIONS.md and docs/SOURCE_CONTEXT_SESSION_EXPORT.md.`;
const COMMON = ['--session', '--session-sha256', '--tip-sha256', '--timeout-ms'];
function options(args) {
  if (!Array.isArray(args) || args.length > 21 || args.some(a => typeof a !== 'string' || Buffer.byteLength(a) > 4096)) fail('invalid_session_cli_arguments');
  const operation = args[0], profiles = {
    init: [['--session', '--from-bundle', '--from-sha256', '--limits-file', '--timeout-ms'], ['--session', '--from-bundle', '--from-sha256', '--limits-file']],
    step: [[...COMMON, '--followup-file', '--token-file', '--ca-file'], ['--session', '--session-sha256', '--tip-sha256', '--followup-file', '--token-file']],
    status: [COMMON, ['--session', '--session-sha256', '--tip-sha256']],
    export: [[...COMMON, '--output', '--export-limits-file'], ['--session', '--session-sha256', '--tip-sha256', '--output']],
    'inspect-export': [[...COMMON, '--output', '--export-sha256'], ['--session', '--session-sha256', '--tip-sha256', '--output', '--export-sha256']],
    recover: [[...COMMON, '--request-sha256', '--candidate-sha256'], ['--session', '--session-sha256', '--tip-sha256', '--request-sha256']],
    dispatch: [[...COMMON, '--request-sha256', '--token-file', '--ca-file'], ['--session', '--session-sha256', '--tip-sha256', '--request-sha256', '--token-file']],
  };
  if (!Object.hasOwn(profiles, operation)) fail('invalid_session_cli_operation');
  const [allowed, required] = profiles[operation], fields = new Map();
  for (let i = 1; i < args.length; i += 2) {
    const flag = args[i], value = args[i + 1];
    if (!allowed.includes(flag) || fields.has(flag) || !value || value.startsWith('--')) fail('invalid_session_cli_option');
    fields.set(flag, value);
  }
  if (required.some(k => !fields.has(k))) fail('missing_session_cli_option');
  for (const [k, v] of fields) {
    if (k.endsWith('-sha256') && !/^[0-9a-f]{64}$/.test(v)) fail('context_session_pin_required');
    if (k.endsWith('-file') || ['--session', '--from-bundle', '--output'].includes(k)) absolute(v);
  }
  const timeout = fields.get('--timeout-ms') ?? '30000';
  if (!/^[1-9][0-9]{0,5}$/.test(timeout) || Number(timeout) > 300000) fail('invalid_session_cli_timeout');
  return { operation, fields, timeout: Number(timeout) };
}
async function emit(stream, value) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  if (bytes.length > 65536) fail('context_session_output_limit');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => { if (done) return; done = true; clearTimeout(timer); if (!error) stream.removeListener('error', onError); error ? reject(error) : resolve(); };
    const onError = error => finish(error), timer = setTimeout(() => {
      const error = new Error('context_session_output_timeout'); stream.destroy(error); finish(error);
    }, 10000);
    stream.once('error', onError);
    try { stream.write(bytes, error => finish(error)); } catch (error) { finish(error); }
  });
}
async function credential(path, check) {
  const bytes = await readPrivate(path, 66, check);
  try {
    if (bytes.some(b => b > 127) || !/^[0-9a-f]{64}(?:\r?\n)?$/.test(bytes.toString('ascii'))) fail('invalid_source_read_token_file');
    return bytes.toString('ascii').replace(/\r?\n$/, '');
  } finally { bytes.fill(0); }
}
function exitCode(result) {
  if (result.type === 'source_context_session_refused') return 2;
  if (result.type.startsWith('source_context_session_export')) return result.all_captured_queries_complete && !result.refused_steps ? 0 : 3;
  if (result.type === 'source_context_session_staged' || result.pending || result.latest_query_complete === false) return 3;
  return 0;
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const controller = new AbortController(), abort = () => controller.abort(new Error('context_session_stop_requested'));
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result, session;
  try {
    if (args.length === 1 && args[0] === '--help') { await emit(stdout, { usage: USAGE }); return 0; }
    const { operation, fields: f, timeout } = options(args), started = performance.now();
    session = f.get('--session');
    const check = () => { controller.signal.throwIfAborted(); if (performance.now() - started >= timeout) fail('context_deadline_exceeded'); };
    const remaining = () => { check(); const n = Math.floor(timeout - (performance.now() - started)); if (n < 1) fail('context_deadline_exceeded'); return n; };
    const local = () => ({ signal: controller.signal, timeoutMs: remaining() });
    const json = async path => parse(await readPrivate(path, 256 * 1024, check));
    const root = f.get('--session-sha256'), tip = f.get('--tip-sha256');
    if (operation === 'init') {
      const limits = await json(f.get('--limits-file'));
      result = await createSession(session, f.get('--from-bundle'), f.get('--from-sha256'), limits, local());
    } else if (operation === 'export') {
      const limits = f.has('--export-limits-file') ? await json(f.get('--export-limits-file')) : {};
      result = await exportSessionContext(session, root, tip, f.get('--output'), limits, local());
    } else if (operation === 'inspect-export') result = await inspectSessionContextExport(session, root, tip, f.get('--output'), f.get('--export-sha256'), local());
    else if (operation === 'status') result = await inspectSession(session, root, tip, local());
    else if (operation === 'recover') result = await recoverSessionStep(session, root, tip, f.get('--request-sha256'), f.get('--candidate-sha256') ?? null, local());
    else {
      const followup = operation === 'step' ? await json(f.get('--followup-file')) : null;
      const token = await credential(f.get('--token-file'), check);
      const ca = f.has('--ca-file') ? await readPrivate(f.get('--ca-file'), 262144, check) : undefined;
      const network = { ...local(), ...(ca ? { ca } : {}) };
      result = operation === 'step'
        ? await runSessionStep(session, root, tip, followup, token, network)
        : await acquireSessionStep(session, root, tip, f.get('--request-sha256'), token, network);
      result = { ...result, session, session_sha256: root };
    }
    await emit(stdout, result); return exitCode(result);
  } catch (error) {
    try {
      await emit(stderr, { type: 'source_context_session_error', code: error.code ?? 'context_session_operation_failed',
        session: session ?? null, repository_mutated: false, acquisition_retried: false,
        ...(error.session_reservation ? { retained_reservation: error.session_reservation } : {}),
        ...(error.context_export_unconfirmed ? { export_publication_unconfirmed: error.context_export_unconfirmed } : {}),
        ...(result ? { retained_result: result } : {}) });
    } catch { /* Preserve files and the original result even when both streams fail. */ }
    return result || error.context_export_unconfirmed ? 4 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
