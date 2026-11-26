#!/usr/bin/env node
// Durable explicit remote branch batches, through the native atomic endpoint.
import { pathToFileURL } from 'node:url';
import { BRANCH_LIMITS, BranchTransactionError, fail, encode, parse, hash, credential,
  prepareBranchTransaction, branchRecord } from './operator/branch_transaction.mjs';
import { sendBranchTransaction, recoverBranchTransaction } from './operator/branch_transaction_transport.mjs';
import { readFile, tokenFile, saveIntent, loadIntent, loadRecord, saveRecord, recordDestination, lifetime } from './operator/branch_transaction_files.mjs';

export const HELP = [
  'usage: node scripts/fg_branch_transaction.mjs prepare --input PRIVATE_JSON --token-file PRIVATE_TOKEN --request-dir NEW',
  '       node scripts/fg_branch_transaction.mjs inspect --request-dir JOB --confirm INTENT_SHA256 [--known PRIVATE_RECORD]',
  '       node scripts/fg_branch_transaction.mjs send|recover --request-dir JOB --confirm INTENT_SHA256',
  '         --token-file PRIVATE_TOKEN --record NEW_PRIVATE_JSON [--known PRIVATE_RECORD] [--ca-file PRIVATE_PEM]',
  '',
  'All commands accept --timeout-ms 1..300000. Paths must be absolute, private, and outside Git worktrees.',
  'Input: endpoint, scope {tenant_id, repository_id, repository_incarnation, principal_id, object_format}, changes.',
  'changes contains 1..32 create/update/delete entries using exact lowercase ref_hex bytes.',
  'create requires new_commit; update requires expected_commit and new_commit; delete requires expected_commit.',
  'Every OID is exact nonzero lowercase hex in the selected SHA-1 or SHA-256 domain.',
  'A rename can be one batch containing delete-old and create-new of the same commit.',
  '',
  'prepare and inspect are offline. Retain the returned intent_sha256 independently and inspect the batch before send.',
  'send requires the original credential and reviewed pin, then submits at most once under the saved key.',
  'recover performs original-key outcome reads only; rotated same-principal outcomes-read credentials may be used.',
  'The native server independently enforces receive/outcome grants, visible objects, non-forced updates and branch protection.',
  'Sponsored source-branch-create credentials do not authorize this atomic receive profile.',
  'A lost reply, refusal of HTTP intake, or absent outcome never proves rollback. Keep the original request and recover.',
  'Each network command requires a new result record; an existing record is never overwritten.',
  'No Git subprocess, object upload, force, automatic retry, tip refresh or PR publication occurs.',
  '',
  'Exit 0: prepared/inspected or native commit; 1: native refusal; 2: preflight/local failure;',
  '3: unresolved network operation or result/output failure. See docs/REMOTE_BRANCH_TRANSACTIONS.md.',
].join('\n') + '\n';
function argumentsFor(args) {
  if (!Array.isArray(args) || !args.length || args.length > 23 || args.some(v => typeof v !== 'string' || v.length > 4096) ||
      args.reduce((n, v) => n + v.length, 0) > 32768) fail('branch_transaction_arguments');
  const action = args[0], required = action === 'prepare' ? ['input', 'token-file', 'request-dir'] :
    action === 'inspect' ? ['request-dir', 'confirm'] :
    ['send', 'recover'].includes(action) ? ['request-dir', 'confirm', 'token-file', 'record'] : null;
  if (required === null) fail('branch_transaction_operation');
  const allowed = [...required, 'timeout-ms', ...(action === 'inspect' ? ['known'] : ['send', 'recover'].includes(action) ? ['known', 'ca-file'] : [])];
  const flags = {};
  for (let i = 1; i < args.length; i += 2) {
    const name = args[i].startsWith('--') ? args[i].slice(2) : '', value = args[i + 1];
    if (!allowed.includes(name) || Object.hasOwn(flags, name) || !value || value.startsWith('--')) fail('branch_transaction_option');
    flags[name] = value;
  }
  if (required.some(k => !Object.hasOwn(flags, k))) fail('branch_transaction_option');
  if (flags['timeout-ms'] !== undefined && (!/^[1-9][0-9]{0,5}$/.test(flags['timeout-ms']) || Number(flags['timeout-ms']) > 300000)) fail('branch_transaction_timeout');
  return { action, flags };
}
function outcomeState(record) { return record.publication?.outcome ?? (record.outcome?.terminal ? record.outcome.state : 'unknown'); }
export async function run(args, { output = text => write(process.stdout, text), errorOutput = text => write(process.stderr, text), signal } = {}) {
  let network = false, retained = null, recordPath = null, saved = false;
  try {
    if (args.length === 1 && args[0] === '--help') { await output(HELP); return 0; }
    const { action, flags } = argumentsFor(args), life = lifetime({ signal, timeoutMs: Number(flags['timeout-ms'] ?? 30000) });
    life.check();
    if (action === 'prepare') {
      const token = await tokenFile(flags['token-file'], life.check);
      const value = parse(await readFile(flags.input, BRANCH_LIMITS.intent, life.check));
      retained = await saveIntent(flags['request-dir'], prepareBranchTransaction(value, token), life.check);
      life.check(); await output(encode(retained).toString()); return 0;
    }
    const intent = await loadIntent(flags['request-dir'], flags.confirm, life.check, action !== 'inspect');
    const known = flags.known === undefined ? null : await loadRecord(flags.known, intent, life.check);
    if (action === 'inspect') {
      await output(encode({ type: 'branch_transaction_inspected', schema_version: 1, intent_sha256: flags.confirm,
        intent, known, read_only: true, network_accessed: false }).toString()); return 0;
    }
    const token = await tokenFile(flags['token-file'], life.check);
    const ca = flags['ca-file'] === undefined ? undefined : await readFile(flags['ca-file'], 128 * 1024, life.check);
    if (action === 'send') {
      credential(token, true);
      if (hash(token) !== intent.credential_sha256) fail('branch_transaction_original_key_and_credential_required');
    }
    recordPath = await recordDestination(flags.record); life.check();
    const options = { timeoutMs: life.remaining(), signal, ca, known: known?.outcome ?? null, publication: known?.publication ?? null,
      ...(action === 'send' ? { confirmKey: intent.key } : {}) };
    network = true;
    let result, failure;
    try { result = await (action === 'send' ? sendBranchTransaction : recoverBranchTransaction)(intent, token, options); }
    catch (error) { failure = error; }
    // The original operation's response drains to bounded custody even if the
    // invocation has stopped. Output failure never erases this result.
    retained = branchRecord(intent, result, failure ?? null);
    await saveRecord(recordPath, retained, intent); saved = true;
    if (failure) throw failure;
    life.check();
    const state = outcomeState(retained);
    await output(encode({ type: 'branch_transaction_result', schema_version: 1, record: recordPath, key: intent.key,
      intent_sha256: flags.confirm, state, dispatched: retained.dispatched,
      outcome: retained.outcome, publication: retained.publication, absence_proves_non_commit: false }).toString());
    return state === 'committed' ? 0 : state === 'refused' ? 1 : 3;
  } catch (error) {
    const diagnostic = { type: 'branch_transaction_error', schema_version: 1,
      code: error instanceof BranchTransactionError ? error.code : 'branch_transaction_local_or_output_failure',
      phase: error instanceof BranchTransactionError ? error.phase : 'local',
      record: recordPath, record_saved: saved, outcome_unknown: true,
      ...(retained ? { retained_result: retained } : error.branch_progress ? { retained_result: error.branch_progress } : {}) };
    try { await errorOutput(encode(diagnostic).toString()); } catch { /* Retained custody stays available. */ }
    return network || retained || error.branch_progress ? 3 : 2;
  }
}
function write(stream, text) {
  if (Buffer.byteLength(text) > 1024 * 1024) return Promise.reject(new Error('branch_transaction_output_limit'));
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = error => {
      if (done) return; done = true; clearTimeout(timer);
      setImmediate(() => { stream.removeListener('error', onError); error ? reject(error) : resolve(); });
    };
    const onError = error => finish(error), timer = setTimeout(() => finish(new Error('branch_transaction_output_timeout')), 10000);
    stream.once('error', onError);
    try { stream.write(text, finish); } catch (error) { finish(error); }
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const stop = new AbortController(), abort = () => stop.abort(), pipe = () => {};
  process.on('SIGINT', abort); process.on('SIGTERM', abort);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { process.exitCode = await run(process.argv.slice(2), { signal: stop.signal }); }
  finally {
    process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
    process.stdout.removeListener('error', pipe); process.stderr.removeListener('error', pipe);
  }
}
