#!/usr/bin/env node
// Explicit remote PR operator actions; no canonical filesystem access or Git.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { preparePull, submitPull, recoverPull } from './operator/remote_pull.mjs';
import { PULL_LIMITS, PullError, failPull, pullCanonical, parsePullJson, pullTokenFingerprint, isPullReview } from './operator/pull_command.mjs';
import { readPullPrivate, readPullToken, savePullIntent, loadPullIntent, readPullRecord,
  pullRecord, checkPullRecordDestination, savePullRecord, loadPullBundle } from './operator/pull_files.mjs';

export const HELP = `Usage: node scripts/remote_pull.mjs <prepare|inspect|send|recover> [options]

prepare --input PRIVATE_JSON --token-file PRIVATE_TOKEN --request-dir NEW_SLOT
        [--bundle PRIVATE_CANDIDATE_BUNDLE]
inspect --request-dir EXISTING_SLOT [--known PRIVATE_RECORD]
send --request-dir EXISTING_SLOT --token-file ORIGINAL_TOKEN --confirm-key SAVED_KEY
     --record NEW_PRIVATE_JSON [--fast-forward-only]
     [--confirm-candidate EXACT_NATIVE_OID] [--confirm-merge-method merge-commit|squash]
recover --request-dir EXISTING_SLOT --token-file ORIGINAL_OR_ROTATED_TOKEN
        --record NEW_PRIVATE_JSON

send/recover: [--known PRIVATE_RECORD] [--timeout-ms 1..300000] [--ca-file PRIVATE_PEM]

Input: endpoint, scope {tenant_id, repository_id, repository_incarnation,
principal_id, object_format}, number, action, fields. Native numbers/versions
are decimal strings. open/update/close/reopen require full PR metadata and
expected_version; comment requires body and separate discussion expected_version;
fast-forward requires pull_request_version and exact source/target refs and tips.
approve/request-changes/withdraw require exact PR version, policy epoch, refs,
tips, merge base and candidate commit, plus reviewer-stream expected_version/reason.
merge requires that exact candidate and explicit required_reviewers and method.
Read current coordinates through the native PR API/browser; they are never guessed.

prepare and inspect are offline. send requires the original token/key and
--fast-forward-only for a fast-forward intent. Candidate actions also require
--confirm-candidate; merge additionally requires --confirm-merge-method matching
the saved method. approve/request-changes/merge take --bundle during prepare,
not send; withdraw never takes one. Review the actual native candidate beforehand:
inspect prints saved intent coordinates, not a Git diff or proof of review.
No strategy fallback, force, version/tip refresh or automatic retry is available.
recover only reads the original outcome, even without the bundle or after rotation.

POSIX private owned files/directories outside Git worktrees are mandatory.
The complete intent is synced before networking and never overwritten. --record
is mandatory for network commands; it names a new, create-only result file.
After interrupted preparation retain the slot; it is not repaired automatically.
After an uncertain send retain the original request and use recover, not a new key.

Exit 0: prepared/inspected or confirmed native commit; 1: native refusal;
2: validation/local-file failure before network admission; 3: unknown/incomplete
network operation or result-output failure. No missing result proves non-commit.
No token is printed or accepted directly as an argument. See docs/REMOTE_PULL_REQUESTS.md.
`;
function parse(args) {
  if (args.length < 1 || args.length > 25 || args.some(s => typeof s !== 'string' || s.length > 4096) ||
      args.reduce((n, s) => n + s.length, 0) > 32768) failPull('invalid_pull_arguments');
  const action = args[0];
  const required = action === 'prepare' ? ['input', 'token-file', 'request-dir'] : action === 'inspect' ? ['request-dir']
    : action === 'send' ? ['request-dir', 'token-file', 'confirm-key', 'record'] : action === 'recover' ? ['request-dir', 'token-file', 'record'] : null;
  if (!required) failPull('unknown_pull_command');
  const allowed = [...required, ...(action === 'prepare' ? ['bundle'] : action === 'inspect' ? ['known'] : ['send', 'recover'].includes(action)
    ? ['known', 'timeout-ms', 'ca-file', ...(action === 'send' ? ['fast-forward-only', 'confirm-candidate', 'confirm-merge-method'] : [])] : [])];
  const flags = {};
  for (let i = 1; i < args.length; i++) {
    const name = args[i].startsWith('--') ? args[i].slice(2) : '';
    if (!allowed.includes(name) || Object.hasOwn(flags, name)) failPull('invalid_or_duplicate_pull_option');
    if (name === 'fast-forward-only') flags[name] = true;
    else { const value = args[++i]; if (!value || value.startsWith('--')) failPull('missing_pull_option_value'); flags[name] = value; }
  }
  if (required.some(name => !Object.hasOwn(flags, name))) failPull('required_pull_option');
  if (flags['timeout-ms'] !== undefined && (!/^[1-9][0-9]{0,5}$/.test(flags['timeout-ms']) || Number(flags['timeout-ms']) > 300000)) failPull('invalid_pull_timeout');
  return { action, flags };
}
function diagnostic(error) {
  return { type: 'remote_pull_error', schema_version: 1, code: error instanceof PullError ? error.code : 'pull_local_or_output_failure',
    outcome_unknown: true, phase: error instanceof PullError ? error.phase : 'local',
    dispatched: error instanceof PullError ? error.dispatched : null,
    publication: error instanceof PullError ? error.publication : null };
}
export async function run(args, { output = text => write(process.stdout, text), errorOutput = text => write(process.stderr, text), signal } = {}) {
  let network = false, recordPath = null, savedRecord = null;
  try {
    if (args.length === 0 || (args.length === 1 && args[0] === '--help')) { await output(HELP); return 0; }
    const { action, flags } = parse(args);
    if (signal?.aborted) failPull('pull_cancelled');
    if (action === 'prepare') {
      const token = await readPullToken(flags['token-file']);
      const value = parsePullJson(await readPullPrivate(flags.input, PULL_LIMITS.intent));
      const bundle = flags.bundle === undefined ? null : await readPullPrivate(flags.bundle, PULL_LIMITS.bundle);
      const intent = await savePullIntent(flags['request-dir'], preparePull(value, token, bundle), bundle);
      await output(pullCanonical({ type: 'remote_pull_prepared', schema_version: 1, request_dir: resolve(flags['request-dir']),
        key: intent.key, number: intent.number, action: intent.action, publication_attempted: false })); return 0;
    }
    const intent = await loadPullIntent(flags['request-dir'], { sync: action !== 'inspect' });
    const known = flags.known === undefined ? null : await readPullRecord(flags.known, intent);
    if (action === 'inspect') {
      await output(pullCanonical({ type: 'remote_pull_intent', schema_version: 1, intent, known })); return 0;
    }
    const token = await readPullToken(flags['token-file']);
    const ca = flags['ca-file'] === undefined ? undefined : await readPullPrivate(flags['ca-file'], 128 * 1024);
    recordPath = await checkPullRecordDestination(flags.record);
    const options = { timeoutMs: flags['timeout-ms'] === undefined ? 30000 : Number(flags['timeout-ms']), signal, ca,
      known: known?.outcome ?? null, publication: known?.publication ?? null };
    if (action === 'send') {
      if (flags['confirm-key'] !== intent.key || (intent.action === 'fast-forward') !== (flags['fast-forward-only'] === true)) failPull('confirm_exact_pull_request');
      // Identity equality is checked again by submitPull before its first await.
      if (pullTokenFingerprint(token) !== intent.credential_fingerprint) failPull('original_pull_credential_required');
      options.confirmKey = intent.key;
      if (flags['fast-forward-only']) options.confirmFastForward = true;
      if (isPullReview(intent.action) ? flags['confirm-candidate'] !== intent.fields.candidate_commit : flags['confirm-candidate'] !== undefined) failPull('confirm_exact_pull_candidate');
      if (intent.action === 'merge' ? flags['confirm-merge-method'] !== intent.fields.method : flags['confirm-merge-method'] !== undefined) failPull('confirm_exact_pull_merge_method');
      if (flags['confirm-candidate'] !== undefined) options.confirmCandidate = flags['confirm-candidate'];
      if (flags['confirm-merge-method'] !== undefined) options.confirmMergeMethod = flags['confirm-merge-method'];
      if (intent.bundle && !known?.outcome?.terminal && !known?.publication) {
        options.bundle = await loadPullBundle(flags['request-dir'], intent, { sync: true });
      }
    }
    if (signal?.aborted) failPull('pull_cancelled');
    network = true;
    let result, failure = null;
    try { result = await (action === 'send' ? submitPull : recoverPull)(intent, token, options); }
    catch (error) { failure = error; }
    const record = pullRecord(intent, result, failure);
    try { savedRecord = await savePullRecord(recordPath, record, intent); }
    catch (error) {
      await errorOutput(pullCanonical({ type: 'remote_pull_record_failure', schema_version: 1, outcome_unknown: !record.outcome?.terminal,
        record_path: recordPath, staging_path: error.stagingPath ?? null, record })); return 3;
    }
    await output(pullCanonical({ type: 'remote_pull_result', schema_version: 1, record_path: savedRecord, ...record }));
    if (failure || !result.outcome.terminal) return 3;
    return result.outcome.state === 'committed' ? 0 : 1;
  } catch (error) {
    try { await errorOutput(pullCanonical({ ...diagnostic(error), record_path: savedRecord ?? recordPath })); } catch { /* The original synced request remains. */ }
    return network || savedRecord ? 3 : 2;
  }
}
function write(stream, text) {
  return new Promise((resolve, reject) => { stream.write(text, error => error ? reject(error) : resolve()); });
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  // Event listeners keep a broken pipe observable by the awaited write callback.
  const pipe = () => {}; process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { process.exitCode = await run(process.argv.slice(2), { output: text => write(process.stdout, text),
    errorOutput: text => write(process.stderr, text), signal: controller.signal }); }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
