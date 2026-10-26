#!/usr/bin/env node
// Remote issue operator CLI. Native APIs authenticate; local files never do.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { prepareIssue, submitIssue, recoverIssue, validateIssuePublication, parseIssueJson, issueCanonical,
  IssueError, issueTokenFingerprint } from './operator/remote_issue.mjs';
import { validateOutcomeReply } from './operator/transaction_outcome.mjs';
import { readIssuePrivate, readIssueToken, saveIssueIntent, loadIssueIntent,
  checkIssueRecordDestination, saveIssueRecord } from './operator/issue_files.mjs';

export const HELP = `Usage: node scripts/remote_issue.mjs <prepare|inspect|send|recover> [options]

prepare --input PRIVATE_JSON --token-file PRIVATE_TOKEN --request-dir NEW_PRIVATE_SLOT
inspect --request-dir EXISTING_SLOT
send --request-dir EXISTING_SLOT --token-file ORIGINAL_TOKEN --confirm-key EXACT_SAVED_KEY
recover --request-dir EXISTING_SLOT --token-file ORIGINAL_OR_ROTATED_TOKEN

send/recover additionally accept:
  --timeout-ms 1..300000      Whole network operation, default 30000
  --ca-file PRIVATE_PEM      Explicit trusted CA; verification cannot be disabled
  --known PRIVATE_RECORD    Retained result from THIS request, to refuse regression
  --record NEW_PRIVATE_JSON Write a complete, synced, create-only result record

Input JSON: endpoint, scope {tenant_id, repository_id, repository_incarnation,
principal_id}, number, expected_version, action, fields. Numbers/versions are
canonical decimal strings, not JSON numbers. Actions: open/edit/comment/
append-comment/close/reopen/assign/unassign. Only append-comment requires
expected_version: null, takes body only and sends no predecessor field.
Strict comment still requires an exact positive version. No mode fallback.
Native issue-write and outcome-read grants are independent.
The principal is an expected authenticated identity, never sent as a form field.

POSIX only; files and immediate parent directories must be private and owned.
Request slots/records must be outside Git worktrees. No slot, key, request body or
record is overwritten. prepare and inspect do not contact the server. send never
refreshes an expected version or retries automatically. Interrupted slots refuse.
Unknown outcomes retain the original request; recover does not send a mutation.
A rotated credential can recover only the original principal, never resubmit.

Exit 0: prepared/inspected, or confirmed native commit; 1: native terminal refusal;
2: local input/files failure before networking; 3: incomplete/unknown operation
or result-output failure. No error or missing outcome proves non-commit.
Private records/requests may contain issue text; tokens are read only from files.
See docs/REMOTE_ISSUES.md for the issue v1 incarnation-precondition limitation.
`;
const fail = code => { throw new IssueError(code, { phase: 'arguments' }); };
function parse(args) {
  if (!Array.isArray(args) || args.length > 24 || args.some(value => typeof value !== 'string' || !value || value.length > 8192) ||
      args.reduce((n, value) => n + value.length, 0) > 65536) fail('invalid_issue_arguments');
  if (args.length === 1 && args[0] === '--help') return { action: 'help' };
  const action = args[0], flags = {}, network = ['send', 'recover'].includes(action);
  const allowed = action === 'prepare' ? ['input', 'token-file', 'request-dir'] : action === 'inspect' ? ['request-dir']
    : network ? ['request-dir', 'token-file', 'timeout-ms', 'ca-file', 'known', 'record', ...(action === 'send' ? ['confirm-key'] : [])] : [];
  if (!allowed.length) fail('invalid_issue_cli_action');
  for (let i = 1; i < args.length; i += 2) {
    const key = args[i].startsWith('--') ? args[i].slice(2) : '', value = args[i + 1];
    if (!allowed.includes(key) || Object.hasOwn(flags, key) || value === undefined || value.startsWith('--')) fail('invalid_issue_cli_option');
    flags[key] = value;
  }
  const required = action === 'prepare' ? allowed : action === 'inspect' ? ['request-dir']
    : ['request-dir', 'token-file', ...(action === 'send' ? ['confirm-key'] : [])];
  if (required.some(key => !Object.hasOwn(flags, key))) fail('missing_issue_cli_option');
  const timeout = flags['timeout-ms'] ?? '30000';
  if (!/^[1-9][0-9]{0,5}$/.test(timeout) || Number(timeout) > 300000) fail('invalid_issue_cli_timeout');
  return { action, flags, network, timeoutMs: Number(timeout) };
}
function knownResult(value, intent) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 12 ||
      ['type', 'schema_version', 'endpoint', 'key', 'number', 'expected_version', 'action', 'dispatched_this_call',
        'outcome', 'publication', 'absence_proves_non_commit', 'delivery_acknowledged'].some(key => !Object.hasOwn(value, key)) ||
      value.type !== 'remote_issue_result' || value.schema_version !== 1 || value.absence_proves_non_commit !== false ||
      value.delivery_acknowledged !== null || typeof value.dispatched_this_call !== 'boolean' ||
      ['endpoint', 'key', 'number', 'expected_version', 'action'].some(key => value[key] !== intent[key])) fail('issue_known_record_mismatch');
  const outcome = validateOutcomeReply(value.outcome, intent.scope);
  if (value.dispatched_this_call !== (value.publication !== null)) fail('issue_known_publication_mismatch');
  if (value.publication !== null) {
    const p = validateIssuePublication(value.publication, intent, value.publication.outcome === 'committed' ? 200 : 409);
    if (!outcome.terminal || outcome.transaction.tx_id !== p.tx_id || outcome.state !== p.outcome ||
        outcome.decision.decision_sequence !== p.decision_sequence ||
        (outcome.decision.repository_commit_id ?? null) !== p.repository_commit_id ||
        (outcome.decision.refusal_record_id ?? null) !== p.refusal_record_id || (outcome.decision.code ?? null) !== p.refusal_code) fail('issue_known_publication_mismatch');
  }
  return outcome;
}
export async function runIssueCli(args, { signal } = {}) {
  let networkStarted = false, observedResult = null;
  const check = () => { if (signal?.aborted) throw new IssueError('issue_cancelled', { phase: 'local' }); };
  try {
    const options = parse(args); check();
    if (options.action === 'help') return { text: HELP, exitCode: 0 };
    const { action, flags } = options;
    if (action === 'prepare') {
      const input = parseIssueJson(await readIssuePrivate(flags.input)), token = await readIssueToken(flags['token-file']); check();
      const intent = await saveIssueIntent(flags['request-dir'], prepareIssue(input, token)); check();
      return { value: { type: 'remote_issue_prepared', schema_version: 1, request_directory: resolve(flags['request-dir']),
        key: intent.key, scope: intent.scope, number: intent.number, expected_version: intent.expected_version,
        action: intent.action, network_contacted: false, published: false, authentication_established: false }, exitCode: 0 };
    }
    const intent = await loadIssueIntent(flags['request-dir'], action === 'send'); check();
    if (action === 'inspect') return { value: { type: 'remote_issue_intent', schema_version: 1,
      intent, network_contacted: false, authentication_established: false }, exitCode: 0 };
    const token = await readIssueToken(flags['token-file']);
    const ca = flags['ca-file'] ? await readIssuePrivate(flags['ca-file'], 128 * 1024) : undefined;
    const known = flags.known ? knownResult(parseIssueJson(await readIssuePrivate(flags.known)), intent) : undefined;
    if (flags.record) await checkIssueRecordDestination(flags.record);
    if (action === 'send' && flags['confirm-key'] !== intent.key) fail('confirm_original_issue_key');
    if (action === 'send' && issueTokenFingerprint(token) !== intent.credential_fingerprint) fail('original_issue_credential_required');
    if (ca && !ca.length) fail('invalid_issue_ca');
    check(); networkStarted = true;
    const transport = { signal, ca, known, timeoutMs: options.timeoutMs };
    const value = action === 'send' ? await submitIssue(intent, token, { ...transport, confirmKey: flags['confirm-key'] })
      : await recoverIssue(intent, token, transport);
    observedResult = value;
    if (flags.record) await saveIssueRecord(flags.record, value);
    return { value, exitCode: value.outcome.terminal ? value.outcome.state === 'committed' ? 0 : 1 : 3 };
  } catch (error) {
    const typed = error instanceof IssueError;
    return { value: { type: 'remote_issue_error', schema_version: 1,
      code: typed ? error.code : 'issue_local_or_output_failure', phase: typed ? error.phase : networkStarted ? 'result_output' : 'files',
      http_status: typed ? error.status : null, dispatched_this_call: observedResult?.dispatched_this_call ?? (typed ? error.dispatched : null),
      publication: observedResult?.publication ?? (typed ? error.publication : null),
      native_result: observedResult, outcome_unknown: observedResult ? !observedResult.outcome.terminal : true, absence_proves_non_commit: false,
      original_request_deleted: false, result_output_may_be_incomplete: networkStarted }, exitCode: networkStarted || signal?.aborted ? 3 : 2 };
  }
}
async function entry() {
  const controller = new AbortController(), abort = () => controller.abort();
  process.on('SIGINT', abort); process.on('SIGTERM', abort);
  // Keep stream errors inside the result-output path, not an unhandled event.
  const observe = () => {}; process.stdout.on('error', observe);
  let result;
  try {
    result = await runIssueCli(process.argv.slice(2), { signal: controller.signal });
    const output = result.text ?? issueCanonical(result.value);
    await new Promise((resolve, reject) => process.stdout.write(output, error => error ? reject(error) : resolve()));
    process.exitCode = result.exitCode;
  } catch {
    process.exitCode = 3;
    const native = result?.value?.type === 'remote_issue_result' ? result.value : result?.value?.native_result ?? null;
    process.stderr.write(issueCanonical({ type: 'remote_issue_output_failure', outcome_unknown: native ? !native.outcome.terminal : true,
      native_result: native, absence_proves_non_commit: false }));
  } finally { process.off('SIGINT', abort); process.off('SIGTERM', abort); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await entry();
