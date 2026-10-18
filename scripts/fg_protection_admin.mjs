#!/usr/bin/env node
// Remote operator entry point; the existing Rust HTTP admission path owns policy.
import { pathToFileURL } from 'node:url';
import { ProtectionError, LIMITS, canonical, endpoint, inspectProtection, prepareIntent, scope, policy } from './operator/review_protection.mjs';
import { loadIntent, privateJson, readToken, saveIntent } from './operator/protection_files.mjs';
import { sendSavedIntent, recoverSavedIntent } from './operator/protection_journal.mjs';

const HELP = `usage: node scripts/fg_protection_admin.mjs <inspect|prepare|show-intent|send|outcome> [options]
  inspect --endpoint <repository-URL> --token-file <private-file>
          [--scope-file <private-json>] [--expected-head <token>]
  prepare --endpoint <repository-URL> --token-file <private-file>
          --scope-file <private-json> --principal <32-hex-id>
          --policy-file <private-json> --intent <new-private-directory> [--clear]
  show-intent --intent <private-directory>
  send --endpoint <independently-confirmed-repository-URL> --token-file <original-private-token>
       --intent <private-directory> --confirm-intent <displayed-sha256> [--retry]
  outcome --endpoint <independently-confirmed-repository-URL> --token-file <private-token>
          --intent <private-directory>

Network operations accept --timeout-ms <1..300000> (default 30000).
HTTPS is required except literal 127.0.0.1 or [::1]. Tokens never appear in argv
or saved intents. Preparation reads the complete native policy and writes only
an immutable local intent; it sends no mutation. Remote bootstrap is refused.
A complete replacement preserves ONLY its explicitly listed administrators and
branches, including required_checks selectors in the policy file. --clear is mandatory
for removing all branch rules. Every successful
replacement advances the policy epoch and invalidates earlier approvals.
Sending requires the original token and digest confirmation. A prior send marker
also requires --retry; only identical bytes and the original key are retried.
Outcome lookup permits a rotated token for the same original principal with the
independent outcomes-read grant. It never reexecutes or invents a transaction.
Exit 0: read/prepared/committed; 2: refusal; 3: unknown; 4: observed terminal with
local persistence, cleanup or output failure. No exit code proves non-commit.
Read docs/REMOTE_REVIEW_PROTECTION.md before publishing policy changes.`;
function fail(code) { throw new ProtectionError(code); }
export function parseArgs(args) {
  if (!Array.isArray(args) || args.length > 24 || args.some(arg => typeof arg !== 'string' || arg.length > 4096) ||
      args.reduce((n, arg) => n + arg.length, 0) > 32768) fail('argument_limit');
  if (args.length === 1 && args[0] === '--help') return { command: 'help' };
  const command = args[0], sets = {
    inspect: ['endpoint', 'token-file', 'scope-file', 'expected-head', 'timeout-ms'],
    prepare: ['endpoint', 'token-file', 'scope-file', 'principal', 'policy-file', 'intent', 'clear', 'timeout-ms'],
    'show-intent': ['intent'],
    send: ['endpoint', 'token-file', 'intent', 'confirm-intent', 'retry', 'timeout-ms'],
    outcome: ['endpoint', 'token-file', 'intent', 'timeout-ms'],
  };
  if (!Object.hasOwn(sets, command)) fail('unknown_command');
  const options = {};
  for (let index = 1; index < args.length; index++) {
    const flag = args[index];
    if (!flag.startsWith('--') || !sets[command].includes(flag.slice(2)) || Object.hasOwn(options, flag.slice(2))) fail('unknown_or_duplicate_option');
    const key = flag.slice(2);
    if (key === 'clear' || key === 'retry') options[key] = true;
    else {
      const value = args[++index];
      if (!value || value.startsWith('--')) fail('option_value_required');
      options[key] = value;
    }
  }
  const required = command === 'inspect' ? ['endpoint', 'token-file'] : command === 'prepare'
    ? ['endpoint', 'token-file', 'scope-file', 'principal', 'policy-file', 'intent']
    : command === 'send' ? ['endpoint', 'token-file', 'intent', 'confirm-intent']
    : command === 'outcome' ? ['endpoint', 'token-file', 'intent'] : ['intent'];
  if (required.some(key => options[key] === undefined)) fail('required_option_missing');
  if (options.endpoint) endpoint(options.endpoint);
  if (options['timeout-ms'] !== undefined && (!/^[1-9][0-9]{0,5}$/.test(options['timeout-ms']) || Number(options['timeout-ms']) > 300000)) fail('invalid_timeout');
  return { command, ...options };
}
export function intentSummary(intent) {
  const before = intent.source.policy, after = intent.replacement;
  const changes = (old, next) => ({ added: next.filter(value => !old.includes(value)), removed: old.filter(value => !next.includes(value)) });
  const old = new Map(before.branches.map(row => [row.reference_hex, row]));
  const next = new Map(after.branches.map(row => [row.reference_hex, row]));
  const checkChanges = (before = [], after = []) => {
    const diff = changes(before.map(value => JSON.stringify(value)), after.map(value => JSON.stringify(value)));
    return { checks_added: diff.added.map(value => JSON.parse(value)), checks_removed: diff.removed.map(value => JSON.parse(value)) };
  };
  return { type: 'prepared_review_protection', intent_sha256: intent.intent_sha256, endpoint: intent.endpoint,
    scope: intent.scope, principal_id: intent.principal_id, source_head: intent.source.source_head,
    expected_version: intent.source.version, expected_epoch: intent.source.policy_epoch,
    administrators: changes(before.administrators, after.administrators),
    branches: [...new Set([...old.keys(), ...next.keys()])].sort().map(reference_hex => {
      const before = old.get(reference_hex), after = next.get(reference_hex);
      const checks = checkChanges(before?.required_checks, after?.required_checks);
      return { reference_hex, ...changes(before?.required_reviewers ?? [], after?.required_reviewers ?? []),
        ...(checks.checks_added.length || checks.checks_removed.length ? checks : {}) };
    }).filter(row => row.added.length || row.removed.length || row.checks_added?.length || row.checks_removed?.length),
    clears_all_branch_protection: intent.clear, replacement_invalidates_earlier_approvals: true,
    mutation_sent_by_this_command: false, original_outcome: 'not_queried' };
}
export async function run(args, { signal, output = text => new Promise((resolve, reject) => process.stdout.write(text, error => error ? reject(error) : resolve())) } = {}) {
  const options = parseArgs(args);
  if (signal?.aborted) fail('cancelled');
  if (options.command === 'help') { await output(`${HELP}\n`); return 0; }
  if (options.command === 'show-intent') { await output(canonical(intentSummary(await loadIntent(options.intent)))); return 0; }
  const token = await readToken(options['token-file']);
  if (options.command === 'send' || options.command === 'outcome') {
    const context = { expectedEndpoint: options.endpoint, timeoutMs: Number(options['timeout-ms'] ?? '30000'), signal };
    const result = options.command === 'send'
      ? await sendSavedIntent(options.intent, token, { ...context, confirmation: options['confirm-intent'], retry: options.retry ?? false })
      : await recoverSavedIntent(options.intent, token, context);
    try { await output(canonical({ type: 'review_protection_result', ...result, absence_proves_non_commit: false })); }
    catch {
      const error = new ProtectionError('output_failure_after_observation', { outcomeUnknown: !result.summary.terminal });
      error.observation = result; throw error;
    }
    return result.summary.terminal ? result.summary.state === 'committed' ? 0 : 2 : 3;
  }
  const expectedScope = options['scope-file'] ? scope(await privateJson(options['scope-file'], 4096)) : null;
  // Bound and validate intended replacement before spending a network request.
  const replacement = options.command === 'prepare' ? policy(await privateJson(options['policy-file'], LIMITS.response)) : null;
  const snapshot = await inspectProtection(options.endpoint, token, { expectedScope,
    expectedHead: options['expected-head'] ?? null, timeoutMs: Number(options['timeout-ms'] ?? '30000'), signal });
  if (options.command === 'inspect') { await output(canonical(snapshot)); return 0; }
  const intent = prepareIntent({ endpoint: options.endpoint, token, principal_id: options.principal,
    expectedScope, snapshot, replacement, clear: options.clear ?? false });
  if (signal?.aborted) fail('cancelled');
  await saveIntent(options.intent, intent);
  await output(canonical(intentSummary(intent)));
  return 0;
}
async function main() {
  // The write callback reports output failure; do not let the stream's error
  // event terminate before the retained terminal is reported on stderr.
  process.stdout.on('error', () => {});
  const controller = new AbortController(), stop = () => controller.abort();
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  try { process.exitCode = await run(process.argv.slice(2), { signal: controller.signal }); }
  catch (error) {
    process.stderr.write(canonical({ type: 'protection_operator_error', code: error instanceof ProtectionError ? error.code : 'local_io_or_output_failure',
      outcome_unknown: error?.observation?.summary.terminal ? false : error?.outcomeUnknown === true ? true : null, absence_proves_non_commit: false, status: error?.status ?? null,
      observation: error?.observation ?? null }));
    process.exitCode = error?.observation?.summary.terminal ? 4 : error?.outcomeUnknown ? 3 : 2;
  } finally { process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
