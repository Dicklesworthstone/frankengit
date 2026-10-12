#!/usr/bin/env node
// Remote operator entry point; the existing Rust HTTP admission path owns policy.
import { pathToFileURL } from 'node:url';
import { ProtectionError, LIMITS, canonical, endpoint, inspectProtection, prepareIntent, scope, policy } from './operator/review_protection.mjs';
import { loadIntent, privateJson, readToken, saveIntent } from './operator/protection_files.mjs';

const HELP = `usage: node scripts/fg_protection_admin.mjs <inspect|prepare|show-intent> [options]
  inspect --endpoint <repository-URL> --token-file <private-file>
          [--scope-file <private-json>] [--expected-head <token>]
  prepare --endpoint <repository-URL> --token-file <private-file>
          --scope-file <private-json> --principal <32-hex-id>
          --policy-file <private-json> --intent <new-private-directory> [--clear]
  show-intent --intent <private-directory>

Network operations accept --timeout-ms <1..300000> (default 30000).
HTTPS is required except literal 127.0.0.1 or [::1]. Tokens never appear in argv
or saved intents. Preparation reads the complete native policy and writes only
an immutable local intent; it sends no mutation. Remote bootstrap is refused.
A complete replacement preserves ONLY its explicitly listed administrators and
branches. --clear is mandatory for removing all branch rules. Every successful
replacement advances the policy epoch and invalidates earlier approvals.
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
  };
  if (!Object.hasOwn(sets, command)) fail('unknown_command');
  const options = {};
  for (let index = 1; index < args.length; index++) {
    const flag = args[index];
    if (!flag.startsWith('--') || !sets[command].includes(flag.slice(2)) || Object.hasOwn(options, flag.slice(2))) fail('unknown_or_duplicate_option');
    const key = flag.slice(2);
    if (key === 'clear') options[key] = true;
    else {
      const value = args[++index];
      if (!value || value.startsWith('--')) fail('option_value_required');
      options[key] = value;
    }
  }
  const required = command === 'inspect' ? ['endpoint', 'token-file'] : command === 'prepare'
    ? ['endpoint', 'token-file', 'scope-file', 'principal', 'policy-file', 'intent'] : ['intent'];
  if (required.some(key => options[key] === undefined)) fail('required_option_missing');
  if (options.endpoint) endpoint(options.endpoint);
  if (options['timeout-ms'] !== undefined && (!/^[1-9][0-9]{0,5}$/.test(options['timeout-ms']) || Number(options['timeout-ms']) > 300000)) fail('invalid_timeout');
  return { command, ...options };
}
export function intentSummary(intent) {
  const before = intent.source.policy, after = intent.replacement;
  const changes = (old, next) => ({ added: next.filter(value => !old.includes(value)), removed: old.filter(value => !next.includes(value)) });
  const old = new Map(before.branches.map(row => [row.reference_hex, row.required_reviewers]));
  const next = new Map(after.branches.map(row => [row.reference_hex, row.required_reviewers]));
  return { type: 'prepared_review_protection', intent_sha256: intent.intent_sha256, endpoint: intent.endpoint,
    scope: intent.scope, principal_id: intent.principal_id, source_head: intent.source.source_head,
    expected_version: intent.source.version, expected_epoch: intent.source.policy_epoch,
    administrators: changes(before.administrators, after.administrators),
    branches: [...new Set([...old.keys(), ...next.keys()])].sort().map(reference_hex => ({ reference_hex,
      ...changes(old.get(reference_hex) ?? [], next.get(reference_hex) ?? []) })).filter(row => row.added.length || row.removed.length),
    clears_all_branch_protection: intent.clear, replacement_invalidates_earlier_approvals: true,
    transaction_created: false, published: false };
}
export async function run(args, { signal, output = text => new Promise((resolve, reject) => process.stdout.write(text, error => error ? reject(error) : resolve())) } = {}) {
  const options = parseArgs(args);
  if (signal?.aborted) fail('cancelled');
  if (options.command === 'help') { await output(`${HELP}\n`); return 0; }
  if (options.command === 'show-intent') { await output(canonical(intentSummary(await loadIntent(options.intent)))); return 0; }
  const token = await readToken(options['token-file']);
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
  const controller = new AbortController(), stop = () => controller.abort();
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  try { process.exitCode = await run(process.argv.slice(2), { signal: controller.signal }); }
  catch (error) {
    process.stderr.write(canonical({ type: 'protection_operator_error', code: error instanceof ProtectionError ? error.code : 'local_io_or_output_failure',
      outcome_unknown: error?.outcomeUnknown === true, status: error?.status ?? null }));
    process.exitCode = error?.outcomeUnknown ? 3 : 2;
  } finally { process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
