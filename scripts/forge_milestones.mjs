#!/usr/bin/env node
// Remote standalone milestone lifecycle; native APIs own every decision.
import { pathToFileURL } from 'node:url';
import { decimal } from '../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { milestoneOperatorOptions, runMilestoneOperation } from './lib/forge-milestone-operator.mjs';
import { milestoneReadOptions, runMilestoneRead } from './lib/forge-milestone-reader.mjs';
import { operatorError, operatorJson, readPrivateOperatorFile, operatorPath } from './lib/forge-operator-io.mjs';
import { runOperatorCli } from './lib/forge-operator-cli.mjs';

export const HELP = `Usage: node scripts/forge_milestones.mjs OPERATION
  --url https://HOST/REPOSITORY_ROUTE/ui/milestones/
  --tenant-id HEX --repository-id HEX --token-file PRIVATE_FILE [--record PRIVATE_NEW_FILE]

open: --number N --expected-version 0 --title TEXT [--body TEXT | --body-file PRIVATE_FILE] [--due-at UNIX_SECONDS]
edit: --number N --expected-version N [--title TEXT] [--body TEXT | --body-file PRIVATE_FILE]
  [--due-at UNIX_SECONDS | --clear-due-at]
close|reopen: --number N --expected-version N
status|retry: use only the connection options and the ORIGINAL --record.
list|show: read only, no --record. show requires --number N and includes lifecycle history.
  [--after N --expected-head TOKEN] [--limit 1..100 --max-pages 1..100]
  [--max-output-bytes 1..8388608]
Reads default to one page. Continuations pin the original snapshot, including
open/closed member-issue counts. Due dates are UTC Unix seconds 0..253402300799;
omission preserves the date on edit, while --clear-due-at removes it.
All commands accept --timeout-ms 1..300000 (whole operation, default 30000).

HTTPS is required except on loopback. The legacy /ui/issues/ repository selector
is also accepted. Private token files contain either a 64-character lowercase
hexadecimal repository token or fgagent_ plus 64 lowercase hexadecimal digits,
with one optional final LF. Ordinary tokens need issues-read/write; sponsored
tokens need independent milestones-read/write. Recovery needs outcomes-read.
A write grant never implies read. No principal or local storage path is supplied.

Fresh mutations check the exact repository/version, synchronize a token-free
recovery record, then send once. Keep every record: status only observes; retry
observes first and may resend the SAME request/key once. Missing outcome never
proves non-commit. Records bind the original credential fingerprint.
Token, body and record files must be owner-private, regular and single-link.
The record parent must already exist and be owner-private. Unix profile only.
Use forge_issues.mjs set-milestone, clear-milestone and search --milestone for
issue membership. Closing a milestone does not change member issues.

Exit 0: committed terminal outcome or complete read; 3: native terminal refusal;
4: bounded read prefix with continuation; 2: unknown outcome or error.
`;

export function milestoneArguments(args) {
  if (!Array.isArray(args) || args.length > 48 || args.some(arg => typeof arg !== 'string' || arg.includes('\0') || arg.length > 65536) ||
      args.reduce((bytes, arg) => bytes + Buffer.byteLength(arg), 0) > 256 * 1024) throw operatorError('milestone_operator_argument_limit');
  const operation = args[0], map = new Map(); let clearDue = false;
  const allowed = ['--url', '--tenant-id', '--repository-id', '--token-file', '--record', '--number', '--expected-version',
    '--title', '--body', '--body-file', '--due-at', '--timeout-ms', '--after', '--expected-head', '--limit', '--max-pages', '--max-output-bytes'];
  for (let i = 1; i < args.length; i++) {
    const flag = args[i];
    if (flag === '--clear-due-at') {
      if (clearDue) throw operatorError('milestone_operator_duplicate_option');
      clearDue = true; continue;
    }
    if (!allowed.includes(flag) || map.has(flag)) throw operatorError('milestone_operator_unknown_or_duplicate_option');
    const value = args[++i];
    if (value === undefined) throw operatorError('milestone_operator_missing_value');
    map.set(flag, value);
  }
  if ((map.has('--body') && map.has('--body-file')) || (clearDue && map.has('--due-at'))) throw operatorError('milestone_operator_conflicting_fields');
  if (clearDue && operation !== 'edit') throw operatorError('milestone_operator_clear_due_at_inapplicable');
  const reading = ['list', 'show'].includes(operation);
  const connection = { operation, href: map.get('--url'), tenant: map.get('--tenant-id'), repository: map.get('--repository-id'),
    tokenFile: map.get('--token-file'), ...(map.has('--timeout-ms') ? { timeoutMs: decimal(map.get('--timeout-ms'), 'timeout', 1) } : {}) };
  if (reading) {
    if (['--record', '--expected-version', '--title', '--body', '--body-file', '--due-at'].some(flag => map.has(flag))) throw operatorError('milestone_read_mutation_option');
    const raw = { ...connection };
    for (const [flag, field] of [['--number', 'number'], ['--after', 'after'], ['--limit', 'limit'],
      ['--max-pages', 'maxPages'], ['--max-output-bytes', 'maxOutputBytes']]) {
      if (map.has(flag)) raw[field] = decimal(map.get(flag), field, field === 'after' ? 0 : 1);
    }
    if (map.has('--expected-head')) raw.head = map.get('--expected-head');
    return { options: milestoneReadOptions(raw), bodyFile: null, reading: true };
  }
  if (['--after', '--expected-head', '--limit', '--max-pages', '--max-output-bytes'].some(flag => map.has(flag))) throw operatorError('milestone_operator_read_option');
  const fields = {};
  if (map.has('--title')) fields.title = map.get('--title');
  if (map.has('--body')) fields.body = map.get('--body');
  if (map.has('--body-file')) fields.body = 'pending private file';
  if (operation === 'open' && !Object.hasOwn(fields, 'body')) fields.body = '';
  if (map.has('--due-at')) fields.due_at = decimal(map.get('--due-at'), 'milestone due date');
  if (clearDue) fields.due_at = null;
  const raw = { ...connection, record: map.get('--record'),
    ...(map.has('--number') ? { number: decimal(map.get('--number'), 'milestone number', 1) } : {}),
    ...(map.has('--expected-version') ? { expectedVersion: decimal(map.get('--expected-version'), 'expected version') } : {}),
    ...(Object.keys(fields).length ? { fields } : {}) };
  return { options: milestoneOperatorOptions(raw),
    bodyFile: map.has('--body-file') ? operatorPath(map.get('--body-file')) : null, reading: false };
}

export async function runMilestoneCommand(args, signal) {
  if (args.length === 1 && args[0] === '--help') return { text: HELP, exitCode: 0 };
  const { options, bodyFile, reading } = milestoneArguments(args);
  const deadline = AbortSignal.timeout(options.timeoutMs), combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
  if (bodyFile !== null) {
    const bytes = await readPrivateOperatorFile(bodyFile, 65536, () => combined.throwIfAborted(), 0);
    try { options.fields.body = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
    finally { bytes.fill(0); }
  }
  if (reading) {
    const result = await runMilestoneRead({ ...options, signal: combined });
    return { text: operatorJson(result), exitCode: result.complete ? 0 : 4 };
  }
  const result = await runMilestoneOperation({ ...options, signal: combined });
  return { text: operatorJson(result), exitCode: result.state !== 'terminal_observed' ? 2 : result.result.outcome === 'committed' ? 0 : 3 };
}

async function main() {
  await runOperatorCli(process.argv.slice(2), {
    timeout: args => args.length === 1 && args[0] === '--help' ? 30000 : milestoneArguments(args).options.timeoutMs,
    run: runMilestoneCommand,
    failure: (error, completed) => operatorJson({ type: 'forge_milestone_operator_error', code: error.code ?? 'milestone_operator_failed',
      operation_completed: completed, state: error.operator_state ?? null, record: error.record ?? null,
      record_sha256: error.record_sha256 ?? null, http_status: error.status ?? null }),
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
