#!/usr/bin/env node
// Remote standalone discussion lifecycle; native APIs own every decision.
import { pathToFileURL } from 'node:url';
import { decimal } from '../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { discussionOperatorOptions, runDiscussionOperation } from './lib/forge-discussion-operator.mjs';
import { discussionReadOptions, runDiscussionRead } from './lib/forge-discussion-reader.mjs';
import { operatorError, operatorJson, readPrivateOperatorFile, operatorPath } from './lib/forge-operator-io.mjs';
import { runOperatorCli } from './lib/forge-operator-cli.mjs';

export const HELP = `Usage: node scripts/forge_discussions.mjs OPERATION
  --url https://HOST/REPOSITORY_ROUTE/ui/discussions/
  --tenant-id HEX --repository-id HEX --token-file PRIVATE_FILE [--record PRIVATE_NEW_FILE]

open: --number N --expected-version 0 --title TEXT [--body TEXT | --body-file PRIVATE_FILE]
edit: --number N --expected-version N [--title TEXT] [--body TEXT | --body-file PRIVATE_FILE]
comment: --number N --expected-version N (--body TEXT | --body-file PRIVATE_FILE)
append-comment: --number N (--body TEXT | --body-file PRIVATE_FILE) (no --expected-version)
close|reopen|lock|unlock: --number N --expected-version N
status|retry: use only the connection options and the ORIGINAL --record.
list|show: read only, no --record. show returns state and history for --number N.
  [--after N --expected-head TOKEN] [--limit 1..100 --max-pages 1..100]
  [--max-output-bytes 1..8388608]
Reads default to one page; every continuation retains its original snapshot.
All commands accept --timeout-ms 1..300000 (whole operation, default 30000).

Discussion read/write scopes are independent of issue and PR grants. Mutations
first check the repository and strict version (or existence for append-comment),
sync a token-free recovery record, then send once. Concurrent append comments
keep their own original key; strict comments never silently become appends.
Locks forbid new comments, including appends, but do not prevent edits or closing.

HTTPS is required except on loopback. The token file contains the original
64-character lowercase hexadecimal bearer token, optionally followed by one LF.
Token, body and record files must be owner-private, regular and single-link.
The record parent must already exist and be owner-private. Unix profile only.
The authenticated server chooses the actor; no principal or local node is supplied.
Keep every record: status only observes; retry observes first and may resend the
SAME request/key once. Missing outcome never proves non-commit. No automatic retry,
predecessor refresh, record overwrite or credential substitution is performed.
Use archive_native_discussions.mjs for a complete bounded read archive.

Exit 0: committed terminal outcome or complete read; 3: native terminal refusal;
4: bounded read prefix with continuation; 2: unknown outcome or error.
`;

export function discussionArguments(args) {
  if (!Array.isArray(args) || args.length > 48 || args.some(arg => typeof arg !== 'string' || arg.includes('\0') || arg.length > 65536) ||
      args.reduce((bytes, arg) => bytes + Buffer.byteLength(arg), 0) > 256 * 1024) throw operatorError('discussion_operator_argument_limit');
  const operation = args[0], map = new Map();
  const allowed = ['--url', '--tenant-id', '--repository-id', '--token-file', '--record', '--number', '--expected-version',
    '--title', '--body', '--body-file', '--timeout-ms', '--after', '--expected-head', '--limit', '--max-pages', '--max-output-bytes'];
  for (let i = 1; i < args.length; i++) {
    const flag = args[i];
    if (!allowed.includes(flag) || map.has(flag)) throw operatorError('discussion_operator_unknown_or_duplicate_option');
    const value = args[++i];
    if (value === undefined) throw operatorError('discussion_operator_missing_value');
    map.set(flag, value);
  }
  if (map.has('--body') && map.has('--body-file')) throw operatorError('discussion_operator_conflicting_fields');
  const reading = ['list', 'show'].includes(operation);
  const connection = { operation, href: map.get('--url'), tenant: map.get('--tenant-id'), repository: map.get('--repository-id'),
    tokenFile: map.get('--token-file'), ...(map.has('--timeout-ms') ? { timeoutMs: decimal(map.get('--timeout-ms'), 'timeout', 1) } : {}) };
  if (reading) {
    if (['--record', '--expected-version', '--title', '--body', '--body-file'].some(flag => map.has(flag))) throw operatorError('discussion_read_mutation_option');
    const raw = { ...connection };
    for (const [flag, field] of [['--number', 'number'], ['--after', 'after'], ['--limit', 'limit'],
      ['--max-pages', 'maxPages'], ['--max-output-bytes', 'maxOutputBytes']]) {
      if (map.has(flag)) raw[field] = decimal(map.get(flag), field, field === 'after' ? 0 : 1);
    }
    if (map.has('--expected-head')) raw.head = map.get('--expected-head');
    return { options: discussionReadOptions(raw), bodyFile: null, reading: true };
  }
  if (['--after', '--expected-head', '--limit', '--max-pages', '--max-output-bytes'].some(flag => map.has(flag))) throw operatorError('discussion_operator_read_option');
  const fields = {};
  if (map.has('--title')) fields.title = map.get('--title');
  if (map.has('--body')) fields.body = map.get('--body');
  if (map.has('--body-file')) fields.body = 'pending private file';
  if (operation === 'open' && !Object.hasOwn(fields, 'body')) fields.body = '';
  const raw = { ...connection, record: map.get('--record'),
    ...(map.has('--number') ? { number: decimal(map.get('--number'), 'discussion number', 1) } : {}),
    ...(map.has('--expected-version') ? { expectedVersion: decimal(map.get('--expected-version'), 'expected version') } : {}),
    ...(Object.keys(fields).length ? { fields } : {}) };
  return { options: discussionOperatorOptions(raw),
    bodyFile: map.has('--body-file') ? operatorPath(map.get('--body-file')) : null, reading: false };
}

export async function runDiscussionCommand(args, signal) {
  if (args.length === 1 && args[0] === '--help') return { text: HELP, exitCode: 0 };
  const { options, bodyFile, reading } = discussionArguments(args);
  const deadline = AbortSignal.timeout(options.timeoutMs), combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
  if (bodyFile !== null) {
    const bytes = await readPrivateOperatorFile(bodyFile, 65536, () => combined.throwIfAborted(), 0);
    try { options.fields.body = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
    finally { bytes.fill(0); }
  }
  if (reading) {
    const result = await runDiscussionRead({ ...options, signal: combined });
    return { text: operatorJson(result), exitCode: result.complete ? 0 : 4 };
  }
  const result = await runDiscussionOperation({ ...options, signal: combined });
  return { text: operatorJson(result), exitCode: result.state !== 'terminal_observed' ? 2 : result.result.outcome === 'committed' ? 0 : 3 };
}

async function main() {
  await runOperatorCli(process.argv.slice(2), {
    timeout: args => args.length === 1 && args[0] === '--help' ? 30000 : discussionArguments(args).options.timeoutMs,
    run: runDiscussionCommand,
    failure: (error, completed) => operatorJson({ type: 'forge_discussion_operator_error', code: error.code ?? 'discussion_operator_failed',
      operation_completed: completed, state: error.operator_state ?? null, record: error.record ?? null,
      record_sha256: error.record_sha256 ?? null, http_status: error.status ?? null }),
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
