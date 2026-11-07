#!/usr/bin/env node
// Remote inbox reads and exact preference recovery; no local node is opened.
import { pathToFileURL } from 'node:url';
import { decimal } from '../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { inboxOperatorOptions, runInboxOperation } from './lib/forge-inbox-operator.mjs';
import { operatorError, operatorJson } from './lib/forge-operator-io.mjs';
import { runOperatorCli } from './lib/forge-operator-cli.mjs';

export const HELP = `Usage: node scripts/forge_inbox.mjs OPERATION
  --kind issue|discussion|pull_request --url EXACT_INBOX_PAGE_URL
  --tenant-id HEX --repository-id HEX --token-file PRIVATE_FILE

Issue URL: https://HOST/REPOSITORY_ROUTE/ui/notifications/
Discussion URL: https://HOST/REPOSITORY_ROUTE/ui/discussion-notifications/
Pull request URL: https://HOST/REPOSITORY_ROUTE/ui/pull-notifications/
list: [--limit 1..100 --max-pages 1..100] [--unread-only] [--include-muted]
  [--after N --expected-head TOKEN --expected-principal HEX --expected-incarnation HEX]
show: --number N [--expected-head TOKEN --expected-principal HEX --expected-incarnation HEX]
Reads accept --max-output-bytes 1..8388608; no --record.
Historical reads and continuations require BOTH observed identity guards.

subscribe|mute|automatic|unread:
  --number N --expected-version N --expected-principal HEX --expected-incarnation HEX
  --record PRIVATE_NEW_FILE
read: the same fields plus --read-through OBSERVED_THREAD_VERSION
expected-version is the exact PREFERENCE version; use 0 for no preference stream.
Identity guards constrain the authenticated recipient; they never choose one.
read acknowledges only the given prefix, even if newer activity arrives.
For pull_request use activity_version: lifecycle changes, comments and reviews.
Pull request HTTP operations require pulls-read and reviews-read; preference changes
also require notifications-write.

status|retry: connection options and ORIGINAL --record only.
status never writes. retry observes first, then may send the SAME request/key once.
Keep each private, token-free record after success, refusal or interruption.
No overwrite, automatic retry, fresh retry key or silent version refresh.

All operations accept --timeout-ms 1..300000 (whole invocation; default 30000).
HTTPS required except loopback HTTP. No redirects, cookies or token in argv.
Token files contain 64 lowercase hex characters, optionally one final newline.
Token and record files must be owner-private regular single-link files; the
record parent must already be owner-private. Unix filesystem profile only.
Numbers retain the shipped client's safe-integer limit; larger u64s refuse.
Exit 0: complete read or committed terminal observation; 3: terminal refusal;
4: bounded read prefix with continuation; 2: unresolved, interrupted or error.
`;

export function inboxArguments(args) {
  if (!Array.isArray(args) || args.length > 70 || args.some(value => typeof value !== 'string' || value.includes('\0') || value.length > 4096) ||
      args.reduce((sum, value) => sum + Buffer.byteLength(value), 0) > 32 * 1024) throw operatorError('inbox_operator_argument_limit');
  const map = new Map(), flags = new Set();
  const values = ['--kind', '--url', '--tenant-id', '--repository-id', '--token-file', '--record', '--number',
    '--expected-version', '--read-through', '--expected-principal', '--expected-incarnation', '--after', '--expected-head',
    '--limit', '--max-pages', '--max-output-bytes', '--timeout-ms'];
  for (let i = 1; i < args.length; i++) {
    const flag = args[i];
    if (flags.has(flag) || map.has(flag)) throw operatorError('inbox_operator_duplicate_option');
    if (['--unread-only', '--include-muted'].includes(flag)) { flags.add(flag); continue; }
    if (!values.includes(flag)) throw operatorError('inbox_operator_unknown_option');
    const value = args[++i];
    if (value === undefined) throw operatorError('inbox_operator_missing_value');
    map.set(flag, value);
  }
  const raw = { operation: args[0], kind: map.get('--kind'), href: map.get('--url'),
    tenant: map.get('--tenant-id'), repository: map.get('--repository-id'), tokenFile: map.get('--token-file') };
  for (const [flag, field] of [['--record', 'record'], ['--expected-head', 'head'],
    ['--expected-principal', 'expectedPrincipal'], ['--expected-incarnation', 'expectedIncarnation']]) {
    if (map.has(flag)) raw[field] = map.get(flag);
  }
  for (const [flag, field] of [['--number', 'number'], ['--expected-version', 'expectedVersion'], ['--read-through', 'readThrough'],
    ['--after', 'after'], ['--limit', 'limit'], ['--max-pages', 'maxPages'], ['--max-output-bytes', 'maxOutputBytes'], ['--timeout-ms', 'timeoutMs']]) {
    if (map.has(flag)) raw[field] = decimal(map.get(flag), field, ['expectedVersion', 'after'].includes(field) ? 0 : 1);
  }
  if (flags.has('--unread-only')) raw.unreadOnly = true;
  if (flags.has('--include-muted')) raw.includeMuted = true;
  inboxOperatorOptions(raw);
  return raw;
}

export async function runInboxCommand(args, signal) {
  if (args.length === 1 && args[0] === '--help') return { text: HELP, exitCode: 0 };
  const result = await runInboxOperation({ ...inboxArguments(args), signal });
  const exitCode = result.read_only ? result.complete ? 0 : 4
    : result.state !== 'terminal_observed' ? 2 : result.result.outcome === 'committed' ? 0 : 3;
  return { text: operatorJson(result), exitCode };
}

async function main() {
  await runOperatorCli(process.argv.slice(2), {
    timeout: args => args.length === 1 && args[0] === '--help' ? 30000 : inboxArguments(args).timeoutMs ?? 30000,
    run: runInboxCommand,
    failure: (error, completed) => operatorJson({ type: 'forge_inbox_operator_error', code: error.code ?? 'inbox_operator_failed',
      operation_completed: completed, state: error.operator_state ?? null, record: error.record ?? null,
      record_sha256: error.record_sha256 ?? null, http_status: error.status ?? null, absence_proves_non_commit: false }),
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
