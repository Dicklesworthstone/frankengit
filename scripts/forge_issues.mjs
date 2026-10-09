#!/usr/bin/env node
// Authenticated issue mutations and explicit recovery; no local node is opened.
import { pathToFileURL } from 'node:url';
import { decimal } from '../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { issueReadOptions, runIssueRead } from './lib/forge-issue-reader.mjs';
import { issueOperatorOptions, runIssueOperation } from './lib/forge-issue-operator.mjs';
import { operatorError, operatorJson, readPrivateOperatorFile, operatorPath } from './lib/forge-operator-io.mjs';

export const HELP = `Usage: node scripts/forge_issues.mjs OPERATION
  --url https://HOST/REPOSITORY_ROUTE/ui/issues/
  --tenant-id HEX --repository-id HEX --token-file PRIVATE_FILE [--record PRIVATE_NEW_FILE]

open: --number N --expected-version 0 --title TEXT [--body TEXT | --body-file PRIVATE_FILE] [--label TEXT ...]
edit: --number N --expected-version N [--title TEXT] [--body TEXT | --body-file PRIVATE_FILE] [--label TEXT ... | --clear-labels]
comment: --number N --expected-version N (--body TEXT | --body-file PRIVATE_FILE)
close|reopen: --number N --expected-version N
status|retry: use only the connection options and the ORIGINAL --record.
list|show|search: read only, no --record. show requires --number N.
  [--after N --expected-head TOKEN] [--limit 1..100 --max-pages 1..100]
  [--max-output-bytes 1..8388608]
search filters: [--state open|closed|all] [--opened-by HEX] [--query TEXT]
  [--case-sensitive] [--label TEXT ...] [--max-scan 1..1000]
Reads default to one page; continuations pin the original snapshot and predicate.
All commands accept --timeout-ms 1..300000 (whole operation, default 30000).

HTTPS is required except for explicit loopback HTTP. The token file contains a
64-character lowercase hex bearer token, optionally followed by one newline.
Token, body and record files must be owner-private, regular and single-link.
The record parent must already exist and be owner-private. Unix profile only.
The native server authenticates the principal; no --principal or local storage
path is accepted. A fresh mutation first checks the exact repository/version,
synchronizes its token-free recovery record, then sends once. Keep the record:
status only observes; retry observes first and may resend the SAME request/key
once. Missing outcome is NOT non-commit. No automatic retry or record overwrite.
Exit 0: committed terminal outcome or complete read; 3: terminal refusal;
4: bounded read prefix with continuation; 2: unknown or error.
`;
export function issueArguments(args) {
  if (!Array.isArray(args) || args.length > 140 || args.some(a => typeof a !== 'string' || a.includes('\0') || a.length > 65536) ||
      args.reduce((n, a) => n + Buffer.byteLength(a), 0) > 256 * 1024) throw operatorError('issue_operator_argument_limit');
  const operation = args[0], map = new Map(), labels = []; let clear = false, caseSensitive = false;
  const allowed = ['--url', '--tenant-id', '--repository-id', '--token-file', '--record', '--number', '--expected-version',
    '--title', '--body', '--body-file', '--timeout-ms', '--after', '--expected-head', '--limit', '--max-pages',
    '--max-output-bytes', '--state', '--opened-by', '--query', '--max-scan'];
  for (let i = 1; i < args.length; i++) {
    const flag = args[i];
    if (flag === '--case-sensitive') { if (caseSensitive) throw operatorError('issue_operator_duplicate_option'); caseSensitive = true; continue; }
    if (flag === '--clear-labels') { if (clear) throw operatorError('issue_operator_duplicate_option'); clear = true; continue; }
    if (flag !== '--label' && (!allowed.includes(flag) || map.has(flag))) throw operatorError('issue_operator_unknown_or_duplicate_option');
    const value = args[++i]; if (value === undefined) throw operatorError('issue_operator_missing_value');
    if (flag === '--label') labels.push(value); else map.set(flag, value);
  }
  if ((clear && labels.length) || (map.has('--body') && map.has('--body-file'))) throw operatorError('issue_operator_conflicting_fields');
  const reading = ['list', 'show', 'search'].includes(operation);
  if (reading) {
    if (clear || ['--record', '--expected-version', '--title', '--body', '--body-file'].some(k => map.has(k))) throw operatorError('issue_read_mutation_option');
    if (operation !== 'search' && (labels.length || caseSensitive || ['--state', '--opened-by', '--query', '--max-scan'].some(k => map.has(k)))) throw operatorError('issue_read_search_inapplicable');
    const query = {};
    if (map.has('--state') && map.get('--state') !== 'all') query.state = map.get('--state');
    if (map.has('--opened-by')) query.opened_by = map.get('--opened-by');
    if (map.has('--query')) query.text = map.get('--query');
    if (caseSensitive) query.case_sensitive = true;
    if (labels.length) query.labels = labels;
    const raw = { operation, href: map.get('--url'), tenant: map.get('--tenant-id'), repository: map.get('--repository-id'),
      tokenFile: map.get('--token-file'), ...(operation === 'search' ? { query } : {}) };
    for (const [flag, field] of [['--number', 'number'], ['--after', 'after'], ['--limit', 'limit'], ['--max-pages', 'maxPages'],
      ['--max-output-bytes', 'maxOutputBytes'], ['--max-scan', 'maxScan'], ['--timeout-ms', 'timeoutMs']]) {
      if (map.has(flag)) raw[field] = decimal(map.get(flag), field, field === 'after' ? 0 : 1);
    }
    if (map.has('--expected-head')) raw.head = map.get('--expected-head');
    return { options: issueReadOptions(raw), bodyFile: null, reading: true };
  }
  if (caseSensitive || ['--after', '--expected-head', '--limit', '--max-pages', '--max-output-bytes', '--state', '--opened-by', '--query', '--max-scan'].some(k => map.has(k))) throw operatorError('issue_operator_read_option');
  const fields = {};
  if (map.has('--title')) fields.title = map.get('--title');
  if (map.has('--body')) fields.body = map.get('--body');
  if (map.has('--body-file')) fields.body = 'pending private file';
  if (operation === 'open' && !Object.hasOwn(fields, 'body')) fields.body = '';
  if (labels.length || clear) fields.labels = labels;
  const raw = { operation, href: map.get('--url'), tenant: map.get('--tenant-id'), repository: map.get('--repository-id'),
    tokenFile: map.get('--token-file'), record: map.get('--record'),
    ...(map.has('--number') ? { number: decimal(map.get('--number'), 'issue number', 1) } : {}),
    ...(map.has('--expected-version') ? { expectedVersion: decimal(map.get('--expected-version'), 'expected version') } : {}),
    ...(Object.keys(fields).length ? { fields } : {}),
    ...(map.has('--timeout-ms') ? { timeoutMs: decimal(map.get('--timeout-ms'), 'timeout', 1) } : {}) };
  return { options: issueOperatorOptions(raw), bodyFile: map.has('--body-file') ? operatorPath(map.get('--body-file')) : null };
}
export async function runIssueCommand(args, signal) {
  if (args.length === 1 && args[0] === '--help') return { text: HELP, exitCode: 0 };
  const { options, bodyFile, reading } = issueArguments(args);
  // Include private-body intake in the same finite command deadline.
  const deadline = AbortSignal.timeout(options.timeoutMs), combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
  if (bodyFile !== null) {
    const bytes = await readPrivateOperatorFile(bodyFile, 65536, () => combined.throwIfAborted(), 0);
    try { options.fields.body = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
    finally { bytes.fill(0); }
  }
  if (reading) {
    const result = await runIssueRead({ ...options, signal: combined });
    return { text: operatorJson(result), exitCode: result.complete ? 0 : 4 };
  }
  const result = await runIssueOperation({ ...options, signal: combined });
  return { text: operatorJson(result), exitCode: result.state !== 'terminal_observed' ? 2 : result.result.outcome === 'committed' ? 0 : 3 };
}
async function main() {
  const stop = new AbortController(), abort = () => stop.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  let completed = false;
  process.stdout.on('error', () => { abort(); process.exitCode = 2; });
  process.stderr.on('error', () => { abort(); process.exitCode = 2; });
  try {
    const result = await runIssueCommand(process.argv.slice(2), stop.signal); completed = true;
    process.exitCode = result.exitCode;
    await new Promise((resolve, reject) => process.stdout.write(result.text, e => e ? reject(e) : resolve()));
  } catch (e) {
    process.exitCode = 2;
    process.stderr.write(operatorJson({ type: 'forge_issue_operator_error', code: e.code ?? 'issue_operator_failed',
      operation_completed: completed, state: e.operator_state ?? null, record: e.record ?? null,
      record_sha256: e.record_sha256 ?? null, http_status: e.status ?? null }));
  } finally { process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
