#!/usr/bin/env node
// Native tag publication, bounded reads and original-request recovery.
import { pathToFileURL } from 'node:url';
import { decimal, hex, text, utf8 } from '../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { tagOperatorOptions, runTagOperation } from './lib/forge-tag-operator.mjs';
import { operatorError, operatorJson, operatorPath, readPrivateOperatorFile } from './lib/forge-operator-io.mjs';
import { runOperatorCli } from './lib/forge-operator-cli.mjs';

export const HELP = `Usage: node scripts/forge_tags.mjs OPERATION
  --url https://HOST/REPOSITORY_ROUTE/ui/tags/
  --tenant-id HEX --repository-id HEX --token-file PRIVATE_FILE

list: --object-format sha1|sha256
show: --object-format sha1|sha256 --ref REF | --ref-hex HEX
lightweight: --object-format sha1|sha256 --record PRIVATE_NEW_FILE
  --ref REF | --ref-hex HEX --source-ref REF | --source-ref-hex HEX --target OID
annotated: same creation options, plus --target-kind commit|tree|blob|tag
  --tagger 'Name <email>' --timestamp UNIX_SECONDS --message-file PRIVATE_FILE
delete: --object-format sha1|sha256 --record PRIVATE_NEW_FILE
  --ref REF | --ref-hex HEX --expected-object OUTER_TAG_OID
status|retry: connection options and the ORIGINAL --record only.

Creation requires an absent destination; there is no replace/force operation.
Source selection must match the exact caller --target. Delete compares the
outer tag OID, never its peeled commit. Ref names are complete refs/tags/*;
source refs are complete refs/*. Hex encodes exact original name bytes.
Annotated message bytes are preserved (empty, CRLF and non-UTF-8 permitted,
NUL refused), at most 65536 bytes. No inferred tagger, timestamp or newline.
Timestamps are exact safe integers 0..9007199254740991. Tags are not signed
or cryptographically verified; preserved signature text supplies no trust.

Reads/preflight accept --limit 1..100 and --max-pages 1..100, retaining at
most 2048 source refs per invocation. Defaults: limit 100, list one page,
show/mutations 20 pages. Reads accept --max-output-bytes 1..8388608.
List returns a bounded tag prefix from the native all-ref inventory. A partial
prefix requires restarting with a larger budget; cross-process cursors are
not supported. Show and mutation selection refuse an exhausted scan budget.
All commands accept --timeout-ms 1..300000 (whole invocation, default 30000).

HTTPS is required except on loopback. Use an ordinary 64-character lowercase
hex token, optionally followed by LF. Reads and mutation preflight need read;
publication needs receive; status/retry need outcomes-read. The same original
credential fingerprint is required for recovery; rotated tokens are refused.
Token/message/record files must be owner-private, regular and single-link;
record parents must exist and be owner-private. Unix profile only.

Fresh writes sync a token-free private recovery record before submission.
Keep every record. Status observes only; retry observes then may submit the
SAME request/key once. Missing outcome or cancellation never proves non-commit.
Exit 0: committed terminal result or complete read; 3: native refusal;
4: incomplete bounded inventory; 2: error or unresolved outcome.
`;

export function tagArguments(args) {
  if (!Array.isArray(args) || args.length > 48 || args.some(arg => typeof arg !== 'string' || arg.includes('\0') || arg.length > 65536) ||
      args.reduce((n, arg) => n + Buffer.byteLength(arg), 0) > 256 * 1024) throw operatorError('tag_operator_argument_limit');
  const operation = args[0], map = new Map();
  const mapping = { '--url': 'href', '--tenant-id': 'tenant', '--repository-id': 'repository', '--token-file': 'tokenFile',
    '--record': 'record', '--object-format': 'objectFormat', '--target': 'target', '--target-kind': 'targetKind',
    '--tagger': 'tagger', '--expected-object': 'expectedObject', '--timestamp': 'timestamp',
    '--timeout-ms': 'timeoutMs', '--limit': 'limit', '--max-pages': 'maxPages', '--max-output-bytes': 'maxOutputBytes' };
  const special = ['--ref', '--ref-hex', '--source-ref', '--source-ref-hex', '--message-file'];
  for (let i = 1; i < args.length; i++) {
    const flag = args[i];
    if ((!Object.hasOwn(mapping, flag) && !special.includes(flag)) || map.has(flag)) throw operatorError('tag_operator_unknown_or_duplicate_option');
    if (args[i + 1] === undefined) throw operatorError('tag_operator_missing_value');
    map.set(flag, args[++i]);
  }
  const raw = { operation };
  for (const [flag, field] of Object.entries(mapping)) if (map.has(flag)) {
    raw[field] = ['timestamp', 'timeoutMs', 'limit', 'maxPages', 'maxOutputBytes'].includes(field)
      ? decimal(map.get(flag), field, field === 'timestamp' ? 0 : 1) : map.get(flag);
  }
  for (const [name, field] of [['ref', 'refHex'], ['source-ref', 'sourceRefHex']]) {
    if (map.has(`--${name}`) && map.has(`--${name}-hex`)) throw operatorError('tag_operator_reference_encoding');
    if (map.has(`--${name}`)) raw[field] = hex(utf8.encode(text(map.get(`--${name}`), 1024, 'reference')));
    if (map.has(`--${name}-hex`)) raw[field] = map.get(`--${name}-hex`);
  }
  let messageFile = null;
  if (map.has('--message-file')) {
    if (operation !== 'annotated') throw operatorError('tag_operator_message_inapplicable');
    messageFile = operatorPath(map.get('--message-file')); raw.messageHex = '';
  }
  const options = tagOperatorOptions(raw);
  if (operation === 'annotated' && messageFile === null) throw operatorError('tag_operator_message_required');
  if (messageFile !== null && messageFile === options.record) throw operatorError('tag_operator_separate_record');
  if (messageFile !== null && messageFile === options.tokenFile) throw operatorError('tag_operator_message_is_credential');
  return { options, messageFile };
}

export async function runTagCommand(args, signal) {
  if (args.length === 1 && args[0] === '--help') return { text: HELP, exitCode: 0 };
  const { options, messageFile } = tagArguments(args);
  const deadline = AbortSignal.timeout(options.timeoutMs), combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
  if (messageFile !== null) {
    const bytes = await readPrivateOperatorFile(messageFile, 65536, () => combined.throwIfAborted(), 0);
    try { options.messageHex = bytes.toString('hex'); } finally { bytes.fill(0); }
  }
  const result = await runTagOperation({ ...options, signal: combined });
  return { text: operatorJson(result), exitCode: ['list', 'show'].includes(options.operation) ? result.complete ? 0 : 4
    : result.state !== 'terminal_observed' ? 2 : result.result.outcome === 'committed' ? 0 : 3 };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runOperatorCli(process.argv.slice(2), {
    timeout: args => args.length === 1 && args[0] === '--help' ? 30000 : tagArguments(args).options.timeoutMs,
    run: runTagCommand,
    failure: (error, completed) => operatorJson({ type: 'forge_tag_operator_error', code: error.code ?? 'tag_operator_failed',
      operation_completed: completed, state: error.operator_state ?? null, record: error.record ?? null,
      record_sha256: error.record_sha256 ?? null, http_status: error.status ?? null }),
  });
}
