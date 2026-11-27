#!/usr/bin/env node
// Remote canonical symbolic HEAD selection with exact durable request custody.
import { pathToFileURL } from 'node:url';
import { decimal, hex, utf8 } from '../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { refName } from '../crates/fgit-node/src/smart_http/server/browser/branches.mjs';
import { defaultBranchOperatorOptions, runDefaultBranchOperation } from './lib/forge-default-branch-operator.mjs';
import { operatorError, operatorJson } from './lib/forge-operator-io.mjs';
import { runOperatorCli } from './lib/forge-operator-cli.mjs';

export const HELP = `Usage: node scripts/forge_default_branch.mjs OPERATION
  --url https://HOST/REPOSITORY_ROUTE/ui/default-branch/
  --tenant-id HEX --repository-id HEX --token-file PRIVATE_FILE

show: read current canonical default, including absent/unborn state.
list: read current default and bounded branch candidates at the SAME snapshot.
  [--after-hex REF_HEX --expected-head TOKEN] [--limit 1..100 --max-pages 1..100]
show|list: [--expected-head TOKEN] [--max-output-bytes 1..8388608]; no record.
A list continuation retains its exact hex cursor and head. Native current-head
pins refuse after any intervening publication; they are not historical reads.

set-default:
  (--ref FULL_BRANCH | --ref-hex REF_HEX)
  (--expected-default FULL_BRANCH | --expected-default-hex REF_HEX | --expect-no-default)
  --expected-tip sha1:OID|sha256:OID --record PRIVATE_NEW_FILE
  [--max-pages 1..21]
The old symbolic target and exact new tip are mandatory expectations.
An unborn named target still needs its exact old name; it is not absent.
Fresh selection searches at most 2048 visible refs through the shipped client.
The native server checks the current administrator policy and target Commit.
This changes canonical HEAD; direct refs and PR bases do not move.

status|retry: connection options and ORIGINAL --record only.
status observes. retry observes first and may resend the SAME request/key once.
Keep every record, including unknown or refused requests. No automatic retry,
record replacement or silent refresh of either expectation.

Private token files contain 64 lowercase hexadecimal characters, optionally one
final LF. Sponsored tokens are not accepted. The native administrator profile
also refuses canonically declared agents using ordinary tokens.
Reads require read. Fresh writes additionally need default-branch-write and
the server's --enable-default-branch-admin with installed administrator policy.
Recovery requires outcomes-read independently. HTTPS required except loopback.
Token and record files must be owner-private regular single-link files; record
parents must already be owner-private. Unix filesystem profile only.
All commands accept --timeout-ms 1..300000 (whole invocation, default 30000).
Exit 0: complete read or committed terminal observation; 3: terminal refusal;
4: bounded list prefix with continuation; 2: unknown outcome or error.
`;

export function defaultBranchArguments(args) {
  if (!Array.isArray(args) || args.length > 48 ||
      args.some(value => typeof value !== 'string' || value.includes('\0') || value.length > 4096) ||
      args.reduce((sum, value) => sum + Buffer.byteLength(value), 0) > 32 * 1024) throw operatorError('default_branch_operator_argument_limit');
  const values = new Map(); let absent = false;
  const allowed = ['--url', '--tenant-id', '--repository-id', '--token-file', '--record',
    '--ref', '--ref-hex', '--expected-default', '--expected-default-hex', '--expected-tip',
    '--after-hex', '--expected-head', '--limit', '--max-pages', '--max-output-bytes', '--timeout-ms'];
  for (let i = 1; i < args.length; i++) {
    const flag = args[i];
    if (flag === '--expect-no-default') {
      if (absent) throw operatorError('default_branch_operator_duplicate_option');
      absent = true; continue;
    }
    if (!allowed.includes(flag) || values.has(flag)) throw operatorError('default_branch_operator_unknown_or_duplicate_option');
    const value = args[++i];
    if (value === undefined) throw operatorError('default_branch_operator_missing_value');
    values.set(flag, value);
  }
  if ((values.has('--ref') && values.has('--ref-hex')) ||
      (values.has('--expected-default') && values.has('--expected-default-hex'))) throw operatorError('default_branch_operator_ambiguous_reference');
  const raw = { operation: args[0], href: values.get('--url'), tenant: values.get('--tenant-id'),
    repository: values.get('--repository-id'), tokenFile: values.get('--token-file') };
  for (const [flag, field] of [['--record', 'record'], ['--ref-hex', 'referenceHex'], ['--expected-default-hex', 'expectedDefaultHex'],
    ['--expected-tip', 'expectedTip'], ['--after-hex', 'afterHex'], ['--expected-head', 'head']]) {
    if (values.has(flag)) raw[field] = values.get(flag);
  }
  if (values.has('--ref')) raw.referenceHex = hex(utf8.encode(refName(values.get('--ref'))));
  if (values.has('--expected-default')) raw.expectedDefaultHex = hex(utf8.encode(refName(values.get('--expected-default'))));
  if (absent) raw.expectNoDefault = true;
  for (const [flag, field] of [['--limit', 'limit'], ['--max-pages', 'maxPages'], ['--max-output-bytes', 'maxOutputBytes'], ['--timeout-ms', 'timeoutMs']]) {
    if (values.has(flag)) raw[field] = decimal(values.get(flag), field, 1);
  }
  return defaultBranchOperatorOptions(raw);
}

export async function runDefaultBranchCommand(args, signal) {
  if (args.length === 1 && args[0] === '--help') return { text: HELP, exitCode: 0 };
  const result = await runDefaultBranchOperation({ ...defaultBranchArguments(args), ...(signal ? { signal } : {}) });
  const exitCode = result.read_only ? result.complete ? 0 : 4
    : result.state !== 'terminal_observed' ? 2 : result.result.outcome === 'committed' ? 0 : 3;
  return { text: operatorJson(result), exitCode };
}
async function main() {
  await runOperatorCli(process.argv.slice(2), {
    timeout: args => args.length === 1 && args[0] === '--help' ? 30000 : defaultBranchArguments(args).timeoutMs,
    run: runDefaultBranchCommand,
    failure: (error, completed) => operatorJson({ type: 'forge_default_branch_operator_error',
      code: error.code ?? 'default_branch_operator_failed', operation_completed: completed,
      state: error.operator_state ?? null, record: error.record ?? null,
      record_sha256: error.record_sha256 ?? null, http_status: error.status ?? null, absence_proves_non_commit: false }),
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
