#!/usr/bin/env node
// Headless remote PR selection, canonical checks and exact retained output.
import { pathToFileURL } from 'node:url';
import { decimal } from '../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { checkReadOptions, runCheckRead } from './lib/forge-check-reader.mjs';
import { operatorError, operatorJson } from './lib/forge-operator-io.mjs';
import { runOperatorCli } from './lib/forge-operator-cli.mjs';

export const HELP = `Usage: node scripts/forge_checks.mjs OPERATION
  --url https://HOST/REPOSITORY_ROUTE/ui/pulls/
  --tenant-id HEX --repository-id HEX --token-file PRIVATE_FILE
  [--incarnation-id HEX --object-format sha1|sha256]

list: bounded PR metadata pages, including exact ref bytes and native tips.
  [--after PR_NUMBER --expected-head TOKEN] [--limit 1..100 --max-pages 1..100]
show: --number PR_NUMBER [--expected-head TOKEN]
checks: --number PR_NUMBER [--after CHECK_ID --expected-head TOKEN]
  [--limit 1..100 --max-pages 1..100]
All later pages retain the original snapshot, incarnation and source head.
No missing, stale or empty check list establishes passing CI or merge permission.

evidence|log: --number PR_NUMBER --check EXACT_CHECK_ID
  --expected-head ORIGINAL_SNAPSHOT --expected-sha256 EVIDENCE_SHA256
  --expected-bytes EVIDENCE_BYTES --evidence-token-file PRIVATE_FILE
  [--after CHECK_CURSOR --limit 1..100 --max-pages 1..100]
evidence: [--output NEW_PRIVATE_FILE]
log: --step ZERO_BASED_INDEX --stream stdout|stderr --output NEW_PRIVATE_FILE
Select the exact check, snapshot, digest and length from a checks result.
The default evidence lookup scans at most ten pages of 100 checks. A missing
selection or page budget exhaustion refuses; it never chooses another check.
Evidence reports retain exact stdout_hex/stderr_hex. Log export writes the
original bytes, including binary or empty streams, with no text conversion.
Unsupported reports remain downloadable as raw evidence; no log is invented.

The PR token needs pulls-read; listing checks additionally needs the sponsored
pulls-feedback-read scope for fgagent credentials. Evidence uses only the
explicitly selected evidence token: ordinary tokens need pulls-read plus
artifact-read, sponsored tokens need pulls-check-evidence-read. The same token
file may be selected explicitly for both roles if it has the required grants.
No generic artifact, mutation, outcome, execution or administration route is used.
Credentials are 64 lowercase hex characters or fgagent_ plus 64 lowercase hex,
with at most one final LF. Token files must be private single-link regular files.

Output parents must already be owner-private directories. A new 0600 output is
published only after complete evidence and report verification; existing names
are never replaced. Retain a published file even if stdout delivery later fails.
Downloads are retained observations, not independent execution verification.
No native storage root or fg executable is required. HTTPS except loopback.
--timeout-ms 1..300000 bounds the whole invocation (default 30000).
--max-output-bytes 1..8388608 bounds JSON output, including its envelope.
Exit 0: complete read/export (not a CI-success claim); 4: bounded page prefix
with an exact continuation; 2: invalid, refused, incomplete or cancelled read.
See docs/REMOTE_PULL_CHECKS.md.
`;

export function checkArguments(args) {
  if (!Array.isArray(args) || args.length > 48 || args.some(value => typeof value !== 'string' ||
      value.length > 4096 || /[\0\r\n]/u.test(value)) ||
      args.reduce((size, value) => size + Buffer.byteLength(value), 0) > 32768) throw operatorError('forge_check_argument_limit');
  const names = { '--url': 'href', '--tenant-id': 'tenant', '--repository-id': 'repository',
    '--incarnation-id': 'incarnation', '--object-format': 'objectFormat', '--token-file': 'tokenFile',
    '--number': 'number', '--expected-head': 'head', '--after': 'after', '--limit': 'limit', '--max-pages': 'maxPages',
    '--evidence-token-file': 'evidenceTokenFile', '--check': 'checkId', '--expected-sha256': 'expectedSha256',
    '--expected-bytes': 'expectedBytes', '--output': 'output', '--step': 'step', '--stream': 'stream',
    '--timeout-ms': 'timeoutMs', '--max-output-bytes': 'maxOutputBytes' };
  const raw = { operation: args[0] };
  for (let i = 1; i < args.length;) {
    const flag = args[i++], name = names[flag], value = args[i++];
    if (!name || Object.hasOwn(raw, name) || value === undefined || value === '' || value.startsWith('--')) {
      throw operatorError('forge_check_unknown_duplicate_or_missing_option');
    }
    raw[name] = value;
  }
  for (const name of ['number', 'limit', 'maxPages', 'expectedBytes', 'step', 'timeoutMs', 'maxOutputBytes',
    ...(raw.operation === 'list' ? ['after'] : [])]) {
    if (raw[name] !== undefined) raw[name] = decimal(raw[name], name, name === 'step' || name === 'after' ? 0 : 1);
  }
  return checkReadOptions(raw);
}

export async function runCheckCommand(args, signal) {
  if (args.length === 1 && args[0] === '--help') return { text: HELP, exitCode: 0, output: null };
  const result = await runCheckRead({ ...checkArguments(args), ...(signal ? { signal } : {}) });
  return { text: operatorJson(result), exitCode: result.complete ? 0 : 4, output: result.export?.output ?? null };
}
async function main() {
  let exported = null;
  await runOperatorCli(process.argv.slice(2), {
    timeout: args => args.length === 1 && args[0] === '--help' ? 30000 : checkArguments(args).timeoutMs,
    run: async (args, signal) => {
      const result = await runCheckCommand(args, signal); exported = result.output; return result;
    },
    failure: (error, completed) => operatorJson({ type: 'forge_pull_check_error', schema_version: 1,
      code: error.code ?? 'forge_check_read_failed', http_status: error.status ?? null,
      operation_completed: completed, output: exported ?? error.output ?? null,
      output_may_exist: exported !== null || Boolean(error.output_may_exist),
      read_only: true, mutation_submitted: false }),
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
