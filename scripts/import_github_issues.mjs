#!/usr/bin/env node
// GitHub is read-only. Native issue publication is a separately confirmed phase.
import { pathToFileURL } from 'node:url';
import { prepareGithubIssueImport, runGithubIssueImport } from './lib/github-issue-import.mjs';
import { captureGithubIssues, parseCapture, issueImportSteps, CAPTURE_LIMIT } from './lib/github-issue-source.mjs';
import { operatorError, operatorJson, operatorPath, privateRecordPath, absentRecord,
  readPrivateOperatorFile, saveOperatorRecord, recordDigest } from './lib/forge-operator-io.mjs';

export const HELP = `Usage: node scripts/import_github_issues.mjs capture
  --repository OWNER/REPO --issue NUMBER [--issue NUMBER ...] --out PRIVATE_NEW_FILE
  [--token-file PRIVATE_GITHUB_TOKEN] [--timeout-ms 1..300000]
  [--max-read-bytes 1..268435456]

Usage: node scripts/import_github_issues.mjs inspect --capture PRIVATE_FILE [--offset NUMBER]

Usage: node scripts/import_github_issues.mjs prepare
  --capture PRIVATE_FILE --workdir NEW_PRIVATE_DIRECTORY
  --url https://HOST/REPOSITORY_ROUTE/ui/issues/ --tenant-id HEX --repository-id HEX
  --token-file PRIVATE_NATIVE_TOKEN [--offset NUMBER] [--timeout-ms 1..300000]

Usage: node scripts/import_github_issues.mjs run|status
  --workdir DIRECTORY --url https://HOST/REPOSITORY_ROUTE/ui/issues/
  --tenant-id HEX --repository-id HEX --token-file PRIVATE_ORIGINAL_NATIVE_TOKEN
  --confirm PREPARED_PLAN_SHA256 [--timeout-ms 1..300000]
  [--max-mutations 1..2200] [--retry-unresolved] (retry is run-only)

Prepare seals a source copy, exact number mapping, every original request/key
and the original native credential fingerprint without network or publication.
Run verifies the complete private request set before any destination access. Restart checks canonical original outcomes;
only explicit --retry-unresolved permits an exact resend. Never recreate a lost
request or change a conflicting version. Keep the entire work directory.
Status never submits a mutation; it can retain validated local observations.
A killed sender leaves its lock blocking run, but status remains available.
Exit 0: prepared/captured/inspected or all steps committed; 1: bounded/pending;
3: canonical refusal; 2: error (possibly after partial or complete publication).

Capture fetches only the explicitly selected issues and every current comment,
in two equal observations. It is NOT an atomic GitHub snapshot. Quiesce source
edits during migration. Pull requests are refused, not converted into issues.
The 1 MiB package supports up to 100 issues and 2000 comments. Fields exceeding
native issue limits are refused rather than truncated. No attachment is fetched.
Inspect prints the complete exact native command proposal without sending it.
Source authors, times, assignees, milestones, label metadata and locked status
are attributed source data, NOT native permissions, historical events or roles.
The GitHub credential is used only with api.github.com and is never saved.
This Unix operator requires private files and a private existing output parent.
`;
function integer(v) {
  if (typeof v !== 'string' || !/^(0|[1-9][0-9]*)$/.test(v) || !Number.isSafeInteger(Number(v))) throw operatorError('github_import_integer');
  return Number(v);
}
export function importArguments(args) {
  if (!Array.isArray(args) || args.length > 230 || args.some(v => typeof v !== 'string' || v.length > 4096 || /[\0\r\n]/.test(v))) throw operatorError('github_import_arguments');
  const operation = args[0], values = new Map(), issues = [];
  const destination = ['--workdir', '--url', '--tenant-id', '--repository-id', '--token-file', '--timeout-ms'];
  const allowed = operation === 'capture' ? ['--repository', '--issue', '--out', '--token-file', '--timeout-ms', '--max-read-bytes']
    : operation === 'inspect' ? ['--capture', '--offset']
    : operation === 'prepare' ? [...destination, '--capture', '--offset']
    : ['run', 'status'].includes(operation) ? [...destination, '--confirm', '--max-mutations', ...(operation === 'run' ? ['--retry-unresolved'] : [])] : [];
  if (!allowed.length) throw operatorError('github_import_operation');
  for (let i = 1; i < args.length; i += 2) {
    const key = args[i], value = args[i + 1];
    if (key === '--retry-unresolved' && operation === 'run' && !values.has(key)) { values.set(key, true); i--; continue; }
    if (!allowed.includes(key) || value === undefined || !value || value.startsWith('--') || (key !== '--issue' && values.has(key))) throw operatorError('github_import_option');
    if (key === '--issue') issues.push(integer(value)); else values.set(key, value);
  }
  const required = operation === 'capture' ? ['--repository', '--out']
    : operation === 'inspect' ? ['--capture']
    : ['--workdir', '--url', '--tenant-id', '--repository-id', '--token-file', operation === 'prepare' ? '--capture' : '--confirm'];
  if (required.some(k => !values.has(k)) || (operation === 'capture' && !issues.length)) throw operatorError('github_import_required_option');
  return { operation, values, issues };
}
export async function runGithubImportCommand(args, signal) {
  if (args.length === 1 && args[0] === '--help') return { text: HELP, exitCode: 0 };
  const { operation, values, issues } = importArguments(args);
  if (['prepare', 'run', 'status'].includes(operation)) {
    const common = { workdir: values.get('--workdir'), href: values.get('--url'), tenant: values.get('--tenant-id'),
      repository: values.get('--repository-id'), tokenFile: values.get('--token-file'), signal,
      timeoutMs: integer(values.get('--timeout-ms') ?? '300000') };
    const result = operation === 'prepare'
      ? await prepareGithubIssueImport({ ...common, captureFile: values.get('--capture'), offset: integer(values.get('--offset') ?? '0') })
      : await runGithubIssueImport({ ...common, operation, confirm: values.get('--confirm'),
        retryUnresolved: values.has('--retry-unresolved'), maxMutations: integer(values.get('--max-mutations') ?? '100') });
    return { text: operatorJson(result), exitCode: operation === 'prepare' || result.complete ? 0 : result.stop_reason === 'terminal_refusal' ? 3 : 1 };
  }
  if (operation === 'inspect') {
    const bytes = await readPrivateOperatorFile(values.get('--capture'), CAPTURE_LIMIT, () => signal?.throwIfAborted());
    const capture = parseCapture(bytes), steps = issueImportSteps(capture, integer(values.get('--offset') ?? '0'));
    return { text: operatorJson({ type: 'github_issue_import_proposal', capture_sha256: recordDigest(bytes),
      source: capture.source, steps, mutation_submitted: false }), exitCode: 0 };
  }
  const timeoutMs = integer(values.get('--timeout-ms') ?? '300000');
  if (timeoutMs < 1 || timeoutMs > 300000) throw operatorError('github_import_timeout');
  const stop = new AbortController(), combined = signal ? AbortSignal.any([signal, stop.signal]) : stop.signal;
  const timer = setTimeout(() => stop.abort(), timeoutMs), check = () => combined.throwIfAborted();
  let tokenBytes;
  try {
    const out = await privateRecordPath(values.get('--out')); await absentRecord(out); check();
    let token = null;
    if (values.has('--token-file')) {
      if (operatorPath(values.get('--token-file')) === out) throw operatorError('github_import_separate_token');
      tokenBytes = await readPrivateOperatorFile(values.get('--token-file'), 256, check);
      token = new TextDecoder('utf-8', { fatal: true }).decode(tokenBytes).replace(/\n$/, '');
    }
    const result = await captureGithubIssues({ repository: values.get('--repository'), numbers: issues, token,
      signal: combined, timeoutMs, maxReadBytes: integer(values.get('--max-read-bytes') ?? String(64 * 1024 * 1024)) });
    check(); const saved = await saveOperatorRecord(out, result.bytes, check);
    return { text: operatorJson({ type: 'github_issue_capture', path: saved.path, sha256: saved.sha256,
      source: result.capture.source, issues: result.capture.issues.length,
      comments: result.capture.issues.reduce((n, issue) => n + issue.comments.length, 0),
      requests: result.requests, read_bytes: result.read_bytes, atomic_source_snapshot: false, mutation_submitted: false }), exitCode: 0 };
  } finally { tokenBytes?.fill(0); clearTimeout(timer); stop.abort(); }
}
async function main() {
  const stop = new AbortController(), abort = () => stop.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  process.stdout.on('error', () => { abort(); process.exitCode = 2; });
  process.stderr.on('error', () => { abort(); process.exitCode = 2; });
  let completedResult = null;
  try {
    const result = await runGithubImportCommand(process.argv.slice(2), stop.signal); completedResult = result.text; process.exitCode = result.exitCode;
    await new Promise((resolve, reject) => process.stdout.write(result.text, e => e ? reject(e) : resolve()));
  } catch (error) {
    process.exitCode = 2;
    process.stderr.write(operatorJson({ type: 'github_issue_import_error', code: error.code ?? 'github_import_failed',
      http_status: error.status ?? null, retry_after_seconds: error.retry_after_seconds ?? null,
      import_progress: error.import_progress ?? null, observed_terminal: error.observed_terminal ?? null,
      completed_result: completedResult }));
  } finally { process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
