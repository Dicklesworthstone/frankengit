#!/usr/bin/env node
// Read and draft only. No code path in this executable publishes a PR or review.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { capturePullReviews, reviewCanonical, parseReviewJson, failReview, ReviewSnapshotError } from './operator/pull_review_snapshot.mjs';
import { draftPullReview } from './operator/pull_review_draft.mjs';
import { readReviewPrivate, reviewDestination, saveReviewJson, loadReviewCapture } from './operator/pull_review_files.mjs';
export const HELP = `Usage: node scripts/fg_pull_review.mjs capture|inspect|draft [options]

capture --input PRIVATE_SELECTION_JSON --token-file PRIVATE_TOKEN --output NEW_CAPTURE_JSON
        [--ca-file PRIVATE_PEM] [--timeout-ms 1..300000]
inspect --capture PRIVATE_CAPTURE_JSON --sha256 RETAINED_CAPTURE_HASH
draft   --capture PRIVATE_CAPTURE_JSON --sha256 RETAINED_CAPTURE_HASH
        --input PRIVATE_CHOICE_JSON --output NEW_COMMAND_INPUT_JSON

Selection: endpoint, scope {tenant_id, repository_id, repository_incarnation,
object_format}, number (decimal string), expected_head (snapshot token or null).
Choice: principal_id and explicit action. approve/request-changes/withdraw/merge
use candidate review subjects. update/close/reopen/fast-forward use captured PR
metadata; update accepts an explicit title and/or body replacement, not new tips.
Approve/request-changes also require reason, merge_base, candidate_commit.
Withdraw requires only reason: its original subject/candidate is retained.
Merge requires merge_base, candidate_commit, method merge-commit|squash, and
required_reviewers. Candidate OIDs are raw native lowercase hex, chosen by you.

Capture only reads the native API; inspect and draft are offline and take no token.
Draft outputs input for scripts/remote_pull.mjs prepare. close/reopen preserve
all metadata; fast-forward still needs --fast-forward-only at the separate sender. It does NOT approve,
create a request/key, upload a bundle, merge, or claim any vote grants permission.
Use the existing prepare/inspect/send/recover workflow for explicit publication.

Private owned POSIX files outside Git worktrees only. Outputs are create-only.
Retain the printed SHA-256 separately; it checks local integrity, not authority.
Full inspection prints private repository/review text. Tokens are never printed.
No automatic retry, refreshed subject, new strategy or TLS verification bypass.
Exit 0: complete read/inspection/draft (including typed missing PR); 2: invalid
local input; 3: incomplete network, file publication or output. Retain interrupted
files. See docs/REMOTE_PR_REVIEW_SNAPSHOTS.md.
`;
function options(args) {
  if (!Array.isArray(args) || args.length < 1 || args.length > 15 || args.some(a => typeof a !== 'string' || a.length > 4096)) failReview('invalid_review_arguments');
  const action = args[0], required = { capture: ['input', 'token-file', 'output'], inspect: ['capture', 'sha256'], draft: ['capture', 'sha256', 'input', 'output'] }[action];
  if (!required) failReview('unknown_review_command');
  const allowed = [...required, ...(action === 'capture' ? ['ca-file', 'timeout-ms'] : [])], flags = {};
  for (let i = 1; i < args.length; i += 2) {
    const name = args[i].startsWith('--') ? args[i].slice(2) : '', value = args[i + 1];
    if (!allowed.includes(name) || Object.hasOwn(flags, name) || !value || value.startsWith('--')) failReview('invalid_review_option');
    flags[name] = value;
  }
  if (required.some(name => !Object.hasOwn(flags, name))) failReview('missing_review_option');
  if (flags['timeout-ms'] !== undefined && (!/^[1-9][0-9]{0,5}$/.test(flags['timeout-ms']) || Number(flags['timeout-ms']) > 300000)) failReview('invalid_review_timeout');
  return { action, flags };
}
const write = (stream, text) => new Promise((resolve, reject) => stream.write(text, e => e ? reject(e) : resolve()));
export async function run(args, { output = text => write(process.stdout, text), errorOutput = text => write(process.stderr, text), signal } = {}) {
  let started = false, destination = null, saved = null;
  try {
    if (args.length === 0 || (args.length === 1 && args[0] === '--help')) { await output(HELP); return 0; }
    const { action, flags } = options(args);
    if (signal?.aborted) failReview('review_cancelled');
    if (flags.output !== undefined) destination = await reviewDestination(flags.output);
    let value;
    if (action === 'capture') {
      const selected = parseReviewJson(await readReviewPrivate(flags.input, 16384));
      const bytes = await readReviewPrivate(flags['token-file'], 65);
      if (bytes.length !== 64 && !(bytes.length === 65 && bytes[64] === 10)) failReview('invalid_review_token_file');
      const token = bytes.subarray(0, 64).toString('utf8');
      if (!/^[0-9a-f]{64}$/.test(token)) failReview('invalid_review_token_file');
      const ca = flags['ca-file'] === undefined ? undefined : await readReviewPrivate(flags['ca-file'], 131072);
      started = true;
      value = await capturePullReviews(selected, token, { signal, ca, timeoutMs: Number(flags['timeout-ms'] ?? '30000') });
    } else {
      value = await loadReviewCapture(flags.capture, flags.sha256);
      if (action === 'inspect') { await output(reviewCanonical(value)); return 0; }
      // A native body is 64 KiB, but JSON escaping can expand it sixfold.
      // Bound the choice envelope separately; the drafter still enforces native UTF-8 limits.
      value = draftPullReview(value, parseReviewJson(await readReviewPrivate(flags.input, 512 * 1024)));
    }
    if (signal?.aborted) failReview('review_cancelled');
    started = true; saved = await saveReviewJson(destination, value);
    await output(reviewCanonical({ type: action === 'capture' ? 'pull_review_captured' : 'pull_review_drafted', schema_version: 1,
      ...saved, ...(action === 'capture' ? { found: value.pull.found, snapshot_token: value.pull.snapshot_token,
        reviewers: value.review_pages.reduce((n, p) => n + p.reviews.length, 0) } : { action: value.action, number: value.number, source_capture_sha256: flags.sha256 }),
      publication_attempted: false, merge_authorized: false }));
    return 0;
  } catch (error) {
    try { await errorOutput(reviewCanonical({ type: 'pull_review_error', schema_version: 1,
      code: error instanceof ReviewSnapshotError ? error.code : 'review_file_or_output_failure',
      status: error instanceof ReviewSnapshotError ? error.status : null, path: saved?.path ?? destination,
      saved_sha256: saved?.sha256 ?? null, publication_attempted: false })); } catch { /* A complete named output remains inspectable. */ }
    return started ? 3 : 2;
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort(), pipe = () => {};
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { process.exitCode = await run(process.argv.slice(2), { signal: controller.signal }); }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
