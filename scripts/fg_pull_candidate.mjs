#!/usr/bin/env node
// Read-only native candidate acquisition, private replay, and explicit drafting.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { capturePullCandidate, candidateInput, candidateCanonical } from './operator/pull_candidate_capture.mjs';
import { CandidateError, candidateFail, candidateJson, CANDIDATE_IO_LIMITS } from './operator/pull_candidate_io.mjs';
import { readCandidatePrivate, readCandidateToken, candidateDestination, candidateClock,
  saveCandidatePackage, loadCandidatePackage, saveCandidateJson } from './operator/pull_candidate_files.mjs';
import { draftCandidateReview } from './operator/pull_candidate_draft.mjs';

export const HELP = `Usage: node scripts/fg_pull_candidate.mjs <capture|inspect|draft> [options]

capture --input PRIVATE_JSON --token-file PRIVATE_TOKEN --output-dir NEW_PRIVATE_DIR
        [--ca-file PRIVATE_PEM] [--max-wire-bytes N] [--max-review-pages 1..8]
inspect --package PRIVATE_DIR --sha256 INDEPENDENT_MANIFEST_HASH
draft   --package PRIVATE_DIR --sha256 INDEPENDENT_MANIFEST_HASH
        --choices PRIVATE_JSON --output NEW_PRIVATE_JSON

All commands: [--timeout-ms 1..300000] (default 30000, one operation deadline).
Capture input: endpoint, scope {tenant_id, repository_id, repository_incarnation,
object_format}, number (decimal string), metadata {author, committer, timestamp
(decimal string), message}, method (merge-commit or squash), optional expected_head.
No identity, timestamp, merge method or branch is inferred from ambient state.

Inspect is offline and emits the retained PR/reviewer/preparation/inspection JSON,
including raw native diff/hunk bytes. Treat it as private untrusted data, not
approval, an independently recomputed diff, or current permission to merge.

Draft choices: action (approve, request-changes or merge), principal_id,
candidate_commit (exact raw inspected OID), plus reason for a review or explicit
method and required_reviewers for a merge. The method must match the inspected
candidate. Drafts use complete retained reviewer predecessors and never refresh
source tips or policy epochs. Withdraw stale reviews with fg_pull_review.mjs.

Only capture reads a credential or contacts the native node; it never publishes.
Inspect and draft accept no credential, URL override, strategy fallback or retry.
Pass the draft and saved candidate.bundle separately to remote_pull.mjs prepare;
its original-key, candidate and merge-method send confirmations remain mandatory.

POSIX owned private files/directories outside Git worktrees are required. Outputs
are create-only. Preserve interrupted slots; they are not repaired or overwritten.
Keep the returned manifest hash separately. An unverified self-selected new root
cannot establish that transported bytes are your originally inspected candidate.

Exit 0: completed capture/inspection/draft; 1: captured conflict or up-to-date
noncandidate; 2: local input/file/pin/draft refusal; 3: acquisition, save or output
failure after work began. See docs/PULL_CANDIDATE_PACKAGES.md for limits.
`;
function parse(args) {
  if (!Array.isArray(args) || args.length > 25 || args.some(v => typeof v !== 'string' || v.length > 4096) ||
      args.reduce((n, v) => n + v.length, 0) > 32768) candidateFail('invalid_candidate_arguments');
  const action = args[0], required = action === 'capture' ? ['input', 'token-file', 'output-dir']
    : action === 'inspect' ? ['package', 'sha256'] : action === 'draft' ? ['package', 'sha256', 'choices', 'output'] : null;
  if (!required) candidateFail('unknown_candidate_command');
  const allowed = [...required, 'timeout-ms', ...(action === 'capture' ? ['ca-file', 'max-wire-bytes', 'max-review-pages'] : [])], flags = {};
  for (let i = 1; i < args.length; i += 2) {
    const name = args[i].startsWith('--') ? args[i].slice(2) : '', value = args[i + 1];
    if (!allowed.includes(name) || Object.hasOwn(flags, name) || !value || value.startsWith('--')) candidateFail('invalid_candidate_option');
    flags[name] = value;
  }
  if (required.some(name => !Object.hasOwn(flags, name))) candidateFail('missing_candidate_option');
  for (const [name, maximum] of [['timeout-ms', 300000], ['max-wire-bytes', CANDIDATE_IO_LIMITS.wire], ['max-review-pages', CANDIDATE_IO_LIMITS.reviewPages]]) {
    if (flags[name] !== undefined && (!/^[1-9][0-9]{0,8}$/.test(flags[name]) || Number(flags[name]) > maximum)) candidateFail('invalid_candidate_limit');
  }
  return { action, flags };
}
const write = (stream, text) => new Promise((resolve, reject) => stream.write(text, error => error ? reject(error) : resolve()));
export async function run(args, { output = text => write(process.stdout, text), errorOutput = text => write(process.stderr, text), signal } = {}) {
  let begun = false, completed = null;
  try {
    if (args.length === 0 || (args.length === 1 && args[0] === '--help')) { await output(HELP); return 0; }
    const { action, flags } = parse(args), check = candidateClock({ timeoutMs: Number(flags['timeout-ms'] ?? 30000), signal });
    const options = () => ({ timeoutMs: check(), signal });
    if (action === 'capture') {
      const destination = await candidateDestination(flags['output-dir'], options());
      const input = candidateInput(candidateJson(await readCandidatePrivate(flags.input, 512 * 1024, options()), 512 * 1024));
      const token = await readCandidateToken(flags['token-file'], options());
      const ca = flags['ca-file'] === undefined ? undefined : await readCandidatePrivate(flags['ca-file'], 128 * 1024, options());
      begun = true;
      const result = await capturePullCandidate(input, token, { ...options(), ca,
        ...(flags['max-wire-bytes'] ? { maxWireBytes: Number(flags['max-wire-bytes']) } : {}),
        ...(flags['max-review-pages'] ? { maxReviewPages: Number(flags['max-review-pages']) } : {}) });
      completed = await saveCandidatePackage(destination, result.capture, result.bundle, options());
      await output(candidateCanonical({ type: 'pull_candidate_saved', schema_version: 1, ...completed, usage: result.usage, published: false }));
      return completed.state === 'clean' ? 0 : 1;
    }
    const value = await loadCandidatePackage(flags.package, flags.sha256, options());
    if (action === 'inspect') {
      completed = { path: value.path, sha256: value.sha256, state: value.capture.preparation.state };
      await output(candidateCanonical({ type: 'pull_candidate_inspection', schema_version: 1, ...completed, capture: value.capture, published: false }));
      return 0;
    }
    const destination = await candidateDestination(flags.output, options());
    const choice = candidateJson(await readCandidatePrivate(flags.choices, 512 * 1024, options()), 512 * 1024);
    const draft = await draftCandidateReview(value.capture, value.bundle, choice, options());
    begun = true; completed = await saveCandidateJson(destination, draft, options());
    await output(candidateCanonical({ type: 'pull_candidate_draft', schema_version: 1, ...completed, action: draft.action,
      package_sha256: value.sha256, bundle_path: value.bundle_path, candidate_commit: draft.fields.candidate_commit, published: false }));
    return 0;
  } catch (error) {
    try { await errorOutput(candidateCanonical({ type: 'pull_candidate_error', schema_version: 1,
      code: error instanceof CandidateError ? error.code : 'candidate_local_or_output_failure',
      phase: error instanceof CandidateError ? error.phase : 'local', status: error instanceof CandidateError ? error.status : null,
      completed, published: false })); } catch { /* Synced package/request files are not erased by a broken pipe. */ }
    return begun || completed !== null ? 3 : 2;
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort(), pipe = () => {};
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { process.exitCode = await run(process.argv.slice(2), { signal: controller.signal }); }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
