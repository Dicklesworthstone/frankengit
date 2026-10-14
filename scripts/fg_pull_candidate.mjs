#!/usr/bin/env node
// Read-only native candidate acquisition, private replay, and explicit drafting.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { capturePullCandidate, resolvePullCandidate, candidateResolutionChoices, RESOLUTION_CHOICE_BYTES,
  CANDIDATE_CAPTURE_SCHEMA, candidateInput, candidateCanonical } from './operator/pull_candidate_capture.mjs';
import { CandidateError, candidateFail, candidateJson, CANDIDATE_IO_LIMITS } from './operator/pull_candidate_io.mjs';
import { readCandidatePrivate, readCandidateToken, candidateDestination, candidateClock,
  saveCandidatePackage, loadCandidatePackage, saveCandidateJson, separateCandidateDestination } from './operator/pull_candidate_files.mjs';
import { draftCandidateReview } from './operator/pull_candidate_draft.mjs';
import { stageCandidateReview } from './operator/pull_candidate_stage.mjs';

export const HELP = `Usage: node scripts/fg_pull_candidate.mjs <capture|resolve|inspect|draft|stage> [options]

capture --input PRIVATE_JSON --token-file PRIVATE_TOKEN --output-dir NEW_PRIVATE_DIR
        [--ca-file PRIVATE_PEM] [--max-wire-bytes N] [--max-review-pages 1..8]
resolve --package PRIVATE_CONFLICT_DIR --sha256 INDEPENDENT_MANIFEST_HASH
        --choices PRIVATE_JSON --token-file PRIVATE_TOKEN --output-dir NEW_PRIVATE_DIR
        [--ca-file PRIVATE_PEM] [--max-wire-bytes N]
inspect --package PRIVATE_DIR --sha256 INDEPENDENT_MANIFEST_HASH
draft   --package PRIVATE_DIR --sha256 INDEPENDENT_MANIFEST_HASH
        --choices PRIVATE_JSON --output NEW_PRIVATE_JSON
stage   --package PRIVATE_DIR --sha256 INDEPENDENT_MANIFEST_HASH
        --choices PRIVATE_JSON --token-file PRIVATE_TOKEN --request-dir NEW_PRIVATE_DIR

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

Resolve requires one explicit choice for every original conflict: base, ours
(target), theirs (source), delete, or file. Use raw path_hex; file also requires
mode 100644 or 100755 and content_hex (empty/binary allowed). The original
package fixes all coordinates, commit metadata and merge method. The resolved
package is new and keeps the original conflict report and exact choices.

Only capture and resolve contact the native node; neither publishes a repository
mutation. Stage is offline: it fingerprints the explicit private credential and
saves a sender request directly from the pinned, inspected package, copying its
verified bundle without an intermediate draft or separately selected bundle file.
Inspect and draft accept no credential, URL override, strategy fallback or retry.
Pass the draft and saved candidate.bundle separately to remote_pull.mjs prepare,
or use stage to create that exact request in one operation. The sender
still requires separate original-key, candidate and merge-method confirmations.

POSIX owned private files/directories outside Git worktrees are required. Outputs
are create-only and must remain outside their source package. Preserve interrupted slots; they are not repaired or overwritten.
Keep the returned manifest hash separately. An unverified self-selected new root
cannot establish that transported bytes are your originally inspected candidate.

Exit 0: completed capture/resolution/inspection/draft/staging; 1: captured conflict or up-to-date
noncandidate; 2: local input/file/pin/draft refusal; 3: acquisition, save or output
failure after work began. See docs/PULL_CANDIDATE_PACKAGES.md for limits.
`;
function parse(args) {
  if (!Array.isArray(args) || args.length > 25 || args.some(v => typeof v !== 'string' || v.length > 4096) ||
      args.reduce((n, v) => n + v.length, 0) > 32768) candidateFail('invalid_candidate_arguments');
  const action = args[0], required = action === 'capture' ? ['input', 'token-file', 'output-dir']
    : action === 'resolve' ? ['package', 'sha256', 'choices', 'token-file', 'output-dir']
    : action === 'stage' ? ['package', 'sha256', 'choices', 'token-file', 'request-dir']
    : action === 'inspect' ? ['package', 'sha256'] : action === 'draft' ? ['package', 'sha256', 'choices', 'output'] : null;
  if (!required) candidateFail('unknown_candidate_command');
  const allowed = [...required, 'timeout-ms', ...(['capture', 'resolve'].includes(action) ? ['ca-file', 'max-wire-bytes'] : []),
    ...(action === 'capture' ? ['max-review-pages'] : [])], flags = {};
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
    if (action === 'stage') {
      const choices = candidateJson(await readCandidatePrivate(flags.choices, 512 * 1024, options()), 512 * 1024);
      const token = await readCandidateToken(flags['token-file'], options());
      completed = await stageCandidateReview({ package: flags.package, sha256: flags.sha256, choices,
        request_dir: flags['request-dir'] }, token, options());
      await output(candidateCanonical({ type: 'pull_candidate_staged', schema_version: 1, ...completed, published: false }));
      return 0;
    }
    const value = await loadCandidatePackage(flags.package, flags.sha256, options());
    if (action === 'resolve') {
      // Refuse unrelated or already resolved input before reading a credential.
      if (value.capture.schema !== CANDIDATE_CAPTURE_SCHEMA || value.capture.preparation.state !== 'conflicted') {
        candidateFail('original_candidate_conflicts_required');
      }
      const destination = separateCandidateDestination(await candidateDestination(flags['output-dir'], options()), value.path);
      // Hex expands raw choices by two; names/JSON have a separate bounded envelope.
      const maximum = 2 * RESOLUTION_CHOICE_BYTES + 64 * 1024;
      const choices = candidateResolutionChoices(candidateJson(await readCandidatePrivate(flags.choices, maximum, options()), maximum));
      const token = await readCandidateToken(flags['token-file'], options());
      const ca = flags['ca-file'] === undefined ? undefined : await readCandidatePrivate(flags['ca-file'], 128 * 1024, options());
      begun = true;
      const result = await resolvePullCandidate(value.capture, choices, token, { ...options(), ca,
        ...(flags['max-wire-bytes'] ? { maxWireBytes: Number(flags['max-wire-bytes']) } : {}) });
      completed = await saveCandidatePackage(destination, result.capture, result.bundle, options());
      await output(candidateCanonical({ type: 'pull_candidate_resolved', schema_version: 1, ...completed,
        source_package_sha256: value.sha256, usage: result.usage, published: false }));
      return 0;
    }
    if (action === 'inspect') {
      completed = { path: value.path, sha256: value.sha256, state: value.capture.preparation.state };
      await output(candidateCanonical({ type: 'pull_candidate_inspection', schema_version: 1, ...completed, capture: value.capture, published: false }));
      return 0;
    }
    const destination = separateCandidateDestination(await candidateDestination(flags.output, options()), value.path);
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
      completed, ...(error instanceof CandidateError && error.phase === 'staging' ? { request_dir: error.requestDir } : {}), published: false })); } catch { /* Synced package/request files are not erased by a broken pipe. */ }
    return begun || completed !== null || (error instanceof CandidateError && error.phase === 'staging') ? 3 : 2;
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort(), pipe = () => {};
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { process.exitCode = await run(process.argv.slice(2), { signal: controller.signal }); }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
