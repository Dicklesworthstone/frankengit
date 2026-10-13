// Convert a complete retained read into input for remote_pull.mjs prepare.
// This does not select a review decision, generate a candidate or authorize a merge.
import { validateReviewCapture, reviewFields, reviewPrincipal, reviewText, reviewU64,
  reviewOid, failReview } from './pull_review_snapshot.mjs';
const U64 = 18446744073709551615n;
function writableVersion(value, minimum = 0n) {
  reviewU64(value, minimum); if (BigInt(value) === U64) failReview('review_version_exhausted'); return value;
}
function nativeInput(value, format) { return reviewOid(value, format).slice(format.length + 1); }
function selectedCandidate(value, format) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(value) || /^0+$/.test(value)) failReview('invalid_review_candidate');
  return value;
}
export function draftPullReview(input, choice) {
  const capture = validateReviewCapture(input), action = choice?.action;
  if (!['approve', 'request-changes', 'withdraw', 'merge'].includes(action)) failReview('explicit_review_action_required');
  const merge = action === 'merge', withdraw = action === 'withdraw';
  reviewFields(choice, ['action', 'principal_id', ...(withdraw ? [] : ['merge_base', 'candidate_commit']),
    ...(merge ? ['method', 'required_reviewers'] : ['reason'])]);
  const principal = reviewPrincipal(choice.principal_id), { selection, pull } = capture;
  if (!pull.found) failReview('review_pull_missing');
  const row = capture.review_pages.flatMap(page => page.reviews).find(row => row.reviewer === principal);
  let subject, candidate;
  if (withdraw) {
    // Withdrawal retains the previously recorded subject, even if tips, PR
    // version or policy have since changed. Never withdraw an invented vote.
    if (!row || row.candidate === null || row.decision === 'withdraw') failReview('no_candidate_review_to_withdraw');
    subject = row.subject; candidate = row.candidate;
  } else {
    if (pull.pull_request.state !== 'open' || pull.pull_request.data === null) failReview('review_requires_open_metadata');
    subject = { ...pull.pull_request.data, pull_request_version: pull.pull_request.version,
      policy_epoch: capture.review_pages[0].policy_epoch };
    candidate = { merge_base: `${selection.scope.object_format}:${selectedCandidate(choice.merge_base, selection.scope.object_format)}`,
      candidate_commit: `${selection.scope.object_format}:${selectedCandidate(choice.candidate_commit, selection.scope.object_format)}` };
  }
  const fields = { pull_request_version: writableVersion(subject.pull_request_version, 1n),
    policy_epoch: subject.policy_epoch };
  for (const side of ['source', 'target']) {
    if (subject[`${side}_ref`] === null) failReview('byte_only_review_form_unsupported');
    fields[`${side}_ref`] = subject[`${side}_ref`];
  }
  for (const side of ['source', 'target']) fields[`${side}_tip`] = nativeInput(subject[`${side}_tip`], selection.scope.object_format);
  for (const name of ['merge_base', 'candidate_commit']) fields[name] = nativeInput(candidate[name], selection.scope.object_format);
  if (merge) {
    if (!['merge-commit', 'squash'].includes(choice.method)) failReview('explicit_review_merge_method_required');
    if (!Array.isArray(choice.required_reviewers) || choice.required_reviewers.length < 1 || choice.required_reviewers.length > 32) failReview('invalid_reviewers');
    const reviewers = Array.from(choice.required_reviewers, reviewPrincipal).sort();
    if (new Set(reviewers).size !== reviewers.length || reviewers.includes(principal)) failReview('invalid_reviewers');
    fields.required_reviewers = reviewers; fields.method = choice.method;
    // The explicit set is not inferred from displayed approvals. Eligibility,
    // independence, candidate validity and current protection remain native.
  } else {
    fields.expected_version = writableVersion(row?.version ?? '0', withdraw ? 1n : 0n);
    fields.reason = reviewText(choice.reason, 4096);
    if (!fields.reason.trim()) failReview('empty_review_reason');
  }
  return { endpoint: selection.endpoint, scope: { tenant_id: selection.scope.tenant_id,
    repository_id: selection.scope.repository_id, repository_incarnation: selection.scope.repository_incarnation,
    principal_id: principal, object_format: selection.scope.object_format }, number: selection.number, action, fields };
}
