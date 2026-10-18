// Explicit decisions over a fully inspected candidate. No token, network,
// idempotency key, policy evaluation, or automatic publication is involved.
import { validateCandidateCapture, candidateCanonical } from './pull_candidate_capture.mjs';
import { candidateKeys, candidateJson, candidateFail, CandidateError } from './pull_candidate_io.mjs';
import { candidateClock } from './pull_candidate_files.mjs';
import { pullCommand, pullScope, PullError } from './pull_command.mjs';

export async function draftCandidateReview(input, bundle, selection, options = {}) {
  try {
    const check = candidateClock(options); check();
    if (bundle !== null && typeof SharedArrayBuffer !== 'undefined' && bundle?.buffer instanceof SharedArrayBuffer) candidateFail('candidate_shared_bundle_refused');
    if (!['approve', 'request-changes', 'merge'].includes(selection?.action)) candidateFail('explicit_candidate_draft_action_required');
    const merge = selection.action === 'merge';
    candidateKeys(selection, ['action', 'principal_id', 'candidate_commit', ...(merge ? ['method', 'required_reviewers'] : ['reason'])]);
    // Detach choices before the asynchronous native commit/body hash checks.
    const choice = candidateJson(Buffer.from(candidateCanonical(selection)), 512 * 1024);
    const checked = await validateCandidateCapture(input, bundle); check();
    const { capture, artifact, reviews } = checked;
    if (artifact === null) candidateFail('candidate_draft_requires_clean_inspection');
    if (choice.candidate_commit !== artifact.fields.candidate_commit) candidateFail('confirm_exact_inspected_candidate');
    if (merge && choice.method !== artifact.method) candidateFail('candidate_draft_method_changed');
    const scope = pullScope({ ...capture.request.scope, principal_id: choice.principal_id });
    const fields = Object.fromEntries(Object.entries(artifact.fields).filter(([key]) => key !== 'object_format')
      .map(([key, value]) => [key, typeof value === 'number' ? String(value) : value]));
    if (merge) {
      fields.method = choice.method; fields.required_reviewers = choice.required_reviewers;
    } else {
      // Absence is meaningful only because validation exhausted every retained
      // reviewer page. Stale prior votes still own their exact stream version.
      fields.expected_version = String(reviews.find(row => row.reviewer === scope.principal_id)?.version ?? 0);
      fields.reason = choice.reason;
    }
    const command = pullCommand(capture.request.number, choice.action, fields, scope.object_format);
    if (merge && command.fields.required_reviewers.includes(scope.principal_id)) candidateFail('candidate_submitter_is_required_reviewer');
    check();
    return { endpoint: capture.request.endpoint, scope, number: command.number, action: command.action, fields: command.fields };
  } catch (error) {
    if (error instanceof CandidateError) throw error;
    throw new CandidateError(error instanceof PullError ? error.code : 'invalid_candidate_draft');
  }
}
