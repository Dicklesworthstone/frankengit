// Offline bridge from an independently pinned inspected package to the existing
// durable sender. No fresh source lookup or repository publication occurs here.
import { candidateCanonical } from './pull_candidate_capture.mjs';
import { candidateKeys, candidateJson, candidateToken, CandidateError, candidateFail } from './pull_candidate_io.mjs';
import { candidateClock, candidateDestination, loadCandidatePackage, separateCandidateDestination } from './pull_candidate_files.mjs';
import { draftCandidateReview } from './pull_candidate_draft.mjs';
import { preparePull, pullCanonical, pullHash, PullError } from './pull_command.mjs';
import { savePullIntent } from './pull_files.mjs';

export async function stageCandidateReview(input, token, options = {}) {
  try {
    const check = candidateClock(options), signal = options.signal; check(); candidateToken(token);
    candidateKeys(input, ['package', 'sha256', 'choices', 'request_dir']);
    for (const field of ['package', 'request_dir']) if (typeof input[field] !== 'string' ||
        !input[field].length || input[field].length > 4096 || input[field].includes('\0')) candidateFail('invalid_candidate_stage_path');
    if (typeof input.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(input.sha256)) candidateFail('candidate_package_pin_required');
    // Choices and paths detach before the first file read. The token is a bounded
    // primitive; it enters only the existing preparer's fingerprint calculation.
    const selected = candidateJson(Buffer.from(candidateCanonical(input)), 512 * 1024);
    const remaining = () => ({ timeoutMs: check(), signal });
    const destination = await candidateDestination(selected.request_dir, remaining());
    const verified = await loadCandidatePackage(selected.package, selected.sha256, remaining());
    separateCandidateDestination(destination, verified.path);
    const draft = await draftCandidateReview(verified.capture, verified.bundle, selected.choices, remaining());
    const intent = preparePull(draft, token, verified.bundle); check();
    const receipt = { request_dir: destination, package_sha256: verified.sha256,
      intent_sha256: pullHash(pullCanonical(intent)), key: intent.key, number: intent.number,
      action: intent.action, candidate_commit: intent.fields.candidate_commit,
      method: intent.fields.method ?? null, publication_attempted: false };
    // Begin one create-only local publication and drain it. The existing saver
    // snapshots the exact verified bundle, syncs it, then publishes intent.json.
    // A late signal must not hide its completed result or schedule another key.
    // Filesystem sync is not hard-preemptible and can exceed the intake deadline.
    try { await savePullIntent(destination, intent, verified.bundle); }
    catch {
      // A competitor may own this directory. Do not report our proposed key as
      // its saved key, erase the slot, or reconstruct an interrupted preparation.
      const error = new CandidateError('candidate_request_staging_incomplete', { phase: 'staging' });
      error.requestDir = destination; throw error;
    }
    return receipt;
  } catch (error) {
    if (error instanceof CandidateError) throw error;
    throw new CandidateError(error instanceof PullError ? error.code : 'candidate_request_staging_failed');
  }
}
