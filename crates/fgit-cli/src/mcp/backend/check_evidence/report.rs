//! Optional byte coordinates from the existing canonical workflow decoder.
//! The result is a locator into evidence, never an independent execution claim.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Span {
    pub(super) offset: usize,
    pub(super) bytes: usize,
}

#[cfg(target_os = "linux")]
pub(super) fn span(
    backend: &NodeTools,
    selected: &output::Selected<'_>,
    live: &dyn Fn() -> bool,
) -> Option<Span> {
    use fgit_crypto::{Digest, DigestAlgorithm, DigestBytes};
    use fgit_forge::event::workflow_check::WorkflowCheckConclusion;
    use fgit_runner::Commitment;
    use fgit_runner::coordinator::delivery::journal::history::decode_trusted_observation;

    let result = selected.result;
    let row = result.page.checks.first()?;
    let expected = Commitment::try_from_digest(Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&row.evidence_sha256).ok()?,
    ))
    .ok()?;
    let decoded = decode_trusted_observation(
        &result.evidence,
        expected,
        fgit_forge::event::workflow_check::MAX_CHECK_EVIDENCE_BYTES,
        live,
    )
    .ok()?;
    let report = decoded.report();
    if decoded.tenant() != backend.options.tenant
        || decoded.repository() != backend.options.repository
        || decoded.source_commit() != result.page.source_tip
        || decoded.run_id().commitment().digest().bytes().as_bytes() != row.run_id
        || decoded
            .attempt_id()
            .commitment()
            .digest()
            .bytes()
            .as_bytes()
            != row.attempt_id
        || report.graph.digest().bytes().as_bytes() != row.graph_root
        || report.jobs.len() != 1
        || report.jobs[0].id != row.job
        || (conclusion(report.jobs[0].outcome) != row.conclusion
            // Older publishers retained success as ActionRequired. Reading
            // their exact diagnostics must not upgrade the canonical fact.
            && !(row.conclusion == WorkflowCheckConclusion::ActionRequired
                && report.jobs[0].outcome == fgit_runner::workflow::JobOutcome::Succeeded))
    {
        return None;
    }
    let json = decoded.report_json();
    let offset = result.evidence.len().checked_sub(json.len())?;
    let prefix = offset.checked_sub(8)?;
    let bytes = u64::try_from(json.len()).ok()?.to_be_bytes();
    if result.evidence.get(offset..)? != json.as_bytes()
        || result.evidence.get(prefix..offset)? != bytes
    {
        return None;
    }
    Some(Span {
        offset,
        bytes: json.len(),
    })
}

#[cfg(target_os = "linux")]
const fn conclusion(
    outcome: fgit_runner::workflow::JobOutcome,
) -> fgit_forge::event::workflow_check::WorkflowCheckConclusion {
    use fgit_forge::event::workflow_check::WorkflowCheckConclusion;
    use fgit_runner::workflow::JobOutcome;
    match outcome {
        JobOutcome::Succeeded => WorkflowCheckConclusion::Success,
        JobOutcome::Skipped => WorkflowCheckConclusion::ActionRequired,
        JobOutcome::Failed | JobOutcome::Refused | JobOutcome::OutputLimit => {
            WorkflowCheckConclusion::Failure
        }
        JobOutcome::Cancelled => WorkflowCheckConclusion::Cancelled,
        JobOutcome::TimedOut => WorkflowCheckConclusion::TimedOut,
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn span(
    _backend: &NodeTools,
    _selected: &output::Selected<'_>,
    _live: &dyn Fn() -> bool,
) -> Option<Span> {
    None
}
