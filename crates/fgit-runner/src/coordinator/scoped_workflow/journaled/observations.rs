//! The receiving side of persisted trusted-workflow evidence.
//!
//! A journal checksum proves byte integrity, not that its evidence describes
//! the proposed job. This reader validates the existing observation frame,
//! reconstructs typed reports, and binds a completed proposal to those exact
//! source/run/attempt/limit coordinates. It never authenticates a producer,
//! issues a CheckReceipt, resumes execution, or upgrades a local success.

use super::super::{
    ObservationBinding, TrustedWorkflowReceipt, OBSERVATION_DOMAIN,
    CoordinatorExecutionProfile,
};
use crate::coordinator::delivery::{CheckDeliveryBatch, CheckDeliveryRefusal};
use crate::workflow::{JobOutcome, WorkflowReport, MAX_JOBS, MAX_STEPS};
use crate::{
    AttemptId, CheckRunConclusion, CheckRunStatus, Commitment, RunnerText, TrustDomain,
    WorkflowRunId,
};
use fgit_crypto::{Digest, DigestAlgorithm, DigestBytes};
use fgit_types::{GitOid, GitOidSha1, GitOidSha256, RepositoryId, TenantId};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

mod json;

/// Same finite upper envelope as the existing custody evidence format.
pub const MAX_OBSERVATION_BYTES: usize = 64 * 1024 * 1024;
const MAX_JOB_BYTES: usize = 1024;

/// Errors do not reflect scripts, logs, untrusted identifiers, or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationRefusal {
    InvalidLimits,
    RecordTooLarge,
    CommitmentMismatch,
    InvalidFrame,
    InvalidReport,
    UnsupportedProfile,
    BindingMismatch,
    FactNotCompleted,
    EvidenceMissing,
    Cancelled,
    AllocationFailed,
    Journal(CheckDeliveryRefusal),
}
impl std::fmt::Display for ObservationRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "local workflow evidence refused: {self:?}")
    }
}
impl std::error::Error for ObservationRefusal {}
impl From<CheckDeliveryRefusal> for ObservationRefusal {
    fn from(error: CheckDeliveryRefusal) -> Self { Self::Journal(error) }
}

/// A commitment-checked local observation, NOT an authenticated check result.
/// Fields are immutable. A multi-job workflow record cannot substitute for a
/// single-job proposal body; a one-job workflow can have identical full/job bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLocalObservation {
    evidence: Commitment,
    receipt: TrustedWorkflowReceipt,
}
impl VerifiedLocalObservation {
    pub const fn evidence(&self) -> Commitment { self.evidence }
    pub const fn report(&self) -> &WorkflowReport { &self.receipt.report }
    pub const fn run_id(&self) -> WorkflowRunId { self.receipt.binding.run }
    pub const fn attempt_id(&self) -> AttemptId { self.receipt.binding.attempt }
    pub const fn tenant(&self) -> TenantId { self.receipt.binding.tenant }
    pub const fn repository(&self) -> RepositoryId { self.receipt.binding.repository }
    pub const fn authority_head(&self) -> Commitment { self.receipt.binding.head }
    pub const fn source_commit(&self) -> GitOid { self.receipt.binding.source }
    pub const fn logical_now(&self) -> u64 { self.receipt.logical_now }
    pub fn job_attempt(&self, job: &str) -> Option<u32> {
        self.receipt.attempts.get(job).copied()
    }
    pub fn requires_containment(&self) -> bool {
        self.report().jobs.iter().any(|job| job.requires_containment())
    }
    /// Existing deterministic report JSON, including authoritative_check=false
    /// and byte-preserving hexadecimal stdout/stderr. No terminal control bytes
    /// from logs are interpreted by this rendering.
    pub fn report_json(&self) -> String { self.report().to_json() }
}

/// Decode the existing observation format, including exact nanosecond limits
/// that the display JSON alone cannot reconstruct. `expected` must come from
/// the caller's selected proposal or retained receipt, not from these bytes.
///
/// This is deliberately NOT a general JSON reader: only the versioned emitter's
/// exact grammar is accepted. Duplicate/unknown fields, alternate escaping,
/// reordered fields, forged summary bits, and any trailing suffix refuse.
/// Allocation, output, collection and string ceilings precede their growth.
/// The caller still authenticates the producer and authorizes log disclosure.
pub fn decode_trusted_observation(
    bytes: &[u8],
    expected: Commitment,
    maximum_bytes: usize,
    live: &dyn Fn() -> bool,
) -> Result<VerifiedLocalObservation, ObservationRefusal> {
    if maximum_bytes == 0 || maximum_bytes > MAX_OBSERVATION_BYTES {
        return Err(ObservationRefusal::InvalidLimits);
    }
    checkpoint(live)?;
    if bytes.len() > maximum_bytes { return Err(ObservationRefusal::RecordTooLarge); }
    if Commitment::of_bytes(bytes) != expected {
        return Err(ObservationRefusal::CommitmentMismatch);
    }
    checkpoint(live)?;
    let mut input = FrameInput(bytes);
    if input.take(OBSERVATION_DOMAIN.len())? != OBSERVATION_DOMAIN {
        return Err(ObservationRefusal::InvalidFrame);
    }
    let run = WorkflowRunId(input.root()?);
    let attempt = AttemptId(input.root()?);
    let head = input.root()?;
    let tenant = TenantId::from_bytes(input.array()?);
    let repository = RepositoryId::from_bytes(input.array()?);
    let source = match input.byte()? {
        1 => GitOid::Sha1(GitOidSha1::from_bytes(input.array()?)),
        2 => GitOid::Sha256(GitOidSha256::from_bytes(input.array()?)),
        _ => return Err(ObservationRefusal::InvalidFrame),
    };
    let trust = TrustDomain::new(RunnerText::parse("observation.trust", input.text(256)?)
        .map_err(|_| ObservationRefusal::InvalidFrame)?);
    let step_timeout = input.duration()?;
    let run_timeout = input.duration()?;
    let logical_now = input.u64()?;
    let count = input.size()?;
    if count == 0 || count > MAX_JOBS { return Err(ObservationRefusal::InvalidFrame); }
    let mut attempts = BTreeMap::new();
    let mut previous: Option<String> = None;
    for _ in 0..count {
        checkpoint(live)?;
        let name = input.text(MAX_JOB_BYTES)?;
        if !valid_job(name) || previous.as_ref().is_some_and(|last| last.as_str() >= name) {
            return Err(ObservationRefusal::InvalidFrame);
        }
        let attempt = u32::from_be_bytes(input.array()?);
        previous = Some(name.to_owned());
        attempts.insert(name.to_owned(), attempt);
    }
    let encoded_report = input.field(maximum_bytes)?;
    if !input.0.is_empty() { return Err(ObservationRefusal::InvalidFrame); }
    let report = json::report(encoded_report, step_timeout, run_timeout, live)?;
    if report.jobs.len() != attempts.len() { return Err(ObservationRefusal::InvalidReport); }
    let mut seen = BTreeSet::new();
    let mut steps = 0usize;
    for job in &report.jobs {
        checkpoint(live)?;
        let attempt = *attempts.get(&job.id).ok_or(ObservationRefusal::InvalidReport)?;
        if !seen.insert(&job.id) || !valid_job(&job.id)
            || (attempt == 0 && (!job.steps.is_empty() || job.outcome == JobOutcome::Succeeded))
            || (job.outcome == JobOutcome::Skipped && (!job.steps.is_empty() || job.failure.is_some() || attempt != 0))
        { return Err(ObservationRefusal::InvalidReport); }
        steps = steps.checked_add(job.steps.len()).ok_or(ObservationRefusal::InvalidReport)?;
        if steps > MAX_STEPS { return Err(ObservationRefusal::InvalidReport); }
    }
    let receipt = TrustedWorkflowReceipt {
        binding: ObservationBinding { run, attempt, tenant, repository, head, source, trust },
        report, attempts, logical_now,
    };
    // The emitter is the single source of canonical byte spelling. This also
    // rejects a false "succeeded" bit and millisecond/nanosecond disagreement.
    checkpoint(live)?;
    if receipt.frame() != bytes { return Err(ObservationRefusal::InvalidFrame); }
    checkpoint(live)?;
    Ok(VerifiedLocalObservation { evidence: expected, receipt })
}

/// Validate one completed proposal against one exact, single-job observation.
/// Success and skipped jobs remain ActionRequired. This returns no check grant
/// and does not accept evidence for a different index merely because its hash
/// happens to be retained in the same journal.
pub fn verify_trusted_job(
    batch: &CheckDeliveryBatch,
    fact_index: usize,
    evidence: &[u8],
    maximum_bytes: usize,
    live: &dyn Fn() -> bool,
) -> Result<VerifiedLocalObservation, ObservationRefusal> {
    checkpoint(live)?;
    let CoordinatorExecutionProfile::TrustedWorkflow { source, limits } = batch.execution_profile() else {
        return Err(ObservationRefusal::UnsupportedProfile);
    };
    let fact = batch.facts().get(fact_index).ok_or(ObservationRefusal::FactNotCompleted)?;
    if fact.status != CheckRunStatus::Completed { return Err(ObservationRefusal::FactNotCompleted); }
    let root = fact.receipt_commitment.ok_or(ObservationRefusal::EvidenceMissing)?;
    let observed = decode_trusted_observation(evidence, root, maximum_bytes, live)?;
    let binding = &observed.receipt.binding;
    let report = observed.report();
    if binding.run != batch.run_id() || binding.attempt != batch.attempt_id()
        || binding.tenant != batch.tenant() || binding.repository != batch.repository()
        || binding.head != batch.authority_head() || binding.source != batch.source_commit()
        || &binding.trust != batch.trust_domain()
        || report.source != source || report.graph != batch.graph_commitment() || report.limits != limits
        || observed.logical_now() != fact.timestamp_millis || report.jobs.len() != 1
        || report.jobs[0].id != fact.job_id || fact.run_id != batch.run_id()
        || fact.conclusion != Some(conclusion(report.jobs[0].outcome))
    { return Err(ObservationRefusal::BindingMismatch); }
    Ok(observed)
}

fn conclusion(outcome: JobOutcome) -> CheckRunConclusion {
    // Must agree with CoordinatedExecutor::observe_job. Round-trip tests execute
    // the production producer rather than using this mapping to make fixtures.
    match outcome {
        JobOutcome::Succeeded | JobOutcome::Skipped => CheckRunConclusion::ActionRequired,
        JobOutcome::Failed | JobOutcome::Refused | JobOutcome::OutputLimit => CheckRunConclusion::Failure,
        JobOutcome::Cancelled => CheckRunConclusion::Cancelled,
        JobOutcome::TimedOut => CheckRunConclusion::TimedOut,
    }
}
fn checkpoint(live: &dyn Fn() -> bool) -> Result<(), ObservationRefusal> {
    if live() { Ok(()) } else { Err(ObservationRefusal::Cancelled) }
}
fn valid_job(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_JOB_BYTES && !name.chars().any(char::is_control)
}
fn commitment(bytes: &[u8]) -> Result<Commitment, ObservationRefusal> {
    let digest = Digest::new(DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(bytes).map_err(|_| ObservationRefusal::InvalidFrame)?);
    Commitment::try_from_digest(digest).map_err(|_| ObservationRefusal::InvalidFrame)
}
struct FrameInput<'a>(&'a [u8]);
impl<'a> FrameInput<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ObservationRefusal> {
        let result = self.0.get(..count).ok_or(ObservationRefusal::InvalidFrame)?;
        self.0 = &self.0[count..]; Ok(result)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ObservationRefusal> {
        self.take(N)?.try_into().map_err(|_| ObservationRefusal::InvalidFrame)
    }
    fn byte(&mut self) -> Result<u8, ObservationRefusal> { Ok(self.array::<1>()?[0]) }
    fn u64(&mut self) -> Result<u64, ObservationRefusal> { Ok(u64::from_be_bytes(self.array()?)) }
    fn size(&mut self) -> Result<usize, ObservationRefusal> {
        usize::try_from(self.u64()?).map_err(|_| ObservationRefusal::InvalidFrame)
    }
    fn root(&mut self) -> Result<Commitment, ObservationRefusal> { commitment(self.take(32)?) }
    fn field(&mut self, maximum: usize) -> Result<&'a [u8], ObservationRefusal> {
        let count = self.size()?;
        if count > maximum { return Err(ObservationRefusal::RecordTooLarge); }
        self.take(count)
    }
    fn text(&mut self, maximum: usize) -> Result<&'a str, ObservationRefusal> {
        std::str::from_utf8(self.field(maximum)?).map_err(|_| ObservationRefusal::InvalidFrame)
    }
    fn duration(&mut self) -> Result<Duration, ObservationRefusal> {
        let nanos = u128::from_be_bytes(self.array()?);
        // Reject out-of-profile durations before narrowing or constructing.
        if nanos == 0 || nanos > 3_600_000_000_000 { return Err(ObservationRefusal::InvalidReport); }
        Ok(Duration::from_nanos(u64::try_from(nanos).map_err(|_| ObservationRefusal::InvalidReport)?))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod journal_tests;
