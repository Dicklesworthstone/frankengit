//! Public, evidence-bound cancellation of one complete Intent Run.
//!
//! The internal [`crate::cancellation`] module owns the request → drain →
//! finalize state machine. This module owns the public construction boundary
//! and commits the exact [`crate::IntentRunCommitment`] plus any optional
//! [`crate::ActiveClaimContinuityReceipt`] into the request and completion
//! identities.
//!
//! Cancellation is intentionally asymmetric with handoff. Handoff continues a
//! plan and therefore needs proof that its context stayed applicable.
//! Cancellation is a conservative stop operation and must remain available
//! precisely when authority-adjacent context, conflicts, evidence, peers, or
//! obligations changed. [`RunCancellationIntent::request`] therefore binds the
//! exact latest situation and complete reconciliation report without requiring
//! context equivalence. [`RunCancellationIntent::request_with_continuity`] may
//! additionally retain a continuity proof when only logical time advanced.
//!
//! This facade performs no task mutation, process reap, workspace cleanup,
//! effect transition, downstream probe, or canonical publication.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::Digest;

use crate::{
    ActiveClaimContinuityReceipt, ActiveClaimContinuityReceiptId, ActiveClaimContinuityRefusal,
    ActiveTaskClaim, AgentInstanceId, AgentSituationReceipt, CancellationContainmentEvidence,
    CancellationDebtTransfer, IntentRun, IntentRunCommitment, IntentRunIdentityRefusal,
    LogicalTime, RunCancellationRefusal, RunCancellationState, RunId, RunReconciliationReport,
    RunReconciliationReportId, SituationId, TaskClaimCancellationProjection,
};

const PUBLIC_CANCELLATION_DOMAIN: &[u8] = b"frankengit.agent.public-run-cancellation/v2\0";
const PUBLIC_COMPLETION_DOMAIN: &[u8] = b"frankengit.agent.public-run-cancellation-completion/v2\0";

/// Stable identity of one publicly constructible cancellation request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunCancellationId([u8; 32]);

impl RunCancellationId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RunCancellationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("run-cancellation:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable identity of one publicly completed cancellation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunCancellationCompletionId([u8; 32]);

impl RunCancellationCompletionId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RunCancellationCompletionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("run-cancellation-completion:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Immutable public request to stop one run and drain all responsibilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCancellationIntent {
    cancellation_id: RunCancellationId,
    run_commitment: IntentRunCommitment,
    claim_continuity_id: Option<ActiveClaimContinuityReceiptId>,
    inner: crate::cancellation::RunCancellationIntent,
}

impl RunCancellationIntent {
    /// Requests cancellation from one exact latest situation and effect inventory.
    ///
    /// An active claim does not make continuity a prerequisite. Context change
    /// may itself be the reason cancellation is necessary. The request freezes
    /// the supplied situation, claim, task generation, complete run identity,
    /// and complete run effect inventory; completion still requires explicit
    /// task release or transfer and terminal settlement, debt transfer, or
    /// containment.
    ///
    /// # Errors
    ///
    /// Refuses complete-run substitution before invoking the internal engine,
    /// then preserves every typed run, authority, report, claim,
    /// task-generation, requester, bound, and canonical-framing refusal.
    pub fn request(
        situation: &AgentSituationReceipt,
        run: &IntentRun,
        initial_reconciliation: RunReconciliationReport,
        active_claim: Option<ActiveTaskClaim>,
        requested_by: AgentInstanceId,
        reason_root: Digest,
    ) -> Result<Self, RunCancellationRequestRefusal> {
        let run_commitment =
            validate_request_basis(situation, run, &initial_reconciliation, active_claim)?;
        let inner = crate::cancellation::RunCancellationIntent::request(
            situation,
            run,
            initial_reconciliation,
            active_claim,
            requested_by,
            reason_root,
        )
        .map_err(RunCancellationRequestRefusal::Cancellation)?;
        Self::finish(inner, run_commitment, None)
    }

    /// Requests cancellation while additionally retaining a full-context
    /// continuity proof.
    ///
    /// This stronger evidence is useful when only logical time advanced. It is
    /// never required to stop a run. The receipt is revalidated against the
    /// active claim, later situation, and complete run, then committed into the
    /// public request identity.
    ///
    /// # Errors
    ///
    /// Refuses complete-run, continuity, or cancellation-state substitutions
    /// and unrepresentable public framing.
    pub fn request_with_continuity(
        later_situation: &AgentSituationReceipt,
        run: &IntentRun,
        initial_reconciliation: RunReconciliationReport,
        active_claim: ActiveTaskClaim,
        continuity: ActiveClaimContinuityReceipt,
        requested_by: AgentInstanceId,
        reason_root: Digest,
    ) -> Result<Self, RunCancellationRequestRefusal> {
        let run_commitment = validate_request_basis(
            later_situation,
            run,
            &initial_reconciliation,
            Some(active_claim),
        )?;
        validate_continuity_source(active_claim, continuity)?;
        continuity
            .validate_for(active_claim, later_situation, run)
            .map_err(RunCancellationRequestRefusal::Continuity)?;
        let inner = crate::cancellation::RunCancellationIntent::request(
            later_situation,
            run,
            initial_reconciliation,
            Some(active_claim),
            requested_by,
            reason_root,
        )
        .map_err(RunCancellationRequestRefusal::Cancellation)?;
        Self::finish(inner, run_commitment, Some(continuity.receipt_id()))
    }

    fn finish(
        inner: crate::cancellation::RunCancellationIntent,
        run_commitment: IntentRunCommitment,
        claim_continuity_id: Option<ActiveClaimContinuityReceiptId>,
    ) -> Result<Self, RunCancellationRequestRefusal> {
        let cancellation_id = RunCancellationId(public_cancellation_commitment(
            inner.cancellation_id().as_bytes(),
            run_commitment,
            claim_continuity_id,
        )?);
        Ok(Self {
            cancellation_id,
            run_commitment,
            claim_continuity_id,
            inner,
        })
    }

    /// Completes cancellation from a later complete effect inventory.
    ///
    /// The final report must retain the exact complete run frozen by the
    /// request. The internal engine then preserves exact effect membership,
    /// immutable effect identity, monotone evidence and consumed budget,
    /// explicit task release or transfer, and named transfer/containment
    /// evidence for unresolved debt.
    ///
    /// # Errors
    ///
    /// Refuses complete-run substitution before preserving every inner typed
    /// cancellation refusal.
    pub fn complete(
        &self,
        final_reconciliation: RunReconciliationReport,
        task_claim_resolution: Option<TaskClaimCancellationProjection>,
        debt_transfers: Vec<CancellationDebtTransfer>,
        containment_evidence: Vec<CancellationContainmentEvidence>,
    ) -> Result<RunCancellationCompletion, RunCancellationCompletionRefusal> {
        if final_reconciliation.run_commitment() != self.run_commitment {
            return Err(RunCancellationCompletionRefusal::RunCommitmentMismatch {
                expected: self.run_commitment,
                observed: final_reconciliation.run_commitment(),
            });
        }
        let inner = self
            .inner
            .complete(
                final_reconciliation,
                task_claim_resolution,
                debt_transfers,
                containment_evidence,
            )
            .map_err(RunCancellationCompletionRefusal::Cancellation)?;
        let completion_id = RunCancellationCompletionId(public_completion_commitment(
            self.cancellation_id,
            inner.completion_id().as_bytes(),
        )?);
        Ok(RunCancellationCompletion {
            completion_id,
            cancellation_id: self.cancellation_id,
            run_commitment: self.run_commitment,
            inner,
        })
    }

    /// Stable cancellation-request identity.
    #[must_use]
    pub const fn cancellation_id(&self) -> RunCancellationId {
        self.cancellation_id
    }

    /// Complete machine-enforced run being cancelled.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Optional full-context continuity evidence retained by the request.
    #[must_use]
    pub const fn claim_continuity_id(&self) -> Option<ActiveClaimContinuityReceiptId> {
        self.claim_continuity_id
    }

    /// Run being cancelled.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.inner.run_id()
    }

    /// Situation observed when cancellation was requested.
    #[must_use]
    pub const fn source_situation_id(&self) -> SituationId {
        self.inner.source_situation_id()
    }

    /// Task generation frozen by the request, when observed.
    #[must_use]
    pub const fn source_task_projection_generation(&self) -> Option<[u8; 32]> {
        self.inner.source_task_projection_generation()
    }

    /// Active claim frozen by the request, when present.
    #[must_use]
    pub const fn active_claim(&self) -> Option<ActiveTaskClaim> {
        self.inner.active_claim()
    }

    /// Agent executor that requested cancellation.
    #[must_use]
    pub const fn requested_by(&self) -> AgentInstanceId {
        self.inner.requested_by()
    }

    /// Logical request instant.
    #[must_use]
    pub const fn requested_at(&self) -> LogicalTime {
        self.inner.requested_at()
    }

    /// Commitment to the cancellation reason and request evidence.
    #[must_use]
    pub const fn reason_root(&self) -> Digest {
        self.inner.reason_root()
    }

    /// Complete effect inventory frozen at request time.
    #[must_use]
    pub const fn initial_reconciliation(&self) -> &RunReconciliationReport {
        self.inner.initial_reconciliation()
    }
}

/// Verified terminal cancellation record retaining its public request identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCancellationCompletion {
    completion_id: RunCancellationCompletionId,
    cancellation_id: RunCancellationId,
    run_commitment: IntentRunCommitment,
    inner: crate::cancellation::RunCancellationCompletion,
}

impl RunCancellationCompletion {
    /// Stable public completion identity.
    #[must_use]
    pub const fn completion_id(&self) -> RunCancellationCompletionId {
        self.completion_id
    }

    /// Public cancellation request completed.
    #[must_use]
    pub const fn cancellation_id(&self) -> RunCancellationId {
        self.cancellation_id
    }

    /// Complete machine-enforced run that was cancelled.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Cancelled run.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.inner.run_id()
    }

    /// Logical completion instant.
    #[must_use]
    pub const fn completed_at(&self) -> LogicalTime {
        self.inner.completed_at()
    }

    /// Initial frozen effect inventory.
    #[must_use]
    pub const fn initial_report_id(&self) -> RunReconciliationReportId {
        self.inner.initial_report_id()
    }

    /// Complete final effect inventory.
    #[must_use]
    pub const fn final_reconciliation(&self) -> &RunReconciliationReport {
        self.inner.final_reconciliation()
    }

    /// Task-claim release or transfer evidence, when a claim was active.
    #[must_use]
    pub const fn task_claim_resolution(&self) -> Option<TaskClaimCancellationProjection> {
        self.inner.task_claim_resolution()
    }

    /// Explicit escalation transfers.
    #[must_use]
    pub fn debt_transfers(&self) -> &[CancellationDebtTransfer] {
        self.inner.debt_transfers()
    }

    /// Explicit leak-containment evidence.
    #[must_use]
    pub fn containment_evidence(&self) -> &[CancellationContainmentEvidence] {
        self.inner.containment_evidence()
    }

    /// Terminal cancellation interpretation.
    #[must_use]
    pub const fn state(&self) -> RunCancellationState {
        self.inner.state()
    }
}

/// Why public cancellation request construction failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunCancellationRequestRefusal {
    /// Complete run identity could not be produced.
    RunIdentity(IntentRunIdentityRefusal),
    /// Situation carries another complete run under the same or another ID.
    SituationRunCommitmentMismatch {
        /// Commitment computed from the supplied run.
        expected: IntentRunCommitment,
        /// Commitment retained by the latest situation.
        observed: Option<IntentRunCommitment>,
    },
    /// Active claim belongs to another complete run.
    ActiveClaimRunCommitmentMismatch {
        /// Commitment computed from the supplied run.
        expected: IntentRunCommitment,
        /// Commitment retained by the active claim.
        observed: IntentRunCommitment,
    },
    /// Initial effect inventory belongs to another complete run.
    InitialReportRunCommitmentMismatch {
        /// Commitment computed from the supplied run.
        expected: IntentRunCommitment,
        /// Commitment retained by the report.
        observed: IntentRunCommitment,
    },
    /// Optional full-context continuity evidence was substituted or stale.
    Continuity(ActiveClaimContinuityRefusal),
    /// Internal cancellation request validation refused the inputs.
    Cancellation(RunCancellationRefusal),
    /// Public evidence-carrying identity framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for RunCancellationRequestRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunIdentity(refusal) => {
                write!(formatter, "cancellation run identity refused: {refusal}")
            }
            Self::SituationRunCommitmentMismatch { expected, observed } => write!(
                formatter,
                "cancellation situation run commitment {observed:?} differs from {expected}"
            ),
            Self::ActiveClaimRunCommitmentMismatch { expected, observed } => write!(
                formatter,
                "cancellation active-claim run commitment {observed} differs from {expected}"
            ),
            Self::InitialReportRunCommitmentMismatch { expected, observed } => write!(
                formatter,
                "cancellation report run commitment {observed} differs from {expected}"
            ),
            Self::Continuity(refusal) => {
                write!(formatter, "cancellation continuity refused: {refusal}")
            }
            Self::Cancellation(refusal) => {
                write!(formatter, "cancellation request refused: {refusal}")
            }
            Self::Codec(refusal) => {
                write!(formatter, "public cancellation framing refused: {refusal}")
            }
        }
    }
}

impl core::error::Error for RunCancellationRequestRefusal {}

impl From<IntentRunIdentityRefusal> for RunCancellationRequestRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<CodecRefusal> for RunCancellationRequestRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

impl PartialEq<RunCancellationRefusal> for RunCancellationRequestRefusal {
    fn eq(&self, other: &RunCancellationRefusal) -> bool {
        matches!(self, Self::Cancellation(refusal) if refusal == other)
    }
}

impl PartialEq<RunCancellationRequestRefusal> for RunCancellationRefusal {
    fn eq(&self, other: &RunCancellationRequestRefusal) -> bool {
        other == self
    }
}

/// Why public cancellation completion failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunCancellationCompletionRefusal {
    /// Final effect inventory belongs to another complete run.
    RunCommitmentMismatch {
        /// Complete run frozen by the request.
        expected: IntentRunCommitment,
        /// Complete run retained by the final report.
        observed: IntentRunCommitment,
    },
    /// Internal cancellation completion refused the lifecycle evidence.
    Cancellation(RunCancellationRefusal),
}

impl fmt::Display for RunCancellationCompletionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunCommitmentMismatch { expected, observed } => write!(
                formatter,
                "final cancellation report run commitment {observed} differs from {expected}"
            ),
            Self::Cancellation(refusal) => {
                write!(formatter, "cancellation completion refused: {refusal}")
            }
        }
    }
}

impl core::error::Error for RunCancellationCompletionRefusal {}

impl From<RunCancellationRefusal> for RunCancellationCompletionRefusal {
    fn from(value: RunCancellationRefusal) -> Self {
        Self::Cancellation(value)
    }
}

impl PartialEq<RunCancellationRefusal> for RunCancellationCompletionRefusal {
    fn eq(&self, other: &RunCancellationRefusal) -> bool {
        matches!(self, Self::Cancellation(refusal) if refusal == other)
    }
}

impl PartialEq<RunCancellationCompletionRefusal> for RunCancellationRefusal {
    fn eq(&self, other: &RunCancellationCompletionRefusal) -> bool {
        other == self
    }
}

fn validate_request_basis(
    situation: &AgentSituationReceipt,
    run: &IntentRun,
    initial_reconciliation: &RunReconciliationReport,
    active_claim: Option<ActiveTaskClaim>,
) -> Result<IntentRunCommitment, RunCancellationRequestRefusal> {
    let run_commitment = run.commitment()?;
    if situation.intent_run_commitment() != Some(run_commitment) {
        return Err(
            RunCancellationRequestRefusal::SituationRunCommitmentMismatch {
                expected: run_commitment,
                observed: situation.intent_run_commitment(),
            },
        );
    }
    if let Some(claim) = active_claim
        && claim.run_commitment() != run_commitment {
            return Err(
                RunCancellationRequestRefusal::ActiveClaimRunCommitmentMismatch {
                    expected: run_commitment,
                    observed: claim.run_commitment(),
                },
            );
        }
    if initial_reconciliation.run_commitment() != run_commitment {
        return Err(
            RunCancellationRequestRefusal::InitialReportRunCommitmentMismatch {
                expected: run_commitment,
                observed: initial_reconciliation.run_commitment(),
            },
        );
    }
    Ok(run_commitment)
}

fn validate_continuity_source(
    active_claim: ActiveTaskClaim,
    continuity: ActiveClaimContinuityReceipt,
) -> Result<(), RunCancellationRequestRefusal> {
    let expected = active_claim.situation_id();
    let observed = *continuity.from_situation_id().as_bytes();
    if expected != observed {
        return Err(RunCancellationRequestRefusal::Continuity(
            ActiveClaimContinuityRefusal::ActivationSituationMismatch { expected, observed },
        ));
    }
    Ok(())
}

fn public_cancellation_commitment(
    inner_cancellation_id: &[u8; 32],
    run_commitment: IntentRunCommitment,
    claim_continuity_id: Option<ActiveClaimContinuityReceiptId>,
) -> Result<[u8; 32], RunCancellationRequestRefusal> {
    let mut encoder = Encoder::with_capacity(192);
    encoder.write_bytes("public_run_cancellation_domain", PUBLIC_CANCELLATION_DOMAIN)?;
    encoder.write_raw(inner_cancellation_id);
    encoder.write_raw(run_commitment.as_bytes());
    match claim_continuity_id {
        Some(receipt_id) => {
            encoder.write_bool(true);
            encoder.write_raw(receipt_id.as_bytes());
        }
        None => encoder.write_bool(false),
    }
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn public_completion_commitment(
    cancellation_id: RunCancellationId,
    inner_completion_id: &[u8; 32],
) -> Result<[u8; 32], RunCancellationCompletionRefusal> {
    let mut encoder = Encoder::with_capacity(160);
    encoder.write_bytes(
        "public_run_cancellation_completion_domain",
        PUBLIC_COMPLETION_DOMAIN,
    )?;
    encoder.write_raw(cancellation_id.as_bytes());
    encoder.write_raw(inner_completion_id);
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

impl From<CodecRefusal> for RunCancellationCompletionRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Cancellation(RunCancellationRefusal::Codec(value))
    }
}
