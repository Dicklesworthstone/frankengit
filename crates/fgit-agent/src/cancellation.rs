//! Debt-preserving cancellation of one complete Intent Run.
//!
//! Cancellation is a protocol, not a dropped connection or status bit.
//! [`RunCancellationIntent`] freezes one authority-bound situation, the active
//! task claim when present, and the complete [`crate::RunReconciliationReport`]
//! at the request instant. [`RunCancellationCompletion`] accepts only the same
//! effect set after legal lifecycle progress.
//!
//! Escalation and leak containment are not mislabeled as settlement. A run may
//! complete with debt only when every escalation has explicit transfer
//! evidence and every leak has explicit containment evidence. Reserved or
//! committed effects still requiring automation keep cancellation open.
//!
//! This module performs no task-system mutation, obligation transition,
//! downstream probe, process kill, workspace cleanup, or canonical publication.
//! Those components return the typed evidence consumed here.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_resource::{ObligationState, ResourceError};
use fgit_types::{Digest, PrincipalId};

use crate::{
    ActiveTaskClaim, ActiveTaskClaimId, AgentChangePlanId, AgentInstanceId,
    AgentSituationReceipt, EffectId, EffectRecord, EffectResolutionAction,
    EffectTerminalOutcome, IntentRun, LogicalTime, RunId, RunReconciliationReport,
    RunReconciliationReportId, SituationComponentKind, SituationId, TaskClaimReceiptId,
    WorkTaskId,
};

/// Maximum transfer or containment evidence rows accepted by one completion.
pub const MAX_CANCELLATION_EVIDENCE_ENTRIES: usize = crate::MAX_RECONCILIATION_EFFECTS;
const CANCELLATION_DOMAIN: &[u8] = b"frankengit.agent.run-cancellation/v1\0";
const COMPLETION_DOMAIN: &[u8] = b"frankengit.agent.run-cancellation-completion/v1\0";

/// Stable identity of one cancellation request.
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

/// Stable identity of one completed cancellation.
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

/// Task-system outcome reported while releasing the run's active claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TaskClaimCancellationOutcome {
    /// The task is no longer assigned or reserved by this run.
    Released,
    /// The task and its coordination debt moved to another run.
    Transferred {
        /// Successor run selected by the task-system adapter.
        successor_run_id: RunId,
    },
}

impl TaskClaimCancellationOutcome {
    const fn code_point(self) -> u8 {
        match self {
            Self::Released => 1,
            Self::Transferred { .. } => 2,
        }
    }
}

/// Adapter-observed task-claim resolution supplied to cancellation completion.
///
/// This is an untrusted projection until [`RunCancellationIntent::complete`]
/// validates it against the frozen active claim and task generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskClaimCancellationProjection {
    active_claim_id: ActiveTaskClaimId,
    claim_id: TaskClaimReceiptId,
    plan_id: AgentChangePlanId,
    task_id: WorkTaskId,
    assignee: RunId,
    previous_task_projection_generation: [u8; 32],
    resulting_task_projection_generation: [u8; 32],
    resolved_at: LogicalTime,
    outcome: TaskClaimCancellationOutcome,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
}

impl TaskClaimCancellationProjection {
    /// Creates one complete adapter observation.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        active_claim_id: ActiveTaskClaimId,
        claim_id: TaskClaimReceiptId,
        plan_id: AgentChangePlanId,
        task_id: WorkTaskId,
        assignee: RunId,
        previous_task_projection_generation: [u8; 32],
        resulting_task_projection_generation: [u8; 32],
        resolved_at: LogicalTime,
        outcome: TaskClaimCancellationOutcome,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Self {
        Self {
            active_claim_id,
            claim_id,
            plan_id,
            task_id,
            assignee,
            previous_task_projection_generation,
            resulting_task_projection_generation,
            resolved_at,
            outcome,
            adapter_identity,
            evidence_root,
        }
    }

    /// Activated claim resolved by the adapter.
    #[must_use]
    pub const fn active_claim_id(self) -> ActiveTaskClaimId {
        self.active_claim_id
    }

    /// Underlying task-claim receipt.
    #[must_use]
    pub const fn claim_id(self) -> TaskClaimReceiptId {
        self.claim_id
    }

    /// Plan bound to the claim.
    #[must_use]
    pub const fn plan_id(self) -> AgentChangePlanId {
        self.plan_id
    }

    /// Task resolved by the adapter.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }

    /// Run that previously owned the claim.
    #[must_use]
    pub const fn assignee(self) -> RunId {
        self.assignee
    }

    /// Task generation observed by the cancellation request.
    #[must_use]
    pub const fn previous_task_projection_generation(self) -> [u8; 32] {
        self.previous_task_projection_generation
    }

    /// Task generation after release or transfer.
    #[must_use]
    pub const fn resulting_task_projection_generation(self) -> [u8; 32] {
        self.resulting_task_projection_generation
    }

    /// Logical resolution instant.
    #[must_use]
    pub const fn resolved_at(self) -> LogicalTime {
        self.resolved_at
    }

    /// Release or transfer outcome.
    #[must_use]
    pub const fn outcome(self) -> TaskClaimCancellationOutcome {
        self.outcome
    }

    /// Adapter implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Evidence supporting the task-system mutation.
    #[must_use]
    pub const fn evidence_root(self) -> Digest {
        self.evidence_root
    }
}

/// Evidence that one escalated effect was transferred to its named owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancellationDebtTransfer {
    effect_id: EffectId,
    owner: PrincipalId,
    evidence_root: Digest,
}

impl CancellationDebtTransfer {
    /// Creates one explicit escalation transfer receipt.
    #[must_use]
    pub const fn new(effect_id: EffectId, owner: PrincipalId, evidence_root: Digest) -> Self {
        Self {
            effect_id,
            owner,
            evidence_root,
        }
    }

    /// Escalated effect transferred.
    #[must_use]
    pub const fn effect_id(self) -> EffectId {
        self.effect_id
    }

    /// Principal that accepted responsibility.
    #[must_use]
    pub const fn owner(self) -> PrincipalId {
        self.owner
    }

    /// Transfer evidence commitment.
    #[must_use]
    pub const fn evidence_root(self) -> Digest {
        self.evidence_root
    }
}

/// Evidence that one leaked effect has been contained and recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancellationContainmentEvidence {
    effect_id: EffectId,
    evidence_root: Digest,
}

impl CancellationContainmentEvidence {
    /// Creates one containment evidence row.
    #[must_use]
    pub const fn new(effect_id: EffectId, evidence_root: Digest) -> Self {
        Self {
            effect_id,
            evidence_root,
        }
    }

    /// Leaked effect contained.
    #[must_use]
    pub const fn effect_id(self) -> EffectId {
        self.effect_id
    }

    /// Containment evidence commitment.
    #[must_use]
    pub const fn evidence_root(self) -> Digest {
        self.evidence_root
    }
}

/// Terminal interpretation of a cancellation completion.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RunCancellationState {
    /// Every effect is terminal and the task claim was released or transferred.
    Clean,
    /// No automation remains, but escalated effects were explicitly transferred.
    DebtTransferred {
        /// Escalated effects transferred.
        count: u32,
    },
    /// Leaks were explicitly contained; escalated effects may also be transferred.
    Contained {
        /// Escalated effects transferred.
        transferred: u32,
        /// Leaked effects with containment evidence.
        contained_leaks: u32,
    },
}

impl RunCancellationState {
    const fn code_point(self) -> u8 {
        match self {
            Self::Clean => 1,
            Self::DebtTransferred { .. } => 2,
            Self::Contained { .. } => 3,
        }
    }
}

/// Immutable request to stop one run and drain all of its responsibilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCancellationIntent {
    cancellation_id: RunCancellationId,
    run_id: RunId,
    source_situation_id: SituationId,
    source_task_projection_generation: Option<[u8; 32]>,
    active_claim: Option<ActiveTaskClaim>,
    requested_by: AgentInstanceId,
    requested_at: LogicalTime,
    reason_root: Digest,
    initial_reconciliation: RunReconciliationReport,
}

impl RunCancellationIntent {
    /// Requests cancellation from one exact situation and effect inventory.
    ///
    /// The run may already be expired; expiry stops new effects but does not
    /// discharge existing obligations. The supplied reconciliation report must
    /// have been assembled at the exact situation observation.
    ///
    /// # Errors
    ///
    /// Refuses run, authority, time, claim, task-generation, requester, and
    /// report substitution, plus unrepresentable canonical framing.
    pub fn request(
        situation: &AgentSituationReceipt,
        run: &IntentRun,
        initial_reconciliation: RunReconciliationReport,
        active_claim: Option<ActiveTaskClaim>,
        requested_by: AgentInstanceId,
        reason_root: Digest,
    ) -> Result<Self, RunCancellationRefusal> {
        if requested_by.value() == 0 {
            return Err(RunCancellationRefusal::ZeroRequesterIdentity);
        }
        if situation.intent_run_id() != Some(run.run_id()) {
            return Err(RunCancellationRefusal::SituationRunMismatch);
        }
        let run_authority = run
            .authority_read_receipt()
            .ok_or(RunCancellationRefusal::RunAuthorityReceiptRequired)?;
        if run_authority != situation.authority_read_receipt() {
            return Err(RunCancellationRefusal::RunAuthorityMismatch);
        }
        if initial_reconciliation.run_id() != run.run_id() {
            return Err(RunCancellationRefusal::InitialReportRunMismatch);
        }
        if initial_reconciliation.authority_read_receipt() != run_authority {
            return Err(RunCancellationRefusal::InitialReportAuthorityMismatch);
        }
        if initial_reconciliation.observed_at() != situation.observed_at() {
            return Err(RunCancellationRefusal::InitialReportObservationMismatch {
                situation: situation.observed_at(),
                report: initial_reconciliation.observed_at(),
            });
        }

        let source_task_projection_generation = situation
            .component(SituationComponentKind::TaskProjection)
            .generation_commitment();
        if let Some(claim) = active_claim {
            if claim.assignee() != run.run_id() {
                return Err(RunCancellationRefusal::ActiveClaimRunMismatch);
            }
            if !claim.is_live_at(situation.observed_at()) {
                return Err(RunCancellationRefusal::ActiveClaimExpired {
                    expires_at: claim.expires_at(),
                    observed_at: situation.observed_at(),
                });
            }
            if source_task_projection_generation.is_none() {
                return Err(RunCancellationRefusal::TaskProjectionUnavailable);
            }
        }

        let mut intent = Self {
            cancellation_id: RunCancellationId([0; 32]),
            run_id: run.run_id(),
            source_situation_id: situation.situation_id(),
            source_task_projection_generation,
            active_claim,
            requested_by,
            requested_at: situation.observed_at(),
            reason_root,
            initial_reconciliation,
        };
        intent.cancellation_id = RunCancellationId(intent_commitment(&intent)?);
        Ok(intent)
    }

    /// Completes cancellation from a later complete effect inventory.
    ///
    /// # Errors
    ///
    /// Refuses another run or authority basis, time rollback, changed effect
    /// membership or immutable effect identity, illegal lifecycle progress,
    /// removed output/reconciliation evidence, budget regression, incomplete
    /// task-claim resolution, outstanding automation, missing/extra transfer or
    /// containment evidence, and unrepresentable canonical framing.
    pub fn complete(
        &self,
        final_reconciliation: RunReconciliationReport,
        task_claim_resolution: Option<TaskClaimCancellationProjection>,
        mut debt_transfers: Vec<CancellationDebtTransfer>,
        mut containment_evidence: Vec<CancellationContainmentEvidence>,
    ) -> Result<RunCancellationCompletion, RunCancellationRefusal> {
        validate_final_report(self, &final_reconciliation)?;
        validate_effect_progress(self, &final_reconciliation)?;
        validate_task_claim_resolution(self, &final_reconciliation, task_claim_resolution)?;
        canonicalize_debt_transfers(&mut debt_transfers)?;
        canonicalize_containment_evidence(&mut containment_evidence)?;
        validate_terminal_debt(
            &final_reconciliation,
            &debt_transfers,
            &containment_evidence,
        )?;

        let transferred = u32::try_from(debt_transfers.len()).map_err(|_| {
            RunCancellationRefusal::CountUnrepresentable {
                field: "debt_transfers",
                observed: debt_transfers.len(),
            }
        })?;
        let contained_leaks = u32::try_from(containment_evidence.len()).map_err(|_| {
            RunCancellationRefusal::CountUnrepresentable {
                field: "containment_evidence",
                observed: containment_evidence.len(),
            }
        })?;
        let state = if contained_leaks != 0 {
            RunCancellationState::Contained {
                transferred,
                contained_leaks,
            }
        } else if transferred != 0 {
            RunCancellationState::DebtTransferred { count: transferred }
        } else {
            RunCancellationState::Clean
        };

        let mut completion = RunCancellationCompletion {
            completion_id: RunCancellationCompletionId([0; 32]),
            cancellation_id: self.cancellation_id,
            run_id: self.run_id,
            completed_at: final_reconciliation.observed_at(),
            initial_report_id: self.initial_reconciliation.report_id(),
            final_reconciliation,
            task_claim_resolution,
            debt_transfers,
            containment_evidence,
            state,
        };
        completion.completion_id =
            RunCancellationCompletionId(completion_commitment(&completion)?);
        Ok(completion)
    }

    /// Stable cancellation-request identity.
    #[must_use]
    pub const fn cancellation_id(&self) -> RunCancellationId {
        self.cancellation_id
    }

    /// Run being cancelled.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Situation observed when cancellation was requested.
    #[must_use]
    pub const fn source_situation_id(&self) -> SituationId {
        self.source_situation_id
    }

    /// Task generation frozen by the request, when observed.
    #[must_use]
    pub const fn source_task_projection_generation(&self) -> Option<[u8; 32]> {
        self.source_task_projection_generation
    }

    /// Active claim frozen by the request, when present.
    #[must_use]
    pub const fn active_claim(&self) -> Option<ActiveTaskClaim> {
        self.active_claim
    }

    /// Agent executor that requested cancellation.
    #[must_use]
    pub const fn requested_by(&self) -> AgentInstanceId {
        self.requested_by
    }

    /// Logical request instant.
    #[must_use]
    pub const fn requested_at(&self) -> LogicalTime {
        self.requested_at
    }

    /// Commitment to the cancellation reason and request evidence.
    #[must_use]
    pub const fn reason_root(&self) -> Digest {
        self.reason_root
    }

    /// Complete effect inventory frozen at request time.
    #[must_use]
    pub const fn initial_reconciliation(&self) -> &RunReconciliationReport {
        &self.initial_reconciliation
    }
}

/// Verified terminal cancellation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCancellationCompletion {
    completion_id: RunCancellationCompletionId,
    cancellation_id: RunCancellationId,
    run_id: RunId,
    completed_at: LogicalTime,
    initial_report_id: RunReconciliationReportId,
    final_reconciliation: RunReconciliationReport,
    task_claim_resolution: Option<TaskClaimCancellationProjection>,
    debt_transfers: Vec<CancellationDebtTransfer>,
    containment_evidence: Vec<CancellationContainmentEvidence>,
    state: RunCancellationState,
}

impl RunCancellationCompletion {
    /// Stable completion identity.
    #[must_use]
    pub const fn completion_id(&self) -> RunCancellationCompletionId {
        self.completion_id
    }

    /// Cancellation request completed.
    #[must_use]
    pub const fn cancellation_id(&self) -> RunCancellationId {
        self.cancellation_id
    }

    /// Cancelled run.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Logical completion instant.
    #[must_use]
    pub const fn completed_at(&self) -> LogicalTime {
        self.completed_at
    }

    /// Initial frozen effect inventory.
    #[must_use]
    pub const fn initial_report_id(&self) -> RunReconciliationReportId {
        self.initial_report_id
    }

    /// Complete final effect inventory.
    #[must_use]
    pub const fn final_reconciliation(&self) -> &RunReconciliationReport {
        &self.final_reconciliation
    }

    /// Task-claim release or transfer evidence, when a claim was active.
    #[must_use]
    pub const fn task_claim_resolution(&self) -> Option<TaskClaimCancellationProjection> {
        self.task_claim_resolution
    }

    /// Explicit escalation transfers.
    #[must_use]
    pub fn debt_transfers(&self) -> &[CancellationDebtTransfer] {
        &self.debt_transfers
    }

    /// Explicit leak-containment evidence.
    #[must_use]
    pub fn containment_evidence(&self) -> &[CancellationContainmentEvidence] {
        &self.containment_evidence
    }

    /// Terminal cancellation interpretation.
    #[must_use]
    pub const fn state(&self) -> RunCancellationState {
        self.state
    }
}

/// Why cancellation request or completion failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunCancellationRefusal {
    /// Requester identity used the reserved all-zero value.
    ZeroRequesterIdentity,
    /// Situation names another run.
    SituationRunMismatch,
    /// Run lacks a complete authenticated authority receipt.
    RunAuthorityReceiptRequired,
    /// Situation and run use different authority positions.
    RunAuthorityMismatch,
    /// Initial report names another run.
    InitialReportRunMismatch,
    /// Initial report uses another authority position.
    InitialReportAuthorityMismatch,
    /// Initial report and situation were assembled at different instants.
    InitialReportObservationMismatch {
        /// Situation observation.
        situation: LogicalTime,
        /// Report observation.
        report: LogicalTime,
    },
    /// Active claim belongs to another run.
    ActiveClaimRunMismatch,
    /// Active claim is no longer live at cancellation request.
    ActiveClaimExpired {
        /// Exclusive claim expiry.
        expires_at: LogicalTime,
        /// Request observation.
        observed_at: LogicalTime,
    },
    /// Active claim exists but the situation omitted its task projection.
    TaskProjectionUnavailable,
    /// Final report names another run.
    FinalReportRunMismatch,
    /// Final report uses another authority position.
    FinalReportAuthorityMismatch,
    /// Final report observation moved backwards.
    FinalObservationRollback {
        /// Cancellation request instant.
        requested_at: LogicalTime,
        /// Final report observation.
        observed_at: LogicalTime,
    },
    /// Final report has a different number of effects.
    EffectSetSizeChanged {
        /// Frozen effect count.
        expected: usize,
        /// Final effect count.
        observed: usize,
    },
    /// Final report removed or substituted one effect identity.
    EffectSetChanged {
        /// Frozen identity at this stable position.
        expected: EffectId,
        /// Final identity at this stable position.
        observed: EffectId,
    },
    /// An immutable accepted-effect field changed during cancellation.
    EffectIdentityChanged {
        /// Affected effect.
        effect_id: EffectId,
        /// Immutable field changed.
        field: &'static str,
    },
    /// Effect lifecycle moved along no legal cancellation path.
    IllegalEffectProgress {
        /// Affected effect.
        effect_id: EffectId,
        /// Frozen state.
        from: ObligationState,
        /// Final state.
        to: ObligationState,
    },
    /// A previously recorded terminal marker changed.
    TerminalOutcomeChanged {
        /// Affected effect.
        effect_id: EffectId,
    },
    /// Cumulative charged resource accounting moved backwards.
    EffectBudgetRegressed {
        /// Affected effect.
        effect_id: EffectId,
        /// First regressed grade.
        deficit: ResourceError,
    },
    /// Previously recorded output evidence disappeared.
    EffectOutputRemoved {
        /// Affected effect.
        effect_id: EffectId,
        /// Missing output commitment.
        commitment: [u8; 32],
    },
    /// Previously recorded reconciliation evidence disappeared or changed.
    ReconciliationEvidenceRegressed {
        /// Affected effect.
        effect_id: EffectId,
    },
    /// Task-claim resolution supplied when no claim was active.
    UnexpectedTaskClaimResolution,
    /// Active task claim was not released or transferred.
    MissingTaskClaimResolution,
    /// Task-claim projection names another activated claim.
    TaskClaimIdentityMismatch,
    /// Task-claim projection names another underlying claim.
    TaskClaimReceiptMismatch,
    /// Task-claim projection names another plan.
    TaskClaimPlanMismatch,
    /// Task-claim projection names another task.
    TaskClaimTaskMismatch,
    /// Task-claim projection names another assignee.
    TaskClaimAssigneeMismatch,
    /// Task-claim resolution began from another projection generation.
    TaskClaimGenerationMismatch {
        /// Frozen generation.
        expected: [u8; 32],
        /// Adapter predecessor generation.
        observed: [u8; 32],
    },
    /// Resulting task generation used the reserved all-zero value.
    ZeroResultingTaskGeneration,
    /// Task-claim resolution did not advance the projection generation.
    TaskGenerationUnchanged,
    /// Task-claim resolution predates the cancellation request.
    TaskClaimResolvedBeforeRequest {
        /// Cancellation request instant.
        requested_at: LogicalTime,
        /// Task resolution instant.
        resolved_at: LogicalTime,
    },
    /// Task-claim resolution appears after the final report observation.
    TaskClaimResolvedAfterCompletion {
        /// Task resolution instant.
        resolved_at: LogicalTime,
        /// Final report observation.
        completed_at: LogicalTime,
    },
    /// Task adapter used the reserved all-zero identity.
    ZeroTaskAdapterIdentity,
    /// Transfer tried to hand the task back to the cancelled run.
    TaskTransferredToCancelledRun,
    /// Transfer/containment collection exceeded its hard ceiling.
    TooManyEvidenceEntries {
        /// Collection name.
        field: &'static str,
        /// Entries supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// One escalation transfer effect appeared twice.
    DuplicateDebtTransfer {
        /// Repeated effect.
        effect_id: EffectId,
    },
    /// One leak-containment effect appeared twice.
    DuplicateContainmentEvidence {
        /// Repeated effect.
        effect_id: EffectId,
    },
    /// Reserved or committed effect still requires automation.
    CancellationStillInProgress {
        /// Affected effect.
        effect_id: EffectId,
        /// Required action.
        action: EffectResolutionAction,
    },
    /// Escalated effect has no transfer receipt.
    MissingDebtTransfer {
        /// Affected effect.
        effect_id: EffectId,
    },
    /// Transfer owner differs from the escalation owner.
    DebtTransferOwnerMismatch {
        /// Affected effect.
        effect_id: EffectId,
        /// Owner named by the effect record.
        expected: PrincipalId,
        /// Owner named by transfer evidence.
        observed: PrincipalId,
    },
    /// Transfer evidence names an effect that is not escalated.
    UnexpectedDebtTransfer {
        /// Affected effect.
        effect_id: EffectId,
    },
    /// Leaked effect has no containment evidence.
    MissingContainmentEvidence {
        /// Affected effect.
        effect_id: EffectId,
    },
    /// Containment evidence names an effect that is not leaked.
    UnexpectedContainmentEvidence {
        /// Affected effect.
        effect_id: EffectId,
    },
    /// A bounded count could not be represented in the wire profile.
    CountUnrepresentable {
        /// Count field.
        field: &'static str,
        /// Value observed.
        observed: usize,
    },
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for RunCancellationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "run cancellation refused: {self:?}")
    }
}

impl core::error::Error for RunCancellationRefusal {}

impl From<CodecRefusal> for RunCancellationRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_final_report(
    intent: &RunCancellationIntent,
    report: &RunReconciliationReport,
) -> Result<(), RunCancellationRefusal> {
    if report.run_id() != intent.run_id {
        return Err(RunCancellationRefusal::FinalReportRunMismatch);
    }
    if report.authority_read_receipt()
        != intent.initial_reconciliation.authority_read_receipt()
    {
        return Err(RunCancellationRefusal::FinalReportAuthorityMismatch);
    }
    if report.observed_at() < intent.requested_at {
        return Err(RunCancellationRefusal::FinalObservationRollback {
            requested_at: intent.requested_at,
            observed_at: report.observed_at(),
        });
    }
    Ok(())
}

fn validate_effect_progress(
    intent: &RunCancellationIntent,
    final_report: &RunReconciliationReport,
) -> Result<(), RunCancellationRefusal> {
    let initial = intent.initial_reconciliation.effects();
    let final_effects = final_report.effects();
    if initial.len() != final_effects.len() {
        return Err(RunCancellationRefusal::EffectSetSizeChanged {
            expected: initial.len(),
            observed: final_effects.len(),
        });
    }
    for (before, after) in initial.iter().zip(final_effects) {
        let before = before.record();
        let after = after.record();
        if before.effect_id != after.effect_id {
            return Err(RunCancellationRefusal::EffectSetChanged {
                expected: before.effect_id,
                observed: after.effect_id,
            });
        }
        validate_effect_identity(before, after)?;
        if !state_can_advance(before.obligation_state, after.obligation_state) {
            return Err(RunCancellationRefusal::IllegalEffectProgress {
                effect_id: before.effect_id,
                from: before.obligation_state,
                to: after.obligation_state,
            });
        }
        if before.terminal_outcome.is_some()
            && before.terminal_outcome != after.terminal_outcome
        {
            return Err(RunCancellationRefusal::TerminalOutcomeChanged {
                effect_id: before.effect_id,
            });
        }
        if let Some(deficit) = after
            .budget_consumed
            .first_deficit(&before.budget_consumed)
        {
            return Err(RunCancellationRefusal::EffectBudgetRegressed {
                effect_id: before.effect_id,
                deficit,
            });
        }
        for commitment in &before.output_commitments {
            if !after.output_commitments.contains(commitment) {
                return Err(RunCancellationRefusal::EffectOutputRemoved {
                    effect_id: before.effect_id,
                    commitment: *commitment,
                });
            }
        }
        if !reconciliation_evidence_extends(
            before.reconciliation_evidence.as_ref(),
            after.reconciliation_evidence.as_ref(),
        ) {
            return Err(RunCancellationRefusal::ReconciliationEvidenceRegressed {
                effect_id: before.effect_id,
            });
        }
    }
    Ok(())
}

fn validate_effect_identity(
    before: &EffectRecord,
    after: &EffectRecord,
) -> Result<(), RunCancellationRefusal> {
    let effect_id = before.effect_id;
    macro_rules! unchanged {
        ($field:ident) => {
            if before.$field != after.$field {
                return Err(RunCancellationRefusal::EffectIdentityChanged {
                    effect_id,
                    field: stringify!($field),
                });
            }
        };
    }
    unchanged!(run_id);
    unchanged!(agent_instance_id);
    unchanged!(parent_effect_id);
    unchanged!(capability_id);
    unchanged!(effect_class);
    unchanged!(operation);
    unchanged!(input_commitment);
    unchanged!(source_authority_receipt);
    unchanged!(budget_reserved);
    unchanged!(external_idempotency_key);
    unchanged!(accepted_at);
    if before.obligation_class.is_some() && before.obligation_class != after.obligation_class {
        return Err(RunCancellationRefusal::EffectIdentityChanged {
            effect_id,
            field: "obligation_class",
        });
    }
    Ok(())
}

const fn state_can_advance(from: ObligationState, to: ObligationState) -> bool {
    match from {
        ObligationState::Reserved => true,
        ObligationState::Committed => matches!(
            to,
            ObligationState::Committed
                | ObligationState::DeferredExternally
                | ObligationState::Escalated
                | ObligationState::Acknowledged
                | ObligationState::TerminallyFailed
                | ObligationState::Leaked
        ),
        ObligationState::DeferredExternally => matches!(
            to,
            ObligationState::DeferredExternally
                | ObligationState::Escalated
                | ObligationState::Acknowledged
                | ObligationState::TerminallyFailed
                | ObligationState::Leaked
        ),
        ObligationState::Escalated => matches!(
            to,
            ObligationState::Escalated
                | ObligationState::Acknowledged
                | ObligationState::TerminallyFailed
                | ObligationState::Leaked
        ),
        ObligationState::Acknowledged => matches!(to, ObligationState::Acknowledged),
        ObligationState::Aborted => matches!(to, ObligationState::Aborted),
        ObligationState::TerminallyFailed => matches!(to, ObligationState::TerminallyFailed),
        ObligationState::Leaked => matches!(to, ObligationState::Leaked),
    }
}

fn reconciliation_evidence_extends(
    before: Option<&crate::ReconciliationEvidence>,
    after: Option<&crate::ReconciliationEvidence>,
) -> bool {
    match (before, after) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(before), Some(after)) => {
            before.downstream_idempotency == after.downstream_idempotency
                && before.transitions.len() <= after.transitions.len()
                && before
                    .transitions
                    .iter()
                    .zip(&after.transitions)
                    .all(|(left, right)| left == right)
        }
    }
}

fn validate_task_claim_resolution(
    intent: &RunCancellationIntent,
    final_report: &RunReconciliationReport,
    projection: Option<TaskClaimCancellationProjection>,
) -> Result<(), RunCancellationRefusal> {
    match (intent.active_claim, projection) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(RunCancellationRefusal::UnexpectedTaskClaimResolution),
        (Some(_), None) => Err(RunCancellationRefusal::MissingTaskClaimResolution),
        (Some(claim), Some(projection)) => {
            if projection.active_claim_id != claim.activation_id() {
                return Err(RunCancellationRefusal::TaskClaimIdentityMismatch);
            }
            if projection.claim_id != claim.claim_id() {
                return Err(RunCancellationRefusal::TaskClaimReceiptMismatch);
            }
            if projection.plan_id != claim.plan_id() {
                return Err(RunCancellationRefusal::TaskClaimPlanMismatch);
            }
            if projection.task_id != claim.task_id() {
                return Err(RunCancellationRefusal::TaskClaimTaskMismatch);
            }
            if projection.assignee != intent.run_id {
                return Err(RunCancellationRefusal::TaskClaimAssigneeMismatch);
            }
            let expected = intent
                .source_task_projection_generation
                .ok_or(RunCancellationRefusal::TaskProjectionUnavailable)?;
            if projection.previous_task_projection_generation != expected {
                return Err(RunCancellationRefusal::TaskClaimGenerationMismatch {
                    expected,
                    observed: projection.previous_task_projection_generation,
                });
            }
            if is_zero(&projection.resulting_task_projection_generation) {
                return Err(RunCancellationRefusal::ZeroResultingTaskGeneration);
            }
            if projection.resulting_task_projection_generation
                == projection.previous_task_projection_generation
            {
                return Err(RunCancellationRefusal::TaskGenerationUnchanged);
            }
            if projection.resolved_at < intent.requested_at {
                return Err(RunCancellationRefusal::TaskClaimResolvedBeforeRequest {
                    requested_at: intent.requested_at,
                    resolved_at: projection.resolved_at,
                });
            }
            if projection.resolved_at > final_report.observed_at() {
                return Err(RunCancellationRefusal::TaskClaimResolvedAfterCompletion {
                    resolved_at: projection.resolved_at,
                    completed_at: final_report.observed_at(),
                });
            }
            if is_zero(&projection.adapter_identity) {
                return Err(RunCancellationRefusal::ZeroTaskAdapterIdentity);
            }
            if let TaskClaimCancellationOutcome::Transferred { successor_run_id } =
                projection.outcome
                && successor_run_id == intent.run_id
            {
                return Err(RunCancellationRefusal::TaskTransferredToCancelledRun);
            }
            Ok(())
        }
    }
}

fn canonicalize_debt_transfers(
    transfers: &mut Vec<CancellationDebtTransfer>,
) -> Result<(), RunCancellationRefusal> {
    if transfers.len() > MAX_CANCELLATION_EVIDENCE_ENTRIES {
        return Err(RunCancellationRefusal::TooManyEvidenceEntries {
            field: "debt_transfers",
            observed: transfers.len(),
            limit: MAX_CANCELLATION_EVIDENCE_ENTRIES,
        });
    }
    transfers.sort_unstable_by_key(|entry| entry.effect_id);
    for adjacent in transfers.windows(2) {
        if adjacent[0].effect_id == adjacent[1].effect_id {
            return Err(RunCancellationRefusal::DuplicateDebtTransfer {
                effect_id: adjacent[0].effect_id,
            });
        }
    }
    Ok(())
}

fn canonicalize_containment_evidence(
    evidence: &mut Vec<CancellationContainmentEvidence>,
) -> Result<(), RunCancellationRefusal> {
    if evidence.len() > MAX_CANCELLATION_EVIDENCE_ENTRIES {
        return Err(RunCancellationRefusal::TooManyEvidenceEntries {
            field: "containment_evidence",
            observed: evidence.len(),
            limit: MAX_CANCELLATION_EVIDENCE_ENTRIES,
        });
    }
    evidence.sort_unstable_by_key(|entry| entry.effect_id);
    for adjacent in evidence.windows(2) {
        if adjacent[0].effect_id == adjacent[1].effect_id {
            return Err(RunCancellationRefusal::DuplicateContainmentEvidence {
                effect_id: adjacent[0].effect_id,
            });
        }
    }
    Ok(())
}

fn validate_terminal_debt(
    report: &RunReconciliationReport,
    transfers: &[CancellationDebtTransfer],
    containment: &[CancellationContainmentEvidence],
) -> Result<(), RunCancellationRefusal> {
    for effect in report.effects() {
        let record = effect.record();
        match effect.required_action() {
            EffectResolutionAction::NoFurtherAction => {}
            EffectResolutionAction::AbortReservation
            | EffectResolutionAction::ReconcileCommittedEffect => {
                return Err(RunCancellationRefusal::CancellationStillInProgress {
                    effect_id: record.effect_id,
                    action: effect.required_action(),
                });
            }
            EffectResolutionAction::ResolveEscalation => {
                let transfer = transfers
                    .binary_search_by_key(&record.effect_id, |entry| entry.effect_id)
                    .ok()
                    .map(|index| transfers[index])
                    .ok_or(RunCancellationRefusal::MissingDebtTransfer {
                        effect_id: record.effect_id,
                    })?;
                let expected = match record.terminal_outcome {
                    Some(EffectTerminalOutcome::Escalated { owner, .. }) => owner,
                    _ => {
                        return Err(RunCancellationRefusal::MissingDebtTransfer {
                            effect_id: record.effect_id,
                        });
                    }
                };
                if transfer.owner != expected {
                    return Err(RunCancellationRefusal::DebtTransferOwnerMismatch {
                        effect_id: record.effect_id,
                        expected,
                        observed: transfer.owner,
                    });
                }
            }
            EffectResolutionAction::ContainLeak => {
                if containment
                    .binary_search_by_key(&record.effect_id, |entry| entry.effect_id)
                    .is_err()
                {
                    return Err(RunCancellationRefusal::MissingContainmentEvidence {
                        effect_id: record.effect_id,
                    });
                }
            }
        }
    }
    for transfer in transfers {
        if !report.effects().iter().any(|effect| {
            effect.record().effect_id == transfer.effect_id
                && effect.required_action() == EffectResolutionAction::ResolveEscalation
        }) {
            return Err(RunCancellationRefusal::UnexpectedDebtTransfer {
                effect_id: transfer.effect_id,
            });
        }
    }
    for evidence in containment {
        if !report.effects().iter().any(|effect| {
            effect.record().effect_id == evidence.effect_id
                && effect.required_action() == EffectResolutionAction::ContainLeak
        }) {
            return Err(RunCancellationRefusal::UnexpectedContainmentEvidence {
                effect_id: evidence.effect_id,
            });
        }
    }
    Ok(())
}

fn intent_commitment(intent: &RunCancellationIntent) -> Result<[u8; 32], RunCancellationRefusal> {
    let mut encoder = Encoder::with_capacity(512);
    encoder.write_bytes("run_cancellation_domain", CANCELLATION_DOMAIN)?;
    encoder.write_raw(&intent.run_id.value().to_be_bytes());
    encoder.write_raw(intent.source_situation_id.as_bytes());
    match intent.source_task_projection_generation {
        Some(generation) => {
            encoder.write_bool(true);
            encoder.write_raw(&generation);
        }
        None => encoder.write_bool(false),
    }
    match intent.active_claim {
        Some(claim) => {
            encoder.write_bool(true);
            encoder.write_raw(claim.activation_id().as_bytes());
            encoder.write_raw(claim.claim_id().as_bytes());
            encoder.write_raw(claim.plan_id().as_bytes());
            encoder.write_raw(claim.task_id().as_bytes());
            encoder.write_raw(&claim.assignee().value().to_be_bytes());
            encoder.write_scalar(claim.observed_at().value());
            encoder.write_scalar(claim.expires_at().value());
        }
        None => encoder.write_bool(false),
    }
    encoder.write_raw(&intent.requested_by.value().to_be_bytes());
    encoder.write_scalar(intent.requested_at.value());
    encoder.write_digest(&intent.reason_root)?;
    encoder.write_raw(intent.initial_reconciliation.report_id().as_bytes());
    Ok(hash(encoder.into_bytes()))
}

fn completion_commitment(
    completion: &RunCancellationCompletion,
) -> Result<[u8; 32], RunCancellationRefusal> {
    let mut encoder = Encoder::with_capacity(768);
    encoder.write_bytes("run_cancellation_completion_domain", COMPLETION_DOMAIN)?;
    encoder.write_raw(completion.cancellation_id.as_bytes());
    encoder.write_raw(&completion.run_id.value().to_be_bytes());
    encoder.write_scalar(completion.completed_at.value());
    encoder.write_raw(completion.initial_report_id.as_bytes());
    encoder.write_raw(completion.final_reconciliation.report_id().as_bytes());
    match completion.task_claim_resolution {
        Some(projection) => {
            encoder.write_bool(true);
            write_task_claim_resolution(&mut encoder, projection)?;
        }
        None => encoder.write_bool(false),
    }
    write_count(
        &mut encoder,
        "cancellation.debt_transfers",
        completion.debt_transfers.len(),
    )?;
    for transfer in &completion.debt_transfers {
        encoder.write_raw(&transfer.effect_id.value().to_be_bytes());
        encoder.write_opaque_id(transfer.owner.as_bytes());
        encoder.write_digest(&transfer.evidence_root)?;
    }
    write_count(
        &mut encoder,
        "cancellation.containment_evidence",
        completion.containment_evidence.len(),
    )?;
    for evidence in &completion.containment_evidence {
        encoder.write_raw(&evidence.effect_id.value().to_be_bytes());
        encoder.write_digest(&evidence.evidence_root)?;
    }
    encoder.write_raw_byte(completion.state.code_point());
    match completion.state {
        RunCancellationState::Clean => {}
        RunCancellationState::DebtTransferred { count } => encoder.write_scalar(count),
        RunCancellationState::Contained {
            transferred,
            contained_leaks,
        } => {
            encoder.write_scalar(transferred);
            encoder.write_scalar(contained_leaks);
        }
    }
    Ok(hash(encoder.into_bytes()))
}

fn write_task_claim_resolution(
    encoder: &mut Encoder,
    projection: TaskClaimCancellationProjection,
) -> Result<(), RunCancellationRefusal> {
    encoder.write_raw(projection.active_claim_id.as_bytes());
    encoder.write_raw(projection.claim_id.as_bytes());
    encoder.write_raw(projection.plan_id.as_bytes());
    encoder.write_raw(projection.task_id.as_bytes());
    encoder.write_raw(&projection.assignee.value().to_be_bytes());
    encoder.write_raw(&projection.previous_task_projection_generation);
    encoder.write_raw(&projection.resulting_task_projection_generation);
    encoder.write_scalar(projection.resolved_at.value());
    encoder.write_raw_byte(projection.outcome.code_point());
    if let TaskClaimCancellationOutcome::Transferred { successor_run_id } = projection.outcome {
        encoder.write_raw(&successor_run_id.value().to_be_bytes());
    }
    encoder.write_raw(&projection.adapter_identity);
    encoder.write_digest(&projection.evidence_root)?;
    Ok(())
}

fn write_count(
    encoder: &mut Encoder,
    field: &'static str,
    count: usize,
) -> Result<(), RunCancellationRefusal> {
    let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(count).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    Ok(())
}

fn hash(bytes: Vec<u8>) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&bytes);
    hasher.finish()
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
