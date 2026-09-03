//! Task-claim receipts and post-claim refresh activation.
//!
//! A change plan is inert and a task projection is derived metadata. The
//! adapter that mutates Beads or another task system therefore returns a
//! [`TaskClaimProjection`], not authority. This module validates that projection
//! against the exact pulse, plan, complete run, and conflict surface, commits it
//! into a [`TaskClaimReceipt`], and requires a fresh
//! [`crate::AgentSituationReceipt`] to observe both the post-claim task
//! generation and the same complete Intent Run before the claim becomes usable.
//!
//! The receipt grants no repository mutation authority and reserves no files by
//! itself. It proves only that one external task/coordination projection
//! reported the expected claim transition under the exact plan and run.
//! Repository effects still require ordinary capabilities, obligations, and
//! canonical publication.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::{Digest, HeadGeneration, RepositoryAuthorityHeadId, RepositoryId};

use crate::{
    AgentChangePlan, AgentChangePlanId, AgentControlPulse, AgentSituationReceipt, IntentRun,
    IntentRunCommitment, IntentRunIdentityRefusal, LogicalTime, PlanSurface, PulseState, RunId,
    SituationComponentKind, WorkAction, WorkFrontierId, WorkTaskId,
};

/// Largest conflict/reservation surface admitted by one claim.
pub const MAX_CLAIM_SURFACES: usize = crate::MAX_PLAN_ENTRIES;
const CLAIM_DOMAIN: &[u8] = b"frankengit.agent.task-claim/v2\0";
const ACTIVATION_DOMAIN: &[u8] = b"frankengit.agent.task-claim-activation/v2\0";

/// Stable identity of one validated task-claim receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskClaimReceiptId([u8; 32]);

impl TaskClaimReceiptId {
    /// Raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TaskClaimReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task-claim:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable identity of a post-refresh claim activation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActiveTaskClaimId([u8; 32]);

impl ActiveTaskClaimId {
    /// Raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ActiveTaskClaimId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("active-task-claim:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Adapter-observed result of one task claim mutation.
///
/// This is deliberately a claim *input*, not a receipt. All fields remain
/// caller supplied until [`TaskClaimReceipt::admit`] checks them against the
/// exact control-plane objects. The complete run commitment is taken only from
/// those authenticated control objects, never from this untrusted projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskClaimProjection {
    task_id: WorkTaskId,
    plan_id: AgentChangePlanId,
    assignee: RunId,
    previous_task_projection_generation: [u8; 32],
    claimed_task_projection_generation: [u8; 32],
    reserved_surfaces: Vec<PlanSurface>,
    claimed_at: LogicalTime,
    expires_at: LogicalTime,
    adapter_identity: [u8; 32],
    claim_evidence_root: Digest,
}

impl TaskClaimProjection {
    /// Creates the complete adapter observation to validate.
    #[must_use]
    pub const fn new(
        task_id: WorkTaskId,
        plan_id: AgentChangePlanId,
        assignee: RunId,
        previous_task_projection_generation: [u8; 32],
        claimed_task_projection_generation: [u8; 32],
        reserved_surfaces: Vec<PlanSurface>,
        claimed_at: LogicalTime,
        expires_at: LogicalTime,
        adapter_identity: [u8; 32],
        claim_evidence_root: Digest,
    ) -> Self {
        Self {
            task_id,
            plan_id,
            assignee,
            previous_task_projection_generation,
            claimed_task_projection_generation,
            reserved_surfaces,
            claimed_at,
            expires_at,
            adapter_identity,
            claim_evidence_root,
        }
    }

    /// Task the adapter reports claimed.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.task_id
    }

    /// Plan the adapter reports bound to the claim.
    #[must_use]
    pub const fn plan_id(&self) -> AgentChangePlanId {
        self.plan_id
    }

    /// Run the adapter reports as assignee.
    #[must_use]
    pub const fn assignee(&self) -> RunId {
        self.assignee
    }

    /// Task projection generation before the mutation.
    #[must_use]
    pub const fn previous_task_projection_generation(&self) -> &[u8; 32] {
        &self.previous_task_projection_generation
    }

    /// Task projection generation after the mutation.
    #[must_use]
    pub const fn claimed_task_projection_generation(&self) -> &[u8; 32] {
        &self.claimed_task_projection_generation
    }

    /// Conflict surfaces the adapter reports reserved.
    #[must_use]
    pub fn reserved_surfaces(&self) -> &[PlanSurface] {
        &self.reserved_surfaces
    }

    /// Logical mutation instant.
    #[must_use]
    pub const fn claimed_at(&self) -> LogicalTime {
        self.claimed_at
    }

    /// Exclusive claim expiry.
    #[must_use]
    pub const fn expires_at(&self) -> LogicalTime {
        self.expires_at
    }

    /// Identity of the adapter implementation/profile.
    #[must_use]
    pub const fn adapter_identity(&self) -> &[u8; 32] {
        &self.adapter_identity
    }

    /// Evidence supporting the external mutation result.
    #[must_use]
    pub const fn claim_evidence_root(&self) -> Digest {
        self.claim_evidence_root
    }
}

/// Validated immutable task claim, pending a post-claim situation refresh.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskClaimReceipt {
    claim_id: TaskClaimReceiptId,
    plan_id: AgentChangePlanId,
    pulse_id: [u8; 32],
    situation_id: [u8; 32],
    frontier_id: WorkFrontierId,
    repository_id: RepositoryId,
    authority_head_id: RepositoryAuthorityHeadId,
    authority_head_generation: HeadGeneration,
    task_id: WorkTaskId,
    action: WorkAction,
    assignee: RunId,
    run_commitment: IntentRunCommitment,
    previous_task_projection_generation: [u8; 32],
    claimed_task_projection_generation: [u8; 32],
    reserved_surfaces: Vec<PlanSurface>,
    claimed_at: LogicalTime,
    expires_at: LogicalTime,
    adapter_identity: [u8; 32],
    claim_evidence_root: Digest,
}

impl TaskClaimReceipt {
    /// Validates one task-system claim result against the complete control turn.
    ///
    /// # Errors
    ///
    /// Refuses a non-actionable pulse, pulse/plan/complete-run substitution,
    /// authority mismatch, stale or unchanged task generation, wrong
    /// task/assignee/plan, incomplete reservation surface, invalid time window,
    /// claim lifetime beyond the run, zero adapter identity, duplicate
    /// reservation entries, excessive surfaces, and unrepresentable canonical
    /// framing.
    pub fn admit(
        pulse: &AgentControlPulse,
        plan: &AgentChangePlan,
        run: &IntentRun,
        mut projection: TaskClaimProjection,
    ) -> Result<Self, TaskClaimRefusal> {
        let run_commitment = validate_claim_control(pulse, plan, run)?;
        validate_projection(pulse, plan, run, &mut projection)?;

        let mut receipt = Self {
            claim_id: TaskClaimReceiptId([0; 32]),
            plan_id: plan.plan_id(),
            pulse_id: *pulse.pulse_id().as_bytes(),
            situation_id: *pulse.situation_id(),
            frontier_id: pulse.frontier_id(),
            repository_id: pulse.repository_id(),
            authority_head_id: pulse.authority_head_id(),
            authority_head_generation: pulse.authority_head_generation(),
            task_id: plan.task_id(),
            action: plan.action(),
            assignee: run.run_id(),
            run_commitment,
            previous_task_projection_generation: projection.previous_task_projection_generation,
            claimed_task_projection_generation: projection.claimed_task_projection_generation,
            reserved_surfaces: projection.reserved_surfaces,
            claimed_at: projection.claimed_at,
            expires_at: projection.expires_at,
            adapter_identity: projection.adapter_identity,
            claim_evidence_root: projection.claim_evidence_root,
        };
        receipt.claim_id = TaskClaimReceiptId(claim_commitment(&receipt)?);
        Ok(receipt)
    }

    /// Activates the claim only after a new situation observes its post-claim
    /// task projection generation and exact complete run.
    ///
    /// # Errors
    ///
    /// Refuses authority movement, another active run or run commitment,
    /// missing/inconsistent task projection material, an unobserved claim
    /// generation, time rollback, expiry, and unrepresentable activation
    /// framing.
    pub fn activate(
        &self,
        refreshed: &AgentSituationReceipt,
        run: &IntentRun,
    ) -> Result<ActiveTaskClaim, TaskClaimRefusal> {
        validate_activation(self, refreshed, run)?;
        let mut active = ActiveTaskClaim {
            activation_id: ActiveTaskClaimId([0; 32]),
            claim_id: self.claim_id,
            plan_id: self.plan_id,
            situation_id: *refreshed.situation_id().as_bytes(),
            task_id: self.task_id,
            assignee: self.assignee,
            run_commitment: self.run_commitment,
            observed_at: refreshed.observed_at(),
            expires_at: self.expires_at,
        };
        active.activation_id = ActiveTaskClaimId(activation_commitment(&active)?);
        Ok(active)
    }

    /// Stable claim identity.
    #[must_use]
    pub const fn claim_id(&self) -> TaskClaimReceiptId {
        self.claim_id
    }

    /// Exact plan bound to the claim.
    #[must_use]
    pub const fn plan_id(&self) -> AgentChangePlanId {
        self.plan_id
    }

    /// Pulse that preceded the claim mutation.
    #[must_use]
    pub const fn pulse_id(&self) -> &[u8; 32] {
        &self.pulse_id
    }

    /// Situation that preceded the claim mutation.
    #[must_use]
    pub const fn situation_id(&self) -> &[u8; 32] {
        &self.situation_id
    }

    /// Frontier that selected the task.
    #[must_use]
    pub const fn frontier_id(&self) -> WorkFrontierId {
        self.frontier_id
    }

    /// Repository whose task projection was claimed.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Repository authority position under which the plan remains valid.
    #[must_use]
    pub const fn authority_head_id(&self) -> RepositoryAuthorityHeadId {
        self.authority_head_id
    }

    /// Repository authority generation under which the plan remains valid.
    #[must_use]
    pub const fn authority_head_generation(&self) -> HeadGeneration {
        self.authority_head_generation
    }

    /// Claimed task.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.task_id
    }

    /// Action the claim permits the plan to attempt.
    #[must_use]
    pub const fn action(&self) -> WorkAction {
        self.action
    }

    /// Run coordination identity assigned by the task projection.
    #[must_use]
    pub const fn assignee(&self) -> RunId {
        self.assignee
    }

    /// Complete machine-enforced run identity assigned by the claim.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Projection generation the claim mutation replaced.
    #[must_use]
    pub const fn previous_task_projection_generation(&self) -> &[u8; 32] {
        &self.previous_task_projection_generation
    }

    /// Projection generation a refreshed situation must observe.
    #[must_use]
    pub const fn claimed_task_projection_generation(&self) -> &[u8; 32] {
        &self.claimed_task_projection_generation
    }

    /// Exact reserved conflict surface.
    #[must_use]
    pub fn reserved_surfaces(&self) -> &[PlanSurface] {
        &self.reserved_surfaces
    }

    /// Logical claim instant.
    #[must_use]
    pub const fn claimed_at(&self) -> LogicalTime {
        self.claimed_at
    }

    /// Exclusive claim expiry.
    #[must_use]
    pub const fn expires_at(&self) -> LogicalTime {
        self.expires_at
    }

    /// Adapter identity.
    #[must_use]
    pub const fn adapter_identity(&self) -> &[u8; 32] {
        &self.adapter_identity
    }

    /// Claim mutation evidence root.
    #[must_use]
    pub const fn claim_evidence_root(&self) -> Digest {
        self.claim_evidence_root
    }

    /// Whether this claim's reserved surface overlaps another live claim in the
    /// same repository held by a different complete run.
    #[must_use]
    pub fn conflicts_with(&self, other: &Self, at: LogicalTime) -> bool {
        self.repository_id == other.repository_id
            && (self.assignee != other.assignee || self.run_commitment != other.run_commitment)
            && self.is_live_at(at)
            && other.is_live_at(at)
            && surfaces_overlap(&self.reserved_surfaces, &other.reserved_surfaces)
    }

    /// Whether the claim is inside its exclusive time window.
    #[must_use]
    pub const fn is_live_at(&self, at: LogicalTime) -> bool {
        self.claimed_at.value() <= at.value() && at.value() < self.expires_at.value()
    }
}

/// Claim proven visible in a refreshed situation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveTaskClaim {
    activation_id: ActiveTaskClaimId,
    claim_id: TaskClaimReceiptId,
    plan_id: AgentChangePlanId,
    situation_id: [u8; 32],
    task_id: WorkTaskId,
    assignee: RunId,
    run_commitment: IntentRunCommitment,
    observed_at: LogicalTime,
    expires_at: LogicalTime,
}

impl ActiveTaskClaim {
    /// Stable activation identity.
    #[must_use]
    pub const fn activation_id(self) -> ActiveTaskClaimId {
        self.activation_id
    }

    /// Underlying claim identity.
    #[must_use]
    pub const fn claim_id(self) -> TaskClaimReceiptId {
        self.claim_id
    }

    /// Bound plan identity.
    #[must_use]
    pub const fn plan_id(self) -> AgentChangePlanId {
        self.plan_id
    }

    /// Fresh situation that observed the task claim.
    #[must_use]
    pub const fn situation_id(self) -> [u8; 32] {
        self.situation_id
    }

    /// Claimed task.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }

    /// Active assignee coordination identity.
    #[must_use]
    pub const fn assignee(self) -> RunId {
        self.assignee
    }

    /// Complete machine-enforced identity of the active assignee.
    #[must_use]
    pub const fn run_commitment(self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Observation instant of the activating refresh.
    #[must_use]
    pub const fn observed_at(self) -> LogicalTime {
        self.observed_at
    }

    /// Exclusive claim expiry.
    #[must_use]
    pub const fn expires_at(self) -> LogicalTime {
        self.expires_at
    }

    /// Whether the activated claim remains live.
    #[must_use]
    pub const fn is_live_at(self, at: LogicalTime) -> bool {
        self.observed_at.value() <= at.value() && at.value() < self.expires_at.value()
    }
}

/// Why task-claim admission or activation failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskClaimRefusal {
    /// Pulse has no actionable task.
    PulseNotActionable {
        /// Pulse state observed.
        state: PulseState,
    },
    /// Plan does not belong to the supplied pulse.
    PlanPulseMismatch,
    /// Plan task/action differs from the pulse selection.
    PlanSelectionMismatch,
    /// Plan and supplied run IDs disagree.
    PlanRunMismatch {
        /// Run bound to the plan.
        expected: RunId,
        /// Supplied run.
        observed: RunId,
    },
    /// Plan and supplied complete run commitments disagree.
    PlanRunCommitmentMismatch {
        /// Commitment bound to the plan.
        expected: IntentRunCommitment,
        /// Commitment computed from the supplied run.
        observed: IntentRunCommitment,
    },
    /// Pulse and supplied complete run commitments disagree.
    PulseRunCommitmentMismatch {
        /// Commitment bound to the plan and supplied run.
        expected: IntentRunCommitment,
        /// Commitment retained by the pulse, when present.
        observed: Option<IntentRunCommitment>,
    },
    /// Run lacks a complete authenticated authority receipt.
    RunAuthorityReceiptRequired,
    /// Run and pulse/claim name different authority positions.
    RunAuthorityMismatch,
    /// Complete run identity could not be produced.
    RunIdentity(IntentRunIdentityRefusal),
    /// Run was expired at claim or refresh time.
    RunExpired {
        /// Expired run.
        run_id: RunId,
        /// Logical instant checked.
        observed: LogicalTime,
    },
    /// Projection names another task.
    ProjectionTaskMismatch {
        /// Plan task.
        expected: WorkTaskId,
        /// Projection task.
        observed: WorkTaskId,
    },
    /// Projection names another plan.
    ProjectionPlanMismatch {
        /// Expected plan.
        expected: AgentChangePlanId,
        /// Projection plan.
        observed: AgentChangePlanId,
    },
    /// Projection assigns another run.
    ProjectionAssigneeMismatch {
        /// Expected run.
        expected: RunId,
        /// Projection assignee.
        observed: RunId,
    },
    /// Projection did not start from the pulse's task generation.
    PreviousTaskGenerationMismatch {
        /// Pulse generation.
        expected: [u8; 32],
        /// Projection predecessor.
        observed: [u8; 32],
    },
    /// Post-claim generation used the reserved all-zero identity.
    ZeroClaimedTaskGeneration,
    /// Claim mutation did not produce a new task projection generation.
    TaskGenerationUnchanged,
    /// Claim result predates the pulse it claims to have acted on.
    ClaimBeforePulse {
        /// Pulse observation time.
        pulse_observed: LogicalTime,
        /// Claim mutation time.
        claimed_at: LogicalTime,
    },
    /// Claim expiry is not strictly later than claim time.
    InvalidClaimWindow {
        /// Claim time.
        claimed_at: LogicalTime,
        /// Exclusive expiry.
        expires_at: LogicalTime,
    },
    /// Claim expires after its run.
    ClaimOutlivesRun {
        /// Claim expiry.
        claim_expires_at: LogicalTime,
        /// Run expiry.
        run_expires_at: LogicalTime,
    },
    /// Adapter identity used the reserved all-zero value.
    ZeroAdapterIdentity,
    /// Reservation surface exceeded the hard ceiling.
    TooManyReservedSurfaces {
        /// Entries supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// Reservation surface repeated one selector.
    DuplicateReservedSurface {
        /// Repeated surface.
        surface: PlanSurface,
    },
    /// Projection reservation surface differs from the plan.
    ReservationSurfaceMismatch,
    /// Refreshed situation moved repository authority.
    RefreshedAuthorityMismatch,
    /// Refreshed situation belongs to another run ID.
    RefreshedRunMismatch,
    /// Refreshed situation or supplied run carries another complete run.
    RefreshedRunCommitmentMismatch {
        /// Commitment bound to the claim.
        expected: IntentRunCommitment,
        /// Commitment retained by the refreshed situation, when present.
        observed: Option<IntentRunCommitment>,
    },
    /// Refreshed task component is omitted or structurally inconsistent.
    RefreshedTaskProjectionUnavailable,
    /// Refreshed situation did not observe the post-claim generation.
    ClaimGenerationNotObserved {
        /// Claimed generation.
        expected: [u8; 32],
        /// Refreshed generation.
        observed: [u8; 32],
    },
    /// Refreshed situation predates the claim mutation.
    RefreshedTimeRollback {
        /// Claim mutation time.
        claimed_at: LogicalTime,
        /// Refreshed observation time.
        observed: LogicalTime,
    },
    /// Claim expired before or at refreshed observation.
    ClaimExpired {
        /// Exclusive expiry.
        expires_at: LogicalTime,
        /// Refreshed observation time.
        observed: LogicalTime,
    },
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for TaskClaimRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PulseNotActionable { state } => {
                write!(formatter, "pulse is not actionable: {state:?}")
            }
            Self::PlanPulseMismatch => formatter.write_str("plan belongs to another pulse"),
            Self::PlanSelectionMismatch => {
                formatter.write_str("plan selection differs from the pulse")
            }
            Self::PlanRunMismatch { expected, observed } => {
                write!(
                    formatter,
                    "plan run {expected} differs from supplied run {observed}"
                )
            }
            Self::PlanRunCommitmentMismatch { expected, observed } => write!(
                formatter,
                "plan run commitment {expected} differs from supplied run {observed}"
            ),
            Self::PulseRunCommitmentMismatch { expected, observed } => write!(
                formatter,
                "pulse run commitment {observed:?} differs from expected {expected}"
            ),
            Self::RunAuthorityReceiptRequired => formatter.write_str(
                "task claim requires a run with a complete authenticated authority receipt",
            ),
            Self::RunAuthorityMismatch => {
                formatter.write_str("run authority differs from the claim control turn")
            }
            Self::RunIdentity(refusal) => {
                write!(formatter, "task claim run identity refused: {refusal}")
            }
            Self::RunExpired { run_id, observed } => {
                write!(formatter, "run {run_id} is expired at {observed}")
            }
            Self::ProjectionTaskMismatch { expected, observed } => write!(
                formatter,
                "claim projection task {observed} differs from plan task {expected}"
            ),
            Self::ProjectionPlanMismatch { expected, observed } => write!(
                formatter,
                "claim projection plan {observed} differs from expected {expected}"
            ),
            Self::ProjectionAssigneeMismatch { expected, observed } => write!(
                formatter,
                "claim projection assignee {observed} differs from run {expected}"
            ),
            Self::PreviousTaskGenerationMismatch { .. } => formatter
                .write_str("claim projection predecessor differs from the pulse task generation"),
            Self::ZeroClaimedTaskGeneration => {
                formatter.write_str("claimed task generation may not be all zero")
            }
            Self::TaskGenerationUnchanged => {
                formatter.write_str("task claim did not advance the task projection")
            }
            Self::ClaimBeforePulse {
                pulse_observed,
                claimed_at,
            } => write!(
                formatter,
                "claim at {claimed_at} predates pulse observation {pulse_observed}"
            ),
            Self::InvalidClaimWindow {
                claimed_at,
                expires_at,
            } => write!(
                formatter,
                "claim window is empty or inverted: {claimed_at}..{expires_at}"
            ),
            Self::ClaimOutlivesRun {
                claim_expires_at,
                run_expires_at,
            } => write!(
                formatter,
                "claim expires at {claim_expires_at} after run expiry {run_expires_at}"
            ),
            Self::ZeroAdapterIdentity => {
                formatter.write_str("task-claim adapter identity may not be all zero")
            }
            Self::TooManyReservedSurfaces { observed, limit } => write!(
                formatter,
                "claim reserves {observed} surfaces, limit {limit}"
            ),
            Self::DuplicateReservedSurface { surface } => write!(
                formatter,
                "claim repeats {:?} selector {}",
                surface.kind(),
                surface.selector()
            ),
            Self::ReservationSurfaceMismatch => {
                formatter.write_str("claim reservation surface differs from the plan")
            }
            Self::RefreshedAuthorityMismatch => formatter.write_str(
                "post-claim situation moved repository authority and invalidated the plan",
            ),
            Self::RefreshedRunMismatch => {
                formatter.write_str("post-claim situation names another active run")
            }
            Self::RefreshedRunCommitmentMismatch { expected, observed } => write!(
                formatter,
                "post-claim run commitment {observed:?} differs from claim run {expected}"
            ),
            Self::RefreshedTaskProjectionUnavailable => formatter
                .write_str("post-claim situation has no observed task projection generation"),
            Self::ClaimGenerationNotObserved { .. } => formatter
                .write_str("post-claim situation does not observe the claimed task generation"),
            Self::RefreshedTimeRollback {
                claimed_at,
                observed,
            } => write!(
                formatter,
                "post-claim situation time {observed} predates claim {claimed_at}"
            ),
            Self::ClaimExpired {
                expires_at,
                observed,
            } => write!(
                formatter,
                "claim expired at {expires_at} before observation {observed}"
            ),
            Self::Codec(refusal) => write!(formatter, "task claim framing refused: {refusal}"),
        }
    }
}

impl core::error::Error for TaskClaimRefusal {}

impl From<IntentRunIdentityRefusal> for TaskClaimRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<CodecRefusal> for TaskClaimRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_claim_control(
    pulse: &AgentControlPulse,
    plan: &AgentChangePlan,
    run: &IntentRun,
) -> Result<IntentRunCommitment, TaskClaimRefusal> {
    if pulse.state() != PulseState::Actionable {
        return Err(TaskClaimRefusal::PulseNotActionable {
            state: pulse.state(),
        });
    }
    if plan.pulse_id() != pulse.pulse_id().as_bytes() {
        return Err(TaskClaimRefusal::PlanPulseMismatch);
    }
    let selected = pulse
        .selected()
        .ok_or(TaskClaimRefusal::PulseNotActionable {
            state: pulse.state(),
        })?;
    if plan.task_id() != selected.task_id() || plan.action() != selected.action() {
        return Err(TaskClaimRefusal::PlanSelectionMismatch);
    }
    if plan.intent_run_id() != run.run_id() {
        return Err(TaskClaimRefusal::PlanRunMismatch {
            expected: plan.intent_run_id(),
            observed: run.run_id(),
        });
    }
    let run_commitment = run.commitment()?;
    if plan.intent_run_commitment() != run_commitment {
        return Err(TaskClaimRefusal::PlanRunCommitmentMismatch {
            expected: plan.intent_run_commitment(),
            observed: run_commitment,
        });
    }
    if pulse.active_run_commitment() != Some(run_commitment) {
        return Err(TaskClaimRefusal::PulseRunCommitmentMismatch {
            expected: run_commitment,
            observed: pulse.active_run_commitment(),
        });
    }
    let run_receipt = run
        .authority_read_receipt()
        .ok_or(TaskClaimRefusal::RunAuthorityReceiptRequired)?;
    if run_receipt.repository_id() != pulse.repository_id()
        || run_receipt.authority_head_id() != pulse.authority_head_id()
        || run_receipt.authority_head_generation() != pulse.authority_head_generation()
    {
        return Err(TaskClaimRefusal::RunAuthorityMismatch);
    }
    Ok(run_commitment)
}

fn validate_projection(
    pulse: &AgentControlPulse,
    plan: &AgentChangePlan,
    run: &IntentRun,
    projection: &mut TaskClaimProjection,
) -> Result<(), TaskClaimRefusal> {
    if projection.task_id != plan.task_id() {
        return Err(TaskClaimRefusal::ProjectionTaskMismatch {
            expected: plan.task_id(),
            observed: projection.task_id,
        });
    }
    if projection.plan_id != plan.plan_id() {
        return Err(TaskClaimRefusal::ProjectionPlanMismatch {
            expected: plan.plan_id(),
            observed: projection.plan_id,
        });
    }
    if projection.assignee != run.run_id() {
        return Err(TaskClaimRefusal::ProjectionAssigneeMismatch {
            expected: run.run_id(),
            observed: projection.assignee,
        });
    }
    if projection.previous_task_projection_generation != *pulse.task_projection_generation() {
        return Err(TaskClaimRefusal::PreviousTaskGenerationMismatch {
            expected: *pulse.task_projection_generation(),
            observed: projection.previous_task_projection_generation,
        });
    }
    if is_zero(&projection.claimed_task_projection_generation) {
        return Err(TaskClaimRefusal::ZeroClaimedTaskGeneration);
    }
    if projection.claimed_task_projection_generation
        == projection.previous_task_projection_generation
    {
        return Err(TaskClaimRefusal::TaskGenerationUnchanged);
    }
    if projection.claimed_at.value() < pulse.observed_at().value() {
        return Err(TaskClaimRefusal::ClaimBeforePulse {
            pulse_observed: pulse.observed_at(),
            claimed_at: projection.claimed_at,
        });
    }
    if !run.is_open_at(projection.claimed_at) {
        return Err(TaskClaimRefusal::RunExpired {
            run_id: run.run_id(),
            observed: projection.claimed_at,
        });
    }
    if projection.expires_at.value() <= projection.claimed_at.value() {
        return Err(TaskClaimRefusal::InvalidClaimWindow {
            claimed_at: projection.claimed_at,
            expires_at: projection.expires_at,
        });
    }
    if projection.expires_at.value() > run.expiry().value() {
        return Err(TaskClaimRefusal::ClaimOutlivesRun {
            claim_expires_at: projection.expires_at,
            run_expires_at: run.expiry(),
        });
    }
    if is_zero(&projection.adapter_identity) {
        return Err(TaskClaimRefusal::ZeroAdapterIdentity);
    }
    if projection.reserved_surfaces.len() > MAX_CLAIM_SURFACES {
        return Err(TaskClaimRefusal::TooManyReservedSurfaces {
            observed: projection.reserved_surfaces.len(),
            limit: MAX_CLAIM_SURFACES,
        });
    }
    projection.reserved_surfaces.sort_unstable();
    for adjacent in projection.reserved_surfaces.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(TaskClaimRefusal::DuplicateReservedSurface {
                surface: adjacent[0],
            });
        }
    }
    if projection.reserved_surfaces != plan.conflict_surface() {
        return Err(TaskClaimRefusal::ReservationSurfaceMismatch);
    }
    Ok(())
}

fn validate_activation(
    claim: &TaskClaimReceipt,
    refreshed: &AgentSituationReceipt,
    run: &IntentRun,
) -> Result<(), TaskClaimRefusal> {
    let authority = refreshed.authority_read_receipt();
    if authority.repository_id() != claim.repository_id
        || authority.authority_head_id() != claim.authority_head_id
        || authority.authority_head_generation() != claim.authority_head_generation
    {
        return Err(TaskClaimRefusal::RefreshedAuthorityMismatch);
    }
    if refreshed.intent_run_id() != Some(claim.assignee) || run.run_id() != claim.assignee {
        return Err(TaskClaimRefusal::RefreshedRunMismatch);
    }
    let run_commitment = run.commitment()?;
    if run_commitment != claim.run_commitment
        || refreshed.intent_run_commitment() != Some(claim.run_commitment)
    {
        return Err(TaskClaimRefusal::RefreshedRunCommitmentMismatch {
            expected: claim.run_commitment,
            observed: refreshed.intent_run_commitment(),
        });
    }
    let run_receipt = run
        .authority_read_receipt()
        .ok_or(TaskClaimRefusal::RunAuthorityReceiptRequired)?;
    if run_receipt != authority {
        return Err(TaskClaimRefusal::RunAuthorityMismatch);
    }
    if refreshed.observed_at().value() < claim.claimed_at.value() {
        return Err(TaskClaimRefusal::RefreshedTimeRollback {
            claimed_at: claim.claimed_at,
            observed: refreshed.observed_at(),
        });
    }
    if refreshed.observed_at().value() >= claim.expires_at.value() {
        return Err(TaskClaimRefusal::ClaimExpired {
            expires_at: claim.expires_at,
            observed: refreshed.observed_at(),
        });
    }
    if !run.is_open_at(refreshed.observed_at()) {
        return Err(TaskClaimRefusal::RunExpired {
            run_id: run.run_id(),
            observed: refreshed.observed_at(),
        });
    }
    let task = refreshed.component(SituationComponentKind::TaskProjection);
    let generation = match (
        task.generation_commitment(),
        task.omission_reason(),
        task.omission_detail_commitment(),
    ) {
        (Some(generation), None, None) => generation,
        _ => return Err(TaskClaimRefusal::RefreshedTaskProjectionUnavailable),
    };
    if generation != claim.claimed_task_projection_generation {
        return Err(TaskClaimRefusal::ClaimGenerationNotObserved {
            expected: claim.claimed_task_projection_generation,
            observed: generation,
        });
    }
    Ok(())
}

fn claim_commitment(claim: &TaskClaimReceipt) -> Result<[u8; 32], TaskClaimRefusal> {
    let mut encoder = Encoder::with_capacity(832);
    encoder.write_bytes("task_claim_domain", CLAIM_DOMAIN)?;
    encoder.write_raw(claim.plan_id.as_bytes());
    encoder.write_raw(&claim.pulse_id);
    encoder.write_raw(&claim.situation_id);
    encoder.write_raw(claim.frontier_id.as_bytes());
    encoder.write_opaque_id(claim.repository_id.as_bytes());
    encoder.write_internal_object_id(claim.authority_head_id.as_internal_object_id())?;
    encoder.write_scalar(claim.authority_head_generation.get());
    encoder.write_raw(claim.task_id.as_bytes());
    encoder.write_raw_byte(work_action_code(claim.action));
    encoder.write_raw(&claim.assignee.value().to_be_bytes());
    encoder.write_raw(claim.run_commitment.as_bytes());
    encoder.write_raw(&claim.previous_task_projection_generation);
    encoder.write_raw(&claim.claimed_task_projection_generation);
    write_surfaces(&mut encoder, &claim.reserved_surfaces)?;
    encoder.write_scalar(claim.claimed_at.value());
    encoder.write_scalar(claim.expires_at.value());
    encoder.write_raw(&claim.adapter_identity);
    encoder.write_digest(&claim.claim_evidence_root)?;
    Ok(hash(encoder.into_bytes()))
}

fn activation_commitment(active: &ActiveTaskClaim) -> Result<[u8; 32], TaskClaimRefusal> {
    let mut encoder = Encoder::with_capacity(320);
    encoder.write_bytes("task_claim_activation_domain", ACTIVATION_DOMAIN)?;
    encoder.write_raw(active.claim_id.as_bytes());
    encoder.write_raw(active.plan_id.as_bytes());
    encoder.write_raw(&active.situation_id);
    encoder.write_raw(active.task_id.as_bytes());
    encoder.write_raw(&active.assignee.value().to_be_bytes());
    encoder.write_raw(active.run_commitment.as_bytes());
    encoder.write_scalar(active.observed_at.value());
    encoder.write_scalar(active.expires_at.value());
    Ok(hash(encoder.into_bytes()))
}

fn write_surfaces(encoder: &mut Encoder, surfaces: &[PlanSurface]) -> Result<(), TaskClaimRefusal> {
    let count = u32::try_from(surfaces.len()).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field: "task_claim.reserved_surfaces",
        observed: u64::try_from(surfaces.len()).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    for surface in surfaces {
        encoder.write_raw_byte(surface_kind_code(surface.kind()));
        encoder.write_digest(&surface.selector())?;
    }
    Ok(())
}

fn hash(bytes: Vec<u8>) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&bytes);
    hasher.finish()
}

fn surfaces_overlap(left: &[PlanSurface], right: &[PlanSurface]) -> bool {
    let mut left_index = 0;
    let mut right_index = 0;
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            core::cmp::Ordering::Less => left_index += 1,
            core::cmp::Ordering::Greater => right_index += 1,
            core::cmp::Ordering::Equal => return true,
        }
    }
    false
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

const fn work_action_code(action: WorkAction) -> u8 {
    match action {
        WorkAction::Implement => 1,
        WorkAction::Verify => 2,
        WorkAction::Rework => 3,
    }
}

const fn surface_kind_code(kind: crate::PlanSurfaceKind) -> u8 {
    match kind {
        crate::PlanSurfaceKind::RepositoryPath => 1,
        crate::PlanSurfaceKind::Ref => 2,
        crate::PlanSurfaceKind::ForgeEntity => 3,
        crate::PlanSurfaceKind::SchemaOrRegistry => 4,
        crate::PlanSurfaceKind::EvidenceTarget => 5,
        crate::PlanSurfaceKind::ExternalEffect => 6,
        crate::PlanSurfaceKind::Workspace => 7,
    }
}
