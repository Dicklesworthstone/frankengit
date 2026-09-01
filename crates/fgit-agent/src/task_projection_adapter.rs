//! Deterministic task-projection transitions for claim, release, and transfer.
//!
//! [`crate::TaskClaimProjection`] and
//! [`crate::TaskClaimCancellationProjection`] are adapter observations. This
//! module supplies the missing transition kernel that a Beads or other task
//! backend can place behind those observations. It validates one exact
//! predecessor snapshot, computes one deterministic successor generation, and
//! returns both the successor snapshot and the projection consumed by the
//! existing claim/cancellation protocols.
//!
//! The kernel is deliberately storage-agnostic. A production adapter must
//! persist the transition with exact-predecessor compare-and-replace semantics
//! and return the persisted evidence root. [`TaskProjectionSnapshot`] is an
//! immutable value, not a durable database and not repository authority.
//!
//! Transfer is represented as release of the source lease plus an assignment
//! hint for the successor. The successor still opens its own Intent Run, plan,
//! pulse, claim receipt, and activation against the new generation; a transfer
//! never reuses the source plan or mints receiver authority.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::Digest;

use crate::{
    ActiveTaskClaim, AgentChangePlan, AgentChangePlanId, AgentControlPulse, IntentRun,
    LogicalTime, PlanSurface, RunId, TaskClaimCancellationOutcome,
    TaskClaimCancellationProjection, TaskClaimProjection, TaskClaimReceipt, TaskPhase,
    WorkAction, WorkTaskId,
};

const SNAPSHOT_DOMAIN: &[u8] = b"frankengit.agent.task-projection-snapshot/v1\0";
const GENERATION_DOMAIN: &[u8] = b"frankengit.agent.task-projection-generation/v1\0";
const TRANSITION_DOMAIN: &[u8] = b"frankengit.agent.task-projection-transition/v1\0";

/// Stable identity of one immutable task-projection snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskProjectionSnapshotId([u8; 32]);

impl TaskProjectionSnapshotId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TaskProjectionSnapshotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task-snapshot:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable identity of one task-projection transition.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskProjectionTransitionId([u8; 32]);

impl TaskProjectionTransitionId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TaskProjectionTransitionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task-transition:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Assignment projected by the task backend.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TaskProjectionAssignment {
    /// No run is currently preferred or assigned.
    Unassigned,
    /// The task is assigned to one Intent Run.
    Assigned(RunId),
}

/// Active lease material retained by the projection kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjectionLease {
    plan_id: AgentChangePlanId,
    assignee: RunId,
    previous_generation: [u8; 32],
    claimed_generation: [u8; 32],
    reserved_surfaces: Vec<PlanSurface>,
    claimed_at: LogicalTime,
    expires_at: LogicalTime,
}

impl TaskProjectionLease {
    /// Plan that established this lease.
    #[must_use]
    pub const fn plan_id(&self) -> AgentChangePlanId {
        self.plan_id
    }

    /// Run assigned by this lease.
    #[must_use]
    pub const fn assignee(&self) -> RunId {
        self.assignee
    }

    /// Projection generation replaced by the claim.
    #[must_use]
    pub const fn previous_generation(&self) -> &[u8; 32] {
        &self.previous_generation
    }

    /// Projection generation created by the claim.
    #[must_use]
    pub const fn claimed_generation(&self) -> &[u8; 32] {
        &self.claimed_generation
    }

    /// Exact coordination surface reserved by the claim.
    #[must_use]
    pub fn reserved_surfaces(&self) -> &[PlanSurface] {
        &self.reserved_surfaces
    }

    /// Logical claim instant.
    #[must_use]
    pub const fn claimed_at(&self) -> LogicalTime {
        self.claimed_at
    }

    /// Exclusive lease expiry.
    #[must_use]
    pub const fn expires_at(&self) -> LogicalTime {
        self.expires_at
    }
}

/// Immutable task state at one derived projection generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjectionSnapshot {
    snapshot_id: TaskProjectionSnapshotId,
    task_id: WorkTaskId,
    generation: [u8; 32],
    phase: TaskPhase,
    assignment: TaskProjectionAssignment,
    lease: Option<TaskProjectionLease>,
}

impl TaskProjectionSnapshot {
    /// Imports one observed task row without claiming durability or authority.
    ///
    /// # Errors
    ///
    /// Refuses the reserved all-zero generation and an assigned terminal task.
    pub fn observed(
        task_id: WorkTaskId,
        generation: [u8; 32],
        phase: TaskPhase,
        assignment: TaskProjectionAssignment,
    ) -> Result<Self, TaskProjectionAdapterRefusal> {
        if is_zero(&generation) {
            return Err(TaskProjectionAdapterRefusal::ZeroGeneration);
        }
        if phase_is_terminal(phase)
            && !matches!(assignment, TaskProjectionAssignment::Unassigned)
        {
            return Err(TaskProjectionAdapterRefusal::TerminalTaskAssigned { phase });
        }
        let mut snapshot = Self {
            snapshot_id: TaskProjectionSnapshotId([0; 32]),
            task_id,
            generation,
            phase,
            assignment,
            lease: None,
        };
        snapshot.snapshot_id = TaskProjectionSnapshotId(snapshot_commitment(&snapshot)?);
        Ok(snapshot)
    }

    /// Applies one exact plan claim to this projection snapshot.
    ///
    /// # Errors
    ///
    /// Refuses stale pulse generations, task/phase/plan/run substitution,
    /// assignment conflicts, an existing lease, invalid or amplified lifetime,
    /// a zero adapter profile, generation collision, and canonical framing
    /// failure.
    #[allow(clippy::too_many_arguments)]
    pub fn claim(
        &self,
        pulse: &AgentControlPulse,
        plan: &AgentChangePlan,
        run: &IntentRun,
        claimed_at: LogicalTime,
        expires_at: LogicalTime,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Result<TaskClaimApplication, TaskProjectionAdapterRefusal> {
        validate_claim_basis(self, pulse, plan, run)?;
        if self.lease.is_some() {
            return Err(TaskProjectionAdapterRefusal::ActiveLeaseExists);
        }
        match self.assignment {
            TaskProjectionAssignment::Unassigned => {}
            TaskProjectionAssignment::Assigned(assigned) if assigned == run.run_id() => {}
            TaskProjectionAssignment::Assigned(assigned) => {
                return Err(TaskProjectionAdapterRefusal::AssignedToOther {
                    assigned,
                    requested: run.run_id(),
                });
            }
        }
        if claimed_at.value() < pulse.observed_at().value() {
            return Err(TaskProjectionAdapterRefusal::ClaimBeforePulse {
                pulse_observed_at: pulse.observed_at(),
                claimed_at,
            });
        }
        if !run.is_open_at(claimed_at) {
            return Err(TaskProjectionAdapterRefusal::RunExpiredAtClaim {
                expires_at: run.expiry(),
                claimed_at,
            });
        }
        if expires_at.value() <= claimed_at.value() {
            return Err(TaskProjectionAdapterRefusal::InvalidClaimWindow {
                claimed_at,
                expires_at,
            });
        }
        if expires_at.value() > run.expiry().value() {
            return Err(TaskProjectionAdapterRefusal::ClaimOutlivesRun {
                claim_expires_at: expires_at,
                run_expires_at: run.expiry(),
            });
        }
        if is_zero(&adapter_identity) {
            return Err(TaskProjectionAdapterRefusal::ZeroAdapterIdentity);
        }

        let reserved_surfaces = plan.conflict_surface().to_vec();
        let next_generation = derive_claim_generation(
            self,
            plan,
            run,
            claimed_at,
            expires_at,
            &reserved_surfaces,
            adapter_identity,
            evidence_root,
        )?;
        validate_successor_generation(self.generation, next_generation)?;

        let projection = TaskClaimProjection::new(
            self.task_id,
            plan.plan_id(),
            run.run_id(),
            self.generation,
            next_generation,
            reserved_surfaces.clone(),
            claimed_at,
            expires_at,
            adapter_identity,
            evidence_root,
        );
        let lease = TaskProjectionLease {
            plan_id: plan.plan_id(),
            assignee: run.run_id(),
            previous_generation: self.generation,
            claimed_generation: next_generation,
            reserved_surfaces,
            claimed_at,
            expires_at,
        };
        let phase = phase_after_claim(plan.action());
        let after = TaskProjectionSnapshot::from_parts(
            self.task_id,
            next_generation,
            phase,
            TaskProjectionAssignment::Assigned(run.run_id()),
            Some(lease),
        )?;
        let transition = TaskProjectionTransition::build(
            self,
            &after,
            TaskProjectionTransitionKind::Claimed {
                action: plan.action(),
            },
            claimed_at,
            adapter_identity,
            evidence_root,
        )?;
        Ok(TaskClaimApplication {
            snapshot: after,
            transition,
            projection,
        })
    }

    /// Releases one activated claim back to an unassigned actionable phase.
    ///
    /// Release remains available after the claim or run expires; expiry prevents
    /// new work, not responsibility cleanup.
    ///
    /// # Errors
    ///
    /// Refuses lease, receipt, claim, run, generation, surface, and time
    /// substitution, a zero adapter profile, generation collision, and framing
    /// failure.
    #[allow(clippy::too_many_arguments)]
    pub fn release(
        &self,
        claim_receipt: &TaskClaimReceipt,
        active_claim: ActiveTaskClaim,
        source_run: &IntentRun,
        disposition: TaskReleaseDisposition,
        resolved_at: LogicalTime,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Result<TaskResolutionApplication, TaskProjectionAdapterRefusal> {
        let lease = validate_resolution_basis(
            self,
            claim_receipt,
            active_claim,
            source_run,
            resolved_at,
            adapter_identity,
        )?;
        let next_phase = disposition.phase();
        let kind = TaskProjectionTransitionKind::Released { next_phase };
        let next_generation = derive_resolution_generation(
            self,
            claim_receipt,
            active_claim,
            kind,
            resolved_at,
            adapter_identity,
            evidence_root,
        )?;
        validate_successor_generation(self.generation, next_generation)?;
        let projection = TaskClaimCancellationProjection::new(
            active_claim.activation_id(),
            active_claim.claim_id(),
            active_claim.plan_id(),
            active_claim.task_id(),
            active_claim.assignee(),
            self.generation,
            next_generation,
            resolved_at,
            TaskClaimCancellationOutcome::Released,
            adapter_identity,
            evidence_root,
        );
        let after = TaskProjectionSnapshot::from_parts(
            self.task_id,
            next_generation,
            next_phase,
            TaskProjectionAssignment::Unassigned,
            None,
        )?;
        let transition = TaskProjectionTransition::build(
            self,
            &after,
            kind,
            resolved_at,
            adapter_identity,
            evidence_root,
        )?;
        debug_assert_eq!(lease.claimed_generation, self.generation);
        Ok(TaskResolutionApplication {
            snapshot: after,
            transition,
            projection,
        })
    }

    /// Transfers assignment preference to another run and releases the source
    /// lease atomically at one projection generation.
    ///
    /// The successor receives no plan, capability, or active claim. It must
    /// build a new pulse and plan, claim the new generation, and activate that
    /// claim before continuing work.
    ///
    /// # Errors
    ///
    /// Refuses source lease substitution, self-transfer, a successor from a
    /// different authority basis, an expired successor, zero adapter identity,
    /// generation collision, and framing failure.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer(
        &self,
        claim_receipt: &TaskClaimReceipt,
        active_claim: ActiveTaskClaim,
        source_run: &IntentRun,
        successor_run: &IntentRun,
        resolved_at: LogicalTime,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Result<TaskResolutionApplication, TaskProjectionAdapterRefusal> {
        validate_resolution_basis(
            self,
            claim_receipt,
            active_claim,
            source_run,
            resolved_at,
            adapter_identity,
        )?;
        if successor_run.run_id() == source_run.run_id() {
            return Err(TaskProjectionAdapterRefusal::TransferToSourceRun);
        }
        let source_authority = source_run
            .authority_read_receipt()
            .ok_or(TaskProjectionAdapterRefusal::RunAuthorityReceiptRequired)?;
        let successor_authority = successor_run
            .authority_read_receipt()
            .ok_or(TaskProjectionAdapterRefusal::SuccessorAuthorityReceiptRequired)?;
        if source_authority != successor_authority {
            return Err(TaskProjectionAdapterRefusal::SuccessorAuthorityMismatch);
        }
        if !successor_run.is_open_at(resolved_at) {
            return Err(TaskProjectionAdapterRefusal::SuccessorRunExpired {
                expires_at: successor_run.expiry(),
                resolved_at,
            });
        }

        let kind = TaskProjectionTransitionKind::Transferred {
            successor_run_id: successor_run.run_id(),
        };
        let next_generation = derive_resolution_generation(
            self,
            claim_receipt,
            active_claim,
            kind,
            resolved_at,
            adapter_identity,
            evidence_root,
        )?;
        validate_successor_generation(self.generation, next_generation)?;
        let projection = TaskClaimCancellationProjection::new(
            active_claim.activation_id(),
            active_claim.claim_id(),
            active_claim.plan_id(),
            active_claim.task_id(),
            active_claim.assignee(),
            self.generation,
            next_generation,
            resolved_at,
            TaskClaimCancellationOutcome::Transferred {
                successor_run_id: successor_run.run_id(),
            },
            adapter_identity,
            evidence_root,
        );
        let after = TaskProjectionSnapshot::from_parts(
            self.task_id,
            next_generation,
            self.phase,
            TaskProjectionAssignment::Assigned(successor_run.run_id()),
            None,
        )?;
        let transition = TaskProjectionTransition::build(
            self,
            &after,
            kind,
            resolved_at,
            adapter_identity,
            evidence_root,
        )?;
        Ok(TaskResolutionApplication {
            snapshot: after,
            transition,
            projection,
        })
    }

    fn from_parts(
        task_id: WorkTaskId,
        generation: [u8; 32],
        phase: TaskPhase,
        assignment: TaskProjectionAssignment,
        lease: Option<TaskProjectionLease>,
    ) -> Result<Self, TaskProjectionAdapterRefusal> {
        let mut snapshot = Self {
            snapshot_id: TaskProjectionSnapshotId([0; 32]),
            task_id,
            generation,
            phase,
            assignment,
            lease,
        };
        snapshot.snapshot_id = TaskProjectionSnapshotId(snapshot_commitment(&snapshot)?);
        Ok(snapshot)
    }

    /// Stable snapshot identity.
    #[must_use]
    pub const fn snapshot_id(&self) -> TaskProjectionSnapshotId {
        self.snapshot_id
    }

    /// Task represented by the snapshot.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.task_id
    }

    /// Exact projection generation.
    #[must_use]
    pub const fn generation(&self) -> &[u8; 32] {
        &self.generation
    }

    /// Projected task phase.
    #[must_use]
    pub const fn phase(&self) -> TaskPhase {
        self.phase
    }

    /// Projected assignment.
    #[must_use]
    pub const fn assignment(&self) -> TaskProjectionAssignment {
        self.assignment
    }

    /// Active lease, when a claim transition established one.
    #[must_use]
    pub const fn lease(&self) -> Option<&TaskProjectionLease> {
        self.lease.as_ref()
    }
}

/// Release destination for a cancelled or relinquished task claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TaskReleaseDisposition {
    /// Return the task to ordinary open work.
    ReturnToOpen,
    /// Make the failed or interrupted attempt explicit rework.
    RequireRework,
}

impl TaskReleaseDisposition {
    const fn phase(self) -> TaskPhase {
        match self {
            Self::ReturnToOpen => TaskPhase::Open,
            Self::RequireRework => TaskPhase::Rework,
        }
    }

    const fn code_point(self) -> u8 {
        match self {
            Self::ReturnToOpen => 1,
            Self::RequireRework => 2,
        }
    }
}

/// Semantic class of one task-projection transition.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TaskProjectionTransitionKind {
    /// One run acquired the task under a selected action.
    Claimed {
        /// Action selected by the control pulse.
        action: WorkAction,
    },
    /// One run released its lease.
    Released {
        /// Resulting unassigned phase.
        next_phase: TaskPhase,
    },
    /// One run released its lease and assigned the task to a successor.
    Transferred {
        /// Successor preference; not an active claim.
        successor_run_id: RunId,
    },
}

impl TaskProjectionTransitionKind {
    const fn code_point(self) -> u8 {
        match self {
            Self::Claimed { .. } => 1,
            Self::Released { .. } => 2,
            Self::Transferred { .. } => 3,
        }
    }
}

/// Stable receipt for one exact-predecessor task transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskProjectionTransition {
    transition_id: TaskProjectionTransitionId,
    before_snapshot_id: TaskProjectionSnapshotId,
    after_snapshot_id: TaskProjectionSnapshotId,
    task_id: WorkTaskId,
    previous_generation: [u8; 32],
    resulting_generation: [u8; 32],
    kind: TaskProjectionTransitionKind,
    observed_at: LogicalTime,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
}

impl TaskProjectionTransition {
    fn build(
        before: &TaskProjectionSnapshot,
        after: &TaskProjectionSnapshot,
        kind: TaskProjectionTransitionKind,
        observed_at: LogicalTime,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Result<Self, TaskProjectionAdapterRefusal> {
        let mut transition = Self {
            transition_id: TaskProjectionTransitionId([0; 32]),
            before_snapshot_id: before.snapshot_id,
            after_snapshot_id: after.snapshot_id,
            task_id: before.task_id,
            previous_generation: before.generation,
            resulting_generation: after.generation,
            kind,
            observed_at,
            adapter_identity,
            evidence_root,
        };
        transition.transition_id =
            TaskProjectionTransitionId(transition_commitment(&transition)?);
        Ok(transition)
    }

    /// Stable transition identity.
    #[must_use]
    pub const fn transition_id(self) -> TaskProjectionTransitionId {
        self.transition_id
    }

    /// Exact predecessor snapshot.
    #[must_use]
    pub const fn before_snapshot_id(self) -> TaskProjectionSnapshotId {
        self.before_snapshot_id
    }

    /// Exact successor snapshot.
    #[must_use]
    pub const fn after_snapshot_id(self) -> TaskProjectionSnapshotId {
        self.after_snapshot_id
    }

    /// Task changed.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }

    /// Replaced generation.
    #[must_use]
    pub const fn previous_generation(self) -> [u8; 32] {
        self.previous_generation
    }

    /// New generation.
    #[must_use]
    pub const fn resulting_generation(self) -> [u8; 32] {
        self.resulting_generation
    }

    /// Transition semantics.
    #[must_use]
    pub const fn kind(self) -> TaskProjectionTransitionKind {
        self.kind
    }

    /// Logical mutation observation.
    #[must_use]
    pub const fn observed_at(self) -> LogicalTime {
        self.observed_at
    }

    /// Adapter implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Persistence or external-mutation evidence root.
    #[must_use]
    pub const fn evidence_root(self) -> Digest {
        self.evidence_root
    }
}

/// Result of one successful claim transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskClaimApplication {
    snapshot: TaskProjectionSnapshot,
    transition: TaskProjectionTransition,
    projection: TaskClaimProjection,
}

impl TaskClaimApplication {
    /// Successor task snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &TaskProjectionSnapshot {
        &self.snapshot
    }

    /// Exact transition receipt.
    #[must_use]
    pub const fn transition(&self) -> TaskProjectionTransition {
        self.transition
    }

    /// Projection consumed by [`TaskClaimReceipt::admit`].
    #[must_use]
    pub const fn projection(&self) -> &TaskClaimProjection {
        &self.projection
    }

    /// Decomposes the application for persistence and admission.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        TaskProjectionSnapshot,
        TaskProjectionTransition,
        TaskClaimProjection,
    ) {
        (self.snapshot, self.transition, self.projection)
    }
}

/// Result of one successful release or transfer transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskResolutionApplication {
    snapshot: TaskProjectionSnapshot,
    transition: TaskProjectionTransition,
    projection: TaskClaimCancellationProjection,
}

impl TaskResolutionApplication {
    /// Successor task snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &TaskProjectionSnapshot {
        &self.snapshot
    }

    /// Exact transition receipt.
    #[must_use]
    pub const fn transition(&self) -> TaskProjectionTransition {
        self.transition
    }

    /// Projection consumed by cancellation completion or handoff transfer logic.
    #[must_use]
    pub const fn projection(&self) -> &TaskClaimCancellationProjection {
        &self.projection
    }

    /// Decomposes the application for persistence and reconciliation.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        TaskProjectionSnapshot,
        TaskProjectionTransition,
        TaskClaimCancellationProjection,
    ) {
        (self.snapshot, self.transition, self.projection)
    }
}

/// Why the deterministic task-projection kernel refused a transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionAdapterRefusal {
    /// Projection generation used the reserved all-zero value.
    ZeroGeneration,
    /// A terminal task carried an assignment.
    TerminalTaskAssigned {
        /// Terminal phase observed.
        phase: TaskPhase,
    },
    /// Pulse carried no selected task.
    PulseNotActionable,
    /// Snapshot and pulse name different tasks.
    PulseTaskMismatch,
    /// Snapshot and pulse name different task phases.
    PulsePhaseMismatch {
        /// Snapshot phase.
        snapshot: TaskPhase,
        /// Pulse phase.
        pulse: TaskPhase,
    },
    /// Pulse used another task-projection generation.
    PulseGenerationMismatch {
        /// Snapshot generation.
        snapshot: [u8; 32],
        /// Pulse generation.
        pulse: [u8; 32],
    },
    /// Plan belongs to another pulse.
    PlanPulseMismatch,
    /// Plan names another task.
    PlanTaskMismatch,
    /// Plan phase differs from the snapshot.
    PlanPhaseMismatch {
        /// Snapshot phase.
        snapshot: TaskPhase,
        /// Plan phase.
        plan: TaskPhase,
    },
    /// Plan action differs from the pulse selection.
    PlanActionMismatch,
    /// Plan belongs to another run.
    PlanRunMismatch {
        /// Plan run.
        expected: RunId,
        /// Supplied run.
        observed: RunId,
    },
    /// Pulse names another active run.
    PulseRunMismatch,
    /// Run lacks a complete authenticated authority receipt.
    RunAuthorityReceiptRequired,
    /// Snapshot is assigned to another run.
    AssignedToOther {
        /// Existing assignment.
        assigned: RunId,
        /// Requested claimant.
        requested: RunId,
    },
    /// Snapshot already carries an active lease.
    ActiveLeaseExists,
    /// Claim mutation predates the pulse observation.
    ClaimBeforePulse {
        /// Pulse observation.
        pulse_observed_at: LogicalTime,
        /// Proposed claim time.
        claimed_at: LogicalTime,
    },
    /// Source run is expired at claim time.
    RunExpiredAtClaim {
        /// Exclusive run expiry.
        expires_at: LogicalTime,
        /// Proposed claim time.
        claimed_at: LogicalTime,
    },
    /// Claim interval is empty or inverted.
    InvalidClaimWindow {
        /// Claim instant.
        claimed_at: LogicalTime,
        /// Exclusive expiry.
        expires_at: LogicalTime,
    },
    /// Claim expiry exceeds run expiry.
    ClaimOutlivesRun {
        /// Claim expiry.
        claim_expires_at: LogicalTime,
        /// Run expiry.
        run_expires_at: LogicalTime,
    },
    /// Adapter implementation/profile identity was all zero.
    ZeroAdapterIdentity,
    /// Successor generation was zero or identical to its predecessor.
    GenerationDidNotAdvance,
    /// Release/transfer snapshot has no active lease.
    MissingActiveLease,
    /// Claim receipt names another task.
    ClaimReceiptTaskMismatch,
    /// Claim receipt names another plan.
    ClaimReceiptPlanMismatch,
    /// Claim receipt names another run.
    ClaimReceiptRunMismatch,
    /// Claim receipt generation differs from the active snapshot.
    ClaimReceiptGenerationMismatch,
    /// Claim receipt reserved another conflict surface.
    ClaimReceiptSurfaceMismatch,
    /// Active claim names another claim receipt.
    ActiveClaimReceiptMismatch,
    /// Active claim names another plan.
    ActiveClaimPlanMismatch,
    /// Active claim names another task.
    ActiveClaimTaskMismatch,
    /// Active claim names another run.
    ActiveClaimRunMismatch,
    /// Resolution predates activation observation.
    ResolutionBeforeActivation {
        /// Activation observation.
        activated_at: LogicalTime,
        /// Proposed resolution.
        resolved_at: LogicalTime,
    },
    /// Transfer selected the source run as its own successor.
    TransferToSourceRun,
    /// Successor run lacks a complete authenticated authority receipt.
    SuccessorAuthorityReceiptRequired,
    /// Source and successor runs use different authority receipts.
    SuccessorAuthorityMismatch,
    /// Successor run is expired at transfer time.
    SuccessorRunExpired {
        /// Exclusive successor expiry.
        expires_at: LogicalTime,
        /// Transfer instant.
        resolved_at: LogicalTime,
    },
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for TaskProjectionAdapterRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task projection transition refused: {self:?}")
    }
}

impl core::error::Error for TaskProjectionAdapterRefusal {}

impl From<CodecRefusal> for TaskProjectionAdapterRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_claim_basis(
    snapshot: &TaskProjectionSnapshot,
    pulse: &AgentControlPulse,
    plan: &AgentChangePlan,
    run: &IntentRun,
) -> Result<(), TaskProjectionAdapterRefusal> {
    let selected = pulse
        .selected()
        .ok_or(TaskProjectionAdapterRefusal::PulseNotActionable)?;
    if selected.task_id() != snapshot.task_id {
        return Err(TaskProjectionAdapterRefusal::PulseTaskMismatch);
    }
    if selected.phase() != snapshot.phase {
        return Err(TaskProjectionAdapterRefusal::PulsePhaseMismatch {
            snapshot: snapshot.phase,
            pulse: selected.phase(),
        });
    }
    if *pulse.task_projection_generation() != snapshot.generation {
        return Err(TaskProjectionAdapterRefusal::PulseGenerationMismatch {
            snapshot: snapshot.generation,
            pulse: *pulse.task_projection_generation(),
        });
    }
    if plan.pulse_id() != pulse.pulse_id().as_bytes() {
        return Err(TaskProjectionAdapterRefusal::PlanPulseMismatch);
    }
    if plan.task_id() != snapshot.task_id {
        return Err(TaskProjectionAdapterRefusal::PlanTaskMismatch);
    }
    if plan.task_phase() != snapshot.phase {
        return Err(TaskProjectionAdapterRefusal::PlanPhaseMismatch {
            snapshot: snapshot.phase,
            plan: plan.task_phase(),
        });
    }
    if plan.action() != selected.action() {
        return Err(TaskProjectionAdapterRefusal::PlanActionMismatch);
    }
    if plan.intent_run_id() != run.run_id() {
        return Err(TaskProjectionAdapterRefusal::PlanRunMismatch {
            expected: plan.intent_run_id(),
            observed: run.run_id(),
        });
    }
    if pulse.active_run() != Some(run.run_id()) {
        return Err(TaskProjectionAdapterRefusal::PulseRunMismatch);
    }
    run.authority_read_receipt()
        .ok_or(TaskProjectionAdapterRefusal::RunAuthorityReceiptRequired)?;
    Ok(())
}

fn validate_resolution_basis<'a>(
    snapshot: &'a TaskProjectionSnapshot,
    claim_receipt: &TaskClaimReceipt,
    active_claim: ActiveTaskClaim,
    source_run: &IntentRun,
    resolved_at: LogicalTime,
    adapter_identity: [u8; 32],
) -> Result<&'a TaskProjectionLease, TaskProjectionAdapterRefusal> {
    let lease = snapshot
        .lease
        .as_ref()
        .ok_or(TaskProjectionAdapterRefusal::MissingActiveLease)?;
    if claim_receipt.task_id() != snapshot.task_id {
        return Err(TaskProjectionAdapterRefusal::ClaimReceiptTaskMismatch);
    }
    if claim_receipt.plan_id() != lease.plan_id {
        return Err(TaskProjectionAdapterRefusal::ClaimReceiptPlanMismatch);
    }
    if claim_receipt.assignee() != lease.assignee || source_run.run_id() != lease.assignee {
        return Err(TaskProjectionAdapterRefusal::ClaimReceiptRunMismatch);
    }
    if *claim_receipt.claimed_task_projection_generation() != snapshot.generation
        || lease.claimed_generation != snapshot.generation
    {
        return Err(TaskProjectionAdapterRefusal::ClaimReceiptGenerationMismatch);
    }
    if claim_receipt.reserved_surfaces() != lease.reserved_surfaces {
        return Err(TaskProjectionAdapterRefusal::ClaimReceiptSurfaceMismatch);
    }
    if active_claim.claim_id() != claim_receipt.claim_id() {
        return Err(TaskProjectionAdapterRefusal::ActiveClaimReceiptMismatch);
    }
    if active_claim.plan_id() != lease.plan_id {
        return Err(TaskProjectionAdapterRefusal::ActiveClaimPlanMismatch);
    }
    if active_claim.task_id() != snapshot.task_id {
        return Err(TaskProjectionAdapterRefusal::ActiveClaimTaskMismatch);
    }
    if active_claim.assignee() != lease.assignee {
        return Err(TaskProjectionAdapterRefusal::ActiveClaimRunMismatch);
    }
    if resolved_at.value() < active_claim.observed_at().value() {
        return Err(TaskProjectionAdapterRefusal::ResolutionBeforeActivation {
            activated_at: active_claim.observed_at(),
            resolved_at,
        });
    }
    if is_zero(&adapter_identity) {
        return Err(TaskProjectionAdapterRefusal::ZeroAdapterIdentity);
    }
    source_run
        .authority_read_receipt()
        .ok_or(TaskProjectionAdapterRefusal::RunAuthorityReceiptRequired)?;
    Ok(lease)
}

fn derive_claim_generation(
    snapshot: &TaskProjectionSnapshot,
    plan: &AgentChangePlan,
    run: &IntentRun,
    claimed_at: LogicalTime,
    expires_at: LogicalTime,
    surfaces: &[PlanSurface],
    adapter_identity: [u8; 32],
    evidence_root: Digest,
) -> Result<[u8; 32], TaskProjectionAdapterRefusal> {
    let mut encoder = Encoder::with_capacity(512);
    encoder.write_bytes("task_projection_generation_domain", GENERATION_DOMAIN)?;
    encoder.write_raw_byte(1);
    encoder.write_raw(&snapshot.generation);
    encoder.write_raw(snapshot.task_id.as_bytes());
    encoder.write_raw(plan.plan_id().as_bytes());
    encoder.write_raw(&run.run_id().value().to_be_bytes());
    encoder.write_scalar(claimed_at.value());
    encoder.write_scalar(expires_at.value());
    write_surfaces(&mut encoder, surfaces)?;
    encoder.write_raw(&adapter_identity);
    encoder.write_digest(&evidence_root)?;
    Ok(hash(&encoder.into_bytes()))
}

fn derive_resolution_generation(
    snapshot: &TaskProjectionSnapshot,
    claim_receipt: &TaskClaimReceipt,
    active_claim: ActiveTaskClaim,
    kind: TaskProjectionTransitionKind,
    resolved_at: LogicalTime,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
) -> Result<[u8; 32], TaskProjectionAdapterRefusal> {
    let mut encoder = Encoder::with_capacity(512);
    encoder.write_bytes("task_projection_generation_domain", GENERATION_DOMAIN)?;
    encoder.write_raw_byte(kind.code_point());
    encoder.write_raw(&snapshot.generation);
    encoder.write_raw(snapshot.task_id.as_bytes());
    encoder.write_raw(claim_receipt.claim_id().as_bytes());
    encoder.write_raw(active_claim.activation_id().as_bytes());
    write_transition_kind(&mut encoder, kind)?;
    encoder.write_scalar(resolved_at.value());
    encoder.write_raw(&adapter_identity);
    encoder.write_digest(&evidence_root)?;
    Ok(hash(&encoder.into_bytes()))
}

fn snapshot_commitment(
    snapshot: &TaskProjectionSnapshot,
) -> Result<[u8; 32], TaskProjectionAdapterRefusal> {
    let mut encoder = Encoder::with_capacity(512);
    encoder.write_bytes("task_projection_snapshot_domain", SNAPSHOT_DOMAIN)?;
    encoder.write_raw(snapshot.task_id.as_bytes());
    encoder.write_raw(&snapshot.generation);
    encoder.write_raw_byte(task_phase_code(snapshot.phase));
    match snapshot.assignment {
        TaskProjectionAssignment::Unassigned => encoder.write_bool(false),
        TaskProjectionAssignment::Assigned(run_id) => {
            encoder.write_bool(true);
            encoder.write_raw(&run_id.value().to_be_bytes());
        }
    }
    match &snapshot.lease {
        None => encoder.write_bool(false),
        Some(lease) => {
            encoder.write_bool(true);
            encoder.write_raw(lease.plan_id.as_bytes());
            encoder.write_raw(&lease.assignee.value().to_be_bytes());
            encoder.write_raw(&lease.previous_generation);
            encoder.write_raw(&lease.claimed_generation);
            write_surfaces(&mut encoder, &lease.reserved_surfaces)?;
            encoder.write_scalar(lease.claimed_at.value());
            encoder.write_scalar(lease.expires_at.value());
        }
    }
    Ok(hash(&encoder.into_bytes()))
}

fn transition_commitment(
    transition: &TaskProjectionTransition,
) -> Result<[u8; 32], TaskProjectionAdapterRefusal> {
    let mut encoder = Encoder::with_capacity(512);
    encoder.write_bytes("task_projection_transition_domain", TRANSITION_DOMAIN)?;
    encoder.write_raw(transition.before_snapshot_id.as_bytes());
    encoder.write_raw(transition.after_snapshot_id.as_bytes());
    encoder.write_raw(transition.task_id.as_bytes());
    encoder.write_raw(&transition.previous_generation);
    encoder.write_raw(&transition.resulting_generation);
    write_transition_kind(&mut encoder, transition.kind)?;
    encoder.write_scalar(transition.observed_at.value());
    encoder.write_raw(&transition.adapter_identity);
    encoder.write_digest(&transition.evidence_root)?;
    Ok(hash(&encoder.into_bytes()))
}

fn write_transition_kind(
    encoder: &mut Encoder,
    kind: TaskProjectionTransitionKind,
) -> Result<(), TaskProjectionAdapterRefusal> {
    encoder.write_raw_byte(kind.code_point());
    match kind {
        TaskProjectionTransitionKind::Claimed { action } => {
            encoder.write_raw_byte(work_action_code(action));
        }
        TaskProjectionTransitionKind::Released { next_phase } => {
            encoder.write_raw_byte(task_phase_code(next_phase));
        }
        TaskProjectionTransitionKind::Transferred { successor_run_id } => {
            encoder.write_raw(&successor_run_id.value().to_be_bytes());
        }
    }
    Ok(())
}

fn write_surfaces(
    encoder: &mut Encoder,
    surfaces: &[PlanSurface],
) -> Result<(), TaskProjectionAdapterRefusal> {
    let count = u32::try_from(surfaces.len()).map_err(|_| {
        CodecRefusal::ValueUnrepresentable {
            field: "task_projection.reserved_surfaces",
            observed: u64::try_from(surfaces.len()).unwrap_or(u64::MAX),
            limit: u64::from(u32::MAX),
        }
    })?;
    encoder.write_scalar(count);
    for surface in surfaces {
        encoder.write_raw_byte(surface_kind_code(surface.kind()));
        encoder.write_digest(&surface.selector())?;
    }
    Ok(())
}

fn validate_successor_generation(
    previous: [u8; 32],
    resulting: [u8; 32],
) -> Result<(), TaskProjectionAdapterRefusal> {
    if is_zero(&resulting) || resulting == previous {
        return Err(TaskProjectionAdapterRefusal::GenerationDidNotAdvance);
    }
    Ok(())
}

const fn phase_after_claim(action: WorkAction) -> TaskPhase {
    match action {
        WorkAction::Implement => TaskPhase::InProgress,
        WorkAction::Verify => TaskPhase::VerificationPending,
        WorkAction::Rework => TaskPhase::Rework,
    }
}

const fn phase_is_terminal(phase: TaskPhase) -> bool {
    matches!(
        phase,
        TaskPhase::Verified | TaskPhase::Closed | TaskPhase::Superseded
    )
}

const fn task_phase_code(phase: TaskPhase) -> u8 {
    match phase {
        TaskPhase::Open => 1,
        TaskPhase::InProgress => 2,
        TaskPhase::ImplementationReady => 3,
        TaskPhase::VerificationPending => 4,
        TaskPhase::Rework => 5,
        TaskPhase::Verified => 6,
        TaskPhase::Closed => 7,
        TaskPhase::Superseded => 8,
    }
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

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
