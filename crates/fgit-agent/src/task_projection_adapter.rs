//! Deterministic task-projection transitions for claim, release, and transfer.
//!
//! This module is the pure semantic kernel between an authority-bound control
//! turn and a durable task backend. It validates one exact predecessor state,
//! computes one deterministic successor state, and emits the existing claim or
//! cancellation projection consumed by the wider Agent Control Plane.
//!
//! The successor generation is a commitment to logical task state, including
//! the complete machine identity of an active lease holder or transferred
//! assignment preference. It does not depend on which conforming adapter
//! executed the transition or on the evidence bytes that adapter later retains.
//! Adapter identity and the declared evidence contract remain committed by
//! [`TaskProjectionTransition`], so audit identity stays distinct without
//! making backend choice alter task state.
//!
//! Values in this module are immutable derived coordination state. They are not
//! durable storage and never become repository authority.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::Digest;

use crate::{
    ActiveTaskClaim, AgentChangePlan, AgentChangePlanId, AgentControlPulse, IntentRun,
    IntentRunCommitment, IntentRunIdentityRefusal, LogicalTime, PlanSurface, RunId,
    TaskClaimCancellationOutcome, TaskClaimCancellationProjection, TaskClaimProjection,
    TaskClaimReceipt, TaskPhase, WorkAction, WorkTaskId,
};

const SNAPSHOT_DOMAIN: &[u8] = b"frankengit.agent.task-projection-snapshot/v4\0";
const GENERATION_DOMAIN: &[u8] = b"frankengit.agent.task-projection-generation/v4\0";
const TRANSITION_DOMAIN: &[u8] = b"frankengit.agent.task-projection-transition/v4\0";

/// Stable identity of one immutable semantic task snapshot.
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

/// Stable identity of one evidenced task transition.
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
    /// The task is assigned to one complete Intent Run.
    ///
    /// Without a lease this is a transfer preference rather than active work
    /// authority. The named run must still construct a fresh plan and claim.
    Assigned {
        /// Coordination identity.
        run_id: RunId,
        /// Complete machine-enforced identity.
        run_commitment: IntentRunCommitment,
    },
}

impl TaskProjectionAssignment {
    /// Builds one complete assignment or transfer preference.
    #[must_use]
    pub const fn assigned(run_id: RunId, run_commitment: IntentRunCommitment) -> Self {
        Self::Assigned {
            run_id,
            run_commitment,
        }
    }

    /// Assigned coordination identity, when present.
    #[must_use]
    pub const fn run_id(self) -> Option<RunId> {
        match self {
            Self::Unassigned => None,
            Self::Assigned { run_id, .. } => Some(run_id),
        }
    }

    /// Assigned complete run identity, when present.
    #[must_use]
    pub const fn run_commitment(self) -> Option<IntentRunCommitment> {
        match self {
            Self::Unassigned => None,
            Self::Assigned { run_commitment, .. } => Some(run_commitment),
        }
    }
}

/// Active lease material retained by a claimed task projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjectionLease {
    plan_id: AgentChangePlanId,
    assignee: RunId,
    run_commitment: IntentRunCommitment,
    previous_generation: [u8; 32],
    claimed_generation: [u8; 32],
    reserved_surfaces: Vec<PlanSurface>,
    claimed_at: LogicalTime,
    expires_at: LogicalTime,
}

impl TaskProjectionLease {
    /// Reconstructs one structurally valid persisted lease.
    ///
    /// # Errors
    ///
    /// Refuses zero or unchanged generations, an empty/inverted interval,
    /// empty/duplicate/excessive reservation surfaces, and canonical framing
    /// bounds that cannot be represented.
    #[allow(clippy::too_many_arguments)]
    pub fn observed(
        plan_id: AgentChangePlanId,
        assignee: RunId,
        run_commitment: IntentRunCommitment,
        previous_generation: [u8; 32],
        claimed_generation: [u8; 32],
        mut reserved_surfaces: Vec<PlanSurface>,
        claimed_at: LogicalTime,
        expires_at: LogicalTime,
    ) -> Result<Self, TaskProjectionAdapterRefusal> {
        if is_zero(&previous_generation) || is_zero(&claimed_generation) {
            return Err(TaskProjectionAdapterRefusal::ZeroGeneration);
        }
        if previous_generation == claimed_generation {
            return Err(TaskProjectionAdapterRefusal::LeaseGenerationDidNotAdvance);
        }
        if expires_at <= claimed_at {
            return Err(TaskProjectionAdapterRefusal::InvalidClaimWindow {
                claimed_at,
                expires_at,
            });
        }
        canonicalize_surfaces(&mut reserved_surfaces)?;
        if reserved_surfaces.is_empty() {
            return Err(TaskProjectionAdapterRefusal::EmptyReservedSurface);
        }
        Ok(Self {
            plan_id,
            assignee,
            run_commitment,
            previous_generation,
            claimed_generation,
            reserved_surfaces,
            claimed_at,
            expires_at,
        })
    }

    /// Plan that established this lease.
    #[must_use]
    pub const fn plan_id(&self) -> AgentChangePlanId {
        self.plan_id
    }

    /// Run coordination identity assigned by this lease.
    #[must_use]
    pub const fn assignee(&self) -> RunId {
        self.assignee
    }

    /// Complete machine-enforced run identity assigned by this lease.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
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

/// Immutable semantic task state at one derived projection generation.
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
    /// Refuses zero task/generation identities and an assigned terminal task.
    pub fn observed(
        task_id: WorkTaskId,
        generation: [u8; 32],
        phase: TaskPhase,
        assignment: TaskProjectionAssignment,
    ) -> Result<Self, TaskProjectionAdapterRefusal> {
        Self::from_parts(task_id, generation, phase, assignment, None)
    }

    /// Imports one observed active lease from a durable backend reread.
    ///
    /// Assignment is derived from the lease and cannot be supplied separately.
    ///
    /// # Errors
    ///
    /// Refuses a generation not equal to the lease's claimed generation, a
    /// terminal leased phase, and every structural snapshot refusal.
    pub fn observed_with_lease(
        task_id: WorkTaskId,
        generation: [u8; 32],
        phase: TaskPhase,
        lease: TaskProjectionLease,
    ) -> Result<Self, TaskProjectionAdapterRefusal> {
        if generation != lease.claimed_generation {
            return Err(TaskProjectionAdapterRefusal::LeaseGenerationMismatch {
                snapshot: generation,
                lease: lease.claimed_generation,
            });
        }
        Self::from_parts(
            task_id,
            generation,
            phase,
            TaskProjectionAssignment::assigned(lease.assignee, lease.run_commitment),
            Some(lease),
        )
    }

    /// Applies one exact plan claim to this projection snapshot.
    ///
    /// # Errors
    ///
    /// Refuses stale pulse generations, task/phase/plan/complete-run
    /// substitution, assignment conflicts, an existing lease, invalid or
    /// amplified lifetime, a zero adapter profile, generation collision, and
    /// canonical framing failure.
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
        let run_commitment = validate_claim_basis(self, pulse, plan, run)?;
        if self.lease.is_some() {
            return Err(TaskProjectionAdapterRefusal::ActiveLeaseExists);
        }
        match self.assignment {
            TaskProjectionAssignment::Unassigned => {}
            TaskProjectionAssignment::Assigned {
                run_id,
                run_commitment: assigned_commitment,
            } if run_id == run.run_id() && assigned_commitment == run_commitment => {}
            TaskProjectionAssignment::Assigned { run_id, .. } if run_id != run.run_id() => {
                return Err(TaskProjectionAdapterRefusal::AssignedToOther {
                    assigned: run_id,
                    requested: run.run_id(),
                });
            }
            TaskProjectionAssignment::Assigned {
                run_id,
                run_commitment: assigned_commitment,
            } => {
                return Err(
                    TaskProjectionAdapterRefusal::AssignedRunCommitmentMismatch {
                        run_id,
                        expected: assigned_commitment,
                        observed: run_commitment,
                    },
                );
            }
        }
        if claimed_at < pulse.observed_at() {
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
        if expires_at <= claimed_at {
            return Err(TaskProjectionAdapterRefusal::InvalidClaimWindow {
                claimed_at,
                expires_at,
            });
        }
        if expires_at > run.expiry() {
            return Err(TaskProjectionAdapterRefusal::ClaimOutlivesRun {
                claim_expires_at: expires_at,
                run_expires_at: run.expiry(),
            });
        }
        if is_zero(&adapter_identity) {
            return Err(TaskProjectionAdapterRefusal::ZeroAdapterIdentity);
        }

        let mut reserved_surfaces = plan.conflict_surface().to_vec();
        canonicalize_surfaces(&mut reserved_surfaces)?;
        if reserved_surfaces.is_empty() {
            return Err(TaskProjectionAdapterRefusal::EmptyReservedSurface);
        }
        let next_generation = derive_claim_generation(
            self,
            plan,
            run.run_id(),
            run_commitment,
            claimed_at,
            expires_at,
            &reserved_surfaces,
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
        let lease = TaskProjectionLease::observed(
            plan.plan_id(),
            run.run_id(),
            run_commitment,
            self.generation,
            next_generation,
            reserved_surfaces,
            claimed_at,
            expires_at,
        )?;
        let phase = phase_after_claim(plan.action());
        let after = Self::from_parts(
            self.task_id,
            next_generation,
            phase,
            TaskProjectionAssignment::assigned(run.run_id(), run_commitment),
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
    /// Refuses lease, receipt, claim, complete-run, generation, surface, and
    /// time substitution, a zero adapter profile, generation collision, and
    /// framing failure.
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
        validate_resolution_basis(
            self,
            claim_receipt,
            active_claim,
            source_run,
            resolved_at,
            adapter_identity,
        )?;
        let next_phase = disposition.phase();
        let kind = TaskProjectionTransitionKind::Released { next_phase };
        let next_generation =
            derive_resolution_generation(self, claim_receipt, active_claim, kind, resolved_at)?;
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
        let after = Self::from_parts(
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
        Ok(TaskResolutionApplication {
            snapshot: after,
            transition,
            projection,
        })
    }

    /// Transfers assignment preference to another run and releases the source
    /// lease atomically at one projection generation.
    ///
    /// The successor receives no plan, capability, or active claim. Its complete
    /// run commitment is retained in both the semantic assignment and
    /// transition audit identity. It must build a new pulse and plan, claim the
    /// new generation, and activate that claim before continuing work.
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
        let successor_run_commitment = successor_run.commitment()?;

        let kind = TaskProjectionTransitionKind::Transferred {
            successor_run_id: successor_run.run_id(),
            successor_run_commitment,
        };
        let next_generation =
            derive_resolution_generation(self, claim_receipt, active_claim, kind, resolved_at)?;
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
        let after = Self::from_parts(
            self.task_id,
            next_generation,
            self.phase,
            TaskProjectionAssignment::assigned(successor_run.run_id(), successor_run_commitment),
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
        if is_zero(task_id.as_bytes()) {
            return Err(TaskProjectionAdapterRefusal::ZeroTaskId);
        }
        if is_zero(&generation) {
            return Err(TaskProjectionAdapterRefusal::ZeroGeneration);
        }
        if phase_is_terminal(phase)
            && (!matches!(assignment, TaskProjectionAssignment::Unassigned) || lease.is_some())
        {
            return Err(TaskProjectionAdapterRefusal::TerminalTaskAssigned { phase });
        }
        if let Some(active) = lease.as_ref() {
            let expected =
                TaskProjectionAssignment::assigned(active.assignee, active.run_commitment);
            if assignment != expected {
                return Err(TaskProjectionAdapterRefusal::LeaseAssignmentMismatch);
            }
            if generation != active.claimed_generation {
                return Err(TaskProjectionAdapterRefusal::LeaseGenerationMismatch {
                    snapshot: generation,
                    lease: active.claimed_generation,
                });
            }
        }
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

    /// Stable semantic snapshot identity.
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
        /// Successor coordination preference; not an active claim.
        successor_run_id: RunId,
        /// Complete successor run committed by task state and audit record.
        successor_run_commitment: IntentRunCommitment,
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

/// Stable audit receipt for one exact-predecessor task transition.
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
        transition.transition_id = TaskProjectionTransitionId(transition_commitment(&transition)?);
        Ok(transition)
    }

    /// Stable evidenced transition identity.
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

    /// New semantic generation.
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

    /// Declared persistence/mutation evidence contract.
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
    /// Reserved all-zero task identity.
    ZeroTaskId,
    /// Projection generation used the reserved all-zero value.
    ZeroGeneration,
    /// A terminal task carried an assignment or lease.
    TerminalTaskAssigned {
        /// Terminal phase observed.
        phase: TaskPhase,
    },
    /// A lease and explicit assignment disagree.
    LeaseAssignmentMismatch,
    /// Snapshot and lease name different claimed generations.
    LeaseGenerationMismatch {
        /// Snapshot generation.
        snapshot: [u8; 32],
        /// Lease claimed generation.
        lease: [u8; 32],
    },
    /// Lease predecessor and successor generation are identical.
    LeaseGenerationDidNotAdvance,
    /// Reservation surface is empty.
    EmptyReservedSurface,
    /// Reservation surface exceeded the plan ceiling.
    TooManyReservedSurfaces {
        /// Entries supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// Reservation surface repeats one selector.
    DuplicateReservedSurface {
        /// Repeated surface.
        surface: PlanSurface,
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
    /// Plan belongs to another run ID.
    PlanRunMismatch {
        /// Plan run.
        expected: RunId,
        /// Supplied run.
        observed: RunId,
    },
    /// Plan carries another complete run commitment.
    PlanRunCommitmentMismatch {
        /// Commitment bound to the plan.
        expected: IntentRunCommitment,
        /// Commitment computed from the supplied run.
        observed: IntentRunCommitment,
    },
    /// Pulse names another active run ID.
    PulseRunMismatch,
    /// Pulse carries another complete run commitment.
    PulseRunCommitmentMismatch {
        /// Commitment computed from the supplied run.
        expected: IntentRunCommitment,
        /// Commitment retained by the pulse, when present.
        observed: Option<IntentRunCommitment>,
    },
    /// Run lacks a complete authenticated authority receipt.
    RunAuthorityReceiptRequired,
    /// Complete run identity could not be produced.
    RunIdentity(IntentRunIdentityRefusal),
    /// Snapshot is assigned to another run.
    AssignedToOther {
        /// Existing assignment.
        assigned: RunId,
        /// Requested claimant.
        requested: RunId,
    },
    /// Snapshot is assigned to the same numeric run ID but another complete
    /// machine identity.
    AssignedRunCommitmentMismatch {
        /// Reused coordination ID.
        run_id: RunId,
        /// Complete run selected by the assignment.
        expected: IntentRunCommitment,
        /// Complete run attempting the claim.
        observed: IntentRunCommitment,
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
    /// Snapshot assignment differs from its active lease.
    ActiveLeaseAssignmentMismatch,
    /// Active lease belongs to another complete run.
    LeaseRunCommitmentMismatch {
        /// Commitment retained by the lease.
        expected: IntentRunCommitment,
        /// Commitment computed from the supplied source run.
        observed: IntentRunCommitment,
    },
    /// Claim receipt names another task.
    ClaimReceiptTaskMismatch,
    /// Claim receipt names another plan.
    ClaimReceiptPlanMismatch,
    /// Claim receipt names another run ID.
    ClaimReceiptRunMismatch,
    /// Claim receipt carries another complete run commitment.
    ClaimReceiptRunCommitmentMismatch,
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
    /// Active claim names another run ID.
    ActiveClaimRunMismatch,
    /// Active claim carries another complete run commitment.
    ActiveClaimRunCommitmentMismatch,
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

impl From<IntentRunIdentityRefusal> for TaskProjectionAdapterRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

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
) -> Result<IntentRunCommitment, TaskProjectionAdapterRefusal> {
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
    let run_commitment = run.commitment()?;
    if plan.intent_run_commitment() != run_commitment {
        return Err(TaskProjectionAdapterRefusal::PlanRunCommitmentMismatch {
            expected: plan.intent_run_commitment(),
            observed: run_commitment,
        });
    }
    if pulse.active_run_commitment() != Some(run_commitment) {
        return Err(TaskProjectionAdapterRefusal::PulseRunCommitmentMismatch {
            expected: run_commitment,
            observed: pulse.active_run_commitment(),
        });
    }
    Ok(run_commitment)
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
    let expected_assignment =
        TaskProjectionAssignment::assigned(lease.assignee, lease.run_commitment);
    if snapshot.assignment != expected_assignment {
        return Err(TaskProjectionAdapterRefusal::ActiveLeaseAssignmentMismatch);
    }
    let source_run_commitment = source_run.commitment()?;
    if lease.run_commitment != source_run_commitment {
        return Err(TaskProjectionAdapterRefusal::LeaseRunCommitmentMismatch {
            expected: lease.run_commitment,
            observed: source_run_commitment,
        });
    }
    if claim_receipt.task_id() != snapshot.task_id {
        return Err(TaskProjectionAdapterRefusal::ClaimReceiptTaskMismatch);
    }
    if claim_receipt.plan_id() != lease.plan_id {
        return Err(TaskProjectionAdapterRefusal::ClaimReceiptPlanMismatch);
    }
    if claim_receipt.assignee() != lease.assignee || source_run.run_id() != lease.assignee {
        return Err(TaskProjectionAdapterRefusal::ClaimReceiptRunMismatch);
    }
    if claim_receipt.run_commitment() != lease.run_commitment {
        return Err(TaskProjectionAdapterRefusal::ClaimReceiptRunCommitmentMismatch);
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
    if active_claim.run_commitment() != lease.run_commitment {
        return Err(TaskProjectionAdapterRefusal::ActiveClaimRunCommitmentMismatch);
    }
    if resolved_at < active_claim.observed_at() {
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
    run_id: RunId,
    run_commitment: IntentRunCommitment,
    claimed_at: LogicalTime,
    expires_at: LogicalTime,
    surfaces: &[PlanSurface],
) -> Result<[u8; 32], TaskProjectionAdapterRefusal> {
    let mut encoder = Encoder::with_capacity(576);
    encoder.write_bytes("task_projection_generation_domain", GENERATION_DOMAIN)?;
    encoder.write_raw_byte(1);
    encoder.write_raw(&snapshot.generation);
    encoder.write_raw(snapshot.task_id.as_bytes());
    encoder.write_raw(plan.plan_id().as_bytes());
    encoder.write_raw(&run_id.value().to_be_bytes());
    encoder.write_raw(run_commitment.as_bytes());
    encoder.write_raw_byte(work_action_code(plan.action()));
    encoder.write_scalar(claimed_at.value());
    encoder.write_scalar(expires_at.value());
    write_surfaces(&mut encoder, surfaces)?;
    Ok(hash(&encoder.into_bytes()))
}

fn derive_resolution_generation(
    snapshot: &TaskProjectionSnapshot,
    claim_receipt: &TaskClaimReceipt,
    active_claim: ActiveTaskClaim,
    kind: TaskProjectionTransitionKind,
    resolved_at: LogicalTime,
) -> Result<[u8; 32], TaskProjectionAdapterRefusal> {
    let mut encoder = Encoder::with_capacity(576);
    encoder.write_bytes("task_projection_generation_domain", GENERATION_DOMAIN)?;
    encoder.write_raw_byte(kind.code_point());
    encoder.write_raw(&snapshot.generation);
    encoder.write_raw(snapshot.task_id.as_bytes());
    encoder.write_raw(claim_receipt.claim_id().as_bytes());
    encoder.write_raw(claim_receipt.run_commitment().as_bytes());
    encoder.write_raw(active_claim.activation_id().as_bytes());
    write_transition_kind(&mut encoder, kind)?;
    encoder.write_scalar(resolved_at.value());
    Ok(hash(&encoder.into_bytes()))
}

fn snapshot_commitment(
    snapshot: &TaskProjectionSnapshot,
) -> Result<[u8; 32], TaskProjectionAdapterRefusal> {
    let mut encoder = Encoder::with_capacity(608);
    encoder.write_bytes("task_projection_snapshot_domain", SNAPSHOT_DOMAIN)?;
    encoder.write_raw(snapshot.task_id.as_bytes());
    encoder.write_raw(&snapshot.generation);
    encoder.write_raw_byte(task_phase_code(snapshot.phase));
    match snapshot.assignment {
        TaskProjectionAssignment::Unassigned => encoder.write_bool(false),
        TaskProjectionAssignment::Assigned {
            run_id,
            run_commitment,
        } => {
            encoder.write_bool(true);
            encoder.write_raw(&run_id.value().to_be_bytes());
            encoder.write_raw(run_commitment.as_bytes());
        }
    }
    match &snapshot.lease {
        None => encoder.write_bool(false),
        Some(lease) => {
            encoder.write_bool(true);
            encoder.write_raw(lease.plan_id.as_bytes());
            encoder.write_raw(&lease.assignee.value().to_be_bytes());
            encoder.write_raw(lease.run_commitment.as_bytes());
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
    let mut encoder = Encoder::with_capacity(576);
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
        TaskProjectionTransitionKind::Transferred {
            successor_run_id,
            successor_run_commitment,
        } => {
            encoder.write_raw(&successor_run_id.value().to_be_bytes());
            encoder.write_raw(successor_run_commitment.as_bytes());
        }
    }
    Ok(())
}

fn canonicalize_surfaces(
    surfaces: &mut Vec<PlanSurface>,
) -> Result<(), TaskProjectionAdapterRefusal> {
    if surfaces.len() > crate::MAX_PLAN_ENTRIES {
        return Err(TaskProjectionAdapterRefusal::TooManyReservedSurfaces {
            observed: surfaces.len(),
            limit: crate::MAX_PLAN_ENTRIES,
        });
    }
    surfaces.sort_unstable();
    for pair in surfaces.windows(2) {
        if pair[0] == pair[1] {
            return Err(TaskProjectionAdapterRefusal::DuplicateReservedSurface {
                surface: pair[0],
            });
        }
    }
    Ok(())
}

fn write_surfaces(
    encoder: &mut Encoder,
    surfaces: &[PlanSurface],
) -> Result<(), TaskProjectionAdapterRefusal> {
    let count = u32::try_from(surfaces.len()).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field: "task_projection.reserved_surfaces",
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
