//! Strict coordination from control-plane objects to task adapter mutations.
//!
//! [`crate::task_projection`] defines the backend-neutral compare-and-mutate
//! protocol. This module connects that protocol to the already-existing pulse,
//! plan, claim, situation, and cancellation evidence types so callers do not
//! hand-assemble a plausible-looking projection after mutating a task system.
//!
//! Claiming and releasing are potentially effectful. If the adapter returns an
//! observation that fails local validation, or a validated mutation later fails
//! claim-receipt integration, the outcome preserves the exact request and
//! evidence for reconciliation instead of returning an error that sounds like
//! nothing happened. Releasing a claim remains available after run or claim
//! expiry, provided the latest task snapshot still proves exact ownership.
//!
//! A production adapter still owns durable task-system I/O. This module grants
//! no repository authority and performs no canonical publication.

use core::fmt;

use fgit_types::Digest;

use crate::{
    ActiveTaskClaim, AgentChangePlan, AgentControlPulse, AgentSituationReceipt, IntentRun,
    LogicalTime, RunId, SituationComponentKind, TaskClaimCancellationOutcome,
    TaskClaimCancellationProjection, TaskClaimProjection, TaskClaimReceipt, TaskClaimRefusal,
    TaskMutationAttempt, TaskMutationAttemptRefusal, TaskMutationObservation, TaskMutationReceipt,
    TaskMutationRefusal, TaskMutationRequest, TaskProjectionAdapter, TaskProjectionGeneration,
    TaskProjectionSnapshot, WorkAction, WorkTaskId, apply_task_mutation,
};

/// Complete successful claim transition across task mutation and claim receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedTask {
    request: TaskMutationRequest,
    mutation_receipt: TaskMutationReceipt,
    claim_receipt: TaskClaimReceipt,
}

impl ClaimedTask {
    /// Exact idempotent mutation request.
    #[must_use]
    pub const fn request(&self) -> &TaskMutationRequest {
        &self.request
    }

    /// Validated task-system mutation result.
    #[must_use]
    pub const fn mutation_receipt(&self) -> &TaskMutationReceipt {
        &self.mutation_receipt
    }

    /// Existing claim receipt consumed by activation and later control objects.
    #[must_use]
    pub const fn claim_receipt(&self) -> &TaskClaimReceipt {
        &self.claim_receipt
    }
}

/// Post-commit integration failure that must be reconciled rather than retried.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimIntegrationRefusal {
    /// Existing claim-receipt admission refused the committed adapter result.
    Claim(TaskClaimRefusal),
    /// A committed result lost the claim expiry guaranteed by request
    /// construction. This indicates an internal adapter-contract defect.
    MissingClaimExpiry,
}

/// Result after the adapter may have applied or recognized a claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimTaskOutcome {
    /// Mutation and claim-receipt admission both completed.
    Claimed(ClaimedTask),
    /// The adapter returned an observation that failed local validation. The
    /// task system may have committed; probe by request identity.
    MutationNeedsReconciliation {
        /// Exact request issued once.
        request: TaskMutationRequest,
        /// Adapter observation retained for probing.
        observation: TaskMutationObservation,
        /// Local observation-validation refusal.
        refusal: TaskMutationRefusal,
    },
    /// The task-system mutation was validated, but downstream claim integration
    /// found an invariant mismatch. The mutation must be reconciled; it must not
    /// be retried as though nothing happened.
    CommittedNeedsReconciliation {
        /// Exact request whose result committed.
        request: TaskMutationRequest,
        /// Committed task-system mutation.
        mutation_receipt: TaskMutationReceipt,
        /// Post-commit integration refusal.
        refusal: ClaimIntegrationRefusal,
    },
}

/// Complete release transition and cancellation projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedTask {
    request: TaskMutationRequest,
    mutation_receipt: TaskMutationReceipt,
    cancellation_projection: TaskClaimCancellationProjection,
}

impl ReleasedTask {
    /// Exact idempotent release request.
    #[must_use]
    pub const fn request(&self) -> &TaskMutationRequest {
        &self.request
    }

    /// Validated task-system mutation result.
    #[must_use]
    pub const fn mutation_receipt(&self) -> &TaskMutationReceipt {
        &self.mutation_receipt
    }

    /// Projection consumed by run-cancellation completion.
    #[must_use]
    pub const fn cancellation_projection(&self) -> &TaskClaimCancellationProjection {
        &self.cancellation_projection
    }
}

/// Result after the adapter may have applied or recognized a release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseTaskOutcome {
    /// Mutation and cancellation projection completed.
    Released(ReleasedTask),
    /// The adapter returned an observation that failed local validation. The
    /// release may have committed; probe by request identity rather than
    /// replaying a fresh release.
    MutationNeedsReconciliation {
        /// Exact request issued once.
        request: TaskMutationRequest,
        /// Adapter observation retained for probing.
        observation: TaskMutationObservation,
        /// Local observation-validation refusal.
        refusal: TaskMutationRefusal,
    },
}

/// Claims the exact task selected by a pulse and plan.
///
/// The adapter is invoked exactly once. Ambiguous backend outcomes remain typed
/// errors and require an adapter probe by request ID; malformed observations are
/// returned as reconciliation outcomes because the backend may have committed.
///
/// # Errors
///
/// Refuses snapshot/pulse/plan/run substitution, task or phase mismatch,
/// request construction failure, and definite pre-observation adapter refusal.
#[allow(clippy::too_many_arguments)]
pub fn claim_selected_task<A: TaskProjectionAdapter>(
    adapter: &mut A,
    snapshot: &TaskProjectionSnapshot,
    authority: &crate::AuthorityReadReceipt,
    pulse: &AgentControlPulse,
    plan: &AgentChangePlan,
    run: &IntentRun,
    requested_at: LogicalTime,
    expires_at: LogicalTime,
    evidence_contract_root: Digest,
) -> Result<ClaimTaskOutcome, TaskCoordinatorRefusal> {
    validate_claim_basis(snapshot, authority, pulse, plan, run)?;
    let request = TaskMutationRequest::claim(
        snapshot,
        authority,
        run,
        plan.task_id(),
        plan.plan_id(),
        requested_at,
        expires_at,
        plan.conflict_surface().to_vec(),
        evidence_contract_root,
    )?;
    let mutation_receipt = match apply_task_mutation(adapter, &request)? {
        TaskMutationAttempt::Applied(receipt) => receipt,
        TaskMutationAttempt::NeedsReconciliation {
            observation,
            refusal,
            ..
        } => {
            return Ok(ClaimTaskOutcome::MutationNeedsReconciliation {
                request,
                observation,
                refusal,
            });
        }
    };
    let Some(claim_expiry) = mutation_receipt.after().claim_expiry() else {
        return Ok(ClaimTaskOutcome::CommittedNeedsReconciliation {
            request,
            mutation_receipt,
            refusal: ClaimIntegrationRefusal::MissingClaimExpiry,
        });
    };
    let projection = TaskClaimProjection::new(
        plan.task_id(),
        plan.plan_id(),
        run.run_id(),
        *mutation_receipt.previous_generation().as_bytes(),
        *mutation_receipt.resulting_generation().as_bytes(),
        mutation_receipt.after().reserved_surfaces().to_vec(),
        mutation_receipt.observed_at(),
        claim_expiry,
        mutation_receipt.adapter_identity(),
        mutation_receipt.evidence_root(),
    );
    match TaskClaimReceipt::admit(pulse, plan, run, projection) {
        Ok(claim_receipt) => Ok(ClaimTaskOutcome::Claimed(ClaimedTask {
            request,
            mutation_receipt,
            claim_receipt,
        })),
        Err(refusal) => Ok(ClaimTaskOutcome::CommittedNeedsReconciliation {
            request,
            mutation_receipt,
            refusal: ClaimIntegrationRefusal::Claim(refusal),
        }),
    }
}

/// Releases an exact active task claim from the latest task projection.
///
/// Run and claim expiry do not disable release. The adapter must still compare
/// the exact latest generation and row ownership.
///
/// # Errors
///
/// Refuses situation/snapshot/plan/claim/run substitution, unavailable task
/// projection, request construction failure, and definite pre-observation
/// adapter refusal.
#[allow(clippy::too_many_arguments)]
pub fn release_active_task<A: TaskProjectionAdapter>(
    adapter: &mut A,
    snapshot: &TaskProjectionSnapshot,
    latest_situation: &AgentSituationReceipt,
    plan: &AgentChangePlan,
    active_claim: ActiveTaskClaim,
    run: &IntentRun,
    requested_at: LogicalTime,
    evidence_contract_root: Digest,
) -> Result<ReleaseTaskOutcome, TaskCoordinatorRefusal> {
    validate_release_basis(snapshot, latest_situation, plan, active_claim, run)?;
    let authority = latest_situation.authority_read_receipt();
    let request = TaskMutationRequest::release(
        snapshot,
        authority,
        run,
        plan.task_id(),
        plan.plan_id(),
        active_claim.activation_id(),
        requested_at,
        evidence_contract_root,
    )?;
    let mutation_receipt = match apply_task_mutation(adapter, &request)? {
        TaskMutationAttempt::Applied(receipt) => receipt,
        TaskMutationAttempt::NeedsReconciliation {
            observation,
            refusal,
            ..
        } => {
            return Ok(ReleaseTaskOutcome::MutationNeedsReconciliation {
                request,
                observation,
                refusal,
            });
        }
    };
    let cancellation_projection = TaskClaimCancellationProjection::new(
        active_claim.activation_id(),
        active_claim.claim_id(),
        active_claim.plan_id(),
        active_claim.task_id(),
        active_claim.assignee(),
        *mutation_receipt.previous_generation().as_bytes(),
        *mutation_receipt.resulting_generation().as_bytes(),
        mutation_receipt.observed_at(),
        TaskClaimCancellationOutcome::Released,
        mutation_receipt.adapter_identity(),
        mutation_receipt.evidence_root(),
    );
    Ok(ReleaseTaskOutcome::Released(ReleasedTask {
        request,
        mutation_receipt,
        cancellation_projection,
    }))
}

/// Pre-commit refusal from the strict task coordination layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskCoordinatorRefusal {
    /// Snapshot generation differs from the pulse task generation.
    PulseGenerationMismatch {
        /// Pulse generation.
        expected: [u8; 32],
        /// Snapshot generation.
        observed: [u8; 32],
    },
    /// Plan belongs to another pulse.
    PlanPulseMismatch,
    /// Plan belongs to another situation.
    PlanSituationMismatch,
    /// Plan belongs to another frontier.
    PlanFrontierMismatch,
    /// Plan names another run.
    PlanRunMismatch {
        /// Plan run.
        expected: RunId,
        /// Supplied run.
        observed: RunId,
    },
    /// Pulse has no selected actionable row.
    PulseSelectionMissing,
    /// Pulse selection differs from the plan.
    PulseSelectionMismatch,
    /// Snapshot row is absent or has another phase.
    SnapshotTaskPhaseMismatch {
        /// Planned task.
        task_id: WorkTaskId,
        /// Planned phase.
        expected: crate::TaskPhase,
        /// Snapshot phase, when present.
        observed: Option<crate::TaskPhase>,
    },
    /// Plan action is inconsistent with its selected phase.
    PlanActionMismatch {
        /// Plan phase.
        phase: crate::TaskPhase,
        /// Plan action.
        action: WorkAction,
    },
    /// Latest situation names another run.
    SituationRunMismatch,
    /// Latest situation omitted the task projection.
    SituationTaskProjectionUnavailable,
    /// Latest situation and snapshot name different task generations.
    SituationGenerationMismatch {
        /// Situation generation.
        expected: [u8; 32],
        /// Snapshot generation.
        observed: [u8; 32],
    },
    /// Situation/snapshot or caller/snapshot use different authenticated reads.
    SituationAuthorityMismatch,
    /// Active claim belongs to another plan.
    ClaimPlanMismatch,
    /// Active claim belongs to another task.
    ClaimTaskMismatch,
    /// Active claim belongs to another run.
    ClaimRunMismatch,
    /// Task mutation request construction refused the exact inputs.
    Mutation(TaskMutationRefusal),
    /// Definite pre-observation adapter refusal.
    Attempt(TaskMutationAttemptRefusal),
}

impl fmt::Display for TaskCoordinatorRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task coordination refused: {self:?}")
    }
}

impl core::error::Error for TaskCoordinatorRefusal {}

impl From<TaskMutationRefusal> for TaskCoordinatorRefusal {
    fn from(value: TaskMutationRefusal) -> Self {
        Self::Mutation(value)
    }
}

impl From<TaskMutationAttemptRefusal> for TaskCoordinatorRefusal {
    fn from(value: TaskMutationAttemptRefusal) -> Self {
        Self::Attempt(value)
    }
}

fn validate_claim_basis(
    snapshot: &TaskProjectionSnapshot,
    authority: &crate::AuthorityReadReceipt,
    pulse: &AgentControlPulse,
    plan: &AgentChangePlan,
    run: &IntentRun,
) -> Result<(), TaskCoordinatorRefusal> {
    if snapshot.generation().as_bytes() != pulse.task_projection_generation() {
        return Err(TaskCoordinatorRefusal::PulseGenerationMismatch {
            expected: *pulse.task_projection_generation(),
            observed: *snapshot.generation().as_bytes(),
        });
    }
    if plan.pulse_id() != pulse.pulse_id().as_bytes() {
        return Err(TaskCoordinatorRefusal::PlanPulseMismatch);
    }
    if plan.situation_id() != pulse.situation_id() {
        return Err(TaskCoordinatorRefusal::PlanSituationMismatch);
    }
    if plan.frontier_id() != pulse.frontier_id() {
        return Err(TaskCoordinatorRefusal::PlanFrontierMismatch);
    }
    if plan.intent_run_id() != run.run_id() {
        return Err(TaskCoordinatorRefusal::PlanRunMismatch {
            expected: plan.intent_run_id(),
            observed: run.run_id(),
        });
    }
    let selected = pulse
        .selected()
        .ok_or(TaskCoordinatorRefusal::PulseSelectionMissing)?;
    if selected.task_id() != plan.task_id()
        || selected.phase() != plan.task_phase()
        || selected.action() != plan.action()
    {
        return Err(TaskCoordinatorRefusal::PulseSelectionMismatch);
    }
    let row = snapshot.row(plan.task_id());
    if row.map(crate::TaskProjectionRow::phase) != Some(plan.task_phase()) {
        return Err(TaskCoordinatorRefusal::SnapshotTaskPhaseMismatch {
            task_id: plan.task_id(),
            expected: plan.task_phase(),
            observed: row.map(crate::TaskProjectionRow::phase),
        });
    }
    if required_action(plan.task_phase()) != Some(plan.action()) {
        return Err(TaskCoordinatorRefusal::PlanActionMismatch {
            phase: plan.task_phase(),
            action: plan.action(),
        });
    }
    let authority_id = authority
        .receipt_id()
        .map_err(crate::TaskProjectionRefusal::from)
        .map_err(TaskMutationRefusal::from)?;
    if snapshot.authority_read_receipt_id() != authority_id {
        return Err(TaskCoordinatorRefusal::SituationAuthorityMismatch);
    }
    Ok(())
}

fn validate_release_basis(
    snapshot: &TaskProjectionSnapshot,
    situation: &AgentSituationReceipt,
    plan: &AgentChangePlan,
    active_claim: ActiveTaskClaim,
    run: &IntentRun,
) -> Result<(), TaskCoordinatorRefusal> {
    if situation.intent_run_id() != Some(run.run_id()) {
        return Err(TaskCoordinatorRefusal::SituationRunMismatch);
    }
    let situation_generation = situation
        .component(SituationComponentKind::TaskProjection)
        .generation_commitment()
        .ok_or(TaskCoordinatorRefusal::SituationTaskProjectionUnavailable)?;
    if snapshot.generation().as_bytes() != &situation_generation {
        return Err(TaskCoordinatorRefusal::SituationGenerationMismatch {
            expected: situation_generation,
            observed: *snapshot.generation().as_bytes(),
        });
    }
    let situation_authority = situation
        .authority_read_receipt()
        .receipt_id()
        .map_err(crate::TaskProjectionRefusal::from)
        .map_err(TaskMutationRefusal::from)?;
    if snapshot.authority_read_receipt_id() != situation_authority {
        return Err(TaskCoordinatorRefusal::SituationAuthorityMismatch);
    }
    if plan.intent_run_id() != run.run_id() {
        return Err(TaskCoordinatorRefusal::PlanRunMismatch {
            expected: plan.intent_run_id(),
            observed: run.run_id(),
        });
    }
    if active_claim.plan_id() != plan.plan_id() {
        return Err(TaskCoordinatorRefusal::ClaimPlanMismatch);
    }
    if active_claim.task_id() != plan.task_id() {
        return Err(TaskCoordinatorRefusal::ClaimTaskMismatch);
    }
    if active_claim.assignee() != run.run_id() {
        return Err(TaskCoordinatorRefusal::ClaimRunMismatch);
    }
    Ok(())
}

const fn required_action(phase: crate::TaskPhase) -> Option<WorkAction> {
    match phase {
        crate::TaskPhase::Open | crate::TaskPhase::InProgress => Some(WorkAction::Implement),
        crate::TaskPhase::ImplementationReady | crate::TaskPhase::VerificationPending => {
            Some(WorkAction::Verify)
        }
        crate::TaskPhase::Rework => Some(WorkAction::Rework),
        crate::TaskPhase::Verified | crate::TaskPhase::Closed | crate::TaskPhase::Superseded => {
            None
        }
    }
}

/// Converts a raw generation to the typed adapter vocabulary.
///
/// This helper is useful to transport adapters that receive a generation from
/// an existing `AgentSituationReceipt`.
///
/// # Errors
///
/// Refuses the reserved all-zero generation.
pub fn task_projection_generation(
    generation: [u8; 32],
) -> Result<TaskProjectionGeneration, crate::TaskProjectionRefusal> {
    TaskProjectionGeneration::try_from_bytes(generation)
}
