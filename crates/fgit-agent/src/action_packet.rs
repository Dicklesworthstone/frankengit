//! Bounded Level-1 action packets for one concrete agent operation sequence.
//!
//! A plan is an inert contract over a whole selected task. An
//! [`AgentActionPacket`] narrows that plan to the smallest useful execution
//! surface: exact ordered steps, approved context, targets, per-step budgets,
//! evidence obligations, peer-change commitments, and stop preconditions.
//!
//! The packet grants no authority and performs no effect. Every step must fit
//! both the plan and the complete live [`crate::IntentRun`]. The situation,
//! plan, activated claim, and supplied run must carry the same
//! [`crate::IntentRunCommitment`]; reusing a numeric [`crate::RunId`] cannot
//! widen or silently narrow the executor. Consequential execution still goes
//! through the effect broker and the owning obligation protocol.
//!
//! # Claim continuity boundary
//!
//! [`crate::ActiveTaskClaim`] commits the situation that first observed its
//! post-claim task generation and complete run. This slice therefore accepts
//! only that exact activation situation. A later situation may be equally
//! valid, but proving the task projection and surrounding context remained the
//! same requires a separate typed continuity receipt.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_resource::{ResourceError, ResourceVector};
use fgit_types::Digest;

use crate::{
    ActiveTaskClaim, ActiveTaskClaimId, AgentChangePlan, AgentChangePlanId, AgentSituationReceipt,
    ClassSet, ContextPacket, ContextPacketId, IntentRun, IntentRunCommitment,
    IntentRunIdentityRefusal, LogicalTime, OperationClass, PlanRequirementId, PlanSurface, RunId,
    SituationComponentKind, SituationId, WorkTaskId,
};

/// Maximum ordered steps in one action packet.
pub const MAX_ACTION_STEPS: usize = 64;
/// Maximum context packets in one action packet.
pub const MAX_ACTION_CONTEXT_PACKETS: usize = crate::MAX_PLAN_ENTRIES;
/// Maximum peer-change commitments in one action packet.
pub const MAX_ACTION_PEER_CHANGES: usize = crate::MAX_PLAN_ENTRIES;
const ACTION_PACKET_DOMAIN: &[u8] = b"frankengit.agent.action-packet/v2\0";

/// Stable identity of one action packet.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentActionPacketId([u8; 32]);

impl AgentActionPacketId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AgentActionPacketId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("action-packet:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable identity of one ordered action step.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActionStepId([u8; 32]);

impl ActionStepId {
    /// Creates an identity from fixed-width bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

/// One concrete, ordered action under the packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionStep {
    step_id: ActionStepId,
    operation: OperationClass,
    target: PlanSurface,
    input_root: Digest,
    expected_output_root: Digest,
    resource_budget: ResourceVector,
    evidence_requirement: Option<PlanRequirementId>,
}

impl ActionStep {
    /// Creates one complete action step.
    #[must_use]
    pub const fn new(
        step_id: ActionStepId,
        operation: OperationClass,
        target: PlanSurface,
        input_root: Digest,
        expected_output_root: Digest,
        resource_budget: ResourceVector,
        evidence_requirement: Option<PlanRequirementId>,
    ) -> Self {
        Self {
            step_id,
            operation,
            target,
            input_root,
            expected_output_root,
            resource_budget,
            evidence_requirement,
        }
    }

    /// Stable step identity.
    #[must_use]
    pub const fn step_id(self) -> ActionStepId {
        self.step_id
    }

    /// Operation class the executor must authorize through the broker.
    #[must_use]
    pub const fn operation(self) -> OperationClass {
        self.operation
    }

    /// Exact plan-contained target.
    #[must_use]
    pub const fn target(self) -> PlanSurface {
        self.target
    }

    /// Input artifact/parameter contract.
    #[must_use]
    pub const fn input_root(self) -> Digest {
        self.input_root
    }

    /// Expected output contract.
    #[must_use]
    pub const fn expected_output_root(self) -> Digest {
        self.expected_output_root
    }

    /// Per-step resource ceiling.
    #[must_use]
    pub const fn resource_budget(self) -> ResourceVector {
        self.resource_budget
    }

    /// Plan evidence requirement this step is expected to discharge.
    #[must_use]
    pub const fn evidence_requirement(self) -> Option<PlanRequirementId> {
        self.evidence_requirement
    }
}

/// A precondition that must remain true before each effectful step.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ActionPrecondition {
    /// Authenticated authority head remains the packet basis.
    AuthorityUnchanged = 0,
    /// Activated task claim remains live.
    ClaimLive = 1,
    /// Declared conflict surface remains clear or owned by this run.
    ConflictSurfaceClear = 2,
    /// Required capability remains valid at effect time.
    CapabilityValid = 3,
    /// Step and aggregate resource reservations remain available.
    BudgetAvailable = 4,
    /// No cancellation request has superseded this packet.
    CancellationNotRequested = 5,
    /// Context packet identities and authority basis still match.
    ContextStillApplicable = 6,
}

impl ActionPrecondition {
    /// Every condition in stable bit order.
    pub const ALL: [Self; 7] = [
        Self::AuthorityUnchanged,
        Self::ClaimLive,
        Self::ConflictSurfaceClear,
        Self::CapabilityValid,
        Self::BudgetAvailable,
        Self::CancellationNotRequested,
        Self::ContextStillApplicable,
    ];

    const fn bit(self) -> u16 {
        1_u16 << (self as u8)
    }
}

/// Closed set of action preconditions.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActionPreconditionSet(u16);

impl ActionPreconditionSet {
    /// Conditions every executable packet must carry.
    pub const MANDATORY: Self = Self(
        ActionPrecondition::AuthorityUnchanged.bit()
            | ActionPrecondition::ClaimLive.bit()
            | ActionPrecondition::ConflictSurfaceClear.bit()
            | ActionPrecondition::CapabilityValid.bit()
            | ActionPrecondition::BudgetAvailable.bit()
            | ActionPrecondition::CancellationNotRequested.bit()
            | ActionPrecondition::ContextStillApplicable.bit(),
    );

    /// Builds a set from explicit conditions.
    #[must_use]
    pub fn from_conditions(conditions: &[ActionPrecondition]) -> Self {
        let mut bits = 0_u16;
        for condition in conditions {
            bits |= condition.bit();
        }
        Self(bits)
    }

    /// Stable bit mask.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether one condition is present.
    #[must_use]
    pub const fn contains(self, condition: ActionPrecondition) -> bool {
        self.0 & condition.bit() != 0
    }

    /// Whether every condition in `other` is present.
    #[must_use]
    pub const fn contains_all(self, other: Self) -> bool {
        other.0 & !self.0 == 0
    }

    /// Conditions present here and absent in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Conditions in declaration order.
    pub fn iter(self) -> impl Iterator<Item = ActionPrecondition> {
        ActionPrecondition::ALL
            .into_iter()
            .filter(move |condition| self.contains(*condition))
    }
}

/// Bounded inputs used to construct one action packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentActionPacketSpec {
    steps: Vec<ActionStep>,
    peer_change_roots: Vec<Digest>,
    preconditions: ActionPreconditionSet,
    expected_result_root: Digest,
    refusal_contract_root: Digest,
    continuation_contract_root: Digest,
    executor_profile: [u8; 32],
}

impl AgentActionPacketSpec {
    /// Creates the required packet frame.
    #[must_use]
    pub const fn new(
        steps: Vec<ActionStep>,
        preconditions: ActionPreconditionSet,
        expected_result_root: Digest,
        refusal_contract_root: Digest,
        continuation_contract_root: Digest,
        executor_profile: [u8; 32],
    ) -> Self {
        Self {
            steps,
            peer_change_roots: Vec::new(),
            preconditions,
            expected_result_root,
            refusal_contract_root,
            continuation_contract_root,
            executor_profile,
        }
    }

    /// Adds visible peer-change commitments.
    #[must_use]
    pub fn with_peer_change_roots(mut self, peer_change_roots: Vec<Digest>) -> Self {
        self.peer_change_roots = peer_change_roots;
        self
    }
}

/// One complete, authority-bound Level-1 execution packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentActionPacket {
    packet_id: AgentActionPacketId,
    situation_id: SituationId,
    task_projection_generation: [u8; 32],
    plan_id: AgentChangePlanId,
    active_claim_id: ActiveTaskClaimId,
    task_id: WorkTaskId,
    run_id: RunId,
    run_commitment: IntentRunCommitment,
    observed_at: LogicalTime,
    context_packet_ids: Vec<ContextPacketId>,
    steps: Vec<ActionStep>,
    aggregate_budget: ResourceVector,
    peer_change_roots: Vec<Digest>,
    preconditions: ActionPreconditionSet,
    expected_result_root: Digest,
    refusal_contract_root: Digest,
    continuation_contract_root: Digest,
    executor_profile: [u8; 32],
}

impl AgentActionPacket {
    /// Builds one packet for the exact activated plan attempt.
    ///
    /// # Errors
    ///
    /// Refuses mismatched or expired run/claim/situation inputs, any complete
    /// run substitution, a situation other than the claim-activation receipt,
    /// missing/unapproved/mixed-authority context, empty/duplicate/excessive
    /// steps, operations or targets outside the plan, missing evidence
    /// requirements, zero or amplified budgets, absent mandatory preconditions,
    /// duplicate peer changes, a zero executor profile, and unrepresentable
    /// canonical framing.
    pub fn build(
        situation: &AgentSituationReceipt,
        plan: &AgentChangePlan,
        active_claim: ActiveTaskClaim,
        run: &IntentRun,
        context_packets: &[ContextPacket],
        mut spec: AgentActionPacketSpec,
    ) -> Result<Self, ActionPacketRefusal> {
        let (task_projection_generation, run_commitment) =
            validate_control_basis(situation, plan, active_claim, run)?;
        let context_packet_ids = validate_context(plan, run, context_packets)?;
        let aggregate_budget = validate_steps(plan, run, &spec.steps)?;
        canonicalize_peer_changes(&mut spec.peer_change_roots)?;
        if !spec
            .preconditions
            .contains_all(ActionPreconditionSet::MANDATORY)
        {
            return Err(ActionPacketRefusal::MissingPreconditions {
                missing: ActionPreconditionSet::MANDATORY.difference(spec.preconditions),
            });
        }
        if is_zero(&spec.executor_profile) {
            return Err(ActionPacketRefusal::ZeroExecutorProfile);
        }

        let mut packet = Self {
            packet_id: AgentActionPacketId([0; 32]),
            situation_id: situation.situation_id(),
            task_projection_generation,
            plan_id: plan.plan_id(),
            active_claim_id: active_claim.activation_id(),
            task_id: active_claim.task_id(),
            run_id: run.run_id(),
            run_commitment,
            observed_at: situation.observed_at(),
            context_packet_ids,
            steps: spec.steps,
            aggregate_budget,
            peer_change_roots: spec.peer_change_roots,
            preconditions: spec.preconditions,
            expected_result_root: spec.expected_result_root,
            refusal_contract_root: spec.refusal_contract_root,
            continuation_contract_root: spec.continuation_contract_root,
            executor_profile: spec.executor_profile,
        };
        packet.packet_id = AgentActionPacketId(packet_commitment(&packet)?);
        Ok(packet)
    }

    /// Stable packet identity.
    #[must_use]
    pub const fn packet_id(&self) -> AgentActionPacketId {
        self.packet_id
    }

    /// Exact situation basis.
    #[must_use]
    pub const fn situation_id(&self) -> SituationId {
        self.situation_id
    }

    /// Exact observed task-projection generation.
    #[must_use]
    pub const fn task_projection_generation(&self) -> &[u8; 32] {
        &self.task_projection_generation
    }

    /// Exact plan narrowed by this packet.
    #[must_use]
    pub const fn plan_id(&self) -> AgentChangePlanId {
        self.plan_id
    }

    /// Activated claim authorizing the plan attempt.
    #[must_use]
    pub const fn active_claim_id(&self) -> ActiveTaskClaimId {
        self.active_claim_id
    }

    /// Exact task selected by the plan and activated claim.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.task_id
    }

    /// Intent Run coordination identity whose scope was revalidated.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Complete machine-enforced run identity whose scope was revalidated.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Logical packet observation time.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Complete plan-approved context packet identities.
    #[must_use]
    pub fn context_packet_ids(&self) -> &[ContextPacketId] {
        &self.context_packet_ids
    }

    /// Ordered action steps.
    #[must_use]
    pub fn steps(&self) -> &[ActionStep] {
        &self.steps
    }

    /// Sum of all per-step resource ceilings.
    #[must_use]
    pub const fn aggregate_budget(&self) -> ResourceVector {
        self.aggregate_budget
    }

    /// Peer-change commitments visible when the packet was built.
    #[must_use]
    pub fn peer_change_roots(&self) -> &[Digest] {
        &self.peer_change_roots
    }

    /// Preconditions required before every effectful step.
    #[must_use]
    pub const fn preconditions(&self) -> ActionPreconditionSet {
        self.preconditions
    }

    /// Expected result schema/artifact contract.
    #[must_use]
    pub const fn expected_result_root(&self) -> Digest {
        self.expected_result_root
    }

    /// Typed refusal/result contract.
    #[must_use]
    pub const fn refusal_contract_root(&self) -> Digest {
        self.refusal_contract_root
    }

    /// Continuation contract for the next packet or reconciliation step.
    #[must_use]
    pub const fn continuation_contract_root(&self) -> Digest {
        self.continuation_contract_root
    }

    /// Executor implementation/profile identity.
    #[must_use]
    pub const fn executor_profile(&self) -> [u8; 32] {
        self.executor_profile
    }
}

/// Why action-packet construction failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionPacketRefusal {
    /// Situation names another run.
    SituationRunMismatch,
    /// Situation carries another complete run commitment.
    SituationRunCommitmentMismatch {
        /// Commitment computed from the supplied run.
        expected: IntentRunCommitment,
        /// Commitment retained by the situation, when present.
        observed: Option<IntentRunCommitment>,
    },
    /// Run lacks a complete authenticated authority receipt.
    RunAuthorityReceiptRequired,
    /// Situation and run use different authority positions.
    RunAuthorityMismatch,
    /// Plan names another run.
    PlanRunMismatch,
    /// Plan carries another complete run commitment.
    PlanRunCommitmentMismatch {
        /// Commitment computed from the supplied run.
        expected: IntentRunCommitment,
        /// Commitment retained by the plan.
        observed: IntentRunCommitment,
    },
    /// Activated claim names another plan.
    ClaimPlanMismatch,
    /// Activated claim names another task.
    ClaimTaskMismatch,
    /// Activated claim names another run.
    ClaimRunMismatch,
    /// Activated claim carries another complete run commitment.
    ClaimRunCommitmentMismatch {
        /// Commitment computed from the supplied run.
        expected: IntentRunCommitment,
        /// Commitment retained by the claim.
        observed: IntentRunCommitment,
    },
    /// Situation is not the exact receipt that activated the claim.
    ClaimSituationMismatch {
        /// Situation committed by the activated claim.
        expected: [u8; 32],
        /// Situation supplied to the packet builder.
        observed: [u8; 32],
    },
    /// Complete run identity could not be produced.
    RunIdentity(IntentRunIdentityRefusal),
    /// Activated claim is expired at packet construction.
    ClaimExpired {
        /// Exclusive claim expiry.
        expires_at: LogicalTime,
        /// Packet observation.
        observed_at: LogicalTime,
    },
    /// Run is expired at packet construction.
    RunExpired {
        /// Exclusive run expiry.
        expires_at: LogicalTime,
        /// Packet observation.
        observed_at: LogicalTime,
    },
    /// Current situation omitted the task projection.
    TaskProjectionUnavailable,
    /// Supplied run no longer covers all plan effects.
    PlanOperationsOutsideRun {
        /// Plan operations missing from the supplied run.
        missing: ClassSet,
    },
    /// Plan budget exceeds the supplied run.
    PlanBudgetOutsideRun {
        /// First deficient resource grade.
        deficit: ResourceError,
    },
    /// Too many context packets were supplied.
    TooManyContextPackets {
        /// Packets supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// Context packet belongs to another authority position.
    ContextAuthorityMismatch {
        /// Mismatched packet.
        packet_id: ContextPacketId,
    },
    /// Context packet was not admitted by the plan.
    ContextNotInPlan {
        /// Unapproved packet.
        packet_id: ContextPacketId,
    },
    /// A context packet admitted by the plan was omitted from the action.
    MissingContextPacket {
        /// Required packet.
        packet_id: ContextPacketId,
    },
    /// Context packet authorizes operations outside the plan.
    ContextScopeOutsidePlan {
        /// Packet with excessive scope.
        packet_id: ContextPacketId,
        /// Operations absent from the plan.
        missing: ClassSet,
    },
    /// Context packet identity appeared twice.
    DuplicateContextPacket {
        /// Repeated packet.
        packet_id: ContextPacketId,
    },
    /// No action step was declared.
    EmptySteps,
    /// Step count exceeded the hard ceiling.
    TooManySteps {
        /// Steps supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// Step identity used the reserved all-zero value.
    ZeroStepId,
    /// Step identity appeared twice.
    DuplicateStepId {
        /// Repeated identity.
        step_id: ActionStepId,
    },
    /// Step operation is outside the plan.
    OperationOutsidePlan {
        /// Step identity.
        step_id: ActionStepId,
        /// Unauthorized operation.
        operation: OperationClass,
    },
    /// Step target is outside the intended plan surface.
    TargetOutsidePlan {
        /// Step identity.
        step_id: ActionStepId,
        /// Unapproved target.
        target: PlanSurface,
    },
    /// Step declared no resource ceiling.
    EmptyStepBudget {
        /// Step identity.
        step_id: ActionStepId,
    },
    /// Aggregate budget arithmetic overflowed.
    AggregateBudgetOverflow {
        /// Step whose addition overflowed.
        step_id: ActionStepId,
        /// Resource algebra refusal.
        source: ResourceError,
    },
    /// Aggregate step budget exceeds the plan ceiling.
    AggregateBudgetExceedsPlan {
        /// First deficient resource grade.
        deficit: ResourceError,
    },
    /// Step names an evidence requirement absent from the plan.
    UnknownEvidenceRequirement {
        /// Step identity.
        step_id: ActionStepId,
        /// Unknown requirement.
        requirement_id: PlanRequirementId,
    },
    /// Evidence-submission step carries no requirement identity.
    EvidenceStepWithoutRequirement {
        /// Step identity.
        step_id: ActionStepId,
    },
    /// Mandatory stop preconditions are missing.
    MissingPreconditions {
        /// Missing conditions.
        missing: ActionPreconditionSet,
    },
    /// Peer-change collection exceeded its hard ceiling.
    TooManyPeerChanges {
        /// Entries supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// Peer-change commitment appeared twice.
    DuplicatePeerChange {
        /// Repeated commitment.
        root: Digest,
    },
    /// Executor profile used the reserved all-zero value.
    ZeroExecutorProfile,
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for ActionPacketRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "action packet refused: {self:?}")
    }
}

impl core::error::Error for ActionPacketRefusal {}

impl From<IntentRunIdentityRefusal> for ActionPacketRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<CodecRefusal> for ActionPacketRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_control_basis(
    situation: &AgentSituationReceipt,
    plan: &AgentChangePlan,
    claim: ActiveTaskClaim,
    run: &IntentRun,
) -> Result<([u8; 32], IntentRunCommitment), ActionPacketRefusal> {
    if situation.intent_run_id() != Some(run.run_id()) {
        return Err(ActionPacketRefusal::SituationRunMismatch);
    }
    let run_commitment = run.commitment()?;
    if situation.intent_run_commitment() != Some(run_commitment) {
        return Err(ActionPacketRefusal::SituationRunCommitmentMismatch {
            expected: run_commitment,
            observed: situation.intent_run_commitment(),
        });
    }
    let authority = run
        .authority_read_receipt()
        .ok_or(ActionPacketRefusal::RunAuthorityReceiptRequired)?;
    if authority != situation.authority_read_receipt() {
        return Err(ActionPacketRefusal::RunAuthorityMismatch);
    }
    if plan.intent_run_id() != run.run_id() {
        return Err(ActionPacketRefusal::PlanRunMismatch);
    }
    if plan.intent_run_commitment() != run_commitment {
        return Err(ActionPacketRefusal::PlanRunCommitmentMismatch {
            expected: run_commitment,
            observed: plan.intent_run_commitment(),
        });
    }
    if claim.plan_id() != plan.plan_id() {
        return Err(ActionPacketRefusal::ClaimPlanMismatch);
    }
    if claim.task_id() != plan.task_id() {
        return Err(ActionPacketRefusal::ClaimTaskMismatch);
    }
    if claim.assignee() != run.run_id() {
        return Err(ActionPacketRefusal::ClaimRunMismatch);
    }
    if claim.run_commitment() != run_commitment {
        return Err(ActionPacketRefusal::ClaimRunCommitmentMismatch {
            expected: run_commitment,
            observed: claim.run_commitment(),
        });
    }
    let observed_situation = *situation.situation_id().as_bytes();
    if claim.situation_id() != observed_situation {
        return Err(ActionPacketRefusal::ClaimSituationMismatch {
            expected: claim.situation_id(),
            observed: observed_situation,
        });
    }
    if !claim.is_live_at(situation.observed_at()) {
        return Err(ActionPacketRefusal::ClaimExpired {
            expires_at: claim.expires_at(),
            observed_at: situation.observed_at(),
        });
    }
    if !run.is_open_at(situation.observed_at()) {
        return Err(ActionPacketRefusal::RunExpired {
            expires_at: run.expiry(),
            observed_at: situation.observed_at(),
        });
    }
    let generation = situation
        .component(SituationComponentKind::TaskProjection)
        .generation_commitment()
        .ok_or(ActionPacketRefusal::TaskProjectionUnavailable)?;
    if !plan
        .effect_plan()
        .is_subset_of(run.allowed_operation_classes())
    {
        return Err(ActionPacketRefusal::PlanOperationsOutsideRun {
            missing: plan
                .effect_plan()
                .difference(run.allowed_operation_classes()),
        });
    }
    if let Some(deficit) = run.resource_budget().first_deficit(&plan.resource_budget()) {
        return Err(ActionPacketRefusal::PlanBudgetOutsideRun { deficit });
    }
    Ok((generation, run_commitment))
}

fn validate_context(
    plan: &AgentChangePlan,
    run: &IntentRun,
    packets: &[ContextPacket],
) -> Result<Vec<ContextPacketId>, ActionPacketRefusal> {
    if packets.len() > MAX_ACTION_CONTEXT_PACKETS {
        return Err(ActionPacketRefusal::TooManyContextPackets {
            observed: packets.len(),
            limit: MAX_ACTION_CONTEXT_PACKETS,
        });
    }
    let authority = run
        .authority_read_receipt()
        .ok_or(ActionPacketRefusal::RunAuthorityReceiptRequired)?;
    let mut ids = Vec::with_capacity(packets.len());
    for packet in packets {
        if packet.authority_read_receipt() != authority {
            return Err(ActionPacketRefusal::ContextAuthorityMismatch {
                packet_id: packet.packet_id(),
            });
        }
        if plan
            .input_context_packets()
            .binary_search(&packet.packet_id())
            .is_err()
        {
            return Err(ActionPacketRefusal::ContextNotInPlan {
                packet_id: packet.packet_id(),
            });
        }
        let scope = packet.control().authorization_scope();
        if !scope.is_subset_of(plan.effect_plan()) {
            return Err(ActionPacketRefusal::ContextScopeOutsidePlan {
                packet_id: packet.packet_id(),
                missing: scope.difference(plan.effect_plan()),
            });
        }
        ids.push(packet.packet_id());
    }
    ids.sort_unstable();
    for adjacent in ids.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(ActionPacketRefusal::DuplicateContextPacket {
                packet_id: adjacent[0],
            });
        }
    }
    for required in plan.input_context_packets() {
        if ids.binary_search(required).is_err() {
            return Err(ActionPacketRefusal::MissingContextPacket {
                packet_id: *required,
            });
        }
    }
    Ok(ids)
}

fn validate_steps(
    plan: &AgentChangePlan,
    run: &IntentRun,
    steps: &[ActionStep],
) -> Result<ResourceVector, ActionPacketRefusal> {
    if steps.is_empty() {
        return Err(ActionPacketRefusal::EmptySteps);
    }
    if steps.len() > MAX_ACTION_STEPS {
        return Err(ActionPacketRefusal::TooManySteps {
            observed: steps.len(),
            limit: MAX_ACTION_STEPS,
        });
    }
    let mut ids = Vec::with_capacity(steps.len());
    let mut aggregate = ResourceVector::ZERO;
    for step in steps {
        if step.step_id.is_zero() {
            return Err(ActionPacketRefusal::ZeroStepId);
        }
        ids.push(step.step_id);
        if !plan.effect_plan().contains(step.operation)
            || !run.allowed_operation_classes().contains(step.operation)
        {
            return Err(ActionPacketRefusal::OperationOutsidePlan {
                step_id: step.step_id,
                operation: step.operation,
            });
        }
        if plan
            .intended_change_surface()
            .binary_search(&step.target)
            .is_err()
        {
            return Err(ActionPacketRefusal::TargetOutsidePlan {
                step_id: step.step_id,
                target: step.target,
            });
        }
        if step.resource_budget.is_zero() {
            return Err(ActionPacketRefusal::EmptyStepBudget {
                step_id: step.step_id,
            });
        }
        aggregate = aggregate.combine(&step.resource_budget).map_err(|source| {
            ActionPacketRefusal::AggregateBudgetOverflow {
                step_id: step.step_id,
                source,
            }
        })?;
        if let Some(requirement_id) = step.evidence_requirement {
            if !plan
                .evidence_plan()
                .iter()
                .any(|requirement| requirement.requirement_id() == requirement_id)
            {
                return Err(ActionPacketRefusal::UnknownEvidenceRequirement {
                    step_id: step.step_id,
                    requirement_id,
                });
            }
        } else if step.operation == OperationClass::SubmitEvidence {
            return Err(ActionPacketRefusal::EvidenceStepWithoutRequirement {
                step_id: step.step_id,
            });
        }
    }
    ids.sort_unstable();
    for adjacent in ids.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(ActionPacketRefusal::DuplicateStepId {
                step_id: adjacent[0],
            });
        }
    }
    if let Some(deficit) = plan.resource_budget().first_deficit(&aggregate) {
        return Err(ActionPacketRefusal::AggregateBudgetExceedsPlan { deficit });
    }
    Ok(aggregate)
}

fn canonicalize_peer_changes(values: &mut [Digest]) -> Result<(), ActionPacketRefusal> {
    if values.len() > MAX_ACTION_PEER_CHANGES {
        return Err(ActionPacketRefusal::TooManyPeerChanges {
            observed: values.len(),
            limit: MAX_ACTION_PEER_CHANGES,
        });
    }
    values.sort_unstable();
    for adjacent in values.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(ActionPacketRefusal::DuplicatePeerChange { root: adjacent[0] });
        }
    }
    Ok(())
}

fn packet_commitment(packet: &AgentActionPacket) -> Result<[u8; 32], ActionPacketRefusal> {
    let mut encoder = Encoder::with_capacity(1_088);
    encoder.write_bytes("agent_action_packet_domain", ACTION_PACKET_DOMAIN)?;
    encoder.write_raw(packet.situation_id.as_bytes());
    encoder.write_raw(&packet.task_projection_generation);
    encoder.write_raw(packet.plan_id.as_bytes());
    encoder.write_raw(packet.active_claim_id.as_bytes());
    encoder.write_raw(packet.task_id.as_bytes());
    encoder.write_raw(&packet.run_id.value().to_be_bytes());
    encoder.write_raw(packet.run_commitment.as_bytes());
    encoder.write_scalar(packet.observed_at.value());
    write_count(
        &mut encoder,
        "action_packet.context_packet_ids",
        packet.context_packet_ids.len(),
    )?;
    for packet_id in &packet.context_packet_ids {
        encoder.write_raw(packet_id.as_bytes());
    }
    write_count(&mut encoder, "action_packet.steps", packet.steps.len())?;
    for step in &packet.steps {
        encoder.write_raw(step.step_id.as_bytes());
        encoder.write_scalar(operation_code(step.operation));
        write_surface(&mut encoder, step.target)?;
        encoder.write_digest(&step.input_root)?;
        encoder.write_digest(&step.expected_output_root)?;
        for (_grade, amount) in step.resource_budget.pairs() {
            encoder.write_scalar(amount);
        }
        match step.evidence_requirement {
            Some(requirement_id) => {
                encoder.write_bool(true);
                encoder.write_raw(requirement_id.as_bytes());
            }
            None => encoder.write_bool(false),
        }
    }
    for (_grade, amount) in packet.aggregate_budget.pairs() {
        encoder.write_scalar(amount);
    }
    write_count(
        &mut encoder,
        "action_packet.peer_change_roots",
        packet.peer_change_roots.len(),
    )?;
    for root in &packet.peer_change_roots {
        encoder.write_digest(root)?;
    }
    encoder.write_scalar(packet.preconditions.bits());
    encoder.write_digest(&packet.expected_result_root)?;
    encoder.write_digest(&packet.refusal_contract_root)?;
    encoder.write_digest(&packet.continuation_contract_root)?;
    encoder.write_raw(&packet.executor_profile);

    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn write_surface(encoder: &mut Encoder, surface: PlanSurface) -> Result<(), ActionPacketRefusal> {
    encoder.write_raw_byte(surface_kind_code(surface.kind()));
    encoder.write_digest(&surface.selector())?;
    Ok(())
}

fn write_count(
    encoder: &mut Encoder,
    field: &'static str,
    count: usize,
) -> Result<(), ActionPacketRefusal> {
    let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(count).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    Ok(())
}

const fn operation_code(operation: OperationClass) -> u16 {
    match operation {
        OperationClass::ReadCanonicalObject => 1,
        OperationClass::ReadDerivedGeneration => 2,
        OperationClass::CreateCandidateObject => 3,
        OperationClass::TreeFsWorkspace => 4,
        OperationClass::ExecuteSandboxedProcess => 5,
        OperationClass::PreparePublication => 6,
        OperationClass::SubmitEvidence => 7,
        OperationClass::MutateForgeEntity => 8,
        OperationClass::ExternalIntegration => 9,
        OperationClass::NetworkDestination => 10,
        OperationClass::SecretHandle => 11,
        OperationClass::DelegateSubIntent => 12,
        OperationClass::ConsumeBudget => 13,
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

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
