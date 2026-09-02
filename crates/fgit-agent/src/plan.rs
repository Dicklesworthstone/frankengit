//! Authority-bound change plans for one selected agent-control action.
//!
//! A work frontier is advisory. Before execution, one selected row needs a
//! complete contract that fixes what will change, what may conflict, which
//! checkpoints are coherent, what evidence is owed, which effects and budget
//! are permitted, and which conditions stop the attempt. [`AgentChangePlan`]
//! is that inert contract.
//!
//! The plan does not claim work, reserve files, execute tools, mutate a
//! workspace, or publish repository state. It is a deterministic commitment
//! over an already validated [`crate::AgentControlPulse`], the exact live
//! [`crate::IntentRun`] including its complete machine commitment,
//! authority-matched context packets, and bounded typed planning inputs.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_resource::{ResourceError, ResourceVector};
use fgit_types::Digest;

use crate::{
    AgentControlPulse, ClassSet, ContextPacket, ContextPacketId, EvidenceClass, IntentRun,
    IntentRunCommitment, IntentRunIdentityRefusal, PulseSelection, PulseState, RunId,
    TaskPhase, WorkAction, WorkFrontierId, WorkTaskId,
};

/// Largest collection accepted in one plan field.
pub const MAX_PLAN_ENTRIES: usize = 256;
/// Largest ordered checkpoint sequence in one plan.
pub const MAX_PLAN_CHECKPOINTS: usize = 64;
const PLAN_DOMAIN: &[u8] = b"frankengit.agent.change-plan/v2\0";

/// Stable SHA-256 identity of a complete change plan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentChangePlanId([u8; 32]);

impl AgentChangePlanId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AgentChangePlanId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("plan:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The kind of resource one declared surface selector addresses.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PlanSurfaceKind {
    /// Repository path or path family.
    RepositoryPath,
    /// Direct or symbolic ref.
    Ref,
    /// Forge entity or stream.
    ForgeEntity,
    /// Canonical schema or registry row.
    SchemaOrRegistry,
    /// Test or verification target.
    EvidenceTarget,
    /// External effect destination or key.
    ExternalEffect,
    /// `TreeFS` workspace or overlay domain.
    Workspace,
}

impl PlanSurfaceKind {
    const fn code_point(self) -> u8 {
        match self {
            Self::RepositoryPath => 1,
            Self::Ref => 2,
            Self::ForgeEntity => 3,
            Self::SchemaOrRegistry => 4,
            Self::EvidenceTarget => 5,
            Self::ExternalEffect => 6,
            Self::Workspace => 7,
        }
    }
}

/// One committed change or conflict selector.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanSurface {
    kind: PlanSurfaceKind,
    selector: Digest,
}

impl PlanSurface {
    /// Creates a typed surface selector from its canonical commitment.
    #[must_use]
    pub const fn new(kind: PlanSurfaceKind, selector: Digest) -> Self {
        Self { kind, selector }
    }

    /// Surface kind.
    #[must_use]
    pub const fn kind(self) -> PlanSurfaceKind {
        self.kind
    }

    /// Commitment to the exact selector.
    #[must_use]
    pub const fn selector(self) -> Digest {
        self.selector
    }
}

/// Opaque checkpoint identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanCheckpointId([u8; 32]);

impl PlanCheckpointId {
    /// Constructs an identity from fixed-width bytes.
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

/// What coherent result one checkpoint must land.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PlanCheckpointPurpose {
    /// Establish the exact basis and ownership boundary.
    InspectBasis,
    /// Land one complete implementation slice.
    ImplementSlice,
    /// Land one complete correction after a named failed gate.
    RepairSlice,
    /// Produce the designated verification evidence.
    VerifySlice,
    /// Reconcile effects, obligations, or cancellation before handoff/close.
    Reconcile,
}

impl PlanCheckpointPurpose {
    const fn code_point(self) -> u8 {
        match self {
            Self::InspectBasis => 1,
            Self::ImplementSlice => 2,
            Self::RepairSlice => 3,
            Self::VerifySlice => 4,
            Self::Reconcile => 5,
        }
    }
}

/// One ordered, coherent plan checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanCheckpoint {
    checkpoint_id: PlanCheckpointId,
    purpose: PlanCheckpointPurpose,
    acceptance_slice_root: Digest,
    evidence_slice_root: Digest,
}

impl PlanCheckpoint {
    /// Creates one checkpoint.
    #[must_use]
    pub const fn new(
        checkpoint_id: PlanCheckpointId,
        purpose: PlanCheckpointPurpose,
        acceptance_slice_root: Digest,
        evidence_slice_root: Digest,
    ) -> Self {
        Self {
            checkpoint_id,
            purpose,
            acceptance_slice_root,
            evidence_slice_root,
        }
    }

    /// Stable checkpoint identity.
    #[must_use]
    pub const fn checkpoint_id(self) -> PlanCheckpointId {
        self.checkpoint_id
    }

    /// Coherent result class.
    #[must_use]
    pub const fn purpose(self) -> PlanCheckpointPurpose {
        self.purpose
    }

    /// Contract slice discharged by this checkpoint.
    #[must_use]
    pub const fn acceptance_slice_root(self) -> Digest {
        self.acceptance_slice_root
    }

    /// Evidence contract discharged by this checkpoint.
    #[must_use]
    pub const fn evidence_slice_root(self) -> Digest {
        self.evidence_slice_root
    }
}

/// Opaque acceptance-requirement identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanRequirementId([u8; 32]);

impl PlanRequirementId {
    /// Constructs an identity from fixed-width bytes.
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

/// Evidence owed for one acceptance requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanEvidenceRequirement {
    requirement_id: PlanRequirementId,
    evidence_class: EvidenceClass,
    artifact_contract: Digest,
    requires_independent_verifier: bool,
}

impl PlanEvidenceRequirement {
    /// Creates one evidence obligation.
    #[must_use]
    pub const fn new(
        requirement_id: PlanRequirementId,
        evidence_class: EvidenceClass,
        artifact_contract: Digest,
        requires_independent_verifier: bool,
    ) -> Self {
        Self {
            requirement_id,
            evidence_class,
            artifact_contract,
            requires_independent_verifier,
        }
    }

    /// Stable requirement identity.
    #[must_use]
    pub const fn requirement_id(self) -> PlanRequirementId {
        self.requirement_id
    }

    /// Required evidence class.
    #[must_use]
    pub const fn evidence_class(self) -> EvidenceClass {
        self.evidence_class
    }

    /// Commitment to the expected artifact/result contract.
    #[must_use]
    pub const fn artifact_contract(self) -> Digest {
        self.artifact_contract
    }

    /// Whether policy requires a verifier independent from the implementation.
    #[must_use]
    pub const fn requires_independent_verifier(self) -> bool {
        self.requires_independent_verifier
    }
}

/// A condition that invalidates or stops plan execution.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PlanStopCondition {
    /// Authenticated repository authority moved.
    AuthorityMoved = 0,
    /// Task projection generation changed.
    TaskProjectionMoved = 1,
    /// Declared conflict surface is no longer clear.
    ConflictDetected = 2,
    /// Required capability is unavailable or revoked.
    CapabilityUnavailable = 3,
    /// The plan budget cannot cover the next bounded action.
    BudgetExhausted = 4,
    /// A mandatory evidence gate failed or became indeterminate.
    RequiredEvidenceFailed = 5,
    /// Cancellation was requested.
    CancellationRequested = 6,
    /// An effect or obligation cannot be settled.
    ObligationUnsettled = 7,
}

impl PlanStopCondition {
    /// Every stop condition in stable bit order.
    pub const ALL: [Self; 8] = [
        Self::AuthorityMoved,
        Self::TaskProjectionMoved,
        Self::ConflictDetected,
        Self::CapabilityUnavailable,
        Self::BudgetExhausted,
        Self::RequiredEvidenceFailed,
        Self::CancellationRequested,
        Self::ObligationUnsettled,
    ];

    const fn bit(self) -> u16 {
        1_u16 << (self as u8)
    }
}

/// Closed set of stop conditions.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanStopConditionSet(u16);

impl PlanStopConditionSet {
    /// Conditions every executable plan must carry.
    pub const MANDATORY: Self = Self(
        PlanStopCondition::AuthorityMoved.bit()
            | PlanStopCondition::TaskProjectionMoved.bit()
            | PlanStopCondition::ConflictDetected.bit()
            | PlanStopCondition::BudgetExhausted.bit()
            | PlanStopCondition::RequiredEvidenceFailed.bit()
            | PlanStopCondition::CancellationRequested.bit(),
    );

    /// Builds a set from conditions.
    #[must_use]
    pub fn from_conditions(conditions: &[PlanStopCondition]) -> Self {
        let mut bits = 0_u16;
        for condition in conditions {
            bits |= condition.bit();
        }
        Self(bits)
    }

    /// Raw stable bit mask.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether this set contains one condition.
    #[must_use]
    pub const fn contains(self, condition: PlanStopCondition) -> bool {
        self.0 & condition.bit() != 0
    }

    /// Whether every condition in `other` is present here.
    #[must_use]
    pub const fn contains_all(self, other: Self) -> bool {
        other.0 & !self.0 == 0
    }

    /// Conditions present in `self` and absent in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Conditions in declaration order.
    pub fn iter(self) -> impl Iterator<Item = PlanStopCondition> {
        PlanStopCondition::ALL
            .into_iter()
            .filter(move |condition| self.contains(*condition))
    }
}

/// A shortcut the plan explicitly refuses.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RejectedShortcut {
    /// Empty scaffold or interface without its final abstraction slice.
    EmptyScaffold = 0,
    /// Parallel mutation/publication authority.
    ParallelAuthorityPath = 1,
    /// Weakening an oracle, test, or invariant merely to obtain green output.
    OracleWeakening = 2,
    /// Unbounded input, allocation, retry, or output.
    UnboundedWork = 3,
    /// Ambient or inherited authority outside the run.
    AmbientAuthority = 4,
    /// A second mutable truth plane beside authenticated repository state.
    ParallelTruthPlane = 5,
    /// Blocking bridge inside an asynchronous effect path.
    AsyncBlockingBridge = 6,
    /// Summary prose presented as evidence.
    EvidenceBySummary = 7,
}

impl RejectedShortcut {
    /// Every shortcut in stable bit order.
    pub const ALL: [Self; 8] = [
        Self::EmptyScaffold,
        Self::ParallelAuthorityPath,
        Self::OracleWeakening,
        Self::UnboundedWork,
        Self::AmbientAuthority,
        Self::ParallelTruthPlane,
        Self::AsyncBlockingBridge,
        Self::EvidenceBySummary,
    ];

    const fn bit(self) -> u16 {
        1_u16 << (self as u8)
    }
}

/// Closed set of explicitly rejected shortcuts.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RejectedShortcutSet(u16);

impl RejectedShortcutSet {
    /// Baseline exclusions required by every plan.
    pub const BASELINE: Self = Self(
        RejectedShortcut::EmptyScaffold.bit()
            | RejectedShortcut::OracleWeakening.bit()
            | RejectedShortcut::AmbientAuthority.bit()
            | RejectedShortcut::ParallelTruthPlane.bit()
            | RejectedShortcut::EvidenceBySummary.bit(),
    );

    /// Builds a set from shortcuts.
    #[must_use]
    pub fn from_shortcuts(shortcuts: &[RejectedShortcut]) -> Self {
        let mut bits = 0_u16;
        for shortcut in shortcuts {
            bits |= shortcut.bit();
        }
        Self(bits)
    }

    /// Raw stable bit mask.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether this set contains one shortcut.
    #[must_use]
    pub const fn contains(self, shortcut: RejectedShortcut) -> bool {
        self.0 & shortcut.bit() != 0
    }

    /// Whether every shortcut in `other` is present here.
    #[must_use]
    pub const fn contains_all(self, other: Self) -> bool {
        other.0 & !self.0 == 0
    }

    /// Shortcuts present in `self` and absent in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Shortcuts in declaration order.
    pub fn iter(self) -> impl Iterator<Item = RejectedShortcut> {
        RejectedShortcut::ALL
            .into_iter()
            .filter(move |shortcut| self.contains(*shortcut))
    }
}

/// Approval state bound into a plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanApproval {
    /// Policy says no separate sponsor approval is required.
    NotRequired {
        /// Policy decision supporting that conclusion.
        policy_root: Digest,
    },
    /// A sponsor or policy approver granted this exact plan class.
    Granted {
        /// Approval evidence.
        approval_root: Digest,
    },
}

impl PlanApproval {
    const fn code_point(self) -> u8 {
        match self {
            Self::NotRequired { .. } => 1,
            Self::Granted { .. } => 2,
        }
    }

    const fn root(self) -> Digest {
        match self {
            Self::NotRequired { policy_root } => policy_root,
            Self::Granted { approval_root } => approval_root,
        }
    }
}

/// Bounded inputs used to construct one plan.
///
/// Builder methods replace a field wholesale. The plan constructor later sorts
/// unordered collections, rejects duplicates, and preserves checkpoint order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentChangePlanSpec {
    acceptance_contract_root: Digest,
    owning_invariants: Vec<Digest>,
    intended_change_surface: Vec<PlanSurface>,
    conflict_surface: Vec<PlanSurface>,
    checkpoints: Vec<PlanCheckpoint>,
    evidence_plan: Vec<PlanEvidenceRequirement>,
    effect_plan: ClassSet,
    resource_budget: ResourceVector,
    stop_conditions: PlanStopConditionSet,
    rejected_shortcuts: RejectedShortcutSet,
    non_claims: Vec<Digest>,
    approval: PlanApproval,
}

impl AgentChangePlanSpec {
    /// Creates the required plan frame; optional collections start empty.
    #[must_use]
    pub const fn new(
        acceptance_contract_root: Digest,
        effect_plan: ClassSet,
        resource_budget: ResourceVector,
        stop_conditions: PlanStopConditionSet,
        rejected_shortcuts: RejectedShortcutSet,
        approval: PlanApproval,
    ) -> Self {
        Self {
            acceptance_contract_root,
            owning_invariants: Vec::new(),
            intended_change_surface: Vec::new(),
            conflict_surface: Vec::new(),
            checkpoints: Vec::new(),
            evidence_plan: Vec::new(),
            effect_plan,
            resource_budget,
            stop_conditions,
            rejected_shortcuts,
            non_claims: Vec::new(),
            approval,
        }
    }

    /// Sets invariant commitments.
    #[must_use]
    pub fn with_owning_invariants(mut self, invariants: Vec<Digest>) -> Self {
        self.owning_invariants = invariants;
        self
    }

    /// Sets intended and conflict surfaces.
    #[must_use]
    pub fn with_surfaces(
        mut self,
        intended: Vec<PlanSurface>,
        conflict: Vec<PlanSurface>,
    ) -> Self {
        self.intended_change_surface = intended;
        self.conflict_surface = conflict;
        self
    }

    /// Sets ordered coherent checkpoints.
    #[must_use]
    pub fn with_checkpoints(mut self, checkpoints: Vec<PlanCheckpoint>) -> Self {
        self.checkpoints = checkpoints;
        self
    }

    /// Sets evidence obligations.
    #[must_use]
    pub fn with_evidence_plan(mut self, evidence: Vec<PlanEvidenceRequirement>) -> Self {
        self.evidence_plan = evidence;
        self
    }

    /// Sets explicit non-claim commitments.
    #[must_use]
    pub fn with_non_claims(mut self, non_claims: Vec<Digest>) -> Self {
        self.non_claims = non_claims;
        self
    }
}

/// One complete inert plan for the pulse's selected task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentChangePlan {
    plan_id: AgentChangePlanId,
    pulse_id: [u8; 32],
    situation_id: [u8; 32],
    frontier_id: WorkFrontierId,
    intent_run_id: RunId,
    intent_run_commitment: IntentRunCommitment,
    task_id: WorkTaskId,
    task_phase: TaskPhase,
    action: WorkAction,
    acceptance_contract_root: Digest,
    owning_invariants: Vec<Digest>,
    input_context_packets: Vec<ContextPacketId>,
    intended_change_surface: Vec<PlanSurface>,
    conflict_surface: Vec<PlanSurface>,
    checkpoints: Vec<PlanCheckpoint>,
    evidence_plan: Vec<PlanEvidenceRequirement>,
    effect_plan: ClassSet,
    resource_budget: ResourceVector,
    stop_conditions: PlanStopConditionSet,
    rejected_shortcuts: RejectedShortcutSet,
    non_claims: Vec<Digest>,
    approval: PlanApproval,
}

impl AgentChangePlan {
    /// Builds one plan for the exact selected pulse action.
    ///
    /// # Errors
    ///
    /// Refuses a non-actionable pulse, missing or substituted complete run,
    /// stale run, authority-mismatched context, excessive/duplicate inputs,
    /// incomplete conflict coverage, incoherent checkpoints/evidence,
    /// operation or budget amplification, missing mandatory stop conditions,
    /// missing baseline shortcut refusals, and unrepresentable canonical
    /// framing.
    pub fn build(
        pulse: &AgentControlPulse,
        run: &IntentRun,
        context_packets: &[ContextPacket],
        mut spec: AgentChangePlanSpec,
    ) -> Result<Self, PlanRefusal> {
        let (selected, run_commitment) = validate_plan_run(pulse, run)?;
        validate_plan_scope(run, &spec)?;

        let run_receipt = run
            .authority_read_receipt()
            .ok_or(PlanRefusal::ActiveRunAuthorityReceiptRequired)?;
        let input_context_packets = collect_context_packets(run_receipt, context_packets)?;
        canonicalize_digests("owning_invariants", &mut spec.owning_invariants)?;
        canonicalize_digests("non_claims", &mut spec.non_claims)?;
        canonicalize_surfaces(
            &mut spec.intended_change_surface,
            &mut spec.conflict_surface,
        )?;
        validate_checkpoints(selected.action(), &spec.checkpoints)?;
        canonicalize_evidence(selected.action(), &mut spec.evidence_plan)?;

        let mut plan = Self {
            plan_id: AgentChangePlanId([0; 32]),
            pulse_id: *pulse.pulse_id().as_bytes(),
            situation_id: *pulse.situation_id(),
            frontier_id: pulse.frontier_id(),
            intent_run_id: run.run_id(),
            intent_run_commitment: run_commitment,
            task_id: selected.task_id(),
            task_phase: selected.phase(),
            action: selected.action(),
            acceptance_contract_root: spec.acceptance_contract_root,
            owning_invariants: spec.owning_invariants,
            input_context_packets,
            intended_change_surface: spec.intended_change_surface,
            conflict_surface: spec.conflict_surface,
            checkpoints: spec.checkpoints,
            evidence_plan: spec.evidence_plan,
            effect_plan: spec.effect_plan,
            resource_budget: spec.resource_budget,
            stop_conditions: spec.stop_conditions,
            rejected_shortcuts: spec.rejected_shortcuts,
            non_claims: spec.non_claims,
            approval: spec.approval,
        };
        plan.plan_id = AgentChangePlanId(plan_commitment(&plan)?);
        Ok(plan)
    }

    /// Stable plan identity.
    #[must_use]
    pub const fn plan_id(&self) -> AgentChangePlanId {
        self.plan_id
    }

    /// Pulse this plan elaborates.
    #[must_use]
    pub const fn pulse_id(&self) -> &[u8; 32] {
        &self.pulse_id
    }

    /// Situation receipt this plan elaborates.
    #[must_use]
    pub const fn situation_id(&self) -> &[u8; 32] {
        &self.situation_id
    }

    /// Frontier this plan elaborates.
    #[must_use]
    pub const fn frontier_id(&self) -> WorkFrontierId {
        self.frontier_id
    }

    /// Coordination ID of the run authorized to execute the plan.
    #[must_use]
    pub const fn intent_run_id(&self) -> RunId {
        self.intent_run_id
    }

    /// Complete machine-enforced run identity authorized to execute the plan.
    #[must_use]
    pub const fn intent_run_commitment(&self) -> IntentRunCommitment {
        self.intent_run_commitment
    }

    /// Selected task.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.task_id
    }

    /// Selected projected phase.
    #[must_use]
    pub const fn task_phase(&self) -> TaskPhase {
        self.task_phase
    }

    /// Selected action.
    #[must_use]
    pub const fn action(&self) -> WorkAction {
        self.action
    }

    /// Acceptance contract.
    #[must_use]
    pub const fn acceptance_contract_root(&self) -> Digest {
        self.acceptance_contract_root
    }

    /// Owning invariant commitments.
    #[must_use]
    pub fn owning_invariants(&self) -> &[Digest] {
        &self.owning_invariants
    }

    /// Authority-matched context packet identities.
    #[must_use]
    pub fn input_context_packets(&self) -> &[ContextPacketId] {
        &self.input_context_packets
    }

    /// Exact intended change selectors.
    #[must_use]
    pub fn intended_change_surface(&self) -> &[PlanSurface] {
        &self.intended_change_surface
    }

    /// Coordination/conflict selectors covering every intended change.
    #[must_use]
    pub fn conflict_surface(&self) -> &[PlanSurface] {
        &self.conflict_surface
    }

    /// Ordered coherent checkpoints.
    #[must_use]
    pub fn checkpoints(&self) -> &[PlanCheckpoint] {
        &self.checkpoints
    }

    /// Evidence obligations.
    #[must_use]
    pub fn evidence_plan(&self) -> &[PlanEvidenceRequirement] {
        &self.evidence_plan
    }

    /// Planned effect classes; these grant no authority.
    #[must_use]
    pub const fn effect_plan(&self) -> ClassSet {
        self.effect_plan
    }

    /// Plan-local resource ceiling.
    #[must_use]
    pub const fn resource_budget(&self) -> ResourceVector {
        self.resource_budget
    }

    /// Conditions that stop or invalidate execution.
    #[must_use]
    pub const fn stop_conditions(&self) -> PlanStopConditionSet {
        self.stop_conditions
    }

    /// Explicitly rejected shortcuts.
    #[must_use]
    pub const fn rejected_shortcuts(&self) -> RejectedShortcutSet {
        self.rejected_shortcuts
    }

    /// Explicit non-claim commitments.
    #[must_use]
    pub fn non_claims(&self) -> &[Digest] {
        &self.non_claims
    }

    /// Approval state.
    #[must_use]
    pub const fn approval(&self) -> PlanApproval {
        self.approval
    }
}

/// Why plan construction failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanRefusal {
    /// Pulse has no actionable selected row.
    PulseNotActionable {
        /// Pulse state observed.
        state: PulseState,
    },
    /// Actionable pulse carried no run identity.
    ActiveRunMissing,
    /// Actionable pulse carried no complete run commitment.
    ActiveRunCommitmentMissing,
    /// Supplied run differs from the pulse.
    ActiveRunMismatch {
        /// Run selected by the pulse.
        expected: RunId,
        /// Run supplied to planning.
        observed: RunId,
    },
    /// Same coordination ID carries another complete run commitment.
    ActiveRunCommitmentMismatch {
        /// Commitment selected by the pulse.
        expected: IntentRunCommitment,
        /// Commitment computed from the supplied run.
        observed: IntentRunCommitment,
    },
    /// Supplied run has no complete authenticated authority receipt.
    ActiveRunAuthorityReceiptRequired,
    /// Supplied run is based on another authority position.
    ActiveRunAuthorityMismatch,
    /// Complete run identity could not be produced.
    RunIdentity(IntentRunIdentityRefusal),
    /// Supplied run expired at or before the pulse observation.
    ActiveRunExpired {
        /// Expired run.
        run_id: RunId,
    },
    /// No effect class was declared.
    EmptyEffectPlan,
    /// Effect plan asks for classes outside the run.
    EffectOutsideRun {
        /// Classes absent from the run.
        missing: ClassSet,
    },
    /// Plan declared no resource ceiling.
    EmptyResourceBudget,
    /// Plan resource ceiling exceeds the run.
    ResourceBudgetExceedsRun {
        /// First deficient resource grade.
        deficit: ResourceError,
    },
    /// Required stop conditions are absent.
    MissingStopConditions {
        /// Missing conditions.
        missing: PlanStopConditionSet,
    },
    /// Baseline shortcut refusals are absent.
    MissingRejectedShortcuts {
        /// Missing shortcut exclusions.
        missing: RejectedShortcutSet,
    },
    /// A context packet belongs to another authority position.
    ContextAuthorityMismatch {
        /// Mismatched packet.
        packet_id: ContextPacketId,
    },
    /// The same context packet appeared twice.
    DuplicateContextPacket {
        /// Repeated packet.
        packet_id: ContextPacketId,
    },
    /// One collection exceeded its hard ceiling.
    TooManyEntries {
        /// Collection name.
        field: &'static str,
        /// Entries supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// A logically unordered digest appeared twice.
    DuplicateDigest {
        /// Collection name.
        field: &'static str,
        /// Repeated digest.
        digest: Digest,
    },
    /// Intended change surface was empty.
    EmptyIntendedChangeSurface,
    /// A logically unordered surface appeared twice.
    DuplicateSurface {
        /// Collection name.
        field: &'static str,
        /// Repeated surface.
        surface: PlanSurface,
    },
    /// Conflict surface failed to cover an intended change.
    ConflictSurfaceIncomplete {
        /// Intended surface lacking coordination coverage.
        missing: PlanSurface,
    },
    /// No coherent checkpoint was declared.
    EmptyCheckpointPlan,
    /// Checkpoint identity used the reserved all-zero value.
    ZeroCheckpointId,
    /// Checkpoint identity appeared twice.
    DuplicateCheckpointId {
        /// Repeated identity.
        checkpoint_id: PlanCheckpointId,
    },
    /// Checkpoint sequence does not contain the selected action's final slice.
    MissingActionCheckpoint {
        /// Action selected by the pulse.
        action: WorkAction,
    },
    /// No evidence obligation was declared.
    EmptyEvidencePlan,
    /// Requirement identity used the reserved all-zero value.
    ZeroRequirementId,
    /// Requirement identity appeared twice.
    DuplicateRequirementId {
        /// Repeated identity.
        requirement_id: PlanRequirementId,
    },
    /// Evidence class records absence rather than supporting a claim.
    UnsupportedEvidenceClass {
        /// Invalid required class.
        class: EvidenceClass,
    },
    /// Verification action declared no independent evidence obligation.
    VerificationIndependenceMissing,
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for PlanRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PulseNotActionable { state } => {
                write!(formatter, "agent control pulse is not actionable: {state:?}")
            }
            Self::ActiveRunMissing => formatter.write_str("actionable pulse has no active run"),
            Self::ActiveRunCommitmentMissing => {
                formatter.write_str("actionable pulse has no complete active-run commitment")
            }
            Self::ActiveRunMismatch { expected, observed } => {
                write!(formatter, "supplied run {observed} differs from pulse run {expected}")
            }
            Self::ActiveRunCommitmentMismatch { expected, observed } => write!(
                formatter,
                "supplied run commitment {observed} differs from pulse run {expected}"
            ),
            Self::ActiveRunAuthorityReceiptRequired => formatter.write_str(
                "change planning requires a run with a complete authenticated authority receipt",
            ),
            Self::ActiveRunAuthorityMismatch => {
                formatter.write_str("active run authority differs from the pulse")
            }
            Self::RunIdentity(refusal) => write!(formatter, "active run identity refused: {refusal}"),
            Self::ActiveRunExpired { run_id } => {
                write!(formatter, "active run {run_id} expired before planning")
            }
            Self::EmptyEffectPlan => formatter.write_str("change plan declares no effect classes"),
            Self::EffectOutsideRun { missing } => {
                write!(formatter, "change plan requests unauthorized effect classes {missing}")
            }
            Self::EmptyResourceBudget => {
                formatter.write_str("change plan declares a zero resource budget")
            }
            Self::ResourceBudgetExceedsRun { deficit } => {
                write!(formatter, "change plan exceeds run budget: {deficit}")
            }
            Self::MissingStopConditions { missing } => write!(
                formatter,
                "change plan omits mandatory stop conditions (bits {:#06x})",
                missing.bits()
            ),
            Self::MissingRejectedShortcuts { missing } => write!(
                formatter,
                "change plan omits baseline shortcut refusals (bits {:#06x})",
                missing.bits()
            ),
            Self::ContextAuthorityMismatch { .. } => {
                formatter.write_str("context packet belongs to another authority position")
            }
            Self::DuplicateContextPacket { .. } => {
                formatter.write_str("context packet appears more than once")
            }
            Self::TooManyEntries {
                field,
                observed,
                limit,
            } => write!(formatter, "{field} has {observed} entries, limit {limit}"),
            Self::DuplicateDigest { field, digest } => {
                write!(formatter, "{field} repeats digest {digest}")
            }
            Self::EmptyIntendedChangeSurface => {
                formatter.write_str("change plan declares no intended change surface")
            }
            Self::DuplicateSurface { field, surface } => write!(
                formatter,
                "{field} repeats {:?} selector {}",
                surface.kind(),
                surface.selector()
            ),
            Self::ConflictSurfaceIncomplete { missing } => write!(
                formatter,
                "conflict surface does not cover {:?} selector {}",
                missing.kind(),
                missing.selector()
            ),
            Self::EmptyCheckpointPlan => {
                formatter.write_str("change plan declares no coherent checkpoints")
            }
            Self::ZeroCheckpointId => {
                formatter.write_str("checkpoint identity may not be all zero")
            }
            Self::DuplicateCheckpointId { .. } => {
                formatter.write_str("checkpoint identity appears more than once")
            }
            Self::MissingActionCheckpoint { action } => write!(
                formatter,
                "checkpoint sequence has no coherent slice for {action:?}"
            ),
            Self::EmptyEvidencePlan => {
                formatter.write_str("change plan declares no evidence obligations")
            }
            Self::ZeroRequirementId => {
                formatter.write_str("evidence requirement identity may not be all zero")
            }
            Self::DuplicateRequirementId { .. } => {
                formatter.write_str("evidence requirement identity appears more than once")
            }
            Self::UnsupportedEvidenceClass { class } => write!(
                formatter,
                "evidence class {class} records absence and cannot satisfy a required claim"
            ),
            Self::VerificationIndependenceMissing => formatter.write_str(
                "verification plan declares no independently verified evidence requirement",
            ),
            Self::Codec(refusal) => write!(formatter, "change plan framing refused: {refusal}"),
        }
    }
}

impl core::error::Error for PlanRefusal {}

impl From<IntentRunIdentityRefusal> for PlanRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<CodecRefusal> for PlanRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_plan_run(
    pulse: &AgentControlPulse,
    run: &IntentRun,
) -> Result<(PulseSelection, IntentRunCommitment), PlanRefusal> {
    if pulse.state() != PulseState::Actionable {
        return Err(PlanRefusal::PulseNotActionable {
            state: pulse.state(),
        });
    }
    let selected = pulse.selected().ok_or(PlanRefusal::PulseNotActionable {
        state: pulse.state(),
    })?;
    let expected_run = pulse.active_run().ok_or(PlanRefusal::ActiveRunMissing)?;
    let expected_commitment = pulse
        .active_run_commitment()
        .ok_or(PlanRefusal::ActiveRunCommitmentMissing)?;
    if run.run_id() != expected_run {
        return Err(PlanRefusal::ActiveRunMismatch {
            expected: expected_run,
            observed: run.run_id(),
        });
    }
    let observed_commitment = run.commitment()?;
    if observed_commitment != expected_commitment {
        return Err(PlanRefusal::ActiveRunCommitmentMismatch {
            expected: expected_commitment,
            observed: observed_commitment,
        });
    }
    let run_receipt = run
        .authority_read_receipt()
        .ok_or(PlanRefusal::ActiveRunAuthorityReceiptRequired)?;
    if run_receipt.repository_id() != pulse.repository_id()
        || run_receipt.authority_head_id() != pulse.authority_head_id()
        || run_receipt.authority_head_generation() != pulse.authority_head_generation()
    {
        return Err(PlanRefusal::ActiveRunAuthorityMismatch);
    }
    if !run.is_open_at(pulse.observed_at()) {
        return Err(PlanRefusal::ActiveRunExpired {
            run_id: run.run_id(),
        });
    }
    Ok((selected, observed_commitment))
}

fn validate_plan_scope(
    run: &IntentRun,
    spec: &AgentChangePlanSpec,
) -> Result<(), PlanRefusal> {
    if spec.effect_plan.is_empty() {
        return Err(PlanRefusal::EmptyEffectPlan);
    }
    if !spec
        .effect_plan
        .is_subset_of(run.allowed_operation_classes())
    {
        return Err(PlanRefusal::EffectOutsideRun {
            missing: spec
                .effect_plan
                .difference(run.allowed_operation_classes()),
        });
    }
    if spec.resource_budget.is_zero() {
        return Err(PlanRefusal::EmptyResourceBudget);
    }
    if let Some(deficit) = run.resource_budget().first_deficit(&spec.resource_budget) {
        return Err(PlanRefusal::ResourceBudgetExceedsRun { deficit });
    }
    if !spec
        .stop_conditions
        .contains_all(PlanStopConditionSet::MANDATORY)
    {
        return Err(PlanRefusal::MissingStopConditions {
            missing: PlanStopConditionSet::MANDATORY.difference(spec.stop_conditions),
        });
    }
    if !spec
        .rejected_shortcuts
        .contains_all(RejectedShortcutSet::BASELINE)
    {
        return Err(PlanRefusal::MissingRejectedShortcuts {
            missing: RejectedShortcutSet::BASELINE.difference(spec.rejected_shortcuts),
        });
    }
    Ok(())
}

fn collect_context_packets(
    run_receipt: &crate::AuthorityReadReceipt,
    packets: &[ContextPacket],
) -> Result<Vec<ContextPacketId>, PlanRefusal> {
    check_len("input_context_packets", packets.len(), MAX_PLAN_ENTRIES)?;
    let mut ids = Vec::with_capacity(packets.len());
    for packet in packets {
        if packet.authority_read_receipt() != run_receipt {
            return Err(PlanRefusal::ContextAuthorityMismatch {
                packet_id: packet.packet_id(),
            });
        }
        ids.push(packet.packet_id());
    }
    ids.sort_unstable();
    for adjacent in ids.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(PlanRefusal::DuplicateContextPacket {
                packet_id: adjacent[0],
            });
        }
    }
    Ok(ids)
}

fn canonicalize_digests(
    field: &'static str,
    values: &mut Vec<Digest>,
) -> Result<(), PlanRefusal> {
    check_len(field, values.len(), MAX_PLAN_ENTRIES)?;
    values.sort_unstable();
    for adjacent in values.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(PlanRefusal::DuplicateDigest {
                field,
                digest: adjacent[0],
            });
        }
    }
    Ok(())
}

fn canonicalize_surfaces(
    intended: &mut Vec<PlanSurface>,
    conflict: &mut Vec<PlanSurface>,
) -> Result<(), PlanRefusal> {
    if intended.is_empty() {
        return Err(PlanRefusal::EmptyIntendedChangeSurface);
    }
    canonicalize_surface_set("intended_change_surface", intended)?;
    canonicalize_surface_set("conflict_surface", conflict)?;
    for surface in intended.iter() {
        if conflict.binary_search(surface).is_err() {
            return Err(PlanRefusal::ConflictSurfaceIncomplete { missing: *surface });
        }
    }
    Ok(())
}

fn canonicalize_surface_set(
    field: &'static str,
    values: &mut Vec<PlanSurface>,
) -> Result<(), PlanRefusal> {
    check_len(field, values.len(), MAX_PLAN_ENTRIES)?;
    values.sort_unstable();
    for adjacent in values.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(PlanRefusal::DuplicateSurface {
                field,
                surface: adjacent[0],
            });
        }
    }
    Ok(())
}

fn validate_checkpoints(
    action: WorkAction,
    checkpoints: &[PlanCheckpoint],
) -> Result<(), PlanRefusal> {
    if checkpoints.is_empty() {
        return Err(PlanRefusal::EmptyCheckpointPlan);
    }
    check_len("checkpoints", checkpoints.len(), MAX_PLAN_CHECKPOINTS)?;
    let mut ids = Vec::with_capacity(checkpoints.len());
    let mut action_checkpoint = false;
    for checkpoint in checkpoints {
        if checkpoint.checkpoint_id.is_zero() {
            return Err(PlanRefusal::ZeroCheckpointId);
        }
        ids.push(checkpoint.checkpoint_id);
        action_checkpoint |= matches!(
            (action, checkpoint.purpose),
            (WorkAction::Implement, PlanCheckpointPurpose::ImplementSlice)
                | (WorkAction::Rework, PlanCheckpointPurpose::RepairSlice)
                | (WorkAction::Verify, PlanCheckpointPurpose::VerifySlice)
        );
    }
    ids.sort_unstable();
    for adjacent in ids.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(PlanRefusal::DuplicateCheckpointId {
                checkpoint_id: adjacent[0],
            });
        }
    }
    if !action_checkpoint {
        return Err(PlanRefusal::MissingActionCheckpoint { action });
    }
    Ok(())
}

fn canonicalize_evidence(
    action: WorkAction,
    evidence: &mut Vec<PlanEvidenceRequirement>,
) -> Result<(), PlanRefusal> {
    if evidence.is_empty() {
        return Err(PlanRefusal::EmptyEvidencePlan);
    }
    check_len("evidence_plan", evidence.len(), MAX_PLAN_ENTRIES)?;
    evidence.sort_unstable_by_key(|requirement| requirement.requirement_id);
    let mut independent = false;
    for requirement in evidence.iter() {
        if requirement.requirement_id.is_zero() {
            return Err(PlanRefusal::ZeroRequirementId);
        }
        if !requirement.evidence_class.supports_a_claim() {
            return Err(PlanRefusal::UnsupportedEvidenceClass {
                class: requirement.evidence_class,
            });
        }
        independent |= requirement.requires_independent_verifier;
    }
    for adjacent in evidence.windows(2) {
        if adjacent[0].requirement_id == adjacent[1].requirement_id {
            return Err(PlanRefusal::DuplicateRequirementId {
                requirement_id: adjacent[0].requirement_id,
            });
        }
    }
    if action == WorkAction::Verify && !independent {
        return Err(PlanRefusal::VerificationIndependenceMissing);
    }
    Ok(())
}

fn check_len(field: &'static str, observed: usize, limit: usize) -> Result<(), PlanRefusal> {
    if observed > limit {
        return Err(PlanRefusal::TooManyEntries {
            field,
            observed,
            limit,
        });
    }
    Ok(())
}

fn plan_commitment(plan: &AgentChangePlan) -> Result<[u8; 32], PlanRefusal> {
    let mut encoder = Encoder::with_capacity(1_088);
    encoder.write_bytes("agent_change_plan_domain", PLAN_DOMAIN)?;
    encoder.write_raw(&plan.pulse_id);
    encoder.write_raw(&plan.situation_id);
    encoder.write_raw(plan.frontier_id.as_bytes());
    encoder.write_raw(&plan.intent_run_id.value().to_be_bytes());
    encoder.write_raw(plan.intent_run_commitment.as_bytes());
    encoder.write_raw(plan.task_id.as_bytes());
    encoder.write_raw_byte(task_phase_code(plan.task_phase));
    encoder.write_raw_byte(work_action_code(plan.action));
    encoder.write_digest(&plan.acceptance_contract_root)?;

    write_digests(&mut encoder, "owning_invariants", &plan.owning_invariants)?;
    write_context_ids(&mut encoder, &plan.input_context_packets)?;
    write_surfaces(
        &mut encoder,
        "intended_change_surface",
        &plan.intended_change_surface,
    )?;
    write_surfaces(&mut encoder, "conflict_surface", &plan.conflict_surface)?;
    write_checkpoints(&mut encoder, &plan.checkpoints)?;
    write_evidence(&mut encoder, &plan.evidence_plan)?;
    encoder.write_scalar(plan.effect_plan.bits());
    for (_grade, amount) in plan.resource_budget.pairs() {
        encoder.write_scalar(amount);
    }
    encoder.write_scalar(plan.stop_conditions.bits());
    encoder.write_scalar(plan.rejected_shortcuts.bits());
    write_digests(&mut encoder, "non_claims", &plan.non_claims)?;
    encoder.write_raw_byte(plan.approval.code_point());
    encoder.write_digest(&plan.approval.root())?;

    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn write_digests(
    encoder: &mut Encoder,
    field: &'static str,
    values: &[Digest],
) -> Result<(), PlanRefusal> {
    write_count(encoder, field, values.len())?;
    for value in values {
        encoder.write_digest(value)?;
    }
    Ok(())
}

fn write_context_ids(
    encoder: &mut Encoder,
    values: &[ContextPacketId],
) -> Result<(), PlanRefusal> {
    write_count(encoder, "input_context_packets", values.len())?;
    for value in values {
        encoder.write_raw(value.as_bytes());
    }
    Ok(())
}

fn write_surfaces(
    encoder: &mut Encoder,
    field: &'static str,
    values: &[PlanSurface],
) -> Result<(), PlanRefusal> {
    write_count(encoder, field, values.len())?;
    for value in values {
        encoder.write_raw_byte(value.kind.code_point());
        encoder.write_digest(&value.selector)?;
    }
    Ok(())
}

fn write_checkpoints(
    encoder: &mut Encoder,
    values: &[PlanCheckpoint],
) -> Result<(), PlanRefusal> {
    write_count(encoder, "checkpoints", values.len())?;
    for value in values {
        encoder.write_raw(value.checkpoint_id.as_bytes());
        encoder.write_raw_byte(value.purpose.code_point());
        encoder.write_digest(&value.acceptance_slice_root)?;
        encoder.write_digest(&value.evidence_slice_root)?;
    }
    Ok(())
}

fn write_evidence(
    encoder: &mut Encoder,
    values: &[PlanEvidenceRequirement],
) -> Result<(), PlanRefusal> {
    write_count(encoder, "evidence_plan", values.len())?;
    for value in values {
        encoder.write_raw(value.requirement_id.as_bytes());
        encoder.write_scalar(value.evidence_class.code_point());
        encoder.write_digest(&value.artifact_contract)?;
        encoder.write_bool(value.requires_independent_verifier);
    }
    Ok(())
}

fn write_count(
    encoder: &mut Encoder,
    field: &'static str,
    count: usize,
) -> Result<(), PlanRefusal> {
    let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(count).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    Ok(())
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
