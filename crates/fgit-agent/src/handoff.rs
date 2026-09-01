//! Debt-preserving Agent Control Plane handoff capsules.
//!
//! A handoff is not a prose summary and not a capability grant. It is an inert,
//! deterministic commitment that binds the source run, current plan, activated
//! task claim, latest situation, workspace identity, requirement/evidence
//! state, unresolved work, proposed receiver attenuation, and the complete
//! [`crate::RunReconciliationReport`].
//!
//! The reconciliation report is embedded rather than reduced to a count. This
//! is load-bearing: a reservation, committed-but-unacknowledged effect,
//! escalation, or leak must survive a handoff with its exact effect record and
//! typed required action. A receiver still has to refresh authority and obtain
//! an ordinary child run/capability before acting; this capsule authorizes
//! nothing by itself.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_resource::{ResourceError, ResourceVector};
use fgit_treefs::WorkspaceId;
use fgit_types::Digest;

use crate::{
    ActiveTaskClaim, ActiveTaskClaimId, AgentChangePlan, AgentChangePlanId, AgentInstanceId,
    AgentSituationReceipt, ClassSet, EffectId, EffectResolutionAction, EvidenceRecordRef,
    IntentRun, LogicalTime, OperationClass, ReconciledEffect, RequirementDisposition,
    RunId, RunReconciliationReadiness, RunReconciliationReport, SituationId, VerifierAttestation,
};

/// Maximum entries accepted by any general handoff collection.
pub const MAX_HANDOFF_ENTRIES: usize = 512;
/// Maximum evidence records retained in one handoff.
pub const MAX_HANDOFF_EVIDENCE_RECORDS: usize = 2_048;
/// Maximum verifier attestations retained in one handoff.
pub const MAX_HANDOFF_VERIFIER_ATTESTATIONS: usize = 512;
const HANDOFF_DOMAIN: &[u8] = b"frankengit.agent.handoff-capsule/v1\0";

/// Stable SHA-256 identity of one complete handoff capsule.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentHandoffCapsuleId([u8; 32]);

impl AgentHandoffCapsuleId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AgentHandoffCapsuleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("handoff:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Workspace identity retained by a handoff without copying its tree body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffWorkspaceSnapshot {
    workspace_id: WorkspaceId,
    manifest_commitment: [u8; 32],
}

impl HandoffWorkspaceSnapshot {
    fn from_situation(situation: &AgentSituationReceipt) -> Option<Self> {
        situation.workspace().map(|workspace| Self {
            workspace_id: workspace.workspace_id(),
            manifest_commitment: workspace.manifest_commitment(),
        })
    }

    /// Workspace identity.
    #[must_use]
    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    /// Commitment to the exact workspace manifest.
    #[must_use]
    pub const fn manifest_commitment(self) -> [u8; 32] {
        self.manifest_commitment
    }
}

/// Maximum machine scope the receiver may be granted for this handoff.
///
/// This is a proposed attenuation only. It does not mint a capability or a
/// child run; the ordinary issuer and verifier remain responsible for that.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffCapabilityAttenuation {
    operations: ClassSet,
    resource_budget: ResourceVector,
    expiry: LogicalTime,
}

impl HandoffCapabilityAttenuation {
    /// Creates one proposed receiver scope.
    #[must_use]
    pub const fn new(
        operations: ClassSet,
        resource_budget: ResourceVector,
        expiry: LogicalTime,
    ) -> Self {
        Self {
            operations,
            resource_budget,
            expiry,
        }
    }

    /// Maximum operation classes the receiver may receive.
    #[must_use]
    pub const fn operations(self) -> ClassSet {
        self.operations
    }

    /// Maximum resource budget the receiver may receive.
    #[must_use]
    pub const fn resource_budget(self) -> ResourceVector {
        self.resource_budget
    }

    /// Exclusive expiry of the proposed receiver scope.
    #[must_use]
    pub const fn expiry(self) -> LogicalTime {
        self.expiry
    }
}

/// Bounded caller-supplied handoff material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentHandoffCapsuleSpec {
    source_instance_id: AgentInstanceId,
    target_selector: [u8; 32],
    changed_object_roots: Vec<Digest>,
    requirement_dispositions: Vec<Option<RequirementDisposition>>,
    evidence_records: Vec<EvidenceRecordRef>,
    verifier_attestations: Vec<VerifierAttestation>,
    unresolved_questions: Vec<Digest>,
    failed_approaches: Vec<Digest>,
    requested_next_actions: Vec<Digest>,
    capability_attenuation: HandoffCapabilityAttenuation,
    producer_attestation_root: Digest,
}

impl AgentHandoffCapsuleSpec {
    /// Creates the required handoff frame; optional collections start empty.
    #[must_use]
    pub const fn new(
        source_instance_id: AgentInstanceId,
        target_selector: [u8; 32],
        capability_attenuation: HandoffCapabilityAttenuation,
        producer_attestation_root: Digest,
    ) -> Self {
        Self {
            source_instance_id,
            target_selector,
            changed_object_roots: Vec::new(),
            requirement_dispositions: Vec::new(),
            evidence_records: Vec::new(),
            verifier_attestations: Vec::new(),
            unresolved_questions: Vec::new(),
            failed_approaches: Vec::new(),
            requested_next_actions: Vec::new(),
            capability_attenuation,
            producer_attestation_root,
        }
    }

    /// Sets changed immutable object roots.
    #[must_use]
    pub fn with_changed_object_roots(mut self, roots: Vec<Digest>) -> Self {
        self.changed_object_roots = roots;
        self
    }

    /// Sets requirement dispositions, evidence records, and verifier facts.
    #[must_use]
    pub fn with_evidence(
        mut self,
        dispositions: Vec<Option<RequirementDisposition>>,
        evidence_records: Vec<EvidenceRecordRef>,
        verifier_attestations: Vec<VerifierAttestation>,
    ) -> Self {
        self.requirement_dispositions = dispositions;
        self.evidence_records = evidence_records;
        self.verifier_attestations = verifier_attestations;
        self
    }

    /// Sets unresolved questions and failed approaches.
    #[must_use]
    pub fn with_unresolved_work(
        mut self,
        unresolved_questions: Vec<Digest>,
        failed_approaches: Vec<Digest>,
    ) -> Self {
        self.unresolved_questions = unresolved_questions;
        self.failed_approaches = failed_approaches;
        self
    }

    /// Sets requested next-action commitments.
    #[must_use]
    pub fn with_requested_next_actions(mut self, actions: Vec<Digest>) -> Self {
        self.requested_next_actions = actions;
        self
    }
}

/// Complete, deterministic capsule handed from one agent instance to another.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentHandoffCapsule {
    capsule_id: AgentHandoffCapsuleId,
    source_run_id: RunId,
    source_instance_id: AgentInstanceId,
    target_selector: [u8; 32],
    latest_situation_id: SituationId,
    plan_id: AgentChangePlanId,
    active_claim_id: ActiveTaskClaimId,
    workspace: Option<HandoffWorkspaceSnapshot>,
    changed_object_roots: Vec<Digest>,
    requirement_dispositions: Vec<RequirementDisposition>,
    evidence_records: Vec<EvidenceRecordRef>,
    verifier_attestations: Vec<VerifierAttestation>,
    unresolved_questions: Vec<Digest>,
    failed_approaches: Vec<Digest>,
    reconciliation: RunReconciliationReport,
    requested_next_actions: Vec<Digest>,
    capability_attenuation: HandoffCapabilityAttenuation,
    non_claims: Vec<Digest>,
    producer_attestation_root: Digest,
}

impl AgentHandoffCapsule {
    /// Builds one handoff from exact live control-plane objects.
    ///
    /// # Errors
    ///
    /// Refuses run/plan/claim substitution, authority or observation mismatch,
    /// stale/expired source state, an empty or widened receiver scope, a scope
    /// unable to resolve carried effect debt, missing/duplicate requirement or
    /// evidence material, unbounded collections, duplicate digest entries,
    /// reserved all-zero target identity, and unrepresentable canonical
    /// framing.
    pub fn build(
        latest_situation: &AgentSituationReceipt,
        plan: &AgentChangePlan,
        active_claim: ActiveTaskClaim,
        run: &IntentRun,
        reconciliation: RunReconciliationReport,
        mut spec: AgentHandoffCapsuleSpec,
    ) -> Result<Self, HandoffRefusal> {
        validate_control_basis(
            latest_situation,
            plan,
            active_claim,
            run,
            &reconciliation,
        )?;
        validate_attenuation(
            latest_situation,
            active_claim,
            run,
            &reconciliation,
            spec.capability_attenuation,
        )?;
        if is_zero(&spec.target_selector) {
            return Err(HandoffRefusal::ZeroTargetSelector);
        }

        canonicalize_digests(
            "changed_object_roots",
            &mut spec.changed_object_roots,
            MAX_HANDOFF_ENTRIES,
        )?;
        canonicalize_digests(
            "unresolved_questions",
            &mut spec.unresolved_questions,
            MAX_HANDOFF_ENTRIES,
        )?;
        canonicalize_digests(
            "failed_approaches",
            &mut spec.failed_approaches,
            MAX_HANDOFF_ENTRIES,
        )?;
        canonicalize_digests(
            "requested_next_actions",
            &mut spec.requested_next_actions,
            MAX_HANDOFF_ENTRIES,
        )?;

        let requirement_dispositions = validate_dispositions(
            plan,
            spec.requirement_dispositions,
            spec.evidence_records.is_empty(),
        )?;
        canonicalize_evidence(&mut spec.evidence_records)?;
        canonicalize_verifiers(&mut spec.verifier_attestations)?;

        let mut capsule = Self {
            capsule_id: AgentHandoffCapsuleId([0; 32]),
            source_run_id: run.run_id(),
            source_instance_id: spec.source_instance_id,
            target_selector: spec.target_selector,
            latest_situation_id: latest_situation.situation_id(),
            plan_id: plan.plan_id(),
            active_claim_id: active_claim.activation_id(),
            workspace: HandoffWorkspaceSnapshot::from_situation(latest_situation),
            changed_object_roots: spec.changed_object_roots,
            requirement_dispositions,
            evidence_records: spec.evidence_records,
            verifier_attestations: spec.verifier_attestations,
            unresolved_questions: spec.unresolved_questions,
            failed_approaches: spec.failed_approaches,
            reconciliation,
            requested_next_actions: spec.requested_next_actions,
            capability_attenuation: spec.capability_attenuation,
            non_claims: plan.non_claims().to_vec(),
            producer_attestation_root: spec.producer_attestation_root,
        };
        capsule.capsule_id = AgentHandoffCapsuleId(capsule_commitment(&capsule)?);
        Ok(capsule)
    }

    /// Stable capsule identity.
    #[must_use]
    pub const fn capsule_id(&self) -> AgentHandoffCapsuleId {
        self.capsule_id
    }

    /// Source Intent Run.
    #[must_use]
    pub const fn source_run_id(&self) -> RunId {
        self.source_run_id
    }

    /// Source agent executor.
    #[must_use]
    pub const fn source_instance_id(&self) -> AgentInstanceId {
        self.source_instance_id
    }

    /// Opaque, policy-defined receiver selector.
    #[must_use]
    pub const fn target_selector(&self) -> &[u8; 32] {
        &self.target_selector
    }

    /// Latest situation observed before handoff.
    #[must_use]
    pub const fn latest_situation_id(&self) -> SituationId {
        self.latest_situation_id
    }

    /// Current change plan.
    #[must_use]
    pub const fn plan_id(&self) -> AgentChangePlanId {
        self.plan_id
    }

    /// Activated task claim that permits the current plan attempt.
    #[must_use]
    pub const fn active_claim_id(&self) -> ActiveTaskClaimId {
        self.active_claim_id
    }

    /// Workspace identity and manifest, when one is attached.
    #[must_use]
    pub const fn workspace(&self) -> Option<HandoffWorkspaceSnapshot> {
        self.workspace
    }

    /// Changed immutable object roots.
    #[must_use]
    pub fn changed_object_roots(&self) -> &[Digest] {
        &self.changed_object_roots
    }

    /// Complete positional requirement dispositions.
    #[must_use]
    pub fn requirement_dispositions(&self) -> &[RequirementDisposition] {
        &self.requirement_dispositions
    }

    /// Evidence references retained by the capsule.
    #[must_use]
    pub fn evidence_records(&self) -> &[EvidenceRecordRef] {
        &self.evidence_records
    }

    /// Verifier facts retained for independent classification.
    #[must_use]
    pub fn verifier_attestations(&self) -> &[VerifierAttestation] {
        &self.verifier_attestations
    }

    /// Unresolved question commitments.
    #[must_use]
    pub fn unresolved_questions(&self) -> &[Digest] {
        &self.unresolved_questions
    }

    /// Failed-approach commitments.
    #[must_use]
    pub fn failed_approaches(&self) -> &[Digest] {
        &self.failed_approaches
    }

    /// Complete run-level reconciliation report.
    #[must_use]
    pub const fn reconciliation(&self) -> &RunReconciliationReport {
        &self.reconciliation
    }

    /// Outstanding effects, preserving complete records and typed next actions.
    pub fn outstanding_effects(&self) -> impl Iterator<Item = &ReconciledEffect> {
        self.reconciliation.effects().iter().filter(|effect| {
            effect.required_action() != EffectResolutionAction::NoFurtherAction
        })
    }

    /// Number of outstanding effects or containment failures.
    #[must_use]
    pub const fn outstanding_effect_count(&self) -> u32 {
        self.reconciliation.counts().unsettled()
    }

    /// Highest-priority reconciliation action still required.
    #[must_use]
    pub const fn reconciliation_readiness(&self) -> RunReconciliationReadiness {
        self.reconciliation.readiness()
    }

    /// Requested next-action commitments.
    #[must_use]
    pub fn requested_next_actions(&self) -> &[Digest] {
        &self.requested_next_actions
    }

    /// Maximum receiver scope proposed by the source.
    #[must_use]
    pub const fn capability_attenuation(&self) -> HandoffCapabilityAttenuation {
        self.capability_attenuation
    }

    /// Resource consumption carried from the complete run effect inventory.
    #[must_use]
    pub const fn budget_consumed(&self) -> ResourceVector {
        self.reconciliation.cumulative_budget_consumed()
    }

    /// Explicit non-claims inherited from the plan.
    #[must_use]
    pub fn non_claims(&self) -> &[Digest] {
        &self.non_claims
    }

    /// Commitment to producer attestation evidence.
    #[must_use]
    pub const fn producer_attestation_root(&self) -> Digest {
        self.producer_attestation_root
    }
}

/// Why handoff capsule construction failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoffRefusal {
    /// Situation names another active run.
    SituationRunMismatch,
    /// Run lacks a complete authenticated authority receipt.
    RunAuthorityReceiptRequired,
    /// Situation and run use different authority positions.
    RunAuthorityMismatch,
    /// Plan names another run.
    PlanRunMismatch {
        /// Plan run.
        expected: RunId,
        /// Supplied run.
        observed: RunId,
    },
    /// Active claim names another plan.
    ClaimPlanMismatch,
    /// Active claim names another task.
    ClaimTaskMismatch,
    /// Active claim names another assignee.
    ClaimRunMismatch,
    /// Active claim is expired at the latest situation.
    ClaimExpired {
        /// Exclusive expiry.
        expires_at: LogicalTime,
        /// Latest observation.
        observed_at: LogicalTime,
    },
    /// Source run is expired at the latest situation.
    RunExpired {
        /// Exclusive expiry.
        expires_at: LogicalTime,
        /// Latest observation.
        observed_at: LogicalTime,
    },
    /// Reconciliation report belongs to another run.
    ReconciliationRunMismatch,
    /// Reconciliation report belongs to another authority position.
    ReconciliationAuthorityMismatch,
    /// Reconciliation and situation were not assembled at the same instant.
    ReconciliationObservationMismatch {
        /// Situation observation.
        situation: LogicalTime,
        /// Report observation.
        reconciliation: LogicalTime,
    },
    /// Report says the run was not open at the handoff instant.
    ReconciliationRunNotOpen,
    /// Receiver operation scope is empty.
    EmptyCapabilityAttenuation,
    /// Receiver operation scope exceeds the source run.
    CapabilityOperationAmplification {
        /// Operation classes absent from the source run.
        missing: ClassSet,
    },
    /// Receiver resource budget is zero.
    EmptyCapabilityBudget,
    /// Receiver resource budget exceeds the source run.
    CapabilityBudgetAmplification {
        /// First deficient grade.
        deficit: ResourceError,
    },
    /// Receiver scope has already expired or expires at the handoff instant.
    CapabilityAlreadyExpired {
        /// Latest observation.
        observed_at: LogicalTime,
        /// Proposed expiry.
        expiry: LogicalTime,
    },
    /// Receiver scope outlives the source run.
    CapabilityOutlivesRun {
        /// Proposed expiry.
        expiry: LogicalTime,
        /// Source run expiry.
        run_expiry: LogicalTime,
    },
    /// Receiver scope outlives the source task claim.
    CapabilityOutlivesClaim {
        /// Proposed expiry.
        expiry: LogicalTime,
        /// Source claim expiry.
        claim_expiry: LogicalTime,
    },
    /// Receiver scope cannot resolve one carried effect.
    CapabilityCannotResolveEffect {
        /// Outstanding effect.
        effect_id: EffectId,
        /// Operation class needed to continue it.
        operation: OperationClass,
    },
    /// All-zero receiver selector is reserved.
    ZeroTargetSelector,
    /// One collection exceeded its hard ceiling.
    TooManyEntries {
        /// Collection name.
        field: &'static str,
        /// Entries supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// One unordered digest appeared twice.
    DuplicateDigest {
        /// Collection name.
        field: &'static str,
        /// Repeated digest.
        digest: Digest,
    },
    /// Handoff does not carry one disposition for every plan evidence line.
    RequirementDispositionCountMismatch {
        /// Plan evidence requirements.
        expected: usize,
        /// Dispositions supplied.
        observed: usize,
    },
    /// One requirement has no disposition.
    MissingRequirementDisposition {
        /// Zero-based plan evidence position.
        requirement: usize,
    },
    /// A satisfied/partially satisfied disposition carries no evidence record.
    SatisfiedWithoutEvidence,
    /// One evidence record appeared twice.
    DuplicateEvidenceRecord {
        /// Repeated artifact identity.
        artifact: u128,
    },
    /// One verifier attestation appeared twice.
    DuplicateVerifierAttestation {
        /// Repeated verifier identity.
        verifier: u128,
    },
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for HandoffRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SituationRunMismatch => {
                formatter.write_str("latest situation names another active run")
            }
            Self::RunAuthorityReceiptRequired => formatter.write_str(
                "handoff requires a run with a complete authenticated authority receipt",
            ),
            Self::RunAuthorityMismatch => {
                formatter.write_str("source run authority differs from the latest situation")
            }
            Self::PlanRunMismatch { expected, observed } => write!(
                formatter,
                "plan run {expected} differs from supplied run {observed}"
            ),
            Self::ClaimPlanMismatch => {
                formatter.write_str("active claim belongs to another plan")
            }
            Self::ClaimTaskMismatch => {
                formatter.write_str("active claim belongs to another task")
            }
            Self::ClaimRunMismatch => {
                formatter.write_str("active claim belongs to another run")
            }
            Self::ClaimExpired {
                expires_at,
                observed_at,
            } => write!(
                formatter,
                "active claim expired at {expires_at} before handoff observation {observed_at}"
            ),
            Self::RunExpired {
                expires_at,
                observed_at,
            } => write!(
                formatter,
                "source run expired at {expires_at} before handoff observation {observed_at}"
            ),
            Self::ReconciliationRunMismatch => {
                formatter.write_str("reconciliation report belongs to another run")
            }
            Self::ReconciliationAuthorityMismatch => formatter.write_str(
                "reconciliation report belongs to another authority position",
            ),
            Self::ReconciliationObservationMismatch {
                situation,
                reconciliation,
            } => write!(
                formatter,
                "situation observed at {situation}, reconciliation at {reconciliation}"
            ),
            Self::ReconciliationRunNotOpen => formatter
                .write_str("reconciliation report says the source run was not open"),
            Self::EmptyCapabilityAttenuation => {
                formatter.write_str("handoff receiver scope authorizes no operations")
            }
            Self::CapabilityOperationAmplification { missing } => write!(
                formatter,
                "handoff receiver scope adds operation classes {missing}"
            ),
            Self::EmptyCapabilityBudget => {
                formatter.write_str("handoff receiver scope declares a zero resource budget")
            }
            Self::CapabilityBudgetAmplification { deficit } => write!(
                formatter,
                "handoff receiver budget exceeds the source run: {deficit}"
            ),
            Self::CapabilityAlreadyExpired {
                observed_at,
                expiry,
            } => write!(
                formatter,
                "handoff scope expires at {expiry}, not after observation {observed_at}"
            ),
            Self::CapabilityOutlivesRun { expiry, run_expiry } => write!(
                formatter,
                "handoff scope expires at {expiry} after source run {run_expiry}"
            ),
            Self::CapabilityOutlivesClaim {
                expiry,
                claim_expiry,
            } => write!(
                formatter,
                "handoff scope expires at {expiry} after source claim {claim_expiry}"
            ),
            Self::CapabilityCannotResolveEffect {
                effect_id,
                operation,
            } => write!(
                formatter,
                "handoff scope lacks {operation} needed by outstanding {effect_id}"
            ),
            Self::ZeroTargetSelector => {
                formatter.write_str("handoff target selector may not be all zero")
            }
            Self::TooManyEntries {
                field,
                observed,
                limit,
            } => write!(formatter, "{field} has {observed} entries, limit {limit}"),
            Self::DuplicateDigest { field, digest } => {
                write!(formatter, "{field} repeats digest {digest}")
            }
            Self::RequirementDispositionCountMismatch { expected, observed } => write!(
                formatter,
                "handoff has {observed} requirement dispositions, expected {expected}"
            ),
            Self::MissingRequirementDisposition { requirement } => write!(
                formatter,
                "handoff requirement {requirement} has no disposition"
            ),
            Self::SatisfiedWithoutEvidence => formatter.write_str(
                "handoff claims a satisfied requirement but carries no evidence record",
            ),
            Self::DuplicateEvidenceRecord { artifact } => write!(
                formatter,
                "handoff repeats evidence artifact {artifact:032x}"
            ),
            Self::DuplicateVerifierAttestation { verifier } => write!(
                formatter,
                "handoff repeats verifier attestation {verifier:032x}"
            ),
            Self::Codec(refusal) => {
                write!(formatter, "handoff capsule framing refused: {refusal}")
            }
        }
    }
}

impl core::error::Error for HandoffRefusal {}

impl From<CodecRefusal> for HandoffRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_control_basis(
    latest_situation: &AgentSituationReceipt,
    plan: &AgentChangePlan,
    active_claim: ActiveTaskClaim,
    run: &IntentRun,
    reconciliation: &RunReconciliationReport,
) -> Result<(), HandoffRefusal> {
    if latest_situation.intent_run_id() != Some(run.run_id()) {
        return Err(HandoffRefusal::SituationRunMismatch);
    }
    let run_authority = run
        .authority_read_receipt()
        .ok_or(HandoffRefusal::RunAuthorityReceiptRequired)?;
    if run_authority != latest_situation.authority_read_receipt() {
        return Err(HandoffRefusal::RunAuthorityMismatch);
    }
    if plan.intent_run_id() != run.run_id() {
        return Err(HandoffRefusal::PlanRunMismatch {
            expected: plan.intent_run_id(),
            observed: run.run_id(),
        });
    }
    if active_claim.plan_id() != plan.plan_id() {
        return Err(HandoffRefusal::ClaimPlanMismatch);
    }
    if active_claim.task_id() != plan.task_id() {
        return Err(HandoffRefusal::ClaimTaskMismatch);
    }
    if active_claim.assignee() != run.run_id() {
        return Err(HandoffRefusal::ClaimRunMismatch);
    }
    if !active_claim.is_live_at(latest_situation.observed_at()) {
        return Err(HandoffRefusal::ClaimExpired {
            expires_at: active_claim.expires_at(),
            observed_at: latest_situation.observed_at(),
        });
    }
    if !run.is_open_at(latest_situation.observed_at()) {
        return Err(HandoffRefusal::RunExpired {
            expires_at: run.expiry(),
            observed_at: latest_situation.observed_at(),
        });
    }
    if reconciliation.run_id() != run.run_id() {
        return Err(HandoffRefusal::ReconciliationRunMismatch);
    }
    if reconciliation.authority_read_receipt() != run_authority {
        return Err(HandoffRefusal::ReconciliationAuthorityMismatch);
    }
    if reconciliation.observed_at() != latest_situation.observed_at() {
        return Err(HandoffRefusal::ReconciliationObservationMismatch {
            situation: latest_situation.observed_at(),
            reconciliation: reconciliation.observed_at(),
        });
    }
    if !reconciliation.run_open_at_observation() {
        return Err(HandoffRefusal::ReconciliationRunNotOpen);
    }
    Ok(())
}

fn validate_attenuation(
    latest_situation: &AgentSituationReceipt,
    active_claim: ActiveTaskClaim,
    run: &IntentRun,
    reconciliation: &RunReconciliationReport,
    attenuation: HandoffCapabilityAttenuation,
) -> Result<(), HandoffRefusal> {
    if attenuation.operations.is_empty() {
        return Err(HandoffRefusal::EmptyCapabilityAttenuation);
    }
    if !attenuation
        .operations
        .is_subset_of(run.allowed_operation_classes())
    {
        return Err(HandoffRefusal::CapabilityOperationAmplification {
            missing: attenuation
                .operations
                .difference(run.allowed_operation_classes()),
        });
    }
    if attenuation.resource_budget.is_zero() {
        return Err(HandoffRefusal::EmptyCapabilityBudget);
    }
    if let Some(deficit) = run
        .resource_budget()
        .first_deficit(&attenuation.resource_budget)
    {
        return Err(HandoffRefusal::CapabilityBudgetAmplification { deficit });
    }
    if attenuation.expiry.value() <= latest_situation.observed_at().value() {
        return Err(HandoffRefusal::CapabilityAlreadyExpired {
            observed_at: latest_situation.observed_at(),
            expiry: attenuation.expiry,
        });
    }
    if attenuation.expiry.value() > run.expiry().value() {
        return Err(HandoffRefusal::CapabilityOutlivesRun {
            expiry: attenuation.expiry,
            run_expiry: run.expiry(),
        });
    }
    if attenuation.expiry.value() > active_claim.expires_at().value() {
        return Err(HandoffRefusal::CapabilityOutlivesClaim {
            expiry: attenuation.expiry,
            claim_expiry: active_claim.expires_at(),
        });
    }
    for effect in reconciliation.effects() {
        if effect.required_action() != EffectResolutionAction::NoFurtherAction
            && !attenuation.operations.contains(effect.record().operation)
        {
            return Err(HandoffRefusal::CapabilityCannotResolveEffect {
                effect_id: effect.record().effect_id,
                operation: effect.record().operation,
            });
        }
    }
    Ok(())
}

fn validate_dispositions(
    plan: &AgentChangePlan,
    dispositions: Vec<Option<RequirementDisposition>>,
    evidence_is_empty: bool,
) -> Result<Vec<RequirementDisposition>, HandoffRefusal> {
    if dispositions.len() > MAX_HANDOFF_ENTRIES {
        return Err(HandoffRefusal::TooManyEntries {
            field: "requirement_dispositions",
            observed: dispositions.len(),
            limit: MAX_HANDOFF_ENTRIES,
        });
    }
    if dispositions.len() != plan.evidence_plan().len() {
        return Err(HandoffRefusal::RequirementDispositionCountMismatch {
            expected: plan.evidence_plan().len(),
            observed: dispositions.len(),
        });
    }
    let mut complete = Vec::with_capacity(dispositions.len());
    for (requirement, disposition) in dispositions.into_iter().enumerate() {
        let disposition = disposition.ok_or(HandoffRefusal::MissingRequirementDisposition {
            requirement,
        })?;
        complete.push(disposition);
    }
    if evidence_is_empty
        && complete.iter().any(|disposition| {
            matches!(
                disposition,
                RequirementDisposition::SatisfiedWithEvidence
                    | RequirementDisposition::PartiallySatisfied
            )
        })
    {
        return Err(HandoffRefusal::SatisfiedWithoutEvidence);
    }
    Ok(complete)
}

fn canonicalize_evidence(records: &mut Vec<EvidenceRecordRef>) -> Result<(), HandoffRefusal> {
    if records.len() > MAX_HANDOFF_EVIDENCE_RECORDS {
        return Err(HandoffRefusal::TooManyEntries {
            field: "evidence_records",
            observed: records.len(),
            limit: MAX_HANDOFF_EVIDENCE_RECORDS,
        });
    }
    records.sort_unstable_by_key(|record| {
        (
            record.class.code_point(),
            record.artifact,
            record.refresh_side.map_or(0, refresh_side_code),
        )
    });
    for adjacent in records.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(HandoffRefusal::DuplicateEvidenceRecord {
                artifact: adjacent[0].artifact,
            });
        }
    }
    Ok(())
}

fn canonicalize_verifiers(
    attestations: &mut Vec<VerifierAttestation>,
) -> Result<(), HandoffRefusal> {
    if attestations.len() > MAX_HANDOFF_VERIFIER_ATTESTATIONS {
        return Err(HandoffRefusal::TooManyEntries {
            field: "verifier_attestations",
            observed: attestations.len(),
            limit: MAX_HANDOFF_VERIFIER_ATTESTATIONS,
        });
    }
    attestations.sort_unstable_by_key(verifier_sort_key);
    for adjacent in attestations.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(HandoffRefusal::DuplicateVerifierAttestation {
                verifier: adjacent[0].verifier,
            });
        }
    }
    Ok(())
}

fn verifier_sort_key(
    attestation: &VerifierAttestation,
) -> (
    u128,
    Option<u128>,
    Option<u128>,
    Option<u128>,
    Option<u128>,
    Option<u128>,
    Option<u128>,
    Option<u128>,
    bool,
) {
    (
        attestation.verifier,
        attestation.facts.workspace,
        attestation.facts.credentials,
        attestation.facts.model_harness,
        attestation.facts.context,
        attestation.facts.oracle,
        attestation.facts.sponsor,
        attestation.facts.human,
        attestation.upheld,
    )
}

fn canonicalize_digests(
    field: &'static str,
    values: &mut Vec<Digest>,
    limit: usize,
) -> Result<(), HandoffRefusal> {
    if values.len() > limit {
        return Err(HandoffRefusal::TooManyEntries {
            field,
            observed: values.len(),
            limit,
        });
    }
    values.sort_unstable();
    for adjacent in values.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(HandoffRefusal::DuplicateDigest {
                field,
                digest: adjacent[0],
            });
        }
    }
    Ok(())
}

fn capsule_commitment(capsule: &AgentHandoffCapsule) -> Result<[u8; 32], HandoffRefusal> {
    let mut encoder = Encoder::with_capacity(1_024);
    encoder.write_bytes("agent_handoff_capsule_domain", HANDOFF_DOMAIN)?;
    encoder.write_raw(&capsule.source_run_id.value().to_be_bytes());
    encoder.write_raw(&capsule.source_instance_id.value().to_be_bytes());
    encoder.write_raw(&capsule.target_selector);
    encoder.write_raw(capsule.latest_situation_id.as_bytes());
    encoder.write_raw(capsule.plan_id.as_bytes());
    encoder.write_raw(capsule.active_claim_id.as_bytes());
    match capsule.workspace {
        Some(workspace) => {
            encoder.write_bool(true);
            encoder.write_opaque_id(workspace.workspace_id.as_bytes());
            encoder.write_raw(&workspace.manifest_commitment);
        }
        None => encoder.write_bool(false),
    }
    write_digests(
        &mut encoder,
        "handoff.changed_object_roots",
        &capsule.changed_object_roots,
    )?;
    write_count(
        &mut encoder,
        "handoff.requirement_dispositions",
        capsule.requirement_dispositions.len(),
    )?;
    for disposition in &capsule.requirement_dispositions {
        encoder.write_scalar(disposition.code_point());
    }
    write_evidence(&mut encoder, &capsule.evidence_records)?;
    write_verifiers(&mut encoder, &capsule.verifier_attestations)?;
    write_digests(
        &mut encoder,
        "handoff.unresolved_questions",
        &capsule.unresolved_questions,
    )?;
    write_digests(
        &mut encoder,
        "handoff.failed_approaches",
        &capsule.failed_approaches,
    )?;
    encoder.write_raw(capsule.reconciliation.report_id().as_bytes());
    write_count(
        &mut encoder,
        "handoff.outstanding_effects",
        usize::try_from(capsule.outstanding_effect_count()).unwrap_or(usize::MAX),
    )?;
    for effect in capsule.outstanding_effects() {
        encoder.write_raw(&effect.record().effect_id.value().to_be_bytes());
        encoder.write_raw_byte(effect_action_code(effect.required_action()));
    }
    write_resource_vector(&mut encoder, capsule.budget_consumed());
    write_digests(
        &mut encoder,
        "handoff.requested_next_actions",
        &capsule.requested_next_actions,
    )?;
    encoder.write_scalar(capsule.capability_attenuation.operations.bits());
    write_resource_vector(
        &mut encoder,
        capsule.capability_attenuation.resource_budget,
    );
    encoder.write_scalar(capsule.capability_attenuation.expiry.value());
    write_digests(&mut encoder, "handoff.non_claims", &capsule.non_claims)?;
    encoder.write_digest(&capsule.producer_attestation_root)?;

    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn write_evidence(
    encoder: &mut Encoder,
    records: &[EvidenceRecordRef],
) -> Result<(), HandoffRefusal> {
    write_count(encoder, "handoff.evidence_records", records.len())?;
    for record in records {
        encoder.write_scalar(record.class.code_point());
        encoder.write_raw(&record.artifact.to_be_bytes());
        match record.refresh_side {
            Some(side) => {
                encoder.write_bool(true);
                encoder.write_raw_byte(refresh_side_code(side));
            }
            None => encoder.write_bool(false),
        }
    }
    Ok(())
}

fn write_verifiers(
    encoder: &mut Encoder,
    attestations: &[VerifierAttestation],
) -> Result<(), HandoffRefusal> {
    write_count(
        encoder,
        "handoff.verifier_attestations",
        attestations.len(),
    )?;
    for attestation in attestations {
        encoder.write_raw(&attestation.verifier.to_be_bytes());
        write_optional_u128(encoder, attestation.facts.workspace);
        write_optional_u128(encoder, attestation.facts.credentials);
        write_optional_u128(encoder, attestation.facts.model_harness);
        write_optional_u128(encoder, attestation.facts.context);
        write_optional_u128(encoder, attestation.facts.oracle);
        write_optional_u128(encoder, attestation.facts.sponsor);
        write_optional_u128(encoder, attestation.facts.human);
        encoder.write_bool(attestation.upheld);
    }
    Ok(())
}

fn write_optional_u128(encoder: &mut Encoder, value: Option<u128>) {
    match value {
        Some(value) => {
            encoder.write_bool(true);
            encoder.write_raw(&value.to_be_bytes());
        }
        None => encoder.write_bool(false),
    }
}

fn write_digests(
    encoder: &mut Encoder,
    field: &'static str,
    values: &[Digest],
) -> Result<(), HandoffRefusal> {
    write_count(encoder, field, values.len())?;
    for value in values {
        encoder.write_digest(value)?;
    }
    Ok(())
}

fn write_resource_vector(encoder: &mut Encoder, vector: ResourceVector) {
    for (_grade, amount) in vector.pairs() {
        encoder.write_scalar(amount);
    }
}

fn write_count(
    encoder: &mut Encoder,
    field: &'static str,
    count: usize,
) -> Result<(), HandoffRefusal> {
    let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(count).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    Ok(())
}

const fn refresh_side_code(side: crate::RefreshSide) -> u8 {
    match side {
        crate::RefreshSide::BeforeRefresh => 1,
        crate::RefreshSide::AfterRefresh => 2,
    }
}

const fn effect_action_code(action: EffectResolutionAction) -> u8 {
    match action {
        EffectResolutionAction::NoFurtherAction => 1,
        EffectResolutionAction::AbortReservation => 2,
        EffectResolutionAction::ReconcileCommittedEffect => 3,
        EffectResolutionAction::ResolveEscalation => 4,
        EffectResolutionAction::ContainLeak => 5,
    }
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
