//! Evidence-grounded, retrieval-only outcome learning.
//!
//! An [`OutcomeLearningRecord`] is not authority, policy, a task transition, or
//! proof that a repository mutation committed. It is an immutable retrieval
//! object derived from one exact [`crate::AgentActionPacket`], plan, situation,
//! and run. Future agents may use it to avoid repeated retrieval or failed
//! hypotheses only when its applicability and invalidation conditions still
//! match.
//!
//! The record admits no free-form self-assessment. Requirement results bind
//! typed dispositions to evidence and verifier identities; ownership findings
//! must stay inside the plan's intended surface; failed hypotheses retain their
//! discriminating evidence; resource observations are conserved under the plan
//! budget; and reusable patterns carry both applicability and invalidation
//! commitments. Statistical or model-derived advice never grants capability or
//! suppresses a mandatory gate.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_resource::{ResourceError, ResourceVector};
use fgit_types::Digest;

use crate::{
    AgentActionPacket, AgentActionPacketId, AgentChangePlan, AgentChangePlanId,
    AgentHandoffAcceptanceId, AgentSituationReceipt, EvidenceClass, EvidenceRecordRef,
    IndependenceClassification, IntentRun, LogicalTime, PartyFacts, PlanRequirementId, PlanSurface,
    RequirementDisposition, RunCancellationCompletionId, RunId, SituationId, VerifierAttestation,
    WorkTaskId, classify_independence,
};

/// Maximum entries accepted in one general learning collection.
pub const MAX_LEARNING_ENTRIES: usize = 512;
/// Maximum evidence rows retained under one requirement or hypothesis.
pub const MAX_LEARNING_EVIDENCE: usize = 2_048;
const LEARNING_DOMAIN: &[u8] = b"frankengit.agent.outcome-learning/v1\0";

/// Stable identity of one learning record.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutcomeLearningRecordId([u8; 32]);

impl OutcomeLearningRecordId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for OutcomeLearningRecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("outcome-learning:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Typed terminal interpretation retained by the learning record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LearningTerminalOutcome {
    /// The planned action completed with this result/evidence commitment.
    Completed {
        /// Result or completion evidence.
        result_root: Digest,
    },
    /// Execution stopped at a typed refusal.
    Refused {
        /// Refusal and discriminating-output commitment.
        refusal_root: Digest,
    },
    /// The owning Intent Run completed its cancellation protocol.
    Cancelled {
        /// Verified cancellation completion.
        completion_id: RunCancellationCompletionId,
    },
    /// Responsibility moved to an independently verified receiver.
    HandedOff {
        /// Receiver-side handoff acceptance.
        acceptance_id: AgentHandoffAcceptanceId,
    },
    /// Automation ended with explicit containment evidence.
    Contained {
        /// Containment report commitment.
        evidence_root: Digest,
    },
}

impl LearningTerminalOutcome {
    const fn code_point(self) -> u8 {
        match self {
            Self::Completed { .. } => 1,
            Self::Refused { .. } => 2,
            Self::Cancelled { .. } => 3,
            Self::HandedOff { .. } => 4,
            Self::Contained { .. } => 5,
        }
    }

    const fn is_completed(self) -> bool {
        matches!(self, Self::Completed { .. })
    }
}

/// One plan requirement's terminal disposition and supporting evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearningRequirementOutcome {
    requirement_id: PlanRequirementId,
    disposition: RequirementDisposition,
    evidence: Vec<EvidenceRecordRef>,
    verifier_ids: Vec<u128>,
    reason_root: Digest,
}

impl LearningRequirementOutcome {
    /// Creates one complete requirement result.
    #[must_use]
    pub const fn new(
        requirement_id: PlanRequirementId,
        disposition: RequirementDisposition,
        evidence: Vec<EvidenceRecordRef>,
        verifier_ids: Vec<u128>,
        reason_root: Digest,
    ) -> Self {
        Self {
            requirement_id,
            disposition,
            evidence,
            verifier_ids,
            reason_root,
        }
    }

    /// Plan requirement identity.
    #[must_use]
    pub const fn requirement_id(&self) -> PlanRequirementId {
        self.requirement_id
    }

    /// Terminal disposition.
    #[must_use]
    pub const fn disposition(&self) -> RequirementDisposition {
        self.disposition
    }

    /// Evidence supporting the disposition.
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceRecordRef] {
        &self.evidence
    }

    /// Verifiers explicitly associated with this requirement.
    #[must_use]
    pub fn verifier_ids(&self) -> &[u128] {
        &self.verifier_ids
    }

    /// Commitment to the reason or boundary of the disposition.
    #[must_use]
    pub const fn reason_root(&self) -> Digest {
        self.reason_root
    }
}

/// Evidence-backed conclusion about which declared surface owned the outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmedOwnership {
    surface: PlanSurface,
    evidence_root: Digest,
}

impl ConfirmedOwnership {
    /// Creates one ownership finding.
    #[must_use]
    pub const fn new(surface: PlanSurface, evidence_root: Digest) -> Self {
        Self {
            surface,
            evidence_root,
        }
    }

    /// Plan-contained surface.
    #[must_use]
    pub const fn surface(self) -> PlanSurface {
        self.surface
    }

    /// Evidence supporting the ownership finding.
    #[must_use]
    pub const fn evidence_root(self) -> Digest {
        self.evidence_root
    }
}

/// One hypothesis disproved or rendered non-discriminating by evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedHypothesis {
    hypothesis_root: Digest,
    discriminating_evidence: EvidenceRecordRef,
    applicability_root: Digest,
    invalidation_conditions: Vec<Digest>,
}

impl FailedHypothesis {
    /// Creates one negative-learning row.
    #[must_use]
    pub const fn new(
        hypothesis_root: Digest,
        discriminating_evidence: EvidenceRecordRef,
        applicability_root: Digest,
        invalidation_conditions: Vec<Digest>,
    ) -> Self {
        Self {
            hypothesis_root,
            discriminating_evidence,
            applicability_root,
            invalidation_conditions,
        }
    }

    /// Hypothesis identity.
    #[must_use]
    pub const fn hypothesis_root(&self) -> Digest {
        self.hypothesis_root
    }

    /// Evidence that discriminated against the hypothesis.
    #[must_use]
    pub const fn discriminating_evidence(&self) -> EvidenceRecordRef {
        self.discriminating_evidence
    }

    /// Applicability contract for reuse.
    #[must_use]
    pub const fn applicability_root(&self) -> Digest {
        self.applicability_root
    }

    /// Conditions that make the negative result stale.
    #[must_use]
    pub fn invalidation_conditions(&self) -> &[Digest] {
        &self.invalidation_conditions
    }
}

/// Phase whose measured resource cost is recorded.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LearningPhase {
    /// Situation observation or refresh.
    Observe,
    /// Context retrieval and assembly.
    Retrieve,
    /// Planning and conflict analysis.
    Plan,
    /// Effectful implementation work.
    Execute,
    /// Verification and evidence production.
    Verify,
    /// Reconciliation, handoff, cancellation, or containment.
    Reconcile,
}

impl LearningPhase {
    const fn code_point(self) -> u8 {
        match self {
            Self::Observe => 1,
            Self::Retrieve => 2,
            Self::Plan => 3,
            Self::Execute => 4,
            Self::Verify => 5,
            Self::Reconcile => 6,
        }
    }
}

/// One measured, evidence-bound resource observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LearningResourceObservation {
    observation_root: Digest,
    phase: LearningPhase,
    consumed: ResourceVector,
    evidence_root: Digest,
}

impl LearningResourceObservation {
    /// Creates one measured resource row.
    #[must_use]
    pub const fn new(
        observation_root: Digest,
        phase: LearningPhase,
        consumed: ResourceVector,
        evidence_root: Digest,
    ) -> Self {
        Self {
            observation_root,
            phase,
            consumed,
            evidence_root,
        }
    }

    /// Stable observation identity.
    #[must_use]
    pub const fn observation_root(self) -> Digest {
        self.observation_root
    }

    /// Measured phase.
    #[must_use]
    pub const fn phase(self) -> LearningPhase {
        self.phase
    }

    /// Measured resources.
    #[must_use]
    pub const fn consumed(self) -> ResourceVector {
        self.consumed
    }

    /// Measurement evidence.
    #[must_use]
    pub const fn evidence_root(self) -> Digest {
        self.evidence_root
    }
}

/// A reusable pattern with an explicit scope and expiry boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusablePattern {
    pattern_root: Digest,
    applicability_root: Digest,
    invalidation_conditions: Vec<Digest>,
    expected_savings: ResourceVector,
    evidence_root: Digest,
}

impl ReusablePattern {
    /// Creates one reusable pattern.
    #[must_use]
    pub const fn new(
        pattern_root: Digest,
        applicability_root: Digest,
        invalidation_conditions: Vec<Digest>,
        expected_savings: ResourceVector,
        evidence_root: Digest,
    ) -> Self {
        Self {
            pattern_root,
            applicability_root,
            invalidation_conditions,
            expected_savings,
            evidence_root,
        }
    }

    /// Pattern identity.
    #[must_use]
    pub const fn pattern_root(&self) -> Digest {
        self.pattern_root
    }

    /// Applicability contract.
    #[must_use]
    pub const fn applicability_root(&self) -> Digest {
        self.applicability_root
    }

    /// Conditions that invalidate reuse.
    #[must_use]
    pub fn invalidation_conditions(&self) -> &[Digest] {
        &self.invalidation_conditions
    }

    /// Advisory expected resource savings.
    #[must_use]
    pub const fn expected_savings(&self) -> ResourceVector {
        self.expected_savings
    }

    /// Evidence supporting reuse and the savings estimate.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }
}

/// Bounded inputs used to construct one learning record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeLearningRecordSpec {
    terminal_outcome: LearningTerminalOutcome,
    created_at: LogicalTime,
    producer_facts: PartyFacts,
    applicability_root: Digest,
    invalidation_conditions: Vec<Digest>,
    requirement_outcomes: Vec<LearningRequirementOutcome>,
    confirmed_ownership: Vec<ConfirmedOwnership>,
    failed_hypotheses: Vec<FailedHypothesis>,
    resource_observations: Vec<LearningResourceObservation>,
    reusable_patterns: Vec<ReusablePattern>,
    negative_evidence_refs: Vec<Digest>,
    verifier_attestations: Vec<VerifierAttestation>,
}

impl OutcomeLearningRecordSpec {
    /// Creates the required learning frame; typed collections start empty.
    #[must_use]
    pub const fn new(
        terminal_outcome: LearningTerminalOutcome,
        created_at: LogicalTime,
        producer_facts: PartyFacts,
        applicability_root: Digest,
        invalidation_conditions: Vec<Digest>,
    ) -> Self {
        Self {
            terminal_outcome,
            created_at,
            producer_facts,
            applicability_root,
            invalidation_conditions,
            requirement_outcomes: Vec::new(),
            confirmed_ownership: Vec::new(),
            failed_hypotheses: Vec::new(),
            resource_observations: Vec::new(),
            reusable_patterns: Vec::new(),
            negative_evidence_refs: Vec::new(),
            verifier_attestations: Vec::new(),
        }
    }

    /// Sets complete plan-requirement outcomes.
    #[must_use]
    pub fn with_requirement_outcomes(mut self, outcomes: Vec<LearningRequirementOutcome>) -> Self {
        self.requirement_outcomes = outcomes;
        self
    }

    /// Sets evidence-backed ownership findings.
    #[must_use]
    pub fn with_confirmed_ownership(mut self, ownership: Vec<ConfirmedOwnership>) -> Self {
        self.confirmed_ownership = ownership;
        self
    }

    /// Sets failed hypotheses and their discriminating evidence.
    #[must_use]
    pub fn with_failed_hypotheses(mut self, hypotheses: Vec<FailedHypothesis>) -> Self {
        self.failed_hypotheses = hypotheses;
        self
    }

    /// Sets measured resource observations.
    #[must_use]
    pub fn with_resource_observations(
        mut self,
        observations: Vec<LearningResourceObservation>,
    ) -> Self {
        self.resource_observations = observations;
        self
    }

    /// Sets reusable patterns.
    #[must_use]
    pub fn with_reusable_patterns(mut self, patterns: Vec<ReusablePattern>) -> Self {
        self.reusable_patterns = patterns;
        self
    }

    /// Sets explicit negative-evidence references.
    #[must_use]
    pub fn with_negative_evidence_refs(mut self, refs: Vec<Digest>) -> Self {
        self.negative_evidence_refs = refs;
        self
    }

    /// Sets verifier attestations whose independence is machine-classified.
    #[must_use]
    pub fn with_verifier_attestations(mut self, attestations: Vec<VerifierAttestation>) -> Self {
        self.verifier_attestations = attestations;
        self
    }
}

/// Complete, deterministic learning object for retrieval and audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeLearningRecord {
    learning_id: OutcomeLearningRecordId,
    situation_id: SituationId,
    action_packet_id: AgentActionPacketId,
    plan_id: AgentChangePlanId,
    source_run_id: RunId,
    task_id: WorkTaskId,
    terminal_outcome: LearningTerminalOutcome,
    created_at: LogicalTime,
    producer_facts: PartyFacts,
    applicability_root: Digest,
    invalidation_conditions: Vec<Digest>,
    requirement_outcomes: Vec<LearningRequirementOutcome>,
    discriminating_evidence: Vec<EvidenceRecordRef>,
    confirmed_ownership: Vec<ConfirmedOwnership>,
    failed_hypotheses: Vec<FailedHypothesis>,
    resource_observations: Vec<LearningResourceObservation>,
    total_resources_observed: ResourceVector,
    reusable_patterns: Vec<ReusablePattern>,
    negative_evidence_refs: Vec<Digest>,
    verifier_attestations: Vec<VerifierAttestation>,
}

impl OutcomeLearningRecord {
    /// Builds one evidence-grounded retrieval record.
    ///
    /// # Errors
    ///
    /// Refuses packet/plan/run/situation substitution, time rollback,
    /// incomplete or duplicate requirement outcomes, unsupported or absent
    /// evidence, completed outcomes with unmet requirements, missing or
    /// non-independent verifiers, ownership outside the plan, excessive or
    /// duplicate collections, failed hypotheses without discriminating
    /// evidence or invalidation boundaries, resource observations outside the
    /// plan budget, reusable patterns without savings or invalidation
    /// conditions, a missing global invalidation boundary, and unrepresentable
    /// canonical framing.
    pub fn build(
        situation: &AgentSituationReceipt,
        packet: &AgentActionPacket,
        plan: &AgentChangePlan,
        run: &IntentRun,
        mut spec: OutcomeLearningRecordSpec,
    ) -> Result<Self, OutcomeLearningRefusal> {
        validate_basis(situation, packet, plan, run, spec.created_at)?;
        canonicalize_digests(
            "invalidation_conditions",
            &mut spec.invalidation_conditions,
            MAX_LEARNING_ENTRIES,
        )?;
        if spec.invalidation_conditions.is_empty() {
            return Err(OutcomeLearningRefusal::MissingInvalidationConditions);
        }
        canonicalize_verifiers(&mut spec.verifier_attestations)?;
        canonicalize_requirements(
            plan,
            spec.terminal_outcome,
            &spec.producer_facts,
            &spec.verifier_attestations,
            &mut spec.requirement_outcomes,
        )?;
        let discriminating_evidence = collect_discriminating_evidence(&spec.requirement_outcomes)?;
        canonicalize_ownership(plan, &mut spec.confirmed_ownership)?;
        canonicalize_failed_hypotheses(&mut spec.failed_hypotheses)?;
        let total_resources_observed =
            canonicalize_resource_observations(plan, &mut spec.resource_observations)?;
        canonicalize_reusable_patterns(&mut spec.reusable_patterns)?;
        canonicalize_digests(
            "negative_evidence_refs",
            &mut spec.negative_evidence_refs,
            MAX_LEARNING_ENTRIES,
        )?;

        let mut record = Self {
            learning_id: OutcomeLearningRecordId([0; 32]),
            situation_id: situation.situation_id(),
            action_packet_id: packet.packet_id(),
            plan_id: plan.plan_id(),
            source_run_id: run.run_id(),
            task_id: packet.task_id(),
            terminal_outcome: spec.terminal_outcome,
            created_at: spec.created_at,
            producer_facts: spec.producer_facts,
            applicability_root: spec.applicability_root,
            invalidation_conditions: spec.invalidation_conditions,
            requirement_outcomes: spec.requirement_outcomes,
            discriminating_evidence,
            confirmed_ownership: spec.confirmed_ownership,
            failed_hypotheses: spec.failed_hypotheses,
            resource_observations: spec.resource_observations,
            total_resources_observed,
            reusable_patterns: spec.reusable_patterns,
            negative_evidence_refs: spec.negative_evidence_refs,
            verifier_attestations: spec.verifier_attestations,
        };
        record.learning_id = OutcomeLearningRecordId(learning_commitment(&record)?);
        Ok(record)
    }

    /// Stable learning identity.
    #[must_use]
    pub const fn learning_id(&self) -> OutcomeLearningRecordId {
        self.learning_id
    }

    /// Exact situation under which the action packet was created.
    #[must_use]
    pub const fn situation_id(&self) -> SituationId {
        self.situation_id
    }

    /// Exact action packet whose outcome was learned.
    #[must_use]
    pub const fn action_packet_id(&self) -> AgentActionPacketId {
        self.action_packet_id
    }

    /// Exact plan narrowed by the action packet.
    #[must_use]
    pub const fn plan_id(&self) -> AgentChangePlanId {
        self.plan_id
    }

    /// Source Intent Run.
    #[must_use]
    pub const fn source_run_id(&self) -> RunId {
        self.source_run_id
    }

    /// Task whose outcome was learned.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.task_id
    }

    /// Typed terminal interpretation.
    #[must_use]
    pub const fn terminal_outcome(&self) -> LearningTerminalOutcome {
        self.terminal_outcome
    }

    /// Logical record-creation instant.
    #[must_use]
    pub const fn created_at(&self) -> LogicalTime {
        self.created_at
    }

    /// Producer facts used for independence classification.
    #[must_use]
    pub const fn producer_facts(&self) -> PartyFacts {
        self.producer_facts
    }

    /// Global applicability contract.
    #[must_use]
    pub const fn applicability_root(&self) -> Digest {
        self.applicability_root
    }

    /// Conditions that invalidate reuse of the record.
    #[must_use]
    pub fn invalidation_conditions(&self) -> &[Digest] {
        &self.invalidation_conditions
    }

    /// Complete plan-requirement outcomes.
    #[must_use]
    pub fn requirement_outcomes(&self) -> &[LearningRequirementOutcome] {
        &self.requirement_outcomes
    }

    /// Canonical deduplicated evidence that discriminated the result.
    #[must_use]
    pub fn discriminating_evidence(&self) -> &[EvidenceRecordRef] {
        &self.discriminating_evidence
    }

    /// Evidence-backed ownership findings.
    #[must_use]
    pub fn confirmed_ownership(&self) -> &[ConfirmedOwnership] {
        &self.confirmed_ownership
    }

    /// Failed hypotheses and their applicability boundaries.
    #[must_use]
    pub fn failed_hypotheses(&self) -> &[FailedHypothesis] {
        &self.failed_hypotheses
    }

    /// Measured resource observations.
    #[must_use]
    pub fn resource_observations(&self) -> &[LearningResourceObservation] {
        &self.resource_observations
    }

    /// Sum of measured resources, bounded by the plan budget.
    #[must_use]
    pub const fn total_resources_observed(&self) -> ResourceVector {
        self.total_resources_observed
    }

    /// Reusable patterns, each with explicit invalidation conditions.
    #[must_use]
    pub fn reusable_patterns(&self) -> &[ReusablePattern] {
        &self.reusable_patterns
    }

    /// Explicit negative-evidence references.
    #[must_use]
    pub fn negative_evidence_refs(&self) -> &[Digest] {
        &self.negative_evidence_refs
    }

    /// Submitted verifier attestations.
    #[must_use]
    pub fn verifier_attestations(&self) -> &[VerifierAttestation] {
        &self.verifier_attestations
    }

    /// Recomputes every verifier's independence from recorded facts.
    #[must_use]
    pub fn verifier_classifications(&self) -> Vec<IndependenceClassification> {
        self.verifier_attestations
            .iter()
            .map(|attestation| classify_independence(&self.producer_facts, attestation))
            .collect()
    }
}

/// Why a learning record failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutcomeLearningRefusal {
    /// Situation differs from the action packet basis.
    SituationPacketMismatch,
    /// Plan differs from the action packet.
    PacketPlanMismatch,
    /// Run differs from the action packet or plan.
    RunMismatch,
    /// Run lacks a complete authenticated authority receipt.
    RunAuthorityReceiptRequired,
    /// Run and situation use different authority receipts.
    RunAuthorityMismatch,
    /// Learning record predates the action packet.
    CreatedBeforeAction {
        /// Action-packet observation.
        packet_observed_at: LogicalTime,
        /// Proposed learning time.
        created_at: LogicalTime,
    },
    /// Global invalidation conditions were omitted.
    MissingInvalidationConditions,
    /// One collection exceeded its hard ceiling.
    TooManyEntries {
        /// Collection name.
        field: &'static str,
        /// Entries supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// One digest appeared twice in a set-valued collection.
    DuplicateDigest {
        /// Collection name.
        field: &'static str,
        /// Repeated digest.
        digest: Digest,
    },
    /// Requirement-result count differs from the plan.
    RequirementCountMismatch {
        /// Plan requirements.
        expected: usize,
        /// Results supplied.
        observed: usize,
    },
    /// Requirement result names another plan requirement.
    RequirementIdentityMismatch {
        /// Expected requirement.
        expected: PlanRequirementId,
        /// Result supplied.
        observed: PlanRequirementId,
    },
    /// Requirement result appeared twice.
    DuplicateRequirement {
        /// Repeated requirement.
        requirement_id: PlanRequirementId,
    },
    /// A satisfied or partially satisfied requirement carries no evidence.
    SatisfiedRequirementWithoutEvidence {
        /// Requirement missing support.
        requirement_id: PlanRequirementId,
    },
    /// Evidence class records absence instead of supporting the disposition.
    UnsupportedEvidenceClass {
        /// Requirement containing the invalid evidence.
        requirement_id: PlanRequirementId,
        /// Invalid class.
        class: EvidenceClass,
    },
    /// Evidence record appeared twice under one requirement.
    DuplicateRequirementEvidence {
        /// Requirement containing the duplicate.
        requirement_id: PlanRequirementId,
        /// Repeated artifact identity.
        artifact: u128,
    },
    /// Verifier identity appeared twice under one requirement.
    DuplicateRequirementVerifier {
        /// Requirement containing the duplicate.
        requirement_id: PlanRequirementId,
        /// Repeated verifier.
        verifier: u128,
    },
    /// Requirement names no submitted verifier with that identity.
    UnknownRequirementVerifier {
        /// Requirement containing the reference.
        requirement_id: PlanRequirementId,
        /// Missing verifier.
        verifier: u128,
    },
    /// An independently verified plan requirement has no upheld, fully
    /// independent referenced verifier.
    IndependentVerifierMissing {
        /// Requirement needing independence.
        requirement_id: PlanRequirementId,
    },
    /// Completed outcome retains an unmet requirement.
    CompletedWithUnmetRequirement {
        /// Requirement not completed.
        requirement_id: PlanRequirementId,
        /// Disposition observed.
        disposition: RequirementDisposition,
    },
    /// Verifier identity appeared more than once globally.
    DuplicateVerifier {
        /// Repeated verifier.
        verifier: u128,
    },
    /// Ownership finding is outside the plan's intended change surface.
    OwnershipOutsidePlan {
        /// Unapproved surface.
        surface: PlanSurface,
    },
    /// Ownership finding repeated one surface.
    DuplicateOwnership {
        /// Repeated surface.
        surface: PlanSurface,
    },
    /// Failed hypothesis used evidence that cannot support a claim.
    FailedHypothesisUnsupportedEvidence {
        /// Hypothesis identity.
        hypothesis_root: Digest,
        /// Invalid class.
        class: EvidenceClass,
    },
    /// Failed hypothesis omitted its invalidation conditions.
    FailedHypothesisMissingInvalidation {
        /// Hypothesis identity.
        hypothesis_root: Digest,
    },
    /// Failed hypothesis appeared twice.
    DuplicateFailedHypothesis {
        /// Repeated hypothesis.
        hypothesis_root: Digest,
    },
    /// Resource observation declared zero measured work.
    EmptyResourceObservation {
        /// Observation identity.
        observation_root: Digest,
    },
    /// Resource observation appeared twice.
    DuplicateResourceObservation {
        /// Repeated observation.
        observation_root: Digest,
    },
    /// Resource totals overflowed.
    ResourceTotalOverflow {
        /// Resource algebra refusal.
        source: ResourceError,
    },
    /// Measured resource total exceeds the plan budget.
    ResourceTotalExceedsPlan {
        /// First deficient grade.
        deficit: ResourceError,
    },
    /// Reusable pattern claims no positive savings.
    EmptyPatternSavings {
        /// Pattern identity.
        pattern_root: Digest,
    },
    /// Reusable pattern omitted its invalidation conditions.
    PatternMissingInvalidation {
        /// Pattern identity.
        pattern_root: Digest,
    },
    /// Reusable pattern appeared twice.
    DuplicatePattern {
        /// Repeated pattern.
        pattern_root: Digest,
    },
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for OutcomeLearningRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "outcome learning refused: {self:?}")
    }
}

impl core::error::Error for OutcomeLearningRefusal {}

impl From<CodecRefusal> for OutcomeLearningRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_basis(
    situation: &AgentSituationReceipt,
    packet: &AgentActionPacket,
    plan: &AgentChangePlan,
    run: &IntentRun,
    created_at: LogicalTime,
) -> Result<(), OutcomeLearningRefusal> {
    if packet.situation_id() != situation.situation_id() {
        return Err(OutcomeLearningRefusal::SituationPacketMismatch);
    }
    if packet.plan_id() != plan.plan_id() {
        return Err(OutcomeLearningRefusal::PacketPlanMismatch);
    }
    if packet.run_id() != run.run_id() || plan.intent_run_id() != run.run_id() {
        return Err(OutcomeLearningRefusal::RunMismatch);
    }
    let authority = run
        .authority_read_receipt()
        .ok_or(OutcomeLearningRefusal::RunAuthorityReceiptRequired)?;
    if authority != situation.authority_read_receipt() {
        return Err(OutcomeLearningRefusal::RunAuthorityMismatch);
    }
    if created_at < packet.observed_at() {
        return Err(OutcomeLearningRefusal::CreatedBeforeAction {
            packet_observed_at: packet.observed_at(),
            created_at,
        });
    }
    Ok(())
}

fn canonicalize_requirements(
    plan: &AgentChangePlan,
    terminal: LearningTerminalOutcome,
    producer: &PartyFacts,
    attestations: &[VerifierAttestation],
    outcomes: &mut Vec<LearningRequirementOutcome>,
) -> Result<(), OutcomeLearningRefusal> {
    if outcomes.len() > MAX_LEARNING_ENTRIES {
        return Err(OutcomeLearningRefusal::TooManyEntries {
            field: "requirement_outcomes",
            observed: outcomes.len(),
            limit: MAX_LEARNING_ENTRIES,
        });
    }
    outcomes.sort_unstable_by_key(|outcome| outcome.requirement_id);
    for adjacent in outcomes.windows(2) {
        if adjacent[0].requirement_id == adjacent[1].requirement_id {
            return Err(OutcomeLearningRefusal::DuplicateRequirement {
                requirement_id: adjacent[0].requirement_id,
            });
        }
    }
    if outcomes.len() != plan.evidence_plan().len() {
        return Err(OutcomeLearningRefusal::RequirementCountMismatch {
            expected: plan.evidence_plan().len(),
            observed: outcomes.len(),
        });
    }
    for (required, outcome) in plan.evidence_plan().iter().zip(outcomes.iter_mut()) {
        if required.requirement_id() != outcome.requirement_id {
            return Err(OutcomeLearningRefusal::RequirementIdentityMismatch {
                expected: required.requirement_id(),
                observed: outcome.requirement_id,
            });
        }
        canonicalize_requirement_evidence(outcome)?;
        outcome.verifier_ids.sort_unstable();
        for adjacent in outcome.verifier_ids.windows(2) {
            if adjacent[0] == adjacent[1] {
                return Err(OutcomeLearningRefusal::DuplicateRequirementVerifier {
                    requirement_id: outcome.requirement_id,
                    verifier: adjacent[0],
                });
            }
        }
        for verifier in &outcome.verifier_ids {
            if !attestations
                .iter()
                .any(|attestation| attestation.verifier == *verifier)
            {
                return Err(OutcomeLearningRefusal::UnknownRequirementVerifier {
                    requirement_id: outcome.requirement_id,
                    verifier: *verifier,
                });
            }
        }
        if required.requires_independent_verifier()
            && matches!(
                outcome.disposition,
                RequirementDisposition::SatisfiedWithEvidence
                    | RequirementDisposition::PartiallySatisfied
            )
        {
            let independent = outcome.verifier_ids.iter().any(|verifier| {
                attestations.iter().any(|attestation| {
                    attestation.verifier == *verifier
                        && attestation.upheld
                        && classify_independence(producer, attestation).is_fully_independent()
                })
            });
            if !independent {
                return Err(OutcomeLearningRefusal::IndependentVerifierMissing {
                    requirement_id: outcome.requirement_id,
                });
            }
        }
        if terminal.is_completed()
            && !matches!(
                outcome.disposition,
                RequirementDisposition::SatisfiedWithEvidence
                    | RequirementDisposition::NotApplicable
            )
        {
            return Err(OutcomeLearningRefusal::CompletedWithUnmetRequirement {
                requirement_id: outcome.requirement_id,
                disposition: outcome.disposition,
            });
        }
    }
    Ok(())
}

fn canonicalize_requirement_evidence(
    outcome: &mut LearningRequirementOutcome,
) -> Result<(), OutcomeLearningRefusal> {
    if outcome.evidence.len() > MAX_LEARNING_EVIDENCE {
        return Err(OutcomeLearningRefusal::TooManyEntries {
            field: "requirement_evidence",
            observed: outcome.evidence.len(),
            limit: MAX_LEARNING_EVIDENCE,
        });
    }
    if matches!(
        outcome.disposition,
        RequirementDisposition::SatisfiedWithEvidence | RequirementDisposition::PartiallySatisfied
    ) && outcome.evidence.is_empty()
    {
        return Err(
            OutcomeLearningRefusal::SatisfiedRequirementWithoutEvidence {
                requirement_id: outcome.requirement_id,
            },
        );
    }
    outcome.evidence.sort_unstable_by_key(evidence_sort_key);
    for evidence in &outcome.evidence {
        if !evidence.class.supports_a_claim() {
            return Err(OutcomeLearningRefusal::UnsupportedEvidenceClass {
                requirement_id: outcome.requirement_id,
                class: evidence.class,
            });
        }
    }
    for adjacent in outcome.evidence.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(OutcomeLearningRefusal::DuplicateRequirementEvidence {
                requirement_id: outcome.requirement_id,
                artifact: adjacent[0].artifact,
            });
        }
    }
    Ok(())
}

fn collect_discriminating_evidence(
    outcomes: &[LearningRequirementOutcome],
) -> Result<Vec<EvidenceRecordRef>, OutcomeLearningRefusal> {
    let total = outcomes.iter().try_fold(0_usize, |total, outcome| {
        total
            .checked_add(outcome.evidence.len())
            .ok_or(OutcomeLearningRefusal::TooManyEntries {
                field: "discriminating_evidence",
                observed: usize::MAX,
                limit: MAX_LEARNING_EVIDENCE,
            })
    })?;
    if total > MAX_LEARNING_EVIDENCE {
        return Err(OutcomeLearningRefusal::TooManyEntries {
            field: "discriminating_evidence",
            observed: total,
            limit: MAX_LEARNING_EVIDENCE,
        });
    }
    let mut evidence: Vec<_> = outcomes
        .iter()
        .flat_map(|outcome| outcome.evidence.iter().copied())
        .collect();
    evidence.sort_unstable_by_key(evidence_sort_key);
    evidence.dedup();
    Ok(evidence)
}

fn canonicalize_verifiers(
    attestations: &mut Vec<VerifierAttestation>,
) -> Result<(), OutcomeLearningRefusal> {
    if attestations.len() > MAX_LEARNING_ENTRIES {
        return Err(OutcomeLearningRefusal::TooManyEntries {
            field: "verifier_attestations",
            observed: attestations.len(),
            limit: MAX_LEARNING_ENTRIES,
        });
    }
    attestations.sort_unstable_by_key(|attestation| attestation.verifier);
    for adjacent in attestations.windows(2) {
        if adjacent[0].verifier == adjacent[1].verifier {
            return Err(OutcomeLearningRefusal::DuplicateVerifier {
                verifier: adjacent[0].verifier,
            });
        }
    }
    Ok(())
}

fn canonicalize_ownership(
    plan: &AgentChangePlan,
    ownership: &mut Vec<ConfirmedOwnership>,
) -> Result<(), OutcomeLearningRefusal> {
    if ownership.len() > MAX_LEARNING_ENTRIES {
        return Err(OutcomeLearningRefusal::TooManyEntries {
            field: "confirmed_ownership",
            observed: ownership.len(),
            limit: MAX_LEARNING_ENTRIES,
        });
    }
    ownership.sort_unstable_by_key(|finding| finding.surface);
    for finding in ownership.iter() {
        if plan
            .intended_change_surface()
            .binary_search(&finding.surface)
            .is_err()
        {
            return Err(OutcomeLearningRefusal::OwnershipOutsidePlan {
                surface: finding.surface,
            });
        }
    }
    for adjacent in ownership.windows(2) {
        if adjacent[0].surface == adjacent[1].surface {
            return Err(OutcomeLearningRefusal::DuplicateOwnership {
                surface: adjacent[0].surface,
            });
        }
    }
    Ok(())
}

fn canonicalize_failed_hypotheses(
    hypotheses: &mut Vec<FailedHypothesis>,
) -> Result<(), OutcomeLearningRefusal> {
    if hypotheses.len() > MAX_LEARNING_ENTRIES {
        return Err(OutcomeLearningRefusal::TooManyEntries {
            field: "failed_hypotheses",
            observed: hypotheses.len(),
            limit: MAX_LEARNING_ENTRIES,
        });
    }
    for hypothesis in hypotheses.iter_mut() {
        if !hypothesis.discriminating_evidence.class.supports_a_claim() {
            return Err(
                OutcomeLearningRefusal::FailedHypothesisUnsupportedEvidence {
                    hypothesis_root: hypothesis.hypothesis_root,
                    class: hypothesis.discriminating_evidence.class,
                },
            );
        }
        canonicalize_digests(
            "failed_hypothesis.invalidation_conditions",
            &mut hypothesis.invalidation_conditions,
            MAX_LEARNING_ENTRIES,
        )?;
        if hypothesis.invalidation_conditions.is_empty() {
            return Err(
                OutcomeLearningRefusal::FailedHypothesisMissingInvalidation {
                    hypothesis_root: hypothesis.hypothesis_root,
                },
            );
        }
    }
    hypotheses.sort_unstable_by_key(|hypothesis| hypothesis.hypothesis_root);
    for adjacent in hypotheses.windows(2) {
        if adjacent[0].hypothesis_root == adjacent[1].hypothesis_root {
            return Err(OutcomeLearningRefusal::DuplicateFailedHypothesis {
                hypothesis_root: adjacent[0].hypothesis_root,
            });
        }
    }
    Ok(())
}

fn canonicalize_resource_observations(
    plan: &AgentChangePlan,
    observations: &mut Vec<LearningResourceObservation>,
) -> Result<ResourceVector, OutcomeLearningRefusal> {
    if observations.len() > MAX_LEARNING_ENTRIES {
        return Err(OutcomeLearningRefusal::TooManyEntries {
            field: "resource_observations",
            observed: observations.len(),
            limit: MAX_LEARNING_ENTRIES,
        });
    }
    observations.sort_unstable_by_key(|observation| observation.observation_root);
    let mut total = ResourceVector::ZERO;
    for observation in observations.iter() {
        if observation.consumed.is_zero() {
            return Err(OutcomeLearningRefusal::EmptyResourceObservation {
                observation_root: observation.observation_root,
            });
        }
        total = total
            .combine(&observation.consumed)
            .map_err(|source| OutcomeLearningRefusal::ResourceTotalOverflow { source })?;
    }
    for adjacent in observations.windows(2) {
        if adjacent[0].observation_root == adjacent[1].observation_root {
            return Err(OutcomeLearningRefusal::DuplicateResourceObservation {
                observation_root: adjacent[0].observation_root,
            });
        }
    }
    if let Some(deficit) = plan.resource_budget().first_deficit(&total) {
        return Err(OutcomeLearningRefusal::ResourceTotalExceedsPlan { deficit });
    }
    Ok(total)
}

fn canonicalize_reusable_patterns(
    patterns: &mut Vec<ReusablePattern>,
) -> Result<(), OutcomeLearningRefusal> {
    if patterns.len() > MAX_LEARNING_ENTRIES {
        return Err(OutcomeLearningRefusal::TooManyEntries {
            field: "reusable_patterns",
            observed: patterns.len(),
            limit: MAX_LEARNING_ENTRIES,
        });
    }
    for pattern in patterns.iter_mut() {
        if pattern.expected_savings.is_zero() {
            return Err(OutcomeLearningRefusal::EmptyPatternSavings {
                pattern_root: pattern.pattern_root,
            });
        }
        canonicalize_digests(
            "reusable_pattern.invalidation_conditions",
            &mut pattern.invalidation_conditions,
            MAX_LEARNING_ENTRIES,
        )?;
        if pattern.invalidation_conditions.is_empty() {
            return Err(OutcomeLearningRefusal::PatternMissingInvalidation {
                pattern_root: pattern.pattern_root,
            });
        }
    }
    patterns.sort_unstable_by_key(|pattern| pattern.pattern_root);
    for adjacent in patterns.windows(2) {
        if adjacent[0].pattern_root == adjacent[1].pattern_root {
            return Err(OutcomeLearningRefusal::DuplicatePattern {
                pattern_root: adjacent[0].pattern_root,
            });
        }
    }
    Ok(())
}

fn canonicalize_digests(
    field: &'static str,
    values: &mut Vec<Digest>,
    limit: usize,
) -> Result<(), OutcomeLearningRefusal> {
    if values.len() > limit {
        return Err(OutcomeLearningRefusal::TooManyEntries {
            field,
            observed: values.len(),
            limit,
        });
    }
    values.sort_unstable();
    for adjacent in values.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(OutcomeLearningRefusal::DuplicateDigest {
                field,
                digest: adjacent[0],
            });
        }
    }
    Ok(())
}

fn learning_commitment(record: &OutcomeLearningRecord) -> Result<[u8; 32], OutcomeLearningRefusal> {
    let mut encoder = Encoder::with_capacity(2_048);
    encoder.write_bytes("outcome_learning_domain", LEARNING_DOMAIN)?;
    encoder.write_raw(record.situation_id.as_bytes());
    encoder.write_raw(record.action_packet_id.as_bytes());
    encoder.write_raw(record.plan_id.as_bytes());
    encoder.write_raw(&record.source_run_id.value().to_be_bytes());
    encoder.write_raw(record.task_id.as_bytes());
    write_terminal_outcome(&mut encoder, record.terminal_outcome)?;
    encoder.write_scalar(record.created_at.value());
    write_party_facts(&mut encoder, record.producer_facts);
    encoder.write_digest(&record.applicability_root)?;
    write_digests(
        &mut encoder,
        "outcome_learning.invalidation_conditions",
        &record.invalidation_conditions,
    )?;
    write_requirements(&mut encoder, &record.requirement_outcomes)?;
    write_evidence(
        &mut encoder,
        "outcome_learning.discriminating_evidence",
        &record.discriminating_evidence,
    )?;
    write_count(
        &mut encoder,
        "outcome_learning.confirmed_ownership",
        record.confirmed_ownership.len(),
    )?;
    for finding in &record.confirmed_ownership {
        write_surface(&mut encoder, finding.surface)?;
        encoder.write_digest(&finding.evidence_root)?;
    }
    write_count(
        &mut encoder,
        "outcome_learning.failed_hypotheses",
        record.failed_hypotheses.len(),
    )?;
    for hypothesis in &record.failed_hypotheses {
        encoder.write_digest(&hypothesis.hypothesis_root)?;
        write_evidence_record(&mut encoder, hypothesis.discriminating_evidence);
        encoder.write_digest(&hypothesis.applicability_root)?;
        write_digests(
            &mut encoder,
            "outcome_learning.failed_hypothesis.invalidation_conditions",
            &hypothesis.invalidation_conditions,
        )?;
    }
    write_count(
        &mut encoder,
        "outcome_learning.resource_observations",
        record.resource_observations.len(),
    )?;
    for observation in &record.resource_observations {
        encoder.write_digest(&observation.observation_root)?;
        encoder.write_raw_byte(observation.phase.code_point());
        write_resource_vector(&mut encoder, observation.consumed);
        encoder.write_digest(&observation.evidence_root)?;
    }
    write_resource_vector(&mut encoder, record.total_resources_observed);
    write_count(
        &mut encoder,
        "outcome_learning.reusable_patterns",
        record.reusable_patterns.len(),
    )?;
    for pattern in &record.reusable_patterns {
        encoder.write_digest(&pattern.pattern_root)?;
        encoder.write_digest(&pattern.applicability_root)?;
        write_digests(
            &mut encoder,
            "outcome_learning.reusable_pattern.invalidation_conditions",
            &pattern.invalidation_conditions,
        )?;
        write_resource_vector(&mut encoder, pattern.expected_savings);
        encoder.write_digest(&pattern.evidence_root)?;
    }
    write_digests(
        &mut encoder,
        "outcome_learning.negative_evidence_refs",
        &record.negative_evidence_refs,
    )?;
    write_verifiers(&mut encoder, &record.verifier_attestations)?;

    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn write_terminal_outcome(
    encoder: &mut Encoder,
    outcome: LearningTerminalOutcome,
) -> Result<(), OutcomeLearningRefusal> {
    encoder.write_raw_byte(outcome.code_point());
    match outcome {
        LearningTerminalOutcome::Completed { result_root } => {
            encoder.write_digest(&result_root)?;
        }
        LearningTerminalOutcome::Refused { refusal_root } => {
            encoder.write_digest(&refusal_root)?;
        }
        LearningTerminalOutcome::Cancelled { completion_id } => {
            encoder.write_raw(completion_id.as_bytes());
        }
        LearningTerminalOutcome::HandedOff { acceptance_id } => {
            encoder.write_raw(acceptance_id.as_bytes());
        }
        LearningTerminalOutcome::Contained { evidence_root } => {
            encoder.write_digest(&evidence_root)?;
        }
    }
    Ok(())
}

fn write_requirements(
    encoder: &mut Encoder,
    outcomes: &[LearningRequirementOutcome],
) -> Result<(), OutcomeLearningRefusal> {
    write_count(
        encoder,
        "outcome_learning.requirement_outcomes",
        outcomes.len(),
    )?;
    for outcome in outcomes {
        encoder.write_raw(outcome.requirement_id.as_bytes());
        encoder.write_scalar(outcome.disposition.code_point());
        write_evidence(
            encoder,
            "outcome_learning.requirement_evidence",
            &outcome.evidence,
        )?;
        write_count(
            encoder,
            "outcome_learning.requirement_verifiers",
            outcome.verifier_ids.len(),
        )?;
        for verifier in &outcome.verifier_ids {
            encoder.write_raw(&verifier.to_be_bytes());
        }
        encoder.write_digest(&outcome.reason_root)?;
    }
    Ok(())
}

fn write_evidence(
    encoder: &mut Encoder,
    field: &'static str,
    evidence: &[EvidenceRecordRef],
) -> Result<(), OutcomeLearningRefusal> {
    write_count(encoder, field, evidence.len())?;
    for record in evidence {
        write_evidence_record(encoder, *record);
    }
    Ok(())
}

fn write_evidence_record(encoder: &mut Encoder, record: EvidenceRecordRef) {
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

fn write_verifiers(
    encoder: &mut Encoder,
    attestations: &[VerifierAttestation],
) -> Result<(), OutcomeLearningRefusal> {
    write_count(
        encoder,
        "outcome_learning.verifier_attestations",
        attestations.len(),
    )?;
    for attestation in attestations {
        encoder.write_raw(&attestation.verifier.to_be_bytes());
        write_party_facts(encoder, attestation.facts);
        encoder.write_bool(attestation.upheld);
    }
    Ok(())
}

fn write_party_facts(encoder: &mut Encoder, facts: PartyFacts) {
    write_optional_u128(encoder, facts.workspace);
    write_optional_u128(encoder, facts.credentials);
    write_optional_u128(encoder, facts.model_harness);
    write_optional_u128(encoder, facts.context);
    write_optional_u128(encoder, facts.oracle);
    write_optional_u128(encoder, facts.sponsor);
    write_optional_u128(encoder, facts.human);
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

fn write_surface(
    encoder: &mut Encoder,
    surface: PlanSurface,
) -> Result<(), OutcomeLearningRefusal> {
    encoder.write_raw_byte(surface_kind_code(surface.kind()));
    encoder.write_digest(&surface.selector())?;
    Ok(())
}

fn write_digests(
    encoder: &mut Encoder,
    field: &'static str,
    values: &[Digest],
) -> Result<(), OutcomeLearningRefusal> {
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
) -> Result<(), OutcomeLearningRefusal> {
    let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(count).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    Ok(())
}

fn evidence_sort_key(record: &EvidenceRecordRef) -> (u16, u128, u8) {
    (
        record.class.code_point(),
        record.artifact,
        record.refresh_side.map_or(0, refresh_side_code),
    )
}

const fn refresh_side_code(side: crate::RefreshSide) -> u8 {
    match side {
        crate::RefreshSide::BeforeRefresh => 1,
        crate::RefreshSide::AfterRefresh => 2,
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
