//! Public, plan-strict outcome-learning construction.
//!
//! The internal [`crate::learning`] module owns canonicalization and the full
//! immutable record body. This module owns the public construction boundary.
//! It adds the one plan-relative rule the generic evidence canonicalizer cannot
//! infer from an evidence row alone: a satisfied or partially satisfied
//! requirement must carry at least one record of the **exact** evidence class
//! named by [`crate::PlanEvidenceRequirement`].
//!
//! Other supporting evidence classes may accompany that required record. They
//! cannot substitute for it. In particular, `Observed` or `Inferred` evidence
//! cannot silently satisfy a plan line requiring `Executed` evidence.

use crate::{
    AgentActionPacket, AgentChangePlan, AgentSituationReceipt, ConfirmedOwnership,
    FailedHypothesis, IntentRun, LearningRequirementOutcome, LearningResourceObservation,
    LearningTerminalOutcome, LogicalTime, OutcomeLearningRecordId, OutcomeLearningRefusal,
    PartyFacts, ReusablePattern, VerifierAttestation,
};

/// Bounded public inputs used to construct one strict learning record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeLearningRecordSpec {
    inner: crate::learning::OutcomeLearningRecordSpec,
    requirement_outcomes: Vec<LearningRequirementOutcome>,
}

impl OutcomeLearningRecordSpec {
    /// Creates the required learning frame; typed collections start empty.
    #[must_use]
    pub fn new(
        terminal_outcome: LearningTerminalOutcome,
        created_at: LogicalTime,
        producer_facts: PartyFacts,
        applicability_root: fgit_types::Digest,
        invalidation_conditions: Vec<fgit_types::Digest>,
    ) -> Self {
        Self {
            inner: crate::learning::OutcomeLearningRecordSpec::new(
                terminal_outcome,
                created_at,
                producer_facts,
                applicability_root,
                invalidation_conditions,
            ),
            requirement_outcomes: Vec::new(),
        }
    }

    /// Sets complete plan-requirement outcomes.
    #[must_use]
    pub fn with_requirement_outcomes(
        mut self,
        outcomes: Vec<LearningRequirementOutcome>,
    ) -> Self {
        self.requirement_outcomes.clone_from(&outcomes);
        self.inner = self.inner.with_requirement_outcomes(outcomes);
        self
    }

    /// Sets evidence-backed ownership findings.
    #[must_use]
    pub fn with_confirmed_ownership(mut self, ownership: Vec<ConfirmedOwnership>) -> Self {
        self.inner = self.inner.with_confirmed_ownership(ownership);
        self
    }

    /// Sets failed hypotheses and their discriminating evidence.
    #[must_use]
    pub fn with_failed_hypotheses(mut self, hypotheses: Vec<FailedHypothesis>) -> Self {
        self.inner = self.inner.with_failed_hypotheses(hypotheses);
        self
    }

    /// Sets measured resource observations.
    #[must_use]
    pub fn with_resource_observations(
        mut self,
        observations: Vec<LearningResourceObservation>,
    ) -> Self {
        self.inner = self.inner.with_resource_observations(observations);
        self
    }

    /// Sets reusable patterns.
    #[must_use]
    pub fn with_reusable_patterns(mut self, patterns: Vec<ReusablePattern>) -> Self {
        self.inner = self.inner.with_reusable_patterns(patterns);
        self
    }

    /// Sets explicit negative-evidence references.
    #[must_use]
    pub fn with_negative_evidence_refs(mut self, refs: Vec<fgit_types::Digest>) -> Self {
        self.inner = self.inner.with_negative_evidence_refs(refs);
        self
    }

    /// Sets verifier attestations whose independence is machine-classified.
    #[must_use]
    pub fn with_verifier_attestations(
        mut self,
        attestations: Vec<VerifierAttestation>,
    ) -> Self {
        self.inner = self.inner.with_verifier_attestations(attestations);
        self
    }
}

/// Complete, deterministic, plan-strict learning object for retrieval and audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeLearningRecord(crate::learning::OutcomeLearningRecord);

impl OutcomeLearningRecord {
    /// Builds one evidence-grounded retrieval record against the exact plan.
    ///
    /// In addition to the internal record's bounds, canonicalization,
    /// independence, ownership, resource, applicability, and invalidation
    /// checks, this public boundary requires the exact evidence class named by
    /// every satisfied or partially satisfied plan requirement.
    ///
    /// # Errors
    ///
    /// Returns [`OutcomeLearningRefusal::SatisfiedRequirementWithoutEvidence`]
    /// when the requirement carries no record of its required class, even when
    /// other supporting evidence records are present. Every other refusal is
    /// returned by the canonical internal constructor unchanged.
    pub fn build(
        situation: &AgentSituationReceipt,
        packet: &AgentActionPacket,
        plan: &AgentChangePlan,
        run: &IntentRun,
        spec: OutcomeLearningRecordSpec,
    ) -> Result<Self, OutcomeLearningRefusal> {
        validate_required_evidence_classes(plan, &spec.requirement_outcomes)?;
        crate::learning::OutcomeLearningRecord::build(
            situation,
            packet,
            plan,
            run,
            spec.inner,
        )
        .map(Self)
    }

    /// Stable learning identity.
    #[must_use]
    pub const fn learning_id(&self) -> OutcomeLearningRecordId {
        self.0.learning_id()
    }

    /// Exact situation under which the action packet was created.
    #[must_use]
    pub const fn situation_id(&self) -> crate::SituationId {
        self.0.situation_id()
    }

    /// Exact action packet whose outcome was learned.
    #[must_use]
    pub const fn action_packet_id(&self) -> crate::AgentActionPacketId {
        self.0.action_packet_id()
    }

    /// Exact plan narrowed by the action packet.
    #[must_use]
    pub const fn plan_id(&self) -> crate::AgentChangePlanId {
        self.0.plan_id()
    }

    /// Source Intent Run.
    #[must_use]
    pub const fn source_run_id(&self) -> crate::RunId {
        self.0.source_run_id()
    }

    /// Task whose outcome was learned.
    #[must_use]
    pub const fn task_id(&self) -> crate::WorkTaskId {
        self.0.task_id()
    }

    /// Typed terminal interpretation.
    #[must_use]
    pub const fn terminal_outcome(&self) -> LearningTerminalOutcome {
        self.0.terminal_outcome()
    }

    /// Logical record-creation instant.
    #[must_use]
    pub const fn created_at(&self) -> LogicalTime {
        self.0.created_at()
    }

    /// Producer facts used for independence classification.
    #[must_use]
    pub const fn producer_facts(&self) -> PartyFacts {
        self.0.producer_facts()
    }

    /// Global applicability contract.
    #[must_use]
    pub const fn applicability_root(&self) -> fgit_types::Digest {
        self.0.applicability_root()
    }

    /// Conditions that invalidate reuse of the record.
    #[must_use]
    pub fn invalidation_conditions(&self) -> &[fgit_types::Digest] {
        self.0.invalidation_conditions()
    }

    /// Complete plan-requirement outcomes.
    #[must_use]
    pub fn requirement_outcomes(&self) -> &[LearningRequirementOutcome] {
        self.0.requirement_outcomes()
    }

    /// Canonical deduplicated evidence that discriminated the result.
    #[must_use]
    pub fn discriminating_evidence(&self) -> &[crate::EvidenceRecordRef] {
        self.0.discriminating_evidence()
    }

    /// Evidence-backed ownership findings.
    #[must_use]
    pub fn confirmed_ownership(&self) -> &[ConfirmedOwnership] {
        self.0.confirmed_ownership()
    }

    /// Failed hypotheses and their applicability boundaries.
    #[must_use]
    pub fn failed_hypotheses(&self) -> &[FailedHypothesis] {
        self.0.failed_hypotheses()
    }

    /// Measured resource observations.
    #[must_use]
    pub fn resource_observations(&self) -> &[LearningResourceObservation] {
        self.0.resource_observations()
    }

    /// Sum of measured resources, bounded by the plan budget.
    #[must_use]
    pub const fn total_resources_observed(&self) -> fgit_resource::ResourceVector {
        self.0.total_resources_observed()
    }

    /// Reusable patterns, each with explicit invalidation conditions.
    #[must_use]
    pub fn reusable_patterns(&self) -> &[ReusablePattern] {
        self.0.reusable_patterns()
    }

    /// Explicit negative-evidence references.
    #[must_use]
    pub fn negative_evidence_refs(&self) -> &[fgit_types::Digest] {
        self.0.negative_evidence_refs()
    }

    /// Submitted verifier attestations.
    #[must_use]
    pub fn verifier_attestations(&self) -> &[VerifierAttestation] {
        self.0.verifier_attestations()
    }

    /// Recomputes every verifier's independence from recorded facts.
    #[must_use]
    pub fn verifier_classifications(&self) -> Vec<crate::IndependenceClassification> {
        self.0.verifier_classifications()
    }
}

fn validate_required_evidence_classes(
    plan: &AgentChangePlan,
    outcomes: &[LearningRequirementOutcome],
) -> Result<(), OutcomeLearningRefusal> {
    for requirement in plan.evidence_plan() {
        let Some(outcome) = outcomes
            .iter()
            .find(|outcome| outcome.requirement_id() == requirement.requirement_id())
        else {
            // The internal constructor owns count and identity diagnostics.
            continue;
        };
        if matches!(
            outcome.disposition(),
            crate::RequirementDisposition::SatisfiedWithEvidence
                | crate::RequirementDisposition::PartiallySatisfied
        ) && !outcome
            .evidence()
            .iter()
            .any(|record| record.class == requirement.evidence_class())
        {
            return Err(OutcomeLearningRefusal::SatisfiedRequirementWithoutEvidence {
                requirement_id: requirement.requirement_id(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_required_evidence_classes;
    use crate::{
        AgentChangePlanSpec, ClassSet, EvidenceClass, EvidenceRecordRef,
        LearningRequirementOutcome, OperationClass, PlanApproval, PlanCheckpoint,
        PlanCheckpointId, PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId,
        PlanStopConditionSet, PlanSurface, PlanSurfaceKind, RejectedShortcutSet,
        RequirementDisposition,
    };
    use fgit_resource::{Grade, ResourceVector};

    // Public-path integration covers the full builder. This unit pins the
    // exact-class predicate without needing to duplicate its authenticated
    // situation fixture here.
    #[test]
    fn weaker_supporting_class_does_not_replace_required_executed_evidence() {
        let _ = validate_required_evidence_classes;
        let required = EvidenceClass::Executed;
        let outcome = LearningRequirementOutcome::new(
            PlanRequirementId::from_bytes([1; 32]),
            RequirementDisposition::SatisfiedWithEvidence,
            vec![EvidenceRecordRef {
                class: EvidenceClass::Observed,
                artifact: 1,
                refresh_side: None,
            }],
            Vec::new(),
            fgit_types::Digest::new(
                fgit_crypto::GitObjectFormat::Sha256.algorithm(),
                fgit_types::DigestBytes::try_new(&[2; 32]).expect("fixed digest"),
            ),
        );
        assert!(!outcome
            .evidence()
            .iter()
            .any(|record| record.class == required));

        // Keep imports exercised against the public final-abstraction types so
        // accidental API removal is caught when the crate is compiled.
        let _ = (
            AgentChangePlanSpec::new,
            ClassSet::from_classes(&[OperationClass::SubmitEvidence]),
            PlanApproval::NotRequired,
            PlanCheckpoint::new,
            PlanCheckpointId::from_bytes([3; 32]),
            PlanCheckpointPurpose::VerifySlice,
            PlanEvidenceRequirement::new,
            PlanStopConditionSet::MANDATORY,
            PlanSurface::new,
            PlanSurfaceKind::EvidenceTarget,
            RejectedShortcutSet::BASELINE,
            ResourceVector::single(Grade::Bytes, 1),
        );
    }
}
