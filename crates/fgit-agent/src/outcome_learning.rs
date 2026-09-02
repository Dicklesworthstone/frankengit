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
}

impl OutcomeLearningRecordSpec {
    /// Creates the required learning frame; typed collections start empty.
    #[must_use]
    pub const fn new(
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
        }
    }

    /// Sets complete plan-requirement outcomes.
    #[must_use]
    pub fn with_requirement_outcomes(mut self, outcomes: Vec<LearningRequirementOutcome>) -> Self {
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
    pub fn with_verifier_attestations(mut self, attestations: Vec<VerifierAttestation>) -> Self {
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
    /// The internal builder first applies its fixed refusal order and
    /// canonicalizes the complete requirement matrix. Only then does this
    /// public boundary require the exact evidence class named by every
    /// satisfied or partially satisfied plan requirement. Malformed duplicate
    /// or mismatched input therefore cannot change the first refusal merely by
    /// changing row order.
    ///
    /// # Errors
    ///
    /// Returns [`OutcomeLearningRefusal::SatisfiedRequirementWithoutEvidence`]
    /// when a structurally valid requirement carries no record of its required
    /// class, even when other supporting evidence records are present. Every
    /// structural refusal is returned by the canonical internal constructor
    /// unchanged.
    pub fn build(
        situation: &AgentSituationReceipt,
        packet: &AgentActionPacket,
        plan: &AgentChangePlan,
        run: &IntentRun,
        spec: OutcomeLearningRecordSpec,
    ) -> Result<Self, OutcomeLearningRefusal> {
        let record = crate::learning::OutcomeLearningRecord::build(
            situation, packet, plan, run, spec.inner,
        )?;
        validate_required_evidence_classes(plan, record.requirement_outcomes())?;
        Ok(Self(record))
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
            // A canonical internal record already proved count and identity
            // completeness, so this branch is defensive only.
            continue;
        };
        if matches!(
            outcome.disposition(),
            crate::RequirementDisposition::SatisfiedWithEvidence
                | crate::RequirementDisposition::PartiallySatisfied
        ) && !carries_required_evidence_class(requirement.evidence_class(), outcome)
        {
            return Err(
                OutcomeLearningRefusal::SatisfiedRequirementWithoutEvidence {
                    requirement_id: requirement.requirement_id(),
                },
            );
        }
    }
    Ok(())
}

fn carries_required_evidence_class(
    required: crate::EvidenceClass,
    outcome: &LearningRequirementOutcome,
) -> bool {
    outcome
        .evidence()
        .iter()
        .any(|record| record.class == required)
}

#[cfg(test)]
mod tests {
    use super::carries_required_evidence_class;
    use crate::{
        EvidenceClass, EvidenceRecordRef, LearningRequirementOutcome, PlanRequirementId,
        RequirementDisposition,
    };

    #[test]
    fn weaker_supporting_class_does_not_replace_required_executed_evidence() {
        let reason_root =
            fgit_authority::outcome_index_root(&[]).expect("empty outcome root is canonical");
        let outcome = LearningRequirementOutcome::new(
            PlanRequirementId::from_bytes([1; 32]),
            RequirementDisposition::SatisfiedWithEvidence,
            vec![EvidenceRecordRef {
                class: EvidenceClass::Observed,
                artifact: 1,
                refresh_side: None,
            }],
            Vec::new(),
            reason_root,
        );

        assert!(!carries_required_evidence_class(
            EvidenceClass::Executed,
            &outcome
        ));
        assert!(carries_required_evidence_class(
            EvidenceClass::Observed,
            &outcome
        ));
    }
}
