//! Public, continuity-bound Agent Control Plane handoff construction.
//!
//! The internal [`crate::handoff`] module owns canonicalization of the capsule
//! body. This module owns the public construction boundary. A caller must use
//! either the exact situation that activated the task claim or a specific
//! [`crate::ActiveClaimContinuityReceipt`] proving that only logical time
//! advanced. The selected proof is committed into the public capsule identity;
//! validation evidence is never checked and then discarded.
//!
//! The facade grants no authority and performs no task transfer. Receiver-side
//! acceptance still revalidates ordinary run authority, attenuation, target
//! resolution, and every inherited effect responsibility.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_resource::ResourceVector;
use fgit_types::Digest;

use crate::{
    ActiveClaimContinuityReceipt, ActiveClaimContinuityReceiptId,
    ActiveClaimContinuityRefusal, ActiveTaskClaim, ActiveTaskClaimId, AgentChangePlan,
    AgentChangePlanId, AgentHandoffCapsuleSpec, AgentInstanceId, AgentSituationReceipt,
    HandoffCapabilityAttenuation, HandoffWorkspaceSnapshot, IntentRun, ReconciledEffect,
    RequirementDisposition, RunId, RunReconciliationReadiness, RunReconciliationReport,
    SituationId, VerifierAttestation,
};

const PUBLIC_HANDOFF_DOMAIN: &[u8] = b"frankengit.agent.public-handoff-capsule/v1\0";

/// Stable identity of one publicly constructible handoff capsule.
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

/// Complete public handoff capsule with an explicit continuity basis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentHandoffCapsule {
    capsule_id: AgentHandoffCapsuleId,
    claim_continuity_id: Option<ActiveClaimContinuityReceiptId>,
    inner: crate::handoff::AgentHandoffCapsule,
}

impl AgentHandoffCapsule {
    /// Builds a handoff at the exact claim-activation situation.
    ///
    /// A later observation, even one carrying the same task generation, is
    /// refused. Use [`Self::build_with_continuity`] with an explicit full-context
    /// continuity receipt for that case.
    ///
    /// # Errors
    ///
    /// Refuses a situation other than the claim's activation situation, then
    /// preserves every typed refusal of the internal capsule canonicalizer.
    pub fn build(
        activation_situation: &AgentSituationReceipt,
        plan: &AgentChangePlan,
        active_claim: ActiveTaskClaim,
        run: &IntentRun,
        reconciliation: RunReconciliationReport,
        spec: AgentHandoffCapsuleSpec,
    ) -> Result<Self, HandoffConstructionRefusal> {
        let observed = *activation_situation.situation_id().as_bytes();
        let expected = active_claim.situation_id();
        if observed != expected {
            return Err(HandoffConstructionRefusal::ClaimSituationMismatch {
                expected,
                observed,
            });
        }
        let inner = crate::handoff::AgentHandoffCapsule::build(
            activation_situation,
            plan,
            active_claim,
            run,
            reconciliation,
            spec,
        )
        .map_err(HandoffConstructionRefusal::Capsule)?;
        Self::finish(inner, None)
    }

    /// Builds a handoff at a later situation proven context-equivalent to claim
    /// activation.
    ///
    /// The continuity receipt is revalidated against the presented claim, later
    /// situation, and complete run. Its source situation must be the situation
    /// retained by the activated claim. The receipt identity is committed into
    /// the resulting public capsule.
    ///
    /// # Errors
    ///
    /// Refuses continuity, claim, situation, run, plan, reconciliation,
    /// attenuation, evidence, bound, and canonical-framing mismatches.
    pub fn build_with_continuity(
        later_situation: &AgentSituationReceipt,
        plan: &AgentChangePlan,
        active_claim: ActiveTaskClaim,
        continuity: ActiveClaimContinuityReceipt,
        run: &IntentRun,
        reconciliation: RunReconciliationReport,
        spec: AgentHandoffCapsuleSpec,
    ) -> Result<Self, HandoffConstructionRefusal> {
        validate_continuity_source(active_claim, continuity)?;
        continuity
            .validate_for(active_claim, later_situation, run)
            .map_err(HandoffConstructionRefusal::Continuity)?;
        let inner = crate::handoff::AgentHandoffCapsule::build(
            later_situation,
            plan,
            active_claim,
            run,
            reconciliation,
            spec,
        )
        .map_err(HandoffConstructionRefusal::Capsule)?;
        Self::finish(inner, Some(continuity.receipt_id()))
    }

    fn finish(
        inner: crate::handoff::AgentHandoffCapsule,
        claim_continuity_id: Option<ActiveClaimContinuityReceiptId>,
    ) -> Result<Self, HandoffConstructionRefusal> {
        let capsule_id = AgentHandoffCapsuleId(public_capsule_commitment(
            inner.capsule_id().as_bytes(),
            claim_continuity_id,
        )?);
        Ok(Self {
            capsule_id,
            claim_continuity_id,
            inner,
        })
    }

    /// Stable public capsule identity.
    #[must_use]
    pub const fn capsule_id(&self) -> AgentHandoffCapsuleId {
        self.capsule_id
    }

    /// Full-context continuity proof used for a later observation, if any.
    #[must_use]
    pub const fn claim_continuity_id(&self) -> Option<ActiveClaimContinuityReceiptId> {
        self.claim_continuity_id
    }

    /// Source Intent Run.
    #[must_use]
    pub const fn source_run_id(&self) -> RunId {
        self.inner.source_run_id()
    }

    /// Source agent executor.
    #[must_use]
    pub const fn source_instance_id(&self) -> AgentInstanceId {
        self.inner.source_instance_id()
    }

    /// Opaque, policy-defined receiver selector.
    #[must_use]
    pub const fn target_selector(&self) -> &[u8; 32] {
        self.inner.target_selector()
    }

    /// Latest situation observed before handoff.
    #[must_use]
    pub const fn latest_situation_id(&self) -> SituationId {
        self.inner.latest_situation_id()
    }

    /// Current change plan.
    #[must_use]
    pub const fn plan_id(&self) -> AgentChangePlanId {
        self.inner.plan_id()
    }

    /// Activated task claim permitting the current plan attempt.
    #[must_use]
    pub const fn active_claim_id(&self) -> ActiveTaskClaimId {
        self.inner.active_claim_id()
    }

    /// Workspace identity and manifest, when attached.
    #[must_use]
    pub const fn workspace(&self) -> Option<HandoffWorkspaceSnapshot> {
        self.inner.workspace()
    }

    /// Changed immutable object roots.
    #[must_use]
    pub fn changed_object_roots(&self) -> &[Digest] {
        self.inner.changed_object_roots()
    }

    /// Complete positional requirement dispositions.
    #[must_use]
    pub fn requirement_dispositions(&self) -> &[RequirementDisposition] {
        self.inner.requirement_dispositions()
    }

    /// Evidence references retained by the capsule.
    #[must_use]
    pub fn evidence_records(&self) -> &[crate::EvidenceRecordRef] {
        self.inner.evidence_records()
    }

    /// Verifier facts retained for independent classification.
    #[must_use]
    pub fn verifier_attestations(&self) -> &[VerifierAttestation] {
        self.inner.verifier_attestations()
    }

    /// Unresolved question commitments.
    #[must_use]
    pub fn unresolved_questions(&self) -> &[Digest] {
        self.inner.unresolved_questions()
    }

    /// Failed-approach commitments.
    #[must_use]
    pub fn failed_approaches(&self) -> &[Digest] {
        self.inner.failed_approaches()
    }

    /// Complete run-level reconciliation report.
    #[must_use]
    pub const fn reconciliation(&self) -> &RunReconciliationReport {
        self.inner.reconciliation()
    }

    /// Outstanding effects preserving complete records and typed next actions.
    pub fn outstanding_effects(&self) -> impl Iterator<Item = &ReconciledEffect> {
        self.inner.outstanding_effects()
    }

    /// Number of outstanding effects or containment failures.
    #[must_use]
    pub const fn outstanding_effect_count(&self) -> u32 {
        self.inner.outstanding_effect_count()
    }

    /// Highest-priority reconciliation action still required.
    #[must_use]
    pub const fn reconciliation_readiness(&self) -> RunReconciliationReadiness {
        self.inner.reconciliation_readiness()
    }

    /// Requested next-action commitments.
    #[must_use]
    pub fn requested_next_actions(&self) -> &[Digest] {
        self.inner.requested_next_actions()
    }

    /// Maximum receiver scope proposed by the source.
    #[must_use]
    pub const fn capability_attenuation(&self) -> HandoffCapabilityAttenuation {
        self.inner.capability_attenuation()
    }

    /// Resource consumption carried from the complete run effect inventory.
    #[must_use]
    pub const fn budget_consumed(&self) -> ResourceVector {
        self.inner.budget_consumed()
    }

    /// Explicit non-claims inherited from the plan.
    #[must_use]
    pub fn non_claims(&self) -> &[Digest] {
        self.inner.non_claims()
    }

    /// Commitment to producer attestation evidence.
    #[must_use]
    pub const fn producer_attestation_root(&self) -> Digest {
        self.inner.producer_attestation_root()
    }
}

/// Why public handoff construction failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoffConstructionRefusal {
    /// Exact-activation construction received another situation.
    ClaimSituationMismatch {
        /// Situation retained by the activated claim.
        expected: [u8; 32],
        /// Situation supplied to the constructor.
        observed: [u8; 32],
    },
    /// Full-context continuity proof was missing, substituted, or stale.
    Continuity(ActiveClaimContinuityRefusal),
    /// Internal capsule canonicalization refused the inputs.
    Capsule(crate::handoff::HandoffRefusal),
    /// Public proof-carrying identity framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for HandoffConstructionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaimSituationMismatch { .. } => formatter.write_str(
                "handoff requires the claim-activation situation or an explicit continuity receipt",
            ),
            Self::Continuity(refusal) => write!(formatter, "handoff continuity refused: {refusal}"),
            Self::Capsule(refusal) => write!(formatter, "handoff capsule refused: {refusal}"),
            Self::Codec(refusal) => write!(formatter, "public handoff framing refused: {refusal}"),
        }
    }
}

impl core::error::Error for HandoffConstructionRefusal {}

impl From<CodecRefusal> for HandoffConstructionRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

impl PartialEq<crate::handoff::HandoffRefusal> for HandoffConstructionRefusal {
    fn eq(&self, other: &crate::handoff::HandoffRefusal) -> bool {
        matches!(self, Self::Capsule(refusal) if refusal == other)
    }
}

impl PartialEq<HandoffConstructionRefusal> for crate::handoff::HandoffRefusal {
    fn eq(&self, other: &HandoffConstructionRefusal) -> bool {
        other == self
    }
}

fn validate_continuity_source(
    active_claim: ActiveTaskClaim,
    continuity: ActiveClaimContinuityReceipt,
) -> Result<(), HandoffConstructionRefusal> {
    let expected = active_claim.situation_id();
    let observed = *continuity.from_situation_id().as_bytes();
    if expected != observed {
        return Err(HandoffConstructionRefusal::Continuity(
            ActiveClaimContinuityRefusal::ActivationSituationMismatch {
                expected,
                observed,
            },
        ));
    }
    Ok(())
}

fn public_capsule_commitment(
    inner_capsule_id: &[u8; 32],
    claim_continuity_id: Option<ActiveClaimContinuityReceiptId>,
) -> Result<[u8; 32], HandoffConstructionRefusal> {
    let mut encoder = Encoder::with_capacity(160);
    encoder.write_bytes("public_handoff_domain", PUBLIC_HANDOFF_DOMAIN)?;
    encoder.write_raw(inner_capsule_id);
    match claim_continuity_id {
        Some(receipt_id) => {
            encoder.write_bool(true);
            encoder.write_raw(receipt_id.as_bytes());
        }
        None => encoder.write_bool(false),
    }
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}
