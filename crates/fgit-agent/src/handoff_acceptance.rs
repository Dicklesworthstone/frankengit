//! Receiver-side verification of an [`crate::AgentHandoffCapsule`].
//!
//! Constructing a capsule proves only what the source committed to. Acceptance
//! independently validates the receiver's authenticated situation and Intent
//! Run, applies the capsule's attenuation ceiling, and preserves every carried
//! effect responsibility. The capsule grants no authority; the receiver acts
//! only through its ordinary, already-issued run and capabilities.
//!
//! This slice accepts only the same authenticated authority-head identity and
//! generation as the source capsule. A later head may be valid, but proving its
//! ancestry needs an authenticated authority-history witness that this crate
//! does not yet carry. Failing closed is preferable to treating a larger
//! generation number as proof of descent.
//!
//! Task-claim transfer is deliberately not inferred here. The capsule commits
//! the source activation identity, but a receiver becomes task owner only after
//! the task-system adapter emits its own post-transfer projection receipt.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_resource::{ResourceError, ResourceVector};
use fgit_types::Digest;

use crate::{
    AgentHandoffCapsule, AgentHandoffCapsuleId, AgentInstanceId, AgentSituationReceipt,
    ClassSet, EffectId, EffectResolutionAction, IntentRun, LogicalTime, OperationClass, RunId,
    SituationId,
};

const ACCEPTANCE_DOMAIN: &[u8] = b"frankengit.agent.handoff-acceptance/v1\0";

/// Stable identity of one verified handoff acceptance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentHandoffAcceptanceId([u8; 32]);

impl AgentHandoffAcceptanceId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AgentHandoffAcceptanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("handoff-acceptance:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Authority relation currently supported by receiver acceptance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HandoffAuthorityRelation {
    /// Source and receiver independently authenticated the same head identity
    /// at the same generation.
    SameAuthenticatedHead,
}

impl HandoffAuthorityRelation {
    const fn code_point(self) -> u8 {
        match self {
            Self::SameAuthenticatedHead => 1,
        }
    }
}

/// Policy-owned evidence resolving an opaque target selector to one receiver.
///
/// This record does not authenticate the receiver. Authentication comes from
/// the receiver's Intent Run and situation receipt; this record proves only
/// which policy resolver said the selector names that receiver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffTargetResolution {
    target_selector: [u8; 32],
    receiver_run_id: RunId,
    receiver_instance_id: AgentInstanceId,
    resolver_identity: [u8; 32],
    evidence_root: Digest,
}

impl HandoffTargetResolution {
    /// Creates one complete selector-resolution observation.
    #[must_use]
    pub const fn new(
        target_selector: [u8; 32],
        receiver_run_id: RunId,
        receiver_instance_id: AgentInstanceId,
        resolver_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Self {
        Self {
            target_selector,
            receiver_run_id,
            receiver_instance_id,
            resolver_identity,
            evidence_root,
        }
    }

    /// Selector resolved.
    #[must_use]
    pub const fn target_selector(self) -> [u8; 32] {
        self.target_selector
    }

    /// Receiver run selected.
    #[must_use]
    pub const fn receiver_run_id(self) -> RunId {
        self.receiver_run_id
    }

    /// Receiver executor selected.
    #[must_use]
    pub const fn receiver_instance_id(self) -> AgentInstanceId {
        self.receiver_instance_id
    }

    /// Resolver implementation/profile identity.
    #[must_use]
    pub const fn resolver_identity(self) -> [u8; 32] {
        self.resolver_identity
    }

    /// Resolution evidence commitment.
    #[must_use]
    pub const fn evidence_root(self) -> Digest {
        self.evidence_root
    }
}

/// One outstanding effect responsibility inherited from the source capsule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffEffectResponsibility {
    effect_id: EffectId,
    operation: OperationClass,
    required_action: EffectResolutionAction,
}

impl HandoffEffectResponsibility {
    /// Effect identity.
    #[must_use]
    pub const fn effect_id(self) -> EffectId {
        self.effect_id
    }

    /// Operation class the receiver must be able to resolve.
    #[must_use]
    pub const fn operation(self) -> OperationClass {
        self.operation
    }

    /// Exact lifecycle action still required.
    #[must_use]
    pub const fn required_action(self) -> EffectResolutionAction {
        self.required_action
    }
}

/// Verified receiver-side acceptance of one capsule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentHandoffAcceptance {
    acceptance_id: AgentHandoffAcceptanceId,
    capsule_id: AgentHandoffCapsuleId,
    receiver_situation_id: SituationId,
    receiver_run_id: RunId,
    receiver_instance_id: AgentInstanceId,
    accepted_at: LogicalTime,
    authority_relation: HandoffAuthorityRelation,
    receiver_operations: ClassSet,
    receiver_budget: ResourceVector,
    receiver_expiry: LogicalTime,
    target_resolution: HandoffTargetResolution,
    effect_responsibilities: Vec<HandoffEffectResponsibility>,
}

impl AgentHandoffCapsule {
    /// Verifies one receiver against this capsule.
    ///
    /// # Errors
    ///
    /// Refuses source-run reuse, missing or mismatched authority, a receiver
    /// situation from another run, stale observation, expired receiver scope,
    /// operation/budget/expiry amplification, a receiver unable to resolve
    /// carried effect debt, invalid selector-resolution evidence, and
    /// unrepresentable canonical framing.
    pub fn accept(
        &self,
        receiver_situation: &AgentSituationReceipt,
        receiver_run: &IntentRun,
        receiver_instance_id: AgentInstanceId,
        target_resolution: HandoffTargetResolution,
    ) -> Result<AgentHandoffAcceptance, HandoffAcceptanceRefusal> {
        if receiver_run.run_id() == self.source_run_id() {
            return Err(HandoffAcceptanceRefusal::SourceRunReuse);
        }
        if receiver_instance_id.value() == 0 {
            return Err(HandoffAcceptanceRefusal::ZeroReceiverInstance);
        }
        if receiver_situation.intent_run_id() != Some(receiver_run.run_id()) {
            return Err(HandoffAcceptanceRefusal::ReceiverSituationRunMismatch);
        }
        let receiver_authority = receiver_run
            .authority_read_receipt()
            .ok_or(HandoffAcceptanceRefusal::ReceiverAuthorityReceiptRequired)?;
        if receiver_authority != receiver_situation.authority_read_receipt() {
            return Err(HandoffAcceptanceRefusal::ReceiverAuthorityMismatch);
        }
        let source_authority = self.reconciliation().authority_read_receipt();
        if source_authority.repository_id() != receiver_authority.repository_id() {
            return Err(HandoffAcceptanceRefusal::RepositoryMismatch);
        }
        if source_authority.authority_head_generation()
            != receiver_authority.authority_head_generation()
            || source_authority.authority_head_id() != receiver_authority.authority_head_id()
        {
            return Err(HandoffAcceptanceRefusal::AuthorityHistoryWitnessRequired);
        }
        if receiver_situation.observed_at() < self.reconciliation().observed_at() {
            return Err(HandoffAcceptanceRefusal::ReceiverObservationRollback {
                source_observed_at: self.reconciliation().observed_at(),
                receiver_observed_at: receiver_situation.observed_at(),
            });
        }
        if !receiver_run.is_open_at(receiver_situation.observed_at()) {
            return Err(HandoffAcceptanceRefusal::ReceiverRunExpired {
                expires_at: receiver_run.expiry(),
                observed_at: receiver_situation.observed_at(),
            });
        }

        validate_target_resolution(self, receiver_run, receiver_instance_id, target_resolution)?;
        validate_receiver_scope(self, receiver_run)?;

        let effect_responsibilities = self
            .outstanding_effects()
            .map(|effect| HandoffEffectResponsibility {
                effect_id: effect.record().effect_id,
                operation: effect.record().operation,
                required_action: effect.required_action(),
            })
            .collect();

        let mut acceptance = AgentHandoffAcceptance {
            acceptance_id: AgentHandoffAcceptanceId([0; 32]),
            capsule_id: self.capsule_id(),
            receiver_situation_id: receiver_situation.situation_id(),
            receiver_run_id: receiver_run.run_id(),
            receiver_instance_id,
            accepted_at: receiver_situation.observed_at(),
            authority_relation: HandoffAuthorityRelation::SameAuthenticatedHead,
            receiver_operations: receiver_run.allowed_operation_classes(),
            receiver_budget: receiver_run.resource_budget(),
            receiver_expiry: receiver_run.expiry(),
            target_resolution,
            effect_responsibilities,
        };
        acceptance.acceptance_id =
            AgentHandoffAcceptanceId(acceptance_commitment(&acceptance)?);
        Ok(acceptance)
    }
}

impl AgentHandoffAcceptance {
    /// Stable acceptance identity.
    #[must_use]
    pub const fn acceptance_id(&self) -> AgentHandoffAcceptanceId {
        self.acceptance_id
    }

    /// Capsule accepted.
    #[must_use]
    pub const fn capsule_id(&self) -> AgentHandoffCapsuleId {
        self.capsule_id
    }

    /// Receiver situation used for independent verification.
    #[must_use]
    pub const fn receiver_situation_id(&self) -> SituationId {
        self.receiver_situation_id
    }

    /// Receiver Intent Run.
    #[must_use]
    pub const fn receiver_run_id(&self) -> RunId {
        self.receiver_run_id
    }

    /// Receiver executor.
    #[must_use]
    pub const fn receiver_instance_id(&self) -> AgentInstanceId {
        self.receiver_instance_id
    }

    /// Logical acceptance instant.
    #[must_use]
    pub const fn accepted_at(&self) -> LogicalTime {
        self.accepted_at
    }

    /// Proven authority relationship.
    #[must_use]
    pub const fn authority_relation(&self) -> HandoffAuthorityRelation {
        self.authority_relation
    }

    /// Receiver operation scope committed into the acceptance.
    #[must_use]
    pub const fn receiver_operations(&self) -> ClassSet {
        self.receiver_operations
    }

    /// Receiver resource budget committed into the acceptance.
    #[must_use]
    pub const fn receiver_budget(&self) -> ResourceVector {
        self.receiver_budget
    }

    /// Receiver run expiry committed into the acceptance.
    #[must_use]
    pub const fn receiver_expiry(&self) -> LogicalTime {
        self.receiver_expiry
    }

    /// Target-selector evidence.
    #[must_use]
    pub const fn target_resolution(&self) -> HandoffTargetResolution {
        self.target_resolution
    }

    /// Outstanding effect responsibilities inherited by the receiver.
    #[must_use]
    pub fn effect_responsibilities(&self) -> &[HandoffEffectResponsibility] {
        &self.effect_responsibilities
    }
}

/// Why receiver-side handoff acceptance failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoffAcceptanceRefusal {
    /// Receiver attempted to reuse the source run identity.
    SourceRunReuse,
    /// Receiver executor used the reserved zero identity.
    ZeroReceiverInstance,
    /// Receiver situation names another run.
    ReceiverSituationRunMismatch,
    /// Receiver run lacks a complete authenticated authority receipt.
    ReceiverAuthorityReceiptRequired,
    /// Receiver situation and run use different authority receipts.
    ReceiverAuthorityMismatch,
    /// Source and receiver belong to different repositories.
    RepositoryMismatch,
    /// Receiver observed another head and supplied no ancestry witness.
    AuthorityHistoryWitnessRequired,
    /// Receiver observation predates the source capsule observation.
    ReceiverObservationRollback {
        /// Source observation.
        source_observed_at: LogicalTime,
        /// Receiver observation.
        receiver_observed_at: LogicalTime,
    },
    /// Receiver run is expired at acceptance.
    ReceiverRunExpired {
        /// Exclusive receiver expiry.
        expires_at: LogicalTime,
        /// Acceptance observation.
        observed_at: LogicalTime,
    },
    /// Selector evidence names another selector.
    TargetSelectorMismatch,
    /// Selector evidence names another run.
    TargetRunMismatch,
    /// Selector evidence names another executor.
    TargetInstanceMismatch,
    /// Selector resolver used the reserved all-zero identity.
    ZeroResolverIdentity,
    /// Receiver operation scope exceeds the capsule attenuation.
    OperationAmplification {
        /// Operation classes absent from the attenuation ceiling.
        missing: ClassSet,
    },
    /// Receiver resource budget exceeds the capsule attenuation.
    BudgetAmplification {
        /// First deficient resource grade.
        deficit: ResourceError,
    },
    /// Receiver expiry exceeds the capsule attenuation.
    ExpiryAmplification {
        /// Receiver expiry.
        receiver_expiry: LogicalTime,
        /// Maximum capsule expiry.
        capsule_expiry: LogicalTime,
    },
    /// Receiver scope cannot resolve one carried effect responsibility.
    CannotResolveEffect {
        /// Carried effect.
        effect_id: EffectId,
        /// Required operation class.
        operation: OperationClass,
    },
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for HandoffAcceptanceRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "handoff acceptance refused: {self:?}")
    }
}

impl core::error::Error for HandoffAcceptanceRefusal {}

impl From<CodecRefusal> for HandoffAcceptanceRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_target_resolution(
    capsule: &AgentHandoffCapsule,
    receiver_run: &IntentRun,
    receiver_instance_id: AgentInstanceId,
    resolution: HandoffTargetResolution,
) -> Result<(), HandoffAcceptanceRefusal> {
    if resolution.target_selector != *capsule.target_selector() {
        return Err(HandoffAcceptanceRefusal::TargetSelectorMismatch);
    }
    if resolution.receiver_run_id != receiver_run.run_id() {
        return Err(HandoffAcceptanceRefusal::TargetRunMismatch);
    }
    if resolution.receiver_instance_id != receiver_instance_id {
        return Err(HandoffAcceptanceRefusal::TargetInstanceMismatch);
    }
    if is_zero(&resolution.resolver_identity) {
        return Err(HandoffAcceptanceRefusal::ZeroResolverIdentity);
    }
    Ok(())
}

fn validate_receiver_scope(
    capsule: &AgentHandoffCapsule,
    receiver_run: &IntentRun,
) -> Result<(), HandoffAcceptanceRefusal> {
    let attenuation = capsule.capability_attenuation();
    let operations = receiver_run.allowed_operation_classes();
    if !operations.is_subset_of(attenuation.operations()) {
        return Err(HandoffAcceptanceRefusal::OperationAmplification {
            missing: operations.difference(attenuation.operations()),
        });
    }
    if let Some(deficit) = attenuation
        .resource_budget()
        .first_deficit(&receiver_run.resource_budget())
    {
        return Err(HandoffAcceptanceRefusal::BudgetAmplification { deficit });
    }
    if receiver_run.expiry() > attenuation.expiry() {
        return Err(HandoffAcceptanceRefusal::ExpiryAmplification {
            receiver_expiry: receiver_run.expiry(),
            capsule_expiry: attenuation.expiry(),
        });
    }
    for effect in capsule.outstanding_effects() {
        if !operations.contains(effect.record().operation) {
            return Err(HandoffAcceptanceRefusal::CannotResolveEffect {
                effect_id: effect.record().effect_id,
                operation: effect.record().operation,
            });
        }
    }
    Ok(())
}

fn acceptance_commitment(
    acceptance: &AgentHandoffAcceptance,
) -> Result<[u8; 32], HandoffAcceptanceRefusal> {
    let mut encoder = Encoder::with_capacity(512);
    encoder.write_bytes("handoff_acceptance_domain", ACCEPTANCE_DOMAIN)?;
    encoder.write_raw(acceptance.capsule_id.as_bytes());
    encoder.write_raw(acceptance.receiver_situation_id.as_bytes());
    encoder.write_raw(&acceptance.receiver_run_id.value().to_be_bytes());
    encoder.write_raw(&acceptance.receiver_instance_id.value().to_be_bytes());
    encoder.write_scalar(acceptance.accepted_at.value());
    encoder.write_raw_byte(acceptance.authority_relation.code_point());
    encoder.write_scalar(acceptance.receiver_operations.bits());
    for (_grade, amount) in acceptance.receiver_budget.pairs() {
        encoder.write_scalar(amount);
    }
    encoder.write_scalar(acceptance.receiver_expiry.value());
    encoder.write_raw(&acceptance.target_resolution.target_selector);
    encoder.write_raw(&acceptance.target_resolution.receiver_run_id.value().to_be_bytes());
    encoder.write_raw(
        &acceptance
            .target_resolution
            .receiver_instance_id
            .value()
            .to_be_bytes(),
    );
    encoder.write_raw(&acceptance.target_resolution.resolver_identity);
    encoder.write_digest(&acceptance.target_resolution.evidence_root)?;
    write_count(
        &mut encoder,
        "handoff_acceptance.effect_responsibilities",
        acceptance.effect_responsibilities.len(),
    )?;
    for responsibility in &acceptance.effect_responsibilities {
        encoder.write_raw(&responsibility.effect_id.value().to_be_bytes());
        encoder.write_scalar(operation_code(responsibility.operation));
        encoder.write_raw_byte(action_code(responsibility.required_action));
    }
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn write_count(
    encoder: &mut Encoder,
    field: &'static str,
    count: usize,
) -> Result<(), HandoffAcceptanceRefusal> {
    let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(count).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    Ok(())
}

const fn action_code(action: EffectResolutionAction) -> u8 {
    match action {
        EffectResolutionAction::NoFurtherAction => 1,
        EffectResolutionAction::AbortReservation => 2,
        EffectResolutionAction::ReconcileCommittedEffect => 3,
        EffectResolutionAction::ResolveEscalation => 4,
        EffectResolutionAction::ContainLeak => 5,
    }
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

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
