//! Cross-head task ownership transfer with two authenticated authority bases.
//!
//! Same-head task claim, release, and transfer use the ordinary
//! [`crate::TaskProjectionMutationEnvelope`], whose predecessor and successor
//! intentionally share one authenticated authority basis. A receiver handoff
//! accepted at a proven descendant head cannot soundly reuse that envelope:
//! the source lease belongs to the historical head while the successor
//! assignment belongs to the receiver's current head.
//!
//! This module keeps those facts separate. [`CrossHeadTaskTransferEnvelope`]
//! retains:
//!
//! - the historical source task snapshot and active lease;
//! - the source claim, handoff capsule, and accepted descendant proof;
//! - a fresh receiver-basis observation of the same semantic predecessor;
//! - a deterministic receiver-basis successor assignment;
//! - both complete Intent Run identities;
//! - one explicit source cancellation projection.
//!
//! Durable execution occurs only against the receiver-basis predecessor. The
//! historical snapshot is proof, not a compare-and-replace target. The store
//! protocol performs at most one exact-predecessor replacement, never retries
//! an ambiguous write, and requires an authenticated reread carrying the exact
//! envelope, acceptance, ancestry, and evidence identities.
//!
//! A confirmed transfer is still only an assignment preference. The receiver
//! must build and persist a new plan and claim. The optional
//! [`CrossHeadTaskTransferActivationReceipt`] proves that ordinary persisted
//! claim and fresh activation started from the exact transfer generation
//! without inheriting the source plan.
//!
//! Task projections remain derived coordination state. No value in this module
//! publishes repository authority or mints a capability.

use core::fmt;

use fgit_authority::AuthorityHeadAncestryReceiptId;
use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::{Digest, RepositoryId};

use crate::{
    ActiveTaskClaim, ActiveTaskClaimId, AgentChangePlanId, AgentHandoffAcceptance,
    AgentHandoffAcceptanceId, AgentHandoffCapsule, AgentHandoffCapsuleId,
    AgentSituationReceipt, AuthorityBoundTaskProjectionSnapshot,
    AuthorityBoundTaskProjectionSnapshotId, AuthorityReadIdentityRefusal,
    AuthorityReadReceipt, AuthorityReadReceiptId, HandoffAuthorityRelation, IntentRun,
    IntentRunCommitment, IntentRunIdentityRefusal, LogicalTime, PersistedTaskClaim,
    SituationComponentKind, SituationId, TaskClaimCancellationOutcome,
    TaskClaimCancellationProjection, TaskClaimReceipt, TaskClaimReceiptId,
    TaskCoordinationRefusal, TaskProjectionAssignment, TaskProjectionLease,
    TaskProjectionPersistenceReceiptId, TaskProjectionStoreFlushDisposition,
    TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal,
    TaskProjectionStoreKey, TaskProjectionStoreReadRefusal, TaskProjectionStoreStage,
    TaskProjectionStoreWriteDisposition, TaskProjectionStoreWriteOutcome,
    TaskProjectionStoreWriteRefusal, WorkTaskId,
};

const GENERATION_DOMAIN: &[u8] =
    b"frankengit.agent.cross-head-task-transfer-generation/v1\0";
const ENVELOPE_DOMAIN: &[u8] =
    b"frankengit.agent.cross-head-task-transfer-envelope/v1\0";
const RECEIPT_DOMAIN: &[u8] =
    b"frankengit.agent.cross-head-task-transfer-receipt/v1\0";
const ACTIVATION_DOMAIN: &[u8] =
    b"frankengit.agent.cross-head-task-transfer-activation/v1\0";

/// Stable identity of one two-authority-basis transfer envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CrossHeadTaskTransferEnvelopeId([u8; 32]);

impl CrossHeadTaskTransferEnvelopeId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CrossHeadTaskTransferEnvelopeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cross-head-task-transfer:")?;
        write_hex(formatter, &self.0)
    }
}

/// Stable identity of one confirmed cross-head transfer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CrossHeadTaskTransferReceiptId([u8; 32]);

impl CrossHeadTaskTransferReceiptId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CrossHeadTaskTransferReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cross-head-task-transferred:")?;
        write_hex(formatter, &self.0)
    }
}

/// Stable identity proving the receiver subsequently acquired an ordinary,
/// persisted claim from the exact transferred generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CrossHeadTaskTransferActivationReceiptId([u8; 32]);

impl CrossHeadTaskTransferActivationReceiptId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CrossHeadTaskTransferActivationReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cross-head-task-transfer-activation:")?;
        write_hex(formatter, &self.0)
    }
}

/// Complete proof-carrying transfer from a historical source lease to a
/// descendant-head receiver assignment preference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossHeadTaskTransferEnvelope {
    envelope_id: CrossHeadTaskTransferEnvelopeId,
    repository_id: RepositoryId,
    task_id: WorkTaskId,
    source_authority_read_receipt_id: AuthorityReadReceiptId,
    receiver_authority_read_receipt_id: AuthorityReadReceiptId,
    source_snapshot: AuthorityBoundTaskProjectionSnapshot,
    receiver_predecessor: AuthorityBoundTaskProjectionSnapshot,
    receiver_successor: AuthorityBoundTaskProjectionSnapshot,
    source_claim_id: TaskClaimReceiptId,
    source_active_claim_id: ActiveTaskClaimId,
    source_plan_id: AgentChangePlanId,
    capsule_id: AgentHandoffCapsuleId,
    acceptance_id: AgentHandoffAcceptanceId,
    ancestry_receipt_id: AuthorityHeadAncestryReceiptId,
    source_run_id: crate::RunId,
    source_run_commitment: IntentRunCommitment,
    receiver_run_id: crate::RunId,
    receiver_run_commitment: IntentRunCommitment,
    transferred_at: LogicalTime,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
    cancellation_projection: TaskClaimCancellationProjection,
}

impl CrossHeadTaskTransferEnvelope {
    /// Builds one cross-head task transfer.
    ///
    /// The source snapshot remains historical proof. The receiver predecessor
    /// must independently observe the same semantic task row under the exact
    /// descendant authority basis retained by the accepted receiver. The
    /// resulting successor is built under that receiver basis, contains no
    /// active lease, and assigns only a preference for the receiver's complete
    /// Intent Run.
    ///
    /// The source run may already be expired because transfer reduces its
    /// responsibility. The receiver run must be live at `transferred_at`.
    ///
    /// # Errors
    ///
    /// Refuses source lease, claim, active-claim, capsule, acceptance,
    /// descendant proof, receiver situation, authority basis, semantic task,
    /// complete-run, time, adapter, and canonical-framing substitution.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        source_snapshot: &AuthorityBoundTaskProjectionSnapshot,
        source_claim: &TaskClaimReceipt,
        source_active_claim: ActiveTaskClaim,
        source_run: &IntentRun,
        capsule: &AgentHandoffCapsule,
        acceptance: &AgentHandoffAcceptance,
        receiver_situation: &AgentSituationReceipt,
        receiver_predecessor: &AuthorityBoundTaskProjectionSnapshot,
        receiver_run: &IntentRun,
        transferred_at: LogicalTime,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Result<Self, CrossHeadTaskTransferRefusal> {
        if is_zero(&adapter_identity) {
            return Err(CrossHeadTaskTransferRefusal::ZeroAdapterIdentity);
        }
        if adapter_identity != *source_claim.adapter_identity() {
            return Err(CrossHeadTaskTransferRefusal::SourceAdapterMismatch {
                expected: *source_claim.adapter_identity(),
                observed: adapter_identity,
            });
        }

        let source_authority = source_run
            .authority_read_receipt()
            .ok_or(CrossHeadTaskTransferRefusal::SourceAuthorityReceiptRequired)?;
        let receiver_authority = receiver_run
            .authority_read_receipt()
            .ok_or(CrossHeadTaskTransferRefusal::ReceiverAuthorityReceiptRequired)?;
        let source_run_commitment = source_run
            .commitment()
            .map_err(CrossHeadTaskTransferRefusal::SourceRunIdentity)?;
        let receiver_run_commitment = receiver_run
            .commitment()
            .map_err(CrossHeadTaskTransferRefusal::ReceiverRunIdentity)?;

        if source_authority.repository_id() != receiver_authority.repository_id() {
            return Err(CrossHeadTaskTransferRefusal::RepositoryMismatch {
                source: source_authority.repository_id(),
                receiver: receiver_authority.repository_id(),
            });
        }
        if source_snapshot.authority_read_receipt() != source_authority {
            return Err(CrossHeadTaskTransferRefusal::SourceSnapshotAuthorityMismatch);
        }
        if receiver_predecessor.authority_read_receipt() != receiver_authority {
            return Err(CrossHeadTaskTransferRefusal::ReceiverSnapshotAuthorityMismatch);
        }
        if source_snapshot.repository_id() != source_authority.repository_id()
            || receiver_predecessor.repository_id() != source_authority.repository_id()
        {
            return Err(CrossHeadTaskTransferRefusal::SnapshotRepositoryMismatch);
        }

        validate_source_lease(
            source_snapshot,
            source_claim,
            source_active_claim,
            source_run,
            source_run_commitment,
        )?;
        validate_handoff(
            source_snapshot,
            source_claim,
            source_active_claim,
            source_run,
            source_run_commitment,
            capsule,
            acceptance,
            receiver_situation,
            receiver_predecessor,
            receiver_run,
            receiver_run_commitment,
        )?;

        if transferred_at < source_snapshot.observed_at()
            || transferred_at < source_active_claim.observed_at()
            || transferred_at < capsule.reconciliation().observed_at()
        {
            return Err(CrossHeadTaskTransferRefusal::TransferBeforeSourceEvidence);
        }
        if transferred_at < acceptance.accepted_at()
            || transferred_at < receiver_predecessor.observed_at()
        {
            return Err(CrossHeadTaskTransferRefusal::TransferBeforeReceiverEvidence);
        }
        if !receiver_run.is_open_at(transferred_at) {
            return Err(CrossHeadTaskTransferRefusal::ReceiverRunExpired {
                expires_at: receiver_run.expiry(),
                transferred_at,
            });
        }

        validate_semantic_predecessor(source_snapshot, receiver_predecessor)?;

        let ancestry = acceptance
            .authority_ancestry()
            .ok_or(CrossHeadTaskTransferRefusal::DescendantAncestryRequired)?;
        let source_authority_read_receipt_id = source_authority.receipt_id()?;
        let receiver_authority_read_receipt_id = receiver_authority.receipt_id()?;
        let next_generation = derive_transfer_generation(
            source_snapshot,
            receiver_predecessor,
            source_claim,
            source_active_claim,
            capsule,
            acceptance,
            ancestry.receipt_id(),
            source_run.run_id(),
            source_run_commitment,
            receiver_run.run_id(),
            receiver_run_commitment,
            transferred_at,
        )?;
        if is_zero(&next_generation) || next_generation == *receiver_predecessor.generation() {
            return Err(CrossHeadTaskTransferRefusal::SuccessorGenerationDidNotAdvance);
        }

        let receiver_successor = AuthorityBoundTaskProjectionSnapshot::observed(
            receiver_authority,
            source_snapshot.task_id(),
            next_generation,
            source_snapshot.phase(),
            TaskProjectionAssignment::assigned(
                receiver_run.run_id(),
                receiver_run_commitment,
            ),
            transferred_at,
        )?;

        let cancellation_projection = TaskClaimCancellationProjection::new(
            source_active_claim.activation_id(),
            source_claim.claim_id(),
            source_claim.plan_id(),
            source_claim.task_id(),
            source_claim.assignee(),
            *source_snapshot.generation(),
            next_generation,
            transferred_at,
            TaskClaimCancellationOutcome::Transferred {
                successor_run_id: receiver_run.run_id(),
            },
            adapter_identity,
            evidence_root,
        );

        let mut envelope = Self {
            envelope_id: CrossHeadTaskTransferEnvelopeId([0; 32]),
            repository_id: source_authority.repository_id(),
            task_id: source_snapshot.task_id(),
            source_authority_read_receipt_id,
            receiver_authority_read_receipt_id,
            source_snapshot: source_snapshot.clone(),
            receiver_predecessor: receiver_predecessor.clone(),
            receiver_successor,
            source_claim_id: source_claim.claim_id(),
            source_active_claim_id: source_active_claim.activation_id(),
            source_plan_id: source_claim.plan_id(),
            capsule_id: capsule.capsule_id(),
            acceptance_id: acceptance.acceptance_id(),
            ancestry_receipt_id: ancestry.receipt_id(),
            source_run_id: source_run.run_id(),
            source_run_commitment,
            receiver_run_id: receiver_run.run_id(),
            receiver_run_commitment,
            transferred_at,
            adapter_identity,
            evidence_root,
            cancellation_projection,
        };
        envelope.envelope_id =
            CrossHeadTaskTransferEnvelopeId(envelope_commitment(&envelope)?);
        Ok(envelope)
    }

    /// Stable idempotency identity.
    #[must_use]
    pub const fn envelope_id(&self) -> CrossHeadTaskTransferEnvelopeId {
        self.envelope_id
    }

    /// Repository namespace.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Task whose assignment is transferred.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.task_id
    }

    /// Exact historical authority read for the source lease.
    #[must_use]
    pub const fn source_authority_read_receipt_id(&self) -> AuthorityReadReceiptId {
        self.source_authority_read_receipt_id
    }

    /// Exact descendant authority read governing the durable mutation.
    #[must_use]
    pub const fn receiver_authority_read_receipt_id(&self) -> AuthorityReadReceiptId {
        self.receiver_authority_read_receipt_id
    }

    /// Historical source snapshot retained as proof.
    #[must_use]
    pub const fn source_snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.source_snapshot
    }

    /// Exact receiver-basis predecessor compared by the task store.
    #[must_use]
    pub const fn receiver_predecessor(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.receiver_predecessor
    }

    /// Desired receiver-basis successor assignment.
    #[must_use]
    pub const fn receiver_successor(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.receiver_successor
    }

    /// Source claim receipt.
    #[must_use]
    pub const fn source_claim_id(&self) -> TaskClaimReceiptId {
        self.source_claim_id
    }

    /// Source claim activation.
    #[must_use]
    pub const fn source_active_claim_id(&self) -> ActiveTaskClaimId {
        self.source_active_claim_id
    }

    /// Source plan. The receiver must not reuse it as its new claim plan.
    #[must_use]
    pub const fn source_plan_id(&self) -> AgentChangePlanId {
        self.source_plan_id
    }

    /// Handoff capsule authorizing no effects but carrying source responsibility.
    #[must_use]
    pub const fn capsule_id(&self) -> AgentHandoffCapsuleId {
        self.capsule_id
    }

    /// Receiver acceptance of the exact capsule.
    #[must_use]
    pub const fn acceptance_id(&self) -> AgentHandoffAcceptanceId {
        self.acceptance_id
    }

    /// Exact bounded descendant proof retained by the acceptance.
    #[must_use]
    pub const fn ancestry_receipt_id(&self) -> AuthorityHeadAncestryReceiptId {
        self.ancestry_receipt_id
    }

    /// Historical source run coordination identity.
    #[must_use]
    pub const fn source_run_id(&self) -> crate::RunId {
        self.source_run_id
    }

    /// Historical source complete run identity.
    #[must_use]
    pub const fn source_run_commitment(&self) -> IntentRunCommitment {
        self.source_run_commitment
    }

    /// Receiver run coordination identity.
    #[must_use]
    pub const fn receiver_run_id(&self) -> crate::RunId {
        self.receiver_run_id
    }

    /// Receiver complete run identity.
    #[must_use]
    pub const fn receiver_run_commitment(&self) -> IntentRunCommitment {
        self.receiver_run_commitment
    }

    /// Logical transfer instant.
    #[must_use]
    pub const fn transferred_at(&self) -> LogicalTime {
        self.transferred_at
    }

    /// Durable task adapter profile.
    #[must_use]
    pub const fn adapter_identity(&self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Predeclared transfer evidence contract.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }

    /// Source cancellation projection made usable only after persistence.
    #[must_use]
    pub const fn cancellation_projection(&self) -> TaskClaimCancellationProjection {
        self.cancellation_projection
    }

    /// Exact predecessor task generation under both authority bases.
    #[must_use]
    pub const fn previous_generation(&self) -> [u8; 32] {
        *self.receiver_predecessor.generation()
    }

    /// Receiver assignment generation.
    #[must_use]
    pub const fn resulting_generation(&self) -> [u8; 32] {
        *self.receiver_successor.generation()
    }

    /// Interprets one authenticated task-store reread.
    ///
    /// # Errors
    ///
    /// Refuses missing, cross-repository, cross-task, wrong-authority,
    /// rollback, partial-metadata, or substituted-successor observations.
    pub fn reconcile(
        &self,
        observed: Option<&CrossHeadTaskTransferPersistedState>,
    ) -> Result<CrossHeadTaskTransferDecision, CrossHeadTaskTransferRefusal> {
        let observed =
            observed.ok_or(CrossHeadTaskTransferRefusal::ProjectionMissing)?;
        let snapshot = observed.snapshot();
        if snapshot.repository_id() != self.repository_id {
            return Err(CrossHeadTaskTransferRefusal::ObservedRepositoryMismatch {
                expected: self.repository_id,
                observed: snapshot.repository_id(),
            });
        }
        if snapshot.task_id() != self.task_id {
            return Err(CrossHeadTaskTransferRefusal::ObservedTaskMismatch {
                expected: self.task_id,
                observed: snapshot.task_id(),
            });
        }
        if !same_receiver_authority_position(
            self.receiver_successor.authority_read_receipt(),
            snapshot.authority_read_receipt(),
        ) {
            return Err(CrossHeadTaskTransferRefusal::ObservedReceiverAuthorityMismatch);
        }
        if snapshot.observed_at() < self.transferred_at {
            return Err(CrossHeadTaskTransferRefusal::ObservationRollback {
                transferred_at: self.transferred_at,
                observed_at: snapshot.observed_at(),
            });
        }

        if semantic_snapshot_matches(&self.receiver_predecessor, snapshot) {
            if observed.last_envelope_id.is_some()
                || observed.acceptance_id.is_some()
                || observed.ancestry_receipt_id.is_some()
            {
                return Err(
                    CrossHeadTaskTransferRefusal::PredecessorCarriesTransferMetadata,
                );
            }
            return Ok(CrossHeadTaskTransferDecision::RetrySafe {
                envelope_id: self.envelope_id,
                current_snapshot_id: snapshot.snapshot_id(),
                current_generation: *snapshot.generation(),
            });
        }

        if semantic_snapshot_matches(&self.receiver_successor, snapshot) {
            validate_successor_metadata(self, observed)?;
            return Ok(CrossHeadTaskTransferDecision::Confirmed(
                CrossHeadTaskTransferReceipt::build(self, observed)?,
            ));
        }

        Ok(CrossHeadTaskTransferDecision::Conflict {
            envelope_id: self.envelope_id,
            current_snapshot_id: snapshot.snapshot_id(),
            current_generation: *snapshot.generation(),
        })
    }
}

/// Authenticated durable task row plus metadata specific to one cross-head
/// transfer attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossHeadTaskTransferPersistedState {
    snapshot: AuthorityBoundTaskProjectionSnapshot,
    last_envelope_id: Option<CrossHeadTaskTransferEnvelopeId>,
    acceptance_id: Option<AgentHandoffAcceptanceId>,
    ancestry_receipt_id: Option<AuthorityHeadAncestryReceiptId>,
    evidence_root: Option<Digest>,
}

impl CrossHeadTaskTransferPersistedState {
    /// Creates one structurally typed store observation.
    #[must_use]
    pub const fn new(
        snapshot: AuthorityBoundTaskProjectionSnapshot,
        last_envelope_id: Option<CrossHeadTaskTransferEnvelopeId>,
        acceptance_id: Option<AgentHandoffAcceptanceId>,
        ancestry_receipt_id: Option<AuthorityHeadAncestryReceiptId>,
        evidence_root: Option<Digest>,
    ) -> Self {
        Self {
            snapshot,
            last_envelope_id,
            acceptance_id,
            ancestry_receipt_id,
            evidence_root,
        }
    }

    /// Complete receiver-basis task snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.snapshot
    }

    /// Last cross-head envelope retained by the backend.
    #[must_use]
    pub const fn last_envelope_id(&self) -> Option<CrossHeadTaskTransferEnvelopeId> {
        self.last_envelope_id
    }

    /// Handoff acceptance retained beside the successor.
    #[must_use]
    pub const fn acceptance_id(&self) -> Option<AgentHandoffAcceptanceId> {
        self.acceptance_id
    }

    /// Authority ancestry receipt retained beside the successor.
    #[must_use]
    pub const fn ancestry_receipt_id(&self) -> Option<AuthorityHeadAncestryReceiptId> {
        self.ancestry_receipt_id
    }

    /// Transfer evidence contract retained beside the successor.
    #[must_use]
    pub const fn evidence_root(&self) -> Option<Digest> {
        self.evidence_root
    }
}

/// Complete-state interpretation of one receiver-basis reread.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossHeadTaskTransferDecision {
    /// Exact successor and all proof metadata were observed.
    Confirmed(CrossHeadTaskTransferReceipt),
    /// Exact predecessor remains current and carries no attempted metadata.
    RetrySafe {
        /// Envelope that has not been observed.
        envelope_id: CrossHeadTaskTransferEnvelopeId,
        /// Current predecessor snapshot.
        current_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
        /// Current predecessor generation.
        current_generation: [u8; 32],
    },
    /// Another semantic task state is current.
    Conflict {
        /// Envelope not applied.
        envelope_id: CrossHeadTaskTransferEnvelopeId,
        /// Current conflicting snapshot.
        current_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
        /// Current conflicting generation.
        current_generation: [u8; 32],
    },
}

/// Immutable confirmation that the receiver-basis successor was persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossHeadTaskTransferReceipt {
    receipt_id: CrossHeadTaskTransferReceiptId,
    envelope_id: CrossHeadTaskTransferEnvelopeId,
    source_authority_read_receipt_id: AuthorityReadReceiptId,
    receiver_authority_read_receipt_id: AuthorityReadReceiptId,
    confirming_authority_read_receipt_id: AuthorityReadReceiptId,
    repository_id: RepositoryId,
    task_id: WorkTaskId,
    successor_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
    previous_generation: [u8; 32],
    resulting_generation: [u8; 32],
    capsule_id: AgentHandoffCapsuleId,
    acceptance_id: AgentHandoffAcceptanceId,
    ancestry_receipt_id: AuthorityHeadAncestryReceiptId,
    source_run_commitment: IntentRunCommitment,
    receiver_run_commitment: IntentRunCommitment,
    evidence_root: Digest,
    observed_at: LogicalTime,
}

impl CrossHeadTaskTransferReceipt {
    fn build(
        envelope: &CrossHeadTaskTransferEnvelope,
        observed: &CrossHeadTaskTransferPersistedState,
    ) -> Result<Self, CrossHeadTaskTransferRefusal> {
        let confirming_authority_read_receipt_id =
            observed.snapshot.authority_read_receipt().receipt_id()?;
        let mut receipt = Self {
            receipt_id: CrossHeadTaskTransferReceiptId([0; 32]),
            envelope_id: envelope.envelope_id,
            source_authority_read_receipt_id: envelope.source_authority_read_receipt_id,
            receiver_authority_read_receipt_id: envelope.receiver_authority_read_receipt_id,
            confirming_authority_read_receipt_id,
            repository_id: envelope.repository_id,
            task_id: envelope.task_id,
            successor_snapshot_id: observed.snapshot.snapshot_id(),
            previous_generation: envelope.previous_generation(),
            resulting_generation: envelope.resulting_generation(),
            capsule_id: envelope.capsule_id,
            acceptance_id: envelope.acceptance_id,
            ancestry_receipt_id: envelope.ancestry_receipt_id,
            source_run_commitment: envelope.source_run_commitment,
            receiver_run_commitment: envelope.receiver_run_commitment,
            evidence_root: envelope.evidence_root,
            observed_at: observed.snapshot.observed_at(),
        };
        receipt.receipt_id =
            CrossHeadTaskTransferReceiptId(receipt_commitment(&receipt)?);
        Ok(receipt)
    }

    /// Stable receipt identity.
    #[must_use]
    pub const fn receipt_id(self) -> CrossHeadTaskTransferReceiptId {
        self.receipt_id
    }

    /// Exact envelope confirmed.
    #[must_use]
    pub const fn envelope_id(self) -> CrossHeadTaskTransferEnvelopeId {
        self.envelope_id
    }

    /// Historical source read identity.
    #[must_use]
    pub const fn source_authority_read_receipt_id(self) -> AuthorityReadReceiptId {
        self.source_authority_read_receipt_id
    }

    /// Descendant receiver read identity that governed mutation construction.
    #[must_use]
    pub const fn receiver_authority_read_receipt_id(self) -> AuthorityReadReceiptId {
        self.receiver_authority_read_receipt_id
    }

    /// Authenticated reread identity confirming the successor.
    #[must_use]
    pub const fn confirming_authority_read_receipt_id(self) -> AuthorityReadReceiptId {
        self.confirming_authority_read_receipt_id
    }

    /// Repository namespace.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Persisted task.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }

    /// Persisted receiver-basis snapshot.
    #[must_use]
    pub const fn successor_snapshot_id(self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.successor_snapshot_id
    }

    /// Source task generation.
    #[must_use]
    pub const fn previous_generation(self) -> [u8; 32] {
        self.previous_generation
    }

    /// Receiver assignment generation.
    #[must_use]
    pub const fn resulting_generation(self) -> [u8; 32] {
        self.resulting_generation
    }

    /// Source handoff capsule.
    #[must_use]
    pub const fn capsule_id(self) -> AgentHandoffCapsuleId {
        self.capsule_id
    }

    /// Receiver handoff acceptance.
    #[must_use]
    pub const fn acceptance_id(self) -> AgentHandoffAcceptanceId {
        self.acceptance_id
    }

    /// Bounded authority ancestry proof.
    #[must_use]
    pub const fn ancestry_receipt_id(self) -> AuthorityHeadAncestryReceiptId {
        self.ancestry_receipt_id
    }

    /// Source complete run identity.
    #[must_use]
    pub const fn source_run_commitment(self) -> IntentRunCommitment {
        self.source_run_commitment
    }

    /// Receiver complete run identity.
    #[must_use]
    pub const fn receiver_run_commitment(self) -> IntentRunCommitment {
        self.receiver_run_commitment
    }

    /// Transfer evidence contract.
    #[must_use]
    pub const fn evidence_root(self) -> Digest {
        self.evidence_root
    }

    /// Confirming observation time.
    #[must_use]
    pub const fn observed_at(self) -> LogicalTime {
        self.observed_at
    }
}

/// Durable backend boundary for a cross-head task transfer.
pub trait CrossHeadTaskTransferStore {
    /// Stable backend implementation/profile identity.
    fn adapter_identity(&self) -> [u8; 32];

    /// Reads the current receiver-basis task row.
    fn read(
        &mut self,
        key: TaskProjectionStoreKey,
    ) -> Result<Option<CrossHeadTaskTransferPersistedState>, TaskProjectionStoreReadRefusal>;

    /// Performs one exact receiver-predecessor compare-and-replace.
    ///
    /// `Err` is a definite pre-mutation refusal. An uncertain result must use
    /// [`TaskProjectionStoreWriteOutcome::Ambiguous`].
    fn compare_and_replace(
        &mut self,
        envelope: &CrossHeadTaskTransferEnvelope,
    ) -> Result<TaskProjectionStoreWriteOutcome, TaskProjectionStoreWriteRefusal>;

    /// Flushes a collaborative/read projection already reflecting this exact
    /// transfer, or reports that no separate flush is required.
    fn flush(
        &mut self,
        envelope: &CrossHeadTaskTransferEnvelope,
    ) -> Result<TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal>;
}

/// Final result of one bounded cross-head transfer store attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossHeadTaskTransferExecution {
    /// Exact successor persistence and required flush were confirmed.
    Confirmed {
        /// Proof-carrying transfer receipt.
        receipt: CrossHeadTaskTransferReceipt,
        /// Compare-and-replace disposition.
        write: TaskProjectionStoreWriteDisposition,
        /// Flush disposition.
        flush: TaskProjectionStoreFlushDisposition,
    },
    /// Another state was current and the transfer definitely did not commit.
    Conflict {
        /// Exact envelope not applied.
        envelope_id: CrossHeadTaskTransferEnvelopeId,
        /// Write disposition.
        write: TaskProjectionStoreWriteDisposition,
        /// Current conflicting snapshot.
        current_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
        /// Current conflicting generation.
        current_generation: [u8; 32],
    },
    /// Possible or historical mutation remains unresolved.
    NeedsReconciliation {
        /// Exact envelope requiring recovery.
        envelope_id: CrossHeadTaskTransferEnvelopeId,
        /// Stage at which certainty was lost.
        stage: TaskProjectionStoreStage,
        /// Write disposition.
        write: TaskProjectionStoreWriteDisposition,
        /// Flush disposition.
        flush: TaskProjectionStoreFlushDisposition,
        /// Reread interpretation, when available.
        decision: Option<CrossHeadTaskTransferDecision>,
        /// Primary reason certainty is incomplete.
        cause: CrossHeadTaskTransferReconciliationCause,
    },
}

/// Why a post-effect transfer remains unresolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossHeadTaskTransferReconciliationCause {
    /// Initial row was already partial or corrupt.
    InitialPersistence(CrossHeadTaskTransferRefusal),
    /// Flush result was ambiguous.
    FlushAmbiguous {
        /// Backend recovery commitment.
        probe_root: Digest,
    },
    /// Flush definitely refused after persistence may have occurred.
    FlushRefused(TaskProjectionStoreFlushRefusal),
    /// Confirming read failed.
    ConfirmingRead(TaskProjectionStoreReadRefusal),
    /// Confirming read found no row.
    ProjectionMissing,
    /// Reread was structurally inconsistent.
    Persistence(CrossHeadTaskTransferRefusal),
    /// Ambiguous write was followed by the predecessor.
    AmbiguousWriteUnresolved,
    /// Definite write result contradicted the confirming row.
    BackendContradiction,
    /// A previously observed successor was later replaced; history is required.
    HistoryRequired,
}

/// Definite pre-effect refusal from cross-head store orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossHeadTaskTransferExecutionRefusal {
    /// Store identity used the reserved all-zero value.
    ZeroAdapterIdentity,
    /// Store profile differs from the envelope profile.
    AdapterIdentityMismatch {
        /// Envelope profile.
        expected: [u8; 32],
        /// Invoked store profile.
        observed: [u8; 32],
    },
    /// Initial authenticated read failed.
    InitialRead(TaskProjectionStoreReadRefusal),
    /// Initial read found no task row.
    InitialProjectionMissing,
    /// Compare-and-replace definitely refused before mutation.
    Write(TaskProjectionStoreWriteRefusal),
}

impl fmt::Display for CrossHeadTaskTransferExecutionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cross-head task-transfer execution refused: {self:?}")
    }
}

impl core::error::Error for CrossHeadTaskTransferExecutionRefusal {}

/// Executes one bounded cross-head transfer store attempt.
///
/// This function performs at most one compare-and-replace and never retries an
/// ambiguous effect.
///
/// # Errors
///
/// Returns only conditions known before mutation. Every uncertainty after a
/// possible effect becomes [`CrossHeadTaskTransferExecution::NeedsReconciliation`].
pub fn execute_cross_head_task_transfer_store<S: CrossHeadTaskTransferStore>(
    store: &mut S,
    envelope: &CrossHeadTaskTransferEnvelope,
) -> Result<CrossHeadTaskTransferExecution, CrossHeadTaskTransferExecutionRefusal> {
    let adapter_identity = store.adapter_identity();
    if is_zero(&adapter_identity) {
        return Err(CrossHeadTaskTransferExecutionRefusal::ZeroAdapterIdentity);
    }
    if adapter_identity != envelope.adapter_identity {
        return Err(
            CrossHeadTaskTransferExecutionRefusal::AdapterIdentityMismatch {
                expected: envelope.adapter_identity,
                observed: adapter_identity,
            },
        );
    }

    let key = TaskProjectionStoreKey::new(envelope.repository_id, envelope.task_id);
    let initial = store
        .read(key)
        .map_err(CrossHeadTaskTransferExecutionRefusal::InitialRead)?;
    let Some(initial) = initial else {
        return Err(CrossHeadTaskTransferExecutionRefusal::InitialProjectionMissing);
    };
    match envelope.reconcile(Some(&initial)) {
        Ok(CrossHeadTaskTransferDecision::Confirmed(_)) => {
            return finish_store_attempt(
                store,
                envelope,
                TaskProjectionStoreWriteDisposition::NotAttempted,
            );
        }
        Ok(CrossHeadTaskTransferDecision::RetrySafe { .. }) => {}
        Ok(CrossHeadTaskTransferDecision::Conflict {
            current_snapshot_id,
            current_generation,
            ..
        }) => {
            return Ok(CrossHeadTaskTransferExecution::Conflict {
                envelope_id: envelope.envelope_id,
                write: TaskProjectionStoreWriteDisposition::NotAttempted,
                current_snapshot_id,
                current_generation,
            });
        }
        Err(refusal) => {
            return Ok(CrossHeadTaskTransferExecution::NeedsReconciliation {
                envelope_id: envelope.envelope_id,
                stage: TaskProjectionStoreStage::InitialRead,
                write: TaskProjectionStoreWriteDisposition::NotAttempted,
                flush: TaskProjectionStoreFlushDisposition::NotAttempted,
                decision: None,
                cause: CrossHeadTaskTransferReconciliationCause::InitialPersistence(refusal),
            });
        }
    }

    let write = store
        .compare_and_replace(envelope)
        .map_err(CrossHeadTaskTransferExecutionRefusal::Write)?;
    finish_store_attempt(store, envelope, write.into())
}

fn finish_store_attempt<S: CrossHeadTaskTransferStore>(
    store: &mut S,
    envelope: &CrossHeadTaskTransferEnvelope,
    write: TaskProjectionStoreWriteDisposition,
) -> Result<CrossHeadTaskTransferExecution, CrossHeadTaskTransferExecutionRefusal> {
    let flush = match store.flush(envelope) {
        Ok(TaskProjectionStoreFlushOutcome::Flushed) => {
            TaskProjectionStoreFlushDisposition::Flushed
        }
        Ok(TaskProjectionStoreFlushOutcome::NotRequired) => {
            TaskProjectionStoreFlushDisposition::NotRequired
        }
        Ok(TaskProjectionStoreFlushOutcome::Ambiguous { probe_root }) => {
            TaskProjectionStoreFlushDisposition::Ambiguous { probe_root }
        }
        Err(refusal) => TaskProjectionStoreFlushDisposition::Refused(refusal),
    };

    let key = TaskProjectionStoreKey::new(envelope.repository_id, envelope.task_id);
    let observed = match store.read(key) {
        Ok(Some(observed)) => observed,
        Ok(None) => {
            return Ok(CrossHeadTaskTransferExecution::NeedsReconciliation {
                envelope_id: envelope.envelope_id,
                stage: TaskProjectionStoreStage::ConfirmingRead,
                write,
                flush,
                decision: None,
                cause: CrossHeadTaskTransferReconciliationCause::ProjectionMissing,
            });
        }
        Err(refusal) => {
            return Ok(CrossHeadTaskTransferExecution::NeedsReconciliation {
                envelope_id: envelope.envelope_id,
                stage: TaskProjectionStoreStage::ConfirmingRead,
                write,
                flush,
                decision: None,
                cause: CrossHeadTaskTransferReconciliationCause::ConfirmingRead(refusal),
            });
        }
    };
    let decision = match envelope.reconcile(Some(&observed)) {
        Ok(decision) => decision,
        Err(refusal) => {
            return Ok(CrossHeadTaskTransferExecution::NeedsReconciliation {
                envelope_id: envelope.envelope_id,
                stage: TaskProjectionStoreStage::Reconcile,
                write,
                flush,
                decision: None,
                cause: CrossHeadTaskTransferReconciliationCause::Persistence(refusal),
            });
        }
    };

    if !flush_is_definite_success(flush) {
        let cause = match flush {
            TaskProjectionStoreFlushDisposition::Ambiguous { probe_root } => {
                CrossHeadTaskTransferReconciliationCause::FlushAmbiguous { probe_root }
            }
            TaskProjectionStoreFlushDisposition::Refused(refusal) => {
                CrossHeadTaskTransferReconciliationCause::FlushRefused(refusal)
            }
            TaskProjectionStoreFlushDisposition::NotAttempted
            | TaskProjectionStoreFlushDisposition::Flushed
            | TaskProjectionStoreFlushDisposition::NotRequired => {
                CrossHeadTaskTransferReconciliationCause::BackendContradiction
            }
        };
        return Ok(CrossHeadTaskTransferExecution::NeedsReconciliation {
            envelope_id: envelope.envelope_id,
            stage: TaskProjectionStoreStage::Flush,
            write,
            flush,
            decision: Some(decision),
            cause,
        });
    }

    match decision {
        CrossHeadTaskTransferDecision::Confirmed(receipt) => {
            Ok(CrossHeadTaskTransferExecution::Confirmed {
                receipt,
                write,
                flush,
            })
        }
        CrossHeadTaskTransferDecision::RetrySafe { .. } => {
            let cause = if matches!(
                write,
                TaskProjectionStoreWriteDisposition::Ambiguous { .. }
            ) {
                CrossHeadTaskTransferReconciliationCause::AmbiguousWriteUnresolved
            } else {
                CrossHeadTaskTransferReconciliationCause::BackendContradiction
            };
            Ok(CrossHeadTaskTransferExecution::NeedsReconciliation {
                envelope_id: envelope.envelope_id,
                stage: TaskProjectionStoreStage::Reconcile,
                write,
                flush,
                decision: Some(decision),
                cause,
            })
        }
        CrossHeadTaskTransferDecision::Conflict {
            current_snapshot_id,
            current_generation,
            ..
        } => {
            if matches!(
                write,
                TaskProjectionStoreWriteDisposition::PreconditionFailed
            ) {
                Ok(CrossHeadTaskTransferExecution::Conflict {
                    envelope_id: envelope.envelope_id,
                    write,
                    current_snapshot_id,
                    current_generation,
                })
            } else {
                Ok(CrossHeadTaskTransferExecution::NeedsReconciliation {
                    envelope_id: envelope.envelope_id,
                    stage: TaskProjectionStoreStage::Reconcile,
                    write,
                    flush,
                    decision: Some(decision),
                    cause: CrossHeadTaskTransferReconciliationCause::HistoryRequired,
                })
            }
        }
    }
}

/// Successfully persisted cross-head assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCrossHeadTaskTransfer {
    envelope: CrossHeadTaskTransferEnvelope,
    receipt: CrossHeadTaskTransferReceipt,
    write: TaskProjectionStoreWriteDisposition,
    flush: TaskProjectionStoreFlushDisposition,
}

impl PersistedCrossHeadTaskTransfer {
    /// Exact proof-carrying envelope.
    #[must_use]
    pub const fn envelope(&self) -> &CrossHeadTaskTransferEnvelope {
        &self.envelope
    }

    /// Authenticated persistence confirmation.
    #[must_use]
    pub const fn receipt(&self) -> CrossHeadTaskTransferReceipt {
        self.receipt
    }

    /// Persisted receiver assignment snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        self.envelope.receiver_successor()
    }

    /// Source cancellation projection made safe by persistence confirmation.
    #[must_use]
    pub const fn cancellation_projection(&self) -> TaskClaimCancellationProjection {
        self.envelope.cancellation_projection()
    }

    /// Compare-and-replace disposition.
    #[must_use]
    pub const fn write_disposition(&self) -> TaskProjectionStoreWriteDisposition {
        self.write
    }

    /// Projection flush disposition.
    #[must_use]
    pub const fn flush_disposition(&self) -> TaskProjectionStoreFlushDisposition {
        self.flush
    }
}

/// Terminal outcome of one persistence-gated cross-head transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossHeadTaskTransferPersistenceOutcome {
    /// Exact receiver assignment was durably confirmed.
    Persisted(PersistedCrossHeadTaskTransfer),
    /// Another row was current and the exact envelope did not commit.
    Conflict {
        /// Complete envelope retained for audit.
        envelope: CrossHeadTaskTransferEnvelope,
        /// Typed store conflict.
        execution: CrossHeadTaskTransferExecution,
    },
    /// Possible or historical effect requires exact recovery.
    NeedsReconciliation {
        /// Complete envelope retained for recovery.
        envelope: CrossHeadTaskTransferEnvelope,
        /// Typed post-effect debt.
        execution: CrossHeadTaskTransferExecution,
    },
}

/// Persists one already-validated cross-head transfer envelope.
///
/// # Errors
///
/// Returns only definite pre-effect store refusals.
pub fn persist_cross_head_task_transfer<S: CrossHeadTaskTransferStore>(
    store: &mut S,
    envelope: CrossHeadTaskTransferEnvelope,
) -> Result<
    CrossHeadTaskTransferPersistenceOutcome,
    CrossHeadTaskTransferExecutionRefusal,
> {
    match execute_cross_head_task_transfer_store(store, &envelope)? {
        CrossHeadTaskTransferExecution::Confirmed {
            receipt,
            write,
            flush,
        } => Ok(CrossHeadTaskTransferPersistenceOutcome::Persisted(
            PersistedCrossHeadTaskTransfer {
                envelope,
                receipt,
                write,
                flush,
            },
        )),
        execution @ CrossHeadTaskTransferExecution::Conflict { .. } => {
            Ok(CrossHeadTaskTransferPersistenceOutcome::Conflict {
                envelope,
                execution,
            })
        }
        execution @ CrossHeadTaskTransferExecution::NeedsReconciliation { .. } => {
            Ok(CrossHeadTaskTransferPersistenceOutcome::NeedsReconciliation {
                envelope,
                execution,
            })
        }
    }
}

/// Proof that the receiver subsequently acquired an ordinary persisted claim
/// from the exact cross-head assignment generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossHeadTaskTransferActivationReceipt {
    receipt_id: CrossHeadTaskTransferActivationReceiptId,
    transfer_receipt_id: CrossHeadTaskTransferReceiptId,
    persisted_claim_receipt_id: TaskProjectionPersistenceReceiptId,
    receiver_claim_id: TaskClaimReceiptId,
    receiver_active_claim_id: ActiveTaskClaimId,
    receiver_situation_id: SituationId,
    receiver_run_commitment: IntentRunCommitment,
    transfer_generation: [u8; 32],
    claimed_generation: [u8; 32],
    observed_at: LogicalTime,
}

impl CrossHeadTaskTransferActivationReceipt {
    /// Validates the receiver's ordinary persisted claim and fresh activation.
    ///
    /// The claim must start from the exact transfer successor generation, use
    /// the same task backend profile and complete receiver run, and bind a new
    /// receiver plan rather than the source plan.
    ///
    /// # Errors
    ///
    /// Refuses transfer, authority, complete-run, task, generation, plan,
    /// persistence, situation, activation, adapter, or time substitution.
    pub fn admit(
        transfer: &PersistedCrossHeadTaskTransfer,
        receiver_run: &IntentRun,
        receiver_situation: &AgentSituationReceipt,
        persisted_claim: &PersistedTaskClaim,
        active_claim: ActiveTaskClaim,
    ) -> Result<Self, CrossHeadTaskTransferActivationRefusal> {
        let envelope = transfer.envelope();
        let receiver_authority = receiver_run
            .authority_read_receipt()
            .ok_or(
                CrossHeadTaskTransferActivationRefusal::ReceiverAuthorityReceiptRequired,
            )?;
        let receiver_run_commitment = receiver_run
            .commitment()
            .map_err(CrossHeadTaskTransferActivationRefusal::ReceiverRunIdentity)?;

        if receiver_run.run_id() != envelope.receiver_run_id
            || receiver_run_commitment != envelope.receiver_run_commitment
        {
            return Err(CrossHeadTaskTransferActivationRefusal::ReceiverRunMismatch);
        }
        if receiver_authority != envelope.receiver_successor.authority_read_receipt() {
            return Err(
                CrossHeadTaskTransferActivationRefusal::ReceiverAuthorityMismatch,
            );
        }
        if receiver_situation.authority_read_receipt() != receiver_authority
            || receiver_situation.intent_run_id() != Some(receiver_run.run_id())
            || receiver_situation.intent_run_commitment()
                != Some(receiver_run_commitment)
        {
            return Err(
                CrossHeadTaskTransferActivationRefusal::ReceiverSituationMismatch,
            );
        }

        let claim_envelope = persisted_claim.envelope();
        if !semantic_snapshot_matches(
            envelope.receiver_successor(),
            claim_envelope.before_snapshot(),
        ) {
            return Err(
                CrossHeadTaskTransferActivationRefusal::ClaimPredecessorMismatch,
            );
        }
        if claim_envelope.before_snapshot().authority_read_receipt()
            != receiver_authority
            || persisted_claim.snapshot().authority_read_receipt()
                != receiver_authority
        {
            return Err(
                CrossHeadTaskTransferActivationRefusal::ClaimAuthorityMismatch,
            );
        }
        if claim_envelope.adapter_identity() != envelope.adapter_identity {
            return Err(CrossHeadTaskTransferActivationRefusal::AdapterMismatch {
                transfer: envelope.adapter_identity,
                claim: claim_envelope.adapter_identity(),
            });
        }

        let claim = persisted_claim.claim_receipt();
        if *claim.adapter_identity() != envelope.adapter_identity {
            return Err(CrossHeadTaskTransferActivationRefusal::AdapterMismatch {
                transfer: envelope.adapter_identity,
                claim: *claim.adapter_identity(),
            });
        }
        if claim.task_id() != envelope.task_id
            || claim.assignee() != envelope.receiver_run_id
            || claim.run_commitment() != envelope.receiver_run_commitment
        {
            return Err(CrossHeadTaskTransferActivationRefusal::ClaimOwnerMismatch);
        }
        if claim.plan_id() == envelope.source_plan_id {
            return Err(CrossHeadTaskTransferActivationRefusal::SourcePlanReused);
        }
        if *claim.previous_task_projection_generation()
            != envelope.resulting_generation()
        {
            return Err(
                CrossHeadTaskTransferActivationRefusal::ClaimGenerationMismatch {
                    expected: envelope.resulting_generation(),
                    observed: *claim.previous_task_projection_generation(),
                },
            );
        }
        if claim.claimed_at() < envelope.transferred_at {
            return Err(
                CrossHeadTaskTransferActivationRefusal::ClaimBeforeTransfer {
                    transferred_at: envelope.transferred_at,
                    claimed_at: claim.claimed_at(),
                },
            );
        }

        if active_claim.claim_id() != claim.claim_id()
            || active_claim.task_id() != claim.task_id()
            || active_claim.plan_id() != claim.plan_id()
            || active_claim.assignee() != claim.assignee()
            || active_claim.run_commitment() != claim.run_commitment()
            || active_claim.expires_at() != claim.expires_at()
        {
            return Err(
                CrossHeadTaskTransferActivationRefusal::ActiveClaimMismatch,
            );
        }
        if active_claim.situation_id()
            != *receiver_situation.situation_id().as_bytes()
            || active_claim.observed_at() != receiver_situation.observed_at()
        {
            return Err(
                CrossHeadTaskTransferActivationRefusal::ActivationSituationMismatch,
            );
        }
        let task_component =
            receiver_situation.component(SituationComponentKind::TaskProjection);
        if task_component.basis_head_id()
            != Some(receiver_authority.authority_head_id())
            || task_component.generation_commitment()
                != Some(*claim.claimed_task_projection_generation())
        {
            return Err(
                CrossHeadTaskTransferActivationRefusal::ActivationGenerationMismatch,
            );
        }

        let persisted_claim_receipt_id =
            persisted_claim.persistence_receipt().receipt_id();
        let mut receipt = Self {
            receipt_id: CrossHeadTaskTransferActivationReceiptId([0; 32]),
            transfer_receipt_id: transfer.receipt.receipt_id(),
            persisted_claim_receipt_id,
            receiver_claim_id: claim.claim_id(),
            receiver_active_claim_id: active_claim.activation_id(),
            receiver_situation_id: receiver_situation.situation_id(),
            receiver_run_commitment,
            transfer_generation: envelope.resulting_generation(),
            claimed_generation: *claim.claimed_task_projection_generation(),
            observed_at: receiver_situation.observed_at(),
        };
        receipt.receipt_id = CrossHeadTaskTransferActivationReceiptId(
            activation_commitment(&receipt)?,
        );
        Ok(receipt)
    }

    /// Stable activation-chain identity.
    #[must_use]
    pub const fn receipt_id(self) -> CrossHeadTaskTransferActivationReceiptId {
        self.receipt_id
    }

    /// Confirmed cross-head transfer.
    #[must_use]
    pub const fn transfer_receipt_id(self) -> CrossHeadTaskTransferReceiptId {
        self.transfer_receipt_id
    }

    /// Ordinary task-claim persistence confirmation.
    #[must_use]
    pub const fn persisted_claim_receipt_id(self) -> TaskProjectionPersistenceReceiptId {
        self.persisted_claim_receipt_id
    }

    /// Receiver claim receipt.
    #[must_use]
    pub const fn receiver_claim_id(self) -> TaskClaimReceiptId {
        self.receiver_claim_id
    }

    /// Fresh receiver claim activation.
    #[must_use]
    pub const fn receiver_active_claim_id(self) -> ActiveTaskClaimId {
        self.receiver_active_claim_id
    }

    /// Situation that observed the receiver claim.
    #[must_use]
    pub const fn receiver_situation_id(self) -> SituationId {
        self.receiver_situation_id
    }

    /// Complete receiver run identity.
    #[must_use]
    pub const fn receiver_run_commitment(self) -> IntentRunCommitment {
        self.receiver_run_commitment
    }

    /// Transfer assignment generation.
    #[must_use]
    pub const fn transfer_generation(self) -> [u8; 32] {
        self.transfer_generation
    }

    /// Receiver claimed generation.
    #[must_use]
    pub const fn claimed_generation(self) -> [u8; 32] {
        self.claimed_generation
    }

    /// Fresh activation observation.
    #[must_use]
    pub const fn observed_at(self) -> LogicalTime {
        self.observed_at
    }
}

/// Why receiver post-transfer activation failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossHeadTaskTransferActivationRefusal {
    /// Receiver run lacks a complete authenticated authority receipt.
    ReceiverAuthorityReceiptRequired,
    /// Complete receiver run identity could not be produced.
    ReceiverRunIdentity(IntentRunIdentityRefusal),
    /// Receiver run differs from the transfer assignment.
    ReceiverRunMismatch,
    /// Receiver run uses another authority read.
    ReceiverAuthorityMismatch,
    /// Receiver situation differs from the supplied complete run or authority.
    ReceiverSituationMismatch,
    /// Persisted claim did not start from the transfer successor.
    ClaimPredecessorMismatch,
    /// Claim persistence uses another receiver authority basis.
    ClaimAuthorityMismatch,
    /// Transfer and receiver claim used different task adapter profiles.
    AdapterMismatch {
        /// Transfer adapter.
        transfer: [u8; 32],
        /// Claim adapter.
        claim: [u8; 32],
    },
    /// Claim names another task or complete receiver.
    ClaimOwnerMismatch,
    /// Receiver attempted to reuse the source plan.
    SourcePlanReused,
    /// Claim did not start from the transfer assignment generation.
    ClaimGenerationMismatch {
        /// Transfer generation.
        expected: [u8; 32],
        /// Claim predecessor.
        observed: [u8; 32],
    },
    /// Receiver claim predates the transfer.
    ClaimBeforeTransfer {
        /// Transfer instant.
        transferred_at: LogicalTime,
        /// Claim instant.
        claimed_at: LogicalTime,
    },
    /// Active claim differs from the persisted claim.
    ActiveClaimMismatch,
    /// Active claim names another situation or observation time.
    ActivationSituationMismatch,
    /// Receiver situation did not observe the claimed generation.
    ActivationGenerationMismatch,
    /// Canonical framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for CrossHeadTaskTransferActivationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cross-head task-transfer activation refused: {self:?}"
        )
    }
}

impl core::error::Error for CrossHeadTaskTransferActivationRefusal {}

impl From<CodecRefusal> for CrossHeadTaskTransferActivationRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

/// Why cross-head transfer construction or reread reconciliation failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossHeadTaskTransferRefusal {
    /// Source run lacks a complete authenticated receipt.
    SourceAuthorityReceiptRequired,
    /// Receiver run lacks a complete authenticated receipt.
    ReceiverAuthorityReceiptRequired,
    /// Source complete run identity could not be produced.
    SourceRunIdentity(IntentRunIdentityRefusal),
    /// Receiver complete run identity could not be produced.
    ReceiverRunIdentity(IntentRunIdentityRefusal),
    /// Source and receiver belong to different repositories.
    RepositoryMismatch {
        /// Source repository.
        source: RepositoryId,
        /// Receiver repository.
        receiver: RepositoryId,
    },
    /// Source snapshot does not retain the source run's exact authority read.
    SourceSnapshotAuthorityMismatch,
    /// Receiver predecessor does not retain the receiver run's exact read.
    ReceiverSnapshotAuthorityMismatch,
    /// Snapshot repository fields disagree with the runs.
    SnapshotRepositoryMismatch,
    /// Source task has no active lease.
    SourceLeaseMissing,
    /// Source lease, assignment, or claim fields disagree.
    SourceLeaseMismatch,
    /// Source active claim differs from the lease and claim receipt.
    SourceActiveClaimMismatch,
    /// Source handoff capsule differs from the lease, claim, run, or report.
    CapsuleMismatch,
    /// Receiver acceptance differs from the capsule, run, or situation.
    AcceptanceMismatch,
    /// Cross-head transfer requires the proven-descendant relation.
    DescendantAcceptanceRequired,
    /// Descendant acceptance omitted its ancestry receipt.
    DescendantAncestryRequired,
    /// Ancestry receipt differs from the source or receiver authority positions.
    AncestryMismatch,
    /// Receiver situation does not retain the accepted complete run and read.
    ReceiverSituationMismatch,
    /// Receiver situation task component differs from the receiver predecessor.
    ReceiverSituationTaskMismatch,
    /// Source and receiver snapshots do not represent the same semantic task row.
    ReceiverPredecessorSemanticMismatch,
    /// Transfer time predates source evidence.
    TransferBeforeSourceEvidence,
    /// Transfer time predates receiver evidence.
    TransferBeforeReceiverEvidence,
    /// Receiver run is expired at transfer.
    ReceiverRunExpired {
        /// Exclusive receiver expiry.
        expires_at: LogicalTime,
        /// Transfer instant.
        transferred_at: LogicalTime,
    },
    /// Adapter identity used the reserved all-zero value.
    ZeroAdapterIdentity,
    /// Transfer attempted to change task backend profile without migration evidence.
    SourceAdapterMismatch {
        /// Backend profile that produced the active source claim.
        expected: [u8; 32],
        /// Backend profile selected for the transfer.
        observed: [u8; 32],
    },
    /// Deterministic successor generation was zero or unchanged.
    SuccessorGenerationDidNotAdvance,
    /// Receiver-basis snapshot construction refused the successor.
    TaskCoordination(Box<TaskCoordinationRefusal>),
    /// Backend reread found no row.
    ProjectionMissing,
    /// Backend reread belongs to another repository.
    ObservedRepositoryMismatch {
        /// Envelope repository.
        expected: RepositoryId,
        /// Observed repository.
        observed: RepositoryId,
    },
    /// Backend reread belongs to another task.
    ObservedTaskMismatch {
        /// Envelope task.
        expected: WorkTaskId,
        /// Observed task.
        observed: WorkTaskId,
    },
    /// Backend reread uses another receiver authority position.
    ObservedReceiverAuthorityMismatch,
    /// Backend reread predates the transfer.
    ObservationRollback {
        /// Transfer instant.
        transferred_at: LogicalTime,
        /// Reread instant.
        observed_at: LogicalTime,
    },
    /// Predecessor row carries transfer metadata even though no transfer
    /// successor is visible.
    PredecessorCarriesTransferMetadata,
    /// Exact successor omitted or changed the envelope identity.
    SuccessorEnvelopeMismatch,
    /// Exact successor omitted or changed the handoff acceptance.
    SuccessorAcceptanceMismatch,
    /// Exact successor omitted or changed the ancestry receipt.
    SuccessorAncestryMismatch,
    /// Exact successor omitted or changed the evidence contract.
    SuccessorEvidenceMismatch,
    /// Exact authenticated-read identity could not be framed.
    AuthorityIdentity(AuthorityReadIdentityRefusal),
    /// Canonical framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for CrossHeadTaskTransferRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cross-head task transfer refused: {self:?}")
    }
}

impl core::error::Error for CrossHeadTaskTransferRefusal {}

impl From<AuthorityReadIdentityRefusal> for CrossHeadTaskTransferRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::AuthorityIdentity(value)
    }
}

impl From<TaskCoordinationRefusal> for CrossHeadTaskTransferRefusal {
    fn from(value: TaskCoordinationRefusal) -> Self {
        Self::TaskCoordination(Box::new(value))
    }
}

impl From<CodecRefusal> for CrossHeadTaskTransferRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_source_lease(
    snapshot: &AuthorityBoundTaskProjectionSnapshot,
    claim: &TaskClaimReceipt,
    active: ActiveTaskClaim,
    source_run: &IntentRun,
    source_run_commitment: IntentRunCommitment,
) -> Result<(), CrossHeadTaskTransferRefusal> {
    let lease = snapshot
        .lease()
        .ok_or(CrossHeadTaskTransferRefusal::SourceLeaseMissing)?;
    if snapshot.assignment()
        != TaskProjectionAssignment::assigned(
            source_run.run_id(),
            source_run_commitment,
        )
        || lease.plan_id() != claim.plan_id()
        || lease.assignee() != source_run.run_id()
        || lease.run_commitment() != source_run_commitment
        || lease.previous_generation()
            != claim.previous_task_projection_generation()
        || lease.claimed_generation() != snapshot.generation()
        || lease.claimed_generation()
            != claim.claimed_task_projection_generation()
        || lease.reserved_surfaces() != claim.reserved_surfaces()
        || lease.claimed_at() != claim.claimed_at()
        || lease.expires_at() != claim.expires_at()
        || claim.repository_id() != snapshot.repository_id()
        || claim.authority_head_id()
            != snapshot.authority_read_receipt().authority_head_id()
        || claim.authority_head_generation()
            != snapshot
                .authority_read_receipt()
                .authority_head_generation()
        || claim.task_id() != snapshot.task_id()
        || claim.assignee() != source_run.run_id()
        || claim.run_commitment() != source_run_commitment
    {
        return Err(CrossHeadTaskTransferRefusal::SourceLeaseMismatch);
    }
    if active.claim_id() != claim.claim_id()
        || active.plan_id() != claim.plan_id()
        || active.task_id() != claim.task_id()
        || active.assignee() != source_run.run_id()
        || active.run_commitment() != source_run_commitment
        || active.expires_at() != claim.expires_at()
    {
        return Err(CrossHeadTaskTransferRefusal::SourceActiveClaimMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_handoff(
    source_snapshot: &AuthorityBoundTaskProjectionSnapshot,
    source_claim: &TaskClaimReceipt,
    source_active_claim: ActiveTaskClaim,
    source_run: &IntentRun,
    source_run_commitment: IntentRunCommitment,
    capsule: &AgentHandoffCapsule,
    acceptance: &AgentHandoffAcceptance,
    receiver_situation: &AgentSituationReceipt,
    receiver_predecessor: &AuthorityBoundTaskProjectionSnapshot,
    receiver_run: &IntentRun,
    receiver_run_commitment: IntentRunCommitment,
) -> Result<(), CrossHeadTaskTransferRefusal> {
    if capsule.source_run_id() != source_run.run_id()
        || capsule.plan_id() != source_claim.plan_id()
        || capsule.active_claim_id() != source_active_claim.activation_id()
        || capsule.reconciliation().run_id() != source_run.run_id()
        || capsule.reconciliation().run_commitment() != source_run_commitment
        || capsule.reconciliation().authority_read_receipt()
            != source_snapshot.authority_read_receipt()
    {
        return Err(CrossHeadTaskTransferRefusal::CapsuleMismatch);
    }
    if acceptance.capsule_id() != capsule.capsule_id()
        || acceptance.receiver_run_id() != receiver_run.run_id()
        || acceptance.receiver_run_commitment() != receiver_run_commitment
        || acceptance.receiver_situation_id() != receiver_situation.situation_id()
        || acceptance.accepted_at() != receiver_situation.observed_at()
    {
        return Err(CrossHeadTaskTransferRefusal::AcceptanceMismatch);
    }
    if acceptance.authority_relation()
        != HandoffAuthorityRelation::DescendantAuthenticatedHead
    {
        return Err(CrossHeadTaskTransferRefusal::DescendantAcceptanceRequired);
    }

    let receiver_authority = receiver_run
        .authority_read_receipt()
        .ok_or(CrossHeadTaskTransferRefusal::ReceiverAuthorityReceiptRequired)?;
    if receiver_situation.authority_read_receipt() != receiver_authority
        || receiver_situation.intent_run_id() != Some(receiver_run.run_id())
        || receiver_situation.intent_run_commitment()
            != Some(receiver_run_commitment)
    {
        return Err(CrossHeadTaskTransferRefusal::ReceiverSituationMismatch);
    }
    let task_component =
        receiver_situation.component(SituationComponentKind::TaskProjection);
    if task_component.basis_head_id()
        != Some(receiver_authority.authority_head_id())
        || task_component.generation_commitment()
            != Some(*receiver_predecessor.generation())
        || receiver_predecessor.observed_at()
            < receiver_situation.observed_at()
    {
        return Err(CrossHeadTaskTransferRefusal::ReceiverSituationTaskMismatch);
    }

    let source_authority = source_run
        .authority_read_receipt()
        .ok_or(CrossHeadTaskTransferRefusal::SourceAuthorityReceiptRequired)?;
    let ancestry = acceptance
        .authority_ancestry()
        .ok_or(CrossHeadTaskTransferRefusal::DescendantAncestryRequired)?;
    let expected_hops = receiver_authority
        .authority_head_generation()
        .get()
        .checked_sub(source_authority.authority_head_generation().get())
        .ok_or(CrossHeadTaskTransferRefusal::AncestryMismatch)?;
    if expected_hops == 0
        || ancestry.repository_id() != source_authority.repository_id()
        || ancestry.ancestor_head_id() != source_authority.authority_head_id()
        || ancestry.ancestor_generation()
            != source_authority.authority_head_generation()
        || ancestry.descendant_head_id()
            != receiver_authority.authority_head_id()
        || ancestry.descendant_generation()
            != receiver_authority.authority_head_generation()
        || ancestry.descendant_version_token()
            != receiver_authority.backend_version_token()
        || u64::from(ancestry.hops()) != expected_hops
    {
        return Err(CrossHeadTaskTransferRefusal::AncestryMismatch);
    }
    Ok(())
}

fn validate_semantic_predecessor(
    source: &AuthorityBoundTaskProjectionSnapshot,
    receiver: &AuthorityBoundTaskProjectionSnapshot,
) -> Result<(), CrossHeadTaskTransferRefusal> {
    if source.task_id() != receiver.task_id()
        || source.generation() != receiver.generation()
        || source.phase() != receiver.phase()
        || source.assignment() != receiver.assignment()
        || !leases_match(source.lease(), receiver.lease())
    {
        return Err(
            CrossHeadTaskTransferRefusal::ReceiverPredecessorSemanticMismatch,
        );
    }
    Ok(())
}

fn same_receiver_authority_position(
    expected: &AuthorityReadReceipt,
    observed: &AuthorityReadReceipt,
) -> bool {
    expected.repository_id() == observed.repository_id()
        && expected.authority_head_id() == observed.authority_head_id()
        && expected.authority_head_generation()
            == observed.authority_head_generation()
        && expected.backend_version_token() == observed.backend_version_token()
}

fn semantic_snapshot_matches(
    expected: &AuthorityBoundTaskProjectionSnapshot,
    observed: &AuthorityBoundTaskProjectionSnapshot,
) -> bool {
    expected.snapshot_id() == observed.snapshot_id()
        && expected.repository_id() == observed.repository_id()
        && expected.task_id() == observed.task_id()
        && expected.generation() == observed.generation()
        && expected.phase() == observed.phase()
        && expected.assignment() == observed.assignment()
        && leases_match(expected.lease(), observed.lease())
}

fn leases_match(left: Option<&TaskProjectionLease>, right: Option<&TaskProjectionLease>) -> bool {
    left == right
}

fn validate_successor_metadata(
    envelope: &CrossHeadTaskTransferEnvelope,
    observed: &CrossHeadTaskTransferPersistedState,
) -> Result<(), CrossHeadTaskTransferRefusal> {
    if observed.last_envelope_id != Some(envelope.envelope_id) {
        return Err(CrossHeadTaskTransferRefusal::SuccessorEnvelopeMismatch);
    }
    if observed.acceptance_id != Some(envelope.acceptance_id) {
        return Err(CrossHeadTaskTransferRefusal::SuccessorAcceptanceMismatch);
    }
    if observed.ancestry_receipt_id != Some(envelope.ancestry_receipt_id) {
        return Err(CrossHeadTaskTransferRefusal::SuccessorAncestryMismatch);
    }
    if observed.evidence_root != Some(envelope.evidence_root) {
        return Err(CrossHeadTaskTransferRefusal::SuccessorEvidenceMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn derive_transfer_generation(
    source_snapshot: &AuthorityBoundTaskProjectionSnapshot,
    receiver_predecessor: &AuthorityBoundTaskProjectionSnapshot,
    source_claim: &TaskClaimReceipt,
    source_active_claim: ActiveTaskClaim,
    capsule: &AgentHandoffCapsule,
    acceptance: &AgentHandoffAcceptance,
    ancestry_receipt_id: AuthorityHeadAncestryReceiptId,
    source_run_id: crate::RunId,
    source_run_commitment: IntentRunCommitment,
    receiver_run_id: crate::RunId,
    receiver_run_commitment: IntentRunCommitment,
    transferred_at: LogicalTime,
) -> Result<[u8; 32], CrossHeadTaskTransferRefusal> {
    let mut encoder = Encoder::with_capacity(768);
    encoder.write_bytes(
        "cross_head_task_transfer_generation_domain",
        GENERATION_DOMAIN,
    )?;
    encoder.write_opaque_id(source_snapshot.repository_id().as_bytes());
    encoder.write_raw(source_snapshot.task_id().as_bytes());
    encoder.write_raw(source_snapshot.generation());
    encoder.write_raw(source_snapshot.snapshot_id().as_bytes());
    encoder.write_raw(receiver_predecessor.snapshot_id().as_bytes());
    encoder.write_raw(source_claim.claim_id().as_bytes());
    encoder.write_raw(source_active_claim.activation_id().as_bytes());
    encoder.write_raw(capsule.capsule_id().as_bytes());
    encoder.write_raw(acceptance.acceptance_id().as_bytes());
    encoder.write_raw(ancestry_receipt_id.as_bytes());
    encoder.write_raw(&source_run_id.value().to_be_bytes());
    encoder.write_raw(source_run_commitment.as_bytes());
    encoder.write_raw(&receiver_run_id.value().to_be_bytes());
    encoder.write_raw(receiver_run_commitment.as_bytes());
    encoder.write_scalar(transferred_at.value());
    Ok(hash(&encoder.into_bytes()))
}

fn envelope_commitment(
    envelope: &CrossHeadTaskTransferEnvelope,
) -> Result<[u8; 32], CrossHeadTaskTransferRefusal> {
    let mut encoder = Encoder::with_capacity(1_024);
    encoder.write_bytes("cross_head_task_transfer_envelope_domain", ENVELOPE_DOMAIN)?;
    encoder.write_opaque_id(envelope.repository_id.as_bytes());
    encoder.write_raw(envelope.task_id.as_bytes());
    encoder.write_raw(envelope.source_authority_read_receipt_id.as_bytes());
    encoder.write_raw(envelope.receiver_authority_read_receipt_id.as_bytes());
    encoder.write_raw(envelope.source_snapshot.snapshot_id().as_bytes());
    encoder.write_raw(envelope.receiver_predecessor.snapshot_id().as_bytes());
    encoder.write_raw(envelope.receiver_successor.snapshot_id().as_bytes());
    encoder.write_raw(envelope.source_snapshot.generation());
    encoder.write_raw(envelope.receiver_successor.generation());
    encoder.write_raw(envelope.source_claim_id.as_bytes());
    encoder.write_raw(envelope.source_active_claim_id.as_bytes());
    encoder.write_raw(envelope.source_plan_id.as_bytes());
    encoder.write_raw(envelope.capsule_id.as_bytes());
    encoder.write_raw(envelope.acceptance_id.as_bytes());
    encoder.write_raw(envelope.ancestry_receipt_id.as_bytes());
    encoder.write_raw(&envelope.source_run_id.value().to_be_bytes());
    encoder.write_raw(envelope.source_run_commitment.as_bytes());
    encoder.write_raw(&envelope.receiver_run_id.value().to_be_bytes());
    encoder.write_raw(envelope.receiver_run_commitment.as_bytes());
    encoder.write_scalar(envelope.transferred_at.value());
    encoder.write_raw(&envelope.adapter_identity);
    encoder.write_digest(&envelope.evidence_root)?;
    Ok(hash(&encoder.into_bytes()))
}

fn receipt_commitment(
    receipt: &CrossHeadTaskTransferReceipt,
) -> Result<[u8; 32], CrossHeadTaskTransferRefusal> {
    let mut encoder = Encoder::with_capacity(768);
    encoder.write_bytes("cross_head_task_transfer_receipt_domain", RECEIPT_DOMAIN)?;
    encoder.write_raw(receipt.envelope_id.as_bytes());
    encoder.write_raw(receipt.source_authority_read_receipt_id.as_bytes());
    encoder.write_raw(receipt.receiver_authority_read_receipt_id.as_bytes());
    encoder.write_raw(receipt.confirming_authority_read_receipt_id.as_bytes());
    encoder.write_opaque_id(receipt.repository_id.as_bytes());
    encoder.write_raw(receipt.task_id.as_bytes());
    encoder.write_raw(receipt.successor_snapshot_id.as_bytes());
    encoder.write_raw(&receipt.previous_generation);
    encoder.write_raw(&receipt.resulting_generation);
    encoder.write_raw(receipt.capsule_id.as_bytes());
    encoder.write_raw(receipt.acceptance_id.as_bytes());
    encoder.write_raw(receipt.ancestry_receipt_id.as_bytes());
    encoder.write_raw(receipt.source_run_commitment.as_bytes());
    encoder.write_raw(receipt.receiver_run_commitment.as_bytes());
    encoder.write_digest(&receipt.evidence_root)?;
    encoder.write_scalar(receipt.observed_at.value());
    Ok(hash(&encoder.into_bytes()))
}

fn activation_commitment(
    receipt: &CrossHeadTaskTransferActivationReceipt,
) -> Result<[u8; 32], CrossHeadTaskTransferActivationRefusal> {
    let mut encoder = Encoder::with_capacity(480);
    encoder.write_bytes(
        "cross_head_task_transfer_activation_domain",
        ACTIVATION_DOMAIN,
    )?;
    encoder.write_raw(receipt.transfer_receipt_id.as_bytes());
    encoder.write_raw(receipt.persisted_claim_receipt_id.as_bytes());
    encoder.write_raw(receipt.receiver_claim_id.as_bytes());
    encoder.write_raw(receipt.receiver_active_claim_id.as_bytes());
    encoder.write_raw(receipt.receiver_situation_id.as_bytes());
    encoder.write_raw(receipt.receiver_run_commitment.as_bytes());
    encoder.write_raw(&receipt.transfer_generation);
    encoder.write_raw(&receipt.claimed_generation);
    encoder.write_scalar(receipt.observed_at.value());
    Ok(hash(&encoder.into_bytes()))
}

const fn flush_is_definite_success(
    disposition: TaskProjectionStoreFlushDisposition,
) -> bool {
    matches!(
        disposition,
        TaskProjectionStoreFlushDisposition::Flushed
            | TaskProjectionStoreFlushDisposition::NotRequired
    )
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8; 32]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
