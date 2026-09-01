//! Exact-predecessor persistence and ambiguous-write reconciliation for tasks.
//!
//! [`crate::task_coordination`] computes a complete repository-scoped semantic
//! transition. This module freezes both predecessor and successor state into a
//! backend mutation envelope and interprets a later authenticated reread after
//! success, timeout, crash, or lost response.
//!
//! A backend observation is constructed from a real
//! [`crate::AuthorityBoundTaskProjectionSnapshot`], not caller-supplied snapshot
//! identity bytes. Reconciliation therefore compares phase, assignment, lease,
//! generation, authority position, and task namespace in addition to transition
//! metadata. Matching an ID string alone is never persistence proof.
//!
//! The evidence root remains a predeclared mutation-evidence contract. The
//! persistence receipt proves that an authenticated reread retained that
//! contract beside the exact semantic successor. Reusing the same evidence
//! contract on an unchanged predecessor is not itself a partial write; only
//! attempted transition identities can establish that contradiction.
//!
//! This module defines no storage implementation and grants no repository
//! authority.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::{Digest, RepositoryId};

use crate::{
    AuthorityBoundTaskClaimApplication, AuthorityBoundTaskProjectionSnapshot,
    AuthorityBoundTaskProjectionSnapshotId, AuthorityBoundTaskProjectionTransition,
    AuthorityBoundTaskProjectionTransitionId, AuthorityBoundTaskResolutionApplication,
    AuthorityReadIdentityRefusal, AuthorityReadReceiptId, LogicalTime, TaskProjectionLease,
    TaskProjectionTransitionKind, WorkTaskId,
};

const ENVELOPE_DOMAIN: &[u8] = b"frankengit.agent.task-mutation-envelope/v2\0";
const RECEIPT_DOMAIN: &[u8] = b"frankengit.agent.task-persistence-receipt/v2\0";

/// Stable identity of one exact-predecessor task mutation request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskProjectionMutationEnvelopeId([u8; 32]);

impl TaskProjectionMutationEnvelopeId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TaskProjectionMutationEnvelopeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task-mutation:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable identity of one confirmed persisted task successor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskProjectionPersistenceReceiptId([u8; 32]);

impl TaskProjectionPersistenceReceiptId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TaskProjectionPersistenceReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task-persisted:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Complete compare-and-replace request for one task transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjectionMutationEnvelope {
    envelope_id: TaskProjectionMutationEnvelopeId,
    repository_id: RepositoryId,
    task_id: WorkTaskId,
    basis_authority_read_receipt_id: AuthorityReadReceiptId,
    before: AuthorityBoundTaskProjectionSnapshot,
    after: AuthorityBoundTaskProjectionSnapshot,
    transition_id: AuthorityBoundTaskProjectionTransitionId,
    inner_transition_id: [u8; 32],
    kind: TaskProjectionTransitionKind,
    transition_observed_at: LogicalTime,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
}

impl TaskProjectionMutationEnvelope {
    /// Freezes one claim application for backend persistence.
    ///
    /// # Errors
    ///
    /// Refuses internal application inconsistency and canonical framing failure.
    pub fn from_claim(
        application: &AuthorityBoundTaskClaimApplication,
    ) -> Result<Self, TaskProjectionPersistenceRefusal> {
        Self::from_parts(
            application.before_snapshot().clone(),
            application.snapshot().clone(),
            application.transition(),
        )
    }

    /// Freezes one release or transfer application for backend persistence.
    ///
    /// # Errors
    ///
    /// Refuses internal application inconsistency and canonical framing failure.
    pub fn from_resolution(
        application: &AuthorityBoundTaskResolutionApplication,
    ) -> Result<Self, TaskProjectionPersistenceRefusal> {
        Self::from_parts(
            application.before_snapshot().clone(),
            application.snapshot().clone(),
            application.transition(),
        )
    }

    fn from_parts(
        before: AuthorityBoundTaskProjectionSnapshot,
        after: AuthorityBoundTaskProjectionSnapshot,
        transition: AuthorityBoundTaskProjectionTransition,
    ) -> Result<Self, TaskProjectionPersistenceRefusal> {
        if before.repository_id() != after.repository_id()
            || transition.repository_id() != after.repository_id()
        {
            return Err(TaskProjectionPersistenceRefusal::ApplicationRepositoryMismatch);
        }
        if before.task_id() != after.task_id() || transition.task_id() != after.task_id() {
            return Err(TaskProjectionPersistenceRefusal::ApplicationTaskMismatch);
        }
        if transition.before_snapshot_id() != before.snapshot_id() {
            return Err(TaskProjectionPersistenceRefusal::ApplicationPredecessorMismatch);
        }
        if transition.after_snapshot_id() != after.snapshot_id() {
            return Err(TaskProjectionPersistenceRefusal::ApplicationSuccessorMismatch);
        }
        if transition.previous_generation() != *before.generation()
            || transition.resulting_generation() != *after.generation()
        {
            return Err(TaskProjectionPersistenceRefusal::ApplicationGenerationMismatch);
        }
        if before.authority_read_receipt_id() != after.authority_read_receipt_id()
            || transition.authority_read_receipt_id() != before.authority_read_receipt_id()
        {
            return Err(TaskProjectionPersistenceRefusal::ApplicationAuthorityMismatch);
        }
        if transition.observed_at() < before.observed_at()
            || after.observed_at() < transition.observed_at()
        {
            return Err(TaskProjectionPersistenceRefusal::ApplicationObservationMismatch);
        }

        let mut envelope = Self {
            envelope_id: TaskProjectionMutationEnvelopeId([0; 32]),
            repository_id: after.repository_id(),
            task_id: after.task_id(),
            basis_authority_read_receipt_id: before.authority_read_receipt_id(),
            before,
            after,
            transition_id: transition.transition_id(),
            inner_transition_id: *transition.inner_transition_id(),
            kind: transition.kind(),
            transition_observed_at: transition.observed_at(),
            adapter_identity: transition.adapter_identity(),
            evidence_root: transition.evidence_root(),
        };
        envelope.envelope_id = TaskProjectionMutationEnvelopeId(envelope_commitment(&envelope)?);
        Ok(envelope)
    }

    /// Reconciles one authenticated backend reread.
    ///
    /// # Errors
    ///
    /// Refuses missing rows, repository/task/authority substitution,
    /// observation rollback, a predecessor carrying this attempted transition,
    /// and an exact successor whose transition or evidence metadata is absent
    /// or changed.
    pub fn reconcile(
        &self,
        observed: Option<&TaskProjectionPersistedState>,
    ) -> Result<TaskProjectionPersistenceDecision, TaskProjectionPersistenceRefusal> {
        let observed = observed.ok_or(TaskProjectionPersistenceRefusal::ProjectionMissing)?;
        let snapshot = observed.snapshot();
        if snapshot.repository_id() != self.repository_id {
            return Err(TaskProjectionPersistenceRefusal::ObservedRepositoryMismatch {
                expected: self.repository_id,
                observed: snapshot.repository_id(),
            });
        }
        if snapshot.task_id() != self.task_id {
            return Err(TaskProjectionPersistenceRefusal::ObservedTaskMismatch {
                expected: self.task_id,
                observed: snapshot.task_id(),
            });
        }
        if !same_authority_position(&self.before, snapshot) {
            return Err(TaskProjectionPersistenceRefusal::ObservedAuthorityPositionMismatch);
        }
        if snapshot.observed_at() < self.transition_observed_at {
            return Err(TaskProjectionPersistenceRefusal::ObservationRollback {
                transition_observed_at: self.transition_observed_at,
                backend_observed_at: snapshot.observed_at(),
            });
        }

        if semantic_snapshot_matches(&self.before, snapshot) {
            if observed.last_transition_id == Some(*self.transition_id.as_bytes())
                || observed.last_inner_transition_id == Some(self.inner_transition_id)
            {
                return Err(
                    TaskProjectionPersistenceRefusal::PredecessorCarriesAttemptedMetadata,
                );
            }
            return Ok(TaskProjectionPersistenceDecision::RetrySafe {
                envelope_id: self.envelope_id,
                current_snapshot_id: snapshot.snapshot_id(),
                current_generation: *snapshot.generation(),
            });
        }

        if semantic_snapshot_matches(&self.after, snapshot) {
            validate_successor_metadata(self, observed)?;
            let receipt = TaskProjectionPersistenceReceipt::build(self, observed)?;
            return Ok(TaskProjectionPersistenceDecision::Confirmed(receipt));
        }

        Ok(TaskProjectionPersistenceDecision::Conflict {
            envelope_id: self.envelope_id,
            current_snapshot_id: snapshot.snapshot_id(),
            current_generation: *snapshot.generation(),
        })
    }

    /// Stable mutation-envelope identity.
    #[must_use]
    pub const fn envelope_id(&self) -> TaskProjectionMutationEnvelopeId {
        self.envelope_id
    }

    /// Repository namespace.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Task being mutated.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.task_id
    }

    /// Exact authenticated read event that authorized mutation construction.
    #[must_use]
    pub const fn basis_authority_read_receipt_id(&self) -> AuthorityReadReceiptId {
        self.basis_authority_read_receipt_id
    }

    /// Complete exact predecessor state.
    #[must_use]
    pub const fn before_snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.before
    }

    /// Complete desired successor state.
    #[must_use]
    pub const fn after_snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.after
    }

    /// Exact predecessor snapshot identity.
    #[must_use]
    pub const fn before_snapshot_id(&self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.before.snapshot_id()
    }

    /// Exact successor snapshot identity.
    #[must_use]
    pub const fn after_snapshot_id(&self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.after.snapshot_id()
    }

    /// Exact predecessor generation.
    #[must_use]
    pub const fn previous_generation(&self) -> [u8; 32] {
        *self.before.generation()
    }

    /// Exact successor generation.
    #[must_use]
    pub const fn resulting_generation(&self) -> [u8; 32] {
        *self.after.generation()
    }

    /// Repository-scoped transition identity.
    #[must_use]
    pub const fn transition_id(&self) -> AuthorityBoundTaskProjectionTransitionId {
        self.transition_id
    }

    /// Semantic transition-body commitment.
    #[must_use]
    pub const fn inner_transition_id(&self) -> [u8; 32] {
        self.inner_transition_id
    }

    /// Claim, release, or transfer semantics.
    #[must_use]
    pub const fn kind(&self) -> TaskProjectionTransitionKind {
        self.kind
    }

    /// Logical transition instant.
    #[must_use]
    pub const fn transition_observed_at(&self) -> LogicalTime {
        self.transition_observed_at
    }

    /// Backend implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(&self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Predeclared mutation-evidence contract.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }
}

/// Authenticated task row read after an attempted mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjectionPersistedState {
    snapshot: AuthorityBoundTaskProjectionSnapshot,
    last_transition_id: Option<[u8; 32]>,
    last_inner_transition_id: Option<[u8; 32]>,
    evidence_root: Option<Digest>,
}

impl TaskProjectionPersistedState {
    /// Creates one backend reread observation from a structurally validated
    /// authority-bound snapshot.
    #[must_use]
    pub const fn new(
        snapshot: AuthorityBoundTaskProjectionSnapshot,
        last_transition_id: Option<[u8; 32]>,
        last_inner_transition_id: Option<[u8; 32]>,
        evidence_root: Option<Digest>,
    ) -> Self {
        Self {
            snapshot,
            last_transition_id,
            last_inner_transition_id,
            evidence_root,
        }
    }

    /// Complete authenticated task state.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.snapshot
    }

    /// Repository namespace read from the backend.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.snapshot.repository_id()
    }

    /// Task read from the backend.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.snapshot.task_id()
    }

    /// Current semantic snapshot identity.
    #[must_use]
    pub const fn snapshot_id(&self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.snapshot.snapshot_id()
    }

    /// Current task-projection generation.
    #[must_use]
    pub const fn generation(&self) -> [u8; 32] {
        *self.snapshot.generation()
    }

    /// Last repository-scoped transition identity, when retained.
    #[must_use]
    pub const fn last_transition_id(&self) -> Option<[u8; 32]> {
        self.last_transition_id
    }

    /// Last inner transition identity, when retained.
    #[must_use]
    pub const fn last_inner_transition_id(&self) -> Option<[u8; 32]> {
        self.last_inner_transition_id
    }

    /// Retained mutation-evidence contract, when present.
    #[must_use]
    pub const fn evidence_root(&self) -> Option<Digest> {
        self.evidence_root
    }

    /// Logical time of the reconciled backend read.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.snapshot.observed_at()
    }
}

/// Deterministic interpretation of a backend reread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskProjectionPersistenceDecision {
    /// The exact semantic successor and all transition metadata were observed.
    Confirmed(TaskProjectionPersistenceReceipt),
    /// The exact predecessor remains current; replaying this envelope is safe.
    RetrySafe {
        /// Mutation request being retried.
        envelope_id: TaskProjectionMutationEnvelopeId,
        /// Still-current predecessor snapshot.
        current_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
        /// Still-current predecessor generation.
        current_generation: [u8; 32],
    },
    /// Another successor won or the row changed incompatibly.
    Conflict {
        /// Mutation request that lost or became stale.
        envelope_id: TaskProjectionMutationEnvelopeId,
        /// Current conflicting snapshot identity.
        current_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
        /// Current conflicting generation.
        current_generation: [u8; 32],
    },
}

/// Verified persistence receipt for the exact task successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskProjectionPersistenceReceipt {
    receipt_id: TaskProjectionPersistenceReceiptId,
    envelope_id: TaskProjectionMutationEnvelopeId,
    basis_authority_read_receipt_id: AuthorityReadReceiptId,
    confirming_authority_read_receipt_id: AuthorityReadReceiptId,
    repository_id: RepositoryId,
    task_id: WorkTaskId,
    snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
    generation: [u8; 32],
    transition_id: [u8; 32],
    inner_transition_id: [u8; 32],
    evidence_root: Digest,
    observed_at: LogicalTime,
}

impl TaskProjectionPersistenceReceipt {
    fn build(
        envelope: &TaskProjectionMutationEnvelope,
        observed: &TaskProjectionPersistedState,
    ) -> Result<Self, TaskProjectionPersistenceRefusal> {
        let confirming_authority_read_receipt_id =
            observed.snapshot.authority_read_receipt().receipt_id()?;
        let mut receipt = Self {
            receipt_id: TaskProjectionPersistenceReceiptId([0; 32]),
            envelope_id: envelope.envelope_id,
            basis_authority_read_receipt_id: envelope.basis_authority_read_receipt_id,
            confirming_authority_read_receipt_id,
            repository_id: envelope.repository_id,
            task_id: envelope.task_id,
            snapshot_id: observed.snapshot.snapshot_id(),
            generation: *observed.snapshot.generation(),
            transition_id: observed
                .last_transition_id
                .ok_or(TaskProjectionPersistenceRefusal::SuccessorTransitionMissing)?,
            inner_transition_id: observed
                .last_inner_transition_id
                .ok_or(TaskProjectionPersistenceRefusal::SuccessorInnerTransitionMissing)?,
            evidence_root: observed
                .evidence_root
                .ok_or(TaskProjectionPersistenceRefusal::SuccessorEvidenceMissing)?,
            observed_at: observed.snapshot.observed_at(),
        };
        receipt.receipt_id =
            TaskProjectionPersistenceReceiptId(receipt_commitment(&receipt)?);
        Ok(receipt)
    }

    /// Stable persistence-receipt identity.
    #[must_use]
    pub const fn receipt_id(self) -> TaskProjectionPersistenceReceiptId {
        self.receipt_id
    }

    /// Exact mutation envelope confirmed.
    #[must_use]
    pub const fn envelope_id(self) -> TaskProjectionMutationEnvelopeId {
        self.envelope_id
    }

    /// Exact read event that authorized the mutation envelope.
    #[must_use]
    pub const fn basis_authority_read_receipt_id(self) -> AuthorityReadReceiptId {
        self.basis_authority_read_receipt_id
    }

    /// Exact authenticated reread that confirmed the successor.
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

    /// Persisted successor snapshot identity.
    #[must_use]
    pub const fn snapshot_id(self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.snapshot_id
    }

    /// Persisted successor generation.
    #[must_use]
    pub const fn generation(self) -> [u8; 32] {
        self.generation
    }

    /// Persisted repository-scoped transition identity.
    #[must_use]
    pub const fn transition_id(self) -> [u8; 32] {
        self.transition_id
    }

    /// Persisted inner transition identity.
    #[must_use]
    pub const fn inner_transition_id(self) -> [u8; 32] {
        self.inner_transition_id
    }

    /// Persisted mutation-evidence contract.
    #[must_use]
    pub const fn evidence_root(self) -> Digest {
        self.evidence_root
    }

    /// Logical time of the confirming reread.
    #[must_use]
    pub const fn observed_at(self) -> LogicalTime {
        self.observed_at
    }
}

/// Why task mutation persistence could not be confirmed safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionPersistenceRefusal {
    /// Application repository differs across its state and transition.
    ApplicationRepositoryMismatch,
    /// Application task differs across its state and transition.
    ApplicationTaskMismatch,
    /// Application predecessor differs from its transition.
    ApplicationPredecessorMismatch,
    /// Application successor differs from its transition.
    ApplicationSuccessorMismatch,
    /// Application predecessor/successor generation differs from its transition.
    ApplicationGenerationMismatch,
    /// Application changed its exact authenticated read basis.
    ApplicationAuthorityMismatch,
    /// Application time ordering is inconsistent.
    ApplicationObservationMismatch,
    /// Backend reread found no task row.
    ProjectionMissing,
    /// Backend reread belongs to another repository.
    ObservedRepositoryMismatch {
        /// Envelope repository.
        expected: RepositoryId,
        /// Backend repository.
        observed: RepositoryId,
    },
    /// Backend reread belongs to another task.
    ObservedTaskMismatch {
        /// Envelope task.
        expected: WorkTaskId,
        /// Backend task.
        observed: WorkTaskId,
    },
    /// Backend reread uses another authority-head position.
    ObservedAuthorityPositionMismatch,
    /// Backend reread predates the transition.
    ObservationRollback {
        /// Transition time.
        transition_observed_at: LogicalTime,
        /// Backend reread time.
        backend_observed_at: LogicalTime,
    },
    /// The predecessor remains current but carries transition identity from
    /// this attempted successor, which is a partial/corrupt write rather than a
    /// safe retry.
    PredecessorCarriesAttemptedMetadata,
    /// Exact successor omitted repository-scoped transition identity.
    SuccessorTransitionMissing,
    /// Exact successor retained another repository-scoped transition identity.
    SuccessorTransitionMismatch {
        /// Envelope transition.
        expected: [u8; 32],
        /// Backend transition.
        observed: [u8; 32],
    },
    /// Exact successor omitted inner transition identity.
    SuccessorInnerTransitionMissing,
    /// Exact successor retained another inner transition identity.
    SuccessorInnerTransitionMismatch {
        /// Envelope inner transition.
        expected: [u8; 32],
        /// Backend inner transition.
        observed: [u8; 32],
    },
    /// Exact successor omitted the mutation-evidence contract.
    SuccessorEvidenceMissing,
    /// Exact successor retained another evidence contract.
    SuccessorEvidenceMismatch {
        /// Envelope evidence root.
        expected: Digest,
        /// Backend evidence root.
        observed: Digest,
    },
    /// Exact authenticated-read identity could not be framed.
    AuthorityIdentity(AuthorityReadIdentityRefusal),
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for TaskProjectionPersistenceRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task projection persistence refused: {self:?}")
    }
}

impl core::error::Error for TaskProjectionPersistenceRefusal {}

impl From<AuthorityReadIdentityRefusal> for TaskProjectionPersistenceRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::AuthorityIdentity(value)
    }
}

impl From<CodecRefusal> for TaskProjectionPersistenceRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn same_authority_position(
    expected: &AuthorityBoundTaskProjectionSnapshot,
    observed: &AuthorityBoundTaskProjectionSnapshot,
) -> bool {
    let expected_receipt = expected.authority_read_receipt();
    let observed_receipt = observed.authority_read_receipt();
    expected_receipt.repository_id() == observed_receipt.repository_id()
        && expected_receipt.authority_head_id() == observed_receipt.authority_head_id()
        && expected_receipt.authority_head_generation()
            == observed_receipt.authority_head_generation()
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
    envelope: &TaskProjectionMutationEnvelope,
    observed: &TaskProjectionPersistedState,
) -> Result<(), TaskProjectionPersistenceRefusal> {
    let transition_id = observed
        .last_transition_id
        .ok_or(TaskProjectionPersistenceRefusal::SuccessorTransitionMissing)?;
    let expected_transition = *envelope.transition_id.as_bytes();
    if transition_id != expected_transition {
        return Err(TaskProjectionPersistenceRefusal::SuccessorTransitionMismatch {
            expected: expected_transition,
            observed: transition_id,
        });
    }

    let inner_transition_id = observed
        .last_inner_transition_id
        .ok_or(TaskProjectionPersistenceRefusal::SuccessorInnerTransitionMissing)?;
    if inner_transition_id != envelope.inner_transition_id {
        return Err(
            TaskProjectionPersistenceRefusal::SuccessorInnerTransitionMismatch {
                expected: envelope.inner_transition_id,
                observed: inner_transition_id,
            },
        );
    }

    let evidence_root = observed
        .evidence_root
        .ok_or(TaskProjectionPersistenceRefusal::SuccessorEvidenceMissing)?;
    if evidence_root != envelope.evidence_root {
        return Err(TaskProjectionPersistenceRefusal::SuccessorEvidenceMismatch {
            expected: envelope.evidence_root,
            observed: evidence_root,
        });
    }
    Ok(())
}

fn envelope_commitment(
    envelope: &TaskProjectionMutationEnvelope,
) -> Result<[u8; 32], TaskProjectionPersistenceRefusal> {
    let mut encoder = Encoder::with_capacity(704);
    encoder.write_bytes("task_mutation_envelope_domain", ENVELOPE_DOMAIN)?;
    encoder.write_opaque_id(envelope.repository_id.as_bytes());
    encoder.write_raw(envelope.task_id.as_bytes());
    encoder.write_raw(envelope.basis_authority_read_receipt_id.as_bytes());
    encoder.write_raw(envelope.before.snapshot_id().as_bytes());
    encoder.write_raw(envelope.after.snapshot_id().as_bytes());
    encoder.write_raw(envelope.before.generation());
    encoder.write_raw(envelope.after.generation());
    encoder.write_raw(envelope.transition_id.as_bytes());
    encoder.write_raw(&envelope.inner_transition_id);
    write_transition_kind(&mut encoder, envelope.kind);
    encoder.write_scalar(envelope.transition_observed_at.value());
    encoder.write_raw(&envelope.adapter_identity);
    encoder.write_digest(&envelope.evidence_root)?;
    Ok(hash(&encoder.into_bytes()))
}

fn receipt_commitment(
    receipt: &TaskProjectionPersistenceReceipt,
) -> Result<[u8; 32], TaskProjectionPersistenceRefusal> {
    let mut encoder = Encoder::with_capacity(544);
    encoder.write_bytes("task_persistence_receipt_domain", RECEIPT_DOMAIN)?;
    encoder.write_raw(receipt.envelope_id.as_bytes());
    encoder.write_raw(receipt.basis_authority_read_receipt_id.as_bytes());
    encoder.write_raw(receipt.confirming_authority_read_receipt_id.as_bytes());
    encoder.write_opaque_id(receipt.repository_id.as_bytes());
    encoder.write_raw(receipt.task_id.as_bytes());
    encoder.write_raw(receipt.snapshot_id.as_bytes());
    encoder.write_raw(&receipt.generation);
    encoder.write_raw(&receipt.transition_id);
    encoder.write_raw(&receipt.inner_transition_id);
    encoder.write_digest(&receipt.evidence_root)?;
    encoder.write_scalar(receipt.observed_at.value());
    Ok(hash(&encoder.into_bytes()))
}

fn write_transition_kind(encoder: &mut Encoder, kind: TaskProjectionTransitionKind) {
    match kind {
        TaskProjectionTransitionKind::Claimed { action } => {
            encoder.write_raw_byte(1);
            encoder.write_raw_byte(match action {
                crate::WorkAction::Implement => 1,
                crate::WorkAction::Verify => 2,
                crate::WorkAction::Rework => 3,
            });
        }
        TaskProjectionTransitionKind::Released { next_phase } => {
            encoder.write_raw_byte(2);
            encoder.write_raw_byte(match next_phase {
                crate::TaskPhase::Open => 1,
                crate::TaskPhase::InProgress => 2,
                crate::TaskPhase::ImplementationReady => 3,
                crate::TaskPhase::VerificationPending => 4,
                crate::TaskPhase::Rework => 5,
                crate::TaskPhase::Verified => 6,
                crate::TaskPhase::Closed => 7,
                crate::TaskPhase::Superseded => 8,
            });
        }
        TaskProjectionTransitionKind::Transferred { successor_run_id } => {
            encoder.write_raw_byte(3);
            encoder.write_raw(&successor_run_id.value().to_be_bytes());
        }
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}
