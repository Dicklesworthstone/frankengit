//! Exact-predecessor persistence and ambiguous-write reconciliation for tasks.
//!
//! [`crate::task_coordination`] computes a repository-scoped transition but does
//! not persist it. This module freezes that transition into a
//! [`TaskProjectionMutationEnvelope`] suitable for a compare-and-replace backend
//! and independently reconciles the task row after success, timeout, crash, or
//! lost response.
//!
//! The evidence root in a transition is a predeclared canonical mutation-
//! evidence contract known before the write. The persistence receipt produced
//! here is the proof that a backend observation retained that contract beside
//! the exact successor. This avoids a circular identity in which a successor
//! generation depends on evidence that can exist only after the successor was
//! stored.
//!
//! No storage implementation lives here. A production Beads adapter must own
//! the actual read/CAS/flush/retry boundary and translate its reconciled row into
//! [`TaskProjectionPersistedState`].

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::{Digest, RepositoryId};

use crate::{
    AuthorityBoundTaskClaimApplication, AuthorityBoundTaskProjectionSnapshotId,
    AuthorityBoundTaskProjectionTransitionId, AuthorityBoundTaskResolutionApplication,
    LogicalTime, TaskProjectionTransitionKind, WorkTaskId,
};

const ENVELOPE_DOMAIN: &[u8] = b"frankengit.agent.task-mutation-envelope/v1\0";
const RECEIPT_DOMAIN: &[u8] = b"frankengit.agent.task-persistence-receipt/v1\0";

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskProjectionMutationEnvelope {
    envelope_id: TaskProjectionMutationEnvelopeId,
    repository_id: RepositoryId,
    task_id: WorkTaskId,
    before_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
    after_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
    previous_generation: [u8; 32],
    resulting_generation: [u8; 32],
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
            application.snapshot().repository_id(),
            application.snapshot().task_id(),
            application.snapshot().snapshot_id(),
            *application.snapshot().generation(),
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
            application.snapshot().repository_id(),
            application.snapshot().task_id(),
            application.snapshot().snapshot_id(),
            *application.snapshot().generation(),
            application.transition(),
        )
    }

    fn from_parts(
        repository_id: RepositoryId,
        task_id: WorkTaskId,
        after_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
        resulting_generation: [u8; 32],
        transition: crate::AuthorityBoundTaskProjectionTransition,
    ) -> Result<Self, TaskProjectionPersistenceRefusal> {
        if transition.repository_id() != repository_id {
            return Err(TaskProjectionPersistenceRefusal::ApplicationRepositoryMismatch);
        }
        if transition.task_id() != task_id {
            return Err(TaskProjectionPersistenceRefusal::ApplicationTaskMismatch);
        }
        if transition.after_snapshot_id() != after_snapshot_id {
            return Err(TaskProjectionPersistenceRefusal::ApplicationSuccessorMismatch);
        }
        if transition.resulting_generation() != resulting_generation {
            return Err(TaskProjectionPersistenceRefusal::ApplicationGenerationMismatch);
        }

        let mut envelope = Self {
            envelope_id: TaskProjectionMutationEnvelopeId([0; 32]),
            repository_id,
            task_id,
            before_snapshot_id: transition.before_snapshot_id(),
            after_snapshot_id,
            previous_generation: transition.previous_generation(),
            resulting_generation,
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

    /// Reconciles one backend read after a CAS attempt or ambiguous response.
    ///
    /// # Errors
    ///
    /// Refuses a missing row, repository/task substitution, observation
    /// rollback, and a successor whose transition, inner transition, or evidence
    /// metadata was omitted or changed.
    pub fn reconcile(
        &self,
        observed: Option<&TaskProjectionPersistedState>,
    ) -> Result<TaskProjectionPersistenceDecision, TaskProjectionPersistenceRefusal> {
        let observed = observed.ok_or(TaskProjectionPersistenceRefusal::ProjectionMissing)?;
        if observed.repository_id != self.repository_id {
            return Err(TaskProjectionPersistenceRefusal::ObservedRepositoryMismatch {
                expected: self.repository_id,
                observed: observed.repository_id,
            });
        }
        if observed.task_id != self.task_id {
            return Err(TaskProjectionPersistenceRefusal::ObservedTaskMismatch {
                expected: self.task_id,
                observed: observed.task_id,
            });
        }
        if observed.observed_at.value() < self.transition_observed_at.value() {
            return Err(TaskProjectionPersistenceRefusal::ObservationRollback {
                transition_observed_at: self.transition_observed_at,
                backend_observed_at: observed.observed_at,
            });
        }

        if observed.snapshot_id == *self.before_snapshot_id.as_bytes()
            && observed.generation == self.previous_generation
        {
            return Ok(TaskProjectionPersistenceDecision::RetrySafe {
                envelope_id: self.envelope_id,
                current_snapshot_id: observed.snapshot_id,
                current_generation: observed.generation,
            });
        }

        if observed.snapshot_id == *self.after_snapshot_id.as_bytes()
            && observed.generation == self.resulting_generation
        {
            validate_successor_metadata(self, observed)?;
            let receipt = TaskProjectionPersistenceReceipt::build(self, observed)?;
            return Ok(TaskProjectionPersistenceDecision::Confirmed(receipt));
        }

        Ok(TaskProjectionPersistenceDecision::Conflict {
            envelope_id: self.envelope_id,
            current_snapshot_id: observed.snapshot_id,
            current_generation: observed.generation,
        })
    }

    /// Stable mutation-envelope identity.
    #[must_use]
    pub const fn envelope_id(self) -> TaskProjectionMutationEnvelopeId {
        self.envelope_id
    }

    /// Repository namespace.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Task being mutated.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }

    /// Exact predecessor snapshot identity.
    #[must_use]
    pub const fn before_snapshot_id(self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.before_snapshot_id
    }

    /// Exact successor snapshot identity.
    #[must_use]
    pub const fn after_snapshot_id(self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.after_snapshot_id
    }

    /// Exact predecessor generation.
    #[must_use]
    pub const fn previous_generation(self) -> [u8; 32] {
        self.previous_generation
    }

    /// Exact successor generation.
    #[must_use]
    pub const fn resulting_generation(self) -> [u8; 32] {
        self.resulting_generation
    }

    /// Repository-scoped transition identity.
    #[must_use]
    pub const fn transition_id(self) -> AuthorityBoundTaskProjectionTransitionId {
        self.transition_id
    }

    /// Semantic transition-body commitment.
    #[must_use]
    pub const fn inner_transition_id(self) -> [u8; 32] {
        self.inner_transition_id
    }

    /// Claim, release, or transfer semantics.
    #[must_use]
    pub const fn kind(self) -> TaskProjectionTransitionKind {
        self.kind
    }

    /// Logical transition instant.
    #[must_use]
    pub const fn transition_observed_at(self) -> LogicalTime {
        self.transition_observed_at
    }

    /// Backend implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Predeclared mutation-evidence contract.
    #[must_use]
    pub const fn evidence_root(self) -> Digest {
        self.evidence_root
    }
}

/// Reconciled task row read from a backend after an attempted mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskProjectionPersistedState {
    repository_id: RepositoryId,
    task_id: WorkTaskId,
    snapshot_id: [u8; 32],
    generation: [u8; 32],
    last_transition_id: Option<[u8; 32]>,
    last_inner_transition_id: Option<[u8; 32]>,
    evidence_root: Option<Digest>,
    observed_at: LogicalTime,
}

impl TaskProjectionPersistedState {
    /// Creates one backend read observation.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        repository_id: RepositoryId,
        task_id: WorkTaskId,
        snapshot_id: [u8; 32],
        generation: [u8; 32],
        last_transition_id: Option<[u8; 32]>,
        last_inner_transition_id: Option<[u8; 32]>,
        evidence_root: Option<Digest>,
        observed_at: LogicalTime,
    ) -> Self {
        Self {
            repository_id,
            task_id,
            snapshot_id,
            generation,
            last_transition_id,
            last_inner_transition_id,
            evidence_root,
            observed_at,
        }
    }

    /// Repository namespace read from the backend.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Task read from the backend.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }

    /// Current scoped snapshot identity bytes.
    #[must_use]
    pub const fn snapshot_id(self) -> [u8; 32] {
        self.snapshot_id
    }

    /// Current task-projection generation.
    #[must_use]
    pub const fn generation(self) -> [u8; 32] {
        self.generation
    }

    /// Last repository-scoped transition identity, when retained.
    #[must_use]
    pub const fn last_transition_id(self) -> Option<[u8; 32]> {
        self.last_transition_id
    }

    /// Last semantic inner transition identity, when retained.
    #[must_use]
    pub const fn last_inner_transition_id(self) -> Option<[u8; 32]> {
        self.last_inner_transition_id
    }

    /// Retained mutation-evidence contract, when present.
    #[must_use]
    pub const fn evidence_root(self) -> Option<Digest> {
        self.evidence_root
    }

    /// Logical time of the reconciled backend read.
    #[must_use]
    pub const fn observed_at(self) -> LogicalTime {
        self.observed_at
    }
}

/// Deterministic interpretation of a backend reread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskProjectionPersistenceDecision {
    /// The exact successor and all transition metadata were observed.
    Confirmed(TaskProjectionPersistenceReceipt),
    /// The exact predecessor remains current; retrying the same envelope is safe.
    RetrySafe {
        /// Mutation request being retried.
        envelope_id: TaskProjectionMutationEnvelopeId,
        /// Still-current predecessor snapshot.
        current_snapshot_id: [u8; 32],
        /// Still-current predecessor generation.
        current_generation: [u8; 32],
    },
    /// Another successor won or the backend row changed incompatibly.
    Conflict {
        /// Mutation request that lost or became stale.
        envelope_id: TaskProjectionMutationEnvelopeId,
        /// Current conflicting snapshot identity.
        current_snapshot_id: [u8; 32],
        /// Current conflicting generation.
        current_generation: [u8; 32],
    },
}

/// Verified persistence receipt for the exact task successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskProjectionPersistenceReceipt {
    receipt_id: TaskProjectionPersistenceReceiptId,
    envelope_id: TaskProjectionMutationEnvelopeId,
    repository_id: RepositoryId,
    task_id: WorkTaskId,
    snapshot_id: [u8; 32],
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
        let mut receipt = Self {
            receipt_id: TaskProjectionPersistenceReceiptId([0; 32]),
            envelope_id: envelope.envelope_id,
            repository_id: envelope.repository_id,
            task_id: envelope.task_id,
            snapshot_id: observed.snapshot_id,
            generation: observed.generation,
            transition_id: observed
                .last_transition_id
                .ok_or(TaskProjectionPersistenceRefusal::SuccessorTransitionMissing)?,
            inner_transition_id: observed
                .last_inner_transition_id
                .ok_or(TaskProjectionPersistenceRefusal::SuccessorInnerTransitionMissing)?,
            evidence_root: observed
                .evidence_root
                .ok_or(TaskProjectionPersistenceRefusal::SuccessorEvidenceMissing)?,
            observed_at: observed.observed_at,
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
    pub const fn snapshot_id(self) -> [u8; 32] {
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

    /// Persisted semantic transition-body commitment.
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
    /// Application repository differs from its transition.
    ApplicationRepositoryMismatch,
    /// Application task differs from its transition.
    ApplicationTaskMismatch,
    /// Application successor snapshot differs from its transition.
    ApplicationSuccessorMismatch,
    /// Application successor generation differs from its transition.
    ApplicationGenerationMismatch,
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
    /// Backend reread predates the transition.
    ObservationRollback {
        /// Transition time.
        transition_observed_at: LogicalTime,
        /// Backend reread time.
        backend_observed_at: LogicalTime,
    },
    /// Exact successor omitted repository-scoped transition identity.
    SuccessorTransitionMissing,
    /// Exact successor retained another repository-scoped transition identity.
    SuccessorTransitionMismatch {
        /// Envelope transition.
        expected: [u8; 32],
        /// Backend transition.
        observed: [u8; 32],
    },
    /// Exact successor omitted semantic inner transition identity.
    SuccessorInnerTransitionMissing,
    /// Exact successor retained another semantic inner transition identity.
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
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for TaskProjectionPersistenceRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task projection persistence refused: {self:?}")
    }
}

impl core::error::Error for TaskProjectionPersistenceRefusal {}

impl From<CodecRefusal> for TaskProjectionPersistenceRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
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
    let mut encoder = Encoder::with_capacity(640);
    encoder.write_bytes("task_mutation_envelope_domain", ENVELOPE_DOMAIN)?;
    encoder.write_opaque_id(envelope.repository_id.as_bytes());
    encoder.write_raw(envelope.task_id.as_bytes());
    encoder.write_raw(envelope.before_snapshot_id.as_bytes());
    encoder.write_raw(envelope.after_snapshot_id.as_bytes());
    encoder.write_raw(&envelope.previous_generation);
    encoder.write_raw(&envelope.resulting_generation);
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
    let mut encoder = Encoder::with_capacity(448);
    encoder.write_bytes("task_persistence_receipt_domain", RECEIPT_DOMAIN)?;
    encoder.write_raw(receipt.envelope_id.as_bytes());
    encoder.write_opaque_id(receipt.repository_id.as_bytes());
    encoder.write_raw(receipt.task_id.as_bytes());
    encoder.write_raw(&receipt.snapshot_id);
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
