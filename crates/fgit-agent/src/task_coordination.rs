//! Exact authority provenance around deterministic task coordination.
//!
//! [`crate::task_projection_adapter`] owns the pure semantic transition kernel.
//! This module binds those values to one authenticated repository-head basis and
//! one monotone observation time without letting verifier time, backend token,
//! or adapter evidence leak into semantic task-state identity.
//!
//! The complete [`crate::AuthorityReadReceipt`] remains attached as provenance.
//! A later reread of the same head and task state may therefore keep the same
//! semantic snapshot identity while still being non-interchangeable for a
//! mutation opened under another authenticated read event.
//!
//! This facade is still derived coordination state. Persistence is owned by the
//! task-store protocol and repository authority remains the ordinary
//! `RepositoryAuthorityHead` CAS path.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::{Digest, RepositoryId};

use crate::task_projection_adapter::{
    TaskClaimApplication, TaskProjectionAdapterRefusal, TaskProjectionAssignment,
    TaskProjectionLease, TaskProjectionSnapshot, TaskProjectionTransition,
    TaskProjectionTransitionKind, TaskReleaseDisposition, TaskResolutionApplication,
};
use crate::{
    ActiveTaskClaim, AgentChangePlan, AgentControlPulse, AuthorityReadIdentityRefusal,
    AuthorityReadReceipt, AuthorityReadReceiptId, IntentRun, LogicalTime,
    TaskClaimCancellationProjection, TaskClaimProjection, TaskClaimReceipt, TaskPhase, WorkTaskId,
};

const SCOPED_SNAPSHOT_DOMAIN: &[u8] = b"frankengit.agent.authority-bound-task-snapshot/v2\0";
const SCOPED_TRANSITION_DOMAIN: &[u8] = b"frankengit.agent.authority-bound-task-transition/v2\0";

/// Stable semantic identity of one authority-position-scoped task state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityBoundTaskProjectionSnapshotId([u8; 32]);

impl AuthorityBoundTaskProjectionSnapshotId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AuthorityBoundTaskProjectionSnapshotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("scoped-task-snapshot:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable audit identity of one repository-scoped task transition.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityBoundTaskProjectionTransitionId([u8; 32]);

impl AuthorityBoundTaskProjectionTransitionId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AuthorityBoundTaskProjectionTransitionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("scoped-task-transition:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Immutable task projection with exact authenticated-read provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBoundTaskProjectionSnapshot {
    snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
    repository_id: RepositoryId,
    authority_read_receipt_id: AuthorityReadReceiptId,
    authority_read_receipt: AuthorityReadReceipt,
    observed_at: LogicalTime,
    inner: TaskProjectionSnapshot,
}

impl AuthorityBoundTaskProjectionSnapshot {
    /// Imports one observed unleased task row under an authenticated read.
    ///
    /// # Errors
    ///
    /// Refuses authority identity framing and every structural refusal of the
    /// deterministic task-state kernel.
    pub fn observed(
        authority: &AuthorityReadReceipt,
        task_id: WorkTaskId,
        generation: [u8; 32],
        phase: TaskPhase,
        assignment: TaskProjectionAssignment,
        observed_at: LogicalTime,
    ) -> Result<Self, TaskCoordinationRefusal> {
        let inner = TaskProjectionSnapshot::observed(task_id, generation, phase, assignment)
            .map_err(TaskCoordinationRefusal::Adapter)?;
        Self::from_inner(authority.clone(), observed_at, inner)
    }

    /// Imports one observed active lease reconstructed by a durable backend.
    ///
    /// # Errors
    ///
    /// Refuses authority identity framing, lease/generation inconsistency, and
    /// every structural refusal of the deterministic task-state kernel.
    pub fn observed_with_lease(
        authority: &AuthorityReadReceipt,
        task_id: WorkTaskId,
        generation: [u8; 32],
        phase: TaskPhase,
        lease: TaskProjectionLease,
        observed_at: LogicalTime,
    ) -> Result<Self, TaskCoordinationRefusal> {
        let inner = TaskProjectionSnapshot::observed_with_lease(task_id, generation, phase, lease)
            .map_err(TaskCoordinationRefusal::Adapter)?;
        Self::from_inner(authority.clone(), observed_at, inner)
    }

    /// Claims this exact task state under the same authenticated read event.
    ///
    /// # Errors
    ///
    /// Refuses exact-read, repository, pulse-time, semantic transition, and
    /// canonical framing mismatches.
    pub fn claim(
        &self,
        pulse: &AgentControlPulse,
        plan: &AgentChangePlan,
        run: &IntentRun,
        claimed_at: LogicalTime,
        expires_at: LogicalTime,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Result<AuthorityBoundTaskClaimApplication, TaskCoordinationRefusal> {
        self.validate_run_authority(run)?;
        if pulse.repository_id() != self.repository_id {
            return Err(TaskCoordinationRefusal::PulseRepositoryMismatch {
                expected: self.repository_id,
                observed: pulse.repository_id(),
            });
        }
        self.validate_observation(pulse.observed_at())?;
        let application = self
            .inner
            .claim(
                pulse,
                plan,
                run,
                claimed_at,
                expires_at,
                adapter_identity,
                evidence_root,
            )
            .map_err(TaskCoordinationRefusal::Adapter)?;
        self.wrap_claim(application, claimed_at)
    }

    /// Releases an activated claim while preserving the exact read basis.
    ///
    /// # Errors
    ///
    /// Refuses exact-read, observation-time, semantic transition, and canonical
    /// framing mismatches.
    pub fn release(
        &self,
        claim_receipt: &TaskClaimReceipt,
        active_claim: ActiveTaskClaim,
        source_run: &IntentRun,
        disposition: TaskReleaseDisposition,
        resolved_at: LogicalTime,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Result<AuthorityBoundTaskResolutionApplication, TaskCoordinationRefusal> {
        self.validate_run_authority(source_run)?;
        self.validate_observation(resolved_at)?;
        let application = self
            .inner
            .release(
                claim_receipt,
                active_claim,
                source_run,
                disposition,
                resolved_at,
                adapter_identity,
                evidence_root,
            )
            .map_err(TaskCoordinationRefusal::Adapter)?;
        self.wrap_resolution(application, resolved_at)
    }

    /// Transfers assignment to a successor on the same exact read basis.
    ///
    /// The successor receives no plan, capability, or active claim. It must
    /// observe and claim the successor task generation separately.
    ///
    /// # Errors
    ///
    /// Refuses source/successor exact-read substitution, observation rollback,
    /// semantic transition, and canonical framing mismatches.
    pub fn transfer(
        &self,
        claim_receipt: &TaskClaimReceipt,
        active_claim: ActiveTaskClaim,
        source_run: &IntentRun,
        successor_run: &IntentRun,
        resolved_at: LogicalTime,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Result<AuthorityBoundTaskResolutionApplication, TaskCoordinationRefusal> {
        self.validate_run_authority(source_run)?;
        self.validate_run_authority(successor_run)?;
        self.validate_observation(resolved_at)?;
        let application = self
            .inner
            .transfer(
                claim_receipt,
                active_claim,
                source_run,
                successor_run,
                resolved_at,
                adapter_identity,
                evidence_root,
            )
            .map_err(TaskCoordinationRefusal::Adapter)?;
        self.wrap_resolution(application, resolved_at)
    }

    fn validate_run_authority(&self, run: &IntentRun) -> Result<(), TaskCoordinationRefusal> {
        let authority = run
            .authority_read_receipt()
            .ok_or(TaskCoordinationRefusal::RunAuthorityReceiptRequired)?;
        if authority.repository_id() != self.repository_id {
            return Err(TaskCoordinationRefusal::RunRepositoryMismatch {
                expected: self.repository_id,
                observed: authority.repository_id(),
            });
        }
        let observed_id = authority.receipt_id()?;
        if observed_id != self.authority_read_receipt_id
            || authority != &self.authority_read_receipt
        {
            return Err(TaskCoordinationRefusal::RunAuthorityMismatch);
        }
        Ok(())
    }

    fn validate_observation(&self, observed: LogicalTime) -> Result<(), TaskCoordinationRefusal> {
        if observed < self.observed_at {
            return Err(TaskCoordinationRefusal::ObservationRollback {
                snapshot_observed_at: self.observed_at,
                proposed_observed_at: observed,
            });
        }
        Ok(())
    }

    fn wrap_claim(
        &self,
        application: TaskClaimApplication,
        observed_at: LogicalTime,
    ) -> Result<AuthorityBoundTaskClaimApplication, TaskCoordinationRefusal> {
        let (inner_snapshot, inner_transition, projection) = application.into_parts();
        let snapshot = Self::from_inner(
            self.authority_read_receipt.clone(),
            observed_at,
            inner_snapshot,
        )?;
        let transition =
            AuthorityBoundTaskProjectionTransition::build(self, &snapshot, &inner_transition)?;
        Ok(AuthorityBoundTaskClaimApplication {
            before_snapshot: self.clone(),
            snapshot,
            transition,
            projection,
        })
    }

    fn wrap_resolution(
        &self,
        application: TaskResolutionApplication,
        observed_at: LogicalTime,
    ) -> Result<AuthorityBoundTaskResolutionApplication, TaskCoordinationRefusal> {
        let (inner_snapshot, inner_transition, projection) = application.into_parts();
        let snapshot = Self::from_inner(
            self.authority_read_receipt.clone(),
            observed_at,
            inner_snapshot,
        )?;
        let transition =
            AuthorityBoundTaskProjectionTransition::build(self, &snapshot, &inner_transition)?;
        Ok(AuthorityBoundTaskResolutionApplication {
            before_snapshot: self.clone(),
            snapshot,
            transition,
            projection,
        })
    }

    fn from_inner(
        authority_read_receipt: AuthorityReadReceipt,
        observed_at: LogicalTime,
        inner: TaskProjectionSnapshot,
    ) -> Result<Self, TaskCoordinationRefusal> {
        let authority_read_receipt_id = authority_read_receipt.receipt_id()?;
        let repository_id = authority_read_receipt.repository_id();
        let mut snapshot = Self {
            snapshot_id: AuthorityBoundTaskProjectionSnapshotId([0; 32]),
            repository_id,
            authority_read_receipt_id,
            authority_read_receipt,
            observed_at,
            inner,
        };
        snapshot.snapshot_id =
            AuthorityBoundTaskProjectionSnapshotId(scoped_snapshot_commitment(&snapshot)?);
        Ok(snapshot)
    }

    /// Stable semantic snapshot identity.
    ///
    /// Exact read-event provenance and freshness are intentionally separate
    /// accessors and do not perturb this identity.
    #[must_use]
    pub const fn snapshot_id(&self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.snapshot_id
    }

    /// Repository namespace of the task projection.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Exact authenticated read event retained as mutation provenance.
    #[must_use]
    pub const fn authority_read_receipt_id(&self) -> AuthorityReadReceiptId {
        self.authority_read_receipt_id
    }

    /// Complete authenticated read event retained by this observation.
    #[must_use]
    pub const fn authority_read_receipt(&self) -> &AuthorityReadReceipt {
        &self.authority_read_receipt
    }

    /// Logical freshness time of this backend observation.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Task represented by the snapshot.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.inner.task_id()
    }

    /// Exact semantic task-projection generation.
    #[must_use]
    pub const fn generation(&self) -> &[u8; 32] {
        self.inner.generation()
    }

    /// Projected task phase.
    #[must_use]
    pub const fn phase(&self) -> TaskPhase {
        self.inner.phase()
    }

    /// Projected assignment.
    #[must_use]
    pub const fn assignment(&self) -> TaskProjectionAssignment {
        self.inner.assignment()
    }

    /// Active lease, when present.
    #[must_use]
    pub const fn lease(&self) -> Option<&TaskProjectionLease> {
        self.inner.lease()
    }
}

/// Repository-scoped transition retaining semantic and audit identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityBoundTaskProjectionTransition {
    transition_id: AuthorityBoundTaskProjectionTransitionId,
    repository_id: RepositoryId,
    authority_read_receipt_id: AuthorityReadReceiptId,
    before_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
    after_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
    inner_transition_id: [u8; 32],
    inner: TaskProjectionTransition,
}

impl AuthorityBoundTaskProjectionTransition {
    fn build(
        before: &AuthorityBoundTaskProjectionSnapshot,
        after: &AuthorityBoundTaskProjectionSnapshot,
        inner: &TaskProjectionTransition,
    ) -> Result<Self, TaskCoordinationRefusal> {
        if before.repository_id != after.repository_id
            || before.authority_read_receipt_id != after.authority_read_receipt_id
        {
            return Err(TaskCoordinationRefusal::SuccessorAuthorityMismatch);
        }
        let inner_transition_id = *inner.transition_id().as_bytes();
        let mut transition = Self {
            transition_id: AuthorityBoundTaskProjectionTransitionId([0; 32]),
            repository_id: before.repository_id,
            authority_read_receipt_id: before.authority_read_receipt_id,
            before_snapshot_id: before.snapshot_id,
            after_snapshot_id: after.snapshot_id,
            inner_transition_id,
            inner: *inner,
        };
        transition.transition_id =
            AuthorityBoundTaskProjectionTransitionId(scoped_transition_commitment(&transition)?);
        Ok(transition)
    }

    /// Stable repository-scoped audit identity.
    #[must_use]
    pub const fn transition_id(self) -> AuthorityBoundTaskProjectionTransitionId {
        self.transition_id
    }

    /// Repository namespace changed by this transition.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Exact authenticated read event used as the mutation basis.
    #[must_use]
    pub const fn authority_read_receipt_id(self) -> AuthorityReadReceiptId {
        self.authority_read_receipt_id
    }

    /// Exact predecessor semantic snapshot.
    #[must_use]
    pub const fn before_snapshot_id(self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.before_snapshot_id
    }

    /// Exact successor semantic snapshot.
    #[must_use]
    pub const fn after_snapshot_id(self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.after_snapshot_id
    }

    /// Pure semantic/audit transition receipt.
    #[must_use]
    pub const fn inner(self) -> TaskProjectionTransition {
        self.inner
    }

    /// Raw inner transition identity.
    #[must_use]
    pub const fn inner_transition_id(&self) -> &[u8; 32] {
        &self.inner_transition_id
    }

    /// Task changed.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.inner.task_id()
    }

    /// Replaced generation.
    #[must_use]
    pub const fn previous_generation(self) -> [u8; 32] {
        self.inner.previous_generation()
    }

    /// New generation.
    #[must_use]
    pub const fn resulting_generation(self) -> [u8; 32] {
        self.inner.resulting_generation()
    }

    /// Transition semantics.
    #[must_use]
    pub const fn kind(self) -> TaskProjectionTransitionKind {
        self.inner.kind()
    }

    /// Logical mutation observation.
    #[must_use]
    pub const fn observed_at(self) -> LogicalTime {
        self.inner.observed_at()
    }

    /// Adapter implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(self) -> [u8; 32] {
        self.inner.adapter_identity()
    }

    /// Declared mutation-evidence contract.
    #[must_use]
    pub const fn evidence_root(self) -> Digest {
        self.inner.evidence_root()
    }
}

/// Successful repository-scoped claim application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBoundTaskClaimApplication {
    before_snapshot: AuthorityBoundTaskProjectionSnapshot,
    snapshot: AuthorityBoundTaskProjectionSnapshot,
    transition: AuthorityBoundTaskProjectionTransition,
    projection: TaskClaimProjection,
}

impl AuthorityBoundTaskClaimApplication {
    /// Exact predecessor snapshot.
    #[must_use]
    pub const fn before_snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.before_snapshot
    }

    /// Successor scoped snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.snapshot
    }

    /// Scoped transition receipt.
    #[must_use]
    pub const fn transition(&self) -> AuthorityBoundTaskProjectionTransition {
        self.transition
    }

    /// Projection consumed by [`TaskClaimReceipt::admit`].
    #[must_use]
    pub const fn projection(&self) -> &TaskClaimProjection {
        &self.projection
    }

    /// Decomposes the application for legacy persistence callers.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        AuthorityBoundTaskProjectionSnapshot,
        AuthorityBoundTaskProjectionTransition,
        TaskClaimProjection,
    ) {
        (self.snapshot, self.transition, self.projection)
    }

    /// Decomposes the complete exact-predecessor application.
    #[must_use]
    pub fn into_complete_parts(
        self,
    ) -> (
        AuthorityBoundTaskProjectionSnapshot,
        AuthorityBoundTaskProjectionSnapshot,
        AuthorityBoundTaskProjectionTransition,
        TaskClaimProjection,
    ) {
        (
            self.before_snapshot,
            self.snapshot,
            self.transition,
            self.projection,
        )
    }
}

/// Successful repository-scoped release or transfer application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBoundTaskResolutionApplication {
    before_snapshot: AuthorityBoundTaskProjectionSnapshot,
    snapshot: AuthorityBoundTaskProjectionSnapshot,
    transition: AuthorityBoundTaskProjectionTransition,
    projection: TaskClaimCancellationProjection,
}

impl AuthorityBoundTaskResolutionApplication {
    /// Exact predecessor snapshot.
    #[must_use]
    pub const fn before_snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.before_snapshot
    }

    /// Successor scoped snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.snapshot
    }

    /// Scoped transition receipt.
    #[must_use]
    pub const fn transition(&self) -> AuthorityBoundTaskProjectionTransition {
        self.transition
    }

    /// Projection consumed by cancellation completion or transfer handling.
    #[must_use]
    pub const fn projection(&self) -> &TaskClaimCancellationProjection {
        &self.projection
    }

    /// Decomposes the application for legacy persistence callers.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        AuthorityBoundTaskProjectionSnapshot,
        AuthorityBoundTaskProjectionTransition,
        TaskClaimCancellationProjection,
    ) {
        (self.snapshot, self.transition, self.projection)
    }

    /// Decomposes the complete exact-predecessor application.
    #[must_use]
    pub fn into_complete_parts(
        self,
    ) -> (
        AuthorityBoundTaskProjectionSnapshot,
        AuthorityBoundTaskProjectionSnapshot,
        AuthorityBoundTaskProjectionTransition,
        TaskClaimCancellationProjection,
    ) {
        (
            self.before_snapshot,
            self.snapshot,
            self.transition,
            self.projection,
        )
    }
}

/// Why repository-scoped task coordination failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskCoordinationRefusal {
    /// Intent Run lacks a complete authenticated authority receipt.
    RunAuthorityReceiptRequired,
    /// Intent Run belongs to another repository.
    RunRepositoryMismatch {
        /// Snapshot repository.
        expected: RepositoryId,
        /// Run repository.
        observed: RepositoryId,
    },
    /// Intent Run used another authenticated read event, even if it named the
    /// same repository head.
    RunAuthorityMismatch,
    /// A successor application changed its authenticated authority basis.
    SuccessorAuthorityMismatch,
    /// Pulse belongs to another repository.
    PulseRepositoryMismatch {
        /// Snapshot repository.
        expected: RepositoryId,
        /// Pulse repository.
        observed: RepositoryId,
    },
    /// Proposed observation predates the current snapshot.
    ObservationRollback {
        /// Current snapshot observation.
        snapshot_observed_at: LogicalTime,
        /// Proposed mutation/pulse observation.
        proposed_observed_at: LogicalTime,
    },
    /// Exact authenticated-read identity could not be framed.
    AuthorityIdentity(AuthorityReadIdentityRefusal),
    /// Pure deterministic transition kernel refused the request.
    Adapter(TaskProjectionAdapterRefusal),
    /// Repository-scoped commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for TaskCoordinationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task coordination refused: {self:?}")
    }
}

impl core::error::Error for TaskCoordinationRefusal {}

impl From<AuthorityReadIdentityRefusal> for TaskCoordinationRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::AuthorityIdentity(value)
    }
}

impl From<CodecRefusal> for TaskCoordinationRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn scoped_snapshot_commitment(
    snapshot: &AuthorityBoundTaskProjectionSnapshot,
) -> Result<[u8; 32], TaskCoordinationRefusal> {
    let mut encoder = Encoder::with_capacity(256);
    encoder.write_bytes(
        "authority_bound_task_snapshot_domain",
        SCOPED_SNAPSHOT_DOMAIN,
    )?;
    encoder.write_opaque_id(snapshot.repository_id.as_bytes());
    encoder.write_internal_object_id(
        snapshot
            .authority_read_receipt
            .authority_head_id()
            .as_internal_object_id(),
    )?;
    encoder.write_scalar(
        snapshot
            .authority_read_receipt
            .authority_head_generation()
            .get(),
    );
    encoder.write_raw(snapshot.inner.snapshot_id().as_bytes());
    Ok(hash(&encoder.into_bytes()))
}

fn scoped_transition_commitment(
    transition: &AuthorityBoundTaskProjectionTransition,
) -> Result<[u8; 32], TaskCoordinationRefusal> {
    let mut encoder = Encoder::with_capacity(320);
    encoder.write_bytes(
        "authority_bound_task_transition_domain",
        SCOPED_TRANSITION_DOMAIN,
    )?;
    encoder.write_opaque_id(transition.repository_id.as_bytes());
    encoder.write_raw(transition.authority_read_receipt_id.as_bytes());
    encoder.write_raw(transition.before_snapshot_id.as_bytes());
    encoder.write_raw(transition.after_snapshot_id.as_bytes());
    encoder.write_raw(&transition.inner_transition_id);
    Ok(hash(&encoder.into_bytes()))
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}
