//! Repository- and time-bound task coordination over the pure projection kernel.
//!
//! [`crate::task_projection_adapter`] owns deterministic claim, release, and
//! transfer state transitions. This module adds the production-facing scope
//! that a task backend must not leave implicit: one repository namespace and a
//! monotone observation time.
//!
//! The facade still does not persist anything. A Beads or other backend must
//! atomically compare-and-replace the exact predecessor generation, durably
//! store the returned transition/evidence, and return ambiguous-write recovery
//! evidence. The values here make those requirements explicit without
//! pretending an in-memory value is a durable task database.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::{Digest, RepositoryId};

use crate::{
    ActiveTaskClaim, AgentChangePlan, AgentControlPulse, AuthorityReadReceipt, IntentRun,
    LogicalTime, TaskClaimCancellationProjection, TaskClaimProjection, TaskClaimReceipt,
    TaskPhase, WorkTaskId,
};
use crate::task_projection_adapter::{
    TaskClaimApplication, TaskProjectionAdapterRefusal, TaskProjectionAssignment,
    TaskProjectionLease, TaskProjectionSnapshot, TaskProjectionTransition,
    TaskProjectionTransitionKind, TaskReleaseDisposition, TaskResolutionApplication,
};

const SCOPED_SNAPSHOT_DOMAIN: &[u8] =
    b"frankengit.agent.authority-bound-task-snapshot/v1\0";
const SCOPED_TRANSITION_DOMAIN: &[u8] =
    b"frankengit.agent.authority-bound-task-transition/v1\0";

/// Stable identity of one repository-scoped task snapshot.
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

/// Stable identity of one repository-scoped task transition.
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

/// Immutable task projection scoped to one repository and observation instant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBoundTaskProjectionSnapshot {
    snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
    repository_id: RepositoryId,
    observed_at: LogicalTime,
    inner: TaskProjectionSnapshot,
}

impl AuthorityBoundTaskProjectionSnapshot {
    /// Imports one observed task row under an authenticated repository receipt.
    ///
    /// # Errors
    ///
    /// Preserves the deterministic kernel's generation/terminal-state refusals
    /// and refuses canonical scope framing failure.
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
        Self::from_inner(authority.repository_id(), observed_at, inner)
    }

    /// Claims this exact repository-scoped task generation.
    ///
    /// # Errors
    ///
    /// Refuses repository substitution, a pulse older than the snapshot, every
    /// refusal of the deterministic transition kernel, and scope framing
    /// failure.
    #[allow(clippy::too_many_arguments)]
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
        self.validate_run_repository(run)?;
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

    /// Releases an activated claim under this repository scope.
    ///
    /// # Errors
    ///
    /// Refuses repository substitution, observation rollback, every refusal of
    /// the deterministic transition kernel, and scope framing failure.
    #[allow(clippy::too_many_arguments)]
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
        self.validate_run_repository(source_run)?;
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

    /// Transfers source assignment to a successor in the same repository.
    ///
    /// The successor receives only an assignment preference. It must produce a
    /// fresh pulse, plan, claim receipt, and activation against the resulting
    /// generation before continuing work.
    ///
    /// # Errors
    ///
    /// Refuses source or successor repository substitution, observation
    /// rollback, every refusal of the deterministic transition kernel, and
    /// scope framing failure.
    #[allow(clippy::too_many_arguments)]
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
        self.validate_run_repository(source_run)?;
        self.validate_run_repository(successor_run)?;
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

    fn validate_run_repository(&self, run: &IntentRun) -> Result<(), TaskCoordinationRefusal> {
        let authority = run
            .authority_read_receipt()
            .ok_or(TaskCoordinationRefusal::RunAuthorityReceiptRequired)?;
        if authority.repository_id() != self.repository_id {
            return Err(TaskCoordinationRefusal::RunRepositoryMismatch {
                expected: self.repository_id,
                observed: authority.repository_id(),
            });
        }
        Ok(())
    }

    fn validate_observation(&self, observed: LogicalTime) -> Result<(), TaskCoordinationRefusal> {
        if observed.value() < self.observed_at.value() {
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
        let snapshot = Self::from_inner(self.repository_id, observed_at, inner_snapshot)?;
        let transition = AuthorityBoundTaskProjectionTransition::build(
            self,
            &snapshot,
            inner_transition,
        )?;
        Ok(AuthorityBoundTaskClaimApplication {
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
        let snapshot = Self::from_inner(self.repository_id, observed_at, inner_snapshot)?;
        let transition = AuthorityBoundTaskProjectionTransition::build(
            self,
            &snapshot,
            inner_transition,
        )?;
        Ok(AuthorityBoundTaskResolutionApplication {
            snapshot,
            transition,
            projection,
        })
    }

    fn from_inner(
        repository_id: RepositoryId,
        observed_at: LogicalTime,
        inner: TaskProjectionSnapshot,
    ) -> Result<Self, TaskCoordinationRefusal> {
        let mut snapshot = Self {
            snapshot_id: AuthorityBoundTaskProjectionSnapshotId([0; 32]),
            repository_id,
            observed_at,
            inner,
        };
        snapshot.snapshot_id =
            AuthorityBoundTaskProjectionSnapshotId(scoped_snapshot_commitment(&snapshot)?);
        Ok(snapshot)
    }

    /// Stable repository-scoped snapshot identity.
    #[must_use]
    pub const fn snapshot_id(&self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.snapshot_id
    }

    /// Repository namespace of the task projection.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Logical observation instant of this snapshot.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Task represented by the snapshot.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.inner.task_id()
    }

    /// Exact task-projection generation.
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

/// Repository-scoped transition retaining the pure kernel receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityBoundTaskProjectionTransition {
    transition_id: AuthorityBoundTaskProjectionTransitionId,
    repository_id: RepositoryId,
    before_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
    after_snapshot_id: AuthorityBoundTaskProjectionSnapshotId,
    inner: TaskProjectionTransition,
}

impl AuthorityBoundTaskProjectionTransition {
    fn build(
        before: &AuthorityBoundTaskProjectionSnapshot,
        after: &AuthorityBoundTaskProjectionSnapshot,
        inner: TaskProjectionTransition,
    ) -> Result<Self, TaskCoordinationRefusal> {
        let mut transition = Self {
            transition_id: AuthorityBoundTaskProjectionTransitionId([0; 32]),
            repository_id: before.repository_id,
            before_snapshot_id: before.snapshot_id,
            after_snapshot_id: after.snapshot_id,
            inner,
        };
        transition.transition_id = AuthorityBoundTaskProjectionTransitionId(
            scoped_transition_commitment(&transition)?,
        );
        Ok(transition)
    }

    /// Stable repository-scoped transition identity.
    #[must_use]
    pub const fn transition_id(self) -> AuthorityBoundTaskProjectionTransitionId {
        self.transition_id
    }

    /// Repository namespace changed by this transition.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Exact predecessor snapshot.
    #[must_use]
    pub const fn before_snapshot_id(self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.before_snapshot_id
    }

    /// Exact successor snapshot.
    #[must_use]
    pub const fn after_snapshot_id(self) -> AuthorityBoundTaskProjectionSnapshotId {
        self.after_snapshot_id
    }

    /// Pure deterministic transition receipt.
    #[must_use]
    pub const fn inner(self) -> TaskProjectionTransition {
        self.inner
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
}

/// Successful repository-scoped claim application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBoundTaskClaimApplication {
    snapshot: AuthorityBoundTaskProjectionSnapshot,
    transition: AuthorityBoundTaskProjectionTransition,
    projection: TaskClaimProjection,
}

impl AuthorityBoundTaskClaimApplication {
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

    /// Decomposes the application for durable persistence and claim admission.
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
}

/// Successful repository-scoped release or transfer application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBoundTaskResolutionApplication {
    snapshot: AuthorityBoundTaskProjectionSnapshot,
    transition: AuthorityBoundTaskProjectionTransition,
    projection: TaskClaimCancellationProjection,
}

impl AuthorityBoundTaskResolutionApplication {
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

    /// Decomposes the application for durable persistence and reconciliation.
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

impl From<CodecRefusal> for TaskCoordinationRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn scoped_snapshot_commitment(
    snapshot: &AuthorityBoundTaskProjectionSnapshot,
) -> Result<[u8; 32], TaskCoordinationRefusal> {
    let mut encoder = Encoder::with_capacity(192);
    encoder.write_bytes("authority_bound_task_snapshot_domain", SCOPED_SNAPSHOT_DOMAIN)?;
    encoder.write_opaque_id(snapshot.repository_id.as_bytes());
    encoder.write_scalar(snapshot.observed_at.value());
    encoder.write_raw(snapshot.inner.snapshot_id().as_bytes());
    Ok(hash(&encoder.into_bytes()))
}

fn scoped_transition_commitment(
    transition: &AuthorityBoundTaskProjectionTransition,
) -> Result<[u8; 32], TaskCoordinationRefusal> {
    let mut encoder = Encoder::with_capacity(256);
    encoder.write_bytes(
        "authority_bound_task_transition_domain",
        SCOPED_TRANSITION_DOMAIN,
    )?;
    encoder.write_opaque_id(transition.repository_id.as_bytes());
    encoder.write_raw(transition.before_snapshot_id.as_bytes());
    encoder.write_raw(transition.after_snapshot_id.as_bytes());
    encoder.write_raw(transition.inner.transition_id().as_bytes());
    Ok(hash(&encoder.into_bytes()))
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}
