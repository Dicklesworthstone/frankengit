//! Persistence-gated cleanup for restart-recovered task claims.
//!
//! [`crate::RecoveredActiveTaskClaim`] proves that a collected durable lease,
//! the original [`crate::TaskClaimReceipt`], a fresh situation, and the complete
//! Intent Run agreed after restart. That proof must not disappear when cleanup
//! mutates the task backend.
//!
//! [`persist_recovered_task_release`] therefore performs the semantic release
//! from the exact reconstructed predecessor, routes it through the ordinary
//! one-shot task-store protocol, and retains the recovery and reconstruction
//! identities in every terminal outcome. A persisted result receives its own
//! receipt that commits both recovery evidence and the confirmed durable task
//! resolution.
//!
//! Release remains a conservative cleanup operation. It may occur after the
//! claim or run has expired, but it may not substitute another task, plan,
//! assignee, exact authenticated read, or store profile.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::Digest;

use crate::{
    IntentRun, LogicalTime, PersistedTaskResolution, RecoveredActiveTaskClaim,
    RecoveredActiveTaskClaimId, TaskClaimReceipt, TaskLeaseReconstructionReceipt,
    TaskLeaseReconstructionReceiptId, TaskPersistenceGateRefusal,
    TaskProjectionMutationEnvelope, TaskProjectionStore, TaskProjectionStoreExecution,
    TaskReleaseDisposition, TaskResolutionPersistenceOutcome, TaskCoordinationRefusal,
    persist_task_resolution,
};

const RECOVERED_RELEASE_DOMAIN: &[u8] =
    b"frankengit.agent.recovered-task-release/v1\0";

/// Stable identity of one confirmed recovered-task release.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PersistedRecoveredTaskReleaseId([u8; 32]);

impl PersistedRecoveredTaskReleaseId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PersistedRecoveredTaskReleaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("persisted-recovered-task-release:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Confirmed durable cleanup that retains restart-recovery evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRecoveredTaskRelease {
    receipt_id: PersistedRecoveredTaskReleaseId,
    recovery_id: RecoveredActiveTaskClaimId,
    lease_reconstruction_id: TaskLeaseReconstructionReceiptId,
    resolution: PersistedTaskResolution,
}

impl PersistedRecoveredTaskRelease {
    /// Stable evidence-preserving release identity.
    #[must_use]
    pub const fn receipt_id(&self) -> PersistedRecoveredTaskReleaseId {
        self.receipt_id
    }

    /// Restart-recovered active claim consumed by the release.
    #[must_use]
    pub const fn recovery_id(&self) -> RecoveredActiveTaskClaimId {
        self.recovery_id
    }

    /// Durable lease reconstruction consumed by the release.
    #[must_use]
    pub const fn lease_reconstruction_id(&self) -> TaskLeaseReconstructionReceiptId {
        self.lease_reconstruction_id
    }

    /// Ordinary confirmed task resolution and cancellation projection.
    #[must_use]
    pub const fn resolution(&self) -> &PersistedTaskResolution {
        &self.resolution
    }
}

/// Terminal outcome of one recovered-task release attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveredTaskReleasePersistenceOutcome {
    /// Exact release successor was confirmed and recovery evidence was retained.
    Persisted(PersistedRecoveredTaskRelease),
    /// Another task state was current and this exact release did not commit.
    Conflict {
        /// Recovery proof whose cleanup was attempted.
        recovery_id: RecoveredActiveTaskClaimId,
        /// Lease reconstruction used as the predecessor.
        lease_reconstruction_id: TaskLeaseReconstructionReceiptId,
        /// Exact release envelope retained for audit and replanning.
        envelope: TaskProjectionMutationEnvelope,
        /// Typed durable-store conflict.
        execution: TaskProjectionStoreExecution,
    },
    /// A possible or historical cleanup effect remains unresolved.
    NeedsReconciliation {
        /// Recovery proof whose cleanup remains unresolved.
        recovery_id: RecoveredActiveTaskClaimId,
        /// Lease reconstruction used as the predecessor.
        lease_reconstruction_id: TaskLeaseReconstructionReceiptId,
        /// Exact release envelope retained for probing.
        envelope: TaskProjectionMutationEnvelope,
        /// Typed durable-store debt.
        execution: TaskProjectionStoreExecution,
    },
}

/// Pre-effect refusal from recovered-task cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskRecoveryPersistenceRefusal {
    /// Recovered claim was produced from another lease reconstruction.
    LeaseReconstructionMismatch {
        /// Reconstruction supplied to cleanup.
        expected: TaskLeaseReconstructionReceiptId,
        /// Reconstruction committed by the recovered claim.
        observed: TaskLeaseReconstructionReceiptId,
    },
    /// Recovered claim was produced from another original claim receipt.
    ClaimMismatch,
    /// Exact reconstructed predecessor refused the semantic release.
    Coordination(TaskCoordinationRefusal),
    /// Persistence gate refused before a terminal store outcome existed.
    Persistence(TaskPersistenceGateRefusal),
    /// Evidence-preserving terminal receipt framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for TaskRecoveryPersistenceRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "recovered task cleanup refused: {self:?}")
    }
}

impl core::error::Error for TaskRecoveryPersistenceRefusal {}

impl From<TaskCoordinationRefusal> for TaskRecoveryPersistenceRefusal {
    fn from(value: TaskCoordinationRefusal) -> Self {
        Self::Coordination(value)
    }
}

impl From<TaskPersistenceGateRefusal> for TaskRecoveryPersistenceRefusal {
    fn from(value: TaskPersistenceGateRefusal) -> Self {
        Self::Persistence(value)
    }
}

impl From<CodecRefusal> for TaskRecoveryPersistenceRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

/// Releases a restart-recovered claim through the durable task-store protocol.
///
/// The invoked store profile becomes the transition adapter identity, so a
/// caller cannot prepare the semantic transition under one adapter and execute
/// it under another. Every conflict or uncertain result retains the exact
/// recovery and reconstruction identities alongside the mutation envelope.
///
/// # Errors
///
/// Refuses recovery/reconstruction or claim substitution, semantic release
/// refusal, a definite pre-effect persistence/store refusal, and terminal
/// receipt framing failure.
#[allow(clippy::too_many_arguments)]
pub fn persist_recovered_task_release<S: TaskProjectionStore>(
    store: &mut S,
    reconstruction: &TaskLeaseReconstructionReceipt,
    recovered: RecoveredActiveTaskClaim,
    claim: &TaskClaimReceipt,
    run: &IntentRun,
    disposition: TaskReleaseDisposition,
    resolved_at: LogicalTime,
    evidence_root: Digest,
) -> Result<RecoveredTaskReleasePersistenceOutcome, TaskRecoveryPersistenceRefusal> {
    if recovered.lease_reconstruction_id() != reconstruction.receipt_id() {
        return Err(TaskRecoveryPersistenceRefusal::LeaseReconstructionMismatch {
            expected: reconstruction.receipt_id(),
            observed: recovered.lease_reconstruction_id(),
        });
    }
    if recovered.claim_id() != claim.claim_id()
        || recovered.active_claim().claim_id() != claim.claim_id()
    {
        return Err(TaskRecoveryPersistenceRefusal::ClaimMismatch);
    }

    let recovery_id = recovered.recovery_id();
    let lease_reconstruction_id = reconstruction.receipt_id();
    let application = reconstruction.snapshot().release(
        claim,
        recovered.active_claim(),
        run,
        disposition,
        resolved_at,
        store.adapter_identity(),
        evidence_root,
    )?;

    match persist_task_resolution(store, application)? {
        TaskResolutionPersistenceOutcome::Persisted(resolution) => {
            let mut persisted = PersistedRecoveredTaskRelease {
                receipt_id: PersistedRecoveredTaskReleaseId([0; 32]),
                recovery_id,
                lease_reconstruction_id,
                resolution,
            };
            persisted.receipt_id =
                PersistedRecoveredTaskReleaseId(release_commitment(&persisted)?);
            Ok(RecoveredTaskReleasePersistenceOutcome::Persisted(persisted))
        }
        TaskResolutionPersistenceOutcome::Conflict {
            envelope,
            execution,
        } => Ok(RecoveredTaskReleasePersistenceOutcome::Conflict {
            recovery_id,
            lease_reconstruction_id,
            envelope,
            execution,
        }),
        TaskResolutionPersistenceOutcome::NeedsReconciliation {
            envelope,
            execution,
        } => Ok(RecoveredTaskReleasePersistenceOutcome::NeedsReconciliation {
            recovery_id,
            lease_reconstruction_id,
            envelope,
            execution,
        }),
    }
}

fn release_commitment(
    persisted: &PersistedRecoveredTaskRelease,
) -> Result<[u8; 32], TaskRecoveryPersistenceRefusal> {
    let mut encoder = Encoder::with_capacity(192);
    encoder.write_bytes("recovered_task_release_domain", RECOVERED_RELEASE_DOMAIN)?;
    encoder.write_raw(persisted.recovery_id.as_bytes());
    encoder.write_raw(persisted.lease_reconstruction_id.as_bytes());
    encoder.write_raw(
        persisted
            .resolution
            .persistence_receipt()
            .receipt_id()
            .as_bytes(),
    );
    Ok(hash(&encoder.into_bytes()))
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}
