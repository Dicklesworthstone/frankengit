//! Persistence-gated cleanup for restart-recovered task claims.
//!
//! [`crate::RecoveredActiveTaskClaim`] proves that a collected durable lease,
//! the original [`crate::TaskClaimReceipt`], a fresh situation, and one complete
//! Intent Run agreed after restart. That proof must not disappear when cleanup
//! mutates the task backend, and the numeric [`crate::RunId`] is not enough to
//! identify the run that recovery validated.
//!
//! [`recover_task_claim_for_cleanup`] therefore performs ordinary recovery and
//! captures the exact [`crate::IntentRunCommitment`] in one uninterruptible API
//! step. [`persist_recovered_task_release`] later re-computes the supplied run
//! commitment before semantic mutation or store I/O. A same-ID run with another
//! authority read, operation scope, resource budget, or expiry fails closed.
//!
//! The release itself is routed through the ordinary one-shot task-store
//! protocol, and success, conflict, and uncertainty all retain the run-bound
//! recovery and lease-reconstruction identities. Release remains a conservative
//! cleanup operation: it may occur after claim or run expiry, but expiry is part
//! of the bound identity and cannot be changed to obtain that path.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::Digest;

use crate::{
    AgentSituationReceipt, IntentRun, IntentRunCommitment, IntentRunIdentityRefusal, LogicalTime,
    PersistedTaskResolution, RecoveredActiveTaskClaim, RecoveredActiveTaskClaimId,
    TaskClaimReceipt, TaskClaimRecoveryRefusal, TaskCoordinationRefusal,
    TaskLeaseReconstructionReceipt, TaskLeaseReconstructionReceiptId, TaskPersistenceGateRefusal,
    TaskProjectionMutationEnvelope, TaskProjectionStore, TaskProjectionStoreExecution,
    TaskReleaseDisposition, TaskResolutionPersistenceOutcome, activate_reconstructed_task_claim,
    persist_task_resolution,
};

const RECOVERY_BINDING_DOMAIN: &[u8] = b"frankengit.agent.run-bound-recovered-task-claim/v1\0";
const RECOVERED_RELEASE_DOMAIN: &[u8] = b"frankengit.agent.recovered-task-release/v2\0";

/// Stable identity of one recovered claim bound to the complete run validated
/// during recovery.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunBoundRecoveredTaskClaimId([u8; 32]);

impl RunBoundRecoveredTaskClaimId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RunBoundRecoveredTaskClaimId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("run-bound-recovered-task-claim:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

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

/// Active task claim recovered and bound to the complete run used during that
/// recovery.
///
/// Construction is private. Callers cannot validate one run during activation
/// and attach another same-ID run commitment afterward.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunBoundRecoveredTaskClaim {
    binding_id: RunBoundRecoveredTaskClaimId,
    recovered: RecoveredActiveTaskClaim,
    run_commitment: IntentRunCommitment,
}

impl RunBoundRecoveredTaskClaim {
    /// Stable run-bound recovery identity.
    #[must_use]
    pub const fn binding_id(self) -> RunBoundRecoveredTaskClaimId {
        self.binding_id
    }

    /// Underlying recovery identity.
    #[must_use]
    pub const fn recovery_id(self) -> RecoveredActiveTaskClaimId {
        self.recovered.recovery_id()
    }

    /// Lease reconstruction consumed by recovery.
    #[must_use]
    pub const fn lease_reconstruction_id(self) -> TaskLeaseReconstructionReceiptId {
        self.recovered.lease_reconstruction_id()
    }

    /// Original claim consumed by recovery.
    #[must_use]
    pub const fn claim_id(self) -> crate::TaskClaimReceiptId {
        self.recovered.claim_id()
    }

    /// Fresh active claim produced by recovery.
    #[must_use]
    pub const fn active_claim(self) -> crate::ActiveTaskClaim {
        self.recovered.active_claim()
    }

    /// Complete machine-enforced run commitment captured during recovery.
    #[must_use]
    pub const fn run_commitment(self) -> IntentRunCommitment {
        self.run_commitment
    }
}

/// Confirmed durable cleanup that retains restart-recovery and complete-run
/// evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRecoveredTaskRelease {
    receipt_id: PersistedRecoveredTaskReleaseId,
    run_bound_recovery_id: RunBoundRecoveredTaskClaimId,
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

    /// Complete-run-bound recovery consumed by the release.
    #[must_use]
    pub const fn run_bound_recovery_id(&self) -> RunBoundRecoveredTaskClaimId {
        self.run_bound_recovery_id
    }

    /// Underlying restart-recovered active claim.
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
        /// Complete-run-bound recovery whose cleanup was attempted.
        run_bound_recovery_id: RunBoundRecoveredTaskClaimId,
        /// Underlying recovery proof.
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
        /// Complete-run-bound recovery whose cleanup remains unresolved.
        run_bound_recovery_id: RunBoundRecoveredTaskClaimId,
        /// Underlying recovery proof.
        recovery_id: RecoveredActiveTaskClaimId,
        /// Lease reconstruction used as the predecessor.
        lease_reconstruction_id: TaskLeaseReconstructionReceiptId,
        /// Exact release envelope retained for probing.
        envelope: TaskProjectionMutationEnvelope,
        /// Typed durable-store debt.
        execution: TaskProjectionStoreExecution,
    },
}

/// Why recovery could not atomically bind the active claim to its complete run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskRecoveryBindingRefusal {
    /// Ordinary lease/claim/situation recovery failed.
    Recovery(TaskClaimRecoveryRefusal),
    /// Complete Intent Run identity could not be produced.
    RunIdentity(IntentRunIdentityRefusal),
    /// Canonical recovery-binding framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for TaskRecoveryBindingRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "run-bound task recovery refused: {self:?}")
    }
}

impl core::error::Error for TaskRecoveryBindingRefusal {}

impl From<TaskClaimRecoveryRefusal> for TaskRecoveryBindingRefusal {
    fn from(value: TaskClaimRecoveryRefusal) -> Self {
        Self::Recovery(value)
    }
}

impl From<IntentRunIdentityRefusal> for TaskRecoveryBindingRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<CodecRefusal> for TaskRecoveryBindingRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
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
    /// Supplied run has the same coordination ID but different machine-enforced
    /// fields from the run captured during recovery.
    RunCommitmentMismatch {
        /// Commitment captured during recovery.
        expected: IntentRunCommitment,
        /// Commitment supplied during cleanup.
        observed: IntentRunCommitment,
    },
    /// Complete Intent Run identity could not be produced.
    RunIdentity(IntentRunIdentityRefusal),
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

impl From<IntentRunIdentityRefusal> for TaskRecoveryPersistenceRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

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

/// Recovers an active claim and captures the exact complete run in the same API
/// call.
///
/// # Errors
///
/// Returns the ordinary recovery refusal, a complete-run identity refusal, or a
/// canonical binding-framing refusal.
pub fn recover_task_claim_for_cleanup(
    reconstruction: &TaskLeaseReconstructionReceipt,
    claim: &TaskClaimReceipt,
    refreshed: &AgentSituationReceipt,
    run: &IntentRun,
) -> Result<RunBoundRecoveredTaskClaim, TaskRecoveryBindingRefusal> {
    let recovered = activate_reconstructed_task_claim(reconstruction, claim, refreshed, run)?;
    let run_commitment = run.commitment()?;
    let mut bound = RunBoundRecoveredTaskClaim {
        binding_id: RunBoundRecoveredTaskClaimId([0; 32]),
        recovered,
        run_commitment,
    };
    bound.binding_id = RunBoundRecoveredTaskClaimId(recovery_binding_commitment(&bound)?);
    Ok(bound)
}

/// Releases a restart-recovered claim through the durable task-store protocol.
///
/// The complete run captured during recovery is revalidated before semantic
/// mutation or store I/O. The invoked store profile becomes the transition
/// adapter identity, so a caller also cannot prepare the transition under one
/// backend and execute it under another.
///
/// # Errors
///
/// Refuses recovery/reconstruction or claim substitution, same-ID complete-run
/// substitution, semantic release refusal, a definite pre-effect store refusal,
/// and terminal receipt framing failure.
#[allow(clippy::too_many_arguments)]
pub fn persist_recovered_task_release<S: TaskProjectionStore>(
    store: &mut S,
    reconstruction: &TaskLeaseReconstructionReceipt,
    recovered: RunBoundRecoveredTaskClaim,
    claim: &TaskClaimReceipt,
    run: &IntentRun,
    disposition: TaskReleaseDisposition,
    resolved_at: LogicalTime,
    evidence_root: Digest,
) -> Result<RecoveredTaskReleasePersistenceOutcome, TaskRecoveryPersistenceRefusal> {
    if recovered.lease_reconstruction_id() != reconstruction.receipt_id() {
        return Err(
            TaskRecoveryPersistenceRefusal::LeaseReconstructionMismatch {
                expected: reconstruction.receipt_id(),
                observed: recovered.lease_reconstruction_id(),
            },
        );
    }
    if recovered.claim_id() != claim.claim_id()
        || recovered.active_claim().claim_id() != claim.claim_id()
    {
        return Err(TaskRecoveryPersistenceRefusal::ClaimMismatch);
    }
    let observed_run_commitment = run.commitment()?;
    if observed_run_commitment != recovered.run_commitment() {
        return Err(TaskRecoveryPersistenceRefusal::RunCommitmentMismatch {
            expected: recovered.run_commitment(),
            observed: observed_run_commitment,
        });
    }

    let run_bound_recovery_id = recovered.binding_id();
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
                run_bound_recovery_id,
                recovery_id,
                lease_reconstruction_id,
                resolution,
            };
            persisted.receipt_id = PersistedRecoveredTaskReleaseId(release_commitment(&persisted)?);
            Ok(RecoveredTaskReleasePersistenceOutcome::Persisted(persisted))
        }
        TaskResolutionPersistenceOutcome::Conflict {
            envelope,
            execution,
        } => Ok(RecoveredTaskReleasePersistenceOutcome::Conflict {
            run_bound_recovery_id,
            recovery_id,
            lease_reconstruction_id,
            envelope,
            execution,
        }),
        TaskResolutionPersistenceOutcome::NeedsReconciliation {
            envelope,
            execution,
        } => Ok(
            RecoveredTaskReleasePersistenceOutcome::NeedsReconciliation {
                run_bound_recovery_id,
                recovery_id,
                lease_reconstruction_id,
                envelope,
                execution,
            },
        ),
    }
}

fn recovery_binding_commitment(
    recovered: &RunBoundRecoveredTaskClaim,
) -> Result<[u8; 32], TaskRecoveryBindingRefusal> {
    let mut encoder = Encoder::with_capacity(128);
    encoder.write_bytes(
        "run_bound_recovered_task_claim_domain",
        RECOVERY_BINDING_DOMAIN,
    )?;
    encoder.write_raw(recovered.recovered.recovery_id().as_bytes());
    encoder.write_raw(recovered.run_commitment.as_bytes());
    Ok(hash(&encoder.into_bytes()))
}

fn release_commitment(
    persisted: &PersistedRecoveredTaskRelease,
) -> Result<[u8; 32], TaskRecoveryPersistenceRefusal> {
    let mut encoder = Encoder::with_capacity(224);
    encoder.write_bytes("recovered_task_release_domain", RECOVERED_RELEASE_DOMAIN)?;
    encoder.write_raw(persisted.run_bound_recovery_id.as_bytes());
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
