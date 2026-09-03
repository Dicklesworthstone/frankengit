//! Bridge from collected task rows to authority-bound single-task state.
//!
//! [`crate::TaskProjectionCollectionReceipt`] owns a complete multi-row
//! generation for frontier construction. [`crate::AuthorityBoundTaskProjectionSnapshot`]
//! owns one exact task state for claim/release/transfer semantics. This module
//! connects the two without fabricating state that the collection did not
//! preserve.
//!
//! An unassigned row is complete by construction and can become a claim basis
//! directly through [`collected_unclaimed_task`]. A claimed row needs durable
//! history not retained by the v1 multi-row projection: predecessor generation,
//! claim instant, and the complete machine-enforced identity of its assignee.
//! [`reconstruct_collected_task_lease`] accepts those facts only in a
//! collection/task/generation-bound observation, revalidates every claim field
//! still present in the row, and emits a separate evidence receipt around the
//! reconstructed semantic snapshot.
//!
//! [`activate_reconstructed_task_claim`] then compares that exact reconstructed
//! lease with the original [`crate::TaskClaimReceipt`] before ordinary fresh-
//! situation activation. This prevents restart recovery from treating a global
//! generation match, a numeric [`crate::RunId`], or a later read of the same
//! authority head as sufficient proof of the task's complete claimant, plan,
//! reservation surface, and lifetime.
//!
//! History adapter identity and evidence never perturb semantic task-state
//! identity. They remain committed by [`TaskLeaseReconstructionReceipt`]. The
//! claimant's [`crate::IntentRunCommitment`] is semantic lease state and does.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::Digest;

use crate::{
    ActiveTaskClaim, AgentSituationReceipt, AuthorityBoundTaskProjectionSnapshot,
    AuthorityReadIdentityRefusal, AuthorityReadReceipt, AuthorityReadReceiptId, IntentRun,
    IntentRunCommitment, IntentRunIdentityRefusal, LogicalTime, RunId, TaskClaimReceipt,
    TaskClaimReceiptId, TaskClaimRefusal, TaskCoordinationRefusal, TaskProjectionAdapterRefusal,
    TaskProjectionAssignment, TaskProjectionCollectionReceipt, TaskProjectionCollectionReceiptId,
    TaskProjectionGeneration, TaskProjectionLease, WorkConflict, WorkTaskId,
};

const LEASE_RECONSTRUCTION_DOMAIN: &[u8] = b"frankengit.agent.task-lease-reconstruction/v2\0";
const CLAIM_RECOVERY_DOMAIN: &[u8] = b"frankengit.agent.task-claim-recovery/v2\0";

/// Stable identity of one evidenced active-lease reconstruction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskLeaseReconstructionReceiptId([u8; 32]);

impl TaskLeaseReconstructionReceiptId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TaskLeaseReconstructionReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task-lease-reconstruction:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable identity of one restart-recovered active claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecoveredActiveTaskClaimId([u8; 32]);

impl RecoveredActiveTaskClaimId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RecoveredActiveTaskClaimId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("recovered-active-task-claim:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Durable history absent from one collected claimed task row.
///
/// The collection receipt, task, current generation, and complete assignee are
/// repeated here so a history response cannot be replayed across another
/// collection or same-ID run while still looking structurally plausible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskLeaseHistoryObservation {
    collection_receipt_id: TaskProjectionCollectionReceiptId,
    task_id: WorkTaskId,
    claimed_generation: TaskProjectionGeneration,
    run_commitment: IntentRunCommitment,
    previous_generation: [u8; 32],
    claimed_at: LogicalTime,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
}

impl TaskLeaseHistoryObservation {
    /// Creates one backend-provided lease-history observation.
    #[must_use]
    pub const fn new(
        collection_receipt_id: TaskProjectionCollectionReceiptId,
        task_id: WorkTaskId,
        claimed_generation: TaskProjectionGeneration,
        run_commitment: IntentRunCommitment,
        previous_generation: [u8; 32],
        claimed_at: LogicalTime,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Self {
        Self {
            collection_receipt_id,
            task_id,
            claimed_generation,
            run_commitment,
            previous_generation,
            claimed_at,
            adapter_identity,
            evidence_root,
        }
    }

    /// Collection whose row this history supplements.
    #[must_use]
    pub const fn collection_receipt_id(&self) -> TaskProjectionCollectionReceiptId {
        self.collection_receipt_id
    }

    /// Claimed task whose history was read.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.task_id
    }

    /// Current claimed generation expected by the history record.
    #[must_use]
    pub const fn claimed_generation(&self) -> TaskProjectionGeneration {
        self.claimed_generation
    }

    /// Complete machine-enforced claimant identity retained by the backend.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Task generation replaced by the claim.
    #[must_use]
    pub const fn previous_generation(&self) -> [u8; 32] {
        self.previous_generation
    }

    /// Logical claim instant retained by the durable backend.
    #[must_use]
    pub const fn claimed_at(&self) -> LogicalTime {
        self.claimed_at
    }

    /// Backend implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(&self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Commitment to the raw lease-history read and decoding evidence.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }
}

/// Evidence that one collected claimed row was reconstructed without invented
/// lease state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskLeaseReconstructionReceipt {
    receipt_id: TaskLeaseReconstructionReceiptId,
    collection_receipt_id: TaskProjectionCollectionReceiptId,
    authority_read_receipt_id: AuthorityReadReceiptId,
    task_id: WorkTaskId,
    run_commitment: IntentRunCommitment,
    previous_generation: [u8; 32],
    claimed_at: LogicalTime,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
    snapshot: AuthorityBoundTaskProjectionSnapshot,
}

impl TaskLeaseReconstructionReceipt {
    /// Stable reconstruction identity.
    #[must_use]
    pub const fn receipt_id(&self) -> TaskLeaseReconstructionReceiptId {
        self.receipt_id
    }

    /// Exact multi-row collection used as the current-state basis.
    #[must_use]
    pub const fn collection_receipt_id(&self) -> TaskProjectionCollectionReceiptId {
        self.collection_receipt_id
    }

    /// Exact authenticated read event used by collection and reconstruction.
    #[must_use]
    pub const fn authority_read_receipt_id(&self) -> AuthorityReadReceiptId {
        self.authority_read_receipt_id
    }

    /// Reconstructed task.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.task_id
    }

    /// Complete machine-enforced claimant identity reconstructed from history.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Generation replaced by the original claim.
    #[must_use]
    pub const fn previous_generation(&self) -> [u8; 32] {
        self.previous_generation
    }

    /// Original claim instant.
    #[must_use]
    pub const fn claimed_at(&self) -> LogicalTime {
        self.claimed_at
    }

    /// Backend profile that supplied the missing history.
    #[must_use]
    pub const fn adapter_identity(&self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Lease-history read/decoding evidence commitment.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }

    /// Reconstructed authority-bound semantic task state.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthorityBoundTaskProjectionSnapshot {
        &self.snapshot
    }
}

/// Active task claim recovered from durable lease and original claim evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredActiveTaskClaim {
    recovery_id: RecoveredActiveTaskClaimId,
    lease_reconstruction_id: TaskLeaseReconstructionReceiptId,
    claim_id: TaskClaimReceiptId,
    active_claim: ActiveTaskClaim,
}

impl RecoveredActiveTaskClaim {
    /// Stable recovery identity.
    #[must_use]
    pub const fn recovery_id(self) -> RecoveredActiveTaskClaimId {
        self.recovery_id
    }

    /// Durable lease reconstruction consumed by this recovery.
    #[must_use]
    pub const fn lease_reconstruction_id(self) -> TaskLeaseReconstructionReceiptId {
        self.lease_reconstruction_id
    }

    /// Original validated task claim.
    #[must_use]
    pub const fn claim_id(self) -> TaskClaimReceiptId {
        self.claim_id
    }

    /// Freshly activated task claim used by action, handoff, release, and
    /// cancellation protocols.
    #[must_use]
    pub const fn active_claim(self) -> ActiveTaskClaim {
        self.active_claim
    }
}

/// Converts one collected unassigned row into the exact authority-bound claim
/// basis.
///
/// # Errors
///
/// Refuses another authenticated read event, a missing task, any assignment or
/// active-claim metadata, and authority-bound snapshot construction failure.
pub fn collected_unclaimed_task(
    collection: &TaskProjectionCollectionReceipt,
    authority: &AuthorityReadReceipt,
    task_id: WorkTaskId,
) -> Result<AuthorityBoundTaskProjectionSnapshot, TaskCollectionBridgeRefusal> {
    validate_authority(collection, authority)?;

    let row = collection
        .snapshot()
        .row(task_id)
        .ok_or(TaskCollectionBridgeRefusal::TaskMissing { task_id })?;
    if row.assignee().is_some()
        || row.plan_id().is_some()
        || row.claim_expiry().is_some()
        || !row.reserved_surfaces().is_empty()
    {
        return Err(TaskCollectionBridgeRefusal::LeaseReconstructionRequired { task_id });
    }

    AuthorityBoundTaskProjectionSnapshot::observed(
        authority,
        task_id,
        *collection.snapshot().generation().as_bytes(),
        row.phase(),
        TaskProjectionAssignment::Unassigned,
        collection.snapshot().observed_at(),
    )
    .map_err(TaskCollectionBridgeRefusal::Coordination)
}

/// Reconstructs one collected claimed row using exact durable lease history.
///
/// The predecessor generation, original claim instant, and complete claimant
/// commitment come from the history observation. Assignee ID, plan, expiry,
/// reservation surface, phase, and current generation come from the validated
/// collection and must be internally complete. Expired leases are accepted
/// because cleanup must remain possible.
///
/// # Errors
///
/// Refuses another authenticated read, replayed or mismatched history, an
/// unclaimed/incomplete/inconsistent row, history observed after the collection,
/// zero adapter identity, invalid lease structure, snapshot construction, and
/// canonical receipt framing failure.
pub fn reconstruct_collected_task_lease(
    collection: &TaskProjectionCollectionReceipt,
    authority: &AuthorityReadReceipt,
    task_id: WorkTaskId,
    history: TaskLeaseHistoryObservation,
) -> Result<TaskLeaseReconstructionReceipt, TaskCollectionBridgeRefusal> {
    let authority_read_receipt_id = validate_authority(collection, authority)?;
    if history.collection_receipt_id != collection.receipt_id() {
        return Err(TaskCollectionBridgeRefusal::HistoryCollectionMismatch {
            expected: collection.receipt_id(),
            observed: history.collection_receipt_id,
        });
    }
    if history.task_id != task_id {
        return Err(TaskCollectionBridgeRefusal::HistoryTaskMismatch {
            expected: task_id,
            observed: history.task_id,
        });
    }
    let current_generation = collection.snapshot().generation();
    if history.claimed_generation != current_generation {
        return Err(TaskCollectionBridgeRefusal::HistoryGenerationMismatch {
            expected: current_generation,
            observed: history.claimed_generation,
        });
    }
    if is_zero(&history.adapter_identity) {
        return Err(TaskCollectionBridgeRefusal::ZeroLeaseAdapterIdentity);
    }

    let row = collection
        .snapshot()
        .row(task_id)
        .ok_or(TaskCollectionBridgeRefusal::TaskMissing { task_id })?;
    let assignee = row
        .assignee()
        .ok_or(TaskCollectionBridgeRefusal::ClaimedTaskRequired { task_id })?;
    let plan_id = row
        .plan_id()
        .ok_or(TaskCollectionBridgeRefusal::IncompleteClaimMetadata { task_id })?;
    let expires_at = row
        .claim_expiry()
        .ok_or(TaskCollectionBridgeRefusal::IncompleteClaimMetadata { task_id })?;
    if row.reserved_surfaces().is_empty() {
        return Err(TaskCollectionBridgeRefusal::IncompleteClaimMetadata { task_id });
    }
    if row.conflict() != WorkConflict::ReservedBy(assignee) {
        return Err(TaskCollectionBridgeRefusal::ClaimConflictMismatch {
            task_id,
            assignee,
            observed: row.conflict(),
        });
    }
    if collection.snapshot().observed_at() < history.claimed_at {
        return Err(TaskCollectionBridgeRefusal::ObservationBeforeClaim {
            claimed_at: history.claimed_at,
            observed_at: collection.snapshot().observed_at(),
        });
    }

    let lease = TaskProjectionLease::observed(
        plan_id,
        assignee,
        history.run_commitment,
        history.previous_generation,
        *current_generation.as_bytes(),
        row.reserved_surfaces().to_vec(),
        history.claimed_at,
        expires_at,
    )
    .map_err(TaskCollectionBridgeRefusal::Lease)?;
    let snapshot = AuthorityBoundTaskProjectionSnapshot::observed_with_lease(
        authority,
        task_id,
        *current_generation.as_bytes(),
        row.phase(),
        lease,
        collection.snapshot().observed_at(),
    )
    .map_err(TaskCollectionBridgeRefusal::Coordination)?;

    let mut receipt = TaskLeaseReconstructionReceipt {
        receipt_id: TaskLeaseReconstructionReceiptId([0; 32]),
        collection_receipt_id: collection.receipt_id(),
        authority_read_receipt_id,
        task_id,
        run_commitment: history.run_commitment,
        previous_generation: history.previous_generation,
        claimed_at: history.claimed_at,
        adapter_identity: history.adapter_identity,
        evidence_root: history.evidence_root,
        snapshot,
    };
    receipt.receipt_id = TaskLeaseReconstructionReceiptId(reconstruction_commitment(&receipt)?);
    Ok(receipt)
}

/// Recovers an active claim only when the reconstructed durable lease and the
/// original claim receipt describe the same task transition and complete run.
///
/// The refreshed situation and supplied run must use the same exact
/// authenticated read event and run commitment as the lease reconstruction.
/// The ordinary claim activation protocol is then applied and its result is
/// committed together with both recovery inputs.
///
/// # Errors
///
/// Refuses missing/inconsistent lease material, any task/plan/run/generation/
/// surface/time/lifetime mismatch, complete-run or exact-read substitution,
/// ordinary activation failure, and canonical recovery framing failure.
pub fn activate_reconstructed_task_claim(
    reconstruction: &TaskLeaseReconstructionReceipt,
    claim: &TaskClaimReceipt,
    refreshed: &AgentSituationReceipt,
    run: &IntentRun,
) -> Result<RecoveredActiveTaskClaim, TaskClaimRecoveryRefusal> {
    let lease = reconstruction
        .snapshot
        .lease()
        .ok_or(TaskClaimRecoveryRefusal::MissingReconstructedLease)?;
    if claim.task_id() != reconstruction.task_id {
        return Err(TaskClaimRecoveryRefusal::TaskMismatch {
            expected: reconstruction.task_id,
            observed: claim.task_id(),
        });
    }
    if claim.plan_id() != lease.plan_id() {
        return Err(TaskClaimRecoveryRefusal::PlanMismatch);
    }
    if claim.assignee() != lease.assignee() || run.run_id() != lease.assignee() {
        return Err(TaskClaimRecoveryRefusal::AssigneeMismatch {
            expected: lease.assignee(),
            observed: claim.assignee(),
            supplied_run: run.run_id(),
        });
    }
    let supplied_run_commitment = run.commitment()?;
    if reconstruction.run_commitment != lease.run_commitment()
        || claim.run_commitment() != lease.run_commitment()
        || supplied_run_commitment != lease.run_commitment()
        || refreshed.intent_run_commitment() != Some(lease.run_commitment())
    {
        return Err(TaskClaimRecoveryRefusal::RunCommitmentMismatch {
            expected: lease.run_commitment(),
            claim: claim.run_commitment(),
            supplied: supplied_run_commitment,
            refreshed: refreshed.intent_run_commitment(),
        });
    }
    if claim.previous_task_projection_generation() != lease.previous_generation() {
        return Err(TaskClaimRecoveryRefusal::PreviousGenerationMismatch {
            expected: *lease.previous_generation(),
            observed: *claim.previous_task_projection_generation(),
        });
    }
    if claim.claimed_task_projection_generation() != lease.claimed_generation()
        || claim.claimed_task_projection_generation() != reconstruction.snapshot.generation()
    {
        return Err(TaskClaimRecoveryRefusal::ClaimedGenerationMismatch {
            expected: *lease.claimed_generation(),
            observed: *claim.claimed_task_projection_generation(),
        });
    }
    if claim.reserved_surfaces() != lease.reserved_surfaces() {
        return Err(TaskClaimRecoveryRefusal::ReservationSurfaceMismatch);
    }
    if claim.claimed_at() != lease.claimed_at() {
        return Err(TaskClaimRecoveryRefusal::ClaimTimeMismatch {
            expected: lease.claimed_at(),
            observed: claim.claimed_at(),
        });
    }
    if claim.expires_at() != lease.expires_at() {
        return Err(TaskClaimRecoveryRefusal::ExpiryMismatch {
            expected: lease.expires_at(),
            observed: claim.expires_at(),
        });
    }

    let refreshed_authority_id = refreshed.authority_read_receipt().receipt_id()?;
    let run_authority = run
        .authority_read_receipt()
        .ok_or(TaskClaimRecoveryRefusal::RunAuthorityReceiptRequired)?;
    let run_authority_id = run_authority.receipt_id()?;
    if refreshed_authority_id != reconstruction.authority_read_receipt_id
        || run_authority_id != reconstruction.authority_read_receipt_id
        || refreshed.authority_read_receipt() != reconstruction.snapshot.authority_read_receipt()
        || run_authority != reconstruction.snapshot.authority_read_receipt()
    {
        return Err(TaskClaimRecoveryRefusal::AuthorityMismatch);
    }

    let active_claim = claim
        .activate(refreshed, run)
        .map_err(TaskClaimRecoveryRefusal::Claim)?;
    if active_claim.run_commitment() != lease.run_commitment() {
        return Err(TaskClaimRecoveryRefusal::RunCommitmentMismatch {
            expected: lease.run_commitment(),
            claim: claim.run_commitment(),
            supplied: supplied_run_commitment,
            refreshed: refreshed.intent_run_commitment(),
        });
    }
    let mut recovered = RecoveredActiveTaskClaim {
        recovery_id: RecoveredActiveTaskClaimId([0; 32]),
        lease_reconstruction_id: reconstruction.receipt_id,
        claim_id: claim.claim_id(),
        active_claim,
    };
    recovered.recovery_id = RecoveredActiveTaskClaimId(claim_recovery_commitment(&recovered)?);
    Ok(recovered)
}

/// Why a collected row could not become authority-bound single-task state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskCollectionBridgeRefusal {
    /// Caller supplied another authenticated read event or authority position.
    AuthorityMismatch,
    /// Requested task is absent from the collected generation.
    TaskMissing {
        /// Missing task identity.
        task_id: WorkTaskId,
    },
    /// The row carries assignment/claim state but direct unclaimed conversion
    /// cannot invent the complete durable lease history.
    LeaseReconstructionRequired {
        /// Claimed or assigned task.
        task_id: WorkTaskId,
    },
    /// Lease history was supplied for an unclaimed task.
    ClaimedTaskRequired {
        /// Unclaimed task.
        task_id: WorkTaskId,
    },
    /// Claimed row omitted plan, expiry, or reservation state.
    IncompleteClaimMetadata {
        /// Incomplete task.
        task_id: WorkTaskId,
    },
    /// Claimed row's conflict state does not reserve the task for its assignee.
    ClaimConflictMismatch {
        /// Inconsistent task.
        task_id: WorkTaskId,
        /// Claimed assignee.
        assignee: RunId,
        /// Collected conflict state.
        observed: WorkConflict,
    },
    /// History observation belongs to another collection.
    HistoryCollectionMismatch {
        /// Expected collection.
        expected: TaskProjectionCollectionReceiptId,
        /// Supplied collection.
        observed: TaskProjectionCollectionReceiptId,
    },
    /// History observation belongs to another task.
    HistoryTaskMismatch {
        /// Requested task.
        expected: WorkTaskId,
        /// History task.
        observed: WorkTaskId,
    },
    /// History observation belongs to another claimed generation.
    HistoryGenerationMismatch {
        /// Collected current generation.
        expected: TaskProjectionGeneration,
        /// History current generation.
        observed: TaskProjectionGeneration,
    },
    /// Collection claims to predate the original claim it already reflects.
    ObservationBeforeClaim {
        /// Original claim instant.
        claimed_at: LogicalTime,
        /// Collection observation instant.
        observed_at: LogicalTime,
    },
    /// Lease-history adapter profile used the reserved all-zero identity.
    ZeroLeaseAdapterIdentity,
    /// Exact authenticated-read identity failed.
    AuthorityIdentity(AuthorityReadIdentityRefusal),
    /// Persisted lease structure failed deterministic validation.
    Lease(TaskProjectionAdapterRefusal),
    /// Authority-bound single-task construction failed.
    Coordination(TaskCoordinationRefusal),
    /// Canonical reconstruction-receipt framing failed.
    Codec(CodecRefusal),
}

/// Why a reconstructed durable lease could not recover an active claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskClaimRecoveryRefusal {
    /// Reconstruction receipt did not carry the claimed lease it promises.
    MissingReconstructedLease,
    /// Original claim belongs to another task.
    TaskMismatch {
        /// Reconstructed task.
        expected: WorkTaskId,
        /// Claim task.
        observed: WorkTaskId,
    },
    /// Original claim belongs to another plan.
    PlanMismatch,
    /// Claim or supplied run names another assignee.
    AssigneeMismatch {
        /// Reconstructed assignee.
        expected: RunId,
        /// Claim assignee.
        observed: RunId,
        /// Supplied run.
        supplied_run: RunId,
    },
    /// Claim, supplied run, refreshed situation, or history carries another
    /// complete claimant identity.
    RunCommitmentMismatch {
        /// Commitment reconstructed from durable history.
        expected: IntentRunCommitment,
        /// Commitment retained by the original claim receipt.
        claim: IntentRunCommitment,
        /// Commitment computed from the supplied run.
        supplied: IntentRunCommitment,
        /// Commitment retained by the refreshed situation, when present.
        refreshed: Option<IntentRunCommitment>,
    },
    /// Claim names another predecessor generation.
    PreviousGenerationMismatch {
        /// Reconstructed predecessor.
        expected: [u8; 32],
        /// Claim predecessor.
        observed: [u8; 32],
    },
    /// Claim names another current generation.
    ClaimedGenerationMismatch {
        /// Reconstructed current generation.
        expected: [u8; 32],
        /// Claim current generation.
        observed: [u8; 32],
    },
    /// Claim reserved another conflict surface.
    ReservationSurfaceMismatch,
    /// Claim records another mutation instant.
    ClaimTimeMismatch {
        /// Reconstructed instant.
        expected: LogicalTime,
        /// Claim instant.
        observed: LogicalTime,
    },
    /// Claim records another exclusive expiry.
    ExpiryMismatch {
        /// Reconstructed expiry.
        expected: LogicalTime,
        /// Claim expiry.
        observed: LogicalTime,
    },
    /// Supplied run lacks a complete authenticated read receipt.
    RunAuthorityReceiptRequired,
    /// Complete run identity could not be produced.
    RunIdentity(IntentRunIdentityRefusal),
    /// Refresh or run substituted another exact authenticated read event.
    AuthorityMismatch,
    /// Exact authenticated-read identity failed.
    AuthorityIdentity(AuthorityReadIdentityRefusal),
    /// Ordinary task-claim activation failed.
    Claim(TaskClaimRefusal),
    /// Canonical recovery framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for TaskCollectionBridgeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task collection bridge refused: {self:?}")
    }
}

impl core::error::Error for TaskCollectionBridgeRefusal {}

impl fmt::Display for TaskClaimRecoveryRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task claim recovery refused: {self:?}")
    }
}

impl core::error::Error for TaskClaimRecoveryRefusal {}

impl From<AuthorityReadIdentityRefusal> for TaskCollectionBridgeRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::AuthorityIdentity(value)
    }
}

impl From<CodecRefusal> for TaskCollectionBridgeRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

impl From<IntentRunIdentityRefusal> for TaskClaimRecoveryRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<AuthorityReadIdentityRefusal> for TaskClaimRecoveryRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::AuthorityIdentity(value)
    }
}

impl From<CodecRefusal> for TaskClaimRecoveryRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_authority(
    collection: &TaskProjectionCollectionReceipt,
    authority: &AuthorityReadReceipt,
) -> Result<AuthorityReadReceiptId, TaskCollectionBridgeRefusal> {
    let authority_read_receipt_id = authority.receipt_id()?;
    if authority_read_receipt_id != collection.authority_read_receipt_id()
        || authority.repository_id() != collection.repository_id()
        || authority.authority_head_id() != collection.authority_head_id()
        || authority.authority_head_generation() != collection.authority_head_generation()
    {
        return Err(TaskCollectionBridgeRefusal::AuthorityMismatch);
    }
    Ok(authority_read_receipt_id)
}

fn reconstruction_commitment(
    receipt: &TaskLeaseReconstructionReceipt,
) -> Result<[u8; 32], TaskCollectionBridgeRefusal> {
    let mut encoder = Encoder::with_capacity(352);
    encoder.write_bytes(
        "task_lease_reconstruction_domain",
        LEASE_RECONSTRUCTION_DOMAIN,
    )?;
    encoder.write_raw(receipt.collection_receipt_id.as_bytes());
    encoder.write_raw(receipt.authority_read_receipt_id.as_bytes());
    encoder.write_raw(receipt.task_id.as_bytes());
    encoder.write_raw(receipt.run_commitment.as_bytes());
    encoder.write_raw(&receipt.previous_generation);
    encoder.write_scalar(receipt.claimed_at.value());
    encoder.write_raw(&receipt.adapter_identity);
    encoder.write_digest(&receipt.evidence_root)?;
    encoder.write_raw(receipt.snapshot.snapshot_id().as_bytes());
    Ok(hash(&encoder.into_bytes()))
}

fn claim_recovery_commitment(
    recovered: &RecoveredActiveTaskClaim,
) -> Result<[u8; 32], TaskClaimRecoveryRefusal> {
    let mut encoder = Encoder::with_capacity(224);
    encoder.write_bytes("task_claim_recovery_domain", CLAIM_RECOVERY_DOMAIN)?;
    encoder.write_raw(recovered.lease_reconstruction_id.as_bytes());
    encoder.write_raw(recovered.claim_id.as_bytes());
    encoder.write_raw(recovered.active_claim.activation_id().as_bytes());
    encoder.write_raw(recovered.active_claim.run_commitment().as_bytes());
    Ok(hash(&encoder.into_bytes()))
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
