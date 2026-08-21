//! The eleven concrete obligations of `docs/CALM_AND_OBLIGATIONS.md` section 7.
//!
//! Each class is a zero-sized marker implementing [`ObligationKind`] plus the
//! payload types its four phases carry. Where the specification states a
//! precondition for commit, that precondition is enforced by making the commit
//! receipt constructible only through a checked constructor: an admitted object
//! cannot be committed without its verification evidence, a repair cannot be
//! committed on decode success alone, a context packet cannot be committed
//! without a complete inclusion and omission accounting, and a charge cannot be
//! committed above its ceiling. Refusing at the type boundary is what makes
//! "commit only after X" a property of the program rather than a review note.

use crate::algebra::Grade;
use crate::ids::{IdempotencyKey, OpaqueHandle};
use crate::settlement::DownstreamIdempotency;
use crate::twophase::{
    ExternallyObserved, InternalEffect, ObligationClass, ObligationKind, ObservationMode,
    TrivialAck,
};
use core::fmt;
use fgit_types::{
    AuthorityVersionToken, Digest, EvidenceRecordId, GenerationId, GitOid, ObjectEnvelopeId,
    PrincipalId, PrincipalSnapshotId, RepositoryAuthorityHeadId, RepositoryCommitId,
    RepositoryDecisionBatchId, SegmentManifestId, TenantId, TxId,
};

// ---------------------------------------------------------------------------
// 7.1 ObjectAdmissionPermit
// ---------------------------------------------------------------------------

/// Admission of one immutable object into the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectAdmissionPermit;

/// The class of object being admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectClass {
    /// A loose or packed Git object.
    GitObject,
    /// An object-aware storage segment.
    Segment,
    /// A repair symbol.
    RepairSymbol,
    /// An evidence or receipt body.
    EvidenceBody,
}

/// What the reserve phase records for an admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectAdmission {
    /// The object class that passed the coarse admission check.
    pub class: ObjectClass,
    /// Length the sender declared before any bytes were trusted.
    pub declared_len: u64,
    /// The quarantine envelope holding the candidate bytes.
    pub staging: ObjectEnvelopeId,
}

/// The structural verdict produced by bounded validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StructureVerdict {
    /// Structure parsed completely within its declared bounds.
    Verified,
    /// Structure was malformed.
    Malformed,
    /// Validation did not finish inside its budget.
    NotValidated,
}

/// Why an admission was abandoned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdmissionAbortReason {
    /// The tenant quota was withdrawn before commit.
    QuotaWithdrawn,
    /// Bytes, identity, digest, length, or structure failed to verify.
    VerificationFailed,
    /// The placement write, its flush, or its publication link failed after
    /// the reservation was taken.
    ///
    /// This is a storage failure, not a verification failure: the candidate
    /// was never shown to be wrong, it was never durably placed. Reporting it
    /// as [`AdmissionAbortReason::VerificationFailed`] would fabricate a
    /// verdict about the bytes that nothing established.
    PlacementWriteFailed,
    /// The owning region was cancelled.
    Cancelled,
    /// An identical object was admitted by another attempt.
    Superseded,
}

/// Refusal from [`AdmittedObject::verified`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionRefusal {
    /// The structural verdict was not [`StructureVerdict::Verified`].
    StructureNotVerified(StructureVerdict),
    /// The verified length did not match the declared length.
    LengthMismatch {
        /// Length the sender declared.
        declared: u64,
        /// Length actually measured.
        verified: u64,
    },
}

impl fmt::Display for AdmissionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::StructureNotVerified(verdict) => {
                write!(
                    f,
                    "admission structure verdict is {verdict:?}, not verified"
                )
            }
            Self::LengthMismatch { declared, verified } => write!(
                f,
                "admission declared {declared} bytes but verified {verified}"
            ),
        }
    }
}

impl std::error::Error for AdmissionRefusal {}

/// Commit evidence for an admission.
///
/// Constructible only through [`AdmittedObject::verified`], which is how
/// "commits only after bytes, native identity, strong digest, length, and
/// structure verify" is enforced rather than merely documented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedObject {
    native_oid: GitOid,
    strong_digest: Digest,
    verified_len: u64,
}

impl AdmittedObject {
    /// Builds commit evidence, refusing anything unverified.
    pub fn verified(
        reservation: &ObjectAdmission,
        native_oid: GitOid,
        strong_digest: Digest,
        verified_len: u64,
        structure: StructureVerdict,
    ) -> Result<Self, AdmissionRefusal> {
        if structure != StructureVerdict::Verified {
            return Err(AdmissionRefusal::StructureNotVerified(structure));
        }
        if verified_len != reservation.declared_len {
            return Err(AdmissionRefusal::LengthMismatch {
                declared: reservation.declared_len,
                verified: verified_len,
            });
        }
        Ok(Self {
            native_oid,
            strong_digest,
            verified_len,
        })
    }

    /// The native object identifier, preserved exactly in its hash domain.
    #[must_use]
    pub const fn native_oid(&self) -> GitOid {
        self.native_oid
    }

    /// The internal strong digest.
    #[must_use]
    pub const fn strong_digest(&self) -> Digest {
        self.strong_digest
    }

    /// The verified length.
    #[must_use]
    pub const fn verified_len(&self) -> u64 {
        self.verified_len
    }
}

/// Abort evidence for an admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionAbandoned {
    /// Why staging and quota were released.
    pub reason: AdmissionAbortReason,
}

impl ObligationKind for ObjectAdmissionPermit {
    const CLASS: ObligationClass = ObligationClass::ObjectAdmissionPermit;
    const OBSERVATION: ObservationMode = ObservationMode::Internal;
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::Bytes, Grade::Objects];
    type Reservation = ObjectAdmission;
    type CommitReceipt = AdmittedObject;
    type AbortReceipt = AdmissionAbandoned;
    type AckEvidence = TrivialAck;
}

impl InternalEffect for ObjectAdmissionPermit {}

// ---------------------------------------------------------------------------
// 7.2 PreparedTxnSlot
// ---------------------------------------------------------------------------

/// One preparation-lane combiner slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedTxnSlot;

/// What the reserve phase records for a preparation slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneSlot {
    /// The per-core preparation lane that owns the transaction.
    pub lane: u16,
    /// The sealed transaction identity being prepared.
    pub transaction: TxId,
}

/// Commit evidence for a preparation slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotHandedOff {
    /// The decision-batch attempt that took ownership of the candidate.
    pub batch_attempt: RepositoryDecisionBatchId,
}

/// Why a preparation slot published no candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NoCandidateReason {
    /// Deterministic policy refused the transaction.
    PolicyRefusal,
    /// A witness failed revalidation against the current head.
    WitnessInvalid,
    /// The owning region was cancelled.
    Cancelled,
    /// Preparation exceeded its budget.
    BudgetExhausted,
}

/// Abort evidence for a preparation slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotAbandoned {
    /// Why no candidate reached a ready slot.
    pub reason: NoCandidateReason,
}

impl ObligationKind for PreparedTxnSlot {
    const CLASS: ObligationClass = ObligationClass::PreparedTxnSlot;
    const OBSERVATION: ObservationMode = ObservationMode::Internal;
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::MemoryBytes];
    type Reservation = LaneSlot;
    type CommitReceipt = SlotHandedOff;
    type AbortReceipt = SlotAbandoned;
    type AckEvidence = TrivialAck;
}

impl InternalEffect for PreparedTxnSlot {}

// ---------------------------------------------------------------------------
// 7.3 HeadCasAttempt
// ---------------------------------------------------------------------------

/// One authority head compare-and-set attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadCasAttempt;

/// What the reserve phase binds for a head compare-and-set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasAttempt {
    /// The exact predecessor version token the attempt replaces.
    pub expected_version: AuthorityVersionToken,
    /// The candidate head being published.
    pub candidate_head: RepositoryAuthorityHeadId,
    /// The decision batch the candidate head commits.
    pub decision_batch: RepositoryDecisionBatchId,
    /// The immutable principal and capability snapshot authorizing publication.
    pub credential: PrincipalSnapshotId,
    /// The attempt deadline, in microseconds on the region's clock.
    pub deadline_micros: u64,
}

/// Commit evidence for a head compare-and-set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasWon {
    /// The store's winning version token.
    pub winning_version: AuthorityVersionToken,
}

/// Why a head compare-and-set published nothing.
///
/// A lost race is ordinary control flow, not an exception: the loser reuses
/// the same sealed request and may not leak candidate state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CasAbortReason {
    /// Another attempt replaced the expected predecessor first.
    LostRace {
        /// The version the store held instead.
        observed_version: AuthorityVersionToken,
    },
    /// The deadline passed before the store answered.
    DeadlineExpired,
    /// The store refused or failed the attempt.
    StoreFailure,
    /// The owning region was cancelled before the attempt reached the store.
    Cancelled,
}

/// Abort evidence for a head compare-and-set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasNotPublished {
    /// Why no head advanced.
    pub reason: CasAbortReason,
}

impl CasNotPublished {
    /// Whether the attempt lost a race rather than failing.
    #[must_use]
    pub const fn is_lost_race(&self) -> bool {
        matches!(self.reason, CasAbortReason::LostRace { .. })
    }
}

impl ObligationKind for HeadCasAttempt {
    const CLASS: ObligationClass = ObligationClass::HeadCasAttempt;
    const OBSERVATION: ObservationMode = ObservationMode::Internal;
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::CpuMicros];
    type Reservation = CasAttempt;
    type CommitReceipt = CasWon;
    type AbortReceipt = CasNotPublished;
    type AckEvidence = TrivialAck;
}

impl InternalEffect for HeadCasAttempt {}

// ---------------------------------------------------------------------------
// 7.4 OutboxEffectPermit
// ---------------------------------------------------------------------------

/// One external effect delivery.
///
/// Section 7.4 says commit "stores the exact downstream acknowledgement" while
/// section 6 makes acknowledgement the separate external-observation record and
/// names webhooks as staying committed until it arrives. This crate follows
/// section 6, which is the normative lifecycle: commit means the effect is
/// canonically owned and dispatched, and the downstream acknowledgement is the
/// acknowledgement evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboxEffectPermit;

/// What the reserve phase records for an outbox delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboxDispatch {
    /// The stable idempotency key that makes retry safe.
    pub idempotency: IdempotencyKey,
    /// The repository commit record this delivery is preconditioned on.
    pub precondition_rcr: RepositoryCommitId,
    /// The destination endpoint, named by the receiving system.
    pub endpoint: OpaqueHandle,
    /// What the downstream promises about duplicate suppression.
    pub idempotency_strength: DownstreamIdempotency,
}

/// Commit evidence for an outbox delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectDispatched {
    /// One-based attempt ordinal of the dispatch that was committed.
    pub attempt: u32,
}

/// Why a delivery was abandoned before dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DispatchAbortReason {
    /// The precondition change record was superseded.
    PreconditionSuperseded,
    /// The endpoint was withdrawn or deauthorized.
    EndpointWithdrawn,
    /// The owning region was cancelled before dispatch.
    Cancelled,
}

/// Abort evidence for an outbox delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchAbandoned {
    /// Why nothing was sent.
    pub reason: DispatchAbortReason,
}

/// Acknowledgement evidence for an outbox delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DownstreamAck {
    /// The exact receipt the downstream returned.
    pub receipt: OpaqueHandle,
    /// Which attempt the downstream acknowledged.
    pub attempt: u32,
}

impl ObligationKind for OutboxEffectPermit {
    const CLASS: ObligationClass = ObligationClass::OutboxEffectPermit;
    const OBSERVATION: ObservationMode = ObservationMode::ExternallyObserved;
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::EgressBytes];
    type Reservation = OutboxDispatch;
    type CommitReceipt = EffectDispatched;
    type AbortReceipt = DispatchAbandoned;
    type AckEvidence = DownstreamAck;
}

impl ExternallyObserved for OutboxEffectPermit {}

// ---------------------------------------------------------------------------
// 7.5 SecretLease
// ---------------------------------------------------------------------------

/// One secret made reachable to one consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretLease;

/// The class of secret being leased.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretClass {
    /// A credential that can move refs.
    RepositoryPush,
    /// A credential that can publish a package version.
    RegistryPublish,
    /// A signing key.
    SigningKey,
    /// A webhook signing secret.
    WebhookSigning,
    /// A runner join token.
    RunnerJoin,
}

/// What the reserve phase binds for a secret lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretGrant {
    /// What kind of secret is being made reachable.
    pub class: SecretClass,
    /// The authenticated principal that may use it.
    pub consumer: PrincipalId,
    /// The delivery channel handle that must be drained on revocation.
    pub delivery: OpaqueHandle,
    /// The single effect class this secret may be used for.
    pub allowed_effect: ObligationClass,
    /// Expiry, in microseconds on the region's clock.
    pub expires_micros: u64,
}

/// Commit evidence for a secret lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretDelivered {
    /// When the secret became reachable.
    pub delivered_micros: u64,
}

/// Why a secret was never delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretAbortReason {
    /// Authorization was withdrawn before delivery.
    AuthorizationWithdrawn,
    /// The lease expired before delivery.
    Expired,
    /// The owning region was cancelled.
    Cancelled,
}

/// Abort evidence for a secret lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretWithheld {
    /// Why the secret never became reachable.
    pub reason: SecretAbortReason,
}

/// Acknowledgement evidence for a secret lease.
///
/// Revocation is the external observation: the lease is not settled until
/// every channel that could still use the secret has been drained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretRevoked {
    /// When revocation completed.
    pub revoked_micros: u64,
    /// How many consumer channels were drained.
    pub drained_consumers: u32,
}

impl ObligationKind for SecretLease {
    const CLASS: ObligationClass = ObligationClass::SecretLease;
    const OBSERVATION: ObservationMode = ObservationMode::ExternallyObserved;
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::SecretExposureMicros];
    type Reservation = SecretGrant;
    type CommitReceipt = SecretDelivered;
    type AbortReceipt = SecretWithheld;
    type AckEvidence = SecretRevoked;
}

impl ExternallyObserved for SecretLease {}

// ---------------------------------------------------------------------------
// 7.6 WorkspaceLease
// ---------------------------------------------------------------------------

/// One workspace overlay and its outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkspaceLease;

/// How a workspace is materialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MaterializerProfile {
    /// A pure in-process tree view with a copy-on-write overlay.
    TreeViewOverlay,
    /// A sparse checkout materialized to a real directory.
    SparseCheckout,
    /// A filesystem mount backed by the tree view.
    MountedView,
}

/// What the reserve phase binds for a workspace lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkspaceRequest {
    /// The immutable workspace generation the overlay belongs to.
    pub overlay: GenerationId,
    /// The immutable base tree the overlay sits on.
    pub base_tree: GitOid,
    /// How the workspace is materialized.
    pub materializer: MaterializerProfile,
}

/// Commit evidence for a workspace lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkspacePublished {
    /// The final workspace snapshot generation.
    pub snapshot: GenerationId,
    /// The evidence record describing what the workspace produced.
    pub evidence: EvidenceRecordId,
}

/// Why a workspace produced no snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkspaceAbortReason {
    /// The owning region was cancelled.
    Cancelled,
    /// Materialization failed.
    MaterializationFailed,
    /// The workspace exceeded its budget.
    BudgetExhausted,
}

/// Abort evidence for a workspace lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkspaceTornDown {
    /// How many outputs were incomplete when teardown ran.
    pub incomplete_outputs: u32,
    /// Why the workspace was torn down.
    pub reason: WorkspaceAbortReason,
}

impl ObligationKind for WorkspaceLease {
    const CLASS: ObligationClass = ObligationClass::WorkspaceLease;
    const OBSERVATION: ObservationMode = ObservationMode::Internal;
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::MemoryBytes, Grade::FileDescriptors];
    type Reservation = WorkspaceRequest;
    type CommitReceipt = WorkspacePublished;
    type AbortReceipt = WorkspaceTornDown;
    type AckEvidence = TrivialAck;
}

impl InternalEffect for WorkspaceLease {}

// ---------------------------------------------------------------------------
// 7.7 RunnerSlot
// ---------------------------------------------------------------------------

/// One sandbox allocation for hostile compute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunnerSlot;

/// The isolation profile a runner executes under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SandboxProfile {
    /// A process sandbox with no network.
    ProcessIsolated,
    /// A virtual machine.
    VirtualMachine,
    /// An ephemeral container image.
    EphemeralImage,
}

/// The network policy a runner executes under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkPolicy {
    /// No egress at all.
    Denied,
    /// Egress only to an explicitly named allowlist.
    Allowlisted,
    /// Unrestricted egress; permitted only outside the truth plane.
    Unrestricted,
}

/// What the reserve phase binds for a runner slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunnerRequest {
    /// Isolation profile.
    pub sandbox: SandboxProfile,
    /// The pinned toolchain or image identity, named by the sandbox provider.
    pub toolchain: OpaqueHandle,
    /// Egress policy.
    pub network: NetworkPolicy,
    /// The cache namespace the job may read and write.
    pub cache_namespace: OpaqueHandle,
}

/// How a runner finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExitClass {
    /// The job succeeded.
    Succeeded,
    /// The job failed on its own terms.
    Failed,
    /// The job was cancelled.
    Cancelled,
    /// The job exceeded a resource ceiling.
    ResourceCeiling,
}

/// Commit evidence for a runner slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunnerFinished {
    /// How the job ended.
    pub exit_class: ExitClass,
    /// How many artifacts it published.
    pub artifacts: u32,
    /// The evidence record rooting the job's logs.
    pub log_root: EvidenceRecordId,
}

/// Why a runner never started.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RunnerAbortReason {
    /// No capacity was available inside the failure domain.
    NoCapacity,
    /// The toolchain or image could not be admitted.
    ToolchainUnavailable,
    /// The owning region was cancelled before start.
    Cancelled,
}

/// Abort evidence for a runner slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunnerNotStarted {
    /// Why no sandbox was allocated.
    pub reason: RunnerAbortReason,
}

/// Whether teardown was cooperative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContainmentClass {
    /// Every child stopped when asked.
    Cooperative,
    /// Something had to be contained by force and is named in the receipt.
    NonCooperative,
}

/// Acknowledgement evidence for a runner slot.
///
/// Cancellation does not return until this exists: the external observation
/// for a runner is that its children were reaped or explicitly contained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunnerReaped {
    /// How many processes were reaped.
    pub processes_reaped: u32,
    /// Whether force was required.
    pub containment: ContainmentClass,
}

impl ObligationKind for RunnerSlot {
    const CLASS: ObligationClass = ObligationClass::RunnerSlot;
    const OBSERVATION: ObservationMode = ObservationMode::ExternallyObserved;
    const REQUIRED_GRADES: &'static [Grade] = &[
        Grade::CpuMicros,
        Grade::MemoryBytes,
        Grade::FileDescriptors,
        Grade::FailureDomainSlots,
    ];
    type Reservation = RunnerRequest;
    type CommitReceipt = RunnerFinished;
    type AbortReceipt = RunnerNotStarted;
    type AckEvidence = RunnerReaped;
}

impl ExternallyObserved for RunnerSlot {}

// ---------------------------------------------------------------------------
// 7.8 RetentionPin
// ---------------------------------------------------------------------------

/// One retention hold protecting canonical objects.
///
/// The obligation covers *establishing* the pin. Releasing one is a separate
/// coordinated operation on the authority head, because absence enables
/// deletion; nothing here can release a pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPin;

/// Why canonical objects must survive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetentionCause {
    /// An open pull request references them.
    OpenPullRequest,
    /// A merge queue entry references them.
    MergeQueue,
    /// A migration is in flight.
    Migration,
    /// A backup is in flight.
    Backup,
    /// A legal hold applies.
    LegalHold,
    /// A sealed transaction is still active.
    ActiveSeal,
    /// A restore is in flight.
    Restore,
}

/// What the reserve phase binds for a retention pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionRequest {
    /// The object envelope whose closure must survive.
    pub root: ObjectEnvelopeId,
    /// Why it must survive.
    pub cause: RetentionCause,
}

/// Commit evidence for a retention pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionHeld {
    /// The authenticated head the pin was established against.
    pub basis_head: RepositoryAuthorityHeadId,
}

/// Why a retention pin was not established.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetentionAbortReason {
    /// The cause disappeared before the pin was published.
    CauseWithdrawn,
    /// The authority head moved and the basis is stale.
    BasisStale,
    /// The owning region was cancelled.
    Cancelled,
}

/// Abort evidence for a retention pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionNotTaken {
    /// Why nothing was pinned.
    pub reason: RetentionAbortReason,
}

impl ObligationKind for RetentionPin {
    const CLASS: ObligationClass = ObligationClass::RetentionPin;
    const OBSERVATION: ObservationMode = ObservationMode::Internal;
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::Objects];
    type Reservation = RetentionRequest;
    type CommitReceipt = RetentionHeld;
    type AbortReceipt = RetentionNotTaken;
    type AckEvidence = TrivialAck;
}

impl InternalEffect for RetentionPin {}

// ---------------------------------------------------------------------------
// 7.9 RepairPermit
// ---------------------------------------------------------------------------

/// One repair decode, verification, and placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairPermit;

/// What the reserve phase binds for a repair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairRequest {
    /// The segment manifest being repaired.
    pub target: SegmentManifestId,
    /// How many symbols the decode budget allows.
    pub decode_budget_symbols: u32,
    /// How many source symbols were available at reserve time.
    pub source_symbols: u32,
}

/// Whether the decoder produced candidate bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DecodeOutcome {
    /// The decoder produced candidate bytes.
    Succeeded,
    /// The decoder could not reconstruct the target.
    Failed,
}

/// Whether the candidate matched every original commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommitmentCheck {
    /// Identity, digest, length, and structure all matched.
    AllVerified,
    /// At least one commitment did not match.
    Mismatch,
    /// Verification did not run.
    NotChecked,
}

/// Whether current authority still wants the repaired placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityRevalidation {
    /// The basis is still current and retention still applies.
    StillCurrent,
    /// The authority head moved.
    HeadMoved,
    /// Retention expired; the data must not be resurrected.
    RetentionExpired,
}

/// Refusal from [`RepairPublished::verified`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairRefusal {
    /// The decoder did not succeed.
    DecodeIncomplete(DecodeOutcome),
    /// The candidate failed at least one original commitment.
    CommitmentsUnverified(CommitmentCheck),
    /// Current authority no longer wants this placement.
    AuthorityRejected(AuthorityRevalidation),
}

impl fmt::Display for RepairRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::DecodeIncomplete(outcome) => write!(f, "repair decode outcome is {outcome:?}"),
            Self::CommitmentsUnverified(check) => {
                write!(f, "repair commitment check is {check:?}")
            }
            Self::AuthorityRejected(state) => write!(f, "repair authority basis is {state:?}"),
        }
    }
}

impl std::error::Error for RepairRefusal {}

/// Commit evidence for a repair.
///
/// Constructible only through [`RepairPublished::verified`], which requires
/// decode success *and* full commitment verification *and* a revalidated
/// authority basis. Decoder success alone cannot commit the permit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairPublished {
    placement: SegmentManifestId,
    authority_basis: RepositoryAuthorityHeadId,
}

impl RepairPublished {
    /// Builds commit evidence, refusing every incomplete repair.
    pub fn verified(
        decode: DecodeOutcome,
        commitments: CommitmentCheck,
        authority: AuthorityRevalidation,
        placement: SegmentManifestId,
        authority_basis: RepositoryAuthorityHeadId,
    ) -> Result<Self, RepairRefusal> {
        if decode != DecodeOutcome::Succeeded {
            return Err(RepairRefusal::DecodeIncomplete(decode));
        }
        if commitments != CommitmentCheck::AllVerified {
            return Err(RepairRefusal::CommitmentsUnverified(commitments));
        }
        if authority != AuthorityRevalidation::StillCurrent {
            return Err(RepairRefusal::AuthorityRejected(authority));
        }
        Ok(Self {
            placement,
            authority_basis,
        })
    }

    /// The published placement.
    #[must_use]
    pub const fn placement(&self) -> SegmentManifestId {
        self.placement
    }

    /// The revalidated authority basis.
    #[must_use]
    pub const fn authority_basis(&self) -> RepositoryAuthorityHeadId {
        self.authority_basis
    }
}

/// Why a repair published nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RepairAbortReason {
    /// The decoder could not reconstruct the target.
    DecodeFailed,
    /// The repaired placement write or its flush failed.
    ///
    /// The candidate may have verified completely; nothing was published.
    PlacementWriteFailed,
    /// The candidate failed an original commitment.
    CommitmentMismatch,
    /// The authority head moved during repair.
    AuthorityMoved,
    /// Retention expired; the data must stay deleted.
    RetentionExpired,
    /// The owning region was cancelled.
    Cancelled,
}

/// Abort evidence for a repair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairNotPublished {
    /// Why quarantine was discarded instead of published.
    pub reason: RepairAbortReason,
}

impl ObligationKind for RepairPermit {
    const CLASS: ObligationClass = ObligationClass::RepairPermit;
    const OBSERVATION: ObservationMode = ObservationMode::Internal;
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::Bytes, Grade::CpuMicros];
    type Reservation = RepairRequest;
    type CommitReceipt = RepairPublished;
    type AbortReceipt = RepairNotPublished;
    type AckEvidence = TrivialAck;
}

impl InternalEffect for RepairPermit {}

// ---------------------------------------------------------------------------
// 7.10 ContextBudgetPermit
// ---------------------------------------------------------------------------

/// One context packet's budget and authorization scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextBudgetPermit;

/// What the reserve phase binds for a context packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextRequest {
    /// The packet identity, owned by the agent layer that assembles packets.
    pub packet: OpaqueHandle,
    /// The principal and capability snapshot every candidate was filtered
    /// through before any text, embedding, or neighbour was disclosed.
    pub authorization_scope: PrincipalSnapshotId,
    /// The token ceiling the packet may not exceed.
    pub token_ceiling: u64,
}

/// Refusal from [`ContextPacketComplete::complete`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextRefusal {
    /// Inclusions plus omissions did not account for every candidate.
    AccountingIncomplete {
        /// Candidates considered.
        considered: u32,
        /// Candidates included.
        included: u32,
        /// Candidates omitted with a recorded reason.
        omitted: u32,
    },
    /// No candidate was considered, so there is nothing to call complete.
    NothingConsidered,
}

impl fmt::Display for ContextRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::AccountingIncomplete {
                considered,
                included,
                omitted,
            } => write!(
                f,
                "context accounting incomplete: {included} included plus {omitted} omitted does not cover {considered} considered"
            ),
            Self::NothingConsidered => f.write_str("context packet considered no candidate"),
        }
    }
}

impl std::error::Error for ContextRefusal {}

/// Commit evidence for a context packet.
///
/// Constructible only through [`ContextPacketComplete::complete`], so a packet
/// cannot be committed unless every candidate it considered is either included
/// or omitted with a recorded reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextPacketComplete {
    considered: u32,
    included: u32,
    omitted: u32,
}

impl ContextPacketComplete {
    /// Builds commit evidence, refusing partial accounting.
    pub fn complete(considered: u32, included: u32, omitted: u32) -> Result<Self, ContextRefusal> {
        if considered == 0 {
            return Err(ContextRefusal::NothingConsidered);
        }
        if included.checked_add(omitted) != Some(considered) {
            return Err(ContextRefusal::AccountingIncomplete {
                considered,
                included,
                omitted,
            });
        }
        Ok(Self {
            considered,
            included,
            omitted,
        })
    }

    /// Candidates considered.
    #[must_use]
    pub const fn considered(&self) -> u32 {
        self.considered
    }

    /// Candidates included.
    #[must_use]
    pub const fn included(&self) -> u32 {
        self.included
    }

    /// Candidates omitted with a recorded reason.
    #[must_use]
    pub const fn omitted(&self) -> u32 {
        self.omitted
    }
}

/// Why a context packet was abandoned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContextAbortReason {
    /// The token or search budget ran out.
    BudgetExhausted,
    /// The authorization scope changed mid-assembly.
    ScopeChanged,
    /// The owning region was cancelled.
    Cancelled,
}

/// Abort evidence for a context packet.
///
/// This type deliberately has no conversion into [`ContextPacketComplete`].
/// Partial evidence is preserved for diagnosis and can never be presented as a
/// complete packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialContextEvidence {
    /// Candidates considered before abandoning.
    pub considered: u32,
    /// Candidates included before abandoning.
    pub included: u32,
    /// Candidates omitted before abandoning.
    pub omitted: u32,
    /// Why assembly stopped.
    pub reason: ContextAbortReason,
}

impl ObligationKind for ContextBudgetPermit {
    const CLASS: ObligationClass = ObligationClass::ContextBudgetPermit;
    const OBSERVATION: ObservationMode = ObservationMode::Internal;
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::Bytes, Grade::CpuMicros];
    type Reservation = ContextRequest;
    type CommitReceipt = ContextPacketComplete;
    type AbortReceipt = PartialContextEvidence;
    type AckEvidence = TrivialAck;
}

impl InternalEffect for ContextBudgetPermit {}

// ---------------------------------------------------------------------------
// 7.11 BillingReservation
// ---------------------------------------------------------------------------

/// One bounded charge against an external account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BillingReservation;

/// How the reservation ceiling was sized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EstimateBasis {
    /// Derived from deterministic receipts.
    Deterministic,
    /// Derived from a statistical forecast.
    Statistical,
}

/// What the reserve phase binds for a charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChargeReservation {
    /// The tenant account to be charged.
    pub account: TenantId,
    /// The maximum that may be charged, in millionths of the accounting unit.
    pub ceiling_micros: u64,
    /// How the ceiling was sized.
    pub estimate_basis: EstimateBasis,
}

/// Refusal from [`ChargeBound::within`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChargeAboveCeiling {
    /// The reserved ceiling.
    pub ceiling_micros: u64,
    /// The amount the caller tried to bind.
    pub actual_micros: u64,
}

impl fmt::Display for ChargeAboveCeiling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "charge of {} exceeds reserved ceiling of {}; an estimate may size a reservation but may not bill past it",
            self.actual_micros, self.ceiling_micros
        )
    }
}

impl std::error::Error for ChargeAboveCeiling {}

/// Commit evidence for a charge.
///
/// Constructible only through [`ChargeBound::within`], so a statistical
/// estimate can size a reservation but can never silently bill beyond it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChargeBound {
    actual_micros: u64,
}

impl ChargeBound {
    /// Binds actual usage, refusing anything above the reserved ceiling.
    pub const fn within(
        reservation: &ChargeReservation,
        actual_micros: u64,
    ) -> Result<Self, ChargeAboveCeiling> {
        if actual_micros > reservation.ceiling_micros {
            return Err(ChargeAboveCeiling {
                ceiling_micros: reservation.ceiling_micros,
                actual_micros,
            });
        }
        Ok(Self { actual_micros })
    }

    /// The bound charge.
    #[must_use]
    pub const fn actual_micros(&self) -> u64 {
        self.actual_micros
    }
}

/// Abort evidence for a charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChargeReleased {
    /// The amount released back to the account, in millionths.
    pub released_micros: u64,
}

/// Acknowledgement evidence for a charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChargeSettled {
    /// The payment processor's own receipt for the settled charge.
    pub processor_receipt: OpaqueHandle,
}

impl ObligationKind for BillingReservation {
    const CLASS: ObligationClass = ObligationClass::BillingReservation;
    const OBSERVATION: ObservationMode = ObservationMode::ExternallyObserved;
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::MoneyMicros];
    type Reservation = ChargeReservation;
    type CommitReceipt = ChargeBound;
    type AbortReceipt = ChargeReleased;
    type AckEvidence = ChargeSettled;
}

impl ExternallyObserved for BillingReservation {}
