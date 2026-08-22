//! Per-class evidence for the eleven concrete obligations.
//!
//! Two things are checked for every class: that its declared required grades
//! are actually enforced at reserve time, and that its four phases carry the
//! payloads section 7 of the obligations document specifies. Where that
//! section states a commit precondition, the checked receipt constructor is
//! exercised with the forbidden case and with the near-identical permitted case
//! that proceeds.

use fgit_resource::algebra::{Grade, ResourceVector};
use fgit_resource::custody::{
    LeakDisposition, ObligationLedger, ObligationState, RegionCloseOutcome, ReserveError,
};
use fgit_resource::ids::{IdempotencyKey, IdentityError, OpaqueHandle, RegionId};
use fgit_resource::kinds::{
    AdmissionAbandoned, AdmissionAbortReason, AdmissionRefusal, AdmittedObject,
    AuthorityRevalidation, BillingReservation, CasAbortReason, CasAttempt, CasNotPublished, CasWon,
    ChargeAboveCeiling, ChargeBound, ChargeReleased, ChargeReservation, ChargeSettled,
    CommitmentCheck, ContainmentClass, ContextAbortReason, ContextBudgetPermit,
    ContextPacketComplete, ContextRefusal, ContextRequest, DecodeOutcome, DispatchAbandoned,
    DispatchAbortReason, DownstreamAck, EffectDispatched, EstimateBasis, ExitClass, HeadCasAttempt,
    LaneSlot, MaterializerProfile, NetworkPolicy, NoCandidateReason, ObjectAdmission,
    ObjectAdmissionPermit, ObjectClass, OutboxDispatch, OutboxEffectPermit, PartialContextEvidence,
    PreparedTxnSlot, RepairAbortReason, RepairNotPublished, RepairPermit, RepairPublished,
    RepairRefusal, RepairRequest, RetentionAbortReason, RetentionCause, RetentionHeld,
    RetentionNotTaken, RetentionPin, RetentionRequest, RunnerAbortReason, RunnerFinished,
    RunnerNotStarted, RunnerReaped, RunnerRequest, RunnerSlot, SandboxProfile, SecretAbortReason,
    SecretClass, SecretDelivered, SecretGrant, SecretLease, SecretRevoked, SecretWithheld,
    SlotAbandoned, SlotHandedOff, StructureVerdict, WorkspaceAbortReason, WorkspaceLease,
    WorkspacePublished, WorkspaceRequest, WorkspaceTornDown,
};
use fgit_resource::settlement::DownstreamIdempotency;
use fgit_resource::twophase::{
    ExternallyObserved, InternalEffect, ObligationClass, ObligationKind, TerminalEvidence,
    TrivialAck,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, EvidenceRecordId,
    GenerationId, GitOid, GitOidSha1, OPAQUE_ID_LEN, ObjectEnvelopeId, OpaqueStoreToken,
    PrincipalId, PrincipalSnapshotId, RepositoryAuthorityHeadId, RepositoryCommitId,
    RepositoryDecisionBatchId, SegmentManifestId, TenantId, TxId,
};

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("code point one is a valid algorithm slot"),
        DigestBytes::try_new(&[tag; 20]).expect("20-byte SHA-1 digest body is valid"),
    )
}

fn envelope(tag: u8) -> ObjectEnvelopeId {
    ObjectEnvelopeId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 20]).expect("valid digest body"),
    )
}

fn head(tag: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 20]).expect("valid digest body"),
    )
}

fn batch(tag: u8) -> RepositoryDecisionBatchId {
    RepositoryDecisionBatchId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 20]).expect("valid digest body"),
    )
}

fn rcr(tag: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 20]).expect("valid digest body"),
    )
}

fn txid(tag: u8) -> TxId {
    TxId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 20]).expect("valid digest body"),
    )
}

fn principal_snapshot(tag: u8) -> PrincipalSnapshotId {
    PrincipalSnapshotId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 20]).expect("valid digest body"),
    )
}

fn generation(tag: u8) -> GenerationId {
    GenerationId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 20]).expect("valid digest body"),
    )
}

fn evidence_record(tag: u8) -> EvidenceRecordId {
    EvidenceRecordId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 20]).expect("valid digest body"),
    )
}

fn segment(tag: u8) -> SegmentManifestId {
    SegmentManifestId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 20]).expect("valid digest body"),
    )
}

const fn principal(tag: u8) -> PrincipalId {
    PrincipalId::from_bytes([tag; OPAQUE_ID_LEN])
}

const fn tenant(tag: u8) -> TenantId {
    TenantId::from_bytes([tag; OPAQUE_ID_LEN])
}

const fn oid(tag: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([tag; GitOidSha1::LEN]))
}

fn token(tag: u8) -> OpaqueStoreToken {
    OpaqueStoreToken::try_new(&[tag; 16]).expect("sixteen bytes is a valid version token")
}

fn opaque(tag: u8) -> OpaqueHandle {
    OpaqueHandle::new(&[tag; 20]).expect("twenty bytes is a valid opaque handle")
}

/// One unit of every grade the class requires, and nothing else.
fn minimal_budget<K: ObligationKind>() -> ResourceVector {
    let pairs: Vec<(Grade, u64)> = K::REQUIRED_GRADES
        .iter()
        .copied()
        .map(|grade| (grade, 1))
        .collect();
    ResourceVector::from_grades(&pairs)
}

/// The same budget with one required grade zeroed out.
fn budget_missing<K: ObligationKind>(missing: Grade) -> ResourceVector {
    minimal_budget::<K>().with(missing, 0)
}

/// Proves that every grade a class declares required is enforced, then settles
/// the permitted twin so the region still reaches quiescence.
fn required_grades_are_load_bearing<K>(
    region: u64,
    reservation: K::Reservation,
    abort: K::AbortReceipt,
) where
    K: ObligationKind,
    K::Reservation: Clone,
    K::AbortReceipt: Clone,
{
    assert!(
        !K::REQUIRED_GRADES.is_empty(),
        "{} must declare at least one required grade",
        K::CLASS
    );
    let capacity = minimal_budget::<K>();
    let ledger = ObligationLedger::root(
        RegionId::new(region),
        LeakDisposition::RecordAndContinue,
        capacity,
    );

    for missing in K::REQUIRED_GRADES.iter().copied() {
        let grant = ledger
            .grant(budget_missing::<K>(missing))
            .expect("a subset of capacity is always grantable");
        let error = ledger
            .reserve::<K>(reservation.clone(), grant)
            .err()
            .unwrap_or_else(|| panic!("{} must refuse a reservation with no {missing}", K::CLASS));
        assert_eq!(
            error,
            ReserveError::MissingGrade {
                class: K::CLASS,
                grade: missing,
            },
            "{} must name the missing grade",
            K::CLASS
        );
        assert_eq!(
            ledger.snapshot().available(),
            capacity,
            "{} must return the grant it refused",
            K::CLASS
        );
    }

    // Near-identical permitted case: the full required set proceeds.
    let grant = ledger.grant(capacity).expect("capacity is grantable");
    let obligation = ledger
        .reserve::<K>(reservation, grant)
        .unwrap_or_else(|error| panic!("{} must accept its required grades: {error}", K::CLASS));
    assert_eq!(obligation.class(), K::CLASS);
    let settled = obligation.abort_unused(abort);
    assert_eq!(settled.state(), ObligationState::Aborted);
    assert!(ledger.leaks().is_empty(), "{} leaked nothing", K::CLASS);
    let outcome = ledger.close();
    assert!(outcome.is_quiescent(), "{}: {outcome:?}", K::CLASS);
}

/// Runs an internal class through the trivial-acknowledgement path.
fn internal_round_trip<K>(region: u64, reservation: K::Reservation, receipt: K::CommitReceipt)
where
    K: InternalEffect,
{
    let capacity = minimal_budget::<K>();
    let ledger = ObligationLedger::root(
        RegionId::new(region),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    let grant = ledger.grant(capacity).expect("capacity is grantable");
    let obligation = ledger
        .reserve::<K>(reservation, grant)
        .unwrap_or_else(|error| panic!("{} reserve: {error}", K::CLASS));
    let settled = obligation
        .commit_internal(receipt, &capacity)
        .unwrap_or_else(|error| panic!("{} commit: {error}", K::CLASS));
    assert_eq!(
        settled.state(),
        ObligationState::Acknowledged,
        "{} settles at commit with no acknowledgement ceremony",
        K::CLASS
    );
    let outcome = ledger.close();
    assert!(outcome.is_quiescent(), "{}: {outcome:?}", K::CLASS);
}

/// Runs an externally observed class through commit and acknowledgement.
fn external_round_trip<K>(
    region: u64,
    reservation: K::Reservation,
    receipt: K::CommitReceipt,
    evidence: K::AckEvidence,
) where
    K: ExternallyObserved,
{
    let capacity = minimal_budget::<K>();
    let ledger = ObligationLedger::root(
        RegionId::new(region),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    let handle = ledger.handle();
    let grant = ledger.grant(capacity).expect("capacity is grantable");
    let obligation = ledger
        .reserve::<K>(reservation, grant)
        .unwrap_or_else(|error| panic!("{} reserve: {error}", K::CLASS));
    let id = obligation.id();
    let committed = obligation
        .commit(receipt, &capacity)
        .unwrap_or_else(|error| panic!("{} commit: {error}", K::CLASS));
    assert_eq!(
        handle.state_of(id),
        Some(ObligationState::Committed),
        "{} stays committed until its recipient is observed",
        K::CLASS
    );
    let settled = committed.acknowledge(evidence);
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    let outcome = ledger.close();
    assert!(outcome.is_quiescent(), "{}: {outcome:?}", K::CLASS);
}

// ---------------------------------------------------------------------------
// Required grades, for all eleven classes
// ---------------------------------------------------------------------------

#[test]
fn every_class_enforces_its_required_grades() {
    required_grades_are_load_bearing::<ObjectAdmissionPermit>(
        101,
        ObjectAdmission {
            class: ObjectClass::GitObject,
            declared_len: 1,
            staging: envelope(1),
        },
        AdmissionAbandoned {
            reason: AdmissionAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<PreparedTxnSlot>(
        102,
        LaneSlot {
            lane: 3,
            transaction: txid(2),
        },
        SlotAbandoned {
            reason: NoCandidateReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<HeadCasAttempt>(
        103,
        CasAttempt {
            expected_version: token(3),
            candidate_head: head(4),
            decision_batch: batch(5),
            credential: principal_snapshot(6),
            deadline_micros: 10_000,
        },
        CasNotPublished {
            reason: CasAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<OutboxEffectPermit>(
        104,
        OutboxDispatch {
            idempotency: IdempotencyKey::new(digest(7)),
            precondition_rcr: rcr(8),
            endpoint: opaque(9),
            idempotency_strength: DownstreamIdempotency::Weak,
        },
        DispatchAbandoned {
            reason: DispatchAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<SecretLease>(
        105,
        SecretGrant {
            class: SecretClass::SigningKey,
            consumer: principal(10),
            delivery: opaque(11),
            allowed_effect: ObligationClass::OutboxEffectPermit,
            expires_micros: 60_000,
        },
        SecretWithheld {
            reason: SecretAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<WorkspaceLease>(
        106,
        WorkspaceRequest {
            overlay: generation(12),
            base_tree: oid(13),
            materializer: MaterializerProfile::TreeViewOverlay,
        },
        WorkspaceTornDown {
            incomplete_outputs: 0,
            reason: WorkspaceAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<RunnerSlot>(
        107,
        RunnerRequest {
            sandbox: SandboxProfile::ProcessIsolated,
            toolchain: opaque(14),
            network: NetworkPolicy::Denied,
            cache_namespace: opaque(15),
        },
        RunnerNotStarted {
            reason: RunnerAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<RetentionPin>(
        108,
        RetentionRequest {
            root: envelope(16),
            cause: RetentionCause::LegalHold,
        },
        RetentionNotTaken {
            reason: RetentionAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<RepairPermit>(
        109,
        RepairRequest {
            target: segment(17),
            decode_budget_symbols: 64,
            source_symbols: 32,
        },
        RepairNotPublished {
            reason: RepairAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<ContextBudgetPermit>(
        110,
        ContextRequest {
            packet: opaque(18),
            authorization_scope: principal_snapshot(19),
            token_ceiling: 4_096,
        },
        PartialContextEvidence {
            considered: 5,
            included: 2,
            omitted: 1,
            reason: ContextAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<BillingReservation>(
        111,
        ChargeReservation {
            account: tenant(20),
            ceiling_micros: 5_000,
            estimate_basis: EstimateBasis::Statistical,
        },
        ChargeReleased {
            released_micros: 5_000,
        },
    );
}

// ---------------------------------------------------------------------------
// Internal classes: trivial acknowledgement at commit
// ---------------------------------------------------------------------------

#[test]
fn internal_classes_settle_at_commit() {
    let admission = ObjectAdmission {
        class: ObjectClass::Segment,
        declared_len: 1,
        staging: envelope(21),
    };
    internal_round_trip::<ObjectAdmissionPermit>(
        201,
        admission,
        AdmittedObject::verified(
            &admission,
            oid(22),
            digest(23),
            1,
            StructureVerdict::Verified,
        )
        .expect("verified evidence"),
    );

    internal_round_trip::<PreparedTxnSlot>(
        202,
        LaneSlot {
            lane: 0,
            transaction: txid(24),
        },
        SlotHandedOff {
            batch_attempt: batch(25),
        },
    );

    internal_round_trip::<HeadCasAttempt>(
        203,
        CasAttempt {
            expected_version: token(26),
            candidate_head: head(27),
            decision_batch: batch(28),
            credential: principal_snapshot(29),
            deadline_micros: 1_000,
        },
        CasWon {
            winning_version: token(30),
        },
    );

    internal_round_trip::<WorkspaceLease>(
        204,
        WorkspaceRequest {
            overlay: generation(31),
            base_tree: oid(32),
            materializer: MaterializerProfile::SparseCheckout,
        },
        WorkspacePublished {
            snapshot: generation(33),
            evidence: evidence_record(34),
        },
    );

    internal_round_trip::<RetentionPin>(
        205,
        RetentionRequest {
            root: envelope(35),
            cause: RetentionCause::OpenPullRequest,
        },
        RetentionHeld {
            basis_head: head(36),
        },
    );

    internal_round_trip::<RepairPermit>(
        206,
        RepairRequest {
            target: segment(37),
            decode_budget_symbols: 8,
            source_symbols: 8,
        },
        RepairPublished::verified(
            DecodeOutcome::Succeeded,
            CommitmentCheck::AllVerified,
            AuthorityRevalidation::StillCurrent,
            segment(38),
            head(39),
        )
        .expect("a fully verified repair"),
    );

    internal_round_trip::<ContextBudgetPermit>(
        207,
        ContextRequest {
            packet: opaque(40),
            authorization_scope: principal_snapshot(41),
            token_ceiling: 512,
        },
        ContextPacketComplete::complete(9, 4, 5).expect("complete accounting"),
    );
}

// ---------------------------------------------------------------------------
// Externally observed classes: committed until observed
// ---------------------------------------------------------------------------

#[test]
fn externally_observed_classes_need_acknowledgement_evidence() {
    external_round_trip::<OutboxEffectPermit>(
        301,
        OutboxDispatch {
            idempotency: IdempotencyKey::new(digest(42)),
            precondition_rcr: rcr(43),
            endpoint: opaque(44),
            idempotency_strength: DownstreamIdempotency::Strong,
        },
        EffectDispatched { attempt: 1 },
        DownstreamAck {
            receipt: opaque(45),
            attempt: 1,
        },
    );

    external_round_trip::<SecretLease>(
        302,
        SecretGrant {
            class: SecretClass::RunnerJoin,
            consumer: principal(46),
            delivery: opaque(47),
            allowed_effect: ObligationClass::RunnerSlot,
            expires_micros: 30_000,
        },
        SecretDelivered {
            delivered_micros: 10,
        },
        SecretRevoked {
            revoked_micros: 20_000,
            drained_consumers: 1,
        },
    );

    external_round_trip::<RunnerSlot>(
        303,
        RunnerRequest {
            sandbox: SandboxProfile::VirtualMachine,
            toolchain: opaque(48),
            network: NetworkPolicy::Allowlisted,
            cache_namespace: opaque(49),
        },
        RunnerFinished {
            exit_class: ExitClass::Succeeded,
            artifacts: 2,
            log_root: evidence_record(50),
        },
        RunnerReaped {
            processes_reaped: 3,
            containment: ContainmentClass::Cooperative,
        },
    );

    external_round_trip::<BillingReservation>(
        304,
        ChargeReservation {
            account: tenant(51),
            ceiling_micros: 900,
            estimate_basis: EstimateBasis::Deterministic,
        },
        ChargeBound::within(
            &ChargeReservation {
                account: tenant(51),
                ceiling_micros: 900,
                estimate_basis: EstimateBasis::Deterministic,
            },
            900,
        )
        .expect("a charge at its ceiling"),
        ChargeSettled {
            processor_receipt: opaque(52),
        },
    );
}

// ---------------------------------------------------------------------------
// Checked commit receipts: forbidden case and permitted twin
// ---------------------------------------------------------------------------

#[test]
fn an_admission_cannot_commit_without_full_verification() {
    let reservation = ObjectAdmission {
        class: ObjectClass::GitObject,
        declared_len: 64,
        staging: envelope(60),
    };

    assert_eq!(
        AdmittedObject::verified(
            &reservation,
            oid(61),
            digest(62),
            64,
            StructureVerdict::NotValidated,
        ),
        Err(AdmissionRefusal::StructureNotVerified(
            StructureVerdict::NotValidated
        )),
        "an unvalidated structure cannot produce commit evidence"
    );
    assert_eq!(
        AdmittedObject::verified(
            &reservation,
            oid(61),
            digest(62),
            63,
            StructureVerdict::Verified,
        ),
        Err(AdmissionRefusal::LengthMismatch {
            declared: 64,
            verified: 63,
        }),
        "a length that disagrees with the declaration cannot commit"
    );

    // Near-identical permitted case: verified structure at the declared length.
    let receipt = AdmittedObject::verified(
        &reservation,
        oid(61),
        digest(62),
        64,
        StructureVerdict::Verified,
    )
    .expect("full verification produces commit evidence");
    assert_eq!(receipt.verified_len(), 64);
    assert_eq!(receipt.native_oid(), oid(61));
    assert_eq!(receipt.strong_digest(), digest(62));
}

#[test]
fn decoder_success_alone_cannot_commit_a_repair() {
    assert_eq!(
        RepairPublished::verified(
            DecodeOutcome::Succeeded,
            CommitmentCheck::NotChecked,
            AuthorityRevalidation::StillCurrent,
            segment(70),
            head(71),
        ),
        Err(RepairRefusal::CommitmentsUnverified(
            CommitmentCheck::NotChecked
        )),
        "a decoded candidate must still meet every original commitment"
    );
    assert_eq!(
        RepairPublished::verified(
            DecodeOutcome::Succeeded,
            CommitmentCheck::AllVerified,
            AuthorityRevalidation::HeadMoved,
            segment(70),
            head(71),
        ),
        Err(RepairRefusal::AuthorityRejected(
            AuthorityRevalidation::HeadMoved
        )),
        "a repair prepared against a stale basis cannot publish"
    );
    assert_eq!(
        RepairPublished::verified(
            DecodeOutcome::Succeeded,
            CommitmentCheck::AllVerified,
            AuthorityRevalidation::RetentionExpired,
            segment(70),
            head(71),
        ),
        Err(RepairRefusal::AuthorityRejected(
            AuthorityRevalidation::RetentionExpired
        )),
        "expired retention must not be resurrected by a repair"
    );
    assert_eq!(
        RepairPublished::verified(
            DecodeOutcome::Failed,
            CommitmentCheck::AllVerified,
            AuthorityRevalidation::StillCurrent,
            segment(70),
            head(71),
        ),
        Err(RepairRefusal::DecodeIncomplete(DecodeOutcome::Failed)),
        "a failed decode cannot commit"
    );

    // Near-identical permitted case: all three preconditions hold.
    let receipt = RepairPublished::verified(
        DecodeOutcome::Succeeded,
        CommitmentCheck::AllVerified,
        AuthorityRevalidation::StillCurrent,
        segment(70),
        head(71),
    )
    .expect("a fully verified repair commits");
    assert_eq!(receipt.placement(), segment(70));
    assert_eq!(receipt.authority_basis(), head(71));
}

#[test]
fn a_context_packet_cannot_commit_with_partial_accounting() {
    assert_eq!(
        ContextPacketComplete::complete(10, 4, 5),
        Err(ContextRefusal::AccountingIncomplete {
            considered: 10,
            included: 4,
            omitted: 5,
        }),
        "one unaccounted candidate blocks the complete packet"
    );
    assert_eq!(
        ContextPacketComplete::complete(0, 0, 0),
        Err(ContextRefusal::NothingConsidered),
        "an empty packet is not a complete packet"
    );

    // Near-identical permitted case: the tenth candidate is accounted for.
    let receipt = ContextPacketComplete::complete(10, 4, 6).expect("complete accounting commits");
    assert_eq!(receipt.considered(), 10);
    assert_eq!(receipt.included(), 4);
    assert_eq!(receipt.omitted(), 6);

    // Abort evidence exists but is a different type with no path to a packet.
    let partial = PartialContextEvidence {
        considered: 10,
        included: 4,
        omitted: 5,
        reason: ContextAbortReason::BudgetExhausted,
    };
    assert_eq!(partial.included + partial.omitted, 9);
    assert_eq!(partial.reason, ContextAbortReason::BudgetExhausted);
}

#[test]
fn a_statistical_estimate_cannot_bill_past_its_ceiling() {
    let reservation = ChargeReservation {
        account: tenant(80),
        ceiling_micros: 1_000,
        estimate_basis: EstimateBasis::Statistical,
    };
    assert_eq!(
        ChargeBound::within(&reservation, 1_001),
        Err(ChargeAboveCeiling {
            ceiling_micros: 1_000,
            actual_micros: 1_001,
        }),
        "one microunit above the reservation is refused"
    );

    // Near-identical permitted case: exactly the ceiling.
    let bound = ChargeBound::within(&reservation, 1_000).expect("a charge at the ceiling commits");
    assert_eq!(bound.actual_micros(), 1_000);
    let under = ChargeBound::within(&reservation, 1).expect("a charge below the ceiling commits");
    assert_eq!(under.actual_micros(), 1);
}

#[test]
fn a_lost_head_cas_race_is_ordinary_control_flow() {
    let capacity = minimal_budget::<HeadCasAttempt>();
    let ledger = ObligationLedger::root(
        RegionId::new(90),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    let grant = ledger.grant(capacity).expect("capacity is grantable");
    let obligation = ledger
        .reserve::<HeadCasAttempt>(
            CasAttempt {
                expected_version: token(91),
                candidate_head: head(92),
                decision_batch: batch(93),
                credential: principal_snapshot(94),
                deadline_micros: 500,
            },
            grant,
        )
        .expect("processor time is the required grade");

    let lost = CasNotPublished {
        reason: CasAbortReason::LostRace {
            observed_version: token(95),
        },
    };
    assert!(lost.is_lost_race(), "a lost race is recognizable as such");

    // Losing charges the processor time actually burned and releases the rest.
    let spent = ResourceVector::single(Grade::CpuMicros, 1);
    let settled = obligation
        .abort(lost, &spent)
        .expect("a loser settles its reservation rather than leaking it");
    assert_eq!(settled.state(), ObligationState::Aborted);
    let snapshot = ledger.snapshot();
    assert!(snapshot.is_conserved());
    assert_eq!(
        snapshot.consumed().get(Grade::CpuMicros),
        1,
        "the loser's processor time is charged, not refunded"
    );
    let outcome = ledger.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");

    // Near-identical permitted case: the same attempt wins instead.
    let winner_ledger = ObligationLedger::root(
        RegionId::new(91),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    let grant = winner_ledger
        .grant(capacity)
        .expect("capacity is grantable");
    let obligation = winner_ledger
        .reserve::<HeadCasAttempt>(
            CasAttempt {
                expected_version: token(91),
                candidate_head: head(92),
                decision_batch: batch(93),
                credential: principal_snapshot(94),
                deadline_micros: 500,
            },
            grant,
        )
        .expect("required grade present");
    let settled = obligation
        .commit_internal(
            CasWon {
                winning_version: token(96),
            },
            &capacity,
        )
        .expect("a winning attempt commits");
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    let outcome = winner_ledger.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn aborting_a_workspace_records_its_incomplete_outputs() {
    let capacity = minimal_budget::<WorkspaceLease>();
    let ledger = ObligationLedger::root(
        RegionId::new(95),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    let grant = ledger.grant(capacity).expect("capacity is grantable");
    let obligation = ledger
        .reserve::<WorkspaceLease>(
            WorkspaceRequest {
                overlay: generation(97),
                base_tree: oid(98),
                materializer: MaterializerProfile::MountedView,
            },
            grant,
        )
        .expect("memory and descriptors are the required grades");
    let settled = obligation.abort_unused(WorkspaceTornDown {
        incomplete_outputs: 4,
        reason: WorkspaceAbortReason::Cancelled,
    });
    assert_eq!(settled.state(), ObligationState::Aborted);
    match ledger.close() {
        RegionCloseOutcome::Quiescent(receipt) => {
            assert_eq!(receipt.settled(), 1);
            assert!(
                receipt.consumed().is_zero(),
                "an unused abort charges nothing"
            );
        }
        RegionCloseOutcome::ContainmentFailure(failure) => {
            panic!("a settled workspace closes quiescent: {failure}")
        }
    }
}

#[test]
fn trivial_acknowledgement_is_the_evidence_type_of_every_internal_class() {
    /// Only compiles when `K::AckEvidence` really is [`TrivialAck`], and only
    /// returns when the value round-trips through the associated type.
    const fn round_trip<K: InternalEffect>() -> K::AckEvidence {
        TrivialAck
    }
    assert_eq!(round_trip::<ObjectAdmissionPermit>(), TrivialAck);
    assert_eq!(round_trip::<PreparedTxnSlot>(), TrivialAck);
    assert_eq!(round_trip::<HeadCasAttempt>(), TrivialAck);
    assert_eq!(round_trip::<WorkspaceLease>(), TrivialAck);
    assert_eq!(round_trip::<RetentionPin>(), TrivialAck);
    assert_eq!(round_trip::<RepairPermit>(), TrivialAck);
    assert_eq!(round_trip::<ContextBudgetPermit>(), TrivialAck);
}

#[test]
fn an_opaque_handle_refuses_what_it_cannot_carry_verbatim() {
    assert_eq!(
        OpaqueHandle::new(&[]).err(),
        Some(IdentityError::Empty),
        "an empty handle names nothing"
    );
    assert_eq!(
        OpaqueHandle::new(&[7_u8; 33]).err(),
        Some(IdentityError::TooLong { offered: 33 }),
        "a handle longer than the carrier is refused, never truncated"
    );

    // Near-identical permitted cases: the two lengths that actually occur.
    let short = OpaqueHandle::new(&[7_u8; 20]).expect("twenty bytes fits");
    let long = OpaqueHandle::new(&[7_u8; 32]).expect("thirty-two bytes fits");
    assert_eq!(short.len(), 20);
    assert_eq!(long.len(), 32);
    assert_eq!(short.as_bytes(), &[7_u8; 20]);
    assert_ne!(
        short, long,
        "length is part of the identity, so a prefix is not the same handle"
    );
    assert!(!short.is_empty());
    assert_eq!(
        short.to_string().len(),
        40,
        "display is lowercase hexadecimal"
    );
}

#[test]
fn a_storage_failure_after_reservation_settles_without_fabricating_a_verdict() {
    let capacity = minimal_budget::<ObjectAdmissionPermit>();
    let ledger = ObligationLedger::root(
        RegionId::new(120),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    let grant = ledger.grant(capacity).expect("capacity is grantable");
    let reservation = ObjectAdmission {
        class: ObjectClass::GitObject,
        declared_len: 1,
        staging: envelope(121),
    };
    let obligation = ledger
        .reserve::<ObjectAdmissionPermit>(reservation, grant)
        .expect("required grades present");

    // The placement write fails after the reservation is taken. Nothing about
    // the bytes was disproved, so the abort must not claim verification failed.
    let settled = obligation.abort_unused(AdmissionAbandoned {
        reason: AdmissionAbortReason::PlacementWriteFailed,
    });
    assert_eq!(settled.state(), ObligationState::Aborted);
    match settled.evidence() {
        TerminalEvidence::Aborted(receipt) => {
            assert_eq!(receipt.reason, AdmissionAbortReason::PlacementWriteFailed);
            assert_ne!(
                receipt.reason,
                AdmissionAbortReason::VerificationFailed,
                "a storage failure must not be recorded as a verdict about the bytes"
            );
        }
        other => panic!("an aborted admission carries abort evidence: {other:?}"),
    }

    let snapshot = ledger.snapshot();
    assert!(snapshot.is_conserved());
    assert_eq!(
        snapshot.available(),
        capacity,
        "an admission that never placed anything returns its whole reservation"
    );
    let outcome = ledger.close();
    assert!(
        outcome.is_quiescent(),
        "a truthfully aborted admission still reaches quiescence: {outcome:?}"
    );

    // Near-identical permitted case: the same reservation whose write succeeds.
    let twin = ObligationLedger::root(
        RegionId::new(121),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    let grant = twin.grant(capacity).expect("capacity is grantable");
    let obligation = twin
        .reserve::<ObjectAdmissionPermit>(reservation, grant)
        .expect("required grades present");
    let settled = obligation
        .commit_internal(
            AdmittedObject::verified(
                &reservation,
                oid(122),
                digest(123),
                1,
                StructureVerdict::Verified,
            )
            .expect("verified evidence"),
            &capacity,
        )
        .expect("a placement that landed commits");
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    let outcome = twin.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}
