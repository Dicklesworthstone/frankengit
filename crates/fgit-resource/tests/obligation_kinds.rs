//! Per-class evidence for the eleven concrete obligations.
//!
//! Two things are checked for every class: that its declared required grades
//! are actually enforced at reserve time, and that its four phases carry the
//! payloads section 7 of the obligations document specifies. Where that
//! section states a commit precondition, the checked receipt constructor is
//! exercised with the forbidden case and with the near-identical permitted case
//! that proceeds.

use core::num::NonZeroU32;
use fgit_resource::algebra::{Grade, ResourceVector};
use fgit_resource::custody::{
    LeakPolicy, ObligationLedger, ObligationState, RegionCloseOutcome, ReserveError,
};
use fgit_resource::ids::{BoundIdentity, IdempotencyKey, RegionId};
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
    ExternallyObserved, InternalEffect, ObligationClass, ObligationKind, TrivialAck,
};

fn identity(tag: u8) -> BoundIdentity {
    BoundIdentity::new(&[tag; 32]).expect("thirty-two bytes is a valid identity")
}

fn policy() -> LeakPolicy {
    LeakPolicy::Recover {
        escalation_threshold: NonZeroU32::new(2).expect("two is non-zero"),
    }
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
    K::Reservation: Copy,
    K::AbortReceipt: Copy,
{
    assert!(
        !K::REQUIRED_GRADES.is_empty(),
        "{} must declare at least one required grade",
        K::CLASS
    );
    let capacity = minimal_budget::<K>();
    let ledger = ObligationLedger::root(RegionId::new(region), policy(), capacity);

    for missing in K::REQUIRED_GRADES.iter().copied() {
        let grant = ledger
            .grant(budget_missing::<K>(missing))
            .expect("a subset of capacity is always grantable");
        let error = ledger
            .reserve::<K>(reservation, grant)
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
    let ledger = ObligationLedger::root(RegionId::new(region), policy(), capacity);
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
    let ledger = ObligationLedger::root(RegionId::new(region), policy(), capacity);
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
            staging: identity(1),
        },
        AdmissionAbandoned {
            reason: AdmissionAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<PreparedTxnSlot>(
        102,
        LaneSlot {
            lane: 3,
            transaction: identity(2),
        },
        SlotAbandoned {
            reason: NoCandidateReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<HeadCasAttempt>(
        103,
        CasAttempt {
            expected_version: identity(3),
            candidate_head: identity(4),
            decision_batch: identity(5),
            credential: identity(6),
            deadline_micros: 10_000,
        },
        CasNotPublished {
            reason: CasAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<OutboxEffectPermit>(
        104,
        OutboxDispatch {
            idempotency: IdempotencyKey::new(identity(7)),
            precondition_rcr: identity(8),
            endpoint: identity(9),
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
            consumer: identity(10),
            delivery: identity(11),
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
            overlay: identity(12),
            base_tree: identity(13),
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
            toolchain: identity(14),
            network: NetworkPolicy::Denied,
            cache_namespace: identity(15),
        },
        RunnerNotStarted {
            reason: RunnerAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<RetentionPin>(
        108,
        RetentionRequest {
            root: identity(16),
            cause: RetentionCause::LegalHold,
        },
        RetentionNotTaken {
            reason: RetentionAbortReason::Cancelled,
        },
    );
    required_grades_are_load_bearing::<RepairPermit>(
        109,
        RepairRequest {
            target: identity(17),
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
            packet: identity(18),
            authorization_scope: identity(19),
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
            account: identity(20),
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
        staging: identity(21),
    };
    internal_round_trip::<ObjectAdmissionPermit>(
        201,
        admission,
        AdmittedObject::verified(
            &admission,
            identity(22),
            identity(23),
            1,
            StructureVerdict::Verified,
        )
        .expect("verified evidence"),
    );

    internal_round_trip::<PreparedTxnSlot>(
        202,
        LaneSlot {
            lane: 0,
            transaction: identity(24),
        },
        SlotHandedOff {
            batch_attempt: identity(25),
        },
    );

    internal_round_trip::<HeadCasAttempt>(
        203,
        CasAttempt {
            expected_version: identity(26),
            candidate_head: identity(27),
            decision_batch: identity(28),
            credential: identity(29),
            deadline_micros: 1_000,
        },
        CasWon {
            winning_version: identity(30),
        },
    );

    internal_round_trip::<WorkspaceLease>(
        204,
        WorkspaceRequest {
            overlay: identity(31),
            base_tree: identity(32),
            materializer: MaterializerProfile::SparseCheckout,
        },
        WorkspacePublished {
            snapshot: identity(33),
            evidence: identity(34),
        },
    );

    internal_round_trip::<RetentionPin>(
        205,
        RetentionRequest {
            root: identity(35),
            cause: RetentionCause::OpenPullRequest,
        },
        RetentionHeld {
            basis_head: identity(36),
        },
    );

    internal_round_trip::<RepairPermit>(
        206,
        RepairRequest {
            target: identity(37),
            decode_budget_symbols: 8,
            source_symbols: 8,
        },
        RepairPublished::verified(
            DecodeOutcome::Succeeded,
            CommitmentCheck::AllVerified,
            AuthorityRevalidation::StillCurrent,
            identity(38),
            identity(39),
        )
        .expect("a fully verified repair"),
    );

    internal_round_trip::<ContextBudgetPermit>(
        207,
        ContextRequest {
            packet: identity(40),
            authorization_scope: identity(41),
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
            idempotency: IdempotencyKey::new(identity(42)),
            precondition_rcr: identity(43),
            endpoint: identity(44),
            idempotency_strength: DownstreamIdempotency::Strong,
        },
        EffectDispatched { attempt: 1 },
        DownstreamAck {
            receipt: identity(45),
            attempt: 1,
        },
    );

    external_round_trip::<SecretLease>(
        302,
        SecretGrant {
            class: SecretClass::RunnerJoin,
            consumer: identity(46),
            delivery: identity(47),
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
            toolchain: identity(48),
            network: NetworkPolicy::Allowlisted,
            cache_namespace: identity(49),
        },
        RunnerFinished {
            exit_class: ExitClass::Succeeded,
            artifacts: 2,
            log_root: identity(50),
        },
        RunnerReaped {
            processes_reaped: 3,
            containment: ContainmentClass::Cooperative,
        },
    );

    external_round_trip::<BillingReservation>(
        304,
        ChargeReservation {
            account: identity(51),
            ceiling_micros: 900,
            estimate_basis: EstimateBasis::Deterministic,
        },
        ChargeBound::within(
            &ChargeReservation {
                account: identity(51),
                ceiling_micros: 900,
                estimate_basis: EstimateBasis::Deterministic,
            },
            900,
        )
        .expect("a charge at its ceiling"),
        ChargeSettled {
            processor_receipt: identity(52),
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
        staging: identity(60),
    };

    assert_eq!(
        AdmittedObject::verified(
            &reservation,
            identity(61),
            identity(62),
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
            identity(61),
            identity(62),
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
        identity(61),
        identity(62),
        64,
        StructureVerdict::Verified,
    )
    .expect("full verification produces commit evidence");
    assert_eq!(receipt.verified_len(), 64);
    assert_eq!(receipt.native_oid(), identity(61));
    assert_eq!(receipt.strong_digest(), identity(62));
}

#[test]
fn decoder_success_alone_cannot_commit_a_repair() {
    assert_eq!(
        RepairPublished::verified(
            DecodeOutcome::Succeeded,
            CommitmentCheck::NotChecked,
            AuthorityRevalidation::StillCurrent,
            identity(70),
            identity(71),
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
            identity(70),
            identity(71),
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
            identity(70),
            identity(71),
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
            identity(70),
            identity(71),
        ),
        Err(RepairRefusal::DecodeIncomplete(DecodeOutcome::Failed)),
        "a failed decode cannot commit"
    );

    // Near-identical permitted case: all three preconditions hold.
    let receipt = RepairPublished::verified(
        DecodeOutcome::Succeeded,
        CommitmentCheck::AllVerified,
        AuthorityRevalidation::StillCurrent,
        identity(70),
        identity(71),
    )
    .expect("a fully verified repair commits");
    assert_eq!(receipt.placement(), identity(70));
    assert_eq!(receipt.authority_basis(), identity(71));
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
        account: identity(80),
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
    let ledger = ObligationLedger::root(RegionId::new(90), policy(), capacity);
    let grant = ledger.grant(capacity).expect("capacity is grantable");
    let obligation = ledger
        .reserve::<HeadCasAttempt>(
            CasAttempt {
                expected_version: identity(91),
                candidate_head: identity(92),
                decision_batch: identity(93),
                credential: identity(94),
                deadline_micros: 500,
            },
            grant,
        )
        .expect("processor time is the required grade");

    let lost = CasNotPublished {
        reason: CasAbortReason::LostRace {
            observed_version: identity(95),
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
    let winner_ledger = ObligationLedger::root(RegionId::new(91), policy(), capacity);
    let grant = winner_ledger
        .grant(capacity)
        .expect("capacity is grantable");
    let obligation = winner_ledger
        .reserve::<HeadCasAttempt>(
            CasAttempt {
                expected_version: identity(91),
                candidate_head: identity(92),
                decision_batch: identity(93),
                credential: identity(94),
                deadline_micros: 500,
            },
            grant,
        )
        .expect("required grade present");
    let settled = obligation
        .commit_internal(
            CasWon {
                winning_version: identity(96),
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
    let ledger = ObligationLedger::root(RegionId::new(95), policy(), capacity);
    let grant = ledger.grant(capacity).expect("capacity is grantable");
    let obligation = ledger
        .reserve::<WorkspaceLease>(
            WorkspaceRequest {
                overlay: identity(97),
                base_tree: identity(98),
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
    fn assert_trivial<K: InternalEffect>() {
        let _evidence: K::AckEvidence = TrivialAck;
    }
    assert_trivial::<ObjectAdmissionPermit>();
    assert_trivial::<PreparedTxnSlot>();
    assert_trivial::<HeadCasAttempt>();
    assert_trivial::<WorkspaceLease>();
    assert_trivial::<RetentionPin>();
    assert_trivial::<RepairPermit>();
    assert_trivial::<ContextBudgetPermit>();
}
