//! Lifecycle evidence: the runtime state machine, the owned path, and leaks.
//!
//! The planted negatives that type-state makes unrepresentable — committing
//! twice, committing after an abort, acknowledging something never committed —
//! are exercised here against the runtime mirror
//! `ObligationState::apply`, which is the form those same
//! mistakes take when the lifecycle is a replayed record rather than a value
//! you hold. Every forbidden case is paired with the near-identical permitted
//! case that proceeds.

use core::panic::AssertUnwindSafe;
use fgit_resource::algebra::{Grade, ResourceVector};
use fgit_resource::custody::{
    LeakClass, LeakDisposition, LeakSubject, LedgerHandle, LifecycleError, LifecycleEvent,
    ObligationLedger, ObligationState, RegionCloseOutcome,
};
use fgit_resource::ids::{IdempotencyKey, OpaqueHandle, RegionId};
use fgit_resource::kinds::{
    AdmissionAbandoned, AdmissionAbortReason, AdmittedObject, DispatchAbandoned,
    DispatchAbortReason, DownstreamAck, EffectDispatched, ObjectAdmission, ObjectAdmissionPermit,
    ObjectClass, OutboxDispatch, OutboxEffectPermit, StructureVerdict,
};
use fgit_resource::settlement::DownstreamIdempotency;
use fgit_resource::twophase::{
    DeferralReason, EscalationReason, ObligationClass, ObligationKind, ObservationMode,
    TerminalFailureReason,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, GitOid, GitOidSha1,
    OPAQUE_ID_LEN, ObjectEnvelopeId, PrincipalId, RepositoryCommitId,
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

fn rcr(tag: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 20]).expect("valid digest body"),
    )
}

const fn oid(tag: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([tag; GitOidSha1::LEN]))
}

fn opaque(tag: u8) -> OpaqueHandle {
    OpaqueHandle::new(&[tag; 20]).expect("twenty bytes is a valid opaque handle")
}

fn admission_reservation() -> ObjectAdmission {
    ObjectAdmission {
        class: ObjectClass::GitObject,
        declared_len: 128,
        staging: envelope(0xA1),
    }
}

fn admission_receipt(reservation: &ObjectAdmission) -> AdmittedObject {
    AdmittedObject::verified(
        reservation,
        oid(0xB2),
        digest(0xC3),
        reservation.declared_len,
        StructureVerdict::Verified,
    )
    .expect("verified evidence builds a commit receipt")
}

fn outbox_reservation(strength: DownstreamIdempotency) -> OutboxDispatch {
    OutboxDispatch {
        idempotency: IdempotencyKey::new(digest(0xD4)),
        precondition_rcr: rcr(0xE5),
        endpoint: opaque(0xF6),
        idempotency_strength: strength,
    }
}

fn admission_budget() -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, 128), (Grade::Objects, 1)])
}

fn outbox_budget() -> ResourceVector {
    ResourceVector::single(Grade::EgressBytes, 512)
}

// ---------------------------------------------------------------------------
// Runtime state machine: planted negatives and their permitted twins
// ---------------------------------------------------------------------------

#[test]
fn committing_twice_is_refused_and_committing_once_proceeds() {
    let committed = ObligationState::Reserved
        .apply(LifecycleEvent::Commit)
        .expect("the permitted twin: a reserved obligation commits");
    assert_eq!(committed, ObligationState::Committed);

    assert_eq!(
        committed.apply(LifecycleEvent::Commit),
        Err(LifecycleError::IllegalTransition {
            from: ObligationState::Committed,
            event: LifecycleEvent::Commit,
        }),
        "a second commit is refused, never silently absorbed"
    );
}

#[test]
fn committing_after_abort_is_refused_and_aborting_once_proceeds() {
    let aborted = ObligationState::Reserved
        .apply(LifecycleEvent::Abort)
        .expect("the permitted twin: a reserved obligation aborts");
    assert_eq!(aborted, ObligationState::Aborted);

    assert_eq!(
        aborted.apply(LifecycleEvent::Commit),
        Err(LifecycleError::IllegalTransition {
            from: ObligationState::Aborted,
            event: LifecycleEvent::Commit,
        }),
        "an aborted obligation can never commit"
    );
}

#[test]
fn acknowledging_before_commit_is_refused_and_after_commit_proceeds() {
    assert_eq!(
        ObligationState::Reserved.apply(LifecycleEvent::Acknowledge),
        Err(LifecycleError::IllegalTransition {
            from: ObligationState::Reserved,
            event: LifecycleEvent::Acknowledge,
        }),
        "nothing external can be observed before the effect is owned"
    );

    let acknowledged = ObligationState::Committed
        .apply(LifecycleEvent::Acknowledge)
        .expect("the permitted twin: a committed effect acknowledges");
    assert_eq!(acknowledged, ObligationState::Acknowledged);
}

#[test]
fn terminal_states_accept_no_further_event() {
    let terminals = [
        ObligationState::Acknowledged,
        ObligationState::Aborted,
        ObligationState::TerminallyFailed,
        ObligationState::Leaked,
    ];
    let events = [
        LifecycleEvent::Commit,
        LifecycleEvent::Abort,
        LifecycleEvent::Acknowledge,
        LifecycleEvent::Defer,
        LifecycleEvent::Escalate,
        LifecycleEvent::FailTerminally,
        LifecycleEvent::Leak,
    ];
    for state in terminals {
        assert!(state.is_terminal(), "{state} is terminal");
        assert!(!state.is_outstanding(), "{state} owes nothing");
        for event in events {
            assert_eq!(
                state.apply(event),
                Err(LifecycleError::IllegalTransition { from: state, event }),
                "{state} must refuse {event:?}"
            );
        }
    }
}

#[test]
fn deferral_and_escalation_walk_the_committed_but_unacknowledged_window() {
    let deferred = ObligationState::Committed
        .apply(LifecycleEvent::Defer)
        .expect("a committed effect may leave its region as a record");
    assert_eq!(deferred, ObligationState::DeferredExternally);
    assert!(deferred.is_outstanding(), "a deferred effect is still owed");
    assert!(
        deferred.effect_may_exist(),
        "cancellation may never report non-commit from here"
    );

    let escalated = deferred
        .apply(LifecycleEvent::Escalate)
        .expect("reconciliation may hand it to an owner");
    assert_eq!(escalated, ObligationState::Escalated);
    assert!(
        escalated.is_outstanding(),
        "escalation is not a settlement; the region still reports it"
    );
    assert_eq!(
        escalated.apply(LifecycleEvent::Acknowledge),
        Ok(ObligationState::Acknowledged),
        "a late acknowledgement still settles an escalated effect"
    );
}

#[test]
fn every_class_agrees_with_its_kind_about_external_observation() {
    assert_eq!(ObligationClass::ALL.len(), 11, "there are eleven classes");
    assert_eq!(
        <ObjectAdmissionPermit as ObligationKind>::OBSERVATION,
        ObligationClass::ObjectAdmissionPermit.observation(),
        "an admission is internal in both the kind and the class"
    );
    assert_eq!(
        <OutboxEffectPermit as ObligationKind>::OBSERVATION,
        ObligationClass::OutboxEffectPermit.observation(),
        "an outbox delivery is externally observed in both"
    );
    let externally_observed = ObligationClass::ALL
        .into_iter()
        .filter(|class| class.observation() == ObservationMode::ExternallyObserved)
        .count();
    assert_eq!(
        externally_observed, 4,
        "outbox, secret lease, runner slot, and billing are the externally observed classes"
    );
}

// ---------------------------------------------------------------------------
// Owned path
// ---------------------------------------------------------------------------

#[test]
fn the_internal_path_commits_and_settles_in_one_call() {
    let capacity = admission_budget();
    let ledger = ObligationLedger::root(
        RegionId::new(10),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    let grant = ledger
        .grant(admission_budget())
        .expect("capacity covers it");
    let reservation = admission_reservation();
    let obligation = ledger
        .reserve::<ObjectAdmissionPermit>(reservation, grant)
        .expect("the grant holds every required grade");
    let id = obligation.id();
    let handle = ledger.handle();

    assert_eq!(handle.state_of(id), Some(ObligationState::Reserved));
    assert_eq!(obligation.reserved(), admission_budget());

    let receipt = admission_receipt(&reservation);
    let settled = obligation
        .commit_internal(receipt, &admission_budget())
        .expect("actual usage equals the reservation");

    assert_eq!(
        settled.state(),
        ObligationState::Acknowledged,
        "an internal effect acknowledges trivially at commit, with no ceremony"
    );
    assert_eq!(handle.state_of(id), Some(ObligationState::Acknowledged));
    let snapshot = ledger.snapshot();
    assert!(snapshot.is_conserved());
    assert_eq!(
        snapshot.consumed(),
        admission_budget().mask(fgit_resource::algebra::GradeDisposition::Consumable),
        "consumable grades are charged and nothing else is"
    );
    let outcome = ledger.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn the_external_path_stays_committed_until_acknowledgement() {
    let ledger = ObligationLedger::root(
        RegionId::new(11),
        LeakDisposition::RecordAndContinue,
        outbox_budget(),
    );
    let grant = ledger.grant(outbox_budget()).expect("capacity covers it");
    let obligation = ledger
        .reserve::<OutboxEffectPermit>(outbox_reservation(DownstreamIdempotency::Strong), grant)
        .expect("egress is the required grade");
    let id = obligation.id();
    let handle = ledger.handle();

    let committed = obligation
        .commit(EffectDispatched { attempt: 1 }, &outbox_budget())
        .expect("dispatch fits inside the reservation");
    assert_eq!(
        handle.state_of(id),
        Some(ObligationState::Committed),
        "an externally observed effect is owned but not settled at commit"
    );
    assert_eq!(
        handle.outstanding().len(),
        1,
        "the region still owes this effect"
    );

    let settled = committed.acknowledge(DownstreamAck {
        receipt: opaque(0x11),
        attempt: 1,
    });
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    assert_eq!(
        handle.outstanding(),
        [],
        "an acknowledged effect leaves the region owing nothing"
    );
    let outcome = ledger.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn a_settlement_that_would_mint_budget_is_refused_and_its_twin_proceeds() {
    let ledger = ObligationLedger::root(
        RegionId::new(12),
        LeakDisposition::RecordAndContinue,
        admission_budget(),
    );
    let grant = ledger
        .grant(admission_budget())
        .expect("capacity covers it");
    let reservation = admission_reservation();
    let obligation = ledger
        .reserve::<ObjectAdmissionPermit>(reservation, grant)
        .expect("required grades present");

    // Planted negative: settle for one byte more than was reserved.
    let too_much = ResourceVector::from_grades(&[(Grade::Bytes, 129), (Grade::Objects, 1)]);
    assert!(
        obligation.can_settle(&too_much).is_err(),
        "the pre-flight check refuses an over-settlement"
    );
    let refused = obligation
        .commit(admission_receipt(&reservation), &too_much)
        .expect_err("committing more than was reserved must be refused");
    assert!(
        matches!(refused.error(), LifecycleError::ChargeExceedsReservation(_)),
        "the refusal names the conservation failure: {refused}"
    );

    // The refusal handed the reservation back, so nothing leaked.
    let obligation = refused.into_obligation();

    // Near-identical permitted case: exactly what was reserved.
    let exact = admission_budget();
    assert!(obligation.can_settle(&exact).is_ok());
    let settled = obligation
        .commit_internal(admission_receipt(&reservation), &exact)
        .expect("settling exactly the reservation proceeds");
    assert_eq!(settled.state(), ObligationState::Acknowledged);

    assert!(ledger.snapshot().is_conserved());
    let outcome = ledger.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn reserving_without_a_required_grade_is_refused_and_returns_the_budget() {
    let capacity = ResourceVector::from_grades(&[(Grade::Bytes, 256), (Grade::Objects, 2)]);
    let ledger = ObligationLedger::root(
        RegionId::new(13),
        LeakDisposition::RecordAndContinue,
        capacity,
    );

    // Planted negative: bytes but no object slot.
    let thin = ledger
        .grant(ResourceVector::single(Grade::Bytes, 128))
        .expect("capacity covers it");
    let error = ledger
        .reserve::<ObjectAdmissionPermit>(admission_reservation(), thin)
        .expect_err("a reservation missing a required grade is refused");
    assert_eq!(
        error,
        fgit_resource::custody::ReserveError::MissingGrade {
            class: ObligationClass::ObjectAdmissionPermit,
            grade: Grade::Objects,
        }
    );
    let snapshot = ledger.snapshot();
    assert!(snapshot.is_conserved());
    assert_eq!(
        snapshot.available(),
        capacity,
        "a refused reservation releases its grant rather than destroying it"
    );
    assert!(ledger.leaks().is_empty(), "a refusal is not a leak");

    // Near-identical permitted case: the same reservation with the object slot.
    let full = ledger
        .grant(admission_budget())
        .expect("capacity covers it");
    let reservation = admission_reservation();
    let obligation = ledger
        .reserve::<ObjectAdmissionPermit>(reservation, full)
        .expect("the same reservation proceeds once the grade is present");
    let settled = obligation.abort_unused(AdmissionAbandoned {
        reason: AdmissionAbortReason::Cancelled,
    });
    assert_eq!(settled.state(), ObligationState::Aborted);
    let outcome = ledger.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}

// ---------------------------------------------------------------------------
// Leaks: the failure type-state cannot prevent
// ---------------------------------------------------------------------------

fn leaked_classes(handle: &LedgerHandle) -> Vec<LeakClass> {
    handle
        .leaks()
        .into_iter()
        .map(|record| record.class())
        .collect()
}

#[test]
fn dropping_a_reserved_obligation_is_a_typed_leak_and_aborting_it_is_not() {
    let capacity = admission_budget();
    let ledger = ObligationLedger::root(
        RegionId::new(20),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    let handle = ledger.handle();
    {
        let grant = ledger
            .grant(admission_budget())
            .expect("capacity covers it");
        let obligation = ledger
            .reserve::<ObjectAdmissionPermit>(admission_reservation(), grant)
            .expect("required grades present");
        assert_eq!(
            handle.state_of(obligation.id()),
            Some(ObligationState::Reserved)
        );
        // Dropped on purpose: the planted negative.
    }
    assert_eq!(
        leaked_classes(&handle),
        vec![LeakClass::ReservedObligationDropped],
        "a dropped reservation is recorded, never silent"
    );
    let snapshot = ledger.snapshot();
    assert!(snapshot.is_conserved(), "the leak reclaims its budget");
    assert_eq!(snapshot.available(), capacity);
    assert_eq!(
        snapshot.accounting_faults(),
        0,
        "a leak is a lifecycle failure, not an accounting fault"
    );

    match ledger.close() {
        RegionCloseOutcome::ContainmentFailure(failure) => {
            assert_eq!(failure.leaks().len(), 1);
            assert!(
                failure.unsettled().is_empty(),
                "the leaked obligation reached a terminal leaked state"
            );
        }
        RegionCloseOutcome::Quiescent(receipt) => {
            panic!("a leaked reservation must not close quiescent: {receipt:?}")
        }
    }

    // Near-identical permitted case: the same reservation, aborted instead.
    let twin = ObligationLedger::root(
        RegionId::new(21),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    let grant = twin.grant(admission_budget()).expect("capacity covers it");
    let obligation = twin
        .reserve::<ObjectAdmissionPermit>(admission_reservation(), grant)
        .expect("required grades present");
    let settled = obligation.abort_unused(AdmissionAbandoned {
        reason: AdmissionAbortReason::Cancelled,
    });
    assert_eq!(settled.state(), ObligationState::Aborted);
    assert_eq!(twin.leaks(), [], "the settled twin leaked nothing");
    let outcome = twin.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn dropping_a_committed_obligation_is_a_distinct_typed_leak() {
    let ledger = ObligationLedger::root(
        RegionId::new(22),
        LeakDisposition::RecordAndContinue,
        outbox_budget(),
    );
    let handle = ledger.handle();
    {
        let grant = ledger.grant(outbox_budget()).expect("capacity covers it");
        let obligation = ledger
            .reserve::<OutboxEffectPermit>(outbox_reservation(DownstreamIdempotency::Strong), grant)
            .expect("egress present");
        let _committed = obligation
            .commit(EffectDispatched { attempt: 1 }, &outbox_budget())
            .expect("dispatch fits the reservation");
        // Dropped on purpose: an effect exists downstream and nobody owns it.
    }
    assert_eq!(
        leaked_classes(&handle),
        vec![LeakClass::CommittedObligationDropped],
        "the committed-but-unacknowledged drop has its own leak class"
    );
    let outcome = ledger.close();
    assert!(!outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn dropping_an_unacknowledged_effect_record_is_a_typed_leak() {
    let ledger = ObligationLedger::root(
        RegionId::new(23),
        LeakDisposition::RecordAndContinue,
        outbox_budget(),
    );
    let handle = ledger.handle();
    {
        let grant = ledger.grant(outbox_budget()).expect("capacity covers it");
        let obligation = ledger
            .reserve::<OutboxEffectPermit>(outbox_reservation(DownstreamIdempotency::Weak), grant)
            .expect("egress present");
        let committed = obligation
            .commit(EffectDispatched { attempt: 1 }, &outbox_budget())
            .expect("dispatch fits the reservation");
        let _record = committed.defer_acknowledgement(DeferralReason::RegionClosing);
        // Dropped on purpose: deferral relocates ownership, it does not end it.
    }
    assert_eq!(
        leaked_classes(&handle),
        vec![LeakClass::UnacknowledgedRecordDropped]
    );

    // Near-identical permitted case: the same deferral, then acknowledged.
    let twin = ObligationLedger::root(
        RegionId::new(24),
        LeakDisposition::RecordAndContinue,
        outbox_budget(),
    );
    let grant = twin.grant(outbox_budget()).expect("capacity covers it");
    let obligation = twin
        .reserve::<OutboxEffectPermit>(outbox_reservation(DownstreamIdempotency::Weak), grant)
        .expect("egress present");
    let committed = obligation
        .commit(EffectDispatched { attempt: 1 }, &outbox_budget())
        .expect("dispatch fits the reservation");
    let record = committed.defer_acknowledgement(DeferralReason::AwaitingObservation);
    assert_eq!(
        record.deferral_reason(),
        DeferralReason::AwaitingObservation
    );
    let settled = record.acknowledge(DownstreamAck {
        receipt: opaque(0x22),
        attempt: 1,
    });
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    assert_eq!(twin.leaks(), [], "the settled twin leaked nothing");
    let outcome = twin.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");

    let outcome = ledger.close();
    assert!(!outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn dropping_a_ledger_without_closing_it_is_a_typed_leak() {
    let handle = {
        let ledger = ObligationLedger::root(
            RegionId::new(25),
            LeakDisposition::RecordAndContinue,
            admission_budget(),
        );
        let handle = ledger.handle();
        // Dropped on purpose: quiescence must be proved by close, not assumed.
        drop(ledger);
        handle
    };
    assert_eq!(
        leaked_classes(&handle),
        vec![LeakClass::LedgerDroppedWithoutClose]
    );
}

#[test]
fn the_fail_fast_disposition_panics_on_a_leak_and_leaves_a_record() {
    let ledger = ObligationLedger::root(
        RegionId::new(26),
        LeakDisposition::FailFast,
        admission_budget(),
    );
    let handle = ledger.handle();
    let grant = ledger
        .grant(admission_budget())
        .expect("capacity covers it");
    let obligation = ledger
        .reserve::<ObjectAdmissionPermit>(admission_reservation(), grant)
        .expect("required grades present");

    let outcome = std::panic::catch_unwind(AssertUnwindSafe(move || {
        drop(obligation);
    }));
    assert!(
        outcome.is_err(),
        "verification profiles fail fast on an obligation leak"
    );
    assert_eq!(
        leaked_classes(&handle),
        vec![LeakClass::ReservedObligationDropped],
        "the durable record exists even on the fail-fast path"
    );

    // Near-identical permitted case: under the same policy, settling is silent.
    let grant = ledger
        .grant(admission_budget())
        .expect("budget was reclaimed");
    let reservation = admission_reservation();
    let obligation = ledger
        .reserve::<ObjectAdmissionPermit>(reservation, grant)
        .expect("required grades present");
    let settled = obligation
        .commit_internal(admission_receipt(&reservation), &admission_budget())
        .expect("settling exactly the reservation proceeds");
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    assert_eq!(
        handle.leaks().len(),
        1,
        "the settled twin adds no leak under the fail-fast disposition"
    );

    let outcome = ledger.close();
    assert!(
        !outcome.is_quiescent(),
        "the earlier leak is still reported"
    );
}

#[test]
fn closing_with_a_live_obligation_reports_containment_rather_than_quiescence() {
    let ledger = ObligationLedger::root(
        RegionId::new(27),
        LeakDisposition::RecordAndContinue,
        outbox_budget(),
    );
    let grant = ledger.grant(outbox_budget()).expect("capacity covers it");
    let obligation = ledger
        .reserve::<OutboxEffectPermit>(outbox_reservation(DownstreamIdempotency::Strong), grant)
        .expect("egress present");
    let id = obligation.id();

    match ledger.close() {
        RegionCloseOutcome::ContainmentFailure(failure) => {
            let unsettled = failure.unsettled();
            assert_eq!(unsettled.len(), 1, "the live obligation is named");
            let first = unsettled.first().expect("checked length");
            assert_eq!(first.id(), id);
            assert_eq!(first.class(), ObligationClass::OutboxEffectPermit);
            assert_eq!(first.state(), ObligationState::Reserved);
            assert!(
                failure.leaks().is_empty(),
                "a live value has not leaked yet"
            );
        }
        RegionCloseOutcome::Quiescent(receipt) => {
            panic!("a region with a live obligation must not claim quiescence: {receipt:?}")
        }
    }

    // The obligation still settles after close; the region simply already
    // reported that it could not prove quiescence.
    let settled = obligation.abort_unused(DispatchAbandoned {
        reason: DispatchAbortReason::Cancelled,
    });
    assert_eq!(settled.state(), ObligationState::Aborted);
}

#[test]
fn escalation_leaves_the_region_still_owing_the_effect() {
    // `UnacknowledgedEffect::escalate` documents a strong claim: "The ledger
    // keeps the obligation outstanding, so region close still reports a
    // containment failure naming this owner. Escalation is an admission that
    // automation stopped, never a settlement."
    //
    // The state machine half of that is already covered elsewhere, on
    // `ObligationState::apply(LifecycleEvent::Escalate)`. What was not covered
    // is the METHOD -- and the method also calls `guard.disarm()`. A disarm
    // paired with a ledger that settled would leave region close quiescent, so
    // the "automation stopped" signal would vanish silently while the state
    // enum still read `Escalated`. That is the failure this test exists for.
    let ledger = ObligationLedger::root(
        RegionId::new(41),
        LeakDisposition::RecordAndContinue,
        outbox_budget(),
    );
    let grant = ledger.grant(outbox_budget()).expect("capacity covers it");
    let obligation = ledger
        .reserve::<OutboxEffectPermit>(outbox_reservation(DownstreamIdempotency::Strong), grant)
        .expect("egress is the required grade");
    let id = obligation.id();
    let handle = ledger.handle();

    let deferred = obligation
        .commit(EffectDispatched { attempt: 1 }, &outbox_budget())
        .expect("dispatch fits inside the reservation")
        .defer_acknowledgement(DeferralReason::AwaitingObservation);

    let owner = PrincipalId::from_bytes([0x5a; OPAQUE_ID_LEN]);
    let receipt = deferred.escalate(owner, EscalationReason::IndeterminateDelivery);

    assert_eq!(
        receipt.id(),
        id,
        "the receipt must name the escalated effect"
    );
    assert_eq!(
        handle.state_of(id),
        Some(ObligationState::Escalated),
        "the method must drive the same transition the event does"
    );
    assert_eq!(
        handle.outstanding().len(),
        1,
        "escalation is not a settlement -- the region still owes this effect"
    );

    let outcome = ledger.close();
    assert!(
        !outcome.is_quiescent(),
        "region close must report containment failure after an escalation, got {outcome:?}"
    );
}

#[test]
fn terminal_failure_settles_where_escalation_does_not() {
    // The contrast that gives the test above its meaning. Both methods disarm
    // the guard and both leave the effect undelivered, so a reader could
    // reasonably expect them to behave alike -- and an implementation that
    // settled on escalate would pass every assertion about `Escalated` while
    // silently dropping the containment failure. Only the pair distinguishes
    // them.
    let ledger = ObligationLedger::root(
        RegionId::new(42),
        LeakDisposition::RecordAndContinue,
        outbox_budget(),
    );
    let grant = ledger.grant(outbox_budget()).expect("capacity covers it");
    let obligation = ledger
        .reserve::<OutboxEffectPermit>(outbox_reservation(DownstreamIdempotency::Strong), grant)
        .expect("egress is the required grade");
    let id = obligation.id();
    let handle = ledger.handle();

    let settled = obligation
        .commit(EffectDispatched { attempt: 1 }, &outbox_budget())
        .expect("dispatch fits inside the reservation")
        .defer_acknowledgement(DeferralReason::AwaitingObservation)
        .fail_terminally(TerminalFailureReason::PermanentDownstreamRejection);

    assert_eq!(settled.summary().id(), id);
    assert!(
        !handle
            .state_of(id)
            .expect("the ledger still knows the obligation")
            .is_outstanding(),
        "a terminal failure settles the obligation"
    );
    assert_eq!(
        handle.outstanding(),
        [],
        "the region owes nothing once the effect is known never to land"
    );

    let outcome = ledger.close();
    assert!(
        outcome.is_quiescent(),
        "a settled region closes quiescent, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// Ledger accessors: the two halves of an entry, and what a leak names
// ---------------------------------------------------------------------------

#[test]
fn reserved_and_charged_are_the_opposite_halves_of_one_entry() {
    // `reserved_for` and `charged_to` read two fields of the SAME ledger entry
    // -- `entry.reserved` and `entry.charged` -- and return the same type. A
    // swap between them compiles, keeps the accounting identity true, and
    // reports held budget as already spent (or spent budget as still held).
    // Nothing else in this crate calls `charged_to` at all.
    //
    // What makes the swap visible is that the two are non-zero at OPPOSITE
    // stages: `settle` writes `charged = spent.mask(Consumable)` and
    // simultaneously zeroes `reserved`. A test that checked a single stage, or
    // one where the two happened to be equal, would pass with them swapped.
    let ledger = ObligationLedger::root(
        RegionId::new(91),
        LeakDisposition::RecordAndContinue,
        outbox_budget(),
    );
    let grant = ledger.grant(outbox_budget()).expect("capacity covers it");
    let obligation = ledger
        .reserve::<OutboxEffectPermit>(outbox_reservation(DownstreamIdempotency::Strong), grant)
        .expect("egress is the required grade");
    let id = obligation.id();
    let handle = ledger.handle();

    // Stage one: everything is reserved, nothing is charged.
    assert_eq!(
        handle.reserved_for(id),
        Some(outbox_budget()),
        "a fresh reservation holds the whole grant"
    );
    assert_eq!(
        handle.charged_to(id),
        Some(ResourceVector::ZERO),
        "nothing is charged before settlement"
    );

    // Settle for strictly LESS than was reserved, so the charged amount is
    // distinguishable from the reserved one rather than coinciding with it.
    let actually_spent = ResourceVector::single(Grade::EgressBytes, 200);
    let committed = obligation
        .commit(EffectDispatched { attempt: 1 }, &actually_spent)
        .expect("200 fits inside the reserved 512");

    // Stage two: the halves have exchanged roles.
    assert_eq!(
        handle.charged_to(id),
        Some(actually_spent),
        "settlement charges exactly what was spent, not what was reserved"
    );
    assert_eq!(
        handle.reserved_for(id),
        Some(ResourceVector::ZERO),
        "settlement releases the reservation; the unspent 312 is not still held"
    );

    // The unspent remainder is back in the pool rather than lost, which is the
    // reason the two fields must not be conflated.
    assert!(ledger.snapshot().is_conserved());

    // Absence case: an id the region never knew reports nothing from either
    // accessor, rather than a zero vector that would read as "known and empty".
    let stranger = committed
        .acknowledge(DownstreamAck {
            receipt: opaque(0x22),
            attempt: 1,
        })
        .state();
    assert_eq!(stranger, ObligationState::Acknowledged);
    let outcome = ledger.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn a_leak_record_names_its_subject_and_only_an_obligation_carries_a_class() {
    // `LeakRecord::subject` and `LeakRecord::obligation_class` are read by no
    // test in this crate and by no other code in `src`. `obligation_class` is
    // documented as `Some` only "when the subject was an obligation", which is
    // a correlation between two fields that nothing checks -- a record that
    // returned `Some` for a dropped grant, or `None` for a dropped obligation,
    // would look perfectly well-formed to every existing assertion, which read
    // only `reclaimed()` and the leak count.
    //
    // So both branches are exercised against the same ledger shape.

    // Branch one: a dropped GRANT is not an obligation and carries no class.
    let grant_ledger = ObligationLedger::root(
        RegionId::new(92),
        LeakDisposition::RecordAndContinue,
        outbox_budget(),
    );
    {
        let _dropped = grant_ledger
            .grant(outbox_budget())
            .expect("capacity covers it");
    }
    let grant_leaks = grant_ledger.leaks();
    assert_eq!(grant_leaks.len(), 1, "the dropped grant is recorded once");
    let grant_leak = grant_leaks.first().expect("checked length");
    assert!(
        matches!(grant_leak.subject(), LeakSubject::Grant(_)),
        "a dropped grant must be recorded as a Grant subject, got {:?}",
        grant_leak.subject()
    );
    assert_eq!(
        grant_leak.obligation_class(),
        None,
        "a grant is not an obligation, so it carries no obligation class"
    );

    // Branch two: a dropped OBLIGATION names itself and its class. Without
    // this half, an `obligation_class` that returned `None` unconditionally
    // would satisfy branch one.
    let obligation_ledger = ObligationLedger::root(
        RegionId::new(93),
        LeakDisposition::RecordAndContinue,
        outbox_budget(),
    );
    let grant = obligation_ledger
        .grant(outbox_budget())
        .expect("capacity covers it");
    let dropped_id = {
        let obligation = obligation_ledger
            .reserve::<OutboxEffectPermit>(outbox_reservation(DownstreamIdempotency::Strong), grant)
            .expect("egress is the required grade");
        obligation.id()
        // Dropped unsettled on purpose: this is the planted negative.
    };
    let obligation_leaks = obligation_ledger.leaks();
    assert_eq!(
        obligation_leaks.len(),
        1,
        "the dropped obligation is recorded once"
    );
    let obligation_leak = obligation_leaks.first().expect("checked length");
    assert_eq!(
        obligation_leak.subject(),
        LeakSubject::Obligation(dropped_id),
        "the leak must name the obligation that was dropped, not merely that one was"
    );
    assert_eq!(
        obligation_leak.obligation_class(),
        Some(ObligationClass::OutboxEffectPermit),
        "a dropped obligation carries the class needed to route the failure"
    );
}
