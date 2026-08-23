#![forbid(unsafe_code)]
//! Acceptance lines 2 and 3: the broker refuses effects outside the run's
//! classes with typed reasons, and budget exhaustion mid-run produces a clean
//! typed stop with the evidence intact
//! (`frankengit-fg030a-agent-intentrun-a8h`).
//!
//! "Evidence intact" is tested behaviourally rather than by reading a counter.
//! After the exhausting refusal, an effect that still fits must succeed: that
//! proves the refusal consumed nothing, which a `remaining == expected`
//! assertion could pass while the budget had been debited and refunded.

use fgit_agent::{
    AuthorityBasisRef, BrokerRefusal, Capability, CapabilityId, ClassSet, EffectBroker, EffectId,
    EffectRequest, IntentRun, LogicalTime, OperationClass, RunId,
};
use fgit_resource::{RegionId, ResourceVector, algebra::Grade};

const fn t(value: u64) -> LogicalTime {
    LogicalTime::new(value)
}

fn bytes(amount: u64) -> ResourceVector {
    ResourceVector::single(Grade::Bytes, amount)
}

const fn basis() -> AuthorityBasisRef {
    AuthorityBasisRef {
        repository_id: 7,
        authority_head_generation: 3,
        authority_head_digest: [0x11; 32],
        verified_at: t(1),
    }
}

/// The run allows two classes and holds 1000 bytes of budget.
fn run() -> IntentRun {
    IntentRun::new(
        RunId::new(1),
        basis(),
        ClassSet::from_classes(&[
            OperationClass::ReadCanonicalObject,
            OperationClass::TreeFsWorkspace,
        ]),
        bytes(1_000),
        t(100),
    )
    .expect("a run with a non-empty scope opens")
}

/// A capability holding only one of the run's two classes, so the two
/// membership refusals can be told apart.
fn capability() -> Capability {
    Capability::issue(
        CapabilityId::new(1),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        bytes(1_000),
        t(0),
        t(100),
    )
    .expect("a capability issues")
}

fn request(id: u128, operation: OperationClass, cost: u64) -> EffectRequest {
    EffectRequest {
        effect_id: EffectId::new(id),
        operation,
        cost: bytes(cost),
        input_commitment: [0x22; 32],
    }
}

fn broker() -> EffectBroker {
    EffectBroker::open(run(), RegionId::new(1))
}

// ---------------------------------------------------------------------------
// The permitted path, built first
// ---------------------------------------------------------------------------

#[test]
fn an_authorized_effect_is_accepted_and_recorded() {
    let mut broker = broker();
    let grant = broker
        .request(
            &capability(),
            t(10),
            &request(1, OperationClass::ReadCanonicalObject, 100),
        )
        .expect("a class both the run and the capability hold, inside budget, is authorized");

    let record = *grant.record();
    assert_eq!(record.effect_id, EffectId::new(1));
    assert_eq!(record.operation, OperationClass::ReadCanonicalObject);
    assert_eq!(record.budget_reserved, bytes(100));
    assert_eq!(broker.records().len(), 1);

    // Releasing the reservation is what makes the region quiescent; an accepted
    // effect is a responsibility, not a return value.
    let _receipt = grant.into_budget().release();
    assert!(broker.close().is_quiescent());
}

// ---------------------------------------------------------------------------
// Acceptance 2: class membership, with the two failures kept distinct
// ---------------------------------------------------------------------------

#[test]
fn an_effect_outside_the_runs_classes_is_refused_naming_the_run_scope() {
    let mut broker = broker();
    // The capability would allow nothing here either, but the run is checked
    // first and must be the reported reason.
    let refusal = broker
        .request(
            &capability(),
            t(10),
            &request(2, OperationClass::SecretHandle, 10),
        )
        .expect_err("SecretHandle is outside the run entirely");

    match refusal {
        BrokerRefusal::OperationOutsideRun { requested, allowed } => {
            assert_eq!(requested, OperationClass::SecretHandle);
            assert_eq!(allowed, run().allowed_operation_classes());
        }
        other => panic!("expected OperationOutsideRun, got {other:?}"),
    }
    assert!(broker.records().is_empty(), "a refusal records no effect");
}

#[test]
fn an_effect_the_run_allows_but_the_capability_lacks_is_a_different_refusal() {
    // This is the pair that matters. Both are "not authorized", and collapsing
    // them would leave an operator unable to tell "this run may never do that"
    // from "this token is too narrow, present a wider one".
    let mut broker = broker();
    let refusal = broker
        .request(
            &capability(),
            t(10),
            &request(3, OperationClass::TreeFsWorkspace, 10),
        )
        .expect_err("the run allows TreeFsWorkspace but this capability does not hold it");

    match refusal {
        BrokerRefusal::OperationOutsideCapability { requested, held } => {
            assert_eq!(requested, OperationClass::TreeFsWorkspace);
            assert!(!held.contains(OperationClass::TreeFsWorkspace));
            assert!(held.contains(OperationClass::ReadCanonicalObject));
        }
        other => panic!("expected OperationOutsideCapability, got {other:?}"),
    }
}

#[test]
fn an_expired_run_refuses_before_anything_else_is_considered() {
    let mut broker = broker();
    let refusal = broker
        .request(
            &capability(),
            t(200),
            &request(4, OperationClass::ReadCanonicalObject, 10),
        )
        .expect_err("the run expired at 100");
    assert!(
        matches!(refusal, BrokerRefusal::RunExpired { .. }),
        "got {refusal:?}"
    );
}

#[test]
fn a_capability_outside_its_window_is_refused_even_inside_an_open_run() {
    let mut broker = broker();
    let narrow = Capability::issue(
        CapabilityId::new(2),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        bytes(1_000),
        t(0),
        t(5),
    )
    .expect("a short-lived capability issues");

    let refusal = broker
        .request(
            &narrow,
            t(10),
            &request(5, OperationClass::ReadCanonicalObject, 10),
        )
        .expect_err("the capability expired at 5 even though the run runs to 100");
    assert!(
        matches!(refusal, BrokerRefusal::CapabilityNotValid { .. }),
        "got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 3: exhaustion is a clean typed stop, and evidence survives it
// ---------------------------------------------------------------------------

#[test]
fn budget_exhaustion_stops_cleanly_and_leaves_every_earlier_record_intact() {
    let mut broker = broker();
    let capability = capability();

    let mut held = Vec::new();
    for id in 1..=3_u128 {
        let grant = broker
            .request(
                &capability,
                t(10),
                &request(id, OperationClass::ReadCanonicalObject, 300),
            )
            .expect("three effects of 300 fit inside a 1000-byte run budget");
        held.push(grant);
    }
    assert_eq!(broker.records().len(), 3);

    // 900 of 1000 spent; this asks for 300 more.
    let refusal = broker
        .request(
            &capability,
            t(10),
            &request(4, OperationClass::ReadCanonicalObject, 300),
        )
        .expect_err("only 100 bytes remain");

    match refusal {
        BrokerRefusal::BudgetExhausted { deficit } => {
            let rendered = deficit.to_string();
            assert!(
                rendered.contains("bytes"),
                "the stop must name the grade that ran out, got {rendered}"
            );
        }
        other => panic!("expected BudgetExhausted, got {other:?}"),
    }

    // EVIDENCE INTACT: the three accepted effects are still recorded, in order,
    // with their reservations unchanged.
    assert_eq!(
        broker.records().len(),
        3,
        "a refusal must not discard evidence"
    );
    for (index, record) in broker.records().iter().enumerate() {
        assert_eq!(record.effect_id, EffectId::new(index as u128 + 1));
        assert_eq!(record.budget_reserved, bytes(300));
    }

    for grant in held {
        let _receipt = grant.into_budget().release();
    }
    assert!(broker.close().is_quiescent());
}

#[test]
fn the_refusal_consumes_nothing_so_an_effect_that_still_fits_is_accepted_after_it() {
    // The behavioural form of "clean stop". If the refusal had debited the
    // budget on its way out, the 100 that genuinely remains would be gone and
    // this would fail — which a count-based assertion would not catch.
    let mut broker = broker();
    let capability = capability();

    let big = broker
        .request(
            &capability,
            t(10),
            &request(1, OperationClass::ReadCanonicalObject, 900),
        )
        .expect("900 of 1000 fits");

    let refused = broker.request(
        &capability,
        t(10),
        &request(2, OperationClass::ReadCanonicalObject, 500),
    );
    assert!(matches!(
        refused,
        Err(BrokerRefusal::BudgetExhausted { .. })
    ));

    let exact = broker
        .request(
            &capability,
            t(10),
            &request(3, OperationClass::ReadCanonicalObject, 100),
        )
        .expect("the remaining 100 is still there after the refusal, and exactly fits");

    assert_eq!(
        broker.records().len(),
        2,
        "only the two acceptances recorded"
    );
    let _a = big.into_budget().release();
    let _b = exact.into_budget().release();
    assert!(broker.close().is_quiescent());
}

#[test]
fn an_effect_costing_exactly_the_remaining_budget_is_accepted() {
    // The inclusive boundary of exhaustion: the bound refuses what exceeds the
    // budget, not what equals it. Without this, a broker that refused at
    // `cost >= remaining` would pass every exhaustion test above.
    let mut broker = broker();
    let grant = broker
        .request(
            &capability(),
            t(10),
            &request(1, OperationClass::ReadCanonicalObject, 1_000),
        )
        .expect("an effect costing the whole budget exactly is affordable");
    let _receipt = grant.into_budget().release();
    assert!(broker.close().is_quiescent());
}

#[test]
fn an_effect_over_the_capabilitys_own_ceiling_is_refused_before_the_run_budget_moves() {
    let mut broker = broker();
    let small = Capability::issue(
        CapabilityId::new(3),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        bytes(50),
        t(0),
        t(100),
    )
    .expect("a low-ceiling capability issues");

    let refusal = broker
        .request(
            &small,
            t(10),
            &request(1, OperationClass::ReadCanonicalObject, 200),
        )
        .expect_err("200 exceeds this capability's own 50-byte ceiling");
    assert!(
        matches!(refusal, BrokerRefusal::CapabilityQuotaExceeded { .. }),
        "got {refusal:?}"
    );

    // And the run's budget is untouched: the full 1000 is still available.
    let grant = broker
        .request(
            &capability(),
            t(10),
            &request(2, OperationClass::ReadCanonicalObject, 1_000),
        )
        .expect("the capability-ceiling refusal did not spend the run's budget");
    let _receipt = grant.into_budget().release();
    assert!(broker.close().is_quiescent());
}

// ---------------------------------------------------------------------------
// The obligation this crate does hold
// ---------------------------------------------------------------------------

#[test]
fn an_accepted_effect_whose_reservation_is_dropped_is_a_containment_failure() {
    // §9: region closure requires every obligation settled. The broker hands
    // out a real reservation, so abandoning one is not silent.
    let mut broker = broker();
    let grant = broker
        .request(
            &capability(),
            t(10),
            &request(1, OperationClass::ReadCanonicalObject, 100),
        )
        .expect("authorized");
    drop(grant);

    assert!(
        !broker.close().is_quiescent(),
        "a dropped reservation must surface at close rather than vanish"
    );
}
