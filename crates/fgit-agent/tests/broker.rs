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

use core::num::NonZeroU32;
use fgit_agent::{
    AgentInstanceId, AuthorityBasisRef, BrokerRefusal, Capability, CapabilityId, ClassSet,
    EffectBroker, EffectId, EffectRequest, IntentRun, LogicalTime, OperationClass, RunId,
};

use fgit_crypto::DigestAlgorithm;
use fgit_resource::{
    DownstreamChannel, DownstreamIdempotency, IdempotencyKey, OpaqueHandle, ReconcilePlan,
    ReconcilePolicy, RegionId, ResourceVector,
    algebra::Grade,
    kinds::{DownstreamAck, OutboxDispatch},
    settlement::{DeliveryVerdict, ProbeVerdict},
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, OPAQUE_ID_LEN, PrincipalId, RepositoryCommitId,
};

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
        parent_effect_id: None,
        operation,
        cost: bytes(cost),
        input_commitment: [0x22; 32],
    }
}

fn broker() -> EffectBroker {
    EffectBroker::open(run(), RegionId::new(1), AgentInstanceId::new(1))
}

fn egress(amount: u64) -> ResourceVector {
    ResourceVector::single(Grade::EgressBytes, amount)
}

fn external_run() -> IntentRun {
    IntentRun::new(
        RunId::new(2),
        basis(),
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        egress(1_000),
        t(100),
    )
    .expect("an external-effect run has a non-empty scope")
}

fn external_capability() -> Capability {
    Capability::issue(
        CapabilityId::new(2),
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        egress(1_000),
        t(0),
        t(100),
    )
    .expect("an external-effect capability issues")
}

fn external_broker() -> EffectBroker {
    EffectBroker::open(external_run(), RegionId::new(2), AgentInstanceId::new(2))
}

fn external_request(id: u128, cost: u64) -> EffectRequest {
    EffectRequest {
        effect_id: EffectId::new(id),
        parent_effect_id: None,
        operation: OperationClass::ExternalIntegration,
        cost: egress(cost),
        input_commitment: [0x33; 32],
    }
}

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&[tag; 32]).expect("SHA-256-sized fixture digest"),
    )
}

fn rcr(tag: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithm::Sha256.id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("SHA-256-sized fixture RCR digest"),
    )
}

fn opaque(tag: u8) -> OpaqueHandle {
    OpaqueHandle::new(&[tag; 20]).expect("a bounded opaque downstream handle")
}

fn external_dispatch(tag: u8, strength: DownstreamIdempotency) -> OutboxDispatch {
    OutboxDispatch {
        idempotency: IdempotencyKey::new(digest(tag)),
        precondition_rcr: rcr(tag.wrapping_add(1)),
        endpoint: opaque(tag.wrapping_add(2)),
        idempotency_strength: strength,
    }
}

const fn reconciliation_policy() -> ReconcilePolicy {
    ReconcilePolicy::new(NonZeroU32::MIN)
}

const fn principal(tag: u8) -> PrincipalId {
    PrincipalId::from_bytes([tag; OPAQUE_ID_LEN])
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

    let record = grant.record().clone();
    assert_eq!(record.effect_id, EffectId::new(1));
    assert_eq!(record.operation, OperationClass::ReadCanonicalObject);
    assert_eq!(record.budget_reserved, bytes(100));
    assert_eq!(broker.records().len(), 1);

    // Releasing the reservation is what makes the region quiescent; an accepted
    // effect is a responsibility, not a return value.
    let _receipt = broker.abort(grant).expect("the accepted effect can abort");
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
        let _receipt = broker.abort(grant).expect("the accepted effect can abort");
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
    let _a = broker
        .abort(big)
        .expect("the first accepted effect can abort");
    let _b = broker
        .abort(exact)
        .expect("the second accepted effect can abort");
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
    let _receipt = broker.abort(grant).expect("the accepted effect can abort");
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
    let _receipt = broker.abort(grant).expect("the accepted effect can abort");
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

// ---------------------------------------------------------------------------
// FG-073: stable effect identity, replay, and external reconciliation
// ---------------------------------------------------------------------------

#[test]
fn duplicate_effect_id_is_refused_before_a_second_budget_grant_and_permitted_twin_proceeds() {
    // The old broker appended a second record and consumed a second grant here.
    // The same request is now a retry of one effect, while a different stable
    // identity is the near-identical permitted second operation.
    let mut broker = broker();
    let capability = capability();
    let first = broker
        .request(
            &capability,
            t(10),
            &request(41, OperationClass::ReadCanonicalObject, 400),
        )
        .expect("the first stable effect identity is accepted");

    let duplicate = broker.request(
        &capability,
        t(10),
        &request(41, OperationClass::ReadCanonicalObject, 400),
    );
    match duplicate {
        Err(BrokerRefusal::DuplicateEffectId { effect_id }) => {
            assert_eq!(effect_id, EffectId::new(41));
        }
        other => panic!("the second stable identity submit must be refused, got {other:?}"),
    }
    assert_eq!(
        broker.records().len(),
        1,
        "the duplicate must not append a second record"
    );

    let twin = broker
        .request(
            &capability,
            t(10),
            &request(42, OperationClass::ReadCanonicalObject, 400),
        )
        .expect("the distinct effect identity is the permitted twin");
    assert_eq!(broker.records().len(), 2);

    let _first = broker.abort(first).expect("the first effect can abort");
    let _twin = broker.abort(twin).expect("the permitted twin can abort");
    assert!(broker.close().is_quiescent());
}

struct CrashAfterDispatch {
    delivered: u32,
    probed: u32,
    probe: ProbeVerdict,
}

impl DownstreamChannel for CrashAfterDispatch {
    fn deliver(&mut self, _: &IdempotencyKey, _: u32) -> DeliveryVerdict {
        self.delivered = self.delivered.saturating_add(1);
        DeliveryVerdict::AmbiguousTimeout
    }

    fn probe(&mut self, _: &IdempotencyKey) -> ProbeVerdict {
        self.probed = self.probed.saturating_add(1);
        self.probe
    }
}

#[test]
fn crash_mid_external_effect_reconciles_to_the_downstream_outcome_and_replays_history() {
    let mut broker = external_broker();
    let dispatch = external_dispatch(0x51, DownstreamIdempotency::Strong);
    let grant = broker
        .request(&external_capability(), t(10), &external_request(51, 300))
        .expect("an authorized external effect reserves one grant");
    let deferred = broker
        .reserve_outbox(grant, dispatch)
        .expect("the external effect becomes the real outbox obligation")
        .dispatch(1, &egress(300))
        .expect("canonical dispatch ownership commits before reconciliation");

    let mut channel = CrashAfterDispatch {
        delivered: 0,
        probed: 0,
        probe: ProbeVerdict::Delivered,
    };
    let mut plan = ReconcilePlan::new(
        dispatch.idempotency,
        dispatch.idempotency_strength,
        reconciliation_policy(),
    );
    let outcome = deferred
        .reconcile(
            &mut plan,
            &mut channel,
            principal(0x51),
            |attempt| DownstreamAck {
                receipt: opaque(0x52),
                attempt,
            },
            vec![[0x53; 32]],
        )
        .expect("a definite downstream probe settles the crash window");
    assert!(matches!(
        outcome,
        fgit_agent::ExternalEffectOutcome::Acknowledged(_)
    ));
    assert_eq!(
        channel.delivered, 1,
        "the effect was retried once by stable key"
    );
    assert_eq!(
        channel.probed, 1,
        "the ambiguous attempt was probed before success"
    );

    let records = broker.records();
    let [record] = records.as_slice() else {
        panic!("one external effect should produce one record: {records:?}");
    };
    assert_eq!(record.effect_id, EffectId::new(51));
    assert_eq!(record.external_idempotency_key, Some(dispatch.idempotency));
    assert_eq!(
        record.obligation_state,
        fgit_resource::ObligationState::Acknowledged
    );
    assert_eq!(
        record.terminal_outcome,
        Some(fgit_agent::EffectTerminalOutcome::Acknowledged)
    );
    assert_eq!(record.output_commitments, vec![[0x53; 32]]);
    assert_eq!(
        record
            .reconciliation_evidence
            .as_ref()
            .expect("the crash drill records downstream observations")
            .transitions
            .len(),
        2
    );

    let replayed = EffectBroker::replay(&broker.journal())
        .expect("the append-only journal reconstructs this run exactly");
    assert_eq!(replayed.records(), records.as_slice());
    assert!(broker.close().is_quiescent());
}

#[test]
fn weak_downstream_unknown_probe_is_an_explicit_escalated_record_not_maybe() {
    let mut broker = external_broker();
    let dispatch = external_dispatch(0x61, DownstreamIdempotency::Weak);
    let grant = broker
        .request(&external_capability(), t(10), &external_request(61, 300))
        .expect("the external effect starts normally");
    let deferred = broker
        .reserve_outbox(grant, dispatch)
        .expect("the real outbox obligation reserves")
        .dispatch(1, &egress(300))
        .expect("the effect reaches the post-commit reconciliation window");
    let mut plan = ReconcilePlan::new(
        dispatch.idempotency,
        dispatch.idempotency_strength,
        reconciliation_policy(),
    );
    let mut channel = CrashAfterDispatch {
        delivered: 0,
        probed: 0,
        probe: ProbeVerdict::Unknown,
    };
    let outcome = deferred
        .reconcile(
            &mut plan,
            &mut channel,
            principal(0x61),
            |attempt| DownstreamAck {
                receipt: opaque(0x62),
                attempt,
            },
            Vec::new(),
        )
        .expect("an undecidable weak downstream is represented, not hidden");
    assert!(matches!(
        outcome,
        fgit_agent::ExternalEffectOutcome::Escalated(_)
    ));

    let record = broker.records().pop().expect("the effect remains recorded");
    assert_eq!(
        record.obligation_state,
        fgit_resource::ObligationState::Escalated
    );
    assert!(matches!(
        record.terminal_outcome,
        Some(fgit_agent::EffectTerminalOutcome::Escalated { .. })
    ));
    assert!(
        !broker.close().is_quiescent(),
        "an explicit unresolved record blocks quiescence rather than becoming maybe"
    );
}
