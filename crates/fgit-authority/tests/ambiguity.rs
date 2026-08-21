//! Ambiguous responses and their resolution.
//!
//! The contract's hardest rule is negative: a caller must not be able to learn
//! non-commit from a timeout, a lost response, or a cancellation. These tests
//! assert both halves — that the caller genuinely cannot tell, and that an
//! exact-key read recovers as much truth as storage can offer.

use fgit_authority::{
    AmbiguityReason, AuthorityFailure, AuthorityRefusal, AuthorityResponse, AuthorityStore,
    CasResolution, EffectKnowledge, FaultDirective, FaultKind, FaultPlan, FaultableAuthorityStore,
    HeadGeneration, HeadInit, HeadKey, HeadReadReceipt, ImmutableKey, MemoryAuthorityStore,
    OpIndex, PutOutcome, PutResolution, StoreInstanceId, ambiguity_of, refusal_of,
    resolve_ambiguous_cas, resolve_ambiguous_put,
};

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(1))
}

fn head_key(name: &str) -> HeadKey {
    HeadKey::new(name.as_bytes().to_vec()).expect("admissible head key")
}

fn immutable_key(name: &str) -> ImmutableKey {
    ImmutableKey::new(name.as_bytes().to_vec()).expect("admissible immutable key")
}

fn created(store: &MemoryAuthorityStore, key: &HeadKey, body: &[u8]) -> HeadReadReceipt {
    match store
        .initialize_head(key, HeadGeneration::FIRST, body)
        .expect("head creation")
    {
        HeadInit::Created(receipt) => receipt,
        other => panic!("a fresh head slot must be created, observed {other:?}"),
    }
}

fn attempt_with(kind: FaultKind) -> (MemoryAuthorityStore, HeadKey, AuthorityFailure) {
    let store = store();
    let key = head_key("repo/head");
    let first = created(&store, &key, b"head-1");
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        kind,
    )]));
    let failure = store
        .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(2), b"head-2")
        .expect_err("an injected loss cannot return an outcome");
    store.install_fault_plan(FaultPlan::none());
    (store, key, failure)
}

#[test]
fn a_response_lost_after_the_effect_resolves_to_applied() {
    let (store, key, failure) = attempt_with(FaultKind::LoseResponse);
    assert!(!failure.proves_no_effect());

    let resolution = resolve_ambiguous_cas(&store, &key, HeadGeneration::from_raw(2), b"head-2")
        .expect("resolution read");
    let CasResolution::Applied(receipt) = resolution else {
        panic!("an effect that really happened must resolve to Applied, observed {resolution:?}");
    };
    assert_eq!(receipt.generation(), HeadGeneration::from_raw(2));
    assert_eq!(receipt.body(), b"head-2");
}

#[test]
fn a_request_lost_before_the_effect_resolves_to_not_applied() {
    let (store, key, failure) = attempt_with(FaultKind::LoseRequest);
    assert!(!failure.proves_no_effect());

    let resolution = resolve_ambiguous_cas(&store, &key, HeadGeneration::from_raw(2), b"head-2")
        .expect("resolution read");
    let CasResolution::NotApplied(receipt) = resolution else {
        panic!("an effect that never happened must resolve to NotApplied, observed {resolution:?}");
    };
    assert_eq!(
        receipt.generation(),
        HeadGeneration::FIRST,
        "the head must still carry the pre-attempt generation"
    );
}

#[test]
fn losing_the_request_and_losing_the_response_are_indistinguishable() {
    let (_, _, lost_request) = attempt_with(FaultKind::LoseRequest);
    let (_, _, lost_response) = attempt_with(FaultKind::LoseResponse);

    assert_eq!(
        lost_request, lost_response,
        "the caller must not be able to tell a lost request from a lost response"
    );
    assert_eq!(
        lost_request,
        AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse)
    );
}

#[test]
fn ambiguity_never_proves_non_commit() {
    for reason in [
        AmbiguityReason::NoResponse,
        AmbiguityReason::Timeout,
        AmbiguityReason::Cancelled,
    ] {
        let failure = AuthorityFailure::Ambiguous(reason);
        assert!(
            !failure.proves_no_effect(),
            "{reason:?} must never license a non-commit conclusion"
        );
        assert_eq!(refusal_of(failure), None);
        assert_eq!(ambiguity_of(failure), Some(reason));
        assert_eq!(
            failure.into_response().effect_knowledge(),
            EffectKnowledge::Unknown
        );
    }
}

#[test]
fn a_refusal_does_prove_non_commit() {
    let failure = AuthorityFailure::Refused(AuthorityRefusal::Throttled);
    assert!(failure.proves_no_effect());
    assert_eq!(refusal_of(failure), Some(AuthorityRefusal::Throttled));
    assert_eq!(ambiguity_of(failure), None);
    assert_eq!(
        failure.into_response().effect_knowledge(),
        EffectKnowledge::NoEffect
    );
    assert_eq!(
        AuthorityResponse::PutIfAbsent(PutOutcome::Created).effect_knowledge(),
        EffectKnowledge::Observed
    );
}

#[test]
fn a_throttled_request_is_a_refusal_and_the_retry_proceeds() {
    let store = store();
    let key = immutable_key("seal/tx-1");
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::Throttle,
    )]));

    let failure = store
        .put_if_absent(&key, b"seal-body")
        .expect_err("a shed request returns no outcome");
    assert_eq!(
        failure,
        AuthorityFailure::Refused(AuthorityRefusal::Throttled)
    );
    assert!(
        failure.proves_no_effect(),
        "shedding before any effect is one of the few cases that does prove non-commit"
    );

    store.install_fault_plan(FaultPlan::none());
    assert_eq!(
        store.put_if_absent(&key, b"seal-body").expect("retry"),
        PutOutcome::Created,
        "the adjacent permitted case must proceed"
    );
}

#[test]
fn a_superseded_head_defers_to_the_outcome_index() {
    let store = store();
    let key = head_key("repo/head");
    let first = created(&store, &key, b"head-1");
    let second = match store
        .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(2), b"head-2")
        .expect("conditional replacement")
    {
        fgit_authority::CasOutcome::Committed(receipt) => receipt,
        fgit_authority::CasOutcome::PredecessorMismatch => panic!("the first write must publish"),
    };
    store
        .compare_exchange_head(&key, second.token(), HeadGeneration::from_raw(3), b"head-3")
        .expect("a third publication");

    let resolution = resolve_ambiguous_cas(&store, &key, HeadGeneration::from_raw(2), b"head-2")
        .expect("resolution read");
    assert!(
        matches!(resolution, CasResolution::Superseded(_)),
        "storage must not guess when the head has moved past the proposal, observed {resolution:?}"
    );
}

#[test]
fn an_absent_head_resolves_to_head_absent() {
    let store = store();
    let key = head_key("repo/never");
    assert_eq!(
        resolve_ambiguous_cas(&store, &key, HeadGeneration::FIRST, b"head-1")
            .expect("resolution read"),
        CasResolution::HeadAbsent
    );
}

#[test]
fn put_resolution_is_complete_because_bodies_are_immutable() {
    let store = store();
    let key = immutable_key("seal/tx-1");
    assert_eq!(
        resolve_ambiguous_put(&store, &key, b"seal-body").expect("resolution read"),
        PutResolution::Absent
    );

    store.put_if_absent(&key, b"seal-body").expect("put");
    assert_eq!(
        resolve_ambiguous_put(&store, &key, b"seal-body").expect("resolution read"),
        PutResolution::PresentIdentical
    );
    assert_eq!(
        resolve_ambiguous_put(&store, &key, b"other-body").expect("resolution read"),
        PutResolution::PresentConflicting(b"seal-body".to_vec())
    );
}

#[test]
fn the_ground_truth_of_an_ambiguous_attempt_lives_only_in_the_fault_log() {
    let scripted = store();
    let key = head_key("repo/head");
    let first = created(&scripted, &key, b"head-1");
    scripted.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::LoseResponse,
    )]));

    let failure = scripted
        .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(2), b"head-2")
        .expect_err("a lost response returns no outcome");
    assert_eq!(
        failure,
        AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse),
        "the caller-visible value carries no ground truth"
    );

    let faults = scripted.fault_log();
    let [record] = faults.records() else {
        panic!(
            "expected exactly one injected fault, observed {:?}",
            faults.records()
        );
    };
    assert_eq!(record.kind, FaultKind::LoseResponse);
    assert_eq!(record.at, OpIndex::ZERO);
    assert!(
        record.effect_reached,
        "the log, and only the log, records that the effect really happened"
    );
    assert_eq!(
        scripted.effect_log().mutation_count(),
        1,
        "the head really did move even though the caller cannot know it"
    );
}
