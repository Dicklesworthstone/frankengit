//! Put-if-absent trichotomy, idempotency, bounds, and complete-or-absent writes.

use fgit_authority::{
    AuthorityFailure, AuthorityRefusal, AuthorityStore, DuplicateDelivery, FaultDirective,
    FaultKind, FaultPlan, FaultPosition, FaultableAuthorityStore, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, OpIndex, PutOutcome, PutResolution, StoreInstanceId,
    resolve_ambiguous_put,
};

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(1))
}

fn immutable_key(name: &str) -> ImmutableKey {
    ImmutableKey::new(name.as_bytes().to_vec()).expect("admissible immutable key")
}

#[test]
fn put_if_absent_returns_three_typed_outcomes() {
    let store = store();
    let key = immutable_key("seal/tx-1");

    assert_eq!(
        store.put_if_absent(&key, b"seal-body").expect("first put"),
        PutOutcome::Created
    );
    assert_eq!(
        store.put_if_absent(&key, b"seal-body").expect("identical retry"),
        PutOutcome::IdenticalRetry
    );
    assert_eq!(
        store.put_if_absent(&key, b"other-body").expect("conflicting put"),
        PutOutcome::Conflict
    );
}

#[test]
fn a_conflicting_put_never_replaces_the_stored_body() {
    let store = store();
    let key = immutable_key("seal/tx-1");
    store.put_if_absent(&key, b"original").expect("first put");
    store.put_if_absent(&key, b"usurper").expect("conflicting put");

    assert_eq!(
        store.read_immutable(&key).expect("read back"),
        ImmutableRead::Present(b"original".to_vec()),
        "an immutable slot must not be replaced by a conflicting write"
    );
}

#[test]
fn a_duplicated_delivery_is_idempotent() {
    let store = store();
    let key = immutable_key("seal/tx-1");
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::DuplicateRequest {
            deliver: DuplicateDelivery::Second,
        },
    )]));

    let outcome = store.put_if_absent(&key, b"seal-body").expect("duplicated put");
    assert_eq!(
        outcome,
        PutOutcome::IdenticalRetry,
        "the second delivery of a duplicated put must observe the first delivery's effect"
    );

    store.install_fault_plan(FaultPlan::none());
    assert_eq!(
        store.read_immutable(&key).expect("read back"),
        ImmutableRead::Present(b"seal-body".to_vec())
    );
    assert_eq!(
        resolve_ambiguous_put(&store, &key, b"seal-body").expect("resolution"),
        PutResolution::PresentIdentical
    );
}

#[test]
fn an_oversize_body_is_refused_and_a_body_at_the_bound_is_accepted() {
    let store = store();
    let limit = store.limits().max_body_bytes;

    let refused = store
        .put_if_absent(&immutable_key("body/oversize"), &vec![0_u8; limit + 1])
        .expect_err("an oversize body must be refused");
    assert_eq!(
        refused,
        AuthorityFailure::Refused(AuthorityRefusal::BodyTooLarge {
            len: limit + 1,
            limit
        })
    );
    assert!(refused.proves_no_effect(), "a bound refusal applies no effect");

    assert_eq!(
        store
            .put_if_absent(&immutable_key("body/at-bound"), &vec![7_u8; limit])
            .expect("a body at the declared bound must be accepted"),
        PutOutcome::Created,
        "the permitted case adjacent to the refusal must proceed"
    );
}

#[test]
fn an_empty_key_is_refused_and_a_one_byte_key_is_accepted() {
    assert!(
        ImmutableKey::new(Vec::new()).is_err(),
        "an empty key cannot name a slot"
    );
    let key = ImmutableKey::new(vec![b'k']).expect("a one-byte key is admissible");
    assert_eq!(
        store().put_if_absent(&key, b"body").expect("put"),
        PutOutcome::Created
    );
}

#[test]
fn a_crash_before_the_effect_leaves_the_slot_absent() {
    let store = store();
    let key = immutable_key("seal/tx-1");
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::Crash {
            position: FaultPosition::BeforeEffect,
        },
    )]));

    let failure = store
        .put_if_absent(&key, b"seal-body")
        .expect_err("a crash during the request cannot return an outcome");
    assert!(
        !failure.proves_no_effect(),
        "a crash in flight must never prove non-commit to the caller"
    );

    store.restart();
    store.install_fault_plan(FaultPlan::none());
    assert_eq!(
        store.read_immutable(&key).expect("read back"),
        ImmutableRead::Absent,
        "a crash before the effect must leave no partial body"
    );
}

#[test]
fn a_crash_after_the_effect_leaves_the_slot_complete() {
    let store = store();
    let key = immutable_key("seal/tx-1");
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::Crash {
            position: FaultPosition::AfterEffect,
        },
    )]));

    let failure = store
        .put_if_absent(&key, b"seal-body")
        .expect_err("a crash before the response cannot return an outcome");
    assert!(!failure.proves_no_effect());

    store.restart();
    store.install_fault_plan(FaultPlan::none());
    assert_eq!(
        store.read_immutable(&key).expect("read back"),
        ImmutableRead::Present(b"seal-body".to_vec()),
        "a body is stored complete or not at all, never truncated"
    );
}

#[test]
fn a_crashed_endpoint_refuses_and_a_restarted_one_proceeds() {
    let store = store();
    let key = immutable_key("seal/tx-1");
    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::Crash {
            position: FaultPosition::BeforeEffect,
        },
    )]));
    let _crashing = store.put_if_absent(&key, b"seal-body");
    assert!(store.is_crashed());

    let refused = store
        .put_if_absent(&key, b"seal-body")
        .expect_err("a crashed endpoint must refuse");
    assert_eq!(
        refused,
        AuthorityFailure::Refused(AuthorityRefusal::Unavailable)
    );
    assert!(
        refused.proves_no_effect(),
        "a request the endpoint never processed does prove non-commit"
    );

    store.restart();
    store.install_fault_plan(FaultPlan::none());
    assert_eq!(
        store.put_if_absent(&key, b"seal-body").expect("after restart"),
        PutOutcome::Created
    );
}
