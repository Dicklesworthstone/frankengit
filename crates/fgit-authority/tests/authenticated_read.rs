//! Authenticated head reads: forged receipts, tampered receipts, endpoint
//! confusion, and the authenticity-is-not-currency rule.

use fgit_authority::{
    AuthorityFailure, AuthorityRefusal, AuthorityStore, AuthorityVersionToken, CasOutcome,
    HeadGeneration, HeadInit, HeadKey, HeadReadReceipt, MemoryAuthorityStore, StoreInstanceId,
    VERSION_TOKEN_BYTES,
};

fn store_at(instance: u64) -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(instance))
}

fn head_key(name: &str) -> HeadKey {
    HeadKey::new(name.as_bytes().to_vec()).expect("admissible head key")
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

#[test]
fn a_genuine_receipt_authenticates() {
    let store = store_at(1);
    let key = head_key("repo/head");
    let receipt = created(&store, &key, b"head-1");

    let authenticated = store
        .authenticate_head_receipt(&receipt)
        .expect("a receipt the store issued must authenticate");
    assert_eq!(authenticated.receipt(), &receipt);
    assert_eq!(
        authenticated.authenticated_by(),
        StoreInstanceId::from_raw(1)
    );
}

#[test]
fn a_token_the_store_never_issued_is_refused() {
    let store = store_at(1);
    let key = head_key("repo/head");
    created(&store, &key, b"head-1");

    let forged = AuthorityVersionToken::from_opaque_bytes([0xAB; VERSION_TOKEN_BYTES]);
    let forged_receipt = HeadReadReceipt::new(
        key.clone(),
        forged,
        HeadGeneration::FIRST,
        b"head-1".to_vec(),
    );

    assert_eq!(
        store
            .authenticate_head_receipt(&forged_receipt)
            .expect_err("a forged receipt must not authenticate"),
        AuthorityFailure::Refused(AuthorityRefusal::UnknownVersionToken)
    );
    assert_eq!(
        store
            .compare_exchange_head(&key, forged, HeadGeneration::from_raw(2), b"head-2")
            .expect_err("a forged token must not win a conditional write"),
        AuthorityFailure::Refused(AuthorityRefusal::UnknownVersionToken),
        "an unissued token is refused, never merely reported as a lost race"
    );
}

#[test]
fn a_tampered_body_or_generation_is_refused() {
    let store = store_at(1);
    let key = head_key("repo/head");
    let genuine = created(&store, &key, b"head-1");

    let tampered_body = HeadReadReceipt::new(
        key.clone(),
        genuine.token(),
        genuine.generation(),
        b"head-forged".to_vec(),
    );
    assert_eq!(
        store
            .authenticate_head_receipt(&tampered_body)
            .expect_err("a substituted body must not authenticate"),
        AuthorityFailure::Refused(AuthorityRefusal::TokenBodyMismatch)
    );

    let tampered_generation = HeadReadReceipt::new(
        key.clone(),
        genuine.token(),
        HeadGeneration::from_raw(99),
        genuine.body().to_vec(),
    );
    assert_eq!(
        store
            .authenticate_head_receipt(&tampered_generation)
            .expect_err("a substituted generation must not authenticate"),
        AuthorityFailure::Refused(AuthorityRefusal::TokenGenerationMismatch)
    );

    let other_key = head_key("repo/other");
    created(&store, &other_key, b"other-1");
    let misdirected = HeadReadReceipt::new(
        other_key,
        genuine.token(),
        genuine.generation(),
        genuine.body().to_vec(),
    );
    assert_eq!(
        store
            .authenticate_head_receipt(&misdirected)
            .expect_err("a receipt pointed at another slot must not authenticate"),
        AuthorityFailure::Refused(AuthorityRefusal::TokenKeyMismatch)
    );

    store
        .authenticate_head_receipt(&genuine)
        .expect("the untampered receipt must still authenticate");
}

#[test]
fn an_authentic_stale_receipt_stays_authentic_and_still_loses() {
    let store = store_at(1);
    let key = head_key("repo/head");
    let first = created(&store, &key, b"head-1");
    let CasOutcome::Committed(_) = store
        .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(2), b"head-2")
        .expect("conditional replacement")
    else {
        panic!("the first conditional write must publish");
    };

    store
        .authenticate_head_receipt(&first)
        .expect("a genuinely issued receipt stays authentic after the head moves");

    assert_eq!(
        store
            .compare_exchange_head(&key, first.token(), HeadGeneration::from_raw(3), b"head-3")
            .expect("a stale token loses rather than erroring"),
        CasOutcome::PredecessorMismatch,
        "authenticity must never be mistaken for currency"
    );
}

#[test]
fn one_endpoint_never_honours_another_endpoints_token() {
    let left = store_at(11);
    let right = store_at(12);
    let key = head_key("repo/head");
    let left_receipt = created(&left, &key, b"head-1");
    let right_receipt = created(&right, &key, b"head-1");

    assert_ne!(
        left_receipt.token(),
        right_receipt.token(),
        "two endpoints must not mint the same token for the same bytes"
    );
    assert_eq!(
        right
            .compare_exchange_head(
                &key,
                left_receipt.token(),
                HeadGeneration::from_raw(2),
                b"head-2"
            )
            .expect_err("endpoint confusion must be refused"),
        AuthorityFailure::Refused(AuthorityRefusal::UnknownVersionToken)
    );
    assert_eq!(
        right
            .authenticate_head_receipt(&left_receipt)
            .expect_err("endpoint confusion must be refused"),
        AuthorityFailure::Refused(AuthorityRefusal::UnknownVersionToken)
    );

    let CasOutcome::Committed(_) = right
        .compare_exchange_head(
            &key,
            right_receipt.token(),
            HeadGeneration::from_raw(2),
            b"head-2",
        )
        .expect("the endpoint's own token must proceed")
    else {
        panic!("the adjacent permitted case must publish");
    };
}

#[test]
fn an_opaque_token_round_trips_through_its_transport_form() {
    let store = store_at(1);
    let key = head_key("repo/head");
    let receipt = created(&store, &key, b"head-1");

    let transported = AuthorityVersionToken::from_opaque_bytes(receipt.token().to_opaque_bytes());
    assert_eq!(
        transported,
        receipt.token(),
        "a token must survive its transport form unchanged"
    );

    let CasOutcome::Committed(published) = store
        .compare_exchange_head(&key, transported, HeadGeneration::from_raw(2), b"head-2")
        .expect("a transported token is the same token")
    else {
        panic!("the transported current token must publish");
    };
    assert_eq!(published.generation(), HeadGeneration::from_raw(2));
    assert_eq!(published.body(), b"head-2");
    assert_ne!(
        published.token(),
        transported,
        "publishing mints a fresh token rather than reusing the predecessor"
    );
}
