#![forbid(unsafe_code)]
//! Every refusal survives being RECORDED, and the one defaulted operation says
//! so honestly (`frankengit-xhzj`).
//!
//! # The gap this closes
//!
//! `AuthorityRefusal` has twelve variants. Nine are named by behavioural tests
//! in this crate — where a *store* refuses. **None of the twelve was ever
//! encoded.** `write_refusal` and `read_refusal` in `history.rs`, reached
//! through tag 6 of the response codec, are exercised by no test:
//!
//! - `tests/lincheck_codec.rs` is the only file that encodes a `History`, and
//!   its fixture carries one response, `ReadHead(HeadRead::Absent)` — no
//!   refusal at all.
//! - `tests/fault_campaign.rs` *builds* `AuthorityResponse::Refused` values,
//!   which is why a grep looks reassuring, but it compares them behaviourally
//!   and never encodes the history it assembles.
//!
//! A behavioural test proves the store refused. Only a round-trip proves the
//! **record** of that refusal survives being written and read back, and this
//! codec is how a linearizability trace becomes an artifact (§9 verifier
//! independence, §10 evidence that is machine-derived rather than asserted). A
//! codec that mangles a refusal corrupts the evidence silently instead of
//! failing.
//!
//! # The defaulted operation
//!
//! `publish_head_with_outcomes` is the trait's only defaulted method, on both
//! the sync and async contracts, and it refuses with `OperationUnsupported` so
//! that a backend without multi-key transactions says so rather than failing to
//! compile — or worse, satisfying the signature with a non-atomic imitation.
//!
//! **Four test doubles across the workspace make a deliberate decision about
//! that default and nothing asserts what it does.** The two directions are both
//! load-bearing:
//!
//! - `fgit-chronicle`'s capsule view *deliberately inherits* it, because that
//!   view wraps a store which composes a CAS and separate puts, so any
//!   delegating implementation would be non-atomic while satisfying the
//!   signature — "a fixture that looks like it publishes atomically and does
//!   not". Inheriting keeps the safe answer as the one you get by doing
//!   nothing.
//! - `fgit-admission`'s async view forwards it explicitly, and its comment
//!   records the incident from not doing so: leaving it on the default "made
//!   this fixture refuse every commit while the blocking surface committed —
//!   which read as the two surfaces disagreeing about the shared core when in
//!   fact the fixture never reached it."
//!
//! # Non-claims
//!
//! This covers the **record** of a refusal, not the decision to raise one. It
//! says nothing about whether any store refuses in the right circumstances.
//! `CapacityExhausted`'s live construction sites are in `fgit-authority-fsqlite`
//! (`engine.rs:556`, `:678`, `:687`), so this file does not test that backend's
//! capacity guards — only that the variant survives being recorded. Nothing
//! here modifies `crates/fgit-authority/src/**`.

use core::future::Future;

use fgit_authority::history::{
    AuthorityHistoryBody, ClientId, History, HistoryEvent, HistoryEventKind, LogicalTime,
    OperationId,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityOp,
    AuthorityRefusal, AuthorityResponse, AuthorityStore, AuthorityVersionToken, CasOutcome,
    DuplicateAbsenceWitness, DuplicateScan, HeadInit, HeadKey, HeadRead, HeadReadReceipt,
    ImmutableKey, ImmutableRead, KeyError, MemoryAuthorityStore, PutOutcome, StoreInstanceId,
    initialize_repository, scan_for_existing_decisions,
};
use fgit_codec::{
    DecodeLimits, RepositoryAuthorityHeadBody, canonical_body_bytes, decode_body, encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_types::OPAQUE_ID_LEN;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::RepositoryId;
use fgit_types::numeric::{HeadGeneration, PolicyEpoch, RegistryEpoch};

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a positive head generation")
}

/// **The compile-time completeness guard.**
///
/// An exhaustive match with no wildcard, so adding a variant to
/// `AuthorityRefusal` makes this file fail to COMPILE rather than silently
/// leaving `every_refusal` behind. A hand-written list of an enum's variants is
/// otherwise exactly the kind of closed vocabulary that acquires a silent gap.
const fn label(refusal: AuthorityRefusal) -> &'static str {
    match refusal {
        AuthorityRefusal::InvalidKey(_) => "InvalidKey",
        AuthorityRefusal::BodyTooLarge { .. } => "BodyTooLarge",
        AuthorityRefusal::CapacityExhausted { .. } => "CapacityExhausted",
        AuthorityRefusal::UnknownVersionToken => "UnknownVersionToken",
        AuthorityRefusal::TokenKeyMismatch => "TokenKeyMismatch",
        AuthorityRefusal::TokenGenerationMismatch => "TokenGenerationMismatch",
        AuthorityRefusal::TokenBodyMismatch => "TokenBodyMismatch",
        AuthorityRefusal::HeadAbsent => "HeadAbsent",
        AuthorityRefusal::NonMonotoneGeneration { .. } => "NonMonotoneGeneration",
        AuthorityRefusal::Throttled => "Throttled",
        AuthorityRefusal::Unavailable => "Unavailable",
        AuthorityRefusal::OperationUnsupported => "OperationUnsupported",
    }
}

/// Every variant, with **distinctive** payload values.
///
/// The numbers differ from each other on purpose: a codec that wrote the right
/// tag but the wrong field, or swapped a pair, produces a decoded value that
/// still matches the variant and fails only on the numbers.
fn every_refusal() -> Vec<AuthorityRefusal> {
    vec![
        AuthorityRefusal::InvalidKey(KeyError::Empty),
        AuthorityRefusal::InvalidKey(KeyError::TooLong {
            len: 4_097,
            limit: 4_096,
        }),
        AuthorityRefusal::BodyTooLarge {
            len: 70_001,
            limit: 65_536,
        },
        AuthorityRefusal::CapacityExhausted {
            occupancy: 1_024,
            limit: 1_023,
        },
        AuthorityRefusal::UnknownVersionToken,
        AuthorityRefusal::TokenKeyMismatch,
        AuthorityRefusal::TokenGenerationMismatch,
        AuthorityRefusal::TokenBodyMismatch,
        AuthorityRefusal::HeadAbsent,
        AuthorityRefusal::NonMonotoneGeneration {
            current: generation(9),
            proposed: generation(4),
        },
        AuthorityRefusal::Throttled,
        AuthorityRefusal::Unavailable,
        AuthorityRefusal::OperationUnsupported,
    ]
}

/// A one-operation history whose response is `refusal`.
fn history_recording(refusal: AuthorityRefusal) -> History<AuthorityOp, AuthorityResponse> {
    let key = HeadKey::new(b"xhzj/trace".to_vec()).expect("bounded head key");
    History::new(vec![
        HistoryEvent::invocation(
            ClientId(1),
            LogicalTime(1),
            OperationId(1),
            AuthorityOp::ReadHead { key },
        ),
        HistoryEvent::response(
            ClientId(1),
            LogicalTime(2),
            OperationId(1),
            AuthorityResponse::Refused(refusal),
        ),
    ])
    .expect("an invocation followed by its response is a valid history")
}

/// Encode a recorded refusal and read it back out of the decoded history.
fn round_trip(refusal: AuthorityRefusal) -> AuthorityRefusal {
    let body = AuthorityHistoryBody::new(history_recording(refusal));
    let frame = encode_body(&body).expect("a history carrying a refusal encodes");
    let decoded = decode_body::<AuthorityHistoryBody>(&frame, DecodeLimits::DEFAULT)
        .expect("a history carrying a refusal decodes");
    assert_eq!(
        decoded, body,
        "the whole body must survive, not merely the refusal"
    );

    match &decoded.history().events()[1].kind {
        HistoryEventKind::Response {
            response: AuthorityResponse::Refused(read_back),
        } => *read_back,
        other => panic!("the recorded response must still be a refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The codec, exhaustively
// ---------------------------------------------------------------------------

/// Every variant survives being recorded, with its payload.
///
/// Exhaustive over `every_refusal` rather than sampled, and the payloads are
/// asserted by equality, so a tag that round-tripped while dropping a field
/// fails here rather than passing a bare variant match.
#[test]
fn every_refusal_variant_round_trips_through_the_trace_codec() {
    for refusal in every_refusal() {
        assert_eq!(
            round_trip(refusal),
            refusal,
            "{} must survive being recorded exactly",
            label(refusal)
        );
    }
}

/// **The distinctness claim.** Twelve variants that all encoded to the same
/// bytes would satisfy every per-variant round-trip above and none of the
/// intent — a decoder is only as useful as the distinctions the encoder kept.
#[test]
fn distinct_refusals_encode_to_distinct_bytes() {
    let mut seen: Vec<(String, Vec<u8>)> = Vec::new();
    for refusal in every_refusal() {
        let body = AuthorityHistoryBody::new(history_recording(refusal));
        let payload = canonical_body_bytes(&body).expect("a recorded refusal is encodable");
        if let Some((other, _)) = seen.iter().find(|(_, bytes)| *bytes == payload) {
            panic!(
                "{:?} and {other} encode to identical bytes, so the trace cannot tell them apart",
                refusal
            );
        }
        seen.push((format!("{refusal:?}"), payload));
    }
    assert_eq!(seen.len(), every_refusal().len());
}

/// The nested `KeyError` has its own two shapes, and both must survive.
///
/// `InvalidKey` is the only variant carrying another enum, so a codec that
/// wrote the outer tag and defaulted the inner one would round-trip the variant
/// while losing which key fault occurred.
#[test]
fn the_nested_key_error_survives_on_both_of_its_shapes() {
    assert_eq!(
        round_trip(AuthorityRefusal::InvalidKey(KeyError::Empty)),
        AuthorityRefusal::InvalidKey(KeyError::Empty)
    );

    let too_long = AuthorityRefusal::InvalidKey(KeyError::TooLong {
        len: 4_097,
        limit: 4_096,
    });
    match round_trip(too_long) {
        AuthorityRefusal::InvalidKey(KeyError::TooLong { len, limit }) => {
            assert_eq!(len, 4_097, "the rejected length must survive by value");
            assert_eq!(limit, 4_096, "the bound must survive by value");
        }
        other => panic!("expected a TooLong key error, got {other:?}"),
    }
}

/// The numeric payloads survive **by value**, and the two fields are not
/// interchangeable.
///
/// Each pair is deliberately asymmetric, so a codec that swapped the two fields
/// of any pair fails here. A symmetric fixture would round-trip either way.
#[test]
fn the_numeric_payloads_survive_by_value_and_in_the_right_order() {
    match round_trip(AuthorityRefusal::BodyTooLarge {
        len: 70_001,
        limit: 65_536,
    }) {
        AuthorityRefusal::BodyTooLarge { len, limit } => {
            assert_eq!((len, limit), (70_001, 65_536));
        }
        other => panic!("expected BodyTooLarge, got {other:?}"),
    }

    match round_trip(AuthorityRefusal::CapacityExhausted {
        occupancy: 1_024,
        limit: 1_023,
    }) {
        AuthorityRefusal::CapacityExhausted { occupancy, limit } => {
            assert_eq!((occupancy, limit), (1_024, 1_023));
        }
        other => panic!("expected CapacityExhausted, got {other:?}"),
    }

    match round_trip(AuthorityRefusal::NonMonotoneGeneration {
        current: generation(9),
        proposed: generation(4),
    }) {
        AuthorityRefusal::NonMonotoneGeneration { current, proposed } => {
            assert_eq!(current, generation(9));
            assert_eq!(proposed, generation(4));
        }
        other => panic!("expected NonMonotoneGeneration, got {other:?}"),
    }
}

/// The variant list is the whole enum.
///
/// The real guard is `label`'s exhaustive match, which fails to compile if a
/// variant is added. This asserts the *list* kept up as well, since `label`
/// alone would still compile if `every_refusal` forgot an entry.
#[test]
fn the_variant_list_covers_every_distinct_label() {
    let mut labels: Vec<&'static str> = every_refusal().into_iter().map(label).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(
        labels.len(),
        12,
        "every AuthorityRefusal variant must appear at least once, got {labels:?}"
    );
}

// ---------------------------------------------------------------------------
// The defaulted operation
// ---------------------------------------------------------------------------

/// A store that is a **complete** delegate except that it never implemented
/// atomic publication — exactly the backend the default exists for.
///
/// Every required method is forwarded, so a refusal from this double can only
/// come from the defaulted method and not from an accidentally-missing one.
struct NoAtomicPublish(MemoryAuthorityStore);

impl AuthorityStore for NoAtomicPublish {
    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.0.put_if_absent(key, body)
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.0.read_immutable(key)
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.0.initialize_head(key, generation, body)
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.0.read_head(key)
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.0
            .compare_exchange_head(key, expected, new_generation, new_body)
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.0.authenticate_head_receipt(receipt)
    }

    // `publish_head_with_outcomes` is deliberately NOT overridden. That is the
    // whole point of this double.
}

/// The async twin of the same double.
struct AsyncNoAtomicPublish(MemoryAuthorityStore);

impl AsyncAuthorityStore for AsyncNoAtomicPublish {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }

    fn put_if_absent(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        let resolved = self.0.put_if_absent(key, body);
        async move { resolved }
    }

    fn read_immutable(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        let resolved = self.0.read_immutable(key);
        async move { resolved }
    }

    fn initialize_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        let resolved = self.0.initialize_head(key, generation, body);
        async move { resolved }
    }

    fn read_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        let resolved = self.0.read_head(key);
        async move { resolved }
    }

    fn compare_exchange_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        let resolved = self
            .0
            .compare_exchange_head(key, expected, new_generation, new_body);
        async move { resolved }
    }

    fn authenticate_head_receipt(
        &self,
        _cx: &Self::Context,
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        let resolved = self.0.authenticate_head_receipt(receipt);
        async move { resolved }
    }

    // Deliberately NOT overridden, as above.
}

/// Drive an already-resolved future to its value, as `async_seal_admission`
/// does. No runtime is involved and none is needed.
fn poll_ready<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("an in-memory delegate must never suspend"),
    }
}

fn digest_of(byte: u8) -> Digest {
    Digest::new(
        IdentityDomain::RepositoryAuthorityHead.algorithm().id(),
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn genesis_head() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x71; OPAQUE_ID_LEN]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest_of(0x10),
        forge_position_root: digest_of(0x11),
        outcome_index_root: digest_of(0x12),
        retention_root: digest_of(0x13),
        outbox_root: digest_of(0x14),
        configuration_root: digest_of(0x15),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

/// Initialize a head on `store` and mint a REAL witness against it.
///
/// `DuplicateAbsenceWitness` has no public constructor on purpose — its own doc
/// says minting "belongs to the duplicate-detection walk, not to callers", since
/// a public constructor "would make the witness a token anyone can forge". So
/// the witness here comes from `scan_for_existing_decisions`, the sanctioned
/// path, and is bound to the token the walk observed.
fn publish_arguments<S>(
    store: &S,
    name: &[u8],
) -> (HeadKey, AuthorityVersionToken, DuplicateAbsenceWitness)
where
    S: AuthorityStore + ?Sized,
{
    let key = HeadKey::new(name.to_vec()).expect("bounded head key");
    // A CANONICAL head body, not raw bytes: the duplicate-detection walk decodes
    // what it reads, so a placeholder head makes the scan refuse with a codec
    // fault instead of minting a witness.
    initialize_repository(store, &key, &genesis_head()).expect("genesis initializes");
    let token = match store.read_head(&key).expect("the head reads") {
        HeadRead::Present(receipt) => receipt.token(),
        HeadRead::Absent => panic!("the head was just initialized"),
    };
    let witness = match scan_for_existing_decisions(store, &key, &[])
        .expect("an empty transaction set walks cleanly")
    {
        DuplicateScan::Absent(witness) => witness,
        DuplicateScan::Found { .. } => panic!("a fresh head has decided nothing"),
    };
    (key, token, witness)
}

/// **The assumption four test doubles rest on.** The sync default refuses, and
/// it refuses with the structural, permanent code rather than a retryable one.
#[test]
fn the_sync_default_publish_refuses_as_operation_unsupported() {
    let store = NoAtomicPublish(MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x92)));
    let (key, token, witness) = publish_arguments(&store, b"xhzj/default-sync");

    let failure = store
        .publish_head_with_outcomes(&key, token, generation(2), b"head-2", &[], &witness)
        .expect_err("a backend that never implemented atomic publication must refuse");
    assert_eq!(
        failure,
        AuthorityFailure::Refused(AuthorityRefusal::OperationUnsupported),
        "the refusal must be the structural one; Unavailable would invite a retry \
         that can never succeed"
    );
}

/// The async default agrees with the sync one, exactly.
///
/// Asserted as equality against the sync result rather than separately, because
/// the claim is that the two surfaces say the *same* thing — the failure mode
/// this guards against is one surface drifting to a retryable code.
#[test]
fn the_async_default_publish_refuses_identically_to_the_sync_one() {
    let sync_store = NoAtomicPublish(MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x93)));
    let async_store =
        AsyncNoAtomicPublish(MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x94)));
    let (key, token, witness) = publish_arguments(&sync_store, b"xhzj/default-async");

    let blocking = sync_store
        .publish_head_with_outcomes(&key, token, generation(2), b"head-2", &[], &witness)
        .expect_err("the sync default refuses");
    let awaited = poll_ready(async_store.publish_head_with_outcomes(
        &(),
        &key,
        token,
        generation(2),
        b"head-2",
        &[],
        &witness,
    ))
    .expect_err("the async default refuses");

    assert_eq!(
        awaited, blocking,
        "the two contracts must inherit the same typed refusal"
    );
    assert_eq!(
        awaited,
        AuthorityFailure::Refused(AuthorityRefusal::OperationUnsupported)
    );
}

/// **The permitted twin.** A store that *does* implement the operation is not
/// refused, so the two tests above measure the default rather than an operation
/// that always fails.
///
/// Without this, an implementation that refused unconditionally would satisfy
/// both of them.
#[test]
fn a_store_that_implements_the_operation_is_not_refused_by_default() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x95));
    let (key, token, witness) = publish_arguments(&store, b"xhzj/implemented");

    let outcome =
        store.publish_head_with_outcomes(&key, token, generation(2), b"head-2", &[], &witness);
    assert_ne!(
        outcome,
        Err(AuthorityFailure::Refused(
            AuthorityRefusal::OperationUnsupported
        )),
        "this store overrides the defaulted method, so it must not inherit its refusal"
    );
}
