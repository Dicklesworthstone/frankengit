//! FG-005b: the declared resource ceilings, differentially against the reference.
//!
//! The bead's matrix names "resource/mailbox/connection admission exhaustion"
//! and its acceptance asks for "byte-identical outcomes/receipts versus the
//! reference profile". `AuthorityLimits` declares four ceilings:
//!
//! ```text
//! body_bytes  immutable_slots  head_slots  version_tokens
//! ```
//!
//! `MemoryAuthorityStore` enforces all four and refuses with
//! `BodyTooLarge` / `CapacityExhausted`. `FsqliteAuthorityStore` enforces
//! **one**: `self.limits.body_bytes` at `engine.rs:466` is the only
//! `limits.`-field access in the whole crate.
//!
//! # Why the existing suites do not catch this
//!
//! `engine_conformance.rs` runs the shared FG-004 suite, which does exercise a
//! ceiling -- `ac_16_bounded_typed_errors` puts an oversize body and expects
//! `BodyTooLarge`, with an at-limit body beside it as the presence case. That
//! passes, because `body_bytes` is the one ceiling both backends enforce.
//!
//! The suite has **no capacity-exhaustion check at all**: `CapacityExhausted`
//! appears nowhere in `fgit-authority/src/suite.rs`. So the three slot ceilings
//! are unexercised by the shared conformance suite, unexercised by the crate's
//! own tests, and divergent between the two backends -- and every lane stayed
//! green over the top of it. A shared suite that covers one member of a family
//! reads, at a glance, as covering the family.
//!
//! # Why this is worse than an unimplemented limit
//!
//! The store does not merely fail to enforce them. It **accepts them and
//! publishes them**: `AuthorityLimits` goes in through `open()`, is stored, and
//! is handed back by `limits()`, which is how the conformance suite discovers
//! what to test. A caller reading `limits()` is told four ceilings are in force
//! when one is.
//!
//! Constitution §3.1: *"Unsupported behavior returns a typed refusal. It never
//! falls back secretly."* Silently ignoring three declared ceilings is the
//! secret fallback, and the typed refusal already exists in the vocabulary --
//! `AuthorityRefusal::CapacityExhausted { occupancy, limit }` -- with the
//! reference store as a worked example of raising it.
//!
//! # What this file does NOT do
//!
//! Fix it. The ceilings belong to `fgit-authority-fsqlite/src`, whose owner is
//! not this campaign's author -- the independence this bead rests on was
//! already spent once today and bought back. Filed instead, with the
//! reproduction parked here ready to un-ignore, which is the arrangement that
//! worked for `frankengit-w1ik`. Filed as `frankengit-nv0a`.

use fgit_authority::{
    AuthorityLimits, AuthorityRefusal, AuthorityStore, HeadGeneration, HeadKey, ImmutableKey,
    MemoryAuthorityStore, MemoryStoreConfig, StoreInstanceId,
};
use fgit_authority_fsqlite::{EngineError, FsqliteAuthorityStore};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx as FsqliteCx;

/// Deliberately tiny, so exhaustion is reached in three operations rather than
/// by allocating anything large.
const fn cramped() -> AuthorityLimits {
    AuthorityLimits {
        body_bytes: 4096,
        immutable_slots: 2,
        head_slots: 1,
        version_tokens: 2,
    }
}

fn node() -> NodeRuntime {
    RuntimeProfile::deterministic()
        .build()
        .expect("the deterministic profile builds")
}

fn body_key(tag: &str) -> ImmutableKey {
    ImmutableKey::new(format!("blob/{tag}").into_bytes()).expect("admissible")
}

/// The engine behind a blocking view, so one script can drive both backends.
struct Engine<'a> {
    node: &'a NodeRuntime,
    cx: FsqliteCx,
    store: FsqliteAuthorityStore,
}

impl<'a> Engine<'a> {
    fn open(node: &'a NodeRuntime, limits: AuthorityLimits) -> Self {
        let native = node.request_cx(BudgetClass::Request);
        let cx = FsqliteCx::new();
        cx.set_native_cx(native);
        let store = node
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                ":memory:".to_owned(),
                StoreInstanceId::from_raw(1),
                limits,
            ))
            .expect("an in-memory store opens");
        Self { node, cx, store }
    }

    fn put(&self, key: &ImmutableKey, body: &[u8]) -> Result<(), AuthorityRefusal> {
        match self
            .node
            .block_on(self.store.put_if_absent(&self.cx, key, body))
        {
            Ok(_) => Ok(()),
            Err(EngineError::Contract(refusal)) => Err(refusal),
            Err(other) => panic!("unexpected engine failure: {other:?}"),
        }
    }

    fn init_head(&self, key: &HeadKey, body: &[u8]) -> Result<(), AuthorityRefusal> {
        let generation = HeadGeneration::try_new(1).expect("a small generation is admissible");
        match self
            .node
            .block_on(self.store.initialize_head(&self.cx, key, generation, body))
        {
            Ok(_) => Ok(()),
            Err(EngineError::Contract(refusal)) => Err(refusal),
            Err(other) => panic!("unexpected engine failure: {other:?}"),
        }
    }
}

/// Fill `immutable_slots` and then one more, against either backend.
fn one_past_the_body_ceiling<F>(mut put: F) -> Result<(), AuthorityRefusal>
where
    F: FnMut(&ImmutableKey, &[u8]) -> Result<(), AuthorityRefusal>,
{
    let limits = cramped();
    for slot in 0..limits.immutable_slots {
        put(&body_key(&format!("fill-{slot}")), b"payload")
            .expect("a body inside the declared ceiling must be accepted");
    }
    put(&body_key("one-too-many"), b"payload")
}

#[test]
fn the_reference_refuses_one_body_past_its_declared_ceiling() {
    // The presence case for the differential below, and the evidence that the
    // ceiling is a real contract rather than a field nobody reads. If this ever
    // fails, the divergence test underneath it is comparing against nothing.
    let reference = MemoryAuthorityStore::with_config(MemoryStoreConfig {
        instance: StoreInstanceId::from_raw(1),
        limits: cramped(),
        ..MemoryStoreConfig::default()
    });

    let refusal = one_past_the_body_ceiling(|key, body| {
        reference
            .put_if_absent(key, body)
            .map(|_| ())
            .map_err(|failure| match failure {
                fgit_authority::AuthorityFailure::Refused(refusal) => refusal,
                fgit_authority::AuthorityFailure::Ambiguous(reason) => panic!(
                    "the reference is deterministic and has no fault plan installed, so it must \
                     not answer ambiguously here: {reason:?}"
                ),
            })
    })
    .expect_err("the reference must refuse the body past its declared ceiling");

    assert!(
        matches!(refusal, AuthorityRefusal::CapacityExhausted { .. }),
        "the reference must name the exhausted capacity so an operator can act on it; got \
         {refusal:?}"
    );
}

#[test]
#[ignore = "red: frankengit-nv0a -- the store enforces 1 of its 4 declared ceilings. Un-ignore with the fix."]
fn the_engine_enforces_every_ceiling_it_declares() {
    // THIS IS RED AND IT IS A REAL DIVERGENCE, not a flaky or aspirational test.
    //
    // `MemoryAuthorityStore` refuses the third body with `CapacityExhausted`.
    // `FsqliteAuthorityStore` accepts it, and will accept the thousandth, while
    // `limits()` keeps reporting a ceiling of two.
    //
    // The same holds for `head_slots` and `version_tokens`; only `body_bytes` is
    // enforced, at engine.rs:466, which is the sole `limits.`-field access in
    // the crate. `body_bytes` is also the only ceiling the shared FG-004 suite
    // exercises, which is why every lane has been green over this.
    let node = node();
    let engine = Engine::open(&node, cramped());

    let refusal = one_past_the_body_ceiling(|key, body| engine.put(key, body)).expect_err(
        "the engine accepted a body past the ceiling it declares through limits(); §3.1 requires \
         a typed refusal rather than a silent fallback, and AuthorityRefusal::CapacityExhausted \
         already exists for exactly this",
    );

    assert!(
        matches!(refusal, AuthorityRefusal::CapacityExhausted { .. }),
        "the engine must refuse with the same typed capacity refusal the reference uses, or the \
         two backends disagree about a declared contract; got {refusal:?}"
    );
}

#[test]
#[ignore = "red: frankengit-nv0a -- head_slots is declared and unenforced. Un-ignore with the fix."]
fn the_engine_enforces_the_head_slot_ceiling_it_declares() {
    // A second ceiling, because one divergence could be an oversight in a
    // single code path and three is a missing concept. `head_slots` is 1 here,
    // so the second distinct head must be refused.
    let node = node();
    let engine = Engine::open(&node, cramped());

    engine
        .init_head(
            &HeadKey::new(b"refs/heads/main".to_vec()).expect("admissible"),
            b"first",
        )
        .expect("the first head is inside the declared ceiling");

    let refusal = engine
        .init_head(
            &HeadKey::new(b"refs/heads/second".to_vec()).expect("admissible"),
            b"second",
        )
        .expect_err("a second head exceeds the declared head_slots ceiling of one");

    assert!(
        matches!(refusal, AuthorityRefusal::CapacityExhausted { .. }),
        "got {refusal:?}"
    );
}
