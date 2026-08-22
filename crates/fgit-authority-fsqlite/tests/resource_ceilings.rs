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
    AuthorityLimits, AuthorityRefusal, AuthorityStore, AuthorityVersionToken, CasOutcome,
    HeadGeneration, HeadInit, HeadKey, ImmutableKey, MemoryAuthorityStore, MemoryStoreConfig,
    PutOutcome, StoreInstanceId,
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
        self.put_outcome(key, body).map(|_| ())
    }

    /// As `put`, keeping the outcome: `Created` and `IdenticalRetry` are the
    /// difference between occupying a slot and occupying nothing, which is
    /// exactly what the capacity exemption turns on.
    fn put_outcome(&self, key: &ImmutableKey, body: &[u8]) -> Result<PutOutcome, AuthorityRefusal> {
        match self
            .node
            .block_on(self.store.put_if_absent(&self.cx, key, body))
        {
            Ok(outcome) => Ok(outcome),
            Err(EngineError::Contract(refusal)) => Err(refusal),
            Err(other) => panic!("unexpected engine failure: {other:?}"),
        }
    }

    fn init_outcome(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityRefusal> {
        match self
            .node
            .block_on(self.store.initialize_head(&self.cx, key, generation, body))
        {
            Ok(outcome) => Ok(outcome),
            Err(EngineError::Contract(refusal)) => Err(refusal),
            Err(other) => panic!("unexpected engine failure: {other:?}"),
        }
    }

    fn exchange(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityRefusal> {
        match self.node.block_on(
            self.store
                .compare_exchange_head(&self.cx, key, expected, generation, body),
        ) {
            Ok(outcome) => Ok(outcome),
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

// ------------------------------------------------- gaps the reproduction cannot see
//
// Everything above is YellowOak's reproduction, un-ignored by the fix and
// otherwise untouched. What follows is the crate owner's addition, closing two
// gaps a wrong fix would sail straight through.
//
// 1. THE EXEMPTION. A guard that simply refused every write once the table was
//    full would pass all three tests above: the fill loops still succeed, and
//    the one-too-many write is still refused. It would also be wrong. A retry
//    of a body already stored occupies no NEW slot, and the reference admits it
//    at capacity -- `reference.rs` puts the capacity check inside the `None`
//    arm, after the identical-retry and conflict arms. Nothing above holds the
//    fix to that, so a refuse-everything guard would read as a fix.
//
// 2. VERSION TOKENS. The bead names three unenforced ceilings and the
//    reproduction covers two. `version_tokens` had no test anywhere, which is
//    how it came to be one of the three.

/// Fill both backends to the immutable ceiling and confirm both are actually
/// full, so a later admission means "exempt" rather than "not yet full".
fn filled_to_capacity(engine: &Engine<'_>, reference: &MemoryAuthorityStore) {
    let limits = cramped();
    for slot in 0..limits.immutable_slots {
        let key = body_key(&format!("fill-{slot}"));
        engine
            .put(&key, b"payload")
            .expect("a body inside the declared ceiling must be accepted by the engine");
        reference
            .put_if_absent(&key, b"payload")
            .expect("a body inside the declared ceiling must be accepted by the reference");
    }

    let past = body_key("one-too-many");
    engine
        .put(&past, b"payload")
        .expect_err("the engine must be at capacity, or the exemption below proves nothing");
    reference
        .put_if_absent(&past, b"payload")
        .expect_err("the reference must be at capacity, or there is nothing to be differential to");
}

fn reference_at(limits: AuthorityLimits) -> MemoryAuthorityStore {
    MemoryAuthorityStore::with_config(MemoryStoreConfig {
        instance: StoreInstanceId::from_raw(1),
        limits,
        ..MemoryStoreConfig::default()
    })
}

#[test]
fn a_body_already_stored_is_still_admitted_at_capacity_by_both_backends() {
    let node = node();
    let engine = Engine::open(&node, cramped());
    let reference = reference_at(cramped());
    filled_to_capacity(&engine, &reference);

    // Occupies nothing new, so the ceiling does not apply to it.
    let existing = body_key("fill-0");

    assert_eq!(
        engine
            .put_outcome(&existing, b"payload")
            .expect("a body already stored occupies no new slot and must be admitted at capacity"),
        PutOutcome::IdenticalRetry,
        "the engine must admit the retry as idempotent rather than refusing it for capacity"
    );

    let reference_outcome = reference
        .put_if_absent(&existing, b"payload")
        .expect("the reference admits the same retry at capacity");
    assert_eq!(
        reference_outcome,
        PutOutcome::IdenticalRetry,
        "the two backends must agree on the exempt case as well as the refused one"
    );
}

#[test]
fn a_head_already_present_is_still_admitted_at_capacity() {
    // `head_slots` is 1, so one head fills the table.
    let node = node();
    let engine = Engine::open(&node, cramped());
    let main = HeadKey::new(b"refs/heads/main".to_vec()).expect("admissible");
    let generation = HeadGeneration::try_new(1).expect("a small generation is admissible");

    let HeadInit::Created(_) = engine
        .init_outcome(&main, generation, b"first")
        .expect("the first head is inside the declared ceiling")
    else {
        panic!("the first head must be created outright");
    };

    engine
        .init_outcome(
            &HeadKey::new(b"refs/heads/other".to_vec()).expect("admissible"),
            generation,
            b"other",
        )
        .expect_err("a second distinct head is past the ceiling, so the table is full");

    // Same key, same generation, same body: an idempotent retry that creates no
    // slot and mints no token. Refusing it for capacity would diverge.
    let retry = engine
        .init_outcome(&main, generation, b"first")
        .expect("an identical retry of an existing head must be admitted at capacity");
    assert!(
        matches!(retry, HeadInit::IdenticalRetry(_)),
        "the retry must be reported as idempotent rather than refused; got {retry:?}"
    );
}

#[test]
fn the_engine_enforces_the_version_token_ceiling_it_declares() {
    // The third of the three unenforced ceilings, and the one nothing tested.
    // `version_tokens` is 2: creating the head mints the first token, one
    // exchange mints the second, and the next mint is past the ceiling.
    let node = node();
    let engine = Engine::open(&node, cramped());
    let reference = reference_at(cramped());
    let main = HeadKey::new(b"refs/heads/main".to_vec()).expect("admissible");

    let first = HeadGeneration::try_new(1).expect("admissible");
    let second = HeadGeneration::try_new(2).expect("admissible");
    let third = HeadGeneration::try_new(3).expect("admissible");

    // --- engine: two mints are inside the ceiling, the third is not.
    let HeadInit::Created(created) = engine
        .init_outcome(&main, first, b"one")
        .expect("the head creation mints the first token, inside the ceiling")
    else {
        panic!("the head must be created outright");
    };

    let CasOutcome::Committed(exchanged) = engine
        .exchange(&main, created.token(), second, b"two")
        .expect("the first exchange mints the second token, inside the ceiling")
    else {
        panic!("the exchange must commit; the predecessor token is the one just issued");
    };

    let refusal = engine
        .exchange(&main, exchanged.token(), third, b"three")
        .expect_err(
            "a third token is past the declared version_tokens ceiling; §3.1 requires a typed \
             refusal rather than minting past a published limit",
        );
    assert!(
        matches!(refusal, AuthorityRefusal::CapacityExhausted { .. }),
        "got {refusal:?}"
    );

    // --- reference: the same script, so this is a divergence test and not just
    // an assertion about one backend.
    let HeadInit::Created(ref_created) = reference
        .initialize_head(&main, first, b"one")
        .expect("the reference creates the head")
    else {
        panic!("the reference must create the head outright");
    };
    let CasOutcome::Committed(ref_exchanged) = reference
        .compare_exchange_head(&main, ref_created.token(), second, b"two")
        .expect("the reference commits the first exchange")
    else {
        panic!("the reference exchange must commit");
    };
    let reference_failure = reference
        .compare_exchange_head(&main, ref_exchanged.token(), third, b"three")
        .expect_err("the reference refuses the third mint too");
    assert!(
        matches!(
            reference_failure,
            fgit_authority::AuthorityFailure::Refused(AuthorityRefusal::CapacityExhausted { .. })
        ),
        "the two backends must refuse the same ceiling the same way; got {reference_failure:?}"
    );
}
