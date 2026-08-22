//! The engine binding, exercised against a real `FrankenSQLite` database.
//!
//! # What this harness proves, and the claim it does not support
//!
//! The [`AuthorityStore`] contract is synchronous; the engine is asynchronous.
//! The bridge below closes that gap by blocking on the runtime once per
//! operation, which is enough to run the **unchanged** FG-004 conformance suite
//! against the fsqlite binding.
//!
//! It is not enough to say anything about cancellation. A
//! `block_on`-per-operation bridge cannot deliver a cancel *during* an
//! operation: by the time control returns to the caller, the operation is
//! already over. So the honest claim here is
//!
//! > the unchanged FG-004 suite passes against the fsqlite binding under a
//! > synchronous harness
//!
//! and it covers the **AC** suite only. `fgit-authority` ships two suites, and
//! this runs one of them:
//!
//! * `run_authority_conformance` -- AC-01..AC-20. Run here, and passing.
//! * `run_fault_conformance` -- AF-01..AF-08. **Not run, and not runnable
//!   against this binding**: it is bound `S: FaultableAuthorityStore`, and
//!   `FsqliteAuthorityStore` has no fault injection to implement it with.
//!
//! So deterministic fault behaviour -- ambiguity, duplication, lost request
//! versus lost response -- is unproven for this backend, and a green run here
//! must not be read as covering it.
//!
//! The claim is also **not** "the binding is conformant under cancellation". That needs
//! a harness that can actually interleave a cancel with an in-flight operation,
//! which is fg005b's crash and equivalence matrix. Writing the non-claim down
//! here is deliberate: this file is exactly where a reader would otherwise
//! assume the stronger property had been established.
//!
//! # The shutdown this harness cannot perform
//!
//! [`run_authority_conformance`] owns the stores it creates and drops them, and
//! a `Drop` cannot await. So the connections opened for the suite fall back to
//! the engine's synchronous close rather than the awaited one this crate
//! otherwise insists on. [`an_explicitly_closed_store_shuts_down_cleanly`]
//! covers the awaited path directly, so the discipline is tested even though
//! the suite cannot follow it.

use std::time::Duration;

use asupersync::cx::Cx as NativeCx;
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityRefusal, AuthorityStore,
    AuthorityVersionToken, CasOutcome, HeadGeneration, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, ImmutableKey, ImmutableRead, PutOutcome, StoreInstanceId,
    run_authority_conformance, run_capacity_conformance,
};
use fgit_authority_fsqlite::{EngineError, FsqliteAuthorityStore};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx as FsqliteCx;

/// A synchronous view of the asynchronous binding, for the contract suite.
struct BlockingStore<'a> {
    node: &'a NodeRuntime,
    cx: FsqliteCx,
    store: FsqliteAuthorityStore,
    /// Held for the store's lifetime so the runtime context outlives every
    /// operation dispatched through it.
    _native: NativeCx,
}

impl<'a> BlockingStore<'a> {
    /// Open a private in-memory store on `node`.
    ///
    /// Each call gets its own database: `:memory:` is per-connection, which is
    /// what the suite needs, since it builds a fresh store per check.
    fn open(node: &'a NodeRuntime, instance: StoreInstanceId) -> Self {
        Self::open_with_limits(node, instance, AuthorityLimits::default())
    }

    /// As `open`, with the ceilings supplied by the caller.
    ///
    /// `run_capacity_conformance` needs a store cramped enough to exhaust in a
    /// few operations; the default `immutable_slots` is 65536.
    fn open_with_limits(
        node: &'a NodeRuntime,
        instance: StoreInstanceId,
        limits: AuthorityLimits,
    ) -> Self {
        let native = node.request_cx(BudgetClass::Request);
        let cx = FsqliteCx::new();
        // Attach explicitly rather than relying on a task-local being set:
        // fsqlite resolves a native context via the attachment first and only
        // then falls back to the ambient one, so this makes the binding to the
        // sanctioned runtime deterministic instead of incidental.
        cx.set_native_cx(native.clone());

        let store = node
            .block_on(FsqliteAuthorityStore::open(
                &cx, ":memory:", instance, limits,
            ))
            .expect("an in-memory store opens");

        Self {
            node,
            cx,
            store,
            _native: native,
        }
    }

    /// Close the connection through the awaited path.
    fn close(mut self) -> Result<(), EngineError> {
        self.node.block_on(self.store.close(&self.cx))
    }
}

impl AuthorityStore for BlockingStore<'_> {
    fn instance_id(&self) -> StoreInstanceId {
        self.store.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.store.limits()
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.node
            .block_on(self.store.put_if_absent(&self.cx, key, body))
            .map_err(EngineError::into_failure)
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.node
            .block_on(self.store.read_immutable(&self.cx, key))
            .map_err(EngineError::into_failure)
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.node
            .block_on(self.store.initialize_head(&self.cx, key, generation, body))
            .map_err(EngineError::into_failure)
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.node
            .block_on(self.store.read_head(&self.cx, key))
            .map_err(EngineError::into_failure)
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.node
            .block_on(self.store.compare_exchange_head(
                &self.cx,
                key,
                expected,
                new_generation,
                new_body,
            ))
            .map_err(EngineError::into_failure)
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.node
            .block_on(self.store.authenticate_head_receipt(&self.cx, receipt))
            .map_err(EngineError::into_failure)
    }
}

/// How many checks `run_authority_conformance` records.
///
/// AC-01..AC-20, recorded unconditionally. Pinned so the guard below measures
/// coverage rather than mere non-emptiness.
const AC_CHECK_COUNT: usize = 20;

fn deterministic_node() -> NodeRuntime {
    RuntimeProfile::deterministic()
        .build()
        .expect("the deterministic profile builds")
}

fn head_key() -> HeadKey {
    HeadKey::new(b"refs/heads/main".to_vec()).expect("a short key is admissible")
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a small generation is admissible")
}

#[test]
fn the_unchanged_fg004_conformance_suite_passes_against_the_engine() {
    let node = deterministic_node();
    let report = run_authority_conformance(|instance| BlockingStore::open(&node, instance));

    // Non-vacuity with teeth. The original guard here was `!is_empty()`, which a
    // single check satisfies -- so a suite that silently shrank to one check
    // would still have let this test report a green conformance run, and this
    // assertion is the only thing standing behind that claim. The AC suite
    // records AC-01..AC-20 unconditionally (a failing check is still recorded),
    // so a count below twenty means checks went missing, not that the backend
    // got better.
    assert!(
        report.checks().len() >= AC_CHECK_COUNT,
        "the AC suite must record at least {AC_CHECK_COUNT} checks, got {}; a shrunken suite \
         proves nothing about the backend",
        report.checks().len()
    );
    assert!(
        report.failures().next().is_none(),
        "the fsqlite binding failed FG-004 checks {:?}",
        report.failed_ids()
    );
}

#[test]
fn an_explicitly_closed_store_shuts_down_cleanly() {
    // The awaited close is the only shutdown path this crate endorses; the
    // engine's synchronous close is a Drop backstop that cannot prove the
    // worker drained. This exercises the endorsed one.
    let node = deterministic_node();
    let store = BlockingStore::open(&node, StoreInstanceId::from_raw(1));
    store.close().expect("the store closes cleanly");
    assert!(
        node.join_root(Duration::from_secs(5)),
        "the runtime did not reach quiescence after an explicit close"
    );
}

#[test]
fn an_immutable_body_is_written_once_and_then_compared() {
    let node = deterministic_node();
    let store = BlockingStore::open(&node, StoreInstanceId::from_raw(1));
    let key = ImmutableKey::new(b"blob/1".to_vec()).expect("admissible");

    assert_eq!(
        store.put_if_absent(&key, b"first").expect("no failure"),
        PutOutcome::Created
    );
    // The identical retry is idempotent rather than a conflict: this is what
    // makes a retry after an ambiguous response safe.
    assert_eq!(
        store.put_if_absent(&key, b"first").expect("no failure"),
        PutOutcome::IdenticalRetry
    );
    // Different bytes at a taken key is immutability being enforced.
    assert_eq!(
        store.put_if_absent(&key, b"second").expect("no failure"),
        PutOutcome::Conflict
    );
    assert_eq!(
        store.read_immutable(&key).expect("no failure"),
        ImmutableRead::Present(b"first".to_vec()),
        "a conflicting put must not have replaced the stored body"
    );

    store.close().expect("closes");
}

#[test]
fn a_stale_but_genuine_token_loses_the_exchange_without_being_refused() {
    // The distinction this whole design exists for. A superseded token is
    // authentic: the store really did issue it. It still loses. Reporting it
    // as a refusal would tell the caller "nothing happened", which is false --
    // something happened, someone else won.
    let node = deterministic_node();
    let store = BlockingStore::open(&node, StoreInstanceId::from_raw(1));
    let key = head_key();

    let HeadInit::Created(first) = store
        .initialize_head(&key, generation(1), b"head-1")
        .expect("no failure")
    else {
        panic!("the first initialization must create the slot");
    };

    let CasOutcome::Committed(second) = store
        .compare_exchange_head(&key, first.token(), generation(2), b"head-2")
        .expect("no failure")
    else {
        panic!("an exchange presenting the current token must commit");
    };

    // `first` is now stale. It is still genuine.
    assert_eq!(
        store
            .compare_exchange_head(&key, first.token(), generation(3), b"head-3")
            .expect("a stale token is a lost race, not a refusal"),
        CasOutcome::PredecessorMismatch
    );

    let authenticated = store
        .authenticate_head_receipt(&first)
        .expect("a superseded receipt still authenticates: authenticity is not currency");
    assert_eq!(authenticated.receipt(), &first);
    assert_eq!(authenticated.authenticated_by(), store.instance_id());

    // The losing exchange changed nothing.
    assert_eq!(
        store.read_head(&key).expect("no failure"),
        HeadRead::Present(second),
        "a lost exchange must leave the head exactly as the winner published it"
    );

    store.close().expect("closes");
}

#[test]
fn a_token_this_store_never_issued_is_refused_rather_than_reported_as_a_lost_race() {
    // Forged and stale are different answers to different questions, and the
    // row count alone cannot tell them apart -- both change zero rows. The
    // engine checks provenance before staleness so a never-issued token is
    // refused instead of being reported as an ordinary loss.
    let node = deterministic_node();
    let store = BlockingStore::open(&node, StoreInstanceId::from_raw(1));
    let key = head_key();

    store
        .initialize_head(&key, generation(1), b"head-1")
        .expect("no failure");

    let forged = AuthorityVersionToken::from_opaque_bytes([0xAA; 16]);
    assert_eq!(
        store
            .compare_exchange_head(&key, forged, generation(2), b"head-2")
            .expect_err("a forged token must be refused"),
        AuthorityFailure::Refused(AuthorityRefusal::UnknownVersionToken)
    );

    // And a forged receipt does not authenticate.
    let receipt = HeadReadReceipt::new(key, forged, generation(1), b"head-1".to_vec());
    assert_eq!(
        store
            .authenticate_head_receipt(&receipt)
            .expect_err("a forged receipt must be refused"),
        AuthorityFailure::Refused(AuthorityRefusal::UnknownVersionToken)
    );

    store.close().expect("closes");
}

#[test]
fn a_generation_that_does_not_advance_is_refused_even_with_the_current_token() {
    // Holding the current token is not sufficient. The anti-rollback condition
    // is part of the UPDATE, so a candidate that would move the head backwards
    // is refused rather than silently winning.
    let node = deterministic_node();
    let store = BlockingStore::open(&node, StoreInstanceId::from_raw(1));
    let key = head_key();

    let HeadInit::Created(first) = store
        .initialize_head(&key, generation(7), b"head-7")
        .expect("no failure")
    else {
        panic!("the first initialization must create the slot");
    };

    let failure = store
        .compare_exchange_head(&key, first.token(), generation(7), b"sideways")
        .expect_err("an equal generation does not advance the head");
    assert_eq!(
        failure,
        AuthorityFailure::Refused(AuthorityRefusal::NonMonotoneGeneration {
            current: generation(7),
            proposed: generation(7),
        })
    );
    assert!(
        failure.proves_no_effect(),
        "a refusal must promise the store applied nothing"
    );

    store.close().expect("closes");
}

#[test]
fn tokens_survive_reopening_because_the_ledger_is_the_counter() {
    // The next issuance sequence is a function of the committed ledger rather
    // than of process memory, so nothing is lost by a kill and nothing is
    // reused by a reopen. An in-memory database cannot be reopened, so this
    // asserts the property that makes that true: successive tokens differ, and
    // each one is recorded.
    let node = deterministic_node();
    let store = BlockingStore::open(&node, StoreInstanceId::from_raw(9));
    let key = head_key();

    let HeadInit::Created(first) = store
        .initialize_head(&key, generation(1), b"head-1")
        .expect("no failure")
    else {
        panic!("the first initialization must create the slot");
    };
    let CasOutcome::Committed(second) = store
        .compare_exchange_head(&key, first.token(), generation(2), b"head-2")
        .expect("no failure")
    else {
        panic!("the exchange must commit");
    };

    assert_ne!(
        first.token(),
        second.token(),
        "a per-write token that repeated would reopen the ABA hole it exists to close"
    );
    // Both are genuine: the ledger recorded each one as it was used.
    store
        .authenticate_head_receipt(&first)
        .expect("the superseded token was issued");
    store
        .authenticate_head_receipt(&second)
        .expect("the current token was issued");

    store.close().expect("closes");
}

/// How many checks `run_capacity_conformance` records: CAP-00..CAP-06.
const CAP_CHECK_COUNT: usize = 7;

#[test]
fn the_capacity_conformance_campaign_passes_against_the_engine() {
    // `frankengit-jyhk`. This backend is the one `frankengit-nv0a` was found in:
    // it published four ceilings through `limits()` and enforced one, and the
    // AC suite stayed green over it because AC-16 exercises `body_bytes`, the
    // single ceiling both backends already enforced.
    //
    // Opt-in, which is weaker than mandatory -- widening the AC factory to take
    // limits is the next-wave change that makes capacity unavoidable for every
    // backend. Until then, this call is the coverage, and a backend that never
    // adds one is exactly the backend that would carry the defect.
    let node = deterministic_node();
    let report = run_capacity_conformance(|instance, limits| {
        BlockingStore::open_with_limits(&node, instance, limits)
    });

    // Same non-vacuity discipline as the AC guard above: `is_pass()` is happiest
    // against a report that ran nothing.
    assert!(
        report.checks().len() >= CAP_CHECK_COUNT,
        "the capacity campaign must record at least {CAP_CHECK_COUNT} checks, got {}; a shrunken \
         campaign proves nothing about the backend",
        report.checks().len()
    );
    assert!(
        report.failures().next().is_none(),
        "the engine must enforce every ceiling it publishes; failures: {:?}",
        report.failed_ids()
    );
}
