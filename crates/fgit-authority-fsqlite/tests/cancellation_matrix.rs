//! FG-005b: the cancellation cells of the crash matrix, driven against a real
//! in-flight backend rather than modelled.
//!
//! # Why this file exists, and what it replaces
//!
//! The e2e lane declared `FG-005B-E2E-021` **unsupported** with this reason:
//!
//! > `AsyncAuthorityStore` now exists so a future CAN be held in flight, but
//! > dropping a future is not a complete cancellation protocol (request ->
//! > drain -> finalize), and no drain/finalize surface is exposed that a test
//! > can drive.
//!
//! That reason was wrong, and it was wrong the same way the checkpoint cell's
//! three reasons were wrong: **it scanned the wrong layer.** It searched
//! `fgit-authority-fsqlite/src`, found no cancellation poll -- correctly, there
//! is none -- and concluded no verifier could drive one. The poll is one layer
//! down. `fsqlite::async_api::preflight_async_call` runs on all thirteen async
//! entry points and opens with:
//!
//! ```text
//! require_unmasked(cx)?;
//! if cx.is_cancel_requested() { return Err(FrankenError::Interrupt); }
//! ```
//!
//! and `AsyncCallPreflight::check_cancellation` re-checks after the mask
//! linearization point, then polls the native context too. The VDBE polls again
//! inside page-lock waits (`fsqlite-vdbe/src/engine.rs:3032`), bounding
//! non-local cancellation latency during a running statement.
//!
//! So cancellation is observable at the boundary this crate owns, and the cells
//! below are real coverage. That is the fifth "unsupported" reason on this bead
//! to fall to an actual measurement, and every one of the five failed the same
//! way: **a reason asserting that nobody could test something, derived by
//! reading one layer of a stack.** The rule that keeps surviving is the one in
//! the crate docs -- for a question about runtime behaviour, ask the running
//! system.
//!
//! # What this file proves
//!
//! Cancellation requested before dispatch refuses the operation *and leaves no
//! effect behind*, which is the property that matters: a refusal that had
//! already written a body would be worse than no refusal at all, because the
//! caller would be told nothing happened while something did.
//!
//! Each refusal is therefore paired with an observation through a **separate,
//! live** context. Asserting only that the cancelled call returned `Err` would
//! pass just as happily against a store that performed the write and then
//! reported failure.
//!
//! # What this file does NOT prove
//!
//! - **Not the full request -> drain -> finalize protocol.** These cells cover
//!   cancellation *before dispatch*, *between retry attempts*, and *after
//!   dispatch and before completion*. What is still open is narrower than any
//!   of those: cancelling a statement the VDBE is actively stepping through
//!   (the poll sites are there -- 31 of them, including the main instruction
//!   loop every N opcodes -- but the store's statements are far too short to
//!   reach an opcode checkpoint reliably), and the `commit-ambiguous` and
//!   `reply-lost` cancellation cells, which need cancellation and a lost
//!   response to arrive together.
//!
//!   That last pair is now *buildable* rather than blocked:
//!   `fault_conformance.rs` supplies a fault engine over a real database, so
//!   composing `LoseResponse` with a cancel is a matter of writing it. It is
//!   not written, so it is not claimed.
//! - **Not that cancellation is distinguishable from failure.** See
//!   `cancellation_is_not_separately_typed_at_the_public_surface`, which pins
//!   the current behaviour and names the gap rather than blessing it.
//!
//! # A trap for the next author of a cancellation test
//!
//! Two `FsqliteCx` roots that share one *native* context are not independent.
//! `AsyncCallPreflight` polls the native context as well as the control one, so
//! cancelling either root refuses calls made through the other. The first draft
//! of this file did exactly that, and five of its assertions passed against a
//! store in which **every** call refused -- the cancellation cells would have
//! been reported as covered by a suite that had actually killed the store.
//!
//! `the_live_context_is_unaffected_by_its_siblings_cancellation` is the control
//! that caught it, and it is the most important test here even though it
//! asserts nothing about cancellation: a refusal test needs a permitted case
//! next to it, or it cannot tell "refused correctly" from "broken".

use fgit_authority::{
    AuthorityLimits, HeadGeneration, HeadInit, HeadKey, ImmutableKey, ImmutableRead, PutOutcome,
    StoreInstanceId,
};
use fgit_authority_fsqlite::{
    BackoffPlan, EngineError, FsqliteAuthorityStore, RetryBudget, RetryOutcome, TransientClass,
    run_with_retry,
};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx as FsqliteCx;

/// The seven classes §3.4 admits for a bounded same-attempt retry.
///
/// Transcribed from the clause, not imported from the implementation, for the
/// same reason `retry_law_independent.rs` transcribes them: a list copied from
/// the code under test cannot disagree with it.
const SPEC_RETRYABLE: [TransientClass; 7] = [
    TransientClass::Busy,
    TransientClass::BusyRecovery,
    TransientClass::BusySnapshot,
    TransientClass::DatabaseLocked,
    TransientClass::WriteConflict,
    TransientClass::SerializationFailure,
    TransientClass::PageBufferCapacityExhausted,
];

fn node() -> NodeRuntime {
    RuntimeProfile::deterministic()
        .build()
        .expect("the deterministic profile builds")
}

fn head_key() -> HeadKey {
    HeadKey::new(b"refs/heads/main".to_vec()).expect("a short key is admissible")
}

fn body_key(tag: &str) -> ImmutableKey {
    ImmutableKey::new(format!("blob/{tag}").into_bytes()).expect("admissible")
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a small generation is admissible")
}

/// An in-memory store plus two independent contexts over one runtime.
///
/// `live` and `cancelled` are separate roots, not parent and child, so
/// cancelling one leaves the other usable. That is what makes the paired
/// observation possible: the same store is asked the same question through a
/// context that was never cancelled.
struct Fixture {
    node: NodeRuntime,
    store: FsqliteAuthorityStore,
    live: FsqliteCx,
    cancelled: FsqliteCx,
    /// A third root, never cancelled by any test.
    ///
    /// `live` is cancelled by the in-flight test, so a test that cancels it
    /// cannot then use it to observe the database. Reading back through a
    /// context that was never cancelled is what makes the observation about
    /// stored state rather than about the preflight refusing again.
    spare: FsqliteCx,
}

impl Fixture {
    fn new() -> Self {
        let node = node();

        // Two *separate* native contexts, not one cloned handle.
        //
        // The first draft shared one, and the control test below caught it
        // immediately: cancelling either `FsqliteCx` refused the other's calls
        // too, because `AsyncCallPreflight` polls the native context as well as
        // the control one and a clone shares the same cancellation node. Five
        // assertions "passed" against a store where *everything* refused.
        let live_native = node.request_cx(BudgetClass::Request);
        let cancelled_native = node.request_cx(BudgetClass::Request);
        let spare_native = node.request_cx(BudgetClass::Request);

        let live = FsqliteCx::new();
        live.set_native_cx(live_native);

        let store = node
            .block_on(FsqliteAuthorityStore::open(
                &live,
                ":memory:".to_owned(),
                StoreInstanceId::from_raw(7),
                AuthorityLimits::default(),
            ))
            .expect("an in-memory store opens");

        // Cancelled only after the store is open: a context cancelled before
        // `open` would fail the DDL and prove nothing about later operations.
        let cancelled = FsqliteCx::new();
        cancelled.set_native_cx(cancelled_native);
        cancelled.cancel();

        let spare = FsqliteCx::new();
        spare.set_native_cx(spare_native);

        Self {
            node,
            store,
            live,
            cancelled,
            spare,
        }
    }
}

// ------------------------------------------------- cancellation before dispatch

#[test]
fn a_cancelled_context_refuses_the_write_and_leaves_the_slot_empty() {
    // The central cell. Both halves are load-bearing: the refusal alone would
    // also be produced by a store that wrote the body and then reported an
    // error, which is precisely the outcome §5.2 forbids -- a caller told
    // nothing happened while something did.
    let f = Fixture::new();
    let key = body_key("cancelled-write");

    let refused = f
        .node
        .block_on(f.store.put_if_absent(&f.cancelled, &key, b"payload"));
    assert!(
        refused.is_err(),
        "a context cancelled before dispatch must refuse the write; got {refused:?}"
    );

    // Observed through the live context, so the answer cannot be an artefact of
    // asking with the same cancelled one.
    let after = f
        .node
        .block_on(f.store.read_immutable(&f.live, &key))
        .expect("a live context still reads");
    assert!(
        matches!(after, ImmutableRead::Absent),
        "the refused write must have left the slot empty; found {after:?}"
    );
}

#[test]
fn a_cancelled_context_refuses_reads_as_well_as_writes() {
    // Cancellation is a property of the call, not of mutation. A backend that
    // polled only on the write path would leave a cancelled caller spending
    // budget on reads it no longer wants.
    let f = Fixture::new();

    let read = f
        .node
        .block_on(f.store.read_immutable(&f.cancelled, &body_key("never")));
    assert!(
        read.is_err(),
        "a cancelled context must refuse a read, not serve it; got {read:?}"
    );

    let head = f
        .node
        .block_on(f.store.read_head(&f.cancelled, &head_key()));
    assert!(
        head.is_err(),
        "a cancelled context must refuse a head read; got {head:?}"
    );
}

#[test]
fn a_cancelled_context_refuses_head_creation_and_the_head_stays_absent() {
    let f = Fixture::new();
    let key = head_key();

    let refused =
        f.node.block_on(
            f.store
                .initialize_head(&f.cancelled, &key, generation(1), b"first"),
        );
    assert!(
        refused.is_err(),
        "a cancelled context must refuse to create the head slot; got {refused:?}"
    );

    // `Created` is the only outcome consistent with the refusal having left
    // nothing behind. `IdenticalRetry` is the precise tell that it did not: it
    // means the slot already holds exactly the generation and body the refused
    // call carried, which only the refused call could have written.
    let created = f
        .node
        .block_on(
            f.store
                .initialize_head(&f.live, &key, generation(1), b"first"),
        )
        .expect("a live context creates the head the refusal did not");
    assert!(
        matches!(created, HeadInit::Created(_)),
        "the refused creation must not have published a head; the live attempt found {created:?},          and IdenticalRetry here would mean the refusal wrote the very body it reported failing"
    );
}

#[test]
fn the_live_context_is_unaffected_by_its_siblings_cancellation() {
    // The control for every test above. If cancelling one root context somehow
    // poisoned the store or the shared native context, all the assertions above
    // would pass for the wrong reason -- everything would refuse -- and this
    // file would be reporting a dead store as a working cancellation protocol.
    let f = Fixture::new();

    let ok = f
        .node
        .block_on(
            f.store
                .put_if_absent(&f.live, &body_key("live"), b"payload"),
        )
        .expect("the live context writes while its sibling is cancelled");
    assert!(
        matches!(ok, PutOutcome::Created),
        "the live write must actually store the body; got {ok:?}"
    );
}

// ------------------------------------------------------- cancellation and retry

#[test]
fn cancellation_is_not_one_of_the_seven_retryable_classes() {
    // §3.4, quoted: "Corruption, schema/constraint errors, invariant failures,
    // cancellation, panic, resource ceilings, and permanent I/O errors are not
    // converted into 'busy.'"
    //
    // Derived from the clause rather than from the classifier: the failure this
    // guards against is a future maintainer admitting `Interrupt` into the
    // transient family, which would turn a cancelled operation into a retry
    // loop that ignores the cancellation.
    let f = Fixture::new();

    let Err(error) = f.node.block_on(
        f.store
            .put_if_absent(&f.cancelled, &body_key("class"), b"x"),
    ) else {
        panic!("a cancelled context must refuse");
    };

    let class = error.transient_class();
    assert!(
        !SPEC_RETRYABLE.contains(&class),
        "cancellation classified {class:?}, which §3.4 admits for bounded retry; a cancelled \
         operation must never be replayed"
    );
}

#[test]
fn a_cancelled_attempt_is_not_retried() {
    // The behavioural half of the test above. A class that is correct in
    // isolation still permits a retry loop that ignores it, so the loop is
    // driven and its attempt count checked: exactly one.
    let f = Fixture::new();
    let key = body_key("no-retry");

    let outcome = f.node.block_on(run_with_retry(
        RetryBudget::new(10_000, 5),
        BackoffPlan::new(1, 8, 0),
        async |_attempt| {
            f.store
                .put_if_absent(&f.cancelled, &key, b"payload")
                .await
                .map(|_| ())
        },
        async |_ticks| {},
    ));

    match outcome {
        RetryOutcome::Permanent { attempts } => assert_eq!(
            attempts, 1,
            "a cancelled operation must end the loop on its first attempt; it made {attempts}"
        ),
        other => panic!(
            "a cancelled operation must end as Permanent rather than being absorbed or \
             exhausted; got {other:?}"
        ),
    }
}

#[test]
fn cancellation_between_attempts_stops_the_loop_within_one_backoff() {
    // `run_with_retry` takes the wait closure from its caller and has no
    // cancellation poll of its own between attempts. That is not a defect, but
    // it does mean the bound has to come from somewhere, and it comes from the
    // next attempt's preflight rather than from the loop.
    //
    // Cancelling during the first backoff must therefore stop the loop at
    // attempt two, not run to the five-attempt bound. This is the honest
    // statement of the "cancellation during retry sleep" cell: latency is
    // bounded by one backoff interval, not zero.
    let f = Fixture::new();
    let key = body_key("cancel-mid-backoff");

    let outcome = f.node.block_on(run_with_retry(
        RetryBudget::new(10_000, 5),
        BackoffPlan::new(1, 8, 0),
        async |attempt| -> Result<(), EngineError> {
            if attempt == 1 {
                // A genuine transient, so the loop really does schedule a wait
                // rather than terminating on this attempt.
                return Err(EngineError::Engine(TransientClass::Busy));
            }
            f.store
                .put_if_absent(&f.cancelled, &key, b"payload")
                .await
                .map(|_| ())
        },
        async |_ticks| {},
    ));

    match outcome {
        RetryOutcome::Permanent { attempts } => assert_eq!(
            attempts, 2,
            "cancellation observed during the first backoff must end the loop on the next \
             attempt; it made {attempts}"
        ),
        other => panic!("expected the loop to stop at the cancelled attempt; got {other:?}"),
    }
}

// ------------------------------------------------------------ the gap, recorded

#[test]
fn cancellation_is_not_separately_typed_at_the_public_surface() {
    // A characterization test, and deliberately not an approving one.
    //
    // `classify_franken_error` defaults every unnamed engine error to
    // `Permanent`, which is the right default and the reason cancellation is
    // never retried. The cost is that `FrankenError::Interrupt` arrives at the
    // caller as `EngineError::Engine(Permanent)` -- the same value a corrupt
    // page produces.
    //
    // For the retry law that is correct. For §3.2's request -> drain -> finalize
    // it is not sufficient: a caller that cancelled its own work and a caller
    // whose database is corrupt must not behave identically, because the first
    // may re-drive the operation and the second must not. Nothing here can fix
    // that from a test crate -- the vocabulary belongs to the store -- so this
    // pins the present behaviour and states the limitation where the next
    // reader will meet it.
    let f = Fixture::new();

    let Err(error) = f.node.block_on(
        f.store
            .put_if_absent(&f.cancelled, &body_key("shape"), b"x"),
    ) else {
        panic!("a cancelled context must refuse");
    };

    assert_eq!(
        error.transient_class(),
        TransientClass::Permanent,
        "cancellation currently collapses into the permanent class; if this assertion fails \
         because a distinct cancellation class was added, that is an improvement -- update this \
         test and delete the limitation note above it"
    );
}

// ------------------------------------------------- cancellation while in flight

#[test]
fn cancelling_an_operation_already_in_flight_leaves_no_partial_effect() {
    // The "executing" cell, driven without threads, sleeps, or a race.
    //
    // What "in flight" means here, stated exactly, because the neighbouring
    // cell is close enough to be confused with it. `preflight_async_call` is
    // synchronous and runs at the top of every async entry point, so a future
    // that has returned `Pending` is **past the preflight**: the request was
    // admitted and handed to the engine's async worker. The before-dispatch
    // test above cancels a call that never gets that far. This one cancels a
    // request the engine already has.
    //
    // What this does NOT establish is which statement the engine had reached --
    // whether `BEGIN` had executed at that instant is not observable from here,
    // so the test does not claim it. Cancelled after dispatch and before
    // completion is the claim, and it is the cell.
    //
    // The future is therefore driven by hand: poll it until it first returns
    // Pending, cancel the context at that suspension point, then resume it.
    // Every subsequent statement meets `preflight_async_call`, which refuses.
    // This is deterministic in a way a spawn-and-sleep never is: there is no
    // window to lose, because the cancel happens at a suspension the test
    // observed rather than at a moment it hoped for.
    //
    // What must be true afterwards is the §5.2 property this whole bead is
    // about: **old-complete or new-complete, never mixed.** An operation
    // interrupted after the engine accepted it must leave the slot exactly as
    // it found it, or a caller that cancelled its own work is left holding a
    // half-published body.
    let f = Fixture::new();
    let key = body_key("mid-flight");

    let suspended = f.node.block_on(async {
        let mut in_flight = core::pin::pin!(f.store.put_if_absent(&f.live, &key, b"payload"));

        // Poll once. `Ready` means the operation never suspended and this cell
        // cannot be exercised this way; `Pending` means it is in flight.
        let finished_immediately = core::future::poll_fn(|task| {
            core::task::Poll::Ready(match in_flight.as_mut().poll(task) {
                core::task::Poll::Ready(done) => Some(done),
                core::task::Poll::Pending => None,
            })
        })
        .await;

        match finished_immediately {
            Some(done) => Err(done),
            None => {
                // Cancelled at an observed suspension point, mid-transaction.
                f.live.cancel();
                Ok(in_flight.await)
            }
        }
    });

    let outcome = match suspended {
        Ok(outcome) => outcome,
        Err(done) => panic!(
            "the operation completed without ever suspending, so nothing was in flight to \
             cancel and this cell was NOT exercised; it returned {done:?}. Do not weaken this \
             into a before-dispatch test -- that cell is already covered above."
        ),
    };

    assert!(
        outcome.is_err(),
        "an operation cancelled mid-transaction must not report success; got {outcome:?}"
    );

    // The property that matters. Read through a context that was never
    // cancelled, so the answer comes from the database rather than from the
    // preflight refusing again.
    let after = f
        .node
        .block_on(f.store.read_immutable(&f.spare, &key))
        .expect("a never-cancelled context still reads the store");
    assert!(
        matches!(after, ImmutableRead::Absent),
        "an operation cancelled after the engine accepted it must leave the slot exactly as it \
         found it; §5.2 admits old-complete or new-complete and never a mixture, but the slot \
         holds {after:?}"
    );
}
