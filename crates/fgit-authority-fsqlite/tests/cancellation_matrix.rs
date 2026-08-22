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
//!   reach an opcode checkpoint reliably; reaching it needs sustained page-lock
//!   contention, which nothing here builds). That is now the ONLY open clause.
//!
//!   **This list used to include `reply-lost`, and that was wrong too.** At
//!   this boundary it is not a distinct cell: the probe measures that a cancel
//!   is caught by the *caller await*, not inside the engine, so cancelling a
//!   dispatched operation simply IS abandoning its reply. The with-cancel
//!   variant is the sweep below; the without-cancel variant is
//!   `fault_conformance.rs`'''s `LoseResponse`, which passes. Their conjunction
//!   produces no observable the store can tell apart from either one.
//!
//!   **This list used to include `commit-ambiguous`, and that was wrong.** It
//!   is not unwritten: the sweep below cancels at `scale - 1`, the window after
//!   the commit has gone through, which IS that cell -- and it is the position
//!   that exposed `frankengit-w1ik`. So commit-ambiguous is written and
//!   *defect-blocked*, which is a different state from unbuilt and belongs to a
//!   different lane cell. The verdict on this paragraph was right and the
//!   reason inside it was wrong; it was caught only because the clause had been
//!   labelled an unverified assertion rather than left to look measured.
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
    AmbiguityReason, AuthorityFailure, AuthorityLimits, HeadGeneration, HeadInit, HeadKey,
    ImmutableKey, ImmutableRead, PutOutcome, StoreInstanceId,
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

// -------------------------------------------------------- the gap, now closed

#[test]
fn cancellation_is_separately_typed_and_never_asserts_non_commit() {
    // This was a characterization test pinning a defect, and it said of its own
    // assertion: "if this assertion fails because a distinct cancellation class
    // was added, that is an improvement -- update this test". It failed for
    // exactly that reason. `frankengit-w1ik`.
    //
    // What it used to pin: `FrankenError::Interrupt` fell through
    // `classify_franken_error`'s default to `Permanent` and reached the caller
    // as `Refused(Unavailable)` -- the same value a corrupt page produces. Two
    // separate faults. A caller that cancelled its own work may re-drive and
    // one holding a corrupt database must not, and they could not tell which
    // they held; and `Refused` asserts in this vocabulary that nothing was
    // applied, which §5.2 forbids for cancellation.
    //
    // Both halves are asserted below, because the second is the constitutional
    // one and would still be broken if only the class had been split.
    let f = Fixture::new();

    let Err(error) = f.node.block_on(
        f.store
            .put_if_absent(&f.cancelled, &body_key("shape"), b"x"),
    ) else {
        panic!("a cancelled context must not report success");
    };

    assert_eq!(
        error.transient_class(),
        TransientClass::Cancelled,
        "cancellation must carry its own class; collapsing it into Permanent is what made it \
         indistinguishable from a corrupt page"
    );

    assert!(
        matches!(
            error.into_failure(),
            AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled)
        ),
        "a cancelled operation must reach the caller as AMBIGUOUS, never as a refusal: §5.2 says \
         client cancellation never proves non-commit, and a late cancel really can land after the \
         commit -- see no_cancellation_position_leaves_a_mixture"
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

/// How many times `put_if_absent` returns `Pending` before it completes.
///
/// Measured rather than assumed. The first version of the sweep below guessed
/// twelve and every position behaved identically, because re-polling a future
/// that is waiting on the engine's worker thread does not advance it -- it
/// spins. The count is therefore a busy-wait length, it varies between runs,
/// and it is only useful as a *scale* for spreading cancellations across the
/// operation's real duration.
fn suspensions_before_completion() -> usize {
    let f = Fixture::new();
    let key = body_key("calibrate");
    f.node.block_on(async {
        let mut in_flight = core::pin::pin!(f.store.put_if_absent(&f.live, &key, b"payload"));
        let mut spins = 0_usize;
        loop {
            let step = core::future::poll_fn(|task| {
                core::task::Poll::Ready(match in_flight.as_mut().poll(task) {
                    core::task::Poll::Ready(value) => Some(value),
                    core::task::Poll::Pending => None,
                })
            })
            .await;
            if step.is_some() {
                return spins;
            }
            spins = spins.saturating_add(1);
            assert!(
                spins < 5_000_000,
                "the operation never completed under a busy poll; the harness cannot calibrate"
            );
        }
    })
}

/// What the caller was told about one cancelled operation.
///
/// Three-valued on purpose. This was a boolean until `frankengit-w1ik` was
/// fixed, and the boolean was itself an instance of the bug: it forced every
/// non-success into "did not happen", which is exactly the claim §5.2 says a
/// cancellation is not entitled to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reported {
    /// The store said the operation committed.
    Committed,
    /// The store declined to say, and the caller must resolve by reading.
    Unknown,
    /// The store asserted the operation did not take effect.
    DidNotHappen,
}

/// Run one `put_if_absent`, cancelling once it has suspended `spins` times.
///
/// Returns what the caller was told, and what the database actually holds
/// afterwards read through a context no test ever cancels.
fn cancel_after_spins(spins: usize) -> (Reported, bool) {
    let f = Fixture::new();
    let key = body_key("sweep");

    let reported = f.node.block_on(async {
        let mut in_flight = core::pin::pin!(f.store.put_if_absent(&f.live, &key, b"payload"));
        let mut done = None;

        for _ in 0..spins {
            let step = core::future::poll_fn(|task| {
                core::task::Poll::Ready(match in_flight.as_mut().poll(task) {
                    core::task::Poll::Ready(value) => Some(value),
                    core::task::Poll::Pending => None,
                })
            })
            .await;
            if let Some(value) = step {
                done = Some(value);
                break;
            }
        }

        let outcome = match done {
            // Completed before the cancellation position was reached. Not a
            // cancellation observation at all, and classified as such.
            Some(value) => value,
            None => {
                f.live.cancel();
                in_flight.await
            }
        };

        // Classified through `into_failure`, the mapping the published
        // `AsyncAuthorityStore` impl applies, so this reads the answer a real
        // caller receives rather than an internal one.
        match outcome {
            Ok(_) => Reported::Committed,
            Err(error) => match error.into_failure() {
                AuthorityFailure::Ambiguous(_) => Reported::Unknown,
                AuthorityFailure::Refused(_) => Reported::DidNotHappen,
            },
        }
    });

    let stored = matches!(
        f.node
            .block_on(f.store.read_immutable(&f.spare, &key))
            .expect("a never-cancelled context still reads the store"),
        ImmutableRead::Present(_)
    );

    (reported, stored)
}

#[test]
fn no_cancellation_position_makes_a_claim_the_database_contradicts() {
    // This test found `frankengit-w1ik` and was parked red until it was fixed.
    //
    // What it measured: at late cancellation positions the store reported
    //
    //     ok=false   while the database holds   stored=true
    //
    // -- "after 1335 of about 1525 suspensions", and again at 1526 of about
    // 1743. A cancel landing once the commit had gone through returned
    // `Refused(Unavailable)`, and `Refused` asserts in this vocabulary that
    // nothing was applied, which §5.2 forbids for cancellation. BoldIbis fixed
    // it in the store at 6e9a559; cancellation now answers
    // `Ambiguous(Cancelled)`.
    //
    // It failed intermittently, because the defect needs the cancel to land
    // after the commit and how many busy-poll spins that takes depends on
    // machine load. Run alone the target passed five times running; run beside
    // one other test binary it failed three times in six. **A flakiness check
    // that does not reproduce the real execution environment is not a flakiness
    // check** -- this one would have relabelled a P1 as noise, and the "fix"
    // would have been loosening the assertion.
    //
    // # Why the assertion is three-valued now, and why that is not a weakening
    //
    // It compared two booleans, reported-ok against stored. **That boolean was
    // itself an instance of the bug**: it forced every non-success into "did
    // not happen". `Ambiguous` is a third answer and a correct one -- a store
    // that says "I do not know, go and read" contradicts nothing.
    //
    // So the rule is now that a store may claim committed, claim
    // not-committed, or decline to claim, and only a CLAIM can be contradicted.
    // Both definite answers are checked exactly as before; the third was
    // previously being scored as a failure it never was. Do not relax it to
    // make the suite green -- that is RH-1, and the point of this whole file
    // is that the words must not outrun the measurement.
    //
    // §5.2's no-mixed-state rule, checked at cancellation points spread across
    // the operation's whole duration rather than at one convenient instant.
    //
    // The single-point test above cancels at the first suspension. This one
    // calibrates against a measured busy-wait length and cancels at fractions
    // of it, including immediately before completion -- the position most
    // likely to catch a store that has committed and is about to report it.
    // At every position the answer the caller was given must match what the
    // database holds.
    let scale = suspensions_before_completion();
    assert!(
        scale > 0,
        "the operation completed without ever suspending, so there is no in-flight window to \
         sweep and this test is not exercising what it claims"
    );

    let positions = [
        1,
        scale / 8,
        scale / 4,
        scale / 2,
        scale.saturating_sub(scale / 8),
        scale.saturating_sub(1),
    ];

    let mut interrupted = 0_usize;
    for position in positions {
        if position == 0 {
            continue;
        }
        let (reported, stored) = cancel_after_spins(position);
        match reported {
            Reported::Committed => assert!(
                stored,
                "cancelling after {position} of about {scale} suspensions reported COMMITTED and \
                 the body is not in the database; a success that did not happen is the worst of \
                 the three mixtures"
            ),
            Reported::DidNotHappen => assert!(
                !stored,
                "cancelling after {position} of about {scale} suspensions asserted the operation \
                 DID NOT HAPPEN while the body is in the database. This is frankengit-w1ik \
                 regressing: §5.2 says client cancellation never proves non-commit, so a \
                 cancelled operation whose outcome the store cannot establish must be Ambiguous, \
                 never Refused"
            ),
            // No claim, nothing to contradict. §5.2's remedy is then exercised
            // rather than assumed: the caller resolves by exact-key read, which
            // is the `stored` observation above, taken through a context that
            // was never cancelled.
            Reported::Unknown => {}
        }
        if reported != Reported::Committed {
            interrupted += 1;
        }
    }

    assert!(
        interrupted > 0,
        "no position actually interrupted the operation, so the checks above are trivial"
    );
}

// ---------------------------------------------------- what the sweep does not say
//
// The sweep never exhibits a cancellation that arrives after the commit and is
// then reported as a success, because the only way there with this harness is to
// let the operation finish -- and an operation that finished was not cancelled.
//
// Before `frankengit-w1ik` that gap invited the wrong inference, since every
// cancellation here ended with the body absent and a reader could have concluded
// that cancellation implies non-commit. It no longer does: the store answers
// `Ambiguous(Cancelled)`, so it declines to make the claim the reader would have
// generalised from. §5.2's rule is now enforced by the store rather than merely
// unviolated by these positions.
//
// > Client cancellation/disconnect never proves non-commit.
//
// What remains unexercised is a cancel and a lost response arriving together.
// `fault_conformance.rs` has the fault engine, so it is buildable -- but the
// probe shows a cancel is caught by the caller's await, which IS abandoning the
// reply, so the conjunction produces no observable the store can distinguish
// from either half alone. Not written, and not claimed.
