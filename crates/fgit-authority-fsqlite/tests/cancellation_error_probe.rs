//! `frankengit-w1ik`: what does the engine actually return for a cancelled
//! operation, and can the store tell pre-effect from mid-effect?
//!
//! # Why this is a probe and not a design
//!
//! The bead says, in as many words, *measure before designing*. The tempting
//! design is a clean split:
//!
//! - `FrankenError::Interrupt` comes from `preflight_async_call`, which runs
//!   before the request is dispatched, so it is genuinely pre-effect and
//!   `Refused` is entitled to assert non-commit;
//! - `FrankenError::Abort` comes from the VDBE's `observe_execution_cancellation`
//!   and its page-lock branch, which run *inside* an executing statement, so the
//!   effect may have landed and `Ambiguous` is the honest answer.
//!
//! That split is real in the sense that those two functions really do return
//! those two values. **It is not usable as stated**, because `Abort` is not a
//! cancellation code: it is produced at 83 sites across `fsqlite-core`,
//! `fsqlite-vdbe`, `fsqlite-btree` and `fsqlite-pager`, the overwhelming
//! majority of which have nothing to do with cancellation. Classifying every
//! `Abort` as a cancelled mid-effect operation would relabel a large family of
//! ordinary engine failures as "may have committed", which is a different lie
//! in the opposite direction.
//!
//! So the question this file exists to answer is narrower and empirical:
//! **which `FrankenError` does a real cancelled operation actually produce, at
//! each of the two points, in this version?** The answer decides whether the
//! fix can split on the error alone, must consult the context, or must collapse
//! everything to `Ambiguous` with a typed non-claim.
//!
//! This is the same discipline that settled the journal-mode question after
//! three wrong readings: `journal_mode_probe.rs` asked `PRAGMA journal_mode`
//! rather than reasoning about defaults. Reading four layers of fsqlite to
//! predict an error value is exactly the move that has failed six times on this
//! bead.
//!
//! Nothing here asserts a design. It pins observations, and it fails loudly if
//! an observation stops holding.
//!
//! # THE ANSWER, measured
//!
//! **Both points produce `Interrupt`.** Not `Interrupt` before and `Abort`
//! after -- `Interrupt` for both. The hypothesised split does not exist at this
//! boundary, and a design built on reading `observe_execution_cancellation`
//! would have been wrong in the way six earlier readings on this bead were
//! wrong.
//!
//! The reason, once measured, is obvious in hindsight and was not obvious
//! before: **the cancel is caught on the client side, not inside the engine.**
//! A dispatched statement is awaited by the caller, and cancellation is
//! observed by that await. The VDBE's own poll sites only fire for work the
//! engine is still stepping through when the flag is already set. So the
//! ordinary mid-flight case never reaches them: the caller stops waiting while
//! the worker keeps going.
//!
//! That is also the mechanism behind `frankengit-w1ik`. The statement can
//! commit in the worker *after* the caller has been told `Interrupt`, which is
//! precisely the "reported ok=false while the database holds stored=true"
//! that `cancellation_matrix.rs` measures.
//!
//! # What follows for the fix
//!
//! The error value cannot carry the distinction, so the store must take it from
//! somewhere else, and it has exactly one honest source: **whether the context
//! was already cancelled when the operation began.**
//!
//! - cancelled on entry  -> the preflight refuses before dispatch, nothing can
//!   have taken effect, and `Refused` is entitled to assert non-commit;
//! - not cancelled on entry, `Interrupt` on exit -> the cancel arrived after
//!   the request was dispatched, the effect may have landed, and `Ambiguous` is
//!   the only answer §5.2 permits.
//!
//! The race between that entry check and the preflight's own check resolves in
//! the safe direction: a cancel landing in between is reported `Ambiguous` when
//! it was really pre-effect, which costs the caller one exact-key read and
//! never asserts a false non-commit.

use asupersync::cx::Cx as NativeCx;
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite::{AsyncConnection, FrankenError};
use fsqlite_types::cx::Cx as FsqliteCx;

fn node() -> NodeRuntime {
    RuntimeProfile::deterministic()
        .build()
        .expect("the deterministic profile builds")
}

/// A context with its own cancellation node.
fn context(node: &NodeRuntime) -> (FsqliteCx, NativeCx) {
    let native = node.request_cx(BudgetClass::Request);
    let cx = FsqliteCx::new();
    cx.set_native_cx(native.clone());
    (cx, native)
}

/// The variant name of an error, so observations read as data rather than as a
/// `Debug` blob whose shape can drift.
const fn variant_of(error: &FrankenError) -> &'static str {
    match error {
        FrankenError::Interrupt => "Interrupt",
        FrankenError::Abort => "Abort",
        FrankenError::Busy => "Busy",
        _ => "other",
    }
}

#[test]
fn cancelling_before_dispatch_produces_interrupt() {
    // The pre-effect point. `preflight_async_call` checks `is_cancel_requested`
    // before anything is sent, so this is the one case where a refusal really
    // is entitled to assert non-commit.
    let node = node();
    let (open_cx, _open_native) = context(&node);
    let connection = node
        .block_on(AsyncConnection::open(&open_cx, ":memory:"))
        .expect("an in-memory connection opens");

    let (cx, _native) = context(&node);
    cx.cancel();

    let error = node
        .block_on(connection.execute(&cx, "CREATE TABLE probe(id INTEGER PRIMARY KEY)"))
        .expect_err("a cancelled context must refuse before dispatch");

    assert_eq!(
        variant_of(&error),
        "Interrupt",
        "a cancel observed by the preflight must surface as Interrupt, or the pre-effect case \
         cannot be told apart from the mid-effect one by error value; got {error:?}"
    );
}

#[test]
fn cancelling_after_dispatch_reports_what_this_file_exists_to_record() {
    // The mid-effect point, driven the same way `cancellation_matrix.rs` drives
    // it: poll until the future first suspends -- which means the preflight has
    // already passed and the engine holds the request -- then cancel, then
    // resume.
    //
    // The observation is printed and pinned rather than predicted. If this is
    // `Interrupt`, the two points are NOT separable by error value and the fix
    // must consult the context or collapse to Ambiguous. If it is `Abort`, they
    // are separable in principle, but only in combination with the context,
    // since Abort alone means many other things.
    let node = node();
    let (open_cx, _open_native) = context(&node);
    let connection = node
        .block_on(AsyncConnection::open(&open_cx, ":memory:"))
        .expect("an in-memory connection opens");
    node.block_on(connection.execute(&open_cx, "CREATE TABLE probe(id INTEGER PRIMARY KEY)"))
        .expect("the table is created");

    let (cx, _native) = context(&node);

    let observed = node.block_on(async {
        let mut in_flight =
            core::pin::pin!(connection.execute(&cx, "INSERT INTO probe(id) VALUES (1)"));

        let immediate = core::future::poll_fn(|task| {
            core::task::Poll::Ready(match in_flight.as_mut().poll(task) {
                core::task::Poll::Ready(done) => Some(done),
                core::task::Poll::Pending => None,
            })
        })
        .await;

        match immediate {
            Some(done) => Err(done),
            None => {
                cx.cancel();
                Ok(in_flight.await)
            }
        }
    });

    let outcome = match observed {
        Ok(outcome) => outcome,
        Err(done) => panic!(
            "the statement never suspended, so nothing was dispatched to cancel and this probe \
             measured the before-dispatch case by accident; it returned {done:?}"
        ),
    };

    match outcome {
        Ok(rows) => {
            // Also a real answer: the cancel lost the race and the statement
            // committed. That is not a defect, and §5.2 is precisely about a
            // caller being unable to assume otherwise.
            println!(
                "PROBE after-dispatch cancel: completed successfully, {rows} row(s) (cancel lost the race)"
            );
        }
        Err(error) => {
            println!(
                "PROBE after-dispatch cancel: variant={} debug={error:?}",
                variant_of(&error)
            );
            // Pinned, because the whole w1ik design rests on it: the
            // after-dispatch cancel produces the SAME value as the
            // before-dispatch one. If this ever becomes `Abort`, the two points
            // have become separable by error value and the fix can be
            // simplified -- but only then, and only by someone who re-ran this.
            assert_eq!(
                variant_of(&error),
                "Interrupt",
                "measured behaviour changed: an after-dispatch cancel used to return Interrupt, \
                 the same value as a before-dispatch one, which is why the store must consult the \
                 context rather than the error. It now returns {error:?}. Re-derive the w1ik \
                 mapping before trusting it"
            );
        }
    }
}
