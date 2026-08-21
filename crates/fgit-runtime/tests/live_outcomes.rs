//! All four `Outcome` arms, produced by the runtime rather than by the test.
//!
//! The adapter in `fgit_runtime::adapter` claims to keep Asupersync's
//! four-valued `Outcome` distinct across the service boundary. Until now that
//! claim was tested by writing `Outcome::Cancelled(..)` and
//! `Outcome::Panicked(..)` directly in the test body and checking that the
//! adapter moved them across unchanged. An independent audit named that for
//! what it is: the adapter was verified against values the test invented, so
//! it proved the `match` arms were spelled correctly and nothing else.
//!
//! What it did not prove is the part that matters — that the runtime ever
//! produces those arms, and that the ones it produces carry what the adapter
//! expects. A cancelled task's `CancelReason` and a contained panic's
//! `PanicPayload` are built by Asupersync, not by this crate, and a hand-built
//! stand-in cannot tell you whether the real ones survive the trip.
//!
//! So every outcome asserted here is produced by a live node: real tasks
//! spawned on a real runtime through `resolve_batch`'s `JoinSet`, really
//! completing, really failing, really panicking, and really being cancelled.
//! The test supplies the *behaviour* that provokes each arm; the runtime
//! decides which arm results.
//!
//! `fgit_runtime::demo`'s own tests already cover the `Ok` and `Err` arms this
//! way — and assert `cancelled == 0, panicked == 0`, which is precisely the
//! hole this file fills.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::Outcome;
use asupersync::combinator::JoinSet;
use asupersync::cx::Cx;
use asupersync::runtime::yield_now;
use asupersync::types::policy::FailFast;

use fgit_runtime::adapter::{CommitAmbiguity, OutcomeClass, ServiceOutcome};
use fgit_runtime::boot::RuntimeProfile;
use fgit_runtime::demo::{BatchSummary, ResolveError, Resolved, resolve_batch};
use fgit_runtime::meter::BudgetClass;

/// A resolver that panics on one specific name and resolves everything else.
///
/// The panic is a real one in real service code — the thing a contained panic
/// is supposed to be — not an `Outcome::Panicked` value written by the test.
async fn panicking_resolver(name: String) -> Result<Resolved, ResolveError> {
    assert!(
        name != "refs/heads/poison",
        "demonstration service panicked while resolving a poisoned reference"
    );
    Ok(Resolved {
        name,
        target: "0f1e2d3c4b5a69788796a5b4c3d2e1f009182736".to_owned(),
    })
}

#[test]
fn a_panicking_service_yields_a_runtime_produced_panicked_outcome() {
    let node = RuntimeProfile::deterministic().build().expect("builds");
    let cx = node.request_cx(BudgetClass::Request);

    let outcomes = node
        .block_on(async {
            resolve_batch(
                &cx,
                8,
                vec![
                    "refs/heads/main".to_owned(),
                    "refs/heads/poison".to_owned(),
                    "refs/heads/dev".to_owned(),
                ],
                panicking_resolver,
            )
            .await
        })
        .expect("the batch is within the admission bound");

    let summary = BatchSummary::of(&outcomes);
    assert_eq!(summary.total(), 3);

    // The runtime contained the panic and reported it as its own arm: it did
    // not unwind the batch, and it did not degrade into a domain error.
    assert_eq!(
        summary.panicked, 1,
        "the runtime must report the panicking member as Panicked, got {summary:?}"
    );
    assert_eq!(
        summary.succeeded, 2,
        "a panic in one member must not disturb its siblings, got {summary:?}"
    );
    assert_eq!(summary.refused, 0);
    assert_eq!(summary.cancelled, 0);

    // The payload is Asupersync's, carrying the message the service panicked
    // with — evidence this arm came from the runtime and not from the test.
    let payload = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            ServiceOutcome::Panicked(payload) => Some(format!("{payload:?}")),
            _ => None,
        })
        .expect("one member panicked");
    assert!(
        payload.contains("poisoned reference"),
        "the contained panic must carry the service's own message, got {payload}"
    );

    drop(cx);
    assert!(node.join_root(Duration::from_secs(5)));
}

#[test]
fn a_cancelled_task_yields_a_runtime_produced_cancelled_outcome() {
    // Cancellation cannot be provoked through `resolve_batch`, which joins its
    // members to completion by construction. So this drives the same primitive
    // `resolve_batch` uses — a bounded `JoinSet` in a child scope — and asks
    // the runtime to cancel it. The `CancelReason` is the runtime's.
    // Several workers, because this test needs the members to be *running*
    // before they are cancelled. The single-worker deterministic profile
    // admits them but need not have dispatched them yet, and cancelling a
    // member that has not begun proves less than cancelling one that has.
    let node = RuntimeProfile::production(4).build().expect("builds");
    let cx = node.request_cx(BudgetClass::Request);

    let started = Arc::new(AtomicUsize::new(0));

    let outcomes: Vec<Outcome<u32, ResolveError>> = node.block_on({
        let started = Arc::clone(&started);
        async move {
            let scope = cx.scope();
            let mut set: JoinSet<'_, u32, ResolveError, FailFast> = JoinSet::new(&scope);

            for _ in 0u32..3 {
                let started = Arc::clone(&started);
                set.spawn(&cx, move |member_cx: Cx| async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    // No success path exists: the only way out of this loop is
                    // the cancellation checkpoint. So an `Ok` in the outcomes
                    // below could not have come from the member finishing.
                    loop {
                        // A service that never reaches a checkpoint cannot be
                        // cancelled cooperatively, and `cancel_all` would block
                        // draining it forever. This is the profile's
                        // "request -> drain -> finalize", not a dropped future.
                        if member_cx.checkpoint().is_err() {
                            return Err(ResolveError::Unknown("cancelled".to_owned()));
                        }
                        yield_now().await;
                    }
                })
                .expect("the node admits the members");
            }

            // Every member must be live before cancellation is meaningful:
            // cancelling a member that never started proves nothing.
            //
            // The bound is generous rather than tight because "has the worker
            // dispatched this task yet" is a scheduling question, not a
            // correctness one — a handful of yields is a race, and losing it
            // would fail the test for the wrong reason. It stays bounded so a
            // member that genuinely never starts fails loudly instead of
            // hanging the suite.
            for _ in 0..100_000 {
                if started.load(Ordering::SeqCst) == 3 {
                    break;
                }
                yield_now().await;
            }
            assert_eq!(
                started.load(Ordering::SeqCst),
                3,
                "all three members must be running before they are cancelled"
            );

            set.cancel_all(&cx).await
        }
    });

    assert_eq!(outcomes.len(), 3, "every member must be accounted for");

    // Lift the runtime's own outcomes through the adapter under test.
    let lifted: Vec<ServiceOutcome<u32, ResolveError>> = outcomes
        .into_iter()
        .map(ServiceOutcome::from_outcome)
        .collect();

    for outcome in &lifted {
        assert_eq!(
            outcome.classify(),
            OutcomeClass::Cancelled,
            "a cancelled member must stay Cancelled across the boundary, got {outcome:?}"
        );
        // Cancellation is not a domain error and not a success.
        assert!(outcome.clone().success().is_none());
    }

    assert!(node.join_root(Duration::from_secs(5)));
}

#[test]
fn a_runtime_cancellation_after_an_observed_effect_carries_commit_ambiguity() {
    // The constitutional rule this crate exists to enforce (AGENTS.md 5.2):
    // client cancellation never proves non-commit. The previous test showed
    // the arm survives; this one shows the *ambiguity* survives with it, using
    // a cancellation the runtime produced rather than one written here.
    let node = RuntimeProfile::deterministic().build().expect("builds");
    let cx = node.request_cx(BudgetClass::Request);

    let outcomes: Vec<Outcome<u32, ResolveError>> = node.block_on(async move {
        let scope = cx.scope();
        let mut set: JoinSet<'_, u32, ResolveError, FailFast> = JoinSet::new(&scope);
        set.spawn(&cx, move |member_cx: Cx| async move {
            loop {
                if member_cx.checkpoint().is_err() {
                    return Err(ResolveError::Unknown("cancelled".to_owned()));
                }
                yield_now().await;
            }
        })
        .expect("the node admits the member");
        set.cancel_all(&cx).await
    });

    let cancelled = outcomes
        .into_iter()
        .next()
        .expect("the member produced an outcome");
    assert!(
        matches!(cancelled, Outcome::Cancelled(_)),
        "the runtime must report cancellation, got {cancelled:?}"
    );

    // A request whose effect was already in flight must not be reported as
    // "not committed" on the strength of a cancellation.
    let lifted = ServiceOutcome::from_outcome_after_effect(cancelled, "idem-7f3a-publish-head-v1");
    assert_eq!(lifted.classify(), OutcomeClass::Cancelled);
    assert_eq!(
        lifted.ambiguity(),
        Some(&CommitAmbiguity::Possible {
            idempotency_key: "idem-7f3a-publish-head-v1".to_owned(),
        }),
        "a cancellation after an observed effect must carry the resolving key"
    );

    assert!(node.join_root(Duration::from_secs(5)));
}
