//! Drop is not close, drop is not rollback, and cancellation at commit is not a refusal.

use fgit_authority_fsqlite::{
    CANCELLATION_PHASES, CancellationOutcome, CancellationPhase, LifecycleError, TransactionEvent,
    TransactionState, WorkerEvent, WorkerState,
};

const WORKER_STATES: [WorkerState; 5] = [
    WorkerState::Open,
    WorkerState::Draining,
    WorkerState::Closed,
    WorkerState::AbandonedByDrop,
    WorkerState::ContainmentFailure,
];

const WORKER_EVENTS: [WorkerEvent; 4] = [
    WorkerEvent::DrainRequested,
    WorkerEvent::CloseCompleted,
    WorkerEvent::JoinTimedOut,
    WorkerEvent::Dropped,
];

const TRANSACTION_STATES: [TransactionState; 5] = [
    TransactionState::Begun,
    TransactionState::Committed,
    TransactionState::RolledBack,
    TransactionState::CommitAmbiguous,
    TransactionState::AbandonedByDrop,
];

const TRANSACTION_EVENTS: [TransactionEvent; 4] = [
    TransactionEvent::CommitAwaited,
    TransactionEvent::RollbackAwaited,
    TransactionEvent::CancelledDuringCommit,
    TransactionEvent::Dropped,
];

#[test]
fn the_request_drain_finalize_path_reaches_closed() {
    let draining = WorkerState::Open
        .apply(WorkerEvent::DrainRequested)
        .expect("a drain may be requested on an open worker");
    assert_eq!(draining, WorkerState::Draining);

    let closed = draining
        .apply(WorkerEvent::CloseCompleted)
        .expect("an awaited close after a drain closes the worker");
    assert_eq!(closed, WorkerState::Closed);
    assert!(closed.proves_quiescent());
}

#[test]
fn dropping_a_worker_never_reaches_closed() {
    // The whole point of the profile's rule: the backstop may release
    // everything, but nothing observed it, so it is not the same state.
    for state in [WorkerState::Open, WorkerState::Draining] {
        let dropped = state
            .apply(WorkerEvent::Dropped)
            .expect("a live worker can be dropped");
        assert_eq!(dropped, WorkerState::AbandonedByDrop);
        assert_ne!(dropped, WorkerState::Closed);
        assert!(
            !dropped.proves_quiescent(),
            "Drop-triggered cleanup cannot prove quiescent shutdown"
        );
    }
}

#[test]
fn closed_is_reachable_only_by_an_awaited_close_after_a_drain() {
    // Exhaustive: enumerate every (state, event) pair and check that the only
    // ones landing in Closed are the intended one. A new event that
    // accidentally reached Closed would fail here rather than in production.
    let mut reaching_closed = Vec::new();
    for state in WORKER_STATES {
        for event in WORKER_EVENTS {
            if state.apply(event) == Ok(WorkerState::Closed) {
                reaching_closed.push((state, event));
            }
        }
    }
    assert_eq!(
        reaching_closed,
        vec![(WorkerState::Draining, WorkerEvent::CloseCompleted)],
        "exactly one transition may prove quiescence"
    );
}

#[test]
fn closing_without_draining_first_is_refused() {
    let refusal = WorkerState::Open
        .apply(WorkerEvent::CloseCompleted)
        .expect_err("closing an open worker would abandon its in-flight commands");
    assert_eq!(
        refusal,
        LifecycleError::NotApplicable {
            state: "open",
            event: "close_completed"
        }
    );
}

#[test]
fn a_join_that_times_out_is_reported_rather_than_swallowed() {
    for state in [WorkerState::Open, WorkerState::Draining] {
        let failed = state
            .apply(WorkerEvent::JoinTimedOut)
            .expect("a join may time out");
        assert_eq!(failed, WorkerState::ContainmentFailure);
        assert!(
            !failed.proves_quiescent(),
            "a worker that did not come back may still hold a thread or descriptor"
        );
    }
}

#[test]
fn every_terminal_worker_state_refuses_every_further_event() {
    for state in WORKER_STATES.into_iter().filter(|s| s.is_terminal()) {
        for event in WORKER_EVENTS {
            assert_eq!(
                state.apply(event),
                Err(LifecycleError::AlreadyTerminal {
                    state: state.as_str()
                }),
                "{state:?} accepted {event:?} after becoming terminal"
            );
        }
    }
}

#[test]
fn only_an_awaited_rollback_is_abort_evidence() {
    let rolled_back = TransactionState::Begun
        .apply(TransactionEvent::RollbackAwaited)
        .expect("a begun transaction may be rolled back");
    assert!(rolled_back.proves_abort());

    let dropped = TransactionState::Begun
        .apply(TransactionEvent::Dropped)
        .expect("a begun transaction may be dropped");
    assert_eq!(dropped, TransactionState::AbandonedByDrop);
    assert!(
        !dropped.proves_abort(),
        "Drop rollback is deferred cleanup, not successful abort evidence"
    );
    assert!(
        dropped.requires_outcome_lookup(),
        "an abandoned transaction leaves an outcome that has to be looked up"
    );
}

#[test]
fn a_cancelled_commit_is_ambiguous_and_never_an_abort() {
    let ambiguous = TransactionState::Begun
        .apply(TransactionEvent::CancelledDuringCommit)
        .expect("a commit may be cancelled in flight");
    assert_eq!(ambiguous, TransactionState::CommitAmbiguous);
    assert!(
        !ambiguous.proves_abort(),
        "the commit may have applied; calling it an abort would be a lie about canonical state"
    );
    assert!(ambiguous.requires_outcome_lookup());
}

#[test]
fn an_awaited_commit_needs_no_lookup() {
    let committed = TransactionState::Begun
        .apply(TransactionEvent::CommitAwaited)
        .expect("a begun transaction may commit");
    assert!(!committed.requires_outcome_lookup());
    assert!(!committed.proves_abort());

    let rolled_back = TransactionState::Begun
        .apply(TransactionEvent::RollbackAwaited)
        .expect("or roll back");
    assert!(
        !rolled_back.requires_outcome_lookup(),
        "an awaited finalizer is its own evidence"
    );
}

#[test]
fn every_terminal_transaction_state_refuses_every_further_event() {
    for state in TRANSACTION_STATES.into_iter().filter(|s| s.is_terminal()) {
        for event in TRANSACTION_EVENTS {
            assert_eq!(
                state.apply(event),
                Err(LifecycleError::AlreadyTerminal {
                    state: state.as_str()
                }),
                "{state:?} accepted {event:?} after becoming terminal"
            );
        }
    }
}

#[test]
fn a_begun_transaction_accepts_every_finalizer_exactly_once() {
    for event in TRANSACTION_EVENTS {
        let after = TransactionState::Begun
            .apply(event)
            .expect("every event applies to a begun transaction");
        assert!(
            after.is_terminal(),
            "{event:?} must finalize the transaction"
        );
    }
}

#[test]
fn the_model_calls_pre_dispatch_effect_free_and_a_cancelled_commit_ambiguous() {
    // Renamed under `frankengit-0kqi`. This asserts a property of the MODEL,
    // and the old name -- "cancellation before the effect proves non commit" --
    // read as a property of the adapter. It is not one: the store cannot tell
    // which phase a cancellation landed in, so it answers Ambiguous(Cancelled)
    // for every phase including this one. The assertions below were always
    // correct; the name was the part that outran them.
    assert_eq!(
        classify(CancellationPhase::BeforeDispatch),
        CancellationOutcome::NoEffect
    );
    assert_eq!(
        classify(CancellationPhase::Queued),
        CancellationOutcome::NoEffect,
        "a queued command is removed before dispatch, so it provably never ran"
    );
    assert_eq!(
        classify(CancellationPhase::CommitInFlight),
        CancellationOutcome::Ambiguous,
        "a cancelled commit may have applied; reporting non-commit here would be the \
         single most damaging thing this adapter could do"
    );
}

#[test]
fn every_phase_after_dispatch_and_before_the_reply_is_ambiguous() {
    for phase in [
        CancellationPhase::Executing,
        CancellationPhase::CommitInFlight,
        CancellationPhase::AwaitingReply,
    ] {
        assert_eq!(
            classify(phase),
            CancellationOutcome::Ambiguous,
            "{phase:?} must not license a non-commit conclusion"
        );
    }
}

#[test]
fn cancellation_during_close_threatens_containment_not_the_outcome() {
    assert_eq!(
        classify(CancellationPhase::DuringClose),
        CancellationOutcome::ContainmentRisk,
        "the operation is already settled; what is in doubt is whether anything is still live"
    );
}

#[test]
fn all_six_phases_are_classified_and_none_is_silently_effect_free() {
    assert_eq!(CANCELLATION_PHASES.len(), 6);
    let effect_free: Vec<CancellationPhase> = CANCELLATION_PHASES
        .into_iter()
        .filter(|phase| classify(*phase) == CancellationOutcome::NoEffect)
        .collect();
    assert_eq!(
        effect_free,
        vec![CancellationPhase::BeforeDispatch, CancellationPhase::Queued],
        "only the two phases before the command reaches the connection may claim no effect"
    );
}

const fn classify(phase: CancellationPhase) -> CancellationOutcome {
    fgit_authority_fsqlite::classify_cancellation(phase)
}

#[test]
fn the_adapter_cannot_source_a_phase_so_the_model_licenses_nothing_about_it() {
    // `frankengit-0kqi`, the structural half.
    //
    // Every other test in this file drives the model against itself, which is
    // the shape YellowOak named: a model checked only against itself is a
    // mirror, not a guard. What was missing was any statement in the crate
    // connecting the model to the adapter it describes -- so a caller could
    // reasonably wire `classify_cancellation` and conclude non-commit from a
    // `NoEffect`, which at this boundary §5.2 forbids.
    //
    // The connection is now a fact in the API rather than a comment: the
    // adapter cannot produce a `CancellationPhase` at all, so the only phase a
    // caller can pass is one it invented, and an invented phase licenses
    // nothing about what this store did.
    assert_eq!(
        fgit_authority_fsqlite::observable_cancellation_phase(),
        None,
        "if this now returns Some, the engine has learned to distinguish \
         cancellation phases -- which is the reopen condition on the docs for \
         both this function and classify_cancellation. Wire the model, then \
         delete this test and say which phase became observable"
    );

    // The presence half: the model itself must still be intact and answering,
    // or the assertion above would be satisfied by a model that had been
    // gutted rather than by one that is correctly unwired.
    assert_eq!(
        classify(CancellationPhase::CommitInFlight),
        CancellationOutcome::Ambiguous,
        "the model must still classify, or this test proves only that something \
         was deleted"
    );
}
