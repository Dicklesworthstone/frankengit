//! The two retry drivers implement one law, not two.
//!
//! There is a synchronous driver (`retry_whole_transaction`) and an
//! asynchronous one (`run_with_retry`), because the engine must await its wait
//! instead of blocking a worker thread. Two drivers is a correctness hazard:
//! the failure mode is not that one is slower, it is that one of them replays a
//! transaction after an indeterminate outcome while the other refuses to. These
//! tests hold them to the same decisions.
//!
//! The async driver is polled here with a no-op waker rather than a runtime.
//! That is sound for exactly these cases and for no others: the futures below
//! never pend, because both the attempt and the wait complete immediately. A
//! test that needed a real wait would need a real runtime.

use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use fgit_authority_fsqlite::{
    BackoffPlan, EngineError, RetryBudget, RetryOutcome, RetryVerdict, TransientClass,
    decide_after_failure, retry_whole_transaction, run_with_retry,
};

/// Drive a future that is known never to pend.
fn poll_to_completion<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => {
            panic!("this harness only drives futures that complete on the first poll")
        }
    }
}

fn budget() -> RetryBudget {
    RetryBudget::new(1_000_000, 5)
}

fn backoff() -> BackoffPlan {
    BackoffPlan::new(2, 64, 0xABCD_1234)
}

/// Every class, so no arm of the law goes unchecked.
const EVERY_CLASS: [TransientClass; 10] = [
    TransientClass::Busy,
    TransientClass::BusyRecovery,
    TransientClass::BusySnapshot,
    TransientClass::DatabaseLocked,
    TransientClass::WriteConflict,
    TransientClass::SerializationFailure,
    TransientClass::PageBufferCapacityExhausted,
    TransientClass::FreshSnapshotRequired,
    TransientClass::OutcomeIndeterminate,
    TransientClass::Permanent,
];

/// Reduce an outcome to a comparable shape.
///
/// The two drivers are generic over different value types, so the outcomes are
/// compared by shape and attempt count rather than by equality.
fn shape<T>(outcome: &RetryOutcome<T>) -> (&'static str, u32) {
    match outcome {
        RetryOutcome::Completed(_) => ("completed", 0),
        RetryOutcome::FreshSnapshotRequired { attempts } => ("fresh-snapshot", *attempts),
        RetryOutcome::OutcomeIndeterminate { attempts } => ("indeterminate", *attempts),
        RetryOutcome::Permanent { attempts } => ("permanent", *attempts),
        RetryOutcome::Exhausted(exhausted) => ("exhausted", exhausted.attempts),
    }
}

#[test]
fn both_drivers_agree_on_every_transient_class() {
    for class in EVERY_CLASS {
        let sync_waits = Mutex::new(Vec::new());
        let synchronous = retry_whole_transaction::<(), _, _>(
            budget(),
            backoff(),
            |_| Err(class),
            |delay| sync_waits.lock().expect("uncontended").push(delay),
        );

        let async_waits = Mutex::new(Vec::new());
        let asynchronous = poll_to_completion(run_with_retry::<(), _, _>(
            budget(),
            backoff(),
            async |_| Err(EngineError::Engine(class)),
            async |delay| async_waits.lock().expect("uncontended").push(delay),
        ));

        assert_eq!(
            shape(&synchronous),
            shape(&asynchronous),
            "the drivers disagree on {}: sync {synchronous:?} vs async {asynchronous:?}",
            class.as_str()
        );
        assert_eq!(
            *sync_waits.lock().expect("uncontended"),
            *async_waits.lock().expect("uncontended"),
            "the drivers waited differently for {}",
            class.as_str()
        );
    }
}

#[test]
fn a_transaction_that_succeeds_is_not_retried_by_either_driver() {
    let sync_attempts = Mutex::new(0_u32);
    let synchronous = retry_whole_transaction(
        budget(),
        backoff(),
        |_| {
            *sync_attempts.lock().expect("uncontended") += 1;
            Ok::<_, TransientClass>(7_u32)
        },
        |_| panic!("a successful transaction must not wait"),
    );

    let async_attempts = Mutex::new(0_u32);
    let asynchronous = poll_to_completion(run_with_retry(
        budget(),
        backoff(),
        async |_| {
            *async_attempts.lock().expect("uncontended") += 1;
            Ok::<_, EngineError>(7_u32)
        },
        async |_| panic!("a successful transaction must not wait"),
    ));

    assert!(matches!(synchronous, RetryOutcome::Completed(7)));
    assert!(matches!(asynchronous, RetryOutcome::Completed(7)));
    assert_eq!(*sync_attempts.lock().expect("uncontended"), 1);
    assert_eq!(*async_attempts.lock().expect("uncontended"), 1);
}

#[test]
fn an_indeterminate_outcome_is_never_replayed_by_either_driver() {
    // The property with teeth. Replaying a transaction whose outcome is
    // unknown can duplicate an effect that already committed, so neither
    // driver may make a second attempt.
    let sync_attempts = Mutex::new(0_u32);
    let synchronous = retry_whole_transaction::<(), _, _>(
        budget(),
        backoff(),
        |_| {
            *sync_attempts.lock().expect("uncontended") += 1;
            Err(TransientClass::OutcomeIndeterminate)
        },
        |_| panic!("an indeterminate outcome must not be waited out and retried"),
    );

    let async_attempts = Mutex::new(0_u32);
    let asynchronous = poll_to_completion(run_with_retry::<(), _, _>(
        budget(),
        backoff(),
        async |_| {
            *async_attempts.lock().expect("uncontended") += 1;
            Err(EngineError::Engine(TransientClass::OutcomeIndeterminate))
        },
        async |_| panic!("an indeterminate outcome must not be waited out and retried"),
    ));

    assert!(matches!(
        synchronous,
        RetryOutcome::OutcomeIndeterminate { attempts: 1 }
    ));
    assert!(matches!(
        asynchronous,
        RetryOutcome::OutcomeIndeterminate { attempts: 1 }
    ));
    assert_eq!(*sync_attempts.lock().expect("uncontended"), 1);
    assert_eq!(*async_attempts.lock().expect("uncontended"), 1);
}

#[test]
fn a_contended_transaction_eventually_succeeds_identically() {
    for succeed_on in 2_u32..=4 {
        let synchronous = retry_whole_transaction(
            budget(),
            backoff(),
            |attempt| {
                if attempt >= succeed_on {
                    Ok::<_, TransientClass>(attempt)
                } else {
                    Err(TransientClass::Busy)
                }
            },
            |_| {},
        );
        let asynchronous = poll_to_completion(run_with_retry(
            budget(),
            backoff(),
            async |attempt| {
                if attempt >= succeed_on {
                    Ok::<_, EngineError>(attempt)
                } else {
                    Err(EngineError::Engine(TransientClass::Busy))
                }
            },
            async |_| {},
        ));

        match (synchronous, asynchronous) {
            (RetryOutcome::Completed(left), RetryOutcome::Completed(right)) => {
                assert_eq!(left, succeed_on);
                assert_eq!(right, succeed_on);
            }
            (left, right) => {
                panic!("both drivers must complete on attempt {succeed_on}: {left:?} / {right:?}")
            }
        }
    }
}

#[test]
fn a_non_engine_error_is_permanent_rather_than_retried() {
    // Only contention is retryable. A marshalling refusal or a contract
    // refusal would produce the identical answer on every replay, so retrying
    // it burns the budget to arrive back where it started.
    let waits = Mutex::new(0_u32);
    let outcome = poll_to_completion(run_with_retry::<(), _, _>(
        budget(),
        backoff(),
        async |_| Err(EngineError::UnknownStatement("head.invented")),
        async |_| *waits.lock().expect("uncontended") += 1,
    ));

    assert!(matches!(outcome, RetryOutcome::Permanent { attempts: 1 }));
    assert_eq!(*waits.lock().expect("uncontended"), 0);
}

#[test]
fn the_shared_decision_is_what_both_drivers_consult() {
    // Non-vacuity: if `decide_after_failure` did not actually govern, the
    // assertions above could pass with two independent implementations that
    // happen to agree today. This pins the decision itself.
    assert_eq!(
        decide_after_failure(
            budget(),
            backoff(),
            1,
            0,
            TransientClass::OutcomeIndeterminate
        ),
        RetryVerdict::OutcomeIndeterminate
    );
    assert_eq!(
        decide_after_failure(budget(), backoff(), 1, 0, TransientClass::Permanent),
        RetryVerdict::Permanent
    );
    assert_eq!(
        decide_after_failure(
            budget(),
            backoff(),
            1,
            0,
            TransientClass::FreshSnapshotRequired
        ),
        RetryVerdict::FreshSnapshotRequired
    );

    let verdict = decide_after_failure(budget(), backoff(), 1, 0, TransientClass::Busy);
    let RetryVerdict::Retry { delay_ticks, .. } = verdict else {
        panic!("a busy engine on the first of five attempts must be retried, got {verdict:?}");
    };
    assert_eq!(
        delay_ticks,
        backoff().delay_ticks(2),
        "the driver must wait exactly what the plan computes for the next attempt"
    );

    // The last admitted attempt exhausts rather than waiting for an attempt
    // that will never be made.
    let verdict = decide_after_failure(budget(), backoff(), 5, 0, TransientClass::Busy);
    assert!(
        matches!(verdict, RetryVerdict::Exhausted(_)),
        "attempt 5 of 5 must exhaust, got {verdict:?}"
    );
}
