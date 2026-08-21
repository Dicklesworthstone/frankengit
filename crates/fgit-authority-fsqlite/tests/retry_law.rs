//! The whole-transaction retry law.
//!
//! The two properties worth testing are the ones that are easy to lose: that
//! the retryable family stays exactly the seven admitted classes, and that the
//! unit of retry is the whole transaction rather than a statement.

use std::cell::RefCell;

use fgit_authority_fsqlite::{
    BackoffPlan, MAX_TRANSIENT_ATTEMPTS, RetryBudget, RetryOutcome, TransientClass,
    classify_is_retryable, retry_whole_transaction,
};

fn plan() -> BackoffPlan {
    BackoffPlan::new(4, 64, 0x5EED_1234)
}

fn generous() -> RetryBudget {
    RetryBudget::new(10_000, MAX_TRANSIENT_ATTEMPTS)
}

#[test]
fn exactly_seven_classes_are_retryable() {
    let retryable: Vec<TransientClass> = [
        TransientClass::Busy,
        TransientClass::BusyRecovery,
        TransientClass::BusySnapshot,
        TransientClass::DatabaseLocked,
        TransientClass::WriteConflict,
        TransientClass::SerializationFailure,
        TransientClass::PageBufferCapacityExhausted,
        TransientClass::FreshSnapshotRequired,
        TransientClass::Permanent,
    ]
    .into_iter()
    .filter(|class| classify_is_retryable(*class))
    .collect();

    assert_eq!(
        retryable,
        TransientClass::RETRYABLE.to_vec(),
        "the transient family drifted; widening it is a contract change"
    );
    assert_eq!(retryable.len(), 7);
}

#[test]
fn a_stale_snapshot_is_surfaced_rather_than_absorbed() {
    // Blindly retrying SnapshotTooOld in place turns a stale read into an
    // unbounded spin, so it must reach the caller for a fresh-snapshot decision.
    assert!(!classify_is_retryable(
        TransientClass::FreshSnapshotRequired
    ));

    let calls = RefCell::new(0_u32);
    let outcome: RetryOutcome<()> = retry_whole_transaction(
        generous(),
        plan(),
        |_| {
            *calls.borrow_mut() += 1;
            Err(TransientClass::FreshSnapshotRequired)
        },
        |_| panic!("a stale snapshot must not sleep and retry"),
    );

    assert_eq!(outcome, RetryOutcome::FreshSnapshotRequired { attempts: 1 });
    assert_eq!(*calls.borrow(), 1, "it must not be retried in place");
}

#[test]
fn a_permanent_failure_is_never_reclassified_as_busy() {
    let calls = RefCell::new(0_u32);
    let outcome: RetryOutcome<()> = retry_whole_transaction(
        generous(),
        plan(),
        |_| {
            *calls.borrow_mut() += 1;
            Err(TransientClass::Permanent)
        },
        |_| panic!("a permanent failure must not sleep"),
    );

    assert_eq!(outcome, RetryOutcome::Permanent { attempts: 1 });
    assert_eq!(*calls.borrow(), 1);
}

#[test]
fn a_first_attempt_success_never_sleeps() {
    let outcome = retry_whole_transaction(
        generous(),
        plan(),
        |attempt| {
            assert_eq!(attempt, 1);
            Ok::<u32, TransientClass>(7)
        },
        |_| panic!("a successful first attempt must not back off"),
    );
    assert_eq!(outcome, RetryOutcome::Completed(7));
    assert_eq!(
        plan().delay_ticks(1),
        0,
        "there is no delay before attempt one"
    );
}

#[test]
fn the_whole_transaction_is_re_invoked_from_the_beginning() {
    let attempts = RefCell::new(Vec::new());
    let sleeps = RefCell::new(Vec::new());

    let outcome = retry_whole_transaction(
        generous(),
        plan(),
        |attempt| {
            attempts.borrow_mut().push(attempt);
            if attempt < 3 {
                Err(TransientClass::WriteConflict)
            } else {
                Ok::<&str, TransientClass>("committed")
            }
        },
        |ticks| sleeps.borrow_mut().push(ticks),
    );

    assert_eq!(outcome, RetryOutcome::Completed("committed"));
    assert_eq!(
        *attempts.borrow(),
        vec![1, 2, 3],
        "each retry re-runs the entire transaction from attempt one's starting point"
    );
    assert_eq!(sleeps.borrow().len(), 2, "one backoff between each pair");
    assert!(
        sleeps.borrow().iter().all(|ticks| *ticks >= 1),
        "a contended loop must always yield"
    );
}

#[test]
fn exhaustion_reports_everything_needed_to_act_on_it() {
    let outcome: RetryOutcome<()> = retry_whole_transaction(
        RetryBudget::new(10_000, 3),
        plan(),
        |_| Err(TransientClass::Busy),
        |_| {},
    );

    let RetryOutcome::Exhausted(exhausted) = outcome else {
        panic!("a persistently busy engine must exhaust, observed {outcome:?}");
    };
    assert_eq!(exhausted.attempts, 3);
    assert_eq!(exhausted.last_class, TransientClass::Busy);
    assert_eq!(
        exhausted.seed,
        plan().seed(),
        "the run must replay from the seed"
    );
    assert!(exhausted.elapsed_ticks > 0);
    assert!(!exhausted.remediation.is_empty());
    assert!(
        exhausted.to_string().contains("busy"),
        "the refusal names the last class: {exhausted}"
    );
}

#[test]
fn the_attempt_bound_cannot_be_raised_or_zeroed_by_a_caller() {
    assert_eq!(
        RetryBudget::new(1, 1_000).max_attempts(),
        MAX_TRANSIENT_ATTEMPTS,
        "a caller must not be able to opt into an unbounded retry loop"
    );
    assert_eq!(
        RetryBudget::new(1, 0).max_attempts(),
        1,
        "a zero-attempt budget would never run the transaction at all"
    );
}

#[test]
fn the_loop_stops_before_the_parent_deadline_rather_than_after() {
    let sleeps = RefCell::new(0_u32);
    let outcome: RetryOutcome<()> = retry_whole_transaction(
        // Enough for the first attempt, nowhere near enough for a backoff.
        RetryBudget::new(1, MAX_TRANSIENT_ATTEMPTS),
        BackoffPlan::new(64, 1024, 0x1234),
        |_| Err(TransientClass::DatabaseLocked),
        |_| *sleeps.borrow_mut() += 1,
    );

    let RetryOutcome::Exhausted(exhausted) = outcome else {
        panic!("the deadline must end the loop, observed {outcome:?}");
    };
    assert_eq!(exhausted.attempts, 1);
    assert_eq!(
        *sleeps.borrow(),
        0,
        "it must refuse before sleeping past the deadline, not discover it afterwards"
    );
    assert!(exhausted.remediation.contains("deadline"));
}

#[test]
fn backoff_is_deterministic_bounded_and_separates_contenders() {
    let left = BackoffPlan::new(4, 64, 0xAAAA);
    let right = BackoffPlan::new(4, 64, 0xAAAA);
    let other = BackoffPlan::new(4, 64, 0xBBBB);

    let left_delays: Vec<u64> = (1..=8).map(|n| left.delay_ticks(n)).collect();
    let right_delays: Vec<u64> = (1..=8).map(|n| right.delay_ticks(n)).collect();
    let other_delays: Vec<u64> = (1..=8).map(|n| other.delay_ticks(n)).collect();

    assert_eq!(left_delays, right_delays, "one seed, one schedule");
    assert_ne!(
        left_delays, other_delays,
        "two contenders with different seeds must separate rather than re-colliding"
    );
    assert!(
        left_delays.iter().skip(1).all(|ticks| *ticks <= 64),
        "no delay may exceed the ceiling: {left_delays:?}"
    );
    assert!(
        left_delays.iter().skip(1).all(|ticks| *ticks >= 1),
        "every backoff must actually yield: {left_delays:?}"
    );
}

#[test]
fn every_class_has_a_stable_name() {
    let mut names: Vec<&str> = [
        TransientClass::Busy,
        TransientClass::BusyRecovery,
        TransientClass::BusySnapshot,
        TransientClass::DatabaseLocked,
        TransientClass::WriteConflict,
        TransientClass::SerializationFailure,
        TransientClass::PageBufferCapacityExhausted,
        TransientClass::FreshSnapshotRequired,
        TransientClass::Permanent,
    ]
    .iter()
    .map(|class| class.as_str())
    .collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "two classes share a receipt name");
}
