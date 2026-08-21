//! FG-005b: the retry law, derived from the specification rather than the code.
//!
//! # Why this file exists alongside `retry_law.rs`
//!
//! `retry_law.rs` and `retry_law_agreement.rs` are written by the author of
//! the code they test. That is implementer evidence: it catches mistakes of
//! *execution* well, and cannot catch mistakes of *understanding* at all. If
//! the retry law were misread, the implementation and its tests would inherit
//! the same misreading and agree perfectly.
//!
//! So these assertions were written by reading
//! `docs/ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md` §3.4 **first**
//! and the implementation **second**. The class names below are transcribed
//! from the specification, not from `TransientClass`. If someone widens the
//! retryable family, this file fails and cites the clause it violates rather
//! than merely reporting that two parts of the code disagree.
//!
//! Written by a pane that did not implement this crate; nothing here edits
//! `fgit-authority-fsqlite/src`.
//!
//! # The result, stated up front because a null result is still a result
//!
//! The implementation **matches** §3.4: the same seven classes, no more and no
//! fewer, with `SnapshotTooOld` correctly outside the retryable set and an
//! unknown error defaulting to permanent. This file is therefore not a defect
//! report. It converts "the implementer believes this is right" into "the
//! clause and the code were compared by someone who did not write the code",
//! which is a different and stronger claim.
//!
//! # What this does NOT claim
//!
//! The backoff assertions below inspect the **plan**, not the waiting.
//! `BackoffPlan`, `RetryBudget` and `decide_after_failure` are all `const fn`,
//! so boundedness, seed reproducibility, deadline arithmetic and the
//! exhaustion receipt are all checkable without a runtime -- which is the only
//! reason that half of §3.4 is reachable here at all.
//!
//! What remains unproven: that the loop actually *sleeps* for the delay it
//! computed, and that a cancellation interrupts a wait already in flight.
//! §3.4 calls the backoff "cancellation-aware", and nothing in this file
//! tests that word. It needs a harness able to observe waiting, which is the
//! same missing harness that blocks cancellation-mid-operation for this
//! backend.

use fgit_authority_fsqlite::TransientClass;

/// The transient family, transcribed verbatim from
/// `ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md` §3.4:
///
/// > Same-attempt bounded retry is limited to the reviewed transient family:
/// > `Busy`, `BusyRecovery`, `BusySnapshot`, `DatabaseLocked`,
/// > `WriteConflict`, `SerializationFailure`, and
/// > `PageBufferCapacityExhausted`
///
/// Spelled out here so the test depends on the clause, not on the code under
/// test. A reader can check this list against the document without opening
/// `retry.rs`.
const SPEC_RETRYABLE: [TransientClass; 7] = [
    TransientClass::Busy,
    TransientClass::BusyRecovery,
    TransientClass::BusySnapshot,
    TransientClass::DatabaseLocked,
    TransientClass::WriteConflict,
    TransientClass::SerializationFailure,
    TransientClass::PageBufferCapacityExhausted,
];

/// Every class the type declares. Kept exhaustive deliberately: a new variant
/// must be added here, which forces a decision about which side of the law it
/// falls on instead of letting it default in silently.
const ALL_CLASSES: [TransientClass; 10] = [
    TransientClass::Busy,
    TransientClass::BusyRecovery,
    TransientClass::BusySnapshot,
    TransientClass::DatabaseLocked,
    TransientClass::WriteConflict,
    TransientClass::SerializationFailure,
    TransientClass::PageBufferCapacityExhausted,
    TransientClass::OutcomeIndeterminate,
    TransientClass::FreshSnapshotRequired,
    TransientClass::Permanent,
];

#[test]
fn exactly_the_seven_specified_classes_are_retryable() {
    for class in SPEC_RETRYABLE {
        assert!(
            class.is_retryable(),
            "§3.4 names {class:?} in the reviewed transient family, but the implementation \
             refuses to retry it"
        );
    }

    // The other direction is the one that matters. Under-retrying is a
    // performance bug; OVER-retrying replays a transaction into a state the
    // engine never promised was clean, which is a correctness bug.
    for class in ALL_CLASSES {
        let specified = SPEC_RETRYABLE.contains(&class);
        assert_eq!(
            class.is_retryable(),
            specified,
            "{class:?} is retryable={} but §3.4 says it should be {specified}; widening the \
             transient family replays transactions into states the engine never called clean",
            class.is_retryable()
        );
    }
}

#[test]
fn the_two_declarations_of_the_retryable_set_cannot_drift_apart() {
    // `TransientClass::RETRYABLE` (an array) and `is_retryable()` (a match)
    // state the same law twice. Two vocabularies for one rule is how a class
    // ends up retried on one path and refused on another, and neither
    // declaration is obviously the authority, so nothing forces an editor of
    // one to touch the other.
    assert_eq!(
        TransientClass::RETRYABLE.len(),
        SPEC_RETRYABLE.len(),
        "the published RETRYABLE set has {} entries; §3.4 names {}",
        TransientClass::RETRYABLE.len(),
        SPEC_RETRYABLE.len()
    );
    for class in TransientClass::RETRYABLE {
        assert!(
            class.is_retryable(),
            "{class:?} is listed in RETRYABLE but is_retryable() refuses it: the array and the \
             match have drifted apart"
        );
        assert!(
            SPEC_RETRYABLE.contains(&class),
            "{class:?} is listed in RETRYABLE but §3.4 does not name it"
        );
    }
    for class in ALL_CLASSES {
        assert_eq!(
            TransientClass::RETRYABLE.contains(&class),
            class.is_retryable(),
            "{class:?} is on one side of RETRYABLE and the other side of is_retryable()"
        );
    }
}

#[test]
fn a_stale_snapshot_is_not_retried_in_place() {
    // §3.4: "`SnapshotTooOld` requires a fresh transaction/snapshot decision
    // and is not blindly retried in place."
    //
    // Retrying it where it failed re-reads the same stale snapshot, so the
    // retry cannot succeed and the loop spins until the budget dies. The class
    // exists precisely so the caller is told to start again rather than to
    // wait.
    assert!(
        !TransientClass::FreshSnapshotRequired.is_retryable(),
        "a stale snapshot retried in place re-reads the same stale snapshot: §3.4 requires a \
         fresh transaction decision, not a wait"
    );
}

#[test]
fn an_indeterminate_outcome_is_neither_retried_nor_called_a_failure() {
    // §3.4 forbids converting anything outside the transient family into
    // "busy". An indeterminate publication is the sharpest case: the engine
    // has explicitly declined to say whether the effect happened. Retrying may
    // double-apply it, and reporting failure claims a non-commit the engine
    // refused to claim.
    assert!(
        !TransientClass::OutcomeIndeterminate.is_retryable(),
        "an indeterminate outcome must never be retried: the engine declined to say whether the \
         effect happened, so a replay may double-apply it"
    );
}

#[test]
fn everything_the_spec_excludes_is_permanent_rather_than_transient() {
    // §3.4: "Corruption, schema/constraint errors, invariant failures,
    // cancellation, panic, resource ceilings, and permanent I/O errors are not
    // converted into 'busy'." They all land in `Permanent`, and the value of
    // that arm is that it is the DEFAULT: an error class this build has never
    // seen fails closed instead of being optimistically retried.
    assert!(
        !TransientClass::Permanent.is_retryable(),
        "the permanent class must never be retried"
    );
    assert!(
        !SPEC_RETRYABLE.contains(&TransientClass::Permanent),
        "§3.4's excluded families must not appear in the transient set"
    );
}

#[test]
fn the_class_list_here_is_exhaustive() {
    // The guard on this file's own fixtures. If a variant is added to
    // `TransientClass` and not to `ALL_CLASSES`, the coverage assertion in
    // `exactly_the_seven_specified_classes_are_retryable` silently stops
    // covering it -- it would iterate a stale list and still pass.
    //
    // Matching exhaustively costs a compile error at exactly the right moment:
    // whoever adds the variant must decide which side of §3.4 it falls on.
    for class in ALL_CLASSES {
        let named: &str = match class {
            TransientClass::Busy => "busy",
            TransientClass::BusyRecovery => "busy_recovery",
            TransientClass::BusySnapshot => "busy_snapshot",
            TransientClass::DatabaseLocked => "database_locked",
            TransientClass::WriteConflict => "write_conflict",
            TransientClass::SerializationFailure => "serialization_failure",
            TransientClass::PageBufferCapacityExhausted => "page_buffer_capacity_exhausted",
            TransientClass::OutcomeIndeterminate => "outcome_indeterminate",
            TransientClass::FreshSnapshotRequired => "fresh_snapshot_required",
            TransientClass::Permanent => "permanent",
        };
        assert!(!named.is_empty(), "every class needs a stable receipt name");
    }
}

// ------------------------------------------------------------- the backoff law
//
// §3.4, second half:
//
//   > Backoff is bounded, cancellation-aware, seeded/receipted where jitter is
//   > used, and stops before the parent deadline. Exhaustion returns a stable
//   > refusal with attempts, elapsed budget, last error class, and remediation.
//
// These inspect the PLAN rather than observing real waiting. `BackoffPlan`,
// `RetryBudget` and `decide_after_failure` are all `const fn`, so the law is
// checkable without a runtime -- which is the only reason this sub-cell is
// reachable at all.
//
// NON-CLAIM: nothing here proves the loop actually sleeps for the computed
// delay, or that a cancel interrupts a wait in flight. That needs a harness
// able to observe waiting, and it stays open.

use fgit_authority_fsqlite::{BackoffPlan, RetryBudget, RetryVerdict, decide_after_failure};

const BASE: u64 = 4;
const CEILING: u64 = 64;
const SEED: u64 = 0x5eed;

#[test]
fn the_backoff_is_bounded_at_every_attempt_including_absurd_ones() {
    // "Backoff is bounded". The interesting input is not attempt 3, it is the
    // attempt number no sane loop reaches: a shift- or multiply-based backoff
    // that never saturates will overflow or wrap there, and a wrapped delay is
    // an UNBOUNDED wait wearing a small number. The bound must come from
    // saturation, not from the caller stopping early.
    let plan = BackoffPlan::new(BASE, CEILING, SEED);
    for attempt in [0_u32, 1, 2, 3, 7, 31, 32, 63, 64, 65, 1000, u32::MAX] {
        let delay = plan.delay_ticks(attempt);
        assert!(
            delay <= CEILING,
            "attempt {attempt} produced a delay of {delay} ticks against a ceiling of {CEILING}: \
             backoff must saturate rather than depend on the caller stopping first"
        );
    }
}

#[test]
fn the_same_seed_reproduces_the_same_delays() {
    // "seeded/receipted where jitter is used". A jittered backoff that cannot
    // be replayed turns an intermittent failure into an unreproducible one,
    // and the seed is carried in RetryExhausted precisely so a receipt can
    // replay it.
    let a = BackoffPlan::new(BASE, CEILING, SEED);
    let b = BackoffPlan::new(BASE, CEILING, SEED);
    assert_eq!(
        a.seed(),
        b.seed(),
        "the seed must be what it was constructed with"
    );
    for attempt in 0..16 {
        assert_eq!(
            a.delay_ticks(attempt),
            b.delay_ticks(attempt),
            "attempt {attempt} differed between two plans built from the same seed; a backoff \
             that cannot be replayed makes an intermittent failure unreproducible"
        );
    }
}

#[test]
fn a_budget_that_cannot_afford_the_next_wait_stops_instead_of_retrying() {
    // "stops before the parent deadline". This is the assertion that matters:
    // a retry loop which waits past its deadline has not just been slow, it
    // has held a transaction open beyond the window its caller reserved.
    let plan = BackoffPlan::new(BASE, CEILING, SEED);
    let starved = RetryBudget::new(0, 8);

    let verdict = decide_after_failure(starved, plan, 1, 0, TransientClass::Busy);
    assert!(
        !matches!(verdict, RetryVerdict::Retry { .. }),
        "a budget with no remaining ticks must not authorise another wait; got {verdict:?}"
    );
    assert!(
        matches!(verdict, RetryVerdict::Exhausted(_)),
        "running out of budget is exhaustion and must be reported as such, not as a permanent \
         error or a silent stop; got {verdict:?}"
    );
}

#[test]
fn exhaustion_carries_every_field_the_clause_names() {
    // "Exhaustion returns a stable refusal with attempts, elapsed budget, last
    // error class, and remediation." A refusal missing any of these is not
    // actionable: the operator cannot tell how hard it tried, how long it
    // took, what actually failed, or what to do next.
    let plan = BackoffPlan::new(BASE, CEILING, SEED);
    let starved = RetryBudget::new(0, 4);
    let verdict = decide_after_failure(starved, plan, 3, 999, TransientClass::WriteConflict);

    let RetryVerdict::Exhausted(report) = verdict else {
        panic!("expected exhaustion, got {verdict:?}");
    };
    assert_eq!(
        report.attempts, 3,
        "the refusal must say how many attempts were made"
    );
    assert_eq!(
        report.elapsed_ticks, 999,
        "the refusal must say how much budget was spent"
    );
    assert_eq!(
        report.last_class,
        TransientClass::WriteConflict,
        "the refusal must name the class that actually failed last"
    );
    assert_eq!(
        report.seed, SEED,
        "the refusal must carry the seed so the run can be replayed"
    );
    assert!(
        !report.remediation.is_empty(),
        "an exhaustion refusal with no remediation tells an operator nothing about what to do next"
    );
}

#[test]
fn a_non_transient_class_short_circuits_whatever_the_budget_says() {
    // The classification decides first; the budget only decides how long a
    // RETRYABLE class may keep trying. If a generous budget could turn a
    // permanent error into a retry, §3.4's exclusion list would be advisory.
    let plan = BackoffPlan::new(BASE, CEILING, SEED);
    let generous = RetryBudget::new(u64::MAX, u32::MAX);

    for (class, expected) in [
        (TransientClass::Permanent, "permanent"),
        (TransientClass::FreshSnapshotRequired, "fresh snapshot"),
        (TransientClass::OutcomeIndeterminate, "indeterminate"),
    ] {
        let verdict = decide_after_failure(generous, plan, 1, 0, class);
        assert!(
            !matches!(verdict, RetryVerdict::Retry { .. }),
            "{expected} ({class:?}) was retried because the budget was generous; classification \
             must decide before budget, or the exclusion list is advisory"
        );
    }
}
