//! The whole-transaction retry law.
//!
//! `docs/ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md` §3.4 states the
//! rule that shapes this module: **retry wraps the whole logical SQL
//! transaction from a fresh snapshot; individual statements are not replayed
//! into an unknown transaction state.** Replaying a statement means guessing
//! what the engine did with the last one, and a guess about a partially applied
//! transaction is how a conditional replacement becomes a double write.
//!
//! So the retryable unit here is a closure that performs the *entire*
//! transaction, and [`retry_whole_transaction`] re-invokes that closure from
//! the beginning. There is no statement-level retry entry point, and there is
//! no way to build one out of what this module exports.
//!
//! # The transient family is closed
//!
//! [`TransientClass`] enumerates exactly the seven classes §3.4 admits, plus
//! the two dispositions that are *not* retries. Widening it is a change to this
//! enum, which is a change a reviewer sees. Corruption, schema and constraint
//! errors, invariant failures, cancellation, panics, resource ceilings, and
//! permanent I/O errors are [`TransientClass::Permanent`] and are never
//! converted into "busy".
//!
//! `SnapshotTooOld` is deliberately not in the retryable set. §3.4 requires a
//! fresh transaction and snapshot decision rather than a blind retry in place,
//! so it maps to [`TransientClass::FreshSnapshotRequired`], which
//! [`retry_whole_transaction`] surfaces to the caller instead of absorbing.

/// How the backend's error disposes of a whole-transaction attempt.
///
/// The seven retryable members are exactly §3.4's list, in its order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransientClass {
    /// The engine is busy.
    Busy,
    /// The engine is recovering.
    BusyRecovery,
    /// A snapshot conflict the engine expects a retry to clear.
    BusySnapshot,
    /// The database file is locked.
    DatabaseLocked,
    /// Two writers touched the same page.
    WriteConflict,
    /// The engine could not serialize the transaction.
    SerializationFailure,
    /// The page buffer filled; a retry from a fresh snapshot may fit.
    PageBufferCapacityExhausted,
    /// `SnapshotTooOld`: the caller must take a fresh snapshot, not retry here.
    ///
    /// Not retryable in place. §3.4 is explicit that this needs a fresh
    /// transaction and snapshot decision, and quietly looping on it would turn
    /// a stale read into an unbounded spin.
    FreshSnapshotRequired,
    /// Anything else. Never retried, never reclassified as busy.
    Permanent,
}

impl TransientClass {
    /// Exactly the classes a same-attempt bounded retry may absorb.
    pub const RETRYABLE: [Self; 7] = [
        Self::Busy,
        Self::BusyRecovery,
        Self::BusySnapshot,
        Self::DatabaseLocked,
        Self::WriteConflict,
        Self::SerializationFailure,
        Self::PageBufferCapacityExhausted,
    ];

    /// Whether a bounded same-attempt retry may absorb this class.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Busy
                | Self::BusyRecovery
                | Self::BusySnapshot
                | Self::DatabaseLocked
                | Self::WriteConflict
                | Self::SerializationFailure
                | Self::PageBufferCapacityExhausted
        )
    }

    /// A stable name for receipts and refusal messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::BusyRecovery => "busy_recovery",
            Self::BusySnapshot => "busy_snapshot",
            Self::DatabaseLocked => "database_locked",
            Self::WriteConflict => "write_conflict",
            Self::SerializationFailure => "serialization_failure",
            Self::PageBufferCapacityExhausted => "page_buffer_capacity_exhausted",
            Self::FreshSnapshotRequired => "fresh_snapshot_required",
            Self::Permanent => "permanent",
        }
    }
}

/// Whether a class may be absorbed, as a free function for table-driven tests.
#[must_use]
pub const fn classify_is_retryable(class: TransientClass) -> bool {
    class.is_retryable()
}

/// The largest number of whole-transaction attempts the profile admits.
pub const MAX_TRANSIENT_ATTEMPTS: u32 = 8;

/// Bounded, cancellation-aware, deterministic backoff.
///
/// Jitter is seeded rather than sampled from the environment, so a contention
/// failure replays. §3.4 requires backoff to be "seeded/receipted where jitter
/// is used" and to stop before the parent deadline; both are properties of the
/// plan rather than of the caller's discipline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackoffPlan {
    base_ticks: u64,
    ceiling_ticks: u64,
    seed: u64,
}

impl BackoffPlan {
    /// A plan with the given base delay, ceiling, and jitter seed.
    #[must_use]
    pub const fn new(base_ticks: u64, ceiling_ticks: u64, seed: u64) -> Self {
        Self {
            base_ticks,
            ceiling_ticks,
            seed,
        }
    }

    /// The jitter seed, recorded in the exhaustion refusal so a run replays.
    #[must_use]
    pub const fn seed(self) -> u64 {
        self.seed
    }

    /// The delay before attempt `attempt`, counting the first attempt as one.
    ///
    /// Exponential to the ceiling, then flat, with deterministic jitter in the
    /// lower half of the interval. The delay is always at least one tick so a
    /// contended loop cannot spin without yielding.
    #[must_use]
    pub const fn delay_ticks(self, attempt: u32) -> u64 {
        if attempt <= 1 {
            return 0;
        }
        let shift = if attempt > 32 { 31 } else { attempt - 2 };
        let grown = self.base_ticks.saturating_mul(1_u64 << shift);
        let bounded = if grown > self.ceiling_ticks {
            self.ceiling_ticks
        } else {
            grown
        };
        // Deterministic jitter: mix the seed with the attempt and take the low
        // half of the interval, so two contenders with different seeds separate
        // instead of re-colliding on every round.
        let mut mixed = self.seed ^ (attempt as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        mixed ^= mixed >> 29;
        mixed = mixed.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed ^= mixed >> 32;
        let half = bounded / 2;
        let jitter = if half == 0 { 0 } else { mixed % (half + 1) };
        let total = bounded.saturating_sub(half).saturating_add(jitter);
        if total == 0 { 1 } else { total }
    }
}

/// The remaining budget a retry loop may spend.
///
/// Ticks are the caller's logical time unit; the loop stops before the parent
/// deadline rather than discovering it after the fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryBudget {
    remaining_ticks: u64,
    max_attempts: u32,
}

impl RetryBudget {
    /// A budget bounded by both time and attempts.
    ///
    /// The attempt count is clamped to [`MAX_TRANSIENT_ATTEMPTS`]: a caller
    /// cannot opt into an unbounded retry loop.
    #[must_use]
    pub const fn new(remaining_ticks: u64, max_attempts: u32) -> Self {
        let max_attempts = if max_attempts > MAX_TRANSIENT_ATTEMPTS {
            MAX_TRANSIENT_ATTEMPTS
        } else if max_attempts == 0 {
            1
        } else {
            max_attempts
        };
        Self {
            remaining_ticks,
            max_attempts,
        }
    }

    /// Ticks still available.
    #[must_use]
    pub const fn remaining_ticks(self) -> u64 {
        self.remaining_ticks
    }

    /// The attempt ceiling in force.
    #[must_use]
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    /// Whether a delay of `ticks` fits before the parent deadline.
    #[must_use]
    pub const fn admits(self, ticks: u64) -> bool {
        ticks <= self.remaining_ticks
    }

    /// The budget after spending `ticks`.
    #[must_use]
    pub const fn spend(self, ticks: u64) -> Self {
        Self {
            remaining_ticks: self.remaining_ticks.saturating_sub(ticks),
            max_attempts: self.max_attempts,
        }
    }
}

/// Why a bounded retry gave up, with everything needed to act on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryExhausted {
    /// Whole-transaction attempts made.
    pub attempts: u32,
    /// Ticks spent waiting between them.
    pub elapsed_ticks: u64,
    /// The class of the last failure.
    pub last_class: TransientClass,
    /// The jitter seed, so the run replays exactly.
    pub seed: u64,
    /// What the operator or caller should do next.
    pub remediation: &'static str,
}

impl core::fmt::Display for RetryExhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "gave up after {} whole-transaction attempts and {} ticks; last class {}; \
             seed {:#x}; {}",
            self.attempts,
            self.elapsed_ticks,
            self.last_class.as_str(),
            self.seed,
            self.remediation
        )
    }
}

impl std::error::Error for RetryExhausted {}

/// How a bounded whole-transaction retry finished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryOutcome<T> {
    /// An attempt succeeded.
    Completed(T),
    /// The caller must take a fresh snapshot and decide again.
    ///
    /// Surfaced rather than absorbed: §3.4 forbids retrying `SnapshotTooOld`
    /// in place.
    FreshSnapshotRequired {
        /// Attempts made before the stale snapshot was observed.
        attempts: u32,
    },
    /// A class outside the transient family ended the operation.
    Permanent {
        /// Attempts made before the permanent failure.
        attempts: u32,
    },
    /// The transient family was hit until the bound ran out.
    Exhausted(RetryExhausted),
}

/// Run one whole logical transaction, retrying only the admitted classes.
///
/// `attempt` performs the **entire** transaction and returns either its value
/// or the class of its failure. It is called from the beginning every time;
/// nothing partial is ever resumed.
///
/// `sleep` receives the computed delay in ticks. It is a parameter rather than
/// a call into a clock so the law is testable without a runtime, and so the
/// runtime adapter can make the wait cancellation-aware.
pub fn retry_whole_transaction<T, A, S>(
    budget: RetryBudget,
    backoff: BackoffPlan,
    mut attempt: A,
    mut sleep: S,
) -> RetryOutcome<T>
where
    A: FnMut(u32) -> Result<T, TransientClass>,
    S: FnMut(u64),
{
    let mut budget = budget;
    let mut elapsed = 0_u64;
    let mut last_class = TransientClass::Permanent;

    for attempt_number in 1..=budget.max_attempts() {
        match attempt(attempt_number) {
            Ok(value) => return RetryOutcome::Completed(value),
            Err(TransientClass::FreshSnapshotRequired) => {
                return RetryOutcome::FreshSnapshotRequired {
                    attempts: attempt_number,
                };
            }
            Err(TransientClass::Permanent) => {
                return RetryOutcome::Permanent {
                    attempts: attempt_number,
                };
            }
            Err(class) => {
                last_class = class;
                if attempt_number == budget.max_attempts() {
                    break;
                }
                let delay = backoff.delay_ticks(attempt_number + 1);
                if !budget.admits(delay) {
                    return RetryOutcome::Exhausted(RetryExhausted {
                        attempts: attempt_number,
                        elapsed_ticks: elapsed,
                        last_class,
                        seed: backoff.seed(),
                        remediation: "the parent deadline would be exceeded by another \
                                      attempt; reduce contention or raise the budget",
                    });
                }
                sleep(delay);
                elapsed = elapsed.saturating_add(delay);
                budget = budget.spend(delay);
            }
        }
    }

    RetryOutcome::Exhausted(RetryExhausted {
        attempts: budget.max_attempts(),
        elapsed_ticks: elapsed,
        last_class,
        seed: backoff.seed(),
        remediation: "the attempt bound was reached; reduce writer concurrency to the \
                      admitted envelope or raise the attempt budget",
    })
}
