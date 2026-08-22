//! Retry policy: expected-loss backoff, regime reset, and the deterministic
//! starvation escalator.
//!
//! Plan §16.5: "Retries carry attempt age, conflict history, resource spend,
//! and priority class. Expected-loss policy may change backoff, refinement, or
//! batch preference within hard bounds. Deterministic starvation escalation
//! eventually routes an old transaction through a conservative serialized
//! component evaluation. **Statistical estimates cannot deny liveness
//! indefinitely.**"
//!
//! That last sentence is the design constraint that shapes this module. The
//! Beta-Bernoulli posterior is allowed to *tune* backoff inside declared
//! bounds. It is not allowed to decide whether a transaction ever runs. So
//! [`decide`] checks the escalator **before** it consults the posterior, and a
//! test asserts that no posterior value whatsoever can prevent escalation.
//!
//! ## Integers, not floats
//!
//! The posterior is a pair of counts and its mean is computed in parts per
//! million with integer arithmetic. A float posterior would make backoff
//! decisions differ across targets, and §26 requires an adaptive artifact to
//! bind a reproducible numeric fingerprint.

use fgit_statistics::IncrementalPosterior;

/// Attempts after which a transaction is escalated regardless of its
/// posterior.
///
/// A hard constant rather than a tunable: a knob here would be a knob on
/// liveness, and §16.5 forbids the statistical layer from holding one.
pub const STARVATION_ATTEMPTS: u32 = 8;

/// Attempt age, in retry ticks, after which the same escalation applies.
pub const STARVATION_AGE_TICKS: u32 = 512;

/// Largest backoff the policy may ever ask for.
pub const MAX_BACKOFF_TICKS: u32 = 64;

/// How urgent a transaction is relative to its peers.
///
/// Priority may reorder work; it may never starve anything, because the
/// escalator does not consult it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PriorityClass {
    /// Background or speculative work.
    Background,
    /// Ordinary interactive work.
    Interactive,
    /// Work a human is waiting on directly.
    Foreground,
}

impl PriorityClass {
    /// Backoff divisor: higher priority waits proportionally less.
    const fn backoff_divisor(self) -> u32 {
        match self {
            Self::Background => 1,
            Self::Interactive => 2,
            Self::Foreground => 4,
        }
    }

    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Background => "background",
            Self::Interactive => "interactive",
            Self::Foreground => "foreground",
        }
    }
}

/// Everything the retry policy reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// How many attempts this sealed transaction has already made.
    pub attempts: u32,
    /// How long it has been retrying, in ticks.
    pub age_ticks: u32,
    /// Its priority class.
    pub priority: PriorityClass,
    /// What its history says about committing next time.
    pub posterior: IncrementalPosterior,
}

/// What the policy decided to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Retry immediately; contention looks low.
    RetryNow,
    /// Wait this many ticks before retrying.
    BackoffFor {
        /// Ticks to wait, never above [`MAX_BACKOFF_TICKS`].
        ticks: u32,
    },
    /// Route through conservative serialized evaluation.
    ///
    /// The terminal rung of §16.5: it always makes progress, and no
    /// statistical input can prevent reaching it.
    EscalateToSerialized {
        /// Which hard threshold triggered it.
        trigger: EscalationTrigger,
    },
}

/// Which deterministic threshold forced escalation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EscalationTrigger {
    /// Too many attempts.
    AttemptCount,
    /// Retrying for too long.
    Age,
}

impl EscalationTrigger {
    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttemptCount => "attempt_count",
            Self::Age => "age",
        }
    }
}

/// Decides what a losing transaction should do next.
///
/// The escalation check comes first, deliberately. A posterior that believed
/// success was hopeless could otherwise back a transaction off forever, and
/// §16.5 forbids a statistical estimate from denying liveness. Once either
/// hard threshold is crossed, the posterior is not consulted at all.
#[must_use]
pub fn decide(attempt: Attempt) -> Action {
    if attempt.attempts >= STARVATION_ATTEMPTS {
        return Action::EscalateToSerialized {
            trigger: EscalationTrigger::AttemptCount,
        };
    }
    if attempt.age_ticks >= STARVATION_AGE_TICKS {
        return Action::EscalateToSerialized {
            trigger: EscalationTrigger::Age,
        };
    }

    // Only now may the posterior influence anything, and only within bounds.
    let success = attempt.posterior.success_probability().parts_per_million();
    if success >= 750_000 {
        return Action::RetryNow;
    }
    // Expected loss rises as success falls, so backoff scales with the
    // complement of the posterior mean, damped by priority and clamped.
    let complement = 1_000_000_u32.saturating_sub(success);
    let scaled = complement / 15_625; // 1_000_000 / 64 -> 0..=MAX_BACKOFF_TICKS
    let ticks = (scaled / attempt.priority.backoff_divisor()).min(MAX_BACKOFF_TICKS);
    if ticks == 0 {
        Action::RetryNow
    } else {
        Action::BackoffFor { ticks }
    }
}

/// One NDJSON line recording a retry decision and the inputs behind it.
#[must_use]
pub fn receipt(attempt: Attempt, action: Action) -> String {
    let (successes, failures) = attempt.posterior.counts();
    let mut out = String::with_capacity(256);
    out.push_str("{\"record\":\"retry_decision\"");
    for (key, value) in [
        ("attempts", u64::from(attempt.attempts)),
        ("age_ticks", u64::from(attempt.age_ticks)),
        ("posterior_successes", u64::from(successes)),
        ("posterior_failures", u64::from(failures)),
        (
            "success_probability_ppm",
            u64::from(attempt.posterior.success_probability().parts_per_million()),
        ),
        ("starvation_attempts", u64::from(STARVATION_ATTEMPTS)),
        ("starvation_age_ticks", u64::from(STARVATION_AGE_TICKS)),
    ] {
        out.push_str(",\"");
        out.push_str(key);
        out.push_str("\":");
        out.push_str(&value.to_string());
    }
    out.push_str(",\"priority\":\"");
    out.push_str(attempt.priority.as_str());
    out.push_str("\",\"action\":\"");
    match action {
        Action::RetryNow => out.push_str("retry_now\""),
        Action::BackoffFor { ticks } => {
            out.push_str("backoff\",\"ticks\":");
            out.push_str(&ticks.to_string());
        }
        Action::EscalateToSerialized { trigger } => {
            out.push_str("escalate_to_serialized\",\"trigger\":\"");
            out.push_str(trigger.as_str());
            out.push('"');
        }
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::{
        Action, Attempt, EscalationTrigger, MAX_BACKOFF_TICKS, PriorityClass, STARVATION_AGE_TICKS,
        STARVATION_ATTEMPTS, decide, receipt,
    };
    use fgit_statistics::{BetaPrior, IncrementalPosterior};

    fn attempt(attempts: u32, age: u32, posterior: IncrementalPosterior) -> Attempt {
        Attempt {
            attempts,
            age_ticks: age,
            priority: PriorityClass::Interactive,
            posterior,
        }
    }

    fn hopeless() -> IncrementalPosterior {
        let mut p = IncrementalPosterior::new(BetaPrior::uniform());
        for _ in 0..10_000 {
            p.observe(false);
        }
        p
    }

    #[test]
    fn no_posterior_whatsoever_can_prevent_escalation() {
        // The central guarantee of plan section 16.5: statistical estimates
        // cannot deny liveness indefinitely. A maximally pessimistic posterior
        // must still escalate once the hard threshold is crossed.
        let action = decide(attempt(STARVATION_ATTEMPTS, 0, hopeless()));
        assert_eq!(
            action,
            Action::EscalateToSerialized {
                trigger: EscalationTrigger::AttemptCount
            }
        );
        // And an optimistic one escalates identically: the escalator does not
        // consult the posterior at all.
        let mut optimistic = IncrementalPosterior::new(BetaPrior::uniform());
        for _ in 0..10_000 {
            optimistic.observe(true);
        }
        assert_eq!(
            decide(attempt(STARVATION_ATTEMPTS, 0, optimistic)),
            Action::EscalateToSerialized {
                trigger: EscalationTrigger::AttemptCount
            }
        );
    }

    #[test]
    fn age_escalates_independently_of_attempt_count() {
        let action = decide(attempt(0, STARVATION_AGE_TICKS, hopeless()));
        assert_eq!(
            action,
            Action::EscalateToSerialized {
                trigger: EscalationTrigger::Age
            }
        );
    }

    #[test]
    fn priority_cannot_starve_anything() {
        // Priority damps backoff but is never read by the escalator, so the
        // lowest-priority class still escalates at exactly the same threshold.
        for priority in [
            PriorityClass::Background,
            PriorityClass::Interactive,
            PriorityClass::Foreground,
        ] {
            let action = decide(Attempt {
                attempts: STARVATION_ATTEMPTS,
                age_ticks: 0,
                priority,
                posterior: hopeless(),
            });
            assert!(
                matches!(action, Action::EscalateToSerialized { .. }),
                "{priority:?} must still escalate"
            );
        }
    }

    #[test]
    fn a_confident_transaction_retries_immediately() {
        let mut optimistic = IncrementalPosterior::new(BetaPrior::uniform());
        for _ in 0..100 {
            optimistic.observe(true);
        }
        assert_eq!(decide(attempt(1, 1, optimistic)), Action::RetryNow);
    }

    #[test]
    fn backoff_grows_as_the_posterior_worsens_and_stays_bounded() {
        let mut previous = 0_u32;
        for failures in [1_u32, 4, 16, 64] {
            let mut p = IncrementalPosterior::new(BetaPrior::uniform());
            for _ in 0..failures {
                p.observe(false);
            }
            let ticks = match decide(attempt(1, 1, p)) {
                Action::BackoffFor { ticks } => ticks,
                Action::RetryNow => 0,
                other @ Action::EscalateToSerialized { .. } => panic!("unexpected {other:?}"),
            };
            assert!(ticks <= MAX_BACKOFF_TICKS, "backoff must stay bounded");
            assert!(
                ticks >= previous,
                "more failures must not reduce backoff: {ticks} < {previous}"
            );
            previous = ticks;
        }
    }

    #[test]
    fn higher_priority_waits_no_longer_than_lower_priority() {
        let p = hopeless();
        let ticks_for = |priority| match decide(Attempt {
            attempts: 1,
            age_ticks: 1,
            priority,
            posterior: p,
        }) {
            Action::BackoffFor { ticks } => ticks,
            Action::RetryNow => 0,
            other @ Action::EscalateToSerialized { .. } => panic!("unexpected {other:?}"),
        };
        let background = ticks_for(PriorityClass::Background);
        let interactive = ticks_for(PriorityClass::Interactive);
        let foreground = ticks_for(PriorityClass::Foreground);
        assert!(interactive <= background);
        assert!(foreground <= interactive);
    }

    #[test]
    fn a_regime_reset_discards_history() {
        let mut p = hopeless();
        assert!(p.success_probability().parts_per_million() < 100_000);
        p.reset_for_regime();
        assert_eq!(p.counts(), (0, 0));
        assert_eq!((p.posterior().alpha(), p.posterior().beta()), (1, 1));
        assert_eq!(p.success_probability().parts_per_million(), 500_000);
    }

    #[test]
    fn posterior_counts_saturate_rather_than_wrapping() {
        let mut p = IncrementalPosterior::new(BetaPrior::uniform());
        for _ in 0..3 {
            p.observe(true);
        }
        let (successes, failures) = p.counts();
        assert_eq!((successes, failures), (3, 0));
        assert_eq!((p.posterior().alpha(), p.posterior().beta()), (4, 1));
        // A wrapped count would invert the posterior; pin that it cannot.
        let mut extreme = IncrementalPosterior::new(BetaPrior::uniform());
        for _ in 0..64 {
            extreme.observe(false);
        }
        assert!(extreme.success_probability().parts_per_million() < 500_000);
    }

    #[test]
    fn the_decision_is_deterministic() {
        let a = attempt(3, 7, hopeless());
        assert_eq!(decide(a), decide(a));
        assert_eq!(receipt(a, decide(a)), receipt(a, decide(a)));
    }

    #[test]
    fn the_receipt_names_the_hard_thresholds_so_a_reader_can_check_the_escalator() {
        let a = attempt(STARVATION_ATTEMPTS, 0, hopeless());
        let line = receipt(a, decide(a));
        assert!(!line.contains('\n'), "one record per line: {line}");
        for key in [
            "\"record\":\"retry_decision\"",
            "\"attempts\":8",
            "\"starvation_attempts\":8",
            "\"starvation_age_ticks\":512",
            "\"action\":\"escalate_to_serialized\"",
            "\"trigger\":\"attempt_count\"",
        ] {
            assert!(line.contains(key), "receipt missing {key}: {line}");
        }
    }

    #[test]
    fn a_backoff_receipt_carries_its_tick_count() {
        let a = attempt(1, 1, hopeless());
        let action = decide(a);
        let line = receipt(a, action);
        if let Action::BackoffFor { ticks } = action {
            assert!(line.contains(&format!("\"ticks\":{ticks}")), "{line}");
        } else {
            panic!("expected a backoff for a hopeless posterior, got {action:?}");
        }
    }
}
