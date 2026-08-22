//! Successive elimination over a fixed arm set, in exact integer arithmetic.
//!
//! Successive elimination pulls every surviving arm equally often and drops an
//! arm once the leader beats it by more than the two confidence widths could
//! explain. It is the no-regret rule that fits this workspace best, because the
//! decision is a comparison and the exploration schedule is round-robin — there
//! is no randomisation to make deterministic and no index to compute.
//!
//! # Where the square root went
//!
//! The usual width is `sqrt(log(2 / delta) / (2 n))`, and neither the square
//! root nor the logarithm has an exact integer form. Rather than approximate
//! them at runtime — which would be either a float path the workspace forbids,
//! or an approximation whose error is itself an unevidenced claim — the widths
//! are **supplied as a declared schedule**: one half-width in parts per million
//! per pull count.
//!
//! That is not a workaround, it is a better division of labour. The schedule is
//! data: auditable, reviewable, bindable into an evidence record alongside the
//! decision it justified, and computable once by whatever tool is appropriate.
//! What stays here is the elimination logic, which is exact.
//!
//! The cost is real and stated: this crate cannot check that a supplied
//! schedule delivers the confidence level it claims. It checks the properties a
//! schedule must have to be a confidence schedule at all — see
//! [`EliminationAssumptionFailure`] — and no more. A schedule that is
//! well-formed but too narrow produces confident, wrong eliminations, and
//! nothing here would notice.
//!
//! # The leader always survives
//!
//! Elimination is relative to the current leader, so the leader can never be
//! eliminated by construction. That is worth stating because the alternative —
//! a rule that could empty the arm set — would leave a controller with nothing
//! to choose, and the natural repair (fall back to the first arm) would be a
//! silent default rather than a decision.

/// Parts per million.
const PARTS_PER_MILLION: u32 = 1_000_000;

/// Why an elimination configuration cannot be used.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EliminationAssumptionFailure {
    /// Fewer than two arms leaves nothing to select between.
    TooFewArms {
        /// The count offered.
        arms: u32,
    },
    /// The schedule has no entries, so no round could be evaluated.
    WidthScheduleEmpty,
    /// A width exceeds one, which cannot bound a difference of two means that
    /// are themselves at most one.
    WidthAboveOne {
        /// Where in the schedule.
        index: usize,
        /// The offending width.
        width: u32,
    },
    /// A width grows with more data.
    ///
    /// A confidence width that widens as evidence accumulates is not a
    /// confidence width. Worse, it would let an arm eliminated at one round
    /// become un-eliminable at the next, so the rule would never converge.
    WidthScheduleNotNonIncreasing {
        /// The index whose predecessor was narrower.
        index: usize,
    },
}

/// Why a round could not be evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EliminationRefusal {
    /// The means offered do not match the configured arm count.
    ArmCountMismatch {
        /// Arms configured.
        expected: u32,
        /// Means offered.
        observed: usize,
    },
    /// A mean above one is not a mean of bounded rewards on this scale.
    MeanAboveOne {
        /// Which arm.
        arm: u32,
        /// The offending mean.
        mean_parts_per_million: u32,
    },
    /// More rounds were run than the declared schedule covers.
    ///
    /// Refused rather than reusing the last width: continuing with a stale
    /// width would keep eliminating on a confidence level the schedule never
    /// claimed for that many pulls.
    ScheduleExhausted {
        /// The round that ran off the end.
        round: u32,
        /// How many rounds the schedule covers.
        covered: usize,
    },
}

/// What one round did.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoundOutcome {
    /// Arms still in contention, in index order.
    pub surviving: Vec<u32>,
    /// Arms eliminated by this round, in index order.
    pub eliminated: Vec<u32>,
    /// The half-width applied.
    pub width_parts_per_million: u32,
}

/// A successive-elimination selector over a fixed arm set.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SuccessiveElimination {
    widths: Vec<u32>,
    active: Vec<bool>,
    round: u32,
}

impl SuccessiveElimination {
    /// Builds a selector from an arm count and a declared width schedule.
    ///
    /// `widths[k]` is the half-width, in parts per million, after round `k`.
    ///
    /// # Errors
    ///
    /// Returns the failed assumption. The schedule must be non-empty, bounded by
    /// one, and non-increasing.
    pub fn new(arms: u32, widths: Vec<u32>) -> Result<Self, EliminationAssumptionFailure> {
        if arms < 2 {
            return Err(EliminationAssumptionFailure::TooFewArms { arms });
        }
        if widths.is_empty() {
            return Err(EliminationAssumptionFailure::WidthScheduleEmpty);
        }
        for (index, width) in widths.iter().enumerate() {
            if *width > PARTS_PER_MILLION {
                return Err(EliminationAssumptionFailure::WidthAboveOne {
                    index,
                    width: *width,
                });
            }
            if index > 0 && *width > widths[index - 1] {
                return Err(EliminationAssumptionFailure::WidthScheduleNotNonIncreasing { index });
            }
        }
        Ok(Self {
            widths,
            active: vec![true; arms as usize],
            round: 0,
        })
    }

    /// Runs one round against the observed means.
    ///
    /// An arm is eliminated when the leader's mean exceeds its own by more than
    /// twice the round's half-width — one width for each arm's own uncertainty.
    ///
    /// # Errors
    ///
    /// Returns [`EliminationRefusal`].
    pub fn advance(&mut self, means: &[u32]) -> Result<RoundOutcome, EliminationRefusal> {
        let arms = self.active.len();
        if means.len() != arms {
            return Err(EliminationRefusal::ArmCountMismatch {
                expected: u32::try_from(arms).unwrap_or(u32::MAX),
                observed: means.len(),
            });
        }
        for (arm, mean) in means.iter().enumerate() {
            if *mean > PARTS_PER_MILLION {
                return Err(EliminationRefusal::MeanAboveOne {
                    arm: u32::try_from(arm).unwrap_or(u32::MAX),
                    mean_parts_per_million: *mean,
                });
            }
        }
        let Some(width) = self.widths.get(self.round as usize).copied() else {
            return Err(EliminationRefusal::ScheduleExhausted {
                round: self.round,
                covered: self.widths.len(),
            });
        };

        // The leader among ACTIVE arms only. An eliminated arm's mean must not
        // set the bar, or a dropped arm could keep eliminating its rivals.
        let leader = (0..arms)
            .filter(|arm| self.active[*arm])
            .map(|arm| means[arm])
            .max()
            .unwrap_or(0);

        // Two widths: one for the leader's uncertainty and one for the
        // challenger's. Using a single width would eliminate an arm that is
        // within its own confidence interval of the leader.
        let gap = u64::from(width) * 2;

        let mut eliminated = Vec::new();
        for arm in 0..arms {
            if !self.active[arm] {
                continue;
            }
            // The leader can never satisfy this against itself, so it always
            // survives.
            if u64::from(leader) - u64::from(means[arm]) > gap {
                self.active[arm] = false;
                eliminated.push(u32::try_from(arm).unwrap_or(u32::MAX));
            }
        }

        self.round = self.round.saturating_add(1);
        Ok(RoundOutcome {
            surviving: self.active_arms(),
            eliminated,
            width_parts_per_million: width,
        })
    }

    /// The arms still in contention, in index order.
    #[must_use]
    pub fn active_arms(&self) -> Vec<u32> {
        (0..self.active.len())
            .filter(|arm| self.active[*arm])
            .map(|arm| u32::try_from(arm).unwrap_or(u32::MAX))
            .collect()
    }

    /// How many rounds have been run.
    #[must_use]
    pub const fn rounds(&self) -> u32 {
        self.round
    }

    /// Whether exactly one arm remains.
    #[must_use]
    pub fn converged(&self) -> bool {
        self.active.iter().filter(|active| **active).count() == 1
    }
}
