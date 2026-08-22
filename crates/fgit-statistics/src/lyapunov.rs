//! Lyapunov progress governor: is the system actually draining, or just busy?
//!
//! A queue-like system is stable when some non-negative potential `V` — backlog,
//! outstanding obligations, unacknowledged effects — trends down. The Lyapunov
//! condition makes that checkable one step at a time:
//!
//! * the potential may never jump by more than a declared bound `B`, and
//! * whenever the potential is **above** a congestion threshold, the step must
//!   decrease it by at least `epsilon`.
//!
//! Below the threshold no decrease is required, because a system that is nearly
//! empty has nothing to drain and demanding progress there would refuse a
//! healthy idle state.
//!
//! # Why this is a governor and not a metric
//!
//! The failure it exists to catch is a controller that is *working* — throughput
//! up, latency flat, every dashboard green — while the backlog it is supposed to
//! be clearing grows. Every per-step measurement looks fine; only the potential
//! reveals it. A governor that merely reports the drift would leave someone to
//! notice; this one returns a verdict the caller must match on, and
//! [`ProgressVerdict::is_violation`] feeds the deterministic fallback.
//!
//! # Which potential the threshold is tested against
//!
//! The decrease requirement is conditioned on the potential the step started
//! from, not the one it reached. Testing the *new* value would let a step that
//! overshot from far above the threshold down to just below it report as
//! compliant, which inverts the check exactly when the system is worst off.

/// How the governor is configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LyapunovConfig {
    /// `B`: the largest single-step increase in potential that is tolerated.
    ///
    /// Applies everywhere, including below the congestion threshold: an idle
    /// system is allowed to have nothing to do, not to explode.
    pub drift_bound: i64,
    /// `epsilon`: the decrease each step must achieve while above the threshold.
    pub required_decrease: i64,
    /// The potential above which progress is required.
    pub congestion_threshold: i64,
}

/// Why a configuration cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LyapunovAssumptionFailure {
    /// `epsilon <= 0` requires no progress at all, so the governor would admit a
    /// system that never drains while appearing to check that it does.
    RequiredDecreaseNotPositive,
    /// A negative bound on an increase is not a bound.
    DriftBoundNegative,
    /// A negative congestion threshold is unreachable by a non-negative
    /// potential, so the decrease requirement would apply always — including to
    /// an empty system, which can never satisfy it.
    ThresholdNegative,
}

/// Why an observation could not be accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LyapunovRefusal {
    /// A Lyapunov potential is non-negative by definition.
    PotentialNegative {
        /// The value offered.
        potential: i64,
    },
}

/// What one step said about the system's progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProgressVerdict {
    /// The first observation: there is no previous potential to drift from.
    Initialized,
    /// The step started below the congestion threshold, so no decrease was
    /// required, and it stayed within the drift bound.
    WithinBoundedRegion {
        /// The observed change.
        drift: i64,
    },
    /// The step decreased the potential by at least `epsilon`.
    Progressing {
        /// The observed change, negative or zero.
        drift: i64,
    },
    /// The potential jumped further than the declared bound allows.
    DriftBoundExceeded {
        /// The observed change.
        drift: i64,
        /// The declared bound.
        bound: i64,
    },
    /// The system was congested and did not drain fast enough.
    InsufficientDecrease {
        /// The observed change.
        drift: i64,
        /// The decrease that was required.
        required: i64,
    },
}

impl ProgressVerdict {
    /// Whether this verdict disqualifies the adaptive candidate.
    ///
    /// [`Self::Initialized`] is **not** a violation: no drift has been observed
    /// yet, and treating "no evidence" as "bad evidence" would put every
    /// controller on its fallback for one step at startup.
    #[must_use]
    pub const fn is_violation(self) -> bool {
        matches!(
            self,
            Self::DriftBoundExceeded { .. } | Self::InsufficientDecrease { .. }
        )
    }

    /// The observed change, when one was computable.
    #[must_use]
    pub const fn drift(self) -> Option<i64> {
        match self {
            Self::Initialized => None,
            Self::WithinBoundedRegion { drift }
            | Self::Progressing { drift }
            | Self::DriftBoundExceeded { drift, .. }
            | Self::InsufficientDecrease { drift, .. } => Some(drift),
        }
    }
}

/// A one-step Lyapunov drift governor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LyapunovGovernor {
    config: LyapunovConfig,
    previous: Option<i64>,
}

impl LyapunovGovernor {
    /// Builds a governor, checking its assumptions first.
    ///
    /// # Errors
    ///
    /// Returns the failed assumption.
    pub const fn new(config: LyapunovConfig) -> Result<Self, LyapunovAssumptionFailure> {
        if config.required_decrease <= 0 {
            return Err(LyapunovAssumptionFailure::RequiredDecreaseNotPositive);
        }
        if config.drift_bound < 0 {
            return Err(LyapunovAssumptionFailure::DriftBoundNegative);
        }
        if config.congestion_threshold < 0 {
            return Err(LyapunovAssumptionFailure::ThresholdNegative);
        }
        Ok(Self {
            config,
            previous: None,
        })
    }

    /// Feeds one potential and returns the verdict for that step.
    ///
    /// # Errors
    ///
    /// Returns [`LyapunovRefusal::PotentialNegative`] for a negative potential,
    /// which is not a Lyapunov function value.
    pub const fn observe(&mut self, potential: i64) -> Result<ProgressVerdict, LyapunovRefusal> {
        if potential < 0 {
            return Err(LyapunovRefusal::PotentialNegative { potential });
        }
        let Some(previous) = self.previous else {
            self.previous = Some(potential);
            return Ok(ProgressVerdict::Initialized);
        };
        self.previous = Some(potential);

        let drift = potential.saturating_sub(previous);

        // The bound applies everywhere: an idle system may have nothing to do,
        // but it may not explode.
        if drift > self.config.drift_bound {
            return Ok(ProgressVerdict::DriftBoundExceeded {
                drift,
                bound: self.config.drift_bound,
            });
        }

        // Conditioned on where the step STARTED -- see the module docs.
        if previous <= self.config.congestion_threshold {
            return Ok(ProgressVerdict::WithinBoundedRegion { drift });
        }
        if drift > -self.config.required_decrease {
            return Ok(ProgressVerdict::InsufficientDecrease {
                drift,
                required: self.config.required_decrease,
            });
        }
        Ok(ProgressVerdict::Progressing { drift })
    }

    /// The potential most recently observed.
    #[must_use]
    pub const fn potential(self) -> Option<i64> {
        self.previous
    }

    /// The configuration in force.
    #[must_use]
    pub const fn config(self) -> LyapunovConfig {
        self.config
    }
}
