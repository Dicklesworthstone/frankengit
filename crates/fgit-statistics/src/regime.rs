//! FG-054 deliverable 3, prototype: regime-shift detection in EXACT INTEGER arithmetic.
//!
//! Not yet a crate. NPC §33's mechanism library is conventionally floating point
//! end to end; this workspace has **no floating point at all** — `CanonicalScalar`
//! is sealed to the eight fixed-width integers, and `f32`/`f64`/`usize`/`isize`
//! are excluded so canonical bytes can never depend on rounding mode, NaN payload,
//! signed zero, or host width. §33.1 also requires an arithmetic fingerprint
//! precisely so a stream's numbers replay exactly.
//!
//! So a detector here must be integer *throughout*, not float-internally-then-
//! quantised: an alarm that depends on `f64` accumulation is irreproducible across
//! targets even when its published output is an integer.
//!
//! # Why two-sided CUSUM and not the textbook Page-Hinkley
//!
//! Page-Hinkley accumulates `x_t - x̄_t - δ` against a **running mean**, and a
//! running mean needs division. Integer division truncates, the truncation error
//! compounds into the accumulator, and the alarm point then depends on the order
//! and width of the arithmetic — the exact irreproducibility this workspace
//! forbids. Rescaling to keep a fractional mean just moves the rounding.
//!
//! Two-sided CUSUM against a **fixed reference** `target` needs no division at
//! all: every operation is add, subtract, compare, and clamp at zero. The
//! sequence of accumulator values is therefore identical on every target, which
//! is what makes the detector's decision path replayable.
//!
//! The cost is honest and stated: CUSUM detects a shift away from a *declared*
//! target, where Page-Hinkley adapts to the observed level. That is a real
//! capability difference and it belongs in the mechanism's assumptions, not
//! hidden — a caller with no defensible target must not use this detector.
//!
//! # Saturation is a refusal, not a wraparound
//!
//! Accumulators saturate rather than wrap. A wrapped accumulator silently
//! *cancels* an alarm — the one failure a drift detector must never have. But
//! saturation is not silently benign either: a saturated accumulator has lost the
//! magnitude of the excursion, so [`Cusum::saturated`] reports it and the
//! assumption check refuses a configuration that can reach saturation within its
//! declared observation bound.

/// Observations and thresholds share one caller-declared fixed-point scale.
///
/// The detector never interprets the scale; it only requires every input to use
/// the same one. §33.1 binds metric+units on the evidence stream, which is where
/// the scale's meaning lives.
pub type Scaled = i64;

/// A regime-shift detector's configuration, with its assumptions checkable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CusumConfig {
    /// The level the stream is declared to hold while in-regime.
    pub target: Scaled,
    /// Slack: excursions smaller than this are absorbed rather than accumulated.
    ///
    /// This is what stops ordinary noise from ramping the accumulator. It must be
    /// positive, or every observation above target accumulates and the detector
    /// alarms on any stream that is not exactly at target.
    pub slack: Scaled,
    /// Decision threshold: the accumulator alarms strictly above this.
    pub threshold: Scaled,
    /// The largest `|observation - target|` the caller declares possible.
    ///
    /// Used only by [`CusumConfig::check_assumptions`] to prove the accumulator
    /// cannot saturate within `max_observations`.
    pub max_deviation: Scaled,
    /// The longest run the caller declares this detector will be asked to absorb.
    pub max_observations: u32,
}

/// Why a configuration cannot be used.
///
/// Every variant names a condition that would make the detector's output
/// meaningless rather than merely suboptimal, which is the line NPC §33 draws
/// between an assumption and a tuning preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssumptionFailure {
    /// `slack <= 0`: noise would accumulate without bound and alarm on any
    /// stream not exactly at target.
    SlackNotPositive,
    /// `threshold <= 0`: the detector would alarm before observing anything.
    ThresholdNotPositive,
    /// `max_deviation < 0`: a bound on an absolute value cannot be negative.
    MaxDeviationNegative,
    /// The declared run can drive the accumulator past `i64::MAX`.
    ///
    /// Saturation loses excursion magnitude, so the detector must refuse the
    /// configuration rather than silently produce a capped statistic.
    CanSaturate {
        /// Worst-case accumulator growth per observation.
        per_observation: Scaled,
        /// Observations the caller declared.
        observations: u32,
    },
}

impl CusumConfig {
    /// Executable assumption check, per §33's requirement that each mechanism's
    /// assumptions be checkable rather than documented.
    ///
    /// # Errors
    ///
    /// Returns the first failed assumption.
    pub const fn check_assumptions(&self) -> Result<(), AssumptionFailure> {
        if self.slack <= 0 {
            return Err(AssumptionFailure::SlackNotPositive);
        }
        if self.threshold <= 0 {
            return Err(AssumptionFailure::ThresholdNotPositive);
        }
        if self.max_deviation < 0 {
            return Err(AssumptionFailure::MaxDeviationNegative);
        }
        // Worst case per observation: the deviation is at its declared maximum
        // and the slack absorbs only `slack` of it.
        let per_observation = self.max_deviation.saturating_sub(self.slack);
        if per_observation > 0 {
            let budget = i64::MAX / per_observation;
            if (self.max_observations as i64) > budget {
                return Err(AssumptionFailure::CanSaturate {
                    per_observation,
                    observations: self.max_observations,
                });
            }
        }
        Ok(())
    }
}

/// Which direction an alarm fired in — a shift up and a shift down are different
/// regimes and a caller's fallback may differ between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shift {
    /// The stream moved above `target`.
    Upward,
    /// The stream moved below `target`.
    Downward,
}

/// A two-sided CUSUM detector.
#[derive(Clone, Copy, Debug)]
pub struct Cusum {
    config: CusumConfig,
    high: Scaled,
    low: Scaled,
    observations: u32,
    saturated: bool,
}

impl Cusum {
    /// Builds a detector, checking its assumptions first.
    ///
    /// # Errors
    ///
    /// Returns the failed assumption; a detector is never constructed from a
    /// configuration whose output would be meaningless.
    pub const fn new(config: CusumConfig) -> Result<Self, AssumptionFailure> {
        match config.check_assumptions() {
            Err(failure) => Err(failure),
            Ok(()) => Ok(Self {
                config,
                high: 0,
                low: 0,
                observations: 0,
                saturated: false,
            }),
        }
    }

    /// Feeds one observation and reports an alarm if the threshold was crossed.
    ///
    /// Every operation is add, subtract, compare and clamp — no division, no
    /// rounding, so the accumulator sequence is identical on every target.
    pub const fn observe(&mut self, value: Scaled) -> Option<Shift> {
        let deviation = value.saturating_sub(self.config.target);

        let high_step = deviation.saturating_sub(self.config.slack);
        let next_high = self.high.saturating_add(high_step);
        self.high = if next_high > 0 { next_high } else { 0 };

        let low_step = deviation.saturating_add(self.config.slack);
        let next_low = self.low.saturating_add(low_step);
        self.low = if next_low < 0 { next_low } else { 0 };

        if self.high == i64::MAX || self.low == i64::MIN {
            self.saturated = true;
        }
        self.observations = self.observations.saturating_add(1);

        if self.high > self.config.threshold {
            Some(Shift::Upward)
        } else if self.low < -self.config.threshold {
            Some(Shift::Downward)
        } else {
            None
        }
    }

    /// The upward accumulator, for a decision-path witness (§8).
    #[must_use]
    pub const fn high(&self) -> Scaled {
        self.high
    }

    /// The downward accumulator, for a decision-path witness (§8).
    #[must_use]
    pub const fn low(&self) -> Scaled {
        self.low
    }

    /// Observations fed so far.
    #[must_use]
    pub const fn observations(&self) -> u32 {
        self.observations
    }

    /// Whether an accumulator ever saturated.
    ///
    /// A saturated accumulator has lost the magnitude of its excursion, so a
    /// caller must treat the statistic as a lower bound rather than a value —
    /// which is why `check_assumptions` refuses configurations that can reach it.
    #[must_use]
    pub const fn saturated(&self) -> bool {
        self.saturated
    }
}
