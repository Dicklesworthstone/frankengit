//! An e-process alarm for a Bernoulli mean, in exact integer arithmetic.
//!
//! An e-process is a non-negative process whose expectation never grows under
//! the null hypothesis. That gives it the property section 33 wants: the alarm
//! `wealth >= 1 / alpha` may be checked at **every** step, after **any** number
//! of observations, without spending error budget on the looking. A p-value
//! checked repeatedly is invalid; an e-process checked repeatedly is not.
//!
//! The wealth here is the betting form: starting at one, each observation
//! multiplies by `1 + lambda * (x - p0)`, where `p0` is the null success rate
//! and `lambda` is the bet size.
//!
//! # The rounding direction is a correctness argument, not a preference
//!
//! Wealth is a product, so truncation *compounds* — the case
//! [`crate::regime`] avoids division to escape. It cannot be avoided here, so it
//! is aimed instead.
//!
//! Every rounding in [`EProcess::observe`] is chosen so the computed wealth is a
//! **lower bound** on the exact wealth: the added term is floored, the
//! subtracted term is ceilinged, and the product is floored. That makes the
//! alarm condition sound rather than merely approximate. Writing `W` for the
//! exact wealth and `W'` for the computed one, `W' <= W` gives
//!
//! ```text
//! { W' >= 1/alpha }  is a subset of  { W >= 1/alpha }
//! ```
//!
//! so `P(alarm) <= P(exact alarm) <= alpha`. **The type-I error guarantee
//! survives the integer arithmetic exactly.** What is lost is power: a true
//! departure may take a few more observations to cross. That is the correct
//! direction to lose in, and it is a real cost, stated rather than hidden.
//!
//! Rounding the other way would be the seductive choice — it detects sooner —
//! and it would silently void the guarantee the mechanism exists to provide.
//!
//! # The assumption that destroys the process if wrong
//!
//! The bet must keep the multiplier positive. With `x = 0` the multiplier is
//! `1 - lambda * p0`. Violate that and wealth reaches zero, the process is no
//! longer able to move, it can never recover, and the alarm can never fire again
//! — a detector that is silently and permanently dead.
//!
//! The textbook condition is `lambda * p0 < 1`, and here it is **wrong by one**.
//! Because the loss term is ceilinged, `lambda * p0 = 0.9999995` satisfies the
//! strict inequality and still ceilings to a loss of exactly one, giving a
//! multiplier of zero. [`EProcess::new`] therefore checks the loss it will
//! actually compute rather than the idealised bound the rounding steps past.
//! The boundary is exercised from both sides in the tests.

/// Parts per million.
const PARTS_PER_MILLION: u128 = 1_000_000;

/// How the e-process is configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EProcessConfig {
    /// The null success rate `p0`, in parts per million.
    pub null_rate_parts_per_million: u32,
    /// The bet size `lambda`, in parts per million.
    pub bet_parts_per_million: u32,
    /// The alarm level `alpha`, in parts per million.
    ///
    /// The alarm fires when wealth reaches `1 / alpha`.
    pub alarm_alpha_parts_per_million: u32,
}

/// Why a configuration cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EProcessAssumptionFailure {
    /// `p0` is not a probability strictly inside `(0, 1)`.
    ///
    /// At `p0 = 0` or `p0 = 1` the null is degenerate and a single contrary
    /// observation is already a proof, so a betting process is the wrong tool.
    NullRateNotInsideUnitInterval {
        /// The offered rate.
        null_rate_parts_per_million: u32,
    },
    /// `lambda <= 0` bets nothing, so wealth never moves.
    BetNotPositive,
    /// `lambda * p0 >= 1`: an observed failure would drive wealth to zero or
    /// below, permanently killing the process.
    BetCanExhaustWealth {
        /// The bet offered.
        bet_parts_per_million: u32,
        /// The null rate it was offered against.
        null_rate_parts_per_million: u32,
    },
    /// `alpha` is not a level strictly inside `(0, 1)`.
    AlarmLevelNotInsideUnitInterval {
        /// The offered level.
        alarm_alpha_parts_per_million: u32,
    },
}

/// Why an observation could not be processed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EProcessRefusal {
    /// The wealth grew past what the accumulator can represent.
    ///
    /// Refused rather than saturated: a saturated wealth would cross the alarm
    /// threshold for an arithmetic reason rather than an evidential one, which
    /// is a false alarm dressed as a detection.
    ///
    /// **Unreachable while the alarm latches, and deliberately retained.** The
    /// smallest admitted `alpha` is one part per million, so the threshold is at
    /// most `1e12`; the alarm stops the wealth at that point, and one further
    /// multiplication by at most `2e6` reaches `2e18` against a `u128` ceiling of
    /// about `3.4e38`. No test can drive this variant, and none pretends to.
    ///
    /// It stays because the bound is a consequence of the latch, not of the
    /// arithmetic. Removing the guard would make a future change to the latching
    /// behaviour silently unsafe instead of loudly refused.
    WealthOverflow,
}

/// What one observation did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EProcessStep {
    /// The wealth moved and the alarm has not fired.
    Accumulating {
        /// Wealth after the step, in parts per million.
        wealth_parts_per_million: u128,
    },
    /// The wealth reached the alarm level on this step or an earlier one.
    Alarmed {
        /// Wealth when the alarm fired, in parts per million.
        wealth_parts_per_million: u128,
    },
}

impl EProcessStep {
    /// Whether the alarm has fired.
    #[must_use]
    pub const fn alarmed(self) -> bool {
        matches!(self, Self::Alarmed { .. })
    }

    /// The wealth after this step.
    #[must_use]
    pub const fn wealth_parts_per_million(self) -> u128 {
        match self {
            Self::Accumulating {
                wealth_parts_per_million,
            }
            | Self::Alarmed {
                wealth_parts_per_million,
            } => wealth_parts_per_million,
        }
    }
}

/// A betting e-process over Bernoulli observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EProcess {
    config: EProcessConfig,
    wealth: u128,
    threshold: u128,
    observations: u32,
    alarmed: bool,
}

/// Ceiling division on `u128`, exact.
const fn div_ceil(numerator: u128, denominator: u128) -> u128 {
    numerator.div_ceil(denominator)
}

impl EProcess {
    /// Builds an e-process, checking the bet cannot exhaust the wealth.
    ///
    /// # Errors
    ///
    /// Returns the failed assumption.
    pub const fn new(config: EProcessConfig) -> Result<Self, EProcessAssumptionFailure> {
        let null = config.null_rate_parts_per_million as u128;
        let bet = config.bet_parts_per_million as u128;
        let alpha = config.alarm_alpha_parts_per_million as u128;

        if null == 0 || null >= PARTS_PER_MILLION {
            return Err(EProcessAssumptionFailure::NullRateNotInsideUnitInterval {
                null_rate_parts_per_million: config.null_rate_parts_per_million,
            });
        }
        if bet == 0 {
            return Err(EProcessAssumptionFailure::BetNotPositive);
        }
        if alpha == 0 || alpha >= PARTS_PER_MILLION {
            return Err(EProcessAssumptionFailure::AlarmLevelNotInsideUnitInterval {
                alarm_alpha_parts_per_million: config.alarm_alpha_parts_per_million,
            });
        }
        // The condition is that the failure multiplier stays strictly positive.
        //
        // The obvious test is `lambda * p0 < 1`, and it is WRONG here by one:
        // `observe` ceilings the loss term, so `lambda * p0 = 0.9999995` already
        // ceilings to a loss of exactly one and a multiplier of zero, while
        // satisfying the strict inequality. The check therefore computes the
        // very loss `observe` will compute, rather than an idealised bound that
        // the rounding then steps past.
        let loss = div_ceil(bet * null, PARTS_PER_MILLION);
        if loss >= PARTS_PER_MILLION {
            return Err(EProcessAssumptionFailure::BetCanExhaustWealth {
                bet_parts_per_million: config.bet_parts_per_million,
                null_rate_parts_per_million: config.null_rate_parts_per_million,
            });
        }

        // The alarm level is 1 / alpha, scaled: 1e6 * 1e6 / alpha. Ceiling, so
        // the threshold is never *below* the true 1/alpha -- the same soundness
        // direction as the wealth rounding.
        let threshold = div_ceil(PARTS_PER_MILLION * PARTS_PER_MILLION, alpha);

        Ok(Self {
            config,
            wealth: PARTS_PER_MILLION,
            threshold,
            observations: 0,
            alarmed: false,
        })
    }

    /// Feeds one Bernoulli observation.
    ///
    /// # Errors
    ///
    /// Returns [`EProcessRefusal::WealthOverflow`] rather than saturating.
    pub const fn observe(&mut self, success: bool) -> Result<EProcessStep, EProcessRefusal> {
        // The alarm is about the supremum over time, so once it has fired it
        // stays fired and the wealth stops moving. This also keeps a long run
        // after an alarm from overflowing for no benefit.
        if self.alarmed {
            return Ok(EProcessStep::Alarmed {
                wealth_parts_per_million: self.wealth,
            });
        }

        let null = self.config.null_rate_parts_per_million as u128;
        let bet = self.config.bet_parts_per_million as u128;

        // multiplier = 1 + lambda * (x - p0), in parts per million.
        //
        // Rounding is aimed so the multiplier is never above the exact value:
        // the added term floors, the subtracted term ceilings. See the module
        // docs for why that keeps the alarm sound.
        let multiplier = if success {
            let gain = bet * (PARTS_PER_MILLION - null) / PARTS_PER_MILLION;
            PARTS_PER_MILLION + gain
        } else {
            let loss = div_ceil(bet * null, PARTS_PER_MILLION);
            // `new` computed this same expression and refused unless it is
            // strictly below one, so this cannot underflow and the multiplier
            // cannot be zero.
            PARTS_PER_MILLION - loss
        };

        // Defensive, and measured to be unreachable while the latch above holds:
        // wealth alarms at `1 / alpha` -- at most 1e12 ppm, since alpha is a
        // non-zero u32 in parts per million -- and the latch then freezes it,
        // whereas this ceiling is around 2.7e32. A run of successes therefore
        // always latches long before it can overflow, which is what the comment
        // on the latch means by "keeps a long run after an alarm from
        // overflowing for no benefit".
        //
        // So this arm has no presence case and cannot honestly be given one.
        // What guarantees it is `the_alarm_latches_and_the_wealth_stops_moving`
        // in tests/e_process_alarm.rs: if that latch is ever removed or made
        // conditional, this becomes reachable and needs its own test.
        let Some(scaled) = self.wealth.checked_mul(multiplier) else {
            return Err(EProcessRefusal::WealthOverflow);
        };
        // Floor, so the running wealth stays a lower bound on the exact wealth.
        self.wealth = scaled / PARTS_PER_MILLION;
        self.observations = self.observations.saturating_add(1);

        if self.wealth >= self.threshold {
            self.alarmed = true;
            return Ok(EProcessStep::Alarmed {
                wealth_parts_per_million: self.wealth,
            });
        }
        Ok(EProcessStep::Accumulating {
            wealth_parts_per_million: self.wealth,
        })
    }

    /// The current wealth, in parts per million.
    ///
    /// A lower bound on the exact wealth, by construction.
    #[must_use]
    pub const fn wealth_parts_per_million(self) -> u128 {
        self.wealth
    }

    /// The wealth at which the alarm fires, in parts per million.
    #[must_use]
    pub const fn alarm_threshold_parts_per_million(self) -> u128 {
        self.threshold
    }

    /// Whether the alarm has fired.
    #[must_use]
    pub const fn alarmed(self) -> bool {
        self.alarmed
    }

    /// How many observations have been absorbed.
    #[must_use]
    pub const fn observations(self) -> u32 {
        self.observations
    }
}
