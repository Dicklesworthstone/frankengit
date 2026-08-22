//! Off-policy evaluation with executable support and effective-sample-size gates.
//!
//! Section 33 permits off-policy evaluation only behind two gates, and both
//! exist because the estimator fails *quietly* without them. An importance
//! weight is `target / behavior`, so a behaviour propensity near zero produces
//! an enormous weight, one sample dominates the estimate, and the result still
//! looks like an average over the whole batch. Nothing about the returned number
//! reveals that it rests on a single observation.
//!
//! * The **support gate** refuses any sample whose behaviour propensity falls
//!   outside the declared range. This is where a logged propensity of zero — an
//!   action the behaviour policy could not have taken — is caught, rather than
//!   becoming a division by zero or an infinite weight.
//! * The **effective-sample-size gate** refuses the whole estimate when the
//!   weights concentrate. It is the check that catches "technically in support
//!   but one weight carries the batch".
//!
//! # Where the arithmetic divides, and why that is safe here
//!
//! [`crate::regime`] avoids division because its error would compound: a
//! truncated running mean feeds back into an accumulator, and the alarm point
//! then depends on the order and width of the arithmetic. Nothing here has that
//! shape. Each weight is computed once from its own two inputs, so truncation is
//! a fixed per-weight quantisation rather than a compounding one, and integer
//! truncation is identical on every target. The distinction is between
//! *deterministic* rounding, which is fine, and rounding that *accumulates*,
//! which is not.
//!
//! The ESS gate divides only when it refuses. `ESS >= k` is tested as
//! `(sum w)^2 >= k * sum w^2`, which needs no division at all; the quotient is
//! computed afterwards purely to name a number in the refusal. That mirrors
//! `fgit-types`' own rule of clamping only when reporting, never when deciding.
//!
//! # Overflow is a refusal
//!
//! Weights are bounded by the declared support floor, but a long enough batch
//! still overflows. Every accumulation is checked, and exhaustion returns
//! [`OpeRefusal::AccumulatorOverflow`] rather than saturating: a saturated total
//! would silently change the estimate's denominator.

/// Parts per million, the fixed-point scale for propensities.
const PARTS_PER_MILLION: u64 = 1_000_000;

/// One logged interaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LoggedSample {
    /// The probability the behaviour policy took this action, in parts per million.
    ///
    /// This is *logged data*, not a derived counter: it comes from whatever
    /// policy was running at the time and may be wrong, stale, or zero. That is
    /// exactly why the support gate exists.
    pub behavior_parts_per_million: u32,
    /// The probability the target policy would take it, in parts per million.
    pub target_parts_per_million: u32,
    /// The observed reward, on the caller's fixed-point scale.
    pub reward: i64,
}

/// How the gates are configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OffPolicyConfig {
    /// The smallest behaviour propensity the caller declares evaluable.
    ///
    /// This is the support floor, and it bounds the largest possible importance
    /// weight at `1_000_000 * 1_000_000 / floor`.
    pub min_behavior_parts_per_million: u32,
    /// The largest behaviour propensity admitted.
    pub max_behavior_parts_per_million: u32,
    /// The smallest effective sample size that admits an estimate.
    pub min_effective_sample_size: u32,
}

/// Why a configuration cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OpeAssumptionFailure {
    /// A support floor of zero admits an unbounded weight, which is the failure
    /// the gate exists to prevent.
    SupportFloorZero,
    /// The floor exceeds the ceiling, so no sample could ever be in support.
    SupportRangeInverted {
        /// The floor offered.
        min: u32,
        /// The ceiling offered.
        max: u32,
    },
    /// A propensity above one is not a probability.
    SupportCeilingAboveOne {
        /// The ceiling offered.
        max: u32,
    },
    /// Requiring an effective sample size of zero disables the gate.
    EffectiveSampleSizeZero,
}

/// Why an estimate was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OpeRefusal {
    /// No samples were offered.
    Empty,
    /// A behaviour propensity fell outside the declared support.
    OutsideSupport {
        /// Which sample.
        index: usize,
        /// The offending propensity.
        behavior_parts_per_million: u32,
    },
    /// A target propensity exceeded one.
    TargetAboveOne {
        /// Which sample.
        index: usize,
        /// The offending propensity.
        target_parts_per_million: u32,
    },
    /// The weights concentrate too much for the batch to support an estimate.
    EffectiveSampleTooSmall {
        /// The effective size, computed only to name it here.
        effective: u64,
        /// What the configuration required.
        required: u32,
    },
    /// The weights summed past what the accumulator can represent.
    AccumulatorOverflow,
    /// Every weight was zero, so the estimate has no denominator.
    ///
    /// Reachable when the target policy assigns zero probability to every logged
    /// action: the batch is in support but says nothing about the target.
    ZeroTotalWeight,
}

/// A self-normalised importance-sampling estimate, with its gate evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OffPolicyEstimate {
    /// The estimated value, on the reward's own scale.
    pub value: i64,
    /// The effective sample size the batch achieved.
    pub effective_sample_size: u64,
    /// How many samples contributed.
    pub samples: u32,
}

/// An off-policy evaluator with both gates configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OffPolicyEvaluator {
    config: OffPolicyConfig,
}

impl OffPolicyEvaluator {
    /// Builds an evaluator, checking the gates are meaningful.
    ///
    /// # Errors
    ///
    /// Returns the failed assumption.
    pub const fn new(config: OffPolicyConfig) -> Result<Self, OpeAssumptionFailure> {
        if config.min_behavior_parts_per_million == 0 {
            return Err(OpeAssumptionFailure::SupportFloorZero);
        }
        if config.max_behavior_parts_per_million as u64 > PARTS_PER_MILLION {
            return Err(OpeAssumptionFailure::SupportCeilingAboveOne {
                max: config.max_behavior_parts_per_million,
            });
        }
        if config.min_behavior_parts_per_million > config.max_behavior_parts_per_million {
            return Err(OpeAssumptionFailure::SupportRangeInverted {
                min: config.min_behavior_parts_per_million,
                max: config.max_behavior_parts_per_million,
            });
        }
        if config.min_effective_sample_size == 0 {
            return Err(OpeAssumptionFailure::EffectiveSampleSizeZero);
        }
        Ok(Self { config })
    }

    /// The configuration in force.
    #[must_use]
    pub const fn config(self) -> OffPolicyConfig {
        self.config
    }

    /// The largest importance weight this configuration admits.
    ///
    /// Bounded by the support floor, which is what makes the accumulator's
    /// capacity a checkable property rather than a hope.
    #[must_use]
    pub const fn max_weight(self) -> u64 {
        PARTS_PER_MILLION * PARTS_PER_MILLION / self.config.min_behavior_parts_per_million as u64
    }

    /// Evaluates the target policy against logged behaviour, gates first.
    ///
    /// # Errors
    ///
    /// Returns [`OpeRefusal`]. The support gate is applied per sample before any
    /// accumulation, so an out-of-support sample cannot contribute to a total
    /// that is later reported as refused.
    pub fn evaluate(self, samples: &[LoggedSample]) -> Result<OffPolicyEstimate, OpeRefusal> {
        if samples.is_empty() {
            return Err(OpeRefusal::Empty);
        }

        let mut sum_weights: u128 = 0;
        let mut sum_squares: u128 = 0;
        let mut sum_weighted_reward: i128 = 0;

        for (index, sample) in samples.iter().enumerate() {
            let behavior = sample.behavior_parts_per_million;
            if u64::from(behavior) < u64::from(self.config.min_behavior_parts_per_million)
                || u64::from(behavior) > u64::from(self.config.max_behavior_parts_per_million)
            {
                return Err(OpeRefusal::OutsideSupport {
                    index,
                    behavior_parts_per_million: behavior,
                });
            }
            if u64::from(sample.target_parts_per_million) > PARTS_PER_MILLION {
                return Err(OpeRefusal::TargetAboveOne {
                    index,
                    target_parts_per_million: sample.target_parts_per_million,
                });
            }

            // One division per weight, from that weight's own two inputs. The
            // truncation does not feed into any later weight, so it quantises
            // rather than compounds.
            let weight = u64::from(sample.target_parts_per_million) * PARTS_PER_MILLION
                / u64::from(behavior);

            sum_weights = sum_weights
                .checked_add(u128::from(weight))
                .ok_or(OpeRefusal::AccumulatorOverflow)?;
            sum_squares = sum_squares
                .checked_add(u128::from(weight) * u128::from(weight))
                .ok_or(OpeRefusal::AccumulatorOverflow)?;
            sum_weighted_reward = i128::from(sample.reward)
                .checked_mul(i128::from(weight))
                .and_then(|term| sum_weighted_reward.checked_add(term))
                .ok_or(OpeRefusal::AccumulatorOverflow)?;
        }

        if sum_weights == 0 {
            return Err(OpeRefusal::ZeroTotalWeight);
        }

        // ESS = (sum w)^2 / sum w^2, tested without dividing:
        // ESS >= k  <=>  (sum w)^2 >= k * (sum w^2).
        let squared_total = sum_weights
            .checked_mul(sum_weights)
            .ok_or(OpeRefusal::AccumulatorOverflow)?;
        let required = u128::from(self.config.min_effective_sample_size);
        let threshold = required
            .checked_mul(sum_squares)
            .ok_or(OpeRefusal::AccumulatorOverflow)?;

        if squared_total < threshold {
            // Divide only to name the number in the refusal, never to decide.
            let effective = squared_total / sum_squares;
            return Err(OpeRefusal::EffectiveSampleTooSmall {
                effective: u64::try_from(effective).unwrap_or(u64::MAX),
                required: self.config.min_effective_sample_size,
            });
        }

        // Self-normalised: dividing by the realised weight total rather than by
        // the sample count keeps the estimate on the reward's scale even when
        // the weights do not average to one.
        //
        // `try_from` rather than `as`: the reward total is signed and the weight
        // total is not, so an `as` cast of a weight total past `i128::MAX` would
        // wrap to a negative divisor and flip the estimate's sign. A total that
        // large is an accumulator failure, which this already has a refusal for.
        let divisor = i128::try_from(sum_weights).map_err(|_| OpeRefusal::AccumulatorOverflow)?;
        let value = sum_weighted_reward / divisor;
        let effective_sample_size = squared_total / sum_squares;

        Ok(OffPolicyEstimate {
            value: i64::try_from(value).unwrap_or_else(|_| {
                if value.is_negative() {
                    i64::MIN
                } else {
                    i64::MAX
                }
            }),
            effective_sample_size: u64::try_from(effective_sample_size).unwrap_or(u64::MAX),
            samples: u32::try_from(samples.len()).unwrap_or(u32::MAX),
        })
    }
}
