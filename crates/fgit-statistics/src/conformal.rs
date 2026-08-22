//! Split conformal bounds, in exact integer arithmetic.
//!
//! Split conformal is the one distribution-free mechanism in section 33's
//! library that needs no floating point at all: the bound *is* an order
//! statistic of the calibration scores, so the only arithmetic is choosing which
//! rank to take. That choice is a ceiling division on integers, and everything
//! after it is a comparison.
//!
//! # The assumption that is usually skipped
//!
//! The rank is `ceil((n + 1) * (1 - alpha))`. When the calibration set is too
//! small for the requested miscoverage level, that rank exceeds `n` — there is
//! no such order statistic, and the honest answer is that no finite bound holds
//! at that level. The textbook convention is to return infinity, which in a
//! system with integer scores becomes "the largest score", and the caller gets a
//! bound that looks finite, looks tight, and guarantees nothing.
//!
//! That is not a corner case. At `alpha = 0.05` it bites for every calibration
//! set below 19, which is exactly the size a first integration reaches for. So
//! [`SplitConformal::new`] refuses the configuration rather than the call: the
//! failure belongs where the level and the set size are chosen, not where a
//! bound is later requested.
//!
//! # Why the caller's scores are not sorted here
//!
//! [`SplitConformal::quantile`] requires ascending input and refuses anything
//! else instead of sorting it. Sorting would be one line and would hide the
//! defect it exists to catch: a caller who passes an unsorted slice has almost
//! always passed the wrong slice — the raw observations rather than the
//! calibration scores, or a set that some earlier step failed to maintain.
//! Silently sorting turns that into a plausible number.

use crate::regime::Scaled;

/// Parts per million, the fixed-point scale for the miscoverage level.
const PARTS_PER_MILLION: u64 = 1_000_000;

/// A split conformal configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConformalConfig {
    /// Miscoverage level, in parts per million.
    ///
    /// `50_000` is the familiar `alpha = 0.05`. Integer parts-per-million rather
    /// than a float so the chosen rank is identical on every target.
    pub alpha_parts_per_million: u32,
    /// How many calibration scores will be supplied.
    pub calibration_size: u32,
}

/// Why a conformal configuration cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConformalAssumptionFailure {
    /// `alpha = 0` asks for total coverage, which no finite bound provides.
    AlphaZero,
    /// `alpha >= 1` asks for a bound that need cover nothing.
    AlphaNotBelowOne {
        /// The offered level.
        alpha_parts_per_million: u32,
    },
    /// An empty calibration set has no order statistics.
    CalibrationEmpty,
    /// The calibration set is too small for the requested level.
    ///
    /// The required rank exceeds the number of scores, so no finite bound holds
    /// at this level. Returning the largest score instead — the usual
    /// convention — produces a bound that looks finite and guarantees nothing.
    CalibrationTooSmall {
        /// The rank the level requires.
        required_rank: u64,
        /// How many scores are available.
        available: u32,
    },
}

/// Why a bound could not be computed from the scores offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConformalRefusal {
    /// The slice length differs from the configured calibration size.
    ///
    /// The rank was chosen for a specific `n`; applying it to a different one
    /// silently changes the coverage level.
    CalibrationSizeMismatch {
        /// The configured size.
        expected: u32,
        /// The size offered.
        observed: usize,
    },
    /// The scores are not in ascending order.
    ScoresUnsorted {
        /// The index whose predecessor was larger.
        index: usize,
    },
}

/// A split conformal bound at a fixed level and calibration size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SplitConformal {
    config: ConformalConfig,
    rank: u32,
}

impl SplitConformal {
    /// Chooses the order statistic for this level, checking it exists.
    ///
    /// # Errors
    ///
    /// Returns the failed assumption. In particular
    /// [`ConformalAssumptionFailure::CalibrationTooSmall`] when the level needs
    /// more calibration scores than will be supplied.
    pub fn new(config: ConformalConfig) -> Result<Self, ConformalAssumptionFailure> {
        if config.alpha_parts_per_million == 0 {
            return Err(ConformalAssumptionFailure::AlphaZero);
        }
        if u64::from(config.alpha_parts_per_million) >= PARTS_PER_MILLION {
            return Err(ConformalAssumptionFailure::AlphaNotBelowOne {
                alpha_parts_per_million: config.alpha_parts_per_million,
            });
        }
        if config.calibration_size == 0 {
            return Err(ConformalAssumptionFailure::CalibrationEmpty);
        }

        // rank = ceil((n + 1) * (1 - alpha)), all in parts per million.
        // `ceil(a / b)` is `(a + b - 1) / b`, exact on integers.
        let keep = PARTS_PER_MILLION - u64::from(config.alpha_parts_per_million);
        let numerator = (u64::from(config.calibration_size) + 1) * keep;
        let rank = numerator.div_ceil(PARTS_PER_MILLION);

        if rank > u64::from(config.calibration_size) {
            return Err(ConformalAssumptionFailure::CalibrationTooSmall {
                required_rank: rank,
                available: config.calibration_size,
            });
        }
        // `rank <= calibration_size` was just proved, so this cannot fail.
        let rank = u32::try_from(rank).unwrap_or(config.calibration_size);
        Ok(Self { config, rank })
    }

    /// The one-based rank of the order statistic this level takes.
    #[must_use]
    pub const fn rank(self) -> u32 {
        self.rank
    }

    /// The configuration this bound was built for.
    #[must_use]
    pub const fn config(self) -> ConformalConfig {
        self.config
    }

    /// The conformal bound: the rank-th smallest calibration score.
    ///
    /// # Errors
    ///
    /// Returns [`ConformalRefusal::CalibrationSizeMismatch`] when the slice is
    /// not the configured length, or [`ConformalRefusal::ScoresUnsorted`] when
    /// it is not ascending. Neither is repaired here — see the module docs.
    pub fn quantile(self, ascending_scores: &[Scaled]) -> Result<Scaled, ConformalRefusal> {
        if ascending_scores.len() != self.config.calibration_size as usize {
            return Err(ConformalRefusal::CalibrationSizeMismatch {
                expected: self.config.calibration_size,
                observed: ascending_scores.len(),
            });
        }
        for index in 1..ascending_scores.len() {
            if ascending_scores[index - 1] > ascending_scores[index] {
                return Err(ConformalRefusal::ScoresUnsorted { index });
            }
        }
        // `rank` is one-based and `new` proved `1 <= rank <= len`.
        Ok(ascending_scores[self.rank as usize - 1])
    }
}
