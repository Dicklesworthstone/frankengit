//! Deterministic probabilities represented as fixed-point parts per million.
//!
//! The checked constructor is the default because this L0 type may be built
//! from untrusted inputs.  Callers that have already established a bounded
//! arithmetic source must name the explicit saturating conversion instead.

use crate::TypeRefusal;

/// Number of parts in one whole probability.
pub const PARTS_PER_MILLION: u32 = 1_000_000;

/// A probability in fixed-point parts per million.
///
/// Integer-valued so that receipts reproduce exactly on every target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Probability(u32);

impl Probability {
    /// Certainly not.
    pub const ZERO: Self = Self(0);
    /// Certainly so.
    pub const ONE: Self = Self(PARTS_PER_MILLION);

    /// Builds a probability, refusing a value above one whole.
    pub fn try_new(parts: u32) -> Result<Self, TypeRefusal> {
        if parts > PARTS_PER_MILLION {
            return Err(TypeRefusal::ValueOutOfRange {
                field: "Probability",
                observed: u64::from(parts),
                minimum: 0,
                maximum: u64::from(PARTS_PER_MILLION),
            });
        }
        Ok(Self(parts))
    }

    /// Builds a probability by explicitly saturating into the valid range.
    ///
    /// This is for callers whose input is derived from a bounded calculation;
    /// callers handling untrusted or policy-relevant input must use
    /// [`Self::try_new`] so an out-of-range value remains observable.
    #[must_use]
    pub const fn saturating_from_parts_per_million(parts: u32) -> Self {
        Self(if parts > PARTS_PER_MILLION {
            PARTS_PER_MILLION
        } else {
            parts
        })
    }

    /// The value in parts per million.
    #[must_use]
    pub const fn parts_per_million(self) -> u32 {
        self.0
    }

    /// True when the probability is exactly zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

#[cfg(test)]
mod tests {
    use super::{PARTS_PER_MILLION, Probability};
    use crate::TypeRefusal;

    #[test]
    fn checked_constructor_refuses_an_out_of_range_probability() {
        assert_eq!(
            Probability::try_new(PARTS_PER_MILLION + 1),
            Err(TypeRefusal::ValueOutOfRange {
                field: "Probability",
                observed: u64::from(PARTS_PER_MILLION + 1),
                minimum: 0,
                maximum: u64::from(PARTS_PER_MILLION),
            })
        );
    }

    #[test]
    fn checked_constructor_admits_the_whole_range_including_certainty() {
        assert_eq!(Probability::try_new(0), Ok(Probability::ZERO));
        assert_eq!(
            Probability::try_new(500_000).map(Probability::parts_per_million),
            Ok(500_000)
        );
        assert_eq!(
            Probability::try_new(PARTS_PER_MILLION),
            Ok(Probability::ONE)
        );
    }

    #[test]
    fn is_zero_distinguishes_zero_from_the_smallest_non_zero_probability() {
        // `is_zero` had no test at all until this one, which matters more than
        // its size: `Probability` sits at L0 and is constructible by every
        // crate, and a predicate fails SILENTLY -- it returns the wrong bool
        // and the caller branches wrongly, with no refusal and no panic for
        // anything downstream to notice.
        //
        // Both polarities, because one alone passes against a predicate that
        // is constant. `GitOid::is_zero` is tested that way in
        // `tests/native.rs`; this matches the convention.
        assert!(Probability::ZERO.is_zero());
        assert!(Probability::try_new(0).expect("zero is in range").is_zero());
        assert!(
            Probability::saturating_from_parts_per_million(0).is_zero(),
            "the saturating path is a separate entry point to the same state"
        );

        // THE DISCRIMINATING CASE. One part per million is the smallest
        // constructible non-zero probability, so it is the value that
        // separates `self.0 == 0` from a sloppier `self.0 <= 1` or any fold
        // that rounds small values to nothing. A test using only ZERO and ONE
        // would pass against several wrong implementations.
        assert!(
            !Probability::try_new(1)
                .expect("one ppm is in range")
                .is_zero(),
            "one part per million is not zero; a probability that small is \
             still a probability, and treating it as zero would let a caller \
             discard a real signal"
        );
        assert!(!Probability::ONE.is_zero());
    }

    #[test]
    fn explicit_saturating_constructor_preserves_the_bounded_counter_path() {
        assert_eq!(
            Probability::saturating_from_parts_per_million(PARTS_PER_MILLION + 1),
            Probability::ONE
        );
        assert_eq!(
            Probability::saturating_from_parts_per_million(0),
            Probability::ZERO
        );
    }
}
