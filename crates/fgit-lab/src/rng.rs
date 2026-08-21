//! Seeded entropy.
//!
//! The lab's randomness is [`SplitMix64`](fgit_authority::SplitMix64) under a
//! recorded seed. That generator is deliberately reused from `fgit-authority`
//! rather than reimplemented here: a second RNG in the workspace would be a
//! second thing to keep in step, and a campaign that drives a faultable store
//! and the lab from *different* generators cannot honestly call its run one
//! replayable experiment.
//!
//! Every draw is counted. The count is part of trace identity, because two
//! runs that end in the same state having consumed a different number of
//! draws did not take the same path — one of them branched somewhere the
//! trace did not record, and that is exactly the kind of hidden divergence
//! replay is supposed to surface.

use fgit_authority::SplitMix64;

/// The laboratory's only entropy source.
///
/// There is no constructor that reads OS entropy. A run's randomness is
/// entirely determined by its seed, so quoting the seed reproduces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeededEntropy {
    seed: u64,
    generator: SplitMix64,
    draws: u64,
}

impl SeededEntropy {
    /// A source for the given seed.
    #[must_use]
    pub const fn from_seed(seed: u64) -> Self {
        Self {
            seed,
            generator: SplitMix64::new(seed),
            draws: 0,
        }
    }

    /// The seed this source was built from.
    ///
    /// Quote this in a campaign report; it is the whole reproduction recipe.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// How many values have been drawn.
    #[must_use]
    pub const fn draws(&self) -> u64 {
        self.draws
    }

    /// Draw the next value.
    pub const fn next_u64(&mut self) -> u64 {
        self.draws = self.draws.saturating_add(1);
        self.generator.next_u64()
    }

    /// Draw a value in `0..bound`.
    ///
    /// A `bound` of zero yields zero and still consumes a draw, so a campaign
    /// that degenerates to an empty range does not silently stop advancing the
    /// generator and thereby change every later draw.
    pub const fn next_below(&mut self, bound: u64) -> u64 {
        self.draws = self.draws.saturating_add(1);
        self.generator.next_below(bound)
    }

    /// Draw a boolean with the given percentage chance of `true`.
    ///
    /// `percent` is clamped to `0..=100`.
    pub const fn chance_percent(&mut self, percent: u8) -> bool {
        let percent = if percent > 100 { 100 } else { percent };
        self.next_below(100) < percent as u64
    }

    /// Choose an index into a collection of `len` items.
    ///
    /// Returns `None` for an empty collection *without* consuming a draw,
    /// because there is no choice to make and consuming one would make the
    /// stream depend on collection sizes the trace does not record.
    pub const fn choose_index(&mut self, len: usize) -> Option<usize> {
        if len == 0 {
            return None;
        }
        Some(self.next_below(len as u64) as usize)
    }

    /// Fork an independent sub-stream labelled by `tag`.
    ///
    /// The child seed is derived from this source's next draw mixed with the
    /// tag, so sub-streams are reproducible and distinct. Forking consumes one
    /// draw from the parent, which keeps the parent's stream a function of how
    /// many forks were taken.
    pub fn fork(&mut self, tag: &str) -> Self {
        let mut mix = self.next_u64();
        for byte in tag.as_bytes() {
            // FNV-1a style folding: cheap, deterministic, and dependent on
            // both the tag bytes and their order.
            mix ^= u64::from(*byte);
            mix = mix.wrapping_mul(0x0100_0000_01b3);
        }
        Self::from_seed(mix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_yields_the_same_stream() {
        let mut first = SeededEntropy::from_seed(0xDEAD_BEEF);
        let mut second = SeededEntropy::from_seed(0xDEAD_BEEF);
        let a: Vec<u64> = (0..64).map(|_| first.next_u64()).collect();
        let b: Vec<u64> = (0..64).map(|_| second.next_u64()).collect();
        assert_eq!(a, b);
        assert_eq!(first.draws(), 64);
        assert_eq!(first, second);
    }

    #[test]
    fn different_seeds_yield_different_streams() {
        let mut first = SeededEntropy::from_seed(1);
        let mut second = SeededEntropy::from_seed(2);
        let a: Vec<u64> = (0..32).map(|_| first.next_u64()).collect();
        let b: Vec<u64> = (0..32).map(|_| second.next_u64()).collect();
        assert_ne!(a, b);
    }

    #[test]
    fn draws_are_counted_so_divergent_paths_are_visible() {
        let mut source = SeededEntropy::from_seed(7);
        assert_eq!(source.draws(), 0);
        source.next_u64();
        source.next_below(10);
        source.chance_percent(50);
        assert_eq!(source.draws(), 3);
    }

    #[test]
    fn a_bounded_draw_stays_in_range() {
        let mut source = SeededEntropy::from_seed(99);
        for bound in [1_u64, 2, 7, 100, 1_000] {
            for _ in 0..200 {
                assert!(source.next_below(bound) < bound, "bound {bound}");
            }
        }
    }

    #[test]
    fn a_zero_bound_still_consumes_a_draw() {
        // If it did not, a degenerate range would silently shift every
        // subsequent draw and break replay in a way nothing would report.
        let mut source = SeededEntropy::from_seed(5);
        assert_eq!(source.next_below(0), 0);
        assert_eq!(source.draws(), 1);
    }

    #[test]
    fn choosing_from_an_empty_collection_consumes_nothing() {
        let mut source = SeededEntropy::from_seed(11);
        assert_eq!(source.choose_index(0), None);
        assert_eq!(source.draws(), 0);

        // Paired permitted case: a non-empty collection yields an in-range
        // index and does consume a draw.
        let index = source.choose_index(4).expect("non-empty");
        assert!(index < 4);
        assert_eq!(source.draws(), 1);
    }

    #[test]
    fn chance_is_clamped_and_the_extremes_are_absolute() {
        let mut always = SeededEntropy::from_seed(3);
        let mut never = SeededEntropy::from_seed(3);
        for _ in 0..200 {
            assert!(always.chance_percent(100));
            assert!(!never.chance_percent(0));
        }
        // Out-of-range percentages clamp rather than wrapping into nonsense.
        let mut clamped = SeededEntropy::from_seed(3);
        for _ in 0..50 {
            assert!(clamped.chance_percent(200));
        }
    }

    #[test]
    fn forks_are_reproducible_distinct_and_tag_sensitive() {
        let child_of = |tag: &str| {
            let mut parent = SeededEntropy::from_seed(42);
            let mut child = parent.fork(tag);
            (0..16).map(|_| child.next_u64()).collect::<Vec<_>>()
        };

        // Same parent seed and tag reproduce exactly.
        assert_eq!(child_of("storage"), child_of("storage"));
        // Different tags are independent sub-streams.
        assert_ne!(child_of("storage"), child_of("packet"));
        // Tag order matters, so near-miss labels do not collide.
        assert_ne!(child_of("ab"), child_of("ba"));
    }

    #[test]
    fn forking_consumes_a_parent_draw() {
        // The parent stream must depend on how many forks were taken,
        // otherwise two runs that forked differently would look identical.
        let mut unforked = SeededEntropy::from_seed(1);
        let mut forked = SeededEntropy::from_seed(1);
        let _child = forked.fork("x");
        assert_eq!(forked.draws(), 1);
        assert_ne!(unforked.next_u64(), forked.next_u64());
    }
}
