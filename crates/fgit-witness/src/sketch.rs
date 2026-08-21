//! Overlap sketches: estimate-only, and structurally unable to prove absence.
//!
//! ## The rule this module exists to enforce
//!
//! Plan §15.6 says conflict sketches "may predict which refinement is
//! worthwhile; they never authorize admission", and §26 is blunter: a
//! statistical artifact "MUST NOT decide … ref atomicity" or any other
//! canonical question. §12 closes the loop — "inconclusive, failed, or
//! over-budget refinement retains the coarse conflict".
//!
//! So a sketch here answers exactly one question: *how likely is it that these
//! two footprints overlap, and within what bounds?* It cannot answer "they do
//! not overlap". That is not a matter of us declining to add the method — it
//! is enforced by the type system, and there is a `compile_fail` doctest below
//! proving a sketch cannot reach the proof constructor.
//!
//! ## We deliberately discard a sound signal
//!
//! Worth being explicit, because it looks like a mistake: two Bloom-style
//! sketches sharing no set bits *would* be a sound disjointness proof, and this
//! module throws that away. The reason is that a sketch's parameters are
//! tunable and adaptive. A bug in bucketing, a width change, or a regime shift
//! would silently turn a "sound" absence claim into an unsound one, and the
//! failure mode is admitting a true conflict — the one outcome §12 forbids
//! outright. The sketch's value is deciding *which* exact refinement to spend
//! budget on, not deciding the conflict itself. Prioritisation, never
//! authorisation.
//!
//! ## No floating point
//!
//! Probabilities are fixed-point parts-per-million. `f32`/`f64` are not
//! `CanonicalScalar` in this workspace precisely because a float cannot be
//! canonically encoded or compared across targets, and a receipt has to be
//! reproducible.

use crate::footprint::{Footprint, Scope};

/// A probability in fixed-point parts per million.
///
/// Integer-valued so a receipt reproduces exactly on every target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Probability(u32);

impl Probability {
    /// Certainly not.
    pub const ZERO: Self = Self(0);
    /// Certainly so.
    pub const ONE: Self = Self(1_000_000);

    /// Builds a probability, clamping into `0..=1_000_000` parts per million.
    ///
    /// Clamping rather than refusing: every caller here derives the value from
    /// bounded counters, so an out-of-range input is an arithmetic slip rather
    /// than untrusted data, and saturating keeps the type total.
    #[must_use]
    pub const fn from_parts_per_million(parts: u32) -> Self {
        Self(if parts > 1_000_000 { 1_000_000 } else { parts })
    }

    /// The value in parts per million.
    #[must_use]
    pub const fn parts_per_million(self) -> u32 {
        self.0
    }

    /// True when the probability is exactly zero.
    ///
    /// Note what this is *not*: a proof that the footprints are disjoint. A
    /// zero estimate means the sketch found no evidence of overlap, which is
    /// an absence of evidence. [`prove_disjoint`] is the only thing in this
    /// crate that decides disjointness, and it does not accept a sketch.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Width of a sketch, in buckets.
///
/// Small and fixed: the sketch is a prioritisation hint, and a large one would
/// cost more to compute than the refinement it is meant to triage.
pub const SKETCH_BUCKETS: usize = 64;

/// A compact, lossy summary of a footprint.
///
/// Deliberately carries no method that returns a disjointness verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlapSketch {
    buckets: u64,
    scopes: u32,
}

/// Deterministic, explicitly non-cryptographic bucket mixer.
///
/// This is not a digest and never becomes an identity. It exists to spread
/// scopes across [`SKETCH_BUCKETS`] reproducibly. `fgit-crypto` owns every
/// value that has to resist an adversary; nothing here does.
fn bucket_of(scope: &Scope) -> u32 {
    let mut state: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |bytes: &[u8]| {
        for byte in bytes {
            state ^= u64::from(*byte);
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    mix(scope.family().as_bytes());
    match scope {
        Scope::Generation | Scope::PolicyEpoch => {}
        Scope::RefNamespace(value)
        | Scope::ExactRef(value)
        | Scope::ForgeStream(value)
        | Scope::PathPrefix(value)
        | Scope::ExactPath(value)
        | Scope::PolicyDomain(value) => mix(value),
        Scope::ForgeEntity { stream, entity } => {
            mix(stream);
            mix(entity);
        }
    }
    u32::try_from(state % SKETCH_BUCKETS as u64).unwrap_or(0)
}

impl OverlapSketch {
    /// Summarizes a footprint.
    ///
    /// A conservative footprint sets every bucket, so it estimates overlap
    /// with everything — which is the correct summary of "I read the whole
    /// generation".
    #[must_use]
    pub fn of(footprint: &Footprint) -> Self {
        if footprint.is_conservative() {
            return Self {
                buckets: u64::MAX,
                scopes: u32::try_from(footprint.len()).unwrap_or(u32::MAX),
            };
        }
        let mut buckets = 0_u64;
        for scope in footprint.scopes() {
            buckets |= 1_u64 << bucket_of(scope);
        }
        Self {
            buckets,
            scopes: u32::try_from(footprint.len()).unwrap_or(u32::MAX),
        }
    }

    /// How many buckets this sketch occupies.
    #[must_use]
    pub const fn occupancy(self) -> u32 {
        self.buckets.count_ones()
    }

    /// How many scopes were summarized.
    #[must_use]
    pub const fn scope_count(self) -> u32 {
        self.scopes
    }

    /// Estimates overlap with another sketch.
    #[must_use]
    pub const fn estimate(self, other: Self) -> OverlapEstimate {
        let shared = (self.buckets & other.buckets).count_ones();
        OverlapEstimate {
            shared_buckets: shared,
            left_occupancy: self.occupancy(),
            right_occupancy: other.occupancy(),
        }
    }
}

/// What a sketch is allowed to say.
///
/// There is no `is_disjoint`, no `proves_absence`, and no `bool` that means
/// "definitely not". The most negative thing this type can express is
/// [`OverlapEstimate::may_overlap`] returning `false`, which means *this
/// sketch found no evidence* — see its documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlapEstimate {
    shared_buckets: u32,
    left_occupancy: u32,
    right_occupancy: u32,
}

impl OverlapEstimate {
    /// Lower and upper bounds on the probability of a real overlap.
    ///
    /// The lower bound is zero whenever no bucket is shared, because bucket
    /// collisions mean a shared bucket is evidence rather than proof. The
    /// upper bound is the share of the smaller footprint's buckets that
    /// collide, which is where a real overlap would have to show up.
    #[must_use]
    pub fn bounds(self) -> (Probability, Probability) {
        let smaller = self.left_occupancy.min(self.right_occupancy);
        if smaller == 0 {
            return (Probability::ZERO, Probability::ZERO);
        }
        let upper_ppm = u64::from(self.shared_buckets)
            .saturating_mul(1_000_000)
            .checked_div(u64::from(smaller))
            .unwrap_or(0);
        let upper =
            Probability::from_parts_per_million(u32::try_from(upper_ppm).unwrap_or(u32::MAX));
        // No lower bound above zero is defensible from a lossy sketch: every
        // shared bucket could be a collision.
        (Probability::ZERO, upper)
    }

    /// How many buckets the two sketches share.
    #[must_use]
    pub const fn shared_buckets(self) -> u32 {
        self.shared_buckets
    }

    /// Whether an overlap is possible as far as this sketch can tell.
    ///
    /// `false` means **no evidence of overlap in this sketch**, not "the
    /// footprints are disjoint". A caller that treats `false` as disjointness
    /// has made exactly the error this module is built to prevent: the sketch
    /// is lossy, its parameters are tunable, and §12 requires an inconclusive
    /// refinement to retain the coarse conflict. Use [`prove_disjoint`] on the
    /// exact footprints when the answer has to be load-bearing.
    #[must_use]
    pub fn may_overlap(self) -> bool {
        let (_, upper) = self.bounds();
        !upper.is_zero()
    }

    /// A bounded triage score: how worthwhile an exact refinement looks.
    ///
    /// Higher means "an exact check is more likely to clear a false conflict".
    /// This is a hint fed to the value-of-information policy, never a verdict.
    #[must_use]
    pub fn refinement_priority(self) -> u32 {
        let (_, upper) = self.bounds();
        1_000_000_u32.saturating_sub(upper.parts_per_million())
    }
}

mod sealed {
    /// Closed over the types that carry exact, lossless scope information.
    pub trait Sealed {}
    impl Sealed for crate::footprint::Footprint {}
}

/// Types from which absence may soundly be concluded.
///
/// Sealed, and implemented only for [`Footprint`] — a lossless, exact
/// description of what was read. [`OverlapSketch`] does **not** implement it
/// and cannot: the trait is sealed in a private module, so no downstream crate
/// can add an implementation either.
pub trait ProvesAbsence: sealed::Sealed {
    /// The exact scopes this value describes.
    fn exact_footprint(&self) -> &Footprint;
}

impl ProvesAbsence for Footprint {
    fn exact_footprint(&self) -> &Self {
        self
    }
}

/// Evidence that two footprints genuinely do not overlap.
///
/// Only obtainable from [`prove_disjoint`], which only accepts exact
/// footprints. A sketch cannot produce one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisjointnessProof {
    left_scopes: usize,
    right_scopes: usize,
}

impl DisjointnessProof {
    /// How many scopes each side contributed, for the receipt.
    #[must_use]
    pub const fn compared(&self) -> (usize, usize) {
        (self.left_scopes, self.right_scopes)
    }
}

/// Decides disjointness from exact footprints.
///
/// Returns `None` when they overlap — there is no "probably disjoint" result,
/// because a probabilistic answer is exactly what must not be load-bearing.
///
/// A sketch cannot be passed here. That is enforced by the sealed
/// [`ProvesAbsence`] bound rather than by convention:
///
/// ```compile_fail
/// use fgit_witness::footprint::{Footprint, Scope};
/// use fgit_witness::sketch::{OverlapSketch, prove_disjoint};
///
/// let left = Footprint::from_scopes([Scope::ExactRef(b"refs/heads/main".to_vec())]);
/// let right = Footprint::from_scopes([Scope::ExactRef(b"refs/tags/v1".to_vec())]);
/// let sketch = OverlapSketch::of(&left);
/// // `OverlapSketch` does not implement the sealed `ProvesAbsence` trait,
/// // so this does not compile: a sketch can never prove absence.
/// let _ = prove_disjoint(&sketch, &right);
/// ```
///
/// The permitted twin, which does compile and is the supported path:
///
/// ```
/// use fgit_witness::footprint::{Footprint, Scope};
/// use fgit_witness::sketch::prove_disjoint;
///
/// let left = Footprint::from_scopes([Scope::ExactRef(b"refs/heads/main".to_vec())]);
/// let right = Footprint::from_scopes([Scope::ExactRef(b"refs/tags/v1".to_vec())]);
/// assert!(prove_disjoint(&left, &right).is_some());
/// ```
#[must_use]
pub fn prove_disjoint<A, B>(left: &A, right: &B) -> Option<DisjointnessProof>
where
    A: ProvesAbsence,
    B: ProvesAbsence,
{
    let left = left.exact_footprint();
    let right = right.exact_footprint();
    if left.overlaps(right) {
        return None;
    }
    Some(DisjointnessProof {
        left_scopes: left.len(),
        right_scopes: right.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::{OverlapSketch, Probability, prove_disjoint};
    use crate::footprint::{Footprint, Scope};

    fn exact(text: &str) -> Scope {
        Scope::ExactRef(text.as_bytes().to_vec())
    }

    #[test]
    fn a_sketch_of_the_conservative_footprint_estimates_overlap_with_everything() {
        let conservative = OverlapSketch::of(&Footprint::conservative());
        let narrow = OverlapSketch::of(&Footprint::from_scopes([exact("refs/heads/main")]));
        let estimate = conservative.estimate(narrow);
        assert!(
            estimate.may_overlap(),
            "reading the whole generation must estimate overlap with anything"
        );
    }

    #[test]
    fn identical_footprints_estimate_the_maximum_upper_bound() {
        let footprint = Footprint::from_scopes([exact("refs/heads/main")]);
        let sketch = OverlapSketch::of(&footprint);
        let (lower, upper) = sketch.estimate(sketch).bounds();
        assert_eq!(
            lower,
            Probability::ZERO,
            "a lossy sketch never proves presence"
        );
        assert_eq!(upper, Probability::ONE);
        assert!(sketch.estimate(sketch).may_overlap());
    }

    #[test]
    fn the_lower_bound_is_always_zero_because_a_shared_bucket_may_be_a_collision() {
        for name in ["refs/heads/a", "refs/heads/b", "refs/tags/v1"] {
            let left = OverlapSketch::of(&Footprint::from_scopes([exact(name)]));
            let right = OverlapSketch::of(&Footprint::from_scopes([exact("refs/heads/main")]));
            let (lower, _) = left.estimate(right).bounds();
            assert_eq!(lower, Probability::ZERO, "{name}");
        }
    }

    #[test]
    fn an_empty_sketch_has_zero_bounds_and_does_not_claim_disjointness() {
        let empty = OverlapSketch::of(&Footprint::empty());
        let other = OverlapSketch::of(&Footprint::from_scopes([exact("refs/heads/main")]));
        let estimate = empty.estimate(other);
        let (lower, upper) = estimate.bounds();
        assert_eq!(lower, Probability::ZERO);
        assert_eq!(upper, Probability::ZERO);
        // may_overlap() is false — but that is absence of evidence, and the
        // load-bearing answer still has to come from the exact path.
        assert!(!estimate.may_overlap());
        assert!(prove_disjoint(&Footprint::empty(), &Footprint::empty()).is_some());
    }

    #[test]
    fn sketching_is_deterministic() {
        let footprint = Footprint::from_scopes([
            exact("refs/heads/main"),
            Scope::PathPrefix(b"src".to_vec()),
            Scope::PolicyEpoch,
        ]);
        assert_eq!(OverlapSketch::of(&footprint), OverlapSketch::of(&footprint));
        // Insertion order is not part of a footprint, so it cannot reach the
        // sketch either.
        let reordered = Footprint::from_scopes([
            Scope::PolicyEpoch,
            Scope::PathPrefix(b"src".to_vec()),
            exact("refs/heads/main"),
        ]);
        assert_eq!(OverlapSketch::of(&footprint), OverlapSketch::of(&reordered));
    }

    #[test]
    fn exact_disjointness_is_decided_only_by_the_exact_path() {
        let left = Footprint::from_scopes([exact("refs/heads/main")]);
        let right = Footprint::from_scopes([exact("refs/tags/v1")]);
        let proof = prove_disjoint(&left, &right).expect("genuinely disjoint");
        assert_eq!(proof.compared(), (1, 1));

        // The near-identical overlapping case returns no proof at all, rather
        // than a weaker one.
        let overlapping = Footprint::from_scopes([Scope::RefNamespace(b"refs/heads".to_vec())]);
        assert!(prove_disjoint(&left, &overlapping).is_none());
    }

    #[test]
    fn refinement_priority_is_bounded_and_favours_likely_false_conflicts() {
        let a = OverlapSketch::of(&Footprint::from_scopes([exact("refs/heads/main")]));
        let same = a.estimate(a).refinement_priority();
        let empty = OverlapSketch::of(&Footprint::empty());
        let none = a.estimate(empty).refinement_priority();
        assert!(
            same <= 1_000_000 && none <= 1_000_000,
            "priority stays bounded"
        );
        assert!(
            none > same,
            "a sketch showing no shared buckets is the better refinement candidate"
        );
    }

    #[test]
    fn probability_clamps_rather_than_wrapping() {
        assert_eq!(
            Probability::from_parts_per_million(2_000_000),
            Probability::ONE
        );
        assert_eq!(Probability::from_parts_per_million(0), Probability::ZERO);
        assert!(Probability::ZERO.is_zero());
        assert!(!Probability::ONE.is_zero());
    }
}
