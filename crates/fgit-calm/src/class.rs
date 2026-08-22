#![forbid(unsafe_code)]
//! The closed seven-class coordination vocabulary.
//!
//! The spelling of each class is the registry's; the meaning is
//! `docs/CALM_AND_OBLIGATIONS.md` section 1. Both are pinned here so a
//! misspelled or invented class is a compile-or-parse failure rather than a row
//! nobody reads.

use core::fmt;

/// Why an operation may or may not proceed without a coordination boundary.
///
/// Closed by construction: a class this enum does not name is a registry
/// defect, which is section 1's own wording.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoordinationClass {
    /// Grow-only information whose union cannot invalidate an earlier result,
    /// admitted only after identity/authorization verification.
    MonotoneWithAuthentication,
    /// Grow-only within one locally authorized scope; discardable without
    /// correctness loss.
    MonotoneScoped,
    /// Algebraically mergeable state with declared bounds, overflow behaviour,
    /// and reset/regime semantics. Retractable observations belong here.
    CommutativeButBounded,
    /// Pure deterministic computation over pinned inputs; produces ordering or
    /// advice, never shared truth.
    LocalDeterministic,
    /// Publication through a subordinate monotone anti-rollback authority.
    OrderedProjection,
    /// Meaning depends on absence, replacement, uniqueness, or revocation;
    /// only the repository authority head can decide it.
    HeadCasRequired,
    /// One externally observable side effect owned by an outbox obligation with
    /// stable idempotency.
    ExclusiveExternalEffect,
}

impl CoordinationClass {
    /// Every class, in the order section 1 declares them.
    ///
    /// Exhaustive by construction: a new variant that is not added here fails
    /// this crate's own coverage test, so the closed set cannot silently grow.
    pub const ALL: &'static [Self] = &[
        Self::MonotoneWithAuthentication,
        Self::MonotoneScoped,
        Self::CommutativeButBounded,
        Self::LocalDeterministic,
        Self::OrderedProjection,
        Self::HeadCasRequired,
        Self::ExclusiveExternalEffect,
    ];

    /// The exact registry spelling.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::MonotoneWithAuthentication => "monotone_with_authentication",
            Self::MonotoneScoped => "monotone_scoped",
            Self::CommutativeButBounded => "commutative_but_bounded",
            Self::LocalDeterministic => "local_deterministic",
            Self::OrderedProjection => "ordered_projection",
            Self::HeadCasRequired => "head_cas_required",
            Self::ExclusiveExternalEffect => "exclusive_external_effect",
        }
    }

    /// Parses a registry cell, refusing anything the vocabulary does not name.
    ///
    /// Returns `None` rather than a default, because a class that fell back to
    /// a permissive value would let a mislabelled row behave like a correct
    /// one -- the failure this vocabulary exists to make impossible.
    #[must_use]
    pub fn parse(tag: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|class| class.tag() == tag)
    }

    /// Whether an operation of this class may proceed without taking a
    /// coordination boundary.
    ///
    /// This is the single property the registry's classification is *for*. It
    /// is deliberately total over the closed set: adding a variant without
    /// deciding its coordination requirement will not compile.
    #[must_use]
    pub const fn is_coordination_free(self) -> bool {
        match self {
            // Adding information cannot invalidate an earlier result, so
            // replicas may accept in any order.
            Self::MonotoneWithAuthentication
            | Self::MonotoneScoped
            | Self::CommutativeButBounded
            | Self::LocalDeterministic => true,
            // Meaning depends on absence, uniqueness, replacement or an
            // externally observable effect: an ordering or authority boundary
            // is required.
            Self::OrderedProjection | Self::HeadCasRequired | Self::ExclusiveExternalEffect => {
                false
            }
        }
    }

    /// Whether this class tolerates reorder, duplication and drop of its
    /// inputs without changing the converged result.
    ///
    /// Distinct from [`Self::is_coordination_free`]: a locally deterministic
    /// computation needs no coordination, but it is a function of pinned
    /// inputs rather than a merge, so dropping an input changes its answer.
    #[must_use]
    pub const fn converges_under_reorder_duplicate_drop(self) -> bool {
        match self {
            Self::MonotoneWithAuthentication
            | Self::MonotoneScoped
            | Self::CommutativeButBounded => true,
            Self::LocalDeterministic
            | Self::OrderedProjection
            | Self::HeadCasRequired
            | Self::ExclusiveExternalEffect => false,
        }
    }
}

impl fmt::Display for CoordinationClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.tag())
    }
}
