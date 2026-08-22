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

    /// The property this class's operations must be shown to have.
    ///
    /// Total over the closed set on purpose. The registry's acceptance is that
    /// every row is exercised by a check *matching its class*, and the way that
    /// silently fails is a class falling through every branch of an
    /// `if`/`else if` chain -- exercised by nothing while the suite reports
    /// green. Dispatching through this enum makes the mapping exhaustive, so a
    /// new class with no assigned direction does not compile.
    #[must_use]
    pub const fn conformance_direction(self) -> ConformanceDirection {
        match self {
            Self::MonotoneWithAuthentication | Self::MonotoneScoped => {
                ConformanceDirection::ConvergesUnderReorderDuplicateDrop
            }
            Self::CommutativeButBounded => ConformanceDirection::BoundedMergeWithReset,
            Self::LocalDeterministic => ConformanceDirection::PinnedInputDeterminism,
            Self::OrderedProjection => ConformanceDirection::AntiRollbackProjection,
            Self::HeadCasRequired => ConformanceDirection::CoordinationIsLoadBearing,
            Self::ExclusiveExternalEffect => ConformanceDirection::IdempotentExternalEffect,
        }
    }
}

impl fmt::Display for CoordinationClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.tag())
    }
}

/// The executable property a coordination class claims about its operations.
///
/// One direction per class, assigned by [`CoordinationClass::conformance_direction`].
/// These are the shapes a mislabelled row is caught by: an operation placed in
/// the wrong class is required to demonstrate a property it does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConformanceDirection {
    /// The merged result is the union of applied facts, whatever the order,
    /// however many duplicates, and whichever redundant copies were dropped.
    ConvergesUnderReorderDuplicateDrop,
    /// A declared merge algebra with declared bounds, declared overflow
    /// behaviour, and reset expressed as a regime advance rather than an
    /// order-dependent truncation.
    BoundedMergeWithReset,
    /// A pure function of pinned inputs under a closed tie-break. Needs no
    /// coordination, yet is NOT drop-tolerant: losing a pinned input changes
    /// the answer, which is why this class is coordination-free without being
    /// convergent.
    PinnedInputDeterminism,
    /// Activation refuses anything but the exact predecessor, so a subordinate
    /// projection can advance but never roll back.
    AntiRollbackProjection,
    /// Removing the coordination boundary must break the operation. If it
    /// behaves identically with and without, the classification was
    /// decorative.
    CoordinationIsLoadBearing,
    /// One externally observable effect per idempotency key, however many
    /// times delivery is retried or reordered.
    IdempotentExternalEffect,
}

impl ConformanceDirection {
    /// Every direction, so a coverage check can assert the mapping is onto.
    pub const ALL: &'static [Self] = &[
        Self::ConvergesUnderReorderDuplicateDrop,
        Self::BoundedMergeWithReset,
        Self::PinnedInputDeterminism,
        Self::AntiRollbackProjection,
        Self::CoordinationIsLoadBearing,
        Self::IdempotentExternalEffect,
    ];

    /// Stable machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ConvergesUnderReorderDuplicateDrop => "converges_under_reorder_duplicate_drop",
            Self::BoundedMergeWithReset => "bounded_merge_with_reset",
            Self::PinnedInputDeterminism => "pinned_input_determinism",
            Self::AntiRollbackProjection => "anti_rollback_projection",
            Self::CoordinationIsLoadBearing => "coordination_is_load_bearing",
            Self::IdempotentExternalEffect => "idempotent_external_effect",
        }
    }
}

impl fmt::Display for ConformanceDirection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.tag())
    }
}
