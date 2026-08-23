#![forbid(unsafe_code)]
//! The conflict-absorbing observation lattice.
//!
//! A non-canonical replica observes one transaction through several channels
//! that may disagree and may arrive in any order. The lattice exists so that
//! disagreement is *retained* rather than resolved:
//!
//! ```text
//!           Conflict
//!           /      \
//!    Committed    Refused
//!           \      /
//!           Reserved
//!               |
//!            Unknown
//! ```
//!
//! Joining `Committed` and `Refused` yields `Conflict`, which is sticky
//! evidence and blocks service until canonical authority is consulted.
//! Timestamp choice cannot erase contradictory terminal facts.
//!
//! # Why this is a join and not a "latest wins" rule
//!
//! Last-writer-wins would make the answer depend on arrival order, so two
//! replicas seeing the same two facts in different orders would disagree — and
//! the one that saw `Refused` last would report a refusal for a transaction
//! that committed. The join is commutative, associative and idempotent, so
//! every replica that has seen the same *set* of observations reports the same
//! state regardless of order, duplication or replay.
//!
//! This lattice is a diagnosis and projection aid. It is **not** the canonical
//! head, and `Conflict` is not a decision: it is the explicit refusal to
//! manufacture one.

use core::cmp::Ordering;
use core::fmt;

/// What a replica currently believes about one transaction.
///
/// This is a partially ordered set, not a totally ordered enum:
/// `Committed` and `Refused` are incomparable.  In particular, it deliberately
/// does not implement `Ord`, because a total ordering would let `max` discard
/// their contradiction instead of producing `Conflict` through [`Self::join`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Observation {
    /// Nothing has been observed.
    Unknown,
    /// The transaction was sealed and is in flight.
    Reserved,
    /// A terminal commit was observed.
    Committed,
    /// A terminal refusal was observed.
    Refused,
    /// Contradictory terminals were observed. Sticky.
    Conflict,
}

impl PartialOrd for Observation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        use Observation::{Committed, Conflict, Refused, Reserved, Unknown};

        // The rows make the partial-order relation explicit. In particular,
        // each terminal has one distinct peer terminal that is incomparable.
        match *self {
            Unknown => match *other {
                Unknown => Some(Ordering::Equal),
                _ => Some(Ordering::Less),
            },
            Reserved => match *other {
                Unknown => Some(Ordering::Greater),
                Reserved => Some(Ordering::Equal),
                Committed | Refused | Conflict => Some(Ordering::Less),
            },
            Committed => match *other {
                Unknown | Reserved => Some(Ordering::Greater),
                Committed => Some(Ordering::Equal),
                Refused => None,
                Conflict => Some(Ordering::Less),
            },
            Refused => match *other {
                Unknown | Reserved => Some(Ordering::Greater),
                Committed => None,
                Refused => Some(Ordering::Equal),
                Conflict => Some(Ordering::Less),
            },
            Conflict => match *other {
                Conflict => Some(Ordering::Equal),
                _ => Some(Ordering::Greater),
            },
        }
    }
}

impl Observation {
    /// Every state, bottom to top.
    pub const ALL: &'static [Self] = &[
        Self::Unknown,
        Self::Reserved,
        Self::Committed,
        Self::Refused,
        Self::Conflict,
    ];

    /// Stable machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Reserved => "reserved",
            Self::Committed => "committed",
            Self::Refused => "refused",
            Self::Conflict => "conflict",
        }
    }

    /// Whether this state is a terminal claim about the transaction.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Refused)
    }

    /// Whether service must block on canonical authority.
    #[must_use]
    pub const fn blocks_service(self) -> bool {
        matches!(self, Self::Conflict)
    }

    /// The least upper bound of two observations.
    ///
    /// Total, order-independent, and absorbing at `Conflict`. Two *different*
    /// terminals join to `Conflict` rather than to either of them: that is the
    /// whole point, and it is why this is not a max over an ordering.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        // Written as "the highest state present wins", with one exception, so
        // the lattice order is explicit rather than encoded in arm sequence.
        //
        // The previous form relied on arm ORDER to place `Unknown` below
        // `Reserved`, and a clippy-directed pattern merge silently destroyed
        // that: `(Unknown | Reserved, value)` matches `(Reserved, Unknown)` by
        // its first alternative and binds `value = Unknown`, so
        // `join(Unknown, Reserved)` and `join(Reserved, Unknown)` disagreed and
        // the join stopped commuting. `the_join_is_a_semilattice` caught it.
        // This form cannot regress that way, because no arm depends on which
        // side an operand arrived on.
        match (self, other) {
            // The exception, and the only rule that invents a state neither
            // operand carried: two DIFFERENT terminals contradict, and the
            // contradiction is retained rather than resolved. `Conflict` then
            // absorbs whatever it meets, which is what makes it sticky.
            (Self::Conflict, _)
            | (_, Self::Conflict)
            | (Self::Committed, Self::Refused)
            | (Self::Refused, Self::Committed) => Self::Conflict,
            // Otherwise the join is the higher of the two states. Terminals
            // dominate `Reserved`, which dominates `Unknown`.
            (Self::Committed, _) | (_, Self::Committed) => Self::Committed,
            (Self::Refused, _) | (_, Self::Refused) => Self::Refused,
            (Self::Reserved, _) | (_, Self::Reserved) => Self::Reserved,
            (Self::Unknown, Self::Unknown) => Self::Unknown,
        }
    }

    /// Folds a sequence of observations into the state they imply.
    ///
    /// The result is a function of the SET of observations, not the sequence:
    /// reordering, duplicating or replaying the input cannot change it.
    #[must_use]
    pub fn observe_all(observations: &[Self]) -> Self {
        observations.iter().copied().fold(Self::Unknown, Self::join)
    }
}

impl fmt::Display for Observation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.tag())
    }
}
