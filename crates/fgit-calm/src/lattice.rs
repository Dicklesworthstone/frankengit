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

use core::fmt;

/// What a replica currently believes about one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        match (self, other) {
            // Conflict absorbs everything, from either side.
            (Self::Conflict, _) | (_, Self::Conflict) => Self::Conflict,
            // Unknown is the identity.
            (Self::Unknown, value) | (value, Self::Unknown) => value,
            // Reserved is below both terminals.
            (Self::Reserved, value) | (value, Self::Reserved) => value,
            // Agreeing terminals stay themselves.
            (Self::Committed, Self::Committed) => Self::Committed,
            (Self::Refused, Self::Refused) => Self::Refused,
            // Contradictory terminals are retained, never resolved.
            (Self::Committed, Self::Refused) | (Self::Refused, Self::Committed) => Self::Conflict,
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
