//! The comparison a review anchor was created under.
//!
//! A review anchor is never created in the abstract: the reviewer was looking
//! at a *presentation* of the source. Either the document stood alone -- an
//! issue body, a wiki page, a release note -- or it was one side of a
//! comparison against another version. Both are first-class, because a comment
//! written against the removed side of a diff and a comment written against
//! the added side are about different code even when the two sides happen to
//! contain identical text.
//!
//! # Why this is a binding and not part of the identity
//!
//! [`crate::AnchorId`] deliberately excludes the basis. A basis advances every
//! time the branch does, so folding it into the identity would hand the same
//! reviewed text a new identifier on every push and no anchor would ever be
//! stable -- the opposite of what an anchor is for. The basis lives on the
//! anchor beside the source object and the span, where [`crate::Anchor::remap`]
//! can compare it and refuse a comparison that is not meaningful.

use crate::limits::{Refusal, RefusalKind, as_u64};

/// Longest host-supplied comparison identity this crate stores.
pub const MAX_BASIS_ID_BYTES: usize = 64;

/// Which side of a comparison the reviewed text was displayed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiffSide {
    /// The version compared against: removed and context lines.
    Old,
    /// The version under review: added and context lines.
    New,
}

impl DiffSide {
    /// Stable machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Old => "old",
            Self::New => "new",
        }
    }
}

/// An opaque host-supplied identity for the version a comparison was taken
/// against.
///
/// This crate never interprets the bytes. The host supplies whatever identity
/// its object model uses, and the anchor carries it unchanged.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BasisId(Box<[u8]>);

impl BasisId {
    /// Records a comparison identity, refusing one that is too long.
    pub fn new(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_BASIS_ID_BYTES {
            return Err(Refusal::exceeded(
                RefusalKind::BasisIdTooLong,
                as_u64(MAX_BASIS_ID_BYTES),
                as_u64(bytes.len()),
            ));
        }
        Ok(Self(Box::from(bytes)))
    }

    /// The recorded identity bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The presentation a review anchor was created against.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnchorBasis {
    /// The document standing alone, not compared against anything.
    Whole,
    /// One side of a comparison against another version of the same object.
    Diff {
        /// Identity of the version the comparison was taken against.
        basis: BasisId,
        /// Which side of that comparison the reviewed text was on.
        side: DiffSide,
    },
}

impl AnchorBasis {
    /// Builds a diff-side basis, refusing an over-long basis identity.
    pub fn diff(basis: &[u8], side: DiffSide) -> Result<Self, Refusal> {
        Ok(Self::Diff {
            basis: BasisId::new(basis)?,
            side,
        })
    }

    /// Stable machine-readable tag for the presentation.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Whole => "whole",
            Self::Diff { side, .. } => side.tag(),
        }
    }

    /// Whether an anchor created under `self` may be remapped onto `other`.
    ///
    /// A standalone document and a diff side are never comparable: identical
    /// text in the two presentations is not the same reviewed location. Two
    /// diff sides are comparable exactly when they are the same side. The basis
    /// identity itself is allowed to differ -- that is the ordinary case of a
    /// branch advancing, and refusing it would make remapping useless for
    /// precisely the surface this crate exists to serve.
    #[must_use]
    pub fn is_comparable_to(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Whole, Self::Whole) => true,
            (Self::Diff { side: mine, .. }, Self::Diff { side: theirs, .. }) => mine == theirs,
            (Self::Whole | Self::Diff { .. }, Self::Whole | Self::Diff { .. }) => false,
        }
    }

    /// Whether `other` is the same side of a comparison against a *different*
    /// version, which is what a branch advancing looks like.
    #[must_use]
    pub fn advances_to(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Diff {
                    basis: mine,
                    side: my_side,
                },
                Self::Diff {
                    basis: theirs,
                    side: their_side,
                },
            ) => my_side == their_side && mine != theirs,
            (Self::Whole | Self::Diff { .. }, Self::Whole | Self::Diff { .. }) => false,
        }
    }
}
