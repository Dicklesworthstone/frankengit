//! Parse-profile identity.
//!
//! Every parsed document, and every anchor derived from one, records the
//! profile that produced it. Remapping an anchor against a document parsed by
//! a different profile is refused rather than attempted, because the two
//! documents do not share a structural vocabulary.

use crate::limits::{Limits, StructuralLimits};

/// The syntax family a profile implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileFamily {
    /// The safe `CommonMark` subset implemented by this crate.
    ///
    /// Deviations from `CommonMark` are documented on [`crate::parse`]. Raw
    /// `HTML` is captured and escaped rather than passed through, link
    /// destinations are policy-checked, and entity references are literal.
    CommonMarkSafe,
}

impl ProfileFamily {
    /// Stable machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::CommonMarkSafe => "commonmark-safe",
        }
    }
}

/// The identity of a parse profile.
///
/// Two documents are structurally comparable exactly when their `ProfileId`
/// values are equal. The identity deliberately excludes ceilings that only
/// decide whether an input is refused (input and output size, anchor context
/// budget, batch width) because those never change an accepted parse result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileId {
    /// Syntax family.
    pub family: ProfileFamily,
    /// Version of that family's implementation in this crate.
    pub version: u32,
    /// Ceilings that decide which documents the profile accepts.
    pub structural: StructuralLimits,
}

impl ProfileId {
    /// Canonical, injective byte encoding used inside anchor identities.
    ///
    /// The encoding is a domain tag followed by length-prefixed fields, so no
    /// two distinct profiles share an encoding and no field boundary is
    /// ambiguous.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"fgit-doc/profile/v1\0");
        let tag = self.family.tag().as_bytes();
        out.extend_from_slice(&crate::limits::as_u64(tag.len()).to_be_bytes());
        out.extend_from_slice(tag);
        out.extend_from_slice(&self.version.to_be_bytes());
        let structural = self.structural.canonical_bytes();
        out.extend_from_slice(&crate::limits::as_u64(structural.len()).to_be_bytes());
        out.extend_from_slice(&structural);
        out
    }
}

/// The current implementation version of [`ProfileFamily::CommonMarkSafe`].
pub const COMMONMARK_SAFE_VERSION: u32 = 1;

/// A complete parse configuration: an identity plus the non-structural ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParseProfile {
    /// Syntax family implemented by this profile.
    pub family: ProfileFamily,
    /// All ceilings, structural and non-structural.
    pub limits: Limits,
}

impl ParseProfile {
    /// The safe `CommonMark` profile with default ceilings.
    pub const DEFAULT: Self = Self {
        family: ProfileFamily::CommonMarkSafe,
        limits: Limits::DEFAULT,
    };

    /// Builds a profile with the safe family and caller-chosen ceilings.
    #[must_use]
    pub const fn with_limits(limits: Limits) -> Self {
        Self {
            family: ProfileFamily::CommonMarkSafe,
            limits,
        }
    }

    /// The identity this profile stamps on the documents it parses.
    #[must_use]
    pub const fn id(&self) -> ProfileId {
        ProfileId {
            family: self.family,
            version: COMMONMARK_SAFE_VERSION,
            structural: self.limits.structural,
        }
    }
}

impl Default for ParseProfile {
    fn default() -> Self {
        Self::DEFAULT
    }
}
