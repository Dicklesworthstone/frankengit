//! Typed refusals for schema description and generation.
//!
//! Every unsupported shape is named here rather than skipped, so a caller can
//! tell "this crate does not describe that body" from "that body has no
//! fields". AGENTS.md §3.1: unsupported behaviour returns a typed refusal and
//! never falls back secretly.

use core::fmt;

/// Why a schema could not be described, resolved, or generated.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SchemaRefusal {
    /// No descriptor is registered for the requested schema family.
    ///
    /// Distinct from [`Self::ShapeUnsupported`]: this is "nobody has described
    /// it", not "the format cannot express it".
    FamilyUnregistered {
        /// The family as the caller spelled it.
        family: Box<str>,
    },
    /// A canonical body exists and is deliberately not described, because the
    /// descriptor format cannot express its shape.
    ///
    /// Carrying the reason rather than a bare "unsupported" is the difference
    /// between a gap someone can close and a gap someone has to rediscover.
    ShapeUnsupported {
        /// The family whose body is not describable.
        family: Box<str>,
        /// The exact construct the format lacks.
        construct: &'static str,
    },
    /// A generated artifact on disk differs from what the generator produces
    /// now, so the committed output is stale.
    ///
    /// This is the staleness gate's refusal. It names the artifact and the
    /// first differing byte offset so the failure is actionable without a
    /// separate diff.
    ArtifactStale {
        /// Repository-relative path of the stale artifact.
        artifact: Box<str>,
        /// Byte offset of the first difference, or the shorter length when one
        /// side is a prefix of the other.
        offset: usize,
    },
    /// A generated artifact that should exist does not.
    ArtifactMissing {
        /// Repository-relative path of the absent artifact.
        artifact: Box<str>,
    },
    /// Two registered descriptors claim the same schema family.
    ///
    /// A duplicate family would make `descriptor_for` depend on iteration
    /// order, which §5.3 forbids for exactly this reason.
    FamilyDuplicated {
        /// The family claimed twice.
        family: Box<str>,
    },
}

impl SchemaRefusal {
    /// Stable machine-readable discriminant.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::FamilyUnregistered { .. } => "family_unregistered",
            Self::ShapeUnsupported { .. } => "shape_unsupported",
            Self::ArtifactStale { .. } => "artifact_stale",
            Self::ArtifactMissing { .. } => "artifact_missing",
            Self::FamilyDuplicated { .. } => "family_duplicated",
        }
    }
}

impl fmt::Display for SchemaRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FamilyUnregistered { family } => {
                write!(formatter, "no descriptor is registered for family {family}")
            }
            Self::ShapeUnsupported { family, construct } => write!(
                formatter,
                "family {family} is not described: the descriptor format cannot express {construct}"
            ),
            Self::ArtifactStale { artifact, offset } => write!(
                formatter,
                "{artifact} is stale: committed output differs from generated output at byte {offset}"
            ),
            Self::ArtifactMissing { artifact } => {
                write!(formatter, "{artifact} is missing and must be generated")
            }
            Self::FamilyDuplicated { family } => {
                write!(formatter, "family {family} is registered more than once")
            }
        }
    }
}

impl core::error::Error for SchemaRefusal {}
