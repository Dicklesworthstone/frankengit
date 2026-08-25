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
    /// A `Structure` or `Union` field names something the registry cannot
    /// resolve.
    ///
    /// Every generated artifact renders such a field as a reference, so an
    /// unresolvable name becomes a dangling type in `TypeScript`, a missing
    /// class in Python and a `$ref` to nothing in JSON Schema. The staleness
    /// gate cannot detect any of that: it compares bytes to bytes, and both
    /// sides agree perfectly on a broken document.
    ReferenceUnresolved {
        /// The descriptor, structure or union whose field holds the reference.
        owner: Box<str>,
        /// The unresolvable name.
        name: Box<str>,
        /// Which registry was searched: `structure` or `union`.
        container: &'static str,
    },
    /// `cargo metadata` could not enumerate the workspace whose canonical
    /// bodies the schema gate must account for.
    WorkspaceMetadataFailed {
        /// Workspace root supplied to the metadata command.
        root: Box<str>,
        /// The command failure, including its status or operating-system error.
        detail: Box<str>,
    },
    /// A crate that declares canonical bodies has no committed description
    /// manifest beside its `Cargo.toml`.
    CanonicalBodyDescriptionManifestMissing {
        /// Workspace package that owns the canonical body.
        crate_name: Box<str>,
        /// Required manifest path.
        manifest: Box<str>,
    },
    /// A committed canonical-body description manifest is not valid TSV.
    CanonicalBodyDescriptionManifestMalformed {
        /// Manifest path.
        manifest: Box<str>,
        /// One-based source line.
        line: usize,
        /// What the malformed line violated.
        detail: Box<str>,
    },
    /// One crate's description manifest names a family more than once.
    CanonicalBodyDescriptionDuplicated {
        /// Manifest path.
        manifest: Box<str>,
        /// Duplicate family.
        family: Box<str>,
    },
    /// A canonical body family found in source has no description in its
    /// owning crate's manifest.
    CanonicalBodyDescriptionMissing {
        /// Workspace package that owns the source.
        crate_name: Box<str>,
        /// Rust source where the canonical body was found.
        source: Box<str>,
        /// Undescribed schema family.
        family: Box<str>,
    },
    /// A manifest claims a family the owning crate no longer encodes.
    CanonicalBodyDescriptionPhantom {
        /// Workspace package that owns the manifest.
        crate_name: Box<str>,
        /// Manifest path.
        manifest: Box<str>,
        /// Family that has no matching canonical body in the crate.
        family: Box<str>,
    },
    /// Two crates give one schema family different descriptions.
    CanonicalBodyDescriptionConflicting {
        /// Shared schema family.
        family: Box<str>,
        /// First manifest that described it.
        first_manifest: Box<str>,
        /// Second manifest that described it differently.
        second_manifest: Box<str>,
    },
    /// The source scanner found a `CanonicalBody` implementation but could
    /// not resolve the family expression it uses.
    CanonicalBodyFamilyUnresolvable {
        /// Rust source containing the implementation.
        source: Box<str>,
        /// The associated-constant expression the scanner could not resolve.
        expression: Box<str>,
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
            Self::ReferenceUnresolved { .. } => "reference_unresolved",
            Self::WorkspaceMetadataFailed { .. } => "workspace_metadata_failed",
            Self::CanonicalBodyDescriptionManifestMissing { .. } => {
                "canonical_body_description_manifest_missing"
            }
            Self::CanonicalBodyDescriptionManifestMalformed { .. } => {
                "canonical_body_description_manifest_malformed"
            }
            Self::CanonicalBodyDescriptionDuplicated { .. } => {
                "canonical_body_description_duplicated"
            }
            Self::CanonicalBodyDescriptionMissing { .. } => "canonical_body_description_missing",
            Self::CanonicalBodyDescriptionPhantom { .. } => "canonical_body_description_phantom",
            Self::CanonicalBodyDescriptionConflicting { .. } => {
                "canonical_body_description_conflicting"
            }
            Self::CanonicalBodyFamilyUnresolvable { .. } => "canonical_body_family_unresolvable",
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
            Self::ReferenceUnresolved {
                owner,
                name,
                container,
            } => write!(
                formatter,
                "{owner} references the {container} {name}, which no registry resolves"
            ),
            Self::WorkspaceMetadataFailed { root, detail } => write!(
                formatter,
                "could not enumerate canonical-body workspace members under {root}: {detail}"
            ),
            Self::CanonicalBodyDescriptionManifestMissing {
                crate_name,
                manifest,
            } => write!(
                formatter,
                "{crate_name} encodes canonical bodies but has no description manifest at {manifest}"
            ),
            Self::CanonicalBodyDescriptionManifestMalformed {
                manifest,
                line,
                detail,
            } => write!(
                formatter,
                "{manifest}:{line} is not a canonical-body description: {detail}"
            ),
            Self::CanonicalBodyDescriptionDuplicated { manifest, family } => write!(
                formatter,
                "{manifest} describes canonical family {family} more than once"
            ),
            Self::CanonicalBodyDescriptionMissing {
                crate_name,
                source,
                family,
            } => write!(
                formatter,
                "{crate_name} encodes canonical family {family} in {source} without a description"
            ),
            Self::CanonicalBodyDescriptionPhantom {
                crate_name,
                manifest,
                family,
            } => write!(
                formatter,
                "{crate_name} manifest {manifest} describes {family}, but no canonical body in that crate uses it"
            ),
            Self::CanonicalBodyDescriptionConflicting {
                family,
                first_manifest,
                second_manifest,
            } => write!(
                formatter,
                "canonical family {family} has conflicting descriptions in {first_manifest} and {second_manifest}"
            ),
            Self::CanonicalBodyFamilyUnresolvable { source, expression } => write!(
                formatter,
                "cannot resolve CanonicalBody::SCHEMA_FAMILY expression {expression} in {source}"
            ),
        }
    }
}

impl core::error::Error for SchemaRefusal {}
