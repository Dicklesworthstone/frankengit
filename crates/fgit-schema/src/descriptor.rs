//! The schema definition format.
//!
//! A [`SchemaDescriptor`] describes one canonical body that `fgit-codec`
//! encodes: its schema identity, its domain separation tag, and its fields in
//! **wire order**. It is a description of an existing type, not a definition
//! of a new one — the canonical types stay hand-owned by `fgit-codec`, and
//! `tests/conformance.rs` is what keeps a descriptor honest about the type it
//! claims to describe.
//!
//! # Why the format is deliberately non-recursive
//!
//! Every type here is flat: [`Cardinality`] carries the container and
//! [`FieldType`] carries the element, so no variant holds another
//! `&'static FieldType`. That is not a simplification for its own sake. A
//! recursive type would let a descriptor express shapes the four described
//! bodies do not have, and an expressible-but-unused shape is an untested one.
//! The one body that genuinely needs recursion is refused by name in
//! `registry`, so the gap is a typed refusal rather than a silent hole.
//!
//! # Determinism
//!
//! Fields are a `&'static [FieldDescriptor]` in declaration order and every
//! emitter walks them in that order. Nothing here is a map, so no output can
//! depend on iteration order (AGENTS.md §5.3).

/// Width of a canonical unsigned scalar, in bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScalarWidth {
    /// 16-bit, big-endian on the wire.
    U16,
    /// 32-bit, big-endian on the wire.
    U32,
    /// 64-bit, big-endian on the wire.
    U64,
}

impl ScalarWidth {
    /// Encoded width in bytes.
    #[must_use]
    pub const fn byte_len(self) -> u32 {
        match self {
            Self::U16 => 2,
            Self::U32 => 4,
            Self::U64 => 8,
        }
    }

    /// The largest value the width can carry.
    #[must_use]
    pub const fn max_value(self) -> u64 {
        match self {
            Self::U16 => u16::MAX as u64,
            Self::U32 => u32::MAX as u64,
            Self::U64 => u64::MAX,
        }
    }

    /// Stable lowercase name used in generated artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
        }
    }
}

/// The wire type of one field, in the canonical vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FieldType {
    /// An unsigned big-endian scalar, usually behind a newtype.
    Scalar(ScalarWidth),
    /// A 16-byte assigned identity (`fgit_types::OPAQUE_ID_LEN`).
    OpaqueId,
    /// An algorithm-tagged digest: a code point plus a length-prefixed body.
    Digest,
    /// An identity derived through an `InternalObjectId`, pinned to a domain.
    ///
    /// The domain travels with the type because two derived identities with
    /// the same digest and different domains are different values, and a
    /// client that drops the domain can alias them.
    DerivedId {
        /// The domain separation tag this identity is bound to.
        domain: &'static str,
    },
    /// A schema identifier: family, major, minor.
    SchemaId,
    /// Length-prefixed UTF-8 text with a declared upper bound.
    Text {
        /// Maximum length in bytes, as the canonical encoder enforces it.
        max_len: u32,
    },
    /// A closed code-point enumeration owned by a named vocabulary.
    CodePoint {
        /// The vocabulary that owns the closed set of code points.
        vocabulary: &'static str,
    },
}

impl FieldType {
    /// Encoded width in bytes when the type is fixed-width.
    ///
    /// `None` means the encoding is length-prefixed and the width depends on
    /// the value, which is exactly the set of fields a fixed-size reader may
    /// not assume it can skip.
    #[must_use]
    pub const fn fixed_byte_len(self) -> Option<u32> {
        match self {
            Self::Scalar(width) => Some(width.byte_len()),
            Self::OpaqueId => Some(16),
            Self::Digest | Self::DerivedId { .. } | Self::SchemaId | Self::Text { .. } => None,
            Self::CodePoint { .. } => Some(2),
        }
    }

    /// Stable machine-readable name used in generated artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scalar(width) => width.as_str(),
            Self::OpaqueId => "opaque-id",
            Self::Digest => "digest",
            Self::DerivedId { .. } => "derived-id",
            Self::SchemaId => "schema-id",
            Self::Text { .. } => "text",
            Self::CodePoint { .. } => "code-point",
        }
    }

    /// One-line description of how the canonical encoder writes this type.
    #[must_use]
    pub const fn wire_encoding(self) -> &'static str {
        match self {
            Self::Scalar(_) => "big-endian unsigned integer of the declared width",
            Self::OpaqueId => "16 raw bytes, no length prefix",
            Self::Digest => "u16 algorithm code point, then a length-prefixed body",
            Self::DerivedId { .. } => {
                "u16 algorithm code point, length-prefixed domain, codec version pair, length-prefixed digest body"
            }
            Self::SchemaId => "length-prefixed family, then u16 major and u16 minor",
            Self::Text { .. } => "u32 length prefix, then that many UTF-8 bytes",
            Self::CodePoint { .. } => "u16 code point drawn from a closed vocabulary",
        }
    }
}

/// Whether a field is always present.
///
/// Kept separate from [`FieldType`] so the format stays non-recursive: the
/// container is here and the element is there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cardinality {
    /// Always present.
    Required,
    /// Encoded behind an explicit presence tag.
    ///
    /// The tag is what keeps an absent value distinct from a zero-like one,
    /// which is why an optional field is not simply a sentinel.
    Optional,
}

impl Cardinality {
    /// Whether the field may be absent.
    #[must_use]
    pub const fn is_optional(self) -> bool {
        matches!(self, Self::Optional)
    }

    /// Stable lowercase name used in generated artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
        }
    }
}

/// One field of a canonical body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldDescriptor {
    /// Field name, matching the Rust field it describes.
    pub name: &'static str,
    /// Wire type of the field's value.
    pub ty: FieldType,
    /// Whether the field is always present.
    pub cardinality: Cardinality,
    /// What the field means, carried into every generated artifact.
    pub doc: &'static str,
}

/// A description of one canonical body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemaDescriptor {
    /// Schema family, matching `CanonicalBody::SCHEMA_FAMILY`.
    pub family: &'static str,
    /// Schema major version, matching `CanonicalBody::SCHEMA_MAJOR`.
    pub major: u16,
    /// Schema minor version, matching `CanonicalBody::SCHEMA_MINOR`.
    pub minor: u16,
    /// Domain separation tag, matching `CanonicalBody::DOMAIN`.
    pub domain: &'static str,
    /// What the body is for.
    pub doc: &'static str,
    /// Fields in wire order. Order is normative: it is the encoding.
    pub fields: &'static [FieldDescriptor],
}

impl SchemaDescriptor {
    /// Number of described fields.
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// The field with this name, if the body has one.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&'static FieldDescriptor> {
        self.fields.iter().find(|field| field.name == name)
    }

    /// Field names in wire order.
    #[must_use]
    pub fn field_names(&self) -> Vec<&'static str> {
        self.fields.iter().map(|field| field.name).collect()
    }

    /// Whether every field is fixed-width, so the body has a constant size.
    ///
    /// Not currently true of any described body, and asserted rather than
    /// assumed: a reader that skips a body by a constant offset would be wrong
    /// for all four.
    #[must_use]
    pub fn is_fixed_size(&self) -> bool {
        self.fields
            .iter()
            .all(|field| field.cardinality == Cardinality::Required)
            && self
                .fields
                .iter()
                .all(|field| field.ty.fixed_byte_len().is_some())
    }

    /// The artifact stem generated files use for this schema.
    ///
    /// Includes the major version because a breaking change generates a second
    /// set of artifacts side by side rather than overwriting the first.
    #[must_use]
    pub fn artifact_stem(&self) -> String {
        format!("{}-v{}", self.family, self.major)
    }
}
