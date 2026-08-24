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
    /// A length-prefixed opaque byte string with exact wire bounds.
    ///
    /// This is distinct from [`Self::Text`]: Git ref names and Merkle digest
    /// bodies are validated bytes, not an assertion that they are UTF-8.
    Bytes {
        /// Smallest permitted byte length.
        min_len: u32,
        /// Largest permitted byte length.
        max_len: u32,
    },
    /// A native Git object identity: an algorithm code point followed by that
    /// algorithm's fixed-width raw object ID.
    GitOid,
    /// A closed code-point enumeration owned by a named vocabulary.
    CodePoint {
        /// The vocabulary that owns the closed set of code points.
        vocabulary: &'static str,
    },
    /// A nested structure, referenced by the name of another descriptor.
    ///
    /// A REFERENCE, never an inline copy. `committed_rcrs` points at the same
    /// `rcr` descriptor the standalone body uses, so the two cannot drift
    /// apart — which is the whole reason the format resolves by name instead
    /// of nesting a `FieldType` inside a `FieldType`.
    Structure {
        /// Registry name of the referenced descriptor.
        name: &'static str,
    },
    /// A discriminated union, referenced by the name of a union descriptor.
    ///
    /// Encoded as a one-byte discriminant followed by that variant's fields.
    /// The byte is raw rather than length-prefixed, so a reader that does not
    /// know the variant cannot skip it — which is why an unknown discriminant
    /// has to be a refusal rather than a skip.
    Union {
        /// Registry name of the referenced union descriptor.
        name: &'static str,
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
            Self::CodePoint { .. } => Some(2),
            // Two different reasons for the same answer, merged because no
            // caller branches on which one applies. Digest/DerivedId/SchemaId/
            // Text/Bytes are length-prefixed, and a Git object ID's width
            // depends on its algorithm, so the width depends on the value.
            // Structure and Union are not: a structure's width is its
            // referenced descriptor's, and a union's depends on the variant.
            // Either way a fixed-size reader may not assume it can skip them.
            Self::Digest
            | Self::DerivedId { .. }
            | Self::SchemaId
            | Self::Text { .. }
            | Self::Bytes { .. }
            | Self::GitOid
            | Self::Structure { .. }
            | Self::Union { .. } => None,
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
            Self::Bytes { .. } => "bytes",
            Self::GitOid => "git-oid",
            Self::CodePoint { .. } => "code-point",
            Self::Structure { .. } => "structure",
            Self::Union { .. } => "union",
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
            Self::Bytes { .. } => "u32 length prefix, then that many validated raw bytes",
            Self::GitOid => {
                "u16 Git hash algorithm code point, then that algorithm's fixed-width raw object ID"
            }
            Self::CodePoint { .. } => "u16 code point drawn from a closed vocabulary",
            Self::Structure { .. } => "the referenced descriptor's fields, inline and in order",
            Self::Union { .. } => "one raw discriminant byte, then that variant's fields",
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
    /// A `u32` count, then that many elements.
    ///
    /// The count is always present, so an empty sequence still costs four
    /// bytes and is distinct from an absent optional. A reader that treats
    /// zero-length and absent alike would conflate "no decisions in this
    /// batch" with "this batch does not carry decisions at all".
    Sequence,
}

impl Cardinality {
    /// Whether the field may be absent.
    #[must_use]
    pub const fn is_optional(self) -> bool {
        matches!(self, Self::Optional)
    }

    /// Whether the field is a counted repetition.
    #[must_use]
    pub const fn is_sequence(self) -> bool {
        matches!(self, Self::Sequence)
    }

    /// Stable lowercase name used in generated artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
            Self::Sequence => "sequence",
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
            .all(|field| matches!(field.cardinality, Cardinality::Required))
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

/// One variant of a discriminated union.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnionVariant {
    /// Variant name, matching the Rust variant it describes.
    pub name: &'static str,
    /// The raw discriminant byte that selects this variant on the wire.
    pub discriminant: u8,
    /// The variant's fields, in wire order.
    pub fields: &'static [FieldDescriptor],
    /// What the variant means.
    pub doc: &'static str,
}

/// A discriminated union: one raw byte, then the selected variant's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnionDescriptor {
    /// Registry name, referenced by [`FieldType::Union`].
    pub name: &'static str,
    /// What the union models.
    pub doc: &'static str,
    /// The variants, in discriminant order.
    pub variants: &'static [UnionVariant],
}

impl UnionDescriptor {
    /// The variant a discriminant byte selects.
    ///
    /// `None` for an unallocated byte, which a decoder must refuse rather than
    /// skip: the payload is not length-prefixed, so an unknown variant leaves
    /// a reader with no way to find the next field.
    #[must_use]
    pub fn variant(&self, discriminant: u8) -> Option<&'static UnionVariant> {
        self.variants
            .iter()
            .find(|variant| variant.discriminant == discriminant)
    }

    /// Whether discriminants are unique and listed in ascending order.
    ///
    /// Checked rather than assumed: a duplicate would make `variant` depend on
    /// slice order, and unsorted variants would make the generated artifact
    /// unstable under an unrelated edit.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.variants
            .windows(2)
            .all(|pair| pair[0].discriminant < pair[1].discriminant)
    }
}

/// A nested structure that is not itself a canonical body.
///
/// `RepositoryDecision` is the case this exists for: it has fields and a wire
/// order, but no schema identity of its own — it is only ever encoded inside a
/// `decision-batch`. Giving it a [`SchemaDescriptor`] would mean inventing a
/// family, a version and a domain it does not have, and an invented domain is
/// exactly the kind of plausible-looking fiction the conformance test cannot
/// catch because nothing on the wire disagrees with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StructureDescriptor {
    /// Registry name, referenced by [`FieldType::Structure`].
    pub name: &'static str,
    /// What the structure models.
    pub doc: &'static str,
    /// Fields in wire order.
    pub fields: &'static [FieldDescriptor],
}
