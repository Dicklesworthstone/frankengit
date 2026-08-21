//! The typed refusal a canonical encoder or decoder returns.
//!
//! Nothing here is an "internal error". Every variant names what was expected,
//! what was observed, and where, so a rejected body can be diagnosed from a
//! log line without re-running the decoder.

use core::fmt;

use fgit_types::{DomainTag, RefusalCode, SchemaFamily, TypeRefusal};

/// Stores a label compactly.
///
/// The label types are inline fixed-capacity buffers, which is right for a
/// value that travels in every identity but wrong for an error: a refusal
/// carrying two of them would push `Result<_, CodecRefusal>` past the size at
/// which returning it by value costs more than the happy path it guards.
fn label(value: &impl core::fmt::Display) -> Box<str> {
    value.to_string().into_boxed_str()
}

/// Why a canonical body could not be encoded or decoded.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CodecRefusal {
    /// The frame did not begin with the canonical magic.
    MagicUnrecognized {
        /// The four bytes actually present.
        observed: [u8; 4],
    },
    /// The frame declares a codec major version this build does not implement.
    ///
    /// Refusing is the point: a newer major may reorder or reinterpret fields,
    /// so guessing would produce a confidently wrong value.
    CodecMajorUnsupported {
        /// Major version the frame declares.
        observed: u16,
        /// Major version this build implements.
        supported: u16,
    },
    /// The frame declares a codec minor version this build does not implement,
    /// and the caller asked for a strict decode.
    ///
    /// Strict decoding accepts only the exact versions it can reproduce. A
    /// body carrying a higher minor may be byte-compatible, but re-encoding it
    /// here would emit this build's minor and so would not reproduce the
    /// original bytes. Relaying such a body is what
    /// [`crate::decode_body_preserving`] is for.
    CodecMinorUnsupported {
        /// Minor version the frame declares.
        observed: u16,
        /// Minor version this build implements.
        supported: u16,
    },
    /// The body declares a schema minor version this build does not implement,
    /// and the caller asked for a strict decode.
    SchemaMinorUnsupported {
        /// Domain separation tag of the body.
        domain: Box<str>,
        /// Minor version the body declares.
        observed: u16,
        /// Minor version this build implements.
        supported: u16,
    },
    /// The body declares a schema major version this build does not implement.
    SchemaMajorUnsupported {
        /// Domain separation tag of the body.
        domain: Box<str>,
        /// Major version the body declares.
        observed: u16,
        /// Major version this build implements.
        supported: u16,
    },
    /// The frame's schema family is not the one the caller asked to decode.
    SchemaFamilyUnexpected {
        /// Family the caller required.
        expected: Box<str>,
        /// Family the frame declares.
        observed: Box<str>,
    },
    /// The frame's domain separation tag is not the one the caller asked to
    /// decode, so the bytes belong to a different schema.
    DomainUnexpected {
        /// Domain the caller required.
        expected: Box<str>,
        /// Domain the frame declares.
        observed: Box<str>,
    },
    /// The input ended before a value that the framing promised.
    InputTruncated {
        /// What was being read.
        field: &'static str,
        /// Bytes still required.
        needed: u64,
        /// Bytes still available.
        available: u64,
        /// Offset the read started at.
        offset: u64,
    },
    /// Bytes remained after the body was fully decoded.
    ///
    /// A canonical body has exactly one byte string, so a suffix means these
    /// are not that body's bytes.
    TrailingBytes {
        /// Offset where the body ended.
        offset: u64,
        /// Bytes left over.
        remaining: u64,
    },
    /// A length exceeded its decode bound.
    LengthBoundExceeded {
        /// What was being read.
        field: &'static str,
        /// Length the input declares.
        observed: u64,
        /// Bound in force.
        limit: u64,
    },
    /// An element count exceeded its decode bound.
    CountBoundExceeded {
        /// What was being read.
        field: &'static str,
        /// Count the input declares.
        observed: u64,
        /// Bound in force.
        limit: u64,
    },
    /// Nesting exceeded its decode bound.
    DepthBoundExceeded {
        /// Bound in force.
        limit: u32,
        /// Offset where the bound was reached.
        offset: u64,
    },
    /// A boolean byte was neither `0x00` nor `0x01`.
    BooleanByteInvalid {
        /// The byte present.
        observed: u8,
        /// Offset of the byte.
        offset: u64,
    },
    /// An optional tag byte was neither `0x00` nor `0x01`.
    OptionTagInvalid {
        /// The byte present.
        observed: u8,
        /// Offset of the byte.
        offset: u64,
    },
    /// A text value was not valid `UTF-8`.
    TextNotUtf8 {
        /// What was being read.
        field: &'static str,
        /// Offset of the text value.
        offset: u64,
    },
    /// A canonical collection's elements were not in strictly ascending
    /// encoded-byte order.
    CollectionUnordered {
        /// What was being read.
        field: &'static str,
        /// Index of the element that broke the order.
        index: u64,
        /// Offset of the collection.
        offset: u64,
    },
    /// A canonical collection contained the same element or key twice.
    CollectionDuplicate {
        /// What was being read.
        field: &'static str,
        /// Index of the repeated element.
        index: u64,
        /// Offset of the collection.
        offset: u64,
    },
    /// A variant tag did not name any member of a closed vocabulary.
    VariantUnknown {
        /// What was being read.
        field: &'static str,
        /// The unmatched tag.
        observed: u32,
        /// Offset of the tag.
        offset: u64,
    },
    /// A value could not be built because it exceeds what the encoder can
    /// represent, for example a byte string longer than a length prefix.
    ValueUnrepresentable {
        /// What was being written.
        field: &'static str,
        /// The offending magnitude.
        observed: u64,
        /// Largest representable magnitude.
        limit: u64,
    },
    /// A body's domain separation tag is not registered in the identity
    /// registry, so no identity can be computed for it.
    ///
    /// This is a refusal rather than a fallback because computing an identity
    /// under an unregistered domain would produce a value nothing else could
    /// verify.
    IdentityDomainUnregistered {
        /// The unregistered tag.
        domain: Box<str>,
    },
    /// A decoded component was rejected by its own type.
    Type(TypeRefusal),
}

impl CodecRefusal {
    /// Builds a domain mismatch from the typed labels.
    #[must_use]
    pub fn domain_unexpected(expected: DomainTag, observed: DomainTag) -> Self {
        Self::DomainUnexpected {
            expected: label(&expected),
            observed: label(&observed),
        }
    }

    /// Builds a schema-family mismatch from the typed labels.
    #[must_use]
    pub fn schema_family_unexpected(expected: SchemaFamily, observed: SchemaFamily) -> Self {
        Self::SchemaFamilyUnexpected {
            expected: label(&expected),
            observed: label(&observed),
        }
    }

    /// Builds an unregistered-domain refusal from the typed label.
    #[must_use]
    pub fn identity_domain_unregistered(domain: DomainTag) -> Self {
        Self::IdentityDomainUnregistered {
            domain: label(&domain),
        }
    }

    /// Builds an unsupported-schema-minor refusal from the typed label.
    #[must_use]
    pub fn schema_minor_unsupported(domain: DomainTag, observed: u16, supported: u16) -> Self {
        Self::SchemaMinorUnsupported {
            domain: label(&domain),
            observed,
            supported,
        }
    }

    /// Builds an unsupported-schema-major refusal from the typed label.
    #[must_use]
    pub fn schema_major_unsupported(domain: DomainTag, observed: u16, supported: u16) -> Self {
        Self::SchemaMajorUnsupported {
            domain: label(&domain),
            observed,
            supported,
        }
    }

    /// Stable machine-readable discriminant for logs and evidence records.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::MagicUnrecognized { .. } => "magic_unrecognized",
            Self::CodecMajorUnsupported { .. } => "codec_major_unsupported",
            Self::CodecMinorUnsupported { .. } => "codec_minor_unsupported",
            Self::SchemaMinorUnsupported { .. } => "schema_minor_unsupported",
            Self::SchemaMajorUnsupported { .. } => "schema_major_unsupported",
            Self::SchemaFamilyUnexpected { .. } => "schema_family_unexpected",
            Self::DomainUnexpected { .. } => "domain_unexpected",
            Self::InputTruncated { .. } => "input_truncated",
            Self::TrailingBytes { .. } => "trailing_bytes",
            Self::LengthBoundExceeded { .. } => "length_bound_exceeded",
            Self::CountBoundExceeded { .. } => "count_bound_exceeded",
            Self::DepthBoundExceeded { .. } => "depth_bound_exceeded",
            Self::BooleanByteInvalid { .. } => "boolean_byte_invalid",
            Self::OptionTagInvalid { .. } => "option_tag_invalid",
            Self::TextNotUtf8 { .. } => "text_not_utf8",
            Self::CollectionUnordered { .. } => "collection_unordered",
            Self::CollectionDuplicate { .. } => "collection_duplicate",
            Self::VariantUnknown { .. } => "variant_unknown",
            Self::ValueUnrepresentable { .. } => "value_unrepresentable",
            Self::IdentityDomainUnregistered { .. } => "identity_domain_unregistered",
            Self::Type(_) => "type_refusal",
        }
    }

    /// The protocol refusal this codec failure reports as.
    ///
    /// The mapping is total and deterministic, so a decode failure and the
    /// refusal recorded in the decision stream never disagree.
    #[must_use]
    pub const fn refusal_code(&self) -> RefusalCode {
        match self {
            Self::MagicUnrecognized { .. }
            | Self::CodecMajorUnsupported { .. }
            | Self::CodecMinorUnsupported { .. }
            | Self::SchemaMinorUnsupported { .. }
            | Self::SchemaMajorUnsupported { .. }
            | Self::SchemaFamilyUnexpected { .. }
            | Self::DomainUnexpected { .. }
            | Self::IdentityDomainUnregistered { .. } => RefusalCode::SchemaUnsupported,
            Self::InputTruncated { .. }
            | Self::TrailingBytes { .. }
            | Self::BooleanByteInvalid { .. }
            | Self::OptionTagInvalid { .. }
            | Self::TextNotUtf8 { .. }
            | Self::CollectionUnordered { .. }
            | Self::CollectionDuplicate { .. }
            | Self::VariantUnknown { .. } => RefusalCode::CanonicalFramingInvalid,
            Self::LengthBoundExceeded { .. }
            | Self::CountBoundExceeded { .. }
            | Self::DepthBoundExceeded { .. }
            | Self::ValueUnrepresentable { .. } => RefusalCode::CanonicalBoundExceeded,
            Self::Type(refusal) => refusal.refusal_code(),
        }
    }
}

impl From<TypeRefusal> for CodecRefusal {
    fn from(refusal: TypeRefusal) -> Self {
        Self::Type(refusal)
    }
}

impl fmt::Display for CodecRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MagicUnrecognized { observed } => {
                write!(formatter, "frame magic unrecognized: {observed:02x?}")
            }
            Self::CodecMajorUnsupported {
                observed,
                supported,
            } => write!(
                formatter,
                "codec major {observed} is unsupported; this build implements {supported}"
            ),
            Self::CodecMinorUnsupported {
                observed,
                supported,
            } => write!(
                formatter,
                "codec minor {observed} is unsupported for a strict decode; this build implements {supported}"
            ),
            Self::SchemaMinorUnsupported {
                domain,
                observed,
                supported,
            } => write!(
                formatter,
                "{domain}: schema minor {observed} is unsupported for a strict decode; this build implements {supported}"
            ),
            Self::SchemaMajorUnsupported {
                domain,
                observed,
                supported,
            } => write!(
                formatter,
                "{domain}: schema major {observed} is unsupported; this build implements {supported}"
            ),
            Self::SchemaFamilyUnexpected { expected, observed } => write!(
                formatter,
                "schema family mismatch: expected {expected}, observed {observed}"
            ),
            Self::DomainUnexpected { expected, observed } => write!(
                formatter,
                "domain mismatch: expected {expected}, observed {observed}"
            ),
            Self::InputTruncated {
                field,
                needed,
                available,
                offset,
            } => write!(
                formatter,
                "{field}: truncated at offset {offset}; needed {needed} bytes, {available} available"
            ),
            Self::TrailingBytes { offset, remaining } => write!(
                formatter,
                "{remaining} trailing bytes after the body ended at offset {offset}"
            ),
            Self::LengthBoundExceeded {
                field,
                observed,
                limit,
            } => write!(
                formatter,
                "{field}: declared length {observed} exceeds the bound {limit}"
            ),
            Self::CountBoundExceeded {
                field,
                observed,
                limit,
            } => write!(
                formatter,
                "{field}: declared count {observed} exceeds the bound {limit}"
            ),
            Self::DepthBoundExceeded { limit, offset } => {
                write!(formatter, "nesting deeper than {limit} at offset {offset}")
            }
            Self::BooleanByteInvalid { observed, offset } => write!(
                formatter,
                "boolean byte 0x{observed:02x} at offset {offset} is neither 0x00 nor 0x01"
            ),
            Self::OptionTagInvalid { observed, offset } => write!(
                formatter,
                "option tag 0x{observed:02x} at offset {offset} is neither 0x00 nor 0x01"
            ),
            Self::TextNotUtf8 { field, offset } => {
                write!(formatter, "{field}: text at offset {offset} is not UTF-8")
            }
            Self::CollectionUnordered {
                field,
                index,
                offset,
            } => write!(
                formatter,
                "{field}: element {index} at offset {offset} is not in ascending canonical order"
            ),
            Self::CollectionDuplicate {
                field,
                index,
                offset,
            } => write!(
                formatter,
                "{field}: element {index} at offset {offset} repeats an earlier element"
            ),
            Self::VariantUnknown {
                field,
                observed,
                offset,
            } => write!(
                formatter,
                "{field}: unknown variant tag {observed} at offset {offset}"
            ),
            Self::ValueUnrepresentable {
                field,
                observed,
                limit,
            } => write!(
                formatter,
                "{field}: value {observed} exceeds the largest representable {limit}"
            ),
            Self::IdentityDomainUnregistered { domain } => write!(
                formatter,
                "domain {domain} is not registered in the identity registry"
            ),
            Self::Type(refusal) => write!(formatter, "{refusal}"),
        }
    }
}

impl std::error::Error for CodecRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Type(refusal) => Some(refusal),
            _ => None,
        }
    }
}
