//! The one typed construction refusal for this crate.
//!
//! Every constructor in `fgit-types` that can reject its input returns
//! [`TypeRefusal`]. A refusal carries the field name, the observed value, and
//! the bound that was violated so a caller can log a precise, reproducible
//! diagnosis instead of an opaque `None`. Nothing in this crate panics on
//! caller-supplied runtime data.

use core::fmt;

use crate::hash::DigestAlgorithmId;
use crate::native::GitHashAlgorithm;

/// Typed rejection produced by a `fgit-types` constructor.
///
/// This is a *construction* refusal, distinct from the protocol vocabularies in
/// [`crate::vocabulary`]: it says a value could not be built, not that a sealed
/// transaction reached a terminal decision. [`TypeRefusal::refusal_code`] maps
/// it onto the protocol vocabulary when a construction failure must be
/// reported as a transaction outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeRefusal {
    /// A bounded byte or character sequence fell outside its declared length
    /// window.
    LengthOutOfRange {
        /// Name of the rejected field, stable across releases.
        field: &'static str,
        /// Length actually supplied.
        observed: u32,
        /// Smallest accepted length.
        minimum: u32,
        /// Largest accepted length.
        maximum: u32,
    },
    /// A byte outside the accepted canonical character set appeared in a
    /// label.
    ByteNotPermitted {
        /// Name of the rejected field.
        field: &'static str,
        /// Zero-based offset of the offending byte.
        offset: u32,
        /// The offending byte value.
        byte: u8,
    },
    /// An integral value fell outside its declared window.
    ValueOutOfRange {
        /// Name of the rejected field.
        field: &'static str,
        /// Value actually supplied.
        observed: u64,
        /// Smallest accepted value.
        minimum: u64,
        /// Largest accepted value.
        maximum: u64,
    },
    /// A wire code point did not name any member of a closed vocabulary.
    /// Decoders return this rather than substituting a default member.
    CodePointUnknown {
        /// Name of the vocabulary that rejected the code point.
        field: &'static str,
        /// The unmatched code point.
        observed: u32,
    },
    /// A typed identifier was built from a digest whose domain separation tag
    /// belongs to a different schema.
    DomainMismatch {
        /// Name of the identifier type that refused the digest.
        field: &'static str,
        /// Domain separation tag the identifier requires.
        expected: &'static str,
    },
    /// Native Git identity crossed a hash domain boundary.
    ///
    /// SHA-1 and SHA-256 object identities are distinct typed domains; equal
    /// digest bytes under different algorithms are not equal identities.
    HashDomainMismatch {
        /// Algorithm the operation requires.
        expected: GitHashAlgorithm,
        /// Algorithm actually supplied.
        observed: GitHashAlgorithm,
    },
    /// A reference name's bytes were individually acceptable but its
    /// structure was not, for example a component ending in `.lock` or a
    /// `..` sequence.
    RefNameStructureInvalid {
        /// Stable machine-readable reason, for example
        /// `"component_ends_with_dot_lock"`.
        reason: &'static str,
        /// Zero-based offset where the violation was detected.
        offset: u32,
    },
    /// A digest body length disagreed with the length the algorithm slot
    /// declares.
    DigestLengthMismatch {
        /// Registry code point of the digest algorithm.
        algorithm: DigestAlgorithmId,
        /// Length the caller declared for the algorithm.
        expected: u32,
        /// Length actually supplied.
        observed: u32,
    },
}

impl TypeRefusal {
    /// Stable machine-readable discriminant for logs and evidence records.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::LengthOutOfRange { .. } => "length_out_of_range",
            Self::ByteNotPermitted { .. } => "byte_not_permitted",
            Self::ValueOutOfRange { .. } => "value_out_of_range",
            Self::CodePointUnknown { .. } => "code_point_unknown",
            Self::DomainMismatch { .. } => "domain_mismatch",
            Self::HashDomainMismatch { .. } => "hash_domain_mismatch",
            Self::RefNameStructureInvalid { .. } => "ref_name_structure_invalid",
            Self::DigestLengthMismatch { .. } => "digest_length_mismatch",
        }
    }

    /// Protocol refusal this construction failure maps to when it has to be
    /// reported as a terminal transaction decision.
    ///
    /// The mapping is total and deterministic so that a decoder failure and
    /// the refusal recorded in the decision stream never disagree.
    #[must_use]
    pub const fn refusal_code(&self) -> crate::vocabulary::RefusalCode {
        use crate::vocabulary::RefusalCode;
        match self {
            Self::LengthOutOfRange { .. } | Self::ValueOutOfRange { .. } => {
                RefusalCode::ResourceBudgetExceeded
            }
            Self::ByteNotPermitted { .. }
            | Self::CodePointUnknown { .. }
            | Self::DomainMismatch { .. } => RefusalCode::SchemaUnsupported,
            Self::RefNameStructureInvalid { .. } => RefusalCode::RefNameInvalid,
            Self::HashDomainMismatch { .. } => RefusalCode::HashAlgorithmDomainMismatch,
            Self::DigestLengthMismatch { .. } => RefusalCode::NativeObjectIdMismatch,
        }
    }
}

impl fmt::Display for TypeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOutOfRange {
                field,
                observed,
                minimum,
                maximum,
            } => write!(
                formatter,
                "{field}: length {observed} outside [{minimum}, {maximum}]"
            ),
            Self::ByteNotPermitted {
                field,
                offset,
                byte,
            } => write!(
                formatter,
                "{field}: byte 0x{byte:02x} at offset {offset} is outside the canonical character set"
            ),
            Self::ValueOutOfRange {
                field,
                observed,
                minimum,
                maximum,
            } => write!(
                formatter,
                "{field}: value {observed} outside [{minimum}, {maximum}]"
            ),
            Self::CodePointUnknown { field, observed } => {
                write!(formatter, "{field}: unknown code point {observed}")
            }
            Self::DomainMismatch { field, expected } => {
                write!(formatter, "{field}: digest domain must be {expected}")
            }
            Self::HashDomainMismatch { expected, observed } => write!(
                formatter,
                "git hash domain mismatch: expected {}, observed {}",
                expected.as_str(),
                observed.as_str()
            ),
            Self::RefNameStructureInvalid { reason, offset } => {
                write!(formatter, "RefName: {reason} at offset {offset}")
            }
            Self::DigestLengthMismatch {
                algorithm,
                expected,
                observed,
            } => write!(
                formatter,
                "digest algorithm {}: expected {expected} bytes, observed {observed}",
                algorithm.code_point()
            ),
        }
    }
}

impl std::error::Error for TypeRefusal {}
