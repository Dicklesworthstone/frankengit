//! Bounded, charset-restricted ASCII labels and the schema identifier built
//! from them.
//!
//! Labels are inline and fixed-capacity so that identity values stay `Copy`,
//! allocation-free, and portable to a `WebAssembly` target. The character set
//! is deliberately narrow: lowercase ASCII letters, digits, and the four
//! separators `-`, `_`, `.`, and `/`. Case folding, Unicode normalization, and
//! locale-sensitive comparison can therefore never change a canonical
//! identity.

use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};

use crate::error::TypeRefusal;

/// Maximum label length in bytes.
pub const MAX_LABEL_LEN: usize = 64;

/// A bounded lowercase ASCII label.
///
/// Accepted bytes are `a`..=`z`, `0`..=`9`, `-`, `_`, `.`, and `/`. The length
/// window is 1..=[`MAX_LABEL_LEN`].
#[derive(Clone, Copy)]
pub struct AsciiSlug {
    bytes: [u8; MAX_LABEL_LEN],
    len: usize,
}

impl AsciiSlug {
    /// Smallest accepted length.
    pub const MIN_LEN: usize = 1;
    /// Largest accepted length.
    pub const MAX_LEN: usize = MAX_LABEL_LEN;

    const fn byte_is_permitted(byte: u8) -> bool {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'-' | b'_' | b'.' | b'/')
    }

    /// Builds a label from runtime bytes, refusing anything outside the length
    /// window or the canonical character set.
    pub fn try_new(field: &'static str, source: &[u8]) -> Result<Self, TypeRefusal> {
        if source.is_empty() || source.len() > Self::MAX_LEN {
            return Err(TypeRefusal::LengthOutOfRange {
                field,
                observed: u32::try_from(source.len()).unwrap_or(u32::MAX),
                minimum: 1,
                maximum: 64,
            });
        }
        let mut bytes = [0_u8; MAX_LABEL_LEN];
        for (offset, byte) in source.iter().copied().enumerate() {
            if !Self::byte_is_permitted(byte) {
                return Err(TypeRefusal::ByteNotPermitted {
                    field,
                    offset: u32::try_from(offset).unwrap_or(u32::MAX),
                    byte,
                });
            }
            bytes[offset] = byte;
        }
        Ok(Self {
            bytes,
            len: source.len(),
        })
    }

    /// Builds a label in a `const` context.
    ///
    /// A violation of the length window or the character set is a
    /// compile-time error when this is used to initialize a `const` item,
    /// which is the only intended use. Runtime callers use
    /// [`AsciiSlug::try_new`], which refuses instead of aborting.
    #[must_use]
    pub const fn from_static(source: &'static str) -> Self {
        let source = source.as_bytes();
        assert!(
            !source.is_empty() && source.len() <= MAX_LABEL_LEN,
            "label length outside 1..=64"
        );
        let mut bytes = [0_u8; MAX_LABEL_LEN];
        let mut offset = 0;
        while offset < source.len() {
            let byte = source[offset];
            assert!(
                Self::byte_is_permitted(byte),
                "label byte outside the canonical character set"
            );
            bytes[offset] = byte;
            offset += 1;
        }
        Self {
            bytes,
            len: source.len(),
        }
    }

    /// The label bytes, without padding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.split_at(self.len).0
    }

    /// The label as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Every accepted byte is ASCII, so the slice is valid UTF-8 by
        // construction; the fallback keeps this total without panicking.
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    /// Label length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Always false: a label cannot be empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl PartialEq for AsciiSlug {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for AsciiSlug {}

impl PartialOrd for AsciiSlug {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AsciiSlug {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl Hash for AsciiSlug {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl fmt::Debug for AsciiSlug {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.as_str())
    }
}

impl fmt::Display for AsciiSlug {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A domain separation tag.
///
/// The tag is the first component hashed into an internal object identity, so
/// two schemas can never produce the same identity from the same body bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainTag(AsciiSlug);

impl DomainTag {
    /// Builds a domain tag in a `const` context.
    #[must_use]
    pub const fn from_static(source: &'static str) -> Self {
        Self(AsciiSlug::from_static(source))
    }

    /// Builds a domain tag from runtime bytes.
    pub fn try_new(source: &[u8]) -> Result<Self, TypeRefusal> {
        AsciiSlug::try_new("DomainTag", source).map(Self)
    }

    /// The tag bytes, without padding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The tag as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for DomainTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

/// The family half of a schema identifier, for example `ref-txn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemaFamily(AsciiSlug);

impl SchemaFamily {
    /// Builds a schema family in a `const` context.
    #[must_use]
    pub const fn from_static(source: &'static str) -> Self {
        Self(AsciiSlug::from_static(source))
    }

    /// Builds a schema family from runtime bytes.
    pub fn try_new(source: &[u8]) -> Result<Self, TypeRefusal> {
        AsciiSlug::try_new("SchemaFamily", source).map(Self)
    }

    /// The family bytes, without padding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The family as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for SchemaFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

/// A schema identifier: one family plus an explicit major and minor version.
///
/// The major version is the compatibility boundary. A decoder that meets an
/// unknown major version refuses; a decoder that meets a known major with a
/// higher minor version may proceed under the framing rules, because minor
/// versions only add optional trailing fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemaId {
    family: SchemaFamily,
    major: u16,
    minor: u16,
}

impl SchemaId {
    /// Builds a schema identifier.
    #[must_use]
    pub const fn new(family: SchemaFamily, major: u16, minor: u16) -> Self {
        Self {
            family,
            major,
            minor,
        }
    }

    /// The schema family.
    #[must_use]
    pub const fn family(&self) -> SchemaFamily {
        self.family
    }

    /// The compatibility-breaking major version.
    #[must_use]
    pub const fn major(&self) -> u16 {
        self.major
    }

    /// The additive minor version.
    #[must_use]
    pub const fn minor(&self) -> u16 {
        self.minor
    }
}

impl fmt::Display for SchemaId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/v{}.{}", self.family, self.major, self.minor)
    }
}
