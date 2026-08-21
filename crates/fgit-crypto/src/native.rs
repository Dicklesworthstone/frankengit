//! Native Git object identity, typed by hash algorithm.
//!
//! NORMATIVE_PROTOCOL_CONTRACTS section 3.1 requires that equal digest bytes
//! under different algorithms are not equal identities and that every API
//! able to cross repository context carries the hash algorithm explicitly.
//! `fgit-types` provides the erased shell `GitObjectId`, which is the right
//! representation when the algorithm is genuinely a runtime value. This module
//! provides the *typed* layer above it: [`GitOid<A>`] is parameterised by an
//! algorithm marker, so a SHA-1 identity and a SHA-256 identity are different
//! Rust types and confusing them is a compile error rather than a comparison
//! that quietly answers `false`.
//!
//! ```
//! use fgit_crypto::{GitObjectKind, GitOid, Sha1};
//!
//! // The empty blob's well-known SHA-1 identity.
//! let oid = GitOid::<Sha1>::of_object(GitObjectKind::Blob, b"");
//! assert_eq!(oid.to_hex(), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
//! ```
//!
//! Cross-format comparison does not compile:
//!
//! ```compile_fail
//! use fgit_crypto::{GitObjectKind, GitOid, Sha1, Sha256};
//!
//! let narrow = GitOid::<Sha1>::of_object(GitObjectKind::Blob, b"");
//! let wide = GitOid::<Sha256>::of_object(GitObjectKind::Blob, b"");
//! let _ = narrow == wide;
//! ```
//!
//! Neither does passing one where the other is expected:
//!
//! ```compile_fail
//! use fgit_crypto::{GitObjectKind, GitOid, Sha1, Sha256};
//!
//! fn requires_sha256(_oid: GitOid<Sha256>) {}
//! requires_sha256(GitOid::<Sha1>::of_object(GitObjectKind::Blob, b""));
//! ```
//!
//! Hex parsing always has an algorithm in scope; there is no untyped
//! `parse_hex(&str)` that guesses from the input width:
//!
//! ```compile_fail
//! let _ = fgit_crypto::GitOid::parse_hex("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
//! ```

use core::fmt;
use core::marker::PhantomData;

use fgit_types::GitObjectId;

use crate::hashing::{DigestHasher, Sha1Hasher, Sha256Hasher};
use crate::registry::DigestAlgorithm;

const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// Sealing module for the closed algorithm set.
#[doc(hidden)]
pub mod closed {
    /// Implemented only by the algorithm markers this crate defines.
    pub trait AlgorithmMarker {}
}

/// A native Git hash algorithm, as a type.
///
/// The trait is sealed: the algorithm set is closed, exactly like the
/// [`DigestAlgorithm`] enumeration it mirrors. A downstream crate cannot add
/// a third Git object format by implementing this trait.
pub trait GitHashAlgorithm:
    closed::AlgorithmMarker + Copy + Clone + fmt::Debug + Eq + Ord + core::hash::Hash
{
    /// The registry entry for this algorithm.
    const ALGORITHM: DigestAlgorithm;
    /// Digest width in bytes.
    const DIGEST_LEN: usize;
    /// Digest width in lowercase hexadecimal characters.
    const HEX_LEN: usize;

    /// Fixed-width digest representation.
    type Digest: Copy + Eq + Ord + core::hash::Hash + fmt::Debug + AsRef<[u8]>;
    /// Streaming hasher producing [`Self::Digest`].
    type Hasher: DigestHasher<Output = Self::Digest> + Clone + fmt::Debug;

    /// Build a digest from exactly [`Self::DIGEST_LEN`] bytes.
    fn digest_from_slice(bytes: &[u8]) -> Option<Self::Digest>;

    /// Erase a digest into the algorithm-tagged shell.
    fn erase_digest(digest: &Self::Digest) -> GitObjectId;
}

/// Algorithm marker for SHA-1 Git object format.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha1;

/// Algorithm marker for SHA-256 Git object format.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256;

impl closed::AlgorithmMarker for Sha1 {}
impl closed::AlgorithmMarker for Sha256 {}

impl GitHashAlgorithm for Sha1 {
    const ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha1;
    const DIGEST_LEN: usize = 20;
    const HEX_LEN: usize = 40;

    type Digest = [u8; 20];
    type Hasher = Sha1Hasher;

    fn digest_from_slice(bytes: &[u8]) -> Option<Self::Digest> {
        bytes.try_into().ok()
    }

    fn erase_digest(digest: &Self::Digest) -> GitObjectId {
        GitObjectId::Sha1(*digest)
    }
}

impl GitHashAlgorithm for Sha256 {
    const ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha256;
    const DIGEST_LEN: usize = 32;
    const HEX_LEN: usize = 64;

    type Digest = [u8; 32];
    type Hasher = Sha256Hasher;

    fn digest_from_slice(bytes: &[u8]) -> Option<Self::Digest> {
        bytes.try_into().ok()
    }

    fn erase_digest(digest: &Self::Digest) -> GitObjectId {
        GitObjectId::Sha256(*digest)
    }
}

/// The four native Git object types.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GitObjectKind {
    /// File content.
    Blob,
    /// Directory listing.
    Tree,
    /// Commit.
    Commit,
    /// Annotated tag.
    Tag,
}

impl GitObjectKind {
    /// Every object type, in Git's canonical numeric order.
    pub const ALL: &'static [Self] = &[Self::Commit, Self::Tree, Self::Blob, Self::Tag];

    /// The exact ASCII label Git writes into the object header.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
            Self::Tag => "tag",
        }
    }

    /// Resolve an object type from its header label.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.label() == label)
    }
}

impl fmt::Display for GitObjectKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Refusal produced while parsing a hexadecimal object identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OidParseError {
    /// The input is not exactly the algorithm's hexadecimal width.
    WrongLength {
        /// Characters the algorithm requires.
        expected: usize,
        /// Characters supplied.
        actual: usize,
    },
    /// The input contains a character that is not a hexadecimal digit.
    NonHexDigit {
        /// Byte offset of the offending character.
        index: usize,
    },
    /// The input contains uppercase hexadecimal. Canonical Git identities are
    /// lowercase; accepting both spellings would give one identity two
    /// canonical forms, so normalising user input is the caller's job.
    NonCanonicalUppercase {
        /// Byte offset of the offending character.
        index: usize,
    },
}

impl fmt::Display for OidParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => write!(
                formatter,
                "object identity must be {expected} hexadecimal characters, got {actual}"
            ),
            Self::NonHexDigit { index } => {
                write!(formatter, "non-hexadecimal character at offset {index}")
            }
            Self::NonCanonicalUppercase { index } => write!(
                formatter,
                "uppercase hexadecimal at offset {index} is not a canonical object identity"
            ),
        }
    }
}

impl std::error::Error for OidParseError {}

/// Refusal produced while hashing a framed Git object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GitHashError {
    /// More content was supplied than the header declared.
    DeclaredLengthOverrun {
        /// Length committed into the object header.
        declared: u64,
        /// Bytes the caller attempted to supply in total.
        received: u64,
    },
    /// Less content was supplied than the header declared.
    DeclaredLengthShortfall {
        /// Length committed into the object header.
        declared: u64,
        /// Bytes actually supplied.
        received: u64,
    },
}

impl fmt::Display for GitHashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeclaredLengthOverrun { declared, received } => write!(
                formatter,
                "object content overruns the declared length: declared {declared}, received {received}"
            ),
            Self::DeclaredLengthShortfall { declared, received } => write!(
                formatter,
                "object content is shorter than the declared length: declared {declared}, received {received}"
            ),
        }
    }
}

impl std::error::Error for GitHashError {}

/// A native Git object identity for one specific hash algorithm.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitOid<A: GitHashAlgorithm> {
    digest: A::Digest,
    algorithm: PhantomData<A>,
}

/// A SHA-1 native Git object identity.
pub type Sha1Oid = GitOid<Sha1>;
/// A SHA-256 native Git object identity.
pub type Sha256Oid = GitOid<Sha256>;

impl<A: GitHashAlgorithm> GitOid<A> {
    /// The registry entry for this identity's algorithm.
    #[must_use]
    pub const fn algorithm() -> DigestAlgorithm {
        A::ALGORITHM
    }

    /// Wrap an already-computed digest.
    #[must_use]
    pub const fn from_digest(digest: A::Digest) -> Self {
        Self {
            digest,
            algorithm: PhantomData,
        }
    }

    /// The digest in its fixed-width representation.
    #[must_use]
    pub const fn digest(&self) -> &A::Digest {
        &self.digest
    }

    /// The digest as raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.digest.as_ref()
    }

    /// The canonical lowercase hexadecimal spelling.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let bytes = self.as_bytes();
        let mut text = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        text
    }

    /// Parse the canonical lowercase hexadecimal spelling.
    ///
    /// The algorithm is the type parameter, so there is no way to call this
    /// without having chosen one.
    pub fn parse_hex(hex: &str) -> Result<Self, OidParseError> {
        let bytes = decode_canonical_hex(hex, A::DIGEST_LEN)?;
        let digest = A::digest_from_slice(&bytes).ok_or(OidParseError::WrongLength {
            expected: A::HEX_LEN,
            actual: hex.len(),
        })?;
        Ok(Self::from_digest(digest))
    }

    /// Erase into the algorithm-tagged shell used where the algorithm is a
    /// runtime value.
    #[must_use]
    pub fn erase(&self) -> GitObjectId {
        A::erase_digest(&self.digest)
    }

    /// Compute the native identity of a complete Git object.
    ///
    /// The preimage is exactly Git's: `<type> <length>\0<content>`.
    #[must_use]
    pub fn of_object(kind: GitObjectKind, content: &[u8]) -> Self {
        let mut hasher = A::Hasher::new();
        for part in object_header(kind, content.len() as u64).iter() {
            hasher.update(part);
        }
        hasher.update(content);
        Self::from_digest(hasher.finish())
    }

    /// Start a streaming identity computation for an object whose length is
    /// known before its content is available.
    #[must_use]
    pub fn object_hasher(kind: GitObjectKind, declared_len: u64) -> GitObjectHasher<A> {
        GitObjectHasher::new(kind, declared_len)
    }
}

/// The three header fragments Git writes before an object's content.
fn object_header(kind: GitObjectKind, length: u64) -> [Vec<u8>; 3] {
    [
        kind.label().as_bytes().to_vec(),
        format!(" {length}").into_bytes(),
        vec![0],
    ]
}

/// Streaming native identity for one framed Git object.
///
/// The declared length is committed into the header before any content byte,
/// which is what makes a mis-declared length a typed refusal instead of a
/// silently different object identity.
#[derive(Clone, Debug)]
pub struct GitObjectHasher<A: GitHashAlgorithm> {
    hasher: A::Hasher,
    declared: u64,
    received: u64,
}

impl<A: GitHashAlgorithm> GitObjectHasher<A> {
    /// Begin hashing an object of `kind` with a declared content length.
    #[must_use]
    pub fn new(kind: GitObjectKind, declared_len: u64) -> Self {
        let mut hasher = A::Hasher::new();
        for part in object_header(kind, declared_len).iter() {
            hasher.update(part);
        }
        Self {
            hasher,
            declared: declared_len,
            received: 0,
        }
    }

    /// Content bytes absorbed so far.
    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }

    /// Content bytes the header committed to.
    #[must_use]
    pub const fn declared(&self) -> u64 {
        self.declared
    }

    /// Absorb the next content chunk.
    ///
    /// A chunk that would push the total past the declared length is refused
    /// and not absorbed.
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), GitHashError> {
        let chunk_len =
            u64::try_from(chunk.len()).expect("a slice length always fits in u64 on supported targets");
        let total = self.received.saturating_add(chunk_len);
        if total > self.declared {
            return Err(GitHashError::DeclaredLengthOverrun {
                declared: self.declared,
                received: total,
            });
        }
        self.hasher.update(chunk);
        self.received = total;
        Ok(())
    }

    /// Finish and produce the identity, refusing a short object.
    pub fn finish(self) -> Result<GitOid<A>, GitHashError> {
        if self.received != self.declared {
            return Err(GitHashError::DeclaredLengthShortfall {
                declared: self.declared,
                received: self.received,
            });
        }
        Ok(GitOid::from_digest(self.hasher.finish()))
    }
}

/// Parse a hexadecimal object identity when the algorithm is a runtime value.
///
/// This is the erased counterpart of [`GitOid::parse_hex`]; the algorithm is a
/// required argument, so there is no spelling of this call that omits it.
pub fn parse_git_oid_hex(
    algorithm: DigestAlgorithm,
    hex: &str,
) -> Result<GitObjectId, OidParseError> {
    let bytes = decode_canonical_hex(hex, algorithm.digest_len())?;
    match algorithm {
        DigestAlgorithm::Sha1 => Sha1::digest_from_slice(&bytes)
            .map(|digest| Sha1::erase_digest(&digest))
            .ok_or(OidParseError::WrongLength {
                expected: algorithm.hex_len(),
                actual: hex.len(),
            }),
        DigestAlgorithm::Sha256 => Sha256::digest_from_slice(&bytes)
            .map(|digest| Sha256::erase_digest(&digest))
            .ok_or(OidParseError::WrongLength {
                expected: algorithm.hex_len(),
                actual: hex.len(),
            }),
    }
}

fn decode_canonical_hex(hex: &str, digest_len: usize) -> Result<Vec<u8>, OidParseError> {
    let expected = digest_len * 2;
    if hex.len() != expected {
        return Err(OidParseError::WrongLength {
            expected,
            actual: hex.len(),
        });
    }
    let source = hex.as_bytes();
    let mut bytes = Vec::with_capacity(digest_len);
    for (index, pair) in source.chunks_exact(2).enumerate() {
        let high = hex_value(pair[0], index * 2)?;
        let low = hex_value(pair[1], index * 2 + 1)?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(byte: u8, index: usize) -> Result<u8, OidParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Err(OidParseError::NonCanonicalUppercase { index }),
        _ => Err(OidParseError::NonHexDigit { index }),
    }
}
