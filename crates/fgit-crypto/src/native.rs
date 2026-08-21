//! Native Git object identity: the hashing that produces the `fgit-types`
//! identity types, typed by algorithm.
//!
//! `fgit-types` owns the native identity *values*: `GitOidSha1` and
//! `GitOidSha256` are distinct nominal types with no conversion and no
//! cross-type comparison, and `GitOid` is the erased form that carries the
//! algorithm at runtime. This module deliberately defines no parallel
//! identity type. What it adds is the algorithm as a *type parameter*, so a
//! generic caller can be written once and still be unable to mix formats:
//!
//! ```
//! use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
//!
//! // `GitOid<Sha1>` is exactly `fgit_types::GitOidSha1`, not a copy of it.
//! let oid: GitOid<Sha1> = GitOid::<Sha1>::of_object(GitObjectKind::Blob, b"");
//! assert_eq!(oid.to_string(), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
//! ```
//!
//! Comparing the two formats does not compile:
//!
//! ```compile_fail
//! use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
//!
//! let narrow = GitOid::<Sha1>::of_object(GitObjectKind::Blob, b"");
//! let wide = GitOid::<Sha256>::of_object(GitObjectKind::Blob, b"");
//! let _ = narrow == wide;
//! ```
//!
//! Neither does substituting one for the other:
//!
//! ```compile_fail
//! use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
//!
//! fn requires_sha256(_oid: GitOid<Sha256>) {}
//! requires_sha256(GitOid::<Sha1>::of_object(GitObjectKind::Blob, b""));
//! ```
//!
//! Hexadecimal parsing never guesses the algorithm from the input width; the
//! typed entry point takes it as a type parameter, so this is ambiguous:
//!
//! ```compile_fail
//! let _ = fgit_crypto::parse_git_oid("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
//! ```

use core::fmt;

use fgit_types::error::TypeRefusal;
use fgit_types::native::{
    GitHashAlgorithm as GitObjectFormat, GitOid as AnyGitOid, GitOidSha1, GitOidSha256,
};

use crate::hashing::{DigestHasher, Sha1Hasher, Sha256Hasher};
use crate::registry::DigestAlgorithm;

/// Sealing module for the closed algorithm set.
#[doc(hidden)]
pub mod closed {
    /// Implemented only by the algorithm markers this crate defines.
    pub trait AlgorithmMarker {}
}

/// A native Git hash algorithm, as a type.
///
/// The trait is sealed: the algorithm set is closed, exactly like the
/// [`DigestAlgorithm`] enumeration it mirrors. A downstream crate cannot add a
/// third Git object format by implementing this trait.
pub trait GitHashAlgorithm:
    closed::AlgorithmMarker + Copy + Clone + fmt::Debug + Eq + Ord + core::hash::Hash
{
    /// The registry entry for this construction.
    const ALGORITHM: DigestAlgorithm;
    /// The declared repository object format that uses it.
    const OBJECT_FORMAT: GitObjectFormat;
    /// Digest width in bytes.
    const DIGEST_LEN: usize;
    /// Digest width in lowercase hexadecimal characters.
    const HEX_LEN: usize;

    /// Fixed-width digest representation.
    type Digest: Copy + Eq + Ord + core::hash::Hash + fmt::Debug + AsRef<[u8]>;
    /// Streaming hasher producing [`Self::Digest`].
    type Hasher: DigestHasher<Output = Self::Digest> + Clone + fmt::Debug;
    /// The `fgit-types` identity value this algorithm produces.
    type Oid: NativeObjectIdentity<Algorithm = Self>;

    /// Wrap a raw digest as the identity value.
    fn oid_from_digest(digest: Self::Digest) -> Self::Oid;

    /// Parse the canonical lowercase hexadecimal form in this algorithm's
    /// domain, delegating to the `fgit-types` decoder.
    fn parse_hex(text: &str) -> Result<Self::Oid, TypeRefusal>;
}

/// The four native Git object types.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GitObjectKind {
    /// Commit.
    Commit,
    /// Directory listing.
    Tree,
    /// File content.
    Blob,
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
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }

    /// Git's canonical numeric object type.
    #[must_use]
    pub const fn type_code(self) -> u8 {
        match self {
            Self::Commit => 1,
            Self::Tree => 2,
            Self::Blob => 3,
            Self::Tag => 4,
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

/// Refusal produced while hashing a framed Git object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GitHashError {
    /// More content was supplied than the header declared.
    DeclaredLengthOverrun {
        /// Length committed into the object header.
        declared: u64,
        /// Total the caller attempted to supply.
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

/// Native identity computation for one `fgit-types` object-identity type.
///
/// The trait is implemented on the `fgit-types` values themselves, so
/// `GitOid::<A>::of_object(..)` reads as identity construction rather than as
/// a conversion through a second identity type.
pub trait NativeObjectIdentity: Copy + Eq + fmt::Debug + Sized {
    /// The algorithm marker that produces this identity.
    type Algorithm: GitHashAlgorithm<Oid = Self>;

    /// Compute the native identity of a complete Git object.
    ///
    /// The preimage is exactly Git's: type label, space, decimal content
    /// length, a zero byte, then the content.
    #[must_use]
    fn of_object(kind: GitObjectKind, content: &[u8]) -> Self {
        let length = u64::try_from(content.len())
            .expect("a slice length always fits in u64 on supported targets");
        let mut hasher =
            <<Self::Algorithm as GitHashAlgorithm>::Hasher as DigestHasher>::new();
        hasher.update(&object_header(kind, length));
        hasher.update(content);
        <Self::Algorithm as GitHashAlgorithm>::oid_from_digest(hasher.finish())
    }

    /// Start a streaming identity computation for an object whose length is
    /// known before its content is available.
    #[must_use]
    fn object_hasher(kind: GitObjectKind, declared_len: u64) -> GitObjectHasher<Self::Algorithm> {
        GitObjectHasher::new(kind, declared_len)
    }

    /// The raw digest bytes.
    fn digest_bytes(&self) -> &[u8];

    /// Erase into the runtime-tagged form.
    fn erase(self) -> AnyGitOid;
}

/// The identity type produced by algorithm `A`.
///
/// This is an alias, not a new type: `GitOid<Sha1>` *is*
/// `fgit_types::GitOidSha1`.
pub type GitOid<A> = <A as GitHashAlgorithm>::Oid;

/// Algorithm marker for the SHA-1 Git object format.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha1;

/// Algorithm marker for the SHA-256 Git object format.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256;

impl closed::AlgorithmMarker for Sha1 {}
impl closed::AlgorithmMarker for Sha256 {}

impl GitHashAlgorithm for Sha1 {
    const ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha1;
    const OBJECT_FORMAT: GitObjectFormat = GitObjectFormat::Sha1;
    const DIGEST_LEN: usize = 20;
    const HEX_LEN: usize = 40;

    type Digest = [u8; 20];
    type Hasher = Sha1Hasher;
    type Oid = GitOidSha1;

    fn oid_from_digest(digest: Self::Digest) -> Self::Oid {
        GitOidSha1::from_bytes(digest)
    }

    fn parse_hex(text: &str) -> Result<Self::Oid, TypeRefusal> {
        GitOidSha1::from_hex(text)
    }
}

impl GitHashAlgorithm for Sha256 {
    const ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha256;
    const OBJECT_FORMAT: GitObjectFormat = GitObjectFormat::Sha256;
    const DIGEST_LEN: usize = 32;
    const HEX_LEN: usize = 64;

    type Digest = [u8; 32];
    type Hasher = Sha256Hasher;
    type Oid = GitOidSha256;

    fn oid_from_digest(digest: Self::Digest) -> Self::Oid {
        GitOidSha256::from_bytes(digest)
    }

    fn parse_hex(text: &str) -> Result<Self::Oid, TypeRefusal> {
        GitOidSha256::from_hex(text)
    }
}

impl NativeObjectIdentity for GitOidSha1 {
    type Algorithm = Sha1;

    fn digest_bytes(&self) -> &[u8] {
        self.as_bytes().as_slice()
    }

    fn erase(self) -> AnyGitOid {
        AnyGitOid::Sha1(self)
    }
}

impl NativeObjectIdentity for GitOidSha256 {
    type Algorithm = Sha256;

    fn digest_bytes(&self) -> &[u8] {
        self.as_bytes().as_slice()
    }

    fn erase(self) -> AnyGitOid {
        AnyGitOid::Sha256(self)
    }
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
        let mut hasher = <A::Hasher as DigestHasher>::new();
        hasher.update(&object_header(kind, declared_len));
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
    /// and not absorbed, so a refused hasher cannot later be finished into a
    /// plausible-looking identity.
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), GitHashError> {
        let chunk_len = u64::try_from(chunk.len())
            .expect("a slice length always fits in u64 on supported targets");
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
    pub fn finish(self) -> Result<A::Oid, GitHashError> {
        if self.received == self.declared {
            Ok(A::oid_from_digest(self.hasher.finish()))
        } else {
            Err(GitHashError::DeclaredLengthShortfall {
                declared: self.declared,
                received: self.received,
            })
        }
    }
}

/// Parse a canonical lowercase hexadecimal identity in a chosen algorithm.
///
/// The algorithm is the type parameter; there is no spelling of this call that
/// leaves it to be inferred from the input width.
pub fn parse_git_oid<A: GitHashAlgorithm>(text: &str) -> Result<A::Oid, TypeRefusal> {
    A::parse_hex(text)
}

/// Compute a native identity when the object format is a runtime value.
#[must_use]
pub fn git_object_id(
    format: GitObjectFormat,
    kind: GitObjectKind,
    content: &[u8],
) -> AnyGitOid {
    match format {
        GitObjectFormat::Sha1 => GitOidSha1::of_object(kind, content).erase(),
        GitObjectFormat::Sha256 => GitOidSha256::of_object(kind, content).erase(),
    }
}

/// The exact header Git writes before an object's content: type label, space,
/// decimal length, and a terminating zero byte.
pub(crate) fn object_header(kind: GitObjectKind, length: u64) -> Vec<u8> {
    let decimal = length.to_string();
    let mut header = Vec::with_capacity(kind.label().len() + decimal.len() + 2);
    header.extend_from_slice(kind.label().as_bytes());
    header.push(b' ');
    header.extend_from_slice(decimal.as_bytes());
    header.push(0);
    header
}
