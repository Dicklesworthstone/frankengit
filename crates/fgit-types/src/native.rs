//! Native Git object identity.
//!
//! A Git object identity is a pair of hash algorithm and digest bytes, and the
//! two supported algorithms are separate typed domains. [`GitOidSha1`] and
//! [`GitOidSha256`] are distinct types with no conversion between them and no
//! cross-type comparison, so a SHA-1 identity cannot be passed where a
//! SHA-256 identity is required, and equal-looking bytes under different
//! algorithms are never equal identities.
//!
//! Native identity is also never an internal identity: nothing here converts
//! to or from [`crate::identity::InternalObjectId`].

use core::fmt;

use crate::error::TypeRefusal;

/// The object format a repository declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GitHashAlgorithm {
    /// The SHA-1 object format, with collision defense applied separately.
    Sha1,
    /// The SHA-256 object format.
    Sha256,
}

impl GitHashAlgorithm {
    /// Every member, in stable code-point order.
    pub const ALL: &'static [Self] = &[Self::Sha1, Self::Sha256];

    /// Stable wire code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::Sha1 => 1,
            Self::Sha256 => 2,
        }
    }

    /// Raw digest length in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => GitOidSha1::LEN,
            Self::Sha256 => GitOidSha256::LEN,
        }
    }

    /// Lowercase name used by Git configuration and by this project's
    /// diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// Recovers a member from its wire code point.
    pub fn from_code_point(code_point: u16) -> Result<Self, TypeRefusal> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code_point() == code_point)
            .ok_or_else(|| TypeRefusal::CodePointUnknown {
                field: "GitHashAlgorithm",
                observed: u32::from(code_point),
            })
    }
}

impl fmt::Display for GitHashAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Parses lowercase hexadecimal into a fixed-size buffer.
fn parse_hex<const N: usize>(field: &'static str, text: &str) -> Result<[u8; N], TypeRefusal> {
    let source = text.as_bytes();
    if source.len() != N * 2 {
        return Err(TypeRefusal::LengthOutOfRange {
            field,
            observed: u32::try_from(source.len()).unwrap_or(u32::MAX),
            minimum: u32::try_from(N * 2).unwrap_or(u32::MAX),
            maximum: u32::try_from(N * 2).unwrap_or(u32::MAX),
        });
    }
    let mut out = [0_u8; N];
    for (index, pair) in source.chunks_exact(2).enumerate() {
        let high = hex_nibble(field, pair[0], index * 2)?;
        let low = hex_nibble(field, pair[1], index * 2 + 1)?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

/// Decodes one lowercase hexadecimal digit.
///
/// Uppercase is refused: object identities have exactly one canonical text
/// form, so `AB` and `ab` must not both be accepted for the same value.
fn hex_nibble(field: &'static str, byte: u8, offset: usize) -> Result<u8, TypeRefusal> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(TypeRefusal::ByteNotPermitted {
            field,
            offset: u32::try_from(offset).unwrap_or(u32::MAX),
            byte,
        }),
    }
}

/// Formats bytes as lowercase hexadecimal.
fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// A native Git object identity in the SHA-1 domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GitOidSha1([u8; Self::LEN]);

impl GitOidSha1 {
    /// Digest length in bytes.
    pub const LEN: usize = 20;
    /// The all-zero identity, which Git uses to mean "no object" in a ref
    /// update and which is never a real object identity.
    pub const ZERO: Self = Self([0_u8; Self::LEN]);

    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Parses the canonical lowercase hexadecimal form.
    pub fn from_hex(text: &str) -> Result<Self, TypeRefusal> {
        parse_hex::<{ Self::LEN }>("GitOidSha1", text).map(Self)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// The algorithm domain this identity belongs to.
    #[must_use]
    pub const fn algorithm(&self) -> GitHashAlgorithm {
        GitHashAlgorithm::Sha1
    }

    /// True for the all-zero "no object" identity.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == Self::ZERO.0
    }
}

impl fmt::Display for GitOidSha1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0)
    }
}

/// A native Git object identity in the SHA-256 domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GitOidSha256([u8; Self::LEN]);

impl GitOidSha256 {
    /// Digest length in bytes.
    pub const LEN: usize = 32;
    /// The all-zero identity, which Git uses to mean "no object" in a ref
    /// update and which is never a real object identity.
    pub const ZERO: Self = Self([0_u8; Self::LEN]);

    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Parses the canonical lowercase hexadecimal form.
    pub fn from_hex(text: &str) -> Result<Self, TypeRefusal> {
        parse_hex::<{ Self::LEN }>("GitOidSha256", text).map(Self)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// The algorithm domain this identity belongs to.
    #[must_use]
    pub const fn algorithm(&self) -> GitHashAlgorithm {
        GitHashAlgorithm::Sha256
    }

    /// True for the all-zero "no object" identity.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == Self::ZERO.0
    }
}

impl fmt::Display for GitOidSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0)
    }
}

/// A native Git object identity whose algorithm is carried at runtime.
///
/// Every interface that can cross repository context uses this form so the
/// algorithm is explicit. Two values in different domains are never equal,
/// even when their digest bytes overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GitOid {
    /// A SHA-1 domain identity.
    Sha1(GitOidSha1),
    /// A SHA-256 domain identity.
    Sha256(GitOidSha256),
}

impl GitOid {
    /// The algorithm domain this identity belongs to.
    #[must_use]
    pub const fn algorithm(&self) -> GitHashAlgorithm {
        match self {
            Self::Sha1(_) => GitHashAlgorithm::Sha1,
            Self::Sha256(_) => GitHashAlgorithm::Sha256,
        }
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Sha1(oid) => oid.as_bytes().as_slice(),
            Self::Sha256(oid) => oid.as_bytes().as_slice(),
        }
    }

    /// Parses the canonical lowercase hexadecimal form in the named domain.
    pub fn from_hex(algorithm: GitHashAlgorithm, text: &str) -> Result<Self, TypeRefusal> {
        match algorithm {
            GitHashAlgorithm::Sha1 => GitOidSha1::from_hex(text).map(Self::Sha1),
            GitHashAlgorithm::Sha256 => GitOidSha256::from_hex(text).map(Self::Sha256),
        }
    }

    /// Returns the SHA-1 identity, refusing a value from the other domain.
    pub fn require_sha1(&self) -> Result<GitOidSha1, TypeRefusal> {
        match self {
            Self::Sha1(oid) => Ok(*oid),
            Self::Sha256(_) => Err(TypeRefusal::HashDomainMismatch {
                expected: GitHashAlgorithm::Sha1,
                observed: GitHashAlgorithm::Sha256,
            }),
        }
    }

    /// Returns the SHA-256 identity, refusing a value from the other domain.
    pub fn require_sha256(&self) -> Result<GitOidSha256, TypeRefusal> {
        match self {
            Self::Sha256(oid) => Ok(*oid),
            Self::Sha1(_) => Err(TypeRefusal::HashDomainMismatch {
                expected: GitHashAlgorithm::Sha256,
                observed: GitHashAlgorithm::Sha1,
            }),
        }
    }

    /// True for the all-zero "no object" identity in either domain.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        match self {
            Self::Sha1(oid) => oid.is_zero(),
            Self::Sha256(oid) => oid.is_zero(),
        }
    }
}

impl From<GitOidSha1> for GitOid {
    fn from(oid: GitOidSha1) -> Self {
        Self::Sha1(oid)
    }
}

impl From<GitOidSha256> for GitOid {
    fn from(oid: GitOidSha256) -> Self {
        Self::Sha256(oid)
    }
}

impl fmt::Display for GitOid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1(oid) => fmt::Display::fmt(oid, formatter),
            Self::Sha256(oid) => fmt::Display::fmt(oid, formatter),
        }
    }
}
