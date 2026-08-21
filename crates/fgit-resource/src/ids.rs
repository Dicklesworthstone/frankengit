//! Region-scoped identifiers and the handle this crate carries verbatim.
//!
//! Every identity that `fgit-types` already types — object envelopes, native
//! object identifiers, digests, transaction identities, decision batches,
//! authority heads and their version tokens, principals, tenants, generations,
//! evidence records, segment manifests — appears in an obligation payload as
//! that exact type, so a receipt cannot confuse two domains that happen to
//! share bytes.
//!
//! [`OpaqueHandle`] covers what is left: an identity whose domain type belongs
//! to a system outside `FrankenGit` (a webhook endpoint, a secret delivery
//! channel, a toolchain image, a payment processor receipt) or to a crate that
//! has not been written yet. This crate records those bytes verbatim and never
//! interprets, derives, or compares them across domains.

use core::fmt;
use fgit_types::Digest;

/// Largest identity byte string this crate carries.
///
/// Sized for a 32-byte strong digest; a 20-byte SHA-1 native object identifier
/// also fits without padding ambiguity because the length is carried alongside.
pub const MAX_IDENTITY_LEN: usize = 32;

/// A byte identity recorded verbatim by a reservation or receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueHandle {
    bytes: [u8; MAX_IDENTITY_LEN],
    len: u8,
}

/// Refusal returned when an identity cannot be carried verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// The caller offered more bytes than [`MAX_IDENTITY_LEN`].
    TooLong {
        /// Number of bytes offered.
        offered: usize,
    },
    /// The caller offered an empty identity, which cannot name anything.
    Empty,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooLong { offered } => {
                write!(f, "identity of {offered} bytes exceeds {MAX_IDENTITY_LEN}")
            }
            Self::Empty => f.write_str("identity must not be empty"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl OpaqueHandle {
    /// Records `bytes` verbatim.
    pub fn new(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.is_empty() {
            return Err(IdentityError::Empty);
        }
        if bytes.len() > MAX_IDENTITY_LEN {
            return Err(IdentityError::TooLong {
                offered: bytes.len(),
            });
        }
        let Ok(len) = u8::try_from(bytes.len()) else {
            return Err(IdentityError::TooLong {
                offered: bytes.len(),
            });
        };
        let mut buffer = [0_u8; MAX_IDENTITY_LEN];
        for (target, source) in buffer.iter_mut().zip(bytes) {
            *target = *source;
        }
        Ok(Self { bytes: buffer, len })
    }

    /// The recorded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }

    /// Number of recorded bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Always `false`: an empty identity cannot be constructed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Display for OpaqueHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The idempotency key that makes one external effect replay-safe.
///
/// The key is the canonical request digest the normative transaction contract
/// derives, so it is a [`Digest`] rather than a free-form string. Reusing a key
/// with different canonical request bytes is a defect the owning protocol must
/// reject before it reaches an obligation; this crate carries the key it was
/// handed and compares it only for equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdempotencyKey(Digest);

impl IdempotencyKey {
    /// Wraps a canonical request digest as an idempotency key.
    #[must_use]
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    /// The underlying digest.
    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.0
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Identifies one ownership region within a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegionId(u64);

impl RegionId {
    /// Names a region.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "region:{}", self.0)
    }
}

/// Identifies one obligation inside one ledger.
///
/// Allocated monotonically by the ledger; it is unique within a region, not
/// globally, and carries no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObligationId {
    region: RegionId,
    sequence: u64,
}

impl ObligationId {
    /// Builds an identifier.
    #[must_use]
    pub const fn new(region: RegionId, sequence: u64) -> Self {
        Self { region, sequence }
    }

    /// The owning region.
    #[must_use]
    pub const fn region(self) -> RegionId {
        self.region
    }

    /// The per-region allocation sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

impl fmt::Display for ObligationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/obligation:{}", self.region, self.sequence)
    }
}

/// Identifies one outstanding budget grant inside one ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantId {
    region: RegionId,
    sequence: u64,
}

impl GrantId {
    /// Builds an identifier.
    #[must_use]
    pub const fn new(region: RegionId, sequence: u64) -> Self {
        Self { region, sequence }
    }

    /// The owning region.
    #[must_use]
    pub const fn region(self) -> RegionId {
        self.region
    }

    /// The per-region allocation sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/grant:{}", self.region, self.sequence)
    }
}
