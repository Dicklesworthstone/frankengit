//! Opaque identity carriers recorded by obligation reservations and receipts.
//!
//! `fgit-resource` sits at layer L0 and deliberately does not interpret,
//! derive, or domain-separate any identity. It records exactly what the
//! reserving caller bound so that a receipt can be replayed and audited. The
//! typed identity domains (native object identifiers, strong digests,
//! transaction identifiers, authority version tokens) are owned by
//! `fgit-types` and `fgit-crypto`; those crates convert into [`BoundIdentity`]
//! at the boundary. Nothing here may be used to decide equality *of domain*:
//! two identities from different domains that share bytes are still different
//! facts, and that distinction lives in the owning crate.

use core::fmt;

/// Largest identity byte string this crate carries.
///
/// Sized for a 32-byte strong digest; a 20-byte SHA-1 native object identifier
/// also fits without padding ambiguity because the length is carried alongside.
pub const MAX_IDENTITY_LEN: usize = 32;

/// A byte identity recorded verbatim by a reservation or receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundIdentity {
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

impl BoundIdentity {
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

impl fmt::Display for BoundIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The idempotency key that makes one external effect replay-safe.
///
/// Reusing a key with different canonical request bytes is a defect the owning
/// protocol must reject; this crate only carries the key it was handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdempotencyKey(BoundIdentity);

impl IdempotencyKey {
    /// Wraps a recorded identity as an idempotency key.
    #[must_use]
    pub const fn new(identity: BoundIdentity) -> Self {
        Self(identity)
    }

    /// The underlying identity.
    #[must_use]
    pub const fn identity(&self) -> BoundIdentity {
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
