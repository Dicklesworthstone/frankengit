//! Version tokens and store identity.
//!
//! The head generation itself is not defined here: it is
//! `fgit_types::HeadGeneration`, the one canonical gap-free monotone counter
//! for the `generation` field of `RepositoryAuthorityHeadBody`. This crate
//! consumes that type rather than minting a parallel one.
//!
//! An authority version token is the opaque conditional-write handle defined in
//! `NORMATIVE_PROTOCOL_CONTRACTS.md` §1: it is obtained from a previously
//! authenticated head read and is protected against ABA by never being reused
//! and by never being derived from the head body.  Two byte-identical head
//! bodies published at different times therefore carry different tokens, which
//! is what makes "restore the previous bytes" observable to a conditional
//! writer that still holds the older token.
//!
//! Tokens are opaque to callers.  They are transportable (a receipt crosses a
//! process boundary) but they carry no caller-interpretable structure: only the
//! issuing store may decide what a token means, and a store rejects any token
//! it did not itself issue.

/// Identity of one authority store instance (endpoint plus credential scope).
///
/// Cross-instance token confusion is a real deployment hazard: a token minted
/// by one endpoint must never be honoured by another.  The instance identity is
/// embedded in every minted token so the check is structural.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoreInstanceId(u64);

impl StoreInstanceId {
    /// Name a store instance.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw instance discriminator.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Number of bytes in the transportable form of a version token.
pub const VERSION_TOKEN_BYTES: usize = 16;

/// An opaque, never-reused conditional-write token.
///
/// The inner bytes are an issuance coordinate, never a function of the stored
/// body.  Callers must treat the value as an uninterpreted handle: compare it
/// for equality, transport it, and hand it back to the store that issued it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityVersionToken([u8; VERSION_TOKEN_BYTES]);

impl AuthorityVersionToken {
    /// Mint the token for one issuance coordinate.
    ///
    /// Only a backend calls this, and only with a per-instance issuance
    /// sequence that never repeats within the instance's lifetime.
    pub(crate) fn mint(instance: StoreInstanceId, issuance: u64) -> Self {
        let mut bytes = [0_u8; VERSION_TOKEN_BYTES];
        bytes[..8].copy_from_slice(&instance.raw().to_be_bytes());
        bytes[8..].copy_from_slice(&issuance.to_be_bytes());
        Self(bytes)
    }

    /// The instance that minted this token, if the token is well formed.
    pub(crate) fn minted_by(self) -> StoreInstanceId {
        let mut raw = [0_u8; 8];
        raw.copy_from_slice(&self.0[..8]);
        StoreInstanceId::from_raw(u64::from_be_bytes(raw))
    }

    /// The transportable form of the token.
    #[must_use]
    pub const fn to_opaque_bytes(self) -> [u8; VERSION_TOKEN_BYTES] {
        self.0
    }

    /// Reconstruct a token from its transportable form.
    ///
    /// This deliberately accepts arbitrary bytes.  Unforgeability is not a
    /// property of the type; it is a property of the store, which refuses any
    /// token that is absent from its own issuance record.
    #[must_use]
    pub const fn from_opaque_bytes(bytes: [u8; VERSION_TOKEN_BYTES]) -> Self {
        Self(bytes)
    }
}

/// Byte-lexicographic index order only.
///
/// The ordering exists so a token can key a sorted map inside a backend.  It
/// carries no semantic meaning: a caller must never infer recency, generation,
/// or issuance sequence from a comparison of two tokens.
impl Ord for AuthorityVersionToken {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for AuthorityVersionToken {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
