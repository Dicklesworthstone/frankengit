//! Bounded, opaque storage keys for the authority substrate.
//!
//! The authority substrate is deliberately key/value shaped: it never parses a
//! head body, a seal body, or any other FrankenGit canonical encoding.  A key
//! is an opaque, bounded, non-empty byte string that the caller derives (for
//! example from tenant/repository/`TxId` scoping as described in
//! `NORMATIVE_PROTOCOL_CONTRACTS.md` §5.2).  Keeping key derivation outside the
//! store is what allows one backend contract to serve the embedded profile, an
//! object-store profile, and a future replicated `authorityd`.
//!
//! Head keys and immutable keys are distinct types over distinct namespaces, so
//! a compare-and-exchange can never be aimed at an immutable body and a
//! put-if-absent can never be aimed at the repository head.

/// Why a byte string is not admissible as an authority key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum KeyError {
    /// An empty key cannot name a slot.
    Empty,
    /// The key exceeds the backend's declared bound.
    TooLong {
        /// Length of the rejected key in bytes.
        len: usize,
        /// The bound that was exceeded.
        limit: usize,
    },
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Empty => f.write_str("authority key is empty"),
            Self::TooLong { len, limit } => {
                write!(
                    f,
                    "authority key of {len} bytes exceeds the {limit}-byte bound"
                )
            }
        }
    }
}

impl std::error::Error for KeyError {}

/// The largest key any first-party authority profile accepts.
///
/// The bound is part of the contract, not a backend detail: a caller that
/// derives longer keys must be refused identically by every profile.
pub const MAX_KEY_BYTES: usize = 256;

const fn validate(bytes: &[u8]) -> Result<(), KeyError> {
    if bytes.is_empty() {
        return Err(KeyError::Empty);
    }
    if bytes.len() > MAX_KEY_BYTES {
        return Err(KeyError::TooLong {
            len: bytes.len(),
            limit: MAX_KEY_BYTES,
        });
    }
    Ok(())
}

/// The key of one repository authority head slot.
///
/// Exactly one head key per repository carries canonical authority; the store
/// itself does not know that rule and treats the key as opaque bytes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HeadKey(Vec<u8>);

impl HeadKey {
    /// Construct a head key from caller-derived scoping bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, KeyError> {
        let bytes = bytes.into();
        validate(&bytes)?;
        Ok(Self(bytes))
    }

    /// The exact scoping bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The key of one immutable body slot (seal, decision batch, capsule, head body).
///
/// Immutable slots are write-once: the only admissible transitions are absent
/// to present, and present to the byte-identical present value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ImmutableKey(Vec<u8>);

impl ImmutableKey {
    /// Construct an immutable-body key from caller-derived scoping bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, KeyError> {
        let bytes = bytes.into();
        validate(&bytes)?;
        Ok(Self(bytes))
    }

    /// The exact scoping bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
