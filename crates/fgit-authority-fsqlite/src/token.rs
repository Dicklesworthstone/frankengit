//! Version tokens for the embedded profile.
//!
//! The rule the whole ABA defence rests on is that a token is **never a
//! function of the body it names**. Here a token is `(instance, issuance
//! sequence)` in big-endian, and the sequence comes from the committed
//! issuance ledger rather than from a counter in memory.
//!
//! That second half is what the embedded profile has to get right and the
//! in-memory reference profile does not: a process that is killed between
//! minting a token and committing it must not, on reopen, mint the same token
//! again. Deriving the next sequence from `MAX(issued_seq)` inside the same
//! transaction that records the row makes reuse impossible by construction —
//! either the transaction committed, in which case the row is there and the
//! next sequence is past it, or it did not, in which case nothing was published
//! under that token either.
//!
//! The cost is one indexed aggregate per write instead of an in-memory
//! increment. That is the right trade: a counter cached in memory is exactly
//! the thing a crash invalidates.

use fgit_authority::{AuthorityVersionToken, HeadGeneration, StoreInstanceId, VERSION_TOKEN_BYTES};

/// A position in one store's append-only issuance ledger.
///
/// Sequences start at one; zero is reserved so that an empty ledger and a
/// first issuance are never confused in a nullable SQL aggregate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IssuanceSequence(u64);

impl IssuanceSequence {
    /// The sequence of the first token a store ever mints.
    pub const FIRST: Self = Self(1);

    /// Name a sequence, refusing the reserved zero.
    pub const fn new(raw: u64) -> Result<Self, TokenMintError> {
        if raw == 0 {
            return Err(TokenMintError::SequenceReserved);
        }
        Ok(Self(raw))
    }

    /// The raw sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Why a token could not be minted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TokenMintError {
    /// Sequence zero is reserved to mean "the ledger is empty".
    SequenceReserved,
    /// The issuance space is exhausted.
    ///
    /// Wrapping would reuse a token, so this refuses instead.
    SequenceExhausted {
        /// The last sequence issued.
        last: u64,
    },
}

impl core::fmt::Display for TokenMintError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::SequenceReserved => {
                f.write_str("issuance sequence zero is reserved for the empty ledger")
            }
            Self::SequenceExhausted { last } => write!(
                f,
                "issuance space exhausted at {last}; wrapping would reuse a version token"
            ),
        }
    }
}

impl std::error::Error for TokenMintError {}

/// The sequence that follows the ledger's current maximum.
///
/// `None` means the ledger is empty, which is the only case that yields
/// [`IssuanceSequence::FIRST`]. This is the exact resolution of the nullable
/// `SELECT MAX(issued_seq)` the statement set issues.
pub const fn next_issuance_after(
    committed_maximum: Option<u64>,
) -> Result<IssuanceSequence, TokenMintError> {
    match committed_maximum {
        None => Ok(IssuanceSequence::FIRST),
        Some(last) => match last.checked_add(1) {
            Some(next) => Ok(IssuanceSequence(next)),
            None => Err(TokenMintError::SequenceExhausted { last }),
        },
    }
}

/// Mint the token for one issuance coordinate.
///
/// The body is not an input. That is the point, and it is the property the
/// contract's ABA check exercises: writing state A, then B, then a
/// byte-identical A yields three different tokens, so a writer still holding
/// the first one loses.
#[must_use]
pub fn mint_token(instance: StoreInstanceId, sequence: IssuanceSequence) -> AuthorityVersionToken {
    let mut bytes = [0_u8; VERSION_TOKEN_BYTES];
    bytes[..8].copy_from_slice(&instance.raw().to_be_bytes());
    bytes[8..].copy_from_slice(&sequence.get().to_be_bytes());
    AuthorityVersionToken::from_opaque_bytes(bytes)
}

/// The instance that minted a token, read back from its transport form.
///
/// A token whose instance is not this store's was minted somewhere else, which
/// is the cheap half of the endpoint-confusion check; the ledger lookup is the
/// authoritative half.
#[must_use]
pub fn token_instance(token: AuthorityVersionToken) -> StoreInstanceId {
    let opaque = token.to_opaque_bytes();
    let mut raw = [0_u8; 8];
    raw.copy_from_slice(&opaque[..8]);
    StoreInstanceId::from_raw(u64::from_be_bytes(raw))
}

/// One row of the append-only issuance ledger.
///
/// The ledger is what an authenticated head read is checked against: it records
/// exactly what was published under each token, so a receipt bearing altered
/// bytes or an altered generation is refused even though its token is genuine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceRecord {
    /// The minted token.
    pub token: AuthorityVersionToken,
    /// Its position in the ledger.
    pub sequence: IssuanceSequence,
    /// The head slot the token was minted for.
    pub head_key: Vec<u8>,
    /// The generation published under it.
    pub generation: HeadGeneration,
    /// The exact bytes published under it.
    pub body_bytes: Vec<u8>,
}

impl IssuanceRecord {
    /// Whether a presented receipt agrees with what was actually issued.
    #[must_use]
    pub fn matches(&self, head_key: &[u8], generation: HeadGeneration, body: &[u8]) -> bool {
        self.head_key == head_key && self.generation == generation && self.body_bytes == body
    }
}
