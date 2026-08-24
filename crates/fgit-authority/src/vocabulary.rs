//! The authority operation and response vocabulary.
//!
//! Every authority backend speaks exactly these operations and exactly these
//! responses.  The vocabulary is the interface between three consumers:
//!
//! * the publication path, which issues typed calls through [`AuthorityStore`];
//! * the linearizability history checker (FG-004b), which records one
//!   `(invoke, return)` pair per operation and searches for a sequential
//!   witness;
//! * the fault and adversarial campaign (FG-004c), which replays scripted
//!   faults and asserts that the caller-visible responses stay within the
//!   contract.
//!
//! # The ambiguity rule
//!
//! [`AuthorityResponse::Ambiguous`] carries no outcome, and no conversion in
//! this crate turns it into a negative result.  A caller that observes it has
//! learned nothing about whether the effect occurred, which is the storage-level
//! form of `NORMATIVE_PROTOCOL_CONTRACTS.md` §14: an API must not return a
//! cancellation or timeout in a form that proves non-commit after the
//! conditional replacement could have happened.  The only admissible next step
//! is an exact-key read (§13.8) and, above this layer, a `TxId` lookup.
//!
//! [`AuthorityStore`]: crate::AuthorityStore

use crate::keys::{HeadKey, ImmutableKey, KeyError};
use fgit_types::HeadGeneration;

use crate::tokens::{AuthorityVersionToken, StoreInstanceId};

/// One authority-store invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityOp {
    /// Write an immutable body if and only if the slot is empty.
    PutIfAbsent {
        /// Slot being written.
        key: ImmutableKey,
        /// Complete body bytes; a partial body is never stored.
        body: Vec<u8>,
    },
    /// Read one immutable body by exact key.
    ReadImmutable {
        /// Slot being read.
        key: ImmutableKey,
    },
    /// Create the repository head slot if and only if it is empty.
    InitializeHead {
        /// Head slot being created.
        key: HeadKey,
        /// Generation carried by the initial head body.
        generation: HeadGeneration,
        /// Canonical initial head bytes.
        body: Vec<u8>,
    },
    /// Read the current head, its version token, and its generation.
    ReadHead {
        /// Head slot being read.
        key: HeadKey,
    },
    /// Replace the head if and only if it still carries the exact predecessor token.
    ///
    /// A successful execution of this operation is the linearization point of a
    /// repository mutation.
    CompareExchangeHead {
        /// Head slot being replaced.
        key: HeadKey,
        /// The exact predecessor token from an authenticated read.
        expected: AuthorityVersionToken,
        /// Generation carried by the proposed head body; must strictly increase.
        new_generation: HeadGeneration,
        /// Canonical proposed head bytes.
        new_body: Vec<u8>,
    },
    /// Ask the store whether a head receipt is one it actually issued.
    AuthenticateHeadReceipt {
        /// The receipt under test.
        receipt: HeadReadReceipt,
    },
}

impl AuthorityOp {
    /// The operation's kind, used for fault targeting and history summaries.
    #[must_use]
    pub const fn kind(&self) -> AuthorityOpKind {
        match self {
            Self::PutIfAbsent { .. } => AuthorityOpKind::PutIfAbsent,
            Self::ReadImmutable { .. } => AuthorityOpKind::ReadImmutable,
            Self::InitializeHead { .. } => AuthorityOpKind::InitializeHead,
            Self::ReadHead { .. } => AuthorityOpKind::ReadHead,
            Self::CompareExchangeHead { .. } => AuthorityOpKind::CompareExchangeHead,
            Self::AuthenticateHeadReceipt { .. } => AuthorityOpKind::AuthenticateHeadReceipt,
        }
    }

    /// Whether a successful execution can change observable store state.
    ///
    /// Only mutating operations can leave a caller in the ambiguous state that
    /// requires exact-key resolution.
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        matches!(
            self,
            Self::PutIfAbsent { .. }
                | Self::InitializeHead { .. }
                | Self::CompareExchangeHead { .. }
        )
    }
}

/// The kind discriminant of an [`AuthorityOp`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthorityOpKind {
    /// [`AuthorityOp::PutIfAbsent`].
    PutIfAbsent,
    /// [`AuthorityOp::ReadImmutable`].
    ReadImmutable,
    /// [`AuthorityOp::InitializeHead`].
    InitializeHead,
    /// [`AuthorityOp::ReadHead`].
    ReadHead,
    /// [`AuthorityOp::CompareExchangeHead`].
    CompareExchangeHead,
    /// [`AuthorityOp::AuthenticateHeadReceipt`].
    AuthenticateHeadReceipt,
}

/// One authority-store response.
///
/// The success variants correspond one-to-one with [`AuthorityOpKind`].
/// [`Self::Refused`] and [`Self::Ambiguous`] may follow any operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityResponse {
    /// Result of [`AuthorityOp::PutIfAbsent`].
    PutIfAbsent(PutOutcome),
    /// Result of [`AuthorityOp::ReadImmutable`].
    ReadImmutable(ImmutableRead),
    /// Result of [`AuthorityOp::InitializeHead`].
    InitializeHead(HeadInit),
    /// Result of [`AuthorityOp::ReadHead`].
    ReadHead(HeadRead),
    /// Result of [`AuthorityOp::CompareExchangeHead`].
    CompareExchangeHead(CasOutcome),
    /// Result of [`AuthorityOp::AuthenticateHeadReceipt`].
    AuthenticateHeadReceipt(AuthenticatedHead),
    /// The store definitely applied no effect.
    Refused(AuthorityRefusal),
    /// The effect status is unknown and MUST NOT be read as non-commit.
    Ambiguous(AmbiguityReason),
}

impl AuthorityResponse {
    /// What this response proves about the effect of the operation.
    #[must_use]
    pub const fn effect_knowledge(&self) -> EffectKnowledge {
        match self {
            Self::Refused(_) => EffectKnowledge::NoEffect,
            Self::Ambiguous(_) => EffectKnowledge::Unknown,
            _ => EffectKnowledge::Observed,
        }
    }

    /// Whether the caller may conclude that no effect occurred.
    ///
    /// This is false for [`Self::Ambiguous`] by construction; there is no other
    /// path in this crate that turns an ambiguous response into a negative.
    #[must_use]
    pub const fn proves_no_effect(&self) -> bool {
        matches!(self.effect_knowledge(), EffectKnowledge::NoEffect)
    }
}

/// What a response proves about whether the store applied an effect.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EffectKnowledge {
    /// The store returned an outcome, so the effect (if any) is known exactly.
    Observed,
    /// The store refused before any effect.
    NoEffect,
    /// Nothing is known; resolve by exact-key read, then by `TxId` lookup.
    Unknown,
}

/// The three admissible outcomes of a put-if-absent against an immutable slot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PutOutcome {
    /// The slot was empty and now holds exactly the supplied body.
    Created,
    /// The slot already held a byte-identical body; the retry is idempotent.
    IdenticalRetry,
    /// The slot already held a different body; immutability forbids replacement.
    Conflict,
}

/// The result of reading one immutable slot by exact key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImmutableRead {
    /// The complete stored body.
    Present(Vec<u8>),
    /// No body has been published at this key.
    Absent,
}

/// The result of creating a repository head slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeadInit {
    /// The head slot was empty and now holds the supplied body.
    Created(HeadReadReceipt),
    /// The head slot already held the identical generation and body.
    IdenticalRetry(HeadReadReceipt),
    /// The head slot already held a different generation or body.
    Conflict,
}

/// The result of reading the repository head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeadRead {
    /// The current head, its token, and its generation.
    Present(HeadReadReceipt),
    /// The repository head has never been created.
    Absent,
}

/// The result of a conditional head replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CasOutcome {
    /// The replacement succeeded; this is the mutation's linearization point.
    Committed(HeadReadReceipt),
    /// The head no longer carries the supplied predecessor token.
    ///
    /// The loser learns nothing else: it must reread authority and then
    /// preserve, refine, rebase, or re-evaluate the same sealed request
    /// (`NORMATIVE_PROTOCOL_CONTRACTS.md` §10 steps 18-19).
    PredecessorMismatch,
}

/// An authenticated read of the repository head.
///
/// The receipt is the storage-layer half of the `AuthorityReadReceipt` defined
/// in `docs/AGENT_PROTOCOL.md` §4.1: it names the head slot, the exact bytes
/// observed, the generation those bytes carry, and the opaque token that must
/// be presented to replace them.
///
/// The type is publicly constructible on purpose.  A fault or adversarial
/// campaign must be able to build a forged or tampered receipt; the security
/// property lives in the store, which refuses any receipt whose token it did
/// not issue and any receipt whose bytes disagree with what it issued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadReadReceipt {
    key: HeadKey,
    token: AuthorityVersionToken,
    generation: HeadGeneration,
    body: Vec<u8>,
}

impl HeadReadReceipt {
    /// Assemble a receipt.
    #[must_use]
    pub const fn new(
        key: HeadKey,
        token: AuthorityVersionToken,
        generation: HeadGeneration,
        body: Vec<u8>,
    ) -> Self {
        Self {
            key,
            token,
            generation,
            body,
        }
    }

    /// The head slot this receipt describes.
    #[must_use]
    pub const fn key(&self) -> &HeadKey {
        &self.key
    }

    /// The conditional-write token for the observed head.
    #[must_use]
    pub const fn token(&self) -> AuthorityVersionToken {
        self.token
    }

    /// The generation carried by the observed head body.
    #[must_use]
    pub const fn generation(&self) -> HeadGeneration {
        self.generation
    }

    /// The exact observed head bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// A head receipt that a backend has checked against its own issuance record.
///
/// # Non-claim
///
/// Authenticity is not currency.  A receipt that the store really did issue
/// stays authentic forever, including after the head has moved on.  Presenting
/// an authenticated stale receipt to a conditional replacement still loses with
/// [`CasOutcome::PredecessorMismatch`], and the conformance suite asserts it.
///
/// The type is a marker for "some backend said yes", not an unforgeable
/// capability: any backend can construct one.  Enforcement is the conformance
/// suite, which requires a backend to refuse receipts it never issued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedHead {
    receipt: HeadReadReceipt,
    verified_against: StoreInstanceId,
}

impl AuthenticatedHead {
    /// Record that `receipt` was verified against `verified_against`'s issuance
    /// record.
    #[must_use]
    pub const fn new(receipt: HeadReadReceipt, verified_against: StoreInstanceId) -> Self {
        Self {
            receipt,
            verified_against,
        }
    }

    /// The verified receipt.
    #[must_use]
    pub const fn receipt(&self) -> &HeadReadReceipt {
        &self.receipt
    }

    /// The STORE whose issuance record the receipt was verified against.
    ///
    /// This names the store, never the reader. It was called `authenticated_by`
    /// and documented as "the instance that performed the verification", which
    /// is a statement about the *reader* — and the value never was that. Both
    /// production construction sites pass the store's own recorded id
    /// (`fgit-authority-fsqlite/src/engine.rs`, `fgit-object-store/src/lib.rs`),
    /// and `establish()` hands every opener of one store the same id, so N cells
    /// sharing a backend all reported the same value.
    ///
    /// That is correct behaviour — a token issued by store X must stay
    /// recognisable as X's — but under the old name it read as an answer to
    /// "which cell served this?", and an operator auditing a multi-cell
    /// deployment would have concluded that one cell served everything. A
    /// missing identity sends a reader looking; a mislabelled one makes them
    /// stop. Measured on three cells over one backend in
    /// `fgit-node/tests/multicell_hint_routing.rs`, all reporting instance 1.
    ///
    /// Per-cell identity is a separate thing that does not exist yet
    /// (`frankengit-1egm`). When it lands, `authenticated_by` is free to mean
    /// what it says.
    #[must_use]
    pub const fn verified_against(&self) -> StoreInstanceId {
        self.verified_against
    }
}

/// A bounded, typed refusal.  A refusal always means no effect was applied.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorityRefusal {
    /// The supplied key is not admissible.
    InvalidKey(KeyError),
    /// The supplied body exceeds the backend's declared bound.
    BodyTooLarge {
        /// Length of the rejected body.
        len: usize,
        /// The bound that was exceeded.
        limit: usize,
    },
    /// The backend's declared slot or version capacity is exhausted.
    CapacityExhausted {
        /// Current occupancy.
        occupancy: usize,
        /// The bound that was reached.
        limit: usize,
    },
    /// The presented token was never issued by this store instance.
    ///
    /// This is the forged-receipt signal, and it is deliberately distinct from
    /// [`CasOutcome::PredecessorMismatch`], which means "issued here, but no
    /// longer current".
    UnknownVersionToken,
    /// The presented token was issued by this store, but for a different key.
    TokenKeyMismatch,
    /// The presented receipt disagrees with the issued generation.
    TokenGenerationMismatch,
    /// The presented receipt disagrees with the issued body bytes.
    TokenBodyMismatch,
    /// The head slot named by the operation has never been created.
    HeadAbsent,
    /// The proposed generation does not strictly increase.
    NonMonotoneGeneration {
        /// Generation currently published.
        current: HeadGeneration,
        /// Generation the caller proposed.
        proposed: HeadGeneration,
    },
    /// The request was shed before reaching any effect; retry with backoff.
    Throttled,
    /// The endpoint rejected the request without processing it.
    ///
    /// This is the connection-refused shape, not the timeout shape.  A timeout
    /// is [`AmbiguityReason::Timeout`] and proves nothing.
    Unavailable,
    /// This backend does not implement the requested operation at all.
    ///
    /// Structural and permanent, which is why it is not
    /// [`AuthorityRefusal::Unavailable`]: that one is the connection-refused
    /// shape, and a caller may reasonably retry it. A backend that cannot
    /// publish atomically will never be able to, so reporting it as an endpoint
    /// rejection would invite a retry that can never succeed.
    ///
    /// Added for the atomic publication primitive: an object store with no
    /// multi-key transaction has to be able to say so honestly rather than
    /// borrow a nearby code. A near-miss refusal is worse than a new variant —
    /// it is a wrong answer that looks like a right one.
    ///
    /// Carries no payload deliberately. A `&'static str` naming the operation
    /// reads well but cannot round-trip through the history decoder without
    /// leaking or inventing a registry, and the caller already knows which
    /// operation it invoked. A field that cannot survive replay is not
    /// evidence.
    OperationUnsupported,
}

impl core::fmt::Display for AuthorityRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::InvalidKey(error) => write!(f, "invalid authority key: {error}"),
            Self::BodyTooLarge { len, limit } => {
                write!(f, "body of {len} bytes exceeds the {limit}-byte bound")
            }
            Self::CapacityExhausted { occupancy, limit } => {
                write!(f, "capacity exhausted at {occupancy} of {limit}")
            }
            Self::UnknownVersionToken => {
                f.write_str("version token was never issued by this store")
            }
            Self::TokenKeyMismatch => f.write_str("version token was issued for a different key"),
            Self::TokenGenerationMismatch => {
                f.write_str("receipt generation disagrees with the issued generation")
            }
            Self::TokenBodyMismatch => f.write_str("receipt body disagrees with the issued body"),
            Self::HeadAbsent => f.write_str("repository head slot does not exist"),
            Self::NonMonotoneGeneration { current, proposed } => write!(
                f,
                "proposed generation {proposed} does not strictly increase past {current}"
            ),
            Self::Throttled => f.write_str("request shed before any effect"),
            Self::OperationUnsupported => {
                f.write_str("this backend does not implement the requested operation")
            }
            Self::Unavailable => f.write_str("endpoint rejected the request without processing it"),
        }
    }
}

impl std::error::Error for AuthorityRefusal {}

/// Why the caller cannot know whether an effect occurred.
///
/// Every variant is indistinguishable from every other at the call site of a
/// real backend; the distinction exists only so a deterministic fault script
/// can record which shape it injected.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AmbiguityReason {
    /// No response arrived.  The request may or may not have reached the effect.
    NoResponse,
    /// The caller's deadline expired.
    Timeout,
    /// The caller cancelled after the request was transmitted.
    ///
    /// Cancellation after transmission never proves non-commit
    /// (`NORMATIVE_PROTOCOL_CONTRACTS.md` §14).
    Cancelled,
}

impl core::fmt::Display for AmbiguityReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match *self {
            Self::NoResponse => "no response arrived",
            Self::Timeout => "deadline expired",
            Self::Cancelled => "cancelled after transmission",
        };
        write!(f, "{text}; effect status unknown")
    }
}

/// The failure half of a typed authority call.
///
/// Splitting refusal from ambiguity at the type level is the point: a caller
/// that wants to conclude "nothing happened" must inspect the variant, and the
/// only variant that licenses that conclusion is [`Self::Refused`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityFailure {
    /// The store definitely applied no effect.
    Refused(AuthorityRefusal),
    /// The effect status is unknown.
    Ambiguous(AmbiguityReason),
}

impl AuthorityFailure {
    /// Whether the caller may conclude that no effect occurred.
    #[must_use]
    pub const fn proves_no_effect(self) -> bool {
        matches!(self, Self::Refused(_))
    }

    /// The corresponding uniform response.
    #[must_use]
    pub const fn into_response(self) -> AuthorityResponse {
        match self {
            Self::Refused(refusal) => AuthorityResponse::Refused(refusal),
            Self::Ambiguous(reason) => AuthorityResponse::Ambiguous(reason),
        }
    }
}

impl core::fmt::Display for AuthorityFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Refused(refusal) => write!(f, "refused: {refusal}"),
            Self::Ambiguous(reason) => write!(f, "ambiguous: {reason}"),
        }
    }
}

impl std::error::Error for AuthorityFailure {}

impl From<KeyError> for AuthorityRefusal {
    fn from(error: KeyError) -> Self {
        Self::InvalidKey(error)
    }
}
