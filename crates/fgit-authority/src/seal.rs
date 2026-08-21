//! Transaction sealing and idempotency-key binding.
//!
//! A seal is durable identity, not a commit and not an ordering event
//! (`NORMATIVE_PROTOCOL_CONTRACTS.md` §5.2). Sealing answers one question — is
//! this attempt the same logical mutation as an earlier one — and answers it
//! with three typed outcomes: created, identical retry, or a pre-decision
//! rejection.
//!
//! # Why sealing alone cannot detect key reuse
//!
//! The transaction identity binds the canonical request digest, so replaying an
//! idempotency key against a *different* request already produces a *different*
//! identity and therefore a different seal. The aliasing the contract forbids
//! cannot happen. But nothing would notice, and §3.3 requires a typed
//! pre-decision rejection rather than silence.
//!
//! Noticing needs a second slot: a binding from
//! `(tenant, repository, principal, idempotency key digest)` to the one
//! transaction identity that key is already committed to. Put-if-absent against
//! that slot yields the three cases directly — absent is a first use, a
//! byte-identical body is a genuine retry, and a conflicting body is
//! `IdempotencyKeyReuse`, rejected before any seal exists and therefore leaving
//! no canonical trace (§5.1).
//!
//! The binding slot holds one canonically encoded identity rather than an
//! identity-bearing body. It is a pointer, not an object, so it has no
//! domain-separated identity of its own.

use fgit_codec::wire::{CanonicalBody, encode_body};
use fgit_codec::{CodecRefusal, DecodeLimits, Decoder, Encoder, TransactionSealBody, decode_body};
use fgit_crypto::IdentityDomain;
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::identity::{PrincipalId, RepositoryId, TenantId, TransactionSealId, TxId};
use fgit_types::vocabulary::RequestRejectionCode;

use crate::contract::AuthorityStore;
use crate::identity::{
    IdempotencyKey, IdentityRefusal, TxIdPreimage, canonical_body_id, derive_tx_id,
};
use crate::keys::{ImmutableKey, KeyError};
use crate::request::SemanticRequest;
use crate::vocabulary::{AuthorityFailure, ImmutableRead, PutOutcome};

/// Namespace prefix of a transaction seal slot.
pub const SEAL_KEY_PREFIX: &[u8] = b"fg/seal/v1/";
/// Namespace prefix of an idempotency-key binding slot.
pub const IDEMPOTENCY_BINDING_KEY_PREFIX: &[u8] = b"fg/idem/v1/";
/// Namespace prefix of an immutable body addressed by its own identity.
pub const BODY_KEY_PREFIX: &[u8] = b"fg/body/v1/";

/// A rejection that happens before any seal exists.
///
/// A pre-seal rejection is not repository history (§5.1). It carries the
/// closed request-rejection vocabulary, which is a different space from the
/// post-seal refusal vocabulary on purpose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestRejection {
    /// The idempotency key is already bound to a different transaction.
    IdempotencyKeyReuse {
        /// The identity the key is already committed to.
        bound: TxId,
        /// The identity this attempt derived.
        attempted: TxId,
    },
}

impl RequestRejection {
    /// The closed pre-seal rejection code.
    #[must_use]
    pub const fn code(&self) -> RequestRejectionCode {
        match *self {
            Self::IdempotencyKeyReuse { .. } => RequestRejectionCode::IdempotencyKeyReuse,
        }
    }
}

impl core::fmt::Display for RequestRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IdempotencyKeyReuse { .. } => f.write_str(
                "idempotency key already bound to a different canonical request; \
                 the two attempts must not alias",
            ),
        }
    }
}

impl std::error::Error for RequestRejection {}

/// Why sealing could not complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SealFailure {
    /// The request was rejected before a seal could exist.
    Rejected(RequestRejection),
    /// The store refused or could not answer.
    Store(AuthorityFailure),
    /// An identity could not be derived.
    Identity(IdentityRefusal),
    /// A canonical body could not be encoded or decoded.
    Codec(CodecRefusal),
    /// A derived slot key was not admissible.
    Key(KeyError),
    /// The stored body at a deterministic key is not the body that key names.
    ///
    /// This is an internal invariant breach, not a client error: the key is a
    /// function of the identity, so a mismatch means two different bodies share
    /// one identity or an encoder is not deterministic. It fails closed.
    SlotContentUnexpected {
        /// Which slot.
        slot: &'static str,
    },
}

impl core::fmt::Display for SealFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rejected(rejection) => write!(f, "{rejection}"),
            Self::Store(failure) => write!(f, "authority store: {failure}"),
            Self::Identity(refusal) => write!(f, "{refusal}"),
            Self::Codec(refusal) => write!(f, "canonical encoding refused: {refusal}"),
            Self::Key(error) => write!(f, "{error}"),
            Self::SlotContentUnexpected { slot } => {
                write!(f, "slot {slot} holds a body its key does not name")
            }
        }
    }
}

impl std::error::Error for SealFailure {}

impl From<AuthorityFailure> for SealFailure {
    fn from(failure: AuthorityFailure) -> Self {
        Self::Store(failure)
    }
}

impl From<IdentityRefusal> for SealFailure {
    fn from(refusal: IdentityRefusal) -> Self {
        Self::Identity(refusal)
    }
}

impl From<CodecRefusal> for SealFailure {
    fn from(refusal: CodecRefusal) -> Self {
        Self::Codec(refusal)
    }
}

impl From<KeyError> for SealFailure {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

/// The slot key of one immutable body, addressed by its own identity.
pub fn body_key<B: CanonicalBody>(
    domain: IdentityDomain,
    body: &B,
) -> Result<ImmutableKey, SealFailure> {
    let id = canonical_body_id(domain, CANONICAL_CODEC_VERSION, body)?;
    let mut bytes = Vec::with_capacity(BODY_KEY_PREFIX.len() + 80);
    bytes.extend_from_slice(BODY_KEY_PREFIX);
    bytes.extend_from_slice(id.domain().as_bytes());
    bytes.push(b'/');
    bytes.extend_from_slice(id.digest().as_bytes());
    Ok(ImmutableKey::new(bytes)?)
}

/// The deterministic seal slot key, scoped by tenant, repository, and identity.
pub fn seal_key(
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tx_id: TxId,
) -> Result<ImmutableKey, SealFailure> {
    let mut bytes = Vec::with_capacity(SEAL_KEY_PREFIX.len() + 96);
    bytes.extend_from_slice(SEAL_KEY_PREFIX);
    bytes.extend_from_slice(tenant_id.as_bytes());
    bytes.extend_from_slice(repository_id.as_bytes());
    bytes.extend_from_slice(tx_id.as_internal_object_id().digest().as_bytes());
    Ok(ImmutableKey::new(bytes)?)
}

/// The deterministic idempotency-binding slot key.
pub fn idempotency_binding_key(
    tenant_id: TenantId,
    repository_id: RepositoryId,
    principal_id: PrincipalId,
    idempotency_key: &IdempotencyKey,
) -> Result<ImmutableKey, SealFailure> {
    let mut bytes = Vec::with_capacity(IDEMPOTENCY_BINDING_KEY_PREFIX.len() + 112);
    bytes.extend_from_slice(IDEMPOTENCY_BINDING_KEY_PREFIX);
    bytes.extend_from_slice(tenant_id.as_bytes());
    bytes.extend_from_slice(repository_id.as_bytes());
    bytes.extend_from_slice(principal_id.as_bytes());
    bytes.extend_from_slice(idempotency_key.digest().bytes().as_bytes());
    Ok(ImmutableKey::new(bytes)?)
}

fn encode_tx_id(tx_id: TxId) -> Result<Vec<u8>, CodecRefusal> {
    let mut out = Encoder::new();
    out.write_internal_object_id(tx_id.as_internal_object_id())?;
    Ok(out.into_bytes())
}

fn decode_tx_id(bytes: &[u8]) -> Result<TxId, SealFailure> {
    let mut input = Decoder::new(bytes, DecodeLimits::DEFAULT);
    let id = input.read_internal_object_id()?;
    input.finish()?;
    TxId::from_internal_object_id(id).map_err(|_| SealFailure::SlotContentUnexpected {
        slot: "idempotency-binding",
    })
}

/// How an idempotency key resolved against its binding slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyBinding {
    /// First use of this key by this principal in this repository.
    Bound(TxId),
    /// The key is already bound to this same identity: a genuine retry.
    Retry(TxId),
}

impl KeyBinding {
    /// The identity the key is bound to, however it resolved.
    #[must_use]
    pub const fn tx_id(self) -> TxId {
        match self {
            Self::Bound(tx_id) | Self::Retry(tx_id) => tx_id,
        }
    }
}

/// How a seal resolved against its slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SealAdmission {
    /// The seal did not exist and now does.
    Created {
        /// Identity of the seal body.
        seal_id: TransactionSealId,
        /// The sealed logical mutation.
        tx_id: TxId,
    },
    /// The seal already existed with byte-identical stable fields.
    ///
    /// The retry continues against the existing seal; it does not regenerate
    /// admission receipts, which are separate records over the seal id.
    IdenticalRetry {
        /// Identity of the seal body.
        seal_id: TransactionSealId,
        /// The sealed logical mutation.
        tx_id: TxId,
    },
}

impl SealAdmission {
    /// The seal identity, however it resolved.
    #[must_use]
    pub const fn seal_id(&self) -> TransactionSealId {
        match *self {
            Self::Created { seal_id, .. } | Self::IdenticalRetry { seal_id, .. } => seal_id,
        }
    }

    /// The sealed logical mutation, however it resolved.
    #[must_use]
    pub const fn tx_id(&self) -> TxId {
        match *self {
            Self::Created { tx_id, .. } | Self::IdenticalRetry { tx_id, .. } => tx_id,
        }
    }

    /// Whether this attempt is the one that created the seal.
    #[must_use]
    pub const fn is_created(&self) -> bool {
        matches!(*self, Self::Created { .. })
    }
}

/// One attempt to seal a semantic request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealAttempt {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Target repository.
    pub repository_id: RepositoryId,
    /// Principal the gateway authenticated.
    pub authenticated_principal_id: PrincipalId,
    /// The client's idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// The canonicalized semantic request.
    pub request: SemanticRequest,
}

impl SealAttempt {
    /// The stable transaction identity and seal body this attempt derives.
    ///
    /// Deriving is pure: it touches no store and is therefore safe to repeat.
    pub fn derive(&self) -> Result<(TxId, TransactionSealBody), SealFailure> {
        let canonical_request_digest = crate::identity::canonical_request_digest(&self.request)?;
        let preimage = TxIdPreimage {
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            authenticated_principal_id: self.authenticated_principal_id,
            idempotency_key: self.idempotency_key.clone(),
            canonical_request_digest,
        };
        let tx_id = derive_tx_id(&preimage)?;
        let seal = TransactionSealBody {
            tx_id,
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            authenticated_principal_id: self.authenticated_principal_id,
            idempotency_key_digest: self.idempotency_key.digest(),
            canonical_request_digest,
            request_schema: self.request.request_schema(),
        };
        Ok((tx_id, seal))
    }
}

/// Bind an idempotency key to one transaction identity, or reject the reuse.
pub fn bind_idempotency_key<S>(
    store: &S,
    attempt: &SealAttempt,
    tx_id: TxId,
) -> Result<KeyBinding, SealFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = idempotency_binding_key(
        attempt.tenant_id,
        attempt.repository_id,
        attempt.authenticated_principal_id,
        &attempt.idempotency_key,
    )?;
    let body = encode_tx_id(tx_id)?;
    match store.put_if_absent(&key, &body)? {
        PutOutcome::Created => Ok(KeyBinding::Bound(tx_id)),
        PutOutcome::IdenticalRetry => Ok(KeyBinding::Retry(tx_id)),
        PutOutcome::Conflict => {
            let bound = match store.read_immutable(&key)? {
                ImmutableRead::Present(stored) => decode_tx_id(&stored)?,
                ImmutableRead::Absent => {
                    return Err(SealFailure::SlotContentUnexpected {
                        slot: "idempotency-binding",
                    });
                }
            };
            Err(SealFailure::Rejected(
                RequestRejection::IdempotencyKeyReuse {
                    bound,
                    attempted: tx_id,
                },
            ))
        }
    }
}

/// Bind the idempotency key and then conditionally create the seal.
///
/// The order matters: reuse is a pre-decision rejection, so it must be settled
/// before any seal exists.
pub fn seal_request<S>(store: &S, attempt: &SealAttempt) -> Result<SealAdmission, SealFailure>
where
    S: AuthorityStore + ?Sized,
{
    let (tx_id, seal) = attempt.derive()?;
    bind_idempotency_key(store, attempt, tx_id)?;
    admit_seal(store, &seal)
}

/// Conditionally create one seal body.
pub fn admit_seal<S>(store: &S, seal: &TransactionSealBody) -> Result<SealAdmission, SealFailure>
where
    S: AuthorityStore + ?Sized,
{
    let seal_id = TransactionSealId::from_internal_object_id(canonical_body_id(
        IdentityDomain::TransactionSeal,
        CANONICAL_CODEC_VERSION,
        seal,
    )?)
    .map_err(|_| SealFailure::SlotContentUnexpected { slot: "seal" })?;
    let key = seal_key(seal.tenant_id, seal.repository_id, seal.tx_id)?;
    let body = encode_body(seal)?;
    match store.put_if_absent(&key, &body)? {
        PutOutcome::Created => Ok(SealAdmission::Created {
            seal_id,
            tx_id: seal.tx_id,
        }),
        PutOutcome::IdenticalRetry => Ok(SealAdmission::IdenticalRetry {
            seal_id,
            tx_id: seal.tx_id,
        }),
        // The slot key is a function of the identity, and the identity is a
        // function of the body, so a different body here is an invariant
        // breach rather than a client-visible condition.
        PutOutcome::Conflict => Err(SealFailure::SlotContentUnexpected { slot: "seal" }),
    }
}

/// Read back one sealed transaction by exact key.
pub fn read_seal<S>(
    store: &S,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tx_id: TxId,
) -> Result<Option<TransactionSealBody>, SealFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = seal_key(tenant_id, repository_id, tx_id)?;
    match store.read_immutable(&key)? {
        ImmutableRead::Absent => Ok(None),
        ImmutableRead::Present(bytes) => {
            let seal: TransactionSealBody = decode_body(&bytes, DecodeLimits::DEFAULT)?;
            if seal.tx_id == tx_id {
                Ok(Some(seal))
            } else {
                Err(SealFailure::SlotContentUnexpected { slot: "seal" })
            }
        }
    }
}
