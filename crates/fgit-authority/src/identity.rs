//! Stable transaction identity.
//!
//! There is exactly one normative derivation of the logical mutation identity,
//! and it lives in `NORMATIVE_PROTOCOL_CONTRACTS.md` §3.3. This module
//! implements that derivation; it deliberately does not restate the formula in
//! prose anywhere, because a second copy of a normative formula is a second
//! formula.
//!
//! The domain separator the contract names is not written out here either: it
//! is committed by `fgit-crypto`'s preimage header, which binds the registered
//! domain tag, the schema family, the schema version, and the body length
//! before any body bytes. The remaining inputs are canonically encoded by
//! [`TxIdPreimage`], so the derivation is exactly one canonical encoding
//! followed by exactly one domain-separated digest.
//!
//! # Body identity
//!
//! [`canonical_body_id`] is a thin call into `fgit_codec::body_id` with the
//! workspace's single production `BodyIdentity`. It used to be a local bridge,
//! written when no production implementation existed and the only one in the
//! tree was test support. `fgit-codec` now owns that seam — it is the one crate
//! that can see both the encoder and the digest — so keeping a second
//! implementation here would be two implementations of one contract.
//!
//! The local version guarded against labelling one body's bytes with another
//! body's domain. That guard is no longer needed rather than merely dropped:
//! `body_id` takes the domain from `B::DOMAIN` instead of from the caller, so
//! the mismatch it defended against is now unrepresentable.

use fgit_codec::wire::{CanonicalBody, canonical_body_bytes};
use fgit_codec::{CodecRefusal, CryptoBodyIdentity, Decoder, Encoder, body_id};
use fgit_crypto::{IdentityDomain, internal_digest_value};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::Digest;
use fgit_types::identity::{InternalObjectId, PrincipalId, RepositoryId, TenantId, TxId};
use fgit_types::label::{DomainTag, SchemaFamily, SchemaId};
use fgit_types::numeric::CodecVersion;

use crate::request::{RequestRefusal, SemanticRequest};

/// Largest idempotency key a client may supply, in bytes.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

/// Why an identity could not be derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityRefusal {
    /// The caller named a domain that is not the body's own domain.
    ///
    /// Labelling one schema's bytes with another schema's domain is how two
    /// bodies end up sharing an identity, so it is refused rather than trusted.
    DomainMismatch {
        /// The domain the body declares.
        expected: DomainTag,
        /// The domain the caller supplied.
        observed: DomainTag,
    },
    /// The idempotency key exceeds its declared bound.
    IdempotencyKeyTooLong {
        /// Length supplied.
        observed: usize,
        /// The bound.
        limit: usize,
    },
    /// The canonical encoder refused.
    Codec(CodecRefusal),
    /// The semantic request was not admissible.
    Request(RequestRefusal),
}

impl core::fmt::Display for IdentityRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DomainMismatch { expected, observed } => write!(
                f,
                "body declares domain {} but the caller named {}",
                expected.as_str(),
                observed.as_str()
            ),
            Self::IdempotencyKeyTooLong { observed, limit } => write!(
                f,
                "idempotency key of {observed} bytes exceeds the bound of {limit}"
            ),
            Self::Codec(refusal) => write!(f, "canonical encoding refused: {refusal}"),
            Self::Request(refusal) => write!(f, "semantic request refused: {refusal}"),
        }
    }
}

impl std::error::Error for IdentityRefusal {}

impl From<CodecRefusal> for IdentityRefusal {
    fn from(refusal: CodecRefusal) -> Self {
        Self::Codec(refusal)
    }
}

impl From<RequestRefusal> for IdentityRefusal {
    fn from(refusal: RequestRefusal) -> Self {
        Self::Request(refusal)
    }
}

/// A client-supplied idempotency key, bounded but otherwise uninterpreted.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdempotencyKey(Vec<u8>);

impl IdempotencyKey {
    /// Accept a key within its declared bound.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, IdentityRefusal> {
        let bytes = bytes.into();
        if bytes.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(IdentityRefusal::IdempotencyKeyTooLong {
                observed: bytes.len(),
                limit: MAX_IDEMPOTENCY_KEY_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    /// The exact key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The digest the seal body records in place of the raw key.
    ///
    /// The transaction identity binds the raw key, exactly as the contract
    /// states; the seal body stores this digest instead, so a stored seal does
    /// not carry a client secret in the clear.
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::new(
            IdentityDomain::RefTransaction.algorithm().id(),
            internal_digest_value(
                IdentityDomain::RefTransaction,
                idempotency_key_schema(),
                &self.0,
            ),
        )
    }
}

fn idempotency_key_schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("idempotency-key"), 1, 0)
}

/// The identity of one canonical body.
///
/// The `domain` argument is retained for call-site legibility and is checked
/// against the body's own domain, but it no longer selects anything: the
/// identity is computed by `fgit_codec::body_id`, which reads the domain from
/// `B::DOMAIN`. A caller naming the wrong domain is refused rather than
/// silently ignored, so the argument cannot become a lie.
pub fn canonical_body_id<B: CanonicalBody>(
    domain: IdentityDomain,
    codec_version: CodecVersion,
    body: &B,
) -> Result<InternalObjectId, IdentityRefusal> {
    if domain.domain_tag() != B::DOMAIN {
        return Err(IdentityRefusal::DomainMismatch {
            expected: B::DOMAIN,
            observed: domain.domain_tag(),
        });
    }
    debug_assert_eq!(
        codec_version,
        fgit_types::CANONICAL_CODEC_VERSION,
        "the shared bridge stamps the canonical codec version"
    );
    Ok(body_id(&CryptoBodyIdentity, body)?)
}

/// The digest binding every client-visible semantic field of one request.
pub fn canonical_request_digest(request: &SemanticRequest) -> Result<Digest, IdentityRefusal> {
    let payload = canonical_body_bytes(request)?;
    Ok(Digest::new(
        IdentityDomain::RefTransaction.algorithm().id(),
        internal_digest_value(
            IdentityDomain::RefTransaction,
            SemanticRequest::schema_id(),
            &payload,
        ),
    ))
}

/// The exact inputs `NORMATIVE_PROTOCOL_CONTRACTS.md` §3.3 names, in its order.
///
/// This body is hashed, never stored: it exists so the derivation reuses the
/// one canonical encoder rather than concatenating fields by hand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxIdPreimage {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Target repository.
    pub repository_id: RepositoryId,
    /// Principal the gateway authenticated.
    pub authenticated_principal_id: PrincipalId,
    /// The raw client idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// The digest of the canonical semantic request.
    pub canonical_request_digest: Digest,
}

impl CanonicalBody for TxIdPreimage {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/ref-txn/v2");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("ref-txn");
    const SCHEMA_MAJOR: u16 = 2;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.tenant_id.as_bytes());
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_opaque_id(self.authenticated_principal_id.as_bytes());
        out.write_bytes("idempotency_key", self.idempotency_key.as_bytes())?;
        out.write_digest(&self.canonical_request_digest)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let tenant_id = TenantId::from_bytes(input.read_opaque_id("tenant_id")?);
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let authenticated_principal_id =
            PrincipalId::from_bytes(input.read_opaque_id("authenticated_principal_id")?);
        let key_bytes = input.read_bytes("idempotency_key")?.to_vec();
        let idempotency_key = IdempotencyKey(key_bytes);
        let canonical_request_digest = input.read_digest()?;
        Ok(Self {
            tenant_id,
            repository_id,
            authenticated_principal_id,
            idempotency_key,
            canonical_request_digest,
        })
    }
}

/// Derive the one stable transaction identity.
///
/// See `NORMATIVE_PROTOCOL_CONTRACTS.md` §3.3 for the normative derivation this
/// implements.
pub fn derive_tx_id(preimage: &TxIdPreimage) -> Result<TxId, IdentityRefusal> {
    let id = canonical_body_id(
        IdentityDomain::RefTransaction,
        CANONICAL_CODEC_VERSION,
        preimage,
    )?;
    TxId::from_internal_object_id(id).map_err(|refusal| IdentityRefusal::Codec(refusal.into()))
}
