//! Typed identities.
//!
//! Three shapes appear here and they are not interchangeable.
//!
//! * **Opaque identities** ([`TenantId`], [`RepositoryId`], [`PrincipalId`],
//!   [`RepositoryIncarnationId`], [`RequestId`]) are assigned, not derived.
//!   They are 128-bit values that stay stable across renames, which is why a
//!   human-readable owner or repository name is never an identity.
//! * **Derived identities** ([`TxId`], [`RepositoryCommitId`], and the rest)
//!   wrap an [`InternalObjectId`] and pin one domain separation tag. A derived
//!   identity refuses to be built from a digest that belongs to another
//!   schema, so a decision-batch identity can never be presented as a
//!   transaction identity.
//! * **Backend tokens** ([`AuthorityVersionToken`]) are opaque store state.
//!   They are excluded from canonical body bytes: a token is evidence for a
//!   conditional write, never part of an identity.
//!
//! The internal-identity rule is that a body's identity is the digest over its
//! domain separation tag, its schema identifier, and its canonical body bytes;
//! `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` section 3.2 states the formula and
//! section 3.3 states the single normative transaction-identity derivation.
//! This crate carries the resulting values and refuses cross-domain
//! substitution; it does not compute digests.

use core::fmt;

use crate::error::TypeRefusal;
use crate::hash::{DigestAlgorithmId, DigestBytes};
use crate::label::{AsciiSlug, DomainTag};
use crate::numeric::CodecVersion;

/// Length of an opaque assigned identity, in bytes.
pub const OPAQUE_ID_LEN: usize = 16;

/// Largest accepted authority version token, in bytes.
pub const MAX_AUTHORITY_VERSION_TOKEN_LEN: usize = 512;

/// Declares a 128-bit opaque assigned identity.
macro_rules! opaque_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        ///
        /// The value is assigned, never derived from content, and stable
        /// across renames.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; OPAQUE_ID_LEN]);

        impl $name {
            /// Wraps raw identity bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; OPAQUE_ID_LEN]) -> Self {
                Self(bytes)
            }

            /// Parses the canonical lowercase hexadecimal form.
            pub fn from_hex(text: &str) -> Result<Self, TypeRefusal> {
                let source = text.as_bytes();
                if source.len() != OPAQUE_ID_LEN * 2 {
                    return Err(TypeRefusal::LengthOutOfRange {
                        field: stringify!($name),
                        observed: u32::try_from(source.len()).unwrap_or(u32::MAX),
                        minimum: 32,
                        maximum: 32,
                    });
                }
                let mut bytes = [0_u8; OPAQUE_ID_LEN];
                for (index, pair) in source.chunks_exact(2).enumerate() {
                    let high = nibble(stringify!($name), pair[0], index * 2)?;
                    let low = nibble(stringify!($name), pair[1], index * 2 + 1)?;
                    bytes[index] = (high << 4) | low;
                }
                Ok(Self(bytes))
            }

            /// The raw identity bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; OPAQUE_ID_LEN] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in &self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

/// Decodes one lowercase hexadecimal digit.
fn nibble(field: &'static str, byte: u8, offset: usize) -> Result<u8, TypeRefusal> {
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

opaque_id!(TenantId, "Identity of one tenant.");
opaque_id!(
    RepositoryId,
    "Identity of one repository within one tenant."
);
opaque_id!(
    RepositoryIncarnationId,
    "Identity of one repository incarnation. Deleting and recreating a repository under the same owner and name produces a new incarnation, so stale refs, tokens, caches, and location records cannot revive the prior repository."
);
opaque_id!(PrincipalId, "Identity of one authenticated principal.");
opaque_id!(
    RequestId,
    "Identity of one network attempt. Tracing only: a request identity carries no idempotency authority and never decides a retry."
);

/// The identity of one immutable internal body.
///
/// The value carries four components: the digest algorithm code point, the
/// domain separation tag of the schema, the canonical codec version the body
/// was encoded with, and the digest bytes. Carrying the codec version inside
/// the identity is what lets a future encoding land without a body's identity
/// silently changing meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InternalObjectId {
    algorithm: DigestAlgorithmId,
    domain: DomainTag,
    codec_version: CodecVersion,
    digest: DigestBytes,
}

impl InternalObjectId {
    /// Builds an internal identity from its four components.
    #[must_use]
    pub const fn new(
        algorithm: DigestAlgorithmId,
        domain: DomainTag,
        codec_version: CodecVersion,
        digest: DigestBytes,
    ) -> Self {
        Self {
            algorithm,
            domain,
            codec_version,
            digest,
        }
    }

    /// The digest algorithm code point.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithmId {
        self.algorithm
    }

    /// The domain separation tag of the schema that produced this body.
    #[must_use]
    pub const fn domain(&self) -> DomainTag {
        self.domain
    }

    /// The canonical codec version the body was encoded with.
    #[must_use]
    pub const fn codec_version(&self) -> CodecVersion {
        self.codec_version
    }

    /// The digest bytes.
    #[must_use]
    pub const fn digest(&self) -> &DigestBytes {
        &self.digest
    }
}

impl fmt::Display for InternalObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}/{}/{}/{}",
            self.domain, self.codec_version, self.algorithm, self.digest
        )
    }
}

/// Declares a domain-pinned derived identity over an [`InternalObjectId`].
macro_rules! derived_id {
    ($name:ident, $domain:literal, $doc:literal) => {
        #[doc = $doc]
        ///
        /// The identity is the digest of one immutable body under the domain
        #[doc = concat!("separation tag `", $domain, "`.")]
        /// Building one from a digest in another domain is a typed refusal.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(InternalObjectId);

        impl $name {
            /// Domain separation tag this identity pins.
            pub const DOMAIN: &'static str = $domain;
            /// Domain separation tag this identity pins, as a value.
            pub const DOMAIN_TAG: DomainTag = DomainTag::from_static($domain);

            /// Stamps the pinned domain onto a freshly computed digest.
            #[must_use]
            pub const fn from_digest(
                algorithm: DigestAlgorithmId,
                codec_version: CodecVersion,
                digest: DigestBytes,
            ) -> Self {
                Self(InternalObjectId::new(
                    algorithm,
                    Self::DOMAIN_TAG,
                    codec_version,
                    digest,
                ))
            }

            /// Adopts an existing internal identity, refusing one whose
            /// domain belongs to another schema.
            pub fn from_internal_object_id(id: InternalObjectId) -> Result<Self, TypeRefusal> {
                if id.domain() == Self::DOMAIN_TAG {
                    Ok(Self(id))
                } else {
                    Err(TypeRefusal::DomainMismatch {
                        field: stringify!($name),
                        expected: $domain,
                    })
                }
            }

            /// The underlying internal identity.
            #[must_use]
            pub const fn as_internal_object_id(&self) -> &InternalObjectId {
                &self.0
            }

            /// Unwraps to the underlying internal identity.
            #[must_use]
            pub const fn into_internal_object_id(self) -> InternalObjectId {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }
    };
}

derived_id!(
    TxId,
    "frankengit/ref-txn/v2",
    "Identity of one sealed logical mutation."
);
derived_id!(
    TransactionSealId,
    "frankengit/txn-seal/v1",
    "Identity of one transaction seal body."
);
derived_id!(
    PreparedTxnCapsuleId,
    "frankengit/prepared-capsule/v1",
    "Identity of one prepared transaction capsule."
);
derived_id!(
    RepositoryCommitId,
    "frankengit/rcr/v1",
    "Identity of one Repository Commit Record."
);
derived_id!(
    RepositoryDecisionBatchId,
    "frankengit/decision-batch/v1",
    "Identity of one repository decision batch body."
);
derived_id!(
    RepositoryAuthorityHeadId,
    "frankengit/authority-head/v1",
    "Identity of one repository authority head body."
);
derived_id!(
    RefusalRecordId,
    "frankengit/refusal-record/v1",
    "Identity of one immutable refusal record."
);
derived_id!(
    RepositoryCapsuleId,
    "frankengit/repository-capsule/v1",
    "Identity of one repository checkpoint capsule."
);
derived_id!(
    PrincipalSnapshotId,
    "frankengit/principal-snapshot/v1",
    "Identity of one immutable principal and capability snapshot."
);
derived_id!(
    ObjectEnvelopeId,
    "frankengit/object-envelope/v1",
    "Identity of one internal object envelope."
);
derived_id!(
    SegmentManifestId,
    "frankengit/segment-manifest/v1",
    "Identity of one object-fabric segment manifest."
);
derived_id!(
    ForgeEventId,
    "frankengit/forge-event/v1",
    "Identity of one canonical forge event body."
);
derived_id!(
    EvidenceRecordId,
    "frankengit/evidence-record/v1",
    "Identity of one immutable evidence record."
);
derived_id!(
    GenerationId,
    "frankengit/generation/v1",
    "Identity of one immutable search, graph, policy, or workspace generation."
);

/// Every domain separation tag this crate pins to a derived identity.
///
/// The list exists so a test can prove the tags are unique: two schemas
/// sharing a tag would let one body's digest be read as the other's identity.
pub const DERIVED_ID_DOMAINS: &[&str] = &[
    TxId::DOMAIN,
    TransactionSealId::DOMAIN,
    PreparedTxnCapsuleId::DOMAIN,
    RepositoryCommitId::DOMAIN,
    RepositoryDecisionBatchId::DOMAIN,
    RepositoryAuthorityHeadId::DOMAIN,
    RefusalRecordId::DOMAIN,
    RepositoryCapsuleId::DOMAIN,
    PrincipalSnapshotId::DOMAIN,
    ObjectEnvelopeId::DOMAIN,
    SegmentManifestId::DOMAIN,
    ForgeEventId::DOMAIN,
    EvidenceRecordId::DOMAIN,
    GenerationId::DOMAIN,
];

/// An opaque backend conditional-write token.
///
/// The token is obtained from a previously authenticated head read and is
/// presented back to the store to make a replacement conditional. It is
/// explicitly not part of any canonical body: identity must not change when a
/// backend reissues a token, and a token must not be replayable as evidence of
/// state. Protection against reuse of a recycled token comes from the head's
/// monotone generation and predecessor checks, not from the token itself.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AuthorityVersionToken(Vec<u8>);

impl AuthorityVersionToken {
    /// Builds a token, refusing an empty or oversized value.
    pub fn try_new(source: &[u8]) -> Result<Self, TypeRefusal> {
        if source.is_empty() || source.len() > MAX_AUTHORITY_VERSION_TOKEN_LEN {
            return Err(TypeRefusal::LengthOutOfRange {
                field: "AuthorityVersionToken",
                observed: u32::try_from(source.len()).unwrap_or(u32::MAX),
                minimum: 1,
                maximum: 512,
            });
        }
        Ok(Self(source.to_vec()))
    }

    /// The opaque token bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Token length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: a token is never empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Display for AuthorityVersionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Name of one preparation profile.
///
/// A profile selects the validation, witness, and evidence configuration a
/// prepared capsule was produced under, so two capsules built by different
/// profiles are never compared as equivalent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PreparationProfileId(AsciiSlug);

impl PreparationProfileId {
    /// Builds a profile name in a `const` context.
    #[must_use]
    pub const fn from_static(source: &'static str) -> Self {
        Self(AsciiSlug::from_static(source))
    }

    /// Builds a profile name from runtime bytes.
    pub fn try_new(source: &[u8]) -> Result<Self, TypeRefusal> {
        AsciiSlug::try_new("PreparationProfileId", source).map(Self)
    }

    /// The profile name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The profile name bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for PreparationProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}
