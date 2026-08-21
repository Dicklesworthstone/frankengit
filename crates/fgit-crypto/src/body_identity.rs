//! Domain-separated internal body identity.
//!
//! NORMATIVE_PROTOCOL_CONTRACTS section 3.2 fixes the construction:
//!
//! ```text
//! InternalObjectId = H(domain_tag || schema_id || canonical_body_bytes)
//! ```
//!
//! The contract does not say how the three fields are joined, and bare
//! concatenation would be ambiguous: `(domain "a", schema "bc")` and
//! `(domain "ab", schema "c")` would produce identical preimages, which
//! defeats the separation the construction exists to provide. This module
//! therefore realises `||` as explicit length-prefixed framing:
//!
//! ```text
//! u8      domain_tag length   (1..=64)
//! bytes   domain_tag ASCII
//! u8      schema_id length    (1..=128)
//! bytes   schema_id ASCII
//! u64be   canonical_body length
//! bytes   canonical_body
//! ```
//!
//! No additional construction label is prefixed. The domain tag *is* the
//! label, following the pattern the same document uses for `TxId`, whose
//! first field is the literal `"frankengit/ref-txn/v2"`. The canonical-codec
//! version is carried in the typed identity (plan section 11.3) but is not
//! hashed, because section 3.2 fixes the preimage to exactly three fields.
//!
//! Two identities produced in different domains over identical body bytes
//! therefore differ, and replaying one under the other's domain is a typed
//! [`InternalIdentityError`], not a silent `false`.

use core::fmt;

use fgit_types::{CodecVersion, DigestBytes, InternalObjectId, SchemaId};

use crate::hashing::sha256_digest;
use crate::registry::{IdentityDomain, InternalDigestAlgorithm};
use crate::native::GitObjectKind;

// The framing writes each label length in one byte. These assertions turn a
// future widening of the `fgit-types` bounds into a compile error here rather
// than a runtime panic in identity computation.
const _: () = assert!(fgit_types::MAX_DOMAIN_TAG_BYTES <= u8::MAX as usize);
const _: () = assert!(fgit_types::MAX_SCHEMA_ID_BYTES <= u8::MAX as usize);

/// Canonical schema label for the strong internal commitment over one native
/// Git object's framed bytes (plan section 11.6).
pub const GIT_PAYLOAD_SCHEMA: &str = "frankengit.git-payload-commitment.v1";

/// Mismatch discovered while verifying an internal body identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InternalIdentityError {
    /// The identity was produced in a different domain. This is the typed
    /// cross-domain replay refusal.
    DomainMismatch {
        /// Domain the verifier required.
        expected: &'static str,
        /// Domain the identity carries.
        actual: String,
    },
    /// The identity was produced under a different schema.
    SchemaMismatch {
        /// Schema the verifier required.
        expected: String,
        /// Schema the identity carries.
        actual: String,
    },
    /// The identity was produced under a different canonical-codec version.
    CodecVersionMismatch {
        /// Version the verifier required.
        expected: CodecVersion,
        /// Version the identity carries.
        actual: CodecVersion,
    },
    /// The identity's digest does not commit to the supplied body.
    DigestMismatch {
        /// Domain under which the digest was recomputed.
        domain: &'static str,
        /// Digest recomputed from the supplied inputs.
        expected: String,
        /// Digest the identity carries.
        actual: String,
    },
}

impl fmt::Display for InternalIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DomainMismatch { expected, actual } => write!(
                formatter,
                "internal identity domain mismatch: expected `{expected}`, found `{actual}`"
            ),
            Self::SchemaMismatch { expected, actual } => write!(
                formatter,
                "internal identity schema mismatch: expected `{expected}`, found `{actual}`"
            ),
            Self::CodecVersionMismatch { expected, actual } => write!(
                formatter,
                "internal identity codec version mismatch: expected {}.{}, found {}.{}",
                expected.major(),
                expected.minor(),
                actual.major(),
                actual.minor()
            ),
            Self::DigestMismatch {
                domain,
                expected,
                actual,
            } => write!(
                formatter,
                "internal identity digest mismatch in domain `{domain}`: expected {expected}, found {actual}"
            ),
        }
    }
}

impl std::error::Error for InternalIdentityError {}

/// Build the exact digest preimage for one internal body identity.
///
/// Exported so an independent verifier can reproduce the construction without
/// re-deriving the framing from prose.
#[must_use]
pub fn internal_id_preimage(
    domain: IdentityDomain,
    schema: &SchemaId,
    canonical_body: &[u8],
) -> Vec<u8> {
    let tag = domain.tag().as_bytes();
    let schema_bytes = schema.as_str().as_bytes();
    let body_len = u64::try_from(canonical_body.len())
        .expect("a slice length always fits in u64 on supported targets");

    let mut preimage = Vec::with_capacity(1 + tag.len() + 1 + schema_bytes.len() + 8 + canonical_body.len());
    preimage.push(
        u8::try_from(tag.len()).expect("a registered domain tag is at most 64 bytes"),
    );
    preimage.extend_from_slice(tag);
    preimage.push(
        u8::try_from(schema_bytes.len()).expect("a SchemaId is at most 128 bytes"),
    );
    preimage.extend_from_slice(schema_bytes);
    preimage.extend_from_slice(&body_len.to_be_bytes());
    preimage.extend_from_slice(canonical_body);
    preimage
}

/// Digest the preimage under the domain's internal algorithm.
#[must_use]
pub fn internal_id_digest(domain: IdentityDomain, preimage: &[u8]) -> Vec<u8> {
    match domain.algorithm() {
        InternalDigestAlgorithm::Sha256 => sha256_digest(preimage).to_vec(),
    }
}

/// Compute the domain-separated identity of one canonical body.
///
/// There is no overload that omits the domain: the closed [`IdentityDomain`]
/// enumeration is a required argument, and the tag it names is committed into
/// the digest.
#[must_use]
pub fn internal_object_id(
    domain: IdentityDomain,
    schema: &SchemaId,
    codec_version: CodecVersion,
    canonical_body: &[u8],
) -> InternalObjectId {
    let preimage = internal_id_preimage(domain, schema, canonical_body);
    let digest = internal_id_digest(domain, &preimage);
    InternalObjectId::new(
        domain.domain_tag(),
        schema.clone(),
        codec_version,
        DigestBytes::new(digest).expect("an internal digest is within the scalar bound"),
    )
}

/// Verify that an identity commits to exactly these inputs.
///
/// This is the checked path. The `fgit-types` shell can hold any digest bytes
/// with any domain tag, so a body that arrives with an attached identity is
/// only trustworthy once this function has agreed with it.
pub fn verify_internal_object_id(
    identity: &InternalObjectId,
    domain: IdentityDomain,
    schema: &SchemaId,
    codec_version: CodecVersion,
    canonical_body: &[u8],
) -> Result<(), InternalIdentityError> {
    if identity.domain().as_str() != domain.tag() {
        return Err(InternalIdentityError::DomainMismatch {
            expected: domain.tag(),
            actual: identity.domain().as_str().to_owned(),
        });
    }
    if identity.schema().as_str() != schema.as_str() {
        return Err(InternalIdentityError::SchemaMismatch {
            expected: schema.as_str().to_owned(),
            actual: identity.schema().as_str().to_owned(),
        });
    }
    if identity.codec_version() != codec_version {
        return Err(InternalIdentityError::CodecVersionMismatch {
            expected: codec_version,
            actual: identity.codec_version(),
        });
    }
    let preimage = internal_id_preimage(domain, schema, canonical_body);
    let digest = internal_id_digest(domain, &preimage);
    if identity.digest().as_bytes() == digest.as_slice() {
        Ok(())
    } else {
        Err(InternalIdentityError::DigestMismatch {
            domain: domain.tag(),
            expected: lowercase_hex(&digest),
            actual: lowercase_hex(identity.digest().as_bytes()),
        })
    }
}

/// The strong internal payload commitment for one native Git object.
///
/// Plan section 11.6 requires SHA-1 repositories to bind object type, length,
/// and exact bytes to an independent stronger digest alongside the visible
/// native identity. The canonical body here is precisely Git's framed object
/// preimage, so the commitment covers all three without depending on the
/// canonical codec.
///
/// This adds independent evidence. It does not replace, translate, or upgrade
/// the native identity, and it never touches historical signature semantics.
#[must_use]
pub fn git_payload_commitment(
    kind: GitObjectKind,
    content: &[u8],
    codec_version: CodecVersion,
) -> InternalObjectId {
    let schema = git_payload_schema();
    let body = git_payload_body(kind, content);
    internal_object_id(
        IdentityDomain::GitPayloadCommitment,
        &schema,
        codec_version,
        &body,
    )
}

/// The canonical body the payload commitment digests: Git's framed object.
#[must_use]
pub fn git_payload_body(kind: GitObjectKind, content: &[u8]) -> Vec<u8> {
    let decimal = content.len().to_string();
    let mut body = Vec::with_capacity(kind.label().len() + decimal.len() + 2 + content.len());
    body.extend_from_slice(kind.label().as_bytes());
    body.push(b' ');
    body.extend_from_slice(decimal.as_bytes());
    body.push(0);
    body.extend_from_slice(content);
    body
}

/// The schema label used by [`git_payload_commitment`].
#[must_use]
pub fn git_payload_schema() -> SchemaId {
    SchemaId::new(GIT_PAYLOAD_SCHEMA).expect("the payload commitment schema label is canonical")
}

pub(crate) fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}
