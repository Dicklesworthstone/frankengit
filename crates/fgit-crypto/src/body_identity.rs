//! Domain-separated internal body identity.
//!
//! `NORMATIVE_PROTOCOL_CONTRACTS.md` section 3.2 fixes the construction:
//!
//! ```text
//! InternalObjectId = H(domain_tag || schema_id || canonical_body_bytes)
//! ```
//!
//! The contract does not say how the three fields are joined, and bare
//! concatenation would be ambiguous: domain `a` with schema `bc` and domain
//! `ab` with schema `c` would produce identical preimages, defeating the
//! separation the construction exists to provide. This module realises `||` as
//! explicit length-prefixed framing, with the schema identifier serialised
//! from the three components `fgit-types` gives it:
//!
//! ```text
//! u8      domain tag length        (1..=64)
//! bytes   domain tag
//! u8      schema family length     (1..=64)
//! bytes   schema family
//! u16be   schema major version
//! u16be   schema minor version
//! u64be   canonical body length
//! bytes   canonical body
//! ```
//!
//! No extra construction label is prefixed. The domain tag *is* the label,
//! following the pattern the same document uses for `TxId`, whose first field
//! is the literal `"frankengit/ref-txn/v2"` — which is also the domain tag
//! `fgit-types` pins on `TxId`. The canonical-codec version is carried in the
//! identity (plan section 11.3) but is not hashed, because section 3.2 fixes
//! the preimage to exactly those three fields.
//!
//! Cross-domain replay is therefore a typed [`InternalIdentityError`] rather
//! than a silent `false`: identical body bytes in two domains produce
//! different digests, and an identity presented under the wrong domain is
//! refused before its digest is even recomputed.

use core::fmt;

use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::identity::InternalObjectId;
use fgit_types::label::{DomainTag, SchemaFamily, SchemaId};
use fgit_types::numeric::CodecVersion;

use crate::hashing::sha256_digest;
use crate::native::GitObjectKind;
use crate::registry::{DigestAlgorithm, IdentityDomain, InternalDigestAlgorithm};

// The framing writes each label length in one byte. This assertion turns a
// future widening of the `fgit-types` label bound into a compile error here
// rather than a runtime panic inside identity computation.
const _: () = assert!(fgit_types::label::MAX_LABEL_LEN <= u8::MAX as usize);

/// Canonical schema family for the strong internal commitment over one native
/// Git object's framed bytes (plan section 11.6).
pub const GIT_PAYLOAD_SCHEMA_FAMILY: &str = "frankengit.git-payload-commitment";

/// The schema identifier used by [`git_payload_commitment`].
pub const GIT_PAYLOAD_SCHEMA: SchemaId =
    SchemaId::new(SchemaFamily::from_static(GIT_PAYLOAD_SCHEMA_FAMILY), 1, 0);

/// Mismatch discovered while verifying an internal body identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InternalIdentityError {
    /// The identity names a different digest construction.
    AlgorithmMismatch {
        /// Construction the domain requires.
        expected: DigestAlgorithm,
        /// Code point the identity carries.
        actual: u16,
    },
    /// The identity was produced in a different domain. This is the typed
    /// cross-domain replay refusal.
    DomainMismatch {
        /// Domain the verifier required.
        expected: &'static str,
        /// Domain the identity carries.
        actual: String,
    },
    /// The identity was produced under a different canonical-codec version.
    CodecVersionMismatch {
        /// Version the verifier required.
        expected: CodecVersion,
        /// Version the identity carries.
        actual: CodecVersion,
    },
    /// The identity's digest does not commit to the supplied schema and body.
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
            Self::AlgorithmMismatch { expected, actual } => write!(
                formatter,
                "internal identity algorithm mismatch: expected `{expected}` (code point {}), found code point {actual}",
                expected.code_point()
            ),
            Self::DomainMismatch { expected, actual } => write!(
                formatter,
                "internal identity domain mismatch: expected `{expected}`, found `{actual}`"
            ),
            Self::CodecVersionMismatch { expected, actual } => write!(
                formatter,
                "internal identity codec version mismatch: expected {expected}, found {actual}"
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
/// Exported so FG-002c's independent verifier can reproduce the construction
/// from data rather than re-deriving the framing from prose.
#[must_use]
pub fn internal_id_preimage(
    domain: IdentityDomain,
    schema: SchemaId,
    canonical_body: &[u8],
) -> Vec<u8> {
    let tag = domain.tag().as_bytes();
    let family = schema.family();
    let family_bytes = family.as_bytes();
    let body_len = u64::try_from(canonical_body.len())
        .expect("a slice length always fits in u64 on supported targets");

    let mut preimage =
        Vec::with_capacity(2 + tag.len() + family_bytes.len() + 4 + 8 + canonical_body.len());
    preimage.push(u8::try_from(tag.len()).expect("a registered domain tag fits the label bound"));
    preimage.extend_from_slice(tag);
    preimage.push(u8::try_from(family_bytes.len()).expect("a schema family fits the label bound"));
    preimage.extend_from_slice(family_bytes);
    preimage.extend_from_slice(&schema.major().to_be_bytes());
    preimage.extend_from_slice(&schema.minor().to_be_bytes());
    preimage.extend_from_slice(&body_len.to_be_bytes());
    preimage.extend_from_slice(canonical_body);
    preimage
}

/// Digest a preimage under one internal construction.
#[must_use]
pub fn internal_digest(algorithm: InternalDigestAlgorithm, preimage: &[u8]) -> Vec<u8> {
    match algorithm {
        InternalDigestAlgorithm::Sha256 => sha256_digest(preimage).to_vec(),
    }
}

/// Compute the domain-separated identity of one canonical body.
///
/// There is no overload that omits the domain: the closed [`IdentityDomain`]
/// enumeration is a required argument, its tag is committed into the digest,
/// and the tag is stamped onto the resulting identity.
#[must_use]
pub fn internal_object_id(
    domain: IdentityDomain,
    schema: SchemaId,
    codec_version: CodecVersion,
    canonical_body: &[u8],
) -> InternalObjectId {
    let preimage = internal_id_preimage(domain, schema, canonical_body);
    let digest = internal_digest(domain.algorithm(), &preimage);
    InternalObjectId::new(
        domain.algorithm().id(),
        domain.domain_tag(),
        codec_version,
        DigestBytes::try_new(&digest).expect("an internal digest is within the shell bound"),
    )
}

/// Verify that an identity commits to exactly these inputs.
///
/// This is the checked path. The `fgit-types` shell can hold any digest bytes
/// under any domain tag, so a body that arrives with an attached identity is
/// trustworthy only once this function has agreed with it.
pub fn verify_internal_object_id(
    identity: &InternalObjectId,
    domain: IdentityDomain,
    schema: SchemaId,
    codec_version: CodecVersion,
    canonical_body: &[u8],
) -> Result<(), InternalIdentityError> {
    let expected_algorithm = domain.algorithm().digest_algorithm();
    if identity.algorithm() != domain.algorithm().id() {
        return Err(InternalIdentityError::AlgorithmMismatch {
            expected: expected_algorithm,
            actual: identity.algorithm().code_point(),
        });
    }
    if identity.domain() != domain.domain_tag() {
        return Err(InternalIdentityError::DomainMismatch {
            expected: domain.tag(),
            actual: identity.domain().as_str().to_owned(),
        });
    }
    if identity.codec_version() != codec_version {
        return Err(InternalIdentityError::CodecVersionMismatch {
            expected: codec_version,
            actual: identity.codec_version(),
        });
    }
    let preimage = internal_id_preimage(domain, schema, canonical_body);
    let digest = internal_digest(domain.algorithm(), &preimage);
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

/// The identity a body would have in `domain`, ignoring any identity already
/// attached to it.
///
/// Useful to a verifier that wants to compare two candidate domains without
/// constructing a shell for each.
#[must_use]
pub fn internal_digest_in_domain(
    domain: IdentityDomain,
    schema: SchemaId,
    canonical_body: &[u8],
) -> Vec<u8> {
    let preimage = internal_id_preimage(domain, schema, canonical_body);
    internal_digest(domain.algorithm(), &preimage)
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
    let body = git_payload_body(kind, content);
    internal_object_id(
        IdentityDomain::GitPayloadCommitment,
        GIT_PAYLOAD_SCHEMA,
        codec_version,
        &body,
    )
}

/// The canonical body the payload commitment digests: Git's framed object.
#[must_use]
pub fn git_payload_body(kind: GitObjectKind, content: &[u8]) -> Vec<u8> {
    let length = u64::try_from(content.len())
        .expect("a slice length always fits in u64 on supported targets");
    let mut body = crate::native::object_header(kind, length);
    body.extend_from_slice(content);
    body
}

/// Lowercase hexadecimal, used in refusal messages and the golden corpus.
#[must_use]
pub fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// The digest algorithm code point an internal domain uses.
#[must_use]
pub fn internal_algorithm_id(domain: IdentityDomain) -> DigestAlgorithmId {
    domain.algorithm().id()
}

/// The domain tag a domain commits into its preimage, as the bounded label.
#[must_use]
pub const fn internal_domain_tag(domain: IdentityDomain) -> DomainTag {
    domain.domain_tag()
}
