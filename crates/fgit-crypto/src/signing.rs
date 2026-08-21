//! Detached signatures over domain-separated bodies.
//!
//! ADR-0003 draws the line at Git object identity: FrankenGit owns the hashes
//! that compute it and reuses every other primitive. Signatures are therefore
//! Ed25519 from `ed25519-dalek`, and this module is the boundary — it owns
//! what is signed, which key may sign it, and what a verifier is required to
//! decide for itself. It does not own the curve arithmetic.
//!
//! # What is signed is never the caller's bytes
//!
//! A signature over a raw body is replayable into any other context that
//! accepts a body. What this module signs is the domain-separated preimage of
//! an *envelope* that commits to the signer's purpose, epoch and key
//! commitment, and to the body's domain, schema and digest. A capsule
//! signature therefore cannot be presented as a release signature, and an
//! `Identity` key's signature cannot be presented as an `AuthorityAdmin`
//! one, because those facts are inside the signed bytes rather than beside
//! them.
//!
//! # A signature is evidence of authorship, never of trustworthiness
//!
//! Plan section 35.6 keeps those claims separate and so does this API. There
//! is no method that verifies a signature against the verifying key carried
//! in the same envelope, because that check proves only that the envelope is
//! internally consistent — which any forger can arrange. [`DetachedSignature`]
//! verifies only against a key the caller supplies from somewhere it already
//! trusts. A caller who genuinely wants the self-attested check must reach for
//! [`DetachedSignature::declared_verifying_key`] and pass it back in, which
//! leaves the trust decision written at the call site where a reviewer can see
//! it.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

use crate::body_identity::internal_id_preimage;
use crate::derive::derive_key;
use crate::keys::{KeyEpoch, KeyPurpose, SecretKey, SignatureCapable};
use crate::mac::TAG_BYTES;
use crate::registry::IdentityDomain;
use crate::schemes::ED25519_CODE_POINT;
use fgit_types::label::{SchemaFamily, SchemaId};

/// Bytes in an Ed25519 signature.
pub const SIGNATURE_BYTES: usize = 64;

/// Bytes in an Ed25519 public key.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// Schema family of the signed-envelope body.
pub const ENVELOPE_SCHEMA_FAMILY: &str = "frankengit.signed-envelope";

/// Schema of the signed-envelope body.
pub const ENVELOPE_SCHEMA: SchemaId =
    SchemaId::new(SchemaFamily::from_static(ENVELOPE_SCHEMA_FAMILY), 1, 0);

/// HKDF salt separating the Ed25519 seed from the key material it comes from.
const SIGNING_SEED_SALT: &[u8] = b"frankengit/signing-seed/ed25519/v1";

/// HKDF info for the Ed25519 seed.
const SIGNING_SEED_INFO: &[u8] = b"ed25519 signing seed";

/// An Ed25519 verifying key, as the caller's trust anchor.
///
/// Deliberately a distinct type from the bytes in a [`DetachedSignature`]. A
/// verifier holds this because it decided to; the envelope's copy is an
/// assertion by whoever produced the envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VerifyingKey {
    bytes: [u8; PUBLIC_KEY_BYTES],
}

impl VerifyingKey {
    /// Adopt a verifying key the caller obtained out of band.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PUBLIC_KEY_BYTES]) -> Self {
        Self { bytes }
    }

    /// The canonical encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.bytes
    }
}

/// Refusal from verifying a detached signature.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SignatureError {
    /// The envelope names a scheme this build does not implement.
    ///
    /// Separate from [`Self::Invalid`] because the two demand different
    /// operator responses: an unimplemented scheme is a deployment or
    /// migration question, a bad signature is a security event.
    UnsupportedScheme {
        /// The scheme code point the envelope declared.
        code_point: u16,
    },
    /// The envelope was produced under a key other than the one supplied.
    ///
    /// Reported before any curve operation, and reported distinctly, so
    /// "you verified against the wrong key" never reads as "this signature is
    /// a forgery".
    KeyMismatch,
    /// The envelope's declared verifying key is not a valid curve point.
    MalformedVerifyingKey,
    /// The signature does not verify over the reconstructed envelope.
    ///
    /// This is the only variant that means what it looks like. The body,
    /// domain, schema, signer purpose, epoch or key commitment differs from
    /// what was signed, or the signature is a forgery; the construction
    /// deliberately does not distinguish between those, because a verifier
    /// that reports *which* field failed is an oracle.
    Invalid,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedScheme { code_point } => write!(
                formatter,
                "signature scheme code point {code_point:#06x} is not implemented by this build"
            ),
            Self::KeyMismatch => formatter
                .write_str("the envelope was produced under a different key than the one supplied"),
            Self::MalformedVerifyingKey => {
                formatter.write_str("the declared verifying key is not a valid Ed25519 point")
            }
            Self::Invalid => formatter.write_str("the signature does not verify"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// A detached signature and the envelope it was computed over.
///
/// Detached: the body travels separately, and verification requires the caller
/// to present the same body again. The envelope carries only what is needed to
/// reconstruct the signed preimage and to notice a key substitution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DetachedSignature {
    scheme: u16,
    purpose: KeyPurpose,
    epoch: KeyEpoch,
    key_commitment: [u8; TAG_BYTES],
    verifying_key: [u8; PUBLIC_KEY_BYTES],
    signature: [u8; SIGNATURE_BYTES],
}

impl DetachedSignature {
    /// Rebuild an envelope from wire fields.
    ///
    /// A decoder reads every one of these out of bytes it does not trust, so
    /// construction is total and deliberately validates nothing: an envelope
    /// naming an unimplemented scheme, an off-curve key or a signature over
    /// different bytes is a *representable* value whose refusal comes from
    /// [`Self::verify_with`]. Refusing at construction would push the decision
    /// into the decoder, which is the layer with the least context for it.
    #[must_use]
    pub const fn from_parts(
        scheme: u16,
        purpose: KeyPurpose,
        epoch: KeyEpoch,
        key_commitment: [u8; TAG_BYTES],
        verifying_key: [u8; PUBLIC_KEY_BYTES],
        signature: [u8; SIGNATURE_BYTES],
    ) -> Self {
        Self {
            scheme,
            purpose,
            epoch,
            key_commitment,
            verifying_key,
            signature,
        }
    }

    /// The signature scheme code point.
    #[must_use]
    pub const fn scheme(&self) -> u16 {
        self.scheme
    }

    /// The purpose of the key that produced this signature.
    #[must_use]
    pub const fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// The rotation epoch of the key that produced this signature.
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// The signing key's commitment, as declared by the envelope.
    #[must_use]
    pub const fn key_commitment(&self) -> &[u8; TAG_BYTES] {
        &self.key_commitment
    }

    /// The raw signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// The verifying key the envelope *claims* was used.
    ///
    /// Named `declared` rather than `verifying_key` on purpose. Passing this
    /// straight back into [`Self::verify_with`] checks only that the envelope
    /// agrees with itself; it establishes nothing about who signed. The name is
    /// the warning, and it is the only way to spell that check.
    #[must_use]
    pub const fn declared_verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(self.verifying_key)
    }

    /// Verify against a key the caller already trusts.
    ///
    /// The body, domain and schema must be the same ones that were signed;
    /// they are not carried in the envelope, because a verifier that accepts
    /// the signer's word for what was signed is not verifying anything.
    pub fn verify_with(
        &self,
        trusted: &VerifyingKey,
        domain: IdentityDomain,
        schema: SchemaId,
        body: &[u8],
    ) -> Result<(), SignatureError> {
        if self.scheme != ED25519_CODE_POINT {
            return Err(SignatureError::UnsupportedScheme {
                code_point: self.scheme,
            });
        }
        if &self.verifying_key != trusted.as_bytes() {
            return Err(SignatureError::KeyMismatch);
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.verifying_key)
            .map_err(|_| SignatureError::MalformedVerifyingKey)?;
        let message = self.signed_preimage(domain, schema, body);
        key.verify(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| SignatureError::Invalid)
    }

    /// Reconstruct the exact bytes that were signed.
    fn signed_preimage(&self, domain: IdentityDomain, schema: SchemaId, body: &[u8]) -> Vec<u8> {
        internal_id_preimage(
            IdentityDomain::SignedEnvelope,
            ENVELOPE_SCHEMA,
            &envelope_body(
                self.scheme,
                self.purpose,
                self.epoch,
                &self.key_commitment,
                domain,
                schema,
                body,
            ),
        )
    }
}

impl<P: SignatureCapable> SecretKey<P> {
    /// This key's Ed25519 verifying key.
    ///
    /// Derived, not generated: the seed comes from the key material through
    /// HKDF under a signing-specific label, so the same material never serves
    /// as both an HKDF key and a curve scalar, and no entropy source is
    /// needed at signing time.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(self.ed25519_signing_key().verifying_key().to_bytes())
    }

    /// Sign a canonical body in a named domain.
    ///
    /// The domain and schema are required arguments for the same reason they
    /// are required by [`crate::internal_object_id`]: a signature that does not
    /// commit to what kind of thing it signed is replayable into every other
    /// kind.
    ///
    /// A signing purpose signs:
    ///
    /// ```
    /// use fgit_crypto::{
    ///     Capsule, IdentityDomain, KeyEpoch, KeyScope, RootSecret, SchemaFamily, SchemaId,
    ///     SecretKey,
    /// };
    ///
    /// let root = RootSecret::from_bytes([0x5a; 32]);
    /// let key = SecretKey::<Capsule>::derive(&root, KeyEpoch::FIRST, KeyScope::OPERATOR);
    /// let schema = SchemaId::new(SchemaFamily::from_static("frankengit.capsule"), 1, 0);
    /// let signed = key.sign(IdentityDomain::RepositoryCapsule, schema, b"body");
    /// assert!(
    ///     signed
    ///         .verify_with(&key.verifying_key(), IdentityDomain::RepositoryCapsule, schema, b"body")
    ///         .is_ok()
    /// );
    /// ```
    ///
    /// A purpose that may not sign has no such method, so the misuse is not a
    /// refusal a caller can forget to check — it is a program that does not
    /// compile:
    ///
    /// ```compile_fail
    /// use fgit_crypto::{
    ///     IdentityDomain, KeyEpoch, KeyScope, RootSecret, SchemaFamily, SchemaId, SecretKey,
    ///     TenantEncryption,
    /// };
    ///
    /// let root = RootSecret::from_bytes([0x5a; 32]);
    /// let key = SecretKey::<TenantEncryption>::derive(&root, KeyEpoch::FIRST, KeyScope::OPERATOR);
    /// let schema = SchemaId::new(SchemaFamily::from_static("frankengit.capsule"), 1, 0);
    /// let _ = key.sign(IdentityDomain::RepositoryCapsule, schema, b"body");
    /// ```
    #[must_use]
    pub fn sign(&self, domain: IdentityDomain, schema: SchemaId, body: &[u8]) -> DetachedSignature {
        let signing = self.ed25519_signing_key();
        let commitment = *self.id().commitment();
        let epoch = self.id().epoch();
        let preimage = internal_id_preimage(
            IdentityDomain::SignedEnvelope,
            ENVELOPE_SCHEMA,
            &envelope_body(
                ED25519_CODE_POINT,
                P::PURPOSE,
                epoch,
                &commitment,
                domain,
                schema,
                body,
            ),
        );
        DetachedSignature {
            scheme: ED25519_CODE_POINT,
            purpose: P::PURPOSE,
            epoch,
            key_commitment: commitment,
            verifying_key: signing.verifying_key().to_bytes(),
            signature: signing.sign(&preimage).to_bytes(),
        }
    }

    /// The Ed25519 key derived from this key's material.
    fn ed25519_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&derive_key(
            SIGNING_SEED_SALT,
            self.material(),
            SIGNING_SEED_INFO,
        ))
    }
}

/// The canonical signed-envelope body.
///
/// Every variable-length field is length-prefixed and every fixed-width field
/// is big-endian, so no two distinct envelopes share an encoding. Bare
/// concatenation would let a longer domain tag borrow the first bytes of a
/// schema family and produce the same bytes from different facts.
fn envelope_body(
    scheme: u16,
    purpose: KeyPurpose,
    epoch: KeyEpoch,
    key_commitment: &[u8; TAG_BYTES],
    body_domain: IdentityDomain,
    body_schema: SchemaId,
    body: &[u8],
) -> Vec<u8> {
    let body_digest = crate::body_identity::internal_digest_value(body_domain, body_schema, body);
    let domain_tag = body_domain.tag().as_bytes();
    let schema_family = body_schema.family();
    let family = schema_family.as_str().as_bytes();
    let digest_bytes = body_digest.as_bytes();

    let mut out = Vec::with_capacity(
        2 + 2
            + 4
            + TAG_BYTES
            + 1
            + domain_tag.len()
            + 1
            + family.len()
            + 4
            + 1
            + digest_bytes.len(),
    );
    out.extend_from_slice(&scheme.to_be_bytes());
    out.extend_from_slice(&purpose.code_point().to_be_bytes());
    out.extend_from_slice(&epoch.get().to_be_bytes());
    out.extend_from_slice(key_commitment);
    out.push(u8::try_from(domain_tag.len()).expect("a registered domain tag is at most 255 bytes"));
    out.extend_from_slice(domain_tag);
    out.push(u8::try_from(family.len()).expect("a bounded schema family is at most 255 bytes"));
    out.extend_from_slice(family);
    out.extend_from_slice(&body_schema.major().to_be_bytes());
    out.extend_from_slice(&body_schema.minor().to_be_bytes());
    out.push(u8::try_from(digest_bytes.len()).expect("an internal digest is at most 255 bytes"));
    out.extend_from_slice(digest_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
    use ed25519_dalek::{Signer, SigningKey};

    /// RFC 8032 section 7.1 known-answer vectors: seed, public key, message,
    /// signature.
    ///
    /// These live here rather than in `tests/` because they pin the *primitive*
    /// this crate reuses, not the envelope this crate owns, and the primitive
    /// is only reachable from inside the module that binds it.
    ///
    /// Independently confirmed before being written down, because a
    /// known-answer vector recalled from memory is not a known answer.
    /// OpenSSL 3.5.3 reproduced all three public keys from their seeds and the
    /// signatures for messages `72` and `af82`; its CLI refuses a zero-length
    /// input, so the empty-message signature was confirmed against
    /// python-cryptography instead. Two independent implementations, neither
    /// of them `ed25519-dalek`.
    const RFC_8032_VECTORS: &[(&str, &str, &str, &str)] = &[
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];

    fn unhex(text: &str) -> Vec<u8> {
        assert!(text.len().is_multiple_of(2), "hex has an even length");
        (0..text.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&text[index..index + 2], 16).expect("vector hex is well formed")
            })
            .collect()
    }

    #[test]
    fn rfc_8032_vectors_reproduce_exactly() {
        for (seed, public, message, signature) in RFC_8032_VECTORS {
            let seed_bytes: [u8; 32] = unhex(seed).try_into().expect("a seed is 32 bytes");
            let key = SigningKey::from_bytes(&seed_bytes);
            assert_eq!(
                key.verifying_key().to_bytes().to_vec(),
                unhex(public),
                "public key for seed {seed}"
            );
            assert_eq!(
                key.sign(&unhex(message)).to_bytes().to_vec(),
                unhex(signature),
                "signature over message {message:?}"
            );
        }
    }

    #[test]
    fn a_single_flipped_bit_in_a_vector_signature_no_longer_verifies() {
        // The paired negative. Without it the test above passes for a
        // verifier that accepts everything.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        for (_, public, message, signature) in RFC_8032_VECTORS {
            let public_bytes: [u8; PUBLIC_KEY_BYTES] =
                unhex(public).try_into().expect("a public key is 32 bytes");
            let key = VerifyingKey::from_bytes(&public_bytes).expect("vector key is on the curve");
            let mut bytes: [u8; SIGNATURE_BYTES] = unhex(signature)
                .try_into()
                .expect("a signature is 64 bytes");
            assert!(
                key.verify(&unhex(message), &Signature::from_bytes(&bytes))
                    .is_ok(),
                "the unmodified vector must verify, or the negative below is vacuous"
            );
            bytes[0] ^= 0x01;
            assert!(
                key.verify(&unhex(message), &Signature::from_bytes(&bytes))
                    .is_err(),
                "a flipped bit must not verify"
            );
        }
    }
}
