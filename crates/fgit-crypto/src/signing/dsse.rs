//! Bounded DSSE v1 issuance and verification with external Ed25519 keys.
//!
//! DSSE authenticates the original payload bytes and their interpretation. It
//! does not use, or change, FrankenGit's native signed-envelope preimage. The
//! caller owns payload-type selection, statement validation and trust policy.
//! PAE contract: <https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey};

use super::{SIGNATURE_BYTES, SignatureError, VerifyingKey};

/// Largest DSSE payload admitted by this control-statement profile.
pub const MAX_DSSE_PAYLOAD_BYTES: usize = 4096;
/// Largest UTF-8 payload-type byte string admitted by this profile.
pub const MAX_DSSE_PAYLOAD_TYPE_BYTES: usize = 256;

/// A finite DSSE control statement or its signature was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DsseSignatureError {
    /// The payload type is empty or exceeds its byte limit.
    PayloadTypeLength {
        /// Observed UTF-8 byte length.
        observed: usize,
    },
    /// The original payload exceeds its byte limit.
    PayloadLength {
        /// Observed byte length.
        observed: usize,
    },
    /// The supplied public key or Ed25519 signature was refused.
    Signature(SignatureError),
}

impl fmt::Display for DsseSignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTypeLength { observed } => write!(
                formatter,
                "DSSE payload type has {observed} bytes; expected 1..={MAX_DSSE_PAYLOAD_TYPE_BYTES}"
            ),
            Self::PayloadLength { observed } => write!(
                formatter,
                "DSSE payload has {observed} bytes; maximum is {MAX_DSSE_PAYLOAD_BYTES}"
            ),
            Self::Signature(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for DsseSignatureError {}

/// An externally provisioned Ed25519 key for bounded DSSE control statements.
///
/// This is the raw seed carried by an RFC 8410 Ed25519 private key, without
/// native key-purpose derivation or signed-envelope framing. The caller owns
/// private-key custody, statement validation and issuance policy. This key
/// cannot issue FrankenGit's native purpose-separated detached signatures.
///
/// Key material is neither exposed nor duplicated by `Clone` or `Copy`; its
/// debug representation is redacted. As with the existing key layer, this type
/// makes no guarantee that every secret copy is erased from memory on drop.
///
/// ```compile_fail
/// use fgit_crypto::DsseEd25519SigningKey;
/// let key = DsseEd25519SigningKey::from_seed([0x42; 32]);
/// let duplicate = key.clone();
/// ```
pub struct DsseEd25519SigningKey {
    key: SigningKey,
}

impl fmt::Debug for DsseEd25519SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DsseEd25519SigningKey(redacted)")
    }
}

impl DsseEd25519SigningKey {
    /// Adopt an externally provisioned 32-byte Ed25519 seed exactly as supplied.
    ///
    /// This does not parse a key file, generate entropy, apply HKDF, or establish
    /// a trust policy. File-format validation and key permission checks belong
    /// to the caller before it supplies these bytes.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// The corresponding raw Ed25519 public identity, suitable for SPKI.
    /// Possession of this identity alone does not establish a verifier's trust.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(self.key.verifying_key().to_bytes())
    }

    /// Sign DSSE v1 PAE over the exact original payload-type and payload bytes.
    ///
    /// The same independent finite limits as verification apply before PAE
    /// allocation or signature work. Empty payloads are valid. No JSON parsing,
    /// canonicalization, repository authorization or native envelope occurs.
    pub fn sign(
        &self,
        payload_type: &str,
        payload: &[u8],
    ) -> Result<[u8; SIGNATURE_BYTES], DsseSignatureError> {
        let message = pre_authentication_encoding(payload_type, payload)?;
        Ok(self.key.sign(&message).to_bytes())
    }
}

/// Verify one DSSE v1 signature over the exact supplied payload and type.
///
/// The public key comes from the caller's independent trust policy, never an
/// envelope's unauthenticated key-ID hint. No JSON decoding, canonicalization,
/// key discovery, lifecycle decision or repository authorization occurs here.
/// Type and payload limits are checked before allocating the PAE preimage.
/// Empty payloads are valid DSSE inputs; the application may require more.
/// Ed25519 strict verification also refuses weak points and malleable signatures.
pub fn verify_dsse_ed25519(
    trusted: &VerifyingKey,
    payload_type: &str,
    payload: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<(), DsseSignatureError> {
    let message = pre_authentication_encoding(payload_type, payload)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(trusted.as_bytes())
        .map_err(|_| DsseSignatureError::Signature(SignatureError::MalformedVerifyingKey))?;
    key.verify_strict(&message, &Signature::from_bytes(signature))
        .map_err(|_| DsseSignatureError::Signature(SignatureError::Invalid))
}

fn pre_authentication_encoding(
    payload_type: &str,
    payload: &[u8],
) -> Result<Vec<u8>, DsseSignatureError> {
    if payload_type.is_empty() || payload_type.len() > MAX_DSSE_PAYLOAD_TYPE_BYTES {
        return Err(DsseSignatureError::PayloadTypeLength {
            observed: payload_type.len(),
        });
    }
    if payload.len() > MAX_DSSE_PAYLOAD_BYTES {
        return Err(DsseSignatureError::PayloadLength {
            observed: payload.len(),
        });
    }
    // Both lengths are bounded above before this addition. Decimal lengths
    // need at most three/four digits, with ten fixed prefix/separator bytes.
    let mut result = Vec::with_capacity(payload_type.len() + payload.len() + 17);
    result.extend_from_slice(b"DSSEv1 ");
    result.extend_from_slice(payload_type.len().to_string().as_bytes());
    result.push(b' ');
    result.extend_from_slice(payload_type.as_bytes());
    result.push(b' ');
    result.extend_from_slice(payload.len().to_string().as_bytes());
    result.push(b' ');
    result.extend_from_slice(payload);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        core::array::from_fn(|index| {
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap()
        })
    }

    #[test]
    fn issuance_matches_external_pae_vectors_and_standard_raw_key_identities() {
        // Public seed/key fixtures: RFC 8032 section 7.1 test 1 and RFC 8410
        // section 10.3. DSSE signatures were generated by Node 24.22.1 crypto
        // over the literal b"DSSEv1 10 text/plain 5 hello", using RFC 8410
        // PKCS#8 seed framing, and cross-checked with Python cryptography.
        // Neither golden uses this PAE builder or ed25519-dalek as its oracle.
        for (seed, public, signature) in [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                concat!(
                    "ad4f9ceb1cb0a25ce8badf78ffe289e0e47d75c997b83ecac941f8c529ed3df33",
                    "9ef9f2500bec62cd697c97b2e4c7281310fe2f68779141dc849788847bd0100"
                ),
            ),
            (
                "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842",
                "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1",
                concat!(
                    "7823bf107918b3a482cd8e17a771332e3f847d22dd381d40e04da3becc34e658e",
                    "24d2bbf14d08551dccda7128810f8b07be1c3ce34eaa9bde615cc96f5cb180b"
                ),
            ),
        ] {
            let key = DsseEd25519SigningKey::from_seed(bytes(seed));
            let trusted = VerifyingKey::from_bytes(bytes(public));
            assert_eq!(key.verifying_key(), trusted);
            let expected = bytes::<SIGNATURE_BYTES>(signature);
            assert_eq!(key.sign("text/plain", b"hello").unwrap(), expected);
            assert_eq!(key.sign("text/plain", b"hello").unwrap(), expected);
            verify_dsse_ed25519(&trusted, "text/plain", b"hello", &expected).unwrap();
        }
    }

    #[test]
    fn issuance_preserves_binary_payload_utf8_lengths_and_payload_spelling() {
        let key = DsseEd25519SigningKey::from_seed([0x73; 32]);
        let trusted =
            ed25519_dalek::VerifyingKey::from_bytes(key.verifying_key().as_bytes()).unwrap();
        for (payload_type, payload, literal_pae) in [
            (
                "é",
                b"\0\xff".as_slice(),
                b"DSSEv1 2 \xc3\xa9 2 \0\xff".as_slice(),
            ),
            ("x", b"".as_slice(), b"DSSEv1 1 x 0 ".as_slice()),
            (
                "json",
                b"{\"a\":1}".as_slice(),
                b"DSSEv1 4 json 7 {\"a\":1}".as_slice(),
            ),
        ] {
            let signature = key.sign(payload_type, payload).unwrap();
            trusted
                .verify_strict(literal_pae, &Signature::from_bytes(&signature))
                .unwrap();
            assert!(
                trusted
                    .verify_strict(payload, &Signature::from_bytes(&signature))
                    .is_err(),
                "a DSSE signature cannot authenticate an unframed payload",
            );
        }
        let compact = key.sign("json", b"{\"a\":1}").unwrap();
        assert!(
            verify_dsse_ed25519(&key.verifying_key(), "json", b"{\"a\": 1}", &compact).is_err()
        );
        let spaced = key.sign("json", b"{\"a\": 1}").unwrap();
        verify_dsse_ed25519(&key.verifying_key(), "json", b"{\"a\": 1}", &spaced).unwrap();
    }

    #[test]
    fn issuance_key_debug_never_discloses_key_material() {
        for seed in [[0; 32], [0x42; 32], [0xff; 32]] {
            let key = DsseEd25519SigningKey::from_seed(seed);
            assert_eq!(format!("{key:?}"), "DsseEd25519SigningKey(redacted)");
            assert_eq!(format!("{key:#?}"), "DsseEd25519SigningKey(redacted)");
        }
    }

    #[test]
    fn pae_uses_original_bytes_and_utf8_byte_lengths() {
        assert_eq!(
            pre_authentication_encoding("text/plain", b"hello world").unwrap(),
            b"DSSEv1 10 text/plain 11 hello world"
        );
        assert_eq!(
            pre_authentication_encoding("é", b"\0\xff").unwrap(),
            b"DSSEv1 2 \xc3\xa9 2 \0\xff"
        );
        assert_eq!(
            pre_authentication_encoding("x", b"").unwrap(),
            b"DSSEv1 1 x 0 "
        );
        assert!(matches!(
            pre_authentication_encoding("", b""),
            Err(DsseSignatureError::PayloadTypeLength { observed: 0 })
        ));
    }

    #[test]
    fn finite_limits_refuse_before_signature_work_with_permitted_boundaries() {
        let key = DsseEd25519SigningKey::from_seed([0x42; 32]);
        let trusted = key.verifying_key();
        let payload_type = "x".repeat(MAX_DSSE_PAYLOAD_TYPE_BYTES);
        let payload = vec![0; MAX_DSSE_PAYLOAD_BYTES];
        let signature = key.sign(&payload_type, &payload).unwrap();
        verify_dsse_ed25519(&trusted, &payload_type, &payload, &signature).unwrap();
        assert_eq!(
            key.sign("", &payload),
            Err(DsseSignatureError::PayloadTypeLength { observed: 0 })
        );
        let excessive_type = format!("{payload_type}x");
        assert_eq!(
            key.sign(&excessive_type, &payload),
            Err(DsseSignatureError::PayloadTypeLength {
                observed: MAX_DSSE_PAYLOAD_TYPE_BYTES + 1,
            })
        );
        assert_eq!(
            key.sign("x", &vec![0; MAX_DSSE_PAYLOAD_BYTES + 1]),
            Err(DsseSignatureError::PayloadLength {
                observed: MAX_DSSE_PAYLOAD_BYTES + 1,
            })
        );
        let utf8_boundary = "é".repeat(MAX_DSSE_PAYLOAD_TYPE_BYTES / 2);
        let empty = key.sign(&utf8_boundary, b"").unwrap();
        verify_dsse_ed25519(&trusted, &utf8_boundary, b"", &empty).unwrap();
        assert_eq!(
            key.sign(&(utf8_boundary + "é"), b""),
            Err(DsseSignatureError::PayloadTypeLength {
                observed: MAX_DSSE_PAYLOAD_TYPE_BYTES + 2,
            })
        );
        assert!(matches!(
            verify_dsse_ed25519(&trusted, &(payload_type + "x"), &payload, &signature),
            Err(DsseSignatureError::PayloadTypeLength { .. })
        ));
        assert!(matches!(
            verify_dsse_ed25519(
                &trusted,
                "x",
                &vec![0; MAX_DSSE_PAYLOAD_BYTES + 1],
                &signature
            ),
            Err(DsseSignatureError::PayloadLength { .. })
        ));
    }

    #[test]
    fn externally_assembled_preimage_binds_type_payload_and_trusted_key() {
        let key = SigningKey::from_bytes(&[0x73; 32]);
        let trusted = VerifyingKey::from_bytes(key.verifying_key().to_bytes());
        // Independent literal construction, not a call to the implementation.
        let signed = key.sign(b"DSSEv1 10 text/plain 5 hello").to_bytes();
        assert_eq!(
            DsseEd25519SigningKey::from_seed([0x73; 32])
                .sign("text/plain", b"hello")
                .unwrap(),
            signed
        );
        verify_dsse_ed25519(&trusted, "text/plain", b"hello", &signed).unwrap();
        let mut damaged = signed;
        damaged[0] ^= 1;
        assert_eq!(
            verify_dsse_ed25519(&trusted, "text/plain", b"hello", &damaged),
            Err(DsseSignatureError::Signature(SignatureError::Invalid))
        );
        for (payload_type, payload) in [
            ("text/plain", b"Hello".as_slice()),
            ("text/html", b"hello".as_slice()),
            ("text/plai", b"n hello".as_slice()),
        ] {
            assert!(verify_dsse_ed25519(&trusted, payload_type, payload, &signed).is_err());
        }
        let other = SigningKey::from_bytes(&[0x74; 32]);
        assert!(
            verify_dsse_ed25519(
                &VerifyingKey::from_bytes(other.verifying_key().to_bytes()),
                "text/plain",
                b"hello",
                &signed,
            )
            .is_err()
        );
        assert!(
            verify_dsse_ed25519(
                &VerifyingKey::from_bytes([0; 32]),
                "text/plain",
                b"hello",
                &[0; SIGNATURE_BYTES],
            )
            .is_err()
        );
    }
}
