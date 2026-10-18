//! Bounded DSSE v1 verification using an independently supplied Ed25519 key.
//!
//! DSSE authenticates the original payload bytes and their interpretation. It
//! does not use, or change, FrankenGit's native signed-envelope preimage. The
//! caller owns payload-type selection, statement validation and trust policy.
//! PAE contract: <https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>.

use core::fmt;

use ed25519_dalek::Signature;

use super::{SIGNATURE_BYTES, SignatureError, VerifyingKey};

/// Largest DSSE payload admitted by this control-statement profile.
pub const MAX_DSSE_PAYLOAD_BYTES: usize = 4096;
/// Largest UTF-8 payload-type byte string admitted by this profile.
pub const MAX_DSSE_PAYLOAD_TYPE_BYTES: usize = 256;

/// A finite DSSE control statement or its signature could not be verified.
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
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let trusted = VerifyingKey::from_bytes(key.verifying_key().to_bytes());
        let payload_type = "x".repeat(MAX_DSSE_PAYLOAD_TYPE_BYTES);
        let payload = vec![0; MAX_DSSE_PAYLOAD_BYTES];
        let signature = key
            .sign(&pre_authentication_encoding(&payload_type, &payload).unwrap())
            .to_bytes();
        verify_dsse_ed25519(&trusted, &payload_type, &payload, &signature).unwrap();
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
        verify_dsse_ed25519(&trusted, "text/plain", b"hello", &signed).unwrap();
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
