//! Tenant envelope encryption.
//!
//! ADR-0003 Amendment 1 selects `XChaCha20`-Poly1305. The 192-bit nonce is the
//! reason: it makes a randomly chosen nonce safe without a durable per-key
//! counter, and a counter that must survive restore, replication and rollback
//! is exactly the kind of state this project treats as authority rather than
//! as a convenience. AES-GCM's 96-bit nonce forces either that counter or a
//! birthday bound around 2^32 messages under one key, and its nonce reuse is
//! catastrophic rather than degrading.
//!
//! # The domain binding is cryptographic, not annotational
//!
//! Plan sections 12.5 and 13.7 require that *"a ciphertext copied across
//! incompatible key domains is not a valid placement"*. A field saying which
//! tenant a ciphertext belongs to does not achieve that; an attacker edits the
//! field. What achieves it is that the key's purpose, epoch and commitment are
//! the AEAD's associated data, so a relabelled ciphertext fails
//! authentication. The tenant and repository reach the same binding by a
//! second route, because the key commitment is derived from the scope.
//!
//! # Nonces are the caller's obligation, and deliberately so
//!
//! [`SecretKey::seal`] takes an [`EnvelopeNonce`] instead of drawing one. This
//! crate is built with `getrandom` disabled, and that is a design position
//! rather than an accident: entropy is a capability the runtime owns, and a
//! primitive that quietly reaches for the operating system is a primitive that
//! cannot be tested deterministically or audited for where its randomness came
//! from. The obligation on the caller is one sentence long — never seal twice
//! under one key with one nonce — and at 192 bits a random nonce satisfies it
//! without coordination.

use core::fmt;

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};

use crate::derive::derive_key;
use crate::keys::{EncryptionCapable, KeyEpoch, KeyPurpose, SecretKey};
use crate::mac::TAG_BYTES;
use crate::schemes::XCHACHA20_POLY1305_CODE_POINT;

/// Bytes in an `XChaCha20`-Poly1305 nonce.
pub const NONCE_BYTES: usize = 24;

/// Bytes in a Poly1305 authentication tag.
pub const AEAD_TAG_BYTES: usize = 16;

/// HKDF salt separating the AEAD key from the key material it comes from.
const SEALING_KEY_SALT: &[u8] = b"frankengit/sealing-key/xchacha20-poly1305/v1";

/// HKDF info for the AEAD key.
const SEALING_KEY_INFO: &[u8] = b"xchacha20-poly1305 sealing key";

/// A nonce for one sealing operation.
///
/// A distinct type rather than a bare array, so "some 24 bytes" cannot be
/// passed where a value the caller promised is unique is required.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvelopeNonce {
    bytes: [u8; NONCE_BYTES],
}

impl EnvelopeNonce {
    /// Adopt nonce bytes the caller is responsible for making unique.
    ///
    /// Uniqueness per key is the caller's obligation and cannot be checked
    /// here: this type sees one operation and has no memory of the others.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_BYTES]) -> Self {
        Self { bytes }
    }

    /// The nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_BYTES] {
        &self.bytes
    }
}

/// Refusal from opening a sealed envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EnvelopeError {
    /// The envelope names an AEAD this build does not implement.
    UnsupportedScheme {
        /// The scheme code point the envelope declared.
        code_point: u16,
    },
    /// The envelope belongs to a different key domain than the key offered.
    ///
    /// Reported before authentication, and reported distinctly, because it is
    /// the placement error plan sections 12.5 and 13.7 name: a ciphertext that
    /// arrived somewhere it does not belong. Authentication would refuse it
    /// too, but as an indistinguishable failure, and an operator investigating
    /// a misrouted replica needs to be told which of the two happened.
    KeyDomainMismatch,
    /// The ciphertext, tag, nonce or associated data does not authenticate.
    ///
    /// Carries no detail about which, on purpose: a decryption failure that
    /// says why is an oracle.
    Unauthenticated,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedScheme { code_point } => write!(
                formatter,
                "aead scheme code point {code_point:#06x} is not implemented by this build"
            ),
            Self::KeyDomainMismatch => formatter
                .write_str("the sealed envelope belongs to a different key domain than this key"),
            Self::Unauthenticated => {
                formatter.write_str("the sealed envelope does not authenticate")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// One authenticated ciphertext and the key domain it is bound to.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SealedEnvelope {
    scheme: u16,
    purpose: KeyPurpose,
    epoch: KeyEpoch,
    key_commitment: [u8; TAG_BYTES],
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    tag: [u8; AEAD_TAG_BYTES],
}

impl SealedEnvelope {
    /// Rebuild an envelope from wire fields.
    ///
    /// Total, for the same reason
    /// [`crate::DetachedSignature::from_parts`] is: a decoder reads all of
    /// this from bytes it does not trust, and the refusal belongs at
    /// [`SecretKey::open`] where the key is available to decide.
    #[must_use]
    pub const fn from_parts(
        scheme: u16,
        purpose: KeyPurpose,
        epoch: KeyEpoch,
        key_commitment: [u8; TAG_BYTES],
        nonce: [u8; NONCE_BYTES],
        ciphertext: Vec<u8>,
        tag: [u8; AEAD_TAG_BYTES],
    ) -> Self {
        Self {
            scheme,
            purpose,
            epoch,
            key_commitment,
            nonce,
            ciphertext,
            tag,
        }
    }

    /// The AEAD scheme code point.
    #[must_use]
    pub const fn scheme(&self) -> u16 {
        self.scheme
    }

    /// The purpose of the key this envelope is bound to.
    #[must_use]
    pub const fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// The rotation epoch this envelope is bound to.
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// The commitment of the key this envelope is bound to.
    #[must_use]
    pub const fn key_commitment(&self) -> &[u8; TAG_BYTES] {
        &self.key_commitment
    }

    /// The nonce used to seal.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    /// The ciphertext.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The authentication tag.
    #[must_use]
    pub const fn tag(&self) -> &[u8; AEAD_TAG_BYTES] {
        &self.tag
    }
}

impl<P: EncryptionCapable> SecretKey<P> {
    /// Seal a plaintext under this key's domain.
    ///
    /// The caller's `associated_data` is authenticated in addition to the key
    /// domain, so placement facts a caller wants bound — a segment identifier,
    /// a generation — become part of what the tag covers.
    #[must_use]
    pub fn seal(
        &self,
        nonce: EnvelopeNonce,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> SealedEnvelope {
        let commitment = *self.id().commitment();
        let epoch = self.id().epoch();
        let aad = domain_associated_data(
            XCHACHA20_POLY1305_CODE_POINT,
            P::PURPOSE,
            epoch,
            &commitment,
            associated_data,
        );
        let mut buffer = plaintext.to_vec();
        let tag = self
            .aead_cipher()
            .encrypt_inout_detached(
                &XNonce::from(*nonce.as_bytes()),
                &aad,
                buffer.as_mut_slice().into(),
            )
            .expect("sealing a buffer of addressable length cannot fail");
        SealedEnvelope {
            scheme: XCHACHA20_POLY1305_CODE_POINT,
            purpose: P::PURPOSE,
            epoch,
            key_commitment: commitment,
            nonce: *nonce.as_bytes(),
            ciphertext: buffer,
            tag: tag.into(),
        }
    }

    /// Open a sealed envelope bound to this key's domain.
    pub fn open(
        &self,
        sealed: &SealedEnvelope,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        if sealed.scheme != XCHACHA20_POLY1305_CODE_POINT {
            return Err(EnvelopeError::UnsupportedScheme {
                code_point: sealed.scheme,
            });
        }
        let commitment = *self.id().commitment();
        if sealed.purpose != P::PURPOSE
            || sealed.epoch != self.id().epoch()
            || sealed.key_commitment != commitment
        {
            return Err(EnvelopeError::KeyDomainMismatch);
        }
        let aad = domain_associated_data(
            sealed.scheme,
            sealed.purpose,
            sealed.epoch,
            &sealed.key_commitment,
            associated_data,
        );
        let mut buffer = sealed.ciphertext.clone();
        self.aead_cipher()
            .decrypt_inout_detached(
                &XNonce::from(sealed.nonce),
                &aad,
                buffer.as_mut_slice().into(),
                &Tag::from(sealed.tag),
            )
            .map_err(|_| EnvelopeError::Unauthenticated)?;
        Ok(buffer)
    }

    /// The AEAD cipher derived from this key's material.
    fn aead_cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(&derive_key(
            SEALING_KEY_SALT,
            self.material(),
            SEALING_KEY_INFO,
        ))
        .expect("a 32-byte derived key is the correct width for XChaCha20-Poly1305")
    }
}

/// The associated data binding a ciphertext to one key domain.
///
/// Length-prefixed for the same reason every other preimage in this crate is:
/// bare concatenation lets a longer caller-supplied field borrow bytes from
/// the field before it, so two different bindings can produce one encoding.
fn domain_associated_data(
    scheme: u16,
    purpose: KeyPurpose,
    epoch: KeyEpoch,
    key_commitment: &[u8; TAG_BYTES],
    caller: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 2 + 4 + TAG_BYTES + 8 + caller.len());
    out.extend_from_slice(&scheme.to_be_bytes());
    out.extend_from_slice(&purpose.code_point().to_be_bytes());
    out.extend_from_slice(&epoch.get().to_be_bytes());
    out.extend_from_slice(key_commitment);
    out.extend_from_slice(
        &u64::try_from(caller.len())
            .expect("a slice length always fits in u64 on supported targets")
            .to_be_bytes(),
    );
    out.extend_from_slice(caller);
    out
}
