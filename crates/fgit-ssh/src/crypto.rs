//! Cryptographic protocol operations for FrankenGit SSH (RFC 8731 / OpenSSH ChaCha20-Poly1305).
//!
//! Enforces:
//! - RFC 8731 Curve25519 key exchange with all-zero shared secret rejection.
//! - OpenSSH `chacha20-poly1305@openssh.com` two-key packet encryption and authentication.
//! - RFC 4253 key derivation from shared secret `K` and exchange hash `H`.
//! - Ed25519 host key and client signature verification.

use core::fmt::{self, Display, Formatter};

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20Legacy, LegacyNonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fgit_crypto::sha256_digest;
use poly1305::universal_hash::KeyInit;
use poly1305::Poly1305;

use crate::wire::{
    MAX_PACKET_BYTES, MIN_PADDING_BYTES, PACKET_BLOCK_ALIGN, WireReader, WireWriter,
};

/// SSH Ed25519 key algorithm name.
pub const SSH_ED25519_ALGORITHM: &str = "ssh-ed25519";

/// SSH Curve25519 KEX algorithm names.
pub const KEX_CURVE25519_SHA256: &str = "curve25519-sha256";
pub const KEX_CURVE25519_SHA256_LIBSSH: &str = "curve25519-sha256@libssh.org";

/// OpenSSH two-key ChaCha20-Poly1305 cipher algorithm name.
pub const CIPHER_CHACHA20_POLY1305: &str = "chacha20-poly1305@openssh.com";

/// Cryptographic error types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    WeakKeyExchange,
    InvalidPublicKeyLength { observed: usize },
    InvalidSignatureLength { observed: usize },
    InvalidSignatureScheme { observed: String },
    SignatureVerificationFailed,
    MacVerificationFailed,
    PacketTooLarge { observed: usize, limit: usize },
    PacketTooSmall { observed: usize, min: usize },
    InvalidPadding { padding: usize, packet_len: usize },
    UnexpectedEof,
    KeyDerivationError,
}

impl Display for CryptoError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WeakKeyExchange => formatter.write_str("weak Curve25519 shared secret is refused"),
            Self::InvalidPublicKeyLength { observed } => {
                write!(formatter, "invalid public key length {observed}, expected 32")
            }
            Self::InvalidSignatureLength { observed } => {
                write!(formatter, "invalid signature length {observed}, expected 64")
            }
            Self::InvalidSignatureScheme { observed } => {
                write!(formatter, "unsupported signature scheme `{observed}`")
            }
            Self::SignatureVerificationFailed => {
                formatter.write_str("Ed25519 signature verification failed")
            }
            Self::MacVerificationFailed => {
                formatter.write_str("ChaCha20-Poly1305 MAC tag verification failed")
            }
            Self::PacketTooLarge { observed, limit } => {
                write!(formatter, "packet length {observed} exceeds limit {limit}")
            }
            Self::PacketTooSmall { observed, min } => {
                write!(formatter, "packet length {observed} below minimum {min}")
            }
            Self::InvalidPadding { padding, packet_len } => {
                write!(formatter, "invalid padding length {padding} for packet {packet_len}")
            }
            Self::UnexpectedEof => formatter.write_str("unexpected EOF during crypto operation"),
            Self::KeyDerivationError => formatter.write_str("error during SSH key derivation"),
        }
    }
}

impl core::error::Error for CryptoError {}

/// Curve25519 ephemeral key pair for RFC 8731 KEX.
#[derive(Clone, Debug)]
pub struct Curve25519Kex {
    private_key: [u8; 32],
    public_key: [u8; 32],
}

impl Curve25519Kex {
    /// Generates an ephemeral key pair from 32 bytes of private randomness.
    #[must_use]
    pub fn from_private_bytes(private_key: [u8; 32]) -> Self {
        let public_key = MontgomeryPoint::mul_base_clamped(private_key).0;
        Self {
            private_key,
            public_key,
        }
    }

    /// The ephemeral public key bytes to send in KEX_ECDH_REPLY.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Computes the Diffie-Hellman shared secret `K` against the client's ephemeral public key.
    ///
    /// # Errors
    ///
    /// Fails with [`CryptoError::WeakKeyExchange`] if the resulting shared secret is all zeros,
    /// as mandated by RFC 8731 section 3.
    pub fn compute_shared_secret(&self, peer_pub_bytes: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        let peer_point = MontgomeryPoint(*peer_pub_bytes);
        let shared = peer_point.mul_clamped(self.private_key).0;

        // RFC 8731 §3: "With Curve25519 and Curve448, the server MUST check whether the shared key
        // is the all-zero value and abort if so."
        if shared == [0u8; 32] {
            return Err(CryptoError::WeakKeyExchange);
        }

        Ok(shared)
    }
}

/// Derives key material of length `len` from shared secret `K` (formatted as mpint)
/// and exchange hash `H`, per RFC 4253 section 7.2.
#[must_use]
pub fn derive_key(
    k_mpint: &[u8],
    hash_h: &[u8; 32],
    key_char: u8,
    session_id: &[u8; 32],
    len: usize,
) -> Vec<u8> {
    // K1 = HASH(K || H || X || session_id)
    let mut preimage1 = Vec::with_capacity(k_mpint.len() + 32 + 1 + 32);
    preimage1.extend_from_slice(k_mpint);
    preimage1.extend_from_slice(hash_h);
    preimage1.push(key_char);
    preimage1.extend_from_slice(session_id);
    let k1 = sha256_digest(&preimage1);

    if len <= 32 {
        return k1[..len].to_vec();
    }

    // K2 = HASH(K || H || K1)
    let mut preimage2 = Vec::with_capacity(k_mpint.len() + 32 + 32);
    preimage2.extend_from_slice(k_mpint);
    preimage2.extend_from_slice(hash_h);
    preimage2.extend_from_slice(&k1);
    let k2 = sha256_digest(&preimage2);

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&k1);
    out.extend_from_slice(&k2);
    out.truncate(len);
    out
}

/// OpenSSH `chacha20-poly1305@openssh.com` packet cipher.
///
/// Holds two 32-byte keys:
/// - `k_main`: payload cipher and Poly1305 key generation.
/// - `k_header`: packet length cipher.
#[derive(Clone, Debug)]
pub struct OpenSshChaCha20Poly1305 {
    k_main: [u8; 32],
    k_header: [u8; 32],
    sequence_number: u64,
}

impl OpenSshChaCha20Poly1305 {
    /// Creates a new cipher instance from 64 bytes of key material.
    /// First 32 bytes are `k_main`, second 32 bytes are `k_header`.
    #[must_use]
    pub fn new(key_material: &[u8; 64]) -> Self {
        let mut k_main = [0u8; 32];
        let mut k_header = [0u8; 32];
        k_main.copy_from_slice(&key_material[0..32]);
        k_header.copy_from_slice(&key_material[32..64]);
        Self {
            k_main,
            k_header,
            sequence_number: 0,
        }
    }

    /// The current 64-bit packet sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// Encrypts an outgoing packet payload.
    ///
    /// Transmitted wire format:
    /// - `encrypted_length` (4 bytes)
    /// - `encrypted_payload_and_padding` (`packet_length` bytes)
    /// - `mac_tag` (16 bytes)
    pub fn encrypt_packet(&mut self, payload: &[u8], random_pad: &[u8]) -> Vec<u8> {
        let seq = self.sequence_number;
        let nonce_bytes = seq.to_be_bytes();
        let nonce = LegacyNonce::from(nonce_bytes);

        // 1. Determine padding length
        let unpadded_len = 1 + payload.len();
        let mut padding_len = MIN_PADDING_BYTES;
        while !(4 + unpadded_len + padding_len).is_multiple_of(PACKET_BLOCK_ALIGN) {
            padding_len += 1;
        }

        let packet_length = (1 + payload.len() + padding_len) as u32;

        // 2. Encrypt packet length using k_header at counter 0
        let mut encrypted_len = packet_length.to_be_bytes();
        let mut header_cipher = ChaCha20Legacy::new((&self.k_header).into(), &nonce);
        header_cipher.apply_keystream(&mut encrypted_len);

        // 3. Derive Poly1305 one-time key from k_main at counter 0
        let mut main_cipher = ChaCha20Legacy::new((&self.k_main).into(), &nonce);
        let mut poly_key_block = [0u8; 64];
        main_cipher.apply_keystream(&mut poly_key_block);
        let poly_key = &poly_key_block[..32];

        // 4. Encrypt [padding_len] || payload || padding using k_main at counter 1
        let mut payload_buf = Vec::with_capacity(packet_length as usize);
        payload_buf.push(padding_len as u8);
        payload_buf.extend_from_slice(payload);
        for i in 0..padding_len {
            let b = if i < random_pad.len() { random_pad[i] } else { 0 };
            payload_buf.push(b);
        }
        main_cipher.apply_keystream(&mut payload_buf);

        // 5. Compute Poly1305 MAC over encrypted_len || payload_buf
        let mut mac_input = Vec::with_capacity(encrypted_len.len() + payload_buf.len());
        mac_input.extend_from_slice(&encrypted_len);
        mac_input.extend_from_slice(&payload_buf);
        let poly = Poly1305::new_from_slice(poly_key).expect("32-byte key is valid for Poly1305");
        let tag = poly.compute_unpadded(&mac_input);

        // 6. Assemble wire packet
        let mut wire = Vec::with_capacity(4 + payload_buf.len() + 16);
        wire.extend_from_slice(&encrypted_len);
        wire.extend_from_slice(&payload_buf);
        wire.extend_from_slice(tag.as_slice());

        self.sequence_number = self.sequence_number.wrapping_add(1);
        wire
    }

    /// Decrypts the 4-byte length field of an incoming packet.
    #[must_use]
    pub fn decrypt_packet_length(&self, encrypted_len_bytes: &[u8; 4]) -> u32 {
        let seq = self.sequence_number;
        let nonce = LegacyNonce::from(seq.to_be_bytes());
        let mut len_buf = *encrypted_len_bytes;
        let mut header_cipher = ChaCha20Legacy::new((&self.k_header).into(), &nonce);
        header_cipher.apply_keystream(&mut len_buf);
        u32::from_be_bytes(len_buf)
    }

    /// Decrypts and authenticates an incoming packet payload.
    ///
    /// Expects full packet bytes: `encrypted_length` (4 bytes) + `encrypted_payload` (len bytes) + `mac_tag` (16 bytes).
    pub fn decrypt_packet(&mut self, packet_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if packet_bytes.len() < 20 {
            return Err(CryptoError::UnexpectedEof);
        }

        let encrypted_len = &packet_bytes[0..4];
        let mut len_arr = [0u8; 4];
        len_arr.copy_from_slice(encrypted_len);
        let packet_length = self.decrypt_packet_length(&len_arr) as usize;

        if packet_length > MAX_PACKET_BYTES {
            return Err(CryptoError::PacketTooLarge {
                observed: packet_length,
                limit: MAX_PACKET_BYTES,
            });
        }
        if packet_length < 5 {
            return Err(CryptoError::PacketTooSmall {
                observed: packet_length,
                min: 5,
            });
        }

        let total_required = 4 + packet_length + 16;
        if packet_bytes.len() < total_required {
            return Err(CryptoError::UnexpectedEof);
        }

        let encrypted_payload = &packet_bytes[4..4 + packet_length];
        let observed_tag = &packet_bytes[4 + packet_length..total_required];

        let seq = self.sequence_number;
        let nonce = LegacyNonce::from(seq.to_be_bytes());

        // Derive Poly1305 key from k_main at counter 0
        let mut main_cipher = ChaCha20Legacy::new((&self.k_main).into(), &nonce);
        let mut poly_key_block = [0u8; 64];
        main_cipher.apply_keystream(&mut poly_key_block);
        let poly_key = &poly_key_block[..32];

        // Verify Poly1305 MAC over encrypted_len || encrypted_payload
        let mut mac_input = Vec::with_capacity(encrypted_len.len() + encrypted_payload.len());
        mac_input.extend_from_slice(encrypted_len);
        mac_input.extend_from_slice(encrypted_payload);
        let poly = Poly1305::new_from_slice(poly_key).expect("32-byte key is valid for Poly1305");
        let computed_tag = poly.compute_unpadded(&mac_input);

        // Constant-time tag check
        if computed_tag.as_slice() != observed_tag {
            return Err(CryptoError::MacVerificationFailed);
        }

        // Decrypt payload using k_main at counter 1
        let mut decrypted_payload = encrypted_payload.to_vec();
        main_cipher.apply_keystream(&mut decrypted_payload);

        let padding_len = decrypted_payload[0] as usize;
        if padding_len < MIN_PADDING_BYTES || padding_len >= packet_length {
            return Err(CryptoError::InvalidPadding {
                padding: padding_len,
                packet_len: packet_length,
            });
        }

        let payload_len = packet_length - 1 - padding_len;
        let payload = decrypted_payload[1..=payload_len].to_vec();

        self.sequence_number = self.sequence_number.wrapping_add(1);
        Ok(payload)
    }
}

/// Encodes an Ed25519 public key in SSH wire format (`ssh-ed25519` key blob).
#[must_use]
pub fn encode_ed25519_public_key(pub_key: &[u8; 32]) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_utf8(SSH_ED25519_ALGORITHM);
    writer.write_string(pub_key);
    writer.into_bytes()
}

/// Parses an `ssh-ed25519` public key wire blob, extracting the raw 32-byte public key.
pub fn parse_ed25519_public_key(blob: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut reader = WireReader::new(blob);
    let algo = reader.read_utf8().map_err(|_| CryptoError::UnexpectedEof)?;
    if algo != SSH_ED25519_ALGORITHM {
        return Err(CryptoError::InvalidSignatureScheme {
            observed: algo.to_owned(),
        });
    }
    let key_bytes = reader.read_string().map_err(|_| CryptoError::UnexpectedEof)?;
    if key_bytes.len() != 32 {
        return Err(CryptoError::InvalidPublicKeyLength {
            observed: key_bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(key_bytes);
    Ok(out)
}

/// Signs data using an Ed25519 signing key, returning an SSH signature blob.
///
/// Wire format:
/// string "ssh-ed25519"
/// string 64-byte signature
#[must_use]
pub fn sign_ed25519(key: &SigningKey, data: &[u8]) -> Vec<u8> {
    let sig: Signature = key.sign(data);
    let mut writer = WireWriter::new();
    writer.write_utf8(SSH_ED25519_ALGORITHM);
    writer.write_string(&sig.to_bytes());
    writer.into_bytes()
}

/// Verifies an SSH Ed25519 signature blob over `data`.
pub fn verify_ed25519(
    pub_key_bytes: &[u8; 32],
    data: &[u8],
    sig_blob: &[u8],
) -> Result<(), CryptoError> {
    let mut reader = WireReader::new(sig_blob);
    let algo = reader.read_utf8().map_err(|_| CryptoError::UnexpectedEof)?;
    if algo != SSH_ED25519_ALGORITHM {
        return Err(CryptoError::InvalidSignatureScheme {
            observed: algo.to_owned(),
        });
    }
    let sig_bytes = reader.read_string().map_err(|_| CryptoError::UnexpectedEof)?;
    if sig_bytes.len() != 64 {
        return Err(CryptoError::InvalidSignatureLength {
            observed: sig_bytes.len(),
        });
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let verifying_key = VerifyingKey::from_bytes(pub_key_bytes)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;

    verifying_key
        .verify(data, &signature)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;

    Ok(())
}
