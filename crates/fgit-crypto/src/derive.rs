//! HKDF-SHA-256 (RFC 5869): the key-derivation and domain-separation step for
//! encryption domains.
//!
//! Like HMAC, HKDF is a construction rather than a primitive — RFC 5869
//! specifies extract-then-expand completely in terms of HMAC — so it is built
//! here on this crate's HMAC-SHA-256 and needs no dependency.
//!
//! # Why this exists in a crate about identity
//!
//! The threat model requires envelope encryption to bind tenant, repository,
//! object class, key purpose and version, and requires a ciphertext copied
//! across incompatible key domains not to be a valid placement. Both are
//! statements about *which key* a domain gets, which is a derivation problem:
//! one root secret, one `info` string per domain, and keys that cannot be
//! confused because the derivation never produced the same bytes twice.
//!
//! The `info` argument is where that domain separation lives, and it takes the
//! same length-prefixed framing as the internal-identity preimage rather than
//! a second convention — see [`crate::internal_id_preimage`]. Concatenating
//! domain fields without framing is how two different domains end up deriving
//! one key.
//!
//! Correctness evidence is the RFC 5869 Appendix A vectors for SHA-256,
//! checked in under `goldens/derive_vectors.tsv` and derived from an
//! implementation outside this crate.

use core::fmt;

use crate::mac::{HmacSha256, TAG_BYTES, hmac_sha256};

/// Longest output HKDF-SHA-256 can produce: 255 blocks of the hash width.
pub const MAX_OUTPUT_BYTES: usize = 255 * TAG_BYTES;

/// Refusal from a derivation whose requested length is out of range.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OutputTooLong {
    /// Bytes requested.
    pub requested: usize,
    /// Largest length the construction can produce.
    pub maximum: usize,
}

impl fmt::Display for OutputTooLong {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "HKDF cannot produce {} bytes; the maximum is {}",
            self.requested, self.maximum
        )
    }
}

impl std::error::Error for OutputTooLong {}

/// RFC 5869 extract: compress input keying material into a pseudorandom key.
///
/// An empty salt becomes a block of zeros, as the RFC specifies. Passing a
/// salt is preferred where one is available; the zero salt is the documented
/// fallback, not an error.
#[must_use]
pub fn extract(salt: &[u8], input_keying_material: &[u8]) -> [u8; TAG_BYTES] {
    if salt.is_empty() {
        hmac_sha256(&[0_u8; TAG_BYTES], input_keying_material)
    } else {
        hmac_sha256(salt, input_keying_material)
    }
}

/// RFC 5869 expand: stretch a pseudorandom key into `output.len()` bytes,
/// separated by `info`.
pub fn expand(
    pseudorandom_key: &[u8; TAG_BYTES],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), OutputTooLong> {
    if output.len() > MAX_OUTPUT_BYTES {
        return Err(OutputTooLong {
            requested: output.len(),
            maximum: MAX_OUTPUT_BYTES,
        });
    }

    let mut previous: [u8; TAG_BYTES] = [0; TAG_BYTES];
    let mut produced = 0_usize;
    let mut counter = 1_u8;
    while produced < output.len() {
        let mut mac = HmacSha256::new(pseudorandom_key);
        if produced > 0 {
            mac.update(&previous);
        }
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finish();

        let remaining = output.len() - produced;
        let take = remaining.min(TAG_BYTES);
        output[produced..produced + take].copy_from_slice(&previous[..take]);
        produced += take;
        counter = counter.wrapping_add(1);
    }
    Ok(())
}

/// RFC 5869 extract-then-expand in one call.
pub fn derive(
    salt: &[u8],
    input_keying_material: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), OutputTooLong> {
    let pseudorandom_key = extract(salt, input_keying_material);
    expand(&pseudorandom_key, info, output)
}

/// Derive exactly one 32-byte key.
///
/// The common case: one root secret, one framed `info` naming the domain, one
/// key out.
#[must_use]
pub fn derive_key(salt: &[u8], input_keying_material: &[u8], info: &[u8]) -> [u8; TAG_BYTES] {
    let mut key = [0_u8; TAG_BYTES];
    derive(salt, input_keying_material, info, &mut key)
        .expect("one hash block is always within the HKDF output bound");
    key
}
