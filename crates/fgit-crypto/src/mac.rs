//! HMAC-SHA-256 (RFC 2104), built on this crate's SHA-256.
//!
//! HMAC is a *construction* over a hash, not a primitive of its own: RFC 2104
//! specifies it completely, and it needs no key schedule, no nonce, and no
//! secret-dependent control flow. That is why it is built here rather than
//! taken as a dependency, and why the same reasoning does **not** extend to
//! signature schemes or AEAD — see the crate documentation for where that
//! line falls.
//!
//! Correctness evidence is the RFC 4231 test vectors, checked in under
//! `goldens/mac_vectors.tsv` and derived from an implementation outside this
//! crate.
//!
//! # Non-claims that matter for a keyed primitive
//!
//! **Timing.** [`verify_mac`] compares with a data-independent fold and a
//! `black_box` so the optimiser cannot short-circuit it. That is the strongest
//! statement safe Rust supports without a dedicated constant-time crate; it is
//! not a measured constant-time guarantee, and it is not proof against
//! compiler versions that reason differently.
//!
//! **Key material is not scrubbed.** Nothing here zeroizes the key block on
//! drop, because the compiler is free to elide such writes and this crate has
//! no `zeroize` dependency. A caller holding long-lived key material should
//! assume it stays in memory until the allocation is reused. Closing that gap
//! is a dependency decision, not something to fake with a manual loop.

use crate::hashing::{DigestHasher, Sha256Hasher, sha256_digest};

/// SHA-256 compression block width, and therefore the HMAC key block width.
const BLOCK_BYTES: usize = 64;
/// Inner padding byte from RFC 2104.
const INNER_PAD: u8 = 0x36;
/// Outer padding byte from RFC 2104.
const OUTER_PAD: u8 = 0x5c;

/// Width of an HMAC-SHA-256 tag, in bytes.
pub const TAG_BYTES: usize = 32;

/// Streaming HMAC-SHA-256.
#[derive(Clone, Debug)]
pub struct HmacSha256 {
    inner: Sha256Hasher,
    outer_pad: [u8; BLOCK_BYTES],
}

impl HmacSha256 {
    /// Start a tag over `key`.
    ///
    /// A key longer than the block width is hashed first and a shorter one is
    /// zero-padded, exactly as RFC 2104 specifies. Both are exercised by the
    /// RFC 4231 vectors.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut block = [0_u8; BLOCK_BYTES];
        if key.len() > BLOCK_BYTES {
            block[..TAG_BYTES].copy_from_slice(&sha256_digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        let mut inner_pad = block;
        for byte in &mut inner_pad {
            *byte ^= INNER_PAD;
        }
        let mut outer_pad = block;
        for byte in &mut outer_pad {
            *byte ^= OUTER_PAD;
        }

        let mut inner = Sha256Hasher::new();
        DigestHasher::update(&mut inner, &inner_pad);
        Self { inner, outer_pad }
    }

    /// Absorb the next chunk of the message.
    pub fn update(&mut self, chunk: &[u8]) {
        DigestHasher::update(&mut self.inner, chunk);
    }

    /// Produce the tag.
    #[must_use]
    pub fn finish(self) -> [u8; TAG_BYTES] {
        let inner = DigestHasher::finish(self.inner);
        let mut outer = Sha256Hasher::new();
        DigestHasher::update(&mut outer, &self.outer_pad);
        DigestHasher::update(&mut outer, &inner);
        DigestHasher::finish(outer)
    }
}

/// One-shot HMAC-SHA-256 over a complete message.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; TAG_BYTES] {
    let mut mac = HmacSha256::new(key);
    mac.update(message);
    mac.finish()
}

/// Compare two tags without branching on where they first differ.
///
/// Always use this rather than `==`: a short-circuiting comparison leaks the
/// length of the matching prefix, which is enough to forge a tag byte by byte.
#[must_use]
pub fn verify_mac(expected: &[u8; TAG_BYTES], candidate: &[u8; TAG_BYTES]) -> bool {
    let mut difference = 0_u8;
    for (left, right) in expected.iter().zip(candidate.iter()) {
        difference |= left ^ right;
    }
    core::hint::black_box(difference) == 0
}
