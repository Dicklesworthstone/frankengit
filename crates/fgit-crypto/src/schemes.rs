//! The signature-scheme registry, and the code points reserved against it.
//!
//! `fgit-codec` carries a `SignatureSchemeId(u16)` on every detached
//! signature and accepts **any non-zero value**, because until now nothing
//! owned the mapping from a code point to a scheme. This module owns it, the
//! same way [`crate::DigestAlgorithm`] owns the digest code points.
//!
//! # Why the reserved range exists before any scheme does
//!
//! `fgit-codec`'s fixtures already use scheme code point 1, with a signature
//! payload of 64 bytes of `0xa0`. Sixty-four bytes is exactly an Ed25519
//! signature, and 1 is the obvious code point to hand Ed25519. Allocating it
//! would turn those fixtures into well-formed-*looking* signatures — right
//! scheme, right length — that only a real verification rejects. A length
//! check would pass.
//!
//! That is the same failure the digest registry already guards against with
//! [`crate::CORPUS_RESERVED_CODE_POINTS`], so the guard has the same shape
//! here: a range no production scheme may occupy, asserted at compile time,
//! and a refusal that names the reservation rather than saying "unknown".
//!
//! # What is registered, and the fixture hazard that comes with it
//!
//! ADR-0003 is accepted and Amendment 1 selects **Ed25519** (RFC 8032), so
//! code point 1 is now allocated to it. That allocation is the one the module
//! warned about above: `fgit-codec`'s fixtures already carry scheme 1 with a
//! 64-byte payload, and 64 bytes is exactly an Ed25519 signature. Those
//! fixtures are now *shaped* like real signatures.
//!
//! Allocating elsewhere to dodge them was rejected. A permanent gap at code
//! point 1, explicable only by test data that existed in August 2026, is worse
//! than the hazard — and it would leave the hazard anyway, since some
//! allocation eventually collides with some fixture.
//!
//! What removes the hazard is that resolving a scheme no longer yields only a
//! length. [`SignatureSchemeRow::signature_len`] exists for framing, but
//! [`crate::DetachedSignature::verify_with`] is the only path that concludes
//! anything, and it requires a caller-supplied trust anchor and the original
//! body. A fixture of 64 constant bytes passes a length check and fails
//! verification, which is the correct outcome and the reason a length check
//! was never sufficient. The owner of `fgit-codec` has been notified to move
//! its fixtures into [`SIGNATURE_SCHEME_RESERVED_CODE_POINTS`], which is what
//! that range is for.

use core::fmt;
use core::ops::RangeInclusive;

use crate::registry::RowStatus;

/// Signature-scheme code points reserved for harness and corpus use, never
/// allocated to a production scheme.
///
/// Deliberately the same range as [`crate::CORPUS_RESERVED_CODE_POINTS`] uses
/// for digests: one convention for "this number is never real", rather than a
/// different one per namespace.
pub const SIGNATURE_SCHEME_RESERVED_CODE_POINTS: RangeInclusive<u16> = 0xfff0..=0xffff;

/// One registered signature scheme.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SignatureSchemeRow {
    /// Stable code point carried on the wire.
    pub code_point: u16,
    /// Stable lowercase scheme name.
    pub name: &'static str,
    /// Signature width in bytes.
    pub signature_len: usize,
    /// Public key width in bytes.
    pub public_key_len: usize,
    /// Row lifecycle.
    pub status: RowStatus,
}

/// Code point of Ed25519, the scheme selected by ADR-0003 Amendment 1.
pub const ED25519_CODE_POINT: u16 = 1;

/// The registered signature schemes.
///
/// One row. A second row is a wire-format change and an ADR amendment, not an
/// addition a contributor makes in passing.
pub const SIGNATURE_SCHEME_REGISTRY: &[SignatureSchemeRow] = &[SignatureSchemeRow {
    code_point: ED25519_CODE_POINT,
    name: "ed25519",
    signature_len: 64,
    public_key_len: 32,
    status: RowStatus::Active,
}];

// The registry is the wire contract, and `signing` is the implementation of
// it. If they disagree the mismatch is a decoding bug that only shows up on a
// real signature, so it is pinned at compile time instead.
const _: () = {
    assert!(SIGNATURE_SCHEME_REGISTRY.len() == 1);
    assert!(SIGNATURE_SCHEME_REGISTRY[0].signature_len == crate::signing::SIGNATURE_BYTES);
    assert!(SIGNATURE_SCHEME_REGISTRY[0].public_key_len == crate::signing::PUBLIC_KEY_BYTES);
};

// A production scheme must never occupy the harness range. Vacuous while the
// registry is empty, and the point is that it stops being vacuous on the first
// allocation rather than having to be remembered then.
const _: () = {
    let mut index = 0;
    while index < SIGNATURE_SCHEME_REGISTRY.len() {
        assert!(SIGNATURE_SCHEME_REGISTRY[index].code_point < 0xfff0);
        index += 1;
    }
};

// Zero is reserved by `fgit-codec`'s `SignatureSchemeId::try_new`, so it must
// never be allocated here either.
const _: () = {
    let mut index = 0;
    while index < SIGNATURE_SCHEME_REGISTRY.len() {
        assert!(SIGNATURE_SCHEME_REGISTRY[index].code_point != 0);
        index += 1;
    }
};

/// One registered authenticated-encryption scheme.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AeadSchemeRow {
    /// Stable code point carried on the wire.
    pub code_point: u16,
    /// Stable lowercase scheme name.
    pub name: &'static str,
    /// Key width in bytes.
    pub key_len: usize,
    /// Nonce width in bytes.
    pub nonce_len: usize,
    /// Authentication tag width in bytes.
    pub tag_len: usize,
    /// Row lifecycle.
    pub status: RowStatus,
}

/// Code point of XChaCha20-Poly1305, selected by ADR-0003 Amendment 1.
pub const XCHACHA20_POLY1305_CODE_POINT: u16 = 1;

/// The registered authenticated-encryption schemes.
///
/// A separate namespace from the signature schemes, sharing only the reserved
/// range. Two registries rather than one because a code point that means
/// "Ed25519" in a signature envelope and "XChaCha20-Poly1305" in a ciphertext
/// envelope is not an ambiguity as long as the two are never read by the same
/// resolver — and keeping them separate is what guarantees that.
pub const AEAD_SCHEME_REGISTRY: &[AeadSchemeRow] = &[AeadSchemeRow {
    code_point: XCHACHA20_POLY1305_CODE_POINT,
    name: "xchacha20-poly1305",
    key_len: 32,
    nonce_len: 24,
    tag_len: 16,
    status: RowStatus::Active,
}];

// Same reasoning as the signature registry: the row is the wire contract and
// the module is the implementation, so a disagreement is pinned here rather
// than discovered on a real ciphertext.
const _: () = {
    assert!(AEAD_SCHEME_REGISTRY.len() == 1);
    assert!(AEAD_SCHEME_REGISTRY[0].nonce_len == crate::envelope::NONCE_BYTES);
    assert!(AEAD_SCHEME_REGISTRY[0].tag_len == crate::envelope::AEAD_TAG_BYTES);
    assert!(AEAD_SCHEME_REGISTRY[0].key_len == crate::mac::TAG_BYTES);
    assert!(AEAD_SCHEME_REGISTRY[0].code_point != 0);
    assert!(AEAD_SCHEME_REGISTRY[0].code_point < 0xfff0);
};

/// Resolve an AEAD scheme code point that arrived as data.
///
/// Shares [`SIGNATURE_SCHEME_RESERVED_CODE_POINTS`] so that "this number is
/// never real" means one thing across the crate.
pub fn resolve_aead_scheme(
    code_point: u16,
) -> Result<&'static AeadSchemeRow, SignatureSchemeError> {
    if SIGNATURE_SCHEME_RESERVED_CODE_POINTS.contains(&code_point) {
        return Err(SignatureSchemeError::ReservedForHarness { code_point });
    }
    AEAD_SCHEME_REGISTRY
        .iter()
        .find(|row| row.code_point == code_point)
        .ok_or(SignatureSchemeError::Unregistered { code_point })
}

/// Refusal from resolving a signature-scheme code point.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SignatureSchemeError {
    /// The code point lies in the harness range and is never a real scheme.
    ///
    /// Distinct from [`Self::Unregistered`] on purpose: this says the number
    /// is *permanently* not a production scheme, so a caller seeing it knows
    /// it is looking at corpus or fixture material rather than at something
    /// that might be admitted later.
    ReservedForHarness {
        /// The code point offered.
        code_point: u16,
    },
    /// No scheme with this code point is registered.
    Unregistered {
        /// The code point offered.
        code_point: u16,
    },
}

impl fmt::Display for SignatureSchemeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedForHarness { code_point } => write!(
                formatter,
                "signature scheme code point {code_point:#06x} is reserved for harness use and is never a production scheme"
            ),
            Self::Unregistered { code_point } => write!(
                formatter,
                "no signature scheme is registered at code point {code_point:#06x}"
            ),
        }
    }
}

impl std::error::Error for SignatureSchemeError {}

/// Resolve a scheme code point that arrived as data.
///
/// A decoder reads this number out of bytes it does not trust, so the step
/// from "a number arrived" to "this is a scheme" has to be able to refuse.
pub fn resolve_signature_scheme(
    code_point: u16,
) -> Result<&'static SignatureSchemeRow, SignatureSchemeError> {
    if SIGNATURE_SCHEME_RESERVED_CODE_POINTS.contains(&code_point) {
        return Err(SignatureSchemeError::ReservedForHarness { code_point });
    }
    SIGNATURE_SCHEME_REGISTRY
        .iter()
        .find(|row| row.code_point == code_point)
        .ok_or(SignatureSchemeError::Unregistered { code_point })
}

/// Whether a code point may ever be allocated to a production scheme.
///
/// Exposed so a caller choosing a fixture value can check it without having to
/// know the range.
#[must_use]
pub fn is_allocatable(code_point: u16) -> bool {
    code_point != 0 && !SIGNATURE_SCHEME_RESERVED_CODE_POINTS.contains(&code_point)
}
