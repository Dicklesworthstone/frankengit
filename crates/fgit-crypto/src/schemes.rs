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
//! # Honest statement of what this does today
//!
//! **No signature scheme is registered.** ADR-0003 proposes where signature
//! primitives come from and has not been accepted, so admitting a scheme now
//! would either pre-empt that decision or record one that has to be withdrawn.
//! Every code point therefore resolves to a refusal.
//!
//! That is the correct behaviour rather than a placeholder: there genuinely is
//! no admitted scheme, and the status quo — a decoder accepting any non-zero
//! `u16` as a scheme — is strictly worse than refusing all of them. The
//! resolver, its two distinct refusals, and the reservation are final; only
//! the row set is empty, and filling it is a data change.

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

/// The registered signature schemes.
///
/// Empty until ADR-0003 is accepted. See the module documentation: this is a
/// recorded absence, not an oversight.
pub const SIGNATURE_SCHEME_REGISTRY: &[SignatureSchemeRow] = &[];

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
