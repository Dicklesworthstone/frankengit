//! Digest value shells.
//!
//! This module owns the *shape* of a digest: a registry code point naming the
//! algorithm plus bounded digest bytes. It deliberately owns no algorithm.
//! Computing a digest, mapping a code point to a concrete construction,
//! declaring the output length of that construction, and the migration policy
//! between constructions all belong to the digest registry in `fgit-crypto`.
//!
//! Keeping the split here means `fgit-types` never depends on a cryptographic
//! implementation, so every protocol body type is expressible before any
//! algorithm is chosen, and choosing one later cannot silently change a body's
//! shape.

use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};

use crate::error::TypeRefusal;

/// Largest digest body this shell can carry, in bytes.
pub const MAX_DIGEST_LEN: usize = 64;
/// Smallest digest body this shell accepts, in bytes.
pub const MIN_DIGEST_LEN: usize = 16;

/// Registry code point naming a digest construction.
///
/// The value is opaque to this crate. `fgit-crypto` owns the mapping from a
/// code point to a construction, its output length, and its status. Code point
/// zero is reserved and never names an algorithm, so a zeroed buffer cannot be
/// mistaken for a valid algorithm slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DigestAlgorithmId(u16);

impl DigestAlgorithmId {
    /// Builds an algorithm code point, refusing the reserved zero slot.
    pub fn try_new(code_point: u16) -> Result<Self, TypeRefusal> {
        if code_point == 0 {
            return Err(TypeRefusal::ValueOutOfRange {
                field: "DigestAlgorithmId",
                observed: 0,
                minimum: 1,
                maximum: u64::from(u16::MAX),
            });
        }
        Ok(Self(code_point))
    }

    /// The registry code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        self.0
    }
}

impl fmt::Display for DigestAlgorithmId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "alg:{}", self.0)
    }
}

/// A bounded digest body.
///
/// Storage is inline and fixed capacity so a digest stays `Copy` and
/// allocation-free on every target.
#[derive(Clone, Copy)]
pub struct DigestBytes {
    bytes: [u8; MAX_DIGEST_LEN],
    len: usize,
}

impl DigestBytes {
    /// Builds a digest body, refusing lengths outside
    /// [`MIN_DIGEST_LEN`]..=[`MAX_DIGEST_LEN`].
    pub fn try_new(source: &[u8]) -> Result<Self, TypeRefusal> {
        if source.len() < MIN_DIGEST_LEN || source.len() > MAX_DIGEST_LEN {
            return Err(TypeRefusal::LengthOutOfRange {
                field: "DigestBytes",
                observed: u32::try_from(source.len()).unwrap_or(u32::MAX),
                minimum: 16,
                maximum: 64,
            });
        }
        let mut bytes = [0_u8; MAX_DIGEST_LEN];
        bytes[..source.len()].copy_from_slice(source);
        Ok(Self {
            bytes,
            len: source.len(),
        })
    }

    /// The digest body, without padding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.split_at(self.len).0
    }

    /// Digest length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Always false: a digest body is never empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl PartialEq for DigestBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for DigestBytes {}

impl PartialOrd for DigestBytes {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DigestBytes {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl Hash for DigestBytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl fmt::Debug for DigestBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DigestBytes(")?;
        for byte in self.as_bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

impl fmt::Display for DigestBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// An algorithm-tagged digest.
///
/// The algorithm travels with the bytes. Two digests with identical bytes but
/// different algorithm code points are different values and never compare
/// equal, which is what keeps a migration from silently aliasing identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest {
    algorithm: DigestAlgorithmId,
    bytes: DigestBytes,
}

impl Digest {
    /// Builds an algorithm-tagged digest.
    #[must_use]
    pub const fn new(algorithm: DigestAlgorithmId, bytes: DigestBytes) -> Self {
        Self { algorithm, bytes }
    }

    /// Builds a digest and checks the body length against a length the caller
    /// obtained from the digest registry.
    ///
    /// This crate cannot know an algorithm's output length, so the expected
    /// length is supplied by the caller rather than assumed.
    pub fn new_checked(
        algorithm: DigestAlgorithmId,
        bytes: DigestBytes,
        registry_len: usize,
    ) -> Result<Self, TypeRefusal> {
        if bytes.len() != registry_len {
            return Err(TypeRefusal::DigestLengthMismatch {
                algorithm,
                expected: u32::try_from(registry_len).unwrap_or(u32::MAX),
                observed: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            });
        }
        Ok(Self { algorithm, bytes })
    }

    /// The algorithm code point.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithmId {
        self.algorithm
    }

    /// The digest body.
    #[must_use]
    pub const fn bytes(&self) -> &DigestBytes {
        &self.bytes
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.algorithm, self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{DigestBytes, MAX_DIGEST_LEN, MIN_DIGEST_LEN};
    use crate::TypeRefusal;

    /// The refusal a length outside the range must produce.
    fn length_refusal(observed: u32) -> TypeRefusal {
        TypeRefusal::LengthOutOfRange {
            field: "DigestBytes",
            observed,
            minimum: 16,
            maximum: 64,
        }
    }

    #[test]
    fn both_extremes_of_the_permitted_range_construct() {
        // THE PERMITTED HALF, at the extremes rather than in the comfortable
        // middle. Every one of the 123 call sites in this workspace passes 32
        // or 16 bytes, so the top of the range had never been constructed at
        // all before this test.
        for len in [MIN_DIGEST_LEN, 17, 32, MAX_DIGEST_LEN - 1, MAX_DIGEST_LEN] {
            let source = vec![0xab_u8; len];
            let digest = DigestBytes::try_new(&source)
                .unwrap_or_else(|refusal| panic!("{len} bytes is inside 16..=64; got {refusal:?}"));
            assert_eq!(
                digest.as_bytes(),
                source.as_slice(),
                "{len} bytes must round-trip exactly; this pins the `len` bookkeeping beside \
                 the guard, since the body is stored in a fixed-capacity array and only `len` \
                 distinguishes payload from padding"
            );
        }
    }

    #[test]
    fn one_step_outside_each_end_refuses_by_payload() {
        // THE FORBIDDEN HALF, one step outside each extreme -- the values an
        // off-by-one moves across. Asserted by PAYLOAD rather than `is_err`,
        // because the observed length is what tells an operator which side of
        // the range was violated, and `is_err` would pass against a refusal
        // that named the wrong field or lost the measurement.
        for len in [0_usize, 1, MIN_DIGEST_LEN - 1] {
            assert_eq!(
                DigestBytes::try_new(&vec![0xcd_u8; len]),
                Err(length_refusal(
                    u32::try_from(len).expect("a test length fits in u32")
                )),
                "{len} bytes is below the minimum and must refuse"
            );
        }

        // MAX + 1 IS THE ONE THAT MATTERS MOST, and it is why this test is
        // filed at P2 rather than as tidying. `DigestBytes` stores its body in
        // an inline `[u8; MAX_DIGEST_LEN]`, and `try_new` copies with
        // `bytes[..source.len()].copy_from_slice(source)` AFTER this check. A
        // guard that admitted 65 bytes would index that array out of range and
        // PANIC. The crate forbids unsafe, so the panic is memory-safe -- but
        // AGENTS.md 3.1 requires a typed refusal, not an abort, and this is
        // the only thing standing between the two.
        for len in [MAX_DIGEST_LEN + 1, MAX_DIGEST_LEN * 2] {
            assert_eq!(
                DigestBytes::try_new(&vec![0xef_u8; len]),
                Err(length_refusal(
                    u32::try_from(len).expect("a test length fits in u32")
                )),
                "{len} bytes is above the maximum and must refuse rather than panic on the \
                 fixed-capacity copy below the guard"
            );
        }
    }
}
