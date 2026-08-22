#![forbid(unsafe_code)]

//! frankengit-76b3: the object-identity width bound, and its ordering against
//! the zero check.
//!
//! `validate_object_identity` (lib.rs:1289) guards every envelope and every
//! pushed record:
//!
//! ```text
//! :1294  object_identity.is_zero()                      -> ZeroObjectIdentity
//! :1297  as_bytes().len() > max_object_identity_bytes    -> ObjectIdentityTooLarge
//! ```
//!
//! The zero check is already covered by the crate's in-src module (lib.rs:1916,
//! through the public `ObjectEnvelope::new`). The WIDTH bound is not covered
//! anywhere, and neither is the order between them.
//!
//! # Why the ordering is worth a test rather than a comment
//!
//! A zero identity is also, under a tight enough limit, an oversized one -- both
//! conditions can hold for the same input. Which refusal a caller receives is
//! then decided purely by the order of two `if`s, and the two say different
//! things: "you sent nothing" versus "your digest is wider than this store
//! accepts". Swapping them would change the diagnosis for that input while
//! leaving every single-fault probe passing.

use fgit_object_fabric::{
    CryptoDigest, DigestAlgorithm, FabricError, ObjectEnvelope, ObjectKind, SegmentLimits,
};
use fgit_types::native::{GitOid, GitOidSha1};

/// A SHA-1 object identity is twenty bytes; that width is what the bound is
/// measured against.
const SHA1_WIDTH: usize = 20;

const fn limits(max_object_identity_bytes: usize) -> SegmentLimits {
    SegmentLimits {
        max_segment_bytes: 64 * 1024,
        max_records: 128,
        max_namespace_bytes: 16,
        max_object_identity_bytes,
        max_envelope_bytes: 256,
        max_record_bytes: 512,
    }
}

const fn oid(byte: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([byte; GitOidSha1::LEN]))
}

/// Builds an envelope around `identity` under `limits`; everything else is held
/// constant so a refusal is attributable to the identity alone.
fn envelope(identity: GitOid, limits: &SegmentLimits) -> Result<ObjectEnvelope, FabricError> {
    let payload = b"payload".to_vec();
    ObjectEnvelope::new(
        vec![b'n'],
        identity,
        ObjectKind::Blob,
        u64::try_from(payload.len()).expect("fixture payload length fits u64"),
        CryptoDigest
            .payload_commitment(ObjectKind::Blob, &payload)
            .expect("registered payload commitment succeeds"),
        vec![b'c'],
        [4_u8; 32],
        None,
        limits,
    )
}

/// An identity wider than the store admits is refused.
///
/// The identity is an ordinary non-zero SHA-1, so the zero check cannot be what
/// fires; only the limit is tightened.
#[test]
fn an_object_identity_wider_than_the_limit_is_refused() {
    let refusal = envelope(oid(0x11), &limits(SHA1_WIDTH - 1))
        .expect_err("a twenty-byte identity exceeds a nineteen-byte limit");

    assert_eq!(refusal, FabricError::ObjectIdentityTooLarge);
}

/// The permitted twin at the exact inclusive boundary: an identity of exactly
/// the limit is accepted.
///
/// The guard is `>`. Written `>=` it would reject a SHA-1 identity under a
/// twenty-byte limit -- that is, the ordinary configuration -- while the
/// nineteen-byte probe above still passed.
#[test]
fn an_object_identity_of_exactly_the_limit_is_accepted() {
    envelope(oid(0x11), &limits(SHA1_WIDTH))
        .expect("an identity of exactly the permitted width must be admitted");
}

/// Ordering: a zero identity that is ALSO oversized reports the zero, not the
/// width.
///
/// Both conditions hold for this input -- the identity is all-zero and twenty
/// bytes against a nineteen-byte limit -- so only the order of the two checks
/// decides the answer. Swap them and this test fails while both single-fault
/// probes above continue to pass, which is exactly the blindness a per-variant
/// corpus has to guard-order.
#[test]
fn a_zero_identity_that_is_also_oversized_reports_the_zero_first() {
    let refusal = envelope(oid(0x00), &limits(SHA1_WIDTH - 1))
        .expect_err("an all-zero identity is refused whatever the width limit");

    assert_eq!(
        refusal,
        FabricError::ZeroObjectIdentity,
        "the zero check precedes the width bound, so an input failing both is \
         diagnosed as empty rather than as too wide",
    );
}
